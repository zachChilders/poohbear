//! ClientHello parsing and the JA4 client fingerprint.
//!
//! rustls does not expose the extension list or its order, which JA4 needs,
//! so the hello is parsed here from the raw handshake bytes before rustls
//! sees them. The parser is strictly bounds-checked: any malformed input is
//! `None`, never a panic.

use ring::digest::{digest, SHA256};

/// What a client offered, in wire order. GREASE values are kept here and
/// dropped only when fingerprinting.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<Vec<u8>>,
    /// From `supported_versions`; empty if the extension is absent.
    pub versions: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
}

const EXT_SNI: u16 = 0x0000;
const EXT_SIG_ALGS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_VERSIONS: u16 = 0x002b;

/// GREASE (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa.
fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|b| (b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    /// A length-prefixed sub-slice, with a `width`-byte length.
    fn vec(&mut self, width: usize) -> Option<Reader<'a>> {
        let n = match width {
            1 => self.u8()? as usize,
            2 => self.u16()? as usize,
            _ => self.u24()?,
        };
        self.take(n).map(Reader)
    }
    fn u16s(mut self) -> Option<Vec<u16>> {
        let mut out = Vec::with_capacity(self.0.len() / 2);
        while !self.0.is_empty() {
            out.push(self.u16()?);
        }
        Some(out)
    }
}

/// Parse a handshake message (starting at the handshake type byte) as a
/// ClientHello.
pub fn parse(handshake: &[u8]) -> Option<ClientHello> {
    let mut r = Reader(handshake);
    if r.u8()? != 1 {
        return None; // not a ClientHello
    }
    let mut body = r.vec(3)?;
    let mut hello = ClientHello {
        legacy_version: body.u16()?,
        ..Default::default()
    };
    body.take(32)?; // random
    body.vec(1)?; // legacy session id
    hello.ciphers = body.vec(2)?.u16s()?;
    body.vec(1)?; // compression methods
    if body.0.is_empty() {
        return Some(hello); // extensions are optional (pre-TLS 1.2 clients)
    }
    let mut exts = body.vec(2)?;
    while !exts.0.is_empty() {
        let kind = exts.u16()?;
        let mut data = exts.vec(2)?;
        hello.extensions.push(kind);
        match kind {
            EXT_SNI => {
                let mut list = data.vec(2)?;
                while !list.0.is_empty() {
                    let name_type = list.u8()?;
                    let name = list.vec(2)?;
                    if name_type == 0 && hello.sni.is_none() {
                        hello.sni = Some(String::from_utf8_lossy(name.0).into_owned());
                    }
                }
            }
            EXT_ALPN => {
                let mut list = data.vec(2)?;
                while !list.0.is_empty() {
                    hello.alpn.push(list.vec(1)?.0.to_vec());
                }
            }
            EXT_VERSIONS => hello.versions = data.vec(1)?.u16s()?,
            EXT_SIG_ALGS => hello.signature_algorithms = data.vec(2)?.u16s()?,
            _ => {}
        }
    }
    Some(hello)
}

impl ClientHello {
    /// The highest offered version, preferring `supported_versions`.
    fn max_version(&self) -> u16 {
        self.versions
            .iter()
            .copied()
            .filter(|v| !is_grease(*v))
            .max()
            .unwrap_or(self.legacy_version)
    }

    /// Offered versions as "1.3", "1.2", ... (GREASE dropped), for the log.
    pub fn version_names(&self) -> Vec<String> {
        let vs: Vec<u16> = if self.versions.is_empty() {
            vec![self.legacy_version]
        } else {
            self.versions.clone()
        };
        vs.into_iter()
            .filter(|v| !is_grease(*v))
            .map(|v| match v {
                0x0304 => "1.3".into(),
                0x0303 => "1.2".into(),
                0x0302 => "1.1".into(),
                0x0301 => "1.0".into(),
                0x0300 => "ssl3".into(),
                other => format!("0x{other:04x}"),
            })
            .collect()
    }

    /// The JA4 fingerprint (FoxIO, TCP), e.g. `t13d1516h2_8daaf6152771_e5627efa2ab1`.
    pub fn ja4(&self) -> String {
        let version = match self.max_version() {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            0x0002 => "s2",
            _ => "00",
        };
        let sni = if self.sni.is_some() { 'd' } else { 'i' };
        let ciphers: Vec<u16> = self
            .ciphers
            .iter()
            .copied()
            .filter(|c| !is_grease(*c))
            .collect();
        let exts: Vec<u16> = self
            .extensions
            .iter()
            .copied()
            .filter(|e| !is_grease(*e))
            .collect();
        let alpn = alpn_chars(self.alpn.first().map(Vec::as_slice));
        let a = format!(
            "t{version}{sni}{:02}{:02}{alpn}",
            ciphers.len().min(99),
            exts.len().min(99)
        );

        let mut sorted_ciphers = ciphers;
        sorted_ciphers.sort_unstable();
        let b = hash12(&hex_list(&sorted_ciphers));

        let mut sorted_exts: Vec<u16> = exts
            .into_iter()
            .filter(|e| *e != EXT_SNI && *e != EXT_ALPN)
            .collect();
        sorted_exts.sort_unstable();
        let c = if sorted_exts.is_empty() {
            "000000000000".to_string()
        } else {
            let sigs: Vec<u16> = self
                .signature_algorithms
                .iter()
                .copied()
                .filter(|s| !is_grease(*s))
                .collect();
            let mut input = hex_list(&sorted_exts);
            if !sigs.is_empty() {
                input.push('_');
                input.push_str(&hex_list(&sigs));
            }
            hash12(&input)
        };
        format!("{a}_{b}_{c}")
    }
}

/// First and last character of the first ALPN value; `00` with none. A
/// non-alphanumeric end is replaced by a hex digit of its byte.
fn alpn_chars(first: Option<&[u8]>) -> String {
    let Some(v) = first.filter(|v| !v.is_empty()) else {
        return "00".into();
    };
    let (f, l) = (v[0], v[v.len() - 1]);
    if f.is_ascii_alphanumeric() && l.is_ascii_alphanumeric() {
        format!("{}{}", f as char, l as char)
    } else {
        let hex = |b: u8| format!("{b:02x}");
        format!("{}{}", &hex(f)[..1], &hex(l)[1..])
    }
}

fn hex_list(vs: &[u16]) -> String {
    vs.iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn hash12(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".into();
    }
    digest(&SHA256, input.as_bytes())
        .as_ref()
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from the JA4 specification.
    fn spec_example() -> ClientHello {
        ClientHello {
            legacy_version: 0x0303,
            ciphers: vec![
                0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
                0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x0a0a,
            ],
            extensions: vec![
                0x1a1a, 0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x000d,
                0x0012, 0x0033, 0x002d, 0x002b, 0x001b, 0x0015, 0x4469,
            ],
            sni: Some("example.com".into()),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            versions: vec![0x2a2a, 0x0304, 0x0303],
            signature_algorithms: vec![
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
        }
    }

    #[test]
    fn ja4_matches_the_specification_example() {
        assert_eq!(spec_example().ja4(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn ja4_edge_cases() {
        let mut h = spec_example();
        h.sni = None;
        h.alpn.clear();
        assert!(h.ja4().starts_with("t13i151600_"));
        h.alpn = vec![vec![0xab, b'x', 0x12]];
        assert!(h.ja4().starts_with("t13i1516a2_"));
        let bare = ClientHello {
            legacy_version: 0x0301,
            ..Default::default()
        };
        assert_eq!(bare.ja4(), "t10i000000_000000000000_000000000000");
        assert!(is_grease(0xfafa) && !is_grease(0x0a1a));
        assert_eq!(spec_example().version_names(), ["1.3", "1.2"]);
    }

    /// Encode a ClientHello the way a client would.
    pub(crate) fn encode(h: &ClientHello) -> Vec<u8> {
        fn with_len(width: usize, body: &[u8]) -> Vec<u8> {
            let n = body.len().to_be_bytes();
            let mut out = n[n.len() - width..].to_vec();
            out.extend_from_slice(body);
            out
        }
        let u16s = |vs: &[u16]| vs.iter().flat_map(|v| v.to_be_bytes()).collect::<Vec<u8>>();
        let mut exts = vec![];
        for &e in &h.extensions {
            let data = match e {
                EXT_SNI => {
                    let name = h.sni.clone().unwrap_or_default();
                    let mut entry = vec![0u8];
                    entry.extend(with_len(2, name.as_bytes()));
                    with_len(2, &entry)
                }
                EXT_ALPN => with_len(
                    2,
                    &h.alpn
                        .iter()
                        .flat_map(|p| with_len(1, p))
                        .collect::<Vec<_>>(),
                ),
                EXT_VERSIONS => with_len(1, &u16s(&h.versions)),
                EXT_SIG_ALGS => with_len(2, &u16s(&h.signature_algorithms)),
                _ => vec![],
            };
            exts.extend(e.to_be_bytes());
            exts.extend(with_len(2, &data));
        }
        let mut body = h.legacy_version.to_be_bytes().to_vec();
        body.extend([7u8; 32]);
        body.extend(with_len(1, &[1, 2, 3]));
        body.extend(with_len(2, &u16s(&h.ciphers)));
        body.extend(with_len(1, &[0]));
        body.extend(with_len(2, &exts));
        let mut msg = vec![1u8];
        msg.extend(with_len(3, &body));
        msg
    }

    #[test]
    fn parses_what_a_client_sends() {
        let h = spec_example();
        assert_eq!(parse(&encode(&h)), Some(h));
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        let good = encode(&spec_example());
        for cut in 0..good.len() {
            let _ = parse(&good[..cut]);
        }
        assert_eq!(parse(&good[..good.len() - 1]), None);
        assert_eq!(parse(b"\x02\x00\x00\x00"), None, "not a ClientHello");
        // A hostile length field inside an extension.
        let mut bad = good.clone();
        let at = bad.len() - 3;
        bad[at] = 0xff;
        let _ = parse(&bad);
    }
}
