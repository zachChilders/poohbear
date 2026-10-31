//! `echo`, `printf` and `base64`: the tools used to write binaries and
//! scripts into a file from a command line.

use super::{split_flags, Streams};
use crate::shell::Shell;

/// Interpret backslash escapes the way `echo -e` and `printf` do: `\n \t \r
/// \a \b \e \f \v \\`, `\xHH`, `\0NNN`. Returns the bytes and whether `\c`
/// asked to stop output.
pub(crate) fn unescape(s: &str) -> (Vec<u8>, bool) {
    let cs: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut buf = [0u8; 4];
    while i < cs.len() {
        if cs[i] != '\\' || i + 1 == cs.len() {
            out.extend_from_slice(cs[i].encode_utf8(&mut buf).as_bytes());
            i += 1;
            continue;
        }
        i += 1;
        match cs[i] {
            'n' => out.push(b'\n'),
            't' => out.push(b'\t'),
            'r' => out.push(b'\r'),
            'a' => out.push(7),
            'b' => out.push(8),
            'e' | 'E' => out.push(0x1b),
            'f' => out.push(12),
            'v' => out.push(11),
            '\\' => out.push(b'\\'),
            'c' => return (out, true),
            'x' => {
                let hex: String = cs[i + 1..]
                    .iter()
                    .take(2)
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect();
                if hex.is_empty() {
                    out.extend_from_slice(b"\\x");
                } else {
                    out.push(u8::from_str_radix(&hex, 16).expect("validated hex"));
                    i += hex.len();
                }
            }
            '0' => {
                let oct: String = cs[i + 1..]
                    .iter()
                    .take(3)
                    .take_while(|c| ('0'..='7').contains(c))
                    .collect();
                out.push(u8::from_str_radix(&oct, 8).unwrap_or(0));
                i += oct.len();
            }
            other => {
                out.push(b'\\');
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
        }
        i += 1;
    }
    (out, false)
}

pub(crate) fn echo(args: &[String]) -> Streams {
    let (mut newline, mut escapes, mut start) = (true, false, 0);
    // Only leading arguments made purely of n/e/E are options.
    for a in args {
        let body = a.strip_prefix('-').unwrap_or("");
        if a.len() > 1 && a.starts_with('-') && body.chars().all(|c| matches!(c, 'n' | 'e' | 'E')) {
            for c in body.chars() {
                match c {
                    'n' => newline = false,
                    'e' => escapes = true,
                    _ => escapes = false,
                }
            }
            start += 1;
        } else {
            break;
        }
    }
    let joined = args[start..].join(" ");
    let mut out = if escapes {
        let (bytes, stop) = unescape(&joined);
        if stop {
            newline = false;
        }
        bytes
    } else {
        joined.into_bytes()
    };
    if newline {
        out.push(b'\n');
    }
    Streams::out(out)
}

pub(crate) fn printf(args: &[String]) -> Streams {
    let Some((format, rest)) = args.split_first() else {
        return Streams::fail(2, "printf: usage: printf [-v var] format [arguments]");
    };
    let mut out = Vec::new();
    let mut next = 0;
    let uses_args = format.contains('%') && format.replace("%%", "").contains('%');
    // The format is reused while arguments remain, as in bash.
    for _ in 0..100 {
        let mut chars = format.chars().peekable();
        let mut literal = String::new();
        while let Some(c) = chars.next() {
            if c != '%' {
                literal.push(c);
                continue;
            }
            out.extend(unescape(&std::mem::take(&mut literal)).0);
            match chars.next() {
                Some('%') => out.push(b'%'),
                Some(conv @ ('s' | 'd' | 'i' | 'c' | 'x' | 'b')) => {
                    let arg = rest.get(next).map_or("", String::as_str);
                    next += 1;
                    match conv {
                        's' => out.extend_from_slice(arg.as_bytes()),
                        'b' => out.extend(unescape(arg).0),
                        'c' => out.extend(
                            arg.chars()
                                .next()
                                .map(|c| c.to_string())
                                .unwrap_or_default()
                                .into_bytes(),
                        ),
                        'x' => out
                            .extend(format!("{:x}", arg.parse::<i64>().unwrap_or(0)).into_bytes()),
                        _ => out.extend(arg.parse::<i64>().unwrap_or(0).to_string().into_bytes()),
                    }
                }
                Some(other) => {
                    out.push(b'%');
                    out.extend(other.to_string().into_bytes());
                }
                None => out.push(b'%'),
            }
        }
        out.extend(unescape(&literal).0);
        if !uses_args || next >= rest.len() {
            break;
        }
    }
    Streams::out(out)
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn encode_base64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in text
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
    {
        let v = ALPHABET.iter().position(|a| *a == c)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits & 0xff) as u8);
        }
    }
    Some(out)
}

pub(crate) fn base64(sh: &mut Shell, args: &[String], stdin: &[u8]) -> Streams {
    let (flags, longs, files) = split_flags(args);
    let decode = flags.contains('d') || longs.iter().any(|l| l == "decode");
    let input = match files.first() {
        None => stdin.to_vec(),
        Some(f) => match sh.fs.read(&sh.abs(f)) {
            Ok(d) => d.to_vec(),
            Err(e) => return Streams::fail(1, format!("base64: {f}: {}", e.message())),
        },
    };
    if decode {
        match decode_base64(&String::from_utf8_lossy(&input)) {
            Some(bytes) => Streams::out(bytes),
            None => Streams::fail(1, "base64: invalid input"),
        }
    } else {
        let encoded = encode_base64(&input);
        let wrapped: Vec<&str> = encoded
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect();
        Streams::out(wrapped.join("\n") + if wrapped.is_empty() { "" } else { "\n" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn unescape_handles_the_escapes_used_to_write_binaries() {
        assert_eq!(unescape(r"a\nb\tc").0, b"a\nb\tc");
        assert_eq!(unescape(r"\x7fELF\x01").0, b"\x7fELF\x01");
        assert_eq!(unescape(r"\0101\0").0, b"A\0");
        assert_eq!(
            unescape(r"\\ \q \x").0,
            b"\\ \\q \\x",
            "unknown escapes stay literal"
        );
        assert_eq!(unescape(r"\e[0m").0, b"\x1b[0m");
        assert_eq!(unescape(r"ab\cdef"), (b"ab".to_vec(), true));
        assert_eq!(unescape("trailing\\").0, b"trailing\\");
        assert_eq!(unescape("héllo").0, "héllo".as_bytes());
    }

    #[test]
    fn echo_options_and_escapes() {
        assert_eq!(echo(&v(&["a", "b"])).out, b"a b\n");
        assert_eq!(echo(&v(&["-n", "a"])).out, b"a");
        assert_eq!(echo(&v(&["-e", r"a\x41\n"])).out, b"aA\n\n");
        assert_eq!(echo(&v(&["-ne", r"x\ty"])).out, b"x\ty");
        assert_eq!(
            echo(&v(&["a\\nb"])).out,
            b"a\\nb\n",
            "no -e means no escapes"
        );
        assert_eq!(echo(&v(&["-e", r"stop\cmore"])).out, b"stop");
        assert_eq!(
            echo(&v(&["-x", "a"])).out,
            b"-x a\n",
            "unknown flags are text"
        );
        assert_eq!(
            echo(&v(&["a", "-n"])).out,
            b"a -n\n",
            "options only at the start"
        );
        assert_eq!(echo(&[]).out, b"\n");
    }

    #[test]
    fn printf_formats_and_reuses_the_format() {
        assert_eq!(printf(&v(&["hello\\n"])).out, b"hello\n");
        assert_eq!(printf(&v(&["%s-%d\\n", "a", "42"])).out, b"a-42\n");
        assert_eq!(printf(&v(&["%s\\n", "a", "b", "c"])).out, b"a\nb\nc\n");
        assert_eq!(printf(&v(&["%x %c %%", "255", "zed"])).out, b"ff z %");
        assert_eq!(
            printf(&v(&["\\x41\\x42"])).out,
            b"AB",
            "how binaries get written"
        );
        assert_eq!(printf(&v(&["%b", r"a\tb"])).out, b"a\tb");
        assert_eq!(printf(&v(&["%q"])).out, b"%q");
        assert_eq!(printf(&v(&["%d", "junk"])).out, b"0");
        assert_eq!(printf(&[]).status, 2);
    }

    #[test]
    fn base64_round_trips_and_matches_known_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(
            decode_base64("Zm9v\nYmFy").unwrap(),
            b"foobar",
            "whitespace ignored"
        );
        assert_eq!(decode_base64("Zg==").unwrap(), b"f");
        assert!(decode_base64("not base64!").is_none());
        let data: Vec<u8> = (0..=255).collect();
        assert_eq!(decode_base64(&encode_base64(&data)).unwrap(), data);
    }
}
