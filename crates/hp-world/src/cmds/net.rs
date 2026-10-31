//! `wget` and `curl`, simulated.
//!
//! **Nothing here touches the network.** A "download" is deterministic
//! content derived from the URL, written into the session's in-memory
//! filesystem, so a fetched payload appears to land and the attacker carries
//! on (revealing the next stage) while we never contact, resolve, or fetch
//! anything. Every fetch raises `payload_fetch`.

use super::Streams;
use crate::fs::MAX_FILE_BYTES;
use crate::shell::Shell;
use crate::timefmt::strftime;

/// A parsed download target.
#[derive(Debug, PartialEq, Eq)]
struct Url {
    full: String,
    https: bool,
    host: String,
    port: u16,
    /// Last path segment, or `index.html`.
    filename: String,
}

fn parse_url(raw: &str) -> Url {
    let full = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let (scheme, rest) = full.split_once("://").unwrap_or(("http", &full));
    let https = scheme.eq_ignore_ascii_case("https");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(80))
        }
        _ => (authority.to_string(), if https { 443 } else { 80 }),
    };
    let clean = path.split(['?', '#']).next().unwrap_or("");
    let filename = clean
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("index.html")
        .to_string();
    Url {
        full,
        https,
        host,
        port,
        filename,
    }
}

fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// A stable pseudo-address for a host name. Avoids private and loopback ranges
/// so it looks like a real internet host.
fn fake_ip(host: &str) -> String {
    let h = fnv(host.as_bytes()).to_le_bytes();
    let mut first = 11 + h[0] % 190;
    if matches!(first, 10 | 127 | 172 | 192) {
        first += 1;
    }
    format!(
        "{first}.{}.{}.{}",
        1 + h[1] % 254,
        1 + h[2] % 254,
        1 + h[3] % 254
    )
}

/// Placeholder content for a URL: stable across calls, plausibly sized, and
/// shaped like what the file name suggests. It is never real attacker
/// infrastructure's content, and nothing here is executable.
fn fake_payload(url: &Url) -> Vec<u8> {
    let mut state = fnv(url.full.as_bytes()) | 1;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let name = url.filename.to_lowercase();
    let script = [".sh", ".pl", ".py", ".bash"]
        .iter()
        .any(|e| name.ends_with(e));
    let mut out = Vec::new();
    if script {
        out.extend_from_slice(format!("#!/bin/sh\n# {}\n", url.filename).as_bytes());
        for _ in 0..40 + next() % 80 {
            out.extend_from_slice(format!(": {:x}\n", next() & 0xffff_ffff).as_bytes());
        }
    } else {
        out.extend_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        let len = 20_000 + (next() % 100_000) as usize;
        while out.len() < len {
            out.extend_from_slice(&next().to_le_bytes());
        }
        out.truncate(len);
    }
    out.truncate(MAX_FILE_BYTES);
    out
}

fn human_len(n: usize) -> String {
    if n < 1024 {
        format!("{n}")
    } else {
        format!("{}K", n.div_ceil(1024))
    }
}

/// Pick `name`, or `name.1`, `name.2`... if it exists (wget does not clobber).
fn unique_name(sh: &Shell, dir: &str, name: &str) -> String {
    let join = |n: &str| format!("{}/{n}", dir.trim_end_matches('/'));
    if !sh.fs.exists(&join(name)) {
        return name.to_string();
    }
    (1..1000)
        .map(|i| format!("{name}.{i}"))
        .find(|n| !sh.fs.exists(&join(n)))
        .unwrap_or_else(|| name.to_string())
}

/// Short flags of wget that take a value.
const WGET_VALUE_SHORT: &str = "OoPtTUewi";
const WGET_VALUE_LONG: &[&str] = &[
    "output-document",
    "output-file",
    "directory-prefix",
    "tries",
    "timeout",
    "user-agent",
    "header",
    "wait",
    "post-data",
    "referer",
    "user",
    "password",
];

pub(crate) fn wget(sh: &mut Shell, args: &[String]) -> Streams {
    let (mut quiet, mut output, mut prefix) = (false, None::<String>, None::<String>);
    let mut urls = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if let Some(long) = a.strip_prefix("--") {
            let (key, inline) = long
                .split_once('=')
                .map_or((long, None), |(k, v)| (k, Some(v.to_string())));
            let value = if WGET_VALUE_LONG.contains(&key) {
                inline.or_else(|| {
                    i += 1;
                    args.get(i - 1).cloned()
                })
            } else {
                None
            };
            match key {
                "quiet" => quiet = true,
                "output-document" => output = value,
                "directory-prefix" => prefix = value,
                _ => {}
            }
        } else if a.starts_with('-') && a.len() > 1 {
            let chars: Vec<char> = a[1..].chars().collect();
            for (n, c) in chars.iter().enumerate() {
                if *c == 'q' {
                    quiet = true;
                } else if WGET_VALUE_SHORT.contains(*c) {
                    let attached: String = chars[n + 1..].iter().collect();
                    let value = if attached.is_empty() {
                        i += 1;
                        args.get(i - 1).cloned()
                    } else {
                        Some(attached)
                    };
                    match c {
                        'O' => output = value,
                        'P' => prefix = value,
                        _ => {}
                    }
                    break;
                }
            }
        } else {
            urls.push(a.clone());
        }
    }
    if urls.is_empty() {
        return Streams::fail(1, "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.");
    }

    let (mut out, mut err, mut status) = (Vec::new(), String::new(), 0);
    for raw in &urls {
        let url = parse_url(raw);
        let data = fake_payload(&url);
        sh.tag("payload_fetch");
        let now = sh.now();
        let ip = fake_ip(&url.host);
        let mime = if url.filename.ends_with(".sh") {
            "application/x-sh"
        } else {
            "application/octet-stream"
        };
        let to_stdout = output.as_deref() == Some("-");

        let dir = prefix
            .as_deref()
            .map_or_else(|| sh.cwd.clone(), |p| sh.abs(p));
        let name = match &output {
            Some(o) if !to_stdout => o.clone(),
            _ => unique_name(sh, &dir, &url.filename),
        };
        let target = if name.starts_with('/') {
            name.clone()
        } else {
            format!("{}/{name}", dir.trim_end_matches('/'))
        };

        if !quiet {
            err.push_str(&format!(
                "--{}--  {}\n",
                strftime("%Y-%m-%d %H:%M:%S", now),
                url.full
            ));
            err.push_str(&format!("Resolving {0} ({0})... {ip}\n", url.host));
            err.push_str(&format!(
                "Connecting to {0} ({0})|{ip}|:{1}... connected.\n",
                url.host, url.port
            ));
            err.push_str("HTTP request sent, awaiting response... 200 OK\n");
            err.push_str(&format!(
                "Length: {} ({}) [{mime}]\n",
                data.len(),
                human_len(data.len())
            ));
            let saving = if to_stdout {
                "'STDOUT'".to_string()
            } else {
                format!("‘{name}’")
            };
            err.push_str(&format!("Saving to: {saving}\n\n"));
        }

        if to_stdout {
            sh.pipe_from_fetch = true;
            out.extend_from_slice(&data);
        } else if let Err(e) = sh.write_file(&target, &data, false) {
            if !quiet {
                err.push_str(&format!(
                    "{name}: {}\n\nCannot write to ‘{name}’ ({}).\n",
                    e.message(),
                    e.message()
                ));
            }
            status = 1;
            continue;
        }
        if !quiet {
            let kb = data.len() as f64 / 1024.0;
            if !to_stdout {
                err.push_str(&format!(
                    "{name:<19} 100%[===================>] {kb:>7.2}K  --.-KB/s    in 0.04s   \n\n"
                ));
            }
            let done = if to_stdout {
                "'STDOUT'".to_string()
            } else {
                format!("‘{name}’")
            };
            err.push_str(&format!(
                "{} (1.21 MB/s) - {done} saved [{1}/{1}]\n\n",
                strftime("%Y-%m-%d %H:%M:%S", now),
                data.len()
            ));
        }
    }
    Streams {
        out,
        err: err.into_bytes(),
        status,
    }
}

const CURL_VALUE_SHORT: &str = "oAHXduWmebcTwK";
const CURL_VALUE_LONG: &[&str] = &[
    "output",
    "user-agent",
    "header",
    "request",
    "data",
    "user",
    "max-time",
    "connect-timeout",
    "retry",
    "referer",
    "cookie",
    "upload-file",
    "data-raw",
    "data-binary",
    "url",
];

pub(crate) fn curl(sh: &mut Shell, args: &[String]) -> Streams {
    let (mut silent, mut remote_name, mut output) = (false, false, None::<String>);
    let mut urls = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        i += 1;
        if let Some(long) = a.strip_prefix("--") {
            let (key, inline) = long
                .split_once('=')
                .map_or((long, None), |(k, v)| (k, Some(v.to_string())));
            let value = if CURL_VALUE_LONG.contains(&key) {
                inline.or_else(|| {
                    i += 1;
                    args.get(i - 1).cloned()
                })
            } else {
                None
            };
            match key {
                "silent" => silent = true,
                "remote-name" => remote_name = true,
                "output" => output = value,
                "url" => urls.extend(value),
                _ => {}
            }
        } else if a.starts_with('-') && a.len() > 1 {
            let chars: Vec<char> = a[1..].chars().collect();
            for (n, c) in chars.iter().enumerate() {
                match c {
                    's' => silent = true,
                    'O' => remote_name = true,
                    c if CURL_VALUE_SHORT.contains(*c) => {
                        let attached: String = chars[n + 1..].iter().collect();
                        let value = if attached.is_empty() {
                            i += 1;
                            args.get(i - 1).cloned()
                        } else {
                            Some(attached)
                        };
                        if *c == 'o' {
                            output = value;
                        }
                        break;
                    }
                    _ => {}
                }
            }
        } else {
            urls.push(a.clone());
        }
    }
    if urls.is_empty() {
        return Streams::fail(
            2,
            "curl: try 'curl --help' or 'curl --manual' for more information",
        );
    }

    let (mut out, mut err, mut status) = (Vec::new(), String::new(), 0);
    for raw in &urls {
        let url = parse_url(raw);
        let data = fake_payload(&url);
        sh.tag("payload_fetch");
        let name = match (&output, remote_name) {
            (Some(o), _) => Some(o.clone()),
            (None, true) => Some(url.filename.clone()),
            (None, false) => None,
        };
        let Some(name) = name else {
            sh.pipe_from_fetch = true;
            out.extend_from_slice(&data);
            continue;
        };
        if let Err(e) = sh.write_file(&sh.abs(&name), &data, false) {
            err.push_str(&format!("Warning: Failed to open the file {name}: {}\ncurl: (23) Failure writing output to destination\n", e.message()));
            status = 23;
            continue;
        }
        if !silent {
            err.push_str(
                "  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n",
            );
            err.push_str(
                "                                 Dload  Upload   Total   Spent    Left  Speed\n",
            );
            err.push_str(&format!("100 {0:>5}  100 {0:>5}    0     0   211k      0 --:--:-- --:--:-- --:--:--  212k\n", data.len()));
        }
    }
    Streams {
        out,
        err: err.into_bytes(),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_split_into_the_parts_the_output_needs() {
        let u = parse_url("http://evil.example/x/bot.sh?v=1#f");
        assert_eq!(
            (u.host.as_str(), u.port, u.https, u.filename.as_str()),
            ("evil.example", 80, false, "bot.sh")
        );
        let u = parse_url("https://a.b:8443/");
        assert_eq!(
            (u.host.as_str(), u.port, u.https, u.filename.as_str()),
            ("a.b", 8443, true, "index.html")
        );
        let u = parse_url("host.example/p/q.bin");
        assert_eq!(
            (u.full.as_str(), u.filename.as_str()),
            ("http://host.example/p/q.bin", "q.bin")
        );
        assert_eq!(
            parse_url("http://user:pw@h.example/a").host,
            "h.example",
            "credentials are not the host"
        );
        assert_eq!(parse_url("http://h.example").filename, "index.html");
    }

    #[test]
    fn fake_addresses_are_stable_and_never_private() {
        assert_eq!(fake_ip("evil.example"), fake_ip("evil.example"));
        assert_ne!(fake_ip("a.example"), fake_ip("b.example"));
        for h in [
            "a",
            "b",
            "c",
            "d",
            "evil.example",
            "10.0.0.1",
            "localhost",
            "x.y.z",
        ] {
            let ip = fake_ip(h);
            let first: u8 = ip.split('.').next().unwrap().parse().unwrap();
            assert!(!matches!(first, 0 | 10 | 127 | 172 | 192), "{ip}");
        }
    }

    #[test]
    fn payloads_are_deterministic_sized_and_shaped_by_name() {
        let sh = parse_url("http://e.example/bot.sh");
        let bin = parse_url("http://e.example/miner");
        assert_eq!(fake_payload(&sh), fake_payload(&sh), "same URL, same bytes");
        assert_ne!(
            fake_payload(&sh),
            fake_payload(&parse_url("http://e.example/other.sh"))
        );
        assert!(fake_payload(&sh).starts_with(b"#!/bin/sh\n"));
        let b = fake_payload(&bin);
        assert!(b.starts_with(b"\x7fELF"));
        assert!((20_000..=120_000).contains(&b.len()), "{}", b.len());
        assert!(b.len() <= MAX_FILE_BYTES);
    }

    #[test]
    fn human_length_like_wget() {
        assert_eq!(human_len(512), "512");
        assert_eq!(human_len(48_231), "48K");
    }
}
