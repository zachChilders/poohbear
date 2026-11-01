//! Turning what a track sent into a well-formed HTTP response.
//!
//! Tracks write either a whole response (`HTTP/1.1 302 Found\nLocation:
//! /\n\nbody`, `\n` or `\r\n` line ends) or just a body (served as a 200
//! HTML page). Either way the plugin owns the framing headers, so a track
//! can never get them wrong: `Content-Length`, `Connection` and `Date` are
//! always computed here, and `Server` comes from the persona unless the
//! track sets its own.

/// Framing headers a track may not set (they are always computed).
const COMPUTED: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "date",
    "keep-alive",
];

pub(crate) struct Frame<'a> {
    pub head_request: bool,
    pub keep_alive: bool,
    /// The `Server` header, from the persona banner.
    pub server: Option<&'a str>,
    /// An IMF-fixdate for the `Date` header.
    pub date: &'a str,
}

pub(crate) fn frame(text: &[u8], f: &Frame) -> Vec<u8> {
    let (status, headers, body) = split(text);
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(200);
    let bodyless = code == 204 || code == 304 || (100..200).contains(&code);

    let mut out = Vec::with_capacity(body.len() + 256);
    let mut line = |s: &str| {
        out.extend_from_slice(s.as_bytes());
        out.extend_from_slice(b"\r\n");
    };
    line(&status);
    let has = |name: &str| headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name));
    if let Some(server) = f.server.filter(|_| !has("server")) {
        line(&format!("Server: {server}"));
    }
    line(&format!("Date: {}", f.date));
    for (n, v) in &headers {
        if !COMPUTED.iter().any(|c| n.eq_ignore_ascii_case(c)) {
            line(&format!("{n}: {v}"));
        }
    }
    if !bodyless {
        line(&format!("Content-Length: {}", body.len()));
    }
    line(if f.keep_alive {
        "Connection: keep-alive"
    } else {
        "Connection: close"
    });
    line("");
    if !f.head_request && !bodyless {
        out.extend_from_slice(body);
    }
    out
}

type Parts<'a> = (String, Vec<(String, String)>, &'a [u8]);

fn split(text: &[u8]) -> Parts<'_> {
    if !text.starts_with(b"HTTP/") {
        let headers = vec![("Content-Type".into(), "text/html; charset=utf-8".into())];
        return ("HTTP/1.1 200 OK".into(), headers, text);
    }
    let crlf = find(text, b"\r\n\r\n").map(|i| (i, 4));
    let lf = find(text, b"\n\n").map(|i| (i, 2));
    let (head, body) = match [crlf, lf].into_iter().flatten().min() {
        Some((i, n)) => (&text[..i], &text[i + n..]),
        None => (text, &b""[..]),
    };
    let head = String::from_utf8_lossy(head);
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap_or("HTTP/1.1 200 OK")
        .trim_end()
        .to_string();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, body)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The response for a request the track did not answer, or that could not
/// be parsed, in the style of nginx.
pub(crate) fn error_page(code: u16, server: Option<&str>) -> Vec<u8> {
    let reason = match code {
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Request Entity Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let footer = server
        .map(|s| format!("<hr><center>{}</center>\r\n", escape(s)))
        .unwrap_or_default();
    format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/html\r\n\r\n\
         <html>\r\n<head><title>{code} {reason}</title></head>\r\n<body>\r\n\
         <center><h1>{code} {reason}</h1></center>\r\n{footer}</body>\r\n</html>\r\n"
    )
    .into_bytes()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: Frame = Frame {
        head_request: false,
        keep_alive: true,
        server: Some("nginx/1.18.0 (Ubuntu)"),
        date: "Sun, 01 Nov 2026 12:00:00 GMT",
    };

    fn s(b: Vec<u8>) -> String {
        String::from_utf8(b).unwrap()
    }

    #[test]
    fn a_bare_body_becomes_a_200_page() {
        assert_eq!(
            s(frame(b"<h1>hi</h1>", &F)),
            "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\nDate: Sun, 01 Nov 2026 12:00:00 GMT\r\n\
             Content-Type: text/html; charset=utf-8\r\nContent-Length: 11\r\nConnection: keep-alive\r\n\r\n<h1>hi</h1>"
        );
    }

    #[test]
    fn a_full_response_keeps_its_status_and_headers_but_not_framing() {
        let text = b"HTTP/1.1 302 Found\nLocation: /home\nContent-Length: 999\nServer: IIS\nConnection: x\n\nmoved";
        let f = Frame {
            keep_alive: false,
            ..F
        };
        assert_eq!(
            s(frame(text, &f)),
            "HTTP/1.1 302 Found\r\nDate: Sun, 01 Nov 2026 12:00:00 GMT\r\nLocation: /home\r\nServer: IIS\r\n\
             Content-Length: 5\r\nConnection: close\r\n\r\nmoved"
        );
    }

    #[test]
    fn crlf_heads_head_requests_and_bodyless_statuses() {
        let text = b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nbody\n\nmore";
        let out = s(frame(
            text,
            &Frame {
                head_request: true,
                ..F
            },
        ));
        assert!(
            out.contains("X-A: 1\r\n") && out.contains("Content-Length: 10\r\n"),
            "{out}"
        );
        assert!(out.ends_with("\r\n\r\n"), "HEAD has no body: {out}");
        let out = s(frame(b"HTTP/1.1 304 Not Modified\n\nignored", &F));
        assert!(
            !out.contains("Content-Length") && out.ends_with("\r\n\r\n"),
            "{out}"
        );
        let out = s(frame(b"HTTP/1.1 204 No Content", &F));
        assert!(out.starts_with("HTTP/1.1 204 No Content\r\n"), "{out}");
    }

    #[test]
    fn error_pages_look_like_nginx_and_escape_the_banner() {
        let page = s(error_page(404, Some("a<b")));
        assert!(page.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(page.contains("<center>a&lt;b</center>"));
        assert!(!s(error_page(400, None)).contains("<hr>"));
    }
}
