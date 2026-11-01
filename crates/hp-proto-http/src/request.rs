//! Reading HTTP/1.x requests off the wire, with hard caps on everything.

use hp_core::AsyncStream;
use hp_kit::Driver;
use hp_log::Record;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Longest request head (request line + headers). nginx's default is 8 KiB
/// per line with four large buffers; 16 KiB total is in the same range.
const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 100;
/// Largest decoded body kept. The session's input cap usually bites first.
pub(crate) const MAX_BODY: usize = 1 << 20;
/// Longest chunk-size or trailer line in a chunked body.
const MAX_CHUNK_LINE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub method: String,
    pub target: String,
    /// The minor version: `HTTP/1.<minor>`.
    pub minor: u8,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// The first header with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn header_has_token(&self, name: &str, token: &str) -> bool {
        self.header(name)
            .is_some_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
    }

    pub fn version(&self) -> String {
        format!("HTTP/1.{}", self.minor)
    }

    /// HTTP/1.1 keeps the connection unless told otherwise; 1.0 only if asked.
    pub fn keep_alive(&self) -> bool {
        if self.minor >= 1 {
            !self.header_has_token("connection", "close")
        } else {
            self.header_has_token("connection", "keep-alive")
        }
    }

    pub fn path(&self) -> &str {
        self.target.split_once('?').map_or(&self.target, |(p, _)| p)
    }

    pub fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }

    /// Headers as `name: value` lines with lowercased names, for tracks to
    /// match with `(?m)^user-agent: ...`.
    pub fn headers_text(&self) -> String {
        let mut out = String::new();
        for (n, v) in &self.headers {
            out.push_str(&n.to_ascii_lowercase());
            out.push_str(": ");
            out.push_str(v);
            out.push('\n');
        }
        out
    }
}

/// Why no request was produced.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// The peer went away or hit the input cap; nothing more to say.
    Closed,
    /// The input is not acceptable HTTP: answer with this status and close.
    Reject(u16),
}

/// Buffers a connection's input across requests (pipelined requests stay in
/// the buffer for the next call).
#[derive(Default)]
pub(crate) struct Reader {
    buf: Vec<u8>,
}

impl Reader {
    async fn fill(&mut self, io: &mut dyn AsyncStream, driver: &mut Driver) -> Result<(), Stop> {
        let mut chunk = [0u8; 8192];
        let n = io.read(&mut chunk).await.map_err(|_| Stop::Closed)?;
        if n == 0 || driver.receive(&chunk[..n]).is_err() {
            return Err(Stop::Closed);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    pub async fn next(
        &mut self,
        io: &mut dyn AsyncStream,
        driver: &mut Driver,
    ) -> Result<Request, Stop> {
        let (mut req, head_len) = loop {
            if let Some(parsed) = parse_head(&self.buf)? {
                break parsed;
            }
            if self.buf.len() > MAX_HEAD {
                return Err(Stop::Reject(431));
            }
            self.fill(io, driver).await?;
        };
        if head_len > MAX_HEAD {
            return Err(Stop::Reject(431));
        }

        let chunked = req
            .header("transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        let length = match (chunked, req.header("content-length")) {
            (true, _) | (false, None) => 0,
            (false, Some(v)) => v.trim().parse::<usize>().map_err(|_| Stop::Reject(400))?,
        };
        if length > MAX_BODY {
            return Err(Stop::Reject(413));
        }
        let wants_body = chunked || length > 0;
        if wants_body
            && self.buf.len() == head_len
            && req
                .header("expect")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"))
        {
            let cont = b"HTTP/1.1 100 Continue\r\n\r\n";
            driver.log().event(Record::tx(cont));
            io.write_all(cont).await.map_err(|_| Stop::Closed)?;
            io.flush().await.map_err(|_| Stop::Closed)?;
        }

        let end = if chunked {
            self.read_chunked(io, driver, head_len, &mut req.body)
                .await?
        } else {
            while self.buf.len() < head_len + length {
                self.fill(io, driver).await?;
            }
            req.body = self.buf[head_len..head_len + length].to_vec();
            head_len + length
        };
        self.buf.drain(..end);
        Ok(req)
    }

    /// The index just past the line starting at `pos` and the line itself
    /// (without CRLF/LF), reading more input as needed.
    async fn line(
        &mut self,
        io: &mut dyn AsyncStream,
        driver: &mut Driver,
        pos: usize,
    ) -> Result<(usize, String), Stop> {
        loop {
            if let Some(i) = self.buf[pos..].iter().position(|&b| b == b'\n') {
                let mut line = &self.buf[pos..pos + i];
                if line.last() == Some(&b'\r') {
                    line = &line[..line.len() - 1];
                }
                return Ok((pos + i + 1, String::from_utf8_lossy(line).into_owned()));
            }
            if self.buf.len() - pos > MAX_CHUNK_LINE {
                return Err(Stop::Reject(400));
            }
            self.fill(io, driver).await?;
        }
    }

    /// Decode a chunked body starting at `pos`; returns the end of the request.
    async fn read_chunked(
        &mut self,
        io: &mut dyn AsyncStream,
        driver: &mut Driver,
        mut pos: usize,
        body: &mut Vec<u8>,
    ) -> Result<usize, Stop> {
        loop {
            let (next, line) = self.line(io, driver, pos).await?;
            let size = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size, 16).map_err(|_| Stop::Reject(400))?;
            pos = next;
            if size == 0 {
                // Trailers, up to the empty line.
                loop {
                    let (next, line) = self.line(io, driver, pos).await?;
                    pos = next;
                    if line.is_empty() {
                        return Ok(pos);
                    }
                }
            }
            if body.len().saturating_add(size) > MAX_BODY {
                return Err(Stop::Reject(413));
            }
            while self.buf.len() < pos + size + 2 {
                self.fill(io, driver).await?;
            }
            body.extend_from_slice(&self.buf[pos..pos + size]);
            pos += size;
            match &self.buf[pos..pos + 2] {
                b"\r\n" => pos += 2,
                [b'\n', _] => pos += 1,
                _ => return Err(Stop::Reject(400)),
            }
        }
    }
}

/// Parse a complete request head from the start of `buf`, if there is one.
fn parse_head(buf: &[u8]) -> Result<Option<(Request, usize)>, Stop> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(buf) {
        Ok(httparse::Status::Partial) => Ok(None),
        Ok(httparse::Status::Complete(n)) => {
            let req = Request {
                method: parsed.method.unwrap_or("").to_string(),
                target: parsed.path.unwrap_or("").to_string(),
                minor: parsed.version.unwrap_or(1),
                headers: parsed
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).into_owned(),
                        )
                    })
                    .collect(),
                body: Vec::new(),
            };
            Ok(Some((req, n)))
        }
        Err(httparse::Error::TooManyHeaders) => Err(Stop::Reject(431)),
        Err(_) => Err(Stop::Reject(400)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(raw: &str) -> Request {
        parse_head(raw.as_bytes()).unwrap().unwrap().0
    }

    #[test]
    fn head_parsing_and_accessors() {
        let r = head("GET /a/b?x=1&y HTTP/1.0\r\nHost: h\r\nConnection: Keep-Alive\r\nUser-Agent: curl/8\r\n\r\n");
        assert_eq!(
            (r.method.as_str(), r.path(), r.query()),
            ("GET", "/a/b", "x=1&y")
        );
        assert_eq!(r.version(), "HTTP/1.0");
        assert!(r.keep_alive());
        assert_eq!(r.header("user-agent"), Some("curl/8"));
        assert_eq!(
            r.headers_text(),
            "host: h\nconnection: Keep-Alive\nuser-agent: curl/8\n"
        );
        assert!(!head("GET / HTTP/1.1\r\nConnection: close\r\n\r\n").keep_alive());
        assert!(head("GET / HTTP/1.1\r\n\r\n").keep_alive());
        assert!(!head("GET / HTTP/1.0\r\n\r\n").keep_alive());
        assert_eq!(parse_head(b"GET / HT"), Ok(None));
        assert_eq!(
            parse_head(b"\x16\x03\x01\x00").unwrap_err(),
            Stop::Reject(400)
        );
    }
}
