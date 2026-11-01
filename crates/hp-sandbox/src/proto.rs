//! The wire format between the honeypot and the broker.
//!
//! One unix-socket connection per shell. The honeypot sends one JSON line
//! ([`Request`]); the broker answers with one JSON line ([`Response`]); from
//! then on the connection *is* the shell's byte stream (what the peer types
//! goes in, what the shell prints comes out). Closing it ends the sandbox, so
//! there is no separate "destroy" call to forget.

use std::io;

use hp_core::ShellRequest;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Longest request or response line, in bytes.
pub const MAX_LINE: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub session_id: String,
    pub user: String,
    /// `Some` for a one-shot command, `None` for a login shell.
    pub command: Option<String>,
    pub terminal: Option<Terminal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Terminal {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    /// Why not. Deliberately vague: it is for the honeypot's log, and must
    /// never carry infrastructure details a peer could learn from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok() -> Response {
        Response {
            ok: true,
            error: None,
        }
    }

    pub fn refused(reason: impl Into<String>) -> Response {
        Response {
            ok: false,
            error: Some(reason.into()),
        }
    }
}

impl From<&ShellRequest> for Request {
    fn from(r: &ShellRequest) -> Request {
        Request {
            session_id: r.session_id.clone(),
            user: r.user.clone(),
            command: r.command.clone(),
            terminal: r.terminal.as_ref().map(|t| Terminal {
                term: t.term.clone(),
                cols: t.cols,
                rows: t.rows,
            }),
        }
    }
}

/// Read one line, a byte at a time. Reading ahead would swallow the first
/// bytes of the shell's output, which can arrive right behind the reply.
pub async fn read_line<R: AsyncRead + Unpin>(r: &mut R, max: usize) -> io::Result<String> {
    let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
    loop {
        if r.read(&mut byte).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        if byte[0] == b'\n' {
            return String::from_utf8(line)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }
        line.push(byte[0]);
        if line.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }
}

pub async fn read_json<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let line = read_line(r, MAX_LINE).await?;
    serde_json::from_str(&line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub async fn write_json<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    value: &T,
) -> io::Result<()> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    w.write_all(&bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_core::Terminal as CoreTerminal;

    #[tokio::test]
    async fn json_lines_round_trip_and_leave_the_stream_after_the_newline_untouched() {
        let mut wire = Vec::new();
        write_json(&mut wire, &Response::ok()).await.unwrap();
        wire.extend_from_slice(b"root@box:~# ");
        let mut r = &wire[..];
        let reply: Response = read_json(&mut r).await.unwrap();
        assert_eq!(reply, Response::ok());
        assert_eq!(
            r, b"root@box:~# ",
            "the shell's first bytes are not consumed"
        );
    }

    #[tokio::test]
    async fn bad_input_is_an_error_not_a_hang() {
        assert!(read_line(&mut &b"no newline"[..], 64).await.is_err());
        assert!(read_line(&mut &b"too long\n"[..], 3).await.is_err());
        assert!(
            read_line(&mut &b"\xff\xfe\n"[..], 64).await.is_err(),
            "not UTF-8"
        );
        assert!(read_json::<_, Response>(&mut &b"{not json}\n"[..])
            .await
            .is_err());
        assert!(
            read_json::<_, Response>(&mut &b"{\"ok\":true,\"extra\":1}\n"[..])
                .await
                .is_ok(),
            "unknown fields are ignored"
        );
    }

    #[test]
    fn refusals_carry_a_reason_and_acceptance_does_not() {
        assert_eq!(
            serde_json::to_string(&Response::ok()).unwrap(),
            r#"{"ok":true}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::refused("busy")).unwrap(),
            r#"{"ok":false,"error":"busy"}"#
        );
    }

    #[test]
    fn a_shell_request_converts_field_for_field() {
        let r = ShellRequest {
            session_id: "s".into(),
            user: "root".into(),
            command: Some("id".into()),
            terminal: Some(CoreTerminal {
                term: "xterm".into(),
                cols: 80,
                rows: 24,
            }),
        };
        let wire = Request::from(&r);
        assert_eq!(
            (wire.user.as_str(), wire.command.as_deref()),
            ("root", Some("id"))
        );
        assert_eq!(
            wire.terminal,
            Some(Terminal {
                term: "xterm".into(),
                cols: 80,
                rows: 24
            })
        );
    }
}
