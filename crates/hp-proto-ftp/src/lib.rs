//! FTP control-channel plugin.
//!
//! The plugin owns the wire format: CRLF-terminated command lines, split into
//! a verb and an argument. What it reports to the behavior:
//!
//! - `USER <name>`  -> `Event::Command("USER <name>")` (the track sends the
//!   `331`), and the name is remembered;
//! - `PASS <pw>`    -> `Event::AuthAttempt` with the remembered name. Whatever
//!   `send` text the track returns is the reply (`230 ...` or `530 ...`),
//!   whether or not `auth` was granted;
//! - anything else  -> `Event::Command(line)`.
//!
//! Only the control connection is served. There are no data connections, so
//! the track should answer `PASV`/`PORT`/`LIST`/`STOR`... itself (typically
//! with `425`/`502`) and tag the interesting ones.

use async_trait::async_trait;
use bytes::Bytes;
use hp_core::{Action, AsyncStream, Event, Protocol, Secret, SessionCtx};
use hp_kit::{apply, Driver, Flow, StreamOut};
use hp_log::{AuthMethod, Record};
use tokio::io::AsyncReadExt;

/// Longest command line kept; a real server also caps this (RFC 959 leaves it
/// open, vsftpd uses 4096). Longer lines are truncated, not rejected.
const MAX_LINE: usize = 4096;

pub struct Ftp;

#[async_trait]
impl Protocol for Ftp {
    fn name(&self) -> &'static str {
        "ftp"
    }

    fn default_ports(&self) -> &[u16] {
        &[21, 2121]
    }

    async fn handle(
        &self,
        mut stream: Box<dyn AsyncStream>,
        ctx: SessionCtx,
    ) -> anyhow::Result<()> {
        let mut driver = Driver::new(ctx.log, ctx.behavior, &ctx.limits);
        converse(stream.as_mut(), &mut driver, ctx.persona.banner.as_deref()).await
    }
}

/// Splits a byte stream into lines. Accepts CRLF or bare LF (clients and
/// scanners send both) and tolerates telnet IAC noise by leaving it in place
/// for the track to see.
#[derive(Default)]
struct Lines {
    buf: Vec<u8>,
}

impl Lines {
    fn feed(&mut self, data: &[u8]) -> Vec<String> {
        let mut out = vec![];
        for &b in data {
            if b == b'\n' {
                if self.buf.last() == Some(&b'\r') {
                    self.buf.pop();
                }
                out.push(String::from_utf8_lossy(&self.buf).into_owned());
                self.buf.clear();
            } else if self.buf.len() < MAX_LINE {
                self.buf.push(b);
            }
        }
        out
    }
}

async fn converse(
    stream: &mut dyn AsyncStream,
    driver: &mut Driver,
    banner: Option<&str>,
) -> anyhow::Result<()> {
    let mut out = StreamOut(stream);
    let mut lines = Lines::default();
    let mut user = String::new();

    // Greeting: the track may send its own on `connected`; the persona banner
    // is the fallback so a track-less run still looks like an FTP server.
    let reply = driver.connect().into_actions();
    let reply = if reply.is_empty() {
        let text = banner.unwrap_or("FTP server ready.");
        vec![Action::Send(Bytes::from(format!("220 {text}\r\n")))]
    } else {
        reply
    };
    if apply(&mut out, driver.log(), reply, false).await?.flow == Flow::Close {
        return Ok(());
    }

    let mut buf = [0u8; 4096];
    loop {
        let n = out.0.read(&mut buf).await?;
        if n == 0 || driver.receive(&buf[..n]).is_err() {
            return Ok(());
        }
        for line in lines.feed(&buf[..n]) {
            let (verb, arg) = split(&line);
            let actions = match verb.to_ascii_uppercase().as_str() {
                "PASS" => {
                    let event = Event::AuthAttempt {
                        user: user.clone(),
                        secret: Secret::new(arg),
                    };
                    let verdict = driver.react(&event).verdict();
                    // Log before any delay so the guess survives a hangup.
                    driver.log().event(Record::Auth {
                        user: user.clone(),
                        method: AuthMethod::Password,
                        credential: arg.into(),
                        accepted: verdict.granted(),
                    });
                    let text = if !verdict.welcome.is_empty() {
                        verdict.welcome
                    } else if verdict.granted() {
                        b"230 Login successful.\r\n".to_vec()
                    } else {
                        b"530 Login incorrect.\r\n".to_vec()
                    };
                    let mut a = vec![Action::Delay(verdict.delay), Action::Send(text.into())];
                    if verdict.close {
                        a.push(Action::Close);
                    }
                    a
                }
                v => {
                    if v == "USER" {
                        user = arg.to_string();
                    }
                    driver
                        .react(&Event::Command(line.trim_end().to_string()))
                        .into_actions()
                }
            };
            if apply(&mut out, driver.log(), actions, false).await?.flow == Flow::Close {
                return Ok(());
            }
        }
    }
}

/// `"USER  bob"` -> `("USER", "bob")`. The argument keeps interior spaces
/// (passwords may contain them) but loses the single separating space run.
fn split(line: &str) -> (&str, &str) {
    let line = line.trim_start();
    match line.split_once(' ') {
        Some((v, a)) => (v, a.trim_start_matches(' ')),
        None => (line, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_testkit::{conformance, kinds, send, session, CtxOptions, Observer, Script};
    use serde_json::Value;
    use tokio::io::AsyncWriteExt;

    async fn run(
        banner: Option<&'static str>,
        script: Script,
        input: &'static [u8],
    ) -> (Vec<u8>, Vec<Value>, Observer) {
        let (ctx, mut obs) = session(CtxOptions {
            script,
            banner,
            max_input_bytes: 4096,
            ..Default::default()
        });
        let (server, mut client) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            client.write_all(input).await.unwrap();
            client.shutdown().await.unwrap();
            let mut got = vec![];
            client.read_to_end(&mut got).await.unwrap();
            got
        });
        Ftp.handle(Box::new(server), ctx).await.unwrap();
        let got = peer.await.unwrap();
        let records = obs.records();
        (got, records, obs)
    }

    #[test]
    fn metadata() {
        assert_eq!(Ftp.name(), "ftp");
        assert_eq!(Ftp.default_ports(), [21, 2121]);
    }

    #[test]
    fn line_splitting_handles_crlf_lf_and_fragments() {
        let mut l = Lines::default();
        assert_eq!(l.feed(b"USER a\r\nPA"), ["USER a"]);
        assert_eq!(l.feed(b"SS b\nQUIT\r\n"), ["PASS b", "QUIT"]);
        assert_eq!(l.feed(&vec![b'x'; MAX_LINE + 50]), Vec::<String>::new());
        assert_eq!(l.feed(b"\n")[0].len(), MAX_LINE);
        assert_eq!(split("USER  bob smith"), ("USER", "bob smith"));
        assert_eq!(split("QUIT"), ("QUIT", ""));
    }

    #[tokio::test]
    async fn greets_with_the_persona_banner_when_the_track_is_silent() {
        let (got, recs, obs) = run(Some("plc-gw-03 FTP"), |_| vec![], b"").await;
        assert_eq!(got, b"220 plc-gw-03 FTP\r\n");
        conformance::envelope(&recs);
        conformance::lifecycle(&obs.seen);
    }

    #[tokio::test]
    async fn the_tracks_greeting_wins_over_the_persona() {
        let (got, _, _) = run(
            Some("ignored"),
            |e| match e {
                Event::Connected => vec![send("220 (vsFTPd 3.0.5)\r\n")],
                _ => vec![],
            },
            b"",
        )
        .await;
        assert_eq!(got, b"220 (vsFTPd 3.0.5)\r\n");
    }

    #[tokio::test]
    async fn user_then_pass_becomes_a_logged_auth_attempt() {
        let (got, recs, obs) = run(
            None,
            |e| match e {
                Event::Command(c) if c.starts_with("USER") => {
                    vec![send("331 Password required.\r\n")]
                }
                Event::AuthAttempt { user, secret }
                    if user == "admin" && secret.expose() == "pw 1" =>
                {
                    vec![Action::AuthResult(true), send("230 Logged in.\r\n")]
                }
                Event::AuthAttempt { .. } => vec![Action::AuthResult(false)],
                _ => vec![],
            },
            b"USER admin\r\nPASS pw 1\r\nPASS other\r\n",
        )
        .await;
        assert_eq!(
            got,
            b"220 FTP server ready.\r\n331 Password required.\r\n230 Logged in.\r\n530 Login incorrect.\r\n"
        );
        let auth: Vec<_> = recs.iter().filter(|r| r["kind"] == "auth").collect();
        assert_eq!(auth.len(), 2);
        assert_eq!(auth[0]["credential"], "pw 1");
        assert_eq!(auth[0]["accepted"], true);
        assert_eq!(auth[1]["accepted"], false);
        assert!(kinds(&recs).contains(&"auth"));
        assert_eq!(obs.seen.all()[1], "cmd:USER admin");
    }

    #[tokio::test]
    async fn other_commands_reach_the_behavior_and_close_ends_the_session() {
        let (got, _, _) = run(
            None,
            |e| match e {
                Event::Command(c) if c == "QUIT" => vec![send("221 Goodbye.\r\n"), Action::Close],
                Event::Command(_) => vec![send("500 ?\r\n")],
                _ => vec![],
            },
            b"syst\r\nQUIT\r\nSYST\r\n",
        )
        .await;
        assert_eq!(got, b"220 FTP server ready.\r\n500 ?\r\n221 Goodbye.\r\n");
    }

    #[tokio::test]
    async fn input_cap_is_enforced() {
        let (ctx, mut obs) = session(CtxOptions {
            max_input_bytes: 4,
            ..Default::default()
        });
        let (server, mut client) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            client.write_all(b"0123456789\r\n").await.unwrap();
            client.shutdown().await.unwrap();
            let mut v = vec![];
            let _ = client.read_to_end(&mut v).await;
        });
        Ftp.handle(Box::new(server), ctx).await.unwrap();
        conformance::input_cap_enforced(&obs.records(), 4);
    }
}
