//! Raw TCP plugin: sends the persona banner, then logs every byte received
//! and lets the session's behavior answer.
//!
//! This is the smallest possible protocol, and the reference for the pattern:
//! the plugin owns the wire (here an unframed byte stream), reports what
//! arrives as `Event`s through the kit's `Driver`, and carries out the
//! reply with the kit's `apply`. Actions that make no sense on a raw stream
//! (`AuthResult`, `Prompt`) are ignored by `apply`.

use async_trait::async_trait;
use bytes::Bytes;
use hp_core::{Action, AsyncStream, Event, Protocol, SessionCtx};
use hp_kit::{apply, Driver, Flow, StreamOut};
use tokio::io::AsyncReadExt;

pub struct Banner;

#[async_trait]
impl Protocol for Banner {
    fn name(&self) -> &'static str {
        "banner"
    }

    fn default_ports(&self) -> &[u16] {
        &[2323]
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

async fn converse(
    stream: &mut dyn AsyncStream,
    driver: &mut Driver,
    banner: Option<&str>,
) -> anyhow::Result<()> {
    let mut out = StreamOut(stream);
    if let Some(b) = banner {
        let line = Action::Send(Bytes::from(format!("{b}\r\n")));
        apply(&mut out, driver.log(), vec![line], false).await?;
    }
    let reply = driver.connect().into_actions();
    if apply(&mut out, driver.log(), reply, false).await?.flow == Flow::Close {
        return Ok(());
    }

    let mut buf = [0u8; 4096];
    loop {
        let n = out.0.read(&mut buf).await?;
        if n == 0 || driver.receive(&buf[..n]).is_err() {
            return Ok(());
        }
        let reply = driver
            .react(&Event::Raw(Bytes::copy_from_slice(&buf[..n])))
            .into_actions();
        if apply(&mut out, driver.log(), reply, false).await?.flow == Flow::Close {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_testkit::{conformance, kinds, send, session, CtxOptions, Observer, Script};
    use serde_json::Value;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    type Peer = tokio::task::JoinHandle<Vec<u8>>;

    struct Outcome {
        received: Vec<u8>,
        records: Vec<Value>,
        obs: Observer,
    }

    /// Run the plugin against an in-memory peer.
    async fn run(
        banner: Option<&'static str>,
        max_input_bytes: u64,
        script: Script,
        peer: impl FnOnce(tokio::io::DuplexStream) -> Peer,
    ) -> Outcome {
        let (ctx, mut obs) = session(CtxOptions {
            script,
            banner,
            max_input_bytes,
            ..Default::default()
        });
        let (server, client) = tokio::io::duplex(8192);
        let client = peer(client);
        Banner
            .handle(Box::new(server), ctx)
            .await
            .expect("session ends cleanly");
        let received = client.await.unwrap();
        let records = obs.records();
        Outcome {
            received,
            records,
            obs,
        }
    }

    /// Peer that writes `data`, half-closes, and returns everything it receives.
    fn writes_then_closes(data: &'static [u8]) -> impl FnOnce(tokio::io::DuplexStream) -> Peer {
        move |mut c| {
            tokio::spawn(async move {
                c.write_all(data).await.unwrap();
                c.shutdown().await.unwrap();
                let mut got = vec![];
                c.read_to_end(&mut got).await.unwrap();
                got
            })
        }
    }

    #[test]
    fn metadata() {
        assert_eq!(Banner.name(), "banner");
        assert_eq!(Banner.default_ports(), [2323]);
    }

    #[tokio::test]
    async fn sends_banner_and_logs_both_directions() {
        let o = run(
            Some("HELLO"),
            1024,
            |_| vec![],
            writes_then_closes(b"root\x00\n"),
        )
        .await;
        assert_eq!(o.received, b"HELLO\r\n");
        assert_eq!(kinds(&o.records), ["tx", "rx"]);
        assert_eq!(o.records[1]["hex"], "726f6f74000a");
        assert_eq!(o.records[1]["text"], "root..");
        conformance::envelope(&o.records);
    }

    #[tokio::test]
    async fn no_banner_means_no_tx() {
        let o = run(None, 1024, |_| vec![], writes_then_closes(b"x")).await;
        assert!(o.received.is_empty());
        assert_eq!(kinds(&o.records), ["rx"]);
    }

    #[tokio::test]
    async fn stops_reading_past_input_limit() {
        let o = run(None, 4, |_| vec![], writes_then_closes(b"0123456789")).await;
        conformance::input_cap_enforced(&o.records, 4);
    }

    #[tokio::test]
    async fn behavior_sees_the_session_lifecycle_in_order() {
        let o = run(None, 1024, |_| vec![], writes_then_closes(b"hi")).await;
        conformance::lifecycle(&o.obs.seen);
        assert_eq!(o.obs.seen.all(), ["Connected", "raw:hi", "Disconnected"]);
    }

    #[tokio::test]
    async fn close_on_connect_skips_reading_but_still_ends_the_lifecycle() {
        let reads_only = |mut c: tokio::io::DuplexStream| -> Peer {
            tokio::spawn(async move {
                let mut got = vec![];
                c.read_to_end(&mut got).await.unwrap();
                got
            })
        };
        let o = run(
            None,
            1024,
            |e| {
                if matches!(e, Event::Connected) {
                    vec![Action::Close]
                } else {
                    vec![]
                }
            },
            reads_only,
        )
        .await;
        assert!(o.records.is_empty());
        conformance::lifecycle(&o.obs.seen);
        assert_eq!(o.obs.seen.all(), ["Connected", "Disconnected"]);
    }

    #[tokio::test]
    async fn close_after_a_reply_ends_the_session() {
        let o = run(
            None,
            1024,
            |e| {
                if matches!(e, Event::Raw(_)) {
                    vec![send("bye"), Action::Close]
                } else {
                    vec![]
                }
            },
            writes_then_closes(b"quit"),
        )
        .await;
        assert_eq!(o.received, b"bye");
        conformance::lifecycle(&o.obs.seen);
    }

    #[tokio::test]
    async fn actions_are_carried_out_and_logged_in_order() {
        let o = run(
            Some("B"),
            1024,
            |e| match e {
                Event::Connected => vec![send("welcome\r\n")],
                Event::Raw(_) => vec![
                    Action::AuthResult(true),    // meaningless on a raw stream: ignored
                    Action::Prompt("> ".into()), // likewise
                    Action::Delay(Duration::from_millis(5)),
                    send("pong\r\n"),
                ],
                _ => vec![],
            },
            writes_then_closes(b"ping"),
        )
        .await;
        assert_eq!(o.received, b"B\r\nwelcome\r\npong\r\n");
        assert_eq!(kinds(&o.records), ["tx", "tx", "rx", "tx"]);
    }
}
