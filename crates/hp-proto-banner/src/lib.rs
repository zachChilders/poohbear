//! Raw TCP plugin: sends the persona banner, then logs every byte received
//! and lets the session's [`Behavior`] answer.
//!
//! This plugin owns the wire (here: an unframed byte stream). It reports what
//! arrives as `Event`s and carries out the `Action`s it gets back; it knows
//! nothing about how those actions are chosen. Actions that make no sense on a
//! raw stream (`AuthResult`) are ignored.

use async_trait::async_trait;
use bytes::Bytes;
use hp_core::{Action, AsyncStream, Event, Protocol, SessionCtx};
use hp_log::{Limit, Record, SessionLogger};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        mut ctx: SessionCtx,
    ) -> anyhow::Result<()> {
        let result = converse(stream.as_mut(), &mut ctx).await;
        // Let the behavior see the end of the session (e.g. to tag it).
        // Nothing can be delivered any more, so its actions are dropped.
        ctx.behavior.react(&Event::Disconnected);
        result
    }
}

async fn converse(stream: &mut dyn AsyncStream, ctx: &mut SessionCtx) -> anyhow::Result<()> {
    if let Some(b) = &ctx.persona.banner {
        send(stream, &ctx.log, format!("{b}\r\n").as_bytes()).await?;
    }
    let actions = ctx.behavior.react(&Event::Connected);
    if !apply(stream, &ctx.log, actions).await? {
        return Ok(());
    }

    let mut total: u64 = 0;
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        total += n as u64;
        if total > ctx.limits.max_input_bytes {
            ctx.log.event(Record::LimitExceeded {
                limit: Limit::MaxInputBytes,
                total,
            });
            return Ok(());
        }
        ctx.log.event(Record::rx(&buf[..n]));
        let actions = ctx
            .behavior
            .react(&Event::Raw(Bytes::copy_from_slice(&buf[..n])));
        if !apply(stream, &ctx.log, actions).await? {
            return Ok(());
        }
    }
}

async fn send(
    stream: &mut dyn AsyncStream,
    log: &SessionLogger,
    data: &[u8],
) -> anyhow::Result<()> {
    stream.write_all(data).await?;
    log.event(Record::tx(data));
    Ok(())
}

/// Carry out actions in order. Returns false if the session should end.
async fn apply(
    stream: &mut dyn AsyncStream,
    log: &SessionLogger,
    actions: Vec<Action>,
) -> anyhow::Result<bool> {
    for action in actions {
        match action {
            Action::Send(data) => send(stream, log, &data).await?,
            Action::Delay(d) => tokio::time::sleep(d).await,
            Action::Close => return Ok(false),
            Action::AuthResult(_) => {}
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_core::{Behavior, Limits, Passive, Persona};
    use hp_log::LogSink;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    type Peer = tokio::task::JoinHandle<Vec<u8>>;

    /// Records every event it sees and replies from a fixed script.
    struct Scripted {
        seen: Arc<Mutex<Vec<String>>>,
        reply: fn(&Event) -> Vec<Action>,
    }
    impl Behavior for Scripted {
        fn react(&mut self, event: &Event) -> Vec<Action> {
            let label = match event {
                Event::Raw(b) => format!("raw:{}", String::from_utf8_lossy(b)),
                other => format!("{other:?}"),
            };
            self.seen.lock().unwrap().push(label);
            (self.reply)(event)
        }
    }

    struct Outcome {
        received: Vec<u8>,
        records: Vec<Value>,
        result: anyhow::Result<()>,
    }

    /// Run the plugin against an in-memory peer.
    async fn run(
        banner: Option<&str>,
        max_input_bytes: u64,
        behavior: Box<dyn Behavior>,
        peer: impl FnOnce(tokio::io::DuplexStream) -> Peer,
    ) -> Outcome {
        let (sink, mut rx) = LogSink::channel(64);
        let ctx = SessionCtx {
            session_id: "s".into(),
            peer: "127.0.0.1:9".parse().unwrap(),
            log: sink.session("s", "127.0.0.1:9".parse().unwrap(), "banner"),
            persona: Persona {
                hostname: None,
                banner: banner.map(String::from),
            },
            limits: Limits {
                session_timeout: Duration::from_secs(5),
                max_input_bytes,
            },
            behavior,
        };
        let (server, client) = tokio::io::duplex(8192);
        let client = peer(client);
        let result = Banner.handle(Box::new(server), ctx).await;
        let received = client.await.unwrap();
        let mut records = vec![];
        while let Ok(line) = rx.try_recv() {
            records.push(serde_json::from_str(&line).unwrap());
        }
        Outcome {
            received,
            records,
            result,
        }
    }

    fn kinds(o: &Outcome) -> Vec<&str> {
        o.records
            .iter()
            .map(|r| r["kind"].as_str().unwrap())
            .collect()
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

    fn scripted(reply: fn(&Event) -> Vec<Action>) -> (Box<dyn Behavior>, Arc<Mutex<Vec<String>>>) {
        let seen = Arc::new(Mutex::new(vec![]));
        (
            Box::new(Scripted {
                seen: seen.clone(),
                reply,
            }),
            seen,
        )
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
            Box::new(Passive),
            writes_then_closes(b"root\x00\n"),
        )
        .await;
        assert!(o.result.is_ok());
        assert_eq!(o.received, b"HELLO\r\n");
        assert_eq!(kinds(&o), ["tx", "rx"]);
        assert_eq!(o.records[1]["hex"], "726f6f74000a");
        assert_eq!(o.records[1]["text"], "root..");
    }

    #[tokio::test]
    async fn no_banner_means_no_tx() {
        let o = run(None, 1024, Box::new(Passive), writes_then_closes(b"x")).await;
        assert!(o.received.is_empty());
        assert_eq!(kinds(&o), ["rx"]);
    }

    #[tokio::test]
    async fn stops_reading_past_input_limit() {
        let o = run(
            None,
            4,
            Box::new(Passive),
            writes_then_closes(b"0123456789"),
        )
        .await;
        let last = o.records.last().unwrap();
        assert_eq!(last["kind"], "limit_exceeded");
        assert_eq!(last["limit"], "max_input_bytes");
        assert!(
            !kinds(&o).contains(&"rx"),
            "over-limit chunk must not be logged as rx"
        );
    }

    #[tokio::test]
    async fn behavior_sees_the_session_lifecycle_in_order() {
        let (b, seen) = scripted(|_| vec![]);
        run(None, 1024, b, writes_then_closes(b"hi")).await;
        assert_eq!(
            *seen.lock().unwrap(),
            ["Connected", "raw:hi", "Disconnected"]
        );
    }

    #[tokio::test]
    async fn actions_are_carried_out_and_logged_in_order() {
        let (b, _) = scripted(|e| match e {
            Event::Connected => vec![Action::Send(Bytes::from_static(b"welcome\r\n"))],
            Event::Raw(_) => vec![
                Action::AuthResult(true), // meaningless on a raw stream: ignored
                Action::Delay(Duration::from_millis(5)),
                Action::Send(Bytes::from_static(b"pong\r\n")),
            ],
            _ => vec![],
        });
        let o = run(Some("B"), 1024, b, writes_then_closes(b"ping")).await;
        assert_eq!(o.received, b"B\r\nwelcome\r\npong\r\n");
        assert_eq!(kinds(&o), ["tx", "tx", "rx", "tx"]);
    }

    #[tokio::test]
    async fn close_action_ends_the_session_and_still_notifies_disconnect() {
        let (b, seen) = scripted(|e| match e {
            Event::Raw(_) => vec![Action::Send(Bytes::from_static(b"bye")), Action::Close],
            _ => vec![],
        });
        let o = run(None, 1024, b, writes_then_closes(b"quit")).await;
        assert_eq!(o.received, b"bye");
        assert_eq!(
            *seen.lock().unwrap(),
            ["Connected", "raw:quit", "Disconnected"]
        );
    }

    #[tokio::test]
    async fn close_on_connect_skips_reading() {
        let (b, seen) = scripted(|e| match e {
            Event::Connected => vec![Action::Close],
            _ => vec![],
        });
        let reads_only = |mut c: tokio::io::DuplexStream| -> Peer {
            tokio::spawn(async move {
                let mut got = vec![];
                c.read_to_end(&mut got).await.unwrap();
                got
            })
        };
        let o = run(None, 1024, b, reads_only).await;
        assert!(kinds(&o).is_empty());
        assert_eq!(*seen.lock().unwrap(), ["Connected", "Disconnected"]);
    }
}
