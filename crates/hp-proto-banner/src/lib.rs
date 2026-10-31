//! Raw TCP "banner + log" plugin: send the persona banner, then log every byte.

use async_trait::async_trait;
use hp_core::{AsyncStream, Protocol, SessionCtx};
use hp_log::{Limit, Record};
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
        ctx: SessionCtx,
    ) -> anyhow::Result<()> {
        if let Some(b) = &ctx.persona.banner {
            let out = format!("{b}\r\n");
            stream.write_all(out.as_bytes()).await?;
            ctx.log.event(Record::tx(out.as_bytes()));
        }
        let mut total: u64 = 0;
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > ctx.limits.max_input_bytes {
                ctx.log.event(Record::LimitExceeded {
                    limit: Limit::MaxInputBytes,
                    total,
                });
                break;
            }
            ctx.log.event(Record::rx(&buf[..n]));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_core::{Limits, Persona};
    use hp_log::LogSink;
    use serde_json::Value;
    use std::time::Duration;

    /// Run the plugin against an in-memory peer; returns (peer end, records).
    async fn run(
        banner: Option<&str>,
        max_input_bytes: u64,
        peer: impl FnOnce(tokio::io::DuplexStream) -> tokio::task::JoinHandle<Vec<u8>>,
    ) -> (Vec<u8>, Vec<Value>) {
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
        };
        let (server, client) = tokio::io::duplex(8192);
        let client = peer(client);
        Banner.handle(Box::new(server), ctx).await.unwrap();
        let received = client.await.unwrap();
        let mut records = vec![];
        while let Ok(line) = rx.try_recv() {
            records.push(serde_json::from_str(&line).unwrap());
        }
        (received, records)
    }

    fn writes_then_closes(
        data: &'static [u8],
    ) -> impl FnOnce(tokio::io::DuplexStream) -> tokio::task::JoinHandle<Vec<u8>> {
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
        let (got, recs) = run(Some("HELLO"), 1024, writes_then_closes(b"root\x00\n")).await;
        assert_eq!(got, b"HELLO\r\n");
        let kinds: Vec<_> = recs.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["tx", "rx"]);
        assert_eq!(recs[1]["hex"], "726f6f74000a");
        assert_eq!(recs[1]["text"], "root..");
    }

    #[tokio::test]
    async fn no_banner_means_no_tx() {
        let (got, recs) = run(None, 1024, writes_then_closes(b"x")).await;
        assert!(got.is_empty());
        assert_eq!(recs.len(), 1);
    }

    #[tokio::test]
    async fn stops_reading_past_input_limit() {
        let (_, recs) = run(None, 4, writes_then_closes(b"0123456789")).await;
        let last = recs.last().unwrap();
        assert_eq!(last["kind"], "limit_exceeded");
        assert_eq!(last["limit"], "max_input_bytes");
        assert!(
            recs.iter().all(|r| r["kind"] != "rx"),
            "over-limit chunk must not be logged as rx"
        );
    }
}
