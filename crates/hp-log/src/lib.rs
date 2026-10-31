//! Structured logging: process logs via `tracing`, session records as JSONL.
//!
//! Captured input is hostile. Raw bytes are never written verbatim: they are
//! logged as hex plus a printable-ASCII rendering (everything else `.`), and
//! all strings pass through serde_json escaping, so attacker data cannot
//! inject extra log lines or fields.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

/// Records buffered between sessions and the writer task.
const QUEUE_CAPACITY: usize = 8192;

pub fn init_tracing() {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}

/// Shared sink. Sessions push complete JSONL lines into a bounded queue that
/// one writer task drains, so they never block on disk I/O and a flood cannot
/// grow memory without limit: when the queue is full, records are dropped
/// and counted.
#[derive(Clone)]
pub struct LogSink {
    tx: mpsc::Sender<String>,
    dropped: Arc<AtomicU64>,
}

impl LogSink {
    /// A sink plus the receiving end of its queue (each item is one line,
    /// newline included). `open` builds on this; tests read from it directly.
    pub fn channel(capacity: usize) -> (LogSink, mpsc::Receiver<String>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            LogSink {
                tx,
                dropped: Arc::default(),
            },
            rx,
        )
    }

    /// Append JSONL records to `path` (None = stdout).
    pub async fn open(path: Option<&Path>) -> anyhow::Result<LogSink> {
        let mut out: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = match path {
            Some(p) => {
                if let Some(dir) = p.parent() {
                    tokio::fs::create_dir_all(dir).await?;
                }
                Box::new(
                    tokio::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)
                        .await?,
                )
            }
            None => Box::new(tokio::io::stdout()),
        };
        let (sink, mut rx) = LogSink::channel(QUEUE_CAPACITY);
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if out.write_all(line.as_bytes()).await.is_err() || out.flush().await.is_err() {
                    tracing::error!("session log write failed");
                }
            }
        });
        Ok(sink)
    }

    pub fn session(&self, session_id: &str, peer: SocketAddr, protocol: &str) -> SessionLogger {
        SessionLogger {
            inner: Arc::new(Inner {
                sink: self.clone(),
                session_id: session_id.into(),
                peer: peer.to_string(),
                protocol: protocol.into(),
            }),
        }
    }

    /// Records lost because the queue was full or the writer had stopped.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn emit(&self, mut line: String) {
        line.push('\n');
        if self.tx.try_send(line).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n.is_power_of_two() {
                tracing::warn!(
                    dropped = n,
                    "session log queue full or closed; dropping records"
                );
            }
        }
    }
}

struct Inner {
    sink: LogSink,
    session_id: String,
    peer: String,
    protocol: String,
}

#[derive(Clone)]
pub struct SessionLogger {
    inner: Arc<Inner>,
}

impl SessionLogger {
    /// Emit one record: `kind` plus extra structured fields. Extra fields
    /// can never override the standard ones (`ts_ms`, `session`, `peer`,
    /// `protocol`, `kind`).
    pub fn record(&self, kind: &str, fields: Value) {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let mut rec = json!({
            "ts_ms": ts,
            "session": self.inner.session_id,
            "peer": self.inner.peer,
            "protocol": self.inner.protocol,
            "kind": kind,
        });
        if let (Some(obj), Value::Object(extra)) = (rec.as_object_mut(), fields) {
            for (k, v) in extra {
                obj.entry(k).or_insert(v);
            }
        }
        self.inner.sink.emit(rec.to_string());
    }

    /// A record with no extra fields.
    pub fn event(&self, kind: &str) {
        self.record(kind, json!({}));
    }

    /// Log bytes received from (`"rx"`) or sent to (`"tx"`) the peer.
    pub fn bytes(&self, dir: &str, data: &[u8]) {
        self.record(
            dir,
            json!({ "len": data.len(), "hex": hex(data), "text": printable(data) }),
        );
    }
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn printable(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger(cap: usize) -> (LogSink, SessionLogger, mpsc::Receiver<String>) {
        let (sink, rx) = LogSink::channel(cap);
        let log = sink.session("s1", "127.0.0.1:9".parse().unwrap(), "test");
        (sink, log, rx)
    }

    #[test]
    fn printable_neutralises_control_bytes() {
        assert_eq!(printable(b"a\r\n\x1b[0mb"), "a...[0mb");
    }

    #[test]
    fn hex_encodes() {
        assert_eq!(hex(&[0, 255, 16]), "00ff10");
    }

    #[test]
    fn records_are_single_json_lines_with_standard_fields() {
        let (_s, log, mut rx) = logger(8);
        log.bytes("rx", b"hi\n");
        let line = rx.try_recv().unwrap();
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["kind"], "rx");
        assert_eq!(v["session"], "s1");
        assert_eq!(v["peer"], "127.0.0.1:9");
        assert_eq!(v["protocol"], "test");
        assert_eq!(
            (v["len"].as_u64(), v["hex"].as_str(), v["text"].as_str()),
            (Some(3), Some("68690a"), Some("hi."))
        );
    }

    #[test]
    fn hostile_input_cannot_inject_lines_or_override_fields() {
        let (_s, log, mut rx) = logger(8);
        log.record(
            "cmd",
            json!({ "kind": "forged", "session": "forged", "data": "a\n{\"kind\":\"forged\"}\r\n" }),
        );
        let line = rx.try_recv().unwrap();
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            (v["kind"].as_str(), v["session"].as_str()),
            (Some("cmd"), Some("s1"))
        );
        assert!(v["data"].as_str().unwrap().contains('\n'));
    }

    #[test]
    fn full_queue_drops_and_counts_instead_of_growing() {
        let (sink, log, mut rx) = logger(2);
        for _ in 0..5 {
            log.event("x");
        }
        assert_eq!(sink.dropped(), 3);
        assert!(rx.try_recv().is_ok() && rx.try_recv().is_ok() && rx.try_recv().is_err());
    }

    #[test]
    fn closed_queue_counts_drops() {
        let (sink, log, rx) = logger(2);
        drop(rx);
        log.event("x");
        assert_eq!(sink.dropped(), 1);
    }

    #[tokio::test]
    async fn open_appends_lines_to_file() {
        let dir = std::env::temp_dir().join(format!("hp-log-test-{}", std::process::id()));
        let path = dir.join("nested/sessions.jsonl");
        let sink = LogSink::open(Some(&path)).await.unwrap();
        let log = sink.session("s", "127.0.0.1:9".parse().unwrap(), "t");
        log.event("a");
        log.event("b");
        for _ in 0..50 {
            if std::fs::read_to_string(&path).map_or(0, |t| t.lines().count()) == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let kinds: Vec<_> = text
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["kind"].clone())
            .collect();
        assert_eq!(kinds, ["a", "b"]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
