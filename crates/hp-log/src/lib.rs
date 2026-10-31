//! Structured logging: process logs via `tracing`, session records as JSONL.
//!
//! Captured input is hostile. Raw bytes are never written verbatim: they are
//! logged as hex plus a printable-ASCII rendering (everything else `.`), and
//! all strings pass through serde_json escaping, so attacker data cannot
//! inject extra log lines or fields.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt().json().with_env_filter(filter).init();
}

/// Shared sink. Records are sent over a channel to one writer task, so
/// sessions never block each other on disk I/O.
#[derive(Clone)]
pub struct LogSink {
    tx: mpsc::UnboundedSender<String>,
}

impl LogSink {
    /// Append JSONL records to `path` (None = stdout).
    pub async fn open(path: Option<&Path>) -> anyhow::Result<LogSink> {
        let mut out: Box<dyn tokio::io::AsyncWrite + Unpin + Send> = match path {
            Some(p) => {
                if let Some(dir) = p.parent() { tokio::fs::create_dir_all(dir).await?; }
                Box::new(tokio::fs::OpenOptions::new().create(true).append(true).open(p).await?)
            }
            None => Box::new(tokio::io::stdout()),
        };
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if out.write_all(line.as_bytes()).await.is_err() || out.write_all(b"\n").await.is_err() {
                    tracing::error!("session log write failed");
                }
                let _ = out.flush().await;
            }
        });
        Ok(LogSink { tx })
    }

    pub fn session(&self, session_id: &str, peer: std::net::SocketAddr, protocol: &str) -> SessionLogger {
        SessionLogger { inner: Arc::new(Inner { sink: self.clone(), session_id: session_id.into(), peer: peer.to_string(), protocol: protocol.into() }) }
    }
}

struct Inner { sink: LogSink, session_id: String, peer: String, protocol: String }

#[derive(Clone)]
pub struct SessionLogger { inner: Arc<Inner> }

impl SessionLogger {
    /// Emit one record: `kind` plus arbitrary structured fields.
    pub fn record(&self, kind: &str, fields: Value) {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let mut rec = json!({
            "ts_ms": ts,
            "session": self.inner.session_id,
            "peer": self.inner.peer,
            "protocol": self.inner.protocol,
            "kind": kind,
        });
        if let (Some(obj), Value::Object(extra)) = (rec.as_object_mut(), fields) {
            for (k, v) in extra { obj.entry(k).or_insert(v); }
        }
        let _ = self.inner.sink.tx.send(rec.to_string());
    }

    /// Log bytes received from (`"rx"`) or sent to (`"tx"`) the peer.
    pub fn bytes(&self, dir: &str, data: &[u8]) {
        self.record(dir, json!({ "len": data.len(), "hex": hex(data), "text": printable(data) }));
    }
}

pub fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn printable(data: &[u8]) -> String {
    data.iter().map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn printable_neutralises_control_bytes() {
        assert_eq!(printable(b"a\r\n\x1b[0mb"), "a...[0mb");
    }
    #[test]
    fn hex_roundtrip() { assert_eq!(hex(&[0, 255, 16]), "00ff10"); }
}
