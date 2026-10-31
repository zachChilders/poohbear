//! Output side: a bounded queue of complete JSONL lines drained by one
//! writer task. Sessions never block on I/O, and a flood cannot grow memory
//! without limit: when the queue is full, lines are dropped and counted.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::session::SessionLogger;

/// Lines buffered between sessions and the writer task.
const QUEUE_CAPACITY: usize = 8192;

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

    /// Append JSONL lines to `path` (None = stdout).
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

    /// A logger that stamps every record with this session's identity.
    pub fn session(&self, session_id: &str, peer: SocketAddr, protocol: &str) -> SessionLogger {
        SessionLogger::new(self.clone(), session_id, peer, protocol)
    }

    /// Lines lost because the queue was full or the writer had stopped.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub(crate) fn emit(&self, mut line: String) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::time::Duration;

    fn logger(cap: usize) -> (LogSink, SessionLogger, mpsc::Receiver<String>) {
        let (sink, rx) = LogSink::channel(cap);
        let log = sink.session("s1", "127.0.0.1:9".parse().unwrap(), "test");
        (sink, log, rx)
    }

    #[test]
    fn full_queue_drops_and_counts_instead_of_growing() {
        let (sink, log, mut rx) = logger(2);
        for _ in 0..5 {
            log.event(crate::Record::Connect);
        }
        assert_eq!(sink.dropped(), 3);
        assert!(rx.try_recv().is_ok() && rx.try_recv().is_ok() && rx.try_recv().is_err());
    }

    #[test]
    fn closed_queue_counts_drops() {
        let (sink, log, rx) = logger(2);
        drop(rx);
        log.event(crate::Record::Connect);
        assert_eq!(sink.dropped(), 1);
    }

    #[tokio::test]
    async fn open_appends_lines_to_file() {
        let dir = std::env::temp_dir().join(format!("hp-log-test-{}", std::process::id()));
        let path = dir.join("nested/sessions.jsonl");
        let sink = LogSink::open(Some(&path)).await.unwrap();
        let log = sink.session("s", "127.0.0.1:9".parse().unwrap(), "t");
        log.event(crate::Record::Connect);
        log.event(crate::Record::Disconnect);
        for _ in 0..50 {
            if std::fs::read_to_string(&path).map_or(0, |t| t.lines().count()) == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let kinds: Vec<_> = text
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap()["kind"].clone())
            .collect();
        assert_eq!(kinds, ["connect", "disconnect"]);
        let _ = std::fs::remove_dir_all(dir);
    }
}
