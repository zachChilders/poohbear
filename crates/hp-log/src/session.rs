//! Per-session handle: wraps each [`Record`] in an envelope carrying the
//! session's identity and a timestamp, then hands the line to the sink.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::record::Record;
use crate::sink::LogSink;

#[derive(Serialize)]
struct Envelope<'a> {
    ts_ms: u64,
    session: &'a str,
    peer: &'a str,
    protocol: &'a str,
    #[serde(flatten)]
    record: &'a Record,
}

struct Identity {
    session: String,
    peer: String,
    protocol: String,
}

#[derive(Clone)]
pub struct SessionLogger {
    sink: LogSink,
    id: Arc<Identity>,
}

impl SessionLogger {
    pub(crate) fn new(sink: LogSink, session: &str, peer: SocketAddr, protocol: &str) -> Self {
        let id = Identity {
            session: session.into(),
            peer: peer.to_string(),
            protocol: protocol.into(),
        };
        SessionLogger {
            sink,
            id: Arc::new(id),
        }
    }

    pub fn event(&self, record: Record) {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let envelope = Envelope {
            ts_ms,
            session: &self.id.session,
            peer: &self.id.peer,
            protocol: &self.id.protocol,
            record: &record,
        };
        match serde_json::to_string(&envelope) {
            Ok(line) => self.sink.emit(line),
            // Records are plain data; this cannot happen, but never panic a session over a log line.
            Err(e) => tracing::error!(error = %e, "failed to encode session record"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn one_line(record: Record) -> (String, Value) {
        let (sink, mut rx) = LogSink::channel(4);
        sink.session("s1", "127.0.0.1:9".parse().unwrap(), "test")
            .event(record);
        let line = rx.try_recv().unwrap();
        let v = serde_json::from_str(&line).unwrap();
        (line, v)
    }

    #[test]
    fn envelope_carries_identity_and_the_record_fields() {
        let (line, v) = one_line(Record::rx(b"hi\n"));
        assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
        assert_eq!(v["kind"], "rx");
        assert_eq!(v["session"], "s1");
        assert_eq!(v["peer"], "127.0.0.1:9");
        assert_eq!(v["protocol"], "test");
        assert!(v["ts_ms"].as_u64().unwrap() > 0);
        assert_eq!(
            (v["len"].as_u64(), v["hex"].as_str(), v["text"].as_str()),
            (Some(3), Some("68690a"), Some("hi."))
        );
    }

    #[test]
    fn hostile_strings_cannot_inject_lines() {
        let evil = "a\n{\"kind\":\"forged\",\"session\":\"x\"}\r\n";
        let (line, v) = one_line(Record::Error { error: evil.into() });
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        assert_eq!(
            (v["kind"].as_str(), v["session"].as_str()),
            (Some("error"), Some("s1"))
        );
        assert_eq!(v["error"], evil, "round-trips as data");
    }
}
