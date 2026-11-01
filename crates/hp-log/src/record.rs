//! The session log schema. This is the single definition of what the
//! honeypot emits; adding or changing a record is a change to this file.
//!
//! Captured input is hostile. Records have no free-form fields: attacker
//! bytes only appear as hex plus a printable-ASCII rendering (everything
//! else `.`), and any attacker-influenced string is escaped by the JSON
//! encoder, so it can neither inject log lines nor override the envelope.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    /// Session accepted and started.
    Connect,
    /// Session over, whatever the reason.
    Disconnect,
    /// Connection refused before a session started.
    Rejected { reason: RejectReason },
    /// Session exceeded its time budget.
    Timeout,
    /// Session task panicked (contained).
    Panic,
    /// Plugin returned an error.
    Error { error: String },
    /// Bytes received from the peer.
    Rx(Payload),
    /// Bytes sent to the peer.
    Tx(Payload),
    /// A per-session limit was hit and the session was cut short.
    LimitExceeded { limit: Limit, total: u64 },
    /// An authentication attempt and the verdict. `credential` is the
    /// password, or the key fingerprint for public-key offers.
    Auth {
        user: String,
        method: AuthMethod,
        credential: String,
        accepted: bool,
    },
    /// A command line the peer submitted.
    Command { command: String, via: CommandSource },
    /// A channel-level request or open (pty, shell, forwarding, ...).
    ChannelRequest { request: ChannelRequestKind },
    /// The behavior flagged this moment for alerting (e.g. `payload_fetch`).
    Tag { tag: String },
    /// The behavior moved the session to another state.
    Transition { from: String, to: String },
    /// The behavior hit a runtime error and skipped a step.
    BehaviorError { error: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    MaxSessions,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    None,
    Password,
    PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandSource {
    /// Typed into an interactive (or piped) shell.
    Shell,
    /// Sent as a one-shot `exec` request.
    Exec,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelRequestKind {
    Pty,
    Shell,
    Exec,
    Subsystem,
    /// A `direct-tcpip` open: the peer tried to use us as a proxy.
    PortForward,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Limit {
    MaxInputBytes,
}

/// A captured byte string, safe to log.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Payload {
    pub len: usize,
    pub hex: String,
    pub text: String,
}

impl Payload {
    pub fn new(data: &[u8]) -> Payload {
        Payload {
            len: data.len(),
            hex: data.iter().map(|b| format!("{b:02x}")).collect(),
            text: data
                .iter()
                .map(|&b| {
                    if (0x20..0x7f).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect(),
        }
    }
}

impl Record {
    pub fn rx(data: &[u8]) -> Record {
        Record::Rx(Payload::new(data))
    }

    pub fn tx(data: &[u8]) -> Record {
        Record::Tx(Payload::new(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn to_json(r: &Record) -> Value {
        serde_json::to_value(r).unwrap()
    }

    #[test]
    fn payload_neutralises_control_bytes_and_hex_encodes() {
        let p = Payload::new(b"a\r\n\x1b[0mb\x00\xff");
        assert_eq!(p.text, "a...[0mb..");
        assert_eq!(p.hex, "610d0a1b5b306d6200ff");
        assert_eq!(p.len, 10);
    }

    #[test]
    fn wire_shape_of_every_record_is_stable() {
        let cases = [
            (Record::Connect, json!({"kind": "connect"})),
            (Record::Disconnect, json!({"kind": "disconnect"})),
            (Record::Timeout, json!({"kind": "timeout"})),
            (Record::Panic, json!({"kind": "panic"})),
            (
                Record::Rejected {
                    reason: RejectReason::MaxSessions,
                },
                json!({"kind": "rejected", "reason": "max_sessions"}),
            ),
            (
                Record::Error { error: "x".into() },
                json!({"kind": "error", "error": "x"}),
            ),
            (
                Record::rx(b"hi"),
                json!({"kind": "rx", "len": 2, "hex": "6869", "text": "hi"}),
            ),
            (
                Record::tx(b"hi"),
                json!({"kind": "tx", "len": 2, "hex": "6869", "text": "hi"}),
            ),
            (
                Record::LimitExceeded {
                    limit: Limit::MaxInputBytes,
                    total: 9,
                },
                json!({"kind": "limit_exceeded", "limit": "max_input_bytes", "total": 9}),
            ),
            (
                Record::Auth {
                    user: "root".into(),
                    method: AuthMethod::Password,
                    credential: "toor".into(),
                    accepted: false,
                },
                json!({"kind": "auth", "user": "root", "method": "password", "credential": "toor", "accepted": false}),
            ),
            (
                Record::Command {
                    command: "ls".into(),
                    via: CommandSource::Exec,
                },
                json!({"kind": "command", "command": "ls", "via": "exec"}),
            ),
            (
                Record::ChannelRequest {
                    request: ChannelRequestKind::PortForward,
                },
                json!({"kind": "channel_request", "request": "port_forward"}),
            ),
            (
                Record::Tag { tag: "t".into() },
                json!({"kind": "tag", "tag": "t"}),
            ),
            (
                Record::Transition {
                    from: "a".into(),
                    to: "b".into(),
                },
                json!({"kind": "transition", "from": "a", "to": "b"}),
            ),
            (
                Record::BehaviorError { error: "e".into() },
                json!({"kind": "behavior_error", "error": "e"}),
            ),
        ];
        for (record, want) in cases {
            assert_eq!(to_json(&record), want);
        }
    }
}
