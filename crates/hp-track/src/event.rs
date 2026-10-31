//! The event-binding contract between the engine and the track language:
//! which kinds of event exist and which variables each one exposes. The
//! validator (`EVENT_VARS`) and the engine (`bind`) share this one definition.

use std::collections::HashMap;

use hp_core::Event;

use crate::expr::Value;

/// Names bound from the current event; usable in any expression.
pub(crate) const EVENT_VARS: &[&str] = &["user", "password", "command", "argv0", "op", "raw"];

/// Read-only facts about the emulated host (`host_user`, `host_cwd`,
/// `host_hostname`), when a host is configured. Each maps to `Host::var` of
/// the name without the prefix.
pub(crate) const HOST_VARS: &[&str] = &["host_user", "host_cwd", "host_hostname"];

/// Names a track may use without declaring them under `vars`.
pub(crate) fn is_builtin(name: &str) -> bool {
    EVENT_VARS.contains(&name) || HOST_VARS.contains(&name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EventKind {
    Connected,
    AuthAttempt,
    Command,
    Request,
    Raw,
    Disconnected,
}

impl EventKind {
    /// Input is what the peer sends. Connect/disconnect are lifecycle
    /// notifications: a track may react to them explicitly, but a state's
    /// `fallback` (the "unexpected input" reply) never answers them.
    pub(crate) fn is_input(self) -> bool {
        !matches!(self, Self::Connected | Self::Disconnected)
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "connected" => Self::Connected,
            "auth_attempt" => Self::AuthAttempt,
            "command" => Self::Command,
            "request" => Self::Request,
            "raw" => Self::Raw,
            "disconnected" => Self::Disconnected,
            _ => return None,
        })
    }
}

/// Bind the variables an event exposes to matchers and expressions.
pub(crate) fn bind(ev: &Event) -> (EventKind, HashMap<String, Value>) {
    let mut env = HashMap::new();
    let s = |x: &str| Value::Str(x.to_string());
    let kind = match ev {
        Event::Connected => EventKind::Connected,
        Event::Disconnected => EventKind::Disconnected,
        Event::AuthAttempt { user, secret } => {
            env.insert("user".into(), s(user));
            env.insert("password".into(), s(secret.expose()));
            EventKind::AuthAttempt
        }
        Event::Command(c) => {
            env.insert("command".into(), s(c));
            env.insert("argv0".into(), s(c.split_whitespace().next().unwrap_or("")));
            EventKind::Command
        }
        Event::Request { op, .. } => {
            env.insert("op".into(), s(op));
            EventKind::Request
        }
        Event::Raw(b) => {
            env.insert(
                "raw".into(),
                Value::Str(String::from_utf8_lossy(b).into_owned()),
            );
            EventKind::Raw
        }
    };
    (kind, env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hp_core::Secret;

    #[test]
    fn every_declared_variable_is_bound_by_some_event_and_nothing_else_is() {
        let events = [
            Event::Connected,
            Event::Disconnected,
            Event::AuthAttempt {
                user: "u".into(),
                secret: Secret::new("p"),
            },
            Event::Command("ls -l".into()),
            Event::Request {
                op: "read".into(),
                args: serde_json::Value::Null,
            },
            Event::Raw(Bytes::from_static(b"x")),
        ];
        let mut bound: Vec<String> = events.iter().flat_map(|e| bind(e).1.into_keys()).collect();
        bound.sort();
        bound.dedup();
        let mut declared: Vec<String> = EVENT_VARS.iter().map(|s| s.to_string()).collect();
        declared.sort();
        assert_eq!(bound, declared, "EVENT_VARS and bind() have drifted apart");
    }

    #[test]
    fn argv0_is_the_first_word() {
        let (kind, env) = bind(&Event::Command("  wget  http://x ".into()));
        assert_eq!(kind, EventKind::Command);
        assert_eq!(env["argv0"], Value::Str("wget".into()));
        assert_eq!(
            bind(&Event::Command(String::new())).1["argv0"],
            Value::Str(String::new())
        );
    }
}
