//! Test support shared by every protocol plugin. Dev-dependency only; it never
//! ships in the honeypot binary.
//!
//! - [`scripted`]: a `Behavior` driven by a plain function, which also
//!   remembers every event it was shown.
//! - [`session`]: a ready-made `SessionCtx` for the plugin to consume, plus an
//!   [`Observer`] the test keeps, to read the log records and the events the
//!   behavior saw.
//! - [`conformance`]: assertions for rules every protocol must satisfy,
//!   independent of its wire format.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hp_core::{Action, Behavior, Event, Limits, Persona, SessionCtx};
use hp_log::LogSink;
use serde_json::Value;
use tokio::sync::mpsc::Receiver;

pub use bytes::Bytes;

// ------------------------------------------------------------ behaviors

/// How a scripted behavior replies: a pure function of the event.
pub type Script = fn(&Event) -> Vec<Action>;

/// Events a behavior has been shown, as short labels: `Connected`,
/// `auth:<user>`, `cmd:<line>`, `raw:<text>`, `Disconnected`.
#[derive(Clone, Default)]
pub struct Seen(Arc<Mutex<Vec<String>>>);

impl Seen {
    pub fn all(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
}

struct Scripted {
    seen: Seen,
    script: Script,
}

impl Behavior for Scripted {
    fn react(&mut self, event: &Event) -> Vec<Action> {
        let label = match event {
            Event::AuthAttempt { user, .. } => format!("auth:{user}"),
            Event::Command(c) => format!("cmd:{c}"),
            Event::Raw(b) => format!("raw:{}", String::from_utf8_lossy(b)),
            other => format!("{other:?}"),
        };
        self.seen.0.lock().unwrap().push(label);
        (self.script)(event)
    }
}

/// A behavior that answers with `script` and records what it sees.
pub fn scripted(script: Script) -> (Box<dyn Behavior>, Seen) {
    let seen = Seen::default();
    (
        Box::new(Scripted {
            seen: seen.clone(),
            script,
        }),
        seen,
    )
}

/// A `Send` action from a string literal.
pub fn send(text: &'static str) -> Action {
    Action::Send(Bytes::from_static(text.as_bytes()))
}

// -------------------------------------------------------------- context

/// Knobs for [`session`].
pub struct CtxOptions {
    pub script: Script,
    pub hostname: Option<&'static str>,
    pub banner: Option<&'static str>,
    pub max_input_bytes: u64,
}

impl Default for CtxOptions {
    fn default() -> Self {
        CtxOptions {
            script: |_| vec![],
            hostname: None,
            banner: None,
            max_input_bytes: 1 << 20,
        }
    }
}

/// What a test keeps after handing the context to a plugin.
pub struct Observer {
    records: Receiver<String>,
    pub seen: Seen,
}

impl Observer {
    /// Every record logged since the last call, parsed.
    pub fn records(&mut self) -> Vec<Value> {
        drain(&mut self.records)
    }

    /// The raw log lines logged since the last call (newline included).
    pub fn lines(&mut self) -> Vec<String> {
        std::iter::from_fn(|| self.records.try_recv().ok()).collect()
    }
}

/// Build a session context for a plugin to consume, and the [`Observer`] to
/// watch it with.
pub fn session(opts: CtxOptions) -> (SessionCtx, Observer) {
    let (sink, records) = LogSink::channel(4096);
    let peer = "127.0.0.1:4000".parse().unwrap();
    let (behavior, seen) = scripted(opts.script);
    let ctx = SessionCtx {
        session_id: "test-session".into(),
        peer,
        log: sink.session("test-session", peer, "test"),
        persona: Persona {
            hostname: opts.hostname.map(String::from),
            banner: opts.banner.map(String::from),
        },
        limits: Limits {
            session_timeout: Duration::from_secs(60),
            max_input_bytes: opts.max_input_bytes,
        },
        behavior,
    };
    (ctx, Observer { records, seen })
}

// -------------------------------------------------------------- records

/// Everything logged so far, parsed.
pub fn drain(rx: &mut Receiver<String>) -> Vec<Value> {
    std::iter::from_fn(|| rx.try_recv().ok())
        .map(|line| serde_json::from_str(&line).expect("every record is valid JSON"))
        .collect()
}

pub fn kinds(records: &[Value]) -> Vec<&str> {
    records
        .iter()
        .map(|r| r["kind"].as_str().expect("record has a kind"))
        .collect()
}

pub fn of_kind<'a>(records: &'a [Value], kind: &str) -> Vec<&'a Value> {
    records.iter().filter(|r| r["kind"] == kind).collect()
}

// --------------------------------------------------------- conformance

/// Rules every protocol plugin must satisfy, whatever its wire format. Call
/// these from a plugin's own tests after driving a realistic session.
pub mod conformance {
    use super::*;

    /// The behavior must see `Connected` first and `Disconnected` last, each
    /// exactly once, so tracks can rely on the lifecycle.
    pub fn lifecycle(seen: &Seen) {
        let all = seen.all();
        let count = |label: &str| all.iter().filter(|s| *s == label).count();
        assert_eq!(
            count("Connected"),
            1,
            "Connected must be delivered once: {all:?}"
        );
        assert_eq!(
            count("Disconnected"),
            1,
            "Disconnected must be delivered once: {all:?}"
        );
        assert_eq!(
            all.first().map(String::as_str),
            Some("Connected"),
            "{all:?}"
        );
        assert_eq!(
            all.last().map(String::as_str),
            Some("Disconnected"),
            "{all:?}"
        );
    }

    /// Every record is a one-line JSON object carrying the session envelope.
    pub fn envelope(records: &[Value]) {
        for r in records {
            for field in ["ts_ms", "session", "peer", "protocol", "kind"] {
                assert!(r.get(field).is_some(), "record missing `{field}`: {r}");
            }
        }
    }

    /// After exceeding the input cap: exactly one `limit_exceeded` record, and
    /// the over-limit data was not logged as received.
    pub fn input_cap_enforced(records: &[Value], cap: u64) {
        let hits = of_kind(records, "limit_exceeded");
        assert_eq!(
            hits.len(),
            1,
            "expected one limit_exceeded record: {records:?}"
        );
        assert_eq!(hits[0]["limit"], "max_input_bytes");
        let logged: u64 = of_kind(records, "rx")
            .iter()
            .filter_map(|r| r["len"].as_u64())
            .sum();
        assert!(
            logged <= cap,
            "logged {logged} bytes received, over the cap of {cap}"
        );
    }

    /// No record may contain a raw control character: hostile input must never
    /// reach the log stream unescaped.
    pub fn no_raw_control_characters(lines: &[String]) {
        for line in lines {
            let body = line.trim_end_matches('\n');
            assert!(
                !body.chars().any(char::is_control),
                "raw control character in log line: {body:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_records_labels_and_replies() {
        let (mut b, seen) = scripted(|e| match e {
            Event::Command(_) => vec![send("ok")],
            _ => vec![],
        });
        assert!(b.react(&Event::Connected).is_empty());
        assert_eq!(b.react(&Event::Command("ls".into())).len(), 1);
        b.react(&Event::Raw(Bytes::from_static(b"zz")));
        assert_eq!(seen.all(), ["Connected", "cmd:ls", "raw:zz"]);
    }

    #[test]
    fn ctx_wires_persona_limits_and_logging() {
        let (ctx, mut obs) = session(CtxOptions {
            hostname: Some("h"),
            banner: Some("b"),
            max_input_bytes: 7,
            ..CtxOptions::default()
        });
        assert_eq!(ctx.persona.hostname.as_deref(), Some("h"));
        assert_eq!(ctx.limits.max_input_bytes, 7);
        ctx.log.event(hp_log::Record::Connect);
        let recs = obs.records();
        assert_eq!(kinds(&recs), ["connect"]);
        assert_eq!(of_kind(&recs, "connect").len(), 1);
        conformance::envelope(&recs);
    }

    #[test]
    fn conformance_lifecycle_accepts_a_good_session() {
        let (mut b, seen) = scripted(|_| vec![]);
        b.react(&Event::Connected);
        b.react(&Event::Disconnected);
        conformance::lifecycle(&seen);
    }

    #[test]
    #[should_panic(expected = "Disconnected must be delivered once")]
    fn conformance_lifecycle_rejects_a_missing_disconnect() {
        let (mut b, seen) = scripted(|_| vec![]);
        b.react(&Event::Connected);
        conformance::lifecycle(&seen);
    }

    #[test]
    fn conformance_input_cap_and_control_characters() {
        let (ctx, mut obs) = session(CtxOptions::default());
        ctx.log.event(hp_log::Record::rx(b"abc"));
        ctx.log.event(hp_log::Record::LimitExceeded {
            limit: hp_log::Limit::MaxInputBytes,
            total: 9,
        });
        let recs = obs.records();
        conformance::input_cap_enforced(&recs, 3);
        conformance::no_raw_control_characters(&["{\"text\":\"a\\u001bb\"}\n".to_string()]);
    }

    #[test]
    #[should_panic(expected = "raw control character")]
    fn conformance_catches_unescaped_control_characters() {
        conformance::no_raw_control_characters(&["{\"text\":\"a\u{1b}b\"}".to_string()]);
    }
}
