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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use hp_core::{
    Action, AsyncStream, Behavior, Event, Limits, Persona, SessionCtx, ShellBackend, ShellRequest,
};
use hp_log::LogSink;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
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

// ------------------------------------------------------------- shell backend

/// A [`ShellBackend`] for tests: a tiny scripted "shell" on an in-memory
/// stream. It prints `fake$ `, answers each line it is sent by calling the
/// responder (`None` ends the shell), and records what it was asked to start
/// and how many shells are still running.
pub struct FakeBackend {
    responder: fn(&str) -> Option<String>,
    fail: bool,
    requests: Mutex<Vec<ShellRequest>>,
    live: Arc<AtomicUsize>,
}

impl FakeBackend {
    pub fn new(responder: fn(&str) -> Option<String>) -> Arc<FakeBackend> {
        Arc::new(FakeBackend {
            responder,
            fail: false,
            requests: Mutex::default(),
            live: Arc::default(),
        })
    }

    /// A backend that cannot start shells.
    pub fn failing() -> Arc<FakeBackend> {
        Arc::new(FakeBackend {
            responder: |_| None,
            fail: true,
            requests: Mutex::default(),
            live: Arc::default(),
        })
    }

    pub fn requests(&self) -> Vec<ShellRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Shells started and not yet finished or dropped by the peer.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl ShellBackend for FakeBackend {
    async fn start(&self, request: ShellRequest) -> anyhow::Result<Box<dyn AsyncStream>> {
        anyhow::ensure!(!self.fail, "no sandbox available");
        let command = request.command.clone();
        self.requests.lock().unwrap().push(request);
        Ok(Box::new(spawn_fake_shell(
            self.responder,
            command,
            self.live.clone(),
        )))
    }
}

/// Start the scripted shell behind [`FakeBackend`] and return the peer's end of
/// its stream. `live` counts shells that have not ended or been dropped.
pub fn spawn_fake_shell(
    responder: fn(&str) -> Option<String>,
    command: Option<String>,
    live: Arc<AtomicUsize>,
) -> DuplexStream {
    let (peer, mut shell) = tokio::io::duplex(8192);
    live.fetch_add(1, Ordering::SeqCst);
    tokio::spawn(async move {
        run_fake_shell(&mut shell, responder, command).await;
        live.fetch_sub(1, Ordering::SeqCst);
    });
    peer
}

async fn run_fake_shell(
    shell: &mut DuplexStream,
    responder: fn(&str) -> Option<String>,
    command: Option<String>,
) {
    if let Some(command) = command {
        let _ = shell
            .write_all(responder(&command).unwrap_or_default().as_bytes())
            .await;
        return;
    }
    let _ = shell.write_all(b"fake$ ").await;
    let (mut buf, mut line) = ([0u8; 1024], String::new());
    while let Ok(n @ 1..) = shell.read(&mut buf).await {
        for &b in &buf[..n] {
            if b != b'\r' && b != b'\n' {
                line.push(b as char);
                continue;
            }
            let Some(out) = responder(&std::mem::take(&mut line)) else {
                return;
            };
            if shell
                .write_all(format!("{out}fake$ ").as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
    }
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

    #[tokio::test]
    async fn fake_backend_runs_a_scripted_shell_and_tracks_it() {
        let backend = FakeBackend::new(|l| (l != "exit").then(|| format!("you said {l}\n")));
        let req = ShellRequest {
            session_id: "s".into(),
            user: "root".into(),
            command: None,
            terminal: None,
        };
        let mut shell = backend.start(req.clone()).await.unwrap();
        let mut buf = [0u8; 64];
        let n = shell.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"fake$ ");
        shell.write_all(b"hi\r").await.unwrap();
        let n = shell.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"you said hi\nfake$ ");
        assert_eq!((backend.requests(), backend.live()), (vec![req], 1));
        shell.write_all(b"exit\n").await.unwrap();
        assert_eq!(shell.read(&mut buf).await.unwrap(), 0, "the shell ended");
        tokio::task::yield_now().await;
        assert_eq!(backend.live(), 0);
    }

    #[tokio::test]
    async fn fake_backend_commands_run_once_and_failure_is_an_error() {
        let backend = FakeBackend::new(|c| Some(format!("ran {c}\n")));
        let req = ShellRequest {
            session_id: "s".into(),
            user: "u".into(),
            command: Some("id".into()),
            terminal: None,
        };
        let mut out = Vec::new();
        backend
            .start(req.clone())
            .await
            .unwrap()
            .read_to_end(&mut out)
            .await
            .unwrap();
        assert_eq!(out, b"ran id\n");
        assert!(FakeBackend::failing().start(req).await.is_err());
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
    fn conformance_input_cap() {
        let (ctx, mut obs) = session(CtxOptions::default());
        ctx.log.event(hp_log::Record::rx(b"abc"));
        ctx.log.event(hp_log::Record::LimitExceeded {
            limit: hp_log::Limit::MaxInputBytes,
            total: 9,
        });
        let recs = obs.records();
        conformance::input_cap_enforced(&recs, 3);
    }
}
