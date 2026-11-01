//! Core types shared by every protocol plugin.
//!
//! Plugins own the wire format; a [`Behavior`] owns what to say back. The two
//! meet only through [`Event`] and [`Action`], so a plugin depends on this
//! crate alone, never on a particular behavior engine.
//! Plugins never get an API for spawning processes or opening outbound sockets.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use hp_log::SessionLogger;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Secret material from an auth attempt. Debug output is redacted; the
/// session log records it deliberately via `expose`.
#[derive(Clone)]
pub struct Secret(String);
impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// plugin -> engine
#[derive(Debug, Clone)]
pub enum Event {
    Connected,
    AuthAttempt {
        user: String,
        secret: Secret,
    },
    Command(String),
    /// A request in a request/response protocol. `op` names it (HTTP:
    /// `"GET /path?q"`). Tracks see these string fields of `args` as
    /// variables: `method`, `path`, `query`, `headers`, `body`, and `user` /
    /// `password` when the request carried credentials.
    Request {
        op: String,
        args: serde_json::Value,
    },
    Raw(Bytes),
    Disconnected,
}

/// engine -> plugin
#[derive(Debug, Clone)]
pub enum Action {
    Send(Bytes),
    AuthResult(bool),
    Delay(Duration),
    /// Set the text shown before each input line in an interactive session
    /// (a shell prompt). Plugins without an interactive prompt ignore it.
    Prompt(String),
    /// Give this session a real shell (see [`ShellBackend`]) when it asks for
    /// one. Without it, shell input is answered by the behavior as commands.
    OpenShell,
    Close,
}

/// Per-session limits enforced by the listener and plugins.
#[derive(Debug, Clone)]
pub struct Limits {
    pub session_timeout: Duration,
    pub max_input_bytes: u64,
}

/// Persona settings that plugins present to the peer.
#[derive(Debug, Clone, Default)]
pub struct Persona {
    pub hostname: Option<String>,
    pub banner: Option<String>,
}

/// Decides how the honeypot responds. One instance per session; plugins feed
/// it protocol events and carry out the actions it returns, in order.
///
/// Implementations must be deterministic given the event sequence and must
/// never perform I/O: everything an attacker sees comes back as [`Action`]s.
pub trait Behavior: Send {
    fn react(&mut self, event: &Event) -> Vec<Action>;
}

/// Creates the per-session [`Behavior`]. Shared across sessions.
pub trait BehaviorFactory: Send + Sync {
    fn start(&self, log: &SessionLogger) -> Box<dyn Behavior>;
}

/// The terminal a peer asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Terminal {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

/// What a real shell is started for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellRequest {
    pub session_id: String,
    pub user: String,
    /// `Some` for a one-shot command (`ssh host cmd`), `None` for a login shell.
    pub command: Option<String>,
    /// Present if the peer asked for a terminal.
    pub terminal: Option<Terminal>,
}

/// Where real shells run (a sandbox per session). The honeypot only sees a
/// byte stream: what the peer types goes in, what the shell prints comes out.
/// Dropping the stream ends the shell.
#[async_trait]
pub trait ShellBackend: Send + Sync {
    async fn start(&self, request: ShellRequest) -> anyhow::Result<Box<dyn AsyncStream>>;
}

/// The behavior that never responds: plugins fall back to their static
/// persona. Used when no track is configured.
pub struct Passive;

impl Behavior for Passive {
    fn react(&mut self, _event: &Event) -> Vec<Action> {
        Vec::new()
    }
}

impl BehaviorFactory for Passive {
    fn start(&self, _log: &SessionLogger) -> Box<dyn Behavior> {
        Box::new(Passive)
    }
}

pub struct SessionCtx {
    pub session_id: String,
    pub peer: SocketAddr,
    pub log: SessionLogger,
    pub persona: Persona,
    pub limits: Limits,
    pub behavior: Box<dyn Behavior>,
}

#[async_trait]
pub trait Protocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_ports(&self) -> &[u16];
    /// Whether the plugin can run over UDP. There, each datagram from a peer
    /// arrives as one read and each write leaves as one datagram, so only
    /// protocols that read whatever arrives (rather than a byte stream with
    /// its own framing and handshakes) should say yes.
    fn supports_udp(&self) -> bool {
        false
    }
    async fn handle(&self, stream: Box<dyn AsyncStream>, ctx: SessionCtx) -> anyhow::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_redacted_everywhere_except_expose() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        let ev = Event::AuthAttempt {
            user: "root".into(),
            secret: s.clone(),
        };
        assert!(!format!("{ev:?}").contains("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn passive_never_responds() {
        let mut b = Passive.start(&hp_log::LogSink::channel(1).0.session(
            "s",
            "127.0.0.1:1".parse().unwrap(),
            "t",
        ));
        assert!(b.react(&Event::Connected).is_empty());
        assert!(b.react(&Event::Command("ls".into())).is_empty());
    }
}
