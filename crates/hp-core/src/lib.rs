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
    AuthAttempt { user: String, secret: Secret },
    Command(String),
    Request { op: String, args: serde_json::Value },
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

/// What an emulated host produced for one command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostReply {
    /// Text for the peer, with plain `\n` line endings (plugins translate).
    pub output: String,
    /// The prompt to show next.
    pub prompt: String,
    /// The session asked to end (`exit`, `logout`).
    pub exit: bool,
    /// Moments worth flagging for alerting (`payload_fetch`, ...), named by
    /// the host because it knows what it just did.
    pub tags: Vec<String>,
}

/// A simulated machine a behavior can drive: a filesystem, a shell, users.
/// It is the shared "world" every protocol sees, so the same persona answers
/// consistently whether reached over SSH, Telnet or anything else. One
/// instance per session.
///
/// Like `Behavior`, a host never performs real I/O.
pub trait Host: Send {
    /// A user logged in; reset to their home directory.
    fn login(&mut self, user: &str) -> HostReply;
    /// Run one command line.
    fn run(&mut self, line: &str) -> HostReply;
    /// A read-only fact about current state: `user`, `cwd`, `hostname`.
    fn var(&self, name: &str) -> Option<String>;
}

/// Creates the per-session [`Host`]. Shared across sessions.
pub trait HostFactory: Send + Sync {
    fn start(&self) -> Box<dyn Host>;
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
