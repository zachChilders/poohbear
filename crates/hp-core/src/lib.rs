//! Core types shared by every protocol plugin.
//!
//! Plugins own the wire format; the (future) track engine owns behavior.
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

pub struct SessionCtx {
    pub session_id: String,
    pub peer: SocketAddr,
    pub log: SessionLogger,
    pub persona: Persona,
    pub limits: Limits,
}

#[async_trait]
pub trait Protocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_ports(&self) -> &[u16];
    async fn handle(&self, stream: Box<dyn AsyncStream>, ctx: SessionCtx) -> anyhow::Result<()>;
}
