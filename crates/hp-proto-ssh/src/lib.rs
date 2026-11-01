//! SSH plugin, built on `russh`.
//!
//! This crate owns the SSH wire protocol: key exchange, encryption, channels
//! and the terminal details of an interactive shell. What the honeypot *says*
//! is decided entirely by the session's `Behavior`; see `handler` for the
//! exact mapping between SSH callbacks and `Event`/`Action`.
//!
//! Known limits of this version:
//! - The host key is generated fresh at startup, so it changes on restart.
//! - The shell prompt is `user@host:~$ `; the working directory is not shown.

mod handler;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use async_trait::async_trait;
use hp_core::{AsyncStream, Protocol, SessionCtx};
use hp_kit::term::to_crlf;
use hp_kit::Driver;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::Config;
use russh::SshId;

use handler::Conn;

const DEFAULT_SERVER_ID: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";

pub struct Ssh {
    config: Arc<Config>,
}

impl Ssh {
    /// `server_id` is the identification string sent on connect, e.g.
    /// `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`. Validated here so a bad
    /// persona fails at startup instead of on every connection.
    pub fn new(server_id: Option<&str>) -> anyhow::Result<Ssh> {
        let id = server_id.unwrap_or(DEFAULT_SERVER_ID);
        validate_server_id(id)?;

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
            .context("generating host key")?;
        let config = Config {
            server_id: SshId::Standard(id.to_string().into()),
            keys: vec![key],
            // Passwords are what we want to capture; keys are only recorded.
            methods: handler::methods(),
            // The behavior decides pacing; no extra fixed delay on top of it.
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            // OpenSSH's default MaxAuthTries.
            max_auth_attempts: 6,
            ..Config::default()
        };
        Ok(Ssh {
            config: Arc::new(config),
        })
    }
}

/// RFC 4253 section 4.2: `SSH-2.0-softwareversion [comments]`, at most 253
/// characters, no control characters.
fn validate_server_id(id: &str) -> anyhow::Result<()> {
    if !id.starts_with("SSH-2.0-") || id.len() == "SSH-2.0-".len() {
        bail!("ssh server id must look like `SSH-2.0-<software>`, got {id:?}");
    }
    if id.len() > 253 || id.chars().any(char::is_control) {
        bail!("ssh server id must be at most 253 characters with no control characters");
    }
    Ok(())
}

#[async_trait]
impl Protocol for Ssh {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn default_ports(&self) -> &[u16] {
        &[22]
    }

    async fn handle(&self, stream: Box<dyn AsyncStream>, ctx: SessionCtx) -> anyhow::Result<()> {
        let mut driver = Driver::new(ctx.log, ctx.behavior, &ctx.limits);

        // Before authentication there is no channel to write to, so anything
        // the behavior sends on connect becomes the pre-auth banner.
        let reply = driver.connect();
        if reply.wants_close() {
            return Ok(());
        }
        let text = reply.text();
        let banner =
            (!text.is_empty()).then(|| String::from_utf8_lossy(&to_crlf(&text)).into_owned());

        let conn = Conn::new(driver, ctx.persona.hostname.as_deref(), banner);
        match russh::server::run_stream(self.config.clone(), stream, conn).await {
            Ok(session) => session.await.or_else(routine),
            Err(e) => routine(e),
        }
    }
}

/// Peers vanishing or hanging up mid-protocol is normal for scanners and
/// brute-forcers; only genuinely unexpected failures are worth an error record.
fn routine(e: russh::Error) -> anyhow::Result<()> {
    match e {
        russh::Error::Disconnect | russh::Error::HUP | russh::Error::IO(_) => Ok(()),
        other => Err(other.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata() {
        let ssh = Ssh::new(None).unwrap();
        assert_eq!(ssh.name(), "ssh");
        assert_eq!(ssh.default_ports(), [22]);
    }

    #[test]
    fn server_id_validation() {
        assert!(Ssh::new(Some("SSH-2.0-OpenSSH_9.6p1 Debian-1")).is_ok());
        for bad in [
            "",
            "OpenSSH_8.9",
            "SSH-1.99-x",
            "SSH-2.0-",
            "SSH-2.0-a\r\nb",
        ] {
            assert!(Ssh::new(Some(bad)).is_err(), "{bad:?} should be rejected");
        }
        assert!(Ssh::new(Some(&format!("SSH-2.0-{}", "x".repeat(300)))).is_err());
    }

    #[test]
    fn routine_errors_are_not_reported() {
        assert!(routine(russh::Error::Disconnect).is_ok());
        assert!(routine(russh::Error::HUP).is_ok());
        assert!(routine(russh::Error::Inconsistent).is_err());
    }
}
