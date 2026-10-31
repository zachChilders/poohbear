//! One SSH connection: maps protocol callbacks onto `Event`s and carries out
//! the `Action`s the session's `Behavior` returns.
//!
//! The mapping, in short:
//! - password auth  -> `Event::AuthAttempt`; `Action::AuthResult` decides
//! - shell line / exec command -> `Event::Command`
//! - public-key offers, forwarding, subsystems -> logged and refused
//!   (the behavior never sees them, and a key is never accepted)

use std::collections::HashMap;
use std::time::Duration;

use hp_core::{Action, Behavior, Event, Secret};
use hp_log::{AuthMethod, ChannelRequestKind, CommandSource, Limit, Record, SessionLogger};
use russh::keys::HashAlg;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet};

use crate::line::{to_crlf, Edit, LineEditor};

/// Concurrent session channels per connection; real sshd defaults to 10.
const MAX_CHANNELS: usize = 8;

pub(crate) struct Conn {
    log: SessionLogger,
    behavior: Box<dyn Behavior>,
    /// Hostname shown in the prompt (already sanitized).
    host: String,
    max_input_bytes: u64,
    received: u64,
    /// Sent to the client as the pre-auth banner.
    auth_banner: Option<String>,
    /// Set once password auth succeeds.
    user: Option<String>,
    /// Text the behavior sent with a successful auth; shown when the shell opens.
    welcome: Vec<u8>,
    channels: HashMap<ChannelId, Chan>,
}

#[derive(Default)]
struct Chan {
    pty: bool,
    /// Present once a shell was started on this channel.
    shell: Option<LineEditor>,
}

/// What `decide` extracted from the behavior's reply to an auth attempt.
struct Decision {
    accepted: bool,
    welcome: Vec<u8>,
    delay: Duration,
    close: bool,
}

/// The authentication methods we advertise.
pub(crate) fn methods() -> MethodSet {
    MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..])
}

/// Reject an attempt while keeping every method on offer, like OpenSSH does
/// until MaxAuthTries. `Auth::reject()` would drop the method just tried,
/// and clients such as paramiko then refuse to try it again, so a
/// brute-forcer would get exactly one password per connection.
fn reject() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(methods()),
        partial_success: false,
    }
}

enum Flow {
    Continue,
    Close,
}

impl Conn {
    pub(crate) fn new(
        log: SessionLogger,
        behavior: Box<dyn Behavior>,
        hostname: Option<&str>,
        max_input_bytes: u64,
        auth_banner: Option<String>,
    ) -> Conn {
        Conn {
            log,
            behavior,
            host: sanitize(hostname.unwrap_or("localhost")),
            max_input_bytes,
            received: 0,
            auth_banner,
            user: None,
            welcome: Vec::new(),
            channels: HashMap::new(),
        }
    }

    /// Reduce the behavior's reply to an auth attempt to a verdict. Later
    /// `AuthResult`s win; with none, the attempt fails.
    fn decide(actions: Vec<Action>) -> Decision {
        let mut d = Decision {
            accepted: false,
            welcome: Vec::new(),
            delay: Duration::ZERO,
            close: false,
        };
        for action in actions {
            match action {
                Action::AuthResult(ok) => d.accepted = ok,
                Action::Send(b) => d.welcome.extend_from_slice(&b),
                Action::Delay(t) => d.delay += t,
                Action::Close => d.close = true,
            }
        }
        d
    }

    fn prompt(&self) -> Vec<u8> {
        let user = self.user.as_deref().unwrap_or("user");
        format!("{user}@{}:~$ ", self.host).into_bytes()
    }

    fn send_prompt(&self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        let prompt = self.prompt();
        self.log.event(Record::tx(&prompt));
        session.data(channel, prompt)
    }

    fn hangup(&self, session: &mut Session) -> Result<(), russh::Error> {
        session.disconnect(Disconnect::ByApplication, "", "")
    }

    /// Carry out a behavior's reply on `channel`. `crlf` is true for pty
    /// sessions, where output needs tty-style line endings.
    async fn run_actions(
        log: &SessionLogger,
        session: &mut Session,
        channel: ChannelId,
        actions: Vec<Action>,
        crlf: bool,
    ) -> Result<Flow, russh::Error> {
        for action in actions {
            match action {
                Action::Send(data) => {
                    let out = if crlf { to_crlf(&data) } else { data.to_vec() };
                    log.event(Record::tx(&out));
                    session.data(channel, out)?;
                }
                Action::Delay(d) => tokio::time::sleep(d).await,
                Action::Close => return Ok(Flow::Close),
                // Auth verdicts only mean something during authentication.
                Action::AuthResult(_) => {}
            }
        }
        Ok(Flow::Continue)
    }

    /// Finish a one-shot channel the way sshd does after a command exits.
    fn finish(&self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        // Runs on every exit path, including the server cancelling a
        // timed-out session. Nothing can be delivered any more, so the
        // behavior's reply is discarded.
        self.behavior.react(&Event::Disconnected);
    }
}

impl Handler for Conn {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.auth_banner.take())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.log.event(Record::Auth {
            user: user.into(),
            method: AuthMethod::None,
            credential: String::new(),
            accepted: false,
        });
        Ok(reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        let event = Event::AuthAttempt {
            user: user.into(),
            secret: Secret::new(password),
        };
        let d = Conn::decide(self.behavior.react(&event));
        // Log before any delay, so the attempt is captured even if the peer
        // gives up while waiting.
        self.log.event(Record::Auth {
            user: user.into(),
            method: AuthMethod::Password,
            credential: password.into(),
            accepted: d.accepted && !d.close,
        });
        tokio::time::sleep(d.delay).await;
        if d.close {
            return Err(russh::Error::Disconnect);
        }
        if d.accepted {
            // The name goes into the prompt, so strip terminal control bytes.
            self.user = Some(sanitize(user));
            self.welcome = d.welcome;
            Ok(Auth::Accept)
        } else {
            Ok(reject())
        }
    }

    /// We never accept keys; we only record which ones are offered.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        self.log.event(Record::Auth {
            user: user.into(),
            method: AuthMethod::PublicKey,
            credential: offer.public_key.fingerprint(HashAlg::Sha256).to_string(),
            accepted: false,
        });
        Ok(reject())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Dropping the handle without answering rejects the channel.
        if self.channels.len() < MAX_CHANNELS {
            self.channels.insert(channel.id(), Chan::default());
            reply.accept().await;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host_to_connect: &str,
        _port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.event(Record::ChannelRequest {
            request: ChannelRequestKind::PortForward,
        });
        drop(reply);
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.event(Record::ChannelRequest {
            request: ChannelRequestKind::Pty,
        });
        match self.channels.get_mut(&channel) {
            Some(chan) => {
                chan.pty = true;
                session.channel_success(channel)
            }
            None => session.channel_failure(channel),
        }
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.event(Record::ChannelRequest {
            request: ChannelRequestKind::Shell,
        });
        let Some(chan) = self
            .channels
            .get_mut(&channel)
            .filter(|c| c.shell.is_none())
        else {
            return session.channel_failure(channel);
        };
        let pty = chan.pty;
        chan.shell = Some(LineEditor::new(pty));
        session.channel_success(channel)?;

        let welcome = std::mem::take(&mut self.welcome);
        if !welcome.is_empty() {
            let out = if pty { to_crlf(&welcome) } else { welcome };
            self.log.event(Record::tx(&out));
            session.data(channel, out)?;
        }
        if pty {
            self.send_prompt(session, channel)?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.event(Record::ChannelRequest {
            request: ChannelRequestKind::Exec,
        });
        if !self.channels.contains_key(&channel) {
            return session.channel_failure(channel);
        }
        session.channel_success(channel)?;
        let command = String::from_utf8_lossy(data).into_owned();
        self.log.event(Record::Command {
            command: command.clone(),
            via: CommandSource::Exec,
        });
        let actions = self.behavior.react(&Event::Command(command));
        match Conn::run_actions(&self.log, session, channel, actions, false).await? {
            Flow::Continue => self.finish(session, channel),
            Flow::Close => self.hangup(session),
        }
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.log.event(Record::ChannelRequest {
            request: ChannelRequestKind::Subsystem,
        });
        session.channel_failure(channel)
    }

    // Environment and X11 requests are politely declined, as a locked-down
    // sshd would. They are routine client noise, so they are not logged.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.received += data.len() as u64;
        if self.received > self.max_input_bytes {
            self.log.event(Record::LimitExceeded {
                limit: Limit::MaxInputBytes,
                total: self.received,
            });
            return self.hangup(session);
        }
        self.log.event(Record::rx(data));

        let Some(chan) = self.channels.get_mut(&channel) else {
            return Ok(());
        };
        let pty = chan.pty;
        let Some(editor) = chan.shell.as_mut() else {
            return Ok(());
        };

        for edit in editor.feed(data) {
            match edit {
                // Echo is derivable from the logged input, so it is not logged.
                Edit::Echo(bytes) => session.data(channel, bytes)?,
                Edit::Line(bytes) => {
                    let command = String::from_utf8_lossy(&bytes).into_owned();
                    self.log.event(Record::Command {
                        command: command.clone(),
                        via: CommandSource::Shell,
                    });
                    let actions = self.behavior.react(&Event::Command(command));
                    if let Flow::Close =
                        Conn::run_actions(&self.log, session, channel, actions, pty).await?
                    {
                        return self.hangup(session);
                    }
                    if pty {
                        self.send_prompt(session, channel)?;
                    }
                }
                Edit::Interrupt => {
                    if pty {
                        self.send_prompt(session, channel)?;
                    }
                }
                Edit::Eof => return self.hangup(session),
            }
        }
        Ok(())
    }

    /// The client closed its input (e.g. `echo cmd | ssh host`): the shell
    /// sees end of file and exits.
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self
            .channels
            .get(&channel)
            .is_some_and(|c| c.shell.is_some())
        {
            self.finish(session, channel)?;
        }
        Ok(())
    }
}

/// Make attacker- or config-supplied text safe to embed in a terminal prompt.
fn sanitize(s: &str) -> String {
    s.chars()
        .take(64)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_control_characters_and_caps_length() {
        assert_eq!(sanitize("ok-host"), "ok-host");
        assert_eq!(sanitize("a\x1b[31m\r\nb"), "a?[31m??b");
        assert_eq!(sanitize(&"x".repeat(500)).len(), 64);
    }

    #[test]
    fn decide_takes_the_last_verdict_and_totals_delays() {
        use bytes::Bytes;
        let d = Conn::decide(vec![
            Action::Delay(Duration::from_millis(5)),
            Action::AuthResult(false),
            Action::Send(Bytes::from_static(b"hi ")),
            Action::Delay(Duration::from_millis(7)),
            Action::AuthResult(true),
            Action::Send(Bytes::from_static(b"there")),
        ]);
        assert!(d.accepted && !d.close);
        assert_eq!(d.welcome, b"hi there");
        assert_eq!(d.delay, Duration::from_millis(12));
        assert!(!Conn::decide(vec![]).accepted, "no verdict means rejected");
        assert!(Conn::decide(vec![Action::Close]).close);
    }
}
