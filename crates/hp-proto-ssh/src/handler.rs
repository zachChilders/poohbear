//! One SSH connection: maps protocol callbacks onto `Event`s and carries out
//! the replies. Everything that is not SSH (lifecycle, input cap, auth
//! verdicts, action application, terminal handling) comes from `hp-kit`.
//!
//! The mapping, in short:
//! - password auth -> `Event::AuthAttempt`; the behavior's verdict decides
//! - shell line / exec command -> `Event::Command`
//! - public-key offers, forwarding, subsystems -> logged and refused
//!   (the behavior never sees them, and a key is never accepted)

use std::collections::HashMap;
use std::sync::Arc;

use hp_core::{Event, Secret, ShellBackend, ShellRequest, Terminal};
use hp_kit::term::{sanitize, to_crlf, Edit, LineEditor};
use hp_kit::{apply, Driver, Flow, Output};
use hp_log::{AuthMethod, ChannelRequestKind, CommandSource, Record};
use russh::keys::HashAlg;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, Disconnect, MethodKind, MethodSet};

use crate::real::RealShell;

/// Concurrent session channels per connection; real sshd defaults to 10.
const MAX_CHANNELS: usize = 8;

/// Longest hostname/username we embed in the default prompt.
const MAX_NAME: usize = 64;

pub(crate) struct Conn {
    driver: Driver,
    /// Hostname for the default prompt (already sanitized).
    host: String,
    /// Sent to the client as the pre-auth banner.
    auth_banner: Option<String>,
    /// Set once password auth succeeds (sanitized: it goes into the prompt).
    user: Option<String>,
    /// Text the behavior sent with a successful auth; shown when the shell opens.
    welcome: Vec<u8>,
    /// The behavior's prompt, if it set one; otherwise `user@host:~$ `.
    prompt: Option<String>,
    channels: HashMap<ChannelId, Chan>,
    session_id: String,
    /// Where real shells run, if configured.
    backend: Option<Arc<dyn ShellBackend>>,
    /// The behavior granted this session a real shell.
    real_shell: bool,
}

#[derive(Default)]
struct Chan {
    /// Present if the peer asked for a pty.
    terminal: Option<Terminal>,
    /// Present once a shell was started on this channel.
    shell: Option<Shell>,
}

enum Shell {
    /// Lines are given to the behavior as commands.
    Scripted(LineEditor),
    /// Bytes go to a sandbox.
    Real(RealShell),
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

/// The kit's [`Output`] over one SSH channel.
struct ChannelOut<'a> {
    session: &'a mut Session,
    channel: ChannelId,
}

impl Output for ChannelOut<'_> {
    type Error = russh::Error;

    fn write(
        &mut self,
        data: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        let result = self.session.data(self.channel, data);
        async move { result }
    }
}

impl Conn {
    pub(crate) fn new(
        driver: Driver,
        session_id: String,
        hostname: Option<&str>,
        auth_banner: Option<String>,
        backend: Option<Arc<dyn ShellBackend>>,
    ) -> Conn {
        Conn {
            session_id,
            backend,
            real_shell: false,
            driver,
            host: sanitize(hostname.unwrap_or("localhost"), MAX_NAME),
            auth_banner,
            user: None,
            welcome: Vec::new(),
            prompt: None,
            channels: HashMap::new(),
        }
    }

    fn prompt_text(&self) -> Vec<u8> {
        match &self.prompt {
            Some(p) => p.clone().into_bytes(),
            None => {
                let user = self.user.as_deref().unwrap_or("user");
                format!("{user}@{}:~$ ", self.host).into_bytes()
            }
        }
    }

    fn send_prompt(&self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        let prompt = self.prompt_text();
        self.driver.log().event(Record::tx(&prompt));
        session.data(channel, prompt)
    }

    fn hangup(&self, session: &mut Session) -> Result<(), russh::Error> {
        session.disconnect(Disconnect::ByApplication, "", "")
    }

    /// Finish a one-shot channel the way sshd does after a command exits.
    fn finish(&self, session: &mut Session, channel: ChannelId) -> Result<(), russh::Error> {
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)
    }

    /// Start a real shell (or, with `command`, a one-shot command) for
    /// `channel`. On failure the request is refused and the reason logged.
    async fn open_real(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        command: Option<String>,
    ) -> Result<(), russh::Error> {
        let log = self.driver.log().clone();
        let terminal = self.channels.get(&channel).and_then(|c| c.terminal.clone());
        let request = ShellRequest {
            session_id: self.session_id.clone(),
            user: self.user.clone().unwrap_or_default(),
            command,
            terminal,
        };
        let started = match &self.backend {
            Some(backend) => {
                RealShell::start(
                    backend.as_ref(),
                    request,
                    session.handle(),
                    channel,
                    log.clone(),
                )
                .await
            }
            None => Err(anyhow::anyhow!("no shell backend is configured")),
        };
        match started {
            Ok(shell) => {
                if let Some(chan) = self.channels.get_mut(&channel) {
                    chan.shell = Some(Shell::Real(shell));
                }
                Ok(())
            }
            Err(e) => {
                log.event(Record::Error {
                    error: format!("{e:#}"),
                });
                session.channel_failure(channel)
            }
        }
    }

    /// Run a command line through the behavior and carry out the reply.
    /// Returns `Flow::Close` if the behavior ended the session.
    async fn command(
        &mut self,
        session: &mut Session,
        channel: ChannelId,
        line: String,
        tty: bool,
    ) -> Result<Flow, russh::Error> {
        let actions = self.driver.react(&Event::Command(line)).into_actions();
        let mut out = ChannelOut { session, channel };
        let applied = apply(&mut out, self.driver.log(), actions, tty).await?;
        if applied.prompt.is_some() {
            self.prompt = applied.prompt;
        }
        Ok(applied.flow)
    }
}

impl Handler for Conn {
    type Error = russh::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>, Self::Error> {
        Ok(self.auth_banner.take())
    }

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.driver.log().event(Record::Auth {
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
        let verdict = self.driver.react(&event).verdict();
        // Log before any delay, so the attempt is captured even if the peer
        // gives up while waiting.
        self.driver.log().event(Record::Auth {
            user: user.into(),
            method: AuthMethod::Password,
            credential: password.into(),
            accepted: verdict.granted(),
        });
        tokio::time::sleep(verdict.delay).await;
        if verdict.close {
            return Err(russh::Error::Disconnect);
        }
        if !verdict.granted() {
            return Ok(reject());
        }
        // The name goes into the prompt, so strip terminal control bytes.
        self.user = Some(sanitize(user, MAX_NAME));
        self.real_shell = verdict.real_shell;
        self.welcome = verdict.welcome;
        self.prompt = verdict.prompt.map(|p| sanitize(&p, 256));
        Ok(Auth::Accept)
    }

    /// We never accept keys; we only record which ones are offered.
    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        offer: russh::server::PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        self.driver.log().event(Record::Auth {
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
        self.driver.log().event(Record::ChannelRequest {
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
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.driver.log().event(Record::ChannelRequest {
            request: ChannelRequestKind::Pty,
        });
        match self.channels.get_mut(&channel) {
            Some(chan) => {
                chan.terminal = Some(Terminal {
                    term: sanitize(term, MAX_NAME),
                    cols: u16::try_from(col_width).unwrap_or(u16::MAX),
                    rows: u16::try_from(row_height).unwrap_or(u16::MAX),
                });
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
        self.driver.log().event(Record::ChannelRequest {
            request: ChannelRequestKind::Shell,
        });
        let Some(chan) = self
            .channels
            .get_mut(&channel)
            .filter(|c| c.shell.is_none())
        else {
            return session.channel_failure(channel);
        };
        if self.real_shell {
            return self.open_real(session, channel, None).await;
        }
        let pty = chan.terminal.is_some();
        chan.shell = Some(Shell::Scripted(LineEditor::new(pty)));
        session.channel_success(channel)?;

        let welcome = std::mem::take(&mut self.welcome);
        if !welcome.is_empty() {
            let out = if pty { to_crlf(&welcome) } else { welcome };
            self.driver.log().event(Record::tx(&out));
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
        self.driver.log().event(Record::ChannelRequest {
            request: ChannelRequestKind::Exec,
        });
        if !self.channels.contains_key(&channel) {
            return session.channel_failure(channel);
        }
        let command = String::from_utf8_lossy(data).into_owned();
        self.driver.log().event(Record::Command {
            command: command.clone(),
            via: CommandSource::Exec,
        });
        if self.real_shell {
            return self.open_real(session, channel, Some(command)).await;
        }
        session.channel_success(channel)?;
        match self.command(session, channel, command, false).await? {
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
        self.driver.log().event(Record::ChannelRequest {
            request: ChannelRequestKind::Subsystem,
        });
        session.channel_failure(channel)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.driver.receive(data).is_err() {
            return self.hangup(session);
        }
        let Some(chan) = self.channels.get_mut(&channel) else {
            return Ok(());
        };
        let pty = chan.terminal.is_some();
        let editor = match chan.shell.as_mut() {
            None => return Ok(()),
            Some(Shell::Real(shell)) => {
                shell.send(data).await;
                return Ok(());
            }
            Some(Shell::Scripted(editor)) => editor,
        };

        for edit in editor.feed(data) {
            match edit {
                // Echo is derivable from the logged input, so it is not logged.
                Edit::Echo(bytes) => session.data(channel, bytes)?,
                Edit::Line(bytes) => {
                    let command = String::from_utf8_lossy(&bytes).into_owned();
                    self.driver.log().event(Record::Command {
                        command: command.clone(),
                        via: CommandSource::Shell,
                    });
                    if self.command(session, channel, command, pty).await? == Flow::Close {
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
        match self
            .channels
            .get_mut(&channel)
            .and_then(|c| c.shell.as_mut())
        {
            // the sandbox's shell sees end of file and ends the channel itself
            Some(Shell::Real(shell)) => shell.end_input().await,
            Some(Shell::Scripted(_)) => self.finish(session, channel)?,
            None => {}
        }
        Ok(())
    }
}
