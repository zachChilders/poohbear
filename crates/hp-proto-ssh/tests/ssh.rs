//! Protocol-level tests: a real `russh` client talks to `Ssh::handle` over an
//! in-memory stream, with a scripted `Behavior` standing in for the track.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use hp_core::{Action, Event, Protocol};
use hp_proto_ssh::Ssh;
use hp_testkit::{conformance, of_kind, send, session, CtxOptions, FakeBackend, Observer, Script};
use russh::client;
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};
use russh::{Channel, ChannelMsg};
use serde_json::Value;
use tokio::task::JoinHandle;

const WAIT: Duration = Duration::from_secs(10);

// ------------------------------------------------------------ behaviors

/// Accepts the password `letmein` (with a welcome message); answers a few commands.
fn script(event: &Event) -> Vec<Action> {
    match event {
        Event::AuthAttempt { secret, .. } if secret.expose() == "letmein" => {
            vec![Action::AuthResult(true), send("Welcome\n")]
        }
        Event::AuthAttempt { .. } => vec![Action::AuthResult(false)],
        Event::Command(c) => match c.as_str() {
            "whoami" => vec![send("admin\n")],
            "bye" => vec![send("goodbye\n"), Action::Close],
            _ => vec![send("not found\n")],
        },
        _ => vec![],
    }
}

// -------------------------------------------------------------- harness

struct Client {
    banner: Arc<Mutex<String>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn auth_banner(
        &mut self,
        banner: &str,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.banner.lock().unwrap().push_str(banner);
        Ok(())
    }
}

struct Harness {
    client: client::Handle<Client>,
    obs: Observer,
    banner: Arc<Mutex<String>>,
    server: JoinHandle<anyhow::Result<()>>,
}

struct Opts {
    script: Script,
    hostname: Option<&'static str>,
    max_input_bytes: u64,
    backend: Option<Arc<FakeBackend>>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            script,
            hostname: Some("plc-gw-03"),
            max_input_bytes: 1 << 20,
            backend: None,
        }
    }
}

async fn start(opts: Opts) -> Harness {
    try_start(opts).await.expect("client connects")
}

async fn try_start(opts: Opts) -> Result<Harness, russh::Error> {
    let (ctx, obs) = session(CtxOptions {
        script: opts.script,
        hostname: opts.hostname,
        max_input_bytes: opts.max_input_bytes,
        ..CtxOptions::default()
    });
    let (server_io, client_io) = tokio::io::duplex(1 << 16);
    let mut ssh = Ssh::new(Some("SSH-2.0-OpenSSH_8.9p1 Test")).unwrap();
    if let Some(backend) = opts.backend {
        ssh = ssh.with_shell_backend(backend);
    }
    let server = tokio::spawn(async move { ssh.handle(Box::new(server_io), ctx).await });

    let banner = Arc::new(Mutex::new(String::new()));
    let handler = Client {
        banner: banner.clone(),
    };
    let client =
        client::connect_stream(Arc::new(client::Config::default()), client_io, handler).await?;
    Ok(Harness {
        client,
        obs,
        banner,
        server,
    })
}

impl Harness {
    async fn login(&mut self) {
        let r = self
            .client
            .authenticate_password("root", "letmein")
            .await
            .unwrap();
        assert!(r.success(), "login should succeed");
    }

    /// Finish the connection and return every session record, in order.
    async fn finish(mut self) -> (Vec<Value>, Vec<String>) {
        let _ = self
            .client
            .disconnect(russh::Disconnect::ByApplication, "", "")
            .await;
        let result = tokio::time::timeout(WAIT, self.server)
            .await
            .expect("server stops")
            .unwrap();
        assert!(result.is_ok(), "{result:?}");
        let records = self.obs.records();
        // Every protocol must satisfy the shared rules; check them on each session.
        conformance::envelope(&records);
        conformance::lifecycle(&self.obs.seen);
        let seen = self.obs.seen.all();
        (records, seen)
    }
}

/// Read channel data until `needle` has been seen; returns everything read.
async fn read_until(ch: &mut Channel<client::Msg>, needle: &str) -> String {
    let mut got = Vec::new();
    tokio::time::timeout(WAIT, async {
        while !String::from_utf8_lossy(&got).contains(needle) {
            match ch.wait().await {
                Some(ChannelMsg::Data { data }) => got.extend_from_slice(&data),
                Some(_) => {}
                None => break,
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&got)
        )
    });
    String::from_utf8_lossy(&got).into_owned()
}

/// Read until the channel closes; returns (output, exit status).
async fn read_to_close(ch: &mut Channel<client::Msg>) -> (String, Option<u32>) {
    let mut got = Vec::new();
    let mut status = None;
    tokio::time::timeout(WAIT, async {
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => got.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    })
    .await
    .expect("channel closes");
    (String::from_utf8_lossy(&got).into_owned(), status)
}

// ---------------------------------------------------------------- tests

#[tokio::test]
async fn password_attempts_are_judged_by_the_behavior_and_logged_in_full() {
    let mut h = start(Opts::default()).await;
    assert!(!h
        .client
        .authenticate_password("root", "123456")
        .await
        .unwrap()
        .success());
    assert!(h
        .client
        .authenticate_password("root", "letmein")
        .await
        .unwrap()
        .success());
    let (records, seen) = h.finish().await;

    let auth: Vec<_> = of_kind(&records, "auth")
        .into_iter()
        .filter(|r| r["method"] == "password")
        .collect();
    assert_eq!(auth.len(), 2);
    assert_eq!(
        (
            auth[0]["user"].as_str(),
            auth[0]["credential"].as_str(),
            &auth[0]["accepted"]
        ),
        (Some("root"), Some("123456"), &Value::Bool(false))
    );
    assert_eq!(
        (auth[1]["credential"].as_str(), &auth[1]["accepted"]),
        (Some("letmein"), &Value::Bool(true))
    );
    assert_eq!(seen.first().map(String::as_str), Some("Connected"));
    assert_eq!(seen.iter().filter(|s| s.starts_with("auth:")).count(), 2);
    assert_eq!(
        seen.last().map(String::as_str),
        Some("Disconnected"),
        "{seen:?}"
    );
}

/// Regression: after a rejected password the server must keep offering
/// `password`. Clients like paramiko and hydra trust this list and give up
/// otherwise, which would cap a brute-forcer at one password per connection.
#[tokio::test]
async fn a_rejection_keeps_every_method_on_offer() {
    let mut h = start(Opts::default()).await;
    for pw in ["a", "b", "c"] {
        let result = h.client.authenticate_password("root", pw).await.unwrap();
        let russh::client::AuthResult::Failure {
            remaining_methods, ..
        } = result
        else {
            panic!("expected a rejection");
        };
        let offered: Vec<_> = remaining_methods.iter().cloned().collect();
        assert!(
            offered.contains(&russh::MethodKind::Password),
            "after {pw:?}: {offered:?}"
        );
        assert!(
            offered.contains(&russh::MethodKind::PublicKey),
            "after {pw:?}: {offered:?}"
        );
    }
}

#[tokio::test]
async fn exec_runs_one_command_and_exits_zero() {
    let mut h = start(Opts::default()).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.exec(true, "whoami").await.unwrap();
    let (out, status) = read_to_close(&mut ch).await;
    assert_eq!(out, "admin\n", "exec output is not tty-translated");
    assert_eq!(status, Some(0));
    let (records, seen) = h.finish().await;
    let cmds = of_kind(&records, "command");
    assert_eq!(
        (cmds[0]["command"].as_str(), cmds[0]["via"].as_str()),
        (Some("whoami"), Some("exec"))
    );
    assert!(seen.contains(&"cmd:whoami".to_string()));
}

#[tokio::test]
async fn interactive_shell_has_welcome_prompt_echo_and_tty_newlines() {
    let mut h = start(Opts::default()).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();

    assert_eq!(
        read_until(&mut ch, "$ ").await,
        "Welcome\r\nroot@plc-gw-03:~$ "
    );
    ch.data_bytes(&b"whoami\r"[..]).await.unwrap();
    assert_eq!(
        read_until(&mut ch, "$ ").await,
        "whoami\r\nadmin\r\nroot@plc-gw-03:~$ "
    );

    // Backspace edits the line before it is submitted.
    ch.data_bytes(&b"whoamX\x7fi\r"[..]).await.unwrap();
    let out = read_until(&mut ch, "$ ").await;
    assert!(out.ends_with("admin\r\nroot@plc-gw-03:~$ "), "{out:?}");

    // Ctrl-C abandons the line and redraws the prompt.
    ch.data_bytes(&b"rm -rf /\x03"[..]).await.unwrap();
    assert!(read_until(&mut ch, "$ ")
        .await
        .ends_with("^C\r\nroot@plc-gw-03:~$ "));

    let (records, seen) = h.finish().await;
    let shell_cmds: Vec<_> = of_kind(&records, "command")
        .iter()
        .map(|r| r["command"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        shell_cmds,
        ["whoami", "whoami"],
        "the abandoned line is never a command"
    );
    assert!(!seen.iter().any(|s| s.contains("rm -rf")));
    let requests: Vec<_> = of_kind(&records, "channel_request")
        .iter()
        .map(|r| r["request"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(requests, ["pty", "shell"]);
    assert!(
        of_kind(&records, "rx").len() >= 3,
        "keystrokes are captured"
    );
}

#[tokio::test]
async fn piped_shell_has_no_echo_or_prompt_and_exits_on_eof() {
    let mut h = start(Opts::default()).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    ch.data_bytes(&b"whoami\nnope\n"[..]).await.unwrap();
    ch.eof().await.unwrap();
    let (out, status) = read_to_close(&mut ch).await;
    assert_eq!(out, "Welcome\nadmin\nnot found\n");
    assert_eq!(status, Some(0));
    h.finish().await;
}

#[tokio::test]
async fn ctrl_d_on_an_empty_line_logs_out() {
    let mut h = start(Opts::default()).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();
    read_until(&mut ch, "$ ").await;
    ch.data_bytes(&b"\x04"[..]).await.unwrap();
    tokio::time::timeout(WAIT, h.server)
        .await
        .expect("server ends the session")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn a_close_action_ends_the_session_after_its_output() {
    let mut h = start(Opts::default()).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();
    read_until(&mut ch, "$ ").await;
    ch.data_bytes(&b"bye\r"[..]).await.unwrap();
    assert!(read_until(&mut ch, "goodbye").await.contains("goodbye\r\n"));
    tokio::time::timeout(WAIT, h.server)
        .await
        .expect("server ends the session")
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn public_keys_are_recorded_but_never_accepted() {
    let mut h = start(Opts::default()).await;
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let r = h
        .client
        .authenticate_publickey("root", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .unwrap();
    assert!(!r.success());
    let (records, seen) = h.finish().await;
    let keys: Vec<_> = of_kind(&records, "auth")
        .into_iter()
        .filter(|r| r["method"] == "public_key")
        .collect();
    assert_eq!(keys.len(), 1);
    assert!(keys[0]["credential"]
        .as_str()
        .unwrap()
        .starts_with("SHA256:"));
    assert_eq!(keys[0]["accepted"], false);
    assert!(
        !seen.iter().any(|s| s.starts_with("auth:")),
        "keys never reach the behavior"
    );
}

#[tokio::test]
async fn forwarding_and_subsystems_are_refused_and_logged() {
    let mut h = start(Opts::default()).await;
    h.login().await;
    assert!(h
        .client
        .channel_open_direct_tcpip("10.0.0.5", 22, "127.0.0.1", 9)
        .await
        .is_err());

    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_subsystem(true, "sftp").await.unwrap();
    let refused = tokio::time::timeout(WAIT, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Failure) => return true,
                Some(ChannelMsg::Success) | None => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(refused, "sftp must be refused");

    let (records, _) = h.finish().await;
    let kinds: Vec<_> = of_kind(&records, "channel_request")
        .iter()
        .map(|r| r["request"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["port_forward", "subsystem"]);
}

#[tokio::test]
async fn oversized_input_is_cut_off_and_logged() {
    let mut h = start(Opts {
        max_input_bytes: 32,
        ..Opts::default()
    })
    .await;
    h.login().await;
    let ch = h.client.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    ch.data_bytes(vec![b'A'; 200]).await.unwrap();
    tokio::time::timeout(WAIT, h.server)
        .await
        .expect("server cuts the session")
        .unwrap()
        .unwrap();
    let records = h.obs.records();
    conformance::input_cap_enforced(&records, 32);
    assert!(
        of_kind(&records, "rx").is_empty(),
        "over-limit input is not logged as rx"
    );
}

#[tokio::test]
async fn hostile_usernames_cannot_inject_terminal_escapes_into_the_prompt() {
    let mut h = start(Opts::default()).await;
    assert!(h
        .client
        .authenticate_password("a\x1b[2Jb", "letmein")
        .await
        .unwrap()
        .success());
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();
    let out = read_until(&mut ch, "$ ").await;
    assert!(!out.contains('\x1b'), "{out:?}");
    assert!(out.contains("a?[2Jb@plc-gw-03"), "{out:?}");
}

#[tokio::test]
async fn missing_hostname_falls_back_to_localhost() {
    let mut h = start(Opts {
        hostname: None,
        ..Opts::default()
    })
    .await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();
    assert!(read_until(&mut ch, "$ ")
        .await
        .ends_with("root@localhost:~$ "));
}

#[tokio::test]
async fn text_sent_on_connect_becomes_the_pre_auth_banner() {
    let mut h = start(Opts {
        script: |e| match e {
            Event::Connected => vec![send("Authorized use only\n")],
            other => script(other),
        },
        ..Opts::default()
    })
    .await;
    h.login().await;
    assert_eq!(*h.banner.lock().unwrap(), "Authorized use only\r\n");
}

#[tokio::test]
async fn a_behavior_can_refuse_the_connection_outright() {
    let h = try_start(Opts {
        script: |e| match e {
            Event::Connected => vec![Action::Close],
            _ => vec![],
        },
        ..Opts::default()
    })
    .await;
    assert!(h.is_err(), "no SSH handshake happens");
}

#[tokio::test]
async fn a_behavior_can_drop_the_connection_during_auth() {
    let mut h = start(Opts {
        script: |e| match e {
            Event::AuthAttempt { .. } => vec![Action::Close],
            _ => vec![],
        },
        ..Opts::default()
    })
    .await;
    let r = h.client.authenticate_password("root", "x").await;
    assert!(r.is_err() || !r.unwrap().success());
    let (records, _) = h.finish().await;
    assert_eq!(of_kind(&records, "auth")[0]["accepted"], false);
}

#[tokio::test]
async fn the_prompt_comes_from_the_behavior_and_follows_it() {
    let mut h = start(Opts {
        script: |e| match e {
            Event::AuthAttempt { .. } => {
                vec![Action::AuthResult(true), Action::Prompt("[start] ".into())]
            }
            Event::Command(c) if c == "cd" => vec![Action::Prompt("[tmp] ".into())],
            _ => vec![],
        },
        ..Opts::default()
    })
    .await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();
    assert_eq!(
        read_until(&mut ch, "] ").await,
        "[start] ",
        "the first prompt is the one sent with the login"
    );
    ch.data_bytes(&b"cd\r"[..]).await.unwrap();
    assert_eq!(read_until(&mut ch, "] ").await, "cd\r\n[tmp] ");
    ch.data_bytes(&b"anything\r"[..]).await.unwrap();
    assert!(
        read_until(&mut ch, "] ").await.ends_with("[tmp] "),
        "a behavior that says nothing leaves the prompt alone"
    );
    h.finish().await;
}

#[tokio::test]
async fn a_hostile_prompt_cannot_carry_terminal_escapes() {
    let mut h = start(Opts {
        script: |e| match e {
            Event::AuthAttempt { .. } => vec![
                Action::AuthResult(true),
                Action::Prompt("\x1b[2J\x07evil$ ".into()),
            ],
            _ => vec![],
        },
        ..Opts::default()
    })
    .await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();
    let prompt = read_until(&mut ch, "$ ").await;
    assert_eq!(prompt, "?[2J?evil$ ");
}

#[tokio::test]
async fn exec_ignores_prompts() {
    let mut h = start(Opts {
        script: |e| match e {
            Event::Command(_) => vec![send("out\n"), Action::Prompt("[p] ".into())],
            other => script(other),
        },
        ..Opts::default()
    })
    .await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.exec(true, "x").await.unwrap();
    let (out, status) = read_to_close(&mut ch).await;
    assert_eq!(
        (out.as_str(), status),
        ("out\n", Some(0)),
        "no prompt without a shell"
    );
}

// ------------------------------------------------------------ real shells

/// A behavior that lets everyone in and hands them a real shell.
fn grants_a_real_shell(e: &Event) -> Vec<Action> {
    match e {
        Event::AuthAttempt { .. } => vec![Action::AuthResult(true), Action::OpenShell],
        _ => vec![],
    }
}

fn real_shell_opts(backend: &Arc<FakeBackend>) -> Opts {
    Opts {
        script: grants_a_real_shell,
        backend: Some(backend.clone()),
        ..Opts::default()
    }
}

fn echoing_backend() -> Arc<FakeBackend> {
    FakeBackend::new(|l| (l != "exit").then(|| format!("ran {l}\n")))
}

#[tokio::test]
async fn a_real_shell_is_bridged_both_ways_and_every_byte_is_logged() {
    let backend = echoing_backend();
    let mut h = start(real_shell_opts(&backend)).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 100, 30, 0, 0, &[])
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();

    // the shell's own prompt, with nothing added by the plugin
    assert_eq!(read_until(&mut ch, "$ ").await, "fake$ ");
    ch.data_bytes(&b"whoami\r"[..]).await.unwrap();
    assert_eq!(read_until(&mut ch, "$ ").await, "ran whoami\nfake$ ");
    ch.data_bytes(&b"exit\r"[..]).await.unwrap();
    let (_, status) = read_to_close(&mut ch).await;
    assert_eq!(status, Some(0));

    let requests = backend.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        (requests[0].user.as_str(), requests[0].command.as_deref()),
        ("root", None)
    );
    let t = requests[0].terminal.as_ref().unwrap();
    assert_eq!((t.term.as_str(), t.cols, t.rows), ("xterm", 100, 30));

    let (records, seen) = h.finish().await;
    let sent: String = of_kind(&records, "rx")
        .iter()
        .map(|r| r["text"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(sent, "whoami.exit.", "keystrokes are captured");
    assert!(
        of_kind(&records, "tx")
            .iter()
            .any(|r| r["text"] == "ran whoami.fake$ "),
        "so is the shell's output"
    );
    assert!(
        of_kind(&records, "command").is_empty(),
        "the behavior is not asked about commands"
    );
    assert_eq!(seen, ["Connected", "auth:root", "Disconnected"]);
}

#[tokio::test]
async fn a_real_one_shot_command_runs_in_the_sandbox() {
    let backend = FakeBackend::new(|c| Some(format!("ran {c}\n")));
    let mut h = start(real_shell_opts(&backend)).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.exec(true, "id -u").await.unwrap();
    assert_eq!(
        read_to_close(&mut ch).await,
        ("ran id -u\n".to_string(), Some(0))
    );
    let requests = backend.requests();
    assert_eq!(
        (
            requests[0].command.as_deref(),
            requests[0].terminal.is_none()
        ),
        (Some("id -u"), true)
    );
    let (records, _) = h.finish().await;
    let cmds = of_kind(&records, "command");
    assert_eq!(
        (cmds[0]["command"].as_str(), cmds[0]["via"].as_str()),
        (Some("id -u"), Some("exec"))
    );
}

#[tokio::test]
async fn closing_the_clients_input_ends_the_shell() {
    let backend = echoing_backend();
    let mut h = start(real_shell_opts(&backend)).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    ch.data_bytes(&b"hostname\n"[..]).await.unwrap();
    ch.eof().await.unwrap();
    let (out, status) = read_to_close(&mut ch).await;
    assert_eq!(
        (out.as_str(), status),
        ("fake$ ran hostname\nfake$ ", Some(0))
    );
    h.finish().await;
}

#[tokio::test]
async fn the_sandbox_is_released_when_the_connection_ends() {
    let backend = echoing_backend();
    let mut h = start(real_shell_opts(&backend)).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    read_until(&mut ch, "$ ").await;
    assert_eq!(backend.live(), 1);
    h.finish().await;
    for _ in 0..100 {
        if backend.live() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the sandbox outlived its session");
}

#[tokio::test]
async fn input_to_a_real_shell_counts_against_the_cap() {
    let backend = echoing_backend();
    let mut h = start(Opts {
        max_input_bytes: 16,
        ..real_shell_opts(&backend)
    })
    .await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    read_until(&mut ch, "$ ").await;
    ch.data_bytes(vec![b'A'; 200]).await.unwrap();
    tokio::time::timeout(WAIT, h.server)
        .await
        .expect("session is cut")
        .unwrap()
        .unwrap();
    let records = h.obs.records();
    conformance::input_cap_enforced(&records, 16);
}

#[tokio::test]
async fn without_a_backend_a_real_shell_is_refused_and_logged() {
    let mut h = start(Opts {
        script: grants_a_real_shell,
        ..Opts::default()
    })
    .await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    assert!(refused(&mut ch).await);
    let (records, _) = h.finish().await;
    assert!(of_kind(&records, "error")[0]["error"]
        .as_str()
        .unwrap()
        .contains("no shell backend"));
}

#[tokio::test]
async fn a_backend_that_cannot_start_a_sandbox_refuses_the_request() {
    let backend = FakeBackend::failing();
    let mut h = start(real_shell_opts(&backend)).await;
    h.login().await;
    let mut ch = h.client.channel_open_session().await.unwrap();
    ch.exec(true, "id").await.unwrap();
    assert!(refused(&mut ch).await);
    let (records, _) = h.finish().await;
    assert!(of_kind(&records, "error")[0]["error"]
        .as_str()
        .unwrap()
        .contains("no sandbox available"));
}

/// Wait for the server to refuse a channel request.
async fn refused(ch: &mut Channel<client::Msg>) -> bool {
    tokio::time::timeout(WAIT, async {
        loop {
            match ch.wait().await {
                Some(ChannelMsg::Failure) => return true,
                Some(ChannelMsg::Success) | None => return false,
                Some(_) => {}
            }
        }
    })
    .await
    .unwrap()
}
