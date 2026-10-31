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
