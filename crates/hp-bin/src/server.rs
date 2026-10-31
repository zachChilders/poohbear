//! Accept loop and per-session supervision: connection cap, timeout and
//! panic isolation, so one bad session can never take down the listener.

use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt;
use hp_core::{AsyncStream, Limits, Persona, Protocol, SessionCtx};
use hp_log::LogSink;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

pub struct Server {
    pub proto: Arc<dyn Protocol>,
    pub sink: LogSink,
    pub limits: Limits,
    pub persona: Persona,
    pub permits: Arc<Semaphore>,
}

impl Server {
    pub fn new(
        proto: Arc<dyn Protocol>,
        sink: LogSink,
        limits: Limits,
        persona: Persona,
        max_sessions: usize,
    ) -> Arc<Server> {
        Arc::new(Server {
            proto,
            sink,
            limits,
            persona,
            permits: Arc::new(Semaphore::new(max_sessions)),
        })
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
            log.record("rejected", json!({ "reason": "max_sessions" }));
            return;
        };
        let ctx = SessionCtx {
            session_id: id,
            peer,
            log: log.clone(),
            persona: self.persona.clone(),
            limits: self.limits.clone(),
        };
        tokio::spawn(async move {
            let _permit = permit;
            log.event("connect");
            let run = AssertUnwindSafe(self.proto.handle(Box::new(stream), ctx)).catch_unwind();
            match tokio::time::timeout(self.limits.session_timeout, run).await {
                Err(_) => log.event("timeout"),
                Ok(Err(_)) => log.event("panic"),
                Ok(Ok(Err(e))) => log.record("error", json!({ "error": e.to_string() })),
                Ok(Ok(Ok(()))) => {}
            }
            log.event("disconnect");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
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
        let (sink, rx) = LogSink::channel(64);
        let limits = Limits {
            session_timeout: timeout,
            max_input_bytes: 1024,
        };
        let server = Server::new(
            Arc::new(Test(mode)),
            sink,
            limits,
            Persona::default(),
            max_sessions,
        );
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
