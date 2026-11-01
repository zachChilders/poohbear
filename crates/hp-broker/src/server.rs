//! The broker's socket: one connection per shell. It admits, plans, starts,
//! bridges, bounds and ends sandboxes, and never lets one outlive its
//! connection or its time limit.

use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use hp_sandbox::proto::{read_json, write_json, Request, Response};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::launch::{plan, Rejected};
use crate::policy::Policy;
use crate::runner::Runner;

/// A peer has this long to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Starting a sandbox is bounded, whatever the runtime does.
const START_TIMEOUT: Duration = Duration::from_secs(90);

pub struct Broker {
    policy: Policy,
    runner: Arc<dyn Runner>,
    permits: Arc<Semaphore>,
}

/// Listen on the policy's socket, replacing a stale one left by a crash.
pub fn bind(policy: &Policy) -> anyhow::Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    let path = &policy.socket;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        anyhow::ensure!(
            meta.file_type().is_socket(),
            "{} exists and is not a socket",
            path.display()
        );
        std::fs::remove_file(path)
            .with_context(|| format!("removing the stale socket {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(policy.socket_mode()))
        .with_context(|| format!("setting permissions on {}", path.display()))?;
    Ok(listener)
}

impl Broker {
    pub fn new(policy: Policy, runner: Arc<dyn Runner>) -> Arc<Broker> {
        let permits = Arc::new(Semaphore::new(policy.max_sandboxes));
        Arc::new(Broker {
            policy,
            runner,
            permits,
        })
    }

    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            match listener.accept().await {
                Ok((conn, _)) => {
                    let broker = self.clone();
                    tokio::spawn(async move { broker.handle(conn).await });
                }
                Err(e) => {
                    warn!(error = %e, "accept failed");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle(&self, mut conn: UnixStream) {
        // Admission first: a flood costs a refusal, not a sandbox.
        let Ok(_permit) = self.permits.clone().try_acquire_owned() else {
            warn!("at capacity; refusing");
            return refuse(&mut conn, "busy").await;
        };
        let request: Request = match timeout(REQUEST_TIMEOUT, read_json(&mut conn)).await {
            Ok(Ok(r)) => r,
            other => {
                warn!(error = ?other.err(), "unreadable request");
                return refuse(&mut conn, "bad request").await;
            }
        };
        let name = format!("hp-{}", uuid::Uuid::new_v4().simple());
        let spec = match plan(&self.policy, &request, &name) {
            Ok(spec) => spec,
            Err(Rejected(why)) => {
                warn!(why, "request rejected");
                return refuse(&mut conn, "rejected").await;
            }
        };
        let started = Instant::now();
        let running = match timeout(START_TIMEOUT, self.runner.start(&spec)).await {
            Ok(Ok(running)) => running,
            failure => {
                // The details are for the operator; the peer learns nothing.
                warn!(sandbox = %name, error = %failure.err().map_or_else(|| "timed out".to_string(), |e| format!("{e:#}")), "could not start a sandbox");
                self.runner.discard(&name).await;
                return refuse(&mut conn, "unavailable").await;
            }
        };
        info!(sandbox = %name, session = %request.session_id, "sandbox started");

        if write_json(&mut conn, &Response::ok()).await.is_ok() {
            // Bounded, whatever the shell is doing.
            let _ = timeout(
                self.policy.session_timeout(),
                bridge(conn, running.io, self.policy.linger()),
            )
            .await;
        }
        running.stop.stop().await;
        info!(sandbox = %name, seconds = started.elapsed().as_secs(), "sandbox ended");
    }
}

async fn refuse(conn: &mut UnixStream, reason: &str) {
    let _ = write_json(conn, &Response::refused(reason)).await;
}

/// Has the peer closed the connection entirely? Writing to a fully closed
/// unix socket fails, even with nothing to write. A peer that only closed
/// its sending side (`echo cmd | ssh host`) still wants the shell's output,
/// so this stays false for it.
fn peer_gone(watcher: &std::fs::File) -> bool {
    use std::io::Write;
    (&*watcher)
        .write(&[])
        .is_err_and(|e| e.kind() != std::io::ErrorKind::WouldBlock)
}

/// Carry bytes both ways until the shell is done. When the peer stops
/// sending, the shell gets end of file. If the peer then hangs up, the
/// sandbox is ended at once; if it only closed its input, the shell has
/// `linger` to finish. Either way, a shell is not left running for no one.
async fn bridge(conn: UnixStream, sandbox: Box<dyn hp_core::AsyncStream>, linger: Duration) {
    // A duplicate of the socket, only to watch for the peer hanging up.
    let watcher = conn
        .as_fd()
        .try_clone_to_owned()
        .ok()
        .map(std::fs::File::from);
    let (mut from_peer, mut to_peer) = conn.into_split();
    let (mut from_shell, mut to_shell): (ReadHalf<_>, WriteHalf<_>) = tokio::io::split(sandbox);
    let upstream = async {
        let _ = tokio::io::copy(&mut from_peer, &mut to_shell).await;
        let _ = to_shell.shutdown().await;
        let deadline = tokio::time::Instant::now() + linger;
        while tokio::time::Instant::now() < deadline && !watcher.as_ref().is_some_and(peer_gone) {
            sleep(Duration::from_millis(200)).await;
        }
    };
    let downstream = async {
        let _ = tokio::io::copy(&mut from_shell, &mut to_peer).await;
        let _ = to_peer.shutdown().await;
    };
    tokio::select! {
        () = upstream => {}
        () = downstream => {}
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use hp_core::{ShellBackend, ShellRequest};
    use hp_sandbox::ContainerBackend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::fake::FakeRunner;
    use crate::launch::Spec;
    use crate::runner::{Running, Stop};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn request(command: Option<&str>) -> ShellRequest {
        ShellRequest {
            session_id: "s1".into(),
            user: "root".into(),
            command: command.map(String::from),
            terminal: None,
        }
    }

    /// A broker on a fresh socket. `extra` is more policy YAML.
    fn start(extra: &str, runner: Arc<dyn Runner>) -> (PathBuf, Arc<Broker>) {
        let socket = std::env::temp_dir().join(format!(
            "hp-broker-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let policy = Policy::parse(&format!(
            "socket: {}\nimage: honeypot/test:1\nhostname: plc-gw-03\n{extra}",
            socket.display()
        ))
        .unwrap();
        let listener = bind(&policy).unwrap();
        let broker = Broker::new(policy, runner);
        tokio::spawn(broker.clone().serve(listener));
        (socket, broker)
    }

    async fn eventually(what: &str, mut ok: impl FnMut() -> bool) {
        for _ in 0..200 {
            if ok() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {what}");
    }

    fn echo() -> Arc<FakeRunner> {
        FakeRunner::new(|l| (l != "exit").then(|| format!("ran {l}\n")))
    }

    #[tokio::test]
    async fn a_shell_is_served_hardened_and_ended_with_the_connection() {
        let runner = echo();
        let (socket, _) = start("", runner.clone());
        let mut shell = ContainerBackend::new(&socket)
            .start(request(None))
            .await
            .unwrap();
        let mut buf = [0u8; 6];
        shell.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"fake$ ");
        shell.write_all(b"id\n").await.unwrap();
        let mut out = [0u8; 13];
        shell.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ran id\nfake$ ");
        assert_eq!(runner.live(), 1);

        let args = &runner.specs()[0];
        assert!(
            args.windows(2).any(|w| w == ["--network", "none"])
                && args.contains(&"--read-only".to_string())
        );

        drop(shell);
        eventually("the sandbox to be stopped", || runner.stopped() == 1).await;
        eventually("the shell to end", || runner.live() == 0).await;
    }

    #[tokio::test]
    async fn one_shot_commands_run_and_the_stream_ends() {
        let runner = FakeRunner::new(|c| Some(format!("ran {c}\n")));
        let (socket, _) = start("", runner.clone());
        let mut shell = ContainerBackend::new(&socket)
            .start(request(Some("uname -a")))
            .await
            .unwrap();
        let mut out = String::new();
        shell.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "ran uname -a\n");
        eventually("the sandbox to be stopped", || runner.stopped() == 1).await;
    }

    #[tokio::test]
    async fn capacity_is_enforced_and_freed() {
        let runner = echo();
        let (socket, _) = start("max_sandboxes: 1\n", runner.clone());
        let backend = ContainerBackend::new(&socket);
        let first = backend.start(request(None)).await.unwrap();
        let err = backend.start(request(None)).await.err().unwrap();
        assert!(format!("{err:#}").contains("refused: busy"), "{err:#}");
        assert_eq!(
            runner.specs().len(),
            1,
            "the refused request started nothing"
        );
        drop(first);
        eventually("the slot to be freed", || runner.stopped() == 1).await;
        assert!(
            backend.start(request(None)).await.is_ok(),
            "a freed slot is reusable"
        );
    }

    #[tokio::test]
    async fn garbage_and_unacceptable_requests_start_nothing() {
        let runner = echo();
        let (socket, _) = start("", runner.clone());
        let ask = |bytes: &'static [u8]| {
            let socket = socket.clone();
            async move {
                let mut c = tokio::net::UnixStream::connect(socket).await.unwrap();
                c.write_all(bytes).await.unwrap();
                let reply: Response = read_json(&mut c).await.unwrap();
                reply
            }
        };
        assert_eq!(
            ask(b"not json at all\n").await,
            Response::refused("bad request")
        );
        assert_eq!(
            ask(b"{\"session_id\":1}\n").await,
            Response::refused("bad request")
        );
        let nul = ask(b"{\"session_id\":\"s\",\"user\":\"root\",\"command\":\"a\\u0000b\",\"terminal\":null}\n").await;
        assert_eq!(nul, Response::refused("rejected"));
        assert!(runner.specs().is_empty());
    }

    #[tokio::test]
    async fn a_silent_peer_is_dropped_and_holds_no_slot() {
        let runner = echo();
        let (socket, _) = start("max_sandboxes: 1\n", runner.clone());
        let _silent = tokio::net::UnixStream::connect(&socket).await.unwrap();
        // the lone slot is held only while a request is being read, and only for REQUEST_TIMEOUT
        sleep(REQUEST_TIMEOUT + Duration::from_millis(300)).await;
        assert!(ContainerBackend::new(&socket)
            .start(request(None))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_failing_runtime_is_refused_without_leaking_why() {
        let runner = FakeRunner::failing();
        let (socket, _) = start("", runner.clone());
        let err = format!(
            "{:#}",
            ContainerBackend::new(&socket)
                .start(request(None))
                .await
                .err()
                .unwrap()
        );
        assert!(err.contains("refused: unavailable"), "{err}");
        assert!(
            !err.contains("docker") && !err.contains("image"),
            "infrastructure details reached the peer: {err}"
        );
        assert_eq!(
            runner.discarded().len(),
            1,
            "whatever was half-created is cleaned up"
        );
        assert!(runner.discarded()[0].starts_with("hp-"));
    }

    /// A runner whose shell never ends by itself and ignores end of input.
    struct Stubborn(Arc<AtomicUsize>);

    struct CountStop(Arc<AtomicUsize>);
    #[async_trait]
    impl Stop for CountStop {
        async fn stop(self: Box<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl Runner for Stubborn {
        async fn start(&self, _: &Spec) -> anyhow::Result<Running> {
            let (io, shell) = tokio::io::duplex(1024);
            tokio::spawn(async move {
                let _keep_open = shell;
                sleep(Duration::from_secs(60)).await;
            });
            Ok(Running {
                io: Box::new(io),
                stop: Box::new(CountStop(self.0.clone())),
            })
        }
    }

    #[tokio::test]
    async fn a_sandbox_cannot_outlive_the_session_timeout() {
        let stopped = Arc::new(AtomicUsize::new(0));
        let (socket, _) = start(
            "session_timeout: 300ms\n",
            Arc::new(Stubborn(stopped.clone())),
        );
        let mut shell = ContainerBackend::new(&socket)
            .start(request(None))
            .await
            .unwrap();
        let mut rest = Vec::new();
        shell.read_to_end(&mut rest).await.unwrap(); // the broker closes the connection
        eventually("the sandbox to be stopped", || {
            stopped.load(Ordering::SeqCst) == 1
        })
        .await;
    }

    #[tokio::test]
    async fn a_shell_that_ignores_end_of_input_is_stopped_after_the_linger() {
        let stopped = Arc::new(AtomicUsize::new(0));
        let (socket, _) = start("linger: 200ms\n", Arc::new(Stubborn(stopped.clone())));
        let mut shell = ContainerBackend::new(&socket)
            .start(request(None))
            .await
            .unwrap();
        shell.shutdown().await.unwrap(); // the peer will send nothing more
        assert_eq!(
            stopped.load(Ordering::SeqCst),
            0,
            "not instantly: output may still be on its way"
        );
        eventually("the linger to expire", || {
            stopped.load(Ordering::SeqCst) == 1
        })
        .await;
    }

    #[tokio::test]
    async fn a_hung_up_peer_stops_the_sandbox_promptly_but_a_half_closed_one_does_not() {
        let stopped = Arc::new(AtomicUsize::new(0));
        let (socket, _) = start("linger: 30s\n", Arc::new(Stubborn(stopped.clone())));
        let backend = ContainerBackend::new(&socket);

        let mut half = backend.start(request(None)).await.unwrap();
        half.shutdown().await.unwrap();
        sleep(Duration::from_millis(700)).await;
        assert_eq!(
            stopped.load(Ordering::SeqCst),
            0,
            "input closed, but the peer still wants the output"
        );

        drop(half); // now it hangs up entirely
        eventually("the hung-up peer's sandbox to be stopped", || {
            stopped.load(Ordering::SeqCst) == 1
        })
        .await;

        let gone = backend.start(request(None)).await.unwrap();
        drop(gone);
        eventually("a peer that hangs up at once", || {
            stopped.load(Ordering::SeqCst) == 2
        })
        .await;
    }

    #[test]
    fn bind_replaces_a_stale_socket_but_never_a_regular_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hp-bind-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy = |name: &str| {
            Policy::parse(&format!(
                "socket: {}/{name}\nimage: i\nhostname: h\nsocket_mode: '600'",
                dir.display()
            ))
            .unwrap()
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = rt.enter();
        let p = policy("a.sock");
        drop(bind(&p).unwrap());
        assert!(bind(&p).is_ok(), "a stale socket from a crash is replaced");
        assert_eq!(
            std::fs::metadata(&p.socket).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let file = policy("regular");
        std::fs::write(&file.socket, "precious").unwrap();
        assert!(
            bind(&file).is_err(),
            "never delete something that is not a socket"
        );
        assert_eq!(std::fs::read_to_string(&file.socket).unwrap(), "precious");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
