//! The honeypot's side: a [`ShellBackend`] that gets shells from the broker.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use hp_core::{AsyncStream, ShellBackend, ShellRequest};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::proto::{read_json, write_json, Request, Response};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Starting a sandbox takes a moment; this is only a backstop.
const START_TIMEOUT: Duration = Duration::from_secs(30);

pub struct ContainerBackend {
    socket: PathBuf,
}

impl ContainerBackend {
    pub fn new(socket: impl Into<PathBuf>) -> ContainerBackend {
        ContainerBackend {
            socket: socket.into(),
        }
    }
}

#[async_trait]
impl ShellBackend for ContainerBackend {
    async fn start(&self, request: ShellRequest) -> anyhow::Result<Box<dyn AsyncStream>> {
        let mut conn = timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket))
            .await
            .context("timed out connecting to the sandbox broker")?
            .with_context(|| {
                format!(
                    "connecting to the sandbox broker at {}",
                    self.socket.display()
                )
            })?;
        write_json(&mut conn, &Request::from(&request))
            .await
            .context("sending the request")?;
        let reply: Response = timeout(START_TIMEOUT, read_json(&mut conn))
            .await
            .context("the sandbox broker did not answer")?
            .context("reading the broker's answer")?;
        anyhow::ensure!(
            reply.ok,
            "the sandbox broker refused: {}",
            reply.error.unwrap_or_default()
        );
        Ok(Box::new(conn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::read_line;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    fn socket_path(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hp-sandbox-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        dir
    }

    fn request() -> ShellRequest {
        ShellRequest {
            session_id: "s1".into(),
            user: "root".into(),
            command: None,
            terminal: None,
        }
    }

    /// A broker stand-in: accepts one connection, reads the request, runs `then`.
    fn fake_broker<F, Fut>(path: &PathBuf, then: F) -> tokio::task::JoinHandle<Request>
    where
        F: FnOnce(UnixStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.unwrap();
            let req: Request = read_json(&mut conn).await.unwrap();
            then(conn).await;
            req
        })
    }

    #[tokio::test]
    async fn the_connection_becomes_the_shell_and_the_first_output_is_not_lost() {
        let path = socket_path("ok");
        let broker = fake_broker(&path, |mut c| async move {
            // reply and first output in one write, as a fast shell would
            c.write_all(b"{\"ok\":true}\nfake$ ").await.unwrap();
            let line = read_line(&mut c, 64).await.unwrap();
            c.write_all(format!("you said {line}\n").as_bytes())
                .await
                .unwrap();
        });
        let mut shell = ContainerBackend::new(&path).start(request()).await.unwrap();
        let mut buf = [0u8; 6];
        shell.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"fake$ ");
        shell.write_all(b"hi\n").await.unwrap();
        let mut rest = Vec::new();
        shell.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"you said hi\n");
        let req = broker.await.unwrap();
        assert_eq!((req.session_id.as_str(), req.user.as_str()), ("s1", "root"));
    }

    #[tokio::test]
    async fn a_refusal_becomes_an_error_with_the_reason() {
        let path = socket_path("refused");
        fake_broker(&path, |mut c| async move {
            write_json(&mut c, &Response::refused("busy"))
                .await
                .unwrap();
        });
        let err = ContainerBackend::new(&path)
            .start(request())
            .await
            .err()
            .unwrap();
        assert!(format!("{err:#}").contains("refused: busy"), "{err:#}");
    }

    #[tokio::test]
    async fn a_broker_that_is_down_or_garbled_is_an_error_not_a_hang() {
        let err = ContainerBackend::new(socket_path("missing"))
            .start(request())
            .await
            .err()
            .unwrap();
        assert!(
            format!("{err:#}").contains("connecting to the sandbox broker"),
            "{err:#}"
        );

        let path = socket_path("garbled");
        fake_broker(&path, |mut c| async move {
            c.write_all(b"definitely not json\n").await.unwrap();
        });
        assert!(ContainerBackend::new(&path).start(request()).await.is_err());

        let path = socket_path("hangup");
        fake_broker(&path, |c| async move { drop(c) });
        assert!(ContainerBackend::new(&path).start(request()).await.is_err());
    }
}
