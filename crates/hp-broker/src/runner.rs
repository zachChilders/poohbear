//! Starting and stopping sandboxes. [`DockerRunner`] is the only code that
//! spawns a process; everything else in the broker works on [`Runner`], so it
//! can be tested without Docker.

use std::os::fd::OwnedFd;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context};
use async_trait::async_trait;
use hp_core::AsyncStream;
use tokio::net::unix::pipe;
use tokio::process::{Child, Command};
use tokio::time::timeout;

use crate::launch::Spec;

/// A running sandbox: the shell's byte stream, and how to end it.
pub struct Running {
    pub io: Box<dyn AsyncStream>,
    pub stop: Box<dyn Stop>,
}

#[async_trait]
pub trait Stop: Send {
    /// End the sandbox and release everything it held. Must not fail or hang.
    async fn stop(self: Box<Self>);
}

#[async_trait]
pub trait Runner: Send + Sync {
    async fn start(&self, spec: &Spec) -> anyhow::Result<Running>;

    /// Remove whatever `start` may have left behind for `name` after it failed
    /// or timed out. Best effort.
    async fn discard(&self, _name: &str) {}
}

const CREATE_TIMEOUT: Duration = Duration::from_secs(60);
const REMOVE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct DockerRunner {
    docker: String,
}

impl DockerRunner {
    pub fn new(docker: impl Into<String>) -> DockerRunner {
        DockerRunner {
            docker: docker.into(),
        }
    }

    /// Remove sandboxes a previous run left behind. Returns how many.
    pub async fn remove_leftovers(&self) -> anyhow::Result<usize> {
        let listed = Command::new(&self.docker)
            .args(["ps", "-aq", "--filter", "label=honeypot.managed=true"])
            .kill_on_drop(true)
            .output()
            .await
            .context("listing sandboxes")?;
        anyhow::ensure!(
            listed.status.success(),
            "docker ps failed: {}",
            String::from_utf8_lossy(&listed.stderr).trim()
        );
        let ids: Vec<String> = String::from_utf8_lossy(&listed.stdout)
            .split_whitespace()
            .map(String::from)
            .collect();
        if !ids.is_empty() {
            remove(&self.docker, &ids).await;
        }
        Ok(ids.len())
    }
}

/// `docker rm -f`, bounded in time, errors ignored (the container may be gone already).
async fn remove(docker: &str, names: &[String]) {
    let rm = Command::new(docker)
        .args(["rm", "-f"])
        .args(names)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status();
    let _ = timeout(REMOVE_TIMEOUT, rm).await;
}

#[async_trait]
impl Runner for DockerRunner {
    async fn start(&self, spec: &Spec) -> anyhow::Result<Running> {
        // Create first: if anything is wrong (image missing, bad runtime), the
        // error stays with the operator. Attaching straight away would put
        // Docker's own error text in front of the peer.
        let created = timeout(
            CREATE_TIMEOUT,
            Command::new(&self.docker)
                .arg("create")
                .args(&spec.args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("docker create timed out")?
        .context("running docker create")?;
        if !created.status.success() {
            bail!(
                "docker create failed: {}",
                String::from_utf8_lossy(&created.stderr).trim()
            );
        }

        // The container's output, stdout and stderr together, comes back on one pipe.
        let (reader, writer) = std::io::pipe().context("creating a pipe")?;
        let spawned = Command::new(&self.docker)
            .args(["start", "-a", "-i", &spec.name])
            .stdin(Stdio::piped())
            .stdout(Stdio::from(writer.try_clone()?))
            .stderr(Stdio::from(writer))
            .kill_on_drop(true)
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) => {
                remove(&self.docker, std::slice::from_ref(&spec.name)).await;
                return Err(e).context("running docker start");
            }
        };
        let stdin = child.stdin.take().expect("stdin is piped");
        let output = pipe::Receiver::from_owned_fd(OwnedFd::from(reader))
            .context("reading the sandbox's output")?;
        Ok(Running {
            io: Box::new(tokio::io::join(output, stdin)),
            stop: Box::new(DockerStop {
                docker: self.docker.clone(),
                name: spec.name.clone(),
                child,
            }),
        })
    }

    async fn discard(&self, name: &str) {
        remove(&self.docker, &[name.to_string()]).await;
    }
}

struct DockerStop {
    docker: String,
    name: String,
    child: Child,
}

#[async_trait]
impl Stop for DockerStop {
    async fn stop(mut self: Box<Self>) {
        let _ = self.child.start_kill();
        remove(&self.docker, std::slice::from_ref(&self.name)).await;
        let _ = timeout(Duration::from_secs(5), self.child.wait()).await;
    }
}
