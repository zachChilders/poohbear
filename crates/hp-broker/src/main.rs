use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use hp_broker::{server, Broker, DockerRunner, Policy};
use tracing::info;

/// The sandbox broker: starts hardened, disposable containers for the
/// honeypot's shells. Run it as its own user, not as the honeypot's.
#[derive(Parser)]
struct Cli {
    /// Path to the policy YAML
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();

    let policy = Policy::load(&Cli::parse().config)?;
    let runner = DockerRunner::new(&policy.docker);
    let left = runner
        .remove_leftovers()
        .await
        .context("cleaning up (is the container runtime reachable?)")?;
    info!(removed = left, socket = %policy.socket.display(), image = %policy.image, max = policy.max_sandboxes, "broker ready");

    let listener = server::bind(&policy)?;
    let docker = policy.docker.clone();
    let broker = Broker::new(policy, Arc::new(runner));
    tokio::select! {
        () = broker.serve(listener) => {}
        _ = tokio::signal::ctrl_c() => info!("shutting down"),
    }
    // Sandboxes die with their connections; sweep any that did not.
    let _ = DockerRunner::new(docker).remove_leftovers().await;
    Ok(())
}
