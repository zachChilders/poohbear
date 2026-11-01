mod behavior;
mod config;
mod server;
mod services;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use behavior::TrackFactory;
use clap::Parser;
use config::{Config, TrackSource};
use hp_core::{BehaviorFactory, Passive, Protocol};
use hp_log::LogSink;
use hp_sandbox::ContainerBackend;
use server::{Server, Settings};
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(about = "Single-protocol honeypot")]
struct Cli {
    /// Path to config YAML. Without it, the PORT environment variable decides
    /// everything (see `services`).
    #[arg(short, long)]
    config: Option<PathBuf>,
}

/// Plugin registry: protocol name -> implementation. Plugins that need
/// persona-derived setup (e.g. the SSH identification string) validate it
/// here, so a bad config fails at startup.
fn plugin(cfg: &Config) -> anyhow::Result<Arc<dyn Protocol>> {
    if cfg.shell_broker.is_some() && cfg.protocol != "ssh" {
        anyhow::bail!("`shell` is only supported by the ssh protocol");
    }
    match cfg.protocol.as_str() {
        "banner" => Ok(Arc::new(hp_proto_banner::Banner)),
        "ftp" => Ok(Arc::new(hp_proto_ftp::Ftp)),
        "ssh" => {
            let ssh = hp_proto_ssh::Ssh::new(cfg.persona.banner.as_deref())?;
            Ok(Arc::new(match &cfg.shell_broker {
                Some(socket) => ssh.with_shell_backend(Arc::new(ContainerBackend::new(socket))),
                None => ssh,
            }))
        }
        other => anyhow::bail!("unknown protocol {other:?} (available: banner, ftp, ssh)"),
    }
}

/// Process-level diagnostics (JSON on stderr). Session records are separate;
/// see `hp-log`.
fn init_tracing() {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cfg = match Cli::parse().config {
        Some(path) => Config::load(&path)?,
        None => Config::from_env(|k| std::env::var(k).ok())?,
    };
    let proto = plugin(&cfg)?;

    // Fail closed: an invalid track means the honeypot does not start.
    let behavior: Arc<dyn BehaviorFactory> = match &cfg.track {
        Some(source) => {
            let track = match source {
                TrackSource::File(path) => hp_track::Track::load(path)?,
                TrackSource::Builtin(yaml) => hp_track::Track::from_yaml(yaml)?,
            };
            tracing::info!(
                track = track.name(),
                states = track.state_count(),
                "track loaded"
            );
            Arc::new(TrackFactory::new(track))
        }
        None => Arc::new(Passive),
    };

    let sink = LogSink::open(cfg.session_log.as_deref()).await?;
    let settings = Settings {
        limits: cfg.limits,
        persona: cfg.persona,
        max_sessions: cfg.max_sessions,
    };
    let server = Server::new(proto, behavior, sink, settings);

    for addr in &cfg.listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))?;
        tracing::info!(%addr, protocol = server.protocol_name(), "listening");
        tokio::spawn(server.clone().serve(listener));
    }
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
