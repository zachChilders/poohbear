mod behavior;
mod config;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use behavior::TrackFactory;
use clap::Parser;
use config::Config;
use hp_core::{BehaviorFactory, Passive, Protocol};
use hp_log::LogSink;
use server::{Server, Settings};
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(about = "Single-protocol honeypot")]
struct Cli {
    /// Path to config YAML
    #[arg(short, long)]
    config: PathBuf,
}

/// Plugin registry: protocol name -> implementation.
fn plugin(name: &str) -> Option<Arc<dyn Protocol>> {
    match name {
        "banner" => Some(Arc::new(hp_proto_banner::Banner)),
        _ => None,
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
    let cfg = Config::load(&Cli::parse().config)?;
    let proto = plugin(&cfg.protocol).ok_or_else(|| {
        anyhow::anyhow!("unknown protocol {:?} (available: banner)", cfg.protocol)
    })?;

    // Fail closed: an invalid track means the honeypot does not start.
    let behavior: Arc<dyn BehaviorFactory> = match &cfg.track {
        Some(path) => {
            let track = hp_track::Track::load(path)?;
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
