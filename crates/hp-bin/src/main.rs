mod config;
mod server;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use config::Config;
use hp_core::{Limits, Persona, Protocol};
use hp_log::LogSink;
use server::Server;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    hp_log::init_tracing();
    let cfg = Config::load(&Cli::parse().config)?;
    let proto = plugin(&cfg.protocol).ok_or_else(|| {
        anyhow::anyhow!("unknown protocol {:?} (available: banner)", cfg.protocol)
    })?;

    // Fail closed: an invalid track means the honeypot does not start.
    if let Some(path) = &cfg.track {
        let track = hp_track::Track::load(path)?;
        tracing::info!(track = %track.name, states = track.states.len(), "track loaded");
    }

    let sink = LogSink::open(cfg.logging.json.as_deref()).await?;
    let limits = Limits {
        session_timeout: cfg.session_timeout()?,
        max_input_bytes: cfg.max_input_bytes()?,
    };
    let persona = Persona {
        hostname: cfg.persona.hostname.clone(),
        banner: cfg.persona.banner.clone(),
    };
    let server = Server::new(proto, sink, limits, persona, cfg.limits.max_sessions);

    for addr in &cfg.listen {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("binding {addr}"))?;
        tracing::info!(%addr, protocol = server.proto.name(), "listening");
        tokio::spawn(server.clone().serve(listener));
    }
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
