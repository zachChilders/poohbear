mod config;

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use config::Config;
use futures_util::FutureExt;
use hp_core::{Limits, Persona, Protocol, SessionCtx};
use hp_log::LogSink;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

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
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    let proto = plugin(&cfg.protocol)
        .ok_or_else(|| anyhow::anyhow!("unknown protocol {:?} (available: banner)", cfg.protocol))?;
    let sink = LogSink::open(cfg.logging.json.as_deref()).await?;
    let limits = Limits { session_timeout: cfg.session_timeout()?, max_input_bytes: cfg.max_input_bytes()? };
    let persona = Persona { hostname: cfg.persona.hostname.clone(), banner: cfg.persona.banner.clone() };
    let permits = Arc::new(Semaphore::new(cfg.limits.max_sessions));

    let mut tasks = Vec::new();
    for addr in &cfg.listen {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!(%addr, protocol = proto.name(), "listening");
        let (proto, sink, limits, persona, permits) =
            (proto.clone(), sink.clone(), limits.clone(), persona.clone(), permits.clone());
        tasks.push(tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(x) => x,
                    Err(e) => { tracing::warn!(error = %e, "accept failed"); continue; }
                };
                // Over the cap: drop the connection rather than queue.
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::warn!(%peer, "max_sessions reached; dropping");
                    continue;
                };
                let id = uuid::Uuid::new_v4().to_string();
                let log = sink.session(&id, peer, proto.name());
                let ctx = SessionCtx { session_id: id, peer, log: log.clone(), persona: persona.clone(), limits: limits.clone() };
                let proto = proto.clone();
                let timeout = limits.session_timeout;
                tokio::spawn(async move {
                    let _permit = permit;
                    log.record("connect", json!({}));
                    // Panic isolation: one bad session must not affect the listener.
                    let run = std::panic::AssertUnwindSafe(proto.handle(Box::new(stream), ctx)).catch_unwind();
                    match tokio::time::timeout(timeout, run).await {
                        Err(_) => log.record("timeout", json!({})),
                        Ok(Err(_)) => log.record("panic", json!({})),
                        Ok(Ok(Err(e))) => log.record("error", json!({ "error": e.to_string() })),
                        Ok(Ok(Ok(()))) => {}
                    }
                    log.record("disconnect", json!({}));
                });
            }
        }));
    }
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");
    Ok(())
}
