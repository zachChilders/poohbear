//! Raw TCP "banner + log" plugin: send the persona banner, then log every byte.

use async_trait::async_trait;
use hp_core::{AsyncStream, Protocol, SessionCtx};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Banner;

#[async_trait]
impl Protocol for Banner {
    fn name(&self) -> &'static str { "banner" }
    fn default_ports(&self) -> &[u16] { &[2323] }

    async fn handle(&self, mut stream: Box<dyn AsyncStream>, ctx: SessionCtx) -> anyhow::Result<()> {
        if let Some(b) = &ctx.persona.banner {
            let out = format!("{b}\r\n");
            stream.write_all(out.as_bytes()).await?;
            ctx.log.bytes("tx", out.as_bytes());
        }
        let mut total: u64 = 0;
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 { break; }
            total += n as u64;
            if total > ctx.limits.max_input_bytes {
                ctx.log.record("limit_exceeded", json!({ "limit": "max_input_bytes", "total": total }));
                break;
            }
            ctx.log.bytes("rx", &buf[..n]);
        }
        Ok(())
    }
}
