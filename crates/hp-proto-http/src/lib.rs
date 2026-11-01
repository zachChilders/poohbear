//! HTTP/1.x plugin (and HTTPS, with `tls:` in the config; see `hp-tls`).
//!
//! The plugin owns the wire format: request parsing (keep-alive, pipelining,
//! `Content-Length` and chunked bodies, `Expect: 100-continue`) and response
//! framing. What it reports to the behavior, once per request:
//!
//! `Event::Request { op: "<METHOD> <target>", args }`, where `args` holds
//! string fields `method`, `path`, `query`, `headers` (lowercased
//! `name: value` lines) and `body`, plus `user`/`password` when the request
//! carried credentials (Basic auth, or a login form posted as urlencoded
//! fields or JSON). Tracks match these as `method:`, `path:`, `headers:`...
//!
//! The behavior's `send`s are the response, framed by [`response::frame`];
//! with none, the answer is a 404. `auth: true` marks captured credentials
//! as accepted in the log. `close` ends the connection after the response,
//! or instead of one when nothing was sent.

mod creds;
mod request;
mod response;

use std::time::SystemTime;

use async_trait::async_trait;
use hp_core::{AsyncStream, Event, Protocol, SessionCtx};
use hp_kit::Driver;
use hp_log::{Header, Payload, Record, SessionLogger};
use request::{Reader, Request, Stop};
use response::{error_page, frame, Frame};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

/// Requests served on one connection before it is closed (nginx: 1000).
const MAX_REQUESTS: usize = 100;

pub struct Http;

#[async_trait]
impl Protocol for Http {
    fn name(&self) -> &'static str {
        "http"
    }

    fn default_ports(&self) -> &[u16] {
        &[80, 8080]
    }

    async fn handle(
        &self,
        mut stream: Box<dyn AsyncStream>,
        ctx: SessionCtx,
    ) -> anyhow::Result<()> {
        let mut driver = Driver::new(ctx.log, ctx.behavior, &ctx.limits);
        let server = ctx.persona.banner.as_deref();
        let result = serve(stream.as_mut(), &mut driver, server).await;
        // Best effort: sends TLS close_notify / FIN.
        let _ = stream.shutdown().await;
        result
    }
}

async fn serve(
    io: &mut dyn AsyncStream,
    driver: &mut Driver,
    server: Option<&str>,
) -> anyhow::Result<()> {
    if driver.connect().wants_close() {
        return Ok(());
    }
    let mut reader = Reader::default();
    for served in 1..=MAX_REQUESTS {
        let req = match reader.next(io, driver).await {
            Ok(req) => req,
            Err(Stop::Closed) => return Ok(()),
            Err(Stop::Reject(code)) => {
                let page = error_page(code, server);
                return respond(io, driver.log(), &page, false, false, server).await;
            }
        };
        log_request(driver, &req);
        let creds = creds::extract(&req);
        let event = Event::Request {
            op: format!("{} {}", req.method, req.target),
            args: args(&req, creds.as_ref()),
        };
        let verdict = driver.react(&event).verdict();
        if let Some(c) = creds {
            driver.log().event(Record::Auth {
                user: c.user,
                method: c.method,
                credential: c.password,
                accepted: verdict.accepted,
            });
        }
        tokio::time::sleep(verdict.delay).await;
        if verdict.close && verdict.welcome.is_empty() {
            return Ok(()); // the track dropped the connection unanswered
        }
        let keep = req.keep_alive() && !verdict.close && served < MAX_REQUESTS;
        let text = if verdict.welcome.is_empty() {
            error_page(404, server)
        } else {
            verdict.welcome
        };
        respond(io, driver.log(), &text, req.method == "HEAD", keep, server).await?;
        if !keep {
            return Ok(());
        }
    }
    Ok(())
}

async fn respond(
    io: &mut dyn AsyncStream,
    log: &SessionLogger,
    text: &[u8],
    head_request: bool,
    keep_alive: bool,
    server: Option<&str>,
) -> anyhow::Result<()> {
    let date = httpdate::fmt_http_date(SystemTime::now());
    let bytes = frame(
        text,
        &Frame {
            head_request,
            keep_alive,
            server,
            date: &date,
        },
    );
    log.event(Record::tx(&bytes));
    io.write_all(&bytes).await?;
    io.flush().await?;
    Ok(())
}

fn log_request(driver: &Driver, req: &Request) {
    driver.log().event(Record::HttpRequest {
        method: req.method.clone(),
        target: req.target.clone(),
        version: req.version(),
        headers: req
            .headers
            .iter()
            .map(|(n, v)| Header {
                name: n.clone(),
                value: v.clone(),
            })
            .collect(),
        body: Payload::new(&req.body),
    });
}

fn args(req: &Request, creds: Option<&creds::Creds>) -> Value {
    let mut args = json!({
        "method": req.method,
        "path": req.path(),
        "query": req.query(),
        "headers": req.headers_text(),
        "body": String::from_utf8_lossy(&req.body),
    });
    if let Some(c) = creds {
        args["user"] = json!(c.user);
        args["password"] = json!(c.password);
    }
    args
}

#[cfg(test)]
mod tests;
