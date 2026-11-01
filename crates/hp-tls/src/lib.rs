//! TLS for any protocol plugin.
//!
//! The server wraps a listener's connections with an [`Acceptor`] before the
//! plugin sees them, so HTTPS, LDAPS, SMTPS, IMAPS... are each "the plain
//! plugin plus `tls:` in the config". Per connection it:
//!
//! 1. reads the ClientHello itself and logs a `tls_client_hello` record (SNI,
//!    ALPN, offered versions, JA4) *before* handshaking, so the fingerprint
//!    is kept even when the client then rejects the certificate;
//! 2. replays those bytes into rustls and completes the handshake;
//! 3. hands the plugin the decrypted stream.
//!
//! A peer that sends something other than a TLS handshake (plain HTTP to
//! 443, a banner grab) is logged as `plaintext_on_tls` and passed through in
//! cleartext: for a honeypot, an answer is worth more than a refusal.
//!
//! No ALPN is negotiated, so clients fall back to the plugin's own protocol
//! (HTTP/1.1, not h2) instead of failing the handshake.

mod cert;
mod hello;
mod prefixed;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use hp_core::AsyncStream;
use hp_log::{Record, SessionLogger};
use rustls::ServerConfig;
use tokio::io::AsyncReadExt;

pub use cert::CertSource;
pub use hello::ClientHello;
use prefixed::Prefixed;

/// How long a peer gets to complete the handshake. Much shorter than a
/// session, so idle connections on a TLS port do not hold session slots.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest ClientHello we will buffer (real ones are well under 4 KiB, even
/// with post-quantum key shares).
const MAX_HELLO: usize = 64 * 1024;

const CONTENT_HANDSHAKE: u8 = 0x16;

/// Shared across sessions; build once at startup so a bad certificate stops
/// the honeypot from starting.
pub struct Acceptor {
    inner: tokio_rustls::TlsAcceptor,
}

impl Acceptor {
    pub fn new(source: &CertSource) -> anyhow::Result<Acceptor> {
        let (chain, key) = cert::load(source)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("TLS protocol versions")?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .context("certificate and key do not match or are unsupported")?;
        Ok(Acceptor {
            inner: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        })
    }

    /// Run the TLS layer for one connection (see the module docs).
    pub async fn accept<S: AsyncStream + 'static>(
        &self,
        stream: S,
        log: &SessionLogger,
    ) -> anyhow::Result<Box<dyn AsyncStream>> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, self.accept_inner(stream, log))
            .await
            .context("TLS handshake timed out")?
    }

    async fn accept_inner<S: AsyncStream + 'static>(
        &self,
        mut stream: S,
        log: &SessionLogger,
    ) -> anyhow::Result<Box<dyn AsyncStream>> {
        let (seen, hello) = read_hello(&mut stream).await?;
        let replay = Prefixed::new(seen, stream);
        let Some(hello) = hello else {
            log.event(Record::PlaintextOnTls);
            return Ok(Box::new(replay));
        };
        if let Some(h) = &hello {
            log.event(Record::TlsClientHello {
                sni: h.sni.clone(),
                alpn: h
                    .alpn
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect(),
                versions: h.version_names(),
                ja4: h.ja4(),
            });
        }
        let tls = self
            .inner
            .accept(replay)
            .await
            .context("TLS handshake failed")?;
        Ok(Box::new(tls))
    }
}

/// Read the start of the connection. Returns every byte read (to be replayed)
/// and:
/// - `None` if it is not a TLS handshake (plaintext);
/// - `Some(None)` if it is TLS but the hello could not be parsed (rustls will
///   then produce the real error);
/// - `Some(Some(hello))` otherwise.
async fn read_hello<S: AsyncStream>(
    stream: &mut S,
) -> anyhow::Result<(Vec<u8>, Option<Option<ClientHello>>)> {
    let mut seen = vec![0u8; 1];
    if stream.read(&mut seen).await? == 0 {
        anyhow::bail!("peer closed before sending anything");
    }
    if seen[0] != CONTENT_HANDSHAKE {
        return Ok((seen, None));
    }
    // Handshake messages may span records; collect until the first message
    // is complete.
    let mut handshake = Vec::new();
    loop {
        // The first record's type byte has already been read.
        let mut header = [0u8; 5];
        let start = if seen.len() == 1 { 1 } else { 0 };
        header[0] = seen[0];
        stream.read_exact(&mut header[start..]).await?;
        seen.extend_from_slice(&header[start..]);
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if header[0] != CONTENT_HANDSHAKE || seen.len() + len > MAX_HELLO {
            return Ok((seen, Some(None)));
        }
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await?;
        seen.extend_from_slice(&body);
        handshake.extend_from_slice(&body);
        if handshake.len() >= 4 {
            let want = 4
                + ((handshake[1] as usize) << 16
                    | (handshake[2] as usize) << 8
                    | handshake[3] as usize);
            if handshake.len() >= want {
                return Ok((seen, Some(hello::parse(&handshake[..want]))));
            }
            if want > MAX_HELLO {
                return Ok((seen, Some(None)));
            }
        }
    }
}

#[cfg(test)]
mod tests;
