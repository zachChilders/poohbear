//! The TLS layer against a real rustls client, over an in-memory pipe.

use std::sync::Arc;

use hp_log::LogSink;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// Accepts any certificate, as scanners do.
#[derive(Debug)]
struct Insecure(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for Insecure {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client(verify: bool) -> tokio_rustls::TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap();
    let mut config = if verify {
        builder
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Insecure(provider)))
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn acceptor() -> Acceptor {
    Acceptor::new(&CertSource::SelfSigned {
        names: vec!["portal.corp.example".into()],
        organization: Some("Example Corp".into()),
    })
    .unwrap()
}

fn records(rx: &mut tokio::sync::mpsc::Receiver<String>) -> Vec<Value> {
    std::iter::from_fn(|| rx.try_recv().ok())
        .map(|l| serde_json::from_str(&l).unwrap())
        .collect()
}

fn logger() -> (SessionLogger, tokio::sync::mpsc::Receiver<String>) {
    let (sink, rx) = LogSink::channel(64);
    (sink.session("s", "127.0.0.1:9".parse().unwrap(), "t"), rx)
}

#[tokio::test]
async fn handshakes_logs_the_hello_and_carries_data() {
    let (log, mut rx) = logger();
    let (server, client_io) = tokio::io::duplex(1 << 16);
    let peer = tokio::spawn(async move {
        let name = ServerName::try_from("portal.corp.example").unwrap();
        let mut tls = client(false).connect(name, client_io).await.unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        tls.read_exact(&mut got).await.unwrap();
        got
    });
    let mut stream = acceptor().accept(server, &log).await.unwrap();
    let mut got = [0u8; 4];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    stream.write_all(b"pong").await.unwrap();
    stream.flush().await.unwrap();
    assert_eq!(&peer.await.unwrap(), b"pong");

    let recs = records(&mut rx);
    assert_eq!(recs.len(), 1, "{recs:?}");
    let hello = &recs[0];
    assert_eq!(hello["kind"], "tls_client_hello");
    assert_eq!(hello["sni"], "portal.corp.example");
    assert_eq!(hello["alpn"], serde_json::json!(["h2", "http/1.1"]));
    assert_eq!(hello["versions"], serde_json::json!(["1.3", "1.2"]));
    let ja4 = hello["ja4"].as_str().unwrap();
    assert!(ja4.starts_with("t13d") && ja4[8..10] == *"h2", "{ja4}");
}

#[tokio::test]
async fn the_hello_is_kept_when_the_client_rejects_the_certificate() {
    let (log, mut rx) = logger();
    let (server, client_io) = tokio::io::duplex(1 << 16);
    let peer = tokio::spawn(async move {
        let name = ServerName::try_from("portal.corp.example").unwrap();
        client(true).connect(name, client_io).await.is_err()
    });
    let err = acceptor().accept(server, &log).await.err().unwrap();
    assert!(format!("{err:#}").contains("handshake"), "{err:#}");
    assert!(peer.await.unwrap(), "the verifying client refused us");
    let recs = records(&mut rx);
    assert_eq!(recs[0]["kind"], "tls_client_hello");
}

#[tokio::test]
async fn plaintext_is_flagged_and_passed_through_whole() {
    let (log, mut rx) = logger();
    let (server, mut client_io) = tokio::io::duplex(1024);
    client_io
        .write_all(b"GET / HTTP/1.1\r\n\r\n")
        .await
        .unwrap();
    let mut stream = acceptor().accept(server, &log).await.unwrap();
    let mut got = [0u8; 18];
    stream.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"GET / HTTP/1.1\r\n\r\n");
    assert_eq!(records(&mut rx)[0]["kind"], "plaintext_on_tls");
}

#[tokio::test]
async fn garbage_after_a_handshake_byte_is_an_error_not_a_panic() {
    let (log, _rx) = logger();
    for input in [
        &b"\x16"[..],
        b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00",
        b"\x16\x03\x01\x00\x04\x02\x00\x00\x00",
        b"\x16\x03\x01\xff\xff",
    ] {
        let (server, mut client_io) = tokio::io::duplex(1024);
        client_io.write_all(input).await.unwrap();
        client_io.shutdown().await.unwrap();
        assert!(acceptor().accept(server, &log).await.is_err(), "{input:?}");
    }
    let (server, client_io) = tokio::io::duplex(16);
    drop(client_io);
    assert!(
        acceptor().accept(server, &log).await.is_err(),
        "silent peer"
    );
}

#[test]
fn bad_certificate_files_fail_at_startup() {
    let dir = std::env::temp_dir().join(format!("hp-tls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("c.pem"), dir.join("k.pem"));
    std::fs::write(&cert, "not a pem").unwrap();
    std::fs::write(&key, "not a pem").unwrap();
    assert!(Acceptor::new(&CertSource::Files { cert, key }).is_err());
}
