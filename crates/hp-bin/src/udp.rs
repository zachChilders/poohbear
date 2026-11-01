//! UDP as sessions. The server splits a socket's datagrams by peer address;
//! each peer gets a [`Flow`], a virtual stream the plugin uses like a TCP
//! connection:
//!
//! - each datagram from the peer is one read (a small read buffer gets the
//!   rest on the next read);
//! - each write leaves as one datagram (writes over [`MAX_DATAGRAM`] are
//!   split);
//! - silence for [`IDLE`] reads as end-of-stream, so quiet peers do not hold
//!   session slots; a datagram after that starts a new session.
//!
//! UDP source addresses are trivially spoofed, so a service that replies can
//! be abused to flood a third party. Each flow therefore sends at most
//! [`AMPLIFICATION`] times the bytes its peer has sent (as QUIC does before
//! address validation). Replies over the budget are dropped, as a lossy
//! network would, and each one is logged as `udp_reply_dropped`.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hp_log::{Record, SessionLogger};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{Instant, Sleep};

/// How long a peer may stay silent before its session ends.
pub const IDLE: Duration = Duration::from_secs(60);
/// Most bytes sent per byte received.
pub const AMPLIFICATION: u64 = 3;
/// Largest datagram we send (fits an Ethernet MTU with IPv4/UDP headers).
pub const MAX_DATAGRAM: usize = 1472;
/// Datagrams queued for a session that is busy (e.g. in a track delay);
/// beyond this they are dropped, like a full socket buffer.
pub const QUEUE: usize = 64;

/// The demultiplexer's handle on a flow.
pub struct Inbox {
    tx: mpsc::Sender<Bytes>,
    received: Arc<AtomicU64>,
}

impl Inbox {
    /// Hand a datagram to the session. False if the session has ended.
    pub fn deliver(&self, datagram: Bytes) -> bool {
        self.received
            .fetch_add(datagram.len() as u64, Ordering::Relaxed);
        match self.tx.try_send(datagram) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => true,
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

pub struct Flow {
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    rx: mpsc::Receiver<Bytes>,
    pending: Bytes,
    /// Bytes the peer has sent (counted on arrival, before the plugin reads,
    /// so a greeting sent on connect is covered by the first datagram).
    received: Arc<AtomicU64>,
    sent: u64,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
    log: SessionLogger,
}

/// A new flow for `peer`, and the inbox that feeds it.
pub fn flow(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    idle: Duration,
    log: SessionLogger,
) -> (Flow, Inbox) {
    let (tx, rx) = mpsc::channel(QUEUE);
    let received = Arc::new(AtomicU64::new(0));
    let flow = Flow {
        socket,
        peer,
        rx,
        pending: Bytes::new(),
        received: received.clone(),
        sent: 0,
        idle,
        timer: Box::pin(tokio::time::sleep(idle)),
        log,
    };
    (flow, Inbox { tx, received })
}

impl AsyncRead for Flow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pending.is_empty() {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(datagram)) => {
                    let deadline = Instant::now() + this.idle;
                    this.timer.as_mut().reset(deadline);
                    this.pending = datagram;
                }
                // Closed or idle: end of stream.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => {
                    return match this.timer.as_mut().poll(cx) {
                        Poll::Ready(()) => Poll::Ready(Ok(())),
                        Poll::Pending => Poll::Pending,
                    }
                }
            }
        }
        let n = this.pending.len().min(buf.remaining());
        buf.put_slice(&this.pending.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Flow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let n = data.len().min(MAX_DATAGRAM);
        let budget = this
            .received
            .load(Ordering::Relaxed)
            .saturating_mul(AMPLIFICATION);
        if this.sent + n as u64 > budget {
            // Dropped, as the network might. Not a log-flooding vector:
            // replies are bounded by input, and input by `max_input_bytes`.
            this.log.event(Record::UdpReplyDropped { len: n });
            return Poll::Ready(Ok(n));
        }
        match this.socket.poll_send_to(cx, &data[..n], this.peer) {
            Poll::Ready(Ok(sent)) => {
                this.sent += sent as u64;
                Poll::Ready(Ok(sent))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_log::LogSink;
    use serde_json::Value;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair(idle: Duration) -> (Flow, Inbox, UdpSocket, mpsc::Receiver<String>) {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (sink, rx) = LogSink::channel(16);
        let peer = client.local_addr().unwrap();
        let log = sink.session("s", peer, "banner/udp");
        let (flow, inbox) = flow(server, peer, idle, log);
        (flow, inbox, client, rx)
    }

    #[tokio::test]
    async fn datagrams_are_reads_and_writes_are_datagrams() {
        let (mut flow, inbox, client, _rx) = pair(IDLE).await;
        assert!(inbox.deliver(Bytes::from_static(b"hello")));
        assert!(inbox.deliver(Bytes::from_static(b"!")));
        let mut small = [0u8; 3];
        assert_eq!(flow.read(&mut small).await.unwrap(), 3);
        assert_eq!(&small, b"hel");
        let mut buf = [0u8; 64];
        assert_eq!(
            flow.read(&mut buf).await.unwrap(),
            2,
            "rest of the datagram"
        );
        assert_eq!(flow.read(&mut buf).await.unwrap(), 1, "next datagram");

        flow.write_all(b"ok").await.unwrap();
        let mut got = [0u8; 64];
        let (n, _) = client.recv_from(&mut got).await.unwrap();
        assert_eq!(&got[..n], b"ok");
    }

    #[tokio::test]
    async fn replies_are_capped_at_three_times_the_input() {
        let (mut flow, inbox, client, mut rx) = pair(IDLE).await;
        inbox.deliver(Bytes::from_static(b"abcd")); // budget: 12 bytes
        flow.write_all(b"0123456789").await.unwrap();
        flow.write_all(b"xyz").await.unwrap(); // would make 13: dropped
        flow.write_all(b"qqq").await.unwrap(); // still over: dropped
        let mut got = [0u8; 64];
        let (n, _) = client.recv_from(&mut got).await.unwrap();
        assert_eq!(&got[..n], b"0123456789");
        let lines: Vec<Value> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|l| serde_json::from_str(&l).unwrap())
            .collect();
        let dropped: Vec<_> = lines.iter().map(|l| (&l["kind"], &l["len"])).collect();
        let kind = serde_json::json!("udp_reply_dropped");
        assert_eq!(
            dropped,
            [
                (&kind, &serde_json::json!(3)),
                (&kind, &serde_json::json!(3))
            ]
        );
        // More input raises the budget again.
        inbox.deliver(Bytes::from_static(b"more"));
        flow.write_all(b"two").await.unwrap();
        let (n, _) = client.recv_from(&mut got).await.unwrap();
        assert_eq!(&got[..n], b"two");
    }

    #[tokio::test]
    async fn large_writes_are_split_into_datagrams() {
        let (mut flow, inbox, client, _rx) = pair(IDLE).await;
        inbox.deliver(Bytes::from(vec![0u8; 2000]));
        flow.write_all(&vec![7u8; 2000]).await.unwrap();
        let mut got = vec![0u8; 4096];
        let (a, _) = client.recv_from(&mut got).await.unwrap();
        let (b, _) = client.recv_from(&mut got).await.unwrap();
        assert_eq!((a, b), (MAX_DATAGRAM, 2000 - MAX_DATAGRAM));
    }

    #[tokio::test]
    async fn silence_and_closing_end_the_stream() {
        let (mut flow, inbox, _client, _rx) = pair(Duration::from_millis(30)).await;
        inbox.deliver(Bytes::from_static(b"x"));
        let mut buf = [0u8; 8];
        assert_eq!(flow.read(&mut buf).await.unwrap(), 1);
        let started = std::time::Instant::now();
        assert_eq!(flow.read(&mut buf).await.unwrap(), 0, "idle is EOF");
        assert!(started.elapsed() >= Duration::from_millis(25));

        let (mut flow, inbox, _client, _rx) = pair(IDLE).await;
        drop(inbox);
        assert_eq!(flow.read(&mut buf).await.unwrap(), 0, "demux gone is EOF");
        let (flow, inbox, _client, _rx) = pair(IDLE).await;
        drop(flow);
        assert!(inbox.is_closed() && !inbox.deliver(Bytes::from_static(b"x")));
    }
}
