//! Carrying a real shell's output to the peer.

use hp_log::{Record, SessionLogger};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::Output;

/// Copy `reader` (a shell's output) to the peer until the shell ends, logging
/// every byte as `tx`. A read error ends the shell like an EOF would; an error
/// writing to the peer is returned.
///
/// The other direction (what the peer types) goes through
/// [`crate::Driver::receive`], which counts it against the input cap and logs
/// it, so both directions are captured in full.
pub async fn pump<R: AsyncRead + Unpin, O: Output>(
    mut reader: R,
    out: &mut O,
    log: &SessionLogger,
) -> Result<(), O::Error> {
    let mut buf = [0u8; 4096];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => return Ok(()),
            Ok(n) => n,
        };
        log.event(Record::tx(&buf[..n]));
        out.write(buf[..n].to_vec()).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_log::LogSink;
    use tokio::io::AsyncWriteExt;

    struct Collect(Vec<u8>, bool);
    impl Output for Collect {
        type Error = &'static str;
        async fn write(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
            if self.1 {
                return Err("peer gone");
            }
            self.0.extend(data);
            Ok(())
        }
    }

    fn log() -> (SessionLogger, tokio::sync::mpsc::Receiver<String>) {
        let (sink, rx) = LogSink::channel(16);
        (sink.session("s", "127.0.0.1:9".parse().unwrap(), "t"), rx)
    }

    #[tokio::test]
    async fn copies_everything_and_logs_it_until_the_shell_ends() {
        let (mut shell, reader) = tokio::io::duplex(64);
        let (log, mut rx) = log();
        shell.write_all(b"root@box:~# ").await.unwrap();
        drop(shell);
        let mut out = Collect(vec![], false);
        pump(reader, &mut out, &log).await.unwrap();
        assert_eq!(out.0, b"root@box:~# ");
        assert!(rx.try_recv().unwrap().contains("\"kind\":\"tx\""));
    }

    #[tokio::test]
    async fn a_peer_that_went_away_is_reported() {
        let (mut shell, reader) = tokio::io::duplex(64);
        shell.write_all(b"x").await.unwrap();
        let (log, _rx) = log();
        let mut gone = Collect(vec![], true);
        assert_eq!(pump(reader, &mut gone, &log).await, Err("peer gone"));
    }
}
