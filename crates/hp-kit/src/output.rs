//! Carrying out a behavior's reply over a plugin's transport.

use std::future::Future;

use hp_core::Action;
use hp_log::{Record, SessionLogger};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::term::{sanitize, to_crlf};

/// Where a plugin's outbound bytes go. Implement it for your transport (a raw
/// stream, an SSH channel, a framed codec) and [`apply`] does the rest.
pub trait Output: Send {
    type Error: Send;
    fn write(&mut self, data: Vec<u8>) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// [`Output`] over any async byte stream.
pub struct StreamOut<'a, W: ?Sized>(pub &'a mut W);

impl<W: AsyncWrite + Unpin + Send + ?Sized> Output for StreamOut<'_, W> {
    type Error = std::io::Error;

    async fn write(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
        self.0.write_all(&data).await
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Flow {
    Continue,
    /// The behavior asked to end the session.
    Close,
}

/// The result of [`apply`].
#[derive(Debug, PartialEq, Eq)]
pub struct Applied {
    pub flow: Flow,
    /// A new prompt, already sanitized, if the behavior set one.
    pub prompt: Option<String>,
}

/// Carry out `actions` in order. Sent bytes are logged as `tx` after any
/// translation, so the log shows exactly what went on the wire.
///
/// `tty` selects terminal output processing: bare `\n` becomes `\r\n`, as a
/// tty does. Behaviors always write plain `\n`.
///
/// `AuthResult` and `OpenShell` are ignored here; they only mean something
/// while authenticating (see [`crate::Reaction::verdict`]).
pub async fn apply<O: Output>(
    out: &mut O,
    log: &SessionLogger,
    actions: Vec<Action>,
    tty: bool,
) -> Result<Applied, O::Error> {
    let mut prompt = None;
    for action in actions {
        match action {
            Action::Send(data) => {
                let data = if tty { to_crlf(&data) } else { data.to_vec() };
                log.event(Record::tx(&data));
                out.write(data).await?;
            }
            Action::Delay(d) => tokio::time::sleep(d).await,
            Action::Prompt(p) => prompt = Some(sanitize(&p, MAX_PROMPT)),
            Action::Close => {
                return Ok(Applied {
                    flow: Flow::Close,
                    prompt,
                })
            }
            Action::AuthResult(_) | Action::OpenShell => {}
        }
    }
    Ok(Applied {
        flow: Flow::Continue,
        prompt,
    })
}

/// Longest prompt we will display.
const MAX_PROMPT: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use hp_log::LogSink;
    use std::time::Duration;

    #[derive(Default)]
    struct Collect(Vec<Vec<u8>>);
    impl Output for Collect {
        type Error = ();
        async fn write(&mut self, data: Vec<u8>) -> Result<(), ()> {
            self.0.push(data);
            Ok(())
        }
    }
    struct Broken;
    impl Output for Broken {
        type Error = &'static str;
        async fn write(&mut self, _: Vec<u8>) -> Result<(), &'static str> {
            Err("peer gone")
        }
    }

    fn log() -> (SessionLogger, tokio::sync::mpsc::Receiver<String>) {
        let (sink, rx) = LogSink::channel(16);
        (sink.session("s", "127.0.0.1:9".parse().unwrap(), "t"), rx)
    }
    fn send(s: &'static str) -> Action {
        Action::Send(Bytes::from_static(s.as_bytes()))
    }

    #[tokio::test]
    async fn sends_in_order_and_logs_what_went_on_the_wire() {
        let (log, mut rx) = log();
        let mut out = Collect::default();
        let r = apply(
            &mut out,
            &log,
            vec![
                send("a\n"),
                Action::Delay(Duration::from_millis(1)),
                send("b\n"),
            ],
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            r,
            Applied {
                flow: Flow::Continue,
                prompt: None
            }
        );
        assert_eq!(out.0, [b"a\r\n".to_vec(), b"b\r\n".to_vec()]);
        let line = rx.try_recv().unwrap();
        assert!(
            line.contains("\"hex\":\"610d0a\""),
            "logged post-translation: {line}"
        );
    }

    #[tokio::test]
    async fn non_tty_output_is_untouched() {
        let (log, _rx) = log();
        let mut out = Collect::default();
        apply(&mut out, &log, vec![send("a\n")], false)
            .await
            .unwrap();
        assert_eq!(out.0, [b"a\n".to_vec()]);
    }

    #[tokio::test]
    async fn close_stops_processing_and_keeps_an_earlier_prompt() {
        let (log, _rx) = log();
        let mut out = Collect::default();
        let r = apply(
            &mut out,
            &log,
            vec![
                Action::Prompt("$ ".into()),
                send("bye"),
                Action::Close,
                send("never"),
            ],
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            r,
            Applied {
                flow: Flow::Close,
                prompt: Some("$ ".into())
            }
        );
        assert_eq!(out.0, [b"bye".to_vec()]);
    }

    #[tokio::test]
    async fn prompts_are_sanitized_and_the_last_one_wins() {
        let (log, _rx) = log();
        let r = apply(
            &mut Collect::default(),
            &log,
            vec![
                Action::Prompt("first".into()),
                Action::Prompt("a\x1b[2Jb$ ".into()),
            ],
            false,
        )
        .await
        .unwrap();
        assert_eq!(r.prompt.as_deref(), Some("a?[2Jb$ "));
    }

    #[tokio::test]
    async fn auth_results_are_ignored_outside_authentication() {
        let (log, _rx) = log();
        let mut out = Collect::default();
        apply(
            &mut out,
            &log,
            vec![Action::AuthResult(true), Action::OpenShell],
            false,
        )
        .await
        .unwrap();
        assert!(out.0.is_empty());
    }

    #[tokio::test]
    async fn transport_errors_propagate() {
        let (log, _rx) = log();
        assert_eq!(
            apply(&mut Broken, &log, vec![send("x")], false)
                .await
                .unwrap_err(),
            "peer gone"
        );
    }

    #[tokio::test]
    async fn stream_out_writes_to_any_async_writer() {
        use tokio::io::AsyncReadExt;
        let (mut a, mut b) = tokio::io::duplex(64);
        StreamOut(&mut a).write(b"hello".to_vec()).await.unwrap();
        drop(a);
        let mut got = vec![];
        b.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");
    }
}
