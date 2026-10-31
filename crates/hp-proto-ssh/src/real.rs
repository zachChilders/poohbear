//! A real shell behind an SSH channel: what the peer types goes to a sandbox
//! (see `hp_core::ShellBackend`) and whatever it prints comes back.

use hp_core::{AsyncStream, ShellBackend, ShellRequest};
use hp_kit::{pump, Output};
use hp_log::SessionLogger;
use russh::server::Handle;
use russh::ChannelId;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::task::JoinHandle;

/// The kit's [`Output`] over an SSH channel, usable from another task.
struct HandleOut {
    handle: Handle,
    channel: ChannelId,
}

impl Output for HandleOut {
    type Error = ();

    fn write(&mut self, data: Vec<u8>) -> impl std::future::Future<Output = Result<(), ()>> + Send {
        let (handle, channel) = (self.handle.clone(), self.channel);
        async move { handle.data(channel, data).await.map_err(|_| ()) }
    }
}

pub(crate) struct RealShell {
    input: WriteHalf<Box<dyn AsyncStream>>,
    output: JoinHandle<()>,
}

impl RealShell {
    /// Start the shell and begin carrying its output to `channel`. The
    /// channel request is confirmed from the output task, so confirmation
    /// always precedes the first byte.
    pub(crate) async fn start(
        backend: &dyn ShellBackend,
        request: ShellRequest,
        handle: Handle,
        channel: ChannelId,
        log: SessionLogger,
    ) -> anyhow::Result<RealShell> {
        let (reader, input) = tokio::io::split(backend.start(request).await?);
        let output = tokio::spawn(async move {
            let _ = handle.channel_success(channel).await;
            let mut out = HandleOut {
                handle: handle.clone(),
                channel,
            };
            let _ = pump(reader, &mut out, &log).await;
            // The shell ended. The stream does not carry its exit status.
            let _ = handle.exit_status_request(channel, 0).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
        Ok(RealShell { input, output })
    }

    /// Pass the peer's input to the shell. A shell that already ended is not an error.
    pub(crate) async fn send(&mut self, data: &[u8]) {
        let _ = self.input.write_all(data).await;
    }

    /// The peer closed its input: the shell sees end of file.
    pub(crate) async fn end_input(&mut self) {
        let _ = self.input.shutdown().await;
    }
}

impl Drop for RealShell {
    /// However the channel ends (closed, session timed out, panic), stop
    /// forwarding and release the sandbox; dropping `input` ends the shell.
    fn drop(&mut self) {
        self.output.abort();
    }
}
