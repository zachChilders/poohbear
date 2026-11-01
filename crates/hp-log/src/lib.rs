//! Session logging: the typed record schema ([`Record`]), the sink that
//! writes it ([`LogSink`]) and the per-session handle ([`SessionLogger`]).
//!
//! Process-level diagnostics are *not* handled here; the binary owns
//! `tracing` setup. This crate is only the session-record output contract.

mod record;
mod session;
mod sink;

pub use record::{
    AuthMethod, ChannelRequestKind, CommandSource, Header, Limit, Payload, Record, RejectReason,
};
pub use session::SessionLogger;
pub use sink::LogSink;
