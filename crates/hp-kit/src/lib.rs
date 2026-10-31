//! Shared plumbing for protocol plugins.
//!
//! A plugin owns exactly one thing: its wire format. Everything that is the
//! same for every protocol lives here, so a new protocol is a codec plus a
//! mapping to `Event`s, and gets the rest right by construction:
//!
//! - [`Driver`]: one per session; talks to the `Behavior`, guarantees the
//!   connect/disconnect lifecycle, enforces the input cap, logs inbound bytes.
//! - [`Reaction`] / [`Verdict`]: reading a behavior's reply (e.g. an auth verdict).
//! - [`apply`] / [`Output`]: carrying out a reply (send, delay, close, prompt)
//!   over whatever transport the plugin has.
//! - [`term`]: terminal behavior shared by every interactive protocol (line
//!   editing, tty newlines, prompt sanitizing).
//!
//! See `docs/ADDING_A_PROTOCOL.md` for the recipe.

mod driver;
mod output;
mod reaction;
pub mod term;

pub use driver::{Driver, InputLimit};
pub use output::{apply, Applied, Flow, Output, StreamOut};
pub use reaction::{Reaction, Verdict};
