//! The emulated machine every protocol shares.
//!
//! A [`World`] is a host spec (YAML: identity, users, files, processes) plus a
//! shell emulator over an in-memory filesystem. A behavior drives it through
//! the `hp_core::Host` interface, so SSH, Telnet or anything else that offers
//! a shell gets the same machine, with real depth, without scripting each
//! command in a track.
//!
//! Nothing here touches the real machine, the network or the clock beyond
//! reading the time. Everything an attacker does lands in a per-session copy
//! of the filesystem.

mod cmds;
pub mod fs;
pub mod parse;
mod shell;
pub mod spec;
pub mod timefmt;

pub use shell::{system_clock, Clock, Shell, ShellHost, World};
pub use spec::HostSpec;
