//! Track engine: YAML-defined per-session state machines.

pub mod engine;
pub mod expr;
pub mod track;

pub use engine::{Outcome, Session};
pub use expr::Value;
pub use track::{Track, TrackError};
