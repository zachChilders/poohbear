//! Track engine: YAML-defined per-session state machines.
//!
//! Layers, bottom to top:
//! - `expr`: the tiny expression/template language (no knowledge of tracks)
//! - `event`: how plugin events are exposed to that language
//! - `schema` -> `compile` -> `model`: untrusted YAML in, validated model out
//! - `engine`: runs a model against events, one [`Session`] per connection
//!
//! The public surface is deliberately small; the compiled model is opaque.

mod compile;
mod engine;
mod event;
mod expr;
mod model;
mod schema;

pub use compile::TrackError;
pub use engine::{Outcome, Session};
pub use expr::Value;
pub use model::Track;
