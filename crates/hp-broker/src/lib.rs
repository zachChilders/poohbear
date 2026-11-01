//! The sandbox broker: the only process that touches the container runtime.
//!
//! The honeypot (which attackers talk to) never holds the runtime's socket,
//! because that is root on the host. It asks this broker over a unix socket
//! for a shell (`hp-sandbox` protocol), and the broker decides everything
//! that matters: the image, the limits, the network (always none), how many
//! sandboxes may exist, and when they die. A compromised honeypot can open
//! shells, which is the product, but cannot choose flags or become root.

pub mod launch;
pub mod policy;
pub mod runner;
pub mod server;

#[cfg(any(test, feature = "testing"))]
pub mod fake;

pub use policy::Policy;
pub use runner::{DockerRunner, Runner};
pub use server::Broker;
