//! How the honeypot reaches a sandboxed shell.
//!
//! The honeypot never touches a container runtime. It asks a separate,
//! privileged broker (`hp-broker`) over a unix socket, using the small
//! protocol in [`proto`], and gets back a byte stream. This crate is the
//! contract and the honeypot's client: it contains no container code.

pub mod proto;

mod client;

pub use client::ContainerBackend;
