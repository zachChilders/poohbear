//! A [`Runner`] that needs no Docker, for tests (here and in the honeypot's
//! end-to-end tests). It runs the testkit's scripted shell and records what it
//! was asked to start and stop.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hp_testkit::spawn_fake_shell;

use crate::launch::Spec;
use crate::runner::{Runner, Running, Stop};

pub struct FakeRunner {
    responder: fn(&str) -> Option<String>,
    fail: bool,
    specs: Mutex<Vec<Spec>>,
    live: Arc<AtomicUsize>,
    stopped: Arc<AtomicUsize>,
    discarded: Mutex<Vec<String>>,
}

impl FakeRunner {
    pub fn new(responder: fn(&str) -> Option<String>) -> Arc<FakeRunner> {
        Arc::new(FakeRunner {
            responder,
            fail: false,
            specs: Mutex::default(),
            live: Arc::default(),
            stopped: Arc::default(),
            discarded: Mutex::default(),
        })
    }

    /// A runner whose sandboxes never start.
    pub fn failing() -> Arc<FakeRunner> {
        Arc::new(FakeRunner {
            fail: true,
            ..Arc::into_inner(FakeRunner::new(|_| None)).expect("sole owner")
        })
    }

    pub fn specs(&self) -> Vec<Vec<String>> {
        self.specs
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.args.clone())
            .collect()
    }

    /// Shells running right now.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// Times `stop` was called.
    pub fn stopped(&self) -> usize {
        self.stopped.load(Ordering::SeqCst)
    }

    pub fn discarded(&self) -> Vec<String> {
        self.discarded.lock().unwrap().clone()
    }
}

/// The command a spec runs, wherever the launcher put it.
fn command_of(args: &[String]) -> Option<String> {
    args.iter()
        .find_map(|a| a.strip_prefix("HP_COMMAND=").map(String::from))
        .or_else(|| {
            args.iter()
                .position(|a| a == "-c")
                .and_then(|i| args.get(i + 1).cloned())
        })
}

struct Stopped(Arc<AtomicUsize>);

#[async_trait]
impl Stop for Stopped {
    async fn stop(self: Box<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Runner for FakeRunner {
    async fn start(&self, spec: &Spec) -> anyhow::Result<Running> {
        anyhow::ensure!(!self.fail, "docker create failed: no such image");
        self.specs.lock().unwrap().push(Spec {
            name: spec.name.clone(),
            args: spec.args.clone(),
        });
        let io = spawn_fake_shell(self.responder, command_of(&spec.args), self.live.clone());
        Ok(Running {
            io: Box::new(io),
            stop: Box::new(Stopped(self.stopped.clone())),
        })
    }

    async fn discard(&self, name: &str) {
        self.discarded.lock().unwrap().push(name.to_string());
    }
}
