//! The validated runtime model of a track. Built only by `compile`; the
//! engine reads it. Only [`Track`] is public API, and it is opaque.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use regex::Regex;

use crate::compile::{self, TrackError};
use crate::event::EventKind;
use crate::expr::{Expr, Template, Value};

#[derive(Debug)]
pub(crate) struct Matcher {
    pub(crate) event: Option<EventKind>,
    /// (event variable name, regex)
    pub(crate) fields: Vec<(&'static str, Regex)>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Delay {
    pub(crate) min: Duration,
    pub(crate) max: Duration,
}

#[derive(Debug)]
pub(crate) enum Setter {
    Lit(Value),
    Expr(Expr),
    Template(Template),
}

#[derive(Debug)]
pub(crate) enum Step {
    Send(Template),
    Set(Vec<(String, Setter)>),
    Delay(Delay),
    Auth(bool),
    /// Give the session a real shell when it asks for one.
    OpenShell,
    Goto(String),
    Tag(String),
    Close,
}

#[derive(Debug)]
pub(crate) struct Rule {
    pub(crate) matcher: Matcher,
    pub(crate) when: Option<Expr>,
    pub(crate) steps: Vec<Step>,
}

#[derive(Debug)]
pub(crate) struct State {
    pub(crate) rules: Vec<Rule>,
    pub(crate) fallback: Vec<Step>,
}

#[derive(Debug)]
pub struct Track {
    pub(crate) name: String,
    pub(crate) vars: BTreeMap<String, Value>,
    pub(crate) start: String,
    pub(crate) states: BTreeMap<String, State>,
}

impl Track {
    /// Read, parse and validate a track file. Any problem is an error.
    pub fn load(path: &Path) -> Result<Track, TrackError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| TrackError(vec![format!("reading {}: {e}", path.display())]))?;
        Track::from_yaml(&text)
    }

    /// Parse and validate track YAML. Any problem is an error.
    pub fn from_yaml(src: &str) -> Result<Track, TrackError> {
        compile::compile(src)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn state_count(&self) -> usize {
        self.states.len()
    }
}
