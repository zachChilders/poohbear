//! The generic FSM: per-session state + variables, driven by plugin events.
//!
//! Evaluation is pure and deterministic given the event sequence and the
//! seed; the seed only affects delay jitter.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hp_core::{Action, Event};

use crate::event::{self, EventKind};
use crate::expr::Value;
use crate::model::{Delay, Rule, Setter, Step, Track};

/// Longest string a variable may hold; keeps a hostile session from growing memory.
const MAX_VAR_LEN: usize = 64 * 1024;

/// What one event produced.
#[derive(Debug, Default)]
pub struct Outcome {
    pub actions: Vec<Action>,
    /// Tags to flag in the session log for alerting.
    pub tags: Vec<String>,
    /// (from, to) state transitions, in order.
    pub transitions: Vec<(String, String)>,
    /// Runtime evaluation errors (the offending step/rule is skipped).
    pub errors: Vec<String>,
}

pub struct Session {
    track: Arc<Track>,
    state: String,
    vars: BTreeMap<String, Value>,
    rng: SplitMix64,
}

impl Session {
    pub fn new(track: Arc<Track>, seed: u64) -> Session {
        Session {
            state: track.start.clone(),
            vars: track.vars.clone(),
            track,
            rng: SplitMix64(seed),
        }
    }

    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn vars(&self) -> &BTreeMap<String, Value> {
        &self.vars
    }

    pub fn step(&mut self, ev: &Event) -> Outcome {
        let track = self.track.clone();
        let mut out = Outcome::default();
        let (kind, mut env) = event::bind(ev);
        let Some(state) = track.states.get(&self.state) else {
            out.errors
                .push(format!("session is in unknown state `{}`", self.state));
            return out;
        };
        for (i, rule) in state.rules.iter().enumerate() {
            match self.try_rule(rule, kind, &env) {
                Ok(Some(caps)) => {
                    env.extend(caps);
                    self.run(&rule.steps, &mut env, &mut out);
                    return out;
                }
                Ok(None) => {}
                Err(e) => out
                    .errors
                    .push(format!("state `{}` rule #{}: {e}", self.state, i + 1)),
            }
        }
        self.run(&state.fallback, &mut env, &mut out);
        out
    }

    /// Ok(Some(captures)) if the rule matches.
    fn try_rule(
        &self,
        rule: &Rule,
        kind: EventKind,
        env: &HashMap<String, Value>,
    ) -> Result<Option<HashMap<String, Value>>, String> {
        if rule.matcher.event.is_some_and(|k| k != kind) {
            return Ok(None);
        }
        let mut caps = HashMap::new();
        for (field, re) in &rule.matcher.fields {
            let Some(Value::Str(text)) = env.get(*field) else {
                return Ok(None);
            };
            let Some(c) = re.captures(text) else {
                return Ok(None);
            };
            for name in re.capture_names().flatten() {
                caps.insert(
                    name.to_string(),
                    Value::Str(c.name(name).map_or("", |m| m.as_str()).to_string()),
                );
            }
        }
        if let Some(when) = &rule.when {
            let lookup = |n: &str| {
                caps.get(n)
                    .or_else(|| env.get(n))
                    .or_else(|| self.vars.get(n))
                    .cloned()
            };
            match when.eval(&lookup)? {
                Value::Bool(true) => {}
                Value::Bool(false) => return Ok(None),
                v => return Err(format!("`when` must be bool, got {}", v.type_name())),
            }
        }
        Ok(Some(caps))
    }

    fn run(&mut self, steps: &[Step], env: &mut HashMap<String, Value>, out: &mut Outcome) {
        for step in steps {
            match step {
                Step::Send(t) => {
                    let r = t.render(&|n| self.lookup(env, n));
                    match r {
                        Ok(s) => out.actions.push(Action::Send(Bytes::from(s))),
                        Err(e) => out.errors.push(format!("send: {e}")),
                    }
                }
                Step::Set(sets) => {
                    for (name, setter) in sets {
                        let r = match setter {
                            Setter::Lit(v) => Ok(v.clone()),
                            Setter::Expr(e) => e.eval(&|n| self.lookup(env, n)),
                            Setter::Template(t) => {
                                t.render(&|n| self.lookup(env, n)).map(Value::Str)
                            }
                        };
                        match r {
                            Ok(Value::Str(s)) if s.len() > MAX_VAR_LEN => out
                                .errors
                                .push(format!("set {name}: value exceeds {MAX_VAR_LEN} bytes")),
                            Ok(v) => {
                                self.vars.insert(name.clone(), v);
                            }
                            Err(e) => out.errors.push(format!("set {name}: {e}")),
                        }
                    }
                }
                Step::Delay(d) => out.actions.push(Action::Delay(self.jitter(*d))),
                Step::Auth(ok) => out.actions.push(Action::AuthResult(*ok)),
                Step::Goto(to) => {
                    out.transitions.push((self.state.clone(), to.clone()));
                    self.state = to.clone();
                }
                Step::Tag(t) => out.tags.push(t.clone()),
                Step::Close => out.actions.push(Action::Close),
            }
        }
    }

    fn lookup(&self, env: &HashMap<String, Value>, n: &str) -> Option<Value> {
        env.get(n).or_else(|| self.vars.get(n)).cloned()
    }

    fn jitter(&mut self, d: Delay) -> Duration {
        let span = d.max.saturating_sub(d.min).as_millis() as u64;
        if span == 0 {
            return d.min;
        }
        d.min + Duration::from_millis(self.rng.next() % (span + 1))
    }
}

struct SplitMix64(u64);
impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
