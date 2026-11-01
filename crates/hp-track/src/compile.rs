//! Validation: turns the raw schema into the runtime model, collecting
//! every problem instead of stopping at the first. Loading is
//! all-or-nothing; the honeypot refuses to start with an invalid track.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt;

use regex::Regex;
use serde_yaml::Value as Yaml;

use crate::event::{EventKind, EVENT_VARS};
use crate::expr::{self, Template, Value};
use crate::model::{Delay, Matcher, Rule, Setter, State, Step, Track};
use crate::schema::{fallback_steps, RawMatch, RawRule, RawState, RawStep, RawTrack};

#[derive(Debug)]
pub struct TrackError(pub Vec<String>);

impl fmt::Display for TrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid track ({} problem(s)):", self.0.len())?;
        for e in &self.0 {
            write!(f, "\n  - {e}")?;
        }
        Ok(())
    }
}
impl std::error::Error for TrackError {}

/// Parse and validate track YAML.
pub(crate) fn compile(src: &str) -> Result<Track, TrackError> {
    let raw: RawTrack = serde_yaml::from_str(src).map_err(|e| TrackError(vec![e.to_string()]))?;
    let mut c = Compiler {
        errs: vec![],
        edges: BTreeMap::new(),
    };
    let track = c.compile(raw);
    if c.errs.is_empty() {
        Ok(track)
    } else {
        Err(TrackError(c.errs))
    }
}

struct Compiler {
    errs: Vec<String>,
    /// state -> goto targets (for reachability)
    edges: BTreeMap<String, BTreeSet<String>>,
}

fn scalar(v: &Yaml) -> Option<Value> {
    match v {
        Yaml::Bool(b) => Some(Value::Bool(*b)),
        Yaml::Number(n) => n.as_i64().map(Value::Int),
        Yaml::String(s) => Some(Value::Str(s.clone())),
        _ => None,
    }
}

impl Compiler {
    fn compile(&mut self, raw: RawTrack) -> Track {
        let mut vars = BTreeMap::new();
        for (k, v) in &raw.vars {
            match scalar(v) {
                Some(val) => {
                    vars.insert(k.clone(), val);
                }
                None => self
                    .errs
                    .push(format!("var `{k}`: must be an integer, string or bool")),
            }
        }
        if raw.name.trim().is_empty() {
            self.errs.push("`name` must not be empty".into());
        }
        if !raw.states.contains_key(&raw.start) {
            self.errs
                .push(format!("`start` names unknown state `{}`", raw.start));
        }

        let var_names: HashSet<String> = vars.keys().cloned().collect();
        let mut states = BTreeMap::new();
        for (name, rs) in raw.states {
            let state = self.compile_state(&name, rs, &var_names);
            states.insert(name, state);
        }

        // goto targets must exist
        let known: HashSet<&String> = states.keys().collect();
        for (from, tos) in &self.edges {
            for to in tos {
                if !known.contains(to) {
                    self.errs
                        .push(format!("state `{from}`: goto targets unknown state `{to}`"));
                }
            }
        }
        // every state must be reachable from start
        if states.contains_key(&raw.start) {
            let mut seen = BTreeSet::from([raw.start.clone()]);
            let mut stack = vec![raw.start.clone()];
            while let Some(s) = stack.pop() {
                for t in self.edges.get(&s).into_iter().flatten() {
                    if seen.insert(t.clone()) {
                        stack.push(t.clone());
                    }
                }
            }
            for s in states.keys().filter(|s| !seen.contains(*s)) {
                self.errs
                    .push(format!("state `{s}` is unreachable from `{}`", raw.start));
            }
        }
        Track {
            name: raw.name,
            vars,
            start: raw.start,
            states,
        }
    }

    fn compile_state(&mut self, name: &str, rs: RawState, vars: &HashSet<String>) -> State {
        self.edges.entry(name.to_string()).or_default();
        let mut rules = Vec::new();
        for (i, r) in rs.on.into_iter().enumerate() {
            let loc = format!("state `{name}` rule #{}", i + 1);
            rules.push(self.compile_rule(name, &loc, r, vars));
        }
        let loc = format!("state `{name}` fallback");
        let fallback = match rs.fallback {
            None => {
                self.errs.push(format!("state `{name}` has no `fallback`"));
                vec![]
            }
            Some(v) => match fallback_steps(v) {
                Err(e) => {
                    self.errs.push(format!("{loc}: {e}"));
                    vec![]
                }
                Ok(raw_steps) => {
                    let known = |n: &str| vars.contains(n) || EVENT_VARS.contains(&n);
                    self.steps(name, &loc, raw_steps, &known, vars)
                }
            },
        };
        State { rules, fallback }
    }

    fn compile_rule(&mut self, state: &str, loc: &str, r: RawRule, vars: &HashSet<String>) -> Rule {
        let (matcher, captures) = self.matcher(loc, r.matcher);
        let known = |n: &str| vars.contains(n) || captures.contains(n) || EVENT_VARS.contains(&n);
        let when = r.when.and_then(|w| match expr::parse(&w) {
            Err(e) => {
                self.errs.push(format!("{loc}: `when`: {e}"));
                None
            }
            Ok(ex) => {
                let mut errs = vec![];
                ex.check(&known, &mut errs);
                self.errs
                    .extend(errs.into_iter().map(|e| format!("{loc}: `when`: {e}")));
                Some(ex)
            }
        });
        let steps = self.steps(state, loc, r.steps, &known, vars);
        Rule {
            matcher,
            when,
            steps,
        }
    }

    fn matcher(&mut self, loc: &str, m: RawMatch) -> (Matcher, HashSet<String>) {
        let mut fields = Vec::new();
        let mut captures = HashSet::new();
        // The event kinds this rule can match: narrowed by `event` and by
        // every field (each field exists only on some kinds of event).
        let mut kinds: Option<Vec<EventKind>> = None;
        if let Some(e) = &m.event {
            match EventKind::parse(e) {
                Some(k) => kinds = Some(vec![k]),
                None => self.errs.push(format!("{loc}: unknown event `{e}`")),
            }
        }
        use EventKind::{AuthAttempt, Command, Raw, Request};
        // The first kind listed is the one a field implies on its own, so
        // `user:` alone still means an auth attempt.
        let specs: [(&'static str, Option<String>, &[EventKind]); 10] = [
            ("command", m.command, &[Command]),
            ("user", m.user, &[AuthAttempt, Request]),
            ("password", m.password, &[AuthAttempt, Request]),
            ("op", m.op, &[Request]),
            ("method", m.method, &[Request]),
            ("path", m.path, &[Request]),
            ("query", m.query, &[Request]),
            ("headers", m.headers, &[Request]),
            ("body", m.body, &[Request]),
            ("raw", m.raw, &[Raw]),
        ];
        let mut conflict = false;
        for (field, pat, allowed) in specs {
            let Some(pat) = pat else { continue };
            let narrowed: Vec<EventKind> = match &kinds {
                None => allowed.to_vec(),
                Some(k) => k.iter().copied().filter(|k| allowed.contains(k)).collect(),
            };
            if narrowed.is_empty() && !conflict {
                conflict = true;
                self.errs.push(format!(
                    "{loc}: match fields conflict (`{field}` cannot apply to {:?})",
                    kinds.as_deref().unwrap_or_default()
                ));
            }
            if !narrowed.is_empty() {
                kinds = Some(narrowed);
            }
            match Regex::new(&pat) {
                Ok(re) => {
                    captures.extend(re.capture_names().flatten().map(String::from));
                    fields.push((field, re));
                }
                Err(e) => self
                    .errs
                    .push(format!("{loc}: bad regex for `{field}`: {e}")),
            }
        }
        (
            Matcher {
                event: kinds.and_then(|k| k.first().copied()),
                fields,
            },
            captures,
        )
    }

    fn steps(
        &mut self,
        state: &str,
        loc: &str,
        raw: Vec<RawStep>,
        known: &dyn Fn(&str) -> bool,
        vars: &HashSet<String>,
    ) -> Vec<Step> {
        let mut out = Vec::new();
        for RawStep(key, val) in raw {
            let mut errs = Vec::new();
            let step = match key.as_str() {
                "send" => match val.as_str() {
                    Some(s) => match Template::parse(s) {
                        Ok(t) => {
                            t.check(known, &mut errs);
                            Some(Step::Send(t))
                        }
                        Err(e) => {
                            errs.push(format!("`send`: {e}"));
                            None
                        }
                    },
                    None => {
                        errs.push("`send` needs a string".into());
                        None
                    }
                },
                "set" => self.set_step(&val, known, vars, &mut errs),
                "delay" => match val.as_str().map(parse_delay) {
                    Some(Ok(d)) => Some(Step::Delay(d)),
                    Some(Err(e)) => {
                        errs.push(format!("`delay`: {e}"));
                        None
                    }
                    None => {
                        errs.push("`delay` needs a string like `400ms` or `1s..2s`".into());
                        None
                    }
                },
                "auth" => match val.as_bool() {
                    Some(b) => Some(Step::Auth(b)),
                    None => {
                        errs.push("`auth` needs true or false".into());
                        None
                    }
                },
                "open_shell" => match val.as_bool() {
                    Some(true) => Some(Step::OpenShell),
                    Some(false) => None,
                    None => {
                        errs.push("`open_shell` needs true or false".into());
                        None
                    }
                },
                "goto" => match val.as_str() {
                    Some(t) => {
                        self.edges
                            .entry(state.to_string())
                            .or_default()
                            .insert(t.to_string());
                        Some(Step::Goto(t.to_string()))
                    }
                    None => {
                        errs.push("`goto` needs a state name".into());
                        None
                    }
                },
                "tag" => match val.as_str() {
                    Some(t) if !t.is_empty() => Some(Step::Tag(t.to_string())),
                    _ => {
                        errs.push("`tag` needs a non-empty string".into());
                        None
                    }
                },
                "close" => match val {
                    Yaml::Bool(false) => None,
                    _ => Some(Step::Close),
                },
                other => {
                    errs.push(format!("unknown step `{other}` (expected send, set, delay, auth, open_shell, goto, tag, close)"));
                    None
                }
            };
            self.errs
                .extend(errs.into_iter().map(|e| format!("{loc}: {e}")));
            out.extend(step);
        }
        out
    }

    fn set_step(
        &mut self,
        val: &Yaml,
        known: &dyn Fn(&str) -> bool,
        vars: &HashSet<String>,
        errs: &mut Vec<String>,
    ) -> Option<Step> {
        let Some(map) = val.as_mapping() else {
            errs.push("`set` needs a map of variable: value".into());
            return None;
        };
        let mut sets = Vec::new();
        for (k, v) in map {
            let Some(name) = k.as_str() else {
                errs.push("`set` keys must be strings".into());
                continue;
            };
            if !vars.contains(name) {
                errs.push(format!(
                    "`set` assigns undeclared var `{name}` (declare it under `vars`)"
                ));
            }
            let setter = match v {
                Yaml::String(s) if expr::is_template(s) => match Template::parse(s) {
                    Ok(t) => {
                        t.check(known, errs);
                        Some(Setter::Template(t))
                    }
                    Err(e) => {
                        errs.push(format!("`set {name}`: {e}"));
                        None
                    }
                },
                Yaml::String(s) => match expr::parse(s) {
                    Ok(ex) => {
                        let mut es = vec![];
                        ex.check(known, &mut es);
                        errs.extend(es.into_iter().map(|e| format!("`set {name}`: {e}")));
                        Some(Setter::Expr(ex))
                    }
                    Err(e) => {
                        errs.push(format!("`set {name}`: {e}"));
                        None
                    }
                },
                other => match scalar(other) {
                    Some(v) => Some(Setter::Lit(v)),
                    None => {
                        errs.push(format!("`set {name}`: unsupported value"));
                        None
                    }
                },
            };
            sets.extend(setter.map(|s| (name.to_string(), s)));
        }
        Some(Step::Set(sets))
    }
}

fn parse_delay(s: &str) -> Result<Delay, String> {
    let one = |p: &str| humantime::parse_duration(p.trim()).map_err(|e| format!("{p:?}: {e}"));
    let (min, max) = match s.split_once("..") {
        Some((a, b)) => (one(a)?, one(b)?),
        None => {
            let d = one(s)?;
            (d, d)
        }
    };
    if min > max {
        return Err(format!("{s:?}: min is greater than max"));
    }
    Ok(Delay { min, max })
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = "
name: t
vars: { n: 0 }
start: a
states:
  a:
    on:
      - match: { command: '^go (?P<x>\\w+)$' }
        when: n < 3
        do: [ { set: { n: 'n + 1' } }, { goto: b } ]
    fallback: { send: 'no\\n' }
  b:
    fallback: [ { send: '${command}' }, { delay: '1s..2s' } ]
";

    fn errs(src: &str) -> String {
        match Track::from_yaml(src) {
            Ok(_) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn valid_track_loads() {
        let t = Track::from_yaml(OK).unwrap();
        assert_eq!((t.name(), t.state_count()), ("t", 2));
    }

    #[test]
    fn rejects_each_class_of_problem() {
        let cases: &[(&str, &str)] = &[
            ("start: a\nstates: {a: {fallback: {send: x}}}", "missing field `name`"),
            ("name: t\nstart: z\nstates: {a: {fallback: {send: x}}}", "unknown state `z`"),
            ("name: t\nstart: a\nstates: {a: {}}", "no `fallback`"),
            ("name: t\nstart: a\nstates: {a: {fallback: {goto: nope}}}", "unknown state `nope`"),
            ("name: t\nstart: a\nstates: {a: {fallback: {send: x}}, b: {fallback: {send: x}}}", "unreachable"),
            ("name: t\nstart: a\nstates: {a: {on: [{match: {command: '('}}], fallback: {send: x}}}", "bad regex"),
            ("name: t\nstart: a\nstates: {a: {fallback: {send: '${nope}'}}}", "unknown variable `nope`"),
            ("name: t\nstart: a\nstates: {a: {on: [{when: 'x > 1'}], fallback: {send: x}}}", "unknown variable `x`"),
            ("name: t\nstart: a\nstates: {a: {fallback: {set: {q: '1'}}}}", "undeclared var `q`"),
            ("name: t\nstart: a\nstates: {a: {fallback: {frob: 1}}}", "unknown step `frob`"),
            ("name: t\nstart: a\nstates: {a: {fallback: {delay: '5s..1s'}}}", "min is greater"),
            ("name: t\nstart: a\nstates: {a: {fallback: {delay: 'soon'}}}", "delay"),
            ("name: t\nstart: a\nstates: {a: {on: [{match: {event: wat}}], fallback: {send: x}}}", "unknown event"),
            ("name: t\nstart: a\nstates: {a: {on: [{match: {command: x, user: y}}], fallback: {send: x}}}", "conflict"),
            ("name: t\nstart: a\nstates: {a: {on: [{match: {event: connected, path: x}}], fallback: {send: x}}}", "`path` cannot apply"),
            ("name: t\nstart: a\nstates: {a: {on: [{match: {body: '('}}], fallback: {send: x}}}", "bad regex for `body`"),
            ("name: t\nstart: a\nstates: {a: {on: [{when: 'len(1,2)'}], fallback: {send: x}}}", "argument"),
            ("name: t\nstart: a\nbogus: 1\nstates: {a: {fallback: {send: x}}}", "bogus"),
            ("name: t\nvars: {v: [1]}\nstart: a\nstates: {a: {fallback: {send: x}}}", "var `v`"),
        ];
        for (src, want) in cases {
            let e = errs(src);
            assert!(e.contains(want), "expected {want:?} in {e:?} for {src}");
        }
    }

    /// Wrap a fallback body in an otherwise valid track.
    fn with_fallback(body: &str) -> String {
        format!("name: t\nvars: {{ n: 0 }}\nstart: a\nstates: {{a: {{fallback: {body}}}}}")
    }

    #[test]
    fn rejects_malformed_steps() {
        let cases: &[(&str, &str)] = &[
            ("{send: 5}", "`send` needs a string"),
            ("{send: 'x ${'}", "unterminated"),
            ("{auth: maybe}", "`auth` needs"),
            ("{open_shell: maybe}", "`open_shell` needs"),
            ("{goto: 5}", "`goto` needs"),
            ("{tag: ''}", "`tag` needs"),
            ("{delay: 5}", "`delay` needs"),
            ("{set: 5}", "`set` needs a map"),
            ("{set: {n: [1]}}", "unsupported value"),
            ("{set: {n: '1 +'}}", "`set n`"),
            ("{set: {n: '${1 +}'}}", "`set n`"),
            ("{set: {n: 'nope + 1'}}", "unknown variable"),
            ("{set: {1: 2}}", "keys must be strings"),
            ("[{send: a, tag: b}]", "exactly one key"),
            ("[1]", "invalid type"),
            ("{1: 2}", "step name must be a string"),
            ("5", "must be a step or a list"),
        ];
        for (body, want) in cases {
            let e = errs(&with_fallback(body));
            assert!(e.contains(want), "expected {want:?} in {e:?} for {body}");
        }
    }

    #[test]
    fn accepts_every_step_kind_and_form() {
        for body in [
            "[{send: 'x'}, {set: {n: 5}}, {set: {n: 'n * 2'}}, {set: {n: '${n}'}}, {delay: 1s}, {auth: true}, {tag: t}, {close: true}, {close: false}]",
            "{send: 'x', tag: t}",
        ] {
            let e = errs(&with_fallback(body));
            assert!(e.is_empty(), "{body}: {e}");
        }
    }

    #[test]
    fn every_match_field_is_accepted_and_captures_are_scoped_to_their_rule() {
        let ok = "name: t\nstart: a\nstates:\n  a:\n    on:\n      - match: { user: '^(?P<u>.+)$' }\n        do: [ { send: '${u}' } ]\n      - match: { password: x }\n      - match: { op: x }\n      - match: { raw: x }\n      - match: { event: connected }\n      - {}\n    fallback: { send: x }\n";
        assert_eq!(errs(ok), "");
        let leaked = ok.replace(
            "      - match: { password: x }",
            "      - match: { password: x }\n        do: [ { send: '${u}' } ]",
        );
        assert!(errs(&leaked).contains("unknown variable `u`"));
    }

    #[test]
    fn load_reads_files_and_reports_io_errors() {
        let dir = std::env::temp_dir().join(format!("hp-track-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.yaml");
        std::fs::write(&path, OK).unwrap();
        assert_eq!(Track::load(&path).unwrap().name, "t");
        std::fs::remove_dir_all(&dir).unwrap();
        let e = Track::load(&path).unwrap_err().to_string();
        assert!(e.contains("reading"), "{e}");
    }

    #[test]
    fn rejects_empty_name() {
        assert!(
            errs("name: ' '\nstart: a\nstates: {a: {fallback: {send: x}}}")
                .contains("`name` must not be empty")
        );
    }

    #[test]
    fn reports_all_problems_at_once() {
        let e = errs(
            "name: t\nstart: a\nstates: {a: {on: [{match: {command: '('}}], fallback: {goto: zz}}}",
        );
        assert!(e.contains("bad regex") && e.contains("zz"), "{e}");
    }
}
