//! Adapter between the track engine and the plugin interface.
//!
//! The engine (`hp-track`) reports an `Outcome`: actions plus tags,
//! transitions and errors. Plugins only understand `Action`s, so this layer
//! hands them the actions and writes everything else to the session log.
//! Neither side knows the other exists.

use std::sync::Arc;

use hp_core::{Action, Behavior, BehaviorFactory, Event};
use hp_log::{Record, SessionLogger};
use hp_track::{Session, Track};

/// Starts a fresh track [`Session`] per connection.
pub struct TrackFactory {
    track: Arc<Track>,
}

impl TrackFactory {
    pub fn new(track: Track) -> TrackFactory {
        TrackFactory {
            track: Arc::new(track),
        }
    }
}

impl BehaviorFactory for TrackFactory {
    fn start(&self, log: &SessionLogger) -> Box<dyn Behavior> {
        // Seeds only jitter delays, so they need to differ, not be secret.
        let seed = uuid::Uuid::new_v4().as_u128() as u64;
        Box::new(TrackBehavior {
            session: Session::new(self.track.clone(), seed),
            log: log.clone(),
        })
    }
}

struct TrackBehavior {
    session: Session,
    log: SessionLogger,
}

impl Behavior for TrackBehavior {
    fn react(&mut self, event: &Event) -> Vec<Action> {
        let out = self.session.step(event);
        for (from, to) in out.transitions {
            self.log.event(Record::Transition { from, to });
        }
        for tag in out.tags {
            self.log.event(Record::Tag { tag });
        }
        for error in out.errors {
            self.log.event(Record::BehaviorError { error });
        }
        out.actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_core::Secret;
    use hp_log::LogSink;
    use serde_json::Value;

    const TRACK: &str = "
name: t
vars: { n: 0 }
start: a
states:
  a:
    on:
      - match: { command: '^go$' }
        do: [ { tag: went }, { send: 'ok' }, { goto: b } ]
      - match: { command: '^bad$' }
        when: n
        do: [ { send: 'never' } ]
    fallback: { send: 'a-fallback' }
  b:
    fallback: { send: 'b-fallback' }
";

    fn start() -> (Box<dyn Behavior>, tokio::sync::mpsc::Receiver<String>) {
        let (sink, rx) = LogSink::channel(16);
        let log = sink.session("s", "127.0.0.1:9".parse().unwrap(), "t");
        let factory = TrackFactory::new(Track::from_yaml(TRACK).unwrap());
        (factory.start(&log), rx)
    }

    fn drain(rx: &mut tokio::sync::mpsc::Receiver<String>) -> Vec<Value> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .map(|l| serde_json::from_str(&l).unwrap())
            .collect()
    }

    fn sent(actions: &[Action]) -> String {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send(b) => Some(String::from_utf8_lossy(b).into_owned()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn returns_actions_and_logs_tags_and_transitions() {
        let (mut b, mut rx) = start();
        let actions = b.react(&Event::Command("go".into()));
        assert_eq!(sent(&actions), "ok");
        let recs = drain(&mut rx);
        let kinds: Vec<_> = recs.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["transition", "tag"]);
        assert_eq!(
            (recs[0]["from"].as_str(), recs[0]["to"].as_str()),
            (Some("a"), Some("b"))
        );
        assert_eq!(recs[1]["tag"], "went");
        assert_eq!(
            sent(&b.react(&Event::Command("x".into()))),
            "b-fallback",
            "state persists"
        );
    }

    #[test]
    fn runtime_errors_are_logged_not_returned() {
        let (mut b, mut rx) = start();
        let actions = b.react(&Event::Command("bad".into()));
        assert_eq!(sent(&actions), "a-fallback");
        let recs = drain(&mut rx);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0]["kind"], "behavior_error");
        assert!(recs[0]["error"].as_str().unwrap().contains("must be bool"));
    }

    #[test]
    fn sessions_are_independent() {
        let (sink, _rx) = LogSink::channel(16);
        let log = sink.session("s", "127.0.0.1:9".parse().unwrap(), "t");
        let factory = TrackFactory::new(Track::from_yaml(TRACK).unwrap());
        let (mut one, mut two) = (factory.start(&log), factory.start(&log));
        one.react(&Event::Command("go".into()));
        assert_eq!(sent(&one.react(&Event::Command("x".into()))), "b-fallback");
        assert_eq!(sent(&two.react(&Event::Command("x".into()))), "a-fallback");
        // unrelated event kinds fall through to the fallback without panicking
        two.react(&Event::AuthAttempt {
            user: "u".into(),
            secret: Secret::new("p"),
        });
    }
}
