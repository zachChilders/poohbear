//! Reading a behavior's reply.

use std::time::Duration;

use hp_core::Action;

/// The ordered actions a behavior returned for one event.
#[derive(Debug, Default)]
pub struct Reaction(Vec<Action>);

impl Reaction {
    pub fn new(actions: Vec<Action>) -> Reaction {
        Reaction(actions)
    }

    pub fn into_actions(self) -> Vec<Action> {
        self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the behavior asked to end the session.
    pub fn wants_close(&self) -> bool {
        self.0.iter().any(|a| matches!(a, Action::Close))
    }

    /// All `Send` payloads concatenated, ignoring everything else. For
    /// protocols with no channel to write to yet (pre-auth banners).
    pub fn text(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for action in &self.0 {
            if let Action::Send(data) = action {
                out.extend_from_slice(data);
            }
        }
        out
    }

    /// Interpret the reply to an authentication attempt.
    pub fn verdict(self) -> Verdict {
        let mut v = Verdict::default();
        for action in self.0 {
            match action {
                // The last verdict wins; with none, the attempt fails.
                Action::AuthResult(ok) => v.accepted = ok,
                Action::Send(data) => v.welcome.extend_from_slice(&data),
                Action::Prompt(p) => v.prompt = Some(p),
                Action::Delay(d) => v.delay += d,
                Action::Close => v.close = true,
            }
        }
        v
    }
}

/// A behavior's decision on an authentication attempt, in protocol-neutral
/// terms. Every protocol with a login (SSH, Telnet, FTP, MQTT, HTTP auth...)
/// reads it the same way.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// The behavior said yes. Check [`Verdict::granted`] before acting.
    pub accepted: bool,
    /// Text sent alongside the verdict; show it once the user is in.
    pub welcome: Vec<u8>,
    /// The prompt to use for the session that follows.
    pub prompt: Option<String>,
    /// Total pacing delay to apply before answering.
    pub delay: Duration,
    /// The behavior wants the connection dropped instead of an answer.
    pub close: bool,
}

impl Verdict {
    /// True only if the user should actually be let in.
    pub fn granted(&self) -> bool {
        self.accepted && !self.close
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn send(s: &'static str) -> Action {
        Action::Send(Bytes::from_static(s.as_bytes()))
    }

    #[test]
    fn verdict_takes_the_last_decision_and_totals_delays() {
        let v = Reaction::new(vec![
            Action::Delay(Duration::from_millis(5)),
            Action::AuthResult(false),
            send("hi "),
            Action::Delay(Duration::from_millis(7)),
            Action::AuthResult(true),
            send("there"),
            Action::Prompt("$ ".into()),
        ])
        .verdict();
        assert!(v.granted());
        assert_eq!(v.welcome, b"hi there");
        assert_eq!(v.delay, Duration::from_millis(12));
        assert_eq!(v.prompt.as_deref(), Some("$ "));
    }

    #[test]
    fn no_verdict_means_not_granted() {
        assert!(!Reaction::default().verdict().granted());
        assert!(!Reaction::new(vec![send("x")]).verdict().granted());
    }

    #[test]
    fn close_overrides_acceptance() {
        let v = Reaction::new(vec![Action::AuthResult(true), Action::Close]).verdict();
        assert!(v.accepted && v.close && !v.granted());
    }

    #[test]
    fn text_and_close_helpers() {
        let r = Reaction::new(vec![send("a"), Action::Delay(Duration::ZERO), send("b")]);
        assert_eq!(r.text(), b"ab");
        assert!(!r.wants_close() && !r.is_empty());
        assert!(Reaction::new(vec![Action::Close]).wants_close());
        assert!(Reaction::default().is_empty());
        assert_eq!(Reaction::new(vec![Action::Close]).into_actions().len(), 1);
    }
}
