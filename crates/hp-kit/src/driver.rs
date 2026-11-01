//! The per-session driver: a plugin's single point of contact with the
//! `Behavior`, and the place the cross-protocol session rules live.

use hp_core::{Behavior, Event, Limits};
use hp_log::{Limit, Record, SessionLogger};

use crate::reaction::Reaction;

/// Returned by [`Driver::receive`] when the peer sent more than the session
/// is allowed. The plugin should end the session.
#[derive(Debug, PartialEq, Eq)]
pub struct InputLimit;

/// Rules every protocol gets for free:
/// - the behavior sees `Disconnected` exactly once, however the session ends
///   (clean close, error, panic, or the server cancelling a timeout), because
///   it is delivered on drop;
/// - inbound bytes are counted against `max_input_bytes`, and the byte that
///   crosses the line is *not* logged as received data;
/// - every inbound chunk is logged as an `rx` record.
pub struct Driver {
    behavior: Box<dyn Behavior>,
    log: SessionLogger,
    max_input_bytes: u64,
    received: u64,
}

impl Driver {
    pub fn new(log: SessionLogger, behavior: Box<dyn Behavior>, limits: &Limits) -> Driver {
        Driver {
            behavior,
            log,
            max_input_bytes: limits.max_input_bytes,
            received: 0,
        }
    }

    pub fn log(&self) -> &SessionLogger {
        &self.log
    }

    /// Tell the behavior a peer connected.
    pub fn connect(&mut self) -> Reaction {
        self.react(&Event::Connected)
    }

    /// Hand the behavior an event and return what it wants done.
    pub fn react(&mut self, event: &Event) -> Reaction {
        Reaction::new(self.behavior.react(event))
    }

    /// Account for and log inbound bytes. Call once per chunk read from the
    /// peer, before interpreting it.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), InputLimit> {
        self.received += data.len() as u64;
        if self.received > self.max_input_bytes {
            self.log.event(Record::LimitExceeded {
                limit: Limit::MaxInputBytes,
                total: self.received,
            });
            return Err(InputLimit);
        }
        self.log.event(Record::rx(data));
        Ok(())
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Nothing can be delivered any more, so the reply is discarded.
        self.behavior.react(&Event::Disconnected);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hp_core::Action;
    use hp_log::LogSink;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct Spy(Arc<Mutex<Vec<String>>>);
    impl Behavior for Spy {
        fn react(&mut self, event: &Event) -> Vec<Action> {
            self.0.lock().unwrap().push(format!("{event:?}"));
            vec![Action::Close]
        }
    }

    fn driver(
        max: u64,
    ) -> (
        Driver,
        Arc<Mutex<Vec<String>>>,
        tokio::sync::mpsc::Receiver<String>,
    ) {
        let (sink, rx) = LogSink::channel(16);
        let log = sink.session("s", "127.0.0.1:9".parse().unwrap(), "t");
        let seen = Arc::new(Mutex::new(vec![]));
        let limits = Limits {
            session_timeout: Duration::from_secs(1),
            max_input_bytes: max,
        };
        (
            Driver::new(log, Box::new(Spy(seen.clone())), &limits),
            seen,
            rx,
        )
    }

    fn kinds(rx: &mut tokio::sync::mpsc::Receiver<String>) -> Vec<String> {
        std::iter::from_fn(|| rx.try_recv().ok())
            .map(|l| serde_kind(&l))
            .collect()
    }
    fn serde_kind(line: &str) -> String {
        let i = line.find("\"kind\":\"").unwrap() + 8;
        line[i..].split('"').next().unwrap().to_string()
    }

    #[test]
    fn disconnect_is_delivered_exactly_once_on_drop() {
        let (mut d, seen, _rx) = driver(10);
        assert!(d.connect().wants_close());
        drop(d);
        assert_eq!(*seen.lock().unwrap(), ["Connected", "Disconnected"]);
    }

    #[test]
    fn disconnect_is_delivered_even_if_never_connected() {
        let (d, seen, _rx) = driver(10);
        drop(d);
        assert_eq!(*seen.lock().unwrap(), ["Disconnected"]);
    }

    #[test]
    fn input_is_logged_until_the_cap_is_crossed() {
        let (mut d, _seen, mut rx) = driver(6);
        assert_eq!(d.receive(b"abc"), Ok(()));
        assert_eq!(d.receive(b"def"), Ok(()), "exactly at the cap is allowed");
        assert_eq!(d.receive(b"g"), Err(InputLimit));
        assert_eq!(kinds(&mut rx), ["rx", "rx", "limit_exceeded"]);
    }

    #[test]
    fn log_accessor_returns_the_session_logger() {
        let (d, _s, mut rx) = driver(1);
        d.log().event(Record::Connect);
        assert_eq!(kinds(&mut rx), ["connect"]);
    }
}
