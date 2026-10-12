//! The one thread that waits for the core's next deadline.
//!
//! The deciding thread says after every step when it next has something to
//! do - a channel's wait over, a listing due or overdue, an allowance or a
//! burst's window at its end - and this thread says so when that time comes,
//! as [`Input::Due`](crate::dispatch::Input::Due). Time is the trail's clock,
//! which counts sleep. The wait itself is `recv_timeout`, which on Windows is
//! `WaitOnAddress` with a relative timeout; whether that timeout runs while
//! the workstation sleeps, Microsoft's pages do not agree, and a process
//! suspended in connected standby is told of the wake at no guaranteed time.
//! So a wait is never longer than [`PATIENCE`] before the clock is read
//! again - the supervisor's interval between asks, so the core is woken no
//! more often than it already is - and a deadline that fell inside a sleep
//! nobody announced is said at most that late.

use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use hedwig_model::trail::Tick;

use crate::PATIENCE;

/// The deadline thread, told of each new deadline.
#[derive(Debug, Clone)]
pub struct Timer {
    set: Sender<Option<Tick>>,
}

impl Timer {
    /// Starts the thread. `clock` reads the trail's clock; `due` is called
    /// once each time a deadline set has passed, and not again until another
    /// is set.
    pub fn start(
        clock: impl Fn() -> Tick + Send + 'static,
        due: impl Fn() + Send + 'static,
    ) -> Timer {
        let (set, told) = mpsc::channel::<Option<Tick>>();
        thread::spawn(move || {
            let mut deadline: Option<Tick> = None;
            loop {
                let heard = match deadline {
                    None => told.recv().map_err(|_| RecvTimeoutError::Disconnected),
                    Some(at) => {
                        let now = clock();
                        if now >= at {
                            due();
                            deadline = None;
                            continue;
                        }
                        told.recv_timeout(Duration::from_millis(at.0 - now.0).min(PATIENCE))
                    }
                };
                match heard {
                    Ok(next) => deadline = next,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            }
        });
        Timer { set }
    }

    /// The deadline from now on, replacing the last; `None` is none.
    pub fn set(&self, at: Option<Tick>) {
        let _ = self.set.send(at);
    }
}
