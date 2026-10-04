//! The supervisor: the process the `Run` value starts, which runs the core as
//! its child and runs another when that one breaks down.
//!
//! It does three things and decides nothing else. It keeps the core in a job
//! that ends with it, so a core never outlives its supervisor or leaves a
//! channel behind. It asks the core, on a fixed beat, to answer from the
//! thread that decides everything, and ends a core that does not. And it
//! starts the next core at once when the last ran long enough to have been
//! sound, and more and more slowly when cores keep failing young.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hedwig_model::process::{CoreState, Exit, Order, Report};
use hedwig_model::trail::Breakdown;
use hedwig_model::wire::{line, read};
use hedwig_win::process::Job;

use crate::PATIENCE;
use crate::record::Claim;

/// How the core is watched: asked every `every`, and ended when an answer
/// takes longer than `within`. Both are measured in time this supervisor was
/// seen to run ([`Ran`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    pub every: Duration,
    pub within: Duration,
}

impl Default for Watch {
    fn default() -> Watch {
        Watch {
            every: PATIENCE,
            within: PATIENCE,
        }
    }
}

impl Watch {
    /// The most one reading of [`Ran`] counts, and the longest the supervisor
    /// waits between readings: a fifth of what the core is given to answer.
    pub fn step(&self) -> Duration {
        self.within / 5
    }
}

/// Time this supervisor was seen to run.
///
/// Each reading adds what the clock says has passed since the last one, and
/// never more than one step. A wait that took longer than it asked for - the
/// workstation slept, the session's processes were suspended, something held
/// this process - was time the core did not run either, and is not counted
/// against it.
#[derive(Debug, Clone, Copy)]
pub struct Ran {
    clock: fn() -> Duration,
    step: Duration,
    read: Duration,
    total: Duration,
}

impl Ran {
    pub fn new(clock: fn() -> Duration, step: Duration) -> Ran {
        Ran {
            clock,
            step,
            read: clock(),
            total: Duration::ZERO,
        }
    }

    /// The running time so far.
    pub fn now(&mut self) -> Duration {
        let read = (self.clock)();
        self.total += read.saturating_sub(self.read).min(self.step);
        self.read = read;
        self.total
    }
}

/// How soon the next core is started after one breaks down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pace {
    /// A core that ran this long was sound: the next starts at once. It is
    /// the minute Windows itself requires of a program before it will restart
    /// it.
    pub settled: Duration,
    /// The wait after the first core to fail younger than that.
    pub first: Duration,
    /// The longest wait, however many have failed young in a row.
    pub longest: Duration,
}

impl Default for Pace {
    fn default() -> Pace {
        Pace {
            settled: Duration::from_secs(60),
            first: Duration::from_secs(1),
            longest: Duration::from_secs(60),
        }
    }
}

impl Pace {
    /// The wait before the next core, given how long the last one ran and how
    /// many before it failed young in a row; and that count afterwards.
    pub fn wait(&self, ran: Duration, young: u32) -> (Duration, u32) {
        if ran >= self.settled {
            return (Duration::ZERO, 0);
        }
        let doubled = self
            .first
            .saturating_mul(2u32.saturating_pow(young.min(31)));
        (doubled.min(self.longest), young.saturating_add(1))
    }
}

#[derive(Debug, Clone)]
pub struct Supervisor {
    /// The program run as the core, and its arguments. In Hedwig this is the
    /// supervisor's own executable in its core role.
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub watch: Watch,
    pub pace: Pace,
    /// The clock running time is read from: [`hedwig_win::clock::elapsed`].
    pub clock: fn() -> Duration,
}

/// What a supervisor does on finding another already running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// The one running stays, and this one ends.
    Leave,
    /// The one running is stopped and this one takes its place.
    Replace,
}

impl Found {
    /// A supervisor started in a desktop session replaces a core that runs
    /// in session 0, where an SSH session into the workstation started it:
    /// that core can raise nothing on a desktop and holds the token of a
    /// network logon. Any other core is left as it is.
    pub fn decide(own_session: u32, core_session: u32) -> Found {
        if own_session != 0 && core_session == 0 {
            Found::Replace
        } else {
            Found::Leave
        }
    }
}

/// How one core ended.
enum Ended {
    Exited(u32),
    Hung,
    Unstarted(String),
}

/// The last line a core wrote to its standard error, kept short and free of
/// anything that could drive a terminal it is shown in.
fn last_line(said: &Mutex<String>) -> String {
    let said = said.lock().map(|said| said.clone()).unwrap_or_default();
    said.chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}

fn order(orders: &mut ChildStdin, order: Order) -> std::io::Result<()> {
    let mut text = line(&order);
    text.push('\n');
    orders.write_all(text.as_bytes())?;
    orders.flush()
}

impl Supervisor {
    /// Runs cores until one ends because the person stopped hedwig.
    ///
    /// `announce` is given the record once, the first time it says something
    /// a starter is waiting to hear: that a core is serving, or that the
    /// first one broke down.
    pub fn run(&self, mut claim: Claim, mut announce: Option<impl Write>) -> Exit {
        let mut after = None;
        let mut young = 0;
        let mut state = CoreState::Starting;
        let mut ran = Ran::new(self.clock, self.watch.step());
        loop {
            let _ = claim.write(state.clone());
            let began = ran.now();
            let said = Arc::new(Mutex::new(String::new()));
            let ended = self.once(&mut ran, after, &said, |pipe, process| {
                let serving = CoreState::Serving { pipe, process };
                if let (Ok(running), Some(mut to)) = (claim.write(serving), announce.take()) {
                    let _ = writeln!(to, "{}", line(&running));
                }
            });
            let (cause, said) = match ended {
                Ended::Exited(status) if Exit::from_status(status) == Some(Exit::Stopped) => {
                    return Exit::Stopped;
                }
                Ended::Exited(status) => (Breakdown::Exited { status }, last_line(&said)),
                Ended::Hung => (Breakdown::Hung, last_line(&said)),
                Ended::Unstarted(why) => (Breakdown::Unstarted, why),
            };
            state = CoreState::Restarting { cause, said };
            if let (Ok(running), Some(mut to)) = (claim.write(state.clone()), announce.take()) {
                let _ = writeln!(to, "{}", line(&running));
            }
            let (wait, failed) = self.pace.wait(ran.now().saturating_sub(began), young);
            young = failed;
            thread::sleep(wait);
            after = Some(cause);
        }
    }

    fn start(&self) -> Result<(Job, Child), String> {
        // A core may start what is the person's own outside it: their
        // GnuPG's agent, which outlives hedwig.
        let job = Job::leavable().map_err(|error| error.to_string())?;
        let mut child = Command::new(&self.program)
            .args(&self.arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| error.to_string())?;
        // The core does nothing until it is told to begin, so nothing it
        // starts can be outside the job.
        if let Err(error) = job.hold(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.to_string());
        }
        Ok((job, child))
    }

    /// Runs one core to its end.
    fn once(
        &self,
        ran: &mut Ran,
        after: Option<Breakdown>,
        said: &Arc<Mutex<String>>,
        mut ready: impl FnMut(hedwig_model::text::PipeName, u32),
    ) -> Ended {
        let (job, mut child) = match self.start() {
            Ok(started) => started,
            Err(why) => return Ended::Unstarted(why),
        };
        let (reports, last_words) = listen(child.stdout.take(), child.stderr.take(), said);
        let ended = self.watch(ran, &job, &mut child, &reports, after, &mut ready);
        // Everything in the job has ended by now, so the core's standard
        // error has closed and its last words are all in.
        if let Some(last_words) = last_words {
            let _ = last_words.join();
        }
        ended
    }

    /// Watches one core until it ends or is ended.
    #[allow(clippy::too_many_arguments, reason = "one core's whole watch")]
    fn watch(
        &self,
        ran: &mut Ran,
        job: &Job,
        child: &mut Child,
        reports: &Receiver<Option<Report>>,
        after: Option<Breakdown>,
        ready: &mut impl FnMut(hedwig_model::text::PipeName, u32),
    ) -> Ended {
        let Some(mut orders) = child.stdin.take() else {
            return end(job, child);
        };
        if order(&mut orders, Order::Begin { after }).is_err() {
            return end(job, child);
        }
        let mut asked: Option<Duration> = None;
        let mut next = ran.now() + self.watch.every;
        loop {
            let now = ran.now();
            let until = asked.map_or(next, |asked| asked + self.watch.within);
            // Never longer than a step, so that a wait the workstation slept
            // through is read as one step and not as the sleep.
            let wait = until.saturating_sub(now).min(self.watch.step());
            match reports.recv_timeout(wait) {
                Ok(Some(Report::Ready { pipe })) => ready(pipe, child.id()),
                Ok(Some(Report::Pong)) => {
                    asked = None;
                    next = ran.now() + self.watch.every;
                }
                // A line that is not a report: the core is not one this
                // supervisor can run.
                Ok(None) => return end(job, child),
                // Not yet, in time this supervisor ran.
                Err(RecvTimeoutError::Timeout) if ran.now() < until => {}
                Err(RecvTimeoutError::Timeout) if asked.is_some() => {
                    let _ = job.end();
                    let _ = child.wait();
                    return Ended::Hung;
                }
                Err(RecvTimeoutError::Timeout) => {
                    // A core whose output something else still holds open
                    // does not show its end there, so it is looked for here.
                    if !matches!(child.try_wait(), Ok(None)) {
                        return self.gone(ran, job, child);
                    }
                    asked = Some(ran.now());
                    // A failed write means the core is ending, which the
                    // next round sees.
                    let _ = order(&mut orders, Order::Ping);
                }
                Err(RecvTimeoutError::Disconnected) => return self.gone(ran, job, child),
            }
        }
    }
}

impl Supervisor {
    /// The core's output closed, or the core has ended. It is given as long
    /// to finish ending as it is given to answer; then whatever is left of
    /// it, and everything it started, is ended.
    fn gone(&self, ran: &mut Ran, job: &Job, child: &mut Child) -> Ended {
        let until = ran.now() + self.watch.within;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if ran.now() < until => thread::sleep(Duration::from_millis(1)),
                _ => break None,
            }
        };
        let _ = job.end();
        let status = status.or_else(|| child.wait().ok());
        let status = status.and_then(|status| status.code());
        Ended::Exited(status.map_or(u32::MAX, i32::cast_unsigned))
    }
}

/// Ends a core that cannot be run, and everything it started.
fn end(job: &Job, child: &mut Child) -> Ended {
    let _ = job.end();
    let status = child.wait().ok().and_then(|status| status.code());
    Ended::Exited(status.map_or(u32::MAX, i32::cast_unsigned))
}

/// Reads the core's reports on one thread and keeps its last words on
/// another. The channel closes when the core's output does.
fn listen(
    output: Option<impl Read + Send + 'static>,
    errors: Option<impl Read + Send + 'static>,
    said: &Arc<Mutex<String>>,
) -> (Receiver<Option<Report>>, Option<thread::JoinHandle<()>>) {
    let (reports, received) = mpsc::channel();
    if let Some(output) = output {
        thread::spawn(move || {
            for written in BufReader::new(output).lines() {
                let Ok(written) = written else { break };
                if reports.send(read::<Report>(&written).ok()).is_err() {
                    break;
                }
            }
        });
    }
    let last_words = errors.map(|errors| {
        let said = Arc::clone(said);
        thread::spawn(move || {
            for written in BufReader::new(errors).lines() {
                let Ok(written) = written else { break };
                if written.trim().is_empty() {
                    continue;
                }
                if let Ok(mut said) = said.lock() {
                    *said = written;
                }
            }
        })
    });
    (received, last_words)
}
