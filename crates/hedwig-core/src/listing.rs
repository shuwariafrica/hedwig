//! Asking a route's platform which of its remotes are running.
//!
//! The deciding thread says when a route is listed and when a listing that
//! has not answered is ended. Each listing is the route's own program, found
//! as a channel's client is, run in a job of its own with the core's
//! variables, its output read whole and its errors kept for the account.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread;

use hedwig_model::remote::Lister;
use hedwig_model::text::{Address, Name, Words};
use hedwig_model::wire::FRAME;
use hedwig_win::Signal;
use hedwig_win::process::Job;
use hedwig_win::search::{SearchError, program_on};
use hedwig_win::start::{Environment, consulted};

use crate::channel::words;
use crate::dispatch::Input;
use crate::run::Message;

/// The listings running now, by route.
pub struct Listings {
    search: OsString,
    environment: Environment,
    messages: Sender<Message>,
    live: BTreeMap<Name, (Arc<Job>, Arc<Signal>)>,
}

impl Listings {
    pub fn new(search: OsString, environment: Environment, messages: Sender<Message>) -> Listings {
        Listings {
            search,
            environment,
            messages,
            live: BTreeMap::new(),
        }
    }

    /// Lists `route`, and tells the deciding thread what it found.
    pub fn list(&mut self, route: Name, lister: Lister) {
        let made = Job::new().and_then(|job| Ok((Arc::new(job), Arc::new(Signal::new()?))));
        let (job, ended) = match made {
            Ok(made) => made,
            Err(error) => return self.say(route, Err(account(&error.to_string()))),
        };
        self.live
            .insert(route.clone(), (Arc::clone(&job), Arc::clone(&ended)));
        let (search, environment) = (self.search.clone(), self.environment.clone());
        let messages = self.messages.clone();
        thread::spawn(move || {
            let found = run(&lister, &search, &environment, &job);
            // A listing ended for overrunning says nothing: the deciding
            // thread has already given up on it and may have started another.
            if !ended.raised() {
                let said = Input::Listed {
                    route,
                    listed: found,
                };
                let _ = messages.send(Message::Input(said));
            }
        });
    }

    /// Ends a listing that has not answered, and everything it started.
    pub fn end(&mut self, route: &Name) {
        if let Some((job, ended)) = self.live.remove(route) {
            let _ = ended.raise();
            let _ = job.end();
        }
    }

    fn say(&self, route: Name, listed: Result<Vec<Address>, Words>) {
        let _ = self
            .messages
            .send(Message::Input(Input::Listed { route, listed }));
    }
}

fn account(text: &str) -> Words {
    words(text)
        .or_else(|| words("the listing ended without saying why"))
        .unwrap_or_else(|| unreachable!("the fallback is words"))
}

/// Runs one listing to its end.
fn run(
    lister: &Lister,
    search: &OsString,
    environment: &Environment,
    job: &Job,
) -> Result<Vec<Address>, Words> {
    let program = program_on(lister.program.as_str(), search).map_err(|error| match error {
        SearchError::Absent | SearchError::NoSearchPath => account(&format!(
            "{} is not in any folder on the search path",
            lister.program.as_str()
        )),
        SearchError::Other(error) => account(&error.to_string()),
    })?;
    let arguments: Vec<OsString> = lister
        .arguments
        .iter()
        .map(|argument| OsString::from(argument.as_str()))
        .collect();
    let (held, output, errors) = consulted(&program, &arguments, environment, job)
        .map_err(|error| account(&error.to_string()))?;
    // Its errors are read while its output is, so neither pipe fills and
    // stops it.
    let said = thread::spawn(move || {
        let mut last = None;
        for line in BufReader::new(errors).lines().map_while(Result::ok) {
            if let Some(line) = words(&line) {
                last = Some(line);
            }
        }
        last
    });
    let mut bytes = Vec::new();
    let read = output.take(FRAME as u64 + 1).read_to_end(&mut bytes);
    let status = held.wait().map_err(|error| account(&error.to_string()))?;
    let _ = job.end();
    let last = said.join().unwrap_or(None);
    let _ = read.map_err(|error| account(&error.to_string()))?;
    if status != 0 {
        return Err(last.unwrap_or_else(|| account(&format!("the listing ended with {status}"))));
    }
    if bytes.len() > FRAME {
        return Err(account("the listing printed more than a mebibyte"));
    }
    let text =
        String::from_utf8(bytes).map_err(|_| account("the listing printed what is not text"))?;
    lister
        .addresses(&text)
        .map_err(|error| account(&error.to_string()))
}
