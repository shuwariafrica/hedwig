//! The control pipe's server: one thread that accepts, and two for each
//! client - one that reads its requests and one that writes what the core has
//! for it.
//!
//! The threads here only move frames. A reader parses a line, hands it to the
//! deciding thread and reads no further until its reply has been written, so
//! a client has one request outstanding at a time; a writer writes what it is
//! given, in order. Neither holds any state of the core's.

use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;

use hedwig_model::frame::{Frames, Line};
use hedwig_model::json::{self, Json};
use hedwig_model::protocol::ToCore;
use hedwig_model::text::PipeName;
use hedwig_model::trail::{Integrity, Origin, Peer};
use hedwig_model::wire::{FRAME, read};
use hedwig_win::Signal;
use hedwig_win::pipe::{Listener, Moved, Pipe};
use hedwig_win::token::Sid;

use crate::PATIENCE;
use crate::channel::Jobs;
use crate::dispatch::{Input, Link, Then};
use crate::peer::placed;
use crate::run::Message;
use zeroize::Zeroize;

/// The error creating an instance fails with while every one is in use.
const ALL_IN_USE: i32 = 231;

/// A frame for a client, and what follows once it is written.
#[derive(Debug)]
pub struct Out {
    pub text: String,
    pub then: Then,
}

/// The integrity level a token's label names, to the four the model knows.
pub fn integrity(level: u32) -> Integrity {
    match level {
        0..0x2000 => Integrity::Low,
        0x2000..0x3000 => Integrity::Medium,
        0x3000..0x4000 => Integrity::High,
        _ => Integrity::System,
    }
}

/// What the pipe says of the client at its other end: its process number as
/// it connected, its logon session, session and integrity level from the
/// token it let the core see, and what that process number then says of its
/// program and its channel. It is read once.
fn peer(pipe: &Pipe, jobs: &Jobs) -> Option<Peer> {
    let process = pipe.client_process().ok()?;
    let standing = pipe.client_token().ok()?.standing().ok()?;
    let (program, channel) = placed(process, jobs);
    Some(Peer {
        origin: Origin {
            process,
            logon: standing.logon,
            session: standing.session,
            integrity: integrity(standing.integrity),
        },
        program,
        channel,
    })
}

/// The `id` of a line that is well-formed enough to have one, so the refusal
/// can be addressed to the request it answers.
fn salvage(text: &str) -> Option<u32> {
    let Ok(Json::Map(members)) = json::parse(text) else {
        return None;
    };
    members.into_iter().find_map(|(key, value)| match value {
        Json::Number(id) if key == "id" => u32::try_from(id).ok(),
        _ => None,
    })
}

fn input(link: Link, found: &Line<'_>) -> Input {
    match found {
        Line::NotText => Input::Garbled {
            link,
            id: None,
            account: "it is not text".to_owned(),
        },
        Line::Text(text) => match read::<ToCore>(text) {
            Ok(frame) => Input::Asked { link, frame },
            Err(error) => Input::Garbled {
                link,
                id: salvage(text),
                account: error.to_string(),
            },
        },
    }
}

/// Reads one client's requests until it leaves.
fn reader(
    pipe: &Pipe,
    link: Link,
    quit: &Signal,
    jobs: &Jobs,
    messages: &Sender<Message>,
    written: &Receiver<()>,
) {
    let mut frames = Frames::default();
    let mut arrived = false;
    // Hands one input to the deciding thread and waits for its reply to be
    // written: one request at a time, and no next one if the connection ends
    // first. What the pipe says of the client is read before the first, and
    // after the bytes that carried it, which is when the pipe can say.
    let mut ask = |asked: Input| {
        if !arrived {
            arrived = true;
            let peer = peer(pipe, jobs);
            let _ = messages.send(Message::Input(Input::Arrived { link, peer }));
        }
        messages.send(Message::Input(asked)).is_ok() && written.recv().is_ok()
    };
    'client: loop {
        while let Some(found) = frames.line() {
            let asked = input(link, &found);
            // The line can be the person's passphrase; its own copy is in
            // the request now, and erases itself.
            frames.erase();
            if !ask(asked) {
                break 'client;
            }
        }
        let Ok(room) = frames.room() else {
            ask(Input::Garbled {
                link,
                id: None,
                account: format!("a frame is at most {FRAME} bytes"),
            });
            break;
        };
        match pipe.read(room, Some(quit)) {
            Ok(Moved::Bytes(count)) => frames.filled(count),
            _ => break,
        }
    }
    let _ = quit.raise();
    let _ = messages.send(Message::Input(Input::Left { link }));
}

/// Writes one client's frames in the order given.
fn writer(
    pipe: &Pipe,
    link: Link,
    quit: &Signal,
    messages: &Sender<Message>,
    frames: Receiver<Out>,
    written: &Sender<()>,
) {
    let mut stopping = false;
    for Out { mut text, then } in frames {
        stopping = then == Then::Stop;
        text.push('\n');
        let moved = pipe.write(text.as_bytes(), Some(quit));
        // The frame can be the person's answer to a prompt, on its way to the
        // channel's client that asked.
        text.zeroize();
        if !matches!(moved, Ok(Moved::Bytes(_))) {
            break;
        }
        let _ = messages.send(Message::Input(Input::Sent { link }));
        match then {
            Then::Nothing => {}
            Then::Continue => {
                let _ = written.send(());
            }
            Then::Close | Then::Stop => {
                // Closing at once would take the frame away before the
                // client read it, so the client is given time to close first.
                let mut rest = [0u8; 64];
                let _ = pipe.read_within(&mut rest, Some(quit), Some(PATIENCE));
                break;
            }
        }
    }
    let _ = quit.raise();
    if stopping {
        let _ = messages.send(Message::Stopped);
    }
}

/// The control pipe, listening.
#[derive(Debug)]
pub struct Server {
    stop: Arc<Signal>,
    quits: Arc<Mutex<Vec<Arc<Signal>>>>,
}

impl Server {
    /// Creates the pipe under `name`, owned by and open to `owner` alone, and
    /// serves every client that connects until [`Server::stop`]. `jobs` are
    /// the live channels', by which a client is placed.
    ///
    /// # Errors
    ///
    /// `PermissionDenied` when a pipe of that name already exists.
    pub fn listen(
        name: &PipeName,
        owner: &Sid,
        jobs: Jobs,
        messages: Sender<Message>,
    ) -> io::Result<Server> {
        let (listener, first) = Listener::bind(&name.to_path(), owner)?;
        let stop = Arc::new(Signal::new()?);
        let quits = Arc::new(Mutex::new(Vec::new()));
        let server = Server {
            stop: Arc::clone(&stop),
            quits: Arc::clone(&quits),
        };
        thread::spawn(move || accept(&listener, first, &stop, &quits, &jobs, &messages));
        Ok(server)
    }

    /// Stops accepting and ends every connection.
    pub fn stop(&self) {
        let _ = self.stop.raise();
        if let Ok(quits) = self.quits.lock() {
            for quit in quits.iter() {
                let _ = quit.raise();
            }
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept(
    listener: &Listener,
    first: Pipe,
    stop: &Signal,
    quits: &Arc<Mutex<Vec<Arc<Signal>>>>,
    jobs: &Jobs,
    messages: &Sender<Message>,
) {
    let (ended, a_link_ended) = mpsc::channel::<()>();
    let mut waiting = first;
    for number in 1u64.. {
        match waiting.accept(stop) {
            Ok(Moved::Bytes(_) | Moved::Closed) => {}
            Ok(Moved::Stopped) => return,
            Err(error) => {
                let _ = messages.send(Message::Broken(error));
                return;
            }
        }
        // The next instance exists before this one is handed over, so the
        // pipe never stops existing. When every instance is in use there is
        // none to make until a client leaves, and a client that comes
        // meanwhile waits its turn.
        let spare = loop {
            match listener.another() {
                Ok(spare) => break spare,
                Err(error) if error.raw_os_error() == Some(ALL_IN_USE) => {
                    let _ = a_link_ended.recv();
                }
                Err(error) => {
                    let _ = messages.send(Message::Broken(error));
                    return;
                }
            }
        };
        let pipe = Arc::new(std::mem::replace(&mut waiting, spare));
        let Ok(quit) = Signal::new().map(Arc::new) else {
            continue;
        };
        if let Ok(mut quits) = quits.lock() {
            quits.push(Arc::clone(&quit));
        }
        let link = Link(number);
        let (outbox, frames) = mpsc::channel();
        let (written, was_written) = mpsc::channel();
        if messages.send(Message::Opened { link, outbox }).is_err() {
            return;
        }
        {
            let (pipe, quit, messages) = (Arc::clone(&pipe), Arc::clone(&quit), messages.clone());
            thread::spawn(move || writer(&pipe, link, &quit, &messages, frames, &written));
        }
        let (messages, ended, quits) = (messages.clone(), ended.clone(), Arc::clone(quits));
        let jobs = Arc::clone(jobs);
        thread::spawn(move || {
            reader(&pipe, link, &quit, &jobs, &messages, &was_written);
            if let Ok(mut quits) = quits.lock() {
                quits.retain(|other| !Arc::ptr_eq(other, &quit));
            }
            let _ = ended.send(());
        });
    }
}
