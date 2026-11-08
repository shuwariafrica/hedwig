//! The control pipe carrying the model's frames: every frame of the model's
//! pinned corpus crosses the real pipe in each direction and arrives as the
//! bytes that were sent, for several clients at once.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_core::channel::Jobs;
use hedwig_core::dispatch::{Input, Link, Then};
use hedwig_core::run::Message;
use hedwig_core::serve::{Out, Server};
use hedwig_model::frame::{Frames, Line};
use hedwig_model::protocol::{FromCore, ToCore};
use hedwig_model::text::PipeName;
use hedwig_model::trail::{Origin, Peer};
use hedwig_model::wire::{FRAME, line, read};
use hedwig_win::pipe::{Moved, Pipe, open};
use hedwig_win::token::Token;

fn pipe_name() -> PipeName {
    let mut drawn = [0u8; 16];
    hedwig_win::random::fill(&mut drawn).unwrap();
    PipeName::try_from(format!("hedwig.{:032x}", u128::from_le_bytes(drawn)).as_str()).unwrap()
}

/// The model's pinned corpus of the written form, split by direction.
struct Corpus {
    requests: Vec<String>,
    replies: Vec<String>,
    notices: Vec<String>,
}

fn corpus() -> Corpus {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../hedwig-model/tests/corpus.jsonl"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let mut corpus = Corpus {
        requests: Vec::new(),
        replies: Vec::new(),
        notices: Vec::new(),
    };
    for written in text.lines() {
        if read::<ToCore>(written).is_ok() {
            corpus.requests.push(written.to_owned());
        } else if let Ok(frame) = read::<FromCore>(written) {
            match frame {
                FromCore::Reply { .. } => corpus.replies.push(written.to_owned()),
                FromCore::Notice(_) => corpus.notices.push(written.to_owned()),
            }
        }
    }
    assert!(corpus.requests.len() > 50 && corpus.replies.len() > 40 && corpus.notices.len() > 10);
    corpus
}

fn next_line(pipe: &Pipe, frames: &mut Frames) -> Option<String> {
    loop {
        if let Some(found) = frames.line() {
            let text = match found {
                Line::Text(text) => text.to_owned(),
                Line::NotText => panic!("not text"),
            };
            frames.erase();
            return Some(text);
        }
        match pipe.read(frames.room().unwrap(), None).unwrap() {
            Moved::Bytes(count) => frames.filled(count),
            _ => return None,
        }
    }
}

fn send(pipe: &Pipe, text: &str) {
    let moved = pipe.write(format!("{text}\n").as_bytes(), None).unwrap();
    assert!(matches!(moved, Moved::Bytes(_)));
}

/// What one connection did, as the deciding thread saw it.
#[derive(Default)]
struct Seen {
    peer: Option<Peer>,
    asked: Vec<String>,
    garbled: Vec<(Option<u32>, String)>,
    sent: usize,
    left: bool,
}

/// Stands where the deciding thread stands: answers request `n` of a
/// connection with notice `n` and then reply `n` of the corpus, and ends a
/// connection that sent something that is not a request.
fn answer(inbox: &Receiver<Message>, corpus: &Corpus, connections: usize) -> BTreeMap<Link, Seen> {
    let mut outboxes = BTreeMap::new();
    let mut seen: BTreeMap<Link, Seen> = BTreeMap::new();
    while seen.values().filter(|seen| seen.left).count() < connections {
        match inbox.recv_timeout(Duration::from_secs(60)).unwrap() {
            Message::Opened { link, outbox } => {
                outboxes.insert(link, outbox);
            }
            Message::Input(Input::Arrived { link, peer }) => {
                seen.entry(link).or_default().peer = peer;
            }
            Message::Input(Input::Asked { link, frame }) => {
                let this = seen.entry(link).or_default();
                let at = this.asked.len();
                this.asked.push(line(&frame));
                let outbox = outboxes.get(&link).unwrap();
                let pick = |from: &[String]| from.get(at % from.len()).unwrap().clone();
                let notice = Out {
                    text: pick(&corpus.notices),
                    then: Then::Nothing,
                };
                let reply = Out {
                    text: pick(&corpus.replies),
                    then: Then::Continue,
                };
                outbox.send(notice).unwrap();
                outbox.send(reply).unwrap();
            }
            Message::Input(Input::Garbled { link, id, account }) => {
                seen.entry(link).or_default().garbled.push((id, account));
                let then = if id.is_some() {
                    Then::Continue
                } else {
                    Then::Close
                };
                let text = r#"{"reply":{"id":0,"reply":{"refused":"not-greeted"}}}"#.to_owned();
                outboxes
                    .get(&link)
                    .unwrap()
                    .send(Out { text, then })
                    .unwrap();
            }
            Message::Input(Input::Sent { link }) => seen.entry(link).or_default().sent += 1,
            Message::Input(Input::Left { link }) => {
                seen.entry(link).or_default().left = true;
                outboxes.remove(&link);
            }
            other => panic!("{other:?}"),
        }
    }
    seen
}

fn own_origin() -> Origin {
    let standing = Token::own().unwrap().standing().unwrap();
    Origin {
        process: std::process::id(),
        logon: standing.logon,
        session: standing.session,
        integrity: hedwig_core::serve::integrity(standing.integrity),
    }
}

const CLIENTS: usize = 4;

/// How long a client here waits for a place at the pipe, as the person's own
/// clients do.
const WAIT: Duration = Duration::from_secs(5);

/// Four clients at once each send every request the protocol has and read a
/// notice and a reply to each. Every frame arrives as it was written, the
/// server reads of each client what it is, and each is seen to leave.
#[test]
fn every_pinned_frame_crosses_the_pipe_both_ways_for_several_clients_at_once() {
    let corpus = corpus();
    let name = pipe_name();
    let (messages, inbox) = mpsc::channel();
    let owner = Token::own().unwrap().user().unwrap();
    let server = Server::listen(&name, &owner, Jobs::default(), messages).unwrap();

    let clients: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let path = name.to_path();
            let requests = corpus.requests.clone();
            let (replies, notices) = (corpus.replies.clone(), corpus.notices.clone());
            thread::spawn(move || {
                let pipe = open(&path, WAIT).unwrap();
                let mut frames = Frames::default();
                for (at, request) in requests.iter().enumerate() {
                    send(&pipe, request);
                    let notice = next_line(&pipe, &mut frames).unwrap();
                    let reply = next_line(&pipe, &mut frames).unwrap();
                    assert_eq!(&notice, notices.get(at % notices.len()).unwrap());
                    assert_eq!(&reply, replies.get(at % replies.len()).unwrap());
                }
            })
        })
        .collect();
    let seen = answer(&inbox, &corpus, CLIENTS);
    for client in clients {
        client.join().unwrap();
    }
    assert_eq!(seen.len(), CLIENTS);
    for this in seen.values() {
        // Read through the pipe: where the client stands, the program it
        // runs, and that it is in no channel's job.
        let peer = this.peer.as_ref().unwrap();
        assert_eq!(peer.origin, own_origin());
        assert_eq!(
            peer.program
                .as_ref()
                .map(|program| PathBuf::from(program.as_str())),
            std::env::current_exe().ok()
        );
        assert_eq!(peer.channel, None);
        assert_eq!(this.asked, corpus.requests);
        assert_eq!(this.sent, corpus.requests.len() * 2);
        assert_eq!(this.garbled, Vec::<(Option<u32>, String)>::new());
    }
    drop(server);
}

/// As many clients as a logon or a script's loop can start, released at the
/// same instant against a core that keeps one instance waiting at a time:
/// each is admitted and answered, however many lost the race for an
/// instance before it won one.
#[test]
fn a_burst_of_clients_is_each_admitted_while_the_core_has_room() {
    const BURST: usize = 64;
    let corpus = corpus();
    let name = pipe_name();
    let (messages, inbox) = mpsc::channel();
    let owner = Token::own().unwrap().user().unwrap();
    let server = Server::listen(&name, &owner, Jobs::default(), messages).unwrap();
    let start = Arc::new(Barrier::new(BURST));
    let clients: Vec<_> = (0..BURST)
        .map(|_| {
            let path = name.to_path();
            let start = Arc::clone(&start);
            let request = corpus.requests.first().unwrap().clone();
            thread::spawn(move || {
                start.wait();
                let pipe = open(&path, WAIT).unwrap();
                let mut frames = Frames::default();
                send(&pipe, &request);
                next_line(&pipe, &mut frames).unwrap();
                next_line(&pipe, &mut frames).unwrap();
            })
        })
        .collect();
    let seen = answer(&inbox, &corpus, BURST);
    for client in clients {
        client.join().unwrap();
    }
    assert_eq!(seen.len(), BURST);
    assert!(seen.values().all(|seen| seen.asked.len() == 1));
    drop(server);
}

/// What is not a request is told apart: a line with an id can be answered
/// and the connection goes on; a line with none, a line that is not text and
/// a line that never ends are each answered once and the connection ends.
#[test]
fn what_is_not_a_request_is_located_and_a_connection_without_frames_is_ended() {
    let corpus = corpus();
    let name = pipe_name();
    let (messages, inbox) = mpsc::channel();
    let owner = Token::own().unwrap().user().unwrap();
    let _server = Server::listen(&name, &owner, Jobs::default(), messages).unwrap();
    let path = name.to_path();

    let client = thread::spawn(move || {
        let began = Instant::now();
        // An unknown request that still carries its id, then a line with none.
        let pipe = open(&path, WAIT).unwrap();
        let mut frames = Frames::default();
        send(&pipe, r#"{"id":5,"request":"reboot"}"#);
        assert!(next_line(&pipe, &mut frames).is_some());
        send(&pipe, "not json");
        assert!(next_line(&pipe, &mut frames).is_some());
        drop(pipe);

        let pipe = open(&path, WAIT).unwrap();
        pipe.write(&[0xff, 0xfe, b'\n'], None).unwrap();
        assert!(next_line(&pipe, &mut Frames::default()).is_some());
        drop(pipe);

        // More than a frame may hold, with no end of line in it.
        let pipe = open(&path, WAIT).unwrap();
        let endless = vec![b'a'; FRAME + 2];
        pipe.write(&endless, None).unwrap();
        assert!(next_line(&pipe, &mut Frames::default()).is_some());
        drop(pipe);
        began.elapsed()
    });
    let seen = answer(&inbox, &corpus, 3);
    // Each connection ended when its client closed, not when the server's
    // patience with an unread frame ran out.
    assert!(client.join().unwrap() < hedwig_core::PATIENCE);
    let garbled: Vec<(Option<u32>, String)> =
        seen.into_values().flat_map(|seen| seen.garbled).collect();
    assert_eq!(
        garbled,
        [
            (
                Some(5),
                "request has \"reboot\", which is not known here".to_owned()
            ),
            (None, "an unexpected character at byte 0".to_owned()),
            (None, "it is not text".to_owned()),
            (None, format!("a frame is at most {FRAME} bytes")),
        ]
    );
}
