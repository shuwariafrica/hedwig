//! What serves an `ssh-agent` capability: each connection admitted at the
//! forward's end, whose requests reach the person's own SSH agent.
//!
//! The agent is reached anew for each request it is given, and the
//! connection to it closed once its answer is read, so no remote holds it
//! between requests: gpg-agent's pipe serves one program at a time, and a
//! remote's client may keep its connection for as long as its session lasts.
//! gpg-agent is reached at its own SSH socket, which it serves on Windows with
//! nothing configured; another agent at its pipe; and a key the workstation's
//! TPM holds is answered for by the core itself ([`crate::machine`]).
//!
//! Three threads carry a connection: one reads the remote, one owns the
//! [`Conversation`] and writes to the remote, and one at a time asks the
//! agent. Nothing the deciding thread does waits on any of them.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;

use hedwig_model::capability::{AgentAt, Home, Installation, Lends};
use hedwig_model::protocol::AgentKey;
use hedwig_model::text::{AgentPipe, Words};
use hedwig_model::trail::Failure;
use hedwig_win::pipe::{Moved, OpenError, Pipe, open_unwaited};
use hedwig_win::process::UNSEEN;
use zeroize::Zeroize;

use crate::agent::{self, Conversation, LIMIT, Out};
use crate::assuan::SocketFile;
use crate::relay::{
    Event, QUEUED, Reach, Relayed, Settle, admitted, gpgconf, home_arguments, launch,
};
use crate::service::{Gate, read_gated};

/// The agent a capability's source names, and what the remote's grant lends
/// of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAgent {
    pub at: AgentAt,
    pub lends: Lends,
}

/// How many times a request is sent to gpg-agent's socket that ended its
/// connection without reading it. Invariant: gpg-agent 2.5.24 ends a
/// connection to that socket when no byte is waiting as its handler first
/// reads (measured); the request
/// goes in the same write as the file's bytes, so a second loss in a row is
/// not that.
const ATTEMPTS: usize = 3;

/// One connection to the agent, opened for one request: what must precede
/// the request on it, and how many bytes the agent writes before its answer.
pub(crate) enum Line {
    Socket {
        stream: TcpStream,
        prelude: Vec<u8>,
        echoed: usize,
    },
    Pipe(Pipe),
    /// The core itself, which needs no connection.
    Machine,
}

impl Drop for Line {
    fn drop(&mut self) {
        if let Line::Socket { prelude, .. } = self {
            prelude.zeroize();
        }
    }
}

/// The SSH socket file of a `GnuPG` home, as its installation's own
/// `gpgconf` names it, and that `gpgconf`.
fn locate(installation: &Installation, home: &Home) -> Result<(PathBuf, PathBuf), Failure> {
    let gpgconf = gpgconf(installation)?;
    let mut arguments: Vec<OsString> = home_arguments(home);
    arguments.push("--list-dirs".into());
    let (printed, ended_well) =
        crate::relay::ran(&gpgconf, &arguments, UNSEEN).map_err(|_| Failure::Unresolved)?;
    let socket = crate::relay::listed(&printed, "agent-ssh-socket")
        .filter(|_| ended_well)
        .ok_or(Failure::Unresolved)?;
    if socket.first() == Some(&b'/') {
        return Err(Failure::Unserved);
    }
    let socket = String::from_utf8(socket).map_err(|_| Failure::Unresolved)?;
    Ok((gpgconf, PathBuf::from(socket)))
}

/// Connects to the agent behind `socket`, admitted only where the process
/// listening is the person's or a service and would itself be let read the
/// file. Each failure is one starting the agent can mend.
fn open_socket(socket: &Path) -> Reach<Line> {
    let (port, prelude, echoed) = match crate::relay::read_socket_file(socket) {
        Err(_) | Ok(Err(_)) => return Reach::failed(Failure::Unreachable),
        Ok(Ok(SocketFile::Native { port, nonce })) => (port, nonce.as_bytes().to_vec(), 0),
        // Cygwin's handshake: the bytes, then the client's credentials -
        // its process and a user and group of 0, which the agent reads and
        // does not use (`assuan-socket.c` `_assuan_sock_check_nonce`) - in
        // the one write; the agent echoes the bytes and sends its own.
        Ok(Ok(SocketFile::Cygwin { port, nonce })) => {
            let mut prelude = nonce.as_bytes().to_vec();
            prelude.extend_from_slice(&std::process::id().to_le_bytes());
            prelude.extend_from_slice(&[0; 4]);
            (port, prelude, 24)
        }
    };
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let Ok(stream) = TcpStream::connect_timeout(&address.into(), crate::PATIENCE) else {
        return Reach::failed(Failure::Unreachable);
    };
    let (admission, holder) = admitted(&stream, socket);
    let result = admission.map(|()| Line::Socket {
        stream,
        prelude,
        echoed,
    });
    Reach { result, holder }
}

/// Opens the agent's pipe, admitted only where the process serving it is
/// the person's or runs a service, as every source's holder is.
fn open_pipe(name: &AgentPipe) -> Reach<Line> {
    let pipe = match open_unwaited(&name.to_path(), crate::PATIENCE) {
        Ok(pipe) => pipe,
        Err(OpenError::Absent | OpenError::Other(_)) => return Reach::failed(Failure::Unreachable),
        Err(OpenError::Busy) => return Reach::failed(Failure::Occupied),
        Err(OpenError::Denied) => return Reach::failed(Failure::Foreign),
    };
    let Some(holder) = pipe.server_process().ok().and_then(crate::holder::of) else {
        return Reach::failed(Failure::Mismatched);
    };
    Reach {
        result: holder.admitted().map(|()| Line::Pipe(pipe)),
        holder: Some(holder),
    }
}

/// A connection to the agent at `at`, nothing sent on it, or the failure
/// that stands after gpg-agent was started once; with what held the pipe or
/// the socket. gpg-agent is started once, outside every job Hedwig holds,
/// where it does not answer: an SSH client never starts it.
pub(crate) fn reach(at: &AgentAt) -> Reach<Line> {
    let (installation, home) = match at {
        AgentAt::Pipe(name) => return open_pipe(name),
        AgentAt::Machine => {
            return Reach {
                result: crate::machine::reach().map(|()| Line::Machine),
                holder: None,
            };
        }
        AgentAt::Gnupg { installation, home } => (installation, home),
    };
    let mut last = Reach::failed(Failure::Unreachable);
    for attempt in 0..2 {
        let (gpgconf, socket) = match locate(installation, home) {
            Ok(located) => located,
            Err(failure) => return Reach::failed(failure),
        };
        let reached = open_socket(&socket);
        if reached.result.is_ok() {
            return reached;
        }
        last = reached;
        if attempt == 0 && launch(&gpgconf, home, false).is_err() {
            return last;
        }
    }
    last
}

/// How one request went unanswered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unanswered {
    /// The agent closed having written nothing: it did not read the request.
    Silent,
    /// The agent closed part-way, wrote more than an agent answers, or could
    /// not be written to.
    Broken,
}

fn fill_socket(stream: &mut TcpStream, into: &mut [u8]) -> Result<(), usize> {
    let mut filled = 0;
    while let Some(free) = into.get_mut(filled..).filter(|free| !free.is_empty()) {
        match stream.read(free) {
            Ok(0) | Err(_) => return Err(filled),
            Ok(read) => filled += read,
        }
    }
    Ok(())
}

fn fill_pipe(pipe: &Pipe, into: &mut [u8]) -> Result<(), usize> {
    let mut filled = 0;
    while let Some(free) = into.get_mut(filled..).filter(|free| !free.is_empty()) {
        match pipe.read(free, None) {
            Ok(Moved::Bytes(read)) if read > 0 => filled += read,
            _ => return Err(filled),
        }
    }
    Ok(())
}

/// Sends `request` and reads the one message that answers it, framed.
fn exchange(line: &mut Line, request: &[u8]) -> Result<Vec<u8>, Unanswered> {
    let written = match line {
        // The file's bytes and the request in one write, so the request is
        // waiting when gpg-agent's handler first reads.
        Line::Socket {
            stream, prelude, ..
        } => {
            let mut whole = std::mem::take(prelude);
            whole.extend_from_slice(request);
            let sent = stream.write_all(&whole).is_ok();
            whole.zeroize();
            sent
        }
        Line::Pipe(pipe) => matches!(pipe.write(request, None), Ok(Moved::Bytes(_))),
        Line::Machine => false,
    };
    if !written {
        return Err(Unanswered::Broken);
    }
    let echoed = match line {
        Line::Socket { echoed, .. } => *echoed,
        Line::Pipe(_) | Line::Machine => 0,
    };
    let read = |line: &mut Line, into: &mut [u8]| match line {
        Line::Socket { stream, .. } => fill_socket(stream, into),
        Line::Pipe(pipe) => fill_pipe(pipe, into),
        Line::Machine => Err(0),
    };
    let mut skipped = vec![0u8; echoed];
    if let Err(filled) = read(line, &mut skipped) {
        return Err(if filled == 0 {
            Unanswered::Silent
        } else {
            Unanswered::Broken
        });
    }
    let mut length = [0u8; 4];
    if let Err(filled) = read(line, &mut length) {
        return Err(if filled == 0 && echoed == 0 {
            Unanswered::Silent
        } else {
            Unanswered::Broken
        });
    }
    let body = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    if body == 0 || body > LIMIT {
        return Err(Unanswered::Broken);
    }
    let mut answer = vec![0u8; 4 + body];
    if let Some(head) = answer.get_mut(..4) {
        head.copy_from_slice(&length);
    }
    read(line, answer.get_mut(4..).unwrap_or_default()).map_err(|_| Unanswered::Broken)?;
    Ok(answer)
}

/// One request to the agent at `at` and its answer, the agent reached anew
/// for it and the connection closed after it; and the program answering
/// where `at` is a pipe.
///
/// # Errors
///
/// What kept the agent from answering: [`Failure::Mismatched`] where it
/// broke off or answered in no form an agent does.
pub fn request(at: &AgentAt, framed: &[u8]) -> Reach<Vec<u8>> {
    if *at == AgentAt::Machine {
        return Reach {
            result: crate::machine::answer(framed),
            holder: None,
        };
    }
    let mut holder = None;
    for _ in 0..ATTEMPTS {
        let reached = reach(at);
        holder = reached.holder;
        let mut line = match reached.result {
            Ok(line) => line,
            Err(failure) => {
                return Reach {
                    result: Err(failure),
                    holder,
                };
            }
        };
        match exchange(&mut line, framed) {
            Ok(answer) => {
                return Reach {
                    result: Ok(answer),
                    holder,
                };
            }
            Err(Unanswered::Silent) if matches!(at, AgentAt::Gnupg { .. }) => {}
            Err(_) => break,
        }
    }
    Reach {
        result: Err(Failure::Mismatched),
        holder,
    }
}

/// The keys the agent at `at` holds, as it lists them, for a grant surface
/// the person opened, or what kept the agent from answering -
/// [`Failure::Mismatched`] for an answer that is no list; with what held the
/// agent's pipe or socket.
pub fn keys(at: &AgentAt) -> Reach<Vec<AgentKey>> {
    const REQUEST_IDENTITIES: [u8; 5] = [0, 0, 0, 1, 11];
    let asked = request(at, &REQUEST_IDENTITIES);
    let result = asked.result.and_then(|answer| {
        let listed = agent::listed(&answer).ok_or(Failure::Mismatched)?;
        Ok(listed
            .into_iter()
            .map(|(key, comment)| AgentKey {
                key,
                comment: std::str::from_utf8(&comment)
                    .ok()
                    .and_then(|comment| Words::try_from(comment).ok()),
            })
            .collect())
    });
    Reach {
        result,
        holder: asked.holder,
    }
}

/// Carries one admitted connection to the agent. `tell` reaches the deciding
/// thread. Returns where the deciding thread settles what the connection
/// asks; the connection itself runs on threads of its own.
pub fn carry(
    client: TcpStream,
    agent: SshAgent,
    tell: impl Fn(Relayed) + Send + Sync + 'static,
) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events.clone()));
    let held = Arc::clone(&settle);
    let tell = Arc::new(tell);
    thread::spawn(move || {
        run(&client, &agent, &tell, &events, &queue, &held);
        tell(Relayed::Ended);
    });
    settle
}

fn run(
    client: &TcpStream,
    agent: &SshAgent,
    tell: &Arc<impl Fn(Relayed) + Send + Sync + 'static>,
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Settle,
) {
    // The agent is reached before the opening is decided, so an opening it
    // cannot serve is refused saying so, and gpg-agent is started for it.
    let reached = reach(&agent.at);
    reached.tell(tell.as_ref());
    drop(reached);
    let gate = Arc::new(Gate::default());
    let Ok(reader) = client.try_clone() else {
        return;
    };
    {
        let (events, gate) = (events.clone(), Arc::clone(&gate));
        thread::spawn(move || read_gated(reader, &events, &gate));
    }
    let mut early = Vec::new();
    let word = loop {
        if let Some(word) = settle.take() {
            break Some(word);
        }
        match queue.recv() {
            Ok(Event::Client(bytes)) => early.extend_from_slice(&bytes),
            Ok(Event::ClientClosed) | Err(_) => break None,
            Ok(_) => {}
        }
    };
    if word != Some(Ok(())) {
        let _ = client.shutdown(Shutdown::Both);
        return;
    }
    gate.open();
    converse(client, agent, tell, events, queue, settle, early);
    let _ = client.shutdown(Shutdown::Both);
}

#[allow(
    clippy::too_many_arguments,
    reason = "the second half of `run`, given everything it holds"
)]
fn converse(
    client: &TcpStream,
    agent: &SshAgent,
    tell: &Arc<impl Fn(Relayed) + Send + Sync + 'static>,
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Settle,
    early: Vec<u8>,
) {
    let Ok(mut to_client) = client.try_clone() else {
        return;
    };
    let mut talk = Conversation::new(agent.lends.clone());
    let mut pending = vec![Event::Client(early)];
    loop {
        let event = match pending.pop() {
            Some(event) => event,
            None => match queue.recv() {
                Ok(event) => event,
                Err(_) => return,
            },
        };
        if let Some(lending) = settle.take_lending() {
            talk.relend(lending.lends);
        }
        let outs = match event {
            Event::Client(bytes) => talk.from_client(&bytes),
            Event::Agent(bytes) => talk.from_agent(&bytes),
            Event::AgentClosed => talk.unanswered(),
            Event::ClientClosed => {
                if let Err(breach) = talk.client_closed() {
                    tell(Relayed::Strayed(breach));
                }
                return;
            }
            Event::Settled => match settle.take() {
                Some(Ok(())) if talk.holds() => Ok(talk.serve()),
                Some(Err(_)) if talk.holds() => talk.refuse(),
                _ => Ok(Vec::new()),
            },
            Event::Called | Event::Viewed => Ok(Vec::new()),
        };
        let outs = match outs {
            Ok(outs) => outs,
            Err(breach) => {
                tell(Relayed::Strayed(breach));
                return;
            }
        };
        for out in outs {
            match out {
                Out::ToClient(bytes) => {
                    if to_client.write_all(&bytes).is_err() {
                        return;
                    }
                }
                Out::ToAgent(request) => ask(agent.at.clone(), request, events.clone(), tell),
                Out::Ask(ask) => tell(Relayed::Signs(ask)),
                Out::Withheld(withheld) => tell(Relayed::Withheld(withheld)),
            }
        }
    }
}

/// Sends one request to the agent on a thread of its own, which gives the
/// answer to the conversation as the agent's bytes, or its absence as the
/// agent closing.
fn ask(
    at: AgentAt,
    message: Vec<u8>,
    events: SyncSender<Event>,
    tell: &Arc<impl Fn(Relayed) + Send + Sync + 'static>,
) {
    let tell = Arc::clone(tell);
    thread::spawn(move || {
        let answered = request(&at, &message);
        if at != AgentAt::Machine {
            tell(Relayed::Held(answered.holder));
        }
        let event = match answered.result {
            Ok(answer) => Event::Agent(answer),
            Err(failure) => {
                tell(Relayed::Lost(failure));
                Event::AgentClosed
            }
        };
        let _ = events.send(event);
    });
}
