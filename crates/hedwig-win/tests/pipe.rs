//! The control pipe as Windows gives it: who owns it and whom it admits, that
//! both ends can write while the other waits to read, and what the server
//! learns of a client.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use hedwig_win::Signal;
use hedwig_win::pipe::{INSTANCES, Listener, Moved, OpenError, Pipe, open};
use hedwig_win::token::{Sid, Token};

fn path(purpose: &str) -> String {
    let mut drawn = [0u8; 8];
    hedwig_win::random::fill(&mut drawn).unwrap();
    format!(
        r"\\.\pipe\hedwig-design-{purpose}-{:016x}",
        u64::from_le_bytes(drawn)
    )
}

fn me() -> Sid {
    Token::own().unwrap().user().unwrap()
}

/// A server end with a client connected to it.
fn pair(purpose: &str) -> (Pipe, Pipe) {
    let path = path(purpose);
    let (_listener, server) = Listener::bind(&path, &me()).unwrap();
    let client = open(&path, Duration::from_secs(1)).unwrap();
    let never = Signal::new().unwrap();
    assert!(matches!(server.accept(&never), Ok(Moved::Bytes(_))));
    (server, client)
}

fn read_exactly(pipe: &Pipe, count: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buffer = [0u8; 4096];
    while got.len() < count {
        match pipe.read(&mut buffer, None).unwrap() {
            Moved::Bytes(read) => got.extend_from_slice(buffer.get(..read).unwrap()),
            other => panic!("{other:?} after {} of {count} bytes", got.len()),
        }
    }
    got
}

/// The pipe is the person's: owned by their account, open to that account
/// alone with no entry for anyone else, and labelled so that a lower
/// integrity level than medium cannot write to it.
#[test]
fn the_pipe_is_owned_by_the_person_and_open_to_them_alone() {
    let (server, client) = pair("security");
    let read = client.security().unwrap();
    // Windows writes some accounts by their SDDL alias - the built-in
    // Administrator as `LA` - so the account is compared as an identifier.
    let (owner, rest) = read
        .strip_prefix("O:")
        .and_then(|rest| rest.split_once("D:P(A;;0x12019f;;;"))
        .unwrap_or_else(|| panic!("{read}"));
    let (trustee, label) = rest.split_once(')').unwrap_or_else(|| panic!("{read}"));
    assert_eq!(Sid::from_text(owner).unwrap(), me(), "{read}");
    assert_eq!(Sid::from_text(trustee).unwrap(), me(), "{read}");
    assert_eq!(label, "S:AI(ML;;NW;;;ME)", "{read}");
    assert_eq!(server.security().unwrap(), read);
    assert_eq!(client.owner().unwrap(), me());
}

/// Both ends write while the other is waiting to read, which a synchronous
/// handle would not allow: the core tells a client something while that
/// client waits for it.
#[test]
fn each_end_writes_while_the_other_waits_to_read() {
    let (server, client) = pair("duplex");
    let (server, client) = (Arc::new(server), Arc::new(client));
    let waiting = {
        let client = Arc::clone(&client);
        thread::spawn(move || read_exactly(&client, 5))
    };
    // The client is blocked in its read by the time this write is made.
    thread::sleep(Duration::from_millis(50));
    assert_eq!(client.write(b"ping\n", None).unwrap(), Moved::Bytes(5));
    assert_eq!(read_exactly(&server, 5), b"ping\n");
    assert_eq!(server.write(b"pong\n", None).unwrap(), Moved::Bytes(5));
    assert_eq!(waiting.join().unwrap(), b"pong\n");

    // A megabyte crosses whole in each direction, more than the pipe's own
    // buffers hold at once.
    let large: Vec<u8> = (0..1_048_576u32).map(|n| (n % 251) as u8).collect();
    let sender = {
        let (server, large) = (Arc::clone(&server), large.clone());
        thread::spawn(move || server.write(&large, None).unwrap())
    };
    assert_eq!(read_exactly(&client, large.len()), large);
    assert_eq!(sender.join().unwrap(), Moved::Bytes(large.len()));
}

#[test]
fn a_waiting_read_and_a_waiting_accept_end_when_asked_to_stop() {
    let (server, client) = pair("stop");
    let stop = Arc::new(Signal::new().unwrap());
    let raiser = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            stop.raise().unwrap();
        })
    };
    let mut buffer = [0u8; 16];
    assert_eq!(
        server.read(&mut buffer, Some(&stop)).unwrap(),
        Moved::Stopped
    );
    raiser.join().unwrap();

    // Stopping a read leaves the pipe whole.
    assert_eq!(client.write(b"x", None).unwrap(), Moved::Bytes(1));
    assert_eq!(server.read(&mut buffer, None).unwrap(), Moved::Bytes(1));

    let path = path("accept");
    let (_listener, waiting) = Listener::bind(&path, &me()).unwrap();
    assert_eq!(waiting.accept(&stop).unwrap(), Moved::Stopped);
}

#[test]
fn a_read_gives_up_as_stopped_when_its_limit_passes() {
    let (server, _client) = pair("limit");
    let began = Instant::now();
    let mut buffer = [0u8; 16];
    let moved = server
        .read_within(&mut buffer, None, Some(Duration::from_millis(100)))
        .unwrap();
    assert_eq!(moved, Moved::Stopped);
    assert!(began.elapsed() >= Duration::from_millis(90));
}

#[test]
fn an_end_whose_other_end_is_gone_says_closed() {
    let (server, client) = pair("closed");
    drop(client);
    let mut buffer = [0u8; 16];
    assert_eq!(server.read(&mut buffer, None).unwrap(), Moved::Closed);
    assert_eq!(server.write(b"late", None).unwrap(), Moved::Closed);
}

/// The first instance is never an instance of a pipe that already exists, so
/// a name somebody else holds is refused, not joined.
#[test]
fn a_name_that_exists_is_refused_not_joined() {
    let path = path("first");
    let (listener, _first) = Listener::bind(&path, &me()).unwrap();
    let again = Listener::bind(&path, &me()).unwrap_err();
    assert_eq!(again.kind(), std::io::ErrorKind::PermissionDenied);
    // Its own further instances are made freely.
    listener.another().unwrap();
}

/// A client is refused as busy only when every instance the pipe may have is
/// held for the whole of its patience; one waiting when an instance frees is
/// given it; one waiting when the pipe goes is told it is absent.
#[test]
fn a_client_is_busy_only_while_every_instance_is_held() {
    assert!(matches!(
        open(&path("absent"), Duration::from_millis(50)),
        Err(OpenError::Absent)
    ));

    let path = path("busy");
    let never = Signal::new().unwrap();
    let (listener, first) = Listener::bind(&path, &me()).unwrap();
    let mut held = vec![(first, open(&path, Duration::from_secs(1)).unwrap())];
    while let Ok(server) = listener.another() {
        held.push((server, open(&path, Duration::from_secs(1)).unwrap()));
    }
    for (server, _) in &held {
        assert!(matches!(server.accept(&never), Ok(Moved::Bytes(_))));
    }
    assert_eq!(held.len(), usize::try_from(INSTANCES).unwrap());

    let began = Instant::now();
    assert!(matches!(
        open(&path, Duration::from_millis(300)),
        Err(OpenError::Busy)
    ));
    assert!(
        began.elapsed() >= Duration::from_millis(300),
        "it waited its turn"
    );

    let waiting = {
        let path = path.clone();
        thread::spawn(move || open(&path, Duration::from_secs(10)).map(|_| ()))
    };
    thread::sleep(Duration::from_millis(100));
    drop(held.pop());
    let spare = listener.another().unwrap();
    assert!(matches!(waiting.join().unwrap(), Ok(())));
    drop(spare);

    let waiting = {
        let path = path.clone();
        thread::spawn(move || open(&path, Duration::from_secs(10)).map(|_| ()))
    };
    thread::sleep(Duration::from_millis(100));
    let began = Instant::now();
    drop(held);
    drop(listener);
    assert!(matches!(waiting.join().unwrap(), Err(OpenError::Absent)));
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "told at once, not at the end of its patience"
    );
}

/// The server learns who connected from the pipe itself: the process, and
/// from the token the client lets it see, the account and where it stands.
/// The client opens the pipe allowing identification and no more.
#[test]
fn the_server_reads_the_client_and_cannot_act_as_it() {
    let (server, client) = pair("client");
    client.write(b"hello\n", None).unwrap();
    assert_eq!(read_exactly(&server, 6), b"hello\n");
    assert_eq!(server.client_process().unwrap(), std::process::id());
    let theirs = server.client_token().unwrap();
    let own = Token::own().unwrap();
    assert_eq!(theirs.user().unwrap(), own.user().unwrap());
    assert_eq!(theirs.standing().unwrap(), own.standing().unwrap());

    // After reading the client the thread is itself again: it can still do
    // what only its own identity may.
    assert_eq!(Token::own().unwrap().user().unwrap(), me());
}
