//! What serves a browser capability: the remote's own `curl`, which its
//! openers' variables name, posts the URL a tool there asks to open; the
//! core decides it, starts the workstation's browser with it, and carries the
//! sign-in's loopback callback back to the remote for the flow's life.
//!
//! A connection reaches the browser first - the program found, where the
//! source names one - and its opening is decided. Its request is then read:
//! `POST /` with the URL as its body, nothing else. Where opening the URL
//! carries a callback, the callback's port is bound on the workstation before
//! the request is decided, so a port another program holds is refused before
//! the browser is given anything. Served, the browser is started and `curl`
//! answered at once, since a tool calls its opener before it serves its own
//! callback; the callback is then carried until it is answered, the flow's
//! time runs out, or the channel ends.

use std::ffi::OsString;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddrV4, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_model::capability::Browser;
use hedwig_model::refusal::Refusal;
use hedwig_model::site::{self, Callback, LONGEST, Opening};
use hedwig_model::text::Port;
use hedwig_model::trail::Failure;
use hedwig_win::Signal;
use hedwig_win::endpoint::{Endpoint, owner};
use hedwig_win::process::{LEAVING, Process};
use hedwig_win::search::program_on;
use hedwig_win::start::apart;
use hedwig_win::token::Token;

use crate::adb::pipe;
use crate::channel::Jobs;
use crate::peer::placed;
use crate::relay::{Event, QUEUED, Relayed, Settle};

/// How long a callback is carried with no answer. Invariant: AWS CLI's own
/// time for the whole flow (`_OVERALL_TIMEOUT`), the longest of the traced
/// tools; past it the tool on the remote has given up.
pub const EXPIRY: Duration = Duration::from_secs(600);

/// The most a request's head may be. Invariant: `curl`'s head for the post is
/// under two hundred bytes; a remote's request is never held beyond this.
const HEAD: usize = 8192;

/// How much of a body longer than the capability reads is read and dropped
/// before it is answered. Invariant: eight times the longest body either
/// relay reads, so a remote's `curl` that posts a little too much is told
/// why; past it the connection is closed as it stands.
const DRAINED: usize = 65_536;

/// How long a callback waits for its carrier to listen. Invariant: the
/// carrier is started as the request is served, and its client connects in
/// the time a channel's does; a browser that reaches the callback first waits
/// this long and no longer.
const CARRIER: Duration = Duration::from_secs(30);

/// What a browser capability opens with, and where its program is looked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Browse {
    pub browser: Browser,
}

/// Why what a remote sent is not the post its `curl` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The head is longer than any `curl` sends, or never ended.
    Head,
    /// Anything but `POST /` in HTTP/1.1.
    Request,
    /// No length, or the body sent in chunks.
    Length,
    /// A body longer than the capability reads: a URL past the longest
    /// Hedwig opens, a notice past the longest remark.
    Long,
    /// The connection closed before the body was whole.
    Cut,
    /// The body is not text.
    Text,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Malformed::Head => "the remote sent a request head longer than curl sends",
            Malformed::Request => "the remote sent a request other than the post curl makes",
            Malformed::Length => "the remote sent a body of no stated length",
            Malformed::Long => "the remote posted more than Hedwig reads",
            Malformed::Cut => "the remote closed the connection before its request was whole",
            Malformed::Text => "the remote posted something that is not text",
        })
    }
}

impl std::error::Error for Malformed {}

/// What a request's head says of its body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Head {
    pub length: usize,
    /// Whether `curl` waits to be told to send the body.
    pub expects: bool,
}

/// Reads a request's head, its last blank line excluded, for a body of at
/// most `longest` bytes.
///
/// # Errors
///
/// [`Malformed`], saying why it is not `curl`'s post.
pub fn head(head: &[u8], longest: usize) -> Result<Head, Malformed> {
    let text = std::str::from_utf8(head).map_err(|_| Malformed::Request)?;
    let mut lines = text.split("\r\n");
    if lines.next() != Some("POST / HTTP/1.1") {
        return Err(Malformed::Request);
    }
    let mut length = None;
    let mut expects = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(Malformed::Request)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let stated = value
                .parse::<usize>()
                .ok()
                .filter(|_| value.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(Malformed::Length)?;
            if stated > longest {
                return Err(Malformed::Long);
            }
            if length.replace(stated).is_some() {
                return Err(Malformed::Length);
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Malformed::Length);
        } else if name.eq_ignore_ascii_case("expect") {
            expects = value.eq_ignore_ascii_case("100-continue");
        }
    }
    Ok(Head {
        length: length.ok_or(Malformed::Length)?,
        expects,
    })
}

/// The answer `curl` is given: `-f` makes every one but the first a failed
/// command, and the opener then prints the URL, as it does where no browser
/// opens. Nothing more is said: the reason is the workstation's to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Opened,
    Malformed,
    Refused,
    Unavailable,
}

impl Answer {
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Answer::Opened => b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
            Answer::Malformed => {
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Answer::Refused => {
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Answer::Unavailable => {
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
        }
    }

    fn of(refusal: &Refusal) -> Answer {
        match refusal {
            Refusal::SourceUnavailable { .. } => Answer::Unavailable,
            _ => Answer::Refused,
        }
    }
}

/// Reads `curl`'s post from `client`: its head, then a body of at most
/// `longest` bytes, telling it to send the body where it waits to be told.
///
/// # Errors
///
/// [`Malformed`], saying why.
pub fn request(client: &mut TcpStream, longest: usize) -> Result<String, Malformed> {
    let mut read = Vec::new();
    let mut buffer = [0u8; 1024];
    let end = loop {
        if let Some(end) = read.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        if read.len() > HEAD {
            return Err(Malformed::Head);
        }
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => return Err(Malformed::Cut),
            Ok(count) => read.extend_from_slice(buffer.get(..count).unwrap_or_default()),
        }
    };
    let stated = match head(read.get(..end).unwrap_or_default(), longest) {
        Err(Malformed::Long) => {
            // A connection closed with bytes unread is reset, and `curl`
            // would read that instead of the answer: what it sends is read
            // first, as far as `DRAINED`.
            let mut taken = read.len().saturating_sub(end + 4);
            let _ = client.set_read_timeout(Some(Duration::from_secs(1)));
            while taken < DRAINED {
                match client.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => taken += count,
                }
            }
            return Err(Malformed::Long);
        }
        stated => stated?,
    };
    let mut body = read.get(end + 4..).unwrap_or_default().to_vec();
    if stated.expects && body.is_empty() {
        client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .map_err(|_| Malformed::Cut)?;
    }
    while body.len() < stated.length {
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => return Err(Malformed::Cut),
            Ok(count) => body.extend_from_slice(buffer.get(..count).unwrap_or_default()),
        }
    }
    if body.len() > stated.length {
        return Err(Malformed::Length);
    }
    String::from_utf8(body).map_err(|_| Malformed::Text)
}

/// The program `browser` names, found as a route's client is; `None` for the
/// person's default browser, which Windows finds by the address.
///
/// # Errors
///
/// [`Failure::Unstartable`] where the program is not on the search path.
pub fn located(
    browser: &Browser,
    search: &std::ffi::OsStr,
) -> Result<Option<std::path::PathBuf>, Failure> {
    match browser {
        Browser::Default => Ok(None),
        Browser::Program { program, .. } => program_on(program.as_str(), search)
            .map(Some)
            .map_err(|_| Failure::Unstartable),
    }
}

/// Starts the browser with `url`: the program and its arguments, the URL
/// last, outside every job Hedwig holds, since the browser is the person's;
/// or what Windows opens an `https` address with for the person.
///
/// # Errors
///
/// [`Failure::Unstartable`] where Windows would not start the program, and
/// [`Failure::Unopened`] where it started nothing for the address.
pub fn start(
    browser: &Browser,
    program: Option<&std::path::Path>,
    url: &str,
) -> Result<(), Failure> {
    match (browser, program) {
        (Browser::Program { arguments, .. }, Some(program)) => {
            let mut given: Vec<OsString> = arguments
                .iter()
                .map(|argument| OsString::from(argument.as_str()))
                .collect();
            given.push(OsString::from(url));
            // What it prints is not read: a browser can hold its output open
            // for as long as it runs.
            apart(program, &given, LEAVING)
                .map(drop)
                .map_err(|_| Failure::Unstartable)
        }
        _ => hedwig_win::shell::open(url).map_err(|_| Failure::Unopened),
    }
}

/// The callback's port bound on the workstation's loopback in each family a
/// browser may try for the host it is given. `Err` where another program holds
/// the port in either.
fn bound(callback: &Callback) -> Result<Vec<Endpoint>, Port> {
    let mut endpoints = Vec::new();
    for address in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        match Endpoint::bind_at(address, callback.port.number()) {
            Ok(endpoint) => endpoints.push(endpoint),
            // A workstation with no IPv6 loopback has nothing there to hold it.
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {}
            Err(_) => return Err(callback.port),
        }
    }
    if endpoints.is_empty() {
        Err(callback.port)
    } else {
        Ok(endpoints)
    }
}

/// Whether a request's first line is the authorisation server's answer the
/// callback waits for: to its path, or any path where the remote's own page
/// was opened, with a code or an error.
pub fn answers(callback: &Callback, line: &str) -> bool {
    let mut words = line.split(' ');
    let (Some(_method), Some(target)) = (words.next(), words.next()) else {
        return false;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let to_path = callback
        .path
        .as_deref()
        .is_none_or(|expected| expected == path);
    let named = query.split('&').any(|pair| {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        name == "code" || name == "error"
    });
    to_path && named
}

/// Carries one admitted connection to the browser. `tell` reaches the
/// deciding thread. Returns where the deciding thread settles its requests
/// and the run gives a served callback its carrier; the connection and the
/// callback run on threads of their own.
pub fn carry(
    client: TcpStream,
    source: Browse,
    search: OsString,
    expiry: Duration,
    jobs: Jobs,
    tell: impl Fn(Relayed) + Send + 'static,
) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events.clone()));
    let held = Arc::clone(&settle);
    thread::spawn(move || {
        run(
            client, &source, &search, expiry, &jobs, &tell, &events, &queue, &held,
        );
        tell(Relayed::Ended);
    });
    settle
}

#[allow(
    clippy::too_many_arguments,
    reason = "each is one thing the relay needs"
)]
fn run(
    mut client: TcpStream,
    source: &Browse,
    search: &std::ffi::OsStr,
    expiry: Duration,
    jobs: &Jobs,
    tell: &impl Fn(Relayed),
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Arc<Settle>,
) {
    let answer = |client: &mut TcpStream, answer: Answer| {
        let _ = client.write_all(answer.bytes());
        let _ = client.shutdown(Shutdown::Both);
    };
    // The post is read whole before anything is decided: it is short, and a
    // connection closed with bytes unread is reset, which `curl` reports as
    // a broken connection instead of the answer.
    let _ = client.set_read_timeout(Some(crate::PATIENCE));
    let asked = match request(&mut client, LONGEST) {
        Ok(asked) => asked,
        Err(malformed) => {
            tell(Relayed::Misread(malformed));
            return answer(&mut client, Answer::Malformed);
        }
    };
    let _ = client.set_read_timeout(None);
    if let Ok(mut watched) = client.try_clone() {
        let events = events.clone();
        // `curl` sends nothing more, so a read that ends is the remote giving
        // up while the request is held.
        thread::spawn(move || {
            let mut byte = [0u8; 1];
            let _ = watched.read(&mut byte);
            let _ = events.send(Event::ClientClosed);
        });
    }
    let located = located(&source.browser, search);
    tell(Relayed::Reached(
        located.as_ref().map(drop).map_err(|failure| *failure),
    ));
    match word(queue, settle) {
        Some(Ok(())) => {}
        Some(Err(refusal)) => return answer(&mut client, Answer::of(&refusal)),
        None => return,
    }
    let Ok(program) = located else {
        return answer(&mut client, Answer::Unavailable);
    };
    let callback = site::url(&asked)
        .ok()
        .map(Opening::of)
        .and_then(|opening| opening.callback);
    let endpoints = match callback.as_ref().map(bound) {
        Some(Ok(endpoints)) => Some(endpoints),
        Some(Err(port)) => {
            tell(Relayed::Opens {
                asked,
                held: Some(port),
            });
            if let Some(Err(refusal)) = word(queue, settle) {
                answer(&mut client, Answer::of(&refusal));
            }
            return;
        }
        None => None,
    };
    tell(Relayed::Opens {
        asked: asked.clone(),
        held: None,
    });
    match word(queue, settle) {
        Some(Ok(())) => {}
        Some(Err(refusal)) => return answer(&mut client, Answer::of(&refusal)),
        None => return,
    }
    let started = start(&source.browser, program.as_deref(), &asked);
    tell(Relayed::Browsed(started));
    if started.is_err() {
        return answer(&mut client, Answer::Unavailable);
    }
    answer(&mut client, Answer::Opened);
    if let (Some(callback), Some(endpoints)) = (callback, endpoints)
        && let Some(end) = called(&callback, endpoints, expiry, jobs, events, queue, settle)
    {
        tell(end);
    }
}

/// The deciding thread's word, waiting for it; `None` where the remote
/// closed first.
fn word(queue: &Receiver<Event>, settle: &Settle) -> Option<Result<(), Refusal>> {
    loop {
        if let Some(word) = settle.take() {
            return Some(word);
        }
        if let Ok(Event::ClientClosed) | Err(_) = queue.recv() {
            return None;
        }
    }
}

/// Carries the callback until it is answered, `expiry` passes, or the
/// deciding thread stops it, which it does when the channel ends; what ended
/// it, unless it was stopped.
fn called(
    callback: &Callback,
    endpoints: Vec<Endpoint>,
    expiry: Duration,
    jobs: &Jobs,
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Arc<Settle>,
) -> Option<Relayed> {
    let Ok(stop) = Signal::new().map(Arc::new) else {
        return Some(Relayed::Expired);
    };
    let mut accepting = Vec::new();
    for endpoint in endpoints {
        let (stop, jobs, events, settle) = (
            Arc::clone(&stop),
            Arc::clone(jobs),
            events.clone(),
            Arc::clone(settle),
        );
        let callback = callback.clone();
        accepting.push(thread::spawn(move || {
            while let Ok(Some(stream)) = endpoint.accept(&stop) {
                let (jobs, events, settle) =
                    (Arc::clone(&jobs), events.clone(), Arc::clone(&settle));
                let callback = callback.clone();
                thread::spawn(move || {
                    if through(&stream, &callback, &settle, &jobs) {
                        let _ = events.send(Event::Called);
                    }
                });
            }
        }));
    }
    let deadline = Instant::now() + expiry;
    let ended = loop {
        if settle.stopped() {
            break None;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        match queue.recv_timeout(left) {
            Ok(Event::Called) => break Some(Relayed::Called),
            Ok(_) => {}
            Err(RecvTimeoutError::Timeout) => break Some(Relayed::Expired),
            Err(RecvTimeoutError::Disconnected) => break None,
        }
    };
    let _ = stop.raise();
    for thread in accepting {
        let _ = thread.join();
    }
    ended
}

/// Carries one connection to the callback on to the remote: only one from a
/// process of the person's own account, and only to the carrier the
/// remote's channel's job holds. Whether it was the answer the callback
/// waits for.
fn through(stream: &TcpStream, callback: &Callback, settle: &Settle, jobs: &Jobs) -> bool {
    if !persons(stream) {
        let _ = stream.shutdown(Shutdown::Both);
        return false;
    }
    let mut first = Vec::new();
    let mut reader = stream;
    let mut byte = [0u8; 1];
    let _ = stream.set_read_timeout(Some(crate::PATIENCE));
    while first.len() < LONGEST && !first.ends_with(b"\r\n") {
        match reader.read(&mut byte) {
            Ok(1) => first.extend_from_slice(&byte),
            _ => break,
        }
    }
    let _ = stream.set_read_timeout(None);
    let answering = std::str::from_utf8(&first)
        .is_ok_and(|line| answers(callback, line.trim_end_matches("\r\n")));
    let Some(onward) = carrier(settle, jobs) else {
        let _ = stream.shutdown(Shutdown::Both);
        return false;
    };
    let mut writer = &onward;
    if writer.write_all(&first).is_err() {
        let _ = stream.shutdown(Shutdown::Both);
        return false;
    }
    pipe(stream, &onward);
    answering
}

/// Whether the process at the other end of `stream` is one of the person's
/// own account.
fn persons(stream: &TcpStream) -> bool {
    let ours = Token::own().and_then(|token| token.user()).ok();
    let theirs = owner(stream)
        .ok()
        .flatten()
        .and_then(|process| Process::open(process).ok())
        .and_then(|process| process.token().ok())
        .and_then(|token| token.user().ok());
    ours.is_some() && theirs == ours
}

/// A connection to the callback's carrier, once the run has given it one and
/// it listens: a process the channel's job holds, never whatever took its
/// port meanwhile.
fn carrier(settle: &Settle, jobs: &Jobs) -> Option<TcpStream> {
    let deadline = Instant::now() + CARRIER;
    loop {
        if let Some((connection, listen)) = settle.carrier() {
            let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listen.number());
            if let Ok(onward) = TcpStream::connect_timeout(&address.into(), crate::PATIENCE) {
                let held = owner(&onward)
                    .ok()
                    .flatten()
                    .is_some_and(|listener| placed(listener, jobs).1 == Some(connection));
                if held {
                    return Some(onward);
                }
                let _ = onward.shutdown(Shutdown::Both);
                return None;
            }
        }
        if Instant::now() >= deadline || settle.stopped() {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use hedwig_model::text::Host;

    use super::*;

    #[test]
    fn curls_post_is_read_and_anything_else_is_not() {
        let curl = "POST / HTTP/1.1\r\nHost: hedwig\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nContent-Length: 27\r\nContent-Type: application/x-www-form-urlencoded";
        assert_eq!(
            head(curl.as_bytes(), LONGEST),
            Ok(Head {
                length: 27,
                expects: false
            })
        );
        let expecting = format!("{curl}\r\nExpect: 100-continue");
        assert!(head(expecting.as_bytes(), LONGEST).unwrap().expects);
        assert_eq!(head(curl.as_bytes(), 26), Err(Malformed::Long));
        for (sent, why) in [
            ("GET / HTTP/1.1\r\nContent-Length: 1", Malformed::Request),
            ("POST /x HTTP/1.1\r\nContent-Length: 1", Malformed::Request),
            ("POST / HTTP/1.0\r\nContent-Length: 1", Malformed::Request),
            ("POST / HTTP/1.1\r\nHost: hedwig", Malformed::Length),
            ("POST / HTTP/1.1\r\nContent-Length: 8193", Malformed::Long),
            ("POST / HTTP/1.1\r\nContent-Length: +5", Malformed::Length),
            (
                "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1",
                Malformed::Length,
            ),
            (
                "POST / HTTP/1.1\r\nTransfer-Encoding: chunked",
                Malformed::Length,
            ),
            ("POST / HTTP/1.1\r\nno colon", Malformed::Request),
        ] {
            assert_eq!(head(sent.as_bytes(), LONGEST), Err(why), "{sent}");
        }
    }

    #[test]
    fn the_callback_is_answered_by_a_code_or_an_error_at_its_path() {
        let host = Host::try_from("127.0.0.1").unwrap();
        let port = Port::try_from(8400).unwrap();
        let aws = Callback {
            host: host.clone(),
            port,
            path: Some("/oauth/callback".to_owned()),
        };
        assert!(answers(
            &aws,
            "GET /oauth/callback?code=abc&state=xyz HTTP/1.1"
        ));
        assert!(answers(
            &aws,
            "GET /oauth/callback?error=access_denied&state=xyz HTTP/1.1"
        ));
        assert!(!answers(&aws, "GET /oauth/callback HTTP/1.1"));
        assert!(!answers(&aws, "GET /favicon.ico HTTP/1.1"));
        assert!(!answers(&aws, "GET /other?code=abc HTTP/1.1"));
        assert!(!answers(&aws, "GET /oauth/callback?codes=abc HTTP/1.1"));
        let page = Callback {
            host,
            port,
            path: None,
        };
        assert!(answers(&page, "GET /?code=abc HTTP/1.1"));
        assert!(answers(&page, "GET /callback?state=s&code=abc HTTP/1.1"));
        assert!(!answers(&page, "GET / HTTP/1.1"));
        assert!(!answers(&page, "nonsense"));
    }
}
