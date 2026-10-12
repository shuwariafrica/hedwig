//! The browser relay with real processes: Windows' own `curl.exe` posts the
//! URL as the remote's `curl` does, and is the browser too, given
//! `-sSL -o NUL` so it follows the stand-in authorisation server's redirect
//! as a browser does and touches no browser of the person's; the callback is
//! carried by `child tap` held in a real job, as the carrier is.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_core::browse::{Browse, EXPIRY, Malformed};
use hedwig_core::channel::Jobs;
use hedwig_core::relay::{Relayed, Settle};
use hedwig_model::capability::Browser;
use hedwig_model::refusal::Refusal;
use hedwig_model::site::Site;
use hedwig_model::text::{Name, Port, Program, Verbatim};
use hedwig_model::trail::{ConnectionId, Failure, Seq};
use hedwig_win::process::Job;

const SYSTEM: &str = r"C:\Windows\System32";

fn curl() -> PathBuf {
    Path::new(SYSTEM).join("curl.exe")
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The stand-in authorisation server's name. A sign-in's issuer is never
/// on the remote's loopback, which would read as the remote's own page.
const IDP: &str = "idp.hedwig.test";

/// The browser: `curl.exe` following redirects, its page dropped, and
/// finding [`IDP`] at `authoriser` on the workstation's loopback.
fn browser(authoriser: u16) -> Browse {
    let resolve = format!("{IDP}:{authoriser}:127.0.0.1");
    Browse {
        browser: Browser::Program {
            program: Program::try_from("curl").unwrap(),
            arguments: ["-q", "-sSL", "-o", "NUL", "--resolve", &resolve]
                .map(|argument| Verbatim::try_from(argument).unwrap())
                .to_vec(),
        },
    }
}

/// A stand-in authorisation server: every request is answered with a
/// redirect to `to`, as `/authorize` answers a sign-in. Counts what it
/// served.
fn authoriser(to: Option<String>) -> (u16, Arc<Mutex<usize>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(Mutex::new(0));
    let counted = Arc::clone(&served);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            *counted.lock().unwrap() += 1;
            let answer = match &to {
                Some(to) => format!(
                    "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
                None => {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned()
                }
            };
            let _ = stream.write_all(answer.as_bytes());
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    (port, served)
}

/// The remote's tool's own callback server: answers each request and keeps
/// its first line.
fn callback_server() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&lines);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buffer = [0u8; 4096];
            let read = stream.read(&mut buffer).unwrap_or(0);
            let text = String::from_utf8_lossy(&buffer[..read]).into_owned();
            kept.lock()
                .unwrap()
                .push(text.lines().next().unwrap_or_default().to_owned());
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nsigned in",
            );
            let _ = stream.shutdown(Shutdown::Write);
        }
    });
    (port, lines)
}

/// What the remote's `curl` posts to the forward, and how it ended.
struct Posted {
    child: Child,
}

impl Posted {
    /// The remote's `curl`, as `BROWSER` names it, at the forward's end.
    fn post(forward: u16, url: &str) -> Posted {
        let child = Command::new(curl())
            .args(["-q", "-fsS", "--noproxy", "hedwig", "--data-raw", url])
            .arg(format!("127.0.0.1:{forward}/"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        Posted { child }
    }

    fn status(self) -> (i32, String) {
        let output = self.child.wait_with_output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

/// The suite runs as the core does, in a job its children may leave: the
/// browser is the person's, and is never started inside a job of Hedwig's.
fn as_the_core_runs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| hedwig_support::leavable_here().unwrap());
}

/// One relayed connection: the forward's end accepted, the relay given it,
/// and what it tells the deciding thread.
struct Relay {
    settle: Arc<Settle>,
    told: Receiver<Relayed>,
}

impl Relay {
    fn accept(forward: &TcpListener, browse: Browse, expiry: Duration, jobs: Jobs) -> Relay {
        as_the_core_runs();
        let (stream, _) = forward.accept().unwrap();
        let (sender, told) = mpsc::channel();
        let sender = Mutex::new(sender);
        let settle = hedwig_core::browse::carry(
            stream,
            browse,
            OsString::from(SYSTEM),
            expiry,
            jobs,
            move |relayed| {
                let _ = sender.lock().unwrap().send(relayed);
            },
        );
        Relay { settle, told }
    }

    fn next(&self) -> Relayed {
        self.told.recv_timeout(Duration::from_secs(30)).unwrap()
    }
}

/// A sign-in's authorisation request, coming back to `callback` on the
/// remote's loopback.
fn authorisation(authoriser: u16, callback: u16) -> String {
    format!(
        "http://{IDP}:{authoriser}/authorize?response_type=code&client_id=hedwig-suite&redirect_uri=http%3A%2F%2F127.0.0.1%3A{callback}%2Foauth%2Fcallback&state=s7&code_challenge=c&code_challenge_method=S256"
    )
}

fn carrier(listen: u16, to: u16, job: &Job, log: &Path) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_child"))
        .args(["tap", &listen.to_string(), &to.to_string()])
        .arg(log)
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    job.hold(&child).unwrap();
    child
}

fn folder(name: &str) -> PathBuf {
    let folder = std::env::temp_dir().join(format!("hedwig-browse-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    folder
}

/// Served, the browser follows the authorisation server's redirect to the
/// callback's port on the workstation, which the relay carries to the
/// remote's own callback server through a carrier in the channel's job; the
/// remote's `curl` is answered at once, before the callback is called.
#[test]
fn a_sign_in_is_opened_and_its_callback_carried_to_the_remote() {
    let folder = folder("served");
    let callback = free_port();
    let (remote_callback, lines) = callback_server();
    let to = format!("http://127.0.0.1:{callback}/oauth/callback?code=c0de&state=s7");
    let (authoriser, served) = authoriser(Some(to));
    let url = authorisation(authoriser, callback);
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let posted = Posted::post(forward.local_addr().unwrap().port(), &url);
    let connection = ConnectionId(Seq(11));
    let job = Arc::new(Job::new().unwrap());
    let jobs = Jobs::default();
    jobs.lock().unwrap().insert(connection, Arc::clone(&job));
    let relay = Relay::accept(&forward, browser(authoriser), EXPIRY, jobs);

    assert_eq!(relay.next(), Relayed::Reached(Ok(())));
    relay.settle.settle(Ok(()));
    assert_eq!(
        relay.next(),
        Relayed::Opens {
            asked: url.clone(),
            held: None
        }
    );
    // The callback's port is the relay's from here: nothing else binds it.
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, callback)).is_err());
    let listen = free_port();
    let mut tap = carrier(listen, remote_callback, &job, &folder.join("tap.log"));
    relay.settle.settle(Ok(()));
    assert_eq!(relay.next(), Relayed::Browsed(Ok(())));
    let (status, said) = posted.status();
    assert_eq!(status, 0, "the remote's curl: {said}");
    relay
        .settle
        .call(connection, Port::try_from(listen).unwrap());
    assert_eq!(relay.next(), Relayed::Called);
    assert_eq!(relay.next(), Relayed::Ended);
    assert_eq!(*served.lock().unwrap(), 1);
    assert_eq!(
        *lines.lock().unwrap(),
        ["GET /oauth/callback?code=c0de&state=s7 HTTP/1.1"]
    );
    // Called, the port is released.
    let started = Instant::now();
    while TcpListener::bind((Ipv4Addr::LOCALHOST, callback)).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the port stays held"
        );
        thread::sleep(Duration::from_millis(50));
    }
    let _ = tap.kill();
    let _ = tap.wait();
    let _ = job.end();
    let _ = std::fs::remove_dir_all(&folder);
}

/// Refused at the opening, or at the URL, the remote's `curl` fails, so its
/// opener prints the URL; nothing is opened, and the callback's port is let
/// go.
#[test]
fn a_refusal_fails_the_remotes_curl_and_opens_nothing() {
    let (authoriser, served) = authoriser(None);
    for at_open in [false, true] {
        let callback = free_port();
        let url = authorisation(authoriser, callback);
        let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let posted = Posted::post(forward.local_addr().unwrap().port(), &url);
        let relay = Relay::accept(&forward, browser(authoriser), EXPIRY, Jobs::default());
        assert_eq!(relay.next(), Relayed::Reached(Ok(())));
        if at_open {
            relay.settle.settle(Ok(()));
            assert!(matches!(relay.next(), Relayed::Opens { held: None, .. }));
            relay.settle.settle(Err(Refusal::UnlistedSite {
                capability: Name::try_from("browser").unwrap(),
                site: format!("http://{IDP}:{authoriser}")
                    .parse::<Site>()
                    .unwrap(),
            }));
        } else {
            relay.settle.settle(Err(Refusal::Paused));
        }
        assert_eq!(relay.next(), Relayed::Ended);
        let (status, said) = posted.status();
        assert_eq!(status, 22, "{said}");
        assert!(said.contains("403"), "{said}");
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, callback)).is_ok());
    }
    assert_eq!(*served.lock().unwrap(), 0, "nothing was opened");
}

/// A callback port another program holds is said before anything is
/// decided, and the browser is never given the URL.
#[test]
fn a_callback_port_another_program_holds_is_said_before_the_decision() {
    let (authoriser, served) = authoriser(None);
    let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let callback = holder.local_addr().unwrap().port();
    let url = authorisation(authoriser, callback);
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let posted = Posted::post(forward.local_addr().unwrap().port(), &url);
    let relay = Relay::accept(&forward, browser(authoriser), EXPIRY, Jobs::default());
    assert_eq!(relay.next(), Relayed::Reached(Ok(())));
    relay.settle.settle(Ok(()));
    let held = Port::try_from(callback).unwrap();
    assert_eq!(
        relay.next(),
        Relayed::Opens {
            asked: url,
            held: Some(held)
        }
    );
    relay.settle.settle(Err(Refusal::CallbackHeld {
        capability: Name::try_from("browser").unwrap(),
        port: held,
    }));
    assert_eq!(relay.next(), Relayed::Ended);
    assert_eq!(posted.status().0, 22);
    assert_eq!(*served.lock().unwrap(), 0);
    drop(holder);
}

/// A device code's page, or any URL with no loopback callback, is opened and
/// nothing is carried; a program not on the search path is the source
/// failing, and the remote's `curl` is told the service is unavailable.
#[test]
fn a_url_without_a_callback_is_only_opened_and_a_missing_browser_fails_the_source() {
    let (authoriser, served) = authoriser(None);
    let url = format!("http://{IDP}:{authoriser}/device?user_code=WDJB-MJHT");
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let posted = Posted::post(forward.local_addr().unwrap().port(), &url);
    let relay = Relay::accept(&forward, browser(authoriser), EXPIRY, Jobs::default());
    assert_eq!(relay.next(), Relayed::Reached(Ok(())));
    relay.settle.settle(Ok(()));
    assert!(matches!(relay.next(), Relayed::Opens { held: None, .. }));
    relay.settle.settle(Ok(()));
    assert_eq!(relay.next(), Relayed::Browsed(Ok(())));
    assert_eq!(relay.next(), Relayed::Ended);
    assert_eq!(posted.status().0, 0);
    let started = Instant::now();
    while *served.lock().unwrap() == 0 {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the browser never came"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let absent = Browse {
        browser: Browser::Program {
            program: Program::try_from("hedwig-no-such-browser").unwrap(),
            arguments: Vec::new(),
        },
    };
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let posted = Posted::post(forward.local_addr().unwrap().port(), &url);
    let relay = Relay::accept(&forward, absent, EXPIRY, Jobs::default());
    assert_eq!(relay.next(), Relayed::Reached(Err(Failure::Unstartable)));
    relay.settle.settle(Err(Refusal::SourceUnavailable {
        capability: Name::try_from("browser").unwrap(),
        failure: Failure::Unstartable,
    }));
    assert_eq!(relay.next(), Relayed::Ended);
    let (status, said) = posted.status();
    assert_eq!(status, 22);
    assert!(said.contains("503"), "{said}");
}

/// A callback nobody answers is let go when its time runs out; one whose
/// channel ended is stopped, and says nothing of how.
#[test]
fn an_unanswered_callback_expires_and_a_stopped_one_ends_quietly() {
    let (authoriser, _) = authoriser(None);
    for stop in [false, true] {
        let callback = free_port();
        let url = authorisation(authoriser, callback);
        let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let posted = Posted::post(forward.local_addr().unwrap().port(), &url);
        let expiry = if stop {
            EXPIRY
        } else {
            Duration::from_millis(500)
        };
        let relay = Relay::accept(&forward, browser(authoriser), expiry, Jobs::default());
        assert_eq!(relay.next(), Relayed::Reached(Ok(())));
        relay.settle.settle(Ok(()));
        assert!(matches!(relay.next(), Relayed::Opens { held: None, .. }));
        relay.settle.settle(Ok(()));
        assert_eq!(relay.next(), Relayed::Browsed(Ok(())));
        assert_eq!(posted.status().0, 0);
        if stop {
            relay.settle.stop();
        } else {
            assert_eq!(relay.next(), Relayed::Expired);
        }
        assert_eq!(relay.next(), Relayed::Ended);
        let started = Instant::now();
        while TcpListener::bind((Ipv4Addr::LOCALHOST, callback)).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the port stays held"
            );
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// What is not `curl`'s post is said and answered as a bad request, and
/// nothing is decided of it; a `curl` that waits to be told to send its body
/// is told.
#[test]
fn what_is_not_curls_post_is_turned_away_and_an_expecting_curl_is_served() {
    for (sent, why) in [
        (
            &b"GET / HTTP/1.1\r\nHost: hedwig\r\n\r\n"[..],
            Malformed::Request,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: hedwig\r\n\r\n",
            Malformed::Length,
        ),
        (
            b"POST / HTTP/1.1\r\nContent-Length: 40\r\n\r\nhttp://cut",
            Malformed::Cut,
        ),
    ] {
        let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut remote = TcpStream::connect(forward.local_addr().unwrap()).unwrap();
        let relay = Relay::accept(&forward, browser(1), EXPIRY, Jobs::default());
        remote.write_all(sent).unwrap();
        if why == Malformed::Cut {
            remote.shutdown(Shutdown::Write).unwrap();
        }
        assert_eq!(relay.next(), Relayed::Misread(why));
        assert_eq!(relay.next(), Relayed::Ended);
        let mut answer = String::new();
        let _ = remote.read_to_string(&mut answer);
        assert!(answer.starts_with("HTTP/1.1 400"), "{answer}");
    }

    let (authoriser, _) = authoriser(None);
    let url = format!("http://{IDP}:{authoriser}/device");
    let forward = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let child = Command::new(curl())
        .args([
            "-q",
            "-fsS",
            "--noproxy",
            "hedwig",
            "-H",
            "Expect: 100-continue",
        ])
        .args(["--data-raw", &url])
        .arg(format!(
            "127.0.0.1:{}/",
            forward.local_addr().unwrap().port()
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let relay = Relay::accept(&forward, browser(authoriser), EXPIRY, Jobs::default());
    assert_eq!(relay.next(), Relayed::Reached(Ok(())));
    relay.settle.settle(Ok(()));
    assert_eq!(
        relay.next(),
        Relayed::Opens {
            asked: url,
            held: None
        }
    );
    relay.settle.settle(Err(Refusal::Paused));
    assert_eq!(relay.next(), Relayed::Ended);
    assert_eq!(Posted { child }.status().0, 22);
}
