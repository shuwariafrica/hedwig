//! The serial relay with real sockets and pyserial's own RFC 2217 client, on
//! the bench's ports: what the workstation has no COM port to show.
//!
//! A connection is handed over as the forward's end hands one over: accepted
//! on a loopback port, its other end pyserial's. What is decided is the
//! suite's to say, as the deciding thread would. pyserial is the release
//! wheel `HEDWIG_PYSERIAL` names, which `scripts\fetch-test-tools.ps1` fetches,
//! run by the workstation's own Python.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_core::relay::{Relayed, Settle};
use hedwig_core::serial::{Lines, Serial, carry};
use hedwig_model::refusal::Refusal;
use hedwig_model::text::PortName;
use hedwig_model::trail::Failure;
use hedwig_support::bench::{Bench, Wiring};

const WAIT: Duration = Duration::from_secs(20);

fn script(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("serial")
        .join(name)
}

/// pyserial's client running `script` against `url`.
fn pyserial(script_name: &str, url: &str) -> Child {
    let wheel = std::env::var_os("HEDWIG_PYSERIAL")
        .expect("HEDWIG_PYSERIAL names pyserial's wheel: run scripts\\fetch-test-tools.ps1");
    Command::new("python")
        .arg(script(script_name))
        .arg(url)
        .env("PYTHONPATH", wheel)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the workstation's Python")
}

fn said(child: Child) -> String {
    let out = child.wait_with_output().unwrap();
    let mut said = String::from_utf8_lossy(&out.stdout).into_owned();
    said.push_str(&String::from_utf8_lossy(&out.stderr));
    said
}

/// The relay given the connection pyserial makes to a loopback port, as the
/// forward's end would hand it over; what it tells the deciding thread.
fn relayed(
    bench: Arc<Bench>,
    port: &str,
    script_name: &str,
    listening: &TcpListener,
    url: &str,
) -> (Child, Arc<Settle>, Receiver<Relayed>) {
    let child = pyserial(script_name, url);
    let (stream, _) = listening.accept().unwrap();
    let (told, heard) = mpsc::channel();
    let lines: Arc<dyn Lines> = bench;
    let settle = carry(
        stream,
        Serial {
            port: PortName::try_from(port).unwrap(),
        },
        lines,
        move |relayed| {
            let _ = told.send(relayed);
        },
    );
    (child, settle, heard)
}

fn listening() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "rfc2217://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    (listener, url)
}

fn next(heard: &Receiver<Relayed>) -> Relayed {
    heard
        .recv_timeout(WAIT)
        .expect("the relay tells what happened")
}

#[test]
fn a_served_connection_has_the_port_its_data_its_baud_rate_and_both_lines_and_gives_it_back() {
    let bench = Arc::new(Bench::new(&["COM9"], Wiring::Loop, None).unwrap());
    let (listener, url) = listening();
    for url in [url.clone(), format!("{url}?poll_modem")] {
        let (child, settle, heard) =
            relayed(Arc::clone(&bench), "com9", "client.py", &listener, &url);
        assert_eq!(next(&heard), Relayed::Reached(Ok(())));
        // Nothing is opened before the word, however long it takes.
        let opened = || {
            bench
                .logged()
                .iter()
                .filter(|line| line.contains("opened"))
                .count()
        };
        let opened_before = opened();
        thread::sleep(Duration::from_millis(300));
        assert_eq!(opened(), opened_before);
        settle.settle(Ok(()));
        assert_eq!(next(&heard), Relayed::Opened(Ok(None)));
        let said = said(child);
        assert_eq!(next(&heard), Relayed::Released, "{said}");
        assert_eq!(next(&heard), Relayed::Ended, "{said}");
        for line in [
            "echo True",
            "baud 921600",
            "rts True cts True",
            "rts False cts False",
            "dtr True dsr True",
            "dtr False dsr False",
            "closed",
        ] {
            assert!(said.contains(line), "{url}: {line} in {said}");
        }
        let logged = bench.logged();
        assert_eq!(
            logged
                .iter()
                .filter(|line| line.contains("opened COM9"))
                .count(),
            opened_before + 1
        );
        assert!(
            logged.iter().any(|line| line.ends_with("baud 921600")),
            "{logged:?}"
        );
        assert!(logged.last().unwrap().contains("closed COM9"), "{logged:?}");
    }
}

/// Under a person's `Confirm` rule the word can come later than pyserial's
/// three seconds for the server's negotiation: with its URL as it ships,
/// pyserial gives up, the relay sees it go, and a word that comes after opens
/// nothing; with the URL's own `timeout` past the wait, the same late word
/// serves the connection whole.
#[test]
fn a_word_later_than_pyserials_wait_serves_only_a_url_that_waits_longer() {
    let bench = Arc::new(Bench::new(&["COM9"], Wiring::Loop, None).unwrap());
    let (listener, url) = listening();
    let late = Duration::from_secs(4);

    let (child, settle, heard) = relayed(Arc::clone(&bench), "COM9", "client.py", &listener, &url);
    assert_eq!(next(&heard), Relayed::Reached(Ok(())));
    let said_first = said(child);
    assert!(
        said_first.contains("Remote does not seem to support RFC2217"),
        "{said_first}"
    );
    assert_eq!(next(&heard), Relayed::Ended, "the relay sees the remote go");
    settle.settle(Ok(()));
    thread::sleep(Duration::from_millis(300));
    assert!(
        !bench.logged().iter().any(|line| line.contains("opened")),
        "{:?}",
        bench.logged()
    );

    let waiting = format!("{url}?timeout=10");
    let (child, settle, heard) =
        relayed(Arc::clone(&bench), "COM9", "client.py", &listener, &waiting);
    assert_eq!(next(&heard), Relayed::Reached(Ok(())));
    thread::sleep(late);
    settle.settle(Ok(()));
    assert_eq!(next(&heard), Relayed::Opened(Ok(None)));
    let said_second = said(child);
    assert!(said_second.contains("closed"), "{said_second}");
    assert!(said_second.contains("baud 921600"), "{said_second}");
    assert_eq!(next(&heard), Relayed::Released);
    assert_eq!(next(&heard), Relayed::Ended);
}

#[test]
fn a_refused_connection_never_opens_the_port_and_the_remote_reads_the_end() {
    let bench = Arc::new(Bench::new(&["COM9"], Wiring::Loop, None).unwrap());
    let (listener, url) = listening();
    let (child, settle, heard) = relayed(Arc::clone(&bench), "COM9", "client.py", &listener, &url);
    assert_eq!(next(&heard), Relayed::Reached(Ok(())));
    settle.settle(Err(Refusal::Paused));
    assert_eq!(next(&heard), Relayed::Ended);
    let said = said(child);
    assert!(
        said.contains("Traceback") && !said.contains("closed"),
        "{said}"
    );
    assert!(bench.logged().is_empty(), "{:?}", bench.logged());
}

#[test]
fn an_absent_port_fails_before_the_decision_and_a_busy_one_after_it() {
    let bench = Arc::new(Bench::new(&["COM9"], Wiring::Loop, None).unwrap());
    let (listener, url) = listening();
    let (child, settle, heard) = relayed(Arc::clone(&bench), "COM4", "client.py", &listener, &url);
    assert_eq!(next(&heard), Relayed::Reached(Err(Failure::Absent)));
    settle.settle(Err(Refusal::SourceUnavailable {
        capability: hedwig_model::text::Name::try_from("esp32").unwrap(),
        failure: Failure::Absent,
    }));
    assert_eq!(next(&heard), Relayed::Ended);
    assert!(said(child).contains("Traceback"));
    // Another program holds it: served, the open fails and the remote reads
    // the end; nothing was changed on the line.
    let held = bench.hold("COM9");
    let (listener, url) = listening();
    let (child, settle, heard) = relayed(Arc::clone(&bench), "COM9", "client.py", &listener, &url);
    assert_eq!(next(&heard), Relayed::Reached(Ok(())));
    settle.settle(Ok(()));
    assert_eq!(next(&heard), Relayed::Opened(Err(Failure::Busy)));
    assert_eq!(next(&heard), Relayed::Ended);
    assert!(said(child).contains("Traceback"));
    assert_eq!(bench.logged(), Vec::<String>::new());
    drop(held);
}

/// A link that holds every byte for `delay` each way: a remote one round
/// trip of twice that away.
fn far(delay: Duration) -> (TcpListener, String) {
    let (inner, inner_url) = listening();
    let outer = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("rfc2217://127.0.0.1:{}", outer.local_addr().unwrap().port());
    let target = inner_url.trim_start_matches("rfc2217://").to_owned();
    thread::spawn(move || {
        let (client, _) = outer.accept().unwrap();
        let server = TcpStream::connect(target).unwrap();
        for (from, to) in [
            (client.try_clone().unwrap(), server.try_clone().unwrap()),
            (server, client),
        ] {
            thread::spawn(move || delayed(from, to, delay));
        }
    });
    (inner, url)
}

fn delayed(mut from: TcpStream, to: TcpStream, delay: Duration) {
    let (queue, due) = mpsc::channel::<(Instant, Vec<u8>)>();
    let writer = thread::spawn(move || {
        let mut to = to;
        for (at, bytes) in due {
            let now = Instant::now();
            if at > now {
                thread::sleep(at - now);
            }
            if to.write_all(&bytes).is_err() {
                break;
            }
        }
        let _ = to.shutdown(std::net::Shutdown::Write);
    });
    let mut buffer = [0u8; 4096];
    loop {
        match from.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if queue
                    .send((Instant::now() + delay, buffer[..read].to_vec()))
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    drop(queue);
    let _ = writer.join();
}

fn at(logged: &[String], what: &str) -> u128 {
    logged
        .iter()
        .find(|line| line.ends_with(what))
        .and_then(|line| line.split(' ').next())
        .and_then(|millis| millis.parse().ok())
        .unwrap_or_else(|| panic!("{what} in {logged:?}"))
}

#[test]
fn esptool_s_reset_reaches_a_board_one_round_trip_away_in_its_download_mode() {
    // The board's chip leaves reset once EN has been released for ten
    // milliseconds, and the remote is a hundred away.
    let bench = Arc::new(
        Bench::new(
            &["COM9"],
            Wiring::Board {
                settle: Duration::from_millis(10),
            },
            None,
        )
        .unwrap(),
    );
    let (inner, url) = far(Duration::from_millis(50));
    let (child, settle, heard) = relayed(Arc::clone(&bench), "COM9", "reset.py", &inner, &url);
    assert_eq!(next(&heard), Relayed::Reached(Ok(())));
    settle.settle(Ok(()));
    assert_eq!(
        next(&heard),
        Relayed::Opened(Ok(Some(hedwig_model::protocol::Usb {
            vendor: 0x10C4,
            product: 0xEA60
        })))
    );
    let said = said(child);
    assert_eq!(next(&heard), Relayed::Released);
    assert!(said.contains("waiting for download"), "{said}");
    let logged = bench.logged();
    assert!(
        logged.iter().any(|line| line.ends_with("booted download")),
        "{logged:?}"
    );
    assert!(
        !logged.iter().any(|line| line.ends_with("booted normal")),
        "{logged:?}"
    );
    // pyserial waits for each change to be answered, so its changes reach
    // the line a round trip apart, as the first two do; the two that must
    // reach the board together reach it together.
    let lines: Vec<&String> = logged
        .iter()
        .filter(|line| line.contains("dtr ") || line.contains("rts "))
        .collect();
    let times: Vec<u128> = lines
        .iter()
        .map(|line| line.split(' ').next().unwrap().parse().unwrap())
        .collect();
    let words: Vec<&str> = lines
        .iter()
        .map(|line| line.split_once(' ').unwrap().1)
        .collect();
    // EN held low: DTR lowered while RTS stays raised from the opening.
    let reset = words.iter().position(|word| *word == "dtr off").unwrap();
    let raise = reset
        + words[reset..]
            .iter()
            .position(|word| *word == "dtr on")
            .expect("DTR raised");
    assert_eq!(words.get(raise + 1), Some(&"rts off"), "{logged:?}");
    assert!(times[raise + 1] - times[raise] < 20, "{logged:?}");
    // The changes before it each waited a round trip for their answer.
    assert!(times[reset + 1] - times[reset] >= 90, "{logged:?}");
    let _ = at(&logged, "booted download");
}

/// The stand-in board itself, driven directly: the reset leaves it in its
/// download mode where DTR's raise and RTS's fall reach it together, and
/// boots it normally where they reach it the remote's round trip apart, as
/// a relay applying each change on arrival would.
#[test]
fn the_board_boots_normally_where_its_two_lines_change_a_round_trip_apart() {
    use hedwig_core::serial::Signal;
    for (apart, booted) in [(0, "booted download"), (100, "booted normal")] {
        let bench = Bench::new(
            &["COM9"],
            Wiring::Board {
                settle: Duration::from_millis(10),
            },
            None,
        )
        .unwrap();
        let (line, _) = bench.open(&PortName::try_from("COM9").unwrap()).unwrap();
        for (signal, on) in [
            (Signal::Dtr, true),
            (Signal::Rts, true),
            (Signal::Dtr, false),
        ] {
            line.signal(signal, on).unwrap();
        }
        thread::sleep(Duration::from_millis(100));
        line.signal(Signal::Dtr, true).unwrap();
        thread::sleep(Duration::from_millis(apart));
        line.signal(Signal::Rts, false).unwrap();
        thread::sleep(Duration::from_millis(50));
        line.signal(Signal::Dtr, false).unwrap();
        let mut said = [0u8; 256];
        let read = line.read(&mut said).unwrap();
        assert!(read > 0);
        let logged = bench.logged();
        assert!(
            logged.iter().any(|line| line.ends_with(booted)),
            "{apart}: {logged:?}"
        );
    }
}

#[test]
fn a_remote_that_breaks_the_protocol_and_a_port_that_goes_each_end_the_session_saying_why() {
    use hedwig_core::rfc2217::Breach;
    let bench = Arc::new(Bench::new(&["COM9"], Wiring::Loop, None).unwrap());
    // A remote of its own that sends IAC and a byte no Telnet command is.
    for (port, unplug) in [("COM9", false), ("COM9", true)] {
        let (listener, _) = listening();
        let address = listener.local_addr().unwrap();
        let remote = thread::spawn(move || {
            let mut remote = TcpStream::connect(address).unwrap();
            remote.set_read_timeout(Some(WAIT)).unwrap();
            // A port unplugged as soon as it opens can end the session
            // before its greeting is written.
            let mut greeting = [0u8; 12];
            let greeted = remote.read_exact(&mut greeting);
            if !unplug {
                greeted.unwrap();
                remote.write_all(&[255, 0x41]).unwrap();
            }
            let mut rest = Vec::new();
            let _ = remote.read_to_end(&mut rest);
        });
        let (stream, _) = listener.accept().unwrap();
        let (told, heard) = mpsc::channel();
        let shared = Arc::clone(&bench);
        let lines: Arc<dyn Lines> = shared;
        let settle = carry(
            stream,
            Serial {
                port: PortName::try_from(port).unwrap(),
            },
            lines,
            move |relayed| {
                let _ = told.send(relayed);
            },
        );
        assert_eq!(next(&heard), Relayed::Reached(Ok(())));
        settle.settle(Ok(()));
        assert_eq!(next(&heard), Relayed::Opened(Ok(None)));
        if unplug {
            bench.unplug(port);
            assert_eq!(next(&heard), Relayed::Lost(Failure::Absent));
        } else {
            assert_eq!(next(&heard), Relayed::Broke(Breach::Undefined(0x41)));
        }
        assert_eq!(next(&heard), Relayed::Released);
        assert_eq!(next(&heard), Relayed::Ended);
        remote.join().unwrap();
    }
}
