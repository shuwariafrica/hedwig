//! A stand-in for the core that does what a plan tells it, so a supervisor can
//! be shown a core that panics, hangs, faults or will not start.
//!
//! `child script <dir>` reads `<dir>/plan`, one act to a line, and performs
//! the act for this run: the first line the first time it is started in that
//! folder, the second the next, the last for every run after. Each run
//! appends what the supervisor told it of the run before to `<dir>/afters`.
//!
//! `child supervise <dir>` is a supervisor over `child script <dir>`, as a
//! process of its own, for the cases that end one from outside.
//!
//! `child bench-supervise <dir> loop|board` is a supervisor over the core
//! run on the bench's serial port
//! ([`hedwig_support::bench`]).
//!
//! `child serial-ports` prints the workstation's serial ports as the core
//! lists them, one written form to a line, each followed by what a remote's
//! tool cannot do through it where there is something.
//!
//! `child serial-relay <dir> <port>` carries every connection to a loopback
//! port of its own - written to `<dir>/listening` - to that port through the
//! core's own Windows lines, serving each opening at once, and appends what
//! the relay tells to `<dir>/told`: a run against a real port.
//!
//! `child stand-in <dir> <arguments>` stands in for a route's client: it
//! writes what it was given to `<dir>/given` and does what the first line of
//! `<dir>/plan` says, in an OpenSSH client's own words; `carry` makes it a
//! whole route to this workstation as a remote. `child knock <port>`
//! connects to that loopback port and stays.
//!
//! `child device <model>` is a stand-in device a server attaches by `adb
//! connect` ([`hedwig_support::android::Device`]); it prints its port.
//!
//! `child folder` prints the folder a client finds Hedwig's files in.
//!
//! `child survey options` and `child survey command` print, one to a line,
//! what a survey's client is started with and the command the remote runs;
//! `child survey script <nonce> <file> <plan words>` writes the core's POSIX
//! script for that plan to `<file>`; `child survey read <nonce> <report>
//! [<stated>]` prints what the core reads in the report and makes of it, as
//! [`hedwig_support::experiment::account`] says. A run against a real
//! remote drives readiness with these.
//!
//! `child tap <listen> <to> <file>` records every exchange between a client
//! and a server on the loopback ([`hedwig_support::tap`]).
//!
//! `child 'Username for ...'` and `child 'Password for ...'` answer as `git`'s
//! askpass, as a person at the workstation would.
//!
//! `child probe <pipe>` opens the control pipe of that name and greets, and
//! `child halt <dir>` stops the Hedwig in that folder; each ends with the
//! status in [`hedwig_support::met`] for what it met, for a client
//! that was lowered and can write nowhere the suite reads.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::thread;
use std::time::Duration;

use hedwig_client::{OpenError, Session, StopError, look, stop};
use hedwig_core::record::Claim;
use hedwig_core::store::Places;
use hedwig_core::supervise::{Pace, Supervisor, Watch};
use hedwig_model::process::{Exit, Order, Report};
use hedwig_model::text::PipeName;
use hedwig_model::trail::ClientKind;
use hedwig_model::wire::{line, read};
use hedwig_support::met;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os().skip(1);
    let role = arguments.next().and_then(|role| role.into_string().ok());
    let folder = arguments.next().map(PathBuf::from);
    match (role.as_deref(), folder) {
        (Some("script"), Some(folder)) => script(&folder),
        (Some("supervise"), Some(folder)) => supervise(folder),
        (Some(role @ ("bench-supervise" | "bench-core")), Some(folder)) => {
            let wiring = arguments.next().unwrap_or_default();
            bench(role, folder, &wiring.to_string_lossy())
        }
        // `git`'s askpass, as the person would answer it, which `git` runs
        // with its prompt alone: a user name for the first and a password
        // for the second.
        (Some(prompt), None) if prompt.starts_with("Username for ") => {
            println!("suite-user");
            ExitCode::SUCCESS
        }
        (Some(prompt), None) if prompt.starts_with("Password for ") => {
            println!("suite-asked");
            ExitCode::SUCCESS
        }
        (Some("probe"), Some(pipe)) => ExitCode::from(probe(&pipe)),
        (Some("halt"), Some(folder)) => ExitCode::from(halt(&folder)),
        (Some("sleep"), None) => forever(),
        (Some("folder"), None) => match hedwig_client::folder() {
            Ok(folder) => {
                println!("{}", folder.display());
                ExitCode::SUCCESS
            }
            Err(_) => ExitCode::from(met::OTHER),
        },
        (Some("serial-ports"), None) => serial_ports(),
        (Some("serial-relay"), Some(folder)) => match arguments.next() {
            Some(port) => serial_relay(&folder, &port.to_string_lossy()),
            None => ExitCode::from(Exit::Usage.status()),
        },
        (Some("stand-in"), Some(folder)) => stand_in(&folder, arguments),
        (Some("device"), Some(model)) => device(&model.to_string_lossy()),
        (Some("survey"), Some(what)) => survey(&what.to_string_lossy(), arguments),
        // How the core reads a client that ended: `channel ended <status> <last line>`.
        (Some("channel"), Some(what)) if what.as_os_str() == "ended" => {
            let given: Vec<String> = arguments
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect();
            match given.as_slice() {
                [status, last] => match status.parse::<i32>() {
                    Ok(status) => {
                        println!("{}", hedwig_support::experiment::ending(status, last));
                        ExitCode::SUCCESS
                    }
                    Err(_) => ExitCode::from(Exit::Usage.status()),
                },
                _ => ExitCode::from(Exit::Usage.status()),
            }
        }
        (Some("knock"), Some(port)) => knock(&port, arguments.next().map(PathBuf::from)),
        (Some(role @ ("ask" | "attend" | "tap")), Some(first)) => {
            experiment(role, first, arguments)
        }
        // Starts the agent of the GnuPG in `folder` for the home given next,
        // as the relay starts one.
        (Some("launch"), Some(installation)) => {
            let home = arguments
                .next()
                .map(|home| home.to_string_lossy().into_owned());
            let home = home
                .and_then(|home| hedwig_model::text::Folder::try_from(home.as_str()).ok())
                .map_or(
                    hedwig_model::capability::Home::Default,
                    hedwig_model::capability::Home::At,
                );
            let gpgconf = installation.join("bin").join("gpgconf.exe");
            match hedwig_core::relay::launch(&gpgconf, &home, false) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(met::OTHER),
            }
        }
        (Some("echo"), first) => {
            // Its arguments as it was given them, one to a line.
            let rest: Vec<OsString> = first
                .map(PathBuf::into_os_string)
                .into_iter()
                .chain(arguments)
                .collect();
            for argument in rest {
                println!("{}", argument.to_string_lossy());
            }
            ExitCode::SUCCESS
        }
        _ => ExitCode::from(Exit::Usage.status()),
    }
}

/// The roles a script run against a real remote drives: `ask` and `attend`
/// a running Hedwig ([`hedwig_support::control`]), and `tap` an exchange
/// ([`hedwig_support::tap`]).
fn experiment(
    role: &str,
    first: PathBuf,
    mut arguments: impl Iterator<Item = OsString>,
) -> ExitCode {
    let folder = first.clone();
    let listen = first;
    match role {
        // One request to the core in `folder`: `ask <folder> <request>`.
        "ask" => {
            let request = arguments
                .next()
                .map(|request| request.to_string_lossy().into_owned());
            match request.map(|request| hedwig_support::control::ask(&folder, &request)) {
                Some(Ok(reply)) => {
                    println!("{reply}");
                    ExitCode::SUCCESS
                }
                Some(Err(error)) => {
                    eprintln!("{error}");
                    ExitCode::from(met::OTHER)
                }
                None => ExitCode::from(Exit::Usage.status()),
            }
        }
        "attend" => match hedwig_support::control::attend(
            &folder,
            arguments.next().map(PathBuf::from).as_deref(),
        ) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                ExitCode::from(met::OTHER)
            }
        },
        // Records an exchange: `tap <listen> <to> <file>`.
        "tap" => {
            let to = arguments
                .next()
                .and_then(|to| to.to_str()?.parse::<u16>().ok());
            let file = arguments.next().map(PathBuf::from);
            match (
                listen
                    .to_str()
                    .and_then(|listen| listen.parse::<u16>().ok()),
                to,
                file,
            ) {
                (Some(listen), Some(to), Some(file)) => {
                    match hedwig_support::tap::tap(listen, to, &file) {
                        Ok(()) => ExitCode::SUCCESS,
                        Err(_) => ExitCode::from(met::OTHER),
                    }
                }
                _ => ExitCode::from(Exit::Usage.status()),
            }
        }
        _ => ExitCode::from(Exit::Usage.status()),
    }
}

/// Opens the control pipe named by `pipe` as a terminal would.
fn probe(pipe: &Path) -> u8 {
    let Some(Ok(pipe)) = pipe.to_str().map(PipeName::try_from) else {
        return Exit::Usage.status();
    };
    match Session::open(&pipe) {
        Ok(mut session) => match session.greet(ClientKind::Terminal) {
            Ok(Ok(_)) => met::GREETED,
            _ => met::OTHER,
        },
        Err(OpenError::Absent) => met::ABSENT,
        Err(OpenError::Busy) => met::BUSY,
        Err(OpenError::Denied) => met::DENIED,
        Err(OpenError::NotOurs { .. }) => met::NOT_OURS,
        Err(OpenError::Other(_)) => met::OTHER,
    }
}

/// Stops the Hedwig in `folder` as the command stand-in's `stop` does.
fn halt(folder: &Path) -> u8 {
    let Ok(standing) = look(folder) else {
        return met::OTHER;
    };
    match stop(&standing) {
        Ok(true) => met::STOPPED,
        Ok(false) => met::NOTHING_TO_STOP,
        Err(StopError::Above) => met::ABOVE,
        Err(_) => met::NOT_STOPPED,
    }
}

fn survey(what: &str, given: impl Iterator<Item = OsString>) -> ExitCode {
    use hedwig_core::survey::{Dialect, command, options, posix};
    use hedwig_model::setting::Keepalive;
    use hedwig_model::trail::Asking;
    use hedwig_support::experiment::{account, plan};
    let given: Vec<String> = given
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let mut out = io::stdout().lock();
    let printed = match (what, given.as_slice()) {
        ("options", []) => options(Asking::Nobody, Keepalive::SHIPS)
            .iter()
            .try_for_each(|option| writeln!(out, "{option}")),
        ("command", []) => command(Dialect::Posix)
            .iter()
            .try_for_each(|word| writeln!(out, "{word}")),
        ("script", [nonce, file, words @ ..]) => match plan(words) {
            Ok(plan) => fs::write(file, posix(&plan, nonce)),
            Err(unusable) => Err(io::Error::other(unusable)),
        },
        ("read", [nonce, report, stated @ ..]) => {
            let stated = match stated {
                [stated] => fs::read_to_string(stated),
                _ => Ok(String::new()),
            };
            fs::read_to_string(report)
                .and_then(|output| Ok((output, stated?)))
                .and_then(|(output, stated)| {
                    account(&output, nonce, &stated).map_err(io::Error::other)
                })
                .and_then(|lines| lines.iter().try_for_each(|line| writeln!(out, "{line}")))
        }
        _ => return ExitCode::from(Exit::Usage.status()),
    };
    match printed {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(met::OTHER)
        }
    }
}

fn forever() -> ! {
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn say(report: &Report) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{}", line(report));
    let _ = out.flush();
}

fn ready() {
    if let Ok(pipe) = PipeName::try_from("hedwig.00000000000000000000000000000000") {
        say(&Report::Ready { pipe });
    }
}

/// How many runs this folder has seen, recording this one.
fn run_number(folder: &Path, order: Order) -> usize {
    let afters = folder.join("afters");
    let before = fs::read_to_string(&afters).map_or(0, |text| text.lines().count());
    if let Order::Begin { after } = order
        && let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&afters)
    {
        let _ = writeln!(file, "{}", line(&after));
    }
    before
}

#[allow(
    clippy::panic,
    reason = "a core that panics is what one act stands in for"
)]
fn script(folder: &Path) -> ExitCode {
    hedwig_win::process::quieten();
    let mut orders = io::stdin().lock().lines();
    let first = orders.next().and_then(Result::ok);
    let Some(begin) = first.and_then(|written| read::<Order>(&written).ok()) else {
        return ExitCode::from(Exit::Link.status());
    };
    let run = run_number(folder, begin);
    let plan = fs::read_to_string(folder.join("plan")).unwrap_or_default();
    let acts: Vec<&str> = plan.lines().collect();
    let act = acts.get(run).or(acts.last()).copied().unwrap_or("stop");
    match act {
        "stop" => {
            ready();
            ExitCode::from(Exit::Stopped.status())
        }
        "steady" => {
            ready();
            for written in orders {
                match written
                    .ok()
                    .and_then(|written| read::<Order>(&written).ok())
                {
                    Some(Order::Ping) => say(&Report::Pong),
                    Some(Order::Begin { .. }) => {}
                    None => break,
                }
            }
            ExitCode::from(Exit::Link.status())
        }
        "panic" => {
            ready();
            panic!("the stand-in core panicked on cue");
        }
        "hang" => {
            // Something of its own for the supervisor to end with it, and
            // something started as the person's own GnuPG agent is, which
            // asks to leave the job and outlives it.
            let started = again(&["sleep"]).and_then(|child| hedwig_win::process::instance(&child));
            if let Ok((process, created)) = started {
                let _ = fs::write(folder.join("grandchild"), format!("{process} {created}"));
            }
            // As the core does in every role: a process that outlives this
            // one must hold nothing of the supervisor's pipes.
            hedwig_win::process::seal();
            let left = std::env::current_exe().and_then(|program| {
                use std::os::windows::process::CommandExt;
                Command::new(program)
                    .arg("sleep")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .creation_flags(hedwig_win::process::LEAVING)
                    .spawn()
            });
            if let Ok((process, created)) =
                left.and_then(|child| hedwig_win::process::instance(&child))
            {
                let _ = fs::write(folder.join("left"), format!("{process} {created}"));
            }
            ready();
            forever()
        }
        "mute" => forever(),
        "slow" => {
            // Busy, not stuck: the first question is answered late, and the
            // folder is told when it arrived.
            ready();
            for written in orders {
                if let Some(Order::Ping) = written
                    .ok()
                    .and_then(|written| read::<Order>(&written).ok())
                {
                    let _ = fs::write(folder.join("asked"), "");
                    thread::sleep(Duration::from_millis(600));
                    say(&Report::Pong);
                    return ExitCode::from(Exit::Stopped.status());
                }
            }
            ExitCode::from(Exit::Link.status())
        }
        "fault" => {
            ready();
            // SAFETY: there is none. Reading address zero is the fault this
            // act stands in for, and it ends the process.
            let read = unsafe { std::ptr::read_volatile(std::ptr::null::<u8>()) };
            ExitCode::from(read)
        }
        "garble" => {
            println!("not a report");
            forever()
        }
        other => {
            let status = other
                .strip_prefix("exit:")
                .and_then(|status| status.parse::<u8>().ok())
                .unwrap_or(Exit::Usage.status());
            eprintln!("the stand-in core ends with {status}");
            ExitCode::from(status)
        }
    }
}

fn supervise(folder: PathBuf) -> ExitCode {
    hedwig_win::process::seal();
    let announce = hedwig_win::process::take_output();
    let (Ok(places), Ok(program)) = (Places::at(folder.clone()), std::env::current_exe()) else {
        return ExitCode::from(Exit::Storage.status());
    };
    let Ok(claim) = Claim::take(&places) else {
        return ExitCode::from(Exit::AlreadyRunning.status());
    };
    let supervisor = Supervisor {
        program,
        arguments: vec![OsString::from("script"), folder.into_os_string()],
        watch: Watch {
            every: Duration::from_millis(50),
            within: Duration::from_millis(400),
        },
        pace: Pace {
            settled: Duration::from_secs(60),
            first: Duration::from_millis(50),
            longest: Duration::from_millis(200),
        },
        clock: hedwig_win::clock::elapsed,
    };
    ExitCode::from(supervisor.run(claim, announce).status())
}

/// The core on the bench's port COM9, wired as `wiring` says
/// (`loop`, or `board` for a development board's reset circuit), its log in
/// the folder as `bench.log`; or, as `bench-supervise`, a supervisor over it
/// as `hedwig.exe` runs one: a core with a serial port where the
/// workstation has none.
fn bench(role: &str, folder: PathBuf, wiring: &str) -> ExitCode {
    use hedwig_support::bench::{Bench, Wiring};
    let wiring_of = match wiring {
        "loop" => Wiring::Loop,
        "board" => Wiring::Board {
            settle: Duration::from_millis(10),
        },
        _ => return ExitCode::from(Exit::Usage.status()),
    };
    let Ok(places) = Places::at(folder.clone()) else {
        return ExitCode::from(Exit::Storage.status());
    };
    if role == "bench-core" {
        let Ok(bench) = Bench::new(&["COM9"], wiring_of, Some(&folder.join("bench.log"))) else {
            return ExitCode::from(Exit::Storage.status());
        };
        let exit = hedwig_core::run::run_on(
            places,
            env!("CARGO_PKG_VERSION"),
            std::sync::Arc::new(bench),
        );
        return ExitCode::from(exit.status());
    }
    hedwig_win::process::seal();
    let announce = hedwig_win::process::take_output();
    let Ok(program) = std::env::current_exe() else {
        return ExitCode::from(Exit::Usage.status());
    };
    let Ok(claim) = Claim::take(&places) else {
        return ExitCode::from(Exit::AlreadyRunning.status());
    };
    let supervisor = Supervisor {
        program,
        arguments: vec![
            OsString::from("bench-core"),
            folder.into_os_string(),
            OsString::from(wiring),
        ],
        watch: Watch::default(),
        pace: Pace::default(),
        clock: hedwig_win::clock::elapsed,
    };
    ExitCode::from(supervisor.run(claim, announce).status())
}

fn serial_ports() -> ExitCode {
    use hedwig_core::serial::{Lines, Windows};
    for port in Windows.list() {
        println!("{}", line(&port));
        if let Some(beyond) = port.beyond() {
            println!("beyond {}: {beyond}", port.port);
        }
    }
    ExitCode::SUCCESS
}

fn serial_relay(folder: &Path, port: &str) -> ExitCode {
    use hedwig_core::serial::{Serial, Windows, carry};
    use std::sync::{Arc, Mutex};
    let Ok(port) = hedwig_model::text::PortName::try_from(port) else {
        return ExitCode::from(Exit::Usage.status());
    };
    let listening = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| Ok((listener.local_addr()?.port(), listener)));
    let told = OpenOptions::new()
        .create(true)
        .append(true)
        .open(folder.join("told"));
    let (Ok((number, listener)), Ok(told)) = (listening, told) else {
        return ExitCode::from(met::OTHER);
    };
    if fs::write(folder.join("listening"), number.to_string()).is_err() {
        return ExitCode::from(met::OTHER);
    }
    let told = Arc::new(Mutex::new(told));
    for stream in listener.incoming().flatten() {
        let told = Arc::clone(&told);
        let settle = carry(
            stream,
            Serial { port: port.clone() },
            Arc::new(Windows),
            move |relayed| {
                if let Ok(mut file) = told.lock() {
                    let _ = writeln!(file, "{relayed:?}");
                }
            },
        );
        // The deciding thread's part: the person's run serves every opening.
        settle.settle(Ok(()));
    }
    ExitCode::SUCCESS
}

/// Whether this process's console has a window a person could see.
fn shown() -> bool {
    // SAFETY: asks for this process's own console window; none is null.
    let window = unsafe { windows_sys::Win32::System::Console::GetConsoleWindow() };
    // SAFETY: the handle, where there is one, is the window just named.
    !window.is_null()
        && unsafe { windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible(window) } != 0
}

/// Connects to the loopback port as a channel's client does when the remote
/// uses a forward, and stays. Given a folder, it first says there whether a
/// window shows.
fn knock(port: &Path, folder: Option<PathBuf>) -> ExitCode {
    if let Some(folder) = folder {
        let _ = fs::write(folder.join("descendant"), format!("window={}\n", shown()));
    }
    let port = port.to_str().and_then(|port| port.parse::<u16>().ok());
    let Some(Ok(mut stream)) = port.map(|port| TcpStream::connect((Ipv4Addr::LOCALHOST, port)))
    else {
        return ExitCode::from(Exit::Usage.status());
    };
    let _ = stream.write_all(b"x");
    forever()
}

/// One line on standard error, ended as an OpenSSH client ends its own.
fn utter(line: &str) {
    eprint!("{line}\r\n");
}

const FINGERPRINT: &str = "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s";

fn changed() {
    utter("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
    utter("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
    utter("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
    utter("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
    utter("The fingerprint for the ED25519 key sent by the remote host is");
    utter(&format!("{FINGERPRINT}."));
    utter("Please contact your system administrator.");
}

/// What the remote's server answered for one forward, as the client says it
/// when made to.
fn answer(listen: &str, endpoint: u16, bound: bool) {
    let said = if bound { "success" } else { "failure" };
    // As the in-box client marks what it is made to say: the file by the
    // path it was built from, its backslashes doubled.
    let mark = format!(
        r"C:\\__w\\1\\s\\ssh.c:ssh_confirm_remote_forward():1839 (pid={})",
        std::process::id()
    );
    utter(&format!(
        "debug1: {mark}: remote forward {said} for: listen {listen}, connect 127.0.0.1:{endpoint}"
    ));
    if !bound {
        utter(&format!(
            "{mark}: Warning: remote port forwarding failed for listen path {listen}"
        ));
    }
}

/// A stand-in device for a server to attach by `adb connect`: prints the
/// loopback port it listens at and serves until ended.
fn device(model: &str) -> ExitCode {
    let Ok(device) = hedwig_support::android::Device::start(model) else {
        return ExitCode::from(met::OTHER);
    };
    let mut out = io::stdout();
    let _ = writeln!(out, "{}", device.port());
    let _ = out.flush();
    forever()
}

/// Where a carrying stand-in's remote listens: a loopback address of its own,
/// so what it binds never meets what the workstation's side binds at the
/// same port.
const REMOTE_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

/// The stand-in as a whole route to a remote that is this workstation under
/// Git for Windows' shell: `-G` states nothing; a survey's `/bin/sh -s` runs
/// that shell on the script; anything else holds each remote forward for
/// real, listening at [`REMOTE_LOOPBACK`] and carrying every connection on to
/// the workstation's end, and appends `<port> <endpoint>` for each to
/// `<dir>/carried`, the port the one it listens at.
fn carry(folder: &Path, given: &[String], forwards: &[(&str, u16)]) -> ExitCode {
    if given.iter().any(|argument| argument == "-G") {
        return ExitCode::SUCCESS;
    }
    if given.ends_with(&["/bin/sh".to_owned(), "-s".to_owned()]) {
        return shell(folder);
    }
    for (listen, endpoint) in forwards {
        let asked = listen.parse::<u16>().ok();
        let bound = asked.and_then(|port| TcpListener::bind((REMOTE_LOOPBACK, port)).ok());
        let Some(bound) = bound else {
            answer(listen, *endpoint, false);
            continue;
        };
        let port = bound.local_addr().map_or(0, |address| address.port());
        if asked == Some(0) {
            // Marked as the in-box client marks a line of the function the
            // core's `LogVerbose` names.
            utter(&format!(
                r"C:\\__w\\1\\s\\ssh.c:ssh_confirm_remote_forward():1860 (pid={}): Allocated port {port} for remote forward to 127.0.0.1:{endpoint}",
                std::process::id()
            ));
        } else {
            answer(listen, *endpoint, true);
        }
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(folder.join("carried"))
        {
            let _ = writeln!(file, "{port} {endpoint}");
        }
        let endpoint = *endpoint;
        thread::spawn(move || {
            for remote in bound.incoming() {
                let Ok(remote) = remote else { return };
                thread::spawn(move || {
                    if let Ok(near) = TcpStream::connect((Ipv4Addr::LOCALHOST, endpoint)) {
                        splice(&remote, &near);
                    }
                });
            }
        });
    }
    forever()
}

/// Copies both ways until each end has closed.
fn splice(one: &TcpStream, other: &TcpStream) {
    let (Ok(mut one_from), Ok(mut other_to), Ok(mut other_from), Ok(mut one_to)) = (
        one.try_clone(),
        other.try_clone(),
        other.try_clone(),
        one.try_clone(),
    ) else {
        return;
    };
    let back = thread::spawn(move || {
        let _ = io::copy(&mut other_from, &mut one_to);
        let _ = one_to.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut one_from, &mut other_to);
    let _ = other_to.shutdown(Shutdown::Write);
    let _ = back.join();
}

/// Runs Git for Windows' shell on what arrives on standard input, in a home
/// of the folder's and with only the shell's own tools, Git's and Windows'
/// on its search path, as a remote user's login would.
fn shell(folder: &Path) -> ExitCode {
    let home = folder.join("home");
    let _ = fs::create_dir_all(&home);
    let msys = |path: &Path| {
        let text = path.to_string_lossy().replace('\\', "/");
        match text.split_once(':') {
            Some((drive, rest)) => format!("/{}{rest}", drive.to_ascii_lowercase()),
            None => text,
        }
    };
    let status = Command::new(r"C:\Program Files\Git\usr\bin\sh.exe")
        .arg("-s")
        .env_clear()
        .env("PATH", "/usr/bin:/mingw64/bin:/c/Windows/System32")
        .env("HOME", msys(&home))
        .env("SHELL", "/usr/bin/bash")
        .env("SYSTEMROOT", r"C:\Windows")
        .status();
    match status.ok().and_then(|status| status.code()) {
        Some(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        None => ExitCode::from(1),
    }
}

/// Starts this program again, as something the stand-in starts for itself.
fn again(arguments: &[&str]) -> io::Result<std::process::Child> {
    Command::new(std::env::current_exe()?)
        .args(arguments)
        .spawn()
}

/// What the stand-in was started with: its number, whether a window shows,
/// the variables a prompt would be raised through, and its arguments.
fn account(given: &[String]) -> String {
    let mut account = format!("process={}\nwindow={}\n", std::process::id(), shown());
    for name in [
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "DISPLAY",
        "HEDWIG_PIPE",
    ] {
        let value = std::env::var(name).unwrap_or_else(|_| "<unset>".to_owned());
        account = format!("{account}{name}={value}\n");
    }
    for argument in given {
        account = format!("{account}argument={argument}\n");
    }
    account
}

fn stand_in(folder: &Path, given: impl Iterator<Item = OsString>) -> ExitCode {
    let given: Vec<String> = given
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect();
    let _ = fs::write(folder.join("given"), account(&given));
    let forwards: Vec<(&str, u16)> = given
        .windows(2)
        .filter_map(|pair| match pair {
            [flag, forward] if flag == "-R" => {
                let (listen, endpoint) = forward.rsplit_once(":127.0.0.1:")?;
                Some((listen, endpoint.parse().ok()?))
            }
            _ => None,
        })
        .collect();
    let answers = |bound: &dyn Fn(usize) -> bool| {
        for (index, (listen, endpoint)) in forwards.iter().enumerate() {
            answer(listen, *endpoint, bound(index));
        }
    };
    let plan = fs::read_to_string(folder.join("plan")).unwrap_or_default();
    match plan.lines().next().unwrap_or("idle") {
        "up" => {
            answers(&|_| true);
            forever()
        }
        "refuse-first" => {
            answers(&|index| index != 0);
            forever()
        }
        "refuse-all" => {
            answers(&|_| false);
            forever()
        }
        "changed" => {
            changed();
            utter("Host key verification failed.");
            ExitCode::from(255)
        }
        "changed-lenient" => {
            changed();
            utter("Port forwarding is disabled to avoid man-in-the-middle attacks.");
            forever()
        }
        "unknown" => {
            utter("Host key verification failed.");
            ExitCode::from(255)
        }
        "denied" => {
            utter("dev@build-7.example: Permission denied (publickey).");
            ExitCode::from(255)
        }
        "linger" => {
            // Something of its own that outlives it and holds what it holds.
            let started = again(&["sleep"]).and_then(|child| hedwig_win::process::instance(&child));
            if let Ok((process, created)) = started {
                let _ = fs::write(folder.join("grandchild"), format!("{process} {created}"));
            }
            utter("Connection to build-7.example closed by remote host.");
            ExitCode::from(255)
        }
        "knock" => {
            answers(&|_| true);
            let held: Vec<TcpStream> = forwards
                .iter()
                .filter_map(|(_, endpoint)| {
                    TcpStream::connect((Ipv4Addr::LOCALHOST, *endpoint)).ok()
                })
                .collect();
            let _ = fs::write(folder.join("knocked"), held.len().to_string());
            forever()
        }
        "descend" => {
            answers(&|_| true);
            if let (Some((_, endpoint)), Some(folder)) = (forwards.first(), folder.to_str()) {
                let _ = again(&["knock", &endpoint.to_string(), folder]);
            }
            forever()
        }
        "carry" => carry(folder, &given, &forwards),
        "idle" => forever(),
        other if other.starts_with("probe:") => {
            // A program of the channel's that opens the control pipe, as a
            // prompt's helper would.
            let _ = again(&["probe", other.trim_start_matches("probe:")]);
            forever()
        }
        other => {
            let status = other
                .strip_prefix("exit:")
                .and_then(|status| status.parse::<u8>().ok())
                .unwrap_or(Exit::Usage.status());
            ExitCode::from(status)
        }
    }
}
