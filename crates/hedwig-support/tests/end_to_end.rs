//! The processes themselves: the executable started on demand, its core
//! found and spoken to over the real pipe, one Hedwig to a person, a core
//! ended by force and started again, and clients at another integrity level.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_client::{
    LaunchError, OpenError, Session, SessionError, Standing, launch, look, released_within, stop,
};
use hedwig_core::record::{Claim, ClaimError};
use hedwig_core::store::Places;
use hedwig_model::config::{Catalogue, Change, Configuration, Effect};
use hedwig_model::install::{AtSignIn, Names, Starts};
use hedwig_model::process::{CoreState, Diagnostic, Exit, Instance, Running};
use hedwig_model::protocol::{Attention, Bundle, Needs, Notice, Reply, Request, Status};
use hedwig_model::remote::Remotes;
use hedwig_model::setting::{Autostart, Volume};
use hedwig_model::text::PipeName;
use hedwig_model::trail::{
    Breakdown, ClientKind, Entry, Event, FORM, Form, Integrity, Origin, State, Timestamp,
};
use hedwig_model::wire::{line, page, read, read_stored};
use hedwig_support::Folder;
use hedwig_support::lower::{Level, Lowered, as_restricted};
use hedwig_support::met;
use hedwig_win::Signal;
use hedwig_win::pipe::{Listener, Moved};
use hedwig_win::registry::{RUN, own, remove_value};
use hedwig_win::token::{Sid, Token};

/// An executable built beside the suite's own.
fn built(name: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_child")).with_file_name(name);
    assert!(
        path.exists(),
        "{} is built with the workspace",
        path.display()
    );
    path
}

/// The command-line stand-in, `word --folder <folder>`.
fn command_line(folder: &Path, word: &str) -> (i32, Vec<String>, String) {
    run(Path::new(env!("CARGO_BIN_EXE_command")), folder, word)
}

fn run(program: &Path, folder: &Path, word: &str) -> (i32, Vec<String>, String) {
    let output = Command::new(program)
        .arg(word)
        .arg("--folder")
        .arg(folder)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let lines = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let errors = String::from_utf8(output.stderr).unwrap();
    (output.status.code().unwrap(), lines, errors)
}

/// Takes back the `Run` values of a Hedwig keyed by a folder of the suite's
/// own whatever the test did: the core writes them where it is told to.
struct Taken(Names);

impl Drop for Taken {
    fn drop(&mut self) {
        for starts in Starts::ALL {
            let _ = remove_value(RUN, &self.0.run_value(starts));
        }
    }
}

/// Whether `holds` comes true within `within`.
fn within(within: Duration, mut holds: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if holds() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    holds()
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

/// Waits for the record to satisfy `wanted`.
fn until(folder: &Path, wanted: impl Fn(&Standing) -> bool) -> Standing {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let standing = look(folder).unwrap();
        if wanted(&standing) {
            return standing;
        }
        assert!(Instant::now() < deadline, "{standing:?}");
        thread::sleep(Duration::from_millis(5));
    }
}

fn serving(standing: &Standing) -> Option<(PipeName, u32, Instance)> {
    match standing {
        Standing::Known(Running {
            supervisor,
            core: CoreState::Serving { pipe, process },
        }) => Some((pipe.clone(), *process, *supervisor)),
        _ => None,
    }
}

/// The trail's entries, after the line naming the form it is written in and
/// its head.
fn trail(folder: &Path) -> Vec<Entry> {
    let written = fs::read_to_string(folder.join("trail.jsonl")).unwrap();
    let mut lines = written.lines();
    let form = read::<Form>(lines.next().unwrap()).unwrap();
    assert_eq!(form.trail, FORM);
    read_stored::<State>(lines.next().unwrap()).unwrap();
    lines.map(|line| read::<Entry>(line).unwrap()).collect()
}

/// Ends the Hedwig in `folder` and waits until its supervisor is gone.
fn stopped(folder: &Path) {
    stop(&look(folder).unwrap()).unwrap();
    assert!(released_within(folder, Duration::from_secs(30)));
    assert_eq!(look(folder).unwrap(), Standing::Absent);
}

/// A person in a terminal with no Hedwig running: one command starts it, and the
/// core is found from its record and spoken to over its pipe. What the core
/// read of the client is what the client is; a change is on disk before the
/// client is told it was made; and one act stops it all.
#[test]
#[allow(clippy::too_many_lines, reason = "one workflow, start to stop")]
fn a_person_starts_hedwig_from_a_terminal_talks_to_it_and_stops_it() {
    let folder = Folder::new("start");
    let (status, lines, errors) = command_line(folder.path(), "start");
    assert_eq!((status, errors.as_str()), (0, ""), "{lines:?}");
    let announced: Running = read(lines.first().unwrap()).unwrap();
    let tether = lines.get(1).unwrap();
    println!(
        "started from this session: {tether}, in a job: {}",
        hedwig_win::process::in_a_job().unwrap()
    );
    assert!(["Free", "Tied"].contains(&tether.as_str()));

    let standing = look(folder.path()).unwrap();
    assert_eq!(standing, Standing::Known(announced));
    let (pipe, core, supervisor) = serving(&standing).unwrap();

    let mut session = Session::open(&pipe).unwrap();
    let you = session.greet(ClientKind::Terminal).unwrap().unwrap();
    assert_eq!(you, own_origin(), "read from the pipe, not claimed");
    let Ok(Reply::Status(Status {
        origin, attached, ..
    })) = session.ask(Request::Status).unwrap()
    else {
        panic!("a status");
    };
    assert_eq!(origin.process, core);
    assert_eq!(
        attached
            .iter()
            .map(|client| (client.kind, client.origin))
            .collect::<Vec<_>>(),
        [(ClientKind::Terminal, you)]
    );

    assert_eq!(
        session.ask(Request::Follow { after: None }).unwrap(),
        Ok(Reply::Done(Effect::Changed))
    );
    let on = Change::Autostart(Some(Autostart::AtLogon));
    assert_eq!(
        session.ask(Request::Change(on.clone())).unwrap(),
        Ok(Reply::Changed {
            effect: Effect::Changed,
            held: Vec::new()
        })
    );
    // Told it is done, it is on disk: the entry and the document.
    let mut expected = Configuration::default();
    let catalogue = Catalogue::shipped().unwrap();
    expected.apply(&catalogue, on.clone()).unwrap();
    assert_eq!(
        fs::read_to_string(folder.path().join("configuration.json")).unwrap(),
        page(&expected.export())
    );
    let Notice::Recorded(entry) = session.notice().unwrap() else {
        panic!("the entry it follows");
    };
    assert!(matches!(&entry.event, Event::Changed { change, .. } if *change == on));
    // What keeping the `Run` values found is recorded as the keeping
    // thread answers, whenever that falls among the client's own entries.
    let (found, events): (Vec<Event>, Vec<Event>) = trail(folder.path())
        .into_iter()
        .map(|entry| entry.event)
        .partition(|event| matches!(event, Event::Startup { .. }));
    assert!(matches!(
        events.as_slice(),
        [
            Event::Started { after: None, origin: started, .. },
            Event::Attached { kind: ClientKind::Terminal, origin: attached, attends: Remotes::Every },
            Event::Changed { .. },
        ] if started.process == core && *attached == you
    ));
    assert!(
        found.contains(&Event::Startup {
            starts: Starts::Hedwig,
            found: AtSignIn::AsChosen,
        }),
        "{found:?}"
    );

    // The person's choice is what Windows starts at sign-in: the core writes
    // the value naming its own program and folder, and takes it back once the
    // choice goes.
    let names = Names::keyed(&folder.path().to_string_lossy());
    let _taken = Taken(names.clone());
    let value = names.run_value(Starts::Hedwig);
    let program = built("hedwig.exe");
    let command = names.run_command(program.parent().unwrap().to_str().unwrap(), Starts::Hedwig);
    assert!(within(Duration::from_secs(10), || {
        own(RUN, &value).unwrap().as_deref() == Some(OsStr::new(&command))
    }));
    assert_eq!(own(RUN, &names.run_value(Starts::Icon)).unwrap(), None);
    let gone = Change::Autostart(None);
    assert!(matches!(
        session.ask(Request::Change(gone)).unwrap(),
        Ok(Reply::Changed { .. })
    ));
    assert!(within(Duration::from_secs(10), || own(RUN, &value)
        .unwrap()
        .is_none()));
    let Notice::Recorded(_) = session.notice().unwrap() else {
        panic!("the entry it follows");
    };

    // The interface attaches to the same core as any other client does.
    let interface = Command::new(env!("CARGO_BIN_EXE_interface"))
        .arg(folder.path())
        .output()
        .unwrap();
    assert!(interface.status.success());
    let seen: Origin = read(
        String::from_utf8(interface.stdout)
            .unwrap()
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    assert_eq!((seen.logon, seen.session), (you.logon, you.session));
    assert!(trail(folder.path()).iter().any(|entry| matches!(
        entry.event,
        Event::Attached {
            kind: ClientKind::Interface,
            ..
        }
    )));

    let (status, lines, _) = command_line(folder.path(), "stop");
    assert_eq!(
        (status, lines.as_slice()),
        (0, ["stopped".to_owned()].as_slice())
    );
    assert!(hedwig_support::ended_within(
        supervisor.process,
        supervisor.created,
        Duration::from_secs(30)
    ));
    assert_eq!(look(folder.path()).unwrap(), Standing::Absent);
    // The record stays, saying what its supervisor last said, and is
    // nobody's: nothing is running.
    assert!(folder.path().join("running.json").exists());
    assert!(matches!(
        trail(folder.path()).last().unwrap().event,
        Event::Stopping { .. }
    ));
    assert!(matches!(
        session.ask(Request::Status),
        Err(SessionError::Closed)
    ));
    let (_, lines, _) = command_line(folder.path(), "stop");
    assert_eq!(lines, ["not running"]);
}

/// One Hedwig to a person. A second start is refused while the
/// first runs, by the record the first holds, and says so.
#[test]
fn a_second_hedwig_for_the_same_person_is_refused() {
    let folder = Folder::new("second");
    let (status, _, _) = command_line(folder.path(), "start");
    assert_eq!(status, 0);
    let first = look(folder.path()).unwrap();

    let program = built("hedwig.exe");
    let arguments = ["supervise", "--folder"].map(OsString::from).into_iter();
    let arguments: Vec<OsString> = arguments.chain([folder.path().into()]).collect();
    let second = launch(&program, &arguments).unwrap_err();
    assert!(matches!(
        second,
        LaunchError::Silent(Some(Exit::AlreadyRunning))
    ));
    assert_eq!(second.to_string(), "Hedwig is already running for you");
    let places = Places::at(folder.path().to_path_buf()).unwrap();
    assert!(matches!(Claim::take(&places), Err(ClaimError::Held)));
    assert_eq!(
        look(folder.path()).unwrap(),
        first,
        "the first is untouched"
    );
    stopped(folder.path());
}

/// A core ended by force is started again without anyone noticing it
/// was gone. What was live went with it; what the person had paused stays
/// paused; and the next person to look is told it happened.
#[test]
fn a_core_ended_by_force_is_started_again_and_says_so() {
    let folder = Folder::new("restart");
    assert_eq!(command_line(folder.path(), "start").0, 0);
    let (pipe, core, supervisor) = serving(&look(folder.path()).unwrap()).unwrap();
    let mut session = Session::open(&pipe).unwrap();
    session.greet(ClientKind::Terminal).unwrap().unwrap();
    assert_eq!(
        session.ask(Request::Pause(Remotes::Every)).unwrap(),
        Ok(Reply::Done(Effect::Changed))
    );

    let killed = Command::new("taskkill")
        .args(["/F", "/PID", &core.to_string()])
        .output()
        .unwrap();
    assert!(killed.status.success());
    let standing = until(folder.path(), |standing| {
        serving(standing).is_some_and(|(_, process, _)| process != core)
    });
    let (next_pipe, _, same_supervisor) = serving(&standing).unwrap();
    assert_ne!(next_pipe, pipe, "a new run, a new name");
    assert_eq!(same_supervisor, supervisor);

    let mut session = Session::open(&next_pipe).unwrap();
    session.greet(ClientKind::Interface).unwrap().unwrap();
    let Ok(Reply::Status(status)) = session.ask(Request::Status).unwrap() else {
        panic!("a status");
    };
    assert_eq!(status.paused, [Remotes::Every]);
    assert_eq!(
        status.attached.len(),
        1,
        "the terminal went with the old run"
    );
    let cause = Breakdown::Exited { status: 1 };
    assert_eq!(
        session.ask(Request::Attention).unwrap(),
        Ok(Reply::Attention(vec![Needs {
            attention: Attention::Restarted { cause, times: 1 },
            volume: Volume::Announced,
        }]))
    );
    assert!(trail(folder.path()).iter().any(|entry| matches!(
        entry.event,
        Event::Started { after: Some(after), .. } if after == cause
    )));
    drop(session);
    stopped(folder.path());
}

/// A person's terminal over SSH runs at high integrity and their desktop at
/// medium; as near as one session gets to that, a client at one level is served
/// by a core at the other, in both directions, and the core records each as
/// what it is. The levels seen are printed; in a session that is itself at
/// medium both are medium, and the case is the same-level one.
#[test]
fn a_client_at_another_integrity_level_is_served_and_recorded_as_it_is() {
    let own = own_origin();
    let hedwig_exe = built("hedwig.exe");
    let command_exe = Path::new(env!("CARGO_BIN_EXE_command"));
    let shell = std::env::var_os("ComSpec").unwrap();

    // A core at this session's level, and a terminal below it.
    let above = Folder::new("core-above");
    assert_eq!(command_line(above.path(), "start").0, 0);
    let out = above.path().join("hello.txt");
    let line = format!(
        "\"{}\" /c \"\"{}\" hello --folder \"{}\" > \"{}\"\"",
        Path::new(&shell).display(),
        command_exe.display(),
        above.path().display(),
        out.display()
    );
    let lowered = Lowered::start(&line).unwrap();
    assert_eq!(lowered.wait(Duration::from_secs(60)), Some(0));
    let said = fs::read_to_string(&out).unwrap();
    let mut said = said.lines().skip(1);
    let you: Origin = read(said.next().unwrap()).unwrap();
    let status: Status = read(said.next().unwrap()).unwrap();
    assert_eq!(you.integrity, Integrity::Medium);
    assert_eq!(status.origin.integrity, own.integrity);
    assert_eq!((you.logon, you.session), (own.logon, own.session));
    assert!(trail(above.path()).iter().any(|entry| matches!(
        entry.event,
        Event::Attached { kind: ClientKind::Terminal, origin, .. } if origin == you
    )));
    println!(
        "a core at {:?} served a terminal at {:?}",
        own.integrity, you.integrity
    );
    stopped(above.path());

    // A core below, as the desktop's is, and this session's client above it:
    // the case in which v0.1.0 refused forty clients of forty.
    let below = Folder::new("core-below");
    let line = format!(
        "\"{}\" supervise --folder \"{}\"",
        hedwig_exe.display(),
        below.path().display()
    );
    let supervisor = Lowered::start(&line).unwrap();
    let standing = until(below.path(), |standing| serving(standing).is_some());
    let (pipe, _, _) = serving(&standing).unwrap();
    let mut session = Session::open(&pipe).unwrap();
    let you = session.greet(ClientKind::Terminal).unwrap().unwrap();
    assert_eq!(you, own);
    let Ok(Reply::Status(status)) = session.ask(Request::Status).unwrap() else {
        panic!("a status");
    };
    assert_eq!(status.origin.integrity, Integrity::Medium);
    println!(
        "a core at {:?} served a terminal at {:?}",
        status.origin.integrity, you.integrity
    );
    // The files a core at one level made are the files a core at the other
    // goes on with.
    assert!(trail(below.path()).len() >= 2);
    drop(session);
    stopped(below.path());
    assert!(supervisor.wait(Duration::from_secs(30)).is_some());
    let places = Places::at(below.path().to_path_buf()).unwrap();
    Claim::take(&places).unwrap();
}

/// Who is a client is decided by the pipe alone: its access list names the
/// person's account and its label admits medium integrity and above. The
/// person's own process below medium is refused, and so is one under a token
/// restricted to less than their account. The core adds no check of its own
/// and refuses nobody it is shown.
#[test]
fn the_pipe_admits_the_person_and_nothing_less() {
    let folder = Folder::new("admits");
    assert_eq!(command_line(folder.path(), "start").0, 0);
    let (pipe, _, _) = serving(&look(folder.path()).unwrap()).unwrap();
    let line = format!(
        "\"{}\" probe {}",
        built("child.exe").display(),
        pipe.as_str()
    );
    let met_by = |lowered: Lowered| {
        let status = lowered.wait(Duration::from_secs(60)).unwrap();
        u8::try_from(status).unwrap_or_else(|_| panic!("it ended with {status:#x}"))
    };
    let attached = || {
        trail(folder.path())
            .iter()
            .filter(|entry| matches!(entry.event, Event::Attached { .. }))
            .count()
    };
    assert_eq!(
        met_by(Lowered::at(Level::Medium, &line).unwrap()),
        met::GREETED
    );
    assert_eq!(attached(), 1);
    assert_eq!(met_by(Lowered::at(Level::Low, &line).unwrap()), met::DENIED);

    // Restricted code, everyone and users.
    let bare = ["S-1-5-12", "S-1-1-0", "S-1-5-32-545"];
    let greeted = as_restricted(&bare, || {
        Session::open(&pipe).map(|mut session| session.greet(ClientKind::Terminal))
    })
    .unwrap();
    assert!(matches!(greeted, Err(OpenError::Denied)));
    assert_eq!(attached(), 1, "neither reached the core");
    stopped(folder.path());
}

/// A token restricted to a set that keeps the person's account is the
/// person, as it is for their own files. Only at medium integrity: an
/// elevated administrator's own process and token are open to Administrators
/// and SYSTEM, not to the account, so a client restricted to it cannot read
/// its own token.
#[test]
#[ignore = "needs a session at medium integrity"]
fn a_token_restricted_to_a_set_that_keeps_the_persons_account_is_the_person() {
    assert_eq!(
        own_origin().integrity,
        Integrity::Medium,
        "needs a session at medium integrity"
    );
    let folder = Folder::new("restricted");
    assert_eq!(command_line(folder.path(), "start").0, 0);
    let (pipe, _, _) = serving(&look(folder.path()).unwrap()).unwrap();
    let me = Token::own().unwrap().user().unwrap().to_text().unwrap();
    let with_me = [me.as_str(), "S-1-5-12", "S-1-1-0", "S-1-5-32-545"];
    let you = as_restricted(&with_me, || {
        Session::open(&pipe).map(|mut session| session.greet(ClientKind::Terminal))
    })
    .unwrap()
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(
        (you.process, you.integrity),
        (std::process::id(), Integrity::Medium)
    );
    let attached = trail(folder.path())
        .iter()
        .filter(|entry| matches!(entry.event, Event::Attached { .. }))
        .count();
    assert_eq!(attached, 1);
    stopped(folder.path());
}

/// A Hedwig whose cores keep breaking down is stopped by ending its
/// supervisor. Whether the person's own process at low integrity may do
/// that is Windows' to say, and what it says is printed: the client reports
/// either that it stopped Hedwig or that the supervisor is above it, and
/// never anything else.
#[test]
fn what_a_process_below_the_supervisor_can_stop_is_windows_to_say() {
    let folder = Folder::new("below");
    fs::write(folder.path().join("plan"), "exit:9\n").unwrap();
    let mut supervisor = Command::new(built("child.exe"))
        .arg("supervise")
        .arg(folder.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    until(folder.path(), |standing| {
        matches!(
            standing,
            Standing::Known(Running {
                core: CoreState::Restarting { .. },
                ..
            })
        )
    });
    let line = format!(
        "\"{}\" halt \"{}\"",
        built("child.exe").display(),
        folder.path().display()
    );
    let low = Lowered::at(Level::Low, &line).unwrap();
    let status = low.wait(Duration::from_secs(60)).unwrap();
    let status = u8::try_from(status).unwrap_or(u8::MAX);
    println!(
        "a process at low integrity asked to end a supervisor at {:?}: {}",
        own_origin().integrity,
        match status {
            met::STOPPED => "it was ended",
            met::ABOVE => "Windows refused",
            _ => "something else",
        }
    );
    assert!([met::STOPPED, met::ABOVE].contains(&status), "{status}");
    if status == met::ABOVE {
        assert!(matches!(look(folder.path()).unwrap(), Standing::Known(_)));
        assert!(stop(&look(folder.path()).unwrap()).unwrap());
    }
    supervisor.wait().unwrap();
    assert_eq!(look(folder.path()).unwrap(), Standing::Absent);
}

/// "Stopped by one act" holds when no core answers. A Hedwig whose cores keep
/// breaking down is stopped by ending its supervisor, which the record names.
#[test]
fn a_hedwig_whose_cores_keep_breaking_down_is_still_stopped_by_one_act() {
    let folder = Folder::new("loop");
    fs::write(folder.path().join("plan"), "exit:9\n").unwrap();
    let mut supervisor = Command::new(built("child.exe"))
        .arg("supervise")
        .arg(folder.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let broken = |standing: &Standing| {
        matches!(
            standing,
            Standing::Known(Running {
                core: CoreState::Restarting { .. },
                ..
            })
        )
    };
    let standing = until(folder.path(), broken);
    assert!(matches!(
        &standing,
        Standing::Known(Running {
            core: CoreState::Restarting {
                cause: Breakdown::Exited { status: 9 },
                said
            },
            ..
        }) if said == "the stand-in core ends with 9"
    ));

    assert!(stop(&look(folder.path()).unwrap()).unwrap());
    assert_eq!(
        supervisor.wait().unwrap().code(),
        Some(i32::from(Exit::Stopped.status()))
    );
    assert_eq!(look(folder.path()).unwrap(), Standing::Absent);
    assert!(!stop(&Standing::Absent).unwrap());
    assert!(!stop(&Standing::Unsettled).unwrap());
}

/// What a client finds when there is no core, a record nobody holds, or a
/// pipe that is not the person's.
#[test]
fn a_client_tells_no_hedwig_from_a_stale_record_from_a_pipe_that_is_not_theirs() {
    let folder = Folder::new("look");
    let places = Places::at(folder.path().to_path_buf()).unwrap();
    assert_eq!(look(folder.path()).unwrap(), Standing::Absent);
    // A supervisor that has the record and has not written it yet.
    let mut claim = Claim::take(&places).unwrap();
    assert_eq!(look(folder.path()).unwrap(), Standing::Unsettled);
    // What it writes is believed for as long as it holds the record.
    let name = "hedwig.00000000000000000000000000000000";
    let pipe = PipeName::try_from(name).unwrap();
    let written = claim
        .write(CoreState::Serving {
            pipe: pipe.clone(),
            process: 1,
        })
        .unwrap();
    assert_eq!(look(folder.path()).unwrap(), Standing::Known(written));
    assert!(!released_within(folder.path(), Duration::from_millis(50)));
    // The supervisor ends, however it ends. Its record stays and says what
    // it said; nothing holds it, so nothing is running.
    drop(claim);
    assert!(folder.path().join("running.json").exists());
    assert_eq!(look(folder.path()).unwrap(), Standing::Absent);
    assert!(released_within(folder.path(), Duration::ZERO));

    assert!(matches!(Session::open(&pipe), Err(OpenError::Absent)));

    // A pipe under Hedwig's name that speaks something else.
    let me = Token::own().unwrap().user().unwrap();
    let (_listener, server) = Listener::bind(&pipe.to_path(), &me).unwrap();
    let junk = thread::spawn(move || {
        let never = Signal::new().unwrap();
        server.accept(&never).unwrap();
        let mut buffer = [0u8; 256];
        server.read(&mut buffer, None).unwrap();
        server.write(b"junk\n", None).unwrap();
        // Until the client has gone.
        server.read(&mut buffer, None).unwrap()
    });
    let mut session = Session::open(&pipe).unwrap();
    let greeted = session.greet(ClientKind::Command).unwrap_err();
    assert!(matches!(greeted, SessionError::Garbled(_)), "{greeted}");
    drop(session);
    assert_eq!(junk.join().unwrap(), Moved::Closed);
}

/// A squatter's pipe admits its victim and is owned by the squatter. The
/// client looks at the owner before it writes a byte, and writes none.
/// Another account cannot be had here; a pipe owned by the Administrators
/// group stands in for one, which an elevated session can make and no other
/// can.
#[test]
#[ignore = "needs an elevated session"]
fn a_pipe_that_belongs_to_someone_else_is_sent_nothing() {
    let administrators = Sid::from_text("S-1-5-32-544").unwrap();
    let mut drawn = [0u8; 16];
    hedwig_win::random::fill(&mut drawn).unwrap();
    let name = format!("hedwig.{:032x}", u128::from_le_bytes(drawn));
    let name = PipeName::try_from(name.as_str()).unwrap();
    let (_listener, server) = Listener::bind(&name.to_path(), &administrators).expect(
        "needs an elevated session: only one can make a pipe the Administrators group owns",
    );
    let squatter = thread::spawn(move || {
        let never = Signal::new().unwrap();
        server.accept(&never).unwrap();
        let mut buffer = [0u8; 256];
        server.read(&mut buffer, None).unwrap()
    });
    let refused = Session::open(&name).err().unwrap();
    assert!(matches!(&refused, OpenError::NotOurs { owner } if owner == "S-1-5-32-544"));
    assert_eq!(
        refused.to_string(),
        "the pipe under Hedwig's name belongs to S-1-5-32-544, not to you; nothing was sent to it"
    );
    assert_eq!(squatter.join().unwrap(), Moved::Closed, "it read nothing");
}

/// A command that starts Hedwig is run by something: a shell, an SSH
/// session, a script. What that something holds open, the command holds too,
/// and the supervisor it starts must not: it would keep a pipe of the
/// session's open for as long as Hedwig runs, and whoever reads that pipe
/// would wait that long.
#[test]
fn a_started_hedwig_holds_nothing_of_what_started_it() {
    let folder = Folder::new("handles");
    let (mut reads, writes) = std::io::pipe().unwrap();
    hedwig_support::inheritable(&writes).unwrap();
    // `hedwig start` inherits the writing end along with everything else
    // this process lets its children have.
    assert_eq!(command_line(folder.path(), "start").0, 0);
    drop(writes);
    assert!(serving(&look(folder.path()).unwrap()).is_some());

    // With this process's own end closed, the pipe ends at once unless
    // something Hedwig started still holds it.
    let (done, waited) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut rest = Vec::new();
        let read = std::io::Read::read_to_end(&mut reads, &mut rest);
        let _ = done.send(read.map(|_| rest));
    });
    let rest = waited.recv_timeout(Duration::from_secs(10));
    stopped(folder.path());
    assert_eq!(
        rest.unwrap().unwrap(),
        b"",
        "the pipe ended while Hedwig ran"
    );
}

/// A process started apart is given exactly the arguments it was started
/// with, whatever they contain.
#[test]
fn a_process_started_apart_is_given_its_arguments_as_they_are() {
    let arguments = [
        "plain",
        "with space",
        "",
        "a\"quote",
        "ends with a backslash\\",
        "back\\slash\\\"then quote",
        "C:\\Program Files\\hedwig\\",
        "--folder",
        "tab\there",
    ];
    let mut given = vec![OsString::from("echo")];
    given.extend(arguments.map(OsString::from));
    let started =
        hedwig_win::start::apart(&built("child.exe"), &given, hedwig_win::process::DETACHED)
            .unwrap();
    let mut said = String::new();
    std::io::Read::read_to_string(&mut &started.said, &mut said).unwrap();
    assert_eq!(started.wait().unwrap(), 0);
    assert_eq!(said.lines().collect::<Vec<_>>(), arguments);
}

/// Each way a start can fail says which.
#[test]
fn a_start_that_fails_says_how() {
    let folder = Folder::new("launch");
    let missing = launch(&folder.path().join("no-such.exe"), &[]).unwrap_err();
    assert!(matches!(missing, LaunchError::Spawn(_)));
    assert!(
        missing
            .to_string()
            .starts_with("Hedwig could not be started: ")
    );

    let silent = launch(&built("child.exe"), &[OsString::from("nonsense")]).unwrap_err();
    assert!(matches!(silent, LaunchError::Silent(Some(Exit::Usage))));
    assert_eq!(silent.to_string(), "Hedwig ended as soon as it was started");

    let shell = PathBuf::from(std::env::var_os("ComSpec").unwrap());
    let garbled = launch(&shell, &["/c", "echo", "hello"].map(OsString::from)).unwrap_err();
    assert!(matches!(garbled, LaunchError::Garbled(_)), "{garbled}");

    // A folder that cannot be used ends the supervisor with that status.
    let file = folder.path().join("a-file");
    fs::write(&file, "").unwrap();
    let arguments = ["supervise", "--folder"].map(OsString::from).into_iter();
    let arguments: Vec<OsString> = arguments.chain([file.join("under").into()]).collect();
    let storage = launch(&built("hedwig.exe"), &arguments).unwrap_err();
    assert!(matches!(storage, LaunchError::Silent(Some(Exit::Storage))));
    assert_eq!(
        storage.to_string(),
        "Hedwig cannot use the folder it keeps its files in"
    );
    assert_eq!(
        run(&built("hedwig.exe"), folder.path(), "nonsense").0,
        i32::from(Exit::Usage.status())
    );
}

/// This workspace's build shape, as its manifests and crate roots state it:
/// of the crates `hedwig.exe` is built from, `hedwig-win` alone may contain
/// `unsafe`; the stand-in interface is built from the client and the model
/// and never the core; the executable is built without any interface.
#[test]
fn of_the_command_lines_crates_only_hedwig_win_may_contain_unsafe() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let text = |relative: &str| fs::read_to_string(crates.join(relative)).unwrap();
    for root in [
        "hedwig-model/src/lib.rs",
        "hedwig-core/src/lib.rs",
        "hedwig-client/src/lib.rs",
        "hedwig/src/main.rs",
        "hedwig-support/src/bin/interface.rs",
    ] {
        assert!(text(root).contains("\n#![forbid(unsafe_code)]\n"), "{root}");
    }
    assert!(text("hedwig-win/src/pipe.rs").contains("unsafe {"));

    let depends = |manifest: &str| -> Vec<String> {
        text(manifest)
            .lines()
            .filter_map(|written| written.strip_suffix(".workspace = true"))
            .filter(|name| name.starts_with("hedwig-"))
            .map(str::to_owned)
            .collect()
    };
    let interface = text("hedwig-support/src/bin/interface.rs");
    let interface: Vec<&str> = interface
        .lines()
        .filter_map(|written| written.strip_prefix("use "))
        .filter_map(|path| path.split("::").next())
        .filter(|name| name.starts_with("hedwig_"))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(interface, ["hedwig_client", "hedwig_model"]);
    assert_eq!(
        depends("hedwig-client/Cargo.toml"),
        ["hedwig-model", "hedwig-win"]
    );
    assert_eq!(
        depends("hedwig/Cargo.toml"),
        ["hedwig-model", "hedwig-win", "hedwig-core", "hedwig-client"]
    );
    assert_eq!(
        depends("hedwig-core/Cargo.toml"),
        ["hedwig-model", "hedwig-win"]
    );
    assert_eq!(depends("hedwig-win/Cargo.toml"), Vec::<String>::new());
}

/// Windows' version as its own `kernel32.dll` states it, read by PowerShell
/// apart from Hedwig.
fn windows_version() -> String {
    let read = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"$v=(Get-Item "$env:SystemRoot\System32\kernel32.dll").VersionInfo; '{0}.{1}.{2}.{3}' -f $v.FileMajorPart,$v.FileMinorPart,$v.FileBuildPart,$v.FilePrivatePart"#,
        ])
        .output()
        .unwrap();
    assert!(read.status.success(), "{read:?}");
    String::from_utf8(read.stdout).unwrap().trim().to_owned()
}

/// A supporter's one file, asked of a real core: where the program runs, Windows'
/// own version, the start-up value it could not keep and why, the lines the
/// diagnostics files hold and the file it set aside, beside the replies a
/// supporter reads.
#[test]
fn a_supporter_is_given_what_hedwig_knows_in_one_bundle() {
    // The core runs from a folder the in-box client would split as its
    // askpass, so it keeps no `Run` value and says why; an earlier run left
    // a line of diagnostics; and the configuration cannot be read.
    let split = Folder::new("x.exe y");
    fs::copy(built("hedwig.exe"), split.path().join("hedwig.exe")).unwrap();
    let program = split.path().join("command.exe");
    fs::copy(env!("CARGO_BIN_EXE_command"), &program).unwrap();
    let folder = Folder::new("bundle");
    fs::write(folder.path().join("configuration.json"), b"not a document").unwrap();
    let earlier = Diagnostic {
        at: Timestamp(1_790_000_000_000),
        from: "channel 7".to_owned(),
        said: "Connection refused".to_owned(),
    };
    fs::write(
        folder.path().join("diagnostics.jsonl"),
        line(&earlier) + "\n",
    )
    .unwrap();
    let names = Names::keyed(&folder.path().to_string_lossy());
    let _taken = Taken(names.clone());
    let started = Command::new(&program)
        .arg("start")
        .arg("--folder")
        .arg(folder.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(started.status.success(), "{started:?}");
    let (pipe, _, _) = serving(&look(folder.path()).unwrap()).unwrap();
    let mut session = Session::open(&pipe).unwrap();
    session.greet(ClientKind::Terminal).unwrap().unwrap();
    let on = Change::Autostart(Some(Autostart::AtLogon));
    assert!(matches!(
        session.ask(Request::Change(on.clone())).unwrap(),
        Ok(Reply::Changed { .. })
    ));

    // The `Run` values are kept by a thread of their own: asked until what
    // it found is recorded.
    let unkept = |found: &Option<AtSignIn>| matches!(found, Some(AtSignIn::Unkept(why)) if why.as_str().contains("x.exe y"));
    let mut bundle: Option<Box<Bundle>> = None;
    let found = within(Duration::from_secs(10), || {
        let Ok(Ok(Reply::Bundle(asked))) = session.ask(Request::Bundle) else {
            return false;
        };
        let said = unkept(&asked.settings.workstation.windows.hedwig);
        bundle = Some(asked);
        said
    });
    assert!(found, "the value not kept names the folder: {bundle:?}");
    let bundle = bundle.unwrap();
    assert_eq!(bundle.program, split.path().display().to_string());
    assert_eq!(bundle.windows, windows_version());
    assert_eq!(bundle.version, bundle.status.version);
    assert!(
        bundle.activity.iter().any(|entry| matches!(
            &entry.event,
            Event::Startup { starts: Starts::Hedwig, found } if unkept(&Some(found.clone()))
        )),
        "the activity holds it too"
    );
    assert!(
        bundle.diagnostics.contains(&line(&earlier)),
        "the diagnostics files' lines: {:?}",
        bundle.diagnostics
    );
    assert!(
        bundle
            .set_aside
            .iter()
            .any(|aside| aside.name.starts_with("configuration.unreadable-") && aside.bytes == 14),
        "{:?}",
        bundle.set_aside
    );
    assert!(
        bundle
            .activity
            .iter()
            .any(|entry| matches!(&entry.event, Event::Changed { change, .. } if *change == on))
    );
    assert_eq!(own(RUN, &names.run_value(Starts::Hedwig)).unwrap(), None);

    stopped(folder.path());
}
