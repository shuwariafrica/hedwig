//! The window as a process, against a real core: a Hedwig started in a
//! folder of the suite's own by the command-line stand-in the workspace
//! builds, given something to show through the pipe as any client would,
//! and the window opened on that folder - for a few seconds a window
//! titled for the suite's folder is on the screen. What it shows is read
//! through UI Automation by the scripts in `tests/automation`.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hedwig_client::{Session, Standing, look};
use hedwig_model::capability::{
    AgentAt, Capability, Exposure, Lends, LentKey, Offer, ServiceHost, ServicePort, Setup, Source,
    Stream, Toward,
};
use hedwig_model::config::{Activation, Change, Grant, GrantEntry, Terms};
use hedwig_model::process::CoreState;
use hedwig_model::protocol::{Reply, Request};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::setting::Threshold;
use hedwig_model::text::{Address, AgentPipe, DeviceSerial, Name, Port, SshKey, Words};
use hedwig_model::trail::ClientKind;
use hedwig_shell::{desk, window};
use hedwig_view::trial::{self, Outcome};
use hedwig_view::words::Keyrings;
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetThreadDpiAwarenessContext,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetWindowRect, ICON_BIG, ICON_SMALL, IsWindowVisible, IsZoomed, PostMessageW, SW_MAXIMIZE,
    SW_RESTORE, SWP_NOACTIVATE, SWP_NOZORDER, SendMessageW, SetWindowPos, ShowWindow, WM_CLOSE,
    WM_GETICON,
};

#[path = "../../hedwig-interface/tests/support/restart.rs"]
mod restart;

const WINDOW: &str = env!("CARGO_BIN_EXE_hedwig-window");

/// The command-line stand-in built with the workspace, which starts the
/// `hedwig.exe` beside it.
fn stand_in() -> PathBuf {
    let path = Path::new(WINDOW).with_file_name("command.exe");
    assert!(
        path.exists(),
        "{} is built with the workspace",
        path.display()
    );
    path
}

fn command(folder: &Path, word: &str) -> (Option<i32>, String) {
    let output = Command::new(stand_in())
        .arg(word)
        .arg("--folder")
        .arg(folder)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// Everything the suite started, ended whatever happens.
struct Started {
    folder: PathBuf,
    window: Option<Child>,
}

impl Drop for Started {
    fn drop(&mut self) {
        if let Some(window) = &mut self.window {
            let _ = window.kill();
            let _ = window.wait();
        }
        let _ = command(&self.folder, "stop");
        let _ = std::fs::remove_dir_all(&self.folder);
    }
}

fn within(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    done()
}

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn host() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("build.example").unwrap(),
    }
}

/// Makes a grant and a setting through the pipe, as any client could.
fn grant(folder: &Path) {
    let Standing::Known(running) = look(folder).unwrap() else {
        unreachable!("the core is running")
    };
    let CoreState::Serving { pipe, .. } = running.core else {
        unreachable!("the core is serving")
    };
    let mut session = Session::open(&pipe).unwrap();
    session.greet(ClientKind::Command).unwrap().unwrap();
    for change in [
        Change::Grant {
            grant: Grant {
                capability: name("gpg"),
                remotes: Granted::One(host()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        },
        Change::Burst {
            remotes: Remotes::One(host()),
            threshold: Some(Threshold::Never),
        },
    ] {
        session.ask(Request::Change(change)).unwrap().unwrap();
    }
}

fn listed(process: u32) -> String {
    let held = Command::new("tasklist")
        .args(["/fo", "csv", "/nh", "/fi"])
        .arg(format!("PID eq {process}"))
        .output()
        .unwrap();
    String::from_utf8_lossy(&held.stdout).trim().to_owned()
}

/// The suite's UI Automation script `script`.
fn automation(script: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("automation")
        .join(script)
}

/// What UI Automation reads of the window.
fn read(process: u32) -> String {
    let output = Command::new("pwsh")
        .args(["-NoProfile", "-File"])
        .arg(automation("uia.ps1"))
        .args(["-ProcessId", &process.to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Types `text` into, or presses, the control named `name`, through the
/// suite's script `script`, as assistive technology does.
fn probe(script: &str, process: u32, name: &str, text: Option<&str>) -> bool {
    let mut command = Command::new("pwsh");
    command
        .args(["-NoProfile", "-File"])
        .arg(automation(script))
        .args(["-ProcessId", &process.to_string(), "-Name", name]);
    if let Some(text) = text {
        command.args(["-Text", text]);
    }
    command.status().unwrap().success()
}

#[test]
#[ignore = "needs the desktop's foreground"]
fn the_window_shows_what_is_granted_is_one_for_its_hedwig_and_ends_with_its_window() {
    let folder = std::env::temp_dir().join(format!("Hedwig window {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        window: None,
    };

    if !desk::interactive() {
        let status = Command::new(WINDOW)
            .arg("--folder")
            .arg(&folder)
            .status()
            .unwrap();
        println!("no desktop here; the window ended with {status}");
        assert_eq!(status.code(), Some(4));
        return;
    }

    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    grant(&folder);

    let opened = Instant::now();
    let child = Command::new(WINDOW)
        .arg("--folder")
        .arg(&folder)
        .spawn()
        .unwrap();
    let process = child.id();
    started.window = Some(child);
    assert!(
        within(Duration::from_secs(20), || window::window_of(process)
            .is_some()),
        "no window"
    );
    println!(
        "the window on the screen after {} ms",
        opened.elapsed().as_millis()
    );

    // It greets the core as a viewer: told what is stale and asked
    // nothing, so the presence asks and the window shows.
    let mut seen = String::new();
    let attached = within(Duration::from_secs(10), || {
        seen = command(&folder, "status").1;
        seen.contains(r#""kind":"viewer""#) && !seen.contains(r#""kind":"interface""#)
    });
    assert!(attached, "the window did not attach as it should: {seen}");

    // What it shows is the view's, drawn by WinUI and read back.
    let mut tree = String::new();
    let shown = within(Duration::from_secs(10), || {
        tree = read(process);
        tree.contains("build.example (ssh)")
    });
    println!("what UI Automation reads of it:\n{tree}");
    assert!(shown, "the grant is not shown");
    for expected in [
        r#"Text "What of yours is reachable" focusable=False heading=Level1"#,
        r#"Button "Make a grant""#,
        "Settings for build.example (ssh)",
        "This workstation: settings, export and import",
        // The grant does not let Hedwig write; consent is offered, and asked
        // first with what it writes.
        r#"Button "Let Hedwig write the remote tool's configuration...""#,
    ] {
        assert!(tree.contains(expected), "{expected} is not shown");
    }
    // Its title bar, its taskbar button and ALT+TAB show the executable's
    // icon, which WinUI sets on none of its windows.
    let shown = window::window_of(process).unwrap();
    for kind in [ICON_SMALL, ICON_BIG] {
        // SAFETY: the window is this test's child's; one that has gone
        // answers zero.
        let icon = unsafe { SendMessageW(shown as HWND, WM_GETICON, kind as usize, 0) };
        assert_ne!(icon, 0, "the window has no icon of kind {kind}");
    }
    std::thread::sleep(Duration::from_millis(1000));
    println!("the window open, as Windows lists it: {}", listed(process));

    // A second start for the same Hedwig brings this one forward and ends.
    let again = Command::new(WINDOW)
        .arg("--folder")
        .arg(&folder)
        .status()
        .unwrap();
    assert_eq!(again.code(), Some(0));
    assert!(
        window::window_of(process).is_some(),
        "the first is still the window"
    );

    // Closing the window ends its process, with the status that says the
    // person did, and gives back everything it held.
    let closing = Instant::now();
    assert!(window::close(process));
    let window = started.window.as_mut().unwrap();
    let mut ended = None;
    within(Duration::from_secs(10), || {
        ended = window.try_wait().unwrap();
        ended.is_some()
    });
    assert_eq!(ended.and_then(|status| status.code()), Some(0));
    started.window = None;
    println!(
        "the window closed: its process ended {} ms later, and Windows lists {:?}",
        closing.elapsed().as_millis(),
        listed(process)
    );

    // Looking is not making: nothing was kept of a grant being made.
    let kept = folder.join("interface").join("grant");
    assert!(!kept.exists(), "{} was written", kept.display());
}

/// What the window writes on export and reads on import, through the real
/// core: the person's document written to a file as the window writes it,
/// read back, edited, tried and then made.
#[test]
fn a_configuration_written_to_a_file_is_tried_and_made_by_the_core() {
    let folder = std::env::temp_dir().join(format!("Hedwig import {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let _started = Started {
        folder: folder.clone(),
        window: None,
    };
    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    let Standing::Known(running) = look(&folder).unwrap() else {
        unreachable!("the core is running")
    };
    let CoreState::Serving { pipe, .. } = running.core else {
        unreachable!("the core is serving")
    };
    let mut session = Session::open(&pipe).unwrap();
    session.greet(ClientKind::Command).unwrap().unwrap();
    let Ok(Reply::Document(document)) = session.ask(Request::Export).unwrap() else {
        unreachable!("the core exports")
    };
    let file = folder.join("exported.json");
    std::fs::write(&file, trial::written(&document)).unwrap();
    let mut edited = trial::document(&std::fs::read_to_string(&file).unwrap()).unwrap();
    assert_eq!(edited, *document, "read back as written");
    edited.grants.push(GrantEntry {
        grant: Grant {
            capability: name("gpg"),
            remotes: Granted::One(host()),
        },
        terms: Terms {
            activation: Activation::OnRequest,
            setup: Setup::Inspect,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        },
    });

    let Ok(Reply::Tried(tried)) = session.ask(trial::try_import(edited.clone())).unwrap() else {
        unreachable!("the core tries")
    };
    let outcome = Outcome::of(&tried, &[], Keyrings::default());
    println!("the core's trial, as the window says it: {outcome:?}");
    assert!(matches!(&outcome, Outcome::Would { wider: true, changes } if !changes.is_empty()));
    let Ok(Reply::Document(unchanged)) = session.ask(Request::Export).unwrap() else {
        unreachable!("the core exports")
    };
    assert_eq!(unchanged, document, "a trial makes nothing");

    let made = session.ask(trial::import(edited.clone())).unwrap();
    assert!(matches!(made, Ok(Reply::Changed { .. })), "{made:?}");
    let Ok(Reply::Document(now)) = session.ask(Request::Export).unwrap() else {
        unreachable!("the core exports")
    };
    assert_eq!(*now, edited, "made as tried");
}

/// Through the real core, a grant of an ADB capability whose server
/// cannot be read shows what it lends, the device lent that the server does
/// not hold now as a box that takes it back, why the list could not be read
/// in the core's words, and lending every device and reading the list again,
/// all drawn by WinUI. The capability names a port nothing listens on, so no
/// ADB server of the person's is asked anything.
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_grants_lending_is_drawn_from_what_the_real_core_says() {
    let folder = std::env::temp_dir().join(format!("Hedwig lending {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        window: None,
    };
    assert!(desk::interactive(), "needs the desktop's foreground");
    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");

    // A port the system just gave and took back: nothing listens there.
    let free = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let capability = Capability {
        id: name("adb-suite"),
        source: Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(Port::try_from(free).unwrap()),
            stream: Stream::Adb,
            remote: vec![Offer::Port(ServicePort::Fixed(
                Port::try_from(5037).unwrap(),
            ))],
        },
    };
    let acknowledged = capability.exposure().common(Exposure::ACKNOWLEDGED);
    let Standing::Known(running) = look(&folder).unwrap() else {
        unreachable!("the core is running")
    };
    let CoreState::Serving { pipe, .. } = running.core else {
        unreachable!("the core is serving")
    };
    let mut session = Session::open(&pipe).unwrap();
    session.greet(ClientKind::Command).unwrap().unwrap();
    for change in [
        Change::Define(capability),
        Change::Grant {
            grant: Grant {
                capability: name("adb-suite"),
                remotes: Granted::One(host()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged,
                lends: Lends::devices([DeviceSerial::try_from("emulator-5554").unwrap()]),
            },
        },
    ] {
        session.ask(Request::Change(change)).unwrap().unwrap();
    }
    let refused = session.ask(Request::Devices(name("adb-suite"))).unwrap();
    println!("the core asked for the devices: {refused:?}");
    let Err(refusal) = refused else {
        unreachable!("nothing listens, so no device is listed")
    };

    let child = Command::new(WINDOW)
        .arg("--folder")
        .arg(&folder)
        .spawn()
        .unwrap();
    let process = child.id();
    started.window = Some(child);
    assert!(
        within(Duration::from_secs(20), || window::window_of(process)
            .is_some()),
        "no window"
    );
    let mut tree = String::new();
    let shown = within(Duration::from_secs(15), || {
        tree = read(process);
        tree.contains(&format!("The devices could not be read: {refusal}."))
    });
    println!("what UI Automation reads of it:\n{tree}");
    assert!(shown, "the list's refusal is not shown");
    for expected in [
        r#"Text "Lends emulator-5554""#,
        r#"CheckBox "emulator-5554, which the workstation's ADB server does not hold now""#,
        r#"Button "Lend every device...""#,
        r#"Button "Look again for devices""#,
    ] {
        assert!(tree.contains(expected), "{expected} is not shown");
    }
}

/// The person's own SSH agent, through the real core: a grant lending one
/// key only for logging in to two hosts shows the key as `ssh-add -l` named
/// it when it was lent, the comment kept by the core, and where it may be
/// used, a box that takes it back, the hosts it may log in to to edit,
/// lending it for anything asked first, asking the agent for its keys, and
/// what the agent's own prompts cannot say - all drawn by WinUI. Narrowed to
/// one host it is lent so at once; toward another host, asked first. The
/// agent is at a pipe of the suite's own that nothing serves, so no agent of
/// the person's is reached, and the core's record shows the window asked
/// that agent nothing.
#[test]
#[ignore = "needs the desktop's foreground"]
fn an_agents_keys_are_drawn_from_what_the_real_core_says() {
    let folder = std::env::temp_dir().join(format!("Hedwig agent {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        window: None,
    };
    assert!(desk::interactive(), "needs the desktop's foreground");
    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    let key = |text: &str| SshKey::try_from(text).unwrap();
    let a = key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/fZgxPr11UWZgHjQXEU/F65sUwfaohdFFly5gtgRRs");
    let host_key = key(
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNwo9zNZ1p9OJMHFfawTucuCrkP+GumZ23WooozBOTggm9wkcD/mjb+3nAAyY655XW+KEaqiVzrtd3CsyDdVeX4=",
    );
    let capability = Capability {
        id: name("agent-suite"),
        source: Source::Agent {
            at: AgentAt::Pipe(
                AgentPipe::try_from(format!("hedwig-suite-agent-{}", std::process::id()).as_str())
                    .unwrap(),
            ),
        },
    };
    let acknowledged = capability.exposure().common(Exposure::ACKNOWLEDGED);
    let Standing::Known(running) = look(&folder).unwrap() else {
        unreachable!("the core is running")
    };
    let CoreState::Serving { pipe, .. } = running.core else {
        unreachable!("the core is serving")
    };
    let mut session = Session::open(&pipe).unwrap();
    session.greet(ClientKind::Command).unwrap().unwrap();
    for change in [
        Change::Define(capability),
        Change::Grant {
            grant: Grant {
                capability: name("agent-suite"),
                remotes: Granted::One(host()),
            },
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Inspect,
                acknowledged,
                lends: Lends::of_keys([(
                    a.clone(),
                    LentKey {
                        toward: Toward::Hosts([host_key.clone(), a.clone()].into()),
                        comment: Some(Words::try_from("laptop").unwrap()),
                    },
                )]),
            },
        },
    ] {
        session.ask(Request::Change(change)).unwrap().unwrap();
    }

    let child = Command::new(WINDOW)
        .arg("--folder")
        .arg(&folder)
        .spawn()
        .unwrap();
    let process = child.id();
    started.window = Some(child);
    assert!(
        within(Duration::from_secs(20), || window::window_of(process)
            .is_some()),
        "no window"
    );
    let said = "ED25519 key SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE (laptop)";
    let mut tree = String::new();
    let shown = within(Duration::from_secs(15), || {
        tree = read(process);
        tree.contains(&format!(r#"CheckBox "{said}""#))
    });
    println!("what UI Automation reads of it:\n{tree}");
    assert!(shown, "the lent key is not shown");
    for expected in [
        format!(
            r#"Text "Lends {said} only for logging in to the hosts whose keys are ECDSA SHA256:X4mkNnFzELzfodwwfn4jjh4ZhRfFtBN7vYS3FjS/nR0, ED25519 SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE, and for nothing else""#
        ),
        r#"Text "Only for logging in to the hosts whose keys are ECDSA SHA256:X4mkNnFzELzfodwwfn4jjh4ZhRfFtBN7vYS3FjS/nR0, ED25519 SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE, and for nothing else""#.to_owned(),
        r#"Edit "Hosts it may log in to""#.to_owned(),
        r#"Button "Lend it only for logging in to these hosts""#.to_owned(),
        format!(r#"Button "Lend {said} for anything...""#),
        r#"Button "Lend every key...""#.to_owned(),
        r#"Button "Show your agent's keys, to lend another""#.to_owned(),
        "never the remote".to_owned(),
    ] {
        assert!(tree.contains(&expected), "{expected} is not shown");
    }

    narrowing_is_carried_out_at_once(process, said);
    another_host_is_asked_first(process);

    // Showing the line asked the agent nothing.
    the_core_never_reached(&mut session, "agent-suite");
}

/// The core never reached `capability`'s source: it read nothing of what
/// answers there.
fn the_core_never_reached(session: &mut Session, capability: &str) {
    let Ok(Reply::Workstation(found)) = session.ask(Request::Workstation).unwrap() else {
        unreachable!("the core says what the workstation has")
    };
    let source = found
        .sources
        .iter()
        .find(|found| found.capability == name(capability));
    assert!(
        source.is_none_or(|found| found.holder.is_none()),
        "{source:?}"
    );
}

/// One of the two hosts' keys kept on a key's line: the key lent toward that
/// host alone at once, since that lends less, with its comment kept.
fn narrowing_is_carried_out_at_once(process: u32, said: &str) {
    let mut tree = String::new();
    let one = "build.example ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNwo9zNZ1p9OJMHFfawTucuCrkP+GumZ23WooozBOTggm9wkcD/mjb+3nAAyY655XW+KEaqiVzrtd3CsyDdVeX4=";
    // The box is on the key's line, made when the window renders the reply that brings the line.
    assert!(within(Duration::from_secs(10), || probe(
        "type.ps1",
        process,
        "Hosts it may log in to",
        Some(one)
    )));
    std::thread::sleep(Duration::from_millis(500));
    assert!(probe(
        "invoke.ps1",
        process,
        "Lend it only for logging in to these hosts",
        None
    ));
    let narrowed = format!(
        r#"Text "Lends {said} only for logging in to the host whose key is ECDSA SHA256:X4mkNnFzELzfodwwfn4jjh4ZhRfFtBN7vYS3FjS/nR0, and for nothing else""#
    );
    let lent = within(Duration::from_secs(10), || {
        tree = read(process);
        tree.contains(&narrowed)
    });
    assert!(lent, "narrowing was not carried out:\n{tree}");
    assert!(!tree.contains(r#"Button "Lend it only there""#), "{tree}");
}

/// Another host's key pasted on a key's line and the key lent toward it:
/// asked first, since that lends more, and nothing changed on
/// "Cancel".
fn another_host_is_asked_first(process: u32) {
    let mut tree = String::new();
    let other = "203.0.113.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/fZgxPr11UWZgHjQXEU/F65sUwfaohdFFly5gtgRRs";
    assert!(probe(
        "type.ps1",
        process,
        "Hosts it may log in to",
        Some(other)
    ));
    std::thread::sleep(Duration::from_millis(500));
    assert!(probe(
        "invoke.ps1",
        process,
        "Lend it only for logging in to these hosts",
        None
    ));
    let asked = within(Duration::from_secs(10), || {
        tree = read(process);
        tree.contains(r#"Button "Lend it only there""#)
    });
    assert!(asked, "another host was not asked first:\n{tree}");
    assert!(
        tree.contains("Lend it only for logging in to these hosts?"),
        "{tree}"
    );
    assert!(probe("invoke.ps1", process, "Cancel", None));
    assert!(within(Duration::from_secs(10), || !read(process)
        .contains(r#"Button "Lend it only there""#)));
}

/// The core the record names now, by its process number.
fn serving(folder: &Path) -> Option<u32> {
    match look(folder).ok()? {
        Standing::Known(running) => match running.core {
            CoreState::Serving { process, .. } => Some(process),
            _ => None,
        },
        _ => None,
    }
}

/// A window opened before Hedwig shows Hedwig once it is started from
/// elsewhere, and the core its supervisor starts again after a breakdown,
/// with nothing pressed.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_window_shows_a_hedwig_started_elsewhere_and_its_core_started_again() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let folder = std::env::temp_dir().join(format!("Hedwig window later {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        window: None,
    };
    let window = Command::new(WINDOW)
        .arg("--folder")
        .arg(&folder)
        .spawn()
        .unwrap();
    let process = window.id();
    started.window = Some(window);
    let mut seen = String::new();
    assert!(
        within(Duration::from_secs(20), || {
            seen = read(process);
            seen.contains("Hedwig is not running")
        }),
        "{seen}"
    );

    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    let began = Instant::now();
    let attached = |seen: &str| seen.contains("Nothing of yours is reachable from a remote yet");
    assert!(
        within(Duration::from_secs(15), || {
            seen = read(process);
            attached(&seen)
        }),
        "a Hedwig started elsewhere was not shown:\n{seen}"
    );
    println!(
        "shown {} ms after Hedwig started",
        began.elapsed().as_millis()
    );

    let first = serving(&folder).unwrap();
    let killed = Command::new("taskkill")
        .args(["/f", "/pid"])
        .arg(first.to_string())
        .output()
        .unwrap();
    assert!(killed.status.success(), "{killed:?}");
    let began = Instant::now();
    assert!(
        within(Duration::from_secs(30), || {
            seen = read(process);
            serving(&folder).is_some_and(|next| next != first) && attached(&seen)
        }),
        "the core started again was not shown:\n{seen}"
    );
    println!(
        "the core started again shown {} ms after the first was ended",
        began.elapsed().as_millis()
    );
}

/// Whether the person can see the window: shown, and not cloaked.
fn seen(window: HWND) -> bool {
    let mut cloaked = 0u32;
    // SAFETY: only reads the window's state; the value is a DWORD that
    // outlives the call.
    let read = unsafe {
        DwmGetWindowAttribute(
            window,
            DWMWA_CLOAKED.cast_unsigned(),
            (&raw mut cloaked).cast(),
            4,
        )
    };
    // SAFETY: as above.
    let visible = unsafe { IsWindowVisible(window) } != 0;
    visible && (read != 0 || cloaked == 0)
}

/// The window's handle in the first moment the person could see it, with
/// its rectangle then and whether it was maximised then.
fn shown(process: u32) -> (HWND, RECT, bool) {
    let until = Instant::now() + Duration::from_secs(20);
    let window = loop {
        if let Some(window) = window::window_of(process)
            && seen(window as HWND)
        {
            break window as HWND;
        }
        assert!(Instant::now() < until, "the window was never shown");
    };
    let mut rect = RECT::default();
    // SAFETY: the window is shown; the rectangle is valid for the call.
    unsafe { GetWindowRect(window, &raw mut rect) };
    // SAFETY: as above.
    let zoomed = unsafe { IsZoomed(window) } != 0;
    (window, rect, zoomed)
}

/// Closes the window as its close box does, and waits for its process.
fn close(window: HWND, child: &mut Child) {
    // SAFETY: posting to another process's window passes no pointer.
    unsafe { PostMessageW(window, WM_CLOSE, 0, 0) };
    assert!(within(Duration::from_secs(10), || child
        .try_wait()
        .unwrap()
        .is_some()));
}

/// The window opens where the person left it: in the first moment it can be
/// seen at the rectangle it was moved to, and maximised in that moment where
/// it was closed maximised, restoring to that rectangle.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_window_opens_where_the_person_left_it() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    // Rectangles in the screen's own pixels, as the window keeps them.
    // SAFETY: changes only this thread's awareness.
    unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    let folder = std::env::temp_dir().join(format!("Hedwig place {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let kept = folder.join("interface").join("place");
    let open = || {
        Command::new(WINDOW)
            .arg("--folder")
            .arg(&folder)
            .spawn()
            .unwrap()
    };

    let mut child = open();
    let (handle, _, _) = shown(child.id());
    // Moved and sized as the person would by its frame.
    // SAFETY: the window is another process's; no pointer is passed.
    unsafe {
        SetWindowPos(
            handle,
            std::ptr::null_mut(),
            300,
            150,
            1000,
            800,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
    close(handle, &mut child);
    assert_eq!(
        std::fs::read_to_string(&kept)
            .unwrap()
            .split_whitespace()
            .take(5)
            .collect::<Vec<_>>(),
        ["300", "150", "1300", "950", "restored"]
    );

    let mut child = open();
    let (handle, rect, zoomed) = shown(child.id());
    assert_eq!(
        (rect.left, rect.top, rect.right, rect.bottom, zoomed),
        (300, 150, 1300, 950, false),
        "not where it was left in the first moment it was seen"
    );
    // SAFETY: as above.
    unsafe { ShowWindow(handle, SW_MAXIMIZE) };
    std::thread::sleep(Duration::from_millis(300));
    close(handle, &mut child);

    let mut child = open();
    let (handle, _, zoomed) = shown(child.id());
    assert!(zoomed, "not maximised in the first moment it was seen");
    // SAFETY: as above.
    unsafe { ShowWindow(handle, SW_RESTORE) };
    std::thread::sleep(Duration::from_millis(300));
    let mut rect = RECT::default();
    // SAFETY: as above.
    unsafe { GetWindowRect(handle, &raw mut rect) };
    assert_eq!(
        (rect.left, rect.top, rect.right, rect.bottom),
        (300, 150, 1300, 950)
    );
    close(handle, &mut child);
    std::fs::remove_file(&kept).unwrap();
    let _ = std::fs::remove_dir_all(&folder);
}

#[test]
fn an_argument_it_does_not_know_is_refused_before_anything_is_shown() {
    for arguments in [vec!["--unknown"], vec!["--folder"], vec!["tray"]] {
        let status = Command::new(WINDOW).args(&arguments).status().unwrap();
        assert_eq!(status.code(), Some(2), "{arguments:?}");
    }
}

/// An installer of Windows' own that replaces the window's program closes
/// the window as its close box does: its process ends, and where the person
/// left it is kept for its next opening.
#[test]
#[ignore = "needs the desktop's foreground"]
fn windows_own_installers_close_the_window_and_its_place_is_kept() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let folder = std::env::temp_dir().join(format!("Hedwig restart window {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let kept = folder.join("interface").join("place");
    let mut child = Command::new(WINDOW)
        .arg("--folder")
        .arg(&folder)
        .spawn()
        .unwrap();
    let _ = shown(child.id());
    assert!(!kept.exists(), "a place was kept before the window went");

    let (holders, shut) = restart::shut_down(Path::new(WINDOW));
    assert!(
        holders.contains(&(child.id(), "Hedwig".to_owned())),
        "{holders:?}"
    );
    assert_eq!(shut, 0);
    let ended = within(Duration::from_secs(10), || {
        child.try_wait().unwrap().is_some()
    });
    if !ended {
        let _ = child.kill();
    }
    assert!(ended, "the window stayed");
    assert_eq!(child.try_wait().unwrap().unwrap().code(), Some(0));
    assert!(kept.exists(), "where the window was is not kept");
    let _ = std::fs::remove_dir_all(&folder);
}

/// What a supporter needs, through the real core: the window asks for the
/// core's own bundle and shows each part before anything is saved, and
/// putting it away saves nothing.
#[test]
#[ignore = "needs the desktop's foreground"]
fn what_a_supporter_needs_is_asked_of_the_real_core_and_shown_before_it_is_saved() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let folder = std::env::temp_dir().join(format!("Hedwig bundle {}", std::process::id()));
    std::fs::create_dir_all(&folder).unwrap();
    let mut started = Started {
        folder: folder.clone(),
        window: None,
    };
    let (status, said) = command(&folder, "start");
    assert_eq!(status, Some(0), "{said}");
    grant(&folder);
    let child = Command::new(WINDOW)
        .arg("--folder")
        .arg(&folder)
        .spawn()
        .unwrap();
    let process = child.id();
    started.window = Some(child);
    let _ = shown(process);
    let workstation = "This workstation: settings, export and import";
    let expand = |name: &str| {
        Command::new("pwsh")
            .args(["-NoProfile", "-File"])
            .arg(automation("invoke.ps1"))
            .args(["-ProcessId", &process.to_string(), "-Name", name, "-Expand"])
            .status()
            .unwrap()
            .success()
    };
    assert!(within(Duration::from_secs(10), || expand(workstation)));
    let gather = "Gather what a supporter needs...";
    assert!(within(Duration::from_secs(10), || probe(
        "invoke.ps1",
        process,
        gather,
        None
    )));
    let mut tree = String::new();
    let seen = within(Duration::from_secs(10), || {
        tree = read(process);
        tree.contains("What a supporter receives")
    });
    println!("what UI Automation reads of it:\n{tree}");
    assert!(seen, "the bundle is not shown");
    for expected in [
        "running from",
        "What is reachable, line by line, from 1 remote: build.example (ssh).",
        "What Hedwig wrote down about what went wrong:",
        "It holds no passphrase, answer, PIN or key.",
        r#"Button "Save it...""#,
    ] {
        assert!(tree.contains(expected), "{expected} is not shown");
    }
    assert!(probe("invoke.ps1", process, "Cancel", None));
    assert!(within(Duration::from_secs(10), || !read(process)
        .contains("What a supporter receives")));
}
