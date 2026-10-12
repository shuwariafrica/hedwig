//! A shipped route's client, found by name and given the arguments its entry
//! builds, is read by the workstation's own OpenSSH as the entry means it,
//! and what the core sets on a channel stands over a configuration that says
//! otherwise. `-G` prints what the client would do and connects nowhere; `-F`
//! gives it a configuration of the suite's own, so nothing of the person's is
//! read or run.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::ffi::OsString;
use std::io::Read;
use std::net::TcpListener;
use std::process::Command;

use hedwig_core::channel::options;
use hedwig_model::config::{Catalogue, Change, Configuration};
use hedwig_model::remote::Route;
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{Address, Name, Port, RemotePath};
use hedwig_model::trail::{Asking, Binding, Serving};
use hedwig_win::process::DETACHED;
use hedwig_win::search::program;
use hedwig_win::start::apart;

mod common;
use common::Folder;

/// What the client would do for `address` on `route`, with the core's
/// `options` where the entry puts them.
fn effective(route: &str, address: &str, options: &[&str]) -> Vec<String> {
    configured("", route, address, options)
}

/// As [`effective`], over `configuration` as the person's own.
fn configured(configuration: &str, route: &str, address: &str, options: &[&str]) -> Vec<String> {
    // What ships, and a vendor's route as a person defines it.
    let catalogue = Catalogue::shipped().unwrap();
    let coder: Route =
        hedwig_model::wire::read(include_str!("../../hedwig-model/tests/coder-route.json"))
            .unwrap();
    let mut defined = Configuration::default();
    defined
        .apply(&catalogue, Change::DefineRoute(coder))
        .unwrap();
    let route = defined
        .route(&catalogue, &Name::try_from(route).unwrap())
        .unwrap();
    let folder = Folder::new("routes");
    let empty = folder.path().join("config");
    std::fs::write(&empty, configuration).unwrap();
    let mut given = vec![
        "-F".to_owned(),
        empty.display().to_string(),
        "-G".to_owned(),
    ];
    given.extend(options.iter().map(|option| (*option).to_owned()));
    let arguments: Vec<OsString> = route
        .client
        .arguments(&Address::try_from(address).unwrap(), given)
        .into_iter()
        .map(OsString::from)
        .collect();
    let client = program(route.client.program.as_str()).unwrap();
    let started = apart(&client, &arguments, DETACHED).unwrap();
    let mut said = String::new();
    (&started.said).read_to_string(&mut said).unwrap();
    assert_eq!(started.wait().unwrap(), 0, "{said}");
    said.lines().map(str::to_owned).collect()
}

fn has(lines: &[String], wanted: &str) -> bool {
    lines.iter().any(|line| line == wanted)
}

#[test]
fn the_ssh_route_reaches_the_address_with_the_cores_options() {
    let lines = effective(
        "ssh",
        "dev@build-7.example",
        &[
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "Tag=hedwig",
            "-R",
            "/run/user/1000/gnupg/S.gpg-agent:127.0.0.1:50123",
        ],
    );
    for wanted in [
        "user dev",
        "hostname build-7.example",
        "sessiontype none",
        "exitonforwardfailure yes",
        "tag hedwig",
        "remoteforward /run/user/1000/gnupg/S.gpg-agent [127.0.0.1]:50123",
        "stricthostkeychecking ask",
    ] {
        assert!(has(&lines, wanted), "{wanted}: {lines:?}");
    }
}

/// A route a person defines for a vendor's platform, in the form the
/// documentation publishes: its own options reach the client beside the
/// core's. What its proxy does is not run here.
#[test]
fn a_defined_vendor_route_hands_the_client_its_proxy_and_its_identity() {
    let lines = effective("coder", "build", &["-N", "-o", "Tag=hedwig"]);
    for wanted in [
        "hostname build",
        "tag hedwig",
        "proxycommand coder ssh --stdio %n",
        "stricthostkeychecking false",
        "userknownhostsfile /dev/null",
    ] {
        assert!(has(&lines, wanted), "{wanted}: {lines:?}");
    }
}

/// What a person's configuration might say for the host that a channel must
/// not do, and three forwards of their own.
const CONTRARY: &str = "\
Host build-7.example
    User dev
    BatchMode no
    ExitOnForwardFailure yes
    LogLevel QUIET
    ForwardAgent yes
    ForwardX11 yes
    PermitLocalCommand yes
    LocalCommand echo connected
    ControlMaster auto
    ControlPath ~/.ssh/cm-%C
    ServerAliveInterval 0
    ServerAliveCountMax 100
";

const FORWARDS: &str = "\
    LocalForward 8080 127.0.0.1:8080
    RemoteForward 47470 127.0.0.1:47470
    DynamicForward 1080
";

fn channel_options() -> Vec<String> {
    let port = |number: u16| Port::try_from(number).unwrap();
    let socket = |path: &str| Binding::Socket(RemotePath::try_from(path).unwrap());
    let serving = |capability: &str, binding: Binding| Serving {
        capability: Name::try_from(capability).unwrap(),
        binding,
    };
    options(
        &[
            (
                serving("gpg", socket("/run/user/1000/gnupg/S.gpg-agent")),
                port(50123),
            ),
            (
                serving("ssh-agent", socket("/home/a:b/S.agent")),
                port(50124),
            ),
            (serving("adb", Binding::Port(port(5037))), port(50125)),
        ],
        Asking::Nobody,
        Keepalive::SHIPS,
    )
}

/// Everything the core sets is what the real client does, whatever the
/// person's configuration says of it; the host, the user and their own
/// forwards remain theirs, and the core's forwards are asked for first.
#[test]
fn what_the_core_sets_stands_over_the_persons_configuration() {
    let options = channel_options();
    let options: Vec<&str> = options.iter().map(String::as_str).collect();
    let configuration = format!("{CONTRARY}{FORWARDS}");
    let lines = configured(&configuration, "ssh", "build-7.example", &options);
    for wanted in [
        "user dev",
        "sessiontype none",
        "batchmode yes",
        "exitonforwardfailure no",
        "loglevel INFO",
        "logverbose *:ssh_confirm_remote_forward():*",
        "tag hedwig",
        "forwardagent no",
        "forwardx11 no",
        "permitlocalcommand no",
        "controlmaster false",
        "serveraliveinterval 15",
        "serveralivecountmax 3",
        "localforward 8080 [127.0.0.1]:8080",
        "dynamicforward 1080",
    ] {
        assert!(has(&lines, wanted), "{wanted}: {lines:?}");
    }
    assert!(
        !lines.iter().any(|line| line.starts_with("controlpath ")),
        "no connection is shared"
    );
    let remote: Vec<&str> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("remoteforward "))
        .collect();
    assert_eq!(
        remote,
        [
            "/run/user/1000/gnupg/S.gpg-agent [127.0.0.1]:50123",
            "/home/a:b/S.agent [127.0.0.1]:50124",
            "5037 [127.0.0.1]:50125",
            "47470 [127.0.0.1]:47470",
        ]
    );
}

/// A person who wants their own forwards kept off the channel says so in
/// their configuration, by the tag the core gives it.
#[test]
fn a_configuration_can_keep_its_forwards_off_the_channel_by_its_tag() {
    let options = channel_options();
    let options: Vec<&str> = options.iter().map(String::as_str).collect();
    let configuration =
        format!("{CONTRARY}Match originalhost build-7.example !tagged hedwig\n{FORWARDS}");
    let lines = configured(&configuration, "ssh", "build-7.example", &options);
    assert!(has(&lines, "user dev"));
    let theirs = ["localforward ", "dynamicforward ", "remoteforward 47470 "];
    assert!(
        !lines
            .iter()
            .any(|line| theirs.iter().any(|forward| line.starts_with(forward))),
        "{lines:?}"
    );
    assert_eq!(
        lines
            .iter()
            .filter(|line| line.starts_with("remoteforward "))
            .count(),
        3
    );
}

/// The real client says what one named function logs, and nothing else it
/// would keep to itself, when told to: the means by which the core hears the
/// server's answer for each forward. Shown on a function that runs with no
/// server: the one that connects, sent to a loopback port nothing listens on.
/// The in-box client knows a file by the path it was built from, so a
/// pattern that names the file as the sources do matches nothing.
#[test]
fn the_real_client_says_what_one_function_logs_when_told_to() {
    let folder = Folder::new("verbose");
    let empty = folder.path().join("config");
    std::fs::write(&empty, "").unwrap();
    let closed = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let run = |verbose: &[&str]| {
        let output = Command::new(program("ssh").unwrap())
            .arg("-F")
            .arg(&empty)
            .args(["-o", "IdentityAgent=none", "-o", "BatchMode=yes"])
            .args(["-o", "LogLevel=INFO"])
            .args(verbose)
            .args(["-p", &closed.to_string(), "127.0.0.1"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(255));
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let quiet = run(&[]);
    assert!(!quiet.contains("debug"), "{quiet}");
    let told = run(&["-o", "LogVerbose=*:ssh_connect_direct():*"]);
    let said: Vec<&str> = told
        .lines()
        .filter(|line| line.starts_with("debug"))
        .collect();
    assert!(
        said.iter().any(|line| line.starts_with("debug1: ")),
        "{told}"
    );
    assert!(
        said.iter()
            .all(|line| line.contains(":ssh_connect_direct():") && line.contains("(pid=")),
        "{told}"
    );
    // Where the client writes the file with the folders it was built in, the
    // file's own name at the head of a pattern matches nothing.
    let named = run(&["-o", "LogVerbose=sshconnect.c:ssh_connect_direct():*"]);
    let built_from_a_path = said.iter().any(|line| line.contains(r"\sshconnect.c:"));
    assert_eq!(named.contains("debug"), !built_from_a_path, "{named}");
}
