//! Readiness against real shells and real tools, with no remote: the POSIX
//! script run by a real POSIX shell - Git for Windows' own `sh`, with its own
//! `GnuPG` 2.4 and real Unix-domain socket files - and the PowerShell script run
//! by Windows PowerShell with Gpg4win; what each prints read by the core's
//! own reader; and the in-box client's `-G` stating what a survey's options
//! leave of the person's configuration.
//!
//! Each `GnuPG` here has a home of the suite's own, so nothing reaches the
//! person's agent. Where Git for Windows, its Perl or Gpg4win is not
//! installed, the suites that need it say so and pass: they are evidence
//! only where the workstation has them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write as _};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hedwig_core::survey::{
    Answer, Asked, At, Dialect, Plan, Question, Report, Undo, command, exercise, exercised,
    options, posix, powershell, read, theirs,
};
use hedwig_model::capability::Query;
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{Fingerprint, Mark, Name, Port, RemotePath, Template, Variable};
use hedwig_model::trail::{Asking, Binding, Finding, Write};
use hedwig_support::{Folder, SCDAEMON_LOG, readerless};

const NONCE: &str = "0b7e2c4a91d35f6e8a7b0c1d2e3f4a5b";

const GIT: &str = r"C:\Program Files\Git";

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn msys(path: &Path) -> String {
    let text = path.to_str().unwrap().replace('\\', "/");
    let (drive, rest) = text.split_once(':').unwrap();
    format!("/{}{rest}", drive.to_ascii_lowercase())
}

/// Git for Windows' POSIX shell, with its own tools beside it.
fn posix_shell() -> PathBuf {
    let sh = Path::new(GIT).join(r"usr\bin\sh.exe");
    let tools = [
        "gpgconf.exe",
        "gpg-agent.exe",
        "gpg-connect-agent.exe",
        "perl.exe",
    ];
    assert!(
        sh.exists()
            && tools
                .iter()
                .all(|tool| Path::new(GIT).join(r"usr\bin").join(tool).exists()),
        "needs Git for Windows installed, with its GnuPG and Perl: {GIT}"
    );
    sh
}

/// A remote's shell and home, standing where a Unix remote's would: a home
/// of its own, a `GnuPG` home in it, git reading a configuration of the
/// home's, and on the search path the shell's own tools, then git, then
/// Windows' own `netstat`.
struct Remote {
    sh: PathBuf,
    folder: Folder,
    /// Short, since `GnuPG`'s own longest socket name must fit the shell's
    /// `sun_path` under it.
    home: PathBuf,
    path: String,
    shell: String,
    started: Vec<Child>,
}

impl Remote {
    fn new(sh: PathBuf, purpose: &str) -> Remote {
        let folder = Folder::new(purpose);
        let mut drawn = [0u8; 4];
        hedwig_win::random::fill(&mut drawn).unwrap();
        let home = std::env::temp_dir().join(format!("hs{:08x}", u32::from_le_bytes(drawn)));
        fs::create_dir_all(&home).unwrap();
        Remote {
            sh,
            path: "/usr/bin:/mingw64/bin:/c/Windows/System32".to_owned(),
            shell: "/usr/bin/fish".to_owned(),
            home,
            folder,
            started: Vec::new(),
        }
    }

    fn gnupg(&self) -> PathBuf {
        self.home.join(".gnupg")
    }

    fn socket(&self) -> PathBuf {
        self.gnupg().join("S.gpg-agent")
    }

    fn sh(&self, script: &str) -> String {
        let mut child = Command::new(&self.sh)
            .arg("-s")
            .env_clear()
            .env("PATH", &self.path)
            .env("HOME", msys(&self.home))
            .env("GNUPGHOME", msys(&self.gnupg()))
            .env("GIT_CONFIG_GLOBAL", msys(&self.home.join(".gitconfig")))
            .env("SHELL", &self.shell)
            .env("SYSTEMROOT", r"C:\Windows")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn survey(&self, plan: &Plan) -> Report {
        let output = self.sh(&posix(plan, NONCE));
        read(&output, NONCE).unwrap_or_else(|unread| panic!("{unread:?}: {output}"))
    }

    /// A real gpg-agent of this home's, as a remote user's own would run.
    fn agent(&self) -> u32 {
        readerless(&self.gnupg()).unwrap();
        self.sh("gpg-agent --daemon >/dev/null 2>&1");
        let said = self.sh("gpg-connect-agent 'GETINFO pid' /bye");
        said.lines()
            .find_map(|line| line.strip_prefix("D "))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    /// A listener of Perl's at the socket's path: one that never accepts,
    /// or one that answers as an agent does from a process on no host of
    /// the remote's.
    fn listener(&mut self, answering: bool) {
        readerless(&self.gnupg()).unwrap();
        let script = self.folder.path().join("listen.pl");
        fs::write(
            &script,
            r#"use IO::Socket::UNIX;
my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => $ARGV[0], Listen => 5) or die "bind: $!";
$| = 1;
print "listening\n";
if ($ARGV[1] eq 'answer') {
  while (my $c = $s->accept) {
    $c->autoflush(1);
    print $c "OK Pleased to meet you\n";
    while (my $line = <$c>) {
      if ($line =~ /^GETINFO pid/) { print $c "D 999999\nOK\n" }
      else { print $c "OK closing connection\n"; last }
    }
    close $c;
  }
}
sleep 120;
"#,
        )
        .unwrap();
        let mut child = Command::new(Path::new(GIT).join(r"usr\bin\perl.exe"))
            .arg(msys(&script))
            .arg(msys(&self.socket()))
            .arg(if answering { "answer" } else { "silent" })
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut first = [0u8; 10];
        child.stdout.take().unwrap().read_exact(&mut first).unwrap();
        assert_eq!(&first, b"listening\n");
        self.started.push(child);
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        for child in &mut self.started {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.gnupg().exists() {
            self.sh("gpgconf --kill all >/dev/null 2>&1");
        }
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn gpg_plan() -> Plan {
    Plan {
        asks: vec![Asked {
            capability: name("gpg"),
            server: None,
            questions: vec![Question::Socket(Query::AgentSocket)],
        }],
        ..Plan::default()
    }
}

fn gpg(report: &Report) -> &Answer {
    report.answers.get(&name("gpg")).unwrap()
}

fn at(report: &Report) -> Option<&At> {
    gpg(report)
        .place
        .as_ref()
        .and_then(|place| place.at.as_ref())
}

/// A fresh home: the path is `GnuPG`'s own answer, the folder it needs is
/// made, nothing is at the path, and `GnuPG` left to itself would start its
/// own agent. The report names the remote's system and the person's shell.
#[test]
fn a_fresh_home_is_made_ready_by_the_remotes_own_tools() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "survey-fresh");
    let report = remote.survey(&gpg_plan());
    assert_eq!(report.dialect, Dialect::Posix);
    assert!(report.kernel.as_str().starts_with("MSYS_NT"));
    assert_eq!(report.shell, b"/usr/bin/fish");
    let place = gpg(&report).place.as_ref().unwrap();
    assert_eq!(place.path, msys(&remote.socket()).as_bytes());
    assert_eq!(
        place.created.as_deref(),
        Some(msys(&remote.gnupg()).as_bytes())
    );
    assert!(remote.gnupg().is_dir());
    assert_eq!(place.at, Some(At::Free));
    assert_eq!(gpg(&report).autostart, Some(true));
    assert_eq!(gpg(&report).keyboxd, Some(false));
}

/// A socket the remote's own agent answers at is named and left running; a
/// socket whose agent died is removed; a listener that never answers is named
/// after it was asked twice; one that answers as an agent of no process on
/// the remote is another carrier's, named and left; and a file that is not a
/// socket is named and left.
#[test]
fn what_answers_at_the_path_is_left_and_only_what_nothing_answers_at_is_removed() {
    let sh = posix_shell();
    let mut remote = Remote::new(sh, "survey-sockets");
    let pid = remote.agent();
    assert_eq!(at(&remote.survey(&gpg_plan())), Some(&At::Agent));
    assert!(remote.socket().exists());
    assert!(
        remote
            .sh(&format!("kill -0 {pid} && echo alive"))
            .contains("alive")
    );

    remote.sh(&format!("kill -9 {pid}"));
    std::thread::sleep(Duration::from_millis(500));
    assert!(remote.socket().exists(), "the dead agent's socket stays");
    assert_eq!(at(&remote.survey(&gpg_plan())), Some(&At::Removed));
    assert!(!remote.socket().exists());

    remote.listener(false);
    let began = Instant::now();
    assert_eq!(at(&remote.survey(&gpg_plan())), Some(&At::Silent));
    assert!(began.elapsed() >= Duration::from_secs(6), "asked twice");
    assert!(remote.socket().exists());
    for mut child in remote.started.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
    fs::remove_file(remote.socket()).unwrap();

    remote.listener(true);
    assert_eq!(at(&remote.survey(&gpg_plan())), Some(&At::Answers));
    for mut child in remote.started.drain(..) {
        let _ = child.kill();
        let _ = child.wait();
    }
    fs::remove_file(remote.socket()).unwrap();

    fs::write(remote.socket(), "a note the person keeps here").unwrap();
    assert_eq!(at(&remote.survey(&gpg_plan())), Some(&At::Occupied));
    assert!(remote.socket().exists());
}

/// The path this connection's own forward holds is never probed.
#[test]
fn the_forwards_own_socket_is_not_probed() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "survey-ours");
    remote.agent();
    let mut plan = gpg_plan();
    plan.ours = vec![RemotePath::try_from(msys(&remote.socket()).as_str()).unwrap()];
    assert_eq!(at(&remote.survey(&plan)), Some(&At::Ours));
}

/// What `GnuPG`'s own configuration says is read from it: set not to start
/// an agent, with keys kept in keyboxd; a public key the keyring lacks; and
/// the signing key git names.
#[test]
fn what_stands_between_gpg_and_the_key_is_read_from_the_remotes_configuration() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "survey-cautions");
    readerless(&remote.gnupg()).unwrap();
    fs::write(
        remote.gnupg().join("common.conf"),
        "use-keyboxd\n  no-autostart\n",
    )
    .unwrap();
    fs::write(
        remote.home.join(".gitconfig"),
        "[user]\n\tsigningkey = 7F3A9C02D1E4B6A8!\n",
    )
    .unwrap();
    let key = Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let mut plan = gpg_plan();
    plan.keys = vec![key.clone()];
    let report = remote.survey(&plan);
    let answer = gpg(&report);
    assert_eq!(answer.autostart, Some(false));
    assert_eq!(answer.keyboxd, Some(true));
    assert_eq!(answer.keys, BTreeMap::from([(key, false)]));
    assert_eq!(answer.signing, Some(Some(b"7F3A9C02D1E4B6A8!".to_vec())));
    assert_eq!(answer.format, Some(Vec::new()));
}

/// A private socket's folder is made in the home where no runtime folder is
/// set, and a port something listens on is told from one nothing does.
#[test]
fn a_private_socket_and_a_port() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "survey-other");
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let busy = Port::try_from(taken.local_addr().unwrap().port()).unwrap();
    let free = {
        let spare = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        Port::try_from(spare.local_addr().unwrap().port()).unwrap()
    };
    let plan = Plan {
        asks: vec![
            Asked {
                capability: name("adb"),
                server: Some(name("adb")),
                questions: vec![
                    Question::Private {
                        variable: Variable::try_from("ADB_SERVER_SOCKET").unwrap(),
                        value: Template::try_from("localfilesystem:{}").unwrap(),
                    },
                    Question::Port(busy),
                ],
            },
            Asked {
                capability: name("openocd"),
                server: None,
                questions: vec![Question::Port(free)],
            },
        ],
        ..Plan::default()
    };
    let report = remote.survey(&plan);
    let adb = report.answers.get(&name("adb")).unwrap();
    let private = adb.place.as_ref().unwrap();
    let folder = msys(&remote.home.join(".hedwig"));
    assert_eq!(private.path, format!("{folder}/adb").as_bytes());
    assert_eq!(private.created.as_deref(), Some(folder.as_bytes()));
    assert_eq!(private.at, Some(At::Free));
    assert_eq!(adb.listeners.get(&busy), Some(&true));
    let openocd = report.answers.get(&name("openocd")).unwrap();
    assert_eq!(openocd.listeners.get(&free), Some(&false));
    drop(taken);
}

/// An opener's socket is placed in Hedwig's private folder and both
/// variables the remote's openers read are written into the login shell's
/// files as the exact command lines of the remote's `curl`; a remote with no
/// `curl` says so, and a socket path an opener would split leaves both
/// unwritten, saying why.
#[test]
fn an_openers_variables_name_the_remotes_own_curl_at_the_socket() {
    let sh = posix_shell();
    let mut remote = Remote::new(sh, "survey-opener");
    let variables = ["BROWSER", "GH_BROWSER"].map(|name| Variable::try_from(name).unwrap());
    let plan = Plan {
        asks: vec![Asked {
            capability: name("browser"),
            server: None,
            questions: vec![Question::Opener],
        }],
        writes: variables
            .iter()
            .map(|variable| (name("browser"), Write::Variable(variable.clone())))
            .collect(),
        ..Plan::default()
    };
    remote.shell = "/usr/bin/bash".to_owned();
    remote.path = "/usr/bin:/mingw64/bin".to_owned();
    let report = remote.survey(&plan);
    let browser = report.answers.get(&name("browser")).unwrap();
    assert_eq!(browser.absent, None, "Git for Windows' own curl");
    let socket = format!("{}/browser", msys(&remote.home.join(".hedwig")));
    let place = browser.place.as_ref().unwrap();
    assert_eq!(place.path, socket.as_bytes());
    assert_eq!(place.at, Some(At::Free));
    assert_eq!(
        browser.wrote.len(),
        4,
        "each variable into .bashrc and .profile"
    );
    for (variable, expected) in [
        (
            "BROWSER",
            format!("curl -q -fsS --noproxy hedwig --unix-socket {socket} --data-raw %s hedwig/"),
        ),
        (
            "GH_BROWSER",
            format!("curl -q -fsS --noproxy hedwig --unix-socket {socket} hedwig/ --data-raw"),
        ),
    ] {
        assert_eq!(
            remote.sh(&format!(
                "bash -c '. \"$HOME/.bashrc\"; printf %s \"${variable}\"'"
            )),
            expected
        );
    }

    remote.path = "/usr/bin".to_owned();
    let report = remote.survey(&plan);
    assert_eq!(
        report.answers.get(&name("browser")).unwrap().absent,
        Some(name("curl"))
    );

    let runtime = remote.home.join("run time");
    fs::create_dir_all(&runtime).unwrap();
    let script = format!(
        "XDG_RUNTIME_DIR='{}'\nexport XDG_RUNTIME_DIR\n{}",
        msys(&runtime),
        posix(&plan, NONCE)
    );
    let output = remote.sh(&script);
    let report = read(&output, NONCE).unwrap();
    let unwritten: Vec<&Write> = report
        .answers
        .get(&name("browser"))
        .unwrap()
        .unwritten
        .iter()
        .map(|(write, _)| write)
        .collect();
    assert_eq!(
        unwritten,
        variables
            .iter()
            .map(|variable| Write::Variable(variable.clone()))
            .collect::<Vec<_>>()
            .iter()
            .collect::<Vec<_>>()
    );
}

/// A shell that is not POSIX runs the POSIX survey's command and prints
/// nothing the reader takes for a report: the core then asks in PowerShell.
#[test]
fn a_windows_shell_given_the_posix_command_prints_no_report() {
    let posix_command = command(Dialect::Posix).join(" ");
    for (shell, option) in [("cmd.exe", "/c"), ("powershell.exe", "-Command")] {
        let output = Command::new(shell)
            .args([option, posix_command.as_str()])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{shell}");
        let printed = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            read(&printed, NONCE),
            Err(hedwig_core::survey::Unread::NotBegun)
        );
    }
}

/// The PowerShell survey, run the way a Windows remote runs it - Windows
/// PowerShell reading the script from its input, started by the command the
/// core gives - with Gpg4win named by git's `gpg.program`: the path is that
/// `GnuPG`'s own answer for the home, a socket file naming a port nothing
/// listens on is removed, one naming a port a process other than gpg-agent
/// listens on is another carrier's, and a file in the Cygwin form is not
/// Gpg4win's.
#[test]
#[ignore = "needs GnuPG for Windows installed and registered, as Gpg4win registers it"]
#[allow(
    clippy::too_many_lines,
    reason = "one Windows home, each state of its socket file"
)]
fn the_powershell_survey_reads_a_windows_remotes_gnupg() {
    let gpg4win = registered_gnupg().join("gpg.exe");
    let folder = Folder::new("survey-windows");
    let home = folder.path().join("gnupg");
    readerless(&home).unwrap();
    let config = folder.path().join("gitconfig");
    fs::write(
        &config,
        format!(
            "[gpg]\n\tprogram = {}\n",
            gpg4win.to_str().unwrap().replace('\\', "/")
        ),
    )
    .unwrap();
    let listening = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = Port::try_from(listening.local_addr().unwrap().port()).unwrap();
    let plan = Plan {
        asks: vec![
            Asked {
                capability: name("gpg"),
                server: None,
                questions: vec![Question::Socket(Query::AgentSocket)],
            },
            Asked {
                capability: name("adb"),
                server: Some(name("adb")),
                questions: vec![Question::Port(port)],
            },
        ],
        ..Plan::default()
    };
    let survey = |script: &str| {
        let arguments = command(Dialect::PowerShell);
        let mut child = Command::new("powershell.exe")
            .args(arguments.get(1..).unwrap())
            .env("GNUPGHOME", &home)
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        read(&printed, NONCE).unwrap_or_else(|unread| {
            panic!(
                "{unread:?}: {printed} {}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
    };
    let report = survey(&powershell(&plan, NONCE));
    assert_eq!(report.dialect, Dialect::PowerShell);
    assert_eq!(report.kernel.as_str(), "Windows_NT");
    let place = gpg(&report).place.clone().unwrap();
    let path = PathBuf::from(String::from_utf8(place.path).unwrap());
    let socketdir = path.parent().unwrap().to_path_buf();
    let cleanup = Cleanup(socketdir.clone());
    assert!(
        path.ends_with("S.gpg-agent")
            && socketdir
                .to_str()
                .unwrap()
                .contains(r"\AppData\Local\gnupg\d."),
        "{path:?}"
    );
    assert_eq!(place.at, Some(At::Free));
    assert_eq!(gpg(&report).autostart, Some(true));
    assert_eq!(
        report
            .answers
            .get(&name("adb"))
            .unwrap()
            .listeners
            .get(&port),
        Some(&true)
    );

    let nonce = [7u8; 16];
    let closed = {
        let spare = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        spare.local_addr().unwrap().port()
    };
    fs::create_dir_all(&socketdir).unwrap();
    let file = |port: u16| {
        let mut bytes = format!("{port}\n").into_bytes();
        bytes.extend_from_slice(&nonce);
        bytes
    };
    fs::write(&path, file(closed)).unwrap();
    assert_eq!(at(&survey(&powershell(&plan, NONCE))), Some(&At::Removed));
    assert!(!path.exists());

    fs::write(&path, file(port.number())).unwrap();
    assert_eq!(at(&survey(&powershell(&plan, NONCE))), Some(&At::Answers));
    assert!(path.exists());

    fs::write(
        &path,
        b"!<socket >60124 s 00000000-00000000-00000000-00000000",
    )
    .unwrap();
    assert_eq!(at(&survey(&powershell(&plan, NONCE))), Some(&At::Occupied));
    drop(listening);
    drop(cleanup);
}

/// The socket folder Gpg4win uses for the suite's home is the suite's, in
/// the person's local application data, and goes with it.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What the in-box client states with `-G`: the person's forwards and the
/// options that would take a survey's command or input, as their
/// configuration gives them; the forwards scoped away from Hedwig's
/// connections gone under its tag; and, under the survey's own options,
/// none of them.
#[test]
fn the_in_box_client_states_what_a_survey_leaves_of_the_persons_configuration() {
    let ssh = Path::new(r"C:\Windows\System32\OpenSSH\ssh.exe");
    let folder = Folder::new("survey-stated");
    let config = folder.path().join("config");
    fs::write(
        &config,
        "Host build-7\n    HostName 127.0.0.1\n    LocalForward 8080 localhost:80\n    \
         DynamicForward 1080\n    RemoteForward /run/user/1000/gnupg/S.gpg-agent 127.0.0.1:47470\n    \
         RemoteCommand echo hi\n    SessionType none\n    StdinNull yes\n    \
         ForkAfterAuthentication yes\nHost scoped\n    HostName 127.0.0.1\n\
         Match originalhost scoped !tagged hedwig\n    LocalForward 8081 localhost:80\n",
    )
    .unwrap();
    let stated = |extra: &[String], host: &str| {
        let output = Command::new(ssh)
            .arg("-F")
            .arg(&config)
            .args(extra)
            .args(["-G", host])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    let tagged = ["-o".to_owned(), "Tag=hedwig".to_owned()];
    let forwards = |text: &str| -> Vec<String> {
        theirs(text)
            .into_iter()
            .map(|forward| forward.as_str().to_owned())
            .collect()
    };
    let person = stated(&tagged, "build-7");
    assert_eq!(
        forwards(&person),
        [
            "dynamicforward 1080",
            "localforward 8080 [localhost]:80",
            "remoteforward /run/user/1000/gnupg/S.gpg-agent [127.0.0.1]:47470",
        ]
    );
    for line in [
        "remotecommand echo hi",
        "sessiontype none",
        "stdinnull yes",
        "forkafterauthentication yes",
    ] {
        assert!(person.lines().any(|given| given == line), "{line}");
    }
    assert_eq!(forwards(&stated(&tagged, "scoped")), Vec::<String>::new());
    assert_eq!(
        forwards(&stated(&[], "scoped")),
        ["localforward 8081 [localhost]:80"]
    );

    let survey = stated(&options(Asking::Nobody, Keepalive::SHIPS), "build-7");
    assert_eq!(forwards(&survey), Vec::<String>::new());
    for line in [
        "clearallforwardings yes",
        "sessiontype default",
        "stdinnull no",
        "forkafterauthentication no",
        "requesttty false",
        "escapechar none",
        "batchmode yes",
        "tag hedwig",
    ] {
        assert!(survey.lines().any(|given| given == line), "{line}");
    }
    assert!(
        !survey
            .lines()
            .any(|given| given.starts_with("remotecommand"))
    );

    let channel = stated(
        &hedwig_core::channel::SET
            .iter()
            .flat_map(|set| ["-o".to_owned(), (*set).to_owned()])
            .collect::<Vec<_>>(),
        "build-7",
    );
    assert!(
        channel
            .lines()
            .any(|given| given == "forkafterauthentication no")
    );
}

/// The `bin` folder of the `GnuPG` for Windows installation the system
/// registers - Gpg4win's, or `GnuPG`'s own - found as the relay finds it.
fn registered_gnupg() -> PathBuf {
    hedwig_core::relay::gpgconf(&hedwig_model::capability::Installation::Registered)
        .ok()
        .and_then(|gpgconf| gpgconf.parent().map(Path::to_path_buf))
        .filter(|bin| bin.join("gpg.exe").exists())
        .expect("needs GnuPG for Windows installed and registered, as Gpg4win registers it")
}

fn write_plan(writes: Vec<Write>) -> Plan {
    Plan {
        writes: writes
            .into_iter()
            .map(|write| (name("gpg"), write))
            .collect(),
        ..gpg_plan()
    }
}

fn places<T>(made: &[(Write, Vec<u8>, T)]) -> Vec<(Write, String)> {
    made.iter()
        .map(|(write, place, _)| (write.clone(), String::from_utf8(place.clone()).unwrap()))
        .collect()
}

/// The places of what was found or taken back, which carry no folder.
fn found(list: &[(Write, Vec<u8>)]) -> Vec<(Write, String)> {
    list.iter()
        .map(|(write, place)| (write.clone(), String::from_utf8(place.clone()).unwrap()))
        .collect()
}

/// A write to take back that made no folder.
fn taken(capability: &str, write: Write, place: RemotePath) -> Undo {
    Undo {
        capability: name(capability),
        write,
        place,
        made: None,
    }
}

/// The writes a grant consents to, made by the remote's own shell: each in
/// lines marked as Hedwig's, after what the person had there; found again
/// and left as they are on the next survey; and taken back so the files are
/// what they were, byte for byte. `git` reads the signing key from them.
#[test]
fn a_consented_write_is_marked_kept_and_taken_back_to_the_byte() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "writes-round");
    readerless(&remote.gnupg()).unwrap();
    let common = remote.gnupg().join("common.conf");
    let gitconfig = remote.home.join(".gitconfig");
    let theirs = "# the person's own\nkeyserver hkps://keys.example\n";
    fs::write(&common, theirs).unwrap();
    fs::write(&gitconfig, "[core]\n\teditor = vi\n").unwrap();
    let key = Mark::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let plan = write_plan(vec![Write::NoAutostart, Write::SigningKey(key.clone())]);

    let report = remote.survey(&plan);
    assert_eq!(
        places(&gpg(&report).wrote),
        [
            (Write::NoAutostart, msys(&common)),
            (Write::SigningKey(key.clone()), msys(&gitconfig)),
        ]
    );
    assert_eq!(gpg(&report).autostart, Some(false));
    let written = fs::read_to_string(&common).unwrap();
    assert!(written.starts_with(theirs));
    assert!(written.contains("\n# hedwig gpg no-autostart: written by Hedwig with your consent"));
    assert_eq!(
        remote
            .sh("git config --global --get user.signingkey")
            .trim(),
        key.as_str()
    );

    let again = remote.survey(&plan);
    assert_eq!(
        gpg(&again).wrote,
        Vec::<(Write, Vec<u8>, Option<Vec<u8>>)>::new()
    );
    assert_eq!(gpg(&again).kept.len(), 2);
    assert_eq!(fs::read_to_string(&common).unwrap(), written);

    let undo = Plan {
        undo: vec![
            taken(
                "gpg",
                Write::NoAutostart,
                RemotePath::try_from(msys(&common).as_str()).unwrap(),
            ),
            taken(
                "gpg",
                Write::SigningKey(key),
                RemotePath::try_from(msys(&gitconfig).as_str()).unwrap(),
            ),
        ],
        ..gpg_plan()
    };
    let report = remote.survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 2);
    assert_eq!(fs::read_to_string(&common).unwrap(), theirs);
    assert_eq!(
        fs::read_to_string(&gitconfig).unwrap(),
        "[core]\n\teditor = vi\n"
    );
    assert_eq!(gpg(&report).autostart, Some(true));
}

/// The lines an earlier build wrote, whose marker named the application in
/// lower case: found as Hedwig's, written again with today's marker, and
/// taken back to the byte, by the remote's own POSIX shell.
#[test]
fn a_marker_an_earlier_build_wrote_is_written_again_and_taken_back() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "writes-earlier");
    readerless(&remote.gnupg()).unwrap();
    let common = remote.gnupg().join("common.conf");
    let theirs = "# the person's own\nkeyserver hkps://keys.example\n";
    let earlier = format!("{theirs}{EARLIER_BLOCK}");
    fs::write(&common, &earlier).unwrap();
    let plan = write_plan(vec![Write::NoAutostart]);

    let report = remote.survey(&plan);
    assert_eq!(
        places(&gpg(&report).wrote),
        [(Write::NoAutostart, msys(&common))]
    );
    let written = fs::read_to_string(&common).unwrap();
    assert!(written.starts_with(theirs), "{written}");
    assert!(written.contains(&format!("\n{MARKER}\n")), "{written}");
    assert!(!written.contains("written by hedwig"), "{written}");
    let again = remote.survey(&plan);
    assert_eq!(gpg(&again).kept.len(), 1);

    fs::write(&common, &earlier).unwrap();
    let undo = Plan {
        undo: vec![taken(
            "gpg",
            Write::NoAutostart,
            RemotePath::try_from(msys(&common).as_str()).unwrap(),
        )],
        ..gpg_plan()
    };
    let report = remote.survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 1);
    assert_eq!(fs::read_to_string(&common).unwrap(), theirs);
}

/// The same on a Windows remote, by its own PowerShell.
#[test]
#[ignore = "needs GnuPG for Windows installed and registered, as Gpg4win registers it"]
fn a_windows_remote_s_earlier_marker_is_written_again_and_taken_back() {
    let gpg4win = registered_gnupg().join("gpg.exe");
    let folder = Folder::new("writes-windows-earlier");
    let home = folder.path().join("gnupg");
    readerless(&home).unwrap();
    let config = folder.path().join("gitconfig");
    fs::write(
        &config,
        format!(
            "[gpg]\n\tprogram = {}\n",
            gpg4win.to_str().unwrap().replace('\\', "/")
        ),
    )
    .unwrap();
    let survey = |plan: &Plan| {
        let mut child = Command::new("powershell.exe")
            .args(command(Dialect::PowerShell).get(1..).unwrap())
            .env("GNUPGHOME", &home)
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(powershell(plan, NONCE).as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        read(&String::from_utf8_lossy(&output.stdout), NONCE).unwrap()
    };
    let common = home.join("common.conf");
    let theirs = "# the person's own\nkeyserver hkps://keys.example\n";
    let earlier = format!("{theirs}{EARLIER_BLOCK}");
    fs::write(&common, &earlier).unwrap();

    let report = survey(&write_plan(vec![Write::NoAutostart]));
    assert_eq!(
        places(&gpg(&report).wrote),
        [(Write::NoAutostart, common.to_str().unwrap().to_owned())]
    );
    let written = fs::read_to_string(&common).unwrap();
    assert!(written.starts_with(theirs), "{written}");
    assert!(written.contains(&format!("\n{MARKER}\n")), "{written}");
    assert!(!written.contains("written by hedwig"), "{written}");

    fs::write(&common, &earlier).unwrap();
    let undo = Plan {
        undo: vec![taken(
            "gpg",
            Write::NoAutostart,
            RemotePath::try_from(common.to_str().unwrap()).unwrap(),
        )],
        ..gpg_plan()
    };
    let report = survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 1);
    assert_eq!(fs::read_to_string(&common).unwrap(), theirs);
}

/// The lines a build before the application's name was capitalised wrote
/// for `no-autostart`.
const EARLIER_BLOCK: &str = "# hedwig gpg no-autostart: written by hedwig with your consent; hedwig removes it when that ends\nno-autostart\n# hedwig gpg no-autostart: end\n";

/// The marker written now for `no-autostart`.
const MARKER: &str = "# hedwig gpg no-autostart: written by Hedwig with your consent; Hedwig removes it when that ends";

/// What the person set is never replaced, and a write that would break the
/// remote's own `GnuPG` is not made: their own `no-autostart` and signing key
/// stand, and keys kept in keyboxd keep `no-autostart` out, said.
#[test]
fn what_the_person_set_is_never_replaced() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "writes-theirs");
    readerless(&remote.gnupg()).unwrap();
    fs::write(remote.gnupg().join("gpg.conf"), "no-autostart\n").unwrap();
    fs::write(
        remote.home.join(".gitconfig"),
        "[user]\n\tsigningkey = DEADBEEF\n",
    )
    .unwrap();
    let key = Mark::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let plan = write_plan(vec![Write::NoAutostart, Write::SigningKey(key)]);
    let report = remote.survey(&plan);
    assert!(gpg(&report).wrote.is_empty() && gpg(&report).unwritten.is_empty());
    assert!(!remote.gnupg().join("common.conf").exists());
    assert_eq!(
        fs::read_to_string(remote.home.join(".gitconfig")).unwrap(),
        "[user]\n\tsigningkey = DEADBEEF\n"
    );

    fs::remove_file(remote.gnupg().join("gpg.conf")).unwrap();
    fs::write(remote.gnupg().join("common.conf"), "use-keyboxd\n").unwrap();
    let report = remote.survey(&write_plan(vec![Write::NoAutostart]));
    assert_eq!(
        found(&gpg(&report).unwritten),
        [(
            Write::NoAutostart,
            "its keys are in keyboxd, which gpg could no longer start".to_owned()
        )]
    );
    assert_eq!(
        fs::read_to_string(remote.gnupg().join("common.conf")).unwrap(),
        "use-keyboxd\n"
    );
}

/// A tool's variable goes where the person's login shell reads it: bash's
/// `.bashrc` and its login file, zsh's `.zshenv`, fish's `config.fish`;
/// bash, reading `.bashrc`, then has it. A shell whose startup files Hedwig
/// does not know is said, and nothing written.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one home through every login shell's own files, then the reversal"
)]
fn a_variable_goes_where_the_login_shell_reads_it() {
    let sh = posix_shell();
    let mut remote = Remote::new(sh, "writes-variable");
    let variable = Variable::try_from("ADB_SERVER_SOCKET").unwrap();
    let plan = Plan {
        asks: vec![Asked {
            capability: name("adb"),
            server: Some(name("adb")),
            questions: vec![Question::Private {
                variable: variable.clone(),
                value: Template::try_from("localfilesystem:{}").unwrap(),
            }],
        }],
        writes: vec![(name("adb"), Write::Variable(variable.clone()))],
        ..Plan::default()
    };
    let value = format!("localfilesystem:{}/adb", msys(&remote.home.join(".hedwig")));
    let adb = |report: &Report| report.answers.get(&name("adb")).unwrap().clone();
    let mut undo = Vec::new();
    let mut took = |report: &Report| {
        for (write, place, made) in adb(report).wrote {
            undo.push(Undo {
                capability: name("adb"),
                write,
                place: RemotePath::try_from(String::from_utf8(place).unwrap().as_str()).unwrap(),
                made: made.map(|made| {
                    RemotePath::try_from(String::from_utf8(made).unwrap().as_str()).unwrap()
                }),
            });
        }
    };

    // Ubuntu's own `.bashrc` returns at once for a shell that is not
    // interactive, which is what a command run over SSH has.
    let person =
        "# ~/.bashrc\ncase $- in\n    *i*) ;;\n      *) return;;\nesac\nalias ll='ls -l'\n";
    fs::write(remote.home.join(".bashrc"), person).unwrap();
    remote.shell = "/usr/bin/bash".to_owned();
    let report = remote.survey(&plan);
    let bashrc = msys(&remote.home.join(".bashrc"));
    let profile = msys(&remote.home.join(".profile"));
    assert_eq!(
        places(&adb(&report).wrote),
        [
            (Write::Variable(variable.clone()), bashrc.clone()),
            (Write::Variable(variable.clone()), profile.clone()),
        ]
    );
    took(&report);
    let written = fs::read_to_string(remote.home.join(".bashrc")).unwrap();
    assert!(written.starts_with("# hedwig adb ADB_SERVER_SOCKET: written by Hedwig"));
    assert!(written.ends_with(person));
    assert_eq!(
        remote.sh("bash -c '. \"$HOME/.bashrc\"; printf %s \"$ADB_SERVER_SOCKET\"'"),
        value
    );

    remote.shell = "/usr/bin/zsh".to_owned();
    let report = remote.survey(&plan);
    assert_eq!(
        places(&adb(&report).wrote),
        [(
            Write::Variable(variable.clone()),
            msys(&remote.home.join(".zshenv"))
        )]
    );
    took(&report);
    assert!(
        fs::read_to_string(remote.home.join(".zshenv"))
            .unwrap()
            .contains(&format!("export ADB_SERVER_SOCKET='{value}'"))
    );

    remote.shell = "/usr/bin/fish".to_owned();
    let report = remote.survey(&plan);
    let config = remote.home.join(".config");
    let fish = config.join(r"fish\config.fish");
    assert_eq!(
        adb(&report).wrote,
        [(
            Write::Variable(variable.clone()),
            msys(&fish).into_bytes(),
            Some(msys(&config).into_bytes())
        )]
    );
    took(&report);
    assert!(
        fs::read_to_string(&fish)
            .unwrap()
            .contains(&format!("set -gx ADB_SERVER_SOCKET '{value}'"))
    );

    // tcsh reads `.cshrc` where it finds no `.tcshrc`, and csh then finds
    // Hedwig's lines already there.
    remote.shell = "/bin/tcsh".to_owned();
    let report = remote.survey(&plan);
    let cshrc = remote.home.join(".cshrc");
    assert_eq!(
        places(&adb(&report).wrote),
        [(Write::Variable(variable.clone()), msys(&cshrc))]
    );
    took(&report);
    assert!(
        fs::read_to_string(&cshrc)
            .unwrap()
            .contains(&format!("setenv ADB_SERVER_SOCKET '{value}'"))
    );
    remote.shell = "/bin/csh".to_owned();
    assert_eq!(
        found(&adb(&remote.survey(&plan)).kept),
        [(Write::Variable(variable.clone()), msys(&cshrc))]
    );

    // A POSIX shell's login reads `.profile`, where bash's lines already are.
    for shell in ["/bin/dash", "/bin/ksh", "/bin/mksh", "/bin/sh"] {
        remote.shell = shell.to_owned();
        let report = remote.survey(&plan);
        assert!(adb(&report).wrote.is_empty(), "{shell}");
        assert_eq!(
            found(&adb(&report).kept),
            [(Write::Variable(variable.clone()), profile.clone())],
            "{shell}"
        );
    }

    // nushell is not on this shell's path, so its own folder is taken.
    remote.shell = "/usr/bin/nu".to_owned();
    let report = remote.survey(&plan);
    let nu = config.join(r"nushell\config.nu");
    assert_eq!(
        adb(&report).wrote,
        [(
            Write::Variable(variable.clone()),
            msys(&nu).into_bytes(),
            Some(msys(&config.join("nushell")).into_bytes())
        )]
    );
    took(&report);
    assert!(
        fs::read_to_string(&nu)
            .unwrap()
            .contains(&format!("$env.ADB_SERVER_SOCKET = \"{value}\""))
    );

    remote.shell = "/usr/bin/xonsh".to_owned();
    let report = remote.survey(&plan);
    assert_eq!(
        adb(&report).wrote,
        Vec::<(Write, Vec<u8>, Option<Vec<u8>>)>::new()
    );
    assert!(matches!(
        adb(&report).unwritten.as_slice(),
        [(Write::Variable(_), why)] if String::from_utf8_lossy(why).contains("does not know")
    ));

    remote.survey(&Plan {
        undo,
        ..Plan::default()
    });
    assert_eq!(
        fs::read_to_string(remote.home.join(".bashrc")).unwrap(),
        person
    );
    for file in [".profile", ".zshenv", ".cshrc"] {
        assert!(!remote.home.join(file).exists(), "{file}");
    }
    assert!(!config.exists());
}

/// The public key a grant consents to is imported into the remote's keyring
/// where it lacks it, and deleted when the consent ends.
#[test]
fn a_public_key_is_imported_and_taken_back() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "writes-key");
    readerless(&remote.gnupg()).unwrap();
    readerless(&remote.home.join("other")).unwrap();
    let other = msys(&remote.home.join("other"));
    let made = remote.sh(&format!(
        "mkdir -p {other} && export GNUPGHOME={other} && \
         gpg --batch --passphrase '' --quick-gen-key 'hedwig test <test@hedwig.example>' ed25519 sign never >/dev/null 2>&1 && \
         gpg --with-colons --list-keys | awk -F: '/^fpr/ {{ print $10; exit }}' && \
         gpg --armor --export test@hedwig.example; gpgconf --kill all"
    ));
    let (fingerprint, armoured) = made.split_once('\n').unwrap();
    let key = Fingerprint::try_from(fingerprint.trim()).unwrap();
    let mut plan = write_plan(vec![Write::PublicKey(key.clone())]);
    plan.keys = vec![key.clone()];
    plan.armoured
        .insert(key.clone(), armoured.trim().to_owned());
    let report = remote.survey(&plan);
    assert_eq!(
        places(&gpg(&report).wrote),
        [(Write::PublicKey(key.clone()), msys(&remote.gnupg()))]
    );
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key.clone(), true)]));

    let undo = Plan {
        undo: vec![taken(
            "gpg",
            Write::PublicKey(key.clone()),
            RemotePath::try_from(msys(&remote.gnupg()).as_str()).unwrap(),
        )],
        keys: vec![key.clone()],
        ..gpg_plan()
    };
    let report = remote.survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 1);
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key, false)]));
}

/// On a Windows remote, Gpg4win's `no-autostart` in its own `common.conf`
/// and the socket file its `gpg` reads: a free loopback port, a line feed and
/// the sixteen bytes issued; both taken back when the consent ends.
#[test]
#[ignore = "needs GnuPG for Windows installed and registered, as Gpg4win registers it"]
fn a_windows_remote_is_given_its_socket_file_and_no_autostart() {
    let gpg4win = registered_gnupg().join("gpg.exe");
    let folder = Folder::new("writes-windows");
    let home = folder.path().join("gnupg");
    readerless(&home).unwrap();
    let config = folder.path().join("gitconfig");
    fs::write(
        &config,
        format!(
            "[gpg]\n\tprogram = {}\n",
            gpg4win.to_str().unwrap().replace('\\', "/")
        ),
    )
    .unwrap();
    let issued: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut plan = write_plan(vec![Write::NoAutostart, Write::SocketFile]);
    plan.issued = Some(issued);
    let survey = |plan: &Plan| {
        let mut child = Command::new("powershell.exe")
            .args(command(Dialect::PowerShell).get(1..).unwrap())
            .env("GNUPGHOME", &home)
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(powershell(plan, NONCE).as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        read(&String::from_utf8_lossy(&output.stdout), NONCE).unwrap()
    };
    let report = survey(&plan);
    let path = PathBuf::from(String::from_utf8(gpg(&report).place.clone().unwrap().path).unwrap());
    let cleanup = Cleanup(path.parent().unwrap().to_path_buf());
    let common = home.join("common.conf");
    assert_eq!(
        places(&gpg(&report).wrote),
        [
            (Write::NoAutostart, common.to_str().unwrap().to_owned()),
            (Write::SocketFile, path.to_str().unwrap().to_owned()),
        ]
    );
    assert_eq!(gpg(&report).autostart, Some(false));
    let port = gpg(&report).socket_port.unwrap();
    let mut expected = format!("{port}\n").into_bytes();
    expected.extend_from_slice(&issued);
    assert_eq!(fs::read(&path).unwrap(), expected);

    let undo = Plan {
        undo: vec![
            taken(
                "gpg",
                Write::NoAutostart,
                RemotePath::try_from(common.to_str().unwrap()).unwrap(),
            ),
            taken(
                "gpg",
                Write::SocketFile,
                RemotePath::try_from(path.to_str().unwrap()).unwrap(),
            ),
        ],
        ..gpg_plan()
    };
    let report = survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 2);
    assert!(!common.exists() && !path.exists());
    drop(cleanup);
}

/// On a Windows remote too, a write whose file is in folders that did not
/// exist reports the outermost one it made, and the reversal takes the file
/// and those folders back.
#[test]
#[ignore = "needs GnuPG for Windows installed and registered, as Gpg4win registers it"]
fn a_windows_write_reports_the_folder_it_made_and_its_reversal_removes_it() {
    let gpg4win = registered_gnupg();
    let folder = Folder::new("writes-windows-made");
    let home = folder.path().join("gnupg");
    readerless(&home).unwrap();
    let made = folder.path().join("xdg");
    let config = made.join(r"git\config");
    let key = Mark::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let survey = |plan: &Plan| {
        let path = format!("{};{}", gpg4win.display(), std::env::var("PATH").unwrap());
        let mut child = Command::new("powershell.exe")
            .args(command(Dialect::PowerShell).get(1..).unwrap())
            .env("PATH", path)
            .env("GNUPGHOME", &home)
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(powershell(plan, NONCE).as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        read(&String::from_utf8_lossy(&output.stdout), NONCE).unwrap()
    };
    let report = survey(&write_plan(vec![Write::SigningKey(key.clone())]));
    let sockets = gpg(&report).place.clone().map(|place| {
        Cleanup(
            PathBuf::from(String::from_utf8(place.path).unwrap())
                .parent()
                .unwrap()
                .to_path_buf(),
        )
    });
    assert_eq!(
        gpg(&report).wrote,
        [(
            Write::SigningKey(key.clone()),
            config.to_str().unwrap().as_bytes().to_vec(),
            Some(made.to_str().unwrap().as_bytes().to_vec())
        )]
    );
    let report = survey(&Plan {
        undo: vec![Undo {
            capability: name("gpg"),
            write: Write::SigningKey(key),
            place: RemotePath::try_from(config.to_str().unwrap()).unwrap(),
            made: Some(RemotePath::try_from(made.to_str().unwrap()).unwrap()),
        }],
        ..gpg_plan()
    });
    assert_eq!(gpg(&report).unwrote.len(), 1);
    assert!(!made.exists());
    drop(sockets);
}

/// A real-remote run's plan is given as words, each read as the plan the core
/// would make, and what it cannot take is told apart: a word that is none of
/// a plan's, a capability nothing defines, a report the core's reader
/// refuses, and a system no profile answers to.
#[test]
fn experiment_e1s_plan_is_read_from_words_and_what_it_cannot_take_is_named() {
    use hedwig_support::experiment::{Unusable, account, plan};
    let key = "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2";
    let words: Vec<String> = [
        "ask=gpg".to_owned(),
        format!("key={key}"),
        "ours=/run/user/1000/gnupg/S.gpg-agent".to_owned(),
        "write=gpg/no-autostart".to_owned(),
        format!("write=gpg/signing-key:{key}"),
        "undo=ssh-agent/variable:SSH_AUTH_SOCK=/home/dev/.bashrc".to_owned(),
    ]
    .into();
    let mark = Mark::try_from(key).unwrap();
    assert_eq!(
        plan(&words).unwrap(),
        Plan {
            asks: gpg_plan().asks,
            ours: vec![RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap()],
            keys: vec![Fingerprint::try_from(key).unwrap()],
            writes: vec![
                (name("gpg"), Write::NoAutostart),
                (name("gpg"), Write::SigningKey(mark)),
            ],
            undo: vec![taken(
                "ssh-agent",
                Write::Variable(Variable::try_from("SSH_AUTH_SOCK").unwrap()),
                RemotePath::try_from("/home/dev/.bashrc").unwrap(),
            )],
            ..Plan::default()
        }
    );
    for word in [
        "frob",
        "write=gpg/nothing",
        "undo=gpg/no-autostart",
        "ask=Not A Name",
    ] {
        assert_eq!(
            plan(&[word.to_owned()]),
            Err(Unusable::Word(word.to_owned()))
        );
    }
    assert!(matches!(
        plan(&["ask=nothing-defines-this".to_owned()]),
        Err(Unusable::Capability(_))
    ));
    assert_eq!(
        account("", NONCE, ""),
        Err(Unusable::Report("NotBegun".to_owned()))
    );
    let haiku = format!(
        "hedwig {NONCE} begin posix\nhedwig {NONCE} kernel 4861696b75\nhedwig {NONCE} end\n"
    );
    assert!(matches!(
        account(&haiku, NONCE, ""),
        Err(Unusable::Platform(_))
    ));
}

/// A real-remote run's survey: the script `child survey script` writes is
/// the core's for the plan, and what the remote prints is read and placed as
/// the core does it. Git for Windows' `sh` is a system no profile answers to,
/// so its kernel line is given as a Linux remote's.
#[test]
fn experiment_e1_runs_the_cores_own_survey_and_reads_it_as_the_core_does() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "survey-experiment");
    let child = PathBuf::from(env!("CARGO_BIN_EXE_child"));
    let run = |what: &str, arguments: &[&str]| {
        let output = Command::new(&child)
            .arg("survey")
            .arg(what)
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    assert_eq!(
        run("options", &[]).lines().collect::<Vec<_>>(),
        options(Asking::Nobody, Keepalive::SHIPS)
    );
    assert_eq!(
        run("command", &[]).lines().collect::<Vec<_>>(),
        command(Dialect::Posix)
    );
    let script = remote.folder.path().join("survey.sh");
    let printed = remote.folder.path().join("printed");
    let survey = |expected: &str| -> Vec<String> {
        run("script", &[NONCE, script.to_str().unwrap(), "ask=gpg"]);
        let written = fs::read_to_string(&script).unwrap();
        assert_eq!(written, posix(&gpg_plan(), NONCE));
        let linux = format!("hedwig {NONCE} kernel 4c696e7578");
        let output: String = remote
            .sh(&written)
            .lines()
            .map(|line| {
                if line.starts_with(&format!("hedwig {NONCE} kernel ")) {
                    format!("{linux}\n")
                } else {
                    format!("{line}\n")
                }
            })
            .collect();
        fs::write(&printed, output).unwrap();
        let lines: Vec<String> = run("read", &[NONCE, printed.to_str().unwrap()])
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            lines.first().map(String::as_str),
            Some(r#"{"kernel":"Linux","platform":"linux","shell":"/usr/bin/fish"}"#)
        );
        let gpg = lines.get(1).unwrap();
        assert!(gpg.contains(&format!(r#""at":"{expected}""#)), "{gpg}");
        lines
    };
    let pid = remote.agent();
    let live = survey("agent");
    let gpg = live.get(1).unwrap();
    assert!(gpg.contains(r#"{"agent-live":"#), "{gpg}");
    assert!(
        gpg.contains(r#""blocking":1"#) && gpg.contains(r#""carried":false"#),
        "{gpg}"
    );

    remote.sh(&format!("kill -9 {pid}"));
    std::thread::sleep(Duration::from_millis(500));
    let cleared = survey("removed");
    let gpg = cleared.get(1).unwrap();
    let path = msys(&remote.socket());
    assert!(
        gpg.contains(&format!(r#""prepared":[{{"removed":"{path}"}}]"#)),
        "{gpg}"
    );
    assert!(
        gpg.contains(r#""blocking":0"#) && gpg.contains(r#""carried":true"#),
        "{gpg}"
    );
}

/// A real-remote run judges how its channel's client ended by the core's own reading: the
/// in-box client's two accounts of a dead link are each an `exited` ending
/// that comes back at its pace, and a refused authentication waits for the
/// person.
#[test]
fn experiment_e1_reads_a_clients_ending_as_the_core_does() {
    let child = PathBuf::from(env!("CARGO_BIN_EXE_child"));
    let ended = |status: &str, last: &str| {
        let output = Command::new(&child)
            .args(["channel", "ended", status, last])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    for last in [
        "client_loop: send disconnect: Connection reset",
        "Timeout, server 20.26.192.41 not responding.",
    ] {
        let read = ended("255", last);
        assert!(read.contains(r#""back":"paced""#), "{read}");
        assert!(read.contains("exited") && read.contains(last), "{read}");
    }
    let refused = ended("255", "dev@build-7.example: Permission denied (publickey).");
    assert!(refused.contains(r#""back":"by-the-person""#), "{refused}");
    let usage = Command::new(&child)
        .args(["channel", "ended", "not-a-status", "words"])
        .output()
        .unwrap();
    assert!(!usage.status.success());
}

/// A stand-in for the remote's systemd user manager, on the shell's search
/// path: `list-sockets` prints what listens, and `mask`, `unmask`, `start` and
/// `stop` change it as systemd's own do, the mask a link to `/dev/null` in
/// the user's unit folder. Every call is logged.
fn service_manager(remote: &mut Remote, listening: &str) -> PathBuf {
    let state = remote.folder.path().join("systemd");
    let bin = remote.folder.path().join("bin");
    fs::create_dir_all(state.join("units")).unwrap();
    fs::create_dir_all(&bin).unwrap();
    let line = format!("{listening} gpg-agent.socket   gpg-agent.service\n");
    fs::write(state.join("listening"), &line).unwrap();
    fs::write(state.join("units").join("gpg-agent.socket"), &line).unwrap();
    fs::write(
        bin.join("systemctl"),
        format!(
            r#"#!/bin/sh
s='{state}'
[ "$1" = --user ] && shift
v=$1; shift
echo "$v $*" >> "$s/log"
[ "${{1:-}}" = --now ] && shift
[ "${{1:-}}" = -- ] && shift
d=${{XDG_CONFIG_HOME:-$HOME/.config}}/systemd/user
case $v in
  list-sockets) cat "$s/listening" ;;
  mask)
    if [ -e "$d/$1" ] || [ -L "$d/$1" ]; then echo "Failed to mask unit: File $d/$1 already exists." >&2; exit 1; fi
    mkdir -p "$d" && ln -s /dev/null "$d/$1" || exit 1
    grep -v " $1 " "$s/listening" > "$s/next"; mv "$s/next" "$s/listening" ;;
  unmask) [ -L "$d/$1" ] && rm -f "$d/$1" ;;
  start) if [ -L "$d/$1" ]; then exit 1; fi; cat "$s/units/$1" >> "$s/listening" ;;
  stop) ;;
esac
"#,
            state = msys(&state),
        ),
    )
    .unwrap();
    remote.path = format!("{}:{}", msys(&bin), remote.path);
    state
}

/// With a unit of the service manager at `GnuPG`'s path, readiness names it
/// and connects to nothing there; under consent it masks the unit, stops the
/// agent it started, and reports the unit's file with the folder the mask
/// made; found masked, nothing is written again; taken back, the unit is
/// unmasked and listens again, and the folder is gone. A unit file of the
/// person's is never replaced, and a mask they changed is left listed.
#[test]
fn a_unit_at_gnupgs_path_is_named_masked_with_consent_and_taken_back_exactly() {
    let sh = posix_shell();
    let mut remote = Remote::new(sh, "survey-unit");
    let socket = msys(&remote.socket());
    let state = service_manager(&mut remote, &socket);
    let log = || fs::read_to_string(state.join("log")).unwrap_or_default();
    let config = remote.home.join(".config");
    let unit = config.join(r"systemd\user\gpg-agent.socket");

    let report = remote.survey(&gpg_plan());
    assert_eq!(at(&report), Some(&At::Held(b"gpg-agent.socket".to_vec())));
    assert!(log().contains("list-sockets"));
    assert!(!log().contains("mask"));
    assert!(!config.exists());

    let consented = Plan {
        writes: vec![(name("gpg"), Write::Masked)],
        ..gpg_plan()
    };
    let report = remote.survey(&consented);
    assert!(log().contains("mask --now -- gpg-agent.socket"));
    assert!(log().contains("stop -- gpg-agent.service"));
    assert_eq!(
        gpg(&report).wrote,
        [(
            Write::Masked,
            msys(&unit).into_bytes(),
            Some(msys(&config).into_bytes())
        )]
    );
    assert_eq!(at(&report), Some(&At::Free));
    // The shell's own reading of the link, as the reversal reads it.
    let link = remote.sh(&format!("[ -L '{0}' ] && readlink -- '{0}'", msys(&unit)));
    assert_eq!(link.trim(), "/dev/null");

    let again = remote.survey(&consented);
    assert_eq!(
        gpg(&again).wrote,
        Vec::<(Write, Vec<u8>, Option<Vec<u8>>)>::new()
    );
    assert_eq!(at(&again), Some(&At::Free));

    let undo = Plan {
        undo: vec![Undo {
            capability: name("gpg"),
            write: Write::Masked,
            place: RemotePath::try_from(msys(&unit).as_str()).unwrap(),
            made: Some(RemotePath::try_from(msys(&config).as_str()).unwrap()),
        }],
        ..gpg_plan()
    };
    let report = remote.survey(&undo);
    assert_eq!(found(&gpg(&report).unwrote), [(Write::Masked, msys(&unit))]);
    assert!(log().contains("unmask -- gpg-agent.socket"));
    assert!(log().contains("start -- gpg-agent.socket"));
    assert!(!config.exists());
    assert_eq!(at(&report), Some(&At::Held(b"gpg-agent.socket".to_vec())));

    // The person's own unit file at that place.
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    fs::write(&unit, "[Socket]\nListenStream=%t/gnupg/S.gpg-agent\n").unwrap();
    let report = remote.survey(&consented);
    assert_eq!(
        gpg(&report).wrote,
        Vec::<(Write, Vec<u8>, Option<Vec<u8>>)>::new()
    );
    assert!(matches!(
        gpg(&report).unwritten.as_slice(),
        [(Write::Masked, why)] if String::from_utf8_lossy(why).contains("already exists")
    ));
    assert_eq!(at(&report), Some(&At::Held(b"gpg-agent.socket".to_vec())));
    let report = remote.survey(&undo);
    assert_eq!(gpg(&report).unwrote, Vec::<(Write, Vec<u8>)>::new());
    assert!(unit.exists());
}

/// A credential's socket is placed in Hedwig's private folder; `git`'s own
/// `cache` helper at it is written into `git`'s global configuration after
/// the person's own lines, so their helper is asked first, and the person's
/// helper is named; a second survey keeps it, and taking it back leaves the
/// file as it was, byte for byte.
#[test]
fn gits_helper_line_goes_after_the_persons_and_is_taken_back_to_the_byte() {
    let sh = posix_shell();
    let mut remote = Remote::new(sh, "survey-helper");
    remote.shell = "/usr/bin/bash".to_owned();
    remote.path = "/usr/bin:/mingw64/bin".to_owned();
    let theirs = "[user]\n\tname = Dev\n[credential]\n\thelper = store\n";
    let config = remote.home.join(".gitconfig");
    fs::write(&config, theirs).unwrap();
    let plan = Plan {
        asks: vec![Asked {
            capability: name("git-https"),
            server: None,
            questions: vec![Question::Helper],
        }],
        writes: vec![(name("git-https"), Write::Helper)],
        ..Plan::default()
    };
    // The system's own configuration - Git for Windows names its credential
    // manager there - is kept out, so only the person's helper is named.
    let survey = |plan: &Plan| {
        let script = format!(
            "GIT_CONFIG_NOSYSTEM=1\nexport GIT_CONFIG_NOSYSTEM\n{}",
            posix(plan, NONCE)
        );
        let output = remote.sh(&script);
        read(&output, NONCE).unwrap_or_else(|unread| panic!("{unread:?}: {output}"))
    };
    let report = survey(&plan);
    let answer = report.answers.get(&name("git-https")).unwrap();
    let socket = format!("{}/git-https", msys(&remote.home.join(".hedwig")));
    let place = answer.place.as_ref().unwrap();
    assert_eq!(place.path, socket.as_bytes());
    assert_eq!(place.at, Some(At::Free));
    assert_eq!(answer.helpers, [b"credential.helper store".to_vec()]);
    assert_eq!(answer.wrote.len(), 1, "{answer:?}");
    let helpers = remote.sh("GIT_CONFIG_NOSYSTEM=1 git config --get-all credential.helper");
    assert_eq!(
        helpers.lines().collect::<Vec<_>>(),
        ["store".to_owned(), format!("cache --socket {socket}")]
    );
    let again = survey(&plan);
    assert_eq!(again.answers.get(&name("git-https")).unwrap().kept.len(), 1);

    let undo = Plan {
        undo: vec![Undo {
            capability: name("git-https"),
            write: Write::Helper,
            place: RemotePath::try_from(msys(&config).as_str()).unwrap(),
            made: None,
        }],
        ..Plan::default()
    };
    let report = survey(&undo);
    assert_eq!(
        report
            .answers
            .get(&name("git-https"))
            .unwrap()
            .unwrote
            .len(),
        1
    );
    assert_eq!(fs::read_to_string(&config).unwrap(), theirs);
}

/// A notifier's socket is placed in Hedwig's private folder and
/// `HEDWIG_NOTIFY` written into the login shell's files as the remote's own
/// `curl`; a hook's `$HEDWIG_NOTIFY "..."` in bash then posts its words to
/// the socket as written.
#[test]
fn a_hooks_notify_variable_posts_its_words_through_the_remotes_curl() {
    let sh = posix_shell();
    let mut remote = Remote::new(sh, "survey-notifier");
    remote.shell = "/usr/bin/bash".to_owned();
    remote.path = "/usr/bin:/mingw64/bin".to_owned();
    let variable = Variable::try_from("HEDWIG_NOTIFY").unwrap();
    let plan = Plan {
        asks: vec![Asked {
            capability: name("notices"),
            server: None,
            questions: vec![Question::Notifier],
        }],
        writes: vec![(name("notices"), Write::Variable(variable))],
        ..Plan::default()
    };
    let report = remote.survey(&plan);
    let notices = report.answers.get(&name("notices")).unwrap();
    assert_eq!(notices.absent, None, "Git for Windows' own curl");
    assert_eq!(notices.wrote.len(), 2, "into .bashrc and .profile");
    let folder = remote.home.join(".hedwig");
    let socket = format!("{}/notices", msys(&folder));
    assert_eq!(
        remote.sh("bash -c '. \"$HOME/.bashrc\"; printf %s \"$HEDWIG_NOTIFY\"'"),
        format!("curl -q -fsS --noproxy hedwig --unix-socket {socket} hedwig/ --data-raw")
    );

    // The forward's far end: the socket, carried to a listener that keeps
    // what is posted and answers as the relay does.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let to = listener.local_addr().unwrap();
    let posted = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut read = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let count = stream.read(&mut buffer).unwrap_or(0);
            read.extend_from_slice(buffer.get(..count).unwrap_or_default());
            let text = String::from_utf8_lossy(&read).into_owned();
            if count == 0 || text.ends_with("build 4512 finished") {
                break;
            }
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .unwrap();
        String::from_utf8_lossy(&read).into_owned()
    });
    let at = folder.join("notices");
    let _forward = hedwig_support::unix::Listener::bind(&at)
        .unwrap()
        .forward(to);
    let said = remote.sh(
        "bash -c '. \"$HOME/.bashrc\"; $HEDWIG_NOTIFY \"build 4512 finished\"; echo status=$?'",
    );
    assert!(said.ends_with("status=0\n"), "{said}");
    let request = posted.join().unwrap();
    assert!(
        request.starts_with("POST / HTTP/1.1\r\nHost: hedwig\r\n"),
        "{request}"
    );
    assert!(
        request.ends_with("\r\n\r\nbuild 4512 finished"),
        "{request}"
    );

    // fish holds an imported value as one word, so for fish the command is
    // written as its own list: `$HEDWIG_NOTIFY "..."` then runs as written
    // there, and a child is given the words joined, as bash's is.
    remote.shell = "/usr/bin/fish".to_owned();
    let report = remote.survey(&plan);
    assert_eq!(report.answers.get(&name("notices")).unwrap().wrote.len(), 1);
    let fish = fs::read_to_string(remote.home.join(r".config\fish\config.fish")).unwrap();
    let words = format!(
        "set -gx HEDWIG_NOTIFY 'curl' '-q' '-fsS' '--noproxy' 'hedwig' '--unix-socket' \
         '{socket}' 'hedwig/' '--data-raw'"
    );
    assert!(fish.contains(&words), "{fish}");
}

/// Every file under `folder`, by its path from there, with its length and a
/// hash of its bytes: what a survey must leave as it found it.
fn contents(folder: &Path) -> BTreeMap<String, (usize, u64)> {
    let mut found = BTreeMap::new();
    let mut pending = vec![folder.to_path_buf()];
    while let Some(at) = pending.pop() {
        for entry in fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let name = path
                    .strip_prefix(folder)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let bytes = fs::read(&path).unwrap_or_default();
                let hash = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
                    (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
                });
                found.insert(name, (bytes.len(), hash));
            }
        }
    }
    found
}

/// A key of a home of its own, made with the remote's own `gpg`: its
/// fingerprint and its public half, armoured.
fn throwaway_key(remote: &Remote, home: &str, who: &str) -> (Fingerprint, String) {
    readerless(&remote.home.join(home)).unwrap();
    let other = msys(&remote.home.join(home));
    let made = remote.sh(&format!(
        "export GNUPGHOME={other} && \
         gpg --batch --passphrase '' --quick-gen-key '{who} <{who}@hedwig.example>' ed25519 sign never >/dev/null 2>&1 && \
         gpg --with-colons --list-keys | awk -F: '/^fpr/ {{ print $10; exit }}' && \
         gpg --armor --export {who}@hedwig.example; gpgconf --kill all"
    ));
    let (fingerprint, armoured) = made.split_once('\n').unwrap();
    (
        Fingerprint::try_from(fingerprint.trim()).unwrap(),
        armoured.trim().to_owned(),
    )
}

/// Asking whether the remote holds the workstation's keys writes nothing:
/// a home with no keyring is left with none, and the keys are absent.
#[test]
fn a_survey_makes_no_keyring_in_a_home_that_has_none() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "no-keyring");
    readerless(&remote.gnupg()).unwrap();
    let before = contents(&remote.gnupg());
    let key = Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let plan = Plan {
        keys: vec![key.clone()],
        ..gpg_plan()
    };
    let report = remote.survey(&plan);
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key, false)]));
    assert_eq!(contents(&remote.gnupg()), before);
}

/// A public key imported into a home with no keyring makes the keybox,
/// which the write reports as what it made; its reversal takes the keybox
/// back with the key, and the home is as it was, file for file.
#[test]
fn a_key_imported_where_there_was_no_keyring_is_taken_back_with_the_keyring() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "keyring-made");
    let (key, armoured) = throwaway_key(&remote, "other", "hedwig");
    readerless(&remote.gnupg()).unwrap();
    let before = contents(&remote.gnupg());
    let mut plan = write_plan(vec![Write::PublicKey(key.clone())]);
    plan.keys = vec![key.clone()];
    plan.armoured.insert(key.clone(), armoured);
    let report = remote.survey(&plan);
    let keybox = format!("{}/pubring.kbx", msys(&remote.gnupg()));
    assert_eq!(
        gpg(&report).wrote,
        [(
            Write::PublicKey(key.clone()),
            msys(&remote.gnupg()).into_bytes(),
            Some(keybox.clone().into_bytes())
        )]
    );
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key.clone(), true)]));

    let undo = Plan {
        undo: vec![Undo {
            capability: name("gpg"),
            write: Write::PublicKey(key.clone()),
            place: RemotePath::try_from(msys(&remote.gnupg()).as_str()).unwrap(),
            made: Some(RemotePath::try_from(keybox.as_str()).unwrap()),
        }],
        keys: vec![key.clone()],
        ..gpg_plan()
    };
    let report = remote.survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 1);
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key, false)]));
    assert_eq!(contents(&remote.gnupg()), before);
}

/// A keybox Hedwig's import made that the person has put a key of their own
/// in since is theirs: the reversal takes Hedwig's key out and leaves the
/// keybox with theirs.
#[test]
fn a_keyring_the_person_has_used_since_keeps_their_keys() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "keyring-used");
    let (key, armoured) = throwaway_key(&remote, "other", "hedwig");
    let (theirs, their_half) = throwaway_key(&remote, "theirs", "person");
    readerless(&remote.gnupg()).unwrap();
    let mut plan = write_plan(vec![Write::PublicKey(key.clone())]);
    plan.armoured.insert(key.clone(), armoured);
    let report = remote.survey(&plan);
    let (_, _, made) = gpg(&report).wrote.first().unwrap().clone();
    let half = remote.folder.path().join("theirs.asc");
    fs::write(&half, their_half).unwrap();
    remote.sh(&format!(
        "gpg --batch --import {} >/dev/null 2>&1",
        msys(&half)
    ));

    let undo = Plan {
        undo: vec![Undo {
            capability: name("gpg"),
            write: Write::PublicKey(key.clone()),
            place: RemotePath::try_from(msys(&remote.gnupg()).as_str()).unwrap(),
            made: made.map(|made| {
                RemotePath::try_from(String::from_utf8(made).unwrap().as_str()).unwrap()
            }),
        }],
        keys: vec![key.clone(), theirs.clone()],
        ..gpg_plan()
    };
    let report = remote.survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 1);
    assert_eq!(
        gpg(&report).keys,
        BTreeMap::from([(key, false), (theirs, true)])
    );
    assert!(remote.gnupg().join("pubring.kbx").exists());
}

/// Runs Gpg4win's own `gpg` in `home` with `arguments`.
fn gpg4win(bin: &Path, home: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(bin.join("gpg.exe"))
        .arg("--homedir")
        .arg(home)
        .args(arguments)
        .output()
        .unwrap()
}

/// A key made with Gpg4win's own `gpg` in a home of its own at `maker`: its
/// fingerprint and its public half, armoured.
fn windows_key(bin: &Path, maker: &Path) -> (Fingerprint, String) {
    readerless(maker).unwrap();
    let made_key = gpg4win(
        bin,
        maker,
        &[
            "--batch",
            "--passphrase",
            "",
            "--quick-gen-key",
            "hedwig <hedwig@hedwig.example>",
            "ed25519",
            "sign",
            "never",
        ],
    );
    assert!(made_key.status.success(), "{made_key:?}");
    let listed = gpg4win(bin, maker, &["--with-colons", "--list-keys"]);
    let fingerprint = String::from_utf8(listed.stdout)
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("fpr:"))
        .and_then(|rest| rest.split(':').nth(8).map(str::to_owned))
        .unwrap();
    let exported = gpg4win(
        bin,
        maker,
        &["--armor", "--export", "hedwig@hedwig.example"],
    );
    let _ = Command::new(bin.join("gpgconf.exe"))
        .arg("--homedir")
        .arg(maker)
        .args(["--kill", "all"])
        .output();
    (
        Fingerprint::try_from(fingerprint.as_str()).unwrap(),
        String::from_utf8(exported.stdout)
            .unwrap()
            .trim()
            .to_owned(),
    )
}

/// On a Windows remote, Gpg4win's own `gpg`: asking writes no keyring, a key
/// imported where there was none reports the keybox it made, and its
/// reversal leaves the home as it was, its lock file included.
#[test]
#[ignore = "needs GnuPG for Windows installed and registered, as Gpg4win registers it"]
fn a_windows_remotes_keyring_is_made_and_taken_back_only_with_its_key() {
    let bin = registered_gnupg();
    let folder = Folder::new("keyring-windows");
    let (key, armoured) = windows_key(&bin, &folder.path().join("maker"));

    let home = folder.path().join("gnupg");
    readerless(&home).unwrap();
    let config = folder.path().join("gitconfig");
    fs::write(&config, "").unwrap();
    let survey = |plan: &Plan| {
        let path = format!("{};{}", bin.display(), std::env::var("PATH").unwrap());
        let mut child = Command::new("powershell.exe")
            .args(command(Dialect::PowerShell).get(1..).unwrap())
            .env("PATH", path)
            .env("GNUPGHOME", &home)
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(powershell(plan, NONCE).as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        read(&String::from_utf8_lossy(&output.stdout), NONCE).unwrap()
    };
    let before = contents(&home);
    let asked = survey(&Plan {
        keys: vec![key.clone()],
        ..gpg_plan()
    });
    let sockets = gpg(&asked).place.clone().map(|place| {
        Cleanup(
            PathBuf::from(String::from_utf8(place.path).unwrap())
                .parent()
                .unwrap()
                .to_path_buf(),
        )
    });
    assert_eq!(gpg(&asked).keys, BTreeMap::from([(key.clone(), false)]));
    assert_eq!(contents(&home), before);

    let mut plan = write_plan(vec![Write::PublicKey(key.clone())]);
    plan.keys = vec![key.clone()];
    plan.armoured.insert(key.clone(), armoured);
    let report = survey(&plan);
    let keybox = home.join("pubring.kbx");
    assert_eq!(
        gpg(&report).wrote,
        [(
            Write::PublicKey(key.clone()),
            home.to_str().unwrap().as_bytes().to_vec(),
            Some(keybox.to_str().unwrap().as_bytes().to_vec())
        )],
        "{:?}",
        gpg(&report)
    );
    let report = survey(&Plan {
        undo: vec![Undo {
            capability: name("gpg"),
            write: Write::PublicKey(key.clone()),
            place: RemotePath::try_from(home.to_str().unwrap()).unwrap(),
            made: Some(RemotePath::try_from(keybox.to_str().unwrap()).unwrap()),
        }],
        keys: vec![key.clone()],
        ..gpg_plan()
    });
    assert_eq!(gpg(&report).unwrote.len(), 1);
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key, false)]));
    assert_eq!(contents(&home), before);
    drop(sockets);
}

/// The socket a `gpg` exercise is bound to; its own `gpg` finds the agent.
fn agent_socket() -> Binding {
    Binding::Socket(RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap())
}

/// The person's test of a `gpg` capability signs only where the remote's
/// `GnuPG` home has a keyring: in one with none, signing would make one, so
/// it runs nothing, says why, and leaves the home as it was, file for file.
#[test]
fn an_exercise_makes_no_keyring_in_a_home_that_has_none() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "exercise-no-keyring");
    readerless(&remote.gnupg()).unwrap();
    let before = contents(&remote.gnupg());
    let output = remote.sh(&exercise(
        Dialect::Posix,
        Some(Query::AgentSocket),
        &agent_socket(),
        NONCE,
    ));
    assert_eq!(
        exercised(&output, NONCE),
        Ok(Err(Finding::KeyringAbsent)),
        "{output}"
    );
    assert_eq!(contents(&remote.gnupg()), before);
}

/// Where the home has a keyring - the one Hedwig's consented import made -
/// the remote's `gpg` is run, and its signing makes no trust database.
#[test]
fn an_exercise_signs_where_the_home_has_a_keyring() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "exercise-keyring");
    let (_, armoured) = throwaway_key(&remote, "other", "hedwig");
    readerless(&remote.gnupg()).unwrap();
    let half = remote.folder.path().join("hedwig.asc");
    fs::write(&half, armoured).unwrap();
    remote.sh(&format!(
        "gpg --batch --no-tty --trust-model always --no-auto-check-trustdb --import {} >/dev/null 2>&1",
        msys(&half)
    ));
    assert!(remote.gnupg().join("pubring.kbx").exists());
    let output = remote.sh(&exercise(
        Dialect::Posix,
        Some(Query::AgentSocket),
        &agent_socket(),
        NONCE,
    ));
    assert!(
        matches!(exercised(&output, NONCE), Ok(Ok(_))),
        "the tool ran: {output}"
    );
    assert!(!remote.gnupg().join("trustdb.gpg").exists());
}

/// A Windows remote's exercise, under Windows PowerShell with Gpg4win: in a
/// home with no keyring it runs nothing and makes nothing.
#[test]
#[ignore = "needs GnuPG for Windows installed and registered, as Gpg4win registers it"]
fn a_windows_remotes_exercise_makes_no_keyring_in_a_home_that_has_none() {
    let bin = registered_gnupg();
    let folder = Folder::new("exercise-windows");
    let home = folder.path().join("gnupg");
    readerless(&home).unwrap();
    let config = folder.path().join("gitconfig");
    fs::write(&config, "").unwrap();
    let before = contents(&home);
    let path = format!("{};{}", bin.display(), std::env::var("PATH").unwrap());
    let mut child = Command::new("powershell.exe")
        .args(command(Dialect::PowerShell).get(1..).unwrap())
        .env("PATH", &path)
        .env("GNUPGHOME", &home)
        .env("GIT_CONFIG_GLOBAL", &config)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            exercise(
                Dialect::PowerShell,
                Some(Query::AgentSocket),
                &agent_socket(),
                NONCE,
            )
            .as_bytes(),
        )
        .unwrap();
    let output = String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned();
    // Whatever ran, its agent goes with the home.
    let _ = Command::new(bin.join("gpgconf.exe"))
        .args(["--kill", "all"])
        .env("GNUPGHOME", &home)
        .status();
    let sockets = Command::new(bin.join("gpgconf.exe"))
        .args(["--list-dirs", "socketdir"])
        .env("GNUPGHOME", &home)
        .output()
        .map(|said| PathBuf::from(String::from_utf8_lossy(&said.stdout).trim()));
    let _cleanup = sockets
        .ok()
        // GnuPG's own per-home socket folder, `gnupg\d.<hash>`, and never
        // anything above it.
        .filter(|dir| {
            dir.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("d."))
                && dir.parent().and_then(Path::file_name) == Some("gnupg".as_ref())
        })
        .map(Cleanup);
    assert_eq!(
        exercised(&output, NONCE),
        Ok(Err(Finding::KeyringAbsent)),
        "{output}"
    );
    assert_eq!(contents(&home), before);
}

/// A key Hedwig imported is taken back while an agent holding its secret
/// half answers in the remote's home - as the workstation's own does through
/// the forward whenever a request from the remote is served - and the home is
/// as it was before the write.
#[test]
fn a_key_is_taken_back_while_an_agent_holding_its_secret_half_answers() {
    let sh = posix_shell();
    let remote = Remote::new(sh, "key-held");
    let (key, armoured) = throwaway_key(&remote, "other", "hedwig");
    readerless(&remote.gnupg()).unwrap();
    let secrets = remote.gnupg().join("private-keys-v1.d");
    fs::create_dir_all(&secrets).unwrap();
    for entry in fs::read_dir(remote.home.join("other").join("private-keys-v1.d")).unwrap() {
        let path = entry.unwrap().path();
        fs::copy(&path, secrets.join(path.file_name().unwrap())).unwrap();
    }
    remote.agent();
    // The agent stands in for the workstation's, reached through the forward:
    // its sockets, and its scdaemon's socket and log, are not the home's.
    let files = |home: &Path| -> BTreeMap<String, (usize, u64)> {
        contents(home)
            .into_iter()
            .filter(|(name, _)| !name.starts_with("S.") && name != SCDAEMON_LOG)
            .collect()
    };
    let before = files(&remote.gnupg());

    let mut plan = write_plan(vec![Write::PublicKey(key.clone())]);
    plan.keys = vec![key.clone()];
    plan.armoured.insert(key.clone(), armoured);
    let report = remote.survey(&plan);
    let (_, place, made) = gpg(&report).wrote.first().unwrap().clone();
    let undo = Plan {
        undo: vec![Undo {
            capability: name("gpg"),
            write: Write::PublicKey(key.clone()),
            place: RemotePath::try_from(String::from_utf8(place).unwrap().as_str()).unwrap(),
            made: made.map(|made| {
                RemotePath::try_from(String::from_utf8(made).unwrap().as_str()).unwrap()
            }),
        }],
        keys: vec![key.clone()],
        ..gpg_plan()
    };
    let report = remote.survey(&undo);
    assert_eq!(gpg(&report).unwrote.len(), 1, "{:?}", gpg(&report));
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key, false)]));
    assert_eq!(files(&remote.gnupg()), before);
}

/// The same under Windows PowerShell with Gpg4win: the key goes while an
/// agent holding its secret half answers in the home.
#[test]
#[ignore = "needs GnuPG for Windows installed and registered, as Gpg4win registers it"]
fn a_windows_remotes_key_is_taken_back_while_an_agent_holding_its_secret_half_answers() {
    let bin = registered_gnupg();
    let folder = Folder::new("key-held-windows");
    let maker = folder.path().join("maker");
    let (key, armoured) = windows_key(&bin, &maker);
    let home = folder.path().join("gnupg");
    readerless(&home).unwrap();
    let secrets = home.join("private-keys-v1.d");
    fs::create_dir_all(&secrets).unwrap();
    for entry in fs::read_dir(maker.join("private-keys-v1.d")).unwrap() {
        let path = entry.unwrap().path();
        fs::copy(&path, secrets.join(path.file_name().unwrap())).unwrap();
    }
    let gpgconf = |arguments: &[&str]| {
        Command::new(bin.join("gpgconf.exe"))
            .arg("--homedir")
            .arg(&home)
            .args(arguments)
            .output()
            .unwrap()
    };
    assert!(gpgconf(&["--launch", "gpg-agent"]).status.success());
    let sockets = Cleanup(PathBuf::from(
        String::from_utf8(gpgconf(&["--list-dirs", "socketdir"]).stdout)
            .unwrap()
            .trim(),
    ));
    let config = folder.path().join("gitconfig");
    fs::write(&config, "").unwrap();
    let survey = |plan: &Plan| {
        let path = format!("{};{}", bin.display(), std::env::var("PATH").unwrap());
        let mut child = Command::new("powershell.exe")
            .args(command(Dialect::PowerShell).get(1..).unwrap())
            .env("PATH", path)
            .env("GNUPGHOME", &home)
            .env("GIT_CONFIG_GLOBAL", &config)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(powershell(plan, NONCE).as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        read(&String::from_utf8_lossy(&output.stdout), NONCE).unwrap()
    };
    // The agent stands in for the workstation's; its scdaemon's log is not
    // the home's.
    let files = |home: &Path| -> BTreeMap<String, (usize, u64)> {
        contents(home)
            .into_iter()
            .filter(|(name, _)| name != SCDAEMON_LOG)
            .collect()
    };
    let before = files(&home);
    let mut plan = write_plan(vec![Write::PublicKey(key.clone())]);
    plan.keys = vec![key.clone()];
    plan.armoured.insert(key.clone(), armoured);
    let report = survey(&plan);
    let (_, place, made) = gpg(&report).wrote.first().unwrap().clone();
    let report = survey(&Plan {
        undo: vec![Undo {
            capability: name("gpg"),
            write: Write::PublicKey(key.clone()),
            place: RemotePath::try_from(String::from_utf8(place).unwrap().as_str()).unwrap(),
            made: made.map(|made| {
                RemotePath::try_from(String::from_utf8(made).unwrap().as_str()).unwrap()
            }),
        }],
        keys: vec![key.clone()],
        ..gpg_plan()
    });
    let _ = gpgconf(&["--kill", "all"]);
    assert_eq!(gpg(&report).unwrote.len(), 1, "{:?}", gpg(&report));
    assert_eq!(gpg(&report).keys, BTreeMap::from([(key, false)]));
    assert_eq!(files(&home), before);
    drop(sockets);
}
