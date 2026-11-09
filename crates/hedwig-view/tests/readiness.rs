//! What readiness found on a remote and what Hedwig wrote there, on the
//! window's line and in the icon's menu; consent to write, given knowing what
//! it writes; a test of a capability and what it found.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Instant;

use hedwig_model::capability::{Exposure, Setup};
use hedwig_model::config::{Activation, Change, Terms};
use hedwig_model::protocol::{Exercised, Notice, Proof, Request, Topic, Written};
use hedwig_model::refusal::{Refusal, Withheld};
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::text::{Fingerprint, Grip, Mark, Port, RemotePath, Variable, Words};
use hedwig_model::trail::{
    Binding, Carriage, Entry, Event as Happened, Finding, Key, Keyring, Prepared, Readiness, Seq,
    Target, Tick, Timestamp, Uses, Write,
};
use hedwig_view::act::Act;
use hedwig_view::card::Subject;
use hedwig_view::define;
use hedwig_view::exposure::{self, Board, Line, Shown, Window};
use hedwig_view::glance::{self, Entry as Row};
use hedwig_view::grant::{Draft, Form};
use hedwig_view::link::{Event, Place};
use hedwig_view::words::{self, Keyrings};

mod common;
use common::support::{grant, name, remote, terms};
use common::{Bench, clock};

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

fn key() -> Fingerprint {
    Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap()
}

fn path(text: &str) -> RemotePath {
    RemotePath::try_from(text).unwrap()
}

fn refresh(bench: &mut Bench) {
    for topic in [
        Topic::Status,
        Topic::Exposure,
        Topic::Attention,
        Topic::Configuration,
        Topic::Workstation,
    ] {
        bench.notice(Notice::Stale(topic));
    }
}

/// A core that granted `gpg` to the workspace on `setup`, with the window open
/// so the catalogue and the person's document are known.
fn granted(setup: Setup) -> Bench {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(workspace())),
            terms: Terms {
                setup,
                ..terms(Activation::OnRequest, Exposure::NONE)
            },
        }),
    ));
    assert_eq!(bench.seen().refused, None);
    bench
}

fn window(bench: &Bench) -> Window {
    Window::of(bench.link.seen(), &clock, Instant::now())
}

fn line(window: &Window) -> &Line {
    match &window.board {
        Board::Exposure { groups, .. } => groups
            .iter()
            .flat_map(|group| &group.lines)
            .find(|line| line.remote == Some(workspace()) && line.capability.as_str() == "gpg")
            .expect("gpg's line on the workspace"),
        other => unreachable!("{other:?}"),
    }
}

fn labels(shown: &[Shown]) -> Vec<&str> {
    shown
        .iter()
        .map(|act| match act {
            Shown::Offered { label, .. } | Shown::Withheld { label, .. } => label.as_str(),
        })
        .collect()
}

fn offered<'a>(shown: &'a [Shown], wanted: &str) -> &'a Act {
    shown
        .iter()
        .find_map(|act| match act {
            Shown::Offered { label, act } if label == wanted => Some(act),
            _ => None,
        })
        .unwrap_or_else(|| unreachable!("{wanted} is offered"))
}

/// The entries of the workspace's own menu, as words.
fn menu(bench: &Bench) -> Vec<String> {
    glance::menu(bench.link.seen(), Instant::now())
        .into_iter()
        .find_map(|entry| match entry {
            Row::Group { label, entries } if label == workspace().to_string() => Some(entries),
            _ => None,
        })
        .expect("the workspace is in the menu")
        .into_iter()
        .filter_map(|entry| match entry {
            Row::Line(words) => Some(words),
            Row::Act { label, .. } => Some(label),
            _ => None,
        })
        .collect()
}

/// What Hedwig wrote for gpg on the workspace in these suites: no-autostart,
/// and a mask on the unit at gpg's path with the folder it made.
fn writes() -> [(Write, RemotePath, Option<RemotePath>); 2] {
    [
        (
            Write::NoAutostart,
            path("/home/dev/.gnupg/common.conf"),
            None,
        ),
        (
            Write::Masked,
            path("/home/dev/.config/systemd/user/gpg-agent.socket"),
            Some(path("/home/dev/.config")),
        ),
    ]
}

/// A person reads, on the workspace's line and in its menu, what blocks gpg
/// there, what is carried and still wrong, and what Hedwig wrote with their
/// consent; each in the model's words. Checking again is one act from either,
/// and the core takes it.
#[test]
fn what_readiness_found_and_what_hedwig_wrote_are_on_the_line_and_in_the_menu() {
    let mut bench = granted(Setup::Write);
    let connection = bench.desk.channel_up(&workspace(), "linux");
    bench.desk.trail.push(Happened::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::PublicKeyAbsent(key())]),
    });
    for (write, place, made) in writes() {
        bench.desk.trail.push(Happened::Wrote {
            connection,
            capability: name("gpg"),
            write,
            place,
            made,
        });
    }
    refresh(&mut bench);
    let mask = "a mask on the remote's own service unit, at \
                /home/dev/.config/systemd/user/gpg-agent.socket, in /home/dev/.config, a folder \
                Hedwig made for it";
    let carried = "the remote's keyring lacks the public key \
                   0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2, so its gpg cannot use that key";

    // Carried: the line says where it is reached, and names what is wrong
    // beside it rather than calling it unready.
    let shown = window(&bench);
    let gpg = line(&shown);
    assert!(
        gpg.state.starts_with("reachable there at "),
        "{}",
        gpg.state
    );
    assert_eq!(gpg.cautions, [carried]);
    assert_eq!(
        gpg.written,
        ["no-autostart in /home/dev/.gnupg/common.conf", mask]
    );
    let said = menu(&bench);
    assert!(said.contains(&format!("gpg: also, {carried}")), "{said:?}");
    assert!(
        said.contains(&format!(
            "gpg: Hedwig wrote there, with your consent: no-autostart in \
             /home/dev/.gnupg/common.conf; {mask}"
        )),
        "{said:?}"
    );
    assert!(said.contains(&"Check gpg again".to_owned()), "{said:?}");
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    assert!(
        needs
            .iter()
            .any(|need| need.sentence
                == format!("gpg is carried to dev/build (coder), but {carried}")),
        "{needs:?}"
    );

    // Something now answers at the path: what blocks is the line's state, and
    // what is carried stays beside it, said once.
    let socket = path("/run/user/1000/gnupg/S.gpg-agent");
    bench.desk.trail.push(Happened::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![
            Finding::AgentLive(socket.clone()),
            Finding::PublicKeyAbsent(key()),
        ]),
    });
    refresh(&mut bench);
    let shown = window(&bench);
    let gpg = line(&shown);
    let live = Finding::AgentLive(socket).to_string();
    assert_eq!(gpg.state, format!("not ready: {live}"));
    assert_eq!(gpg.cautions, [carried]);
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    assert!(
        needs.iter().any(|need| need.sentence
            == format!("gpg is not ready on dev/build (coder): {live}; and {carried}")),
        "{needs:?}"
    );

    // Checking again from the menu is a request the core carries out.
    let check = Request::Check {
        remote: workspace(),
        capability: name("gpg"),
    };
    assert_eq!(bench.permits(&check), Ok(()));
    bench.feed(Event::Wish(Place::Tray, check));
    assert_eq!(bench.seen().refused, None);
    assert_eq!(line(&window(&bench)).cautions, Vec::<String>::new());

    // The consent ended and what was written taken back: nothing is listed.
    for (write, place, _) in writes() {
        bench.desk.trail.push(Happened::Unwrote {
            connection,
            capability: name("gpg"),
            write,
            place,
        });
    }
    refresh(&mut bench);
    assert_eq!(line(&window(&bench)).written, Vec::<String>::new());
    assert!(
        !menu(&bench)
            .iter()
            .any(|said| said.contains("Hedwig wrote there"))
    );
}

/// The person consents to a write knowing what it is. A grant that does
/// not let Hedwig write offers to, asked first with every write named; one
/// that does offers to stop, at once. A capability that writes nothing offers
/// neither.
#[test]
fn consent_to_write_is_asked_with_what_is_written() {
    let mut bench = granted(Setup::Inspect);
    bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);
    let shown = window(&bench);
    let gpg = line(&shown);
    assert!(
        !labels(&gpg.acts).contains(&"Stop Hedwig writing there"),
        "{:?}",
        labels(&gpg.acts)
    );
    let Act::Confirm {
        request,
        consequence,
        answer,
    } = offered(
        &gpg.acts,
        "Let Hedwig write the remote tool's configuration...",
    )
    else {
        unreachable!("consent is asked first")
    };
    assert_eq!(answer, "Let Hedwig write", "a button's words, never cut");
    // The keys are written too, and the core has not read them yet: the
    // consent says so rather than listing nothing.
    assert_eq!(
        consequence,
        "On dev/build (coder), where it is missing and never over what you set, Hedwig may write \
         no-autostart in the remote's GnuPG configuration; a mask on the remote's own service unit \
         that holds the path the forward needs, which stops the agent it started there; the file \
         the remote's gpg finds its agent by; and, once it has read them, the public key of each key your GnuPG offers into \
         the remote's keyring, with the one you sign with as the remote git's signing key. Each \
         is marked as Hedwig's where it is, and taken back when you withdraw this."
    );
    assert_eq!(bench.permits(request), Ok(()));
    let request = common::clone(request);
    bench.feed(Event::Wish(
        Place::Line {
            remote: Some(workspace()),
            capability: name("gpg"),
        },
        request,
    ));
    refresh(&mut bench);
    let document = bench.seen().document.clone().expect("the document");
    assert_eq!(
        document
            .grants
            .iter()
            .map(|entry| entry.terms.setup)
            .collect::<Vec<_>>(),
        [Setup::Write]
    );
    let shown = window(&bench);
    let Act::Send(stop) = offered(&line(&shown).acts, "Stop Hedwig writing there") else {
        unreachable!("stopping is one act")
    };
    assert_eq!(bench.permits(stop), Ok(()));

    // A port writes nothing on a remote: no consent is asked for it.
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("selenium-grid", Granted::One(workspace())),
            terms: terms(Activation::OnRequest, Exposure::SERVICE),
        }),
    ));
    assert_eq!(bench.seen().refused, None);
    bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);
    let shown = window(&bench);
    let Board::Exposure { groups, .. } = &shown.board else {
        unreachable!()
    };
    let grid = groups
        .iter()
        .flat_map(|group| &group.lines)
        .find(|line| line.capability.as_str() == "selenium-grid")
        .unwrap();
    assert!(
        !labels(&grid.acts)
            .iter()
            .any(|label| label.contains("writ")),
        "{:?}",
        labels(&grid.acts)
    );
}

/// The grant form says what consent to write lets Hedwig write
/// before the person gives it, in the model's words: before the core has read
/// the keys gpg offers, that their public halves and the signing key come
/// too; once it has, each by its fingerprint. It is asked only where there is
/// something to write, and again when what is granted changes.
#[test]
fn the_grant_form_names_the_writes_before_consent_and_asks_again_for_another_capability() {
    let mut bench = granted(Setup::Inspect);
    let form = |bench: &Bench, draft: &Draft| {
        let attached = bench.seen();
        Form::of(
            draft,
            attached.catalogue.as_ref().unwrap().reference(),
            attached.document.as_ref().unwrap(),
            attached.workstation.as_ref(),
            (None, None),
            None,
        )
    };
    let choose = |bench: &Bench, draft: &mut Draft, capability: &str| {
        let attached = bench.seen();
        draft.choose_capability(
            name(capability),
            attached.catalogue.as_ref().unwrap().reference(),
            attached.document.as_ref().unwrap(),
        );
    };
    let mut draft = Draft::default();
    choose(&bench, &mut draft, "gpg");
    assert_eq!(
        form(&bench, &draft).writable.as_deref(),
        Some(
            "Hedwig may write no-autostart in the remote's GnuPG configuration; a mask on the \
             remote's own service unit that holds the path the forward needs, which stops the \
             agent it started there; the file the remote's gpg finds its agent by; and, once it \
             has read them, the public key of each \
             key your GnuPG offers into the remote's keyring, with the one you sign with as the \
             remote git's signing key"
        )
    );

    // The core reads what gpg offers: the consent names those keys.
    bench.desk.trail.push(Happened::Offered {
        capability: name("gpg"),
        keyring: keyring(),
    });
    bench.told();
    assert_eq!(
        form(&bench, &draft).writable.as_deref(),
        Some(
            "Hedwig may write no-autostart in the remote's GnuPG configuration; a mask on the \
             remote's own service unit that holds the path the forward needs, which stops the \
             agent it started there; the file the remote's gpg finds its agent by; the public key \
             0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 into the remote's keyring; \
             0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 as the remote git's signing key"
        )
    );
    draft.let_write(true);
    assert!(form(&bench, &draft).writes);

    // Consent was to gpg's writes; another capability asks again.
    choose(&bench, &mut draft, "adb");
    let asked = form(&bench, &draft);
    assert!(!asked.writes);
    assert_eq!(asked.writable.as_deref(), Some(ADB_CONSENT));

    choose(&bench, &mut draft, "selenium-grid");
    assert_eq!(form(&bench, &draft).writable, None);
}

/// The keys the workstation's gpg offers in these suites: one primary key
/// that signs, with a subkey that authenticates.
fn keyring() -> Keyring {
    let grip = |text: &str| Grip::try_from(text).unwrap();
    let user = Some(Words::try_from("Dev Builder <dev@example.org>").unwrap());
    Keyring {
        keys: vec![
            Key {
                ssh: None,
                grip: grip("AA11BB22CC33DD44EE55FF6600771188992233AA"),
                fingerprint: key(),
                primary: key(),
                uses: Uses::SIGN,
                user: user.clone(),
                card: None,
            },
            Key {
                ssh: None,
                grip: grip("BB22CC33DD44EE55FF6600771188992233AA11BB"),
                fingerprint: Fingerprint::try_from("5A6B7C8D9E0F1A20E5D4B6E1A2C3F40516273849")
                    .unwrap(),
                primary: key(),
                uses: Uses::AUTHENTICATE,
                user,
                card: None,
            },
        ],
        signing: Some(Mark::try_from(key().as_str()).unwrap()),
    }
}

/// A request through the gpg relay names the key by the keygrip gpg-agent
/// uses; the card, the line's last request and what needs the person name it
/// as the person knows it, from what the workstation offers.
#[test]
fn a_relayed_requests_key_is_named_from_what_the_workstation_offers() {
    let mut bench = granted(Setup::Inspect);
    let connection = bench.desk.channel_up(&workspace(), "linux");
    bench.desk.trail.push(Happened::Offered {
        capability: name("gpg"),
        keyring: keyring(),
    });
    let grip = Grip::try_from("AA11BB22CC33DD44EE55FF6600771188992233AA").unwrap();
    bench.desk.trail.push(Happened::Asked {
        connection,
        capability: name("gpg"),
        operation: hedwig_model::capability::Operation::Sign,
        key: Some(hedwig_model::text::KeyId::Grip(grip.clone())),
    });
    refresh(&mut bench);
    let named = "key 0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 (Dev Builder <dev@example.org>)";
    assert_eq!(
        words::key(
            &hedwig_model::text::KeyId::Grip(grip.clone()),
            bench.seen().keyrings()
        ),
        named,
        "the workstation's keys are read with the rows"
    );
    let entries = bench.desk.trail.entries.clone();
    let said: Vec<String> = exposure::activity(&entries, &clock, bench.seen().keyrings())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert!(
        said.iter()
            .any(|said| said.ends_with(&format!("asked to sign with gpg, {named}"))),
        "{said:?}"
    );
}

/// Where readiness read the remote and no platform profile answers to
/// the system it named, the line offers defining one for that system, its
/// kernel filled in as the remote said it.
#[test]
fn a_remote_no_profile_answers_to_offers_a_platform_for_its_system() {
    let mut bench = granted(Setup::Inspect);
    let connection = bench.desk.channel_up(&workspace(), "linux");
    let haiku = hedwig_model::text::Kernel::try_from("Haiku").unwrap();
    bench.desk.trail.push(Happened::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::NoProfile(Refusal::UnknownKernel(
            haiku.clone(),
        ))]),
    });
    refresh(&mut bench);
    let shown = window(&bench);
    let gpg = line(&shown);
    let Act::Define(draft) = offered(&gpg.acts, "Define a platform for Haiku...") else {
        unreachable!("{:?}", labels(&gpg.acts))
    };
    assert_eq!(**draft, define::Draft::platform_for(&haiku));
    let attached = bench.seen();
    let fields = draft.fields(None);
    let kernel = fields.iter().find(|field| field.key == "kernel").unwrap();
    assert_eq!(
        kernel.input,
        define::Input::Text {
            typed: "Haiku".to_owned(),
            lines: false
        }
    );
    assert!(attached.catalogue.is_some());
    // A finding that is not a refusal offers nothing to define.
    bench.desk.trail.push(Happened::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![Finding::ToolAbsent(name("gpg"))]),
    });
    refresh(&mut bench);
    assert!(
        !labels(&line(&window(&bench)).acts)
            .iter()
            .any(|label| label.starts_with("Define"))
    );
}

/// A person tests a capability with a real request from the line it stands on: the
/// line says it is waiting for the remote's tool, then what was found, until
/// another act is made there. An act made on another line leaves it.
#[test]
fn a_test_is_shown_on_its_line_while_it_runs_and_after() {
    let mut bench = granted(Setup::Inspect);
    bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);
    let here = Place::Line {
        remote: Some(workspace()),
        capability: name("gpg"),
    };
    let exercise = Request::Exercise {
        remote: workspace(),
        capability: name("gpg"),
    };
    assert_eq!(bench.permits(&exercise), Ok(()));

    // The core answers at once; until the notice of what the tool did
    // arrives, the line says it is waiting.
    bench.feed(Event::Wish(here.clone(), exercise));
    assert_eq!(bench.seen().refused, None);
    assert_eq!(
        line(&window(&bench)).proof.as_deref(),
        Some("Testing: waiting for the remote's own tool.")
    );
    // Another remote's test is not this one's.
    bench.notice(Notice::Exercised(Exercised {
        remote: remote("ssh", "x"),
        capability: name("gpg"),
        proof: Proof::Silent(None),
    }));
    assert_eq!(
        line(&window(&bench)).proof.as_deref(),
        Some("Testing: waiting for the remote's own tool.")
    );
    bench.notice(Notice::Exercised(Exercised {
        remote: workspace(),
        capability: name("gpg"),
        proof: Proof::Reached(hedwig_model::trail::RequestId(Seq(40))),
    }));
    assert_eq!(
        line(&window(&bench)).proof.as_deref(),
        Some("Tested: the remote's own tool reached gpg on this workstation through Hedwig.")
    );
    // A refusal on the page leaves the line's test as it was.
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Revoke(grant(
            "gpg",
            Granted::One(remote("ssh", "x")),
        ))),
    ));
    assert!(line(&window(&bench)).proof.is_some());
    // Another act on the line ends it.
    bench.feed(Event::Wish(
        here,
        Request::Check {
            remote: workspace(),
            capability: name("gpg"),
        },
    ));
    assert_eq!(line(&window(&bench)).proof, None);
}

/// Every way a test can end is said for the person, distinct from the others,
/// with the remote tool's own words where it gave some.
#[test]
fn every_test_result_reads_as_words() {
    let gpg = name("gpg");
    let said = [
        Proof::Reached(hedwig_model::trail::RequestId(Seq(7))),
        Proof::Silent(Some(
            Words::try_from("gpg: signing failed: No secret key").unwrap(),
        )),
        Proof::Silent(None),
        Proof::Unrun(Finding::ToolAbsent(name("gpg"))),
    ]
    .map(|proof| words::proof(&proof, &gpg));
    assert_eq!(
        said,
        [
            "Tested: the remote's own tool reached gpg on this workstation through Hedwig.",
            "Tested: the remote's own tool ran, and nothing reached this workstation. Its last \
             words: gpg: signing failed: No secret key",
            "Tested: the remote's own tool ran, and nothing reached this workstation; it said \
             nothing.",
            "Not tested: the remote has no gpg to say where this goes",
        ]
    );
}

/// What Hedwig writes is said before consent in the model's words and, once
/// written, in the view's with where it went; each of the five distinctly.
#[test]
fn every_write_reads_as_words_before_and_after() {
    let variable = Variable::try_from("SSH_AUTH_SOCK").unwrap();
    let writes = [
        Write::NoAutostart,
        Write::PublicKey(key()),
        Write::SigningKey(Mark::try_from(key().as_str()).unwrap()),
        Write::Variable(variable),
        Write::SocketFile,
        Write::Masked,
    ];
    let before: Vec<String> = writes.iter().map(ToString::to_string).collect();
    let after: Vec<String> = writes
        .iter()
        .map(|write| {
            words::written(&Written {
                write: write.clone(),
                place: path("/home/dev/.f"),
                made: None,
            })
        })
        .collect();
    assert_eq!(
        after,
        [
            "no-autostart in /home/dev/.f",
            "the public key 0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2, in the keyring at \
             /home/dev/.f",
            "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 as git's signing key, in /home/dev/.f",
            "SSH_AUTH_SOCK in /home/dev/.f",
            "the socket file /home/dev/.f",
            "a mask on the remote's own service unit, at /home/dev/.f",
        ]
    );
    assert_eq!(
        words::written(&Written {
            write: Write::Masked,
            place: path("/home/dev/.config/systemd/user/gpg-agent-ssh.socket"),
            made: Some(path("/home/dev/.config")),
        }),
        "a mask on the remote's own service unit, at \
         /home/dev/.config/systemd/user/gpg-agent-ssh.socket, in /home/dev/.config, a folder \
         Hedwig made for it"
    );
    // A key's import into a home with no keyring makes the keybox, which is
    // what the write made.
    let keybox = path("/home/dev/.gnupg/pubring.kbx");
    assert_eq!(
        words::written(&Written {
            write: Write::PublicKey(key()),
            place: keybox.clone(),
            made: Some(keybox),
        }),
        format!(
            "the public key {}, in the keyring at /home/dev/.gnupg/pubring.kbx, a keyring Hedwig \
             made for it",
            key()
        )
    );
    let mut all = before.clone();
    all.extend(after);
    let distinct: std::collections::BTreeSet<&String> = all.iter().collect();
    assert_eq!(distinct.len(), all.len(), "{all:?}");
}

/// What Hedwig changed on a remote is read from the trail in the person's
/// words: a folder made, a socket nothing answered at removed, a write made
/// and taken back.
#[test]
fn what_hedwig_changed_on_a_remote_reads_from_the_trail() {
    let entry = |seq: u64, event| Entry {
        seq: Seq(seq),
        at: Timestamp(seq),
        tick: Tick(seq),
        event,
    };
    let connection = hedwig_model::trail::ConnectionId(Seq(1));
    let written = |write| (write, path("/home/dev/.gnupg/common.conf"));
    let (write, place) = written(Write::NoAutostart);
    let entries = [
        entry(
            2,
            Happened::Prepared {
                connection,
                capability: name("gpg"),
                prepared: Prepared::Created(path("/run/user/1000/gnupg")),
            },
        ),
        entry(
            3,
            Happened::Prepared {
                connection,
                capability: name("gpg"),
                prepared: Prepared::Removed(path("/run/user/1000/gnupg/S.gpg-agent")),
            },
        ),
        entry(
            4,
            Happened::Wrote {
                connection,
                capability: name("gpg"),
                write: write.clone(),
                place: place.clone(),
                made: Some(path("/home/dev/.gnupg")),
            },
        ),
        entry(
            5,
            Happened::Unwrote {
                connection,
                capability: name("gpg"),
                write,
                place,
            },
        ),
        entry(
            6,
            Happened::TurnedAway {
                remote: Some(workspace()),
                refusal: Refusal::Withheld {
                    capability: name("adb"),
                    request: Withheld::Ending,
                },
            },
        ),
        entry(
            7,
            Happened::Carried {
                connection,
                capability: name("adb"),
                carriage: Carriage::Reverse(Target::Loopback(Port::try_from(8081).unwrap())),
                endpoint: Port::try_from(50123).unwrap(),
            },
        ),
    ];
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert_eq!(
        said,
        [
            "t7: adb carries a reverse on: a device's connections to it reach port 8081 on the \
             remote",
            "t6: a request to adb was refused because it would have ended the workstation's ADB \
             server",
            "t5: took back no-autostart in /home/dev/.gnupg/common.conf for gpg, as your consent \
             ended",
            "t4: wrote no-autostart in /home/dev/.gnupg/common.conf for gpg, with your consent, \
             making the folder /home/dev/.gnupg",
            "t3: removed the socket /run/user/1000/gnupg/S.gpg-agent, which nothing answered at, \
             for gpg",
            "t2: made the folder /run/user/1000/gnupg for gpg, private to the remote user",
        ]
    );
}

/// A person reads on adb's line where each reverse it carried lands on the
/// remote, with the workstation port its own `adb reverse --list` shows for it;
/// under the remote in the menu, where each lands; and each in the
/// remote's activity as the core answers it. A line carrying none says none.
#[test]
fn a_reverse_carried_reads_on_adbs_line_in_the_menu_and_in_the_activity() {
    let mut bench = granting("adb", Setup::Inspect, Exposure::SERVICE);
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(workspace())),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    ));
    let connection = bench.desk.channel_up(&workspace(), "linux");
    for (target, endpoint) in [
        (Target::Loopback(Port::try_from(8081).unwrap()), 50131),
        (Target::Path(path("/run/user/1000/metro.sock")), 50133),
    ] {
        bench.desk.trail.push(Happened::Carried {
            connection,
            capability: name("adb"),
            carriage: Carriage::Reverse(target),
            endpoint: Port::try_from(endpoint).unwrap(),
        });
    }
    refresh(&mut bench);

    let shown = window(&bench);
    assert_eq!(
        line_of(&shown, "adb").carried,
        [
            "A device's connections reach port 8081 on the remote, which adb reverse --list on \
             this workstation shows as tcp:50131",
            "A device's connections reach the socket /run/user/1000/metro.sock on the remote, \
             which adb reverse --list on this workstation shows as tcp:50133",
        ]
    );
    assert_eq!(line_of(&shown, "gpg").carried, Vec::<String>::new());
    assert!(
        menu(&bench).contains(
            &"adb: a device's connections reach port 8081 on the remote; the socket \
              /run/user/1000/metro.sock on the remote"
                .to_owned()
        ),
        "{:?}",
        menu(&bench)
    );

    bench.feed(Event::Review(Some(workspace())));
    let activity = bench.seen().activity.as_ref().unwrap();
    let said: Vec<String> = exposure::activity(
        activity.entries.as_ref().unwrap(),
        &clock,
        Keyrings::default(),
    )
    .into_iter()
    .map(|(_, said)| said)
    .filter(|said| said.contains("reverse"))
    .collect();
    assert_eq!(said.len(), 2, "{said:?}");
    assert!(
        said.iter()
            .all(|said| said.contains("adb carries a reverse on"))
    );
    assert!(
        said.first().is_some_and(
            |newest| newest.ends_with("the socket /run/user/1000/metro.sock on the remote")
        ),
        "newest first: {said:?}"
    );
}

/// What adb's consent says, the model's write then the reach of each binding
/// and Gradle's client.
const ADB_CONSENT: &str = "Hedwig may write ADB_SERVER_SOCKET in your shell's startup on the \
                           remote. With it, what reads ADB_SERVER_SOCKET on the remote reaches \
                           adb through a socket only the remote user can open; without it, \
                           through port 5037 there, which every user and program on the remote \
                           can reach. Gradle's own client, which runs connectedAndroidTest, reads \
                           no socket: a remote that runs Gradle takes ADB on the port, where you \
                           leave this off.";

/// A core that granted `capability` to the workspace on `setup`, naming
/// `exposure`, with the window open.
fn granting(capability: &str, setup: Setup, exposure: Exposure) -> Bench {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant(capability, Granted::One(workspace())),
            terms: Terms {
                setup,
                ..terms(Activation::OnRequest, exposure)
            },
        }),
    ));
    assert_eq!(bench.seen().refused, None);
    bench
}

fn line_of<'w>(window: &'w Window, capability: &str) -> &'w Line {
    match &window.board {
        Board::Exposure { groups, .. } => groups
            .iter()
            .flat_map(|group| &group.lines)
            .find(|line| line.remote == Some(workspace()) && line.capability.as_str() == capability)
            .unwrap_or_else(|| unreachable!("{capability}'s line on the workspace")),
        other => unreachable!("{other:?}"),
    }
}

/// Consenting to
/// adb's write, the person reads who on the remote reaches their server with
/// it and without it, and that Gradle's client takes the port; on the line's
/// question as in the grant form.
#[test]
fn adbs_consent_says_what_each_binding_reaches_and_that_gradle_takes_the_port() {
    let mut bench = granting("adb", Setup::Inspect, Exposure::SERVICE);
    bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);
    let shown = window(&bench);
    let Act::Confirm { consequence, .. } = offered(
        &line_of(&shown, "adb").acts,
        "Let Hedwig write the remote tool's configuration...",
    ) else {
        unreachable!("consent is asked first")
    };
    let reach = ADB_CONSENT
        .split_once(". ")
        .map(|(_, reach)| reach)
        .unwrap();
    assert_eq!(
        *consequence,
        format!(
            "On dev/build (coder), where it is missing and never over what you set, Hedwig may \
             write ADB_SERVER_SOCKET in your shell's startup on the remote. Each is marked as \
             Hedwig's where it is, and taken back when you withdraw this. {reach}"
        )
    );

    // Taking the consent back moves the forward to the port every user
    // of the remote reaches, which the model counts wider, so it is asked
    // first with the same reach - where gpg's is one act.
    let mut bench = granting("adb", Setup::Write, Exposure::SERVICE);
    bench.desk.channel_up(&workspace(), "linux");
    refresh(&mut bench);
    let shown = window(&bench);
    let Act::Confirm {
        request,
        consequence,
        ..
    } = offered(&line_of(&shown, "adb").acts, "Stop Hedwig writing there...")
    else {
        unreachable!("taking consent back from adb is asked first")
    };
    assert_eq!(
        *consequence,
        format!("On dev/build (coder), Hedwig takes back what it wrote. {reach}")
    );
    assert_eq!(bench.permits(request), Ok(()));
}

/// A person reads on adb's own line, and under the remote in the menu,
/// what the relay refused the remote and how often, in the model's words,
/// for as long as it needs them; another capability's line says nothing of it.
#[test]
fn a_request_the_adb_relay_withheld_is_on_adbs_line_and_in_the_menu() {
    let mut bench = granting("adb", Setup::Inspect, Exposure::SERVICE);
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(workspace())),
            terms: terms(Activation::OnRequest, Exposure::NONE),
        }),
    ));
    bench.desk.channel_up(&workspace(), "linux");
    let withheld = |request| Happened::TurnedAway {
        remote: Some(workspace()),
        refusal: Refusal::Withheld {
            capability: name("adb"),
            request,
        },
    };
    bench.desk.trail.push(withheld(Withheld::Ending));
    bench.desk.trail.push(withheld(Withheld::Ending));
    bench.desk.trail.push(withheld(Withheld::Reaching));
    refresh(&mut bench);
    let ending = "a request to adb was refused because it would have ended the workstation's ADB \
                  server";
    let reaching = "a request to adb was refused because it would have had the workstation's ADB \
                    server attach an emulator at a port the remote named";
    let shown = window(&bench);
    let adb = line_of(&shown, "adb");
    let mut turned = adb.turned.clone();
    turned.sort();
    assert_eq!(
        turned,
        [format!("{ending}, 2 times"), format!("{reaching}, once")]
    );
    assert_eq!(line_of(&shown, "gpg").turned, Vec::<String>::new());
    let said = menu(&bench);
    assert!(said.contains(&format!("{ending}, 2 times")), "{said:?}");
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    assert!(
        needs
            .iter()
            .any(|need| need.sentence == format!("Refused 2 times for dev/build (coder): {ending}")),
        "{needs:?}"
    );
}

/// What Hedwig could not carry on to the remote is on the capability's line
/// and in the menu with how often, is the refusal itself in the remote's
/// activity, and waits for nobody's word, so no card raises it.
#[test]
fn a_request_with_no_carrier_is_said_on_its_line_in_the_menu_and_the_activity_and_on_no_card() {
    let unhauled = |why: &str| Happened::TurnedAway {
        remote: Some(workspace()),
        refusal: Refusal::Withheld {
            capability: name("adb"),
            request: Withheld::Unhauled(Words::try_from(why).unwrap()),
        },
    };
    let said = |why: &str| {
        format!(
            "a request to adb was refused because Hedwig could not carry it on to the remote: {why}"
        )
    };
    let mut bench = granting("adb", Setup::Inspect, Exposure::SERVICE);
    bench.desk.channel_up(&workspace(), "linux");
    let taken = "the remote's ssh server would not listen at port 7100";
    bench.desk.trail.push(unhauled(taken));
    bench.desk.trail.push(unhauled(taken));
    refresh(&mut bench);
    let often = format!("{}, 2 times", said(taken));
    assert_eq!(
        line_of(&window(&bench), "adb").turned,
        std::slice::from_ref(&often)
    );
    let listed = menu(&bench);
    assert!(listed.contains(&often), "{listed:?}");
    let attention = bench
        .link
        .seen()
        .attached()
        .and_then(|attached| attached.attention.as_ref())
        .expect("what needs the person");
    assert!(
        attention
            .iter()
            .all(|needs| Subject::of(&needs.attention).is_none()),
        "{attention:?}"
    );

    let denied = "dev@build-7.example: Permission denied (publickey).";
    let entries = [Entry {
        seq: Seq(1),
        at: Timestamp(1),
        tick: Tick(1),
        event: unhauled(denied),
    }];
    let activity: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert_eq!(activity, [format!("t1: {}", said(denied))]);
}

/// What readiness finds is the line's state in the model's words
/// where it blocks - a unit of the remote's service manager at the path, the
/// remote's own ADB server at either binding - and carried beside it where it
/// does not, a command that misses the variable among them.
#[test]
fn a_unit_a_live_server_and_a_missed_variable_read_in_the_models_words() {
    let mut bench = granted(Setup::Inspect);
    let connection = bench.desk.channel_up(&workspace(), "linux");
    let socket = path("/run/user/1000/gnupg/S.gpg-agent");
    let unit = Finding::UnitListens {
        unit: Words::try_from("gpg-agent.socket").unwrap(),
        path: socket.clone(),
    };
    let unset = Finding::VariableUnset(Variable::try_from("SSH_AUTH_SOCK").unwrap());
    bench.desk.trail.push(Happened::Checked {
        connection,
        capability: name("gpg"),
        readiness: Readiness::Unready(vec![unit.clone(), unset.clone()]),
    });
    refresh(&mut bench);
    let gpg = window(&bench);
    let gpg = line(&gpg);
    assert_eq!(
        gpg.state,
        "not ready: the remote's service manager holds /run/user/1000/gnupg/S.gpg-agent for \
         gpg-agent.socket, and would start the remote's own agent there; Hedwig masks \
         gpg-agent.socket where you let it write, and otherwise leaves it"
    );
    assert_eq!(
        gpg.cautions,
        [
            "a command the remote runs over SSH does not find SSH_AUTH_SOCK pointing at the socket \
          Hedwig forwards, so such a command must set it itself"
        ]
    );
    let program = name("adb");
    for (at, said) in [
        (
            Binding::Socket(path("/run/user/1000/hedwig/adb")),
            "at /run/user/1000/hedwig/adb",
        ),
        (Binding::Port(Port::try_from(5037).unwrap()), "on port 5037"),
    ] {
        let live = Finding::ServerLive {
            program: program.clone(),
            at,
        };
        assert!(live.blocks());
        assert_eq!(
            words::standing(&hedwig_model::protocol::Standing::Unready(vec![live]), None),
            format!(
                "not ready: the remote's own adb server listens {said}; Hedwig leaves it \
                 running, and forwards there once you stop it with adb kill-server"
            )
        );
    }
}
