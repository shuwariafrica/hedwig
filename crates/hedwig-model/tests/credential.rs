//! A remote's `git` asking the workstation for a credential: its request read
//! as `git`'s cache helper sends it, the workstation's own answer read and
//! passed on without what the remote does not need, and the one gate that
//! decides it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod support;

use hedwig_model::capability::{Capability, Exposure, Form, Lends, Operation, Setup, Source, Spot};
use hedwig_model::config::{Activation, Change, Configuration, Terms};
use hedwig_model::credential::{
    Action, CHALLENGES, LONGEST, Place, Unfilled, Unread, read, released,
};
use hedwig_model::gate::{Interaction, Verdict, World};
use hedwig_model::platform::Platform;
use hedwig_model::policy::{Basis, Mode, RuleScope, Selector};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, Remotes};
use hedwig_model::site::Site;
use hedwig_model::text::{Program, Words};
use hedwig_model::trail::{ClientKind, Outcome, Write};
use support::{DESKTOP, OVER_SSH, Seeded, Trail, catalogue, grant, name, remote};

/// What Ubuntu 24.04's `git` 2.43.0 sent through its cache helper for a push
/// to a repository behind Basic authentication, as recorded.
const GET: &[u8] = b"action=get\ntimeout=900\nprotocol=http\nhost=127.0.0.1:18463\nwwwauth[]=Basic realm=\"hedwig-probe\"\n";

/// The `store` that followed it, carrying back the secret released.
const STORE: &[u8] = b"action=store\ntimeout=900\nprotocol=http\nhost=127.0.0.1:18463\nusername=hedwig-probe\npassword=0123456789abcdefghijklmn\n";

/// What `git credential fill` prints for a site Git Credential Manager holds a
/// token for: the request echoed, the pair, an expiry, and a refresh token the
/// remote never needs (`Documentation/git-credential.adoc`).
const FILLED: &[u8] = b"protocol=https\nhost=github.com\nusername=octocat\npassword=gho_16C7e42F292c6912E7710c838347Ae178B4a\npassword_expiry_utc=1790000000\noauth_refresh_token=ghr_1B4a2e77838347a7E420ce178F2E7c6912E1\n";

fn program(text: &str) -> Program {
    Program::try_from(text).unwrap()
}

fn site(text: &str) -> Site {
    text.parse().unwrap()
}

fn credentials(sites: &[&str]) -> Capability {
    Capability {
        id: name("git-https"),
        source: Source::Credentials {
            git: program("git"),
            sites: sites.iter().map(|text| site(text)).collect(),
        },
    }
}

#[test]
fn gits_request_is_read_and_the_secret_it_carries_back_is_never_kept() {
    let asked = read(GET).unwrap();
    assert_eq!(asked.action, Action::Get);
    let Place::Site(url) = asked.wanted.place().unwrap() else {
        unreachable!("an http request leads to a site")
    };
    assert_eq!(Site::of(&url), site("http://localhost"));
    assert!(!asked.wanted.bearer());
    assert_eq!(
        asked.wanted.to_fill(),
        b"protocol=http\nhost=127.0.0.1:18463\nwwwauth[]=Basic realm=\"hedwig-probe\"\n\n"
    );

    let stored = read(STORE).unwrap();
    assert_eq!(stored.action, Action::Store);
    let kept = format!("{stored:?}");
    assert!(!kept.contains("0123456789abcdefghijklmn"), "{kept}");
    let filled = String::from_utf8(stored.wanted.to_fill()).unwrap();
    assert!(!filled.contains("password"), "{filled}");
    assert!(filled.contains("username=hedwig-probe\n"), "{filled}");

    let erase = read(b"action=erase\ntimeout=900\nprotocol=https\nhost=github.com\nusername=octocat\npassword=gho_x\n").unwrap();
    assert_eq!(erase.action, Action::Erase);
    assert_eq!(
        read(b"action=exit\ntimeout=900\n").unwrap().action,
        Action::Other
    );
    assert_eq!(
        read(b"action=frobnicate\ntimeout=900\n").unwrap().action,
        Action::Other
    );
}

/// `git` 2.46 and later say they read a bearer credential; the workstation's
/// `git` is told so, and a path, a user name and every challenge pass on.
#[test]
fn a_newer_git_is_asked_for_a_bearer_credential_and_names_its_path_and_user() {
    let asked = read(b"action=get\ntimeout=900\ncapability[]=authtype\ncapability[]=state\nprotocol=https\nhost=dev.azure.com\npath=org/project/_git/repo\nusername=me\nwwwauth[]=Bearer authorization_uri=https://login.example.invalid\nwwwauth[]=Basic realm=\"x\"\nstate[]=hedwig:1\n").unwrap();
    assert!(asked.wanted.bearer());
    assert_eq!(
        String::from_utf8(asked.wanted.to_fill()).unwrap(),
        "capability[]=authtype\nprotocol=https\nhost=dev.azure.com\npath=org/project/_git/repo\nusername=me\nwwwauth[]=Bearer authorization_uri=https://login.example.invalid\nwwwauth[]=Basic realm=\"x\"\n\n"
    );
}

/// What the workstation's `git credential fill` is given reads back, as a
/// request, as what the remote asked: the request round-trips.
#[test]
fn what_the_workstation_is_given_reads_back_as_what_was_asked() {
    for request in [
        GET.to_vec(),
        b"action=get\ntimeout=900\ncapability[]=authtype\nprotocol=https\nhost=github.com\npath=a/b\nusername=u\n".to_vec(),
        b"action=get\ntimeout=900\nprotocol=cert\npath=/home/u/client.p12\n".to_vec(),
    ] {
        let asked = read(&request).unwrap();
        let mut again = b"action=get\ntimeout=900\n".to_vec();
        again.extend(asked.wanted.to_fill());
        assert_eq!(read(&again).unwrap(), asked);
    }
}

#[test]
fn what_git_does_not_send_is_refused_with_why() {
    let mut long = b"action=get\ntimeout=900\nwwwauth[]=".to_vec();
    long.resize(LONGEST + 1, b'a');
    let mut challenges = b"action=get\ntimeout=900\nprotocol=https\nhost=a.example\n".to_vec();
    for _ in 0..=CHALLENGES {
        challenges.extend_from_slice(b"wwwauth[]=Basic\n");
    }
    for (sent, why) in [
        (long, Unread::TooLong),
        (b"timeout=900\naction=get\n".to_vec(), Unread::Action),
        (b"".to_vec(), Unread::Action),
        (b"action=get\n".to_vec(), Unread::Timeout),
        (b"action=get\ntimeout=\n".to_vec(), Unread::Timeout),
        (b"action=get\ntimeout=-1\n".to_vec(), Unread::Timeout),
        (
            b"action=get\ntimeout=900\nprotocol\n".to_vec(),
            Unread::Line,
        ),
        (challenges, Unread::Line),
        (
            b"action=get\ntimeout=900\nhost=a\r\n".to_vec(),
            Unread::Value,
        ),
        (
            b"action=get\ntimeout=900\nusername=\x01\n".to_vec(),
            Unread::Value,
        ),
        (
            b"action=get\ntimeout=900\npath=\xff\n".to_vec(),
            Unread::Value,
        ),
        (
            b"action=get\ntimeout=900\nprotocol=https\nhost=exa mple\n".to_vec(),
            Unread::Host,
        ),
        (
            b"action=get\ntimeout=900\nprotocol=https\n".to_vec(),
            Unread::Host,
        ),
        (
            b"action=get\ntimeout=900\nprotocol=https\nhost=-x\n".to_vec(),
            Unread::Host,
        ),
        (
            b"action=get\ntimeout=900\nprotocol=https\nhost=a@b\n".to_vec(),
            Unread::Host,
        ),
    ] {
        assert_eq!(read(&sent), Err(why), "{}", String::from_utf8_lossy(&sent));
        assert_ne!(why.to_string(), "");
    }
}

/// A client certificate's passphrase and a mail server's login are `git`'s
/// credentials too, and are named by their protocol, never read as a site.
#[test]
fn another_protocol_is_named_and_never_read_as_a_site() {
    let cert = read(b"action=get\ntimeout=900\nprotocol=cert\npath=/home/u/client.p12\n").unwrap();
    assert_eq!(
        cert.wanted.place().unwrap(),
        Place::Other(Some(Words::try_from("cert").unwrap()))
    );
    let smtp = read(b"action=get\ntimeout=900\nprotocol=smtp\nhost=smtp.example:587\n").unwrap();
    assert_eq!(
        smtp.wanted.place().unwrap(),
        Place::Other(Some(Words::try_from("smtp").unwrap()))
    );
    let none = read(b"action=get\ntimeout=900\nhost=example\n").unwrap();
    assert_eq!(none.wanted.place().unwrap(), Place::Other(None));
}

/// Whatever a hostile remote sends is read or refused, never a panic, and
/// what the workstation is then given holds only the lines this reader
/// writes, one to a line.
#[test]
fn noise_from_a_remote_is_read_or_refused_and_never_reaches_the_workstation_as_more() {
    let pieces: [&[u8]; 16] = [
        b"action=get\n",
        b"timeout=900\n",
        b"protocol=https\n",
        b"host=github.com\n",
        b"password=x\n",
        b"url=https://evil.example\n",
        b"capability[]=authtype\n",
        b"wwwauth[]=Basic\n",
        b"=\n",
        b"\n",
        b"\r",
        b"\0",
        b"=",
        b"path=a\tb\n",
        b"\xc3\xa9",
        b"quit=1\n",
    ];
    let mut seeded = Seeded(43);
    let mut read_some = 0;
    for _ in 0..5_000 {
        // Half begin as `git` begins, so the lines after are read too.
        let mut sent = if seeded.below(2) == 0 {
            b"action=get
timeout=900
"
            .to_vec()
        } else {
            Vec::new()
        };
        for _ in 0..seeded.below(12) {
            sent.extend_from_slice(seeded.pick(&pieces));
        }
        if let Ok(asked) = read(&sent) {
            read_some += 1;
            let filled = asked.wanted.to_fill();
            let filled = String::from_utf8(filled).unwrap();
            for line in filled.lines().filter(|line| !line.is_empty()) {
                let key = line.split_once('=').unwrap().0;
                assert!(
                    [
                        "capability[]",
                        "protocol",
                        "host",
                        "path",
                        "username",
                        "wwwauth[]"
                    ]
                    .contains(&key),
                    "{line}"
                );
            }
        }
    }
    assert!(read_some > 100);
}

#[test]
fn the_workstations_answer_is_released_without_what_the_remote_never_needs() {
    let answer = released(FILLED, false).unwrap();
    assert_eq!(
        answer.answer().as_slice(),
        b"username=octocat\npassword=gho_16C7e42F292c6912E7710c838347Ae178B4a\npassword_expiry_utc=1790000000\n"
    );
    assert_eq!(format!("{answer:?}"), "Released(redacted)");
    // What the remote is given reads back as the same credential.
    assert_eq!(released(&answer.answer(), false).unwrap(), answer);

    let bearer = b"protocol=https\nhost=dev.azure.com\ncapability[]=authtype\nauthtype=Bearer\ncredential=eyJ0eXAi\nephemeral=1\n";
    let given = released(bearer, true).unwrap();
    assert_eq!(
        given.answer().as_slice(),
        b"capability[]=authtype\nauthtype=Bearer\ncredential=eyJ0eXAi\nephemeral=1\n"
    );
    assert_eq!(released(&given.answer(), true).unwrap(), given);
    // A remote that does not read a bearer credential is given none.
    assert_eq!(released(bearer, false), Err(Unfilled::Incomplete));

    let mut long = b"password=".to_vec();
    long.resize(LONGEST + 1, b'a');
    for (filled, why) in [
        (
            b"protocol=https\nhost=github.com\n".to_vec(),
            Unfilled::Incomplete,
        ),
        (b"username=u\n".to_vec(), Unfilled::Incomplete),
        (b"username=u\npassword\n".to_vec(), Unfilled::Malformed),
        (
            b"username=u\npassword=a\x07b\n".to_vec(),
            Unfilled::Malformed,
        ),
        (b"username=u\npassword=\xff\n".to_vec(), Unfilled::Malformed),
        (long, Unfilled::TooLong),
    ] {
        assert_eq!(released(&filled, false), Err(why));
        assert_ne!(why.to_string(), "");
    }
    // An expiry is passed on only as digits.
    let odd = released(b"username=u\npassword=p\npassword_expiry_utc=soon\n", false).unwrap();
    assert_eq!(odd.answer().as_slice(), b"username=u\npassword=p\n");
}

struct Scene {
    catalogue: hedwig_model::config::Catalogue,
    configuration: Configuration,
    trail: Trail,
    connection: hedwig_model::trail::ConnectionId,
}

impl Scene {
    fn new(capability: &Capability) -> Scene {
        let catalogue = catalogue();
        let host = remote("ssh", "build");
        let mut configuration = Configuration::default();
        for change in [
            Change::Define(capability.clone()),
            Change::Grant {
                grant: grant("git-https", Granted::One(host.clone())),
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Write,
                    acknowledged: Exposure::SECRET,
                    lends: Lends::none(),
                },
            },
        ] {
            configuration.apply(&catalogue, change).unwrap();
        }
        let mut trail = Trail::started();
        let connection = trail.open(&host, "linux");
        Scene {
            catalogue,
            configuration,
            trail,
            connection,
        }
    }

    fn decide(&self, sent: &[u8]) -> Verdict {
        let state = self.trail.state();
        let place = read(sent).unwrap().wanted.place().unwrap();
        World {
            catalogue: &self.catalogue,
            configuration: &self.configuration,
            state: &state,
        }
        .credential(
            self.connection,
            &name("git-https"),
            &place,
            self.trail.tick(),
        )
    }
}

/// A credential is confirmed unless the person says otherwise, and
/// refused naming the site wherever no site admits it, it would cross the
/// network unencrypted, or it is not a site at all.
#[test]
fn a_credential_is_decided_at_the_one_gate() {
    let capability = credentials(&["https://github.com", "http://localhost:18463"]);
    let mut scene = Scene::new(&capability);
    scene.trail.attach(ClientKind::Terminal, DESKTOP);
    let get = |host: &str, protocol: &str| {
        format!("action=get\ntimeout=900\nprotocol={protocol}\nhost={host}\n").into_bytes()
    };
    assert_eq!(
        scene.decide(&get("github.com", "https")),
        Verdict::Hold(Basis::Default)
    );
    assert_eq!(scene.decide(GET), Verdict::Hold(Basis::Default));
    assert_eq!(
        scene.decide(&get("gitlab.com", "https")),
        Verdict::Refuse(Refusal::UnlistedCredential {
            capability: name("git-https"),
            site: site("https://gitlab.com"),
        })
    );
    assert_eq!(
        scene.decide(&get("github.com:8443", "https")),
        Verdict::Refuse(Refusal::UnlistedCredential {
            capability: name("git-https"),
            site: site("https://github.com:8443"),
        })
    );
    assert_eq!(
        scene.decide(&get("github.com", "http")),
        Verdict::Refuse(Refusal::Cleartext {
            capability: name("git-https"),
            site: site("http://github.com"),
        })
    );
    assert_eq!(
        scene.decide(b"action=get\ntimeout=900\nprotocol=smtp\nhost=smtp.example\n"),
        Verdict::Refuse(Refusal::NotWeb {
            capability: name("git-https"),
            protocol: Some(Words::try_from("smtp").unwrap()),
        })
    );

    // The person's own rule decides it.
    let rule = Change::Rule {
        scope: RuleScope {
            remotes: Remotes::Every,
            capability: Selector::Only(name("git-https")),
            operation: Selector::Every,
            key: hedwig_model::policy::Keys::Every,
        },
        mode: Mode::Notify,
    };
    scene.configuration.apply(&scene.catalogue, rule).unwrap();
    assert!(matches!(
        scene.decide(&get("github.com", "https")),
        Verdict::Serve(Outcome::Served(Basis::Rule(_)))
    ));
    // A remote nothing granted is refused before any site is read.
    let state = scene.trail.state();
    let other = World {
        catalogue: &scene.catalogue,
        configuration: &Configuration::default(),
        state: &state,
    }
    .credential(
        scene.connection,
        &name("git-https"),
        &Place::Other(None),
        scene.trail.tick(),
    );
    assert!(
        matches!(
            other,
            Verdict::Refuse(Refusal::UnknownCapability(_) | Refusal::NotGranted { .. })
        ),
        "{other:?}"
    );
}

/// Nobody reachable, a confirmed release is refused, as every held request.
#[test]
fn a_credential_nobody_can_confirm_is_refused() {
    let scene = Scene::new(&credentials(&["https://github.com"]));
    let verdict = scene.decide(b"action=get\ntimeout=900\nprotocol=https\nhost=github.com\n");
    assert!(
        matches!(verdict, Verdict::Refuse(Refusal::NobodyReachable(_))),
        "{verdict:?}"
    );
}

/// A sign-in the workstation's helper would raise is let happen only where
/// the person allowed the request in the session the core runs in.
#[test]
fn a_helper_may_ask_only_where_the_person_allowed_it_at_the_desktop() {
    let mut scene = Scene::new(&credentials(&["https://github.com"]));
    let desk = scene.trail.attach(ClientKind::Interface, DESKTOP);
    let away = scene.trail.attach(ClientKind::Terminal, OVER_SSH);
    let state = scene.trail.state();
    let world = World {
        catalogue: &scene.catalogue,
        configuration: &scene.configuration,
        state: &state,
    };
    assert_eq!(
        world.interaction(&Outcome::Allowed(desk)),
        Interaction::Allowed
    );
    assert_eq!(world.interaction(&Outcome::Allowed(away)), Interaction::Off);
    assert_eq!(world.interaction(&Outcome::Covered), Interaction::Off);
    assert_eq!(
        world.interaction(&Outcome::Served(Basis::Default)),
        Interaction::Off
    );
}

/// The capability's one form is git's helper at a private socket, written
/// under consent; a Windows remote has none, and a second capability
/// answering the same remote's git is refused with the first.
#[test]
fn a_credential_is_carried_only_where_git_can_be_pointed_at_it() {
    let catalogue = catalogue();
    let capability = credentials(&["https://github.com"]);
    assert_eq!(capability.exposure(), Exposure::SECRET);
    assert_eq!(capability.forms(), vec![Form::Helper]);
    assert_eq!(capability.consent(None).writes, vec![Write::Helper]);
    assert_eq!(Form::Helper.spots(), vec![Spot::Helper]);
    assert_eq!(
        capability.dialect().operations(),
        &[Operation::Connect],
        "serving the opening is the release"
    );
    let shipped = Configuration::default();
    let linux = shipped.platform(&catalogue, &name("linux")).unwrap();
    let windows: &Platform = shipped.platform(&catalogue, &name("windows")).unwrap();
    assert_eq!(capability.carrier(linux, Setup::Write), Ok(Form::Helper));
    assert!(matches!(
        capability.carrier(linux, Setup::Inspect),
        Err(Refusal::NeedsRemoteSetup { .. })
    ));
    assert_eq!(
        capability.carrier(windows, Setup::Write),
        Err(Refusal::NoCarrier {
            capability: name("git-https"),
            platform: name("windows"),
        })
    );
    assert_eq!(
        Refusal::NoCarrier {
            capability: name("git-https"),
            platform: name("windows"),
        }
        .to_string(),
        "a windows remote's own SSH server has no way to carry git-https"
    );

    let mut scene = Scene::new(&capability);
    let mut second = credentials(&["https://gitlab.com"]);
    second.id = name("git-lab");
    for change in [
        Change::Define(second),
        Change::Grant {
            grant: grant("git-lab", Granted::One(remote("ssh", "build"))),
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::SECRET,
                lends: Lends::none(),
            },
        },
    ] {
        scene.configuration.apply(&scene.catalogue, change).unwrap();
    }
    let state = scene.trail.state();
    let plan = World {
        catalogue: &scene.catalogue,
        configuration: &scene.configuration,
        state: &state,
    }
    .plan(scene.connection)
    .unwrap();
    assert_eq!(
        plan.get(&name("git-https")),
        Some(&Err(Refusal::Shared {
            capability: name("git-https"),
            with: name("git-lab"),
            spot: Spot::Helper,
        }))
    );
}

/// A site on plain `http` beyond the remote's loopback is refused where the
/// person names it, since no request for it could be served.
#[test]
fn a_cleartext_site_is_refused_where_it_is_named() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    assert_eq!(
        configuration.apply(
            &catalogue,
            Change::Define(credentials(&[
                "https://github.com",
                "http://git.example.invalid"
            ]))
        ),
        Err(Refusal::Cleartext {
            capability: name("git-https"),
            site: site("http://git.example.invalid"),
        })
    );
    assert!(
        configuration
            .apply(
                &catalogue,
                Change::Define(credentials(&["http://localhost"]))
            )
            .is_ok()
    );
}

/// Nothing that answers for the person's credentials ships: its sites are
/// theirs, each named by a refusal and added in one act.
#[test]
fn no_shipped_capability_releases_a_credential() {
    let catalogue = catalogue();
    assert!(
        !Configuration::default()
            .definitions(&catalogue)
            .capabilities
            .iter()
            .any(|defined| matches!(defined.definition.source, Source::Credentials { .. }))
    );
}
