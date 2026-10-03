//! One key named once across `gpg` and SSH: gpg-agent's keyring ties a key's
//! keygrip and fingerprints to its SSH public half, so a statement about the
//! key decides its use through either dialect, and its card's safeguards
//! are read for both.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::{Exposure, Lends, Operation, Setup, Toward};
use hedwig_model::config::{Activation, Change, Configuration, Terms};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::policy::{Basis, KeyName, Keys, Mode, RuleScope, Selector};
use hedwig_model::remote::{Granted, Remotes};
use hedwig_model::text::{Fingerprint, Grip, KeyId, Serial, SshKey};
use hedwig_model::trail::{
    Card, ClientKind, ConnectionId, Event, Held, Key, Keyring, Outcome, Presence, Touch, Uses,
};

mod support;
use support::{DESKTOP, Trail, catalogue, grant, name, remote};

/// A release key: a primary that signs, and a subkey on a card that
/// authenticates and is offered for SSH, as gpg-agent writes its public half.
const PRIMARY: &str = "07B56DFBBA12BB80FA84939C76F8274EF1651088";
const AUTH_PRINT: &str = "5A1B9C0D2E3F405162738495A6B7C8D9E0F1A2B3";
const AUTH_GRIP: &str = "9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3";
const SIGN_GRIP: &str = "64EFB4597F2EB1968F187B7235A461FC48342EC5";
const AUTH_SSH: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1cuDWSQ4xW25Rb1dBGnBjWHV2DfwPn/bqUaSYf4z15";
const CARD: &str = "D2760001240103040006123456780000";

fn ssh() -> SshKey {
    SshKey::try_from(AUTH_SSH).unwrap()
}

fn keyring(tied: bool) -> Keyring {
    let primary = Fingerprint::try_from(PRIMARY).unwrap();
    Keyring {
        keys: vec![
            Key {
                grip: Grip::try_from(SIGN_GRIP).unwrap(),
                fingerprint: primary.clone(),
                primary: primary.clone(),
                uses: Uses::SIGN,
                user: None,
                card: None,
                ssh: None,
            },
            Key {
                grip: Grip::try_from(AUTH_GRIP).unwrap(),
                fingerprint: Fingerprint::try_from(AUTH_PRINT).unwrap(),
                primary,
                uses: Uses::AUTHENTICATE,
                user: None,
                card: Some(Serial::try_from(CARD).unwrap()),
                ssh: tied.then(ssh),
            },
        ],
        signing: None,
    }
}

struct Scene {
    configuration: Configuration,
    trail: Trail,
    connection: ConnectionId,
}

/// `gpg`, `gpg-ssh` and `ssh-agent` granted to one host, the authentication
/// key lent by both agent capabilities, `rules` written, each `GnuPG`
/// capability offering the keyring, the card read with `touch` on its
/// authentication key, and an interface present to ask.
fn scene(tied: bool, touch: Touch, rules: &[(RuleScope, Mode)]) -> Scene {
    let catalogue = catalogue();
    let host = remote("ssh", "build");
    let lent = Lends::of_keys([(ssh(), Toward::Anywhere.into())]);
    let mut configuration = Configuration::default();
    for (capability, lends) in [
        ("gpg", Lends::none()),
        ("gpg-ssh", lent.clone()),
        ("ssh-agent", lent),
    ] {
        configuration
            .apply(
                &catalogue,
                Change::Grant {
                    grant: grant(capability, Granted::One(host.clone())),
                    terms: Terms {
                        activation: Activation::OnRequest,
                        setup: Setup::Inspect,
                        acknowledged: Exposure::NONE,
                        lends,
                    },
                },
            )
            .unwrap();
    }
    for (scope, mode) in rules {
        configuration
            .apply(
                &catalogue,
                Change::Rule {
                    scope: scope.clone(),
                    mode: *mode,
                },
            )
            .unwrap();
    }
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    for capability in ["gpg", "gpg-ssh"] {
        trail.push(Event::Offered {
            capability: name(capability),
            keyring: keyring(tied),
        });
    }
    trail.push(Event::Card(Card {
        serial: Serial::try_from(CARD).unwrap(),
        keys: vec![Held {
            grip: Grip::try_from(AUTH_GRIP).unwrap(),
            touch: Some(touch),
        }],
        pin: None,
    }));
    let client = trail.attach(ClientKind::Interface, DESKTOP);
    trail.push(Event::Presence {
        client,
        presence: Presence::Present,
    });
    Scene {
        configuration,
        trail,
        connection,
    }
}

impl Scene {
    fn ask(&self, capability: &str, operation: Operation, key: &KeyId) -> Verdict {
        let catalogue = catalogue();
        let state = self.trail.state();
        let world = World {
            catalogue: &catalogue,
            configuration: &self.configuration,
            state: &state,
        };
        world.decide(
            self.connection,
            &name(capability),
            operation,
            Some(key),
            self.trail.tick(),
        )
    }
}

fn rule(keys: Keys) -> RuleScope {
    RuleScope {
        remotes: Remotes::Every,
        capability: Selector::Every,
        operation: Selector::Every,
        key: keys,
    }
}

fn lax() -> (RuleScope, Mode) {
    (rule(Keys::Every), Mode::Unattended)
}

fn held(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Hold(_))
}

/// Served by the lax rule, with nobody asked.
fn unattended(verdict: &Verdict) -> bool {
    matches!(
        verdict,
        Verdict::Serve(Outcome::Served(Basis::Rule(scope)) | Outcome::Unseen(Basis::Rule(scope)))
            if *scope == lax().0
    )
}

/// A statement naming the release key by its primary fingerprint, by the
/// authentication subkey's fingerprint, or by its keygrip decides that
/// key's login through gpg-agent's SSH socket, over a laxer one for every
/// key; untied, it would not, and the login is served unattended.
#[test]
fn a_statement_about_an_openpgp_key_decides_its_ssh_use() {
    let login = KeyId::Ssh(ssh());
    for name_ in [
        KeyName::Fingerprint(Fingerprint::try_from(PRIMARY).unwrap()),
        KeyName::Fingerprint(Fingerprint::try_from(AUTH_PRINT).unwrap()),
        KeyName::Grip(Grip::try_from(AUTH_GRIP).unwrap()),
    ] {
        let strict = rule(Keys::Only(name_.clone()));
        let tied = scene(true, Touch::Off, &[(strict.clone(), Mode::Confirm), lax()]);
        assert_eq!(
            tied.ask("gpg-ssh", Operation::Authenticate, &login),
            Verdict::Hold(Basis::Rule(strict.clone())),
            "{name_:?}"
        );
        let untied = scene(false, Touch::Off, &[(strict, Mode::Confirm), lax()]);
        assert!(
            unattended(&untied.ask("gpg-ssh", Operation::Authenticate, &login)),
            "{name_:?}"
        );
    }
}

/// A statement naming the key by its SSH public half decides its use
/// through `gpg` too: a card's `PKAUTH` names the key by its keygrip.
#[test]
fn a_statement_about_an_ssh_key_decides_its_use_through_gpg() {
    let strict = rule(Keys::Only(KeyName::Ssh(ssh())));
    let tied = scene(true, Touch::Off, &[(strict.clone(), Mode::Confirm), lax()]);
    let by_grip = KeyId::Grip(Grip::try_from(AUTH_GRIP).unwrap());
    assert_eq!(
        tied.ask("gpg", Operation::Authenticate, &by_grip),
        Verdict::Hold(Basis::Rule(strict.clone()))
    );
    let other = KeyId::Grip(Grip::try_from(SIGN_GRIP).unwrap());
    assert!(
        unattended(&tied.ask("gpg", Operation::Sign, &other)),
        "another key of the same primary is not that key"
    );
    let untied = scene(false, Touch::Off, &[(strict, Mode::Confirm), lax()]);
    assert!(unattended(&untied.ask(
        "gpg",
        Operation::Authenticate,
        &by_grip
    )));
}

/// The card's safeguards are read for the key whichever dialect uses it: a
/// key whose card asks for a touch is not one usable with nobody there, so a
/// rule serving those unattended leaves its SSH login to the next statement.
#[test]
fn a_card_key_s_touch_decides_its_ssh_use() {
    let no_touch = (rule(Keys::NeedingNoTouch), Mode::Unattended);
    let confirm = (rule(Keys::Every), Mode::Confirm);
    let login = KeyId::Ssh(ssh());
    let touched = scene(true, Touch::On, &[no_touch.clone(), confirm.clone()]);
    assert!(held(&touched.ask(
        "gpg-ssh",
        Operation::Authenticate,
        &login
    )));
    let off = scene(true, Touch::Off, &[no_touch.clone(), confirm]);
    assert_eq!(
        off.ask("gpg-ssh", Operation::Authenticate, &login),
        Verdict::Serve(Outcome::Served(Basis::Rule(no_touch.0)))
    );
}

/// An agent the core reads no keyring of - here the well-known pipe's -
/// names the key by its public half and nothing more: a statement about an
/// `OpenPGP` fingerprint does not reach it, one about the SSH key does.
#[test]
fn an_agent_without_a_keyring_names_a_key_by_its_public_half_alone() {
    let login = KeyId::Ssh(ssh());
    let by_print = rule(Keys::Only(KeyName::Fingerprint(
        Fingerprint::try_from(PRIMARY).unwrap(),
    )));
    let scene_ = scene(true, Touch::Off, &[(by_print, Mode::Confirm), lax()]);
    assert!(unattended(&scene_.ask(
        "ssh-agent",
        Operation::Authenticate,
        &login
    )));
    let by_ssh = rule(Keys::Only(KeyName::Ssh(ssh())));
    let scene_ = scene(true, Touch::Off, &[(by_ssh.clone(), Mode::Confirm), lax()]);
    assert_eq!(
        scene_.ask("ssh-agent", Operation::Authenticate, &login),
        Verdict::Hold(Basis::Rule(by_ssh))
    );
}

/// A row tells a key gpg-agent offers for SSH apart by the name SSH
/// requests give it, so a surface shows how its login would be decided.
#[test]
fn a_row_of_gpg_ssh_tells_the_offered_key_apart_by_its_public_half() {
    let strict = rule(Keys::Only(KeyName::Fingerprint(
        Fingerprint::try_from(PRIMARY).unwrap(),
    )));
    let scene_ = scene(true, Touch::Off, &[(strict, Mode::Confirm)]);
    let catalogue = catalogue();
    let state = scene_.trail.state();
    let world = World {
        catalogue: &catalogue,
        configuration: &scene_.configuration,
        state: &state,
    };
    let client = hedwig_model::trail::ClientId(hedwig_model::trail::Seq(0));
    let row = world
        .rows(client, scene_.trail.tick())
        .into_iter()
        .find(|row| row.capability == name("gpg-ssh"))
        .expect("a row for gpg-ssh");
    let keyed: Vec<&KeyId> = row
        .decides
        .iter()
        .filter_map(|decides| decides.key.as_ref())
        .collect();
    assert!(keyed.contains(&&KeyId::Ssh(ssh())), "{:?}", row.decides);
    assert!(
        !keyed.iter().any(|key| matches!(key, KeyId::Grip(_))),
        "an SSH request never names a keygrip: {:?}",
        row.decides
    );
    let _ = grant("gpg", Granted::One(remote("ssh", "build")));
}
