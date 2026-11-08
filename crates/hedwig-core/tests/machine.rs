//! A key the workstation's TPM holds: what the deciding function makes of
//! making, finding and deleting one, and the core's own signer against this
//! workstation's TPM. Every key here has a name of the run's own and is
//! deleted.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

mod common;

use hedwig_core::agent::FAILURE;
use hedwig_core::dispatch::{Core, Effect, Input, Link, Now, Step};
use hedwig_core::machine::{self, PREFIX};
use hedwig_model::capability::{Exposure, KeyKind, Lends, Setup, Toward};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::protocol::{AgentKey, FromCore, Notice, PROTOCOL, Reply, Request, ToCore, Topic};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::text::{Address, Name, SshKey, Words, ssh_string};
use hedwig_model::trail::{ClientKind, Event, Integrity, Origin, Tick, Timestamp};

const TERMINAL: Link = Link(1);
const VIEWER: Link = Link(2);
const NOW: Now = Now {
    at: Timestamp(1_790_000_000_000),
    tick: Tick(1_000),
};
const DESKTOP: Origin = Origin {
    process: 4100,
    logon: 0x3e7_0000,
    session: 2,
    integrity: Integrity::Medium,
};
const P256: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrm25FDDmgurPp+9REqiJK8zAJcpqMSElCklOS/AsegLtx+gx5BUgH5CnBk5aAOQSkrVsP5DuaWeib+dCzCSqo=";
const OTHER: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1cuDWSQ4xW25Rb1dBGnBjWHV2DfwPn/bqUaSYf4z15";

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn key(text: &str) -> SshKey {
    SshKey::try_from(text).unwrap()
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("dev@build-7.example").unwrap(),
    }
}

struct Scene {
    core: Core,
    asked: u32,
}

impl Scene {
    /// A terminal and a viewer attached, `machine-ssh` granted to the remote
    /// lending `P256` and `OTHER`.
    fn new() -> Scene {
        let mut core = Core::new(
            Catalogue::shipped().unwrap(),
            Configuration::default(),
            Vec::new(),
            "0.2.0".to_owned(),
        );
        core.begin(DESKTOP, None, Vec::new(), NOW);
        let mut scene = Scene { core, asked: 0 };
        scene.attach(TERMINAL, ClientKind::Terminal);
        scene.attach(VIEWER, ClientKind::Interface);
        scene.ask(
            TERMINAL,
            Request::Change(Change::Grant {
                grant: Grant {
                    capability: name("machine-ssh"),
                    remotes: Granted::One(remote()),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Write,
                    acknowledged: Exposure::NONE,
                    lends: Lends::of_keys(
                        [P256, OTHER].map(|text| (key(text), Toward::Anywhere.into())),
                    ),
                },
            }),
        );
        scene
    }

    fn step(&mut self, input: Input) -> Step {
        let step = self.core.step(input, NOW);
        common::keyed(&mut self.core, step, NOW)
    }

    fn attach(&mut self, link: Link, kind: ClientKind) {
        self.step(Input::Arrived {
            link,
            peer: Some(DESKTOP.into()),
        });
        self.ask(
            link,
            Request::Hello {
                protocol: PROTOCOL,
                kind,
                attends: Remotes::Every,
            },
        );
    }

    fn ask(&mut self, link: Link, request: Request) -> Step {
        self.asked += 1;
        let frame = ToCore {
            id: self.asked,
            request,
        };
        let step = self.step(Input::Asked { link, frame });
        self.sent(&step, link);
        step
    }

    fn sent(&mut self, step: &Step, link: Link) {
        for _ in step
            .effects
            .iter()
            .filter(|effect| matches!(effect, Effect::Send { link: to, .. } if *to == link))
        {
            self.core.step(Input::Sent { link }, NOW);
        }
    }

    fn lends(&self) -> Lends {
        self.core
            .configuration()
            .grants()
            .next()
            .map(|(_, terms)| terms.lends.clone())
            .unwrap()
    }
}

fn reply(step: &Step, to: Link) -> Option<&Result<Reply, Refusal>> {
    step.effects.iter().find_map(|effect| match effect {
        Effect::Send {
            link,
            frame: FromCore::Reply { reply, .. },
            ..
        } if *link == to => Some(reply),
        _ => None,
    })
}

fn notices(step: &Step, to: Link) -> Vec<Notice> {
    step.effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Send {
                link,
                frame: FromCore::Notice(notice),
                ..
            } if *link == to => Some(notice.clone()),
            _ => None,
        })
        .collect()
}

fn events(step: &Step) -> Vec<Event> {
    step.entries
        .iter()
        .map(|entry| entry.event.clone())
        .collect()
}

/// Making a key goes to the TPM off the deciding thread; made, it is
/// recorded and answered, and the viewer that lists the TPM's keys is told
/// they changed. A refusal from the TPM is the reply, and nothing is
/// recorded.
#[test]
fn a_key_made_is_recorded_answered_and_told_to_the_client_that_lists_keys() {
    let mut scene = Scene::new();
    let step = scene.ask(VIEWER, Request::Keys(name("machine-ssh")));
    let listing = scene.asked;
    assert!(step.effects.iter().any(|effect| matches!(
        effect,
        Effect::Keys { capability, .. } if *capability == name("machine-ssh")
    )));
    let step = scene.step(Input::Keys {
        link: VIEWER,
        id: listing,
        capability: name("machine-ssh"),
        listed: hedwig_core::relay::Reach {
            result: Ok(Vec::new()),
            holder: None,
        },
    });
    scene.sent(&step, VIEWER);

    let step = scene.ask(
        TERMINAL,
        Request::MakeKey {
            name: name("laptop"),
            kind: KeyKind::EcdsaP256,
        },
    );
    let id = scene.asked;
    assert!(step.effects.iter().any(|effect| matches!(
        effect,
        Effect::MakeKey { link, id: asked, kind: KeyKind::EcdsaP256, name: made }
            if *link == TERMINAL && *asked == id && *made == name("laptop")
    )));
    assert!(reply(&step, TERMINAL).is_none(), "answered once made");

    let made = AgentKey {
        key: key(P256),
        comment: Some(Words::try_from("laptop").unwrap()),
    };
    let step = scene.step(Input::Made {
        link: TERMINAL,
        id,
        name: name("laptop"),
        made: Ok(made.clone()),
    });
    assert_eq!(reply(&step, TERMINAL), Some(&Ok(Reply::Made(made))));
    assert!(events(&step).iter().any(|event| matches!(
        event,
        Event::KeyMade { key: made, name: named, .. } if *made == key(P256) && *named == name("laptop")
    )));
    assert_eq!(
        notices(&step, VIEWER),
        [Notice::Stale(Topic::Keys(name("machine-ssh")))]
    );
    assert!(notices(&step, TERMINAL).is_empty(), "it lists nothing");

    for refusal in [
        Refusal::KeyExists(name("laptop")),
        Refusal::KindUnmade(KeyKind::Rsa4096),
        Refusal::NoTpm,
    ] {
        scene.ask(
            TERMINAL,
            Request::MakeKey {
                name: name("laptop"),
                kind: KeyKind::Rsa4096,
            },
        );
        let step = scene.step(Input::Made {
            link: TERMINAL,
            id: scene.asked,
            name: name("laptop"),
            made: Err(refusal.clone()),
        });
        assert_eq!(reply(&step, TERMINAL), Some(&Err(refusal)));
        assert!(events(&step).is_empty(), "{step:?}");
        assert_eq!(notices(&step, VIEWER), Vec::<Notice>::new());
    }
}

/// Deleting a key is found in the TPM first, so a key it does not hold
/// changes nothing; found, every lending of it is taken back and recorded
/// before the TPM is asked to delete it; deleted, it is recorded and
/// answered.
#[test]
fn a_key_is_found_unlent_then_deleted() {
    let mut scene = Scene::new();
    let step = scene.ask(TERMINAL, Request::DeleteKey(key(P256)));
    let id = scene.asked;
    assert!(step.effects.iter().any(|effect| matches!(
        effect,
        Effect::FindKey { link, id: asked, key: found } if *link == TERMINAL && *asked == id && *found == key(P256)
    )));
    let step = scene.step(Input::Found {
        link: TERMINAL,
        id,
        key: key(P256),
        found: Err(Refusal::KeyAbsent(key(P256))),
    });
    assert_eq!(
        reply(&step, TERMINAL),
        Some(&Err(Refusal::KeyAbsent(key(P256))))
    );
    assert_eq!(events(&step), Vec::<Event>::new());
    assert_eq!(scene.lends().keys().count(), 2);
    scene.sent(&step, TERMINAL);

    scene.ask(TERMINAL, Request::DeleteKey(key(P256)));
    let id = scene.asked;
    let step = scene.step(Input::Found {
        link: TERMINAL,
        id,
        key: key(P256),
        found: Ok(name("laptop")),
    });
    assert!(reply(&step, TERMINAL).is_none(), "answered once deleted");
    assert!(events(&step).iter().any(|event| matches!(
        event,
        Event::Changed { change: Change::Grant { terms, .. }, .. }
            if terms.lends.key(&key(P256)).is_none() && terms.lends.key(&key(OTHER)).is_some()
    )));
    assert!(step.keep.is_some(), "the changed document is kept");
    assert!(step.effects.iter().any(|effect| matches!(
        effect,
        Effect::DeleteKey { name: named, key: deleted, .. } if *named == name("laptop") && *deleted == key(P256)
    )));
    assert_eq!(scene.lends().keys().count(), 1);

    let step = scene.step(Input::Deleted {
        link: TERMINAL,
        id,
        name: name("laptop"),
        key: key(P256),
        deleted: Ok(()),
    });
    assert!(matches!(reply(&step, TERMINAL), Some(Ok(Reply::Done(_)))));
    assert!(events(&step).iter().any(|event| matches!(
        event,
        Event::KeyDeleted { key: gone, .. } if *gone == key(P256)
    )));
    scene.sent(&step, TERMINAL);

    scene.ask(TERMINAL, Request::DeleteKey(key(OTHER)));
    let id = scene.asked;
    scene.step(Input::Found {
        link: TERMINAL,
        id,
        key: key(OTHER),
        found: Ok(name("old")),
    });
    let step = scene.step(Input::Deleted {
        link: TERMINAL,
        id,
        name: name("old"),
        key: key(OTHER),
        deleted: Err(Refusal::NoTpm),
    });
    assert_eq!(reply(&step, TERMINAL), Some(&Err(Refusal::NoTpm)));
    assert_eq!(events(&step), Vec::<Event>::new());
    assert!(scene.lends().is_none(), "lent nowhere, though still held");
}

/// A name of this run's own beneath Hedwig's prefix.
fn run_name(what: &str) -> Name {
    name(&format!("hedwig-test-{}-{what}", std::process::id()))
}

/// Deletes the run's key by name when dropped, should a test stop first.
struct Cleared(Name);

impl Drop for Cleared {
    fn drop(&mut self) {
        if let Ok(provider) = hedwig_win::tpm::Provider::platform()
            && let Ok(key) = provider.open(&format!("{PREFIX}{}", self.0))
        {
            let _ = key.delete();
        }
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn string(into: &mut Vec<u8>, bytes: &[u8]) {
    into.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    into.extend_from_slice(bytes);
}

fn sign_request(key: &SshKey, data: &[u8], flags: u32) -> Vec<u8> {
    let mut body = vec![13];
    string(&mut body, &key.blob());
    string(&mut body, data);
    body.extend_from_slice(&flags.to_be_bytes());
    framed(&body)
}

/// The algorithm a signature answer names.
fn signed_as(answer: &[u8]) -> String {
    assert_eq!(answer.get(4), Some(&14), "{answer:?}");
    let (signature, rest) = ssh_string(answer.get(5..).unwrap()).unwrap();
    assert_eq!(rest, []);
    let (algorithm, rest) = ssh_string(signature).unwrap();
    let (raw, rest) = ssh_string(rest).unwrap();
    assert!(rest.is_empty() && !raw.is_empty());
    String::from_utf8(algorithm.to_vec()).unwrap()
}

/// Against this workstation's TPM: keys are made under the person's names,
/// listed as such by the protocol's own answer, sign what the protocol asks
/// in the form each key type's signature takes - SHA-2 for RSA, never SHA-1 -
/// and answer a key not Hedwig's, or noise, with a failure. A name made
/// twice and a kind this TPM does not make are refused; a key is deleted by
/// its public half alone.
#[test]
#[ignore = "needs a TPM that makes ECDSA P-256 and P-384 and RSA 2048 keys"]
fn the_core_s_signer_makes_lists_signs_and_deletes_keys_in_the_tpm() {
    let p256 = run_name("p256");
    let p384 = run_name("p384");
    let rsa = run_name("rsa");
    let _cleared = [&p256, &p384, &rsa].map(|name| Cleared(name.clone()));
    let made = |name: &Name, kind: KeyKind| match machine::make(name, kind) {
        Err(Refusal::NoTpm) => {
            panic!("needs a TPM that makes ECDSA P-256 and P-384 and RSA 2048 keys")
        }
        made => made.expect("made"),
    };
    let made_p256 = made(&p256, KeyKind::EcdsaP256);
    let made_p384 = made(&p384, KeyKind::EcdsaP384);
    let made_rsa = made(&rsa, KeyKind::Rsa2048);
    assert_eq!(made_p256.key.kind(), "ecdsa-sha2-nistp256");
    assert_eq!(made_p384.key.kind(), "ecdsa-sha2-nistp384");
    assert_eq!(made_rsa.key.kind(), "ssh-rsa");
    assert_eq!(made_p256.comment.as_ref().unwrap().as_str(), p256.as_str());

    let listed = machine::keys().expect("listed");
    for made in [&made_p256, &made_p384, &made_rsa] {
        assert!(listed.contains(made), "{made:?}");
    }
    let identities = machine::answer(&framed(&[11])).expect("answered");
    let read = hedwig_core::agent::listed(&identities).expect("an identities answer");
    for made in [&made_p256, &made_p384, &made_rsa] {
        let comment = made.comment.as_ref().unwrap().as_str().as_bytes().to_vec();
        assert!(read.contains(&(made.key.clone(), comment)));
    }

    let data = b"SSHSIG data a remote's ssh-keygen sends";
    for (made, flags, algorithm) in [
        (&made_p256, 0, "ecdsa-sha2-nistp256"),
        (&made_p384, 0, "ecdsa-sha2-nistp384"),
        (&made_rsa, 4, "rsa-sha2-512"),
        (&made_rsa, 2, "rsa-sha2-256"),
    ] {
        let answer = machine::answer(&sign_request(&made.key, data, flags)).expect("answered");
        assert_eq!(signed_as(&answer), algorithm);
    }
    assert_eq!(
        machine::answer(&sign_request(&made_rsa.key, data, 0)).unwrap(),
        FAILURE,
        "SHA-1 is never signed"
    );
    assert_eq!(
        machine::answer(&sign_request(&key(OTHER), data, 0)).unwrap(),
        FAILURE
    );
    for noise in [&[][..], &[0, 0, 0, 1, 13][..], &[0, 0, 0, 1, 18][..]] {
        assert_eq!(machine::answer(noise).unwrap(), FAILURE);
    }

    assert_eq!(
        machine::make(&p256, KeyKind::EcdsaP256),
        Err(Refusal::KeyExists(p256.clone()))
    );
    let wide = run_name("p521");
    let _wide = Cleared(wide.clone());
    match machine::make(&wide, KeyKind::EcdsaP521) {
        Err(refusal) => assert_eq!(refusal, Refusal::KindUnmade(KeyKind::EcdsaP521)),
        Ok(made) => machine::delete(&wide, &made.key).expect("deleted"),
    }

    assert_eq!(machine::find(&made_p384.key), Ok(p384.clone()));
    assert_eq!(
        machine::delete(&p384, &made_p256.key),
        Err(Refusal::KeyAbsent(made_p256.key.clone())),
        "a name now holding another key is not deleted"
    );
    for (name, made) in [(&p256, &made_p256), (&p384, &made_p384), (&rsa, &made_rsa)] {
        machine::delete(name, &made.key).expect("deleted");
        assert_eq!(
            machine::find(&made.key),
            Err(Refusal::KeyAbsent(made.key.clone()))
        );
        assert_eq!(
            machine::delete(name, &made.key),
            Err(Refusal::KeyAbsent(made.key.clone()))
        );
    }
    assert_eq!(machine::reach(), Ok(()));
}
