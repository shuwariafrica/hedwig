//! A channel's prompts, decided with nothing running: who may ask, what is
//! put to the person and how loudly, what each answer is carried back as,
//! what a decline does per kind, and what happens when nobody can be asked,
//! when the person leaves, and when the client takes its question back.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use hedwig_core::channel::{asked, words};
use hedwig_core::dispatch::{Core, Effect, Input, Link, Now, Step, Then};
use hedwig_model::capability::{Exposure, Lends, Setup};
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
use hedwig_model::protocol::{
    Answer, Attention, FromCore, Hint, Notice, PROTOCOL, Reply, Request, ToCore, Withdrawn,
};
use hedwig_model::refusal::{Refusal, Whereabouts};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::setting::Volume;
use hedwig_model::text::{Address, Location, Name, RemotePath, Secret, Words};
use hedwig_model::trail::{
    Asking, Binding, ChannelEnd, ClientKind, ConnectionId, Event, Gave, Given, Integrity, Origin,
    Peer, PromptId, PromptKind, Serving, Tick, Timestamp,
};
use hedwig_model::wire::{line, read};

mod common;

const NOW: Now = Now {
    at: Timestamp(1_790_000_000_000),
    tick: Tick(40),
};

const DESKTOP: Origin = Origin {
    process: 4200,
    logon: 0x3e7_0001,
    session: 2,
    integrity: Integrity::Medium,
};

const TERMINAL: Link = Link(1);
const ASKER: Link = Link(2);
const SCRIPT: Link = Link(3);

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn remote() -> RemoteId {
    RemoteId {
        route: name("ssh"),
        address: Address::try_from("dev@build-7.example").unwrap(),
    }
}

fn said(text: &str) -> Words {
    words(text).unwrap()
}

/// A reply with its id, or a notice, and what follows it.
type Sent = (Option<(u32, Result<Reply, Refusal>)>, Option<Notice>, Then);

/// Everything sent to `link` in a step: replies with their id and what
/// follows them, and notices.
fn sent(step: &Step, to: Link) -> Vec<Sent> {
    step.effects
        .iter()
        .filter_map(|effect| match effect {
            Effect::Send { link, frame, then } if *link == to => Some(match frame {
                FromCore::Reply { id, reply } => {
                    (Some((*id, read(&line(reply)).unwrap())), None, *then)
                }
                FromCore::Notice(notice) => (None, Some(notice.clone()), *then),
            }),
            _ => None,
        })
        .collect()
}

fn replies(step: &Step, to: Link) -> Vec<(u32, Result<Reply, Refusal>, Then)> {
    sent(step, to)
        .into_iter()
        .filter_map(|(reply, _, then)| reply.map(|(id, reply)| (id, reply, then)))
        .collect()
}

fn notices(step: &Step, to: Link) -> Vec<Notice> {
    sent(step, to)
        .into_iter()
        .filter_map(|(_, notice, _)| notice)
        .collect()
}

fn events(step: &Step) -> Vec<Event> {
    step.entries
        .iter()
        .map(|entry| entry.event.clone())
        .collect()
}

struct Scene {
    core: Core,
    connection: ConnectionId,
    asked: u32,
    /// Whom the channel's client was started to ask.
    asking: Asking,
}

impl Scene {
    /// A core with `gpg` granted on request to every remote on `ssh`, a
    /// channel started to one of them, and, where `watched`, a terminal
    /// that watches every remote.
    fn new(watched: bool) -> Scene {
        let mut core = Core::new(
            Catalogue::shipped().unwrap(),
            Configuration::default(),
            Vec::new(),
            "0.2.0".to_owned(),
        );
        core.begin(DESKTOP, None, Vec::new(), NOW);
        let mut scene = Scene {
            core,
            connection: ConnectionId(hedwig_model::trail::Seq(0)),
            asked: 0,
            asking: Asking::Nobody,
        };
        let kind = if watched {
            ClientKind::Terminal
        } else {
            ClientKind::Command
        };
        scene.arrive(TERMINAL, Some(DESKTOP.into()));
        scene.ask(
            TERMINAL,
            Request::Hello {
                protocol: PROTOCOL,
                kind,
                attends: Remotes::Every,
            },
        );
        scene.ask(
            TERMINAL,
            Request::Change(Change::Grant {
                grant: Grant {
                    capability: name("gpg"),
                    remotes: Granted::Route(name("ssh")),
                },
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Inspect,
                    acknowledged: Exposure::NONE,
                    lends: Lends::none(),
                },
            }),
        );
        scene.ask(
            TERMINAL,
            Request::Connect {
                remote: remote(),
                with: Vec::new(),
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        );
        let (connection, _) = scene.core.state().connection(&remote()).unwrap();
        scene.connection = connection;
        let serving = vec![Serving {
            capability: name("gpg"),
            binding: Binding::Socket(
                RemotePath::try_from("/run/user/1000/gnupg/S.gpg-agent").unwrap(),
            ),
        }];
        let step = scene.core.step(
            Input::Channel {
                connection,
                told: common::placing(&serving),
            },
            NOW,
        );
        let Some(Effect::Start { asking, .. }) = step
            .effects
            .iter()
            .find(|effect| matches!(effect, Effect::Start { .. }))
        else {
            panic!("the channel starts: {step:?}");
        };
        scene.asking = *asking;
        scene
    }

    fn arrive(&mut self, link: Link, peer: Option<Peer>) {
        self.core.step(Input::Arrived { link, peer }, NOW);
    }

    fn ask(&mut self, link: Link, request: Request) -> Step {
        self.asked += 1;
        let frame = ToCore {
            id: self.asked,
            request,
        };
        let step = self.core.step(Input::Asked { link, frame }, NOW);
        for _ in sent(&step, link) {
            self.core.step(Input::Sent { link }, NOW);
        }
        step
    }

    /// The channel's own askpass, greeted from inside its job.
    fn asker(&mut self) -> Step {
        let peer = Peer {
            origin: Origin {
                process: 9100,
                ..DESKTOP
            },
            program: Some(Location::try_from(r"C:\Program Files\hedwig\hedwig.exe").unwrap()),
            channel: Some(self.connection),
        };
        self.arrive(ASKER, Some(peer));
        self.ask(
            ASKER,
            Request::Hello {
                protocol: PROTOCOL,
                kind: ClientKind::Prompt,
                attends: Remotes::Every,
            },
        )
    }

    /// The askpass asks `text`; the prompt it raised, where one was.
    fn prompt(&mut self, text: &str, hint: Option<Hint>) -> (Step, Option<PromptId>) {
        self.asker();
        let step = self.ask(
            ASKER,
            Request::Prompt {
                words: said(text),
                hint,
            },
        );
        let prompt = step.entries.iter().find_map(|entry| match entry.event {
            Event::Prompted { .. } => Some(PromptId(entry.seq)),
            _ => None,
        });
        (step, prompt)
    }

    fn answer(&mut self, prompt: PromptId, answer: Answer) -> Step {
        self.ask(TERMINAL, Request::Answer { prompt, answer })
    }
}

const PASSPHRASE: &str = r"Enter passphrase for key 'C:\Users\dev\.ssh\id_ed25519': ";
const HOST_KEY: &str = "The authenticity of host 'build-7 (203.0.113.7)' can't be established.\nED25519 key fingerprint is SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ";

/// Each prompt the client can raise is known by its own words, and only a
/// notice by its hint: the in-box client leaves `confirm` set once it has
/// set it.
#[test]
fn a_prompt_is_known_by_the_clients_own_words() {
    let cases = [
        (HOST_KEY, None, PromptKind::UnknownHostKey),
        (HOST_KEY, Some(Hint::Confirm), PromptKind::UnknownHostKey),
        (PASSPHRASE, Some(Hint::Confirm), PromptKind::KeyPassphrase),
        (
            "dev@build-7.example's password: ",
            None,
            PromptKind::Password,
        ),
        (
            "Enter dev@build-7.example's old password: ",
            None,
            PromptKind::Password,
        ),
        (
            "Retype dev@build-7.example's new password: ",
            None,
            PromptKind::Password,
        ),
        (
            r"Enter PIN for ECDSA-SK key C:\Users\dev\.ssh\id_ecdsa_sk: ",
            None,
            PromptKind::SecurityKeyPin,
        ),
        (
            "(dev@build-7.example) Verification code: ",
            None,
            PromptKind::Challenge,
        ),
        (
            "(dev@build-7.example) Password: ",
            None,
            PromptKind::Challenge,
        ),
        (
            "Add key id_ed25519 (dev@build-7) to agent?",
            Some(Hint::Confirm),
            PromptKind::AgentConfirmation,
        ),
        (
            "Confirm user presence for key ECDSA-SK SHA256:abc",
            Some(Hint::Notice),
            PromptKind::SecurityKeyTouch,
        ),
        (
            "Something no release of the client says",
            None,
            PromptKind::Challenge,
        ),
    ];
    for (text, hint, kind) in cases {
        assert_eq!(asked(&said(text), hint), kind, "{text}");
    }
    // A line break in the client's words is a space in what is shown.
    assert!(said(HOST_KEY).as_str().contains("established. ED25519"));
}

/// The channel's askpass is admitted only from inside a live channel's job,
/// and asks as that channel's remote; anything else is refused at the
/// greeting, and no other kind of client may ask.
#[test]
fn only_a_channels_own_process_asks() {
    let mut scene = Scene::new(true);
    let step = scene.asker();
    assert!(matches!(
        replies(&step, ASKER).as_slice(),
        [(_, Ok(Reply::Welcome { .. }), Then::Continue)]
    ));

    scene.arrive(SCRIPT, Some(DESKTOP.into()));
    let step = scene.ask(
        SCRIPT,
        Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Prompt,
            attends: Remotes::Every,
        },
    );
    assert!(matches!(
        replies(&step, SCRIPT).as_slice(),
        [(
            _,
            Err(Refusal::NoChannel { process: 4200, .. }),
            Then::Close
        )]
    ));

    let step = scene.ask(
        TERMINAL,
        Request::Prompt {
            words: said(PASSPHRASE),
            hint: None,
        },
    );
    assert!(matches!(
        replies(&step, TERMINAL).as_slice(),
        [(_, Err(Refusal::NoChannel { .. }), Then::Continue)]
    ));
}

/// Put to the person: recorded as the remote's, raised to the watching
/// terminal as interrupting, and left unanswered to the asker until the
/// person answers; their text goes to the asker alone, and the trail says
/// only that it was text.
#[test]
fn the_persons_text_goes_to_the_asker_alone() {
    let mut scene = Scene::new(true);
    let (step, prompt) = scene.prompt(PASSPHRASE, None);
    let prompt = prompt.expect("put to the person");
    assert_eq!(
        events(&step),
        [Event::Prompted {
            connection: scene.connection,
            kind: PromptKind::KeyPassphrase,
            words: said(PASSPHRASE),
        }]
    );
    assert!(replies(&step, ASKER).is_empty(), "the asker waits");
    let raised: Vec<Notice> = notices(&step, TERMINAL)
        .into_iter()
        .filter(|notice| matches!(notice, Notice::Raised(_)))
        .collect();
    assert!(matches!(
        raised.as_slice(),
        [Notice::Raised(needs)]
            if needs.volume == Volume::Interrupts
                && matches!(&needs.attention, Attention::Prompt { remote: from, kind: PromptKind::KeyPassphrase, .. } if *from == remote())
    ));

    let secret = "correct horse battery staple";
    let step = scene.answer(prompt, Answer::Text(Secret::from(secret.to_owned())));
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Answered { prompt: over, by: Some(Gave { given: Given::Text, .. }) }]
            if *over == prompt
    ));
    let to_asker = replies(&step, ASKER);
    let [(_, Ok(Reply::Answer(Answer::Text(given))), Then::Close)] = to_asker.as_slice() else {
        panic!("{to_asker:?}");
    };
    assert_eq!(given.expose(), secret);
    assert!(matches!(
        replies(&step, TERMINAL).as_slice(),
        [(_, Ok(Reply::Done(_)), Then::Continue)]
    ));
    assert!(notices(&step, TERMINAL).iter().any(
        |notice| matches!(notice, Notice::Withdrawn(Withdrawn::Prompt(over)) if *over == prompt)
    ));
    for entry in &step.entries {
        assert!(!line(entry).contains(secret), "never recorded");
    }
}

/// A yes or a no: a host key accepted is handed to the client as `yes`; one
/// declined ends the channel, as the client would end itself.
#[test]
fn a_host_key_is_accepted_or_the_channel_ends() {
    let mut scene = Scene::new(true);
    let (_, prompt) = scene.prompt(HOST_KEY, Some(Hint::Confirm));
    let step = scene.answer(prompt.unwrap(), Answer::Accept);
    assert!(matches!(
        replies(&step, ASKER).as_slice(),
        [(_, Ok(Reply::Answer(Answer::Accept)), Then::Close)]
    ));

    let mut scene = Scene::new(true);
    let (_, prompt) = scene.prompt(HOST_KEY, None);
    let step = scene.answer(prompt.unwrap(), Answer::Decline);
    let connection = scene.connection;
    assert!(events(&step).contains(&Event::Down {
        connection,
        end: ChannelEnd::Declined(PromptKind::UnknownHostKey)
    }));
    assert!(step.effects.contains(&Effect::End { connection }));
    assert!(replies(&step, ASKER).is_empty(), "ended, never answered");
}

/// What a decline is carried as depends on what an empty answer would do:
/// a passphrase declined is handed to the client, which tries its next key;
/// a password, a challenge or a PIN declined ends the channel before any
/// empty answer can reach the server or the key.
#[test]
fn a_decline_never_reaches_the_server_as_an_empty_answer() {
    let mut scene = Scene::new(true);
    let (_, prompt) = scene.prompt(PASSPHRASE, None);
    let step = scene.answer(prompt.unwrap(), Answer::Decline);
    assert!(matches!(
        replies(&step, ASKER).as_slice(),
        [(_, Ok(Reply::Answer(Answer::Decline)), Then::Close)]
    ));
    assert!(
        !events(&step)
            .iter()
            .any(|event| matches!(event, Event::Down { .. }))
    );

    for (text, kind) in [
        ("dev@build-7.example's password: ", PromptKind::Password),
        (
            "(dev@build-7.example) Verification code: ",
            PromptKind::Challenge,
        ),
        (
            "Enter PIN for ECDSA-SK key id_ecdsa_sk: ",
            PromptKind::SecurityKeyPin,
        ),
    ] {
        let mut scene = Scene::new(true);
        let (_, prompt) = scene.prompt(text, None);
        let step = scene.answer(prompt.unwrap(), Answer::Decline);
        let connection = scene.connection;
        assert!(
            events(&step).contains(&Event::Down {
                connection,
                end: ChannelEnd::Declined(kind)
            }),
            "{text}"
        );
        assert!(replies(&step, ASKER).is_empty(), "{text}");
    }
}

/// An answer is what the prompt asks for, from a client that attends the
/// person; anything else is refused and the prompt stays.
#[test]
fn an_answer_that_does_not_fit_is_refused() {
    let mut scene = Scene::new(true);
    let (_, prompt) = scene.prompt(PASSPHRASE, None);
    let prompt = prompt.unwrap();
    let step = scene.answer(prompt, Answer::Accept);
    assert!(matches!(
        replies(&step, TERMINAL).as_slice(),
        [(
            _,
            Err(Refusal::AnswerUnfit {
                kind: PromptKind::KeyPassphrase
            }),
            _
        )]
    ));
    let step = scene.answer(prompt, Answer::Text(Secret::from("yes".to_owned())));
    assert!(
        step.entries.len() == 1,
        "the prompt stayed and is answered now"
    );

    let mut scene = Scene::new(true);
    let (_, prompt) = scene.prompt(HOST_KEY, None);
    let step = scene.answer(
        prompt.unwrap(),
        Answer::Text(Secret::from("yes".to_owned())),
    );
    assert!(matches!(
        replies(&step, TERMINAL).as_slice(),
        [(
            _,
            Err(Refusal::AnswerUnfit {
                kind: PromptKind::UnknownHostKey
            }),
            _
        )]
    ));

    // A command attends nobody: an answer from it is refused.
    let mut scene = Scene::new(true);
    let (_, prompt) = scene.prompt(PASSPHRASE, None);
    scene.arrive(SCRIPT, Some(DESKTOP.into()));
    scene.ask(
        SCRIPT,
        Request::Hello {
            protocol: PROTOCOL,
            kind: ClientKind::Command,
            attends: Remotes::Every,
        },
    );
    let step = scene.ask(
        SCRIPT,
        Request::Answer {
            prompt: prompt.unwrap(),
            answer: Answer::Decline,
        },
    );
    assert!(matches!(
        replies(&step, SCRIPT).as_slice(),
        [(_, Err(Refusal::NotAttending), _)]
    ));
}

/// With nobody to put it to, a prompt ends the channel as needing the
/// person, and the asker is refused.
#[test]
fn a_prompt_nobody_can_answer_ends_the_channel_as_needing_the_person() {
    let mut scene = Scene::new(false);
    let (step, prompt) = scene.prompt(r"Enter PIN for ECDSA-SK key id_ecdsa_sk: ", None);
    assert!(prompt.is_none());
    let connection = scene.connection;
    assert_eq!(
        events(&step),
        [Event::Down {
            connection,
            end: ChannelEnd::Needs(PromptKind::SecurityKeyPin)
        }]
    );
    assert!(matches!(
        replies(&step, ASKER).as_slice(),
        [(
            _,
            Err(Refusal::NobodyReachable(Whereabouts::Away)),
            Then::Close
        )]
    ));
}

/// The last person leaving, or going away, while a prompt waits ends the
/// channel as needing them.
#[test]
fn a_prompt_left_waiting_when_the_person_leaves_ends_the_channel() {
    let mut scene = Scene::new(true);
    let (_, prompt) = scene.prompt(PASSPHRASE, None);
    assert!(prompt.is_some());
    let step = scene.core.step(Input::Left { link: TERMINAL }, NOW);
    let connection = scene.connection;
    assert!(events(&step).contains(&Event::Down {
        connection,
        end: ChannelEnd::Needs(PromptKind::KeyPassphrase)
    }));
}

/// A key's touch is a notice: nothing answers it, the client takes it back
/// when the key is touched, and the person is told it is over.
#[test]
fn a_touch_notice_is_withdrawn_when_the_client_takes_it_back() {
    let mut scene = Scene::new(true);
    let (step, prompt) = scene.prompt(
        "Confirm user presence for key ECDSA-SK SHA256:abc",
        Some(Hint::Notice),
    );
    let prompt = prompt.unwrap();
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Prompted {
            kind: PromptKind::SecurityKeyTouch,
            ..
        }]
    ));
    let step = scene.answer(prompt, Answer::Accept);
    assert!(matches!(
        replies(&step, TERMINAL).as_slice(),
        [(
            _,
            Err(Refusal::AnswerUnfit {
                kind: PromptKind::SecurityKeyTouch
            }),
            _
        )]
    ));
    let step = scene.core.step(Input::Left { link: ASKER }, NOW);
    assert!(matches!(
        events(&step).as_slice(),
        [Event::Answered { prompt: over, by: None }, Event::Detached { .. }] if *over == prompt
    ));
    assert!(notices(&step, TERMINAL).iter().any(
        |notice| matches!(notice, Notice::Withdrawn(Withdrawn::Prompt(over)) if *over == prompt)
    ));
    assert!(scene.core.state().prompt(prompt).is_none());
}

/// A channel started while a surface watches its remote may ask; one
/// started with nobody there runs in batch mode.
#[test]
fn whom_a_channel_may_ask_is_decided_as_it_starts() {
    assert_eq!(Scene::new(true).asking, Asking::Person);
    assert_eq!(Scene::new(false).asking, Asking::Nobody);
}
