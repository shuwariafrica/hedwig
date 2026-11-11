//! Where every value comes from: each setting with the statement that decided
//! it and the limit that holds it, a change's reply naming what holds what it
//! states, and a trial that says what a statement would change before it is
//! made.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU32;

use hedwig_model::capability::{Exposure, Lends, Operation, Setup};
use hedwig_model::config::{Activation, Change, Configuration, Document, Effect, Terms};
use hedwig_model::gate::Capped;
use hedwig_model::organisation::{
    GrantScope, Holding, Limit, Part, Place, Policy, Start, Statement,
};
use hedwig_model::policy::{Keys, Mode, RuleScope, Selector};
use hedwig_model::protocol::{
    Contact, Differs, Line, Reply, Request, Row, Settings, Standing, Through, Trial, Tried, Would,
};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::scope::{Audience, Holder};
use hedwig_model::setting::{
    Autostart, Burst, CapScope, Condition, Heard, Lengths, Longest, Said, Settled, Threshold,
    Volume, Waits, Workstation,
};
use hedwig_model::text::Words;
use hedwig_model::trail::{ClientId, ClientKind};
use hedwig_model::wire::line;

mod support;
use support::desk::Desk;
use support::{DESKTOP, catalogue, grant, name, remote, terms};

const MACHINE: Audience = Audience::Machine;
const PERSON: Audience = Audience::Person;

fn at(audience: Audience, part: Part) -> Place {
    Place { audience, part }
}

fn written(audience: Audience, statement: &Statement) -> Line {
    let text = match statement {
        Statement::Limit(limit) => line(limit),
        Statement::Start(start) => line(start),
        Statement::Ask(words) => words.as_str().to_owned(),
    };
    Line {
        place: at(audience, statement.part()),
        text,
    }
}

fn limit(audience: Audience, limit: Limit) -> Line {
    written(audience, &Statement::Limit(limit))
}

fn start(audience: Audience, start: Start) -> Line {
    written(audience, &Statement::Start(start))
}

fn policy(lines: &[Line]) -> Policy {
    Policy::read(lines.iter().map(|line| (line.place, line.text.as_str())))
}

fn host() -> RemoteId {
    remote("ssh", "ops@bastion.example")
}

fn seconds(seconds: u32) -> Longest {
    Longest::Seconds(NonZeroU32::new(seconds).unwrap())
}

fn every_rule(remotes: Remotes) -> RuleScope {
    RuleScope {
        remotes,
        capability: Selector::Every,
        operation: Selector::Every,
        key: Keys::Every,
    }
}

/// A desk with an attending interface and `gpg` granted to `host`.
fn desk_with(activation: Activation, setup: Setup) -> (Desk, ClientId) {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    desk.send(
        interface,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(host())),
            terms: Terms {
                activation,
                setup,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        }),
    )
    .unwrap();
    (desk, interface)
}

fn settings(desk: &mut Desk, client: ClientId, remotes: Vec<RemoteId>) -> Settings {
    let Ok(Reply::Settings(settings)) = desk.send(client, Request::Settings { remotes }) else {
        unreachable!("the settings are read")
    };
    *settings
}

fn held(reply: Result<Reply, Refusal>) -> Vec<Holding> {
    let Ok(Reply::Changed { held, .. }) = reply else {
        unreachable!("the change was made: {reply:?}")
    };
    held
}

fn tried(desk: &mut Desk, client: ClientId, trial: Trial) -> Tried {
    let Ok(Reply::Tried(tried)) = desk.send(client, Request::Try(Box::new(trial))) else {
        unreachable!("a trial is always answered")
    };
    *tried
}

fn trial() -> Trial {
    Trial {
        policy: None,
        document: None,
        change: None,
        remotes: Vec::new(),
    }
}

fn rate() -> Threshold {
    Threshold::At(Burst {
        requests: std::num::NonZeroU8::new(5).unwrap(),
        seconds: NonZeroU32::new(60).unwrap(),
    })
}

fn everything() -> CapScope {
    CapScope {
        remotes: Remotes::Every,
        key: Keys::Every,
    }
}

fn mine() -> CapScope {
    CapScope {
        remotes: Remotes::One(host()),
        key: Keys::Every,
    }
}

/// A person's settings under an organisation that starts, caps and says
/// whom to ask, with a starting line it cannot read.
fn managed() -> (Desk, ClientId) {
    let (mut desk, interface) = desk_with(Activation::OnRequest, Setup::Inspect);
    desk.govern(&policy(&[
        start(
            MACHINE,
            Start::Burst {
                remotes: Remotes::Route(name("ssh")),
                threshold: rate(),
            },
        ),
        start(PERSON, Start::Autostart(Autostart::AtLogon)),
        limit(
            MACHINE,
            Limit::Cap {
                scope: everything(),
                longest: seconds(900),
            },
        ),
        written(
            MACHINE,
            &Statement::Ask(Words::try_from("the IT desk, extension 4444").unwrap()),
        ),
        // The second line of the person's starting point.
        Line {
            place: at(PERSON, Part::Start),
            text: "{\"autostart\":\"always\"}".to_owned(),
        },
    ]));
    for change in [
        Change::Hear {
            remotes: Remotes::One(host()),
            heard: Heard::Unready(Waits::Shown),
        },
        Change::Cap {
            scope: mine(),
            longest: Some(seconds(60)),
        },
    ] {
        desk.send(interface, Request::Change(change)).unwrap();
    }
    (desk, interface)
}

#[test]
fn every_setting_says_where_its_value_comes_from_and_who_holds_it() {
    let (mut desk, interface) = managed();
    let ssh = Remotes::Route(name("ssh"));
    let (at_rate, everything, mine) = (rate(), everything(), mine());
    let elsewhere = remote("codespaces", "fluffy-space-7x9q");
    let read = settings(&mut desk, interface, vec![elsewhere.clone()]);

    let workstation = &read.workstation;
    assert_eq!(
        workstation.lengths,
        Settled {
            value: Lengths::ships(),
            said: Said::Ships,
        }
    );
    assert_eq!(
        workstation.autostart,
        Settled {
            value: Autostart::AtLogon,
            said: Said::Start {
                audience: PERSON,
                scope: Workstation,
            },
        }
    );
    assert_eq!(
        workstation.contacts,
        vec![Contact {
            audience: MACHINE,
            words: Words::try_from("the IT desk, extension 4444").unwrap(),
        }]
    );
    assert!(matches!(
        workstation.unread.as_slice(),
        [misread] if misread.place == at(PERSON, Part::Start) && misread.unread.lines == [1]
    ));

    let on = |remote: &RemoteId| {
        read.remotes
            .iter()
            .find(|settings| settings.remote == *remote)
            .expect("the remote's settings")
    };
    let bastion = on(&host());
    assert_eq!(
        bastion.threshold,
        Settled {
            value: at_rate,
            said: Said::Start {
                audience: MACHINE,
                scope: ssh,
            },
        }
    );
    let volume = |condition| {
        bastion
            .volumes
            .iter()
            .find(|loudness| loudness.condition == condition)
            .map(|loudness| loudness.volume.clone())
            .expect("every condition")
    };
    assert_eq!(bastion.volumes.len(), Condition::EVERY.len());
    assert_eq!(
        volume(Condition::Unready),
        Settled {
            value: Volume::Shown,
            said: Said::Person(Remotes::One(host())),
        }
    );
    assert_eq!(volume(Condition::Served).said, Said::Ships);
    assert_eq!(
        bastion.caps,
        vec![
            Capped {
                longest: seconds(60),
                holder: Holder::Person,
                scope: mine,
            },
            Capped {
                longest: seconds(900),
                holder: Holder::Organisation(MACHINE),
                scope: everything,
            },
        ]
    );
    // A remote the asker names is answered for, though the core knows
    // nothing of it.
    assert_eq!(on(&elsewhere).threshold.said, Said::Ships);
}

#[test]
fn a_row_says_on_what_terms_its_grant_serves_and_which_limits_hold_them() {
    let (mut desk, interface) = desk_with(Activation::Continuous, Setup::Write);
    let row = |desk: &Desk| desk.row(interface, &host(), &name("gpg"));
    assert_eq!(
        row(&desk).terms,
        Some(Terms {
            activation: Activation::Continuous,
            setup: Setup::Write,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        })
    );
    assert_eq!(row(&desk).holds, Vec::<Holding>::new());

    let connects = Limit::Activation {
        scope: GrantScope {
            capability: Selector::Every,
            remotes: Remotes::Every,
        },
        most: Activation::OnRequest,
    };
    let inspects = Limit::InspectOnly(GrantScope {
        capability: Selector::Only(name("gpg")),
        remotes: Remotes::Route(name("ssh")),
    });
    desk.govern(&policy(&[
        limit(MACHINE, connects.clone()),
        limit(PERSON, inspects.clone()),
    ]));
    assert_eq!(
        row(&desk).terms,
        Some(Terms {
            activation: Activation::OnRequest,
            setup: Setup::Inspect,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        })
    );
    assert_eq!(
        row(&desk).holds,
        vec![
            Holding {
                holder: Holder::Organisation(MACHINE),
                limit: connects,
            },
            Holding {
                holder: Holder::Organisation(PERSON),
                limit: inspects,
            },
        ]
    );
}

#[test]
fn the_reply_to_a_change_names_each_limit_that_holds_what_it_states() {
    let (mut desk, interface) = desk_with(Activation::OnRequest, Setup::Inspect);
    desk.channel_up(&host(), "linux");
    let floor = RuleScope {
        remotes: Remotes::Every,
        capability: Selector::Only(name("gpg")),
        operation: Selector::Only(Operation::Sign),
        key: Keys::Every,
    };
    let connects = Limit::Activation {
        scope: GrantScope {
            capability: Selector::Every,
            remotes: Remotes::Every,
        },
        most: Activation::WhileRunning,
    };
    let cap = Limit::Cap {
        scope: CapScope {
            remotes: Remotes::Route(name("ssh")),
            key: Keys::Every,
        },
        longest: seconds(900),
    };
    desk.govern(&policy(&[
        limit(
            MACHINE,
            Limit::Floor {
                scope: floor.clone(),
                mode: Mode::Confirm,
            },
        ),
        limit(MACHINE, connects.clone()),
        limit(PERSON, cap.clone()),
    ]));
    let organisation = |audience, limit| Holding {
        holder: Holder::Organisation(audience),
        limit,
    };
    let floor = organisation(
        MACHINE,
        Limit::Floor {
            scope: floor,
            mode: Mode::Confirm,
        },
    );

    let rule = Change::Rule {
        scope: every_rule(Remotes::One(host())),
        mode: Mode::Unattended,
    };
    assert_eq!(
        held(desk.send(interface, Request::Change(rule))),
        vec![floor.clone()]
    );
    let continuous = Change::Grant {
        grant: grant("gpg", Granted::One(host())),
        terms: terms(Activation::Continuous, Exposure::NONE),
    };
    assert_eq!(
        held(desk.send(interface, Request::Change(continuous))),
        vec![organisation(MACHINE, connects.clone())]
    );
    let mine = Change::Cap {
        scope: CapScope {
            remotes: Remotes::One(host()),
            key: Keys::Every,
        },
        longest: Some(seconds(3600)),
    };
    assert_eq!(
        held(desk.send(interface, Request::Change(mine))),
        vec![organisation(PERSON, cap.clone())]
    );
    let quiet = Change::Burst {
        remotes: Remotes::Every,
        threshold: Some(Threshold::Never),
    };
    assert_eq!(
        held(desk.send(interface, Request::Change(quiet))),
        Vec::<Holding>::new()
    );

    // An import names everything the limits hold of the document.
    let document = desk.configuration.export();
    let mut everything = held(desk.send(interface, Request::Import(Box::new(document))));
    everything.sort();
    let mut expected = vec![
        floor,
        organisation(MACHINE, connects),
        organisation(PERSON, cap),
    ];
    expected.sort();
    assert_eq!(everything, expected);
}

#[test]
fn a_trial_changes_nothing_and_says_exactly_what_making_it_would() {
    let (mut desk, interface) = desk_with(Activation::OnRequest, Setup::Inspect);
    desk.channel_up(&host(), "linux");
    let adb = Change::Grant {
        grant: grant("adb", Granted::One(host())),
        terms: terms(Activation::OnRequest, Exposure::SERVICE),
    };
    let recorded = desk.trail.entries.len();
    let before = desk.configuration.clone();
    let Tried::Would(would) = tried(
        &mut desk,
        interface,
        Trial {
            change: Some(adb.clone()),
            ..trial()
        },
    ) else {
        unreachable!("the gate takes the change")
    };
    assert_eq!(desk.trail.entries.len(), recorded);
    assert_eq!(desk.configuration, before);
    assert_eq!(would.reach, hedwig_model::config::Reach::Wider);
    let [
        Differs {
            before: None,
            after: Some(added),
        },
    ] = would.rows.as_slice()
    else {
        unreachable!("one row would be added: {:?}", would.rows)
    };
    assert_eq!(added.capability, name("adb"));

    desk.send(interface, Request::Change(adb)).unwrap();
    assert_eq!(&desk.row(interface, &host(), &name("adb")), added);
}

/// A baseline a person with nothing set would meet: two starting grants,
/// one that waits for the person, and a floor.
fn baseline() -> Vec<Line> {
    vec![
        start(
            MACHINE,
            Start::Grant {
                grant: grant("gpg", Granted::Route(name("ssh"))),
                activation: Activation::WhileRunning,
            },
        ),
        start(
            MACHINE,
            Start::Grant {
                grant: grant("adb", Granted::Route(name("ssh"))),
                activation: Activation::OnRequest,
            },
        ),
        limit(
            MACHINE,
            Limit::Floor {
                scope: every_rule(Remotes::Every),
                mode: Mode::Confirm,
            },
        ),
    ]
}

#[test]
fn a_baseline_is_tried_as_a_new_person_would_meet_it() {
    let (mut desk, interface) = desk_with(Activation::OnRequest, Setup::Inspect);
    let baseline = baseline();
    let empty = Configuration::default().export();
    let Tried::Would(would) = tried(
        &mut desk,
        interface,
        Trial {
            policy: Some(baseline.clone()),
            document: Some(empty.clone()),
            remotes: vec![host()],
            ..trial()
        },
    ) else {
        unreachable!("an empty document imports")
    };
    let after: Vec<&Row> = would
        .rows
        .iter()
        .filter_map(|differs| differs.after.as_ref())
        .collect();
    let gpg = after
        .iter()
        .find(|row| row.capability == name("gpg"))
        .expect("the starting grant's row");
    assert!(matches!(
        gpg.through,
        Through::Start {
            audience: Audience::Machine,
            ..
        }
    ));
    assert!(
        gpg.decides
            .iter()
            .all(|decides| decides.mode == Mode::Confirm)
    );
    let adb = after
        .iter()
        .find(|row| row.capability == name("adb"))
        .expect("the starting grant that waits");
    assert_eq!(
        adb.standing,
        Standing::Unavailable(Refusal::ExposureNotAcknowledged {
            capability: name("adb"),
            missing: Exposure::SERVICE,
        })
    );

    // With a limit it cannot read, the baseline serves nothing.
    let mut broken = baseline;
    broken.push(Line {
        place: at(MACHINE, Part::Limits),
        text: "{\"floor\":\"never\"}".to_owned(),
    });
    let Tried::Would(would) = tried(
        &mut desk,
        interface,
        Trial {
            policy: Some(broken),
            document: Some(empty),
            remotes: vec![host()],
            ..trial()
        },
    ) else {
        unreachable!("an empty document imports")
    };
    assert!(
        would
            .rows
            .iter()
            .filter_map(|differs| differs.after.as_ref())
            .all(|row| row.standing == Standing::Unavailable(Refusal::Unread(MACHINE)))
    );
    let Some(Differs {
        after: Some(workstation),
        ..
    }) = &would.workstation
    else {
        unreachable!("what cannot be read is said")
    };
    assert_eq!(workstation.unread.len(), 1);
}

#[test]
fn a_policy_trial_says_what_reading_that_policy_would_do() {
    let (mut desk, interface) = desk_with(Activation::OnRequest, Setup::Inspect);
    desk.channel_up(&host(), "linux");
    let lines = vec![limit(
        PERSON,
        Limit::Floor {
            scope: every_rule(Remotes::One(host())),
            mode: Mode::Confirm,
        },
    )];
    let Tried::Would(would) = tried(
        &mut desk,
        interface,
        Trial {
            policy: Some(lines.clone()),
            ..trial()
        },
    ) else {
        unreachable!("a policy is always read")
    };
    assert_eq!(would.reach, hedwig_model::config::Reach::NoWider);
    let [
        Differs {
            before: Some(_),
            after: Some(predicted),
        },
    ] = would.rows.as_slice()
    else {
        unreachable!("one row would change: {:?}", would.rows)
    };
    desk.govern(&policy(&lines));
    assert_eq!(&desk.row(interface, &host(), &name("gpg")), predicted);

    // Withdrawing the limit again lets more through.
    let Tried::Would(would) = tried(
        &mut desk,
        interface,
        Trial {
            policy: Some(Vec::new()),
            ..trial()
        },
    ) else {
        unreachable!("a policy is always read")
    };
    assert_eq!(would.reach, hedwig_model::config::Reach::Wider);
}

#[test]
fn a_trial_the_gate_would_refuse_says_why_and_changes_nothing() {
    let (mut desk, interface) = desk_with(Activation::OnRequest, Setup::Inspect);
    let recorded = desk.trail.entries.len();
    let unknown = Change::Grant {
        grant: grant("vault", Granted::One(host())),
        terms: terms(Activation::OnRequest, Exposure::NONE),
    };
    assert_eq!(
        tried(
            &mut desk,
            interface,
            Trial {
                change: Some(unknown),
                ..trial()
            }
        ),
        Tried::Refused(Refusal::UnknownCapability(name("vault")))
    );
    let older = Document {
        version: 1,
        ..Configuration::default().export()
    };
    assert_eq!(
        tried(
            &mut desk,
            interface,
            Trial {
                document: Some(older),
                ..trial()
            }
        ),
        Tried::Refused(Refusal::DocumentVersion {
            found: 1,
            supported: hedwig_model::config::DOCUMENT,
        })
    );
    assert_eq!(desk.trail.entries.len(), recorded);
    let Tried::Would(nothing) = tried(&mut desk, interface, trial()) else {
        unreachable!("an empty trial is answered")
    };
    assert_eq!(
        *nothing,
        Would {
            reach: hedwig_model::config::Reach::NoWider,
            rows: Vec::new(),
            remotes: Vec::new(),
            workstation: None,
        }
    );
    assert!(matches!(
        desk.send(
            interface,
            Request::Change(Change::Autostart(Some(Autostart::Off)))
        ),
        Ok(Reply::Changed {
            effect: Effect::Changed,
            ..
        })
    ));
}
