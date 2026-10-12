//! A removal of Hedwig begun and not finished: said where the person looks,
//! refused where an act would open a connection, kept across a run and a
//! compaction, and ended only by the person keeping Hedwig.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod support;

use hedwig_model::capability::{Exposure, Lends};
use hedwig_model::config::{Activation, Change, Configuration};
use hedwig_model::gate::World;
use hedwig_model::protocol::{Attention, Needs, Request, Topic};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::Granted;
use hedwig_model::setting::Volume;
use hedwig_model::trail::{
    CEILING, ClientId, ClientKind, Event, Opener, State, Timestamp, Withdrew, compact,
};

use support::{DESKTOP, Trail, capability, catalogue, grant, name, remote, terms};

/// `gpg` granted to every remote of the `coder` route, held continuously.
fn held() -> Configuration {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    configuration
        .apply(
            &catalogue,
            Change::Grant {
                grant: grant("gpg", Granted::Route(name("coder"))),
                terms: terms(
                    Activation::Continuous,
                    capability(&catalogue, "gpg").exposure(),
                ),
            },
        )
        .expect("the grant is accepted");
    configuration
}

fn connect() -> Request {
    Request::Connect {
        remote: remote("coder", "dev/build"),
        with: Vec::new(),
        acknowledged: Exposure::NONE,
        lends: Lends::none(),
    }
}

/// What the world answers for `state` under [`held`].
fn asked<T>(state: &State, ask: impl FnOnce(&World<'_>) -> T) -> T {
    let catalogue = catalogue();
    let configuration = held();
    ask(&World {
        catalogue: &catalogue,
        configuration: &configuration,
        state,
    })
}

/// A run with a terminal and the interface attached, in which the terminal
/// began removing Hedwig a second in.
fn begun() -> (Trail, ClientId, ClientId, Withdrew) {
    let mut trail = Trail::started();
    let terminal = trail.attach(ClientKind::Terminal, DESKTOP);
    let interface = trail.attach(ClientKind::Interface, DESKTOP);
    trail.wait(1_000);
    let entry = trail.push(Event::Withdrawn { by: terminal });
    let since = Withdrew {
        entry,
        at: Timestamp(1_790_000_001_000),
    };
    (trail, terminal, interface, since)
}

#[test]
fn a_removal_begun_is_said_where_the_person_looks_and_refused_at_each_connecting_act() {
    let build = remote("coder", "dev/build");
    let mut before = Trail::started();
    let terminal = before.attach(ClientKind::Terminal, DESKTOP);
    asked(&before.state(), |world| {
        assert_eq!(world.wants(&build), Some(Opener::Grant));
        assert_eq!(
            world.status(terminal, before.tick()).unwrap().withdrawn,
            None
        );
    });

    let (trail, terminal, interface, since) = begun();
    asked(&trail.state(), |world| {
        assert_eq!(
            world.status(terminal, trail.tick()).unwrap().withdrawn,
            Some(since)
        );
        let said = Needs {
            attention: Attention::Withdrawn(since),
            volume: Volume::Shown,
        };
        for client in [terminal, interface] {
            assert!(world.attention(client, trail.tick()).contains(&said));
        }
        assert_eq!(said.attention.item(), None, "nothing puts it away");
        assert_eq!(said.attention.remote(), None);
        assert_eq!(world.wants(&build), None);
        for request in [
            connect(),
            Request::Check {
                remote: build.clone(),
                capability: name("gpg"),
            },
            Request::Exercise {
                remote: build.clone(),
                capability: name("gpg"),
            },
        ] {
            assert_eq!(
                world.permit(terminal, &request),
                Err(Refusal::Withdrawn),
                "{request:?}"
            );
        }
        for request in [Request::Restore, Request::Withdraw, Request::Withdrawal] {
            assert_eq!(world.permit(terminal, &request), Ok(()), "{request:?}");
        }
    });
}

#[test]
fn a_removal_outlives_a_run_and_a_compaction_and_ends_when_the_person_keeps_hedwig() {
    let build = remote("coder", "dev/build");
    let (mut trail, _, interface, since) = begun();

    // Asked again, the removal keeps the entry it began at.
    trail.wait(1_000);
    trail.push(Event::Withdrawn { by: interface });
    assert_eq!(trail.state().withdrawn(), Some(since));

    trail.push(Event::Started {
        version: "0.2.1".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    assert_eq!(trail.state().withdrawn(), Some(since));
    let at = trail.entries.last().unwrap().at;
    let (head, compacted) = compact(State::default(), trail.entries.clone(), at, CEILING);
    assert!(matches!(
        compacted.first().map(|entry| &entry.event),
        Some(Event::Kept { .. })
    ));
    assert_eq!(head.withdrawn(), Some(since));
    assert_eq!(State::after(head, &compacted).withdrawn(), Some(since));

    let terminal = trail.attach(ClientKind::Terminal, DESKTOP);
    let interface = trail.attach(ClientKind::Interface, DESKTOP);
    let kept = trail.push(Event::Restored { by: interface });
    asked(&trail.state(), |world| {
        assert_eq!(
            world.status(terminal, trail.tick()).unwrap().withdrawn,
            None
        );
        assert_eq!(world.wants(&build), Some(Opener::Grant));
        assert_eq!(world.permit(terminal, &connect()), Ok(()));
        let told = |client| -> Vec<Attention> {
            world
                .attention(client, trail.tick())
                .into_iter()
                .map(|needs| needs.attention)
                .collect()
        };
        // Keeping Hedwig lets more through: every other surface is told.
        assert!(told(terminal).iter().any(|attention| matches!(
            attention,
            Attention::Widened { entry, kind: ClientKind::Interface, .. } if entry.seq == kept
        )));
        assert!(
            !told(interface)
                .iter()
                .any(|attention| matches!(attention, Attention::Widened { .. }))
        );
        assert!(
            !told(terminal)
                .iter()
                .any(|attention| matches!(attention, Attention::Withdrawn(_)))
        );
    });
    assert_eq!(
        Event::Restored { by: interface }.touches(),
        [Topic::Status, Topic::Exposure, Topic::Attention]
    );
}
