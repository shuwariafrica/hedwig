//! A remote's job telling the person something: its words cleaned into a
//! remark that reads only as written, the gate that keeps or refuses it, the
//! bound on what one remote sends, and the person's attention it becomes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

mod support;

use hedwig_model::capability::{Capability, Dialect, Exposure, Form, Lends, Setup, Source};
use hedwig_model::config::{Activation, Change, Configuration, Terms};
use hedwig_model::gate::World;
use hedwig_model::protocol::Attention;
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, Remotes};
use hedwig_model::setting::{Condition, Heard, Volume, Waits};
use hedwig_model::text::{REMARK, Remark, TextError, Variable};
use hedwig_model::trail::{
    ClientId, ClientKind, Event, Item, NOTICE_WINDOW, NOTICES_AT_ONCE, NOTICES_KEPT, Seq, Write,
};
use support::{DESKTOP, Seeded, Trail, catalogue, grant, name, remote};

/// Each control character and each character that turns text around goes;
/// a line break, a tab and a separator become a blank; what is left is the
/// remote's words as written, trimmed.
#[test]
fn a_remark_reads_only_as_written() {
    for (said, kept) in [
        ("build finished", "build finished"),
        ("  deploy\tdone\r\n", "deploy done"),
        ("\u{1b}[31mred\u{1b}[0m", "[31mred[0m"),
        ("pay\u{202e}gnp.exe", "paygnp.exe"),
        ("a\u{2066}b\u{2069}c\u{200f}d\u{061c}e", "abcde"),
        ("line\u{2028}next\u{2029}para", "line next para"),
        ("bell\u{7}\u{85}\u{9f}", "bell"),
        (
            "caf\u{e9} \u{1f680} \u{65e5}\u{672c}",
            "caf\u{e9} \u{1f680} \u{65e5}\u{672c}",
        ),
    ] {
        assert_eq!(Remark::cleaned(said).unwrap().as_str(), kept, "{said:?}");
    }
    assert_eq!(Remark::cleaned("\u{7}\n\u{202e}"), Err(TextError::Empty));
    let long = "x".repeat(REMARK + 1);
    assert!(matches!(
        Remark::cleaned(&long),
        Err(TextError::TooLong { .. })
    ));
    assert!(Remark::try_from("two\nlines").is_err());
    assert!(Remark::try_from("over\u{202e}ride").is_err());
}

/// Whatever a remote posts, what is kept holds no control character and
/// nothing that turns text around.
#[test]
fn no_remark_holds_what_could_make_it_read_as_other_words() {
    let alphabet = [
        "a",
        " ",
        "\n",
        "\t",
        "\r",
        "\u{1b}",
        "\u{7}",
        "\u{7f}",
        "\u{85}",
        "\u{202a}",
        "\u{202e}",
        "\u{2066}",
        "\u{2069}",
        "\u{200e}",
        "\u{2028}",
        "\u{e9}",
        "\u{1f680}",
    ];
    let mut seeded = Seeded(46);
    let mut kept = 0;
    for _ in 0..5_000 {
        let said: String = (0..seeded.below(24))
            .map(|_| *seeded.pick(&alphabet))
            .collect();
        if let Ok(remark) = Remark::cleaned(&said) {
            kept += 1;
            assert!(
                remark.as_str().chars().all(|c| !c.is_control()
                    && !"\u{202a}\u{202e}\u{2066}\u{2069}\u{200e}\u{2028}".contains(c)),
                "{said:?}"
            );
            assert_eq!(Remark::try_from(remark.as_str()).unwrap(), remark);
        }
    }
    assert!(kept > 1_000);
}

/// The capability exposes the person's attention, which a grant names;
/// carried only behind a private socket and its variable, written under
/// consent; it decides nothing, so no rule has an operation to name.
#[test]
fn notices_expose_attention_and_are_carried_behind_their_variable() {
    let catalogue = catalogue();
    let notices = support::capability(&catalogue, "notices");
    assert_eq!(notices.source, Source::Notices);
    assert_eq!(notices.exposure(), Exposure::ATTENTION);
    assert_eq!(
        Exposure::ACKNOWLEDGED.common(Exposure::ATTENTION),
        Exposure::ATTENTION
    );
    assert_eq!(notices.dialect(), Dialect::Notice);
    assert_eq!(notices.dialect().operations(), []);
    assert_eq!(notices.forms(), [Form::Notifier]);
    assert_eq!(
        notices.consent(None).writes,
        [Write::Variable(
            Variable::try_from("HEDWIG_NOTIFY").unwrap()
        )]
    );
    let shipped = Configuration::default();
    let windows = shipped.platform(&catalogue, &name("windows")).unwrap();
    assert!(matches!(
        notices.carrier(windows, Setup::Write),
        Err(Refusal::NoCarrier { .. })
    ));
    // A grant that does not name what it exposes serves nothing.
    let mut configuration = Configuration::default();
    let unnamed = configuration.apply(
        &catalogue,
        Change::Grant {
            grant: grant("notices", Granted::One(remote("ssh", "build"))),
            terms: Terms {
                activation: Activation::OnRequest,
                setup: Setup::Write,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            },
        },
    );
    assert!(matches!(
        unnamed,
        Err(Refusal::ExposureNotAcknowledged { .. })
    ));
}

fn granted() -> (Configuration, Trail, hedwig_model::trail::ConnectionId) {
    let catalogue = catalogue();
    let host = remote("ssh", "build");
    let mut configuration = Configuration::default();
    configuration
        .apply(
            &catalogue,
            Change::Grant {
                grant: grant("notices", Granted::One(host.clone())),
                terms: Terms {
                    activation: Activation::OnRequest,
                    setup: Setup::Write,
                    acknowledged: Exposure::ATTENTION,
                    lends: Lends::none(),
                },
            },
        )
        .unwrap();
    let mut trail = Trail::started();
    let connection = trail.open(&host, "linux");
    (configuration, trail, connection)
}

fn noticed(trail: &mut Trail, connection: hedwig_model::trail::ConnectionId, said: &str) -> Seq {
    trail.push(Event::Noticed {
        connection,
        capability: name("notices"),
        remark: Remark::try_from(said).unwrap(),
        unheard: 0,
    })
}

/// A notice is kept whoever is there - nothing is held for it - and refused
/// only as any request is before its mode, or for coming too fast: past
/// [`NOTICES_AT_ONCE`] in [`NOTICE_WINDOW`], until the oldest leaves it.
#[test]
fn a_notice_is_refused_only_before_any_mode_and_for_coming_too_fast() {
    let catalogue = catalogue();
    let (configuration, mut trail, connection) = granted();
    let notices = name("notices");
    let world = |trail: &Trail, configuration: &Configuration| {
        let state = trail.state();
        World {
            catalogue: &catalogue,
            configuration,
            state: &state,
        }
        .notice(connection, &notices, trail.tick())
    };
    assert_eq!(
        world(&trail, &configuration),
        Ok(()),
        "nobody is there, and it is kept"
    );
    for _ in 0..NOTICES_AT_ONCE {
        trail.wait(1_000);
        noticed(&mut trail, connection, "step done");
    }
    assert_eq!(
        world(&trail, &configuration),
        Err(Refusal::Hushed {
            capability: notices.clone()
        })
    );
    trail.wait(NOTICE_WINDOW - 9_000);
    assert_eq!(
        world(&trail, &configuration),
        Ok(()),
        "the oldest has left the window"
    );
    assert!(matches!(
        world(&trail, &Configuration::default()),
        Err(Refusal::NotGranted { .. })
    ));
    trail.push(Event::Paused {
        scope: Remotes::Every,
        by: ClientId(Seq(1)),
    });
    assert_eq!(world(&trail, &configuration), Err(Refusal::Paused));
    let unknown = hedwig_model::trail::ConnectionId(Seq(999));
    let state = trail.state();
    assert_eq!(
        World {
            catalogue: &catalogue,
            configuration: &configuration,
            state: &state,
        }
        .notice(unknown, &notices, trail.tick()),
        Err(Refusal::UnknownConnection(unknown))
    );
    // A connection of another capability is never a notice's.
    let gpg = Capability {
        id: name("gpg"),
        source: support::capability(&catalogue, "gpg").source,
    };
    let state = trail.state();
    assert!(
        World {
            catalogue: &catalogue,
            configuration: &configuration,
            state: &state,
        }
        .notice(connection, &gpg.id, trail.tick())
        .is_err()
    );
}

/// Each notice is the person's to read at the volume they hear that remote's
/// notices at, announced as it ships; the newest [`NOTICES_KEPT`] are kept
/// across a restart, and putting one away puts away every earlier one.
#[test]
fn notices_are_the_persons_to_read_until_put_away() {
    let catalogue = catalogue();
    let (mut configuration, mut trail, connection) = granted();
    let viewer = trail.attach(ClientKind::Interface, DESKTOP);
    let mut seqs = Vec::new();
    for count in 0..=NOTICES_KEPT {
        seqs.push(noticed(
            &mut trail,
            connection,
            &format!("job {count} done"),
        ));
    }
    let attention = |trail: &Trail, configuration: &Configuration| {
        let state = trail.state();
        World {
            catalogue: &catalogue,
            configuration,
            state: &state,
        }
        .attention(viewer, trail.tick())
        .into_iter()
        .filter_map(|needs| match needs.attention {
            Attention::Noticed { notice, .. } => Some((notice, needs.volume)),
            _ => None,
        })
        .collect::<Vec<_>>()
    };
    let kept = attention(&trail, &configuration);
    assert_eq!(kept.len(), NOTICES_KEPT);
    assert_eq!(kept.first().unwrap().0, seqs[1], "the oldest went");
    assert!(kept.iter().all(|(_, volume)| *volume == Volume::Announced));
    assert_eq!(Condition::Noticed.ships(), Volume::Announced);

    configuration
        .apply(
            &catalogue,
            Change::Hear {
                remotes: Remotes::One(remote("ssh", "build")),
                heard: Heard::Noticed(Waits::Shown),
            },
        )
        .unwrap();
    assert!(
        attention(&trail, &configuration)
            .iter()
            .all(|(_, volume)| *volume == Volume::Shown)
    );

    trail.push(Event::Started {
        version: "0.2.0".to_owned(),
        origin: DESKTOP,
        after: None,
    });
    let viewer = trail.attach(ClientKind::Interface, DESKTOP);
    let state = trail.state();
    let after = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    }
    .attention(viewer, trail.tick());
    assert_eq!(
        after
            .iter()
            .filter(|needs| matches!(needs.attention, Attention::Noticed { .. }))
            .count(),
        NOTICES_KEPT,
        "a notice is not live: it outlasts the run"
    );
    let through = seqs[10];
    trail.push(Event::PutAway {
        item: Item::Noticed {
            remote: remote("ssh", "build"),
            through,
        },
        by: viewer,
    });
    let left: Vec<Seq> = {
        let state = trail.state();
        World {
            catalogue: &catalogue,
            configuration: &configuration,
            state: &state,
        }
        .attention(viewer, trail.tick())
        .into_iter()
        .filter_map(|needs| match needs.attention {
            Attention::Noticed { notice, .. } => Some(notice),
            _ => None,
        })
        .collect()
    };
    assert!(left.iter().all(|notice| *notice > through));
    assert_eq!(left.len(), NOTICES_KEPT + 1 - 11);
}
