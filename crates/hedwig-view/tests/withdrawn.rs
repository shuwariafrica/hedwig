//! A removal of Hedwig that has not finished, where the person looks: the
//! window's head, the icon's tooltip and menu, the acts the core refuses
//! while it lasts, and keeping Hedwig from the window or another surface.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Instant;

use hedwig_model::capability::Exposure;
use hedwig_model::config::{Activation, Change};
use hedwig_model::protocol::{Attention, Request};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::trail::ClientKind;
use hedwig_view::act::Act;
use hedwig_view::exposure::{Board, Line, Shown, Window};
use hedwig_view::glance::{self, Entry, Glance};
use hedwig_view::link::{Event, Place};
use hedwig_view::words::{self, BEING_REMOVED, KEEPS, Keyrings};

mod common;
use common::support::{DESKTOP, grant, remote, terms};
use common::{Bench, clock};

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

/// A core with `gpg` granted to the workspace, and the link of `bench`.
fn granted(mut bench: Bench) -> Bench {
    bench.attach();
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(workspace())),
            terms: terms(Activation::OnRequest, Exposure::NONE),
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
            .find(|line| line.capability.as_str() == "gpg")
            .expect("gpg's line"),
        other => unreachable!("{other:?}"),
    }
}

fn connect(line: &Line) -> &Shown {
    line.acts
        .iter()
        .find(|shown| match shown {
            Shown::Offered { label, .. } | Shown::Withheld { label, .. } => label == "Connect",
        })
        .expect("Connect is on the line")
}

/// A person's removal stopped after it took back what Hedwig wrote. The window says
/// so at the head of its page, once, since when, with the two ways out and
/// keeping Hedwig put to them first; every act that would connect says why it
/// cannot; kept, the head goes and the line connects again.
#[test]
fn a_removal_under_way_heads_the_window_and_each_connecting_act_says_why() {
    let mut bench = granted(Bench::viewer());
    assert!(matches!(
        connect(line(&window(&bench))),
        Shown::Offered { .. }
    ));
    bench.feed(Event::Wish(Place::Window, Request::Withdraw));
    assert_eq!(bench.seen().refused, None);

    let shown = window(&bench);
    let [head] = &shown.heads[..] else {
        unreachable!("{:?}", shown.heads)
    };
    let since = bench
        .seen()
        .status
        .as_ref()
        .and_then(|status| status.withdrawn)
        .expect("the status says it");
    assert_eq!(
        head.sentence,
        format!(
            "Hedwig is being removed and serves no remote, since {}: it connects to none but to \
             take back what it wrote. Keep Hedwig to serve your remotes again as you consented, \
             or finish removing it in Windows' Installed apps.",
            clock(since.at)
        )
    );
    assert_eq!(
        head.acts,
        [Shown::Offered {
            label: "Keep Hedwig...".to_owned(),
            act: Act::Confirm {
                request: Request::Restore,
                consequence: KEEPS.to_owned(),
                answer: "Keep Hedwig".to_owned(),
            },
        }]
    );
    // Said once: not again among what needs the person.
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    assert!(
        needs
            .iter()
            .all(|need| !need.sentence.starts_with(BEING_REMOVED)),
        "{needs:?}"
    );
    assert_eq!(
        connect(line(&shown)),
        &Shown::Withheld {
            label: "Connect".to_owned(),
            why: Refusal::Withdrawn.to_string(),
        }
    );

    bench.feed(Event::Wish(Place::Window, Request::Restore));
    let kept = window(&bench);
    assert_eq!(kept.heads, []);
    assert!(matches!(connect(line(&kept)), Shown::Offered { .. }));
}

/// The icon, present all day, says the removal on its tooltip and first in
/// its menu, with keeping Hedwig confirmed as resuming is; kept from the
/// window, the icon is told how, and its menu no longer says it.
#[test]
fn the_icon_says_a_removal_under_way_and_hears_when_hedwig_is_kept_elsewhere() {
    let mut bench = granted(Bench::new());
    bench.feed(Event::Wish(Place::Tray, Request::Withdraw));
    let tip = Glance::of(bench.link.seen()).tip().to_owned();
    assert_eq!(tip, format!("{BEING_REMOVED} - 1 to look at"));
    let menu = glance::menu(bench.link.seen(), Instant::now());
    let at = menu
        .iter()
        .position(|entry| *entry == Entry::Line(BEING_REMOVED.to_owned()))
        .expect("said in the menu");
    assert_eq!(
        menu.get(at + 1),
        Some(&Entry::Act {
            label: "Keep Hedwig...".to_owned(),
            act: Act::Confirm {
                request: Request::Restore,
                consequence: KEEPS.to_owned(),
                answer: "Keep Hedwig".to_owned(),
            },
            chief: false,
        })
    );

    let window = bench.desk.attend(ClientKind::Viewer, DESKTOP);
    bench.desk.send(window, Request::Restore).unwrap();
    bench.told();
    let attention = bench.seen().attention.clone().unwrap_or_default();
    let said: Vec<String> = attention
        .iter()
        .map(|needs| words::attention(&needs.attention, Keyrings::default()))
        .collect();
    assert!(
        attention
            .iter()
            .any(|needs| matches!(needs.attention, Attention::Widened { .. })),
        "{said:?}"
    );
    assert!(
        said.contains(
            &"Hedwig was kept from Hedwig's window, or another program that shows Hedwig in \
              session 2: its removal ended, and it serves your remotes again as you consented"
                .to_owned()
        ),
        "{said:?}"
    );
    assert!(
        !glance::menu(bench.link.seen(), Instant::now())
            .contains(&Entry::Line(BEING_REMOVED.to_owned()))
    );
}
