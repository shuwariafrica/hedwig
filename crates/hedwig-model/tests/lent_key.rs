//! A lent key is its public half, lent once, toward a reach and with the
//! comment its agent gave it: narrowing a key lends less, reaching
//! further lends more, a comment lends nothing, and of two equally narrow
//! grants the one reaching less decides.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::cmp::Ordering;
use std::collections::BTreeSet;

use hedwig_model::capability::{Exposure, Lends, LentKey, Setup, Toward};
use hedwig_model::config::{Activation, Change, Reach, Terms};
use hedwig_model::protocol::Request;
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::text::{DeviceSerial, SshKey, TextError, Words};
use hedwig_model::trail::ClientKind;
use hedwig_model::wire::{Miss, WireError, line, read};

mod support;
use support::desk::Desk;
use support::{DESKTOP, catalogue, grant, name, pattern, remote};

/// An ED25519 key whose 32 bytes are all `n`, written as OpenSSH writes one.
fn key(n: u8) -> SshKey {
    let mut blob = Vec::new();
    for field in [&b"ssh-ed25519"[..], &[n; 32][..]] {
        blob.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(field);
    }
    SshKey::from_blob(&blob).unwrap()
}

fn hosts(of: &[u8]) -> Toward {
    Toward::Hosts(of.iter().map(|n| key(*n)).collect())
}

fn lent(keys: &[(u8, Toward)]) -> Lends {
    Lends::of_keys(
        keys.iter()
            .map(|(n, toward)| (key(*n), toward.clone().into())),
    )
}

fn commented(n: u8, toward: Toward, comment: &str) -> Lends {
    Lends::of_keys([(
        key(n),
        LentKey {
            toward,
            comment: Some(Words::try_from(comment).unwrap()),
        },
    )])
}

fn host() -> RemoteId {
    remote("ssh", "dev@build.example")
}

fn terms(lends: Lends) -> Terms {
    Terms {
        activation: Activation::OnRequest,
        setup: Setup::Inspect,
        acknowledged: Exposure::KEY_USE,
        lends,
    }
}

#[test]
fn narrowing_a_key_lends_less_and_reaching_further_lends_more() {
    let mut desk = Desk::new(catalogue());
    let interface = desk.attend(ClientKind::Interface, DESKTOP);
    let change = |lends: Lends| Change::Grant {
        grant: grant("ssh-agent", Granted::One(host())),
        terms: terms(lends),
    };
    let widens = |desk: &Desk, lends: Lends| {
        desk.ask_world(|world| world.widens(&Request::Change(change(lends))))
    };
    desk.send(
        interface,
        Request::Change(change(commented(1, Toward::Anywhere, "laptop"))),
    )
    .unwrap();
    for (lends, reach) in [
        // The account the interface's line was asked first by.
        (lent(&[(1, hosts(&[7, 8]))]), Reach::NoWider),
        (lent(&[(1, hosts(&[]))]), Reach::NoWider),
        (lent(&[(1, Toward::Anywhere)]), Reach::NoWider),
        (commented(1, Toward::Anywhere, "work"), Reach::NoWider),
        (Lends::none(), Reach::NoWider),
        (
            lent(&[(1, Toward::Anywhere), (2, hosts(&[7]))]),
            Reach::Wider,
        ),
        (lent(&[(2, Toward::Anywhere)]), Reach::Wider),
        (Lends::Every, Reach::Wider),
    ] {
        assert_eq!(widens(&desk, lends.clone()), reach, "{}", line(&lends));
    }

    desk.send(
        interface,
        Request::Change(change(lent(&[(1, hosts(&[7, 8]))]))),
    )
    .unwrap();
    for (lends, reach) in [
        (lent(&[(1, hosts(&[7]))]), Reach::NoWider),
        (lent(&[(1, hosts(&[8, 7]))]), Reach::NoWider),
        (lent(&[(1, hosts(&[7, 9]))]), Reach::Wider),
        (lent(&[(1, hosts(&[9]))]), Reach::Wider),
        (lent(&[(1, Toward::Anywhere)]), Reach::Wider),
    ] {
        assert_eq!(widens(&desk, lends.clone()), reach, "{}", line(&lends));
    }
}

#[test]
fn of_two_equally_narrow_grants_the_one_reaching_less_decides() {
    let set = hedwig_model::remote::Set {
        id: name("bench"),
        members: vec![hedwig_model::remote::Member::One(host())],
    };
    // Each pair: what a pattern's grant lends, what a set's grant lends, and
    // which decides. A pattern and a set select one remote equally narrowly.
    for (by_pattern, by_set, decides) in [
        (
            lent(&[(1, Toward::Anywhere)]),
            lent(&[(1, hosts(&[7]))]),
            lent(&[(1, hosts(&[7]))]),
        ),
        (
            lent(&[(1, hosts(&[7, 8]))]),
            lent(&[(1, hosts(&[8]))]),
            lent(&[(1, hosts(&[8]))]),
        ),
        // The host keys' text would have the first decide.
        (
            lent(&[(1, hosts(&[2, 9]))]),
            lent(&[(1, hosts(&[9]))]),
            lent(&[(1, hosts(&[9]))]),
        ),
        // Neither within the other: a key that can sign is the wider.
        (
            lent(&[(1, Toward::Anywhere)]),
            lent(&[(1, hosts(&[7, 8])), (2, hosts(&[7]))]),
            lent(&[(1, hosts(&[7, 8])), (2, hosts(&[7]))]),
        ),
    ] {
        let mut desk = Desk::new(catalogue());
        let interface = desk.attend(ClientKind::Interface, DESKTOP);
        desk.send(interface, Request::Change(Change::DefineSet(set.clone())))
            .unwrap();
        for (remotes, lends) in [
            (
                Granted::Matching {
                    route: name("ssh"),
                    pattern: pattern("dev@*"),
                },
                by_pattern,
            ),
            (Granted::Set(name("bench")), by_set),
        ] {
            desk.send(
                interface,
                Request::Change(Change::Grant {
                    grant: grant("ssh-agent", remotes),
                    terms: terms(lends),
                }),
            )
            .unwrap();
        }
        desk.channel_up(&host(), "linux");
        let state = desk.trail.state();
        let (_, link) = state.connection(&host()).expect("a channel is up");
        let lending = desk.ask_world(|world| world.lending(link, &name("ssh-agent")));
        assert_eq!(lending, Some((decides, false)));
    }
}

/// A small generator, seeded, so a failure names the case that made it.
struct Draw(u64);

impl Draw {
    fn next(&mut self, below: u8) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        u8::try_from(self.0 % u64::from(below)).unwrap()
    }

    fn lends(&mut self) -> Lends {
        if self.next(12) == 0 {
            return Lends::Every;
        }
        let devices: BTreeSet<DeviceSerial> = (0..self.next(3))
            .map(|_| {
                DeviceSerial::try_from(format!("emulator-555{}", self.next(3)).as_str()).unwrap()
            })
            .collect();
        let keys = (0..self.next(4))
            .map(|_| {
                let toward = if self.next(3) == 0 {
                    Toward::Anywhere
                } else {
                    let count = self.next(4);
                    Toward::Hosts((0..count).map(|_| key(10 + self.next(4))).collect())
                };
                let comment = (self.next(4) == 0).then(|| Words::try_from("laptop").unwrap());
                (key(self.next(4)), LentKey { toward, comment })
            })
            .collect();
        Lends::Named { devices, keys }
    }
}

/// The order is total, agrees with equality, and puts every set before each
/// set that reaches more than it, so "the less exposing" can never be a set
/// that reaches more.
#[test]
fn what_is_lent_is_ordered_by_what_it_reaches() {
    let mut draw = Draw(0x9e37_79b9_7f4a_7c15);
    let drawn: Vec<Lends> = (0..400).map(|_| draw.lends()).collect();
    let mut within = 0;
    for one in &drawn {
        assert!(!one.exceeds(one));
        assert!(one <= &Lends::Every);
        for other in &drawn {
            assert_eq!(one.cmp(other) == Ordering::Equal, one == other);
            assert_eq!(one.cmp(other), other.cmp(one).reverse());
            if !one.exceeds(other) && other.exceeds(one) {
                within += 1;
                assert!(one < other, "{} before {}", line(one), line(other));
            }
        }
    }
    assert!(within > 10_000, "{within} pairs one within the other");
    let mut sorted = drawn.clone();
    sorted.sort();
    for window in sorted.windows(3) {
        let [a, b, c] = window else { unreachable!() };
        assert!(a <= b && b <= c && a <= c);
    }
}

/// A lent key is written with where it may be used and its comment, and
/// read back as written; a key named twice, whatever its reach, is refused,
/// as is a comment that is not words or a record without one.
#[test]
fn a_lent_key_is_written_with_its_reach_and_comment_and_read_back() {
    let both = Lends::Named {
        devices: BTreeSet::new(),
        keys: [
            (
                key(1),
                LentKey {
                    toward: Toward::Anywhere,
                    comment: Some(Words::try_from("laptop").unwrap()),
                },
            ),
            (key(2), hosts(&[7]).into()),
        ]
        .into(),
    };
    let written = line(&both);
    assert_eq!(
        written,
        format!(
            r#"[{{"key":"{}","toward":"anywhere","comment":"laptop"}},{{"key":"{}","toward":{{"hosts":["{}"]}},"comment":null}}]"#,
            key(1),
            key(2),
            key(7)
        )
    );
    assert_eq!(read::<Lends>(&written), Ok(both));

    let miss = |text: String| match read::<Lends>(&text).expect_err("refused") {
        WireError::Fault(fault) => (fault.path(), fault.miss),
        other => unreachable!("{other:?}"),
    };
    let twice = format!(
        r#"[{{"key":"{k}","toward":"anywhere","comment":null}},{{"key":"{k}","toward":{{"hosts":[]}},"comment":null}}]"#,
        k = key(1)
    );
    assert_eq!(miss(twice), ("1".to_owned(), Miss::Repeated));
    assert_eq!(
        miss(format!(r#"[{{"key":"{}","toward":"anywhere"}}]"#, key(1))),
        ("0".to_owned(), Miss::Missing("comment"))
    );
    assert!(matches!(
        miss(format!(
            r#"[{{"key":"{}","toward":"anywhere","comment":"a\u0007bell"}}]"#,
            key(1)
        )),
        (_, Miss::Text(TextError::Character { .. }))
    ));
}
