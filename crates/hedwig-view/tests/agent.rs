//! The person's own SSH agent at the surfaces: keys lent by grant, named as
//! the person's agent named them when they were lent, read from the agent
//! only when the person asks; where each lent key may be used, narrowed at
//! once and widened asked first on its line;
//! a key a remote reached for lent from where the refusal shows; a login
//! told from a signature at the card and in the activity; the agent defined
//! where it is; and who answers at its pipe, with what the agent's own
//! prompts cannot say.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::time::Instant;

use hedwig_model::capability::{AgentAt, Exposure, Lends, LentKey, Operation, Source, Toward};
use hedwig_model::config::{Activation, Change, Terms};
use hedwig_model::gate::Verdict;
use hedwig_model::holder::{Rights, SignedIn, SourceHolder, Whose};
use hedwig_model::policy::{Keys as KeyScope, Mode, RuleScope, Selector};
use hedwig_model::protocol::{AgentKey, Notice, Request, Topic};
use hedwig_model::refusal::{Refusal, Withheld};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::text::{AgentPipe, KeyId, Location, SshKey, Words};
use hedwig_model::trail::{Event as Happened, Failure, Health, Payload, RequestId};
use hedwig_view::act::Act;
use hedwig_view::card::{Card, Deck, Why};
use hedwig_view::define::{self, Edit, Kind};
use hedwig_view::exposure::{self, Board, Line, Shown, Window};
use hedwig_view::grant::{self, Draft, Form, Owed};
use hedwig_view::link::{Event, Place};
use hedwig_view::words;

mod common;
use common::support::{grant, name, remote, terms};
use common::{Bench, clock};

/// A key a real remote signed a commit with, whose fingerprint
/// `git verify-commit` printed there.
const A: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/fZgxPr11UWZgHjQXEU/F65sUwfaohdFFly5gtgRRs";
const A_SAID: &str = "ED25519 key SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE";
/// A security key's public half, as `ssh-keygen -l` named it.
const SK: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIEX/dQ0v4127bEo8eeG1EV0ApO2lWbW8QijeUmdqzOkiAAAABHNzaDo=";
const SK_SAID: &str = "ED25519-SK key SHA256:Waob+Q0aMrFVZlh0quFilLFF7TWazTaDD2O79RknZPA";
/// A host's key, as `ssh-keyscan` prints a line of it.
const HOST: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNwo9zNZ1p9OJMHFfawTucuCrkP+GumZ23WooozBOTggm9wkcD/mjb+3nAAyY655XW+KEaqiVzrtd3CsyDdVeX4=";
const HOST_SAID: &str = "ECDSA SHA256:X4mkNnFzELzfodwwfn4jjh4ZhRfFtBN7vYS3FjS/nR0";

fn key(text: &str) -> SshKey {
    SshKey::try_from(text).unwrap()
}

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

/// The person's agent holds A, which it calls `laptop`, and a security key
/// it calls `yubikey`.
fn held() -> Vec<AgentKey> {
    vec![
        AgentKey {
            key: key(A),
            comment: Some(Words::try_from("laptop").unwrap()),
        },
        AgentKey {
            key: key(SK),
            comment: Some(Words::try_from("yubikey").unwrap()),
        },
    ]
}

fn comment(text: &str) -> Words {
    Words::try_from(text).unwrap()
}

/// A lent toward `toward` with the comment the person's agent listed it
/// with, as the grant form and the line lend it.
fn lent_a(toward: Toward) -> Lends {
    Lends::of_keys([(
        key(A),
        LentKey {
            toward,
            comment: Some(comment("laptop")),
        },
    )])
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

fn asked_for_keys(bench: &Bench) -> usize {
    bench
        .sent
        .iter()
        .filter(|frame| matches!(frame.request, Request::Keys(_)))
        .count()
}

fn granting(lends: Lends) -> Change {
    Change::Grant {
        grant: grant("ssh-agent", Granted::One(workspace())),
        terms: Terms {
            lends,
            ..terms(Activation::OnRequest, Exposure::KEY_USE)
        },
    }
}

/// The window's link attached, the person's agent `held()`, and
/// `ssh-agent` granted to the workspace lending `lends`.
fn lending(lends: Lends) -> Bench {
    let mut bench = Bench::viewer();
    bench.attach();
    bench.desk.held.keys.insert(name("ssh-agent"), Ok(held()));
    bench.feed(Event::Window(true));
    bench.feed(Event::Wish(Place::Window, Request::Change(granting(lends))));
    assert_eq!(bench.seen().refused, None);
    bench
}

fn window(bench: &Bench) -> Window {
    Window::of(bench.link.seen(), &clock, Instant::now())
}

fn agent(window: &Window) -> &Line {
    match &window.board {
        Board::Exposure { groups, .. } => groups
            .iter()
            .flat_map(|group| &group.lines)
            .find(|line| {
                line.remote == Some(workspace()) && line.capability.as_str() == "ssh-agent"
            })
            .expect("ssh-agent's line on the workspace"),
        other => unreachable!("{other:?}"),
    }
}

fn label(shown: &Shown) -> &str {
    match shown {
        Shown::Offered { label, .. } | Shown::Withheld { label, .. } => label,
    }
}

fn act(shown: &Shown) -> &Act {
    match shown {
        Shown::Offered { act, .. } => act,
        Shown::Withheld { .. } => unreachable!("withheld"),
    }
}

fn request(shown: &Shown) -> Request {
    match act(shown) {
        Act::Send(request) | Act::Confirm { request, .. } => common::clone(request),
        other => unreachable!("{other:?}"),
    }
}

fn lent_in_document(bench: &Bench) -> Lends {
    bench
        .seen()
        .document
        .as_ref()
        .unwrap()
        .grants
        .iter()
        .find(|entry| entry.grant.capability.as_str() == "ssh-agent")
        .unwrap()
        .terms
        .lends
        .clone()
}

fn form(bench: &Bench, draft: &Draft) -> Form {
    let attached = bench.seen();
    Form::of(
        draft,
        attached.catalogue.as_ref().unwrap().reference(),
        attached.document.as_ref().unwrap(),
        attached.workstation.as_ref(),
        (None, attached.agent_keys.get(&name("ssh-agent"))),
        None,
    )
}

/// A person grants their agent: the form asks the agent nothing until they choose
/// it, then lists its keys as their agent names them; none is lent until
/// they name one; each lent key may log in anywhere and sign, or only log in
/// to the hosts whose keys they paste; the grant the core takes lends
/// exactly that; and the form says that the agent's own prompts cannot name
/// the remote, so Hedwig's decision per remote stands in their place.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one person's flow through the grant form"
)]
fn a_grant_of_the_persons_agent_lends_the_keys_they_name_where_they_say() {
    let mut bench = Bench::viewer();
    bench.attach();
    bench.desk.held.keys.insert(name("ssh-agent"), Ok(held()));
    bench.feed(Event::Window(true));
    let mut draft = Draft::default();
    let attached = bench.seen();
    let (reference, document) = (
        attached.catalogue.as_ref().unwrap().reference().clone(),
        attached.document.clone().unwrap(),
    );
    draft.choose_capability(name("ssh-agent"), &reference, &document);
    let keying = form(&bench, &draft).keying.unwrap();
    assert_eq!(
        asked_for_keys(&bench),
        0,
        "showing the form asks the agent nothing"
    );
    assert!(keying.ask);
    assert_eq!(
        keying.listing.as_deref(),
        Some(
            "Hedwig has not asked your agent which keys it holds: it asks only when you do, \
             since a password manager can ask you to approve the list."
        )
    );
    assert_eq!(keying.asks, words::AGENT_ASKS);
    assert!(keying.asks.contains("never the remote"));

    // Choosing it is the person's act: the agent is asked once.
    bench.feed(Event::Keys(name("ssh-agent")));
    bench.feed(Event::Keys(name("ssh-agent")));
    assert_eq!(asked_for_keys(&bench), 1);
    let keying = form(&bench, &draft).keying.unwrap();
    assert_eq!(keying.listing, None);
    assert_eq!(
        keying
            .keys
            .iter()
            .map(|choice| (choice.label.as_str(), choice.chosen))
            .collect::<Vec<_>>(),
        [
            (format!("{A_SAID} (laptop)").as_str(), false),
            (format!("{SK_SAID} (yubikey)").as_str(), false),
        ]
    );
    assert_eq!(
        keying.lends,
        "lends no key: the remote is told of none until you lend one"
    );

    draft.lend_key(&keying.keys[0], true);
    let keying = form(&bench, &draft).keying.unwrap();
    assert_eq!(keying.keys[0].hosts.as_deref(), Some(""));
    assert_eq!(
        keying.lends,
        format!("lends {A_SAID} (laptop) for logging in to any host, and for signing")
    );
    // Pasted as ssh-keyscan prints it: only for logging in there.
    draft.type_hosts(key(A), &format!("build.example {HOST}"));
    let keying = form(&bench, &draft).keying.unwrap();
    assert_eq!(keying.keys[0].invalid, None);
    draft.acknowledge("key-use", true);
    draft.choose_route(name("coder"), &reference);
    draft.choose_activation(Activation::OnRequest);
    let Ok(Change::Grant { terms, .. }) = draft.change(&reference, &document) else {
        unreachable!("{:?}", draft.change(&reference, &document))
    };
    // Lent with the comment the agent listed it with.
    assert_eq!(terms.lends, lent_a(Toward::Hosts([key(HOST)].into())));
    // Something that is no host's key is said beneath it, and owed.
    draft.type_hosts(key(A), "build.example");
    let keying = form(&bench, &draft).keying.unwrap();
    assert_eq!(
        keying.keys[0].invalid.as_deref(),
        Some(
            "\"build.example\" names no host's key: paste each host's key as ssh-keyscan or a \
             known_hosts line prints it, one to a line."
        )
    );
    assert!(matches!(
        draft.change(&reference, &document),
        Err(Owed::Hosts { .. })
    ));
    draft.type_hosts(key(A), HOST);

    // The draft is kept on disk with what was typed, and read back whole.
    assert_eq!(Draft::read(&draft.written()), Ok(draft.clone()));

    // A key taken back loses what was typed for it.
    let keying = form(&bench, &draft).keying.unwrap();
    draft.lend_key(&keying.keys[1], true);
    draft.lend_key(&keying.keys[1], false);
    assert_eq!(draft.lends.key(&key(SK)), None);
    let change = draft.change(&reference, &document).unwrap();
    bench.feed(Event::Wish(Place::Window, Request::Change(change)));
    assert_eq!(bench.seen().refused, None);
    assert_eq!(
        lent_in_document(&bench),
        lent_a(Toward::Hosts([key(HOST)].into()))
    );

    // Every key is a choice of its own.
    draft.lend_every(true);
    let keying = form(&bench, &draft).keying.unwrap();
    assert!(keying.every);
    assert_eq!(
        keying.lends,
        "lends every key the agent holds, now and later, for anything"
    );
}

/// A person reads on the grant's line which keys it lends, each named as their
/// agent named it when they lent it, and where each may be used, and changes
/// it there: a key taken back in one act; narrowed to the hosts they paste at
/// once, since that lends less; a host added, lent for anything again,
/// and a key lent, each asked first, the key with the comment their agent
/// listed it with. Showing the line asks the agent nothing; the person
/// asks.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one person's flow over a line's keys"
)]
fn a_grants_line_lends_narrows_and_takes_back_its_keys() {
    let mut bench = lending(lent_a(Toward::Anywhere));
    let line = || Place::Line {
        remote: Some(workspace()),
        capability: name("ssh-agent"),
    };
    let shown = window(&bench);
    let keys = agent(&shown).keys.as_ref().unwrap();
    assert_eq!(
        asked_for_keys(&bench),
        0,
        "showing the line asks the agent nothing"
    );
    assert_eq!(
        keys.lends,
        format!("lends {A_SAID} (laptop) for logging in to any host, and for signing")
    );
    assert_eq!(keys.asks, words::AGENT_ASKS);
    assert_eq!(keys.keys.len(), 1);
    assert_eq!(keys.keys[0].label, format!("{A_SAID} (laptop)"));
    assert_eq!(
        keys.keys[0].toward.as_deref(),
        Some("for logging in to any host, and for signing")
    );
    assert_eq!(keys.keys[0].hosts.as_deref(), Some(""));
    assert_eq!(keys.keys[0].anywhere, None);
    assert_eq!(
        keys.keys[0].act.as_ref().map(label),
        Some(format!("Stop lending {A_SAID} (laptop)").as_str())
    );
    assert_eq!(
        keys.acts.iter().map(label).collect::<Vec<_>>(),
        [
            "Lend every key...",
            "Show your agent's keys, to lend another"
        ]
    );

    // The person asks: the agent is read once, and its other key offered.
    bench.feed(Event::Wish(line(), request(&keys.acts[1])));
    assert_eq!(asked_for_keys(&bench), 1);
    let shown = window(&bench);
    let keys = agent(&shown).keys.as_ref().unwrap();
    assert_eq!(
        keys.keys
            .iter()
            .map(|line| (line.label.as_str(), line.lent, line.act.as_ref().map(label)))
            .collect::<Vec<_>>(),
        [
            (
                format!("{A_SAID} (laptop)").as_str(),
                true,
                Some(format!("Stop lending {A_SAID} (laptop)").as_str())
            ),
            (
                format!("{SK_SAID} (yubikey)").as_str(),
                false,
                Some(format!("Lend {SK_SAID} (yubikey)...").as_str())
            ),
        ]
    );
    let Act::Confirm { consequence, .. } = act(keys.keys[1].act.as_ref().unwrap()) else {
        unreachable!("lending a key is asked first")
    };
    assert_eq!(
        consequence,
        &format!(
            "dev/build (coder) can then log in to any host with {SK_SAID} (yubikey) and sign with \
             it - a commit, a tag, a file - each as you set for that remote."
        )
    );

    // Narrowed to the host pasted: a key lent toward one host lends less
    // than the same key lent anywhere (`Lends::exceeds`), so the
    // model's judge carries it out at once, keeping the comment.
    let attached = bench.seen();
    let narrowed = exposure::restrict(
        attached,
        Some(&workspace()),
        &name("ssh-agent"),
        &key(A),
        &format!("build.example {HOST}\r"),
    )
    .unwrap();
    assert_eq!(
        label(&narrowed),
        "Lend it only for logging in to these hosts"
    );
    assert!(
        matches!(act(&narrowed), Act::Send(_)),
        "narrowing is carried out at once: {:?}",
        act(&narrowed)
    );
    assert_eq!(
        exposure::restrict(
            attached,
            Some(&workspace()),
            &name("ssh-agent"),
            &key(A),
            "build.example"
        ),
        Err(
            "\"build.example\" names no host's key: paste each host's key as ssh-keyscan or a \
             known_hosts line prints it, one to a line."
                .to_owned()
        )
    );
    bench.feed(Event::Wish(line(), request(&narrowed)));
    assert_eq!(bench.seen().refused, None);
    assert_eq!(
        lent_in_document(&bench),
        lent_a(Toward::Hosts([key(HOST)].into()))
    );
    // A host added lends more: asked first, with what it then lets through.
    let added = exposure::restrict(
        bench.seen(),
        Some(&workspace()),
        &name("ssh-agent"),
        &key(A),
        &format!("{HOST}\n{A}"),
    )
    .unwrap();
    assert_eq!(
        label(&added),
        "Lend it only for logging in to these hosts..."
    );
    let Act::Confirm { consequence, .. } = act(&added) else {
        unreachable!("lending toward one more host is asked first")
    };
    assert_eq!(
        consequence,
        &format!(
            "{A_SAID} (laptop) is then lent to dev/build (coder) only for logging in to the hosts \
             whose keys are {HOST_SAID}, ED25519 SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE, \
             and for nothing else."
        )
    );
    let shown = window(&bench);
    let keys = agent(&shown).keys.as_ref().unwrap();
    assert_eq!(
        keys.keys[0].toward.as_deref(),
        Some(
            format!(
                "only for logging in to the host whose key is {HOST_SAID}, and for nothing else"
            )
            .as_str()
        )
    );
    assert_eq!(keys.keys[0].hosts.as_deref(), Some(HOST));
    // Lent for anything again: asked first.
    let anywhere = keys.keys[0].anywhere.as_ref().unwrap();
    assert_eq!(
        label(anywhere),
        format!("Lend {A_SAID} (laptop) for anything...")
    );
    assert!(matches!(act(anywhere), Act::Confirm { .. }));
    assert_eq!(bench.permits(&request(anywhere)), Ok(()));
    bench.feed(Event::Wish(line(), request(anywhere)));
    let shown = window(&bench);
    assert_eq!(agent(&shown).keys.as_ref().unwrap().keys[0].anywhere, None);

    // Taken back in one act.
    let stop = agent(&shown).keys.as_ref().unwrap().keys[0]
        .act
        .as_ref()
        .unwrap();
    assert!(matches!(act(stop), Act::Send(_)));
    bench.feed(Event::Wish(line(), request(stop)));
    assert_eq!(lent_in_document(&bench), Lends::none());
    let shown = window(&bench);
    let keys = agent(&shown).keys.as_ref().unwrap();
    assert_eq!(
        keys.lends,
        "lends no key: the remote is told of none until you lend one"
    );

    // Lent from the agent's list: with the comment the agent listed it with.
    let lend = keys
        .keys
        .iter()
        .find(|line| line.key == key(SK))
        .and_then(|line| line.act.as_ref())
        .unwrap();
    assert!(matches!(act(lend), Act::Confirm { .. }));
    bench.feed(Event::Wish(line(), request(lend)));
    assert_eq!(
        lent_in_document(&bench),
        Lends::of_keys([(
            key(SK),
            LentKey {
                toward: Toward::Anywhere,
                comment: Some(comment("yubikey")),
            }
        )])
    );
}

/// A remote that asked for a key the grant does not lend, or used one
/// beyond the hosts it is lent toward, is told on the line in the model's
/// words, and the key is lent there and from what needs the person, asked
/// first.
#[test]
fn a_key_a_remote_reached_for_is_lent_from_where_its_refusal_shows() {
    let mut bench = lending(lent_a(Toward::Hosts([key(HOST)].into())));
    bench.desk.channel_up(&workspace(), "linux");
    for request in [Withheld::KeyUnlent(key(SK)), Withheld::Elsewhere(key(A))] {
        bench.desk.trail.push(Happened::TurnedAway {
            remote: Some(workspace()),
            refusal: Refusal::Withheld {
                capability: name("ssh-agent"),
                request,
            },
        });
    }
    refresh(&mut bench);
    let shown = window(&bench);
    let line = agent(&shown);
    let mut turned = line.turned.clone();
    turned.sort();
    assert_eq!(
        turned,
        [
            "a request to ssh-agent was refused because it asked for sk-ssh-ed25519@openssh.com, \
             which the grant does not lend, once",
            "a request to ssh-agent was refused because it used ssh-ed25519 for something other \
             than logging in to a host the grant names for it, once",
        ]
    );
    let keys = line.keys.as_ref().unwrap();
    assert_eq!(
        keys.acts.iter().map(label).collect::<Vec<_>>(),
        [
            format!("Lend {SK_SAID}...").as_str(),
            "Lend every key...",
            "Show your agent's keys, to lend another"
        ]
    );
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    let mut offered: Vec<&str> = needs
        .iter()
        .flat_map(|need| &need.acts)
        .map(label)
        .filter(|label| label.starts_with("Lend"))
        .collect();
    offered.sort_unstable();
    let mut wanted = [
        format!("Lend {A_SAID} (laptop) for anything..."),
        format!("Lend {SK_SAID}..."),
    ];
    wanted.sort();
    assert_eq!(offered, wanted);
    for need in needs {
        for shown in need
            .acts
            .iter()
            .filter(|shown| label(shown).starts_with("Lend"))
        {
            assert_eq!(bench.permits(&request(shown)), Ok(()));
        }
    }
}

/// The presence, attending, with `ssh-agent` granted lending A and every
/// request it carries for the workspace asked first, and the workspace's
/// channel up.
fn holding() -> (Bench, hedwig_model::trail::ConnectionId) {
    let mut bench = Bench::attached();
    for change in [
        granting(lent_a(Toward::Anywhere)),
        Change::Rule {
            scope: RuleScope {
                remotes: Remotes::One(workspace()),
                capability: Selector::Only(name("ssh-agent")),
                operation: Selector::Every,
                key: KeyScope::Every,
            },
            mode: Mode::Confirm,
        },
    ] {
        bench.feed(Event::Wish(Place::Window, Request::Change(change)));
        assert_eq!(bench.seen().refused, None);
    }
    let connection = bench.desk.channel_up(&workspace(), "linux");
    (bench, connection)
}

/// The remote's tool asks, as the relay records it: the request with its
/// key, at once what it asks to have signed, then what the gate said.
fn ask(
    bench: &mut Bench,
    connection: hedwig_model::trail::ConnectionId,
    operation: Operation,
    payload: Payload,
) -> RequestId {
    let now = bench.desk.trail.tick();
    let id = KeyId::Ssh(key(A));
    let verdict = bench
        .desk
        .ask_world(|world| world.decide(connection, &name("ssh-agent"), operation, Some(&id), now));
    let request = RequestId(bench.desk.trail.push(Happened::Asked {
        connection,
        capability: name("ssh-agent"),
        operation,
        key: Some(id),
    }));
    bench
        .desk
        .trail
        .push(Happened::Payload { request, payload });
    assert!(matches!(verdict, Verdict::Hold(_)), "{verdict:?}");
    bench.desk.trail.push(Happened::Held { request });
    refresh(bench);
    request
}

fn card(bench: &Bench) -> Card {
    let attached = bench.seen();
    let attention = attached.attention.as_deref().unwrap();
    let mut deck = Deck::default();
    deck.settle(attention, 0);
    deck.card(
        attention,
        Why {
            rows: bench.rows(),
            keyrings: attached.keyrings(),
            ..Why::default()
        },
    )
    .unwrap()
}

/// A person reads at the card whether the remote asks to log in - as whom, and to
/// the host whose key it names - or to sign, and what: the held request
/// carries its payload. The key is named as their agent named it when they
/// lent it, with nothing asked of the agent.
#[test]
fn a_login_is_told_from_a_signature_at_the_card() {
    let (mut bench, connection) = holding();
    ask(
        &mut bench,
        connection,
        Operation::Authenticate,
        Payload::Authentication {
            user: Some(Words::try_from("hedwig-e1").unwrap()),
            host: Some(key(HOST)),
        },
    );
    let shown = card(&bench);
    assert_eq!(
        shown.heading,
        "dev/build (coder) asks to log in with ssh-agent"
    );
    let fact = |shown: &Card, named: &str| {
        shown
            .facts
            .iter()
            .find(|(label, _)| *label == named)
            .map(|(_, said)| said.clone())
    };
    assert_eq!(fact(&shown, "Key"), Some(format!("{A_SAID} (laptop)")));
    assert_eq!(asked_for_keys(&bench), 0, "the agent is asked nothing");
    assert_eq!(
        fact(&shown, "For"),
        Some(format!(
            "a login as hedwig-e1 to the host whose key is {HOST_SAID}"
        ))
    );
    let sought = |bench: &Bench| {
        bench
            .sent
            .iter()
            .filter(|frame| matches!(frame.request, Request::Activity { .. }))
            .count()
    };
    let once = sought(&bench);
    refresh(&mut bench);
    assert_eq!(sought(&bench), once, "each held request is looked for once");

    ask(
        &mut bench,
        connection,
        Operation::Sign,
        Payload::Signature {
            namespace: Some(Words::try_from("git").unwrap()),
        },
    );
    let attached = bench.seen();
    let item = attached
        .attention
        .as_deref()
        .unwrap()
        .iter()
        .map(|needs| &needs.attention)
        .find(|item| {
            matches!(
                item,
                hedwig_model::protocol::Attention::Request {
                    operation: Operation::Sign,
                    ..
                }
            )
        })
        .unwrap();
    let signing = Card::of(
        item,
        Why {
            rows: bench.rows(),
            keyrings: attached.keyrings(),
            ..Why::default()
        },
        0,
    )
    .unwrap();
    assert_eq!(
        signing.heading,
        "dev/build (coder) asks to sign with ssh-agent"
    );
    assert_eq!(
        fact(&signing, "For").as_deref(),
        Some("a signature in git's namespace, as git makes for a commit or a tag")
    );
}

/// A person reads in the remote's activity each login and each signature with
/// the key that made it and what it was for.
#[test]
fn the_activity_says_each_login_and_signature_with_its_key() {
    let (mut bench, connection) = holding();
    ask(
        &mut bench,
        connection,
        Operation::Authenticate,
        Payload::Authentication {
            user: Some(Words::try_from("hedwig-e1").unwrap()),
            host: None,
        },
    );
    bench.feed(Event::Review(Some(workspace())));
    let attached = bench.seen();
    let entries = attached
        .activity
        .as_ref()
        .unwrap()
        .entries
        .as_ref()
        .unwrap();
    let here = workspace();
    let keyrings = attached.keyrings().of_remote(&here);
    let said: Vec<String> = exposure::activity(entries, &clock, keyrings)
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert!(
        said.iter().any(|said| said.ends_with(&format!(
            "asked to log in with ssh-agent, {A_SAID} (laptop), for a login as hedwig-e1 to a \
             host it does not name - waiting for your answer"
        ))),
        "{said:#?}"
    );
    // Its payload alone, where the request is on an earlier page.
    let late: Vec<_> = entries
        .iter()
        .filter(|entry| matches!(entry.event, Happened::Payload { .. }))
        .cloned()
        .collect();
    let said = exposure::activity(&late, &clock, attached.keyrings());
    assert!(said[0].1.ends_with(
        "a request asked earlier was for a login as hedwig-e1 to a host it does not name"
    ));
}

/// The words of a payload, of where a key may be used and of an operation.
#[test]
fn what_a_request_asks_to_have_signed_is_said_in_full() {
    assert_eq!(words::operation(Operation::Authenticate), "log in with");
    assert_eq!(words::verb(Operation::Authenticate), "log in");
    assert_eq!(words::did(Operation::Authenticate), "logged in with");
    for (payload, said) in [
        (
            Payload::Signature {
                namespace: Some(Words::try_from("file").unwrap()),
            },
            "a signature in the namespace file",
        ),
        (
            Payload::Signature { namespace: None },
            "a signature in a namespace that is not words",
        ),
        (
            Payload::Authentication {
                user: None,
                host: None,
            },
            "a login as a user that is not words to a host it does not name",
        ),
        (
            Payload::Unread,
            "data that is neither a login nor a signature OpenSSH makes",
        ),
    ] {
        assert_eq!(words::payload(&payload), said);
    }
    assert_eq!(
        words::toward(&Toward::Hosts([key(HOST), key(A)].into())),
        format!(
            "only for logging in to the hosts whose keys are {HOST_SAID}, {}, and for nothing \
             else",
            "ED25519 SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE"
        )
    );
    // A certificate is said to be one.
    let certificate = key(
        "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIGFG7LAAlpPLspreFN4e9neBiJcDg4KhJt2Yh4CAX14eAAAAIItLZoUun7m4kwftUgE3qXUy3IrZuqIlD7BcOv+KMz1XAAAAAAAAAAAAAAABAAAACmlkLWVkMjU1MTkAAAALAAAAB3NvbWVvbmUAAAAAAAAAAP//////////AAAAAAAAAIIAAAAVcGVybWl0LVgxMS1mb3J3YXJkaW5nAAAAAAAAABdwZXJtaXQtYWdlbnQtZm9yd2FyZGluZwAAAAAAAAAWcGVybWl0LXBvcnQtZm9yd2FyZGluZwAAAAAAAAAKcGVybWl0LXB0eQAAAAAAAAAOcGVybWl0LXVzZXItcmMAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAg5eRbSjkGoGFm7LVeJLj6YysK6Umitp2eyBkUoiVTor8AAABTAAAAC3NzaC1lZDI1NTE5AAAAQHKGqM7+7CenTJOI1HH+GlqiQI5FwRvtImXt9s6Dv8TTQC6oXtGMMszDrK8UsBp54VehGBZv5Qjn6n3khp7ySgE=",
    );
    assert_eq!(
        words::ssh_key(&certificate, words::Keyrings::default()),
        "ED25519 certificate SHA256:vey71A1LmxIAaLPYhQZyjT4sAvzulhaLQh9DQrRaoyg"
    );
}

/// The person defines an agent of their own where it is: the pipe Windows'
/// SSH clients use, gpg-agent's socket for a home, or another agent's own
/// pipe; each is read back into the form as it was made.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "each place an agent can be, defined and read back"
)]
fn an_agent_is_defined_where_it_is() {
    let mut bench = Bench::viewer();
    bench.attach();
    bench.feed(Event::Window(true));
    let attached = bench.seen();
    let (vocabulary, document) = (
        attached.catalogue.as_ref().unwrap(),
        attached.document.clone().unwrap(),
    );
    let mut draft = define::Draft::new(Kind::Capability);
    let reference = vocabulary.reference();
    draft.edit(
        Edit::Typed {
            key: "name".to_owned(),
            text: "pageant-agent".to_owned(),
        },
        reference,
        &document,
    );
    draft.edit(
        Edit::Chose {
            key: "source".to_owned(),
            at: 1,
        },
        reference,
        &document,
    );
    let shown = define::Form::of(&draft, vocabulary, &document, None, None);
    let invalid: Vec<_> = shown
        .fields
        .iter()
        .filter_map(|field| field.invalid.clone())
        .collect();
    assert!(invalid.is_empty(), "{invalid:?}");
    let labels: Vec<&str> = shown.fields.iter().map(|field| field.label).collect();
    assert_eq!(labels, ["Name", "What it is", "Where your agent is"]);
    // The well-known pipe is the first choice.
    let Ok(Shown::Offered { act, .. }) = &shown.ready else {
        unreachable!("{:?}", shown.ready)
    };
    let Act::Send(Request::Change(Change::Define(made))) = act else {
        unreachable!("{act:?}")
    };
    assert_eq!(
        made.source,
        Source::Agent {
            at: AgentAt::Pipe(AgentPipe::well_known())
        }
    );
    draft.edit(
        Edit::Chose {
            key: "agent".to_owned(),
            at: 2,
        },
        reference,
        &document,
    );
    let shown = define::Form::of(&draft, vocabulary, &document, None, None);
    assert_eq!(
        shown
            .fields
            .last()
            .and_then(|field| field.invalid.as_deref()),
        Some("Nothing is filled in.")
    );
    draft.edit(
        Edit::Typed {
            key: "agent-pipe".to_owned(),
            text: "pageant.arash.0123abcd".to_owned(),
        },
        reference,
        &document,
    );
    let shown = define::Form::of(&draft, vocabulary, &document, None, None);
    let Ok(Shown::Offered {
        act: Act::Send(Request::Change(change)),
        ..
    }) = &shown.ready
    else {
        unreachable!("{:?}", shown.ready)
    };
    bench.feed(Event::Wish(
        Place::Defining,
        common::clone(&Request::Change(change.clone())),
    ));
    assert_eq!(bench.seen().refused, None);
    let document = bench.seen().document.clone().unwrap();
    let mine =
        define::Draft::changing(Kind::Capability, &name("pageant-agent"), &document).unwrap();
    let shown = define::Form::of(
        &mine,
        bench.seen().catalogue.as_ref().unwrap(),
        &document,
        None,
        None,
    );
    assert_eq!(
        shown
            .fields
            .iter()
            .map(|field| field.label)
            .collect::<Vec<_>>(),
        ["What it is", "Where your agent is", "Its pipe"]
    );
    let definitions = define::Definitions::of(
        &bench.seen().catalogue.as_ref().unwrap().definitions,
        bench.seen().catalogue.as_ref().unwrap().reference(),
        &document,
        None,
    );
    assert_eq!(
        definitions.own[0].says,
        "your SSH agent at the pipe pageant.arash.0123abcd"
    );

    // gpg-agent's socket for a home of its own.
    let mut socket = define::Draft::new(Kind::Capability);
    let catalogue = bench.seen().catalogue.as_ref().unwrap();
    for (key, at) in [("source", 1), ("agent", 1)] {
        socket.edit(
            Edit::Chose {
                key: key.to_owned(),
                at,
            },
            catalogue.reference(),
            &document,
        );
    }
    for (key, text) in [("name", "work-ssh"), ("home", r"C:\keys\work")] {
        socket.edit(
            Edit::Typed {
                key: key.to_owned(),
                text: text.to_owned(),
            },
            catalogue.reference(),
            &document,
        );
    }
    let shown = define::Form::of(&socket, catalogue, &document, None, None);
    assert_eq!(
        shown
            .fields
            .iter()
            .map(|field| field.label)
            .collect::<Vec<_>>(),
        [
            "Name",
            "What it is",
            "Where your agent is",
            "GnuPG's folder",
            "GnuPG home"
        ]
    );
    assert!(shown.ready.is_ok(), "{:?}", shown.ready);
}

/// What answers for the agent is said where it is granted - on its line, in
/// the model's sentence for the holder, and on the grant form - as the core
/// last read it, and read again when the core says the workstation changed,
/// without asking the agent anything.
#[test]
fn what_answers_for_an_agent_is_said_where_it_is_granted() {
    let mut bench = lending(Lends::none());
    // The core's survey records each source's health before any reach.
    bench.desk.trail.push(Happened::Source {
        capability: name("ssh-agent"),
        health: Health::Sound,
    });
    refresh(&mut bench);
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("ssh-agent"),
        holder: Some(SourceHolder {
            program: Location::try_from(
                r"C:\Users\person\AppData\Local\1Password\app\8\1Password.exe",
            )
            .unwrap(),
            session: 2,
            whose: Whose::Person {
                logon: 0x4ef_6b65,
                signed_in: SignedIn::Locally,
                rights: Rights::Standard,
            },
        }),
    });
    bench.told();
    let program = r"C:\Users\person\AppData\Local\1Password\app\8\1Password.exe";
    assert_eq!(
        agent(&window(&bench)).answers,
        [format!(
            "ssh-agent answers on this workstation: {program}, yours, in session 2."
        )]
    );
    let attached = bench.seen();
    let capability = grant::capability(
        attached.catalogue.as_ref().unwrap().reference(),
        attached.document.as_ref().unwrap(),
        &name("ssh-agent"),
    )
    .unwrap();
    assert_eq!(
        grant::answering(&capability, attached.workstation.as_ref()),
        Some(format!(
            "ssh-agent is answered by {program}, yours, in session 2"
        ))
    );
    bench.desk.trail.push(Happened::HeldBy {
        capability: name("ssh-agent"),
        holder: None,
    });
    bench.desk.trail.push(Happened::Source {
        capability: name("ssh-agent"),
        health: Health::Failing(Failure::Unreachable),
    });
    refresh(&mut bench);
    assert_eq!(
        agent(&window(&bench)).answers,
        ["Nothing answers for ssh-agent on this workstation."]
    );
    let attached = bench.seen();
    assert_eq!(
        grant::answering(&capability, attached.workstation.as_ref()),
        None
    );
    assert_eq!(asked_for_keys(&bench), 0);
}

/// A person gives the key they sign releases with a rule of its own before a remote
/// first uses it: each key a statement can name that none does is offered
/// under each operation that names a key, with each rule that would decide it
/// otherwise; made, the key has an entry of its own and is offered no more.
#[test]
fn a_key_no_statement_names_yet_is_given_a_rule_of_its_own() {
    let mut bench = lending(lent_a(Toward::Anywhere));
    let shown = window(&bench);
    let line = agent(&shown);
    let signing = line
        .policy
        .iter()
        .find(|policy| policy.when == "when it asks to sign")
        .unwrap();
    assert_eq!(
        signing
            .keys
            .iter()
            .map(|rule| rule.key.as_str())
            .collect::<Vec<_>>(),
        [format!("{A_SAID} (laptop)")]
    );
    let labels: Vec<&str> = signing.keys[0].changes.iter().map(label).collect();
    assert!(
        labels.contains(&"Ask me first, always for this key here"),
        "{labels:?}"
    );
    let connecting = line
        .policy
        .iter()
        .find(|policy| policy.when == "when it asks to connect")
        .unwrap();
    assert!(connecting.keys.is_empty(), "a connection names no key");
    let ask = signing.keys[0]
        .changes
        .iter()
        .find(|shown| label(shown) == "Ask me first, always for this key here")
        .unwrap();
    assert!(
        matches!(act(ask), Act::Send(_)),
        "stricter is carried out at once"
    );
    bench.feed(Event::Wish(
        Place::Line {
            remote: Some(workspace()),
            capability: name("ssh-agent"),
        },
        request(ask),
    ));
    assert_eq!(bench.seen().refused, None);
    let shown = window(&bench);
    let line = agent(&shown);
    let keyed = line
        .policy
        .iter()
        .find(|policy| policy.when == format!("when it asks to sign with {A_SAID} (laptop)"))
        .expect("the key's own entry");
    assert_eq!(keyed.now, words::mode(Mode::Confirm));
    let signing = line
        .policy
        .iter()
        .find(|policy| policy.when == "when it asks to sign")
        .unwrap();
    assert!(signing.keys.is_empty(), "{:?}", signing.keys);
}

/// The same for a `GnuPG` source: every key its keyrings offer, a primary
/// naming its subkeys with it, and a key a card holds that no keyring offers.
#[test]
fn a_gnupg_key_no_statement_names_yet_is_offered_its_own_rule() {
    use hedwig_model::text::{Fingerprint, Grip, Serial};
    use hedwig_model::trail::{Card, Held, Key, Keyring, Touch, Uses};

    let mut bench = Bench::viewer();
    bench.attach();
    bench.feed(Event::Window(true));
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("gpg", Granted::One(workspace())),
            terms: terms(Activation::OnRequest, Exposure::KEY_USE),
        }),
    ));
    let grip = |text: &str| Grip::try_from(text).unwrap();
    let primary = Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap();
    let subkey = Fingerprint::try_from("5A6B7C8D9E0F1A20E5D4B6E1A2C3F40516273849").unwrap();
    let key = |grip_text: &str, fingerprint: &Fingerprint| Key {
        ssh: None,
        grip: grip(grip_text),
        fingerprint: fingerprint.clone(),
        primary: primary.clone(),
        uses: Uses::SIGN,
        user: Some(Words::try_from("Release <release@example.org>").unwrap()),
        card: None,
    };
    bench.desk.trail.push(Happened::Offered {
        capability: name("gpg"),
        keyring: Keyring {
            keys: vec![
                key("AA11BB22CC33DD44EE55FF6600771188992233AA", &primary),
                key("BB22CC33DD44EE55FF6600771188992233AA11BB", &subkey),
            ],
            signing: None,
        },
    });
    bench.desk.trail.push(Happened::Card(Card {
        serial: Serial::try_from("D2760001240103040006123456780000").unwrap(),
        keys: vec![Held {
            grip: grip("CC33DD44EE55FF6600771188992233AA11BB22CC"),
            touch: Some(Touch::On),
        }],
        pin: None,
    }));
    refresh(&mut bench);
    let shown = window(&bench);
    let Board::Exposure { groups, .. } = &shown.board else {
        unreachable!()
    };
    let line = groups
        .iter()
        .flat_map(|group| &group.lines)
        .find(|line| line.capability.as_str() == "gpg")
        .unwrap();
    let signing = line
        .policy
        .iter()
        .find(|policy| policy.when == "when it asks to sign with")
        .or_else(|| {
            line.policy
                .iter()
                .find(|policy| policy.when == "when it asks to sign")
        })
        .unwrap();
    assert_eq!(
        signing
            .keys
            .iter()
            .map(|rule| rule.key.as_str())
            .collect::<Vec<_>>(),
        [
            "key 0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 (Release <release@example.org>) and \
             its subkeys",
            "subkey 5A6B7C8D9E0F1A20E5D4B6E1A2C3F40516273849 (Release <release@example.org>)",
            "the key with keygrip CC33DD44EE55FF6600771188992233AA11BB22CC, which is not among \
             the keys this workstation's GnuPG offers",
        ]
    );
    for rule in &signing.keys {
        for shown in &rule.changes {
            assert_eq!(bench.permits(&request(shown)), Ok(()), "{}", label(shown));
        }
    }
}

/// The card's usual answer to a held signature, sent from the card's place,
/// settles the request.
#[test]
fn a_held_signature_is_settled_by_the_cards_usual_answer() {
    let (mut bench, connection) = holding();
    let request = ask(
        &mut bench,
        connection,
        Operation::Sign,
        Payload::Signature {
            namespace: Some(Words::try_from("git").unwrap()),
        },
    );
    let shown = card(&bench);
    let first = shown.choices.first().expect("the usual answer");
    let hedwig_view::card::Does::Send(answer) = &first.does else {
        unreachable!("{:?}", first.does)
    };
    assert!(
        matches!(answer, Request::Decide { request: asked, .. } if *asked == request),
        "{answer:?}"
    );
    bench.feed(Event::Wish(Place::Card, common::clone(answer)));
    assert_eq!(bench.seen().refused, None);
    refresh(&mut bench);
    let waiting = bench
        .seen()
        .attention
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|needs| hedwig_view::card::Subject::of(&needs.attention).is_some())
        .count();
    assert_eq!(waiting, 0, "the request still waits");
}

/// Keys the core says changed are read again where they were read, and
/// nowhere else: the core knows of a change only to keys it makes or deletes
/// itself, and asking an agent for its list can make a password manager ask
/// the person.
#[test]
fn keys_the_core_says_changed_are_read_again_where_they_were_read() {
    let mut bench = Bench::viewer();
    bench.attach();
    bench.desk.held.keys.insert(name("ssh-agent"), Ok(held()));
    bench.feed(Event::Window(true));
    let asked = |bench: &Bench| {
        bench
            .sent
            .iter()
            .filter(|frame| matches!(frame.request, Request::Keys(_)))
            .count()
    };
    bench.notice(Notice::Stale(Topic::Keys(name("ssh-agent"))));
    assert_eq!(asked(&bench), 0, "keys never read are not read on a notice");
    bench.feed(Event::Keys(name("ssh-agent")));
    assert_eq!(asked(&bench), 1);
    bench.notice(Notice::Stale(Topic::Keys(name("ssh-agent"))));
    assert_eq!(asked(&bench), 2, "read again where they were read");
    bench.notice(Notice::Stale(Topic::Keys(name("gpg-ssh"))));
    assert_eq!(asked(&bench), 2, "another agent's are not");
}

/// A person acts from a remote's activity as from the line: a login served with a
/// key the grant lends anywhere offers lending it only for logging in to that
/// login's host, carried out at once as narrowing is on the line,
/// keeping its comment; a key turned away because the grant does not lend it
/// offers lending it; an entry no act is due on offers nothing.
#[test]
fn an_entry_of_the_activity_offers_what_the_line_offers_for_it() {
    let (mut bench, connection) = holding();
    let request = ask(
        &mut bench,
        connection,
        Operation::Authenticate,
        Payload::Authentication {
            user: Some(Words::try_from("hedwig-e1").unwrap()),
            host: Some(key(HOST)),
        },
    );
    bench.feed(Event::Wish(
        Place::Card,
        Request::Decide {
            request,
            decision: hedwig_model::protocol::Decision::Once,
        },
    ));
    assert_eq!(bench.seen().refused, None);
    bench.desk.trail.push(Happened::TurnedAway {
        remote: Some(workspace()),
        refusal: Refusal::Withheld {
            capability: name("ssh-agent"),
            request: Withheld::KeyUnlent(key(SK)),
        },
    });
    refresh(&mut bench);
    // The window reads the configuration a grant's acts are judged by.
    bench.feed(Event::Window(true));
    bench.feed(Event::Review(Some(workspace())));
    let attached = bench.seen();
    let entries = attached
        .activity
        .as_ref()
        .unwrap()
        .entries
        .as_ref()
        .unwrap();
    let acts = exposure::entry_acts(entries, &workspace(), attached);
    let said = exposure::activity(entries, &clock, attached.keyrings());
    let offered: Vec<(&str, Vec<&str>)> = said
        .iter()
        .filter_map(|(seq, text)| {
            let (capability, shown) = acts.get(seq)?;
            assert_eq!(*capability, name("ssh-agent"));
            Some((text.as_str(), shown.iter().map(label).collect()))
        })
        .collect();
    assert_eq!(offered.len(), 2, "{said:#?}");
    let (turned, lend) = &offered[0];
    assert!(turned.contains("which the grant does not lend"), "{turned}");
    assert!(lend.len() == 1 && lend[0].starts_with("Lend "), "{lend:?}");
    let (login, narrow) = &offered[1];
    assert!(
        login.contains(&format!("to the host whose key is {HOST_SAID}")),
        "{login}"
    );
    assert_eq!(narrow, &["Lend it only for logging in to this host"]);

    let (_, shown) = acts
        .values()
        .find(|(_, shown)| label(&shown[0]).starts_with("Lend it only"))
        .unwrap();
    let Act::Send(Request::Change(change)) = act(&shown[0]) else {
        unreachable!("narrowing is carried out at once: {:?}", act(&shown[0]))
    };
    assert_eq!(*change, granting(lent_a(Toward::Hosts([key(HOST)].into()))));
}

fn named(keyrings: words::Keyrings<'_>) -> String {
    words::ssh_key(&key(A), keyrings)
}

/// One key lent to two remotes, each grant keeping the comment the agent gave
/// it when that grant lent it: each remote's card, line and activity name the
/// key as that remote's own `ssh-add -l` printed it; where no grant names it
/// for the remote in hand, the agent's own list as last read, then any
/// grant's.
#[test]
fn a_lent_key_is_named_as_the_grant_it_is_named_for_keeps_it() {
    let other = remote("coder", "dev/other");
    let mut bench = lending(lent_a(Toward::Anywhere));
    let renamed = Lends::of_keys([(
        key(A),
        LentKey {
            toward: Toward::Anywhere,
            comment: Some(comment("old laptop")),
        },
    )]);
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("ssh-agent", Granted::One(other.clone())),
            terms: Terms {
                lends: renamed,
                ..terms(Activation::OnRequest, Exposure::KEY_USE)
            },
        }),
    ));
    assert_eq!(bench.seen().refused, None);
    bench.desk.channel_up(&workspace(), "linux");
    bench.desk.channel_up(&other, "linux");
    refresh(&mut bench);
    let (here, agent) = (workspace(), name("ssh-agent"));
    let attached = bench.seen();
    assert_eq!(
        named(attached.keyrings().of_capability(&here, &agent)),
        format!("{A_SAID} (laptop)")
    );
    assert_eq!(
        named(attached.keyrings().of_remote(&other)),
        format!("{A_SAID} (old laptop)")
    );
    // Named for no grant: any grant's, the rows' first.
    assert!(
        [
            format!("{A_SAID} (laptop)"),
            format!("{A_SAID} (old laptop)")
        ]
        .contains(&named(attached.keyrings())),
        "{}",
        named(attached.keyrings())
    );
    // The agent asked by the person: its list for what no grant names here.
    bench.feed(Event::Keys(name("ssh-agent")));
    let attached = bench.seen();
    assert_eq!(named(attached.keyrings()), format!("{A_SAID} (laptop)"));
    assert_eq!(
        named(attached.keyrings().of_remote(&other)),
        format!("{A_SAID} (old laptop)")
    );
    let shown = window(&bench);
    let Board::Exposure { groups, .. } = &shown.board else {
        unreachable!()
    };
    let labels: Vec<&str> = groups
        .iter()
        .flat_map(|group| &group.lines)
        .filter(|line| line.capability.as_str() == "ssh-agent")
        .filter_map(|line| line.keys.as_ref())
        .flat_map(|keys| &keys.keys)
        .filter(|line| line.key == key(A))
        .map(|line| line.label.as_str())
        .collect();
    let mut labels = labels;
    labels.sort_unstable();
    assert_eq!(
        labels,
        [
            format!("{A_SAID} (laptop)").as_str(),
            format!("{A_SAID} (old laptop)").as_str()
        ]
    );
}
