//! A remote's sign-in in the workstation's browser, at the surfaces: the
//! capability whose source is the person's browser defined in the window with
//! its sites - Hedwig ships none - a page refused for want of a site offered
//! as the site to add, and what the browser opened read in the remote's
//! activity.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::{Browser, Capability, Exposure, Operation, Source};
use hedwig_model::config::{Activation, Change, Document, Reference, Terms};
use hedwig_model::organisation::{Part, Start};
use hedwig_model::protocol::{Notice, Request, Topic};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::site::Site;
use hedwig_model::text::{Port, Program, Verbatim};
use hedwig_model::trail::{
    Carry, Entry, Event as Happened, Failure, Health, RequestId, Seq, Tick, Timestamp,
};
use hedwig_view::act::Act;
use hedwig_view::define::{Definitions, Draft, Edit, Field, Form, Input, Kind};
use hedwig_view::exposure::{self, Board, Line, Shown, Window};
use hedwig_view::grant;
use hedwig_view::link::{Event, Place};
use hedwig_view::words::Keyrings;

mod common;
use common::support::{grant, name, remote, terms};
use common::{Bench, clock};

fn workspace() -> RemoteId {
    remote("coder", "dev/build")
}

fn signin() -> Site {
    "https://signin.example.org".parse().unwrap()
}

fn portal() -> Site {
    "https://*.portal.example.org".parse().unwrap()
}

fn bench() -> Bench {
    let mut bench = Bench::attached();
    bench.feed(Event::Window(true));
    bench
}

fn known(bench: &Bench) -> (Reference, Document) {
    let attached = bench.seen();
    (
        attached
            .catalogue
            .as_ref()
            .expect("the catalogue")
            .reference()
            .clone(),
        attached.document.clone().expect("the document"),
    )
}

fn edit(draft: &mut Draft, bench: &Bench, edit: Edit) {
    let (reference, document) = known(bench);
    draft.edit(edit, &reference, &document);
}

fn typed(key: &str, text: &str) -> Edit {
    Edit::Typed {
        key: key.to_owned(),
        text: text.to_owned(),
    }
}

fn chose(key: &str, at: usize) -> Edit {
    Edit::Chose {
        key: key.to_owned(),
        at,
    }
}

fn form(draft: &Draft, bench: &Bench) -> Form {
    let document = known(bench).1;
    let vocabulary = bench.seen().catalogue.as_ref().expect("the catalogue");
    Form::of(draft, vocabulary, &document, None, None)
}

/// What a field holds as the form shows it: text as typed, a choice by its
/// place, a pick by its value.
fn held(fields: &[Field], key: &str) -> String {
    match &fields.iter().find(|field| field.key == key).unwrap().input {
        Input::Text { typed, .. } => typed.clone(),
        Input::Choice { chosen, .. } => chosen.to_string(),
        Input::Pick { options, chosen } => chosen
            .and_then(|at| options.get(at))
            .map(|option| option.value.clone())
            .unwrap_or_default(),
    }
}

/// The person's own capability named `capability`, opening their default
/// browser at `sites`.
fn define_browser(bench: &mut Bench, capability: &str, sites: Vec<Site>) {
    wish(
        bench,
        &Request::Change(Change::Define(Capability {
            id: name(capability),
            source: Source::Browser {
                browser: Browser::Default,
                sites,
            },
        })),
    );
}

fn wish(bench: &mut Bench, request: &Request) {
    assert_eq!(bench.permits(request), Ok(()));
    bench.feed(Event::Wish(Place::Window, common::clone(request)));
    assert_eq!(bench.seen().refused, None);
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

fn window(bench: &Bench) -> Window {
    Window::of(bench.link.seen(), &clock, std::time::Instant::now())
}

fn line<'w>(window: &'w Window, capability: &str) -> &'w Line {
    match &window.board {
        Board::Exposure { groups, .. } => groups
            .iter()
            .flat_map(|group| &group.lines)
            .find(|line| line.remote == Some(workspace()) && line.capability.as_str() == capability)
            .unwrap_or_else(|| unreachable!("{capability}'s line on the workspace")),
        other => unreachable!("{other:?}"),
    }
}

/// A grant of `capability` to the workspace, the browser's exposure named,
/// its channel up, and the remote refused a page at `site` through it.
fn refused(bench: &mut Bench, capability: &str, site: Site) {
    wish(
        bench,
        &Request::Change(Change::Grant {
            grant: grant(capability, Granted::One(workspace())),
            terms: Terms {
                ..terms(Activation::OnRequest, Exposure::BROWSER)
            },
        }),
    );
    bench.desk.channel_up(&workspace(), "linux");
    bench.desk.trail.push(Happened::TurnedAway {
        remote: Some(workspace()),
        refusal: Refusal::UnlistedSite {
            capability: name(capability),
            site,
        },
    });
    refresh(bench);
}

/// The act `label` begins with, among `shown`.
fn offered<'s>(shown: &'s [Shown], label: &str) -> &'s Act {
    shown
        .iter()
        .find_map(|shown| match shown {
            Shown::Offered { label: at, act } if at.starts_with(label) => Some(act),
            _ => None,
        })
        .unwrap_or_else(|| unreachable!("no {label} among {shown:?}"))
}

/// A site is typed as the model writes it - a host, `*.` for it and every
/// name beneath it, a port only where it is not the scheme's own, `localhost`
/// for the remote's own loopback - and the form takes each such line; one
/// that is not a site is said beneath the field in the model's own words,
/// each reason apart.
#[test]
fn a_site_is_typed_as_the_model_writes_it_and_refused_in_its_words() {
    let bench = bench();
    let sites = |text: &str| {
        let mut draft = Draft::new(Kind::Capability);
        edit(&mut draft, &bench, chose("source", 3));
        edit(&mut draft, &bench, typed("sites", text));
        form(&draft, &bench)
            .fields
            .into_iter()
            .find(|field| field.key == "sites")
            .unwrap()
            .invalid
    };
    let written = [
        "https://signin.example.org",
        "https://*.portal.example.org",
        "https://signin.example.org:8443",
        "http://localhost",
        "http://localhost:8400",
        "https://[2001:db8::1]",
        "http://intranet.example:8080",
    ];
    for text in written {
        assert_eq!(sites(text), None, "{text}");
    }
    assert_eq!(
        sites(&written.join("\r")),
        None,
        "a line to each, as WinUI breaks them"
    );
    for (text, why) in [
        (
            "ftp://files.example.org",
            "it is not an https or http address",
        ),
        (
            "https://signin.example.org/oauth",
            "a site is a scheme and a host, with no path",
        ),
        (
            "https://*.localhost",
            "the remote's own loopback is written localhost, with no `*.`",
        ),
    ] {
        assert_eq!(
            sites(text),
            Some(format!("\"{text}\" is not a site: {why}.")),
            "{text}"
        );
    }
    for text in ["https://name@signin.example.org", "signin.example.org"] {
        assert!(sites(text).is_some(), "{text}");
    }
}

/// A person defines a capability that opens a remote's sign-in in the browser
/// profile they keep for its services: the program, its arguments and the
/// sites, each checked as typed. The core takes it, the window lists it with
/// what it opens, and changing it fills the form with what was made.
#[test]
fn a_browser_capability_is_defined_with_its_sites_and_changed_as_made() {
    let mut bench = bench();
    let mut draft = Draft::new(Kind::Capability);
    edit(&mut draft, &bench, chose("source", 3));
    edit(&mut draft, &bench, typed("name", "work-sign-in"));
    edit(&mut draft, &bench, chose("browser", 1));
    edit(&mut draft, &bench, typed("browser-program", "msedge"));
    edit(
        &mut draft,
        &bench,
        typed("browser-arguments", "--profile-directory=Work"),
    );
    edit(
        &mut draft,
        &bench,
        typed("sites", "https://signin.example.org\nftp://x"),
    );
    let shown = form(&draft, &bench);
    let keys: Vec<&str> = shown.fields.iter().map(|field| field.key).collect();
    assert_eq!(
        keys,
        [
            "name",
            "source",
            "browser",
            "browser-program",
            "browser-arguments",
            "sites"
        ]
    );
    let sites = shown
        .fields
        .iter()
        .find(|field| field.key == "sites")
        .unwrap();
    assert_eq!(
        sites.invalid.as_deref(),
        Some("\"ftp://x\" is not a site: it is not an https or http address.")
    );
    assert!(shown.ready.is_err());

    edit(
        &mut draft,
        &bench,
        typed(
            "sites",
            // As WinUI's TextBox hands it over: a line broken by \r alone.
            "https://signin.example.org\rhttps://*.portal.example.org",
        ),
    );
    let defined = Capability {
        id: name("work-sign-in"),
        source: Source::Browser {
            browser: Browser::Program {
                program: Program::try_from("msedge").unwrap(),
                arguments: vec![Verbatim::try_from("--profile-directory=Work").unwrap()],
            },
            sites: vec![signin(), portal()],
        },
    };
    let request = match form(&draft, &bench).ready {
        Ok(Shown::Offered {
            act: Act::Send(request) | Act::Confirm { request, .. },
            ..
        }) => request,
        other => unreachable!("{other:?}"),
    };
    assert_eq!(request, Request::Change(Change::Define(defined.clone())));
    wish(&mut bench, &request);

    let (reference, document) = known(&bench);
    let outside = &bench.seen().catalogue.as_ref().unwrap().definitions;
    let listed = Definitions::of(outside, &reference, &document, None);
    let own = listed
        .own
        .iter()
        .find(|own| own.name == name("work-sign-in"))
        .unwrap();
    assert_eq!(
        own.says,
        "msedge, opening https://signin.example.org, https://*.portal.example.org"
    );

    // Changed, the form holds what was made, and makes it again unchanged.
    let changing = Draft::changing(Kind::Capability, &name("work-sign-in"), &document).unwrap();
    let fields = form(&changing, &bench).fields;
    assert_eq!(held(&fields, "source"), "3");
    assert_eq!(held(&fields, "browser"), "1");
    assert_eq!(held(&fields, "browser-program"), "msedge");
    assert_eq!(
        held(&fields, "browser-arguments"),
        "--profile-directory=Work"
    );
    assert_eq!(
        held(&fields, "sites"),
        "https://signin.example.org\nhttps://*.portal.example.org"
    );
    assert!(matches!(
        form(&changing, &bench).ready,
        Ok(Shown::Offered { act: Act::Send(Request::Change(Change::Define(ref again))) | Act::Confirm { request: Request::Change(Change::Define(ref again)), .. }, .. }) if *again == defined
    ));
}

/// The first sign-in through a capability of the person's own is refused,
/// naming the narrowest site that would admit it; the line and what needs the
/// person offer to open that site from now on, asked first since it lets more
/// through, and once it is opened the offer is gone.
#[test]
fn a_refused_site_is_offered_to_add_to_the_persons_own_capability() {
    let mut bench = bench();
    define_browser(&mut bench, "work-sign-in", vec![portal()]);
    refused(&mut bench, "work-sign-in", signin());
    let shown = window(&bench);
    let line = line(&shown, "work-sign-in");
    assert_eq!(
        line.turned,
        [
            "the remote asked to open https://signin.example.org, which is not among the sites \
          work-sign-in opens, once"
        ]
    );
    let Act::Confirm {
        request,
        consequence,
        answer,
    } = offered(&line.acts, "Open https://signin.example.org from now on")
    else {
        unreachable!("opening a site lets more through")
    };
    assert_eq!(answer, "Open it from now on");
    assert_eq!(
        consequence,
        "A remote work-sign-in is granted to can then have your browser open \
         https://signin.example.org, where your signed-in sessions are, whenever it asks."
    );
    let added = Request::Change(Change::Define(Capability {
        id: name("work-sign-in"),
        source: Source::Browser {
            browser: Browser::Default,
            sites: vec![portal(), signin()],
        },
    }));
    assert_eq!(*request, added);
    let Board::Exposure { needs, .. } = &shown.board else {
        unreachable!()
    };
    let need = needs
        .iter()
        .find(|need| {
            need.sentence
                .contains("not among the sites work-sign-in opens")
        })
        .unwrap();
    assert_eq!(
        offered(&need.acts, "Open https://signin.example.org from now on"),
        &Act::Confirm {
            request: common::clone(&added),
            consequence: consequence.clone(),
            answer: answer.clone(),
        }
    );

    wish(&mut bench, &added);
    refresh(&mut bench);
    let shown = window(&bench);
    assert!(
        !self::line(&shown, "work-sign-in")
            .acts
            .iter()
            .any(|act| matches!(act, Shown::Offered { label, .. } if label.starts_with("Open https://signin"))),
        "a site already opened is offered no more"
    );
}

/// Hedwig ships no capability that opens the person's browser: the grant
/// form, where the person looks for what to grant, offers defining one of
/// their own, its source chosen. Named `browser` - a name nothing ships - it
/// is theirs to grant and to open a refused site with from now on.
#[test]
fn the_grant_form_begins_the_persons_own_browser_which_may_be_named_browser() {
    let mut bench = bench();
    let (reference, document) = known(&bench);
    assert!(
        !reference
            .capabilities
            .iter()
            .any(|known| matches!(known.source, Source::Browser { .. })),
        "nothing shipped opens the person's browser"
    );
    let shown = grant::Form::of(
        &grant::Draft::default(),
        &reference,
        &document,
        None,
        (None, None),
        None,
    );
    let (label, draft) = shown
        .defines
        .iter()
        .find(|(label, _)| label.contains("browser"))
        .unwrap_or_else(|| unreachable!("{:?}", shown.defines));
    assert_eq!(label, "Define your browser, for a remote's sign-in...");
    let fields = form(draft, &bench).fields;
    assert_eq!(held(&fields, "source"), "3");
    assert_eq!(
        held(&fields, "name"),
        "",
        "the name is the person's to give"
    );

    define_browser(&mut bench, "browser", vec![portal()]);
    refused(&mut bench, "browser", signin());
    let shown = window(&bench);
    let Act::Confirm { request, .. } = offered(
        &line(&shown, "browser").acts,
        "Open https://signin.example.org from now on",
    ) else {
        unreachable!("opening a site lets more through")
    };
    assert_eq!(
        *request,
        Request::Change(Change::Define(Capability {
            id: name("browser"),
            source: Source::Browser {
                browser: Browser::Default,
                sites: vec![portal(), signin()],
            },
        }))
    );
    let (reference, document) = known(&bench);
    let shown = grant::Form::of(
        &grant::Draft::default(),
        &reference,
        &document,
        None,
        (None, None),
        None,
    );
    assert!(
        !shown
            .defines
            .iter()
            .any(|(label, _)| label.contains("browser")),
        "once the person has one, the list holds it: {:?}",
        shown.defines
    );
}

/// A browser capability the organisation defines is not the person's to
/// change: the site refused under it begins a capability of their own that
/// opens it too, filled from the organisation's, its name theirs to give.
#[test]
fn a_site_refused_under_the_organisations_browser_begins_one_of_the_persons_own() {
    let mut bench = bench();
    let theirs = Capability {
        id: name("org-sign-in"),
        source: Source::Browser {
            browser: Browser::Default,
            sites: vec![portal()],
        },
    };
    bench.govern(&[(
        Part::Start,
        hedwig_model::wire::line(&Start::Define(theirs)),
    )]);
    refused(&mut bench, "org-sign-in", signin());
    let shown = window(&bench);
    let Act::Define(draft) = offered(
        &line(&shown, "org-sign-in").acts,
        "Define a capability that opens https://signin.example.org...",
    ) else {
        unreachable!("a definition begins")
    };
    assert_eq!(draft.kind, Kind::Capability);
    assert_eq!(draft.changing, None);
    let fields = form(draft, &bench).fields;
    assert_eq!(held(&fields, "source"), "3");
    assert_eq!(held(&fields, "browser"), "0");
    assert_eq!(
        held(&fields, "sites"),
        "https://*.portal.example.org\nhttps://signin.example.org"
    );
    assert_eq!(
        held(&fields, "name"),
        "",
        "the name is the person's to give"
    );
}

/// A person reads what a remote's sign-in did: what it asked, the site the browser
/// was given and the port carried for its answer, and why that ended - never
/// the URL, which the core does not keep.
#[test]
fn a_sign_in_reads_in_the_remotes_activity_by_its_site() {
    // A request is known by the entry that asked it.
    let request = RequestId(Seq(1));
    let at = |seq: u64, event| Entry {
        seq: Seq(seq),
        at: Timestamp(seq),
        tick: Tick(seq),
        event,
    };
    let entries = [
        at(
            1,
            Happened::Asked {
                connection: hedwig_model::trail::ConnectionId(Seq(1)),
                capability: name("browser"),
                operation: Operation::Open,
                key: None,
            },
        ),
        at(
            2,
            Happened::Browsed {
                request,
                site: signin(),
                callback: Some(Port::try_from(41_007).unwrap()),
            },
        ),
        at(
            3,
            Happened::Uncarried {
                request,
                end: Carry::Called,
            },
        ),
    ];
    let said: Vec<String> = exposure::activity(&entries, &clock, Keyrings::default())
        .into_iter()
        .map(|(_, said)| said)
        .collect();
    assert!(
        said.iter()
            .any(|said| said.contains("asked to open a page in browser")),
        "{said:?}"
    );
    assert!(
        said.iter().any(|said| said.contains(
            "your browser opened https://signin.example.org, its answer carried back to port \
             41007 on the remote"
        )),
        "{said:?}"
    );
    assert!(
        said.iter()
            .any(|said| said.contains("the sign-in's answer reached the remote")),
        "{said:?}"
    );
    assert!(!said.iter().any(|said| said.contains("/oauth")));
}

/// A browser that cannot be started stands on its capability's line in the
/// model's sentence, as any failure of the workstation's own side does: a
/// program named that is not there, and Windows' default that opened nothing,
/// two causes with two remedies.
#[test]
fn a_browser_that_cannot_be_started_is_said_on_its_line_by_which_way() {
    for (failure, said) in [
        (
            Failure::Unstartable,
            "cannot be served: browser names a program that is not on this workstation's search \
             path, or that would not start",
        ),
        (
            Failure::Unopened,
            "cannot be served: browser opens addresses with your default browser, and this \
             workstation has none set for web addresses, or the one set would not start",
        ),
    ] {
        let mut bench = bench();
        define_browser(&mut bench, "browser", vec![signin()]);
        wish(
            &mut bench,
            &Request::Change(Change::Grant {
                grant: grant("browser", Granted::One(workspace())),
                terms: terms(Activation::OnRequest, Exposure::BROWSER),
            }),
        );
        bench.desk.channel_up(&workspace(), "linux");
        bench.desk.trail.push(Happened::Source {
            capability: name("browser"),
            health: Health::Failing(failure),
        });
        refresh(&mut bench);
        assert_eq!(line(&window(&bench), "browser").state, said);
    }
}
