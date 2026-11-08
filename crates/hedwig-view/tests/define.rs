//! What the person defines in the window - a capability, a route, a platform,
//! a set of remotes - made, changed and removed through the change the core
//! takes from any client, with what it refuses shown where it was asked.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::Exposure;
use hedwig_model::config::{Activation, Change, Document, Reference};
use hedwig_model::protocol::Request;
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::Granted;
use hedwig_view::act::Act;
use hedwig_view::define::{Defined, Definitions, Draft, Edit, Form, Input, Kind};
use hedwig_view::exposure::Shown;
use hedwig_view::grant;
use hedwig_view::link::{Event, Place, Vocabulary};

mod common;
use common::Bench;
use common::support::{grant, name, terms};

/// A core with the window open, so the catalogue and the document are known.
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

fn vocabulary(bench: &Bench) -> &Vocabulary {
    bench.seen().catalogue.as_ref().expect("the catalogue")
}

fn typed(draft: &mut Draft, bench: &Bench, key: &str, text: &str) {
    let (reference, document) = known(bench);
    draft.edit(
        Edit::Typed {
            key: key.to_owned(),
            text: text.to_owned(),
        },
        &reference,
        &document,
    );
}

fn chose(draft: &mut Draft, bench: &Bench, key: &str, at: usize) {
    let (reference, document) = known(bench);
    draft.edit(
        Edit::Chose {
            key: key.to_owned(),
            at,
        },
        &reference,
        &document,
    );
}

fn form(draft: &Draft, bench: &Bench) -> Form {
    let document = known(bench).1;
    let refused = bench
        .seen()
        .refused
        .as_ref()
        .filter(|(place, _)| *place == Place::Defining)
        .map(|(_, refusal)| refusal.to_string());
    Form::of(draft, vocabulary(bench), &document, None, refused)
}

/// The request the form's act makes, and whether it is asked first.
fn ready(form: &Form) -> (&Request, bool) {
    match &form.ready {
        Ok(Shown::Offered {
            act: Act::Send(request),
            ..
        }) => (request, false),
        Ok(Shown::Offered {
            act: Act::Confirm { request, .. },
            ..
        }) => (request, true),
        other => unreachable!("not ready: {other:?}"),
    }
}

fn make(bench: &mut Bench, place: Place, request: &Request) {
    assert_eq!(bench.permits(request), Ok(()));
    bench.feed(Event::Wish(place, common::clone(request)));
}

fn listed(bench: &Bench) -> Definitions {
    let (reference, document) = known(bench);
    let refused = bench
        .seen()
        .refused
        .as_ref()
        .and_then(|(place, refusal)| match place {
            Place::Defined { kind, name } => Some((*kind, name.clone(), refusal.to_string())),
            _ => None,
        });
    let outside = &bench
        .seen()
        .catalogue
        .as_ref()
        .expect("the catalogue")
        .definitions;
    Definitions::of(
        outside,
        &reference,
        &document,
        refused
            .as_ref()
            .map(|(kind, name, why)| (*kind, name, why.as_str())),
    )
}

/// A person defines a service Hedwig does not ship, field by field: what is
/// not yet usable says why beneath the field, and the act that makes it
/// stands once everything is. The core takes it as it takes any client's
/// change, and the window lists it as the person's own.
#[test]
fn a_capability_is_defined_field_by_field_and_listed_as_the_persons_own() {
    let mut bench = bench();
    let mut draft = Draft::new(Kind::Capability);
    chose(&mut draft, &bench, "source", 2);
    typed(&mut draft, &bench, "name", "Lab Grid");
    let shown = form(&draft, &bench);
    let field = |shown: &Form, key: &str| {
        shown
            .fields
            .iter()
            .find(|field| field.key == key)
            .cloned()
            .expect("the field is shown")
    };
    assert!(
        field(&shown, "name")
            .invalid
            .is_some_and(|why| why.starts_with("\"Lab Grid\" cannot be used: ")),
        "{:?}",
        field(&shown, "name")
    );
    assert_eq!(
        field(&shown, "port").invalid.as_deref(),
        Some("\"\" is not a port: a number from 1 to 65535.")
    );
    assert!(shown.ready.is_err());

    typed(&mut draft, &bench, "name", "lab-grid");
    typed(&mut draft, &bench, "host", "grid.lab.internal");
    typed(&mut draft, &bench, "port", "4444");
    // Where the remote's tool finds it is still unsaid.
    assert_eq!(
        form(&draft, &bench).ready.err().as_deref(),
        Some("Say where the remote's tool finds it: a port, or a variable and its value.")
    );
    typed(&mut draft, &bench, "remote-port", "4444");
    let shown = form(&draft, &bench);
    assert_eq!(shown.heading, "Define a capability");
    let (request, asked) = ready(&shown);
    assert!(!asked, "a new name widens nothing");
    make(&mut bench, Place::Defining, request);
    assert_eq!(bench.seen().refused, None);

    let listed = listed(&bench);
    let own: Vec<(&str, &str)> = listed
        .own
        .iter()
        .map(|defined| (defined.name.as_str(), defined.says.as_str()))
        .collect();
    assert_eq!(
        own,
        [(
            "lab-grid",
            "the service at grid.lab.internal, port 4444; on the remote, through port 4444"
        )]
    );
    // What ships is listed apart, to start from and not to change.
    assert!(listed.outside.iter().any(|(kind, names)| {
        *kind == Kind::Capability
            && names
                .iter()
                .any(|known| known.name.as_str() == "playwright" && known.by == "what Hedwig ships")
    }));
}

/// A preset whose port only the person knows is defined from it: the fields
/// fill from the preset, the port is said, and the shipped name stays the
/// preset's. A name Hedwig ships is refused by the core, at the form.
#[test]
fn a_preset_is_started_from_and_a_shipped_name_is_refused_at_the_form() {
    let mut bench = bench();
    let (reference, document) = known(&bench);
    let mut draft = Draft::new(Kind::Capability);
    let starts = form(&draft, &bench).starts;
    let playwright = starts
        .iter()
        .position(|known| known == "playwright")
        .expect("playwright can be started from");
    draft.edit(Edit::From(playwright), &reference, &document);
    let shown = form(&draft, &bench);
    let port = shown
        .fields
        .iter()
        .find(|field| field.key == "port")
        .unwrap();
    assert_eq!(
        port.input,
        Input::Text {
            typed: String::new(),
            lines: false
        }
    );
    typed(&mut draft, &bench, "port", "3000");
    typed(&mut draft, &bench, "remote-port", "3000");
    typed(&mut draft, &bench, "name", "playwright");
    let shown = form(&draft, &bench);
    let (request, _) = ready(&shown);
    bench.feed(Event::Wish(Place::Defining, common::clone(request)));
    assert_eq!(
        bench.seen().refused,
        Some((Place::Defining, Refusal::Reserved(name("playwright"))))
    );
    assert_eq!(
        form(&draft, &bench).refused,
        Some(Refusal::Reserved(name("playwright")).to_string())
    );

    typed(&mut draft, &bench, "name", "playwright-3000");
    let shown = form(&draft, &bench);
    let (request, _) = ready(&shown);
    make(&mut bench, Place::Defining, request);
    assert_eq!(bench.seen().refused, None);
    assert_eq!(form(&draft, &bench).refused, None);
}

/// A definition something is granted under is changed as the person's own:
/// asked first, since what is granted under its name now reaches what it
/// says. Removed while granted, the core refuses, and the refusal stands on
/// the definition; removed once nothing goes by it, it is gone.
#[test]
fn a_granted_definition_is_changed_with_a_question_and_removed_only_once_unused() {
    let mut bench = bench();
    let mut draft = Draft::new(Kind::Capability);
    chose(&mut draft, &bench, "source", 2);
    typed(&mut draft, &bench, "name", "lab-grid");
    typed(&mut draft, &bench, "port", "4444");
    typed(&mut draft, &bench, "remote-port", "4444");
    let shown = form(&draft, &bench);
    let (request, _) = ready(&shown);
    make(&mut bench, Place::Defining, request);
    make(
        &mut bench,
        Place::Window,
        &Request::Change(Change::Grant {
            grant: grant("lab-grid", Granted::Route(name("ssh"))),
            terms: terms(Activation::OnRequest, Exposure::SERVICE),
        }),
    );

    let (_, document) = known(&bench);
    let mut draft =
        Draft::changing(Kind::Capability, &name("lab-grid"), &document).expect("the person's own");
    // The name is not a field: what is granted goes by it.
    assert!(
        !form(&draft, &bench)
            .fields
            .iter()
            .any(|field| field.key == "name")
    );
    typed(&mut draft, &bench, "port", "4445");
    let shown = form(&draft, &bench);
    assert_eq!(shown.heading, "Change your capability lab-grid");
    let (request, asked) = ready(&shown);
    assert!(asked, "what is granted under it reaches something else");
    make(&mut bench, Place::Defining, request);
    assert_eq!(bench.seen().refused, None);
    assert!(
        listed(&bench)
            .own
            .first()
            .unwrap()
            .says
            .contains("port 4445")
    );

    let remove = |bench: &Bench| match &listed(bench).own.first().unwrap().remove {
        Shown::Offered {
            act: Act::Confirm { request, .. },
            ..
        } => common::clone(request),
        other => unreachable!("{other:?}"),
    };
    let here = Place::Defined {
        kind: Kind::Capability,
        name: name("lab-grid"),
    };
    bench.feed(Event::Wish(here.clone(), remove(&bench)));
    assert_eq!(
        listed(&bench).own.first().unwrap().refused,
        Some(Refusal::CapabilityInUse(name("lab-grid")).to_string())
    );
    make(
        &mut bench,
        Place::Window,
        &Request::Change(Change::Revoke(grant(
            "lab-grid",
            Granted::Route(name("ssh")),
        ))),
    );
    let request = remove(&bench);
    make(&mut bench, here, &request);
    assert_eq!(listed(&bench).own, Vec::<Defined>::new());
}

/// A route, a platform and a set are each defined from the form, listed in
/// the person's words, and removed.
#[test]
#[allow(clippy::too_many_lines, reason = "one person's flow over three kinds")]
fn a_route_a_platform_and_a_set_are_defined_listed_and_removed() {
    let mut bench = bench();
    let mut route = Draft::new(Kind::Route);
    typed(&mut route, &bench, "name", "lab");
    typed(&mut route, &bench, "program", "lab-ssh");
    typed(&mut route, &bench, "after", "{address}");
    chose(&mut route, &bench, "listing", 1);
    typed(&mut route, &bench, "lister", "lab-ssh");
    typed(&mut route, &bench, "lister-arguments", "list\n--running");
    typed(&mut route, &bench, "header", "1");
    chose(&mut route, &bench, "identity", 1);
    let shown = form(&route, &bench);
    let (request, _) = ready(&shown);
    make(&mut bench, Place::Defining, request);

    let mut platform = Draft::new(Kind::Platform);
    typed(&mut platform, &bench, "name", "haiku");
    typed(&mut platform, &bench, "kernel", "Haiku");
    typed(&mut platform, &bench, "path-bytes", "126");
    chose(&mut platform, &bench, "forwarding", 1);
    let shown = form(&platform, &bench);
    let (request, _) = ready(&shown);
    make(&mut bench, Place::Defining, request);

    let mut set = Draft::new(Kind::Set);
    typed(&mut set, &bench, "name", "builders");
    typed(&mut set, &bench, "members", "ssh build.example\nlab ci-*");
    let shown = form(&set, &bench);
    let (request, _) = ready(&shown);
    make(&mut bench, Place::Defining, request);
    assert_eq!(bench.seen().refused, None);

    let said: Vec<(Kind, String)> = listed(&bench)
        .own
        .iter()
        .map(|defined| (defined.kind, defined.says.clone()))
        .collect();
    assert_eq!(
        said,
        [
            (
                Kind::Route,
                "lab-ssh <Hedwig's options> <address>; lab-ssh lists the running ones; each \
                 known by your sign-in to the platform"
                    .to_owned()
            ),
            (
                Kind::Platform,
                "a remote that calls its system Haiku; Unix-domain sockets, paths of up to 126 \
                 bytes; agent forwarding refused"
                    .to_owned()
            ),
            (Kind::Set, "build.example (ssh), ci-* on lab".to_owned()),
        ]
    );
    // A member on a route that is not defined is refused by the core.
    let mut stray = Draft::new(Kind::Set);
    typed(&mut stray, &bench, "name", "strays");
    typed(&mut stray, &bench, "members", "nowhere host.example");
    let shown = form(&stray, &bench);
    let (request, _) = ready(&shown);
    bench.feed(Event::Wish(Place::Defining, common::clone(request)));
    assert_eq!(
        bench.seen().refused,
        Some((Place::Defining, Refusal::UnknownRoute(name("nowhere"))))
    );

    // A platform is matched by the system a remote names, so the core removes
    // it whatever it serves; removing it says what then serves that system.
    let haiku = listed(&bench)
        .own
        .into_iter()
        .find(|defined| defined.kind == Kind::Platform)
        .unwrap();
    let Shown::Offered {
        act: Act::Confirm { consequence, .. },
        ..
    } = haiku.remove
    else {
        unreachable!()
    };
    assert_eq!(
        consequence,
        "haiku, your platform, is no longer defined. A remote that calls its system Haiku is then \
         served by no profile."
    );

    // Removed, last first: the set names the route.
    for defined in listed(&bench).own.into_iter().rev() {
        let Shown::Offered {
            act: Act::Confirm { request, .. },
            ..
        } = &defined.remove
        else {
            unreachable!()
        };
        let here = Place::Defined {
            kind: defined.kind,
            name: defined.name.clone(),
        };
        make(&mut bench, here.clone(), request);
        assert!(
            bench
                .seen()
                .refused
                .as_ref()
                .is_none_or(|(place, _)| *place != here),
            "{}",
            defined.name
        );
    }
    assert_eq!(listed(&bench).own, Vec::<Defined>::new());
}

/// What is typed is checked as the model checks it, beneath the field it is
/// in: a set's member names its route, an argument is one to a line, a
/// socket path's size is a number.
#[test]
fn what_cannot_be_used_says_why_beneath_its_own_field() {
    let bench = bench();
    let why = |draft: &Draft, key: &str| {
        form(draft, &bench)
            .fields
            .into_iter()
            .find(|field| field.key == key)
            .and_then(|field| field.invalid)
    };
    let mut set = Draft::new(Kind::Set);
    typed(&mut set, &bench, "members", "build.example");
    assert_eq!(
        why(&set, "members").as_deref(),
        Some("\"build.example\" names no route: write the route, a space, then the remote.")
    );
    let mut platform = Draft::new(Kind::Platform);
    typed(&mut platform, &bench, "path-bytes", "many");
    assert_eq!(
        why(&platform, "path-bytes").as_deref(),
        Some("\"many\" is not a number of bytes from 1 to 65535.")
    );
    // An emulated platform asks no size.
    chose(&mut platform, &bench, "sockets", 1);
    assert!(
        !form(&platform, &bench)
            .fields
            .iter()
            .any(|field| field.key == "path-bytes")
    );
    let mut route = Draft::new(Kind::Route);
    typed(&mut route, &bench, "program", "lab ssh");
    assert!(
        why(&route, "program").is_some_and(|why| why.starts_with("\"lab ssh\" cannot be used: ")),
    );
}

/// Every definition Hedwig ships reads into the form and back to itself:
/// the form says exactly what the model holds, in both directions.
#[test]
fn every_shipped_definition_reads_into_the_form_and_back() {
    let bench = bench();
    let (reference, _) = known(&bench);
    // The shipped ones, as if they were the person's own.
    let document = Document {
        capabilities: reference.capabilities.clone(),
        routes: reference.routes.clone(),
        platforms: reference.platforms.clone(),
        sets: reference.sets.clone(),
        ..known(&bench).1
    };
    let mut seen = 0;
    for (kind, names, expected) in [
        (
            Kind::Capability,
            reference
                .capabilities
                .iter()
                .map(|known| known.id.clone())
                .collect::<Vec<_>>(),
            reference
                .capabilities
                .iter()
                .map(|known| Change::Define(known.clone()))
                .collect::<Vec<_>>(),
        ),
        (
            Kind::Route,
            reference
                .routes
                .iter()
                .map(|known| known.id.clone())
                .collect(),
            reference
                .routes
                .iter()
                .map(|known| Change::DefineRoute(known.clone()))
                .collect(),
        ),
        (
            Kind::Platform,
            reference
                .platforms
                .iter()
                .map(|known| known.family.clone())
                .collect(),
            reference
                .platforms
                .iter()
                .map(|known| Change::DefinePlatform(known.clone()))
                .collect(),
        ),
    ] {
        for (named, expected) in names.iter().zip(expected) {
            // The TPM's keys and the person's attention are outside the
            // prerelease's core: this form defines neither, and offers no
            // change to them.
            let Some(draft) = Draft::changing(kind, named, &document) else {
                assert!(
                    kind == Kind::Capability
                        && ["machine-ssh", "notices"].contains(&named.as_str()),
                    "{named}"
                );
                continue;
            };
            let shown = Form::of(&draft, vocabulary(&bench), &document, None, None);
            let request = match &shown.ready {
                Ok(Shown::Offered {
                    act: Act::Send(request) | Act::Confirm { request, .. },
                    ..
                }) => request,
                // A preset with no port stated is the one case the form
                // cannot write back: the person states it.
                Err(why) => {
                    assert!(
                        kind == Kind::Capability
                            && ["playwright", "chrome-for-testing"].contains(&named.as_str()),
                        "{named}: {why}"
                    );
                    continue;
                }
                other => unreachable!("{other:?}"),
            };
            assert_eq!(*request, Request::Change(expected), "{named}");
            seen += 1;
        }
    }
    assert!(seen >= 16, "{seen}");
}

/// A platform for a system another profile already answers to is
/// the person's to ask for and the core's to refuse, where it is made: the
/// window asks first what the profile would serve, as the model counts a new
/// profile wider, and the refusal stands at the form in the model's words.
/// Renamed to answer to its own system, it is made.
#[test]
fn a_platform_for_a_system_another_answers_to_is_refused_at_the_form() {
    let mut bench = bench();
    let mut platform = Draft::new(Kind::Platform);
    typed(&mut platform, &bench, "name", "lab-linux");
    typed(&mut platform, &bench, "kernel", "Linux");
    typed(&mut platform, &bench, "path-bytes", "108");
    let shown = form(&platform, &bench);
    let Ok(Shown::Offered {
        label,
        act: Act::Confirm {
            request,
            consequence,
            ..
        },
    }) = &shown.ready
    else {
        unreachable!("{:?}", shown.ready)
    };
    assert_eq!(label, "Define lab-linux...");
    assert_eq!(
        consequence,
        "A remote that calls its system Linux is then served as lab-linux: what is granted to it \
         is carried in the forms its sockets take, where it was served as linux."
    );
    bench.feed(Event::Wish(Place::Defining, common::clone(request)));
    let claimed = Refusal::KernelClaimed {
        kernel: hedwig_model::text::Kernel::try_from("Linux").unwrap(),
        first: name("lab-linux"),
        second: name("linux"),
    };
    assert_eq!(
        bench.seen().refused,
        Some((Place::Defining, claimed.clone()))
    );
    assert_eq!(form(&platform, &bench).refused, Some(claimed.to_string()));

    typed(&mut platform, &bench, "kernel", "Plan9");
    let shown = form(&platform, &bench);
    let Ok(Shown::Offered {
        act: Act::Confirm {
            request,
            consequence,
            ..
        },
        ..
    }) = &shown.ready
    else {
        unreachable!("{:?}", shown.ready)
    };
    assert_eq!(
        consequence,
        "A remote that calls its system Plan9 is then served as lab-linux: what is granted to it \
         is carried in the forms its sockets take, where no profile served it."
    );
    make(&mut bench, Place::Defining, request);
    assert_eq!(bench.seen().refused, None);
    // Removing it is asked with what it ends.
    let removal = listed(&bench)
        .own
        .into_iter()
        .find(|defined| defined.name.as_str() == "lab-linux")
        .unwrap()
        .remove;
    let Shown::Offered {
        act: Act::Confirm { consequence, .. },
        ..
    } = removal
    else {
        unreachable!()
    };
    assert_eq!(
        consequence,
        "lab-linux, your platform, is no longer defined. A remote that calls its system Plan9 is \
         then served by no profile."
    );
}

/// What is defined outside the person's configuration is listed
/// with whose it is, and a name two sources define differently - the
/// person's own among them - is listed only as a collision, with each source:
/// it serves nothing until all but one rename theirs. The window reads it
/// again when the organisation's statements change.
#[test]
fn whose_each_outside_definition_is_and_each_collision_is_said_with_its_sources() {
    use hedwig_model::capability::{Access, AgentAt, Capability, Home, Installation, Source};
    use hedwig_model::organisation::{Part, Start};
    use hedwig_model::text::AgentPipe;

    let mut bench = bench();
    let mine = Capability {
        id: name("bench-licence"),
        source: Source::Agent {
            at: AgentAt::Pipe(AgentPipe::try_from("bench-agent").unwrap()),
        },
    };
    make(
        &mut bench,
        Place::Defining,
        &Request::Change(Change::Define(mine.clone())),
    );
    let theirs = Capability {
        id: mine.id.clone(),
        source: Source::Gnupg {
            installation: Installation::Registered,
            home: Home::Default,
            access: Access::Restricted,
        },
    };
    let lab = Capability {
        id: name("lab-agent"),
        source: Source::Agent {
            at: AgentAt::Pipe(AgentPipe::try_from("bench-agent").unwrap()),
        },
    };
    bench.govern(&[
        (
            Part::Start,
            hedwig_model::wire::line(&Start::Define(theirs)),
        ),
        (Part::Start, hedwig_model::wire::line(&Start::Define(lab))),
    ]);
    let listed = listed(&bench);
    let capabilities = &listed
        .outside
        .iter()
        .find(|(kind, _)| *kind == Kind::Capability)
        .unwrap()
        .1;
    let whose = |wanted: &str| {
        capabilities
            .iter()
            .find(|known| known.name.as_str() == wanted)
            .map(|known| known.by.as_str())
    };
    assert_eq!(whose("gpg"), Some("what Hedwig ships"));
    assert_eq!(
        whose("lab-agent"),
        Some("your organisation's starting point for this machine")
    );
    assert_eq!(
        whose("bench-licence"),
        None,
        "a colliding name defines nothing"
    );
    assert_eq!(
        listed.collisions,
        [
            "The capability bench-licence is defined differently by your organisation's starting \
          point for this machine and you, so nothing that goes by it is served until all but one \
          of them rename theirs."
        ]
    );
}

/// A preset whose port only the person knows is never granted to fail at
/// the core: chosen in the grant form, the form owes the model's own words
/// for the refusal the core would give, and offers the person's own begun
/// from it; made with its port, that is what the form grants.
#[test]
fn a_preset_left_incomplete_is_completed_from_the_grant_form() {
    let mut bench = bench();
    let (reference, document) = known(&bench);
    let mut granting = grant::Draft::default();
    granting.choose_capability(name("playwright"), &reference, &document);
    let shown = grant::Form::of(&granting, &reference, &document, None, (None, None), None);
    let incomplete = Refusal::CapabilityIncomplete {
        capability: name("playwright"),
    };
    assert_eq!(shown.ready, Err(format!("{incomplete}.")));
    // The core refuses that grant in the same words.
    bench.feed(Event::Wish(
        Place::Window,
        Request::Change(Change::Grant {
            grant: grant("playwright", Granted::Route(name("ssh"))),
            terms: terms(Activation::OnRequest, Exposure::SERVICE),
        }),
    ));
    assert_eq!(bench.seen().refused, Some((Place::Window, incomplete)));

    let (label, mut draft) = shown.completes.expect("its own, from the preset");
    assert_eq!(label, "Define playwright with its port...");
    let begun = form(&draft, &bench);
    let field = |key: &str| {
        begun
            .fields
            .iter()
            .find(|field| field.key == key)
            .map(|field| field.input.clone())
    };
    let empty = Some(Input::Text {
        typed: String::new(),
        lines: false,
    });
    assert_eq!(field("name"), empty, "the name is the person's to give");
    assert_eq!(field("port"), empty, "the port is what was unstated");
    typed(&mut draft, &bench, "name", "playwright-9323");
    typed(&mut draft, &bench, "port", "9323");
    typed(&mut draft, &bench, "remote-port", "9323");
    let shown = form(&draft, &bench);
    let (request, _) = ready(&shown);
    make(&mut bench, Place::Defining, request);
    assert!(
        bench
            .seen()
            .refused
            .as_ref()
            .is_none_or(|(place, _)| *place != Place::Defining),
        "{:?}",
        bench.seen().refused
    );
    assert_eq!(draft.named(), Some(name("playwright-9323")));

    let (reference, document) = known(&bench);
    granting.choose_capability(name("playwright-9323"), &reference, &document);
    let shown = grant::Form::of(&granting, &reference, &document, None, (None, None), None);
    assert_eq!(shown.completes, None);
    assert_eq!(
        shown.ready,
        Err("Choose which remotes it is granted to.".to_owned())
    );
}
