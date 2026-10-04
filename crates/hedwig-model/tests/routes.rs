//! What a route declares, and that a shipped route and one somebody defines
//! are one form: a client the workstation already has, how its remotes are
//! listed, and what stands for a remote's identity. Nothing here names a
//! product.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use hedwig_model::capability::Exposure;
use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Effect, Reference};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{
    Argument, Client, Discovery, Granted, Identity, ListError, Lister, Listing, Route,
};
use hedwig_model::text::{Program, TextError, Verbatim};
use hedwig_model::wire::{line, read};

mod support;
use support::{address, catalogue, coder, grant, name, terms};

fn shipped() -> Catalogue {
    Catalogue::shipped().expect("the shipped catalogue loads")
}

fn route(catalogue: &Catalogue, id: &str) -> Route {
    catalogue.route(&name(id)).expect("a shipped route").clone()
}

/// What the core would add for one connection; the route decides only where.
fn options() -> Vec<String> {
    ["-N", "-o", "ExitOnForwardFailure=yes"]
        .map(str::to_owned)
        .to_vec()
}

#[test]
fn the_core_route_is_the_persons_own_ssh_with_their_own_configuration() {
    let ssh = route(&shipped(), "ssh");
    assert_eq!(ssh.client.program.as_str(), "ssh");
    assert!(
        ssh.client.before.is_empty(),
        "nothing overrides their config"
    );
    assert_eq!(
        ssh.client
            .arguments(&address("ops@bastion.example"), options()),
        [
            "-N",
            "-o",
            "ExitOnForwardFailure=yes",
            "ops@bastion.example"
        ]
    );
    assert_eq!(ssh.listing, Listing::Blind);
    assert_eq!(ssh.discovery(), Discovery::Blind);
    assert_eq!(ssh.identity, Identity::HostKey);
}

/// A vendor's route is a definition, whoever makes it. `codespaces` ships,
/// additive and unverified until it is run against a real Codespace. `coder`
/// does not: a person defines it, in the form the documentation publishes, and
/// it then reaches its remotes, lists them and carries a grant that follows
/// their lives as the shipped one does. Nothing but data differs.
#[test]
fn a_vendor_route_is_a_definition_whether_it_ships_or_a_person_makes_it() {
    let catalogue = shipped();
    let ids: Vec<String> = catalogue
        .reference()
        .routes
        .iter()
        .map(|route| route.id.to_string())
        .collect();
    assert_eq!(ids, ["codespaces", "ssh"]);

    let follows = Change::Grant {
        grant: grant("gpg", Granted::Route(name("coder"))),
        terms: terms(Activation::WhileRunning, Exposure::NONE),
    };
    let mut configuration = Configuration::default();
    assert_eq!(
        configuration.apply(&catalogue, follows.clone()),
        Err(Refusal::UnknownRoute(name("coder")))
    );
    assert_eq!(
        configuration.apply(&catalogue, Change::DefineRoute(coder())),
        Ok(Effect::Changed)
    );
    assert_eq!(
        configuration.apply(&catalogue, follows),
        Ok(Effect::Changed)
    );
    let coder = configuration
        .route(&catalogue, &name("coder"))
        .expect("the person's route")
        .clone();
    assert_eq!(coder.client.program.as_str(), "ssh");
    let arguments = coder.client.arguments(&address("build"), options());
    assert_eq!(arguments.last().map(String::as_str), Some("build"));
    assert!(arguments.contains(&"ProxyCommand=coder ssh --stdio %n".to_owned()));
    assert_eq!(coder.identity, Identity::Platform);

    let codespaces = route(&catalogue, "codespaces");
    assert_eq!(codespaces.client.program.as_str(), "gh");
    assert_eq!(
        codespaces
            .client
            .arguments(&address("fluffy-space-7x9q"), options()),
        [
            "codespace",
            "ssh",
            "--codespace",
            "fluffy-space-7x9q",
            "--",
            "-N",
            "-o",
            "ExitOnForwardFailure=yes"
        ],
        "the core's options reach the real ssh after the separator"
    );
    for listed in [&coder, &codespaces] {
        assert_eq!(listed.discovery(), Discovery::Lists);
    }
}

/// An address is one argument wherever the entry puts it, whatever it holds.
#[test]
fn an_address_is_always_one_whole_argument() {
    let client = Client {
        program: Program::try_from("tool").unwrap(),
        before: vec![Argument::Address],
        after: vec![Argument::Address],
    };
    let arguments = client.arguments(&address("dev@host=x"), Vec::new());
    assert_eq!(arguments, ["dev@host=x", "dev@host=x"]);
}

#[test]
fn a_listing_is_read_as_one_address_a_line_after_its_heading() {
    let lister = Lister {
        program: Program::try_from("coder").unwrap(),
        arguments: Vec::new(),
        header: 1,
    };
    let printed = "WORKSPACE\r\nbuild\r\n\r\n  owner/release  \r\n";
    assert_eq!(
        lister.addresses(printed),
        Ok(vec![address("build"), address("owner/release")])
    );
    assert_eq!(lister.addresses("WORKSPACE\n"), Ok(Vec::new()));
    // A listing with one line that is not an address is not a listing: a
    // remote read as absent would be taken as stopped.
    assert_eq!(
        lister.addresses("WORKSPACE\nbuild\n-oProxyCommand=x\n"),
        Err(ListError {
            line: 3,
            error: TextError::LeadingHyphen,
        })
    );
    assert_eq!(
        lister
            .addresses("WORKSPACE\nbuild;rm\n")
            .unwrap_err()
            .to_string(),
        "line 2 of the listing is not a remote's address: ';' at byte 5 is not allowed here"
    );
}

/// A route the person defines - a platform Hedwig does not ship - is one
/// change of data, and a grant that follows its remotes' lives is accepted on
/// it as on a shipped one. It is in their document, and while a grant goes
/// by it, it stays.
#[test]
fn a_route_nobody_has_met_is_one_definition_away() {
    let catalogue = catalogue();
    let lab = Route {
        id: name("lab"),
        client: Client {
            program: Program::try_from("ssh").unwrap(),
            before: vec![
                Argument::Literal(Verbatim::try_from("-J").unwrap()),
                Argument::Literal(Verbatim::try_from("bastion.lab.example").unwrap()),
            ],
            after: vec![Argument::Address],
        },
        listing: Listing::Lists(Lister {
            program: Program::try_from("lab-inventory").unwrap(),
            arguments: vec![Verbatim::try_from("--running").unwrap()],
            header: 0,
        }),
        identity: Identity::HostKey,
    };
    let grant_lab = Change::Grant {
        grant: grant("gpg", Granted::Route(name("lab"))),
        terms: terms(Activation::WhileRunning, Exposure::NONE),
    };
    let mut configuration = Configuration::default();
    assert_eq!(
        configuration.apply(&catalogue, grant_lab.clone()),
        Err(Refusal::UnknownRoute(name("lab")))
    );
    assert_eq!(
        configuration.apply(&catalogue, Change::DefineRoute(lab.clone())),
        Ok(Effect::Changed)
    );
    assert_eq!(
        configuration.apply(&catalogue, grant_lab),
        Ok(Effect::Changed)
    );
    assert_eq!(configuration.route(&catalogue, &name("lab")), Ok(&lab));
    assert_eq!(configuration.export().routes, std::slice::from_ref(&lab));
    assert_eq!(
        configuration.apply(&catalogue, Change::UndefineRoute(name("lab"))),
        Err(Refusal::RouteInUse(name("lab")))
    );
    assert_eq!(
        Refusal::RouteInUse(name("lab")).to_string(),
        "remotes on lab are still named by a grant, a denial or a rule; remove those first"
    );

    // A shipped name is not the person's to redefine, in a change or in a
    // catalogue: two entries under one name never collide silently.
    let ssh = Route {
        id: name("ssh"),
        ..lab.clone()
    };
    assert_eq!(
        Configuration::default().apply(&catalogue, Change::DefineRoute(ssh)),
        Err(Refusal::Reserved(name("ssh")))
    );
    let mut reference = catalogue.reference();
    reference.routes.push(lab.clone());
    reference.routes.push(lab);
    assert_eq!(
        Catalogue::new(reference),
        Err(Refusal::Reserved(name("lab")))
    );
}

#[test]
fn a_route_is_written_and_read_back_as_the_same_route() {
    for route in catalogue().reference().routes {
        let text = line(&route);
        assert_eq!(read::<Route>(&text), Ok(route), "{text}");
    }
    let reference: Reference = catalogue().reference();
    let text = line(&reference);
    assert_eq!(read::<Reference>(&text).unwrap(), reference);
}

#[test]
fn the_listing_arguments_of_a_route_are_each_one_argument() {
    let Listing::Lists(codespaces) = route(&shipped(), "codespaces").listing else {
        panic!("codespaces lists its remotes");
    };
    let jq = codespaces.arguments.last().map(Verbatim::as_str);
    assert_eq!(jq, Some(r#".[] | select(.state == "Available") | .name"#));
    let Listing::Lists(coder) = coder().listing else {
        panic!("coder lists its remotes");
    };
    assert!(
        coder
            .arguments
            .iter()
            .any(|argument| argument.as_str() == "owner:me status:running")
    );
    assert_eq!(coder.header, 1);
}
