//! What a remote asks the workstation's browser to open: the URL read where it
//! arrives, the callback it carries, the sites that admit it, and the gate
//! that decides it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

mod support;

use hedwig_model::capability::{Browser, Capability, Exposure, Operation, Source};
use hedwig_model::config::{Activation, Change, Collision, Configuration, Reach};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::policy::Basis;
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{Granted, RemoteId};
use hedwig_model::site::{
    Callback, Hosts, LONGEST, Opening, Scheme, Site, SiteError, Unopenable, url,
};
use hedwig_model::text::{Host, Port};
use hedwig_model::trail::{ClientKind, Outcome};
use support::{DESKTOP, Trail, catalogue, grant, name, remote, terms};

fn host(text: &str) -> Host {
    Host::try_from(text).unwrap()
}

fn port(number: u16) -> Port {
    Port::try_from(number).unwrap()
}

/// The authorisation request AWS CLI 2.37.7 opens for `aws sso login`
/// (`awscli/botocore/utils.py`, `_get_authorization_uri`).
const AWS: &str = "https://oidc.eu-west-1.amazonaws.com/authorize?response_type=code&client_id=Zm9v&redirect_uri=http%3A%2F%2F127.0.0.1%3A41237%2Foauth%2Fcallback&state=b5e3&code_challenge_method=S256&scopes=sso%3Aaccount%3Aaccess&code_challenge=x4Y";

#[test]
fn a_url_is_read_to_its_site_and_the_rest_as_written() {
    let read = url("HTTPS://OIDC.eu-west-1.amazonaws.com/authorize?a=b#frag").unwrap();
    assert_eq!(read.scheme, Scheme::Https);
    assert_eq!(read.host, host("oidc.eu-west-1.amazonaws.com"));
    assert_eq!(read.port, port(443));
    assert_eq!(read.target, "/authorize?a=b#frag");
    assert_eq!(read.path(), "/authorize");
    let read = url("http://[::1]:8000").unwrap();
    assert_eq!((read.host.as_str(), read.port.number()), ("::1", 8000));
    assert_eq!(read.target, "/");
    assert!(read.loopback());
    assert_eq!(read.to_string(), "http://[::1]:8000/");
    let read = url("https://github.com?x=1").unwrap();
    assert_eq!(read.target, "/?x=1");
}

#[test]
fn what_is_not_an_https_or_http_url_is_refused_with_why() {
    for (text, why) in [
        ("ms-msdt:/id PCWDiagnostic", Unopenable::NotUrl),
        ("search-ms:query=x", Unopenable::NotUrl),
        ("file:///C:/Windows/System32/calc.exe", Unopenable::Scheme),
        ("javascript://%0aalert(1)", Unopenable::Scheme),
        (
            "https://github.com@evil.example/login",
            Unopenable::Credentials,
        ),
        ("https://user:pass@github.com/", Unopenable::Credentials),
        ("https://exa mple.com/", Unopenable::NotUrl),
        ("https://example.com/\u{7f}", Unopenable::NotUrl),
        ("", Unopenable::NotUrl),
        ("https://", Unopenable::Host),
        ("https://[::1/", Unopenable::Host),
        ("https://example.com:0/", Unopenable::Host),
        ("https://example.com:65536/", Unopenable::Host),
        ("https://exa_mple.com/", Unopenable::Host),
    ] {
        assert_eq!(url(text), Err(why), "{text}");
    }
    let long = format!("https://example.com/{}", "a".repeat(LONGEST));
    assert_eq!(url(&long), Err(Unopenable::TooLong));
}

/// The three kinds of sign-in flow: a loopback callback named in the
/// request's `redirect_uri`, the remote's own page on its loopback, and a
/// device code's page, which carries nothing.
#[test]
fn an_opening_carries_the_loopback_port_its_flow_comes_back_to() {
    let aws = Opening::of(url(AWS).unwrap());
    assert_eq!(
        aws.callback,
        Some(Callback {
            host: host("127.0.0.1"),
            port: port(41237),
            path: Some("/oauth/callback".to_owned()),
        })
    );
    let kubelogin = Opening::of(url("http://localhost:8000/").unwrap());
    assert_eq!(
        kubelogin.callback,
        Some(Callback {
            host: host("localhost"),
            port: port(8000),
            path: None,
        })
    );
    for carried_nothing in [
        "https://github.com/login/device",
        "https://microsoft.com/devicelogin?otc=ABCD1234",
        "https://idp.example/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fcb",
        "https://idp.example/authorize?redirect_uri=http%3A%2F%2Fapp.example%3A8000%2Fcb",
        "https://idp.example/authorize?redirect_uri=not%20a%20url",
    ] {
        assert_eq!(
            Opening::of(url(carried_nothing).unwrap()).callback,
            None,
            "{carried_nothing}"
        );
    }
}

#[test]
fn a_site_admits_its_scheme_its_hosts_and_its_port() {
    let exactly = "https://github.com".parse::<Site>().unwrap();
    let within = "https://*.example.invalid:8443".parse::<Site>().unwrap();
    let loopback = "http://localhost".parse::<Site>().unwrap();
    let admits = |site: &Site, text: &str| site.admits(&url(text).unwrap());
    assert!(admits(&exactly, "https://github.com/login/device"));
    assert!(!admits(&exactly, "https://github.com:8443/"));
    assert!(!admits(&exactly, "http://github.com/"));
    assert!(!admits(&exactly, "https://gist.github.com/"));
    assert!(admits(&within, "https://login.example.invalid:8443/"));
    assert!(admits(&within, "https://example.invalid:8443/"));
    assert!(!admits(&within, "https://evilexample.invalid:8443/"));
    assert!(!admits(&within, "https://login.example.invalid/"));
    assert!(admits(&loopback, "http://localhost:8000/"));
    assert!(admits(&loopback, "http://127.0.0.1:18000/"));
    assert!(admits(&loopback, "http://[::1]:41237/"));
    assert!(!admits(&loopback, "http://localhost.example/"));
    assert!(
        !admits(&exactly, "https://localhost/"),
        "a loopback only by its own site"
    );
    for text in [
        AWS,
        "http://localhost:8000/",
        "https://example.invalid:8443/x",
    ] {
        let read = url(text).unwrap();
        assert!(Site::of(&read).admits(&read), "{text}");
    }
}

/// A site's written form is what the person types, what a refusal names and
/// what a document holds: each written form reads back to itself, each site
/// writes to what reads back to it, and one site has one form.
#[test]
fn a_site_is_written_as_it_is_typed_and_read_back_both_ways() {
    for text in [
        "https://signin.example.org",
        "https://*.portal.example.org",
        "https://signin.example.org:8443",
        "http://localhost",
        "http://localhost:8400",
        "http://localhost:80",
        "https://[2001:db8::1]",
        "https://[2001:db8::1]:8443",
        "http://intranet.example:8080",
    ] {
        let site: Site = text.parse().unwrap();
        assert_eq!(site.to_string(), text);
        assert_eq!(
            hedwig_model::wire::line(&site),
            format!("\"{text}\""),
            "the document's form is the written form"
        );
        assert_eq!(
            hedwig_model::wire::read::<Site>(&format!("\"{text}\"")),
            Ok(site)
        );
    }
    for text in [
        AWS,
        "http://127.0.0.1:41237/oauth/callback",
        "https://login.example.invalid:8443/x",
        "https://[2001:db8::1]/",
    ] {
        let site = Site::of(&url(text).unwrap());
        assert_eq!(site.to_string().parse::<Site>(), Ok(site));
    }
    // One site, one form: the scheme's own port after a named host is no
    // port of the site's, and any address of the loopback is the loopback,
    // whose own port 80 is a port of the site's, since it admits any.
    let signin: Site = "https://signin.example.org".parse().unwrap();
    assert_eq!("https://signin.example.org:443".parse(), Ok(signin.clone()));
    assert_eq!("HTTPS://SignIn.Example.org/".parse(), Ok(signin));
    let loopback: Site = "http://localhost".parse().unwrap();
    for text in ["http://127.0.0.1", "http://[::1]", "http://127.1.2.3"] {
        assert_eq!(text.parse(), Ok(loopback.clone()), "{text}");
    }
    assert_eq!(loopback.hosts(), &Hosts::Loopback);
    assert_eq!(loopback.port(), None);
    assert_eq!(
        "http://localhost:80".parse::<Site>().unwrap().port(),
        Some(port(80))
    );
    // What the core would not open is no site, and neither is a path or the
    // loopback with names beneath it; each says why, and a document says
    // where.
    for (text, why) in [
        (
            "ftp://files.example.org",
            SiteError::Unopenable(Unopenable::Scheme),
        ),
        (
            "https://name@signin.example.org",
            SiteError::Unopenable(Unopenable::Credentials),
        ),
        (
            "signin.example.org",
            SiteError::Unopenable(Unopenable::NotUrl),
        ),
        ("", SiteError::Unopenable(Unopenable::NotUrl)),
        (
            "https://signin.example.org:0",
            SiteError::Unopenable(Unopenable::Host),
        ),
        ("https://signin.example.org/oauth", SiteError::Path),
        ("https://signin.example.org?a=b", SiteError::Path),
        ("https://*.localhost", SiteError::LoopbackWithin),
        ("http://*.127.0.0.1:8000", SiteError::LoopbackWithin),
    ] {
        assert_eq!(text.parse::<Site>(), Err(why), "{text}");
        assert!(why.to_string().len() > 12, "{why:?}");
    }
    assert_eq!(
        hedwig_model::wire::read::<Site>("\"https://signin.example.org/oauth\"")
            .unwrap_err()
            .to_string(),
        "the value is not a site: a site is a scheme and a host, with no path"
    );
    assert!(hedwig_model::wire::read::<Site>(r#"{"scheme":"https"}"#).is_err());
}

/// The gate: what decide refuses is refused first; then a URL the browser
/// does not open, then one no site admits, each with the site a person would
/// add; and a listed one is decided at its mode with what it carries.
#[test]
fn an_opening_is_decided_at_the_one_gate() {
    let catalogue = catalogue();
    let host_remote: RemoteId = remote("coder", "dev/build");
    let mut configuration = Configuration::default();
    let mut sites = support::corpus::sites();
    sites.truncate(1);
    for change in [
        Change::Define(Capability {
            id: name("sign-in"),
            source: Source::Browser {
                browser: Browser::Default,
                sites,
            },
        }),
        Change::Grant {
            grant: grant("sign-in", Granted::One(host_remote.clone())),
            terms: terms(Activation::OnRequest, Exposure::BROWSER),
        },
    ] {
        configuration.apply(&catalogue, change).unwrap();
    }
    let mut trail = Trail::started();
    trail.attach(ClientKind::Terminal, DESKTOP);
    let connection = trail.open(&host_remote, "linux");
    let state = trail.state();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    let browser = name("sign-in");
    let now = trail.tick();

    let (verdict, opening) = world.open(connection, &browser, AWS, now);
    assert_eq!(verdict, Verdict::Serve(Outcome::Served(Basis::Default)));
    assert_eq!(opening.unwrap().callback.unwrap().port, port(41237));

    let (verdict, opening) =
        world.open(connection, &browser, "https://github.com/login/device", now);
    assert_eq!(
        verdict,
        Verdict::Refuse(Refusal::UnlistedSite {
            capability: browser.clone(),
            site: "https://github.com".parse::<Site>().unwrap(),
        })
    );
    assert_eq!(opening, None);

    let (verdict, _) = world.open(connection, &browser, "file:///C:/x", now);
    assert_eq!(
        verdict,
        Verdict::Refuse(Refusal::Unopenable {
            capability: browser.clone(),
            why: Unopenable::Scheme,
        })
    );

    let (verdict, _) = world.open(connection, &name("gpg"), AWS, now);
    assert!(
        matches!(verdict, Verdict::Refuse(Refusal::NotGranted { .. })),
        "{verdict:?}"
    );
    assert_eq!(
        world.decide(connection, &browser, Operation::Open, None, now),
        Verdict::Serve(Outcome::Served(Basis::Default)),
        "the browser's decision point is its own"
    );
}

/// Nothing Hedwig ships opens the person's browser, so a capability
/// that does is the person's own, under whatever name they give it, `browser`
/// included; the site its first refusal names is added to it in one act, and
/// the grant the person already made serves the next attempt.
#[test]
fn a_refused_site_is_added_in_one_act_to_the_browser_the_person_defined() {
    let catalogue = catalogue();
    let shipped = Configuration::default().definitions(&catalogue);
    assert!(
        !shipped
            .capabilities
            .iter()
            .any(|defined| matches!(defined.definition.source, Source::Browser { .. })),
        "a shipped browser capability would open nothing and could take no site"
    );
    let host_remote: RemoteId = remote("coder", "dev/build");
    let mut configuration = Configuration::default();
    for change in [
        Change::Define(support::browser()),
        Change::Grant {
            grant: grant("browser", Granted::One(host_remote.clone())),
            terms: terms(Activation::OnRequest, Exposure::BROWSER),
        },
    ] {
        configuration.apply(&catalogue, change).unwrap();
    }
    assert_eq!(
        configuration.definitions(&catalogue).collisions,
        Vec::<Collision>::new()
    );
    let mut trail = Trail::started();
    trail.attach(ClientKind::Terminal, DESKTOP);
    let connection = trail.open(&host_remote, "linux");
    let browser = name("browser");
    let open = |configuration: &Configuration, trail: &mut Trail| {
        let now = trail.tick();
        let state = trail.state();
        World {
            catalogue: &catalogue,
            configuration,
            state: &state,
        }
        .open(connection, &browser, "https://github.com/login/device", now)
        .0
    };
    let Verdict::Refuse(Refusal::UnlistedSite { capability, site }) =
        open(&configuration, &mut trail)
    else {
        unreachable!("the first sign-in names its site")
    };
    assert_eq!(site.to_string(), "https://github.com");
    let Source::Browser {
        browser: opener,
        mut sites,
    } = configuration
        .capability(&catalogue, &capability)
        .unwrap()
        .source
    else {
        unreachable!("the capability refused is the browser")
    };
    sites.push(site);
    let added = Change::Define(Capability {
        id: capability,
        source: Source::Browser {
            browser: opener,
            sites,
        },
    });
    assert_eq!(configuration.widens(&catalogue, &added), Reach::Wider);
    configuration.apply(&catalogue, added).unwrap();
    assert_eq!(
        open(&configuration, &mut trail),
        Verdict::Serve(Outcome::Served(Basis::Default))
    );
}
