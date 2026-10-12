//! The configuration is one value behind one gate: a change made in the
//! interface, a change made from the command line and an imported document
//! meet the same checks and the same refusals.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::capability::{
    AgentAt, Capability, Exposure, Lends, Offer, Operation, ServiceHost, ServicePort, Setup,
    Source, Stream,
};
use hedwig_model::config::{
    Activation, Catalogue, Change, Configuration, DOCUMENT, Denial, Document, Effect, GrantEntry,
    RuleEntry, Terms,
};
use hedwig_model::gate::World;
use hedwig_model::platform::{AgentForwarding, Platform, Sockets};
use hedwig_model::policy::{Keys, Mode, RuleScope, Selector};
use hedwig_model::refusal::{Refusal, Section};
use hedwig_model::remote::{Granted, RemoteId, Remotes};
use hedwig_model::setting::Autostart;
use hedwig_model::text::{AgentPipe, Host, Kernel};
use hedwig_model::wire::{page, read};

mod support;
use support::{catalogue, corpus, grant, granting, name, pattern, port, remote, terms};

fn refused(catalogue: &Catalogue, configuration: &Configuration, change: Change) -> Refusal {
    let mut attempt = configuration.clone();
    let refusal = attempt
        .apply(catalogue, change)
        .expect_err("must be refused");
    assert_eq!(&attempt, configuration, "a refused change changes nothing");
    refusal
}

fn granting_one(
    id: &str,
    remotes: Granted,
    activation: Activation,
    acknowledged: Exposure,
) -> Change {
    Change::Grant {
        grant: grant(id, remotes),
        terms: terms(activation, acknowledged),
    }
}

fn service(host: ServiceHost, number: u16) -> Source {
    Source::Service {
        host,
        port: ServicePort::Fixed(port(number)),
        stream: Stream::Opaque,
        remote: vec![Offer::Port(ServicePort::Fixed(port(number)))],
    }
}

/// The three activations, and the one combination that cannot work.
#[test]
fn a_grant_follows_a_workspace_only_on_a_route_that_can_see_it() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    let coder = Granted::Route(name("coder"));
    let host = Granted::One(remote("ssh", "ops@bastion.example"));
    for (remotes, activation) in [
        (coder.clone(), Activation::WhileRunning),
        (coder, Activation::Continuous),
        (host.clone(), Activation::OnRequest),
        (host.clone(), Activation::Continuous),
    ] {
        assert_eq!(
            configuration.apply(
                &catalogue,
                granting_one("gpg", remotes, activation, Exposure::NONE)
            ),
            Ok(Effect::Changed)
        );
    }
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            granting_one("gpg", host, Activation::WhileRunning, Exposure::NONE)
        ),
        Refusal::ActivationNeedsDiscovery { route: name("ssh") }
    );
}

#[test]
fn a_grant_names_a_capability_and_a_route_that_exist() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            granting_one(
                "gpgg",
                Granted::Route(name("coder")),
                Activation::OnRequest,
                Exposure::NONE
            )
        ),
        Refusal::UnknownCapability(name("gpgg"))
    );
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            granting_one(
                "gpg",
                Granted::Route(name("gitpod")),
                Activation::OnRequest,
                Exposure::NONE
            )
        ),
        Refusal::UnknownRoute(name("gitpod"))
    );
}

/// A widening is never silent: the grant itself names what it exposes, in
/// the document where a reviewer reads it, or it is refused.
#[test]
fn a_grant_names_what_it_exposes_or_is_refused() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    let coder = || Granted::Route(name("coder"));
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            granting_one(
                "gpg-unrestricted",
                coder(),
                Activation::OnRequest,
                Exposure::NONE
            )
        ),
        Refusal::ExposureNotAcknowledged {
            capability: name("gpg-unrestricted"),
            missing: Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        }
    );
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            granting_one(
                "adb",
                coder(),
                Activation::OnRequest,
                Exposure::KEY_MANAGEMENT
            )
        ),
        Refusal::ExposureNotAcknowledged {
            capability: name("adb"),
            missing: Exposure::SERVICE,
        }
    );

    let licence = Capability {
        id: name("licence-server"),
        source: service(
            ServiceHost::Named(Host::try_from("licence.lab.example").unwrap()),
            27000,
        ),
    };
    assert_eq!(
        licence.exposure(),
        Exposure::SERVICE.with(Exposure::NETWORK)
    );
    configuration
        .apply(&catalogue, Change::Define(licence))
        .unwrap();
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            granting_one(
                "licence-server",
                coder(),
                Activation::OnRequest,
                Exposure::SERVICE
            )
        ),
        Refusal::ExposureNotAcknowledged {
            capability: name("licence-server"),
            missing: Exposure::NETWORK,
        }
    );
    assert_eq!(
        configuration.apply(
            &catalogue,
            granting_one(
                "licence-server",
                coder(),
                Activation::OnRequest,
                Exposure::SERVICE.with(Exposure::NETWORK)
            )
        ),
        Ok(Effect::Changed)
    );
    assert_eq!(
        configuration.apply(
            &catalogue,
            granting_one("gpg", coder(), Activation::OnRequest, Exposure::NONE)
        ),
        Ok(Effect::Changed),
        "use of a key through the restricted socket needs no ceremony"
    );
}

/// A preset that cannot state its port is a template: it is granted through
/// a capability of the person's own that states it.
#[test]
fn an_unstated_port_blocks_the_grant_until_a_capability_states_it() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    let coder = || Granted::Route(name("coder"));
    for preset in ["playwright", "chrome-for-testing"] {
        assert_eq!(
            refused(
                &catalogue,
                &configuration,
                granting_one(preset, coder(), Activation::OnRequest, Exposure::SERVICE)
            ),
            Refusal::CapabilityIncomplete {
                capability: name(preset)
            }
        );
    }
    configuration
        .apply(
            &catalogue,
            Change::Define(Capability {
                id: name("playwright-ci"),
                source: service(ServiceHost::Workstation, 3000),
            }),
        )
        .unwrap();
    assert_eq!(
        configuration.apply(
            &catalogue,
            granting_one(
                "playwright-ci",
                coder(),
                Activation::OnRequest,
                Exposure::SERVICE
            )
        ),
        Ok(Effect::Changed)
    );
    let bare = Capability {
        id: name("bare"),
        source: Source::Service {
            host: ServiceHost::Workstation,
            port: ServicePort::Fixed(port(9000)),
            stream: Stream::Opaque,
            remote: Vec::new(),
        },
    };
    assert_eq!(
        bare.complete(),
        Err(Refusal::CapabilityIncomplete {
            capability: name("bare")
        })
    );
}

#[test]
fn a_shipped_name_is_never_redefined() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            Change::Define(Capability {
                id: name("gpg"),
                source: Source::Agent {
                    at: AgentAt::Pipe(AgentPipe::well_known()),
                }
            })
        ),
        Refusal::Reserved(name("gpg"))
    );
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            Change::DefinePlatform(Platform {
                kernel: Kernel::try_from("ReactOS").expect("a kernel"),
                family: name("linux"),
                sockets: Sockets::Emulated,
                agent_forwarding: AgentForwarding::Refused,
            })
        ),
        Refusal::Reserved(name("linux"))
    );
    let twice = hedwig_model::config::Reference {
        capabilities: vec![
            Capability {
                id: name("twice"),
                source: Source::Agent {
                    at: AgentAt::Pipe(AgentPipe::well_known()),
                },
            },
            Capability {
                id: name("twice"),
                source: Source::Agent {
                    at: AgentAt::Pipe(AgentPipe::well_known()),
                },
            },
        ],
        ..hedwig_model::config::Reference::default()
    };
    assert_eq!(Catalogue::new(twice), Err(Refusal::Reserved(name("twice"))));
}

#[test]
fn a_capability_in_use_cannot_be_removed_or_made_to_expose_more() {
    let catalogue = catalogue();
    let define = |source| {
        Change::Define(Capability {
            id: name("bench"),
            source,
        })
    };
    let coder = Remotes::Route(name("coder"));
    let users: [Change; 3] = [
        granting_one(
            "bench",
            Granted::Route(name("coder")),
            Activation::OnRequest,
            Exposure::SERVICE,
        ),
        Change::Deny(Denial {
            capability: Selector::Only(name("bench")),
            remotes: coder.clone(),
        }),
        Change::Rule {
            scope: RuleScope {
                remotes: coder,
                capability: Selector::Only(name("bench")),
                operation: Selector::Every,
                key: Keys::Every,
            },
            mode: Mode::Confirm,
        },
    ];
    for user in users {
        let mut configuration = Configuration::default();
        configuration
            .apply(&catalogue, define(service(ServiceHost::Workstation, 3333)))
            .unwrap();
        configuration.apply(&catalogue, user).unwrap();
        assert_eq!(
            refused(&catalogue, &configuration, Change::Undefine(name("bench"))),
            Refusal::CapabilityInUse(name("bench"))
        );
    }

    let mut configuration = Configuration::default();
    configuration
        .apply(&catalogue, define(service(ServiceHost::Workstation, 3333)))
        .unwrap();
    configuration
        .apply(
            &catalogue,
            granting_one(
                "bench",
                Granted::Route(name("coder")),
                Activation::OnRequest,
                Exposure::SERVICE,
            ),
        )
        .unwrap();
    let elsewhere = service(
        ServiceHost::Named(Host::try_from("10.0.0.7").unwrap()),
        3333,
    );
    assert_eq!(
        refused(&catalogue, &configuration, define(elsewhere)),
        Refusal::ExposureNotAcknowledged {
            capability: name("bench"),
            missing: Exposure::NETWORK,
        }
    );
}

#[test]
fn a_rule_or_a_denial_names_what_exists_and_what_the_dialect_raises() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let scope = |remotes, capability: &str, operation| RuleScope {
        remotes,
        capability: Selector::Only(name(capability)),
        operation,
        key: Keys::Every,
    };
    let rule = |scope| Change::Rule {
        scope,
        mode: Mode::Confirm,
    };
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            rule(scope(
                Remotes::Every,
                "adb",
                Selector::Only(Operation::Sign)
            ))
        ),
        Refusal::OperationNotInDialect {
            capability: name("adb"),
            operation: Operation::Sign,
        }
    );
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            rule(scope(
                Remotes::Every,
                "ssh-agent",
                Selector::Only(Operation::Decrypt)
            ))
        ),
        Refusal::OperationNotInDialect {
            capability: name("ssh-agent"),
            operation: Operation::Decrypt,
        }
    );
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            rule(scope(Remotes::Every, "gpgg", Selector::Every))
        ),
        Refusal::UnknownCapability(name("gpgg"))
    );
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            rule(scope(
                Remotes::Route(name("gitpod")),
                "gpg",
                Selector::Every
            ))
        ),
        Refusal::UnknownRoute(name("gitpod"))
    );
    for remotes in [
        Remotes::Matching {
            route: name("gitpod"),
            pattern: pattern("*"),
        },
        Remotes::One(remote("gitpod", "x")),
    ] {
        assert_eq!(
            refused(
                &catalogue,
                &configuration,
                Change::Deny(Denial {
                    capability: Selector::Every,
                    remotes
                })
            ),
            Refusal::UnknownRoute(name("gitpod"))
        );
    }
    assert_eq!(
        refused(
            &catalogue,
            &configuration,
            Change::Deny(Denial {
                capability: Selector::Only(name("gpgg")),
                remotes: Remotes::Every
            })
        ),
        Refusal::UnknownCapability(name("gpgg"))
    );
}

/// Every change is idempotent, and removing what is not there is not an
/// error.
#[test]
fn a_repeated_change_has_no_second_effect() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    for change in corpus::changes() {
        let mut fresh = Configuration::default();
        let Ok(first) = fresh.apply(&catalogue, change.clone()) else {
            continue;
        };
        let once = fresh.clone();
        assert_eq!(
            fresh.apply(&catalogue, change.clone()),
            Ok(Effect::Unchanged)
        );
        assert_eq!(fresh, once);
        let expected = if fresh == Configuration::default() {
            Effect::Unchanged
        } else {
            Effect::Changed
        };
        assert_eq!(first, expected, "{change:?}");
        let _ = configuration.apply(&catalogue, change);
    }
    assert_ne!(configuration, Configuration::default());
}

/// A denial beats every grant; of several grants the narrowest decides; of
/// two equally narrow the less exposing.
#[test]
fn the_terms_for_a_remote_are_resolved_the_same_way_every_time() {
    let catalogue = catalogue();
    let build = remote("coder", "dev/build");
    let other = remote("coder", "ops/db");
    let mut configuration = Configuration::default();
    let mut give = |remotes, activation, setup| {
        configuration
            .apply(
                &catalogue,
                Change::Grant {
                    grant: grant("gpg", remotes),
                    terms: Terms {
                        activation,
                        setup,
                        acknowledged: Exposure::NONE,
                        lends: Lends::none(),
                    },
                },
            )
            .unwrap();
    };
    give(
        Granted::Route(name("coder")),
        Activation::Continuous,
        Setup::Write,
    );
    give(
        Granted::Matching {
            route: name("coder"),
            pattern: pattern("dev/*"),
        },
        Activation::WhileRunning,
        Setup::Write,
    );
    give(
        Granted::Matching {
            route: name("coder"),
            pattern: pattern("*/build"),
        },
        Activation::OnRequest,
        Setup::Inspect,
    );
    let gpg = name("gpg");
    let terms = |configuration: &Configuration, remote: &RemoteId| {
        let state = hedwig_model::trail::State::default();
        World {
            catalogue: &catalogue,
            configuration,
            state: &state,
        }
        .terms(&gpg, remote)
        .map(|(_, terms)| terms)
    };
    assert_eq!(
        terms(&configuration, &other).unwrap().activation,
        Activation::Continuous,
        "only the route-wide grant covers it"
    );
    assert_eq!(
        terms(&configuration, &build),
        Some(Terms {
            activation: Activation::OnRequest,
            setup: Setup::Inspect,
            acknowledged: Exposure::NONE,
            lends: Lends::none(),
        }),
        "two patterns cover it equally narrowly; the less exposing decides"
    );
    assert_eq!(terms(&configuration, &remote("codespaces", "x")), None);

    configuration
        .apply(
            &catalogue,
            Change::Deny(Denial {
                capability: Selector::Every,
                remotes: Remotes::One(build.clone()),
            }),
        )
        .unwrap();
    assert_eq!(terms(&configuration, &build), None);
    assert!(configuration.denies(&catalogue, &gpg, &build));
    assert!(terms(&configuration, &other).is_some());
}

/// Export and import, both directions, as equality - as values and as the
/// page a person keeps in a repository.
#[test]
fn a_configuration_exports_and_imports_as_equality() {
    let catalogue = catalogue();
    let mut configuration = granting(
        &catalogue,
        &[
            ("gpg", Granted::Route(name("coder"))),
            ("adb", Granted::One(remote("ssh", "dev@box"))),
        ],
    );
    for change in corpus::changes() {
        let _ = configuration.apply(&catalogue, change);
    }

    let document = configuration.export();
    assert_eq!(document.version, DOCUMENT);
    let imported = Configuration::import(&catalogue, document.clone()).expect("it imports");
    assert_eq!(imported, configuration);
    assert_eq!(imported.export(), document);

    let text = page(&document);
    let read_back: Document = read(&text).expect("the page reads");
    assert_eq!(read_back, document);
    assert_eq!(
        page(
            &Configuration::import(&catalogue, read_back)
                .unwrap()
                .export()
        ),
        text
    );
}

/// Import is whole or not at all, through the gate every single change goes
/// through.
#[test]
fn an_import_is_refused_whole_for_one_bad_entry() {
    let catalogue = catalogue();
    let good = granting(&catalogue, &[("gpg", Granted::Route(name("coder")))]).export();
    let import = |document: Document| {
        Configuration::import(&catalogue, document).expect_err("must be refused")
    };

    assert_eq!(
        import(Document {
            version: 1,
            ..good.clone()
        }),
        Refusal::DocumentVersion {
            found: 1,
            supported: 2
        }
    );

    let entry = good.grants.first().unwrap().clone();
    assert_eq!(
        import(Document {
            grants: vec![entry.clone(), entry.clone()],
            ..good.clone()
        }),
        Refusal::Repeated(Section::Grants)
    );
    let denial = Denial {
        capability: Selector::Every,
        remotes: Remotes::Every,
    };
    assert_eq!(
        import(Document {
            denials: vec![denial.clone(), denial],
            ..good.clone()
        }),
        Refusal::Repeated(Section::Denials)
    );
    let rule = RuleEntry {
        scope: RuleScope {
            remotes: Remotes::Every,
            capability: Selector::Every,
            operation: Selector::Every,
            key: Keys::Every,
        },
        mode: Mode::Confirm,
    };
    assert_eq!(
        import(Document {
            rules: vec![rule.clone(), rule],
            ..good.clone()
        }),
        Refusal::Repeated(Section::Rules)
    );
    let mine = Capability {
        id: name("mine"),
        source: Source::Agent {
            at: AgentAt::Pipe(AgentPipe::well_known()),
        },
    };
    assert_eq!(
        import(Document {
            capabilities: vec![mine.clone(), mine],
            ..good.clone()
        }),
        Refusal::Repeated(Section::Capabilities)
    );
    let haiku = corpus::platforms().first().unwrap().clone();
    assert_eq!(
        import(Document {
            platforms: vec![haiku.clone(), haiku],
            ..good.clone()
        }),
        Refusal::Repeated(Section::Platforms)
    );
    assert_eq!(
        import(Document {
            routes: vec![corpus::lab(), corpus::lab()],
            ..good.clone()
        }),
        Refusal::Repeated(Section::Routes)
    );

    assert_eq!(
        import(Document {
            grants: vec![GrantEntry {
                grant: grant("gpg-unrestricted", Granted::Route(name("coder"))),
                terms: terms(Activation::OnRequest, Exposure::NONE),
            }],
            ..good
        }),
        Refusal::ExposureNotAcknowledged {
            capability: name("gpg-unrestricted"),
            missing: Exposure::KEY_MANAGEMENT.with(Exposure::SECRET),
        },
        "an imported document cannot widen silently either"
    );
}

/// Starting at logon is a choice like any other: unsaid until the person
/// says it, changed by one idempotent act, part of the document, and unsaid
/// again when they say nothing - which leaves it to the farther sources and
/// is written as `null`, never by leaving the key out.
#[test]
fn autostart_is_unsaid_until_the_person_says_and_is_in_the_document() {
    let catalogue = catalogue();
    let mut configuration = Configuration::default();
    assert_eq!(configuration.autostart(), None);
    assert_eq!(configuration.export().autostart, None);

    let on = Change::Autostart(Some(Autostart::AtLogon));
    assert_eq!(
        configuration.apply(&catalogue, on.clone()),
        Ok(Effect::Changed)
    );
    assert_eq!(configuration.apply(&catalogue, on), Ok(Effect::Unchanged));
    assert_eq!(configuration.autostart(), Some(Autostart::AtLogon));

    let document = configuration.export();
    let text = page(&document);
    assert!(text.contains("\n  \"autostart\": \"at-logon\",\n"));
    let back = Configuration::import(&catalogue, document).unwrap();
    assert_eq!(back, configuration);

    let without = text.replace(",\n  \"autostart\": \"at-logon\"", "");
    assert_eq!(
        read::<Document>(&without).unwrap_err().to_string(),
        "the value has no autostart"
    );

    assert_eq!(
        configuration.apply(&catalogue, Change::Autostart(None)),
        Ok(Effect::Changed)
    );
    assert_eq!(configuration, Configuration::default());
    assert!(page(&configuration.export()).contains("\n  \"autostart\": null,\n"));
}
