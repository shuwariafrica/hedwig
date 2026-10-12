//! Hedwig's model and control protocol, as code that runs.
//!
//! The core holds three things: the shipped [`config::Catalogue`], the
//! person's [`config::Configuration`], and the [`trail::State`] folded from
//! the activity trail. [`gate::World`] reads those three and is the only place
//! anything is decided - what a remote's request gets, what a control client
//! may do, what a surface shows and offers. [`protocol`] is every message
//! between the core and its clients, and [`wire`] how each is written down.
//!
//! Where to start: [`capability`] for what can be exposed, [`remote`] and
//! [`platform`] for where, [`policy`] for how a request is decided. [`frame`]
//! cuts a client's bytes into the lines [`wire`] reads, and [`process`] is what
//! Hedwig's own processes say to each other.
//!
//! # Examples
//!
//! A grant, and the decision on a request that arrives under it:
//!
//! ```
//! use hedwig_model::capability::{Exposure, Lends, Operation, Setup};
//! use hedwig_model::config::{Activation, Catalogue, Change, Configuration, Grant, Terms};
//! use hedwig_model::gate::{Verdict, World};
//! use hedwig_model::refusal::{Refusal, Whereabouts};
//! use hedwig_model::remote::{Granted, RemoteId};
//! use hedwig_model::text::{Address, Name};
//! use hedwig_model::trail::{
//!     ConnectionId, Entry, Event, Integrity, Opener, Origin, Seq, State, Tick, Timestamp,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let catalogue = Catalogue::shipped()?;
//! let workspace = RemoteId {
//!     route: Name::try_from("codespaces")?,
//!     address: Address::try_from("fluffy-space-7x9q")?,
//! };
//! let gpg = Name::try_from("gpg")?;
//!
//! let mut configuration = Configuration::default();
//! configuration.apply(
//!     &catalogue,
//!     Change::Grant {
//!         grant: Grant {
//!             capability: gpg.clone(),
//!             remotes: Granted::Route(Name::try_from("codespaces")?),
//!         },
//!         terms: Terms {
//!             activation: Activation::WhileRunning,
//!             setup: Setup::Inspect,
//!             acknowledged: Exposure::NONE,
//!             lends: Lends::none(),
//!         },
//!     },
//! )?;
//!
//! let origin = Origin { process: 4200, logon: 999, session: 2, integrity: Integrity::Medium };
//! let events = [
//!     Event::Started { version: "0.2.0".to_owned(), origin, after: None },
//!     Event::Opening {
//!         remote: workspace,
//!         with: Vec::new(),
//!         acknowledged: Exposure::NONE,
//!         lends: Lends::none(),
//!         opener: Opener::Grant,
//!     },
//! ];
//! let trail: Vec<Entry> = events
//!     .into_iter()
//!     .zip(1u64..)
//!     .map(|(event, number)| Entry {
//!         seq: Seq(number),
//!         at: Timestamp(0),
//!         tick: Tick(0),
//!         event,
//!     })
//!     .collect();
//! let state = State::fold(&trail);
//! let world = World { catalogue: &catalogue, configuration: &configuration, state: &state };
//!
//! // Granted, but nothing attached reaches the person, so it is refused.
//! assert_eq!(
//!     world.decide(ConnectionId(Seq(2)), &gpg, Operation::Sign, None, Tick(0)),
//!     Verdict::Refuse(Refusal::NobodyReachable(Whereabouts::Away)),
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # What the types rule out
//!
//! Each of these fails to compile, and each is a state the model must never
//! reach.
//!
//! A grant never covers every route at once; the widest it goes is one:
//!
//! ```compile_fail,E0599
//! let everywhere = hedwig_model::remote::Granted::Every;
//! ```
//!
//! Only the Assuan dialect has a restricted axis, so no other can be asked
//! about one:
//!
//! ```compile_fail,E0618
//! use hedwig_model::capability::{Access, Dialect};
//! let dialect = Dialect::SshAgent(Access::Restricted);
//! ```
//!
//! A configuration is never assembled around the gate:
//!
//! ```compile_fail,E0451
//! use hedwig_model::config::Configuration;
//! let configuration = Configuration { autostart: None, ..Configuration::default() };
//! ```
//!
//! Checked text is never built unchecked:
//!
//! ```compile_fail,E0603
//! let address = hedwig_model::text::Address("-oProxyCommand=calc".to_owned());
//! ```
//!
//! A standing rule names remotes, never a live connection, so nothing that
//! should end with a connection can be written into the configuration:
//!
//! ```compile_fail,E0308
//! use hedwig_model::policy::{Keys, RuleScope, Selector};
//! use hedwig_model::trail::{ConnectionId, Seq};
//! let scope = RuleScope {
//!     remotes: ConnectionId(Seq(5)),
//!     capability: Selector::Every,
//!     operation: Selector::Every,
//!     key: Keys::Every,
//! };
//! ```
//!
//! An organisation's starting point cannot choose to serve with nobody
//! there; only a rule the person writes does:
//!
//! ```compile_fail,E0599
//! let start = hedwig_model::policy::Attended::Unattended;
//! ```
//!
//! An organisation cannot name what a grant exposes, nor consent to write,
//! for the person: a starting grant carries neither.
//!
//! ```compile_fail,E0026
//! use hedwig_model::organisation::Start;
//! fn exposes(start: Start) -> bool {
//!     matches!(start, Start::Grant { terms, .. } if terms.acknowledged.is_empty())
//! }
//! ```
//!
//! What an organisation states enters only through the gate that reads it:
//!
//! ```compile_fail,E0451
//! use hedwig_model::organisation::Policy;
//! let policy = Policy { floors: Vec::new(), ..Policy::default() };
//! ```
//!
//! What holds a remote up is not a preference: no statement can name a held
//! request, and only a changed host key can be made to interrupt:
//!
//! ```compile_fail,E0599
//! let request = hedwig_model::setting::Condition::Request;
//! ```
//!
//! ```compile_fail,E0308
//! use hedwig_model::setting::{Heard, Volume};
//! let loud = Heard::Served(Volume::Interrupts);
//! ```
//!
//! A service of the person's own cannot be bound where the remote's `gpg`
//! looks for its agent:
//!
//! ```compile_fail,E0599
//! use hedwig_model::capability::{Offer, Query};
//! let offer = Offer::SocketAt(Query::AgentSocket);
//! ```
//!
//! A route's client is given a checked address, never text as it arrived,
//! so nothing the address check refuses can become the client's
//! destination:
//!
//! ```compile_fail,E0308
//! use hedwig_model::remote::Client;
//! fn reach(client: &Client) -> Vec<String> {
//!     client.arguments("build;calc", Vec::new())
//! }
//! ```
//!
//! An answer to a prompt has no printable form:
//!
//! ```compile_fail,E0277
//! let secret = hedwig_model::text::Secret::from("passphrase".to_owned());
//! println!("{secret}");
//! ```

#![forbid(unsafe_code)]

pub mod beyond;
pub mod capability;
pub mod config;
pub mod credential;
pub mod frame;
pub mod gate;
pub mod hold;
pub mod holder;
pub mod install;
pub mod json;
pub mod organisation;
pub mod platform;
pub mod policy;
pub mod process;
pub mod protocol;
pub mod refusal;
pub mod remote;
pub mod scope;
pub mod setting;
pub mod site;
pub mod text;
pub mod trail;
pub mod wire;
