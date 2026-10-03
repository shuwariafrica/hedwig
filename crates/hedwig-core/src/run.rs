//! The core's one deciding thread, and the threads it keeps busy.
//!
//! Everything arrives here as a [`Message`]: a client's request, a frame
//! written, entries now on disk, an order from the supervisor. The thread
//! never waits on a pipe, a file or a client, so it is always there to answer
//! the supervisor - which is what lets the supervisor tell a core that is
//! busy from one that is stuck.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hedwig_model::config::{Catalogue, Configuration};
use hedwig_model::install::Starts;
use hedwig_model::process::{Exit, Order, Report};
use hedwig_model::protocol::FromCore;
use hedwig_model::remote::{Client, RemoteId};
use hedwig_model::setting::Keepalive;
use hedwig_model::text::{Address, Name, PipeName, Port};
use hedwig_model::trail::{
    Asking, Breakdown, ConnectionId, Entry, Origin, Peer, Store, Target, Tick, Timestamp,
};
use hedwig_model::wire::{line, read};
use hedwig_win::Signal;
use hedwig_win::endpoint::{Endpoint, owner};
use hedwig_win::token::Token;

use hedwig_model::trail::Network;
use hedwig_win::start::Environment;

use crate::adb::{Carriage, Forwarding, Forwards, Reverse, Watch};
use crate::assuan::Nonce;
use crate::channel::{
    Askpass, Channels, Exercising, Hauling, Order as Started, Placing, Setting, Surveying,
};
use crate::dispatch::{Core, Effect, Input, Keep, Knock, Link, Now, Step, Then, Told, Turn};
use crate::listing::Listings;
use crate::peer::placed;
use crate::relay::{Agents, Gnupg, Relayed, Relaying, Settle};
use crate::serve::{Out, Server, integrity};
use crate::service::Service;
use crate::store::{Kept, Opened, Places, StoreError, Trail, load, prepare, settle};
use crate::timer::Timer;

/// What the deciding thread is told.
#[derive(Debug)]
pub enum Message {
    /// A client connected; frames for it go to `outbox`.
    Opened {
        link: Link,
        outbox: Sender<Out>,
    },
    /// Something connected to the workstation end of a forward; `stream` is
    /// the connection, kept until it is admitted or turned away.
    Knocked {
        stream: TcpStream,
        connection: ConnectionId,
        capability: Name,
        peer: Option<Peer>,
    },
    Input(Input),
    /// The client that asked Hedwig to stop has been given its reply.
    Stopped,
    /// The pipe can accept no more clients.
    Broken(io::Error),
    /// What was on disk has been read.
    Loaded(Box<Result<Loaded, StoreError>>),
    /// Everything up to this ticket is on disk.
    Written(u64),
    Failed(StoreError),
    Order(Order),
    /// The supervisor's line closed, or said something that is not an order.
    Orphaned,
}

/// What the writing thread found on disk at the start of a run.
#[derive(Debug)]
pub struct Loaded {
    head: hedwig_model::trail::State,
    entries: Vec<Entry>,
    configuration: Configuration,
    unreadable: Vec<(Store, String)>,
}

/// One thing for the writing thread to put on disk.
struct Job {
    ticket: u64,
    entries: Vec<Entry>,
    keep: Option<Keep>,
    compact: Option<Box<crate::dispatch::Compaction>>,
}

/// The two clocks, read together. `tick` counts from when the core started,
/// on the clock that keeps counting while the workstation sleeps.
#[derive(Clone, Copy)]
struct Clock {
    started: Duration,
}

impl Clock {
    fn now(&self) -> Now {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ticked = hedwig_win::clock::elapsed().saturating_sub(self.started);
        Now {
            at: Timestamp(u64::try_from(since.as_millis()).unwrap_or(u64::MAX)),
            tick: Tick(u64::try_from(ticked.as_millis()).unwrap_or(u64::MAX)),
        }
    }
}

fn own_origin() -> io::Result<Origin> {
    let standing = Token::own()?.standing()?;
    Ok(Origin {
        process: std::process::id(),
        logon: standing.logon,
        session: standing.session,
        integrity: integrity(standing.integrity),
    })
}

fn pipe_name() -> io::Result<PipeName> {
    let mut drawn = [0u8; 16];
    hedwig_win::random::fill(&mut drawn)?;
    let name = format!("hedwig.{:032x}", u128::from_le_bytes(drawn));
    PipeName::try_from(name.as_str()).map_err(|error| io::Error::other(error.to_string()))
}

fn report(report: &Report) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{}", line(report));
    let _ = out.flush();
}

/// The thread that owns the files: it reads them once, then writes what it is
/// given, in order, and says when each is on disk.
fn keeper(places: &Places, at: Timestamp, jobs: Receiver<Job>, messages: &Sender<Message>) {
    let opened = Trail::open(places, at).and_then(|opened| {
        let kept = load(places, at, &opened.entries)?;
        Ok((opened, kept))
    });
    let (mut trail, loaded) = match opened {
        Err(error) => {
            let _ = messages.send(Message::Loaded(Box::new(Err(error))));
            return;
        }
        Ok((opened, kept)) => {
            let Opened {
                trail,
                head,
                entries,
                unreadable,
            } = opened;
            let mut unreadable: Vec<(Store, String)> = unreadable
                .into_iter()
                .map(|account| (Store::Trail, account))
                .collect();
            let configuration = match kept {
                Kept::Absent => Configuration::default(),
                Kept::Read(configuration) => *configuration,
                Kept::Unreadable(account) => {
                    unreadable.push((Store::Configuration, account));
                    Configuration::default()
                }
            };
            let loaded = Loaded {
                head,
                entries,
                configuration,
                unreadable,
            };
            (trail, loaded)
        }
    };
    if messages
        .send(Message::Loaded(Box::new(Ok(loaded))))
        .is_err()
    {
        return;
    }
    for job in jobs {
        // A change to the configuration is prepared, then recorded, then
        // put in place: a run that ends between any two of them is finished
        // or forgotten by the next, never left half done.
        let prepared = job
            .keep
            .as_ref()
            .map_or(Ok(()), |keep| prepare(places, &keep.document, keep.entry));
        let done = prepared
            .and_then(|()| trail.append(&job.entries))
            .and_then(|()| {
                job.keep
                    .as_ref()
                    .map_or(Ok(()), |keep| settle(places, keep.entry))
            })
            .and_then(|()| {
                job.compact.as_ref().map_or(Ok(()), |compact| {
                    if let Some((head, entries)) = &compact.trail {
                        trail.rewrite(places, head, entries)?;
                    }
                    places.forget_aside(compact.before, &compact.raised)
                })
            });
        let said = match done {
            Ok(()) => Message::Written(job.ticket),
            Err(error) => Message::Failed(error),
        };
        if messages.send(said).is_err() {
            return;
        }
    }
}

/// Reads the supervisor's orders from standard input.
fn orders(messages: &Sender<Message>) {
    for written in io::stdin().lock().lines() {
        let order = written
            .ok()
            .and_then(|written| read::<Order>(&written).ok());
        let Some(order) = order else { break };
        if messages.send(Message::Order(order)).is_err() {
            return;
        }
    }
    let _ = messages.send(Message::Orphaned);
}

/// The deciding thread's own state: what it has asked to be written, and
/// what waits on that.
struct Desk {
    core: Core,
    clock: Clock,
    jobs: Sender<Job>,
    issued: u64,
    written: u64,
    /// Effects, each with the ticket that must be on disk before it happens.
    held: VecDeque<(u64, Vec<Effect>)>,
    outboxes: BTreeMap<Link, Sender<Out>>,
    channels: Channels,
    listings: Listings,
    timer: Timer,
    /// Connections to a forward's end that are neither admitted nor turned
    /// away yet.
    knocking: BTreeMap<Knock, TcpStream>,
    knocks: u64,
    /// Where each relayed connection is told the word on what it holds.
    relays: BTreeMap<Knock, Arc<Settle>>,
    /// Each `GnuPG` source's socket file, as its own `gpgconf` last placed it.
    agents: Arc<Agents>,
    /// Every carried reverse's endpoint and carrier.
    carriage: Arc<Carriage>,
    /// Every carried forward's endpoint.
    forwards: Arc<Forwards>,
    /// Each ADB capability's watch of its server's devices.
    watches: BTreeMap<Name, Arc<Watch>>,
    /// Each carried console's endpoint: its channel, its port, and what ends
    /// its endpoint.
    consoles: BTreeMap<(RemoteId, Name, Port), Consoled>,
    /// Each carried callback's carrier: its channel and the port it listens
    /// on.
    calls: BTreeMap<Knock, (ConnectionId, Port)>,
    /// The folders a workstation tool is found in.
    search: OsString,
    /// The workstation's serial ports.
    lines: Arc<dyn crate::serial::Lines>,
    messages: Sender<Message>,
    /// Set when the client told to stop left before it could be answered.
    stopped: bool,
    /// Where the core's files are, which a bundle reads.
    places: Places,
    /// What the core writes about what went wrong.
    diagnostics: crate::diagnostics::Diagnostics,
    /// Faults met before the run's level was known, written once it is.
    early: Vec<Early>,
}

/// A fault met before the run's diagnostics level was set: when, what met
/// it, and what Windows said.
type Early = (Timestamp, &'static str, String);

/// A carried console's channel, the endpoint its carrier forwards to, and
/// what ends that endpoint.
type Consoled = (ConnectionId, Port, Arc<Signal>);

/// What a served callback's carrier is started with.
struct Calling {
    knock: Knock,
    connection: ConnectionId,
    client: Client,
    address: Address,
    target: Target,
    asking: Asking,
    keepalive: Keepalive,
}

impl Desk {
    /// The deciding thread's desk, and the pipe's name, drawn now so that a
    /// channel's client is given it the moment it starts; the pipe itself is
    /// made once the run's first entries are on disk, before anything they
    /// lead to happens.
    fn new(
        core: Core,
        clock: &Clock,
        jobs: &Sender<Job>,
        messages: &Sender<Message>,
        lines: Arc<dyn crate::serial::Lines>,
        places: Places,
        early: Vec<Early>,
    ) -> io::Result<(Desk, PipeName)> {
        let pipe = pipe_name()?;
        let askpass = Askpass {
            program: std::env::current_exe()?,
            pipe: pipe.clone(),
        };
        let timer = {
            let (clock, messages) = (*clock, messages.clone());
            Timer::start(
                move || clock.now().tick,
                move || {
                    let _ = messages.send(Message::Input(Input::Due));
                },
            )
        };
        let setting = Setting::own(&askpass);
        let diagnostics = crate::diagnostics::Diagnostics::start(places.folder());
        let search = setting.search.clone();
        let listings = Listings::new(setting.search.clone(), Environment::own(), messages.clone());
        let desk = Desk {
            core,
            clock: *clock,
            jobs: jobs.clone(),
            issued: 0,
            written: 0,
            held: VecDeque::new(),
            outboxes: BTreeMap::new(),
            channels: Channels::new(setting, messages.clone()).diagnosed(diagnostics.clone()),
            listings,
            timer,
            knocking: BTreeMap::new(),
            knocks: 0,
            relays: BTreeMap::new(),
            carriage: Arc::new(Carriage::default()),
            forwards: Arc::new(Forwards::default()),
            watches: BTreeMap::new(),
            consoles: BTreeMap::new(),
            calls: BTreeMap::new(),
            agents: Arc::new(Agents::default()),
            search,
            lines,
            messages: messages.clone(),
            stopped: false,
            places,
            diagnostics,
            early,
        };
        Ok((desk, pipe))
    }

    /// Takes a step's entries to the writing thread and holds its effects
    /// until they are on disk, behind every effect already held.
    fn take(&mut self, step: Step) {
        let Step {
            entries,
            keep,
            compact,
            effects,
        } = step;
        if !entries.is_empty() || keep.is_some() || compact.is_some() {
            self.issued += 1;
            let _ = self.jobs.send(Job {
                ticket: self.issued,
                entries,
                keep,
                compact,
            });
        }
        self.held.push_back((self.issued, effects));
        self.release();
        self.timer.set(self.core.due());
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one arm per effect, each handed to what carries it out"
    )]
    fn release(&mut self) {
        while self
            .held
            .front()
            .is_some_and(|(ticket, _)| *ticket <= self.written)
        {
            let Some((_, effects)) = self.held.pop_front() else {
                break;
            };
            for effect in effects {
                match effect {
                    Effect::Send { link, frame, then } => self.send(link, &frame, then),
                    Effect::Survey {
                        connection,
                        client,
                        address,
                        dialect,
                        plan,
                        asking,
                        keepalive,
                    } => self.channels.survey(Surveying {
                        connection,
                        client,
                        address,
                        dialect,
                        plan,
                        asking,
                        keepalive,
                    }),
                    Effect::Exercise {
                        connection,
                        client,
                        address,
                        dialect,
                        query,
                        binding,
                        asking,
                        keepalive,
                        ..
                    } => self.channels.exercise(Exercising {
                        connection,
                        client,
                        address,
                        dialect,
                        query,
                        binding,
                        asking,
                        keepalive,
                    }),
                    Effect::Start {
                        connection,
                        client,
                        address,
                        serving,
                        asking,
                        keepalive,
                    } => self.channels.start(Started {
                        connection,
                        client,
                        address,
                        serving,
                        asking,
                        keepalive,
                    }),
                    Effect::End { connection } => {
                        self.channels.end(connection);
                        // A console's carrier ended with the channel's job, and
                        // its endpoint with it.
                        self.consoles.retain(|_, (held, _, stop)| {
                            let keep = *held != connection;
                            if !keep {
                                let _ = stop.raise();
                            }
                            keep
                        });
                    }
                    Effect::Seal { connection } => self.channels.seal(connection),
                    Effect::List { route, lister } => self.listings.list(route, lister),
                    Effect::Unlist { route } => self.listings.end(&route),
                    Effect::Relay {
                        knock,
                        source,
                        presents,
                        capability,
                        ..
                    } => self.relay(knock, &capability, source, presents),
                    Effect::Settle { knock, verdict } => {
                        if let Some(relay) = self.relays.get(&knock) {
                            relay.settle(verdict);
                        }
                    }
                    Effect::Interact { knock } => {
                        if let Some(relay) = self.relays.get(&knock) {
                            relay.interact(hedwig_model::gate::Interaction::Allowed);
                        }
                    }
                    Effect::Refuse { knock } => {
                        self.knocking.remove(&knock);
                    }
                    Effect::Read {
                        connection,
                        sources,
                    } => self.read(connection, sources),
                    Effect::Cards {
                        connection,
                        sources,
                    } => self.read_cards(connection, sources),
                    reversing @ (Effect::Endpoint { .. }
                    | Effect::Withhold { .. }
                    | Effect::Haul { .. }) => self.reversing(reversing),
                    calling @ (Effect::Call { .. } | Effect::Uncall { .. }) => {
                        self.calling(calling);
                    }
                    forwarding @ (Effect::Place { .. }
                    | Effect::Replace { .. }
                    | Effect::Listen { .. }
                    | Effect::Unplace { .. }
                    | Effect::Unlisten { .. }) => self.forwarding(forwarding),
                    Effect::Relend { knock, lending } => {
                        if let Some(relay) = self.relays.get(&knock) {
                            relay.relend(lending);
                        }
                    }
                    Effect::Watch { capability, server } => {
                        self.watch(&capability, server).ensure();
                    }
                    Effect::Unwatch { capability } => {
                        if let Some(watch) = self.watches.remove(&capability) {
                            watch.end();
                        }
                    }
                    Effect::Bundle { link, id, bundle } => {
                        let (places, messages) = (self.places.clone(), self.messages.clone());
                        thread::spawn(move || {
                            let bundle = Box::new(completed(*bundle, &places));
                            let _ =
                                messages.send(Message::Input(Input::Bundled { link, id, bundle }));
                        });
                    }
                    Effect::Diagnose(level) => {
                        self.diagnostics.set(level);
                        for (at, from, said) in self.early.drain(..) {
                            self.diagnostics.fault(at, from, &said);
                        }
                    }
                    Effect::Startup { hedwig, icon } => {
                        let found = match std::env::current_exe() {
                            Ok(program) => {
                                let folder = program.parent().unwrap_or(&program);
                                crate::startup::keep(&self.places.names(), folder, hedwig, icon)
                                    .map(|(starts, kept)| {
                                        (starts, kept.unwrap_or_else(|error| error.found()))
                                    })
                            }
                            Err(error) => {
                                let found = crate::startup::StartupError::Program(error).found();
                                Starts::ALL.map(|starts| (starts, found.clone()))
                            }
                        };
                        let _ = self.messages.send(Message::Input(Input::Startup(found)));
                    }
                    Effect::Ports { asked } => {
                        let (lines, messages) = (Arc::clone(&self.lines), self.messages.clone());
                        thread::spawn(move || {
                            let ports = lines.list();
                            let _ = messages.send(Message::Input(Input::Ports { asked, ports }));
                        });
                    }
                    Effect::Keys {
                        link,
                        id,
                        capability,
                        at,
                    } => {
                        let messages = self.messages.clone();
                        thread::spawn(move || {
                            let listed = Input::Keys {
                                link,
                                id,
                                capability,
                                listed: crate::ssh::keys(&at),
                            };
                            let _ = messages.send(Message::Input(listed));
                        });
                    }
                    // A TPM takes from a tenth of a second to a second to
                    // make, find or delete a key; none of it is on this
                    // thread.
                    Effect::MakeKey {
                        link,
                        id,
                        name,
                        kind,
                    } => {
                        let messages = self.messages.clone();
                        thread::spawn(move || {
                            let made = crate::machine::make(&name, kind);
                            let made = Input::Made {
                                link,
                                id,
                                name,
                                made,
                            };
                            let _ = messages.send(Message::Input(made));
                        });
                    }
                    Effect::FindKey { link, id, key } => {
                        let messages = self.messages.clone();
                        thread::spawn(move || {
                            let found = crate::machine::find(&key);
                            let found = Input::Found {
                                link,
                                id,
                                key,
                                found,
                            };
                            let _ = messages.send(Message::Input(found));
                        });
                    }
                    Effect::DeleteKey {
                        link,
                        id,
                        name,
                        key,
                    } => {
                        let messages = self.messages.clone();
                        thread::spawn(move || {
                            let deleted = crate::machine::delete(&name, &key);
                            let deleted = Input::Deleted {
                                link,
                                id,
                                name,
                                key,
                                deleted,
                            };
                            let _ = messages.send(Message::Input(deleted));
                        });
                    }
                    Effect::Lend {
                        link,
                        id,
                        capability,
                        server,
                    } => {
                        let watch = self.watch(&capability, server);
                        let messages = self.messages.clone();
                        // The tracker is held while the client lists the
                        // devices, so a change reaches it.
                        thread::spawn(move || {
                            watch.ensure();
                            let view = watch.view();
                            let listed = Input::Lendable {
                                link,
                                id,
                                capability,
                                view,
                            };
                            let _ = messages.send(Message::Input(listed));
                        });
                    }
                    consoling @ (Effect::Console { .. } | Effect::Unconsole { .. }) => {
                        self.consoling(consoling);
                    }
                }
            }
        }
    }

    /// Hands an admitted connection to what carries it, which tells the
    /// deciding thread what it asks and is told the word on it.
    fn relay(
        &mut self,
        knock: Knock,
        capability: &Name,
        source: Relaying,
        presents: Option<[u8; 16]>,
    ) {
        let Some(stream) = self.knocking.remove(&knock) else {
            return;
        };
        let messages = self.messages.clone();
        let tell = move |relayed| {
            let relayed = Input::Relayed { knock, relayed };
            let _ = messages.send(Message::Input(relayed));
        };
        let settle = match source {
            Relaying::Gnupg(source) => {
                let presents = presents.map(Nonce::new);
                let agents = Arc::clone(&self.agents);
                crate::relay::carry(stream, presents, source, agents, tell)
            }
            Relaying::Service(service) => crate::service::carry(stream, service, tell),
            Relaying::Adb {
                service,
                carried,
                lending,
            } => {
                let watch = self.watch(capability, service.clone());
                crate::adb::carry(stream, service, carried, lending, watch, tell)
            }
            Relaying::Serial(serial) => {
                crate::serial::carry(stream, serial, Arc::clone(&self.lines), tell)
            }
            Relaying::Agent(agent) => crate::ssh::carry(stream, agent, tell),
            Relaying::Credential(credential) => crate::credential::carry(
                stream,
                credential,
                self.search.clone(),
                Environment::own(),
                tell,
            ),
            Relaying::Notify => crate::notify::carry(stream, tell),
            Relaying::Browse(browse) => crate::browse::carry(
                stream,
                browse,
                self.search.clone(),
                crate::browse::EXPIRY,
                self.channels.jobs(),
                tell,
            ),
        };
        self.relays.insert(knock, settle);
    }

    /// What carries a reverse a remote asked for: its endpoint, its refusal,
    /// or its carrier.
    fn reversing(&mut self, effect: Effect) {
        match effect {
            Effect::Endpoint {
                knock,
                reverse,
                server,
            } => {
                let jobs = self.channels.jobs();
                let endpoint = self.carriage.endpoint(reverse, server, &jobs);
                if let Some(relay) = self.relays.get(&knock) {
                    relay.carry(endpoint.map_err(|_| None));
                }
            }
            Effect::Withhold { knock, withheld } => {
                if let Some(relay) = self.relays.get(&knock) {
                    relay.carry(Err(Some(withheld)));
                }
            }
            Effect::Haul {
                connection,
                reverse,
                client,
                address,
                asking,
                keepalive,
            } => self.haul(connection, reverse, client, address, asking, keepalive),
            _ => {}
        }
    }

    /// Starts the carrier of the endpoint of `reverse` in `connection`'s
    /// channel, unless it is there already, on a workstation port drawn now.
    fn haul(
        &mut self,
        connection: ConnectionId,
        reverse: Reverse,
        client: Client,
        address: Address,
        asking: Asking,
        keepalive: Keepalive,
    ) {
        if self.carriage.hauled(&reverse, connection) {
            return;
        }
        // The port is the system's choice, released for the carrier to bind;
        // a process that took it meanwhile is never let carry, as the
        // endpoint admits only a listener in the channel's job.
        let Some(listen) = Endpoint::bind()
            .ok()
            .and_then(|drawn| Port::try_from(drawn.port()).ok())
        else {
            return;
        };
        self.carriage.haul(&reverse, connection, listen);
        self.channels.haul(Hauling {
            connection,
            client,
            address,
            target: reverse.target,
            listen,
            asking,
            keepalive,
        });
    }

    /// The watch of `capability`'s server, made now where it has none; each
    /// listing it reads is told to the deciding thread.
    fn watch(&mut self, capability: &Name, server: Service) -> Arc<Watch> {
        let messages = self.messages.clone();
        let named = capability.clone();
        Arc::clone(self.watches.entry(capability.clone()).or_insert_with(|| {
            Watch::new(server, move |view| {
                let devices = Input::Devices {
                    capability: named.clone(),
                    view: view.clone(),
                };
                let _ = messages.send(Message::Input(devices));
            })
        }))
    }

    /// What carries a forward a remote asked for: its carrier placed on the
    /// remote, placed again, the server's listener it goes on to, its end, or
    /// the server's own forward removed.
    fn forwarding(&mut self, effect: Effect) {
        match effect {
            Effect::Place {
                knock,
                remote,
                capability,
                port,
                server,
                carrier,
            } => {
                let Some(relay) = self.relays.get(&knock).cloned() else {
                    return;
                };
                let jobs = self.channels.jobs();
                let Ok((listening, endpoint)) = self.forwards.bind(server, &jobs) else {
                    relay.place(Err("the workstation could not bind an endpoint".to_owned()));
                    return;
                };
                let forwards = Arc::clone(&self.forwards);
                let connection = carrier.connection;
                self.channels.place(
                    Placing {
                        connection,
                        client: carrier.client,
                        address: carrier.address,
                        port,
                        listen: endpoint,
                        asking: carrier.asking,
                        keepalive: carrier.keepalive,
                    },
                    move |placed| {
                        if let Ok(port) = placed {
                            let forwarding = Forwarding {
                                remote,
                                capability,
                                port,
                            };
                            forwards.keep(forwarding.clone(), listening);
                            forwards.haul(&forwarding, connection);
                        } else {
                            listening.end();
                        }
                        relay.place(placed);
                    },
                );
            }
            Effect::Replace {
                forwarding,
                server: _,
                carrier,
            } => {
                let Some(endpoint) = self.forwards.endpoint_of(&forwarding) else {
                    return;
                };
                self.forwards.haul(&forwarding, carrier.connection);
                let messages = self.messages.clone();
                self.channels.place(
                    Placing {
                        connection: carrier.connection,
                        client: carrier.client,
                        address: carrier.address,
                        port: forwarding.port.number(),
                        listen: endpoint,
                        asking: carrier.asking,
                        keepalive: carrier.keepalive,
                    },
                    move |placed| {
                        if placed.is_err() {
                            let retaken = Input::Retaken { forwarding };
                            let _ = messages.send(Message::Input(retaken));
                        }
                    },
                );
            }
            Effect::Listen {
                forwarding,
                listener,
            } => self.forwards.listen(&forwarding, Some(listener)),
            Effect::Unplace {
                connection,
                forwarding,
            } => {
                if let Some(endpoint) = self.forwards.release(&forwarding) {
                    self.channels.unhaul(connection, endpoint);
                }
            }
            Effect::Unlisten {
                server,
                id,
                listener,
            } => {
                thread::spawn(move || crate::adb::unlisten(&server, id, listener));
            }
            _ => {}
        }
    }

    /// What carries a lent emulator's console: its endpoint and carrier, or
    /// their end.
    fn consoling(&mut self, effect: Effect) {
        match effect {
            Effect::Console {
                remote,
                capability,
                port,
                device,
                network,
                carrier,
            } => {
                let key = (remote, capability.clone(), port);
                if self.consoles.contains_key(&key) {
                    return;
                }
                let made = Endpoint::bind().and_then(|bound| {
                    let endpoint = Port::try_from(bound.port()).map_err(io::Error::other)?;
                    Ok((bound, endpoint, Signal::new()?))
                });
                let Ok((bound, endpoint, stop)) = made else {
                    let (remote, capability, port) = key;
                    let unmade = Input::Unconsoled {
                        remote,
                        capability,
                        port,
                    };
                    let _ = self.messages.send(Message::Input(unmade));
                    return;
                };
                let stop = Arc::new(stop);
                let connection = carrier.connection;
                self.consoles
                    .insert(key.clone(), (connection, endpoint, Arc::clone(&stop)));
                let (jobs, messages) = (self.channels.jobs(), self.messages.clone());
                {
                    let (stop, capability) = (Arc::clone(&stop), capability.clone());
                    thread::spawn(move || {
                        while let Ok(Some(stream)) = bound.accept(&stop) {
                            // Only the carrier, in the remote's channel's job,
                            // is carried on to the console.
                            let ours = owner(&stream).ok().flatten().is_some_and(|process| {
                                placed(process, &jobs).1 == Some(connection)
                            });
                            if !ours {
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                continue;
                            }
                            let (messages, capability) = (messages.clone(), capability.clone());
                            crate::console::carry(stream, port, network, move |_command| {
                                let withheld = Input::Hosted {
                                    connection,
                                    capability: capability.clone(),
                                };
                                let _ = messages.send(Message::Input(withheld));
                            });
                        }
                    });
                }
                let messages = self.messages.clone();
                self.channels.place(
                    Placing {
                        connection,
                        client: carrier.client,
                        address: carrier.address,
                        port: port.number(),
                        listen: endpoint,
                        asking: carrier.asking,
                        keepalive: carrier.keepalive,
                    },
                    move |placed| {
                        let told = match placed {
                            Ok(_) => Input::Consoled {
                                connection,
                                capability,
                                carriage: hedwig_model::trail::Carriage::Console { port, device },
                                endpoint,
                            },
                            Err(_) => Input::Unconsoled {
                                remote: key.0,
                                capability,
                                port,
                            },
                        };
                        let _ = messages.send(Message::Input(told));
                    },
                );
            }
            Effect::Unconsole {
                connection,
                remote,
                capability,
                port,
            } => {
                if let Some((_, endpoint, stop)) = self.consoles.remove(&(remote, capability, port))
                {
                    let _ = stop.raise();
                    self.channels.unhaul(connection, endpoint);
                }
            }
            _ => {}
        }
    }

    /// What carries a served callback: its carrier, or its end.
    fn calling(&mut self, effect: Effect) {
        match effect {
            Effect::Call {
                knock,
                connection,
                client,
                address,
                target,
                asking,
                keepalive,
            } => self.call(Calling {
                knock,
                connection,
                client,
                address,
                target,
                asking,
                keepalive,
            }),
            Effect::Uncall { knock } => self.uncall(knock),
            _ => {}
        }
    }

    /// Starts the carrier of a served callback in its channel, on a
    /// workstation port drawn now, and tells the relay where it listens.
    fn call(&mut self, order: Calling) {
        let Some(listen) = Endpoint::bind()
            .ok()
            .and_then(|drawn| Port::try_from(drawn.port()).ok())
        else {
            return;
        };
        self.calls.insert(order.knock, (order.connection, listen));
        self.channels.haul(Hauling {
            connection: order.connection,
            client: order.client,
            address: order.address,
            target: order.target,
            listen,
            asking: order.asking,
            keepalive: order.keepalive,
        });
        if let Some(relay) = self.relays.get(&order.knock) {
            relay.call(order.connection, listen);
        }
    }

    /// Stops a carried callback: its relay, and its carrier, leaving the rest
    /// of the channel's job running.
    fn uncall(&mut self, knock: Knock) {
        if let Some(relay) = self.relays.get(&knock) {
            relay.stop();
        }
        if let Some((connection, listen)) = self.calls.remove(&knock) {
            self.channels.unhaul(connection, listen);
        }
    }

    /// Reads what each source offers, on a thread of its own.
    fn read(&self, connection: ConnectionId, sources: Vec<(Name, Gnupg)>) {
        let (messages, search) = (self.messages.clone(), self.search.clone());
        let agents = Arc::clone(&self.agents);
        thread::spawn(move || {
            let read = sources
                .into_iter()
                .map(|(capability, source)| {
                    (capability, crate::keys::read(&agents, &source, &search))
                })
                .collect();
            let told = Told::Read { read };
            let _ = messages.send(Message::Input(Input::Channel { connection, told }));
        });
    }

    /// Reads the cards alone each source's scdaemon holds, on a thread of its
    /// own.
    fn read_cards(&self, connection: ConnectionId, sources: Vec<(Name, Gnupg)>) {
        let messages = self.messages.clone();
        let agents = Arc::clone(&self.agents);
        thread::spawn(move || {
            let read = sources
                .into_iter()
                .map(|(capability, source)| (capability, crate::keys::read_cards(&agents, &source)))
                .collect();
            let told = Told::Cards { read };
            let _ = messages.send(Message::Input(Input::Channel { connection, told }));
        });
    }

    /// Keeps a connection to a forward's end until the core has said what
    /// becomes of it, and asks.
    fn knocked(
        &mut self,
        stream: TcpStream,
        connection: ConnectionId,
        capability: Name,
        peer: Option<Peer>,
    ) {
        self.knocks += 1;
        let knock = Knock(self.knocks);
        self.knocking.insert(knock, stream);
        let knocked = Input::Knocked {
            knock,
            connection,
            capability,
            peer,
        };
        let step = self.core.step(knocked, self.clock.now());
        self.take(step);
    }

    fn send(&mut self, link: Link, frame: &FromCore, then: Then) {
        let text = line(frame);
        let last = matches!(then, Then::Close | Then::Stop);
        let sent = self
            .outboxes
            .get(&link)
            .is_some_and(|outbox| outbox.send(Out { text, then }).is_ok());
        if last {
            self.outboxes.remove(&link);
        }
        if !sent && then == Then::Stop {
            self.stopped = true;
        }
    }
}

/// Runs the core until it is stopped or cannot go on, on the workstation's
/// own serial ports.
pub fn run(places: Places, version: &str) -> Exit {
    run_on(places, version, Arc::new(crate::serial::Windows))
}

/// Runs the core on the serial ports `lines` gives.
pub fn run_on(places: Places, version: &str, lines: Arc<dyn crate::serial::Lines>) -> Exit {
    hedwig_win::process::quieten();
    hedwig_win::process::seal();
    let clock = Clock {
        started: hedwig_win::clock::elapsed(),
    };
    let (messages, inbox) = mpsc::channel();
    {
        let messages = messages.clone();
        thread::spawn(move || orders(&messages));
    }
    let Ok(Message::Order(Order::Begin { after })) = inbox.recv() else {
        return Exit::Link;
    };
    let mut early = Vec::new();
    {
        // Told on a thread of the system's, which does no more than pass the
        // word on. A core that cannot be told still runs; its trail then
        // shows a gap where it would have shown a sleep.
        let messages = messages.clone();
        let watched = hedwig_win::power::watch(move |turn| {
            let turn = match turn {
                hedwig_win::power::Turn::Sleeping => Turn::Sleeping,
                hedwig_win::power::Turn::Woke => Turn::Woke,
            };
            let _ = messages.send(Message::Input(Input::Turned(turn)));
        });
        if let Err(error) = watched {
            early.push((clock.now().at, "power", error.to_string()));
        }
    }
    {
        // Likewise: a core that cannot be told still runs, and a lost
        // channel waits out its pace however soon the network returns.
        let messages = messages.clone();
        let watched = hedwig_win::network::watch(move |reach| {
            let network = match reach {
                hedwig_win::network::Reach::Some => Network::Online,
                hedwig_win::network::Reach::None => Network::Offline,
            };
            let _ = messages.send(Message::Input(Input::Network(network)));
        });
        if let Err(error) = watched {
            early.push((clock.now().at, "network", error.to_string()));
        }
    }
    {
        // A core that cannot be told lists the ports afresh only when asked.
        let messages = messages.clone();
        lines.watch(Box::new(move || {
            let _ = messages.send(Message::Input(Input::PortsMoved));
        }));
    }
    let catalogue = match Catalogue::shipped() {
        Ok(catalogue) => catalogue,
        Err(error) => return fail(Exit::Usage, &error.to_string()),
    };
    let (jobs, queued) = mpsc::channel();
    let kept = places.clone();
    {
        let (messages, at) = (messages.clone(), clock.now().at);
        thread::spawn(move || keeper(&kept, at, queued, &messages));
    }
    serve(
        &inbox, &messages, catalogue, &clock, &jobs, after, version, lines, places, early,
    )
}

/// A bundle with what is on disk and the program's own facts added: the
/// diagnostics files' lines, the files set aside, the folder the program runs
/// from, and Windows' version as its own `kernel32.dll` states it. What
/// cannot be read is left out and the rest still sent.
fn completed(
    mut bundle: hedwig_model::protocol::Bundle,
    places: &Places,
) -> hedwig_model::protocol::Bundle {
    bundle.program = std::env::current_exe()
        .ok()
        .and_then(|program| program.parent().map(|folder| folder.display().to_string()))
        .unwrap_or_default();
    bundle.windows = hedwig_win::folder::system()
        .ok()
        .and_then(|system| hedwig_win::version::release(&system.join("kernel32.dll")).ok())
        .flatten()
        .map(|[major, minor, build, revision]| format!("{major}.{minor}.{build}.{revision}"))
        .unwrap_or_default();
    bundle.diagnostics = crate::diagnostics::lines(places.folder());
    bundle.set_aside = places
        .set_aside()
        .unwrap_or_default()
        .into_iter()
        .map(|(path, _, at, bytes)| hedwig_model::protocol::SetAside {
            name: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            bytes,
            at,
        })
        .collect();
    bundle
}

fn fail(exit: Exit, account: &str) -> Exit {
    eprintln!("{account}");
    exit
}

#[allow(
    clippy::too_many_arguments,
    reason = "the run's one loop, given everything the run starts with"
)]
fn serve(
    inbox: &Receiver<Message>,
    messages: &Sender<Message>,
    catalogue: Catalogue,
    clock: &Clock,
    jobs: &Sender<Job>,
    after: Option<Breakdown>,
    version: &str,
    lines: Arc<dyn crate::serial::Lines>,
    places: Places,
    early: Vec<Early>,
) -> Exit {
    // Until the files are read there is no core to ask, and the supervisor is
    // answered all the same.
    // Windows says whether a network is reached as soon as it is asked,
    // which can be before the trail is read: the last it said is kept for
    // the core.
    let mut network = None;
    let loaded = loop {
        match inbox.recv() {
            Ok(Message::Loaded(loaded)) => break *loaded,
            Ok(Message::Order(Order::Ping)) => report(&Report::Pong),
            Ok(Message::Input(Input::Network(said))) => network = Some(said),
            // A sleep before there is a trail to say it in.
            Ok(Message::Order(Order::Begin { .. }) | Message::Input(Input::Turned(_))) => {}
            _ => return Exit::Link,
        }
    };
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(error) => return fail(Exit::Storage, &error.to_string()),
    };
    let origin = match own_origin() {
        Ok(origin) => origin,
        Err(error) => return fail(Exit::Pipe, &error.to_string()),
    };
    let core = Core::resume(
        catalogue,
        loaded.configuration,
        loaded.head,
        loaded.entries,
        version.to_owned(),
    );
    let (mut desk, pipe) = match Desk::new(core, clock, jobs, messages, lines, places, early) {
        Ok(made) => made,
        Err(error) => return fail(Exit::Pipe, &error.to_string()),
    };
    let begun = desk
        .core
        .begin(origin, after, loaded.unreadable, desk.clock.now());
    desk.take(begun);
    if let Some(network) = network {
        let step = desk.core.step(Input::Network(network), desk.clock.now());
        desk.take(step);
    }

    let mut server = None;
    loop {
        let Ok(message) = inbox.recv() else {
            return Exit::Link;
        };
        match message {
            Message::Order(Order::Ping) => report(&Report::Pong),
            Message::Order(Order::Begin { .. }) | Message::Loaded(_) => {}
            Message::Orphaned => return Exit::Link,
            Message::Failed(error) => return fail(Exit::Storage, &error.to_string()),
            Message::Broken(error) => return fail(Exit::Pipe, &error.to_string()),
            Message::Stopped => return Exit::Stopped,
            Message::Written(ticket) => {
                desk.written = ticket;
                // The run's first entries are on disk: the core may be found,
                // and a channel they lead to can ask through the pipe.
                if server.is_none() {
                    let listening = Token::own()
                        .and_then(|token| token.user())
                        .and_then(|owner| {
                            let jobs = desk.channels.jobs();
                            Server::listen(&pipe, &owner, jobs, messages.clone())
                        });
                    match listening {
                        Ok(listening) => {
                            server = Some(listening);
                            report(&Report::Ready { pipe: pipe.clone() });
                        }
                        Err(error) => return fail(Exit::Pipe, &error.to_string()),
                    }
                }
                desk.release();
            }
            Message::Opened { link, outbox } => {
                desk.outboxes.insert(link, outbox);
            }
            Message::Knocked {
                stream,
                connection,
                capability,
                peer,
            } => desk.knocked(stream, connection, capability, peer),
            Message::Input(input) => {
                if let Input::Left { link } = &input {
                    desk.outboxes.remove(link);
                }
                if let Input::Relayed {
                    knock,
                    relayed: Relayed::Ended,
                } = &input
                {
                    desk.relays.remove(knock);
                }
                let step = desk.core.step(input, desk.clock.now());
                desk.take(step);
            }
        }
        if desk.stopped {
            return Exit::Stopped;
        }
    }
}
