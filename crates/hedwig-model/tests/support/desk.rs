//! A stand-in for the core: it carries requests out by appending the events
//! the model names for each, and answers from the fold. It owns no pipe, no
//! channel and no relay, so what the suites drive through it is the model and
//! the protocol alone.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hedwig_model::capability::{
    AgentAt, Exposure, KeyKind, Lends, Operation, ServicePort, Source, Stream,
};
use hedwig_model::config::{Catalogue, Configuration, Effect};
use hedwig_model::gate::{Verdict, World};
use hedwig_model::organisation::Policy;
use hedwig_model::protocol::{
    AgentKey, Answer, Decision, Lendable, Notice, Proof, Reply, Request, SerialPort, Topic,
};
use hedwig_model::refusal::Refusal;
use hedwig_model::remote::{RemoteId, Remotes};
use hedwig_model::text::{Name, Port, RemotePath, SshKey, Words};
use hedwig_model::trail::{
    Binding, ChannelEnd, ClientId, ClientKind, ConnectionId, Event, Failure, Gave, Given, Opener,
    Origin, Outcome, Readiness, RequestId, Serving,
};

use super::{Trail, name};

pub(crate) struct Desk {
    /// What ships, before the organisation's definitions are joined to it.
    pub(crate) shipped: Catalogue,
    pub(crate) catalogue: Catalogue,
    pub(crate) configuration: Configuration,
    pub(crate) trail: Trail,
    /// The answers given to prompts, as the channel's client would receive
    /// them.
    pub(crate) answered: Vec<Answer>,
    /// What the workstation holds as the core reads it, where a suite stands
    /// it up; nothing is stood up at first.
    pub(crate) held: Held,
    /// What each attached client asked for that the core keeps current for
    /// it.
    listing: BTreeMap<ClientId, BTreeSet<Topic>>,
    /// What the core told clients that did not ask, oldest first, until a
    /// suite takes it.
    told: Vec<(ClientId, Notice)>,
}

/// The workstation's side of the requests that read it: an ADB server's
/// devices and an SSH agent's keys by the capability that names each, and
/// the serial ports. A capability with nothing stood up reaches nothing that
/// answers, as the core finds where no server or agent listens.
#[derive(Debug, Clone, Default)]
pub(crate) struct Held {
    pub(crate) devices: BTreeMap<Name, Result<Vec<Lendable>, Failure>>,
    pub(crate) keys: BTreeMap<Name, Result<Vec<AgentKey>, Failure>>,
    pub(crate) ports: Vec<SerialPort>,
    /// The workstation's TPM, where a suite stands one up; `None` is a
    /// provider that does not answer.
    pub(crate) tpm: Option<Tpm>,
}

/// A TPM as the core finds it: the kinds it makes, the keys Hedwig made in
/// it with their names, and the public halves the next keys it makes will
/// have, since a stand-in makes none.
#[derive(Debug, Clone, Default)]
pub(crate) struct Tpm {
    pub(crate) kinds: BTreeSet<KeyKind>,
    pub(crate) keys: Vec<(Name, SshKey)>,
    pub(crate) next: VecDeque<SshKey>,
}

impl Desk {
    pub(crate) fn new(catalogue: Catalogue) -> Desk {
        Desk {
            shipped: catalogue.clone(),
            catalogue,
            configuration: Configuration::default(),
            trail: Trail::started(),
            answered: Vec::new(),
            held: Held::default(),
            listing: BTreeMap::new(),
            told: Vec::new(),
        }
    }

    /// The client leaves: what it listed is kept current for it no more.
    pub(crate) fn detach(&mut self, client: ClientId) {
        self.listing.remove(&client);
        self.trail.push(Event::Detached { client });
    }

    /// `capability`'s server now lists `listed`: the clients that listed its
    /// devices are each told so once, where it differs from what it listed
    /// before.
    pub(crate) fn hold_devices(
        &mut self,
        capability: &Name,
        listed: Result<Vec<Lendable>, Failure>,
    ) -> Vec<(ClientId, Notice)> {
        let unchanged = self
            .held
            .devices
            .get(capability)
            .map_or(listed == Err(Failure::Unreachable), |before| {
                *before == listed
            });
        self.held.devices.insert(capability.clone(), listed);
        self.stale(unchanged, &Topic::Devices(capability.clone()))
    }

    /// The workstation's serial ports are now `ports`: the clients that
    /// listed them are each told so once, where they differ.
    pub(crate) fn hold_ports(&mut self, ports: Vec<SerialPort>) -> Vec<(ClientId, Notice)> {
        let unchanged = self.held.ports == ports;
        self.held.ports = ports;
        self.stale(unchanged, &Topic::Ports)
    }

    fn stale(&self, unchanged: bool, topic: &Topic) -> Vec<(ClientId, Notice)> {
        if unchanged {
            return Vec::new();
        }
        self.listing
            .iter()
            .filter(|(_, listed)| listed.contains(topic))
            .map(|(client, _)| (*client, Notice::Stale(topic.clone())))
            .collect()
    }

    /// What `capability` names: an ADB server that states its port, else
    /// the core cannot list it.
    fn devices(&self, capability: &Name) -> Result<Vec<Lendable>, Refusal> {
        let found = self.configuration.capability(&self.catalogue, capability)?;
        let Source::Service {
            port: ServicePort::Fixed(_),
            stream: Stream::Adb,
            ..
        } = found.source
        else {
            return Err(Refusal::CapabilityIncomplete {
                capability: capability.clone(),
            });
        };
        let listed = self
            .held
            .devices
            .get(capability)
            .cloned()
            .unwrap_or(Err(Failure::Unreachable));
        listed.map_err(|failure| Refusal::SourceUnavailable {
            capability: capability.clone(),
            failure,
        })
    }

    /// What the core told clients that did not ask since this was last
    /// called.
    pub(crate) fn told(&mut self) -> Vec<(ClientId, Notice)> {
        std::mem::take(&mut self.told)
    }

    /// The keys `capability`'s agent holds, as the core asks it; the gate
    /// has let through only a capability whose source is an agent. The TPM's
    /// are the keys Hedwig made, each named.
    fn keys(&self, capability: &Name) -> Result<Vec<AgentKey>, Refusal> {
        if self.machine(capability) {
            let tpm = self.held.tpm.as_ref().ok_or(Refusal::SourceUnavailable {
                capability: capability.clone(),
                failure: Failure::NoTpm,
            })?;
            return Ok(tpm.keys.iter().map(made).collect());
        }
        let listed = self
            .held
            .keys
            .get(capability)
            .cloned()
            .unwrap_or(Err(Failure::Unreachable));
        listed.map_err(|failure| Refusal::SourceUnavailable {
            capability: capability.clone(),
            failure,
        })
    }

    fn machine(&self, capability: &Name) -> bool {
        matches!(
            self.configuration.capability(&self.catalogue, capability),
            Ok(found) if found.source == Source::Agent { at: AgentAt::Machine }
        )
    }

    /// Every client that lists a TPM source's keys is told they changed.
    fn keys_changed(&mut self) {
        let topics: BTreeSet<Topic> = self
            .listing
            .values()
            .flatten()
            .filter(|topic| matches!(topic, Topic::Keys(capability) if self.machine(capability)))
            .cloned()
            .collect();
        for topic in topics {
            let told = self.stale(false, &topic);
            self.told.extend(told);
        }
    }

    /// Makes a key in the stood-up TPM, as the core's TPM makes one.
    fn make(&mut self, client: ClientId, name: Name, kind: KeyKind) -> Result<Reply, Refusal> {
        let tpm = self.held.tpm.as_mut().ok_or(Refusal::NoTpm)?;
        if !tpm.kinds.contains(&kind) {
            return Err(Refusal::KindUnmade(kind));
        }
        if tpm.keys.iter().any(|(held, _)| *held == name) {
            return Err(Refusal::KeyExists(name));
        }
        let key = tpm
            .next
            .pop_front()
            .expect("the suite stood up a key to make");
        tpm.keys.push((name.clone(), key.clone()));
        self.trail.push(Event::KeyMade {
            key: key.clone(),
            name: name.clone(),
            by: client,
        });
        self.keys_changed();
        Ok(Reply::Made(made(&(name, key))))
    }

    /// Deletes a key from the stood-up TPM, after taking it out of every
    /// grant and acceptance that lends it, as the core does.
    fn delete(&mut self, client: ClientId, key: SshKey) -> Result<Reply, Refusal> {
        let tpm = self.held.tpm.as_ref().ok_or(Refusal::NoTpm)?;
        if !tpm.keys.iter().any(|(_, held)| *held == key) {
            return Err(Refusal::KeyAbsent(key));
        }
        for change in self.configuration.unlending(&key) {
            let reach = self.configuration.widens(&self.catalogue, &change);
            self.configuration
                .apply(&self.catalogue, change.clone())
                .expect("taking a key out of what lends it is always applied");
            self.trail.push(Event::Changed {
                change,
                by: client,
                reach,
            });
        }
        let tpm = self.held.tpm.as_mut().ok_or(Refusal::NoTpm)?;
        let at = tpm
            .keys
            .iter()
            .position(|(_, held)| *held == key)
            .expect("found above");
        let (name, key) = tpm.keys.remove(at);
        self.trail.push(Event::KeyDeleted {
            key,
            name,
            by: client,
        });
        self.keys_changed();
        Ok(Reply::Done(Effect::Changed))
    }

    /// The organisation's policy is read again and is now `next`: the core
    /// records what changed and decides under what ships joined with what
    /// `next` defines.
    pub(crate) fn govern(&mut self, next: &Policy) {
        for event in self.trail.state().policy().changes(next) {
            self.trail.push(event);
        }
        self.catalogue = self.shipped.under(next);
    }

    pub(crate) fn ask_world<T>(&self, ask: impl FnOnce(&World<'_>) -> T) -> T {
        let state = self.trail.state();
        ask(&World {
            catalogue: &self.catalogue,
            configuration: &self.configuration,
            state: &state,
        })
    }

    /// The greeting: the core reads the origin from the pipe, never from the
    /// client.
    pub(crate) fn greet(
        &mut self,
        protocol: u32,
        kind: ClientKind,
        origin: Origin,
    ) -> Result<(ClientId, Reply), Refusal> {
        self.greet_to(protocol, kind, origin, Remotes::Every)
    }

    /// The greeting of a client that watches only `attends`.
    pub(crate) fn greet_to(
        &mut self,
        protocol: u32,
        kind: ClientKind,
        origin: Origin,
        attends: Remotes,
    ) -> Result<(ClientId, Reply), Refusal> {
        let hello = Request::Hello {
            protocol,
            kind,
            attends: attends.clone(),
        };
        let nobody = ClientId(hedwig_model::trail::Seq(0));
        self.ask_world(|world| world.permit(nobody, &hello))?;
        let client = self.trail.attach_to(kind, origin, attends);
        Ok((
            client,
            Reply::Welcome {
                protocol,
                version: "0.2.0".to_owned(),
                you: origin,
            },
        ))
    }

    pub(crate) fn attend(&mut self, kind: ClientKind, origin: Origin) -> ClientId {
        self.greet(hedwig_model::protocol::PROTOCOL, kind, origin)
            .expect("the greeting is accepted")
            .0
    }

    /// Carries one request out, or refuses it exactly as `permit` says.
    #[allow(clippy::too_many_lines, reason = "one arm per request")]
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "the method's lifetime is early-bound, so its path is not general enough"
    )]
    pub(crate) fn send(&mut self, client: ClientId, request: Request) -> Result<Reply, Refusal> {
        self.ask_world(|world| world.permit(client, &request))?;
        let reach = self.ask_world(|world| world.widens(&request));
        if let Some(topic) = Topic::listed(&request) {
            self.listing.entry(client).or_default().insert(topic);
        }
        let now = self.trail.tick();
        let reply = match request {
            // The bundle is assembled where the process is, from replies this
            // desk gives each of; diagnostics are written there.
            Request::Hello { .. } | Request::Bundle => Reply::Done(Effect::Unchanged),
            Request::Diagnose(level) => {
                if self.trail.state().diagnose() == level {
                    Reply::Done(Effect::Unchanged)
                } else {
                    self.trail.push(Event::Diagnosed { level, by: client });
                    Reply::Done(Effect::Changed)
                }
            }
            // Only a client greeted as a channel's prompt may ask, and this
            // desk greets none: the process package's core puts prompts.
            Request::Prompt { .. } => unreachable!("the gate refuses a prompt from this desk"),
            Request::Status => Reply::Status(
                self.ask_world(|world| world.status(client, now))
                    .expect("the core has started"),
            ),
            Request::Exposure => Reply::Exposure(self.ask_world(|world| world.rows(client, now))),
            Request::Attention => {
                Reply::Attention(self.ask_world(|world| world.attention(client, now)))
            }
            Request::Catalogue => Reply::Catalogue(self.configuration.definitions(&self.catalogue)),
            Request::Workstation => Reply::Workstation(self.ask_world(|world| world.workstation())),
            Request::Export => Reply::Document(Box::new(self.configuration.export())),
            Request::Activity {
                remote,
                before,
                limit,
            } => Reply::Activity(hedwig_model::trail::page(
                // The stand-in never compacts: nothing was folded before its
                // first entry.
                &hedwig_model::trail::State::default(),
                &self.trail.entries,
                &remote,
                &self.configuration.sets(&self.catalogue),
                before,
                limit,
            )),
            Request::Follow { .. } => Reply::Done(Effect::Changed),
            Request::Devices(capability) => Reply::Devices(self.devices(&capability)?),
            Request::Keys(capability) => Reply::Keys(self.keys(&capability)?),
            Request::MakeKey { name, kind } => self.make(client, name, kind)?,
            Request::DeleteKey(key) => self.delete(client, key)?,
            Request::Ports => Reply::Ports(self.held.ports.clone()),
            Request::Withdraw => {
                if self.trail.state().withdrawn().is_none() {
                    self.trail.push(Event::Withdrawn { by: client });
                }
                Reply::Withdrawal(self.ask_world(|world| world.withdrawal()))
            }
            Request::Withdrawal => Reply::Withdrawal(self.ask_world(|world| world.withdrawal())),
            Request::Restore => {
                if self.trail.state().withdrawn().is_none() {
                    Reply::Done(Effect::Unchanged)
                } else {
                    self.trail.push(Event::Restored { by: client });
                    Reply::Done(Effect::Changed)
                }
            }

            Request::Stop => {
                self.trail.push(Event::Stopping { by: client });
                Reply::Done(Effect::Changed)
            }
            Request::Change(change) => {
                let effect = self
                    .configuration
                    .apply(&self.catalogue, change.clone())
                    .expect("permit accepted it");
                let held = self.ask_world(|world| world.held(client, Some(&change), now));
                if effect == Effect::Changed {
                    self.trail.push(Event::Changed {
                        change,
                        by: client,
                        reach,
                    });
                }
                Reply::Changed { effect, held }
            }
            Request::Import(document) => {
                self.configuration =
                    Configuration::import(&self.catalogue, *document).expect("permit accepted it");
                self.trail.push(Event::Imported { by: client, reach });
                Reply::Changed {
                    effect: Effect::Changed,
                    held: self.ask_world(|world| world.held(client, None, now)),
                }
            }
            Request::Settings { remotes } => {
                Reply::Settings(Box::new(self.ask_world(|world| world.settings(&remotes))))
            }
            Request::Try(trial) => Reply::Tried(Box::new(
                self.ask_world(|world| world.tried(client, &trial, now)),
            )),
            Request::Connect {
                remote,
                with,
                acknowledged,
                lends,
            } => {
                if self.trail.state().connection(&remote).is_some() {
                    Reply::Done(Effect::Unchanged)
                } else {
                    self.trail.push(Event::Opening {
                        remote,
                        with,
                        acknowledged,
                        lends,
                        opener: Opener::Person(client),
                    });
                    Reply::Done(Effect::Changed)
                }
            }
            Request::Disconnect { remote } => {
                let live = self.trail.state().connection(&remote).map(|(id, _)| id);
                match live {
                    Some(connection) => {
                        self.trail.push(Event::Down {
                            connection,
                            end: ChannelEnd::Closed,
                        });
                        Reply::Done(Effect::Changed)
                    }
                    None => Reply::Done(Effect::Unchanged),
                }
            }
            Request::Pause(scope) => {
                let state = self.trail.state();
                let sets = self.configuration.sets(&self.catalogue);
                let covered: Vec<ConnectionId> = state
                    .connections()
                    .filter(|(_, link)| scope.covers(&link.remote, &sets))
                    .map(|(connection, _)| connection)
                    .collect();
                self.trail.push(Event::Paused { scope, by: client });
                for connection in covered {
                    self.trail.push(Event::Down {
                        connection,
                        end: ChannelEnd::Closed,
                    });
                }
                Reply::Done(Effect::Changed)
            }
            Request::Resume(scope) => {
                self.trail.push(Event::Resumed { scope, by: client });
                Reply::Done(Effect::Changed)
            }
            Request::Decide { request, decision } => {
                let state = self.trail.state();
                let ask = state.ask(request).expect("permit found it held").clone();
                if let Some(until) = decision.until(now) {
                    self.trail.push(Event::Allowed {
                        connection: ask.connection,
                        capability: ask.capability,
                        operation: ask.operation,
                        until,
                        by: client,
                        key: ask.key,
                    });
                }
                self.trail.push(Event::Settled {
                    request,
                    outcome: match decision {
                        Decision::Once | Decision::For(_) => Outcome::Allowed(client),
                        Decision::Refuse => Outcome::Refused(Refusal::Declined),
                    },
                });
                Reply::Done(Effect::Changed)
            }
            Request::Answer { prompt, answer } => {
                let given = match answer {
                    Answer::Text(_) => Given::Text,
                    Answer::Accept => Given::Accepted,
                    Answer::Decline => Given::Declined,
                };
                self.answered.push(answer);
                self.trail.push(Event::Answered {
                    prompt,
                    by: Some(Gave { client, given }),
                });
                Reply::Done(Effect::Changed)
            }
            Request::Rule {
                connection,
                scope,
                mode,
            } => {
                self.trail.push(Event::Ruled {
                    connection,
                    scope,
                    mode,
                    by: client,
                });
                Reply::Done(Effect::Changed)
            }
            Request::PutAway(item) => {
                self.trail.push(Event::PutAway { item, by: client });
                Reply::Done(Effect::Changed)
            }
            Request::Check { remote, capability } => {
                let live = self.trail.state().connection(&remote).map(|(id, _)| id);
                if let Some(connection) = live {
                    self.trail.push(Event::Checked {
                        connection,
                        capability: capability.clone(),
                        readiness: Readiness::Ready,
                    });
                }
                Reply::Row(Box::new(self.row(client, &remote, &capability)))
            }
            Request::Exercise { remote, capability } => {
                let (connection, _) = self
                    .trail
                    .state()
                    .connection(&remote)
                    .map(|(id, link)| (id, link.remote.clone()))
                    .expect("permit found it connected");
                let operation = self
                    .configuration
                    .capability(&self.catalogue, &capability)
                    .ok()
                    .and_then(|capability| capability.dialect().operations().last().copied())
                    .expect("a granted capability");
                let (request, _) = self.asks(connection, capability.as_str(), operation);
                self.trail.push(Event::Exercised {
                    connection,
                    capability,
                    proof: Proof::Reached(request),
                    by: client,
                });
                Reply::Done(Effect::Changed)
            }
            Request::Presence(presence) => {
                self.trail.push(Event::Presence { client, presence });
                Reply::Done(Effect::Changed)
            }
            Request::Icon(icon) => {
                let said = self
                    .trail
                    .state()
                    .surface(client)
                    .and_then(|surface| surface.icon);
                if said == Some(icon) {
                    Reply::Done(Effect::Unchanged)
                } else {
                    self.trail.push(Event::Icon { client, icon });
                    Reply::Done(Effect::Changed)
                }
            }
        };
        self.strand();
        Ok(reply)
    }

    /// What was held and can no longer be put to the person is refused at
    /// once, whatever changed, as the core does after every step.
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "the method's lifetime is early-bound, so its path is not general enough"
    )]
    pub(crate) fn strand(&mut self) {
        for (request, whereabouts) in self.ask_world(|world| world.stranded()) {
            self.trail.push(Event::Settled {
                request,
                outcome: Outcome::Refused(Refusal::NobodyReachable(whereabouts)),
            });
        }
    }

    pub(crate) fn row(
        &self,
        client: ClientId,
        remote: &RemoteId,
        capability: &Name,
    ) -> hedwig_model::protocol::Row {
        let now = self.trail.tick();
        self.ask_world(|world| world.rows(client, now))
            .into_iter()
            .find(|row| row.remote.as_ref() == Some(remote) && row.capability == *capability)
            .expect("a row for the grant")
    }

    /// A remote's tool asks through a live connection. The relay records the
    /// request, then what the gate said of it.
    pub(crate) fn asks(
        &mut self,
        connection: ConnectionId,
        capability: &str,
        operation: Operation,
    ) -> (RequestId, Verdict) {
        let now = self.trail.tick();
        let verdict = self
            .ask_world(|world| world.decide(connection, &name(capability), operation, None, now));
        let request = self.trail.ask(connection, capability, operation);
        match &verdict {
            Verdict::Serve(outcome) => {
                self.trail.push(Event::Settled {
                    request,
                    outcome: outcome.clone(),
                });
            }
            Verdict::Hold(_) => {
                self.trail.push(Event::Held { request });
            }
            Verdict::Refuse(refusal) => {
                self.trail.push(Event::Settled {
                    request,
                    outcome: Outcome::Refused(refusal.clone()),
                });
            }
        }
        (request, verdict)
    }

    /// The channel the core holds for a remote comes up: the remote reports
    /// its platform, passes readiness, and the forwards the plan names are
    /// bound.
    pub(crate) fn channel_up(&mut self, remote: &RemoteId, platform: &str) -> ConnectionId {
        let live = self.trail.state().connection(remote).map(|(id, _)| id);
        let connection = live.unwrap_or_else(|| {
            ConnectionId(self.trail.push(Event::Opening {
                remote: remote.clone(),
                with: Vec::new(),
                opener: Opener::Grant,
                acknowledged: Exposure::NONE,
                lends: Lends::none(),
            }))
        });
        self.trail.push(Event::Observed {
            connection,
            platform: name(platform),
        });
        let plan = self
            .ask_world(|world| world.plan(connection))
            .expect("a plan");
        let mut serving = Vec::new();
        for (capability, form) in plan {
            if form.is_err() {
                continue;
            }
            self.trail.push(Event::Checked {
                connection,
                capability: capability.clone(),
                readiness: Readiness::Ready,
            });
            let binding = match capability.as_str() {
                "gpg" | "gpg-unrestricted" => Binding::Socket(
                    RemotePath::try_from("/run/user/2000/gnupg/S.gpg-agent").expect("a path"),
                ),
                _ => Binding::Port(Port::try_from(5037).expect("a port")),
            };
            serving.push(Serving {
                capability,
                binding,
            });
        }
        self.trail.push(Event::Up {
            connection,
            serving,
        });
        connection
    }
}

/// A key Hedwig made, as a list gives it: named by the name it was made
/// with.
fn made((name, key): &(Name, SshKey)) -> AgentKey {
    AgentKey {
        key: key.clone(),
        comment: Words::try_from(name.as_str()).ok(),
    }
}
