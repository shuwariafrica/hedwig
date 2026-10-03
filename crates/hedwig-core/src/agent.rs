//! The OpenSSH agent protocol between a remote's client and the person's own
//! agent, as the relay carries it (RFC 9987; OpenSSH's `PROTOCOL.agent`).
//!
//! The relay answers two requests itself and carries one. A remote asking
//! which keys there are is told the keys its grant lends, from the grant,
//! with nothing sent to the agent; where the grant lends every key, the
//! agent is asked and its answer passed on. A signature is read for its key,
//! which must be lent, and for what it signs - a login to a host, told apart
//! from an `SSHSIG` signature as OpenSSH's own agent tells them apart
//! (`ssh-agent.c`, `parse_userauth_request`, `parse_sshsig_request`) - and
//! held for a decision; served, it goes to the agent unchanged and the
//! agent's answer comes back unchanged. Everything else - adding, removing
//! or locking keys, smartcards, extensions - is answered with a failure and
//! never reaches the agent.
//!
//! Everything here is a function of the bytes given to it.

use std::fmt;

use hedwig_model::capability::{Lends, LentKey, Operation, Toward};
use hedwig_model::refusal::Withheld;
use hedwig_model::text::{SshKey, Words, ssh_string};
use hedwig_model::trail::Payload;

/// The longest message either end may send, its length field aside: what
/// OpenSSH's agent accepts (`ssh-agent.c` `AGENT_MAX_LEN`).
pub const LIMIT: usize = 256 * 1024;

/// `SSH_AGENT_FAILURE`, framed: how an agent says no.
pub const FAILURE: [u8; 5] = [0, 0, 0, 1, 5];

const FAILED: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;
/// `SSH2_AGENT_FAILURE`, which some agents answer with.
const FAILED_TOO: u8 = 30;
/// The message types that add, remove or lock keys, load a smartcard, or
/// reach an extension: `authfd.h`, 17 to 27.
const MANAGING: std::ops::RangeInclusive<u8> = 17..=EXTENSION;
/// A user authentication request (RFC 4252 section 7).
const USERAUTH_REQUEST: u8 = 50;
const HOSTBOUND: &[u8] = b"publickey-hostbound-v00@openssh.com";
const SESSION_BIND: &[u8] = b"session-bind@openssh.com";

/// Which end of the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Side {
    Client,
    Agent,
}

/// Why the relay stopped carrying a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Breach {
    /// A message longer than [`LIMIT`], or bytes piling up past one.
    TooLong(Side),
    /// A message of no bytes, which has no type.
    Empty(Side),
    /// A signature request that is not one: fields missing or left over, or
    /// a key blob that is no key.
    Malformed,
    /// The agent wrote when nothing was asked of it, or more than one answer.
    OutOfTurn,
    /// The agent answered with a message no agent answers that request with.
    NotAnswer,
    /// The end closed in the middle of a message.
    Cut(Side),
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = |side: &Side| match side {
            Side::Client => "the remote",
            Side::Agent => "the agent",
        };
        match self {
            Breach::TooLong(at) => write!(
                f,
                "{} sent a message longer than an SSH agent accepts",
                side(at)
            ),
            Breach::Empty(at) => write!(f, "{} sent an empty message", side(at)),
            Breach::Malformed => f.write_str("the remote sent a signature request that is not one"),
            Breach::OutOfTurn => f.write_str("the agent spoke out of turn"),
            Breach::NotAnswer => f.write_str("the agent sent an answer no agent gives"),
            Breach::Cut(at) => write!(f, "{} closed in the middle of a message", side(at)),
        }
    }
}

/// A signature the conversation holds for a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub operation: Operation,
    pub key: SshKey,
    pub payload: Payload,
}

/// What the relay does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    ToClient(Vec<u8>),
    /// One request for the agent, framed; its one answer comes back through
    /// [`Conversation::from_agent`].
    ToAgent(Vec<u8>),
    /// Hold the conversation until [`Conversation::serve`] or
    /// [`Conversation::refuse`].
    Ask(Ask),
    /// A request answered with a failure at the relay, and why.
    Withheld(Withheld),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Identities,
    Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Turn {
    /// The client's next message is read.
    Idle,
    /// A signature waits for a decision; its message, framed.
    Held(Vec<u8>),
    /// A request is with the agent.
    WithAgent(Expect),
}

/// One relayed connection's conversation.
#[derive(Debug)]
pub struct Conversation {
    turn: Turn,
    lends: Lends,
    client: Vec<u8>,
    agent: Vec<u8>,
}

/// The message at the start of `buffer`, framed, taken out of it; `None`
/// while it has not all arrived.
fn message(buffer: &mut Vec<u8>, side: Side) -> Result<Option<Vec<u8>>, Breach> {
    let Some(length) = buffer.first_chunk::<4>() else {
        return Ok(None);
    };
    let length = usize::try_from(u32::from_be_bytes(*length)).unwrap_or(usize::MAX);
    if length == 0 {
        return Err(Breach::Empty(side));
    }
    if length > LIMIT {
        return Err(Breach::TooLong(side));
    }
    if buffer.len() < 4 + length {
        return Ok(None);
    }
    let rest = buffer.split_off(4 + length);
    Ok(Some(std::mem::replace(buffer, rest)))
}

fn framed(body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn string(into: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    into.extend_from_slice(&length.to_be_bytes());
    into.extend_from_slice(bytes);
}

/// An identities answer naming `keys`, each with the comment the grant kept
/// for it, or none.
pub fn identities<'k>(keys: impl IntoIterator<Item = (&'k SshKey, Option<&'k Words>)>) -> Vec<u8> {
    let named: Vec<(Vec<u8>, &str)> = keys
        .into_iter()
        .map(|(key, comment)| (key.blob(), comment.map_or("", Words::as_str)))
        .collect();
    let mut body = vec![IDENTITIES_ANSWER];
    body.extend_from_slice(&u32::try_from(named.len()).unwrap_or(0).to_be_bytes());
    for (blob, comment) in &named {
        string(&mut body, blob);
        string(&mut body, comment.as_bytes());
    }
    framed(&body)
}

/// Each key an identities answer names, with its comment: `None` where the
/// answer is not one.
pub fn listed(framed_answer: &[u8]) -> Option<Vec<(SshKey, Vec<u8>)>> {
    let body = framed_answer.get(4..)?;
    let (kind, rest) = body.split_first()?;
    if *kind != IDENTITIES_ANSWER {
        return None;
    }
    let (count, mut rest) = rest.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count);
    let mut keys = Vec::new();
    for _ in 0..count {
        let (blob, after) = ssh_string(rest)?;
        let (comment, after) = ssh_string(after)?;
        keys.push((SshKey::from_blob(blob)?, comment.to_vec()));
        rest = after;
    }
    rest.is_empty().then_some(keys)
}

/// What a signature request carries: its key's blob, the data, and its flags,
/// with nothing after.
fn sign_request(body: &[u8]) -> Option<(&[u8], &[u8])> {
    let (blob, rest) = ssh_string(body)?;
    let (data, rest) = ssh_string(rest)?;
    let (_flags, rest) = rest.split_first_chunk::<4>()?;
    rest.is_empty().then_some((blob, data))
}

fn words(bytes: &[u8]) -> Option<Words> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| Words::try_from(text).ok())
}

/// `data` read as a user authentication by the key whose blob is `blob`, as
/// `parse_userauth_request` reads it: a session identifier, the request,
/// `ssh-connection`, a public-key method with its signature to follow, an
/// algorithm, this key, and for the host-bound method the server's key.
fn authentication(data: &[u8], blob: &[u8]) -> Option<Payload> {
    let (session, rest) = ssh_string(data)?;
    let (kind, rest) = rest.split_first()?;
    let (user, rest) = ssh_string(rest)?;
    let (service, rest) = ssh_string(rest)?;
    let (method, rest) = ssh_string(rest)?;
    let (follows, rest) = rest.split_first()?;
    let (_algorithm, rest) = ssh_string(rest)?;
    let (key, rest) = ssh_string(rest)?;
    let well_formed = !session.is_empty()
        && *kind == USERAUTH_REQUEST
        && service == b"ssh-connection"
        && *follows == 1
        && key == blob;
    if !well_formed {
        return None;
    }
    let host = if method == HOSTBOUND {
        let (host, rest) = ssh_string(rest)?;
        if !rest.is_empty() {
            return None;
        }
        Some(SshKey::from_blob(host)?)
    } else if method == b"publickey" && rest.is_empty() {
        None
    } else {
        return None;
    };
    Some(Payload::Authentication {
        user: words(user),
        host,
    })
}

/// `data` read as an `SSHSIG` signature request, as `parse_sshsig_request`
/// reads it.
fn signature(data: &[u8]) -> Option<Payload> {
    let rest = data.strip_prefix(b"SSHSIG")?;
    let (namespace, rest) = ssh_string(rest)?;
    let (_reserved, rest) = ssh_string(rest)?;
    let (_algorithm, rest) = ssh_string(rest)?;
    let (_hash, rest) = ssh_string(rest)?;
    rest.is_empty().then(|| Payload::Signature {
        namespace: words(namespace),
    })
}

/// What a signature by the key whose blob is `blob` over `data` is, and the
/// operation it is decided as: a login is an authentication; anything else
/// is decided as a signature.
pub fn read(data: &[u8], blob: &[u8]) -> (Operation, Payload) {
    if let Some(payload) = authentication(data, blob) {
        return (Operation::Authenticate, payload);
    }
    (Operation::Sign, signature(data).unwrap_or(Payload::Unread))
}

impl Conversation {
    /// A conversation for a remote whose grant lends `lends`.
    pub fn new(lends: Lends) -> Conversation {
        Conversation {
            turn: Turn::Idle,
            lends,
            client: Vec::new(),
            agent: Vec::new(),
        }
    }

    /// What the grant lends changed: what is asked from here is judged by it.
    pub fn relend(&mut self, lends: Lends) {
        self.lends = lends;
    }

    /// Whether a request waits for a decision.
    pub fn holds(&self) -> bool {
        matches!(self.turn, Turn::Held(_))
    }

    /// Bytes from the remote.
    ///
    /// # Errors
    ///
    /// The breach that ends the conversation.
    pub fn from_client(&mut self, bytes: &[u8]) -> Result<Vec<Out>, Breach> {
        self.client.extend_from_slice(bytes);
        // A client may send its next request before the last is answered;
        // what waits is bounded by one message.
        if self.client.len() > 4 + LIMIT {
            return Err(Breach::TooLong(Side::Client));
        }
        self.pump()
    }

    /// The remote closed.
    ///
    /// # Errors
    ///
    /// [`Breach::Cut`] where it closed in the middle of a message.
    pub fn client_closed(&self) -> Result<(), Breach> {
        if self.client.is_empty() {
            Ok(())
        } else {
            Err(Breach::Cut(Side::Client))
        }
    }

    /// Bytes of the agent's answer.
    ///
    /// # Errors
    ///
    /// The breach that ends the conversation.
    pub fn from_agent(&mut self, bytes: &[u8]) -> Result<Vec<Out>, Breach> {
        let Turn::WithAgent(expect) = self.turn else {
            return Err(Breach::OutOfTurn);
        };
        self.agent.extend_from_slice(bytes);
        let Some(answer) = message(&mut self.agent, Side::Agent)? else {
            return Ok(Vec::new());
        };
        if !self.agent.is_empty() {
            return Err(Breach::OutOfTurn);
        }
        let kind = answer.get(4).copied();
        let fits = match expect {
            Expect::Identities => kind == Some(IDENTITIES_ANSWER) && listed(&answer).is_some(),
            Expect::Signature => kind == Some(SIGN_RESPONSE),
        } || matches!(kind, Some(FAILED | FAILED_TOO));
        if !fits {
            return Err(Breach::NotAnswer);
        }
        self.turn = Turn::Idle;
        let mut outs = vec![Out::ToClient(answer)];
        outs.extend(self.pump()?);
        Ok(outs)
    }

    /// The agent ended without answering, or could not be reached: the
    /// remote is told the request failed.
    ///
    /// # Errors
    ///
    /// The breach the client's next request makes.
    pub fn unanswered(&mut self) -> Result<Vec<Out>, Breach> {
        if !matches!(self.turn, Turn::WithAgent(_)) {
            return Ok(Vec::new());
        }
        self.agent.clear();
        self.turn = Turn::Idle;
        let mut outs = vec![Out::ToClient(FAILURE.to_vec())];
        outs.extend(self.pump()?);
        Ok(outs)
    }

    /// Sends the held signature request to the agent.
    pub fn serve(&mut self) -> Vec<Out> {
        match std::mem::replace(&mut self.turn, Turn::WithAgent(Expect::Signature)) {
            Turn::Held(request) => vec![Out::ToAgent(request)],
            other => {
                self.turn = other;
                Vec::new()
            }
        }
    }

    /// Answers the held signature request with a failure, as an agent does
    /// when its owner declines.
    ///
    /// # Errors
    ///
    /// The breach the client's next request makes.
    pub fn refuse(&mut self) -> Result<Vec<Out>, Breach> {
        if !self.holds() {
            return Ok(Vec::new());
        }
        self.turn = Turn::Idle;
        let mut outs = vec![Out::ToClient(FAILURE.to_vec())];
        outs.extend(self.pump()?);
        Ok(outs)
    }

    /// Reads the client's next requests while nothing is outstanding.
    fn pump(&mut self) -> Result<Vec<Out>, Breach> {
        let mut outs = Vec::new();
        while self.turn == Turn::Idle {
            let Some(request) = message(&mut self.client, Side::Client)? else {
                break;
            };
            outs.extend(self.request(request)?);
        }
        Ok(outs)
    }

    fn request(&mut self, request: Vec<u8>) -> Result<Vec<Out>, Breach> {
        let body = request.get(4..).unwrap_or_default();
        let Some((kind, rest)) = body.split_first() else {
            return Err(Breach::Empty(Side::Client));
        };
        let failed = || Out::ToClient(FAILURE.to_vec());
        Ok(match *kind {
            REQUEST_IDENTITIES => match &self.lends {
                Lends::Every => {
                    self.turn = Turn::WithAgent(Expect::Identities);
                    vec![Out::ToAgent(request)]
                }
                Lends::Named { .. } => vec![Out::ToClient(identities(
                    self.lends
                        .keys()
                        .map(|(key, lent)| (key, lent.comment.as_ref())),
                ))],
            },
            SIGN_REQUEST => {
                let (blob, data) = sign_request(rest).ok_or(Breach::Malformed)?;
                let key = SshKey::from_blob(blob).ok_or(Breach::Malformed)?;
                let Some(LentKey { toward, .. }) = self.lends.key(&key) else {
                    return Ok(vec![Out::Withheld(Withheld::KeyUnlent(key)), failed()]);
                };
                let (operation, payload) = read(data, blob);
                let bound = match (toward, &payload) {
                    (Toward::Anywhere, _) => true,
                    (
                        Toward::Hosts(hosts),
                        Payload::Authentication {
                            host: Some(host), ..
                        },
                    ) => hosts.contains(host),
                    (Toward::Hosts(_), _) => false,
                };
                if !bound {
                    return Ok(vec![Out::Withheld(Withheld::Elsewhere(key)), failed()]);
                }
                self.turn = Turn::Held(request);
                vec![Out::Ask(Ask {
                    operation,
                    key,
                    payload,
                })]
            }
            // OpenSSH's client binds each connection it uses to its session
            // and goes on whatever the answer (`sshconnect2.c:1652-1656`):
            // Hedwig binds nothing, so it says so and withholds nothing.
            EXTENSION if ssh_string(rest).is_some_and(|(name, _)| name == SESSION_BIND) => {
                vec![failed()]
            }
            managing if MANAGING.contains(&managing) => {
                vec![Out::Withheld(Withheld::Managing), failed()]
            }
            // A request no agent of this protocol serves, as an agent
            // answers one it does not know.
            _ => vec![failed()],
        })
    }
}
