//! The keys Hedwig makes in the workstation's TPM, and the agent protocol
//! answered for them by the core itself: no agent on Windows holds such a
//! key.
//!
//! A request reaches [`answer`] only once the relay has let it through for a
//! remote whose grant lends the key and the person's policy has decided it,
//! so what is here signs whatever it is given: the TPM asks nobody. Which
//! keys there are is the TPM's store, read each time; a key is named in it
//! [`PREFIX`] and the name the person gave it.

use hedwig_model::capability::KeyKind;
use hedwig_model::protocol::AgentKey;
use hedwig_model::refusal::Refusal;
use hedwig_model::text::{Name, SshKey, Words, ssh_string};
use hedwig_model::trail::Failure;
use hedwig_win::tpm::{Algorithm, Hash, Key, Padding, Provider, Public, TpmError};

use crate::agent::FAILURE;

/// What a key Hedwig made is named in the TPM before the person's name for
/// it. Invariant: it marks Hedwig's keys among every key the person's
/// provider holds, and every other name is passed over unopened.
pub const PREFIX: &str = "hedwig/";

const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENT_RSA_SHA2_256` and `SSH_AGENT_RSA_SHA2_512` (`authfd.h`).
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

fn string(into: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    into.extend_from_slice(&length.to_be_bytes());
    into.extend_from_slice(bytes);
}

/// `magnitude` as an SSH `mpint`: no leading zero bytes, and one where the
/// top bit is set, so it is read as positive (RFC 4251 section 5).
fn mpint(into: &mut Vec<u8>, magnitude: &[u8]) {
    let first = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    let trimmed = magnitude.get(first..).unwrap_or_default();
    let mut bytes = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_some_and(|byte| *byte & 0x80 != 0) {
        bytes.push(0);
    }
    bytes.extend_from_slice(trimmed);
    string(into, &bytes);
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn curve_name(curve: u32) -> Option<(&'static str, Hash)> {
    match curve {
        256 => Some(("nistp256", Hash::Sha256)),
        384 => Some(("nistp384", Hash::Sha384)),
        521 => Some(("nistp521", Hash::Sha512)),
        _ => None,
    }
}

/// A public half as OpenSSH writes its blob (RFC 5656 section 3.1, RFC 4253
/// section 6.6).
pub fn ssh_key(public: &Public) -> Option<SshKey> {
    let mut blob = Vec::new();
    match public {
        Public::Ecdsa { curve, x, y } => {
            let (curve, _) = curve_name(*curve)?;
            string(&mut blob, format!("ecdsa-sha2-{curve}").as_bytes());
            string(&mut blob, curve.as_bytes());
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(4);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            string(&mut blob, &point);
        }
        Public::Rsa { exponent, modulus } => {
            string(&mut blob, b"ssh-rsa");
            mpint(&mut blob, exponent);
            mpint(&mut blob, modulus);
        }
    }
    SshKey::from_blob(&blob)
}

fn algorithm(kind: KeyKind) -> Algorithm {
    match kind {
        KeyKind::EcdsaP256 => Algorithm::EcdsaP256,
        KeyKind::EcdsaP384 => Algorithm::EcdsaP384,
        KeyKind::EcdsaP521 => Algorithm::EcdsaP521,
        KeyKind::Rsa2048 => Algorithm::Rsa { bits: 2048 },
        KeyKind::Rsa3072 => Algorithm::Rsa { bits: 3072 },
        KeyKind::Rsa4096 => Algorithm::Rsa { bits: 4096 },
    }
}

fn provider() -> Result<Provider, Failure> {
    Provider::platform().map_err(|_| Failure::NoTpm)
}

/// Every key Hedwig made, with its public half and its name.
fn held(provider: &Provider) -> Result<Vec<(Key, SshKey, Name)>, Failure> {
    let names = provider.names(PREFIX).map_err(|_| Failure::NoTpm)?;
    let mut held = Vec::new();
    for full in names {
        // A name not of the person's giving, or a key whose public half
        // cannot be read, is no key Hedwig made and can sign with.
        let Some(name) = full
            .strip_prefix(PREFIX)
            .and_then(|name| Name::try_from(name).ok())
        else {
            continue;
        };
        let Ok(key) = provider.open(&full) else {
            continue;
        };
        let Some(public) = key.public().ok().as_ref().and_then(ssh_key) else {
            continue;
        };
        held.push((key, public, name));
    }
    Ok(held)
}

fn listed(key: SshKey, name: &Name) -> AgentKey {
    AgentKey {
        key,
        comment: Words::try_from(name.as_str()).ok(),
    }
}

/// Whether the TPM's provider answers for this logon.
///
/// # Errors
///
/// [`Failure::NoTpm`] where it does not.
pub fn reach() -> Result<(), Failure> {
    provider().map(drop)
}

/// The keys Hedwig made, each named as the person named it.
///
/// # Errors
///
/// [`Failure::NoTpm`] where the provider does not answer.
pub fn keys() -> Result<Vec<AgentKey>, Failure> {
    let provider = provider()?;
    Ok(held(&provider)?
        .into_iter()
        .map(|(_, key, name)| listed(key, &name))
        .collect())
}

/// Makes a key of `kind` named `name`.
///
/// # Errors
///
/// [`Refusal::KeyExists`], [`Refusal::KindUnmade`], or [`Refusal::NoTpm`]
/// for a provider that does not answer or fails otherwise.
pub fn make(name: &Name, kind: KeyKind) -> Result<AgentKey, Refusal> {
    let provider = Provider::platform().map_err(|_| Refusal::NoTpm)?;
    let full = format!("{PREFIX}{name}");
    let key = provider
        .make(&full, algorithm(kind))
        .map_err(|error| match error {
            TpmError::Exists => Refusal::KeyExists(name.clone()),
            TpmError::Unsupported => Refusal::KindUnmade(kind),
            TpmError::Unavailable(_) | TpmError::Missing | TpmError::Failed(_) => Refusal::NoTpm,
        })?;
    if let Some(public) = key.public().ok().as_ref().and_then(ssh_key) {
        Ok(listed(public, name))
    } else {
        // A key whose public half cannot be read can never be registered
        // anywhere, so it is not left behind.
        let _ = key.delete();
        Err(Refusal::NoTpm)
    }
}

/// The name of the key Hedwig made whose public half is `key`.
///
/// # Errors
///
/// [`Refusal::KeyAbsent`] where none is; [`Refusal::NoTpm`] where the
/// provider does not answer.
pub fn find(key: &SshKey) -> Result<Name, Refusal> {
    let provider = Provider::platform().map_err(|_| Refusal::NoTpm)?;
    held(&provider)
        .map_err(|_| Refusal::NoTpm)?
        .into_iter()
        .find(|(_, public, _)| public == key)
        .map(|(_, _, name)| name)
        .ok_or_else(|| Refusal::KeyAbsent(key.clone()))
}

/// Deletes the key named `name`, only where its public half is still `key`.
///
/// # Errors
///
/// [`Refusal::KeyAbsent`] where no such key is there now; [`Refusal::NoTpm`]
/// where the provider does not answer or fails.
pub fn delete(name: &Name, key: &SshKey) -> Result<(), Refusal> {
    let provider = Provider::platform().map_err(|_| Refusal::NoTpm)?;
    let opened = provider
        .open(&format!("{PREFIX}{name}"))
        .map_err(|error| match error {
            TpmError::Missing => Refusal::KeyAbsent(key.clone()),
            _ => Refusal::NoTpm,
        })?;
    if opened.public().ok().as_ref().and_then(ssh_key).as_ref() != Some(key) {
        return Err(Refusal::KeyAbsent(key.clone()));
    }
    opened.delete().map_err(|_| Refusal::NoTpm)
}

/// The signature `key` makes over `data`, as the agent protocol carries it,
/// for a request with `flags`; `None` where the key does not sign as asked.
fn signature(key: &Key, public: &Public, data: &[u8], flags: u32) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match public {
        Public::Ecdsa { curve, x, .. } => {
            let (name, hash) = curve_name(*curve)?;
            let raw = key
                .sign(&hedwig_win::tpm::digest(hash, data).ok()?, Padding::None)
                .ok()?;
            let (r, s) = raw.split_at_checked(x.len())?;
            string(&mut out, format!("ecdsa-sha2-{name}").as_bytes());
            let mut pair = Vec::new();
            mpint(&mut pair, r);
            mpint(&mut pair, s);
            string(&mut out, &pair);
        }
        Public::Rsa { .. } => {
            // SHA-1 `ssh-rsa` is never signed.
            let (name, hash) = if flags & RSA_SHA2_512 != 0 {
                ("rsa-sha2-512", Hash::Sha512)
            } else if flags & RSA_SHA2_256 != 0 {
                ("rsa-sha2-256", Hash::Sha256)
            } else {
                return None;
            };
            let raw = key
                .sign(
                    &hedwig_win::tpm::digest(hash, data).ok()?,
                    Padding::Pkcs1(hash),
                )
                .ok()?;
            string(&mut out, name.as_bytes());
            string(&mut out, &raw);
        }
    }
    Some(out)
}

/// The agent's answer to one framed request: the keys Hedwig made, or a
/// signature by one. Anything else is answered with a failure.
///
/// # Errors
///
/// [`Failure::NoTpm`] where the provider does not answer for this logon.
pub fn answer(request: &[u8]) -> Result<Vec<u8>, Failure> {
    let body = request.get(4..).unwrap_or_default();
    let Some((kind, rest)) = body.split_first() else {
        return Ok(FAILURE.to_vec());
    };
    match *kind {
        REQUEST_IDENTITIES => {
            let keys = keys()?;
            let mut out = vec![IDENTITIES_ANSWER];
            out.extend_from_slice(&u32::try_from(keys.len()).unwrap_or(0).to_be_bytes());
            for listed in keys {
                string(&mut out, &listed.key.blob());
                string(
                    &mut out,
                    listed.comment.as_ref().map_or("", Words::as_str).as_bytes(),
                );
            }
            Ok(framed(&out))
        }
        SIGN_REQUEST => {
            let parsed = ssh_string(rest).and_then(|(blob, rest)| {
                let (data, rest) = ssh_string(rest)?;
                let flags = rest
                    .first_chunk::<4>()
                    .map(|flags| u32::from_be_bytes(*flags))?;
                Some((SshKey::from_blob(blob)?, data, flags))
            });
            let Some((wanted, data, flags)) = parsed else {
                return Ok(FAILURE.to_vec());
            };
            let provider = provider()?;
            let Some((key, _, _)) = held(&provider)?
                .into_iter()
                .find(|(_, public, _)| *public == wanted)
            else {
                return Ok(FAILURE.to_vec());
            };
            let Some(signed) = key
                .public()
                .ok()
                .and_then(|public| signature(&key, &public, data, flags))
            else {
                return Ok(FAILURE.to_vec());
            };
            let mut out = vec![SIGN_RESPONSE];
            string(&mut out, &signed);
            Ok(framed(&out))
        }
        _ => Ok(FAILURE.to_vec()),
    }
}
