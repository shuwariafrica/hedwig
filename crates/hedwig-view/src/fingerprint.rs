//! An SSH key as a person knows it: its type and its SHA-256 fingerprint,
//! as `ssh-add -l`, `ssh-keygen -l`, a password manager and a forge's key
//! settings print them.
//!
//! The model names a key by its public half, whose blob is its identity; a
//! fingerprint is only how it is shown, so it is made here.

use hedwig_model::text::{SshKey, base64, ssh_string, to_base64};

/// FIPS 180-4's initial hash value for SHA-256 (section 5.3.3).
const START: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// FIPS 180-4's round constants for SHA-256 (section 4.2.2).
const ROUNDS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 of `message` (FIPS 180-4, section 6.2).
#[allow(
    clippy::many_single_char_names,
    reason = "a to h are FIPS 180-4's own names for the eight working variables"
)]
pub fn sha256(message: &[u8]) -> [u8; 32] {
    let mut state = START;
    // The message, a 1 bit, zeros to 56 bytes past a block's start, and the
    // message's length in bits (section 5.1.1).
    let bits = u64::try_from(message.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut padded = Vec::with_capacity(message.len() + 72);
    padded.extend_from_slice(message);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bits.to_be_bytes());
    for block in padded.as_chunks::<64>().0 {
        let mut schedule = [0u32; 64];
        for (word, bytes) in schedule.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
        for at in 16..64 {
            let back = |by: usize| schedule.get(at - by).copied().unwrap_or_default();
            let (w16, w15, w7, w2) = (back(16), back(15), back(7), back(2));
            let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
            let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
            if let Some(word) = schedule.get_mut(at) {
                *word = w16.wrapping_add(s0).wrapping_add(w7).wrapping_add(s1);
            }
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (constant, word) in ROUNDS.iter().zip(schedule) {
            let big1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ (!e & g);
            let first = h
                .wrapping_add(big1)
                .wrapping_add(choose)
                .wrapping_add(*constant)
                .wrapping_add(word);
            let big0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let second = big0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(first);
            d = c;
            c = b;
            b = a;
            a = first.wrapping_add(second);
        }
        for (word, add) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *word = word.wrapping_add(add);
        }
    }
    let mut digest = [0u8; 32];
    for (bytes, word) in digest.as_chunks_mut::<4>().0.iter_mut().zip(state) {
        *bytes = word.to_be_bytes();
    }
    digest
}

/// A certificate's type, the plain type it certifies, the name OpenSSH
/// gives that plain type, and how many fields of the plain key follow the
/// certificate's nonce (`sshkey.c`, `sshkey_from_blob_internal`; each type's
/// `deserialize_public`). An ECDSA certificate's curve is in its type.
const CERTIFIED: [(&str, &str, &str, usize); 5] = [
    (
        "ssh-ed25519-cert-v01@openssh.com",
        "ssh-ed25519",
        "ED25519",
        1,
    ),
    ("ssh-rsa-cert-v01@openssh.com", "ssh-rsa", "RSA", 2),
    (
        "sk-ssh-ed25519-cert-v01@openssh.com",
        "sk-ssh-ed25519@openssh.com",
        "ED25519-SK",
        2,
    ),
    (
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ECDSA-SK",
        3,
    ),
    ("ssh-dss-cert-v01@openssh.com", "ssh-dss", "DSA", 4),
];

/// The name OpenSSH gives a plain key's type (each type's `shortname`).
fn plain_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "ssh-ed25519" => Some("ED25519"),
        "ssh-rsa" => Some("RSA"),
        "sk-ssh-ed25519@openssh.com" => Some("ED25519-SK"),
        "sk-ecdsa-sha2-nistp256@openssh.com" => Some("ECDSA-SK"),
        "ssh-dss" => Some("DSA"),
        _ if kind.starts_with("ecdsa-sha2-") && !kind.ends_with("-cert-v01@openssh.com") => {
            Some("ECDSA")
        }
        _ => None,
    }
}

/// A certificate's plain key, as OpenSSH serialises it to fingerprint a
/// certificate: the plain type, then the key's own fields from after the
/// nonce. `None` where the blob is not a certificate this knows.
fn plain(kind: &str, blob: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    const SUFFIX: &str = "-cert-v01@openssh.com";
    let (_, body) = ssh_string(blob)?;
    let (_, mut rest) = ssh_string(body)?;
    let (plain_type, short, fields) = if let Some(curve) = kind
        .strip_prefix("ecdsa-sha2-")
        .and_then(|rest| rest.strip_suffix(SUFFIX))
    {
        (format!("ecdsa-sha2-{curve}"), "ECDSA", 2)
    } else {
        let (_, plain_type, short, fields) = CERTIFIED
            .iter()
            .find(|(certificate, ..)| *certificate == kind)?;
        ((*plain_type).to_owned(), *short, *fields)
    };
    let mut plain = Vec::with_capacity(blob.len());
    let length = u32::try_from(plain_type.len()).ok()?;
    plain.extend_from_slice(&length.to_be_bytes());
    plain.extend_from_slice(plain_type.as_bytes());
    for _ in 0..fields {
        let (field, after) = ssh_string(rest)?;
        let length = u32::try_from(field.len()).ok()?;
        plain.extend_from_slice(&length.to_be_bytes());
        plain.extend_from_slice(field);
        rest = after;
    }
    Some((plain, short))
}

/// An SSH key's type and fingerprint as `ssh-keygen -l` prints them:
/// `ED25519` and `SHA256:` with the digest of the key's plain blob in
/// unpadded base64. A certificate is fingerprinted by the key it certifies,
/// and its type says it is one (`ED25519-CERT`). `None` for a type OpenSSH
/// does not name, which is then shown as the key itself.
pub fn of(key: &SshKey) -> Option<(String, String)> {
    let kind = key.kind();
    let blob = key.blob();
    let (hashed, short) = if let Some(short) = plain_kind(kind) {
        (blob, short.to_owned())
    } else {
        let (plain, short) = plain(kind, &blob)?;
        (plain, format!("{short}-CERT"))
    };
    let encoded = to_base64(&sha256(&hashed));
    Some((short, format!("SHA256:{}", encoded.trim_end_matches('='))))
}

/// The public key a line of text names, as `ssh-keyscan`, a host's
/// `.pub` file, an `authorized_keys` line or a `known_hosts` line writes it:
/// the first type and base64 key in it, whatever names or options stand
/// around them.
pub fn key_in(line: &str) -> Option<SshKey> {
    let words: Vec<&str> = line.split_whitespace().collect();
    words.windows(2).find_map(|pair| match pair {
        [kind, encoded] if base64(encoded).is_some() => {
            SshKey::try_from(format!("{kind} {encoded}").as_str()).ok()
        }
        _ => None,
    })
}
