//! The SSH agent protocol as the relay reads it: what it answers itself,
//! what it holds, what it carries, and what it will not take - over frames
//! built here as OpenSSH's client builds them, and over noise.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::collections::BTreeSet;

use hedwig_core::agent::{
    Ask, Breach, Conversation, FAILURE, LIMIT, Out, Side, identities, listed,
};
use hedwig_model::capability::{Lends, LentKey, Operation, Toward};
use hedwig_model::refusal::Withheld;
use hedwig_model::text::{SshKey, Words};
use hedwig_model::trail::Payload;

const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB1cuDWSQ4xW25Rb1dBGnBjWHV2DfwPn/bqUaSYf4z15";
const OTHER: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIQfBFoTFcymxqayVAmobeqqsWVKCgyRgJhRE4W7CDjAcuptlxzloqrpI2/N0w2y8dLIaPMBQcggIHZExfGvJ8c=";

fn key(text: &str) -> SshKey {
    SshKey::try_from(text).unwrap()
}

fn string(into: &mut Vec<u8>, bytes: &[u8]) {
    into.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    into.extend_from_slice(bytes);
}

/// An identities answer naming `keys` with no comment.
fn listing(keys: &[&SshKey]) -> Vec<u8> {
    identities(keys.iter().map(|key| (*key, None)))
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

/// What OpenSSH's client signs to log in (`sshconnect2.c`, `sign_and_send_pubkey`).
fn userauth(user: &str, key: &SshKey, host: Option<&SshKey>) -> Vec<u8> {
    let mut data = Vec::new();
    string(&mut data, &[0x5a; 32]);
    data.push(50);
    string(&mut data, user.as_bytes());
    string(&mut data, b"ssh-connection");
    let method: &[u8] = if host.is_some() {
        b"publickey-hostbound-v00@openssh.com"
    } else {
        b"publickey"
    };
    string(&mut data, method);
    data.push(1);
    string(&mut data, key.kind().as_bytes());
    string(&mut data, &key.blob());
    if let Some(host) = host {
        string(&mut data, &host.blob());
    }
    data
}

/// What `ssh-keygen -Y sign` has signed (`sshsig.c`, `sshsig_wrap_sign`).
fn sshsig(namespace: &str) -> Vec<u8> {
    let mut data = b"SSHSIG".to_vec();
    string(&mut data, namespace.as_bytes());
    string(&mut data, b"");
    string(&mut data, b"sha512");
    string(&mut data, &[7; 64]);
    data
}

fn sign_request(key: &SshKey, data: &[u8]) -> Vec<u8> {
    let mut body = vec![13];
    string(&mut body, &key.blob());
    string(&mut body, data);
    body.extend_from_slice(&0u32.to_be_bytes());
    framed(&body)
}

fn lending(keys: &[(&str, Toward)]) -> Lends {
    Lends::of_keys(
        keys.iter()
            .map(|(text, toward)| (key(text), toward.clone().into())),
    )
}

fn anywhere(text: &str) -> (&str, Toward) {
    (text, Toward::Anywhere)
}

fn failed() -> Out {
    Out::ToClient(FAILURE.to_vec())
}

const LIST: [u8; 5] = [0, 0, 0, 1, 11];

/// A remote asking which keys there are is told the lent ones from the
/// grant, each with the comment kept when it was lent, the agent never
/// asked; under a grant of every key the agent is asked and its answer
/// passed on as it came.
#[test]
fn the_keys_listed_are_the_grant_s_or_under_every_key_the_agent_s() {
    let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
    let outs = talk.from_client(&LIST).unwrap();
    assert_eq!(outs, vec![Out::ToClient(listing(&[&key(KEY)]))]);
    let Out::ToClient(answer) = &outs[0] else {
        unreachable!()
    };
    assert_eq!(listed(answer), Some(vec![(key(KEY), Vec::new())]));

    let mut talk = Conversation::new(Lends::of_keys([
        (
            key(KEY),
            LentKey {
                toward: Toward::Anywhere,
                comment: Some(Words::try_from("laptop").unwrap()),
            },
        ),
        (key(OTHER), Toward::Hosts(BTreeSet::new()).into()),
    ]));
    let outs = talk.from_client(&LIST).unwrap();
    let [Out::ToClient(answer)] = outs.as_slice() else {
        unreachable!("{outs:?}")
    };
    let mut read = listed(answer).unwrap();
    read.sort();
    let mut lent = vec![(key(KEY), b"laptop".to_vec()), (key(OTHER), Vec::new())];
    lent.sort();
    assert_eq!(read, lent);

    let mut talk = Conversation::new(Lends::none());
    assert_eq!(
        talk.from_client(&LIST).unwrap(),
        vec![Out::ToClient(listing(&[]))]
    );

    let mut talk = Conversation::new(Lends::Every);
    assert_eq!(
        talk.from_client(&LIST).unwrap(),
        vec![Out::ToAgent(LIST.to_vec())]
    );
    let theirs = listing(&[&key(KEY), &key(OTHER)]);
    assert_eq!(
        talk.from_agent(&theirs).unwrap(),
        vec![Out::ToClient(theirs.clone())]
    );
}

/// An identities answer reads back to the keys and comments it names, and
/// anything else is no list.
#[test]
fn an_identities_answer_reads_both_ways() {
    let both = [key(KEY), key(OTHER)];
    let written = listing(&both.each_ref());
    assert_eq!(
        listed(&written),
        Some(vec![(key(KEY), Vec::new()), (key(OTHER), Vec::new())])
    );
    let mut commented = vec![12, 0, 0, 0, 1];
    string(&mut commented, &key(KEY).blob());
    string(&mut commented, b"ali@workstation");
    assert_eq!(
        listed(&framed(&commented)),
        Some(vec![(key(KEY), b"ali@workstation".to_vec())])
    );
    let mut trailing = written.clone();
    trailing.push(0);
    for unread in [
        FAILURE.to_vec(),
        Vec::new(),
        written[..written.len() - 1].to_vec(),
        trailing,
    ] {
        assert_eq!(listed(&unread), None);
    }
}

/// A login is told from a commit's signature by what is signed, as OpenSSH's
/// agent tells them apart, and each is held with what its payload says.
#[test]
fn a_signature_is_held_as_a_login_a_signature_or_data_unread() {
    let host = key(OTHER);
    for (data, operation, payload) in [
        (
            userauth("git", &key(KEY), None),
            Operation::Authenticate,
            Payload::Authentication {
                user: Some(Words::try_from("git").unwrap()),
                host: None,
            },
        ),
        (
            userauth("deploy", &key(KEY), Some(&host)),
            Operation::Authenticate,
            Payload::Authentication {
                user: Some(Words::try_from("deploy").unwrap()),
                host: Some(host.clone()),
            },
        ),
        (
            sshsig("git"),
            Operation::Sign,
            Payload::Signature {
                namespace: Some(Words::try_from("git").unwrap()),
            },
        ),
        (
            b"arbitrary bytes".to_vec(),
            Operation::Sign,
            Payload::Unread,
        ),
        // A login by another key than the one asked to sign it is no login.
        (
            userauth("git", &host, None),
            Operation::Sign,
            Payload::Unread,
        ),
    ] {
        let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
        let request = sign_request(&key(KEY), &data);
        assert_eq!(
            talk.from_client(&request).unwrap(),
            vec![Out::Ask(Ask {
                operation,
                key: key(KEY),
                payload: payload.clone(),
            })],
            "{payload:?}"
        );
        assert!(talk.holds());
        assert_eq!(talk.serve(), vec![Out::ToAgent(request)]);
        let response = framed(&[14, 0, 0, 0, 3, 1, 2, 3]);
        assert_eq!(
            talk.from_agent(&response).unwrap(),
            vec![Out::ToClient(response)]
        );
        assert!(!talk.holds());
    }
}

/// A held signature refused is answered as an agent answers what it will not
/// do, and the next request is read after it.
#[test]
fn a_refused_signature_is_a_failure_and_the_conversation_goes_on() {
    let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
    let mut both = sign_request(&key(KEY), &sshsig("git"));
    both.extend_from_slice(&LIST);
    let outs = talk.from_client(&both).unwrap();
    assert!(matches!(outs.as_slice(), [Out::Ask(_)]), "{outs:?}");
    assert_eq!(
        talk.refuse().unwrap(),
        vec![failed(), Out::ToClient(listing(&[&key(KEY)]))]
    );
    assert_eq!(talk.refuse().unwrap(), Vec::new(), "nothing is held");
    assert_eq!(talk.serve(), Vec::new(), "nothing is held");
}

/// A key the grant does not lend is refused at the relay, and the agent
/// never sees the request.
#[test]
fn a_key_not_lent_never_reaches_the_agent() {
    let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
    assert_eq!(
        talk.from_client(&sign_request(&key(OTHER), &sshsig("git")))
            .unwrap(),
        vec![Out::Withheld(Withheld::KeyUnlent(key(OTHER))), failed()]
    );
    let mut talk = Conversation::new(Lends::none());
    assert_eq!(
        talk.from_client(&sign_request(&key(KEY), &userauth("git", &key(KEY), None)))
            .unwrap(),
        vec![Out::Withheld(Withheld::KeyUnlent(key(KEY))), failed()]
    );
}

/// A key lent toward named hosts signs only a login that names one of them
/// as OpenSSH's servers check it; a login to another host, one that names no
/// host, and any other signature are refused at the relay.
#[test]
fn a_key_lent_toward_hosts_signs_only_a_login_to_one_of_them() {
    let allowed = key(OTHER);
    let elsewhere = SshKey::from_blob(&{
        let mut blob = Vec::new();
        string(&mut blob, b"ssh-ed25519");
        string(&mut blob, &[9; 32]);
        blob
    })
    .unwrap();
    let toward = Toward::Hosts(BTreeSet::from([allowed.clone()]));
    let lent = || Conversation::new(lending(&[(KEY, toward.clone())]));
    assert!(matches!(
        lent()
            .from_client(&sign_request(
                &key(KEY),
                &userauth("deploy", &key(KEY), Some(&allowed))
            ))
            .unwrap()
            .as_slice(),
        [Out::Ask(Ask {
            operation: Operation::Authenticate,
            ..
        })]
    ));
    for data in [
        userauth("deploy", &key(KEY), Some(&elsewhere)),
        userauth("deploy", &key(KEY), None),
        sshsig("git"),
        b"anything".to_vec(),
    ] {
        assert_eq!(
            lent().from_client(&sign_request(&key(KEY), &data)).unwrap(),
            vec![Out::Withheld(Withheld::Elsewhere(key(KEY))), failed()]
        );
    }
}

/// Adding, removing or locking keys, smartcards and extensions are answered
/// with a failure at the relay; a session bind, which OpenSSH's client sends
/// on every connection it uses, is declined without being withheld; a
/// request no agent knows is a failure.
#[test]
fn nothing_that_changes_or_locks_the_agent_reaches_it() {
    let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
    for kind in 17..=27u8 {
        let mut body = vec![kind];
        string(&mut body, b"query");
        assert_eq!(
            talk.from_client(&framed(&body)).unwrap(),
            vec![Out::Withheld(Withheld::Managing), failed()],
            "{kind}"
        );
    }
    let mut bind = vec![27];
    string(&mut bind, b"session-bind@openssh.com");
    string(&mut bind, &key(OTHER).blob());
    assert_eq!(talk.from_client(&framed(&bind)).unwrap(), vec![failed()]);
    for unknown in [1u8, 2, 9, 12, 14, 16, 28, 200] {
        assert_eq!(
            talk.from_client(&framed(&[unknown])).unwrap(),
            vec![failed()]
        );
    }
}

/// Each breach ends the conversation, before anything of it is carried.
#[test]
fn every_breach_ends_the_conversation() {
    let talk = || Conversation::new(lending(&[anywhere(KEY)]));
    assert_eq!(
        talk().from_client(&[0, 0, 0, 0]),
        Err(Breach::Empty(Side::Client))
    );
    let too_long = u32::try_from(LIMIT + 1).unwrap().to_be_bytes();
    assert_eq!(
        talk().from_client(&too_long),
        Err(Breach::TooLong(Side::Client))
    );
    let mut trailing = sign_request(&key(KEY), &sshsig("git"));
    trailing.push(0);
    trailing[3] += 1;
    assert_eq!(talk().from_client(&trailing), Err(Breach::Malformed));
    let mut no_key = vec![13];
    string(&mut no_key, b"\0\0\0\x0bssh-ed25519");
    string(&mut no_key, b"data");
    no_key.extend_from_slice(&[0; 4]);
    assert_eq!(talk().from_client(&framed(&no_key)), Err(Breach::Malformed));
    assert_eq!(talk().from_agent(&FAILURE), Err(Breach::OutOfTurn));

    let mut asked = talk();
    asked
        .from_client(&sign_request(&key(KEY), &sshsig("git")))
        .unwrap();
    asked.serve();
    assert_eq!(
        asked.from_agent(&listing(&[&key(KEY)])),
        Err(Breach::NotAnswer)
    );
    let mut asked = talk();
    asked
        .from_client(&sign_request(&key(KEY), &sshsig("git")))
        .unwrap();
    asked.serve();
    let mut twice = FAILURE.to_vec();
    twice.extend_from_slice(&FAILURE);
    assert_eq!(asked.from_agent(&twice), Err(Breach::OutOfTurn));
    let mut asked = talk();
    asked
        .from_client(&sign_request(&key(KEY), &sshsig("git")))
        .unwrap();
    asked.serve();
    assert_eq!(
        asked.from_agent(&[0, 0, 0, 0]),
        Err(Breach::Empty(Side::Agent))
    );

    let mut cut = talk();
    cut.from_client(&LIST[..3]).unwrap();
    assert_eq!(cut.client_closed(), Err(Breach::Cut(Side::Client)));
    assert_eq!(talk().client_closed(), Ok(()));

    // What waits behind a held request is bounded by one message.
    let mut piling = talk();
    piling
        .from_client(&sign_request(&key(KEY), &sshsig("git")))
        .unwrap();
    let mut flood = u32::try_from(LIMIT).unwrap().to_be_bytes().to_vec();
    flood.resize(4 + LIMIT, 0);
    assert_eq!(piling.from_client(&flood).unwrap(), Vec::new());
    assert_eq!(piling.from_client(&[0]), Err(Breach::TooLong(Side::Client)));
}

/// An agent that does not answer leaves the remote told the request failed,
/// and what was waiting is read after it.
#[test]
fn an_agent_that_does_not_answer_is_a_failure_to_the_remote() {
    let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
    let mut both = sign_request(&key(KEY), &sshsig("git"));
    both.extend_from_slice(&LIST);
    talk.from_client(&both).unwrap();
    talk.serve();
    assert_eq!(
        talk.unanswered().unwrap(),
        vec![failed(), Out::ToClient(listing(&[&key(KEY)]))]
    );
    assert_eq!(talk.unanswered().unwrap(), Vec::new());
}

/// A change of lending reaches the conversation: what is asked from then on
/// is judged by what is lent now.
#[test]
fn a_change_of_lending_is_judged_from_the_next_request() {
    let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
    talk.relend(Lends::none());
    assert_eq!(
        talk.from_client(&sign_request(&key(KEY), &sshsig("git")))
            .unwrap(),
        vec![Out::Withheld(Withheld::KeyUnlent(key(KEY))), failed()]
    );
}

/// Whatever a remote sends, cut wherever it is cut, the conversation never
/// panics, never sends the agent anything but a lent key's signature request
/// or under every key a list, and holds no more than one message's bytes.
#[test]
fn noise_from_a_remote_is_answered_or_ends_the_conversation() {
    let mut state = 0x0bad_5eed_u64;
    let mut next = move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    let pieces = [
        LIST.to_vec(),
        sign_request(&key(KEY), &sshsig("git")),
        sign_request(&key(OTHER), &userauth("git", &key(OTHER), None)),
        framed(&[17]),
        framed(&[27, 0, 0, 0, 1, b'x']),
        vec![0, 0, 0, 0],
        vec![0xff; 4],
    ];
    for _ in 0..2_000 {
        let mut talk = Conversation::new(lending(&[anywhere(KEY)]));
        let mut stream = Vec::new();
        for _ in 0..(next() % 6) {
            let choice = usize::try_from(next() % 8).unwrap();
            match pieces.get(choice) {
                Some(piece) => stream.extend_from_slice(piece),
                None => stream.extend((0..(next() % 40)).map(|_| next().to_le_bytes()[0])),
            }
        }
        let mut rest = stream.as_slice();
        while !rest.is_empty() {
            let cut = usize::try_from(next()).unwrap() % rest.len() + 1;
            let (piece, after) = rest.split_at(cut);
            rest = after;
            match talk.from_client(piece) {
                Ok(outs) => {
                    assert!(
                        !outs.iter().any(|out| matches!(out, Out::ToAgent(_))),
                        "nothing reaches the agent unserved: {outs:?}"
                    );
                }
                Err(_) => break,
            }
            if talk.holds() {
                let served = talk.serve();
                assert!(
                    served
                        .iter()
                        .all(|out| matches!(out, Out::ToAgent(request) if request[4] == 13))
                );
                talk.unanswered().ok();
            }
        }
    }
}

/// A FIDO2 key's public half - its type, the key, and the application it is
/// bound to (`PROTOCOL.u2f`) - is a key like any other to the relay: read,
/// listed, and its login told from a signature by what it signs.
#[test]
fn a_security_key_is_carried_as_any_key_is() {
    let mut blob = Vec::new();
    string(&mut blob, b"sk-ssh-ed25519@openssh.com");
    string(&mut blob, &[0x42; 32]);
    string(&mut blob, b"ssh:");
    let sk = SshKey::from_blob(&blob).unwrap();
    assert_eq!(sk.kind(), "sk-ssh-ed25519@openssh.com");
    assert_eq!(sk.blob(), blob);
    assert_eq!(SshKey::try_from(sk.as_str()), Ok(sk.clone()));
    let mut talk = Conversation::new(lending(&[(sk.as_str(), Toward::Anywhere)]));
    assert_eq!(
        talk.from_client(&LIST).unwrap(),
        vec![Out::ToClient(listing(&[&sk]))]
    );
    assert!(matches!(
        talk.from_client(&sign_request(&sk, &userauth("git", &sk, None)))
            .unwrap()
            .as_slice(),
        [Out::Ask(Ask {
            operation: Operation::Authenticate,
            ..
        })]
    ));
}
