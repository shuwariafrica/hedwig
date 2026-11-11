//! The card readers, against what scdaemon 2.5.24 writes: `SCD KEYINFO
//! --list` (`scd/command.c`, `send_keyinfo`; `scd/app-openpgp.c`,
//! `send_keyinfo_if_available`), `GETINFO card_list` (`scd/app.c`,
//! `send_serialno_and_app_status`), and `GETATTR KEY-FPR`, `EXTCAP`, `UIF` and
//! `CHV-STATUS` (`scd/app-openpgp.c`, `do_getattr`), each escaped as
//! `send_status_info` escapes a value: `%XX` for a control byte, `+`, `"` and
//! `%`, and `+` for a blank.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use hedwig_core::keys::{First, button, cards, from_attributes, held, on_cards, pin, slots, touch};
use hedwig_model::text::{Fingerprint, Grip, Serial};
use hedwig_model::trail::{Card, Held, Key, Keyring, SignaturePin, Touch, Uses};

const SIGNING: &str = "64EFB4597F2EB1968F187B7235A461FC48342EC5";
const DECRYPTING: &str = "1D3AA6A1A0F4C9B92A3B5F07E6E0D0C3D4E5F601";
const PIV: &str = "9A8B7C6D5E4F30211203F4E5D6C7B8A9F0E1D2C3";
const CARD: &str = "D2760001240103040006123456780000";
const OTHER: &str = "FF020001008A1B2C3D4E";

fn lines(text: &[&str]) -> Vec<Vec<u8>> {
    text.iter().map(|line| line.as_bytes().to_vec()).collect()
}

fn grip(text: &str) -> Grip {
    Grip::try_from(text).unwrap()
}

fn serial(text: &str) -> Serial {
    Serial::try_from(text).unwrap()
}

#[test]
fn keyinfo_names_each_key_its_card_and_its_openpgp_slot() {
    let listed = on_cards(&lines(&[
        &format!("KEYINFO {SIGNING} T {CARD} OPENPGP.1 sc"),
        &format!("KEYINFO {DECRYPTING} T {CARD} OPENPGP.2 e"),
        &format!("KEYINFO {PIV} T {OTHER} PIV.9C s"),
        // What is not a card key's line is not one.
        &format!("KEYINFO {SIGNING} D - - - P - - -"),
        "KEYINFO 64EFB4597F2EB1968F187B7235A461FC48342EC T - - -",
        &format!("KEYINFO {SIGNING} T {CARD} OPENPGP.4 sc"),
        "PROGRESS learncard k 0 0",
    ]));
    assert_eq!(
        listed,
        [
            (grip(SIGNING), serial(CARD), Some(1)),
            (grip(DECRYPTING), serial(CARD), Some(2)),
            (grip(PIV), serial(OTHER), None),
            (grip(SIGNING), serial(CARD), None),
        ]
    );
}

#[test]
fn the_button_is_what_extcap_says_of_it() {
    let extcap = |bt: &str| {
        lines(&[&format!(
            "EXTCAP gc=1+ki=1+fc=1+pd=1+mcl3=2048+aac=1+sm=0+si=5+dec=1+bt={bt}+kdf=1"
        )])
    };
    assert_eq!(button(&extcap("1")), Some(true));
    assert_eq!(button(&extcap("0")), Some(false));
    assert_eq!(button(&extcap("x")), None);
    assert_eq!(button(&lines(&["EXTCAP gc=1+ki=1"])), None);
    assert_eq!(button(&[]), None);
}

#[test]
fn each_slots_flag_is_read_as_gpg_card_reads_it() {
    let uif = |slot: usize, value: &str| lines(&[&format!("UIF-{slot} {value}")]);
    for (value, expected) in [
        ("%00+", Some(Touch::Off)),
        ("%01+", Some(Touch::On)),
        ("%02+", Some(Touch::On)),
        ("%03+", Some(Touch::Cached)),
        ("%04+", Some(Touch::Cached)),
        ("%FF+", Some(Touch::Off)),
        ("%05+", None),
    ] {
        assert_eq!(touch(&uif(2, value), 2), expected, "{value}");
    }
    assert_eq!(touch(&uif(1, "%01+"), 2), None, "another slot's flag");
    assert_eq!(touch(&[], 1), None);
}

#[test]
fn the_signature_pin_is_the_first_number_chv_status_gives() {
    assert_eq!(
        pin(&lines(&["CHV-STATUS +1+127+127+127+3+0+3"])),
        Some(SignaturePin::Once)
    );
    assert_eq!(
        pin(&lines(&["CHV-STATUS +0+127+127+127+3+0+3"])),
        Some(SignaturePin::Forced)
    );
    assert_eq!(pin(&lines(&["CHV-STATUS +2+127"])), None);
    assert_eq!(pin(&[]), None);
}

/// Only the first card says what it asks for; a key on another card, or in
/// a slot the first card did not say, is one whose touch is not known.
#[test]
fn what_the_first_card_says_attaches_to_its_own_keys_alone() {
    let listed = [
        (grip(SIGNING), serial(CARD), Some(1)),
        (grip(DECRYPTING), serial(CARD), Some(2)),
        (grip(PIV), serial(OTHER), None),
    ];
    let first = First {
        serial: Some(serial(CARD)),
        touches: [Some(Touch::On), None, Some(Touch::Off)],
        pin: Some(SignaturePin::Forced),
        ..First::default()
    };
    assert_eq!(
        cards(&listed, &first),
        [
            Card {
                serial: serial(CARD),
                keys: vec![
                    Held {
                        grip: grip(SIGNING),
                        touch: Some(Touch::On),
                    },
                    Held {
                        grip: grip(DECRYPTING),
                        touch: None,
                    },
                ],
                pin: Some(SignaturePin::Forced),
            },
            Card {
                serial: serial(OTHER),
                keys: vec![Held {
                    grip: grip(PIV),
                    touch: None,
                }],
                pin: None,
            },
        ]
    );
    let unsaid = cards(&listed, &First::default());
    assert!(
        unsaid
            .iter()
            .all(|card| card.pin.is_none() && card.keys.iter().all(|held| held.touch.is_none()))
    );
}

#[test]
fn card_list_names_each_card_scdaemon_holds() {
    assert_eq!(
        held(&lines(&[
            &format!("SERIALNO {CARD}"),
            &format!("SERIALNO {OTHER}"),
            "PROGRESS learncard k 0 0",
            "SERIALNO",
        ])),
        [serial(CARD), serial(OTHER)]
    );
    assert_eq!(held(&[]), []);
}

const SIGNING_FPR: &str = "1111111111111111111111111111111111111111";
const DECRYPTING_FPR: &str = "2222222222222222222222222222222222222222";
const ELSEWHERE_FPR: &str = "3333333333333333333333333333333333333333";

fn fingerprint(text: &str) -> Fingerprint {
    Fingerprint::try_from(text).unwrap()
}

#[test]
fn key_fpr_names_the_key_in_each_slot() {
    assert_eq!(
        slots(&lines(&[
            &format!("KEY-FPR 1 {SIGNING_FPR}"),
            &format!("KEY-FPR 3 {DECRYPTING_FPR}"),
            &format!("KEY-FPR 4 {ELSEWHERE_FPR}"),
            &format!("KEY-FPR 0 {ELSEWHERE_FPR}"),
            &format!("KEY-FPR x {ELSEWHERE_FPR}"),
            "KEY-FPR 2 1234",
        ])),
        [
            Some(fingerprint(SIGNING_FPR)),
            None,
            Some(fingerprint(DECRYPTING_FPR)),
        ]
    );
    assert_eq!(slots(&[]), [None, None, None]);
}

fn key(grip_text: &str, fingerprint_text: &str) -> Key {
    Key {
        grip: grip(grip_text),
        fingerprint: fingerprint(fingerprint_text),
        primary: fingerprint(SIGNING_FPR),
        uses: Uses::SIGN,
        user: None,
        card: Some(serial(CARD)),
        ssh: None,
    }
}

/// The card as the core knows it: its two `OpenPGP` keys and a PIV key the
/// keyring does not hold, read when the signing key asked for a touch.
fn known() -> Card {
    Card {
        serial: serial(CARD),
        keys: vec![
            Held {
                grip: grip(SIGNING),
                touch: Some(Touch::On),
            },
            Held {
                grip: grip(DECRYPTING),
                touch: None,
            },
            Held {
                grip: grip(PIV),
                touch: None,
            },
        ],
        pin: Some(SignaturePin::Forced),
    }
}

fn keyring() -> Keyring {
    Keyring {
        keys: vec![key(SIGNING, SIGNING_FPR), key(DECRYPTING, DECRYPTING_FPR)],
        signing: None,
    }
}

fn first(slots: [Option<&str>; 3]) -> First {
    First {
        serial: Some(serial(CARD)),
        touches: [Some(Touch::Off), Some(Touch::Cached), Some(Touch::On)],
        pin: Some(SignaturePin::Once),
        slots: slots.map(|slot| slot.map(fingerprint)),
    }
}

/// A known card whose slots hold the keys it is known to hold is read from
/// its attributes alone: every key kept, each slot's key with what the card
/// asks now, a key outside the slots unsaid, so its earlier word stands.
#[test]
fn a_known_card_is_read_again_from_its_attributes_alone() {
    let again = from_attributes(
        &known(),
        &keyring(),
        &first([Some(SIGNING_FPR), Some(DECRYPTING_FPR), None]),
    );
    assert_eq!(
        again,
        Some(Card {
            serial: serial(CARD),
            keys: vec![
                Held {
                    grip: grip(SIGNING),
                    touch: Some(Touch::Off),
                },
                Held {
                    grip: grip(DECRYPTING),
                    touch: Some(Touch::Cached),
                },
                Held {
                    grip: grip(PIV),
                    touch: None,
                },
            ],
            pin: Some(SignaturePin::Once),
        })
    );
    // The fold keeps every key the card is known to hold.
    let folded = known().read_again(again.as_ref().unwrap());
    assert_eq!(folded.keys.len(), 3);
    assert_eq!(folded.touch(&grip(SIGNING)), Some(Touch::Off));
}

/// What attributes alone cannot account for has the cards walked: another
/// card first, a slot holding a key the keyring does not name, a slot holding
/// a key the card is not known to hold, a key the card is known to hold taken
/// out of the slots.
#[test]
fn a_card_whose_slots_changed_is_not_read_from_its_attributes() {
    let mut elsewhere = first([Some(SIGNING_FPR), Some(DECRYPTING_FPR), None]);
    elsewhere.serial = Some(serial(OTHER));
    assert_eq!(from_attributes(&known(), &keyring(), &elsewhere), None);
    let unnamed = first([Some(SIGNING_FPR), Some(DECRYPTING_FPR), Some(ELSEWHERE_FPR)]);
    assert_eq!(from_attributes(&known(), &keyring(), &unnamed), None);
    let mut wider = keyring();
    wider.keys.push(key(
        "4444444444444444444444444444444444444444",
        ELSEWHERE_FPR,
    ));
    assert_eq!(from_attributes(&known(), &wider, &unnamed), None);
    let taken_out = first([Some(SIGNING_FPR), None, None]);
    assert_eq!(from_attributes(&known(), &keyring(), &taken_out), None);
    let mut none_said = first([None, None, None]);
    none_said.serial = None;
    assert_eq!(from_attributes(&known(), &keyring(), &none_said), None);
}

/// A card none of whose keys the keyring names is read from its attributes
/// with every key unsaid, and its PIN as it says now.
#[test]
fn a_card_the_keyring_names_nothing_on_keeps_every_key_unsaid() {
    let piv_only = Card {
        serial: serial(CARD),
        keys: vec![Held {
            grip: grip(PIV),
            touch: Some(Touch::On),
        }],
        pin: None,
    };
    let again = from_attributes(&piv_only, &keyring(), &first([None, None, None])).unwrap();
    assert_eq!(again.keys[0].touch, None);
    assert_eq!(again.pin, Some(SignaturePin::Once));
    assert_eq!(
        piv_only.read_again(&again).touch(&grip(PIV)),
        Some(Touch::On)
    );
}
