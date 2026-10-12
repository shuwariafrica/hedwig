//! The card readers, against what scdaemon 2.5.24 writes: `SCD KEYINFO
//! --list` (`scd/command.c`, `send_keyinfo`; `scd/app-openpgp.c`,
//! `send_keyinfo_if_available`), and `GETATTR EXTCAP`, `UIF` and
//! `CHV-STATUS` (`scd/app-openpgp.c`, `do_getattr`), each escaped as
//! `send_status_info` escapes a value: `%XX` for a control byte, `+`, `"` and
//! `%`, and `+` for a blank.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use hedwig_core::keys::{First, button, cards, on_cards, pin, touch};
use hedwig_model::text::{Grip, Serial};
use hedwig_model::trail::{Card, Held, SignaturePin, Touch};

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
