//! A card put by a program of Hedwig's with no icon, at this desktop:
//! setup's question answered by each of its answers, and a card shown while
//! work runs, which offers none.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::{Duration, Instant};

use hedwig_shell::card::ANSWER;
use hedwig_shell::question::{Question, account};
use hedwig_view::setup;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetDlgItem, IDCANCEL, IsWindowVisible, PostMessageW, WM_COMMAND,
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// The question's window, titled `title`, once it is on the screen.
fn found(title: &str) -> HWND {
    let title = wide(title);
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        // SAFETY: the title is NUL-terminated; no class is named.
        let window = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
        // SAFETY: a null or stale handle answers zero.
        if !window.is_null() && unsafe { IsWindowVisible(window) } != 0 {
            return window;
        }
        assert!(Instant::now() < until, "the question was not shown");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Presses what `command` names on the question titled `title`, from
/// another thread, as a click or ESCAPE would.
fn press(title: &str, command: u16) -> std::thread::JoinHandle<()> {
    let title = title.to_owned();
    std::thread::spawn(move || {
        let window = found(&title);
        // A posted command, as a button sends its dialog when clicked.
        // SAFETY: posting carries no pointer.
        unsafe { PostMessageW(window, WM_COMMAND, usize::from(command), 0) };
    })
}

#[test]
fn setup_hears_which_answer_the_person_chose() {
    let title = format!("Hedwig setup probe {}", std::process::id());
    let mut question = Question::new(&title).unwrap();
    let account = account().unwrap();
    assert_ne!(account, "");
    let card = setup::asking(&account, r"C:\Programs\ShuwariAfrica\Hedwig");
    for (place, answer) in [(0, Some(0)), (1, Some(1)), (2, None)] {
        let pressing = press(&title, ANSWER + place);
        assert_eq!(question.ask(&card).unwrap(), answer, "answer {place}");
        pressing.join().unwrap();
        question.close();
    }
    // ESCAPE is "Cancel".
    let pressing = press(&title, u16::try_from(IDCANCEL).unwrap());
    assert_eq!(question.ask(&card).unwrap(), None);
    pressing.join().unwrap();
    question.close();
}

#[test]
fn a_card_shown_while_work_runs_offers_nothing_and_goes_when_it_is_done() {
    let title = format!("Hedwig removal probe {}", std::process::id());
    let mut question = Question::new(&title).unwrap();
    let looking = {
        let title = title.clone();
        std::thread::spawn(move || {
            let window = found(&title);
            // SAFETY: a control of the dialog, or null.
            unsafe { GetDlgItem(window, i32::from(ANSWER)) }.is_null()
        })
    };
    let done = question
        .during(&setup::installing("arash"), || {
            std::thread::sleep(Duration::from_millis(500));
            7
        })
        .unwrap();
    assert_eq!(done, 7);
    assert!(looking.join().unwrap(), "an answer was offered");
    question.close();
    let title = wide(&title);
    // SAFETY: the title is NUL-terminated.
    let left = unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) };
    assert!(left.is_null(), "the card stayed");
}
