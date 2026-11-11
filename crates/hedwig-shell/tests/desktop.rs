//! The native surfaces, exercised against the session this suite runs in.
//!
//! At a desktop it puts an icon in the notification area and a card on the
//! screen for a few seconds, both titled "hedwig probe", and removes them. In
//! a session with no desktop - an SSH logon - it checks that the shell refuses
//! the icon and says so. It prints which it met. Nothing it shows is given
//! the foreground: what it does to the card it does by sending the card's own
//! windows the messages Windows would.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::time::Duration;

use hedwig_model::capability::Operation;
use hedwig_model::protocol::Attention;
use hedwig_model::protocol::Offering;
use hedwig_model::remote::RemoteId;
use hedwig_model::text::{Address, Fingerprint, Grip, Name, Words};
use hedwig_model::trail::{Key, Keyring, Uses};
use hedwig_model::trail::{PromptId, PromptKind, RequestId, Seq};
use hedwig_shell::card::{
    ALLOWS, ANSWER, BEHIND, CONTENT, FACT, HEADING, NAME, SAYS, Shown, TYPED,
};
use hedwig_shell::host::{Host, Told};
use hedwig_shell::icon::{self, Icon, Nudge};
use hedwig_shell::{desk, settings};
use hedwig_view::arrange::{Layer, Part};
use hedwig_view::card::{self, Card, Why};
use hedwig_view::emblem::{Badge, Emblem, Owl};
use hedwig_view::style::{Colours, pixels};
use hedwig_view::words::Keyrings;
use windows_sys::Win32::Foundation::{HWND, POINT, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MapWindowPoints, MonitorFromWindow,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::Accessibility::{HWINEVENTHOOK, SetWinEventHook, UnhookWinEvent};
use windows_sys::Win32::UI::HiDpi::{
    AreDpiAwarenessContextsEqual, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForWindow,
    GetThreadDpiAwarenessContext,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    IsWindowEnabled, SetActiveWindow, SetFocus, VK_RETURN, VK_TAB,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, EVENT_SYSTEM_ALERT, GUITHREADINFO, GWL_EXSTYLE, GWL_STYLE,
    GetClassNameW, GetForegroundWindow, GetGUIThreadInfo, GetSystemMetrics, GetWindowLongPtrW,
    GetWindowRect, GetWindowTextW, IDCANCEL, IsDialogMessageW, IsWindowVisible, MSG, PostMessageW,
    SM_CXSCREEN, SM_CYSCREEN, SPI_GETWORKAREA, SendMessageW, SetForegroundWindow, SetWindowTextW,
    SystemParametersInfoW, WA_CLICKACTIVE, WINEVENT_OUTOFCONTEXT, WM_ACTIVATE, WM_CHAR, WM_COMMAND,
    WM_KEYDOWN, WM_SYSCHAR, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};

fn remote() -> RemoteId {
    RemoteId {
        route: Name::try_from("coder").unwrap(),
        address: Address::try_from("dev/build").unwrap(),
    }
}

/// What a held request looks like to the person, with a key and the three
/// lengths Hedwig ships, and two more waiting behind it.
fn sample() -> Card {
    let request = Attention::Request {
        payload: None,
        request: RequestId(Seq(9)),
        remote: remote(),
        capability: Name::try_from("gpg").unwrap(),
        operation: Operation::Sign,
        key: Some(hedwig_model::text::KeyId::Grip(grip())),
        offers: [60, 900, 3600]
            .map(|seconds| std::num::NonZeroU32::new(seconds).unwrap())
            .to_vec(),
        capped: None,
    };
    // An address admits no `&`; a key's user ID does.
    let offered = [Offering {
        capability: Name::try_from("gpg").unwrap(),
        keyring: Keyring {
            keys: vec![Key {
                ssh: None,
                grip: grip(),
                fingerprint: Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2")
                    .unwrap(),
                primary: Fingerprint::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap(),
                uses: Uses::SIGN,
                user: Some(Words::try_from("R&D Builds <rd@example.org>").unwrap()),
                card: None,
            }],
            signing: None,
        },
    }];
    Card::of(
        &request,
        Why {
            keyrings: Keyrings::new(Some(&offered), &[]),
            ..Why::default()
        },
        2,
    )
    .unwrap()
}

fn grip() -> Grip {
    Grip::try_from("AA11BB22CC33DD44EE55FF6600771188992233AA").unwrap()
}

fn text(control: HWND) -> String {
    let mut units = [0u16; 512];
    // SAFETY: the buffer is writable for the length given; a null window
    // answers nothing.
    let length = unsafe { GetWindowTextW(control, units.as_mut_ptr(), 512) };
    String::from_utf16_lossy(units.get(..usize::try_from(length).unwrap()).unwrap())
}

fn class(control: HWND) -> String {
    let mut units = [0u16; 64];
    // SAFETY: as in `text`.
    let length = unsafe { GetClassNameW(control, units.as_mut_ptr(), 64) };
    String::from_utf16_lossy(units.get(..usize::try_from(length).unwrap()).unwrap())
}

fn enabled(control: HWND) -> bool {
    // SAFETY: the handle is a control of a live dialog, or null.
    unsafe { IsWindowEnabled(control) != 0 }
}

/// A control's place in the window that holds it.
fn within(control: HWND, holder: HWND) -> (i32, i32, i32, i32) {
    let mut area = RECT::default();
    // SAFETY: the rectangle is a valid place for the window's.
    unsafe { GetWindowRect(control, &raw mut area) };
    // SAFETY: a rectangle is two points, mapped from the screen to the
    // holder's client area.
    unsafe {
        MapWindowPoints(
            std::ptr::null_mut(),
            holder,
            (&raw mut area).cast::<POINT>(),
            2,
        )
    };
    (
        area.left,
        area.top,
        area.right - area.left,
        area.bottom - area.top,
    )
}

/// The window this thread has active and the one that has its focus.
fn own_focus() -> (HWND, HWND) {
    let mut info = GUITHREADINFO {
        cbSize: u32::try_from(size_of::<GUITHREADINFO>()).unwrap(),
        ..GUITHREADINFO::default()
    };
    // SAFETY: no arguments.
    let thread = unsafe { GetCurrentThreadId() };
    // SAFETY: the structure states its size and the thread is this one.
    unsafe { GetGUIThreadInfo(thread, &raw mut info) };
    (info.hwndActive, info.hwndFocus)
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one card, shown once, asked everything"
)]
#[ignore = "needs the desktop's foreground"]
fn the_icon_and_the_card_at_this_desktop() {
    let interactive = desk::interactive();
    let desktop = desk::desktop();
    println!(
        "this session: desktop {interactive}, locked {}, disconnected {}, takes {:?}, \
         double-click {} ms",
        desktop.locked,
        desktop.disconnected,
        desktop.desk,
        desk::settle()
    );
    let host = Host::new().expect("an unshown window can be made in any session");
    let side = icon::side(&host);
    let quiet = Emblem {
        owl: Owl::Dozing,
        badge: Badge::Nothing,
    }
    .draw(side, settings::ink());
    if !interactive {
        // An SSH session: no shell to add an icon to, and the call says so.
        let refused = Icon::add(
            &host,
            "hedwig probe",
            "hedwig probe - nothing is connected",
            &quiet,
        )
        .unwrap_err();
        println!("no desktop here; the shell refused the icon: {refused}");
        return;
    }

    // The icon: added, where the shell put it, and its tooltip and emblem
    // changed.
    let mut icon = Icon::add(
        &host,
        "hedwig probe",
        "hedwig probe - nothing is connected",
        &quiet,
    )
    .expect("the icon is added");
    println!("the icon is at {:?}, {side} pixels square", icon.place());
    assert!(icon.place().is_some());
    icon.say("hedwig probe - reachable from 2 remotes - 1 waiting for your answer")
        .expect("the tooltip changes");
    icon.show(
        &Emblem {
            owl: Owl::Awake,
            badge: Badge::Answer,
        }
        .draw(side, settings::ink()),
    )
    .expect("the emblem changes");

    // The card: made unshown, then raised without the focus.
    let card = sample();
    let appearance = settings::read();
    // SAFETY: no arguments.
    let before = unsafe { GetForegroundWindow() };
    let shown =
        Shown::new("hedwig probe", &card, &appearance, icon.place()).expect("the card is made");
    let dialog: HWND = shown.window();
    // SAFETY: the dialog is alive for as long as `shown` is.
    assert_eq!(unsafe { IsWindowVisible(dialog) }, 0, "made unshown");
    shown.raise().expect("the card is raised");
    assert_eq!(host.told(Duration::from_millis(300)), Vec::<Told>::new());

    // SAFETY: as above.
    assert_ne!(unsafe { IsWindowVisible(dialog) }, 0, "shown");
    // SAFETY: as above.
    let style = unsafe { GetWindowLongPtrW(dialog, GWL_EXSTYLE) };
    assert_ne!(
        style & isize::try_from(WS_EX_TOPMOST).unwrap(),
        0,
        "above other windows"
    );
    // SAFETY: no arguments.
    let after = unsafe { GetForegroundWindow() };
    println!("foreground window before {before:?}, after {after:?}, the card {dialog:?}");
    assert_ne!(after, dialog, "the card did not take the foreground");
    let (active, focus) = own_focus();
    assert!(
        active.is_null() && focus.is_null(),
        "nothing of ours is active or focused"
    );

    // What it says is what the view said, an `&` in a mark shown as itself.
    assert_eq!(text(shown.control(HEADING)), card.heading);
    assert_eq!(card.heading, "dev/build (coder) asks to sign with gpg");
    for (place, (name, fact)) in card.facts.iter().enumerate() {
        let place = u16::try_from(place).unwrap();
        assert_eq!(text(shown.control(NAME + place)), *name);
        assert_eq!(text(shown.control(FACT + place)), *fact);
    }
    assert!(text(shown.control(FACT + 2)).contains("(R&D Builds"));
    // Hedwig sets every line itself, and each keeps its words where a screen
    // reader reads them: a static control of the owner-drawn kind.
    for id in [HEADING, NAME, FACT, NAME + 2, FACT + 2, ALLOWS, BEHIND] {
        let line = shown.control(id);
        assert_eq!(class(line), "Static");
        // SAFETY: the control is alive for as long as `shown` is.
        let style = unsafe { GetWindowLongPtrW(line, GWL_STYLE) };
        assert_eq!(style & 0x1f, 0x0d, "{id} is owner-drawn");
    }
    assert_eq!(Some(text(shown.control(ALLOWS))), card.allows);
    assert_eq!(Some(text(shown.control(BEHIND))), card.waiting());
    assert!(
        shown.control(TYPED).is_null(),
        "nothing is typed at a request"
    );

    // Every answer is one of Windows' own buttons, where the view put it,
    // and takes no press before the card has settled.
    let labels = card::keyed(card.choices.iter().map(|choice| choice.label.as_str()));
    let arranged = shown.arrangement().unwrap();
    // SAFETY: the dialog is alive.
    let dpi = unsafe { GetDpiForWindow(dialog) };
    let rings = pixels(3.0, dpi);
    assert_eq!(labels.len(), 6);
    for (place, label) in labels.iter().enumerate() {
        let answer = shown.control(ANSWER + u16::try_from(place).unwrap());
        assert_eq!(text(answer), *label);
        assert_eq!(class(answer), "Button");
        assert!(
            !enabled(answer),
            "no answer is taken before the card settles"
        );
        let placed = arranged.place(Part::Choice(place)).unwrap();
        let (holder, down) = match placed.layer {
            Layer::Content => (shown.control(CONTENT), 0),
            Layer::Answers => (dialog, arranged.shown),
        };
        assert_eq!(
            within(answer, holder),
            (
                placed.rect.left - rings,
                placed.rect.top + down - rings,
                placed.rect.width + 2 * rings,
                placed.rect.height + 2 * rings
            ),
            "{label}"
        );
    }
    shown.arm(true);
    assert!(enabled(shown.control(ANSWER)) && enabled(shown.control(ANSWER + 5)));

    // An answer pressed is told with its place, whichever layer it is in.
    for place in [0usize, 2, 5] {
        let id = ANSWER + u16::try_from(place).unwrap();
        let holder: HWND = match arranged.place(Part::Choice(place)).unwrap().layer {
            Layer::Content => shown.control(CONTENT),
            Layer::Answers => dialog,
        };
        // SAFETY: what a button tells the window that holds it when it is
        // pressed; the message carries no pointer that is followed.
        unsafe {
            SendMessageW(
                holder,
                WM_COMMAND,
                usize::from(id),
                shown.control(id) as isize,
            )
        };
        assert_eq!(
            host.told(Duration::ZERO),
            [Told::Answered(u16::try_from(place).unwrap())]
        );
    }

    // Brought forward by the keyboard or by Windows, the card's answers are
    // off until it has settled again, and no answer has the keyboard. It is
    // made active for this thread alone: the foreground stays where it was.
    // SAFETY: the dialog is this thread's own.
    unsafe { SetActiveWindow(dialog) };
    assert_eq!(host.told(Duration::ZERO), [Told::Forward]);
    assert!(!enabled(shown.control(ANSWER)) && !enabled(shown.control(ANSWER + 5)));
    // SAFETY: no arguments.
    let foreground = unsafe { GetForegroundWindow() };
    assert_eq!(foreground, after, "the foreground is untouched");
    shown.arm(true);
    let on_an_answer = |focus: HWND| (0..6).any(|place| shown.control(ANSWER + place) == focus);
    assert!(!on_an_answer(own_focus().1), "no answer has the keyboard");

    // No stray key decides. With the keyboard on no answer, a letter and
    // ENTER each do nothing.
    // SAFETY: posting carries no pointer.
    unsafe { PostMessageW(dialog, WM_CHAR, usize::from(b'r'), 0) };
    assert_eq!(host.told(Duration::from_millis(100)), Vec::<Told>::new());
    // SAFETY: as above.
    unsafe { PostMessageW(dialog, WM_KEYDOWN, usize::from(VK_RETURN), 0) };
    assert!(
        host.told(Duration::from_millis(100)).is_empty(),
        "no default"
    );
    // TAB puts the keyboard on the first answer of the work, and ENTER then
    // takes it: two keys, and the second one meant.
    // SAFETY: as above.
    unsafe { PostMessageW(dialog, WM_KEYDOWN, usize::from(VK_TAB), 0) };
    assert_eq!(host.told(Duration::from_millis(100)), Vec::<Told>::new());
    let first: HWND = shown.control(ANSWER);
    assert_eq!(own_focus().1, first, "Allow once has the keyboard");
    // SAFETY: as above.
    unsafe { PostMessageW(first, WM_KEYDOWN, usize::from(VK_RETURN), 0) };
    assert_eq!(host.told(Duration::from_millis(100)), [Told::Answered(0)]);
    // With the keyboard on an answer, a letter typed without ALT is held
    // back from the dialog manager: nothing is told and the keyboard stays.
    // SAFETY: as above.
    unsafe { PostMessageW(first, WM_CHAR, usize::from(b'r'), 0) };
    assert!(
        host.told(Duration::from_millis(100)).is_empty(),
        "held back"
    );
    assert_eq!(own_focus().1, first);
    // Handed to the dialog manager, the same letter presses the answer whose
    // access key it is: this is what holding it back prevents.
    let letter = MSG {
        hwnd: first,
        message: WM_CHAR,
        wParam: usize::from(b'r'),
        ..MSG::default()
    };
    // SAFETY: the message is whole.
    assert_ne!(unsafe { IsDialogMessageW(dialog, &raw const letter) }, 0);
    assert_eq!(
        host.told(Duration::ZERO),
        [Told::Answered(4)],
        "a bare R presses Refuse"
    );
    // ALT and the letter is the access key, whether or not an answer has
    // the keyboard.
    // SAFETY: the dialog is this thread's own.
    unsafe { SetFocus(dialog) };
    // SAFETY: posting carries no pointer; bit 29 says ALT is down.
    unsafe { PostMessageW(dialog, WM_SYSCHAR, usize::from(b'p'), 1 << 29) };
    assert_eq!(
        host.told(Duration::from_millis(100)),
        [Told::Answered(5)],
        "ALT+P pauses"
    );
    // A click on the card is the person's own act on it: the answers stay on.
    // SAFETY: the dialog is alive; the message carries no pointer.
    unsafe {
        SendMessageW(
            dialog,
            WM_ACTIVATE,
            usize::try_from(WA_CLICKACTIVE).unwrap(),
            0,
        )
    };
    assert_eq!(host.told(Duration::ZERO), Vec::<Told>::new());
    assert!(enabled(shown.control(ANSWER)));

    // Escape puts the card aside.
    // SAFETY: as above.
    unsafe { SendMessageW(dialog, WM_COMMAND, usize::try_from(IDCANCEL).unwrap(), 0) };
    assert_eq!(host.told(Duration::ZERO), [Told::Aside]);
    // SAFETY: as above.
    assert_eq!(unsafe { IsWindowVisible(dialog) }, 0, "put aside");

    // A notification through the icon is taken by the shell.
    icon.nudge(
        "hedwig probe",
        "A probe of Hedwig's notification. It removes itself.",
        Nudge::Quiet,
    )
    .expect("the shell takes the notification");
    host.told(Duration::from_millis(1500));

    drop(shown);
    drop(icon);
    host.told(Duration::from_millis(100));
}

/// A prompt whose answer is typed has Windows' own edit box, hiding what is
/// typed, and ENTER sends only once something is in it.
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_typed_answer_is_sent_by_enter_only_when_something_was_typed() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let host = Host::new().expect("an unshown window");
    let item = Attention::Prompt {
        prompt: PromptId(Seq(4)),
        remote: remote(),
        kind: PromptKind::KeyPassphrase,
        words: Words::try_from("Enter passphrase for key '/home/dev/.ssh/id_ed25519':").unwrap(),
    };
    let card = Card::of(&item, Why::default(), 0).unwrap();
    let shown = Shown::new("hedwig probe", &card, &settings::read(), None).expect("the card");
    shown.raise().expect("raised");
    shown.arm(true);
    let typed: HWND = shown.control(TYPED);
    assert_eq!(class(typed), "Edit");
    // SAFETY: the control is alive.
    let style = unsafe { GetWindowLongPtrW(typed, GWL_STYLE) };
    assert_ne!(style & 0x20, 0, "what is typed is hidden");
    assert_eq!(text(shown.control(FACT + 1)), card.facts.get(1).unwrap().1);

    // Brought forward, the keyboard is in the box and nowhere else. With
    // nothing typed ENTER sends nothing; with something typed it sends.
    // SAFETY: no arguments.
    let before = unsafe { GetForegroundWindow() };
    // SAFETY: the dialog is this thread's own.
    unsafe { SetActiveWindow(shown.window()) };
    assert_eq!(host.told(Duration::ZERO), [Told::Forward]);
    // SAFETY: no arguments.
    assert_eq!(unsafe { GetForegroundWindow() }, before);
    shown.arm(true);
    assert_eq!(own_focus().1, typed, "the keyboard is in the box");
    let enter = || {
        // SAFETY: posting carries no pointer.
        unsafe { PostMessageW(typed, WM_KEYDOWN, usize::from(VK_RETURN), 0) };
        host.told(Duration::from_millis(100))
    };
    assert!(enter().is_empty(), "nothing typed, nothing sent");
    let something: Vec<u16> = "probe\0".encode_utf16().collect();
    // SAFETY: the text is NUL-terminated and copied by the call.
    unsafe { SetWindowTextW(typed, something.as_ptr()) };
    let send = u16::try_from(
        card.choices
            .iter()
            .position(|choice| choice.label == "Send")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(enter(), [Told::Answered(send)]);
    // A letter typed in the box is the box's, never an access key.
    // SAFETY: posting carries no pointer.
    unsafe { PostMessageW(typed, WM_CHAR, usize::from(b'd'), 0) };
    assert_eq!(host.told(Duration::from_millis(100)), Vec::<Told>::new());
    // What was typed is taken out, and the box keeps nothing of it.
    // Set text leaves the caret at its start, where the letter went.
    assert_eq!(shown.take_typed().as_deref(), Some("dprobe"));
    assert_eq!(text(typed), "");
    drop(shown);
    host.told(Duration::from_millis(50));
}

/// A confirmation of an act the person chose is a dialog of the card's
/// construction that the person asked for: it takes the keyboard, on its safe
/// answer, and stands in the middle of the work area. It is shown beside a
/// card, each drawn from its own look, and neither answer is ever off. ENTER
/// and ESCAPE cancel; ALT and the verb's letter go ahead.
#[test]
#[allow(clippy::too_many_lines, reason = "one confirmation, asked everything")]
#[ignore = "needs the desktop's foreground"]
fn a_confirmation_has_the_keyboard_on_cancel_beside_a_card() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let host = Host::new().expect("an unshown window");
    let card = sample();
    let held = Shown::new("hedwig probe", &card, &settings::read(), None).expect("the card");
    held.raise().expect("raised");
    let consequence = "Every remote loses what you granted it until Hedwig is started again, \
    and whatever is being served ends now.";
    let confirming = Card::confirming("Stop Hedwig", consequence);
    let asked =
        Shown::new("hedwig probe", &confirming, &settings::read(), None).expect("the confirmation");
    asked.ask();
    let told = host.told(Duration::from_millis(100));
    assert!(!told.contains(&Told::Forward), "{told:?}");
    let dialog: HWND = asked.window();

    // It has the keyboard, on "Cancel", and its answers are on.
    let (active, focus) = own_focus();
    assert_eq!(active, dialog);
    let (go, cancel): (HWND, HWND) = (asked.control(ANSWER), asked.control(ANSWER + 1));
    assert_eq!(focus, cancel, "the keyboard starts on the safe answer");
    assert!(enabled(go) && enabled(cancel));
    assert_eq!(
        (text(go), text(cancel)),
        ("&Stop Hedwig".to_owned(), "&Cancel".to_owned())
    );
    assert_eq!(text(asked.control(HEADING)), "Stop Hedwig?");
    assert_eq!(text(asked.control(SAYS)), consequence);
    assert_eq!(class(asked.control(SAYS)), "Static");
    // SAFETY: the window is alive.
    let extended = unsafe { GetWindowLongPtrW(dialog, GWL_EXSTYLE) };
    assert_ne!(
        extended & isize::try_from(WS_EX_TOPMOST).unwrap(),
        0,
        "above other windows"
    );

    // In the middle of its monitor's work area.
    let mut place = RECT::default();
    // SAFETY: the rectangle is a valid place for the window's.
    unsafe { GetWindowRect(dialog, &raw mut place) };
    // SAFETY: no pointers.
    let monitor = unsafe { MonitorFromWindow(dialog, MONITOR_DEFAULTTONEAREST) };
    let mut info = MONITORINFO {
        cbSize: u32::try_from(size_of::<MONITORINFO>()).unwrap(),
        ..MONITORINFO::default()
    };
    // SAFETY: the structure states its size.
    unsafe { GetMonitorInfoW(monitor, &raw mut info) };
    let work = info.rcWork;
    assert!(
        ((place.left + place.right) - (work.left + work.right)).abs() <= 1,
        "{:?} in {:?}",
        (place.left, place.top, place.right, place.bottom),
        (work.left, work.top, work.right, work.bottom)
    );
    assert!(
        ((place.top + place.bottom) - (work.top + work.bottom)).abs() <= 1,
        "{:?} in {:?}",
        (place.left, place.top, place.right, place.bottom),
        (work.left, work.top, work.right, work.bottom)
    );

    // Each dialog is drawn and arranged from its own look.
    let (card_arranged, asked_arranged) =
        (held.arrangement().unwrap(), asked.arrangement().unwrap());
    assert!(card_arranged.place(Part::Says).is_none());
    assert!(asked_arranged.place(Part::Says).is_some());
    assert_eq!(asked_arranged.order, [0, 1]);

    // ENTER takes the answer that has the keyboard: "Cancel".
    // SAFETY: posting carries no pointer.
    unsafe { PostMessageW(cancel, WM_KEYDOWN, usize::from(VK_RETURN), 0) };
    assert_eq!(
        host.told(Duration::from_millis(100)),
        [Told::Confirmed(None)]
    );
    // ESCAPE is "Cancel".
    // SAFETY: as above.
    unsafe { SendMessageW(dialog, WM_COMMAND, usize::try_from(IDCANCEL).unwrap(), 0) };
    assert_eq!(host.told(Duration::ZERO), [Told::Confirmed(None)]);
    // SAFETY: as above.
    let visible = unsafe { IsWindowVisible(dialog) };
    assert_ne!(visible, 0, "the loop lets it go, not the dialog");
    // A letter without ALT does nothing; ALT and S go ahead.
    // SAFETY: posting carries no pointer.
    unsafe { PostMessageW(cancel, WM_CHAR, usize::from(b's'), 0) };
    assert_eq!(host.told(Duration::from_millis(100)), Vec::<Told>::new());
    // SAFETY: as above; bit 29 says ALT is down.
    unsafe { PostMessageW(cancel, WM_SYSCHAR, usize::from(b's'), 1 << 29) };
    assert_eq!(
        host.told(Duration::from_millis(100)),
        [Told::Confirmed(Some(0))]
    );
    // TAB goes to "Stop Hedwig", and ENTER then takes it.
    // SAFETY: posting carries no pointer.
    unsafe { PostMessageW(cancel, WM_KEYDOWN, usize::from(VK_TAB), 0) };
    host.told(Duration::from_millis(50));
    assert_eq!(own_focus().1, go);
    // SAFETY: as above.
    unsafe { PostMessageW(go, WM_KEYDOWN, usize::from(VK_RETURN), 0) };
    assert_eq!(
        host.told(Duration::from_millis(100)),
        [Told::Confirmed(Some(0))]
    );

    // The card is untouched by it: still off, still its own.
    assert!(!enabled(held.control(ANSWER)), "the card has not settled");
    drop(asked);
    host.told(Duration::from_millis(50));
    assert!(held.arrangement().is_some(), "the card keeps its look");
    assert_eq!(text(held.control(HEADING)), card.heading);
    drop(held);
    host.told(Duration::from_millis(50));
}

/// The alerts this thread was told of: the window each came from.
static ALERTS: std::sync::Mutex<Vec<isize>> = std::sync::Mutex::new(Vec::new());

unsafe extern "system" fn alerted(
    _hook: HWINEVENTHOOK,
    _event: u32,
    window: HWND,
    _object: i32,
    _child: i32,
    _thread: u32,
    _time: u32,
) {
    ALERTS.lock().unwrap().push(window as isize);
}

/// A card is not given the keyboard, so nothing would announce it: it raises
/// an alert from its content, which assistive technology is told is an alert
/// named by the card's question (read back by `painted/accessible.ps1`).
#[test]
#[ignore = "needs the desktop's foreground"]
fn a_card_comes_up_as_an_alert_named_by_its_question() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let host = Host::new().expect("an unshown window");
    // SAFETY: the procedure lives as long as the process; out of context,
    // Windows calls it on this thread from its message loop.
    let hook = unsafe {
        SetWinEventHook(
            EVENT_SYSTEM_ALERT,
            EVENT_SYSTEM_ALERT,
            std::ptr::null_mut(),
            Some(alerted),
            std::process::id(),
            0,
            WINEVENT_OUTOFCONTEXT,
        )
    };
    assert!(!hook.is_null());
    let card = sample();
    let shown = Shown::new("hedwig probe", &card, &settings::read(), None).expect("the card");
    shown.raise().expect("raised");
    host.told(Duration::from_millis(50));
    assert!(
        ALERTS.lock().unwrap().is_empty(),
        "raising alone says nothing"
    );
    shown.announce();
    host.told(Duration::from_millis(200));
    let content: HWND = shown.control(CONTENT);
    assert_eq!(*ALERTS.lock().unwrap(), [content as isize]);

    // SAFETY: the hook is this thread's own.
    unsafe { UnhookWinEvent(hook) };
    drop(shown);
    host.told(Duration::from_millis(50));
}

/// Nothing in Windows signals that an application began or stopped filling
/// the screen but an application desktop toolbar's notification. The host is
/// one without a place: the work area is what it was, and the shell says so
/// when a window fills the screen.
#[test]
#[ignore = "needs the desktop's foreground"]
fn the_shell_says_when_an_application_fills_the_screen() {
    assert!(desk::interactive(), "needs the desktop's foreground");
    let work = || {
        let mut area = RECT::default();
        // SAFETY: the action writes one rectangle through the pointer given.
        unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, (&raw mut area).cast(), 0) };
        (area.left, area.top, area.right, area.bottom)
    };
    let before = work();
    let host = Host::new().expect("an unshown window");
    host.told(Duration::from_millis(100));
    assert_eq!(work(), before, "no part of the screen is reserved");
    println!("the desktop takes {:?} before", desk::desk());

    // A window over the whole of the primary monitor, above the others.
    let class: Vec<u16> = "Static\0".encode_utf16().collect();
    let title: Vec<u16> = "hedwig probe\0".encode_utf16().collect();
    // SAFETY: no arguments.
    let width = unsafe { GetSystemMetrics(SM_CXSCREEN) };
    // SAFETY: no arguments.
    let height = unsafe { GetSystemMetrics(SM_CYSCREEN) };
    // SAFETY: both names are NUL-terminated; no parent makes it top-level.
    let full = unsafe {
        CreateWindowExW(
            WS_EX_TOPMOST,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP | WS_VISIBLE,
            0,
            0,
            width,
            height,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    };
    assert!(!full.is_null());
    // SAFETY: the window is this thread's own.
    let foreground = unsafe { SetForegroundWindow(full) } != 0;
    let told = host.told(Duration::from_millis(1500));
    let during = desk::desk();
    // SAFETY: as above.
    unsafe { DestroyWindow(full) };
    let after = host.told(Duration::from_millis(1500));
    println!(
        "a full-screen window, foreground {foreground}: told {told:?}, takes {during:?}; \
         closed: told {after:?}, takes {:?}",
        desk::desk()
    );
    assert_eq!(work(), before);
    if foreground {
        assert!(told.contains(&Told::Desk), "{told:?}");
        assert_eq!(during, card::Desk::Filled);
        assert!(after.contains(&Told::Desk), "{after:?}");
    }
    drop(host);
    assert_eq!(work(), before);
}

/// What the person has set is read from the Windows Runtime's `UISettings`
/// through the three calls the crate declares itself, in an unpackaged
/// process, and the two change events take the crate's own handler.
#[test]
fn the_persons_settings_are_read_and_watched_at_this_desktop() {
    let host = Host::new().expect("an unshown window can be made in any session");
    let (mode, accent, text) = settings::theme().expect("UISettings answers on the host's thread");
    println!(
        "this person's settings: {mode:?} mode, accent fill {} and text {}, text size {} per \
         cent, contrast theme {}, {:?}",
        accent.fill.hex(),
        accent.text.hex(),
        text.hundredths(),
        settings::contrast(),
        settings::motion()
    );
    assert!((100..=225).contains(&text.hundredths()));
    // The fill and the text are two shades of one accent, never one colour.
    assert_ne!(accent.fill, accent.text);

    let read = settings::read();
    assert_eq!(read.text, text);
    match read.colours {
        Colours::Theme {
            mode: read_mode,
            accent: read_accent,
        } => {
            assert!(!settings::contrast());
            assert_eq!((read_mode, read_accent), (mode, accent));
        }
        // A contrast theme's colours are the system's eight and nothing else.
        Colours::System(system) => {
            assert!(settings::contrast());
            assert_eq!(system, settings::system());
        }
    }

    // Both events accept the handler, and nothing is told while nothing
    // changes; letting the watch go takes the handler back out.
    let watch = settings::Watch::new(&host).expect("both events take the handler");
    let told = host.told(Duration::from_millis(200));
    assert!(!told.contains(&Told::End), "{told:?}");
    drop(watch);
    host.told(Duration::from_millis(50));
}

/// The manifest is a load-time dependency. This suite's executable carries
/// the interface's manifest and imports the task dialog, and it started; the
/// same code linked without the manifest is not started by Windows at all.
#[test]
fn the_manifest_selects_the_common_controls_and_the_scale_windows_11_draws_with() {
    // The common controls are loaded by the host, from the side-by-side
    // assembly the manifest names.
    let _host = Host::new().expect("an unshown window");
    let name: Vec<u16> = "comctl32.dll\0".encode_utf16().collect();
    // SAFETY: the name is NUL-terminated; the module is not freed.
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    assert!(!module.is_null(), "the common controls are loaded");
    let mut path = [0u16; 520];
    // SAFETY: the buffer is writable for the length given.
    let length = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), 520) };
    let path = String::from_utf16_lossy(path.get(..length as usize).unwrap()).to_lowercase();
    println!("common controls: {path}");
    assert!(
        path.contains("microsoft.windows.common-controls_6595b64144ccf1df_6.0."),
        "{path}"
    );
    // SAFETY: no arguments.
    let context = unsafe { GetThreadDpiAwarenessContext() };
    // SAFETY: both are awareness contexts.
    let equal = unsafe {
        AreDpiAwarenessContextsEqual(context, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)
    };
    assert_ne!(equal, 0, "per-monitor awareness, second version");
}
