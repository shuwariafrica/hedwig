//! Where each part of a card goes, for every kind of card the core can
//! raise, at each scale and text size, checked without a desktop.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use std::num::NonZeroU32;

use hedwig_model::capability::Operation;
use hedwig_model::protocol::Attention;
use hedwig_model::remote::RemoteId;
use hedwig_model::text::{Address, Grip, Name, Words};
use hedwig_model::trail::{PromptId, PromptKind, RequestId, Seq};
use hedwig_view::arrange::{self, Arranged, Layer, Measure, Part, Rect, Size, Space, arrange};
use hedwig_view::card::{Card, Weight, Why};
use hedwig_view::style::Type;

/// Text measured as a typewriter sets it: every character half its size
/// wide and a line 4/3 of it tall, at `scale` pixels to the effective pixel
/// and `text` hundredths of the text size Windows ships.
struct Typewriter {
    scale: f32,
    text: f32,
}

impl Measure for Typewriter {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_precision_loss,
        reason = "a test's arithmetic on small whole numbers"
    )]
    fn text(&self, style: Type, text: &str, width: Option<i32>) -> Size {
        let size = style.size() * self.scale * self.text;
        let advance = (size / 2.0).round() as i32;
        let line = (size * 4.0 / 3.0).round() as i32;
        let characters = text.chars().count() as i32;
        match width {
            None => Size {
                width: characters * advance,
                height: line,
            },
            Some(width) => {
                let fit = (width / advance).max(1);
                Size {
                    width: advance * characters.min(fit),
                    height: line * ((characters + fit - 1) / fit).max(1),
                }
            }
        }
    }
}

const PLAIN: Typewriter = Typewriter {
    scale: 1.0,
    text: 1.0,
};

fn name(text: &str) -> Name {
    Name::try_from(text).unwrap()
}

fn workspace() -> RemoteId {
    RemoteId {
        route: name("coder"),
        address: Address::try_from("dev/build").unwrap(),
    }
}

/// A request to sign, with a key and the three lengths Hedwig ships.
fn request(behind: u32) -> Card {
    let item = Attention::Request {
        payload: None,
        request: RequestId(Seq(9)),
        remote: workspace(),
        capability: name("gpg"),
        operation: Operation::Sign,
        key: Some(hedwig_model::text::KeyId::Grip(
            Grip::try_from("0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2").unwrap(),
        )),
        offers: [60, 900, 3600]
            .map(|seconds| NonZeroU32::new(seconds).unwrap())
            .to_vec(),
        capped: None,
    };
    Card::of(&item, Why::default(), behind).unwrap()
}

fn prompt(kind: PromptKind) -> Card {
    let item = Attention::Prompt {
        prompt: PromptId(Seq(4)),
        remote: workspace(),
        kind,
        words: Words::try_from("Enter passphrase for key '/home/dev/.ssh/id_ed25519':").unwrap(),
    };
    Card::of(&item, Why::default(), 0).unwrap()
}

fn place(arranged: &Arranged, part: Part) -> (Layer, Rect) {
    let placed = arranged.place(part).expect("the part is placed");
    (placed.layer, placed.rect)
}

fn choice(card: &Card, label: &str) -> Part {
    Part::Choice(
        card.choices
            .iter()
            .position(|choice| choice.label == label)
            .expect("the card offers the answer"),
    )
}

/// Nothing a card holds lies over anything else, outside the card or inside
/// its padding, whatever the card and the monitor.
fn sound(arranged: &Arranged, padding: i32) {
    for (at, one) in arranged.parts.iter().enumerate() {
        let rect = one.rect;
        assert!(rect.width > 0 && rect.height > 0, "{one:?}");
        assert!(rect.left >= padding, "{one:?}");
        assert!(rect.right() <= arranged.width - padding, "{one:?}");
        assert!(rect.top >= padding, "{one:?}");
        let floor = match one.layer {
            Layer::Content => arranged.extent,
            Layer::Answers => arranged.answers,
        };
        assert!(rect.bottom() <= floor - padding, "{one:?}");
        for other in arranged.parts.iter().skip(at + 1) {
            assert!(
                one.layer != other.layer || !rect.meets(&other.rect),
                "{one:?} lies over {other:?}"
            );
        }
    }
}

const ROOMY: Space = Space {
    dpi: 96,
    tallest: 2000,
};

/// A person mid-commit: the card has Windows 11's dialog measurements. It is
/// between 320 and 548 wide with 24 inside each layer; the heading is first;
/// each fact is under its name; the two answers fill the row in equal
/// columns 8 apart; nothing is cut.
#[test]
fn a_request_is_laid_out_as_windows_11_lays_out_a_dialog() {
    let card = request(0);
    let arranged = arrange(&card, &PLAIN, ROOMY);
    sound(&arranged, 24);
    assert!((320..=548).contains(&arranged.width), "{}", arranged.width);
    assert!(!arranged.scrolls());
    assert_eq!(arranged.height(), arranged.extent + arranged.answers);

    let (layer, heading) = place(&arranged, Part::Heading);
    assert_eq!((layer, heading.left, heading.top), (Layer::Content, 24, 24));
    let (_, first) = place(&arranged, Part::Name(0));
    assert_eq!(first.top, heading.bottom() + 12, "12 under the heading");
    for fact in 0..card.facts.len() {
        let (_, name) = place(&arranged, Part::Name(fact));
        let (_, value) = place(&arranged, Part::Fact(fact));
        assert_eq!(
            value.top,
            name.bottom(),
            "a fact is directly under its name"
        );
        if fact > 0 {
            let (_, above) = place(&arranged, Part::Fact(fact - 1));
            assert!(name.top >= above.bottom() + 12, "12 between facts");
        }
    }

    // The answers: "Allow once" then "Refuse", equal, 8 apart, filling the
    // row, 24 from each edge of their layer.
    let (layer, allow) = place(&arranged, choice(&card, "Allow once"));
    let (_, refuse) = place(&arranged, choice(&card, "Refuse"));
    assert_eq!(layer, Layer::Answers);
    assert_eq!((allow.left, allow.top), (24, 24));
    assert_eq!(refuse.left, allow.right() + 8);
    assert!(
        (0..=1).contains(&(refuse.width - allow.width)),
        "equal but for the pixel an odd width leaves"
    );
    assert_eq!(refuse.right(), arranged.width - 24);
    assert_eq!(arranged.answers, 24 + allow.height + 24);
    // A button is its text and WinUI's padding: 5 above, 6 below, a border.
    assert_eq!(allow.height, 19 + 5 + 6 + 2);
}

/// The card is as wide as WinUI makes a dialog: its texts are wrapped
/// within the widest a dialog may be, and it takes the width of the widest
/// line that gives. The sentence over the allowances is longer than any line
/// that fits, so its first line sets the width.
#[test]
fn a_sentence_that_wraps_sets_the_width_by_its_first_line() {
    let card = request(0);
    let arranged = arrange(&card, &PLAIN, ROOMY);
    // 500 inside the padding holds 71 characters of 7: the first line is 497.
    assert_eq!(arranged.width, 24 + 497 + 24);
    let (_, allows) = place(&arranged, Part::Allows);
    assert_eq!(allows.width, 497);
}

/// An allowance is one act on the card. Each length the person set is
/// an answer of its own in the content, side by side under the sentence that
/// says what it lets through, and never in the row of answers.
#[test]
fn each_allowance_is_one_act_under_what_it_lets_through() {
    let card = request(0);
    assert_eq!(
        card.allows.as_deref(),
        Some(
            "For that time, every request to sign with gpg with the key with keygrip \
             0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2 on this connection is served without \
             asking you."
        )
    );
    let arranged = arrange(&card, &PLAIN, ROOMY);
    let (_, says) = place(&arranged, Part::Allows);
    let labels = [
        "Allow for 1 minute",
        "Allow for 15 minutes",
        "Allow for 1 hour",
    ];
    let rects = labels.map(|label| place(&arranged, choice(&card, label)));
    for (layer, rect) in rects {
        assert_eq!(layer, Layer::Content);
        assert_eq!(rect.top, says.bottom() + 8, "8 under what heads them");
    }
    let [(_, first), (_, second), (_, third)] = rects;
    assert_eq!(first.left, 24);
    assert_eq!(second.left, first.right() + 8);
    assert_eq!(third.left, second.right() + 8);
    // With no lengths set there is no allowance and no sentence about one.
    let item = Attention::Request {
        payload: None,
        request: RequestId(Seq(9)),
        remote: workspace(),
        capability: name("gpg"),
        operation: Operation::Sign,
        key: None,
        offers: Vec::new(),
        capped: None,
    };
    let bare = Card::of(&item, Why::default(), 0).unwrap();
    assert_eq!(bare.allows, None);
    assert!(arrange(&bare, &PLAIN, ROOMY).place(Part::Allows).is_none());
}

/// A person with a remote they do not recognise: pausing it stands by the fact
/// that names it, apart from the answers to this one request.
#[test]
fn pausing_the_remote_stands_by_the_remote() {
    let card = request(0);
    let arranged = arrange(&card, &PLAIN, ROOMY);
    let pause = choice(&card, "Pause this remote");
    let (layer, button) = place(&arranged, pause);
    let (_, from) = place(&arranged, Part::Name(0));
    assert_eq!(card.facts.first().unwrap().0, "From");
    assert_eq!(layer, Layer::Content);
    assert_eq!(button.top, from.top);
    assert_eq!(button.right(), arranged.width - 24);
    assert!(
        from.right() + 12 <= button.left,
        "the fact keeps clear of it"
    );
}

/// The keyboard reaches the answers in the order of the work: the row of
/// answers, the allowances, then the one apart.
#[test]
fn the_keyboard_reaches_the_answers_in_the_order_of_the_work() {
    let card = request(0);
    let arranged = arrange(&card, &PLAIN, ROOMY);
    let weights: Vec<Weight> = arranged
        .order
        .iter()
        .map(|place| card.choices.get(*place).unwrap().weight)
        .collect();
    assert_eq!(
        weights,
        [
            Weight::Usual,
            Weight::Beside,
            Weight::Longer,
            Weight::Longer,
            Weight::Longer,
            Weight::Apart
        ]
    );
    let mut every: Vec<usize> = arranged.order.clone();
    every.sort_unstable();
    assert_eq!(every, (0..card.choices.len()).collect::<Vec<_>>());
}

/// A prompt whose answer is typed has the box under what the prompt says,
/// the full width, and its two answers beneath.
#[test]
fn a_typed_answer_has_its_box_under_the_prompts_own_words() {
    let card = prompt(PromptKind::KeyPassphrase);
    assert!(card.typed);
    let arranged = arrange(&card, &PLAIN, ROOMY);
    sound(&arranged, 24);
    let (layer, typed) = place(&arranged, Part::Typed);
    let (_, said) = place(&arranged, Part::Fact(card.facts.len() - 1));
    assert_eq!(layer, Layer::Content);
    assert_eq!(typed.top, said.bottom() + 12);
    assert_eq!((typed.left, typed.width), (24, arranged.width - 48));
    assert_eq!(typed.height, 32);
    let (_, send) = place(&arranged, choice(&card, "Send"));
    let (_, decline) = place(&arranged, choice(&card, "Do not connect"));
    assert_eq!(send.width, decline.width);
    // A prompt that is answered yes or no has no box.
    let plain = prompt(PromptKind::UnknownHostKey);
    assert!(arrange(&plain, &PLAIN, ROOMY).place(Part::Typed).is_none());
}

/// Every length is an effective pixel at the monitor's scale: at 125 per
/// cent the padding is 30 and the gap between answers 10.
#[test]
fn a_monitors_scale_scales_every_length() {
    let card = request(2);
    for (dpi, scale) in [(96u32, 1.0f32), (120, 1.25), (144, 1.5), (192, 2.0)] {
        let typewriter = Typewriter { scale, text: 1.0 };
        let space = Space { dpi, tallest: 4000 };
        let arranged = arrange(&card, &typewriter, space);
        let padding = hedwig_view::style::pixels(24.0, dpi);
        let gap = hedwig_view::style::pixels(8.0, dpi);
        sound(&arranged, padding);
        let (_, allow) = place(&arranged, choice(&card, "Allow once"));
        let (_, refuse) = place(&arranged, choice(&card, "Refuse"));
        assert_eq!(allow.left, padding, "{dpi}");
        assert_eq!(refuse.left - allow.right(), gap, "{dpi}");
        assert!(
            arranged.width <= hedwig_view::style::pixels(548.0, dpi),
            "{dpi}"
        );
        // What waits behind is said last in the content.
        let (_, waiting) = place(&arranged, Part::Waiting);
        assert_eq!(
            waiting.bottom(),
            arranged.extent - padding - if dpi >= 144 { 2 } else { 1 }
        );
    }
}

/// At the largest text size nothing is cut: the card is as wide as a dialog
/// may be, the allowances are one to a row, and answers whose labels no
/// longer fit half the row are one to a row too.
#[test]
fn at_the_largest_text_size_nothing_is_cut() {
    let large = Typewriter {
        scale: 1.0,
        text: 2.25,
    };
    let card = request(0);
    let arranged = arrange(&card, &large, ROOMY);
    sound(&arranged, 24);
    assert_eq!(arranged.width, 548);
    let allowances = [
        "Allow for 1 minute",
        "Allow for 15 minutes",
        "Allow for 1 hour",
    ]
    .map(|label| place(&arranged, choice(&card, label)).1);
    assert!(allowances.iter().all(|rect| rect.left == 24));
    assert!(
        allowances
            .iter()
            .zip(allowances.iter().skip(1))
            .all(|(above, below)| below.top == above.bottom() + 8),
        "{allowances:?}"
    );
    // "Allow once" and "Refuse" still fit half the row each.
    let (_, allow) = place(&arranged, choice(&card, "Allow once"));
    let (_, refuse) = place(&arranged, choice(&card, "Refuse"));
    assert_eq!((refuse.top, refuse.left), (allow.top, allow.right() + 8));

    // A host key's answers do not: one to a row, the full width.
    let card = prompt(PromptKind::UnknownHostKey);
    let arranged = arrange(&card, &large, ROOMY);
    sound(&arranged, 24);
    let (_, trust) = place(&arranged, choice(&card, "Trust this host"));
    let (_, decline) = place(&arranged, choice(&card, "Do not connect"));
    assert_eq!((trust.left, trust.width), (24, 500));
    assert_eq!((decline.left, decline.top), (24, trust.bottom() + 8));
    assert_eq!(arranged.answers, 24 + 2 * trust.height + 8 + 24);
}

/// Where the answer apart would leave its fact too little width to be read,
/// it goes beneath the fact. Text three times the shipped size is more than
/// Windows allows, and shows the rule.
#[test]
fn an_answer_apart_goes_beneath_its_fact_when_the_fact_would_be_squeezed() {
    let card = request(0);
    let huge = Typewriter {
        scale: 1.0,
        text: 3.0,
    };
    let arranged = arrange(&card, &huge, ROOMY);
    sound(&arranged, 24);
    let (_, pause) = place(&arranged, choice(&card, "Pause this remote"));
    let (_, from) = place(&arranged, Part::Fact(0));
    assert_eq!(from.width, 500, "the fact has the full width");
    assert_eq!((pause.left, pause.top), (24, from.bottom() + 8));
    let (_, next) = place(&arranged, Part::Name(1));
    assert_eq!(next.top, pause.bottom() + 12);
}

/// A card taller than the screen allows shows what fits of its content and
/// scrolls the rest; the answers stay in view and keep their whole height.
#[test]
fn a_card_taller_than_the_screen_scrolls_its_content_under_its_answers() {
    let card = request(1);
    let roomy = arrange(&card, &PLAIN, ROOMY);
    let short = Space {
        dpi: 96,
        tallest: roomy.height() - 100,
    };
    let arranged = arrange(&card, &PLAIN, short);
    assert!(arranged.scrolls());
    assert_eq!(arranged.height(), short.tallest);
    assert_eq!(arranged.answers, roomy.answers);
    assert_eq!(arranged.extent, roomy.extent);
    assert_eq!(arranged.shown, roomy.extent - 100);
    assert_eq!(arranged.parts, roomy.parts, "nothing moves; less is shown");
    // A screen with no room at all still shows the answers.
    let none = arrange(
        &card,
        &PLAIN,
        Space {
            dpi: 96,
            tallest: 10,
        },
    );
    assert_eq!((none.shown, none.answers), (0, roomy.answers));
}

/// The card stands at the corner of the work area the notification area is
/// at, wherever the person put the taskbar, and inside the work area even
/// when it is larger than it.
#[test]
fn the_card_stands_at_the_corner_the_icon_is_at() {
    let work = Rect {
        left: 0,
        top: 0,
        width: 1536,
        height: 816,
    };
    let card = Size {
        width: 500,
        height: 400,
    };
    let icon = |left, top| {
        Some(Rect {
            left,
            top,
            width: 24,
            height: 24,
        })
    };
    // Taskbar at the bottom, the icon at its right: Windows' own arrangement.
    assert_eq!(
        arrange::corner(work, icon(1400, 830), card, 12),
        (1024, 404)
    );
    assert_eq!(arrange::corner(work, None, card, 12), (1024, 404));
    // Taskbar at the top.
    let below = Rect { top: 48, ..work };
    assert_eq!(arrange::corner(below, icon(1400, 12), card, 12), (1024, 60));
    // Taskbar at the left, the icon at its foot.
    let beside = Rect { left: 48, ..work };
    assert_eq!(arrange::corner(beside, icon(12, 780), card, 12), (60, 404));
    // A card larger than the work area begins at its corner.
    let huge = Size {
        width: 2000,
        height: 1000,
    };
    assert_eq!(arrange::corner(work, None, huge, 12), (0, 0));
}

/// A confirmation is laid out as `ContentDialog` lays out a title, its
/// content and two buttons: the consequence 12 under the question, the verb
/// and "Cancel" in equal columns, "Cancel" at the right, the safe action where
/// the guidance puts it.
#[test]
fn a_confirmation_is_laid_out_as_a_dialog_with_its_text_and_two_answers() {
    let card = Card::confirming(
        "Resume all exposure",
        "Everything you have granted becomes reachable from its remotes again.",
    );
    for (space, padding, gap, under) in [
        (ROOMY, 24, 8, 12),
        (
            Space {
                dpi: 120,
                tallest: 900,
            },
            30,
            10,
            15,
        ),
    ] {
        let arranged = arrange(&card, &PLAIN, space);
        sound(&arranged, padding);
        assert!(!arranged.scrolls());
        let (_, heading) = place(&arranged, Part::Heading);
        let (layer, says) = place(&arranged, Part::Says);
        assert_eq!(layer, Layer::Content);
        assert_eq!(says.top, heading.bottom() + under, "{space:?}");
        assert_eq!(says.left, padding);
        assert_eq!(arranged.extent, says.bottom() + padding + 1, "{space:?}");
        let (layer, go) = place(&arranged, choice(&card, "Resume all exposure"));
        let (_, cancel) = place(&arranged, choice(&card, "Cancel"));
        assert_eq!(layer, Layer::Answers);
        assert_eq!(go.left, padding);
        assert_eq!(cancel.left, go.right() + gap);
        assert_eq!(cancel.right(), arranged.width - padding);
        assert_eq!(arranged.order, [0, 1]);
    }
    // The consequence is body text, its width counted when the dialog's is.
    let long = Card::confirming("Stop Hedwig", &"word ".repeat(40));
    let arranged = arrange(&long, &PLAIN, ROOMY);
    // 500 inside the padding holds 71 characters of 7: its first line is 497.
    assert_eq!(
        arranged.width,
        24 + 497 + 24,
        "a long consequence widens it"
    );
}

/// A confirmation stands in the middle of the work area, and inside it
/// however large the confirmation is.
#[test]
fn a_confirmation_stands_in_the_middle_of_the_work_area() {
    let work = Rect {
        left: 0,
        top: 0,
        width: 1600,
        height: 1040,
    };
    let dialog = Size {
        width: 400,
        height: 200,
    };
    assert_eq!(arrange::middle(work, dialog), (600, 420));
    // A second monitor to the right, and a confirmation larger than it.
    let second = Rect {
        left: 1600,
        top: 0,
        width: 1280,
        height: 680,
    };
    let odd = Size {
        width: 401,
        height: 201,
    };
    assert_eq!(arrange::middle(second, odd), (1600 + 439, 239));
    let huge = Size {
        width: 2000,
        height: 900,
    };
    assert_eq!(arrange::middle(second, huge), (1600, 0));
}
