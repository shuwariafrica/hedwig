//! The icon's menu as a menu flyout: where each row goes at each scale, text
//! size and way of opening it, what each key does, and what it is drawn in,
//! checked without a desktop.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests"
)]

use std::time::Instant;

use hedwig_model::protocol::Request;
use hedwig_model::remote::Remotes;
use hedwig_view::act::Act;
use hedwig_view::arrange::{Measure, Rect, Size};
use hedwig_view::glance::{self, Entry};
use hedwig_view::menu::{self, Edge, Key, Kind, Laid, Opened, Space, Step, arrange};
use hedwig_view::paint::Canvas;
use hedwig_view::style::{Accent, Mode, Palette, Rgb, Tint, Type};

mod common;
use common::Bench;

/// Text measured as a typewriter sets it: every character half its size
/// wide and a line 4/3 of it tall, at `scale` pixels to the effective pixel
/// and `text` hundredths of the text size Windows ships; within a width, as
/// many characters to a line as fit.
struct Typewriter {
    scale: f32,
    text: f32,
}

impl Measure for Typewriter {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "a test's arithmetic on small whole numbers"
    )]
    fn text(&self, style: Type, text: &str, width: Option<i32>) -> Size {
        let size = style.size() * self.scale * self.text;
        let (character, line) = (
            (size / 2.0).round() as i32,
            (size * 4.0 / 3.0).round() as i32,
        );
        let count = text.chars().count() as i32;
        let across = width.map_or(count, |width| (width / character).max(1));
        Size {
            width: count.min(across) * character,
            height: ((count + across - 1) / across).max(1) * line,
        }
    }
}

const PLAIN: Typewriter = Typewriter {
    scale: 1.0,
    text: 1.0,
};

fn roomy(dpi: u32) -> Space {
    Space {
        dpi,
        widest: 4000,
        tallest: 4000,
        edge: Edge::System,
    }
}

fn act(label: &str) -> Entry {
    Entry::Act {
        label: label.to_owned(),
        act: Act::Open(None),
        chief: false,
    }
}

/// A menu with every kind of row: two items, a rule, a remote's own menu and
/// a line of words.
fn sample() -> Vec<Entry> {
    vec![
        act("Open Hedwig"),
        Entry::Act {
            label: "Pause all exposure".to_owned(),
            act: Act::Send(Request::Pause(Remotes::Every)),
            chief: false,
        },
        Entry::Rule,
        Entry::Group {
            label: "dev/build (coder)".to_owned(),
            entries: vec![act("Disconnect")],
        },
        Entry::Line("Hedwig was started outside this desktop".to_owned()),
    ]
}

fn kinds(laid: &Laid) -> Vec<Kind> {
    laid.rows.iter().map(|row| row.kind).collect()
}

/// A person glances at the icon's menu: every row is where WinUI puts a menu
/// flyout's. One pixel of edge, 2 inside it above and below; an item's
/// highlight 4 in from the sides and 2 from its neighbours, its text 11 in
/// and 4 above and 5 below when opened with the mouse; a separator a line of
/// 1 with 1 either side, the full width; the menu as wide as its widest row.
#[test]
fn a_menu_is_laid_out_as_windows_11_lays_out_a_menu_flyout() {
    let laid = arrange(&sample(), &PLAIN, roomy(96), Opened::Pointer);
    assert_eq!(
        kinds(&laid),
        [Kind::Item, Kind::Item, Kind::Rule, Kind::Group, Kind::Line]
    );
    let open = &laid.rows[0];
    // 19 is the typewriter's line for 14.
    assert_eq!(
        open.rect,
        Rect {
            left: 1,
            top: 3,
            width: laid.width - 2,
            height: 2 + 4 + 19 + 5 + 2
        }
    );
    assert_eq!(
        open.fill,
        Rect {
            left: 5,
            top: 5,
            width: laid.width - 10,
            height: 28
        }
    );
    assert_eq!((open.text.left, open.text.top), (16, 5 + 4));
    let rule = &laid.rows[2];
    assert_eq!(rule.rect.height, 3);
    assert_eq!(
        rule.fill,
        Rect {
            left: 1,
            top: rule.rect.top + 1,
            width: laid.width - 2,
            height: 1
        }
    );
    // The widest row is the line of words: its text, 11 either side, the
    // margin of 4 either side, then the edges. The group's is its text and
    // its chevron of 12 after 24.
    assert_eq!(laid.width, 2 * 4 + 2 * 11 + 39 * 7 + 2);
    let group = &laid.rows[3];
    let chevron = group.chevron.expect("a submenu has a chevron");
    assert_eq!(chevron.right(), group.fill.right() - 11);
    assert_eq!(chevron.width, 12);
    assert!(group.text.right() <= chevron.left - 24);
    // One row follows another, and the menu ends 2 and the edge after.
    for pair in laid.rows.windows(2) {
        assert_eq!(pair[1].rect.top, pair[0].rect.bottom());
    }
    assert_eq!(laid.extent, laid.rows.last().unwrap().rect.bottom() + 2 + 1);
    assert!(!laid.scrolls());
}

/// Opened with a finger, a row is WinUI's touch row: 8 above the text and 9
/// below; with the keyboard, the mouse's.
#[test]
fn a_menu_opened_by_touch_has_taller_rows() {
    let touch = arrange(&sample(), &PLAIN, roomy(96), Opened::Touch);
    let keyboard = arrange(&sample(), &PLAIN, roomy(96), Opened::Keyboard);
    assert_eq!(touch.rows[0].rect.height, 2 + 8 + 19 + 9 + 2);
    assert_eq!(keyboard.rows[0].rect.height, 2 + 4 + 19 + 5 + 2);
    assert_eq!(
        touch.rows[2].rect.height, keyboard.rows[2].rect.height,
        "a rule is the same"
    );
}

/// On every scale the menu is its effective pixels on that monitor, rows
/// follow one another with nothing between, and nothing leaves the menu.
#[test]
fn every_length_is_effective_pixels_at_each_scale() {
    for (dpi, scale) in [(96, 1.0), (120, 1.25), (144, 1.5), (192, 2.0)] {
        let laid = arrange(
            &sample(),
            &Typewriter { scale, text: 1.0 },
            roomy(dpi),
            Opened::Pointer,
        );
        let px = |effective: f32| hedwig_view::style::pixels(effective, dpi);
        assert_eq!(laid.rows[0].fill.left, laid.edge + px(4.0), "{dpi}");
        assert_eq!(
            laid.rows[0].text.left,
            laid.rows[0].fill.left + px(11.0),
            "{dpi}"
        );
        for row in &laid.rows {
            assert!(
                row.rect.left >= laid.edge && row.rect.right() <= laid.width - laid.edge,
                "{dpi} {row:?}"
            );
            assert!(row.text.right() <= row.fill.right(), "{dpi} {row:?}");
        }
        assert!(laid.width >= px(96.0) && laid.extent >= px(32.0), "{dpi}");
    }
}

/// At the largest text size Windows offers the menu grows with its text and
/// stays within the screen: taller than the screen allows, it scrolls.
#[test]
fn a_raised_text_size_grows_the_menu_and_a_tall_one_scrolls() {
    let large = Typewriter {
        scale: 1.0,
        text: hedwig_view::style::TextScale::new(2.25).size(14.0) / 14.0,
    };
    let plain = arrange(&sample(), &PLAIN, roomy(96), Opened::Pointer);
    let grown = arrange(&sample(), &large, roomy(96), Opened::Pointer);
    assert!(grown.width > plain.width && grown.extent > plain.extent);
    let cramped = Space {
        tallest: 100,
        ..roomy(96)
    };
    let laid = arrange(&sample(), &large, cramped, Opened::Pointer);
    assert!(laid.scrolls());
    assert_eq!(laid.shown, 100);
    // The keyboard landing on the last row brings it into view whole.
    let last = laid.rows.len() - 2;
    let scrolled = menu::reveal(&laid, last, 0);
    let row = &laid.rows[last];
    assert!(row.rect.top >= scrolled && row.rect.bottom() <= scrolled + laid.shown);
    assert_eq!(menu::reveal(&laid, 0, scrolled), 0);
}

/// A menu wider than the work area is held to it; its rows show what fits.
/// A short one is WinUI's least width, an empty one its least height.
#[test]
fn a_menu_is_held_between_the_least_size_and_the_work_area() {
    let long = vec![act(&"a very long remote address ".repeat(20))];
    let space = Space {
        widest: 300,
        ..roomy(96)
    };
    let laid = arrange(&long, &PLAIN, space, Opened::Pointer);
    assert_eq!(laid.width, 300);
    assert!(laid.rows[0].text.right() <= 300 - 1 - 4 - 11);
    let short = arrange(&[act("Go")], &PLAIN, roomy(96), Opened::Pointer);
    assert_eq!(short.width, 96);
    let empty = arrange(&[], &PLAIN, roomy(96), Opened::Pointer);
    assert_eq!(empty.extent, 32);
}

/// A line of words wider than WinUI lets a flyout's content be - 456
/// effective pixels, `FlyoutThemeMaxWidth` - is set on as many lines as it
/// takes there, its row as tall as they are, so nothing the person needs is
/// cut and the menu never spans the screen for one line; where the work area
/// is narrower, it wraps within that. A row the person chooses keeps its one
/// line, as WinUI's do.
#[test]
fn a_long_line_of_words_wraps_at_the_widest_winui_gives_a_flyout() {
    let refused = "gpg-h: Hedwig wrote there, with your consent: no-autostart in the remote's \
                   GnuPG configuration; the file the remote's gpg finds its agent by";
    let entries = vec![act("Disconnect"), Entry::Line(refused.to_owned())];
    for (dpi, scale) in [(96, 1.0), (120, 1.25), (192, 2.0)] {
        let laid = arrange(
            &entries,
            &Typewriter { scale, text: 1.0 },
            roomy(dpi),
            Opened::Pointer,
        );
        let px = |effective: f32| hedwig_view::style::pixels(effective, dpi);
        assert_eq!(laid.width, px(456.0), "{dpi}");
        let line = &laid.rows[1];
        assert!(line.wrapped, "{dpi}");
        assert!(!laid.rows[0].wrapped, "{dpi}");
        assert!(
            line.text.right() <= line.fill.right() - px(11.0),
            "{dpi} {line:?}"
        );
        let one = Typewriter { scale, text: 1.0 }
            .text(Type::Body, "x", None)
            .height;
        assert!(line.text.height >= 2 * one, "{dpi}: {line:?}");
        assert!(
            (line.rect.height - px(2.0 + 4.0 + 5.0 + 2.0) - line.text.height).abs() <= 1,
            "{dpi}: the row grows by its lines: {line:?}"
        );
    }
    let narrow = Space {
        widest: 300,
        ..roomy(96)
    };
    let laid = arrange(&entries, &PLAIN, narrow, Opened::Pointer);
    assert_eq!(laid.width, 300);
    assert!(laid.rows[1].wrapped && laid.rows[1].text.right() <= 300 - 1 - 4 - 11);
    // A short line stays one line; a long item is as wide as it is, within
    // the work area, and shows what fits.
    let short = arrange(&sample(), &PLAIN, roomy(96), Opened::Pointer);
    assert!(short.rows.iter().all(|row| !row.wrapped));
    let item = arrange(&[act(&"x".repeat(80))], &PLAIN, roomy(96), Opened::Pointer);
    assert_eq!(item.width, 2 * 4 + 2 * 11 + 80 * 7 + 2);
    assert!(!item.rows[0].wrapped);
}

/// A `&` of a label's own is drawn as itself: doubled, so the shell never
/// takes it for the access key's marker - a key's user ID in a line, an
/// item's words - and the item's letter is still its own.
#[test]
fn an_ampersand_in_a_label_is_drawn_as_itself() {
    let laid = arrange(
        &[
            act("R&D bench"),
            Entry::Line("signed with key 0E5D (R&D <rd@example.org>)".to_owned()),
        ],
        &PLAIN,
        roomy(96),
        Opened::Pointer,
    );
    assert_eq!(laid.rows[0].label, "&R&&D bench");
    assert_eq!(laid.rows[0].key, Some('r'));
    assert_eq!(
        laid.rows[1].label,
        "signed with key 0E5D (R&&D <rd@example.org>)"
    );
    assert_eq!(laid.rows[1].key, None);
}

/// Under a contrast theme the edge is the two pixels the guidance asks a
/// flyout for, and the rows move in by it.
#[test]
fn under_a_contrast_theme_the_edge_is_two_pixels() {
    let space = Space {
        edge: Edge::Contrast,
        ..roomy(96)
    };
    let laid = arrange(&sample(), &PLAIN, space, Opened::Pointer);
    assert_eq!(laid.edge, 2);
    assert_eq!(laid.rows[0].rect.left, 2);
    assert_eq!(laid.rows[0].rect.top, 4);
}

/// Each item and the remote's menu has its own letter; a line of words and
/// a rule have none.
#[test]
fn every_item_has_an_access_key_of_its_own() {
    let laid = arrange(&sample(), &PLAIN, roomy(96), Opened::Pointer);
    let keys: Vec<Option<char>> = laid.rows.iter().map(|row| row.key).collect();
    assert_eq!(keys, [Some('o'), Some('p'), None, Some('d'), None]);
    assert_eq!(laid.rows[0].label, "&Open Hedwig");
    assert_eq!(
        laid.rows[4].label,
        "Hedwig was started outside this desktop"
    );
}

/// The keyboard, as a menu answers it: down and up go round and pass over
/// what offers nothing; home and end; ENTER does the item or opens the
/// remote's menu, as does the arrow into it; the arrow out closes a submenu
/// and not the menu; ESCAPE closes.
#[test]
fn the_keyboard_moves_and_chooses_as_in_a_menu() {
    let laid = arrange(&sample(), &PLAIN, roomy(96), Opened::Keyboard);
    let rows = &laid.rows;
    assert_eq!(menu::step(rows, None, Key::Down, false), Step::Focus(0));
    assert_eq!(menu::step(rows, None, Key::Up, false), Step::Focus(3));
    assert_eq!(
        menu::step(rows, Some(1), Key::Down, false),
        Step::Focus(3),
        "over the rule"
    );
    assert_eq!(
        menu::step(rows, Some(3), Key::Down, false),
        Step::Focus(0),
        "round, over the line"
    );
    assert_eq!(menu::step(rows, Some(0), Key::Up, false), Step::Focus(3));
    assert_eq!(menu::step(rows, Some(1), Key::Home, false), Step::Focus(0));
    assert_eq!(menu::step(rows, Some(0), Key::End, false), Step::Focus(3));
    assert_eq!(
        menu::step(rows, Some(1), Key::Choose, false),
        Step::Choose(1)
    );
    assert_eq!(menu::step(rows, Some(3), Key::Choose, false), Step::Open(3));
    assert_eq!(menu::step(rows, None, Key::Choose, false), Step::Nothing);
    assert_eq!(menu::step(rows, Some(3), Key::Into, false), Step::Open(3));
    assert_eq!(menu::step(rows, Some(0), Key::Into, false), Step::Nothing);
    assert_eq!(menu::step(rows, Some(0), Key::Out, true), Step::Close);
    assert_eq!(menu::step(rows, Some(0), Key::Out, false), Step::Nothing);
    assert_eq!(menu::step(rows, Some(0), Key::Escape, false), Step::Close);
    let nothing = arrange(
        &[Entry::Line("words".to_owned())],
        &PLAIN,
        roomy(96),
        Opened::Pointer,
    );
    assert_eq!(
        menu::step(&nothing.rows, None, Key::Down, false),
        Step::Nothing
    );
    assert_eq!(
        menu::step(&nothing.rows, None, Key::Escape, false),
        Step::Close
    );
}

/// A letter does what its item does, or opens the remote's menu; a letter
/// two items share moves between them; a letter no item has does nothing.
#[test]
fn a_letter_chooses_the_item_it_is_the_key_of() {
    let laid = arrange(&sample(), &PLAIN, roomy(96), Opened::Keyboard);
    assert_eq!(
        menu::step(&laid.rows, None, Key::Letter('P'), false),
        Step::Choose(1)
    );
    assert_eq!(
        menu::step(&laid.rows, None, Key::Letter('d'), false),
        Step::Open(3)
    );
    assert_eq!(
        menu::step(&laid.rows, None, Key::Letter('z'), false),
        Step::Nothing
    );
    // Two items whose first free letters coincide are told apart by moving.
    let shared = vec![act("Stop"), act("Start"), act("Sleep")];
    let laid = arrange(&shared, &PLAIN, roomy(96), Opened::Keyboard);
    assert_eq!(laid.rows[0].key, Some('s'));
    assert_eq!(laid.rows[1].key, Some('t'));
    let alike = vec![act("Ab"), act("Ab")];
    let laid = arrange(&alike, &PLAIN, roomy(96), Opened::Keyboard);
    assert_eq!(laid.rows[1].key, Some('b'));
}

/// The pointer lands on items and the remote's menu, never on a rule or a
/// line of words.
#[test]
fn the_pointer_lands_only_on_what_can_be_chosen() {
    let laid = arrange(&sample(), &PLAIN, roomy(96), Opened::Pointer);
    let middle = |at: usize| {
        let rect = laid.rows[at].rect;
        (rect.left + rect.width / 2, rect.top + rect.height / 2)
    };
    for (at, expected) in [
        (0, Some(0)),
        (1, Some(1)),
        (2, None),
        (3, Some(3)),
        (4, None),
    ] {
        let (x, y) = middle(at);
        assert_eq!(laid.at(x, y, 0), expected, "row {at}");
    }
    assert_eq!(laid.at(-1, 5, 0), None);
}

/// The menu of an attached hedwig: every act and the remote's menu can be
/// chosen, every line is words only.
#[test]
fn the_icons_menu_becomes_rows_of_the_kind_each_entry_is() {
    let bench = Bench::attached();
    let entries = glance::menu(bench.link.seen(), Instant::now());
    let laid = arrange(&entries, &PLAIN, roomy(96), Opened::Pointer);
    for (entry, row) in entries.iter().zip(&laid.rows) {
        let expected = match entry {
            Entry::Line(_) => Kind::Line,
            Entry::Rule => Kind::Rule,
            Entry::Act { .. } => Kind::Item,
            Entry::Group { .. } => Kind::Group,
        };
        assert_eq!(row.kind, expected);
    }
    assert!(laid.rows.iter().any(|row| row.kind.takes()));
}

fn dark() -> Palette {
    Palette::new(
        Mode::Dark,
        Accent {
            fill: Rgb::new(0x4C, 0xC2, 0xFF),
            text: Rgb::new(0x99, 0xEB, 0xFF),
        },
    )
}

/// What a menu is drawn in: WinUI's resources as they are, since the
/// compositor lays them over the acrylic behind the menu.
#[test]
fn a_menus_inks_are_winuis_resources_over_the_backdrop() {
    let ink = dark().menu();
    assert_eq!(ink.text, Tint::argb(0xFFFF_FFFF));
    assert_eq!(ink.words, Tint::argb(0xC5FF_FFFF));
    assert_eq!(ink.over, Tint::argb(0x0FFF_FFFF));
    assert_eq!(ink.pressed, Tint::argb(0x0AFF_FFFF));
    assert_eq!(ink.rule, Tint::argb(0x15FF_FFFF));
    assert_eq!(ink.chevron, ink.words);
    assert_eq!(ink.solid.hex(), "#2C2C2C");
    let light = Palette::new(
        Mode::Light,
        Accent {
            fill: Rgb::BLACK,
            text: Rgb::BLACK,
        },
    )
    .menu();
    assert_eq!(light.text, Tint::argb(0xE400_0000));
    assert_eq!(light.over, Tint::argb(0x0900_0000));
    assert_eq!(light.rule, Tint::argb(0x0F00_0000));
    assert_eq!(light.solid.hex(), "#F9F9F9");

    // The flyout's edge and the acrylic beneath it: the Fluent tokens, the
    // tint's and the luminosity's opacity applied as `AcrylicBrush` does.
    assert_eq!(ink.edge, Tint::argb(0x3300_0000));
    assert_eq!(ink.acrylic.tint, Tint::argb(0x262C_2C2C));
    assert_eq!(ink.acrylic.luminosity, Tint::argb(0xF52C_2C2C));
    assert_eq!(ink.acrylic.fallback, ink.solid);
    assert_eq!(light.edge, Tint::argb(0x0F00_0000));
    assert_eq!(light.acrylic.tint, Tint::argb(0x00FC_FCFC));
    assert_eq!(light.acrylic.luminosity, Tint::argb(0xD9FC_FCFC));
    assert_eq!(light.acrylic.fallback, light.solid);
}

/// A frame's stroke lies along the inside of its edge only: full where it
/// covers a pixel, smooth at its rounded corner, nothing within it or outside
/// the corner.
#[test]
fn an_outline_is_the_edge_of_a_rounded_rectangle_and_nothing_within() {
    let mut canvas = Canvas::clear(40, 30);
    let edge = Tint::argb(0x3300_0000);
    canvas.outline(
        Rect {
            left: 0,
            top: 0,
            width: 40,
            height: 30,
        },
        10.0,
        1,
        edge,
    );
    // Along a side, away from the corners, the edge pixel is the ink.
    assert_eq!(canvas.at(20, 0), Some((Rgb::BLACK, 0x33)));
    assert_eq!(canvas.at(0, 15), Some((Rgb::BLACK, 0x33)));
    assert_eq!(canvas.at(39, 15), Some((Rgb::BLACK, 0x33)));
    // Within, and beyond the rounded corner, nothing.
    assert_eq!(canvas.at(20, 15), Some((Rgb::BLACK, 0)));
    assert_eq!(canvas.at(1, 15), Some((Rgb::BLACK, 0)));
    assert_eq!(canvas.at(0, 0), Some((Rgb::BLACK, 0)));
    // At the corner the edge is smooth: some pixels are partly covered.
    let partly = (0..10)
        .flat_map(|y| (0..10).map(move |x| (x, y)))
        .filter_map(|(x, y)| canvas.at(x, y))
        .filter(|(_, alpha)| *alpha > 0 && *alpha < 0x33)
        .count();
    assert!(partly > 4, "{partly} partly covered at the corner");
}

/// Over a clear canvas a tint keeps its alpha, so the backdrop shows through
/// what the menu draws; a rounded highlight is smooth at its corner; text is
/// laid over the highlight by how much of each pixel it covers.
#[test]
fn a_canvas_keeps_what_is_drawn_translucent_over_the_backdrop() {
    let mut canvas = Canvas::clear(20, 10);
    assert_eq!(canvas.at(0, 0), Some((Rgb::BLACK, 0)));
    canvas.fill(
        Rect {
            left: 2,
            top: 2,
            width: 16,
            height: 6,
        },
        3.0,
        Tint::argb(0x0FFF_FFFF),
    );
    assert_eq!(canvas.at(10, 5), Some((Rgb::WHITE, 0x0F)));
    assert_eq!(canvas.at(0, 0).map(|(_, alpha)| alpha), Some(0));
    assert_eq!(
        canvas.at(2, 2).map(|(_, alpha)| alpha),
        Some(0),
        "outside the curve"
    );
    let corner = canvas.at(3, 2).map(|(_, alpha)| alpha).unwrap();
    assert!(corner > 0 && corner < 0x0F, "a smooth corner: {corner}");
    // Text over the highlight: full cover is the text's own colour, opaque.
    canvas.mask(4, 4, 2, &[255, 128], Tint::argb(0xFFFF_FFFF));
    assert_eq!(canvas.at(4, 4), Some((Rgb::WHITE, 255)));
    let half = canvas.at(5, 4).map(|(_, alpha)| alpha).unwrap();
    assert!((128..=136).contains(&half), "{half}");
    // As Windows takes it: multiplied by the alpha.
    let pixels = canvas.premultiplied();
    assert_eq!(pixels[5 * 20 + 10], 0x0F0F_0F0F);
    assert_eq!(pixels[4 * 20 + 4], 0xFFFF_FFFF);
    // A solid canvas is opaque everywhere, for a surface with no backdrop.
    let solid = Canvas::solid(2, 2, Rgb::new(0x2C, 0x2C, 0x2C));
    assert_eq!(solid.premultiplied(), vec![0xFF2C_2C2C; 4]);
}

/// WinUI's menu flyout opens over 250 ms on `cubic-bezier(0,0,0,1)`: the
/// menu from half its height, a remote's menu from a third, each growing away
/// from where it was opened, its rows carried by the edge that moves.
#[test]
fn a_menu_opens_as_winuis_menu_flyout_opens() {
    use hedwig_view::arrange::Rect;
    use hedwig_view::motion::{self, Closed, Grows, OPENING};

    assert!(motion::ease(0.0).abs() < 1e-6);
    assert!((motion::ease(1.0) - 1.0).abs() < 1e-6);
    // Fast out of the start, as a direct entrance is: half way through the
    // time, 95 per cent of the way there.
    assert!(
        (motion::ease(0.5) - 0.8899).abs() < 1e-3,
        "{}",
        motion::ease(0.5)
    );
    let mut previous = 0.0;
    for step in 0..=100u8 {
        let value = motion::ease(f32::from(step) / 100.0);
        assert!(value >= previous);
        previous = value;
    }

    let full = Rect {
        left: 100,
        top: 400,
        width: 240,
        height: 300,
    };
    let (start, lifted) = motion::opening(full, Grows::Up, Closed::Menu, 0).unwrap();
    assert_eq!(
        (start.top, start.height, start.top + start.height, lifted),
        (550, 150, 700, 0),
        "half its height, its bottom where it stays"
    );
    let (start, lifted) = motion::opening(full, Grows::Down, Closed::Menu, 0).unwrap();
    assert_eq!(
        (start.top, start.height, lifted),
        (400, 150, 150),
        "its top where it stays, its rows lifted by what is not yet shown"
    );
    let (start, lifted) = motion::opening(full, Grows::Down, Closed::Sub, 0).unwrap();
    assert_eq!(
        (start.height, lifted),
        (99, 201),
        "a remote's menu from a third"
    );
    let mut tallest = 0;
    for at in (0..OPENING).step_by(10) {
        let (place, lifted) = motion::opening(full, Grows::Up, Closed::Menu, at).unwrap();
        assert!(place.height >= tallest && lifted == 0);
        assert_eq!(place.top + place.height, 700);
        tallest = place.height;
    }
    assert_eq!(
        motion::opening(full, Grows::Up, Closed::Menu, OPENING),
        None
    );
}

/// A menu a finger or a pen opened has WinUI's taller rows; the shell says
/// nothing of how it was asked for, so it is read from the cursor Windows
/// stopped drawing, or from where the pointer is beside the anchor.
#[test]
fn how_the_menu_was_opened_is_read_from_the_cursor() {
    let at = (1640, 1050);
    assert_eq!(Opened::of(true, Some(at), at), Opened::Touch);
    assert_eq!(Opened::of(true, None, at), Opened::Touch);
    assert_eq!(Opened::of(false, Some((1641, 1049)), at), Opened::Pointer);
    assert_eq!(Opened::of(false, Some((1600, 900)), at), Opened::Keyboard);
    assert_eq!(Opened::of(false, None, at), Opened::Keyboard);
}

/// Each level casts WinUI's theme shadow for a menu flyout at its depth, as
/// `GetDropShadowRecipe` makes it: the menu at elevation 16, one shadow, black
/// at 0.26 in the dark mode and 0.14 in the light, its blur one wider for the
/// caster standing one pixel within; a remote's menu a tier above, at 20, with
/// an ambient shadow beneath; no elevation above 64. The window's room is
/// WinUI's popup window's.
#[test]
fn each_level_casts_winuis_theme_shadow_for_its_depth_and_mode() {
    let cast = |blur, drop, alpha| menu::Cast { blur, drop, alpha };
    assert_eq!(
        menu::shadow(0, Mode::Dark),
        menu::Shadow {
            ambient: None,
            directional: cast(17.0, 8.0, 66),
        }
    );
    assert_eq!(
        menu::shadow(0, Mode::Light),
        menu::Shadow {
            ambient: None,
            directional: cast(17.0, 8.0, 35),
        }
    );
    assert_eq!(
        menu::shadow(1, Mode::Dark),
        menu::Shadow {
            ambient: Some(cast(20.0 / 3.0 + 1.0, 2.0, 94)),
            directional: cast(21.0, 10.0, 94),
        }
    );
    assert_eq!(
        menu::shadow(1, Mode::Light),
        menu::Shadow {
            ambient: Some(cast(20.0 / 3.0 + 1.0, 2.0, 38)),
            directional: cast(21.0, 10.0, 48),
        }
    );
    assert_eq!(
        menu::shadow(99, Mode::Dark).directional,
        cast(65.0, 32.0, 94)
    );
    assert_eq!(menu::ROOM, (10.0, 2.0, 18.0));
}
