//! The icon's menu as Windows 11 builds a menu flyout: where each row goes,
//! and what each key does.
//!
//! The rows are [`crate::glance::menu`]'s entries. Every length is WinUI's for
//! `MenuFlyoutPresenter`, `MenuFlyoutItem`, `MenuFlyoutSubItem` and
//! `MenuFlyoutSeparator` at `winui3/release/2.5.1`
//! (`CommonStyles/MenuFlyout_themeresources.xaml`), in effective pixels,
//! turned into the pixels of the monitor the menu is on. Text is measured by
//! whoever draws it ([`Measure`]); everything else is decided here and
//! checked without a desktop.

use crate::arrange::{Measure, Rect, Size};
use crate::card::keyed;
use crate::glance::Entry;
use crate::style::{Mode, Type, line, pixels};

/// Inside the edge, above the first row and below the last
/// (`MenuFlyoutPresenterThemePadding` 0,2,0,2).
const PADDING: f32 = 2.0;
/// A menu is no narrower and no lower than this (`FlyoutThemeMinWidth`,
/// `MenuFlyoutThemeMinHeight`).
const NARROWEST: f32 = 96.0;
/// A line of words wraps where the menu would grow wider than this: the
/// widest WinUI lets a flyout's content be (`FlyoutThemeMaxWidth`,
/// `generic.xaml:51`). WinUI's `MenuFlyoutPresenter` sets no widest and clips
/// its items (`MenuFlyout_themeresources.xaml:283`, `:43`), which no line of
/// Hedwig's can afford: a refusal's reason cut is a reason lost.
pub const WRAPS: f32 = 456.0;
const LOWEST: f32 = 32.0;
/// How far a row's highlight is inset from the row: left and right, above
/// and below (`MenuFlyoutItemMargin` 4,2,4,2).
const INSET_SIDE: f32 = 4.0;
const INSET_END: f32 = 2.0;
/// A row's text stands this far inside its highlight: left and right
/// (`MenuFlyoutItemThemePadding`).
const TEXT_SIDE: f32 = 11.0;
/// A submenu's chevron: a 12 glyph, 24 after the text
/// (`MenuFlyoutItemChevronMargin`, `SubItemChevron`).
const CHEVRON: f32 = 12.0;
const CHEVRON_GAP: f32 = 24.0;
/// A separator: a line of 1 with 1 above and below it, the full width
/// (`MenuFlyoutSeparatorThemePadding` -4,1,-4,1 over the item's margin).
const RULE_ABOVE: f32 = 1.0;

/// How the person opened the menu, which decides how tall its rows are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opened {
    /// With the mouse.
    Pointer,
    Keyboard,
    /// With a finger or a pen: rows are taller, as WinUI makes them for
    /// touch.
    Touch,
}

impl Opened {
    /// How the menu the shell asks for at `at` was opened. The shell says
    /// nothing of it, and anchors a menu the pointer asked for where the
    /// pointer is and one the keyboard asked for at the icon; `suppressed`
    /// is Windows not drawing the cursor because the last input was a
    /// finger or a pen (`CURSOR_SUPPRESSED`), and `pointer` where the cursor
    /// is, where Windows says.
    pub fn of(suppressed: bool, pointer: Option<(i32, i32)>, at: (i32, i32)) -> Opened {
        if suppressed {
            return Opened::Touch;
        }
        match pointer {
            Some((x, y)) if (x - at.0).abs() <= 1 && (y - at.1).abs() <= 1 => Opened::Pointer,
            _ => Opened::Keyboard,
        }
    }

    /// Above and below a row's text (`MenuFlyoutItemThemePaddingNarrow`
    /// 11,4,11,5 for a pointer or the keyboard, `MenuFlyoutItemThemePadding`
    /// 11,8,11,9 otherwise).
    fn padding(self) -> (f32, f32) {
        match self {
            Opened::Pointer | Opened::Keyboard => (4.0, 5.0),
            Opened::Touch => (8.0, 9.0),
        }
    }
}

/// What a row of the menu is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Words only: what the menu says, not what it offers.
    Line,
    Rule,
    /// Something the person can choose.
    Item,
    /// A remote's own menu, opened beside this one.
    Group,
}

impl Kind {
    /// Whether the keyboard and the pointer can land on it.
    pub fn takes(self) -> bool {
        matches!(self, Kind::Item | Kind::Group)
    }
}

/// One row, every rectangle within the menu's client area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Its place among the entries it was made from.
    pub entry: usize,
    pub kind: Kind,
    /// The whole row.
    pub rect: Rect,
    /// Where its highlight is drawn; for a rule, the line itself.
    pub fill: Rect,
    /// Where its text is drawn, vertically centred in the highlight.
    pub text: Rect,
    /// A submenu's chevron.
    pub chevron: Option<Rect>,
    /// Its text with its access key marked by `&`, as a label takes it.
    pub label: String,
    /// Whether its text is set on as many lines as it takes within its
    /// width, from the top: a line of words wider than [`WRAPS`] allows.
    pub wrapped: bool,
    /// The letter that chooses it, lower-cased.
    pub key: Option<char>,
}

/// A menu laid out for one monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Laid {
    pub width: i32,
    /// How much of the menu is shown, and how tall it is in all: a menu
    /// taller than the screen allows scrolls.
    pub shown: i32,
    pub extent: i32,
    /// The width of the edge Windows or Hedwig draws round it, inside the
    /// client area.
    pub edge: i32,
    pub rows: Vec<Row>,
}

impl Laid {
    pub fn scrolls(&self) -> bool {
        self.extent > self.shown
    }

    /// The row the keyboard or the pointer can land on at a point of the
    /// client area, with the menu scrolled by `scrolled`.
    pub fn at(&self, x: i32, y: i32, scrolled: i32) -> Option<usize> {
        let y = y + scrolled;
        self.rows.iter().position(|row| {
            row.kind.takes()
                && x >= row.rect.left
                && x < row.rect.right()
                && y >= row.rect.top
                && y < row.rect.bottom()
        })
    }
}

/// Which edge a menu has: Windows' own, of one pixel, or the two pixels a
/// contrast theme asks a flyout for, which Hedwig draws.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    System,
    Contrast,
}

/// The monitor a menu is laid out for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub dpi: u32,
    /// The widest and tallest the menu may be: what the work area allows.
    pub widest: i32,
    pub tallest: i32,
    pub edge: Edge,
}

/// A row's kind, its label with its access key marked, and the size of its
/// text: on one line, or wrapped once the menu's width is known.
struct Planned {
    kind: Kind,
    label: String,
    text: Size,
    wrapped: bool,
}

fn plan(entries: &[Entry], measure: &dyn Measure) -> Vec<Planned> {
    let mut labels = keyed(entries.iter().filter_map(|entry| match entry {
        Entry::Act { label, .. } | Entry::Group { label, .. } => Some(label.as_str()),
        Entry::Line(_) | Entry::Rule => None,
    }))
    .into_iter();
    entries
        .iter()
        .map(|entry| {
            let (kind, text) = match entry {
                Entry::Line(text) => (Kind::Line, text.as_str()),
                Entry::Rule => (Kind::Rule, ""),
                Entry::Act { label, .. } => (Kind::Item, label.as_str()),
                Entry::Group { label, .. } => (Kind::Group, label.as_str()),
            };
            let label = if kind.takes() {
                labels.next().unwrap_or_else(|| text.replace('&', "&&"))
            } else {
                text.replace('&', "&&")
            };
            let text = if kind == Kind::Rule {
                Size::default()
            } else {
                measure.text(Type::Body, text, None)
            };
            Planned {
                kind,
                label,
                text,
                wrapped: false,
            }
        })
        .collect()
}

/// The letter a label's marker stands before, lower-cased; a doubled `&` is
/// the character itself.
fn marked(label: &str) -> Option<char> {
    let mut characters = label.chars();
    while let Some(character) = characters.next() {
        if character == '&' {
            match characters.next() {
                Some('&') => {}
                next => return next.map(|key| key.to_ascii_lowercase()),
            }
        }
    }
    None
}

/// The lengths a level of the menu is laid out with. Across, every length is
/// whole pixels from the edge; down, rows follow one another on a
/// continuous position that is rounded where each edge falls, as WinUI
/// rounds its layout, so a row is as tall as WinUI's and not the sum of its
/// parts each rounded.
struct Pen {
    dpi: u32,
    scale: f32,
    edge: i32,
    inner: i32,
    /// Above and below a row's text, in effective pixels.
    above: f32,
    below: f32,
}

fn whole(value: f32) -> i32 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a place on a screen, rounded, is within an i32"
    )]
    let whole = value.round() as i32;
    whole
}

fn float(value: i32) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

impl Pen {
    fn px(&self, effective: f32) -> i32 {
        pixels(effective, self.dpi)
    }

    /// A row's natural width: its text, WinUI's padding and margin, and a
    /// submenu's chevron.
    fn natural(&self, row: &Planned) -> i32 {
        let chevron = if row.kind == Kind::Group {
            self.px(CHEVRON_GAP) + self.px(CHEVRON)
        } else {
            0
        };
        2 * self.px(INSET_SIDE) + 2 * self.px(TEXT_SIDE) + row.text.width + chevron
    }

    /// `row` placed from `top`, a position in pixels; returns it and where
    /// the next row begins.
    fn place(&self, entry: usize, row: Planned, top: f32) -> (Row, f32) {
        let text_height = float(row.text.height);
        let height = match row.kind {
            Kind::Rule => (2.0 * RULE_ABOVE + 1.0) * self.scale,
            _ => (2.0 * INSET_END + self.above + self.below) * self.scale + text_height,
        };
        let span = |from: f32, to: f32| (whole(from), whole(to) - whole(from));
        let (rect_top, rect_height) = span(top, top + height);
        let rect = Rect {
            left: self.edge,
            top: rect_top,
            width: self.inner,
            height: rect_height,
        };
        let (fill, text, chevron) = if row.kind == Kind::Rule {
            let line = Rect {
                top: whole(top + RULE_ABOVE * self.scale),
                height: line(1.0, self.dpi),
                ..rect
            };
            (line, line, None)
        } else {
            let inset = INSET_END * self.scale;
            let (fill_top, fill_height) = span(top + inset, top + height - inset);
            let fill = Rect {
                left: rect.left + self.px(INSET_SIDE),
                top: fill_top,
                width: rect.width - 2 * self.px(INSET_SIDE),
                height: fill_height,
            };
            // The text stands within WinUI's padding, which is not the same
            // above and below.
            let middle = top + (INSET_END + self.above) * self.scale + text_height / 2.0;
            let chevron = (row.kind == Kind::Group).then(|| Rect {
                left: fill.right() - self.px(TEXT_SIDE) - self.px(CHEVRON),
                // Centred on the text, and half a pixel lower for the
                // chevron's margin of -1 below.
                top: whole(middle + 0.5 * self.scale - CHEVRON * self.scale / 2.0),
                width: self.px(CHEVRON),
                height: self.px(CHEVRON),
            });
            let right = chevron.map_or(fill.right() - self.px(TEXT_SIDE), |chevron| {
                chevron.left - self.px(CHEVRON_GAP)
            });
            let text = Rect {
                left: fill.left + self.px(TEXT_SIDE),
                top: whole(middle - text_height / 2.0),
                width: (right - fill.left - self.px(TEXT_SIDE)).max(0),
                height: row.text.height,
            };
            (fill, text, chevron)
        };
        let key = marked(&row.label);
        let placed = Row {
            entry,
            kind: row.kind,
            rect,
            fill,
            text,
            chevron,
            label: row.label,
            key,
            wrapped: row.wrapped,
        };
        (placed, top + height)
    }
}

/// Lays `entries` out as one level of the menu: a group is a row here and
/// its entries are a menu of their own. The menu is as wide as its widest
/// row, within what the work area allows, a line of words counting no wider
/// than [`WRAPS`] and set on as many lines as it takes; a row the person
/// chooses whose text does not fit then shows what fits.
pub fn arrange(entries: &[Entry], measure: &dyn Measure, space: Space, opened: Opened) -> Laid {
    let (above, below) = opened.padding();
    let mut pen = Pen {
        dpi: space.dpi,
        scale: float(i32::try_from(space.dpi).unwrap_or(96)) / 96.0,
        edge: match space.edge {
            Edge::System => line(1.0, space.dpi),
            Edge::Contrast => line(2.0, space.dpi),
        },
        inner: 0,
        above,
        below,
    };
    let mut planned = plan(entries, measure);
    let narrowest = pen.px(NARROWEST);
    let wraps = pen.px(WRAPS).min(space.widest).max(narrowest) - 2 * pen.edge;
    let natural = planned
        .iter()
        .map(|row| match row.kind {
            Kind::Line => pen.natural(row).min(wraps),
            _ => pen.natural(row),
        })
        .max()
        .unwrap_or_default()
        + 2 * pen.edge;
    let width = natural.max(narrowest).min(space.widest.max(narrowest));
    pen.inner = width - 2 * pen.edge;
    // A line of words wider than the menu now is is set on more lines within
    // what its row gives text.
    let room = pen.inner - 2 * pen.px(INSET_SIDE) - 2 * pen.px(TEXT_SIDE);
    for row in &mut planned {
        if row.kind == Kind::Line && row.text.width > room {
            row.text = measure.text(Type::Body, &row.label.replace("&&", "&"), Some(room));
            row.wrapped = true;
        }
    }
    let mut top = float(pen.edge) + PADDING * pen.scale;
    let mut rows = Vec::with_capacity(planned.len());
    for (entry, row) in planned.into_iter().enumerate() {
        let (placed, next) = pen.place(entry, row, top);
        top = next;
        rows.push(placed);
    }
    let lowest = pen.px(LOWEST);
    let extent = (whole(top + PADDING * pen.scale) + pen.edge).max(lowest);
    Laid {
        width,
        shown: extent.min(space.tallest.max(lowest)),
        extent,
        edge: pen.edge,
        rows,
    }
}

/// A key the menu answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Home,
    End,
    /// ENTER or SPACE.
    Choose,
    /// The arrow that opens a submenu, and the one that closes it: right
    /// and left in a left-to-right language.
    Into,
    Out,
    Escape,
    Letter(char),
}

/// What a key does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Put the keyboard on this row.
    Focus(usize),
    /// Do what this row offers.
    Choose(usize),
    /// Open this row's submenu with the keyboard on its first row.
    Open(usize),
    /// Close this menu: a submenu returns the keyboard to its row, the menu
    /// itself closes.
    Close,
    Nothing,
}

/// What `key` does in a menu of `rows` with the keyboard on `focus`.
/// Up and down go round; a letter chooses the one row it is the key of, or
/// moves on among the rows that share it.
pub fn step(rows: &[Row], focus: Option<usize>, key: Key, nested: bool) -> Step {
    let taking: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.kind.takes())
        .map(|(at, _)| at)
        .collect();
    let (Some(&first), Some(&last)) = (taking.first(), taking.last()) else {
        return match key {
            Key::Escape => Step::Close,
            Key::Out if nested => Step::Close,
            _ => Step::Nothing,
        };
    };
    let now = focus.and_then(|focus| taking.iter().position(|at| *at == focus));
    let count = taking.len();
    let pick = |index: usize| taking.get(index % count).copied().unwrap_or(first);
    let act = |at: usize| match rows.get(at).map(|row| row.kind) {
        Some(Kind::Group) => Step::Open(at),
        Some(Kind::Item) => Step::Choose(at),
        _ => Step::Nothing,
    };
    match key {
        Key::Down => Step::Focus(now.map_or(first, |now| pick(now + 1))),
        Key::Up => Step::Focus(now.map_or(last, |now| pick(now + count - 1))),
        Key::Home => Step::Focus(first),
        Key::End => Step::Focus(last),
        Key::Choose => focus.map_or(Step::Nothing, act),
        Key::Into => match focus {
            Some(at) if rows.get(at).map(|row| row.kind) == Some(Kind::Group) => Step::Open(at),
            _ => Step::Nothing,
        },
        Key::Out if nested => Step::Close,
        Key::Out => Step::Nothing,
        Key::Escape => Step::Close,
        Key::Letter(letter) => {
            let letter = letter.to_ascii_lowercase();
            let matching: Vec<usize> = taking
                .iter()
                .copied()
                .filter(|at| rows.get(*at).and_then(|row| row.key) == Some(letter))
                .collect();
            match matching.as_slice() {
                [] => Step::Nothing,
                [only] => act(*only),
                several => {
                    let next = several
                        .iter()
                        .copied()
                        .find(|at| focus.is_none_or(|focus| *at > focus))
                        .or_else(|| several.first().copied());
                    next.map_or(Step::Nothing, Step::Focus)
                }
            }
        }
    }
}

/// Where a scrolled menu must be to show row `at` whole, from `scrolled`.
/// The first and last rows bring the menu to its ends, so the space above
/// the first and below the last is shown with them.
pub fn reveal(laid: &Laid, at: usize, scrolled: i32) -> i32 {
    let Some(row) = laid.rows.get(at) else {
        return scrolled;
    };
    let furthest = (laid.extent - laid.shown).max(0);
    if at == 0 {
        return 0;
    }
    if at + 1 == laid.rows.len() {
        return furthest;
    }
    let to = if row.rect.top < scrolled + laid.edge {
        row.rect.top - laid.edge
    } else if row.rect.bottom() > scrolled + laid.shown - laid.edge {
        row.rect.bottom() - laid.shown + laid.edge
    } else {
        scrolled
    };
    to.clamp(0, furthest)
}

/// One drop shadow a level of the menu casts, in effective pixels: its blur,
/// how far it falls below the menu, and its black's alpha.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Cast {
    pub blur: f32,
    pub drop: f32,
    pub alpha: u8,
}

/// The shadows a level casts, as WinUI's theme shadow casts them: one in the
/// direction of the light at every elevation, and an ambient one beneath it
/// above an elevation of 16.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shadow {
    pub ambient: Option<Cast>,
    pub directional: Cast,
}

/// How far within the menu's edge the shape that casts its shadow stands, in
/// effective pixels: WinUI's caster is that much smaller on every side, so the
/// menu covers the shadow's innermost pixel, and its blur is that much wider.
pub const CAST_WITHIN: f32 = 1.0;

/// The room round a level's window for its shadow, in effective pixels -
/// beside, above and below - as WinUI sizes a menu flyout's popup window
/// (`CThemeShadow::GetInsetsForWindowedPopup`, `DropShadowDepthClass::Medium`):
/// the window cuts the shadow's tail there, as WinUI's does.
pub const ROOM: (f32, f32, f32) = (10.0, 2.0, 18.0);

/// The shadow level `depth` of a menu casts under `mode`, as WinUI's
/// `GetDropShadowRecipe` makes it for a menu flyout (`DropShadowRecipe.h` and
/// `HWCompNodeWinRT.cpp` at `winui3/release/2.5.1`): the menu raised 32, each
/// submenu 8 above its parent, its elevation half of that and no more than 64;
/// the blur the elevation and one more for the caster standing within the
/// menu, the drop half the elevation, darker in the dark mode.
pub fn shadow(depth: usize, mode: Mode) -> Shadow {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a menu's depth is a handful of levels"
    )]
    let raised = 32.0 + 8.0 * depth.min(64) as f32;
    let elevation = (raised / 2.0).min(64.0);
    // WinUI truncates opacity times 255 to the colour's alpha.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "an opacity between 0 and 1, times 255, truncated as WinUI truncates it"
    )]
    let alpha = |opacity: f32| (opacity * 255.0) as u8;
    let directional = |opacity: f32| Cast {
        blur: elevation + CAST_WITHIN,
        drop: elevation / 2.0,
        alpha: alpha(opacity),
    };
    if elevation <= 16.0 {
        Shadow {
            ambient: None,
            directional: directional(match mode {
                Mode::Light => (elevation / 100.0 + 0.06).min(0.14),
                Mode::Dark => 0.26,
            }),
        }
    } else {
        let (ambient, toward) = match mode {
            Mode::Light => (0.15, 0.19),
            Mode::Dark => (0.37, 0.37),
        };
        Shadow {
            ambient: Some(Cast {
                blur: elevation / 3.0 + CAST_WITHIN,
                drop: 2.0,
                alpha: alpha(ambient),
            }),
            directional: directional(toward),
        }
    }
}
