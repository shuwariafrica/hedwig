//! Where each part of a card goes.
//!
//! The card is built as Windows 11 builds a dialog: a content layer that
//! holds the heading and what the person needs to decide, a line, and beneath
//! it the row of answers. Every length is WinUI's own for that construction,
//! in effective pixels, turned into the pixels of the monitor the card is on.
//! Nothing is measured in dialog units and nothing is cut: text that does not
//! fit wraps, answers that do not fit side by side are stacked, and a card
//! taller than the screen allows scrolls its content under answers that stay
//! where they are.
//!
//! The text is measured by whoever draws it ([`Measure`]); everything else
//! is decided here and checked without a desktop.

use crate::card::{Card, Weight};
use crate::style::{Type, line, pixels};

/// A dialog is no narrower and no wider than this.
const NARROWEST: f32 = 320.0;
const WIDEST: f32 = 548.0;
/// The space inside each of the dialog's two layers, on every side.
const PADDING: f32 = 24.0;
/// Beneath the title.
const UNDER_HEADING: f32 = 12.0;
/// Between two things the content holds.
const BETWEEN: f32 = 12.0;
/// Between two buttons, and between a control and what heads it.
const GAP: f32 = 8.0;
/// A button's text stands this far inside it: left and right, above, below.
const BUTTON_SIDE: f32 = 11.0;
const BUTTON_ABOVE: f32 = 5.0;
const BUTTON_BELOW: f32 = 6.0;
/// A command button is no narrower than this.
const BUTTON_NARROWEST: f32 = 120.0;
/// A box text is typed in is no lower than this.
const BOX_LOWEST: f32 = 32.0;
/// A fact keeps at least this much width beside an answer that stands apart.
const FACT_NARROWEST: f32 = 160.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Size {
    pub width: i32,
    pub height: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

impl Rect {
    pub fn right(&self) -> i32 {
        self.left + self.width
    }

    pub fn bottom(&self) -> i32 {
        self.top + self.height
    }

    pub fn meets(&self, other: &Rect) -> bool {
        self.left < other.right()
            && other.left < self.right()
            && self.top < other.bottom()
            && other.top < self.bottom()
    }
}

/// How large a run of text is when drawn: whoever draws the card says.
pub trait Measure {
    /// The size of `text` in `style` on one line, or wrapped within `width`
    /// pixels where one is given, when its width is that of its widest line.
    /// A word longer than the width is broken.
    fn text(&self, style: Type, text: &str, width: Option<i32>) -> Size;
}

/// A part of a card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Part {
    Heading,
    /// What the heading's question means, beneath it.
    Says,
    /// What a fact is, and the fact.
    Name(usize),
    Fact(usize),
    /// Where an answer is typed.
    Typed,
    /// What an answer that allows for a time lets through.
    Allows,
    /// How many more are waiting.
    Waiting,
    /// An answer, by its place among the card's choices.
    Choice(usize),
}

/// Which of the dialog's two layers a part is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// The heading and what the person needs to decide. It scrolls when the
    /// card is taller than the screen allows; a part's place is where it is
    /// before any scrolling.
    Content,
    /// The row of answers, which stays where it is.
    Answers,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placed {
    pub part: Part,
    pub layer: Layer,
    /// Within its layer, from that layer's top left.
    pub rect: Rect,
}

/// A card laid out for one monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arranged {
    pub width: i32,
    /// How much of the content layer is shown, and how tall it is in all.
    /// The line between the layers is the last of what is shown.
    pub shown: i32,
    pub extent: i32,
    /// The height of the layer of answers, which begins where the content
    /// shown ends.
    pub answers: i32,
    pub parts: Vec<Placed>,
    /// The choices in the order the keyboard reaches them: the row of
    /// answers, then the longer ones, then the one apart.
    pub order: Vec<usize>,
}

impl Arranged {
    pub fn height(&self) -> i32 {
        self.shown + self.answers
    }

    /// Whether the content is taller than what is shown of it.
    pub fn scrolls(&self) -> bool {
        self.extent > self.shown
    }

    pub fn place(&self, part: Part) -> Option<&Placed> {
        self.parts.iter().find(|placed| placed.part == part)
    }
}

/// The monitor a card is laid out for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub dpi: u32,
    /// The tallest the card may be, in pixels: what the screen leaves it.
    pub tallest: i32,
}

struct Pen<'a> {
    card: &'a Card,
    measure: &'a dyn Measure,
    dpi: u32,
    /// The width inside the padding.
    inner: i32,
    parts: Vec<Placed>,
}

impl Pen<'_> {
    fn px(&self, effective: f32) -> i32 {
        pixels(effective, self.dpi)
    }

    fn label(&self, place: usize) -> &str {
        self.card
            .choices
            .get(place)
            .map_or("", |choice| choice.label.as_str())
    }

    /// The size of the button for one of the card's choices.
    fn button(&self, place: usize) -> Size {
        let text = self.measure.text(Type::Body, self.label(place), None);
        let border = 2 * line(1.0, self.dpi);
        Size {
            width: (text.width + 2 * self.px(BUTTON_SIDE) + border).max(self.px(BUTTON_NARROWEST)),
            height: text.height + self.px(BUTTON_ABOVE) + self.px(BUTTON_BELOW) + border,
        }
    }

    fn put(&mut self, part: Part, layer: Layer, rect: Rect) {
        self.parts.push(Placed { part, layer, rect });
    }

    /// Text wrapped within `width` at `top`; returns where it ends.
    fn text(&mut self, part: Part, style: Type, text: &str, top: i32, width: i32) -> i32 {
        let size = self.measure.text(style, text, Some(width));
        let left = self.px(PADDING);
        self.put(
            part,
            Layer::Content,
            Rect {
                left,
                top,
                width,
                height: size.height,
            },
        );
        top + size.height
    }

    /// The width inside the padding, as WinUI finds a dialog's: every text is
    /// measured wrapped within the widest a dialog may be, and the dialog is
    /// as wide as the widest line that gives, and no narrower than a dialog
    /// may be. A sentence too long for one line therefore makes the card as
    /// wide as its own first line, not only as wide as the texts that fit.
    fn widest(&self, row: &[usize], longer: &[usize], apart: &[usize]) -> i32 {
        let padding = 2 * self.px(PADDING);
        let most = self.px(WIDEST) - padding;
        let wrapped = |style, text: &str, within: i32| {
            self.measure.text(style, text, Some(within.max(1))).width
        };
        let gap = self.px(GAP);
        let mut widest = wrapped(Type::Subtitle, &self.card.heading, most);
        if let Some(says) = &self.card.says {
            widest = widest.max(wrapped(Type::Body, says, most));
        }
        let beside: i32 = apart
            .iter()
            .map(|place| self.button(*place).width + self.px(BETWEEN))
            .sum();
        for (at, (name, fact)) in self.card.facts.iter().enumerate() {
            let taken = if at == 0 { beside } else { 0 };
            widest = widest
                .max(wrapped(Type::Caption, name, most - taken) + taken)
                .max(wrapped(Type::Body, fact, most - taken) + taken);
        }
        if let Some(allows) = &self.card.allows {
            widest = widest.max(wrapped(Type::Body, allows, most));
        }
        if let Some(waiting) = self.card.waiting() {
            widest = widest.max(wrapped(Type::Caption, &waiting, most));
        }
        if !longer.is_empty() {
            let buttons: i32 = longer.iter().map(|place| self.button(*place).width).sum();
            widest = widest.max(buttons + gap * (count(longer.len()) - 1));
        }
        let column = row
            .iter()
            .map(|place| self.button(*place).width)
            .max()
            .unwrap_or_default();
        // One answer takes half the row, as a dialog's single button does.
        let columns = count(row.len()).max(2);
        widest = widest.max(column * columns + gap * (columns - 1));
        widest.clamp(self.px(NARROWEST) - padding, most)
    }

    /// Each fact under its name, from `top`; returns where they end. The
    /// answer that ends more than this request stands by the fact it is
    /// about, the first: beside it where the fact keeps room to be read,
    /// beneath it where it would not.
    fn facts(&mut self, apart: &[usize], mut top: i32) -> i32 {
        let (padding, gap, between) = (self.px(PADDING), self.px(GAP), self.px(BETWEEN));
        let inner = self.inner;
        let card = self.card;
        for (at, (name, fact)) in card.facts.iter().enumerate() {
            if at > 0 {
                top += between;
            }
            let began = top;
            let buttons: Vec<(usize, Size)> = if at == 0 {
                apart
                    .iter()
                    .map(|place| (*place, self.button(*place)))
                    .collect()
            } else {
                Vec::new()
            };
            let beside: i32 = buttons.iter().map(|(_, size)| size.width + between).sum();
            let fits = inner - beside >= self.px(FACT_NARROWEST);
            let room = if fits { inner - beside } else { inner };
            top = self.text(Part::Name(at), Type::Caption, name, top, room);
            top = self.text(Part::Fact(at), Type::Body, fact, top, room);
            let mut left = padding + inner;
            for (place, size) in buttons.into_iter().rev() {
                let rect = if fits {
                    left -= size.width;
                    let rect = Rect {
                        left,
                        top: began,
                        width: size.width,
                        height: size.height,
                    };
                    left -= between;
                    rect
                } else {
                    Rect {
                        left: padding,
                        top: top + gap,
                        width: size.width.min(inner),
                        height: size.height,
                    }
                };
                top = top.max(rect.bottom());
                self.put(Part::Choice(place), Layer::Content, rect);
            }
        }
        top
    }

    /// Where an answer is typed, the full width, below `top`.
    fn typed(&mut self, top: i32) -> i32 {
        // A line of the text the box will hold.
        let text = self.measure.text(Type::Body, "Ag", None);
        let height =
            (text.height + self.px(BUTTON_ABOVE) + self.px(BUTTON_BELOW) + 2 * line(1.0, self.dpi))
                .max(self.px(BOX_LOWEST));
        let rect = Rect {
            left: self.px(PADDING),
            top,
            width: self.inner,
            height,
        };
        self.put(Part::Typed, Layer::Content, rect);
        rect.bottom()
    }

    /// The answers that allow for a time, under what they let through: side
    /// by side while they fit, on a further row where they do not.
    fn longer(&mut self, allows: &str, longer: &[usize], top: i32) -> i32 {
        let (padding, gap, inner) = (self.px(PADDING), self.px(GAP), self.inner);
        let mut top = self.text(Part::Allows, Type::Body, allows, top, inner) + gap;
        let mut left = padding;
        let mut lowest = top;
        for place in longer {
            let size = self.button(*place);
            let width = size.width.min(inner);
            if left > padding && left + width > padding + inner {
                left = padding;
                top = lowest + gap;
            }
            let rect = Rect {
                left,
                top,
                width,
                height: size.height,
            };
            lowest = lowest.max(rect.bottom());
            left = rect.right() + gap;
            self.put(Part::Choice(*place), Layer::Content, rect);
        }
        lowest
    }

    /// The row of answers: equal columns that fill the row, or one answer to
    /// a row where a label would not fit its column. Returns the layer's
    /// height.
    fn answers(&mut self, row: &[usize]) -> i32 {
        let (padding, gap, inner) = (self.px(PADDING), self.px(GAP), self.inner);
        let sizes: Vec<Size> = row.iter().map(|place| self.button(*place)).collect();
        let columns = count(row.len()).max(2);
        let column = (inner - gap * (columns - 1)) / columns;
        let tall = sizes
            .iter()
            .map(|size| size.height)
            .max()
            .unwrap_or_default();
        let stacked = row.len() > 3 || sizes.iter().any(|size| size.width > column);
        let mut below = padding;
        for (at, place) in row.iter().enumerate() {
            let rect = if stacked {
                Rect {
                    left: padding,
                    top: below,
                    width: inner,
                    height: tall,
                }
            } else {
                // A single answer takes the right-hand half.
                let slot = if row.len() == 1 { 1 } else { count(at) };
                let left = padding + slot * (column + gap);
                // The last column takes the pixel an odd width leaves, so the
                // row ends where the padding begins.
                let width = if slot == columns - 1 {
                    padding + inner - left
                } else {
                    column
                };
                Rect {
                    left,
                    top: padding,
                    width,
                    height: tall,
                }
            };
            below = rect.bottom() + gap;
            self.put(Part::Choice(*place), Layer::Answers, rect);
        }
        below - gap + padding
    }
}

fn chosen(card: &Card, wanted: impl Fn(Weight) -> bool) -> Vec<usize> {
    card.choices
        .iter()
        .enumerate()
        .filter(|(_, choice)| wanted(choice.weight))
        .map(|(place, _)| place)
        .collect()
}

fn count(items: usize) -> i32 {
    i32::try_from(items).unwrap_or(i32::MAX)
}

/// Lays `card` out for the monitor `space` describes.
pub fn arrange(card: &Card, measure: &dyn Measure, space: Space) -> Arranged {
    let row = chosen(card, |weight| {
        matches!(weight, Weight::Usual | Weight::Beside)
    });
    let longer = chosen(card, |weight| weight == Weight::Longer);
    let apart = chosen(card, |weight| weight == Weight::Apart);
    let mut pen = Pen {
        card,
        measure,
        dpi: space.dpi,
        inner: 0,
        parts: Vec::new(),
    };
    pen.inner = pen.widest(&row, &longer, &apart);
    let (padding, between) = (pen.px(PADDING), pen.px(BETWEEN));
    let inner = pen.inner;

    let mut top = pen.text(Part::Heading, Type::Subtitle, &card.heading, padding, inner);
    top += pen.px(UNDER_HEADING);
    if let Some(says) = &card.says {
        top = pen.text(Part::Says, Type::Body, says, top, inner);
        if !card.facts.is_empty() {
            top += between;
        }
    }
    top = pen.facts(&apart, top);
    if card.typed {
        top = pen.typed(top + between);
    }
    if let Some(allows) = &card.allows {
        top = pen.longer(allows, &longer, top + between);
    }
    if let Some(waiting) = card.waiting() {
        top = pen.text(Part::Waiting, Type::Caption, &waiting, top + between, inner);
    }
    // The content's own padding, and the line that ends it.
    let extent = top + padding + line(1.0, space.dpi);
    let answers = pen.answers(&row);
    Arranged {
        width: inner + 2 * padding,
        shown: extent.min((space.tallest - answers).max(0)),
        extent,
        answers,
        parts: pen.parts,
        order: row.iter().chain(&longer).chain(&apart).copied().collect(),
    }
}

/// Where the card stands: at the corner of the screen's work area nearest
/// the notification-area icon, `margin` pixels in from each edge; with no
/// icon to go by, at the corner where Windows puts the notification area
/// unless the person moved it.
pub fn corner(work: Rect, icon: Option<Rect>, card: Size, margin: i32) -> (i32, i32) {
    let (middle_x, middle_y) = (work.left + work.width / 2, work.top + work.height / 2);
    let (at_right, at_bottom) = icon.map_or((true, true), |icon| {
        (
            icon.left + icon.width / 2 >= middle_x,
            icon.top + icon.height / 2 >= middle_y,
        )
    });
    let left = if at_right {
        work.right() - card.width - margin
    } else {
        work.left + margin
    };
    let top = if at_bottom {
        work.bottom() - card.height - margin
    } else {
        work.top + margin
    };
    (left.max(work.left), top.max(work.top))
}

/// Where a confirmation stands: in the middle of the work area, as Windows
/// centres a dialog that has no window of its own to stand over.
pub fn middle(work: Rect, dialog: Size) -> (i32, i32) {
    (
        (work.left + (work.width - dialog.width) / 2).max(work.left),
        (work.top + (work.height - dialog.height) / 2).max(work.top),
    )
}
