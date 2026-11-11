//! Hedwig's emblem - its logo - drawn at the size Windows asks for,
//! saying at a glance what the notification-area icon says, in colours the
//! taskbar it stands on serves.
//!
//! The shapes are the logo's, read from `packaging/branding/hedwig-logo.svg`
//! as drawn there, each laid by how much of every pixel it covers: the emblem
//! is exact at whatever size a scale asks for, never scaled from another.
//!
//! The owl answers [`glance`](crate::glance)'s two axes, one each: its eyes
//! say whether anything reaches the workstation now, a badge at its corner
//! whether anything waits for the person.

use crate::glance::{Glance, Reach, Waiting};
use crate::paint::Canvas;
use crate::style::{Mode, Rgb, System, Tint};

const LOGO: &str = include_str!("../../../packaging/branding/hedwig-logo.svg");
/// The same shapes in the colours a light taskbar takes: the logo's light
/// face would leave too little of a small icon at 3:1 there.
const LOGO_LIGHT: &str = include_str!("../../../packaging/branding/hedwig-logo-light.svg");
/// The logo's view box, square.
const BOX: f32 = 512.0;
/// Each cubic segment is laid as this many straight ones: at 512 units the
/// longest bends by under a tenth of a unit between them.
const STEPS: u16 = 12;
/// Rows sampled within each row of pixels.
const SAMPLES: u16 = 5;

/// What the owl's eyes say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Owl {
    /// Something reaches the workstation now: the eyes open.
    Awake,
    /// Nothing reaches it - nothing is connected, the person paused it, or
    /// the core has not said yet: the lids half down, no pupil.
    Dozing,
    /// No core answers: as dozing, in greys.
    Absent,
}

/// What waits for the person, at the emblem's corner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Badge {
    Nothing,
    /// Something to look at that holds nothing up: a ring.
    Look,
    /// Something held until the person answers: a filled disc.
    Answer,
}

/// What the emblem stands on, which decides its colours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ink {
    /// A taskbar in Windows' own mode: the logo in the colours for that
    /// mode, and a badge in that mode's own colours.
    Taskbar(Mode),
    /// A contrast theme: its colours and nothing else.
    System(System),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Emblem {
    pub owl: Owl,
    pub badge: Badge,
}

impl Emblem {
    /// The emblem as an executable carries it: the owl awake, nothing waiting.
    pub const PLAIN: Emblem = Emblem {
        owl: Owl::Awake,
        badge: Badge::Nothing,
    };

    /// What the icon shows for what the glance says.
    pub fn of(glance: &Glance) -> Emblem {
        Emblem {
            owl: match glance.reach {
                Reach::Reachable(_) => Owl::Awake,
                Reach::Quiet | Reach::Paused | Reach::Wait => Owl::Dozing,
                Reach::Off => Owl::Absent,
            },
            badge: match glance.waiting {
                Waiting::Nothing => Badge::Nothing,
                Waiting::Look(_) => Badge::Look,
                Waiting::Answer(_) => Badge::Answer,
            },
        }
    }

    /// The emblem `side` pixels square, clear where nothing is drawn.
    pub fn draw(self, side: usize, ink: Ink) -> Canvas {
        let mut canvas = Canvas::clear(side, side);
        let scale = side_f(side) / BOX;
        // Read at each drawing and let go after: the icon is drawn only
        // when what it shows changes, and the presence runs all day.
        let shapes = read(match ink {
            Ink::Taskbar(Mode::Light) => LOGO_LIGHT,
            Ink::Taskbar(Mode::Dark) | Ink::System(_) => LOGO,
        });
        // A lid is the eye's own dark: the pupil's colour.
        let pupil = shapes
            .iter()
            .find(|shape| shape.role == Role::Pupil)
            .map_or(Rgb::new(0, 0, 0), |pupil| pupil.fill);
        for shape in &shapes {
            let own = tint(shape.fill, shape.role, ink, self.owl);
            let band = match (shape.role, self.owl) {
                (Role::Pupil, Owl::Dozing | Owl::Absent) => continue,
                // The lid: the eye's upper half in the pupil's colour and
                // its lower half its own, each laid once, so no edge of the
                // eye is laid twice.
                (Role::Eye, Owl::Dozing | Owl::Absent) => {
                    let middle = shape.middle * scale;
                    let lid = tint(pupil, Role::Pupil, ink, self.owl);
                    lay(&mut canvas, &shape.rings, scale, Band::Above(middle), lid);
                    Band::Below(middle)
                }
                _ => Band::Whole,
            };
            lay(&mut canvas, &shape.rings, scale, band, own);
        }
        badge(&mut canvas, side, self.badge, ink);
        canvas
    }
}

/// What a shape is drawn in: its own colour in the logo, in grey where no
/// core answers; under a contrast theme the window's colour for the field
/// and the eyes, and its text - grey text where no core answers - for the
/// owl's lines.
fn tint(fill: Rgb, role: Role, ink: Ink, owl: Owl) -> Tint {
    opaque(match (ink, role, owl) {
        (Ink::Taskbar(_), _, Owl::Absent) => grey(fill),
        (Ink::Taskbar(_), _, _) => fill,
        (Ink::System(system), Role::Field | Role::Eye, _) => system.window,
        (Ink::System(system), _, Owl::Absent) => system.gray_text,
        (Ink::System(system), _, _) => system.window_text,
    })
}

fn opaque(colour: Rgb) -> Tint {
    Tint {
        colour,
        alpha: 0xff,
    }
}

/// `colour` as the grey of the same relative luminance, so it holds the same
/// contrast against what it stands on.
fn grey(colour: Rgb) -> Rgb {
    let level = |value: u8| {
        let unit = f32::from(value) / 255.0;
        if unit <= 0.040_45 {
            unit / 12.92
        } else {
            ((unit + 0.055) / 1.055).powf(2.4)
        }
    };
    let luminance =
        0.2126 * level(colour.red) + 0.7152 * level(colour.green) + 0.0722 * level(colour.blue);
    let unit = if luminance <= 0.003_130_8 {
        luminance * 12.92
    } else {
        1.055 * luminance.powf(1.0 / 2.4) - 0.055
    };
    let value = byte(unit * 255.0);
    Rgb::new(value, value, value)
}

/// WinUI's critical fill (`SystemFillColorCritical`) and its primary text
/// (`TextFillColorPrimary`), dark then light, at release 2.5.1.
const CRITICAL_DARK: Rgb = Rgb::new(0xff, 0x99, 0xa4);
const CRITICAL_LIGHT: Rgb = Rgb::new(0xc4, 0x2b, 0x1c);
const TEXT_DARK: Tint = Tint::argb(0xffff_ffff);
const TEXT_LIGHT: Tint = Tint::argb(0xe400_0000);

/// The badge at the bottom right: a disc seven sixteenths of the emblem
/// across, parted from the owl by a clear gap a sixteenth wide.
fn badge(canvas: &mut Canvas, side: usize, badge: Badge, ink: Ink) {
    if badge == Badge::Nothing {
        return;
    }
    let side = side_f(side);
    let radius = (side * 7.0 / 32.0).max(3.0);
    let gap = (side / 16.0).max(1.0);
    let centre = (side - radius, side - radius);
    let cut = circle(centre, radius + gap);
    let disc = circle(centre, radius);
    let (fill, ring) = match ink {
        Ink::Taskbar(Mode::Dark) => (opaque(CRITICAL_DARK), TEXT_DARK),
        Ink::Taskbar(Mode::Light) => (opaque(CRITICAL_LIGHT), TEXT_LIGHT),
        Ink::System(system) => (opaque(system.highlight), opaque(system.highlight)),
    };
    let width = canvas.width;
    let cover = coverage(&[cut], 1.0, width, Band::Whole);
    canvas.cut(0, 0, width, &cover);
    match badge {
        Badge::Answer => lay(canvas, &[disc], 1.0, Band::Whole, fill),
        Badge::Look => {
            let thickness = (radius * 0.4).max(1.5);
            let hole = coverage(
                &[circle(centre, radius - thickness)],
                1.0,
                width,
                Band::Whole,
            );
            let mut ring_cover = coverage(&[disc], 1.0, width, Band::Whole);
            for (at, inner) in ring_cover.iter_mut().zip(hole) {
                *at = at.saturating_sub(inner);
            }
            canvas.mask(0, 0, width, &ring_cover, ring);
        }
        Badge::Nothing => {}
    }
}

fn circle((x, y): (f32, f32), radius: f32) -> Vec<(f32, f32)> {
    let steps = 96_u16;
    (0..steps)
        .map(|step| {
            let angle = f32::from(step) / f32::from(steps) * std::f32::consts::TAU;
            (x + radius * angle.cos(), y + radius * angle.sin())
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Frame,
    Face,
    Field,
    Eye,
    Pupil,
    Beak,
}

/// One of the logo's shapes: its colour, its outline as closed polygons in
/// the view box, and the middle of its height, where an eye's lid ends.
struct Shape {
    role: Role,
    fill: Rgb,
    rings: Vec<Vec<(f32, f32)>>,
    middle: f32,
}

/// Of each of the logo's two files: how many shapes were read, of how many
/// it has, and whether its outlines are the other's.
pub fn read_of_logo() -> [(usize, usize, bool); 2] {
    let written = |svg: &str| {
        svg.lines()
            .filter(|line| line.starts_with("<path ") || line.starts_with("<polygon "))
            .count()
    };
    let (logo, light) = (read(LOGO), read(LOGO_LIGHT));
    let same = logo.len() == light.len()
        && logo
            .iter()
            .zip(&light)
            .all(|(one, other)| one.role == other.role && one.rings == other.rings);
    [
        (logo.len(), written(LOGO), same),
        (light.len(), written(LOGO_LIGHT), same),
    ]
}

/// The logo's shapes in the order they are drawn. A shape the reader cannot
/// read is left out, which the suite rules out for the logo as shipped.
fn read(svg: &str) -> Vec<Shape> {
    svg.lines()
        .filter_map(|line| {
            let role = match attribute(line, "class")? {
                "frame" => Role::Frame,
                "face" => Role::Face,
                "field" => Role::Field,
                "eye" => Role::Eye,
                "pupil" => Role::Pupil,
                "beak" => Role::Beak,
                _ => return None,
            };
            let fill = colour(attribute(line, "fill")?)?;
            let rings = if line.starts_with("<polygon ") {
                vec![points(attribute(line, "points")?)?]
            } else {
                outline(attribute(line, "d")?)?
            };
            let (top, bottom) = rings
                .iter()
                .flatten()
                .fold((f32::MAX, f32::MIN), |(top, bottom), (_, y)| {
                    (top.min(*y), bottom.max(*y))
                });
            Some(Shape {
                role,
                fill,
                rings,
                middle: f32::midpoint(top, bottom),
            })
        })
        .collect()
}

/// A colour as SVG writes it, `#rrggbb`.
fn colour(text: &str) -> Option<Rgb> {
    let digits = text.strip_prefix('#').filter(|digits| digits.len() == 6)?;
    let part = |at: usize| u8::from_str_radix(digits.get(at..at + 2)?, 16).ok();
    Some(Rgb::new(part(0)?, part(2)?, part(4)?))
}

fn attribute<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let start = line.find(&format!(" {name}=\""))? + name.len() + 3;
    let rest = line.get(start..)?;
    rest.get(..rest.find('"')?)
}

/// The numbers in `text`, as SVG writes them: `1.07-1.24` is two, `.5.5` is
/// two, and a comma or a space parts them.
fn numbers(text: &str) -> Option<Vec<f32>> {
    let mut found = Vec::new();
    let mut current = String::new();
    let mut dotted = false;
    let flush = |current: &mut String, found: &mut Vec<f32>| -> Option<()> {
        if !current.is_empty() {
            found.push(current.parse().ok()?);
            current.clear();
        }
        Some(())
    };
    for character in text.chars() {
        match character {
            '0'..='9' | 'e' | 'E' => current.push(character),
            '.' => {
                if dotted {
                    flush(&mut current, &mut found)?;
                }
                dotted = true;
                current.push('.');
            }
            '-' | '+' => {
                if !current.ends_with(['e', 'E']) {
                    flush(&mut current, &mut found)?;
                    dotted = false;
                }
                current.push(character);
            }
            ',' | ' ' | '\n' | '\t' => {
                flush(&mut current, &mut found)?;
                dotted = false;
            }
            _ => return None,
        }
    }
    flush(&mut current, &mut found)?;
    Some(found)
}

fn points(text: &str) -> Option<Vec<(f32, f32)>> {
    let values = numbers(text)?;
    let (pairs, rest) = values.as_chunks::<2>();
    (rest.is_empty() && pairs.len() >= 3).then(|| pairs.iter().map(|[x, y]| (*x, *y)).collect())
}

/// A path's outline as closed polygons, from the commands Illustrator
/// writes: moves, lines, horizontal and vertical lines, cubic curves and
/// their smooth form, absolute or relative, and closing.
fn outline(data: &str) -> Option<Vec<Vec<(f32, f32)>>> {
    let mut rings = Vec::new();
    let mut ring: Vec<(f32, f32)> = Vec::new();
    let (mut at, mut start, mut control) = ((0.0_f32, 0.0_f32), (0.0, 0.0), None);
    let mut rest = data.trim();
    while let Some(command) = rest.chars().next() {
        let end = rest
            .char_indices()
            .skip(1)
            .find(|(_, character)| {
                character.is_ascii_alphabetic() && !matches!(character, 'e' | 'E')
            })
            .map_or(rest.len(), |(index, _)| index);
        let values = numbers(rest.get(command.len_utf8()..end)?)?;
        rest = rest.get(end..)?.trim_start();
        let relative = command.is_ascii_lowercase();
        let base = |at: (f32, f32)| if relative { at } else { (0.0, 0.0) };
        match command.to_ascii_uppercase() {
            'M' => {
                for (index, [x, y]) in values.as_chunks::<2>().0.iter().enumerate() {
                    let origin = base(at);
                    at = (origin.0 + x, origin.1 + y);
                    if index == 0 {
                        if ring.len() > 2 {
                            rings.push(std::mem::take(&mut ring));
                        }
                        ring.clear();
                        start = at;
                    }
                    ring.push(at);
                }
                control = None;
            }
            'L' => {
                for [x, y] in values.as_chunks::<2>().0 {
                    let origin = base(at);
                    at = (origin.0 + x, origin.1 + y);
                    ring.push(at);
                }
                control = None;
            }
            'H' => {
                for x in &values {
                    at.0 = if relative { at.0 + x } else { *x };
                    ring.push(at);
                }
                control = None;
            }
            'V' => {
                for y in &values {
                    at.1 = if relative { at.1 + y } else { *y };
                    ring.push(at);
                }
                control = None;
            }
            'C' => {
                for [x1, y1, x2, y2, x, y] in values.as_chunks::<6>().0 {
                    let origin = base(at);
                    let first = (origin.0 + x1, origin.1 + y1);
                    let second = (origin.0 + x2, origin.1 + y2);
                    let to = (origin.0 + x, origin.1 + y);
                    cubic(&mut ring, at, first, second, to);
                    control = Some(second);
                    at = to;
                }
            }
            'S' => {
                for [x2, y2, x, y] in values.as_chunks::<4>().0 {
                    let origin = base(at);
                    // The first control mirrors the last curve's second.
                    let first = control.map_or(at, |(cx, cy)| (2.0 * at.0 - cx, 2.0 * at.1 - cy));
                    let second = (origin.0 + x2, origin.1 + y2);
                    let to = (origin.0 + x, origin.1 + y);
                    cubic(&mut ring, at, first, second, to);
                    control = Some(second);
                    at = to;
                }
            }
            'Z' => {
                if ring.len() > 2 {
                    rings.push(std::mem::take(&mut ring));
                }
                // What follows without a move begins where this began.
                at = start;
                ring.push(at);
                control = None;
            }
            _ => return None,
        }
    }
    if ring.len() > 2 {
        rings.push(ring);
    }
    (!rings.is_empty()).then_some(rings)
}

fn cubic(
    ring: &mut Vec<(f32, f32)>,
    from: (f32, f32),
    first: (f32, f32),
    second: (f32, f32),
    to: (f32, f32),
) {
    for step in 1..=STEPS {
        let along = f32::from(step) / f32::from(STEPS);
        let left = 1.0 - along;
        // The Bernstein weights of the four points.
        let weights = [
            left * left * left,
            3.0 * left * left * along,
            3.0 * left * along * along,
            along * along * along,
        ];
        let point = |part: fn((f32, f32)) -> f32| {
            weights
                .iter()
                .zip([from, first, second, to])
                .map(|(weight, point)| weight * part(point))
                .sum::<f32>()
        };
        ring.push((point(|point| point.0), point(|point| point.1)));
    }
}

/// Which rows of pixels a shape is laid in, by where each row is sampled.
#[derive(Clone, Copy)]
enum Band {
    Whole,
    Above(f32),
    Below(f32),
}

impl Band {
    fn holds(self, y: f32) -> bool {
        match self {
            Band::Whole => true,
            Band::Above(limit) => y < limit,
            Band::Below(limit) => y >= limit,
        }
    }
}

/// Lays `tint` where the rings cover, scaled by `scale`, in `band`.
fn lay(canvas: &mut Canvas, rings: &[Vec<(f32, f32)>], scale: f32, band: Band, tint: Tint) {
    let width = canvas.width;
    let cover = coverage(rings, scale, width, band);
    canvas.mask(0, 0, width, &cover, tint);
}

/// How much of each pixel of a `side`-square the rings cover, by the
/// non-zero rule, as bytes row by row: rows are sampled [`SAMPLES`] times
/// within each pixel, and each span's ends are taken to the fraction of a
/// pixel they cover.
fn coverage(rings: &[Vec<(f32, f32)>], scale: f32, side: usize, band: Band) -> Vec<u8> {
    let mut sums = vec![0.0_f32; side * side];
    let edges: Vec<((f32, f32), (f32, f32))> = rings
        .iter()
        .flat_map(|ring| {
            ring.iter()
                .zip(ring.iter().cycle().skip(1))
                .map(|(from, to)| {
                    (
                        (from.0 * scale, from.1 * scale),
                        (to.0 * scale, to.1 * scale),
                    )
                })
        })
        .collect();
    let weight = 1.0 / f32::from(SAMPLES);
    let mut crossings: Vec<(f32, i32)> = Vec::new();
    for row in 0..side {
        for sample in 0..SAMPLES {
            let y = side_f(row) + (f32::from(sample) + 0.5) * weight;
            if !band.holds(y) {
                continue;
            }
            crossings.clear();
            for &((x0, y0), (x1, y1)) in &edges {
                if (y0 <= y && y < y1) || (y1 <= y && y < y0) {
                    let x = x0 + (y - y0) / (y1 - y0) * (x1 - x0);
                    crossings.push((x, if y1 > y0 { 1 } else { -1 }));
                }
            }
            crossings.sort_by(|one, other| one.0.total_cmp(&other.0));
            let mut winding = 0;
            let mut from = 0.0;
            for &(x, direction) in &crossings {
                let was = winding;
                winding += direction;
                if was == 0 && winding != 0 {
                    from = x;
                } else if was != 0 && winding == 0 {
                    span(&mut sums, side, row, from, x, weight);
                }
            }
        }
    }
    sums.into_iter().map(|sum| byte(sum * 255.0)).collect()
}

/// Adds `weight` times how much of each pixel of `row` lies between `from`
/// and `to`.
fn span(sums: &mut [f32], side: usize, row: usize, from: f32, to: f32, weight: f32) {
    let (from, to) = (from.max(0.0), to.min(side_f(side)));
    if to <= from {
        return;
    }
    let first = whole(from.floor());
    let last = whole(to.ceil()).min(side);
    for column in first..last {
        let left = side_f(column).max(from);
        let right = (side_f(column) + 1.0).min(to);
        if let Some(sum) = sums.get_mut(row * side + column) {
            *sum += (right - left).max(0.0) * weight;
        }
    }
}

fn side_f(value: usize) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "an icon's side is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

fn whole(value: f32) -> usize {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a non-negative column, already floored or ceiled"
    )]
    let column = value.max(0.0) as usize;
    column
}

fn byte(value: f32) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped to 0..=255"
    )]
    let whole = value.round().clamp(0.0, 255.0) as u8;
    whole
}
