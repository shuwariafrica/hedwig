//! The pixels of the shapes a painted control is made of.
//!
//! Windows 11 draws a control as a rounded rectangle with smooth corners, a
//! border that is a gradient, and, with the keyboard on it, two rings
//! outside it. GDI's own rounded rectangle has no smooth edge, so the shape
//! is computed here, pixel by pixel, from how much of each pixel it covers.
//! Nothing here calls Windows: `hedwig-shell` hands the pixels to it, and a
//! shape is checked without a desktop.

use crate::arrange::Rect;
use crate::style::{Face, Focus, Rgb, Side, Tint};

/// A picture of one control: rows of `0x00RRGGBB`, the first row at the top,
/// which is the order and the form a 32-bit bitmap takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Picture {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
}

impl Picture {
    /// The colour at a place, where the picture has one.
    pub fn at(&self, x: usize, y: usize) -> Option<Rgb> {
        if x >= self.width {
            return None;
        }
        let [_, red, green, blue] = self.pixels.get(y * self.width + x)?.to_be_bytes();
        Some(Rgb::new(red, green, blue))
    }
}

/// What a control's picture is made from, every length in pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Shape {
    /// The picture's size: the control and the room its focus rings take.
    pub width: usize,
    pub height: usize,
    /// How far inside the picture the control itself begins, on every side.
    pub inset: f32,
    /// The radius of the control's corners.
    pub radius: f32,
    /// The border's thickness, and its thickness along the bottom.
    pub border: f32,
    pub bottom: f32,
    /// How many pixels an effective pixel is.
    pub scale: f32,
}

fn unit(value: usize) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

/// How much of the pixel centred at (`x`, `y`) a rounded rectangle covers,
/// from none to all of it.
fn cover(x: f32, y: f32, (left, top, right, bottom): (f32, f32, f32, f32), radius: f32) -> f32 {
    let (half_width, half_height) = ((right - left) / 2.0, (bottom - top) / 2.0);
    if half_width <= 0.0 || half_height <= 0.0 {
        return 0.0;
    }
    let radius = radius.clamp(0.0, half_width.min(half_height));
    let across = (x - (left + half_width)).abs() - half_width + radius;
    let down = (y - (top + half_height)).abs() - half_height + radius;
    let outside = across.max(0.0).hypot(down.max(0.0));
    let distance = outside + across.max(down).min(0.0) - radius;
    (0.5 - distance).clamp(0.0, 1.0)
}

/// The colour of a pixel of which each of `parts` covers its share.
fn mixed(parts: &[(Rgb, f32)]) -> Rgb {
    let channel = |of: fn(Rgb) -> u8| {
        let sum: f32 = parts
            .iter()
            .map(|(colour, share)| f32::from(of(*colour)) * share.max(0.0))
            .sum();
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "shares of one pixel sum to it, so the sum is within 0..=255"
        )]
        let whole = sum.round().clamp(0.0, 255.0) as u8;
        whole
    };
    Rgb::new(
        channel(|colour| colour.red),
        channel(|colour| colour.green),
        channel(|colour| colour.blue),
    )
}

fn grown(by: f32, (left, top, right, bottom): (f32, f32, f32, f32)) -> (f32, f32, f32, f32) {
    (left - by, top - by, right + by, bottom + by)
}

/// A control as Windows 11 draws one: `face` within its border on `beneath`,
/// with the focus rings outside it when the keyboard is on it.
pub fn control(shape: &Shape, beneath: Rgb, face: &Face, focus: Option<Focus>) -> Picture {
    let outer = (
        shape.inset,
        shape.inset,
        unit(shape.width) - shape.inset,
        unit(shape.height) - shape.inset,
    );
    let inner = (
        outer.0 + shape.border,
        outer.1 + shape.border,
        outer.2 - shape.border,
        outer.3 - shape.bottom,
    );
    let inner_radius = (shape.radius - shape.border).max(0.0);
    let mut pixels = Vec::with_capacity(shape.width * shape.height);
    for row in 0..shape.height {
        let y = unit(row) + 0.5;
        let from_edge = match face.edge.from {
            Side::Top => y - outer.1,
            Side::Bottom => outer.3 - y,
        };
        let edge = face.edge.at(from_edge / shape.scale);
        for column in 0..shape.width {
            let x = unit(column) + 0.5;
            let within = cover(x, y, outer, shape.radius);
            let filled = cover(x, y, inner, inner_radius).min(within);
            let colour = match focus {
                Some(focus) => {
                    // The inner ring is one effective pixel thick against
                    // the control, the outer two more beyond it.
                    let near = cover(x, y, grown(shape.scale, outer), shape.radius + shape.scale)
                        .max(within);
                    let far = cover(
                        x,
                        y,
                        grown(3.0 * shape.scale, outer),
                        shape.radius + 3.0 * shape.scale,
                    )
                    .max(near);
                    mixed(&[
                        (beneath, 1.0 - far),
                        (focus.outer, far - near),
                        (focus.inner, near - within),
                        (edge, within - filled),
                        (face.fill, filled),
                    ])
                }
                None => mixed(&[
                    (beneath, 1.0 - within),
                    (edge, within - filled),
                    (face.fill, filled),
                ]),
            };
            let (red, green, blue) = (colour.red, colour.green, colour.blue);
            pixels.push(u32::from_be_bytes([0, red, green, blue]));
        }
    }
    Picture {
        width: shape.width,
        height: shape.height,
        pixels,
    }
}

/// A picture with an alpha channel, for a surface Windows composes over a
/// system backdrop: what is drawn is laid over what is already there, and
/// what is drawn nowhere stays clear, so the backdrop shows through it.
#[derive(Debug, Clone, PartialEq)]
pub struct Canvas {
    pub width: usize,
    pub height: usize,
    /// Red, green, blue and alpha from 0 to 1, the colours multiplied by
    /// the alpha.
    pixels: Vec<[f32; 4]>,
}

fn channel(value: u8) -> f32 {
    f32::from(value) / 255.0
}

fn byte(value: f32) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a fraction of 255, clamped to 0..=255"
    )]
    let whole = (value.clamp(0.0, 1.0) * 255.0).round() as u8;
    whole
}

impl Canvas {
    /// A canvas nothing is drawn on: clear everywhere.
    pub fn clear(width: usize, height: usize) -> Canvas {
        Canvas {
            width,
            height,
            pixels: vec![[0.0; 4]; width * height],
        }
    }

    /// A canvas filled with one opaque colour, for a surface with no
    /// backdrop behind it.
    pub fn solid(width: usize, height: usize, colour: Rgb) -> Canvas {
        let pixel = [
            channel(colour.red),
            channel(colour.green),
            channel(colour.blue),
            1.0,
        ];
        Canvas {
            width,
            height,
            pixels: vec![pixel; width * height],
        }
    }

    /// Lays `tint` over the pixel at (`x`, `y`) where it covers `share` of it.
    fn lay(&mut self, x: usize, y: usize, tint: Tint, share: f32) {
        if x >= self.width {
            return;
        }
        let Some(pixel) = self.pixels.get_mut(y * self.width + x) else {
            return;
        };
        let alpha = channel(tint.alpha) * share.clamp(0.0, 1.0);
        let colour = [
            channel(tint.colour.red),
            channel(tint.colour.green),
            channel(tint.colour.blue),
        ];
        for (at, value) in colour.into_iter().enumerate() {
            if let Some(beneath) = pixel.get_mut(at) {
                *beneath = value * alpha + *beneath * (1.0 - alpha);
            }
        }
        if let Some(beneath) = pixel.get_mut(3) {
            *beneath = alpha + *beneath * (1.0 - alpha);
        }
    }

    /// `tint` over a rectangle with corners of `radius` pixels, its edge
    /// smooth.
    pub fn fill(&mut self, rect: Rect, radius: f32, tint: Tint) {
        let bounds = (
            unit_signed(rect.left),
            unit_signed(rect.top),
            unit_signed(rect.right()),
            unit_signed(rect.bottom()),
        );
        let (left, top) = (rect.left.max(0), rect.top.max(0));
        for y in top..rect.bottom().max(0) {
            for x in left..rect.right().max(0) {
                let share = cover(unit_signed(x) + 0.5, unit_signed(y) + 0.5, bounds, radius);
                self.lay(index(x), index(y), tint, share);
            }
        }
    }

    /// `tint` along the inside of a rectangle's edge, `thickness` pixels
    /// deep, its corners of `radius` and smooth: a frame's stroke, or one ring
    /// of a focus visual.
    pub fn outline(&mut self, rect: Rect, radius: f32, thickness: i32, tint: Tint) {
        let bounds = |rect: Rect| {
            (
                unit_signed(rect.left),
                unit_signed(rect.top),
                unit_signed(rect.right()),
                unit_signed(rect.bottom()),
            )
        };
        let outer = bounds(rect);
        let inner = bounds(Rect {
            left: rect.left + thickness,
            top: rect.top + thickness,
            width: rect.width - 2 * thickness,
            height: rect.height - 2 * thickness,
        });
        let within = (radius - unit_signed(thickness)).max(0.0);
        let (left, top) = (rect.left.max(0), rect.top.max(0));
        for y in top..rect.bottom().max(0) {
            for x in left..rect.right().max(0) {
                let (cx, cy) = (unit_signed(x) + 0.5, unit_signed(y) + 0.5);
                let share = cover(cx, cy, outer, radius) - cover(cx, cy, inner, within);
                if share > 0.0 {
                    self.lay(index(x), index(y), tint, share);
                }
            }
        }
    }

    /// `tint` where a mask covers: `coverage` is `width` by `height`
    /// bytes, row by row, how much of each pixel the shape covers - text as
    /// a renderer draws it in greys.
    pub fn mask(&mut self, left: i32, top: i32, width: usize, coverage: &[u8], tint: Tint) {
        if width == 0 {
            return;
        }
        for (at, cover) in coverage.iter().enumerate() {
            let (x, y) = (left + signed(at % width), top + signed(at / width));
            if x >= 0 && y >= 0 && *cover > 0 {
                self.lay(index(x), index(y), tint, channel(*cover));
            }
        }
    }

    /// Clears where a mask covers: `coverage` as for [`Canvas::mask`], each
    /// pixel keeping only what the mask leaves of it - a gap cut around a
    /// badge, through to what the picture stands on.
    pub fn cut(&mut self, left: i32, top: i32, width: usize, coverage: &[u8]) {
        if width == 0 {
            return;
        }
        for (at, cover) in coverage.iter().enumerate() {
            let (x, y) = (left + signed(at % width), top + signed(at / width));
            if x < 0 || y < 0 || index(x) >= self.width {
                continue;
            }
            if let Some(pixel) = self.pixels.get_mut(index(y) * self.width + index(x)) {
                let keep = 1.0 - channel(*cover);
                for value in pixel.iter_mut() {
                    *value *= keep;
                }
            }
        }
    }

    /// The colour and alpha at a place, unmultiplied.
    pub fn at(&self, x: usize, y: usize) -> Option<(Rgb, u8)> {
        if x >= self.width {
            return None;
        }
        let [red, green, blue, alpha] = *self.pixels.get(y * self.width + x)?;
        let whole = |value: f32| byte(if alpha > 0.0 { value / alpha } else { 0.0 });
        Some((Rgb::new(whole(red), whole(green), whole(blue)), byte(alpha)))
    }

    /// The pixels as a 32-bit bitmap with alpha takes them: `0xAARRGGBB`,
    /// the colours multiplied by the alpha, the first row at the top.
    pub fn premultiplied(&self) -> Vec<u32> {
        self.pixels
            .iter()
            .map(|[red, green, blue, alpha]| {
                u32::from_be_bytes([byte(*alpha), byte(*red), byte(*green), byte(*blue)])
            })
            .collect()
    }
}

fn unit_signed(value: i32) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

fn index(value: i32) -> usize {
    usize::try_from(value).unwrap_or_default()
}

fn signed(value: usize) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}
