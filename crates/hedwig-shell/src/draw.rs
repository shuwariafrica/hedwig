//! What the painted surfaces are drawn with: the pictures of controls
//! `hedwig-view` computes, handed to Windows as bitmaps, and their text,
//! set by DirectWrite ([`crate::write`]) where Hedwig draws it and measured
//! by GDI where Windows' own controls draw it.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{COLORREF, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    ANTIALIASED_QUALITY, BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC,
    CreateDIBSection, CreateFontW, CreateSolidBrush, DEFAULT_CHARSET, DIB_RGB_COLORS,
    DRAW_TEXT_FORMAT, DT_CALCRECT, DT_CENTER, DT_EDITCONTROL, DT_END_ELLIPSIS, DT_HIDEPREFIX,
    DT_LEFT, DT_NOPREFIX, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, DeleteDC,
    DeleteObject, DrawTextW, FillRect, HBITMAP, HBRUSH, HDC, HFONT, HGDIOBJ, SelectObject,
    SetBkMode, SetDIBitsToDevice, SetTextColor, TRANSPARENT,
};

use hedwig_view::arrange::{Measure, Size};
use hedwig_view::paint::Picture;
use hedwig_view::style::{Rgb, TextScale, Tint, Type, pixels};

use crate::raw::{size, wide};
use crate::write::{Backing, Keys, Run, Setting, Writer};

/// A colour as GDI takes it.
pub(crate) fn colour(rgb: Rgb) -> COLORREF {
    u32::from(rgb.red) | (u32::from(rgb.green) << 8) | (u32::from(rgb.blue) << 16)
}

/// A solid brush, deleted when this is dropped.
#[derive(Debug)]
pub(crate) struct Brush(HBRUSH);

impl Brush {
    pub(crate) fn new(rgb: Rgb) -> Brush {
        // SAFETY: no pointers; a brush Windows could not make is null, which
        // every call that takes one treats as no brush.
        Brush(unsafe { CreateSolidBrush(colour(rgb)) })
    }

    pub(crate) fn handle(&self) -> HBRUSH {
        self.0
    }

    pub(crate) fn fill(&self, dc: HDC, area: &RECT) {
        // SAFETY: the rectangle is valid for the call and the brush is this
        // value's own.
        unsafe { FillRect(dc, area, self.0) };
    }
}

impl Drop for Brush {
    fn drop(&mut self) {
        // SAFETY: the brush is this value's own and is selected nowhere.
        unsafe { DeleteObject(self.0) };
    }
}

/// The three styles of the ramp as GDI fonts for one monitor and one text
/// size, with a device context to measure them in: what Windows' own
/// controls draw their text with.
#[derive(Debug)]
pub(crate) struct Fonts {
    caption: HFONT,
    body: HFONT,
    subtitle: HFONT,
    icons: HFONT,
    measuring: HDC,
}

fn font(face: &str, weight: u16, height: i32) -> HFONT {
    let face = wide(face);
    // SAFETY: the face name is NUL-terminated and copied by the call. A
    // negative height asks for that many pixels of the font's own size, and
    // the quality for smooth edges in greys.
    unsafe {
        CreateFontW(
            -height,
            0,
            0,
            0,
            i32::from(weight),
            0,
            0,
            0,
            u32::from(DEFAULT_CHARSET),
            0,
            0,
            u32::from(ANTIALIASED_QUALITY),
            0,
            face.as_ptr(),
        )
    }
}

impl Fonts {
    pub(crate) fn new(dpi: u32, text: TextScale) -> Fonts {
        let style = |style: Type| {
            font(
                style.face(),
                style.weight(),
                pixels(text.size(style.size()), dpi),
            )
        };
        Fonts {
            caption: style(Type::Caption),
            body: style(Type::Body),
            subtitle: style(Type::Subtitle),
            icons: font("Segoe Fluent Icons", 400, pixels(12.0, dpi)),
            // SAFETY: a null context asks for one compatible with the screen.
            measuring: unsafe { CreateCompatibleDC(std::ptr::null_mut()) },
        }
    }

    pub(crate) fn of(&self, style: Type) -> HFONT {
        match style {
            Type::Caption => self.caption,
            Type::Body => self.body,
            Type::Subtitle => self.subtitle,
        }
    }
}

impl Drop for Fonts {
    fn drop(&mut self) {
        // SAFETY: the context is this value's own.
        unsafe { DeleteDC(self.measuring) };
        for font in [self.caption, self.body, self.subtitle, self.icons] {
            // SAFETY: the font is this value's own; a control that still
            // names it is destroyed before its fonts are.
            unsafe { DeleteObject(font) };
        }
    }
}

impl Fonts {
    fn sized(&self, style: Type, text: &str, width: Option<i32>) -> Size {
        let units = wide(text);
        let mut area = RECT {
            right: width.unwrap_or_default(),
            ..RECT::default()
        };
        let format = match width {
            // A word longer than the width is broken, as an edit control
            // breaks one: a key's fingerprint has no space to break at.
            Some(_) => DT_CALCRECT | DT_NOPREFIX | DT_WORDBREAK | DT_EDITCONTROL,
            None => DT_CALCRECT | DT_NOPREFIX | DT_SINGLELINE,
        };
        // SAFETY: the font is this value's own and the context its own.
        let before = unsafe { SelectObject(self.measuring, self.of(style)) };
        // SAFETY: the text is NUL-terminated and the rectangle a valid place
        // for the size; with `DT_CALCRECT` nothing is drawn.
        unsafe { DrawTextW(self.measuring, units.as_ptr(), -1, &raw mut area, format) };
        // SAFETY: puts back what was selected before.
        unsafe { SelectObject(self.measuring, before) };
        Size {
            width: area.right - area.left,
            height: area.bottom - area.top,
        }
    }
}

impl Measure for Fonts {
    fn text(&self, style: Type, text: &str, width: Option<i32>) -> Size {
        self.sized(style, text, width)
    }
}

/// How GDI sets a run in a box.
fn format(run: &Run<'_>) -> DRAW_TEXT_FORMAT {
    let keys = match run.keys {
        Keys::Shown => 0,
        Keys::Hidden => DT_HIDEPREFIX,
    };
    match run.setting {
        Setting::Wrapped => DT_LEFT | DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX,
        Setting::Centred => DT_CENTER | DT_VCENTER | DT_SINGLELINE | keys,
        Setting::Row => DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | keys,
        Setting::Glyph => DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
        Setting::Line => DT_LEFT | DT_SINGLELINE | DT_NOPREFIX,
    }
}

fn gdi_set(dc: HDC, font: HFONT, ink: Rgb, label: &str, area: &RECT, format: DRAW_TEXT_FORMAT) {
    let text: Vec<u16> = label.encode_utf16().collect();
    let mut place = *area;
    // SAFETY: the font outlives the call.
    let before = unsafe { SelectObject(dc, font) };
    // SAFETY: no pointers.
    unsafe { SetBkMode(dc, TRANSPARENT.cast_signed()) };
    // SAFETY: no pointers.
    unsafe { SetTextColor(dc, colour(ink)) };
    let length = i32::try_from(text.len()).unwrap_or_default();
    // SAFETY: the text is `length` units and the rectangle valid for the call.
    unsafe { DrawTextW(dc, text.as_ptr(), length, &raw mut place, format) };
    // SAFETY: puts back what was selected before.
    unsafe { SelectObject(dc, before) };
}

/// A 32-bit picture Windows draws into, top row first, with a device context
/// selecting it; both let go when this is dropped.
pub(crate) struct Section {
    dc: HDC,
    bitmap: HBITMAP,
    was: HGDIOBJ,
    bits: *mut c_void,
    count: usize,
}

impl Section {
    pub(crate) fn new(width: i32, height: i32) -> Option<Section> {
        let count = usize::try_from(width).ok()? * usize::try_from(height).ok()?;
        let header = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size::<BITMAPINFOHEADER>(),
                biWidth: width,
                // A negative height says the first row is the top one.
                biHeight: -height,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                ..BITMAPINFOHEADER::default()
            },
            ..BITMAPINFO::default()
        };
        // SAFETY: a null context asks for one compatible with the screen.
        let dc = unsafe { CreateCompatibleDC(std::ptr::null_mut()) };
        let mut bits: *mut c_void = std::ptr::null_mut();
        // SAFETY: the header is complete and `bits` a valid place; the
        // section is zeroed by Windows.
        let bitmap = unsafe {
            CreateDIBSection(
                dc,
                &raw const header,
                DIB_RGB_COLORS,
                &raw mut bits,
                std::ptr::null_mut(),
                0,
            )
        };
        if bitmap.is_null() || bits.is_null() {
            // SAFETY: the context is this function's own.
            unsafe { DeleteDC(dc) };
            return None;
        }
        // SAFETY: the bitmap is selected into this value's own context, and
        // deselected before it is let go.
        let was = unsafe { SelectObject(dc, bitmap) };
        Some(Section {
            dc,
            bitmap,
            was,
            bits,
            count,
        })
    }

    pub(crate) fn dc(&mut self) -> HDC {
        self.dc
    }

    /// Its pixels as `0xAARRGGBB`, once whatever drew into it has finished.
    pub(crate) fn pixels(&self) -> &[u32] {
        // SAFETY: the section holds `count` 32-bit pixels for as long as this
        // value lives, and nothing writes them while they are borrowed.
        unsafe { std::slice::from_raw_parts(self.bits.cast::<u32>(), self.count) }
    }
}

impl Drop for Section {
    fn drop(&mut self) {
        // SAFETY: puts back what was selected, then lets go of what is this
        // value's own.
        unsafe { SelectObject(self.dc, self.was) };
        // SAFETY: as above.
        unsafe { DeleteObject(self.bitmap) };
        // SAFETY: as above.
        unsafe { DeleteDC(self.dc) };
    }
}

/// What a painted surface sets its text with: DirectWrite, measured and
/// drawn by the same layouts, and GDI's fonts for the controls Windows draws
/// itself. With no DirectWrite, and under a contrast theme on the card,
/// where Windows draws the answers, GDI measures and draws everything, so
/// what is measured is always what is drawn.
#[derive(Debug)]
pub(crate) struct Setter {
    fonts: Fonts,
    writer: Option<Writer>,
}

impl Setter {
    pub(crate) fn new(dpi: u32, text: TextScale, backing: Backing, directwrite: bool) -> Setter {
        Setter {
            fonts: Fonts::new(dpi, text),
            writer: directwrite
                .then(|| Writer::new(dpi, text, backing))
                .flatten(),
        }
    }

    /// The GDI font a control of Windows' own is given.
    pub(crate) fn font(&self, style: Type) -> HFONT {
        self.fonts.of(style)
    }

    /// What Windows' own controls measure their text with.
    pub(crate) fn gdi(&self) -> &Fonts {
        &self.fonts
    }

    fn font_of(&self, run: &Run<'_>) -> HFONT {
        run.style
            .map_or(self.fonts.icons, |style| self.fonts.of(style))
    }

    /// Sets a run with the brush `ink` in `area`, over a face of `beneath`
    /// already drawn there.
    pub(crate) fn set(&self, dc: HDC, area: &RECT, run: &Run<'_>, ink: Tint, beneath: Rgb) {
        let written = self
            .writer
            .as_ref()
            .is_some_and(|writer| writer.set(dc, area, run, ink));
        if !written {
            let solid = beneath.under(ink);
            gdi_set(dc, self.font_of(run), solid, run.label, area, format(run));
        }
    }

    /// How much of each pixel of a `width` by `height` box a run covers, row
    /// by row.
    pub(crate) fn coverage(&self, run: &Run<'_>, width: i32, height: i32) -> Vec<u8> {
        if let Some(writer) = &self.writer {
            let cover = writer.coverage(run, width, height);
            if !cover.is_empty() {
                return cover;
            }
        }
        let font = self.font_of(run);
        let Some(mut section) = Section::new(width, height) else {
            return Vec::new();
        };
        // GDI draws the text white on black in greys, so a pixel's grey is
        // its cover.
        let area = RECT {
            left: 0,
            top: 0,
            right: width,
            bottom: height,
        };
        gdi_set(
            section.dc(),
            font,
            Rgb::WHITE,
            run.label,
            &area,
            format(run),
        );
        section
            .pixels()
            .iter()
            .map(|pixel| u8::try_from((pixel >> 8) & 0xff).unwrap_or_default())
            .collect()
    }
}

impl Measure for Setter {
    fn text(&self, style: Type, text: &str, width: Option<i32>) -> Size {
        match &self.writer {
            Some(writer) => writer.text(style, text, width),
            None => self.fonts.text(style, text, width),
        }
    }
}

/// Puts a control's picture on `dc` with its top left at the given place.
pub(crate) fn blit(dc: HDC, left: i32, top: i32, picture: &Picture) {
    let (Ok(width), Ok(height)) = (i32::try_from(picture.width), i32::try_from(picture.height))
    else {
        return;
    };
    let header = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size::<BITMAPINFOHEADER>(),
            biWidth: width,
            // A negative height says the first row is the top one.
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..BITMAPINFOHEADER::default()
        },
        ..BITMAPINFO::default()
    };
    // SAFETY: the header describes exactly the pixels given, which are
    // `width * height` 32-bit values and outlive the call.
    unsafe {
        SetDIBitsToDevice(
            dc,
            left,
            top,
            width.cast_unsigned(),
            height.cast_unsigned(),
            0,
            0,
            0,
            height.cast_unsigned(),
            picture.pixels.as_ptr().cast::<c_void>(),
            &raw const header,
            DIB_RGB_COLORS,
        )
    };
}

/// Puts rows of `0xAARRGGBB` pixels with their alpha on `dc`, with their
/// top left at the given place: a surface over a system backdrop keeps the
/// alpha, so the backdrop shows through where it is clear.
pub(crate) fn blit_alpha(dc: HDC, left: i32, top: i32, width: usize, pixels: &[u32]) {
    blit(
        dc,
        left,
        top,
        &Picture {
            width,
            height: pixels.len().checked_div(width).unwrap_or_default(),
            pixels: pixels.to_vec(),
        },
    );
}

#[cfg(test)]
mod tests {
    use hedwig_view::arrange::Measure;
    use hedwig_view::style::{TextScale, Type};

    use super::Fonts;

    /// GDI, which sets the painted surfaces' text under a contrast theme,
    /// breaks a wrapped line only between words, cutting a word only where it
    /// is wider than the line: within a width a remote path fits on by itself,
    /// the line goes to the next before the path, given as it is; and GDI
    /// draws a word joiner as a glyph of its own, so no text the shell can
    /// hand GDI carries one.
    #[test]
    fn gdi_breaks_a_line_only_between_words_and_draws_a_joiner() {
        let fonts = Fonts::new(120, TextScale::DEFAULT);
        let line = fonts.text(Type::Body, "x", None).height;
        let word = "/home/hedwig-e1/.bashrc";
        let whole = format!("BROWSER in {word}");
        let alone = fonts.text(Type::Body, word, None).width;
        let set = fonts.text(Type::Body, &whole, Some(alone + 2));
        assert_eq!(set.height, 2 * line, "{set:?}");
        assert!(set.width >= alone, "the path whole on its line: {set:?}");
        let cut = fonts.text(Type::Body, &whole, Some(alone / 2));
        assert!(cut.width <= alone / 2, "{cut:?}");
        assert!(
            fonts
                .text(Type::Body, "step-\u{2060}h@example.invalid", None)
                .width
                > fonts.text(Type::Body, "step-h@example.invalid", None).width
        );
    }
}
