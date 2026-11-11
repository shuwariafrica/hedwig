//! Text as Windows 11 sets it: DirectWrite, drawn through Direct2D's software
//! renderer.
//!
//! Neither library is imported by the executable. Both are loaded from the
//! system folder, and nowhere else, the first time a painted surface is made,
//! and stay loaded; what a surface draws with - the factories, its formats
//! and its render target - is made with the surface and let go with it.
//! `windows-sys` carries neither library, so each method is called by its
//! place in its interface's table, in the Windows SDK's order (`um/d2d1.h`,
//! `um/dwrite.h`, `um/dwrite_3.h`, whose overloads take their places from
//! Microsoft's own metadata).
//!
//! The type ramp's text is Segoe UI Variable as one typographic family, its
//! weight an axis and its optical size set from the size of the text, as WinUI
//! sets its own: a named face of the family is one optical size for every
//! size.

use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::HDC;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::GUID;

use hedwig_view::arrange::{Measure, Size};
use hedwig_view::style::{Rgb, TextScale, Tint, Type};

use crate::com::{Com, Object};
use crate::raw::wide;

type Hresult = i32;
type Found = unsafe extern "system" fn() -> isize;
type CreateDirect2d =
    unsafe extern "system" fn(i32, *const GUID, *const c_void, *mut Object) -> Hresult;
type CreateWrite = unsafe extern "system" fn(i32, *const GUID, *mut Object) -> Hresult;

const IID_ID2D1_FACTORY: GUID = GUID::from_u128(0x0615_2247_6f50_465a_9245_118b_fd3b_6007);
const IID_IDWRITE_FACTORY: GUID = GUID::from_u128(0xb859_ee5a_d838_4b5b_a2e8_1adc_7d93_db48);
const IID_ID2D1_FACTORY_1: GUID = GUID::from_u128(0xbb12_d362_daee_4b9a_aa1d_14ba_401c_fa1f);
const IID_IDWRITE_FACTORY_6: GUID = GUID::from_u128(0xf374_4d80_21f7_42eb_b35d_995b_c72f_c223);

/// Windows 11's text face, as one typographic family.
const VARIABLE: &str = "Segoe UI Variable";
/// The weight axis's tag, `wght`, as `DWRITE_MAKE_OPENTYPE_TAG` makes it.
const WEIGHT: u32 = u32::from_le_bytes(*b"wght");

/// `DWRITE_FONT_AXIS_VALUE`.
#[repr(C)]
struct Axis {
    tag: u32,
    value: f32,
}

/// A Direct2D factory for this thread that makes devices over Direct3D: what
/// a composed surface's picture is drawn through.
pub(crate) fn device_factory() -> Option<Com> {
    let library = library()?;
    let mut factory: Object = std::ptr::null_mut();
    // SAFETY: the identifier is the interface's own and the place valid.
    let result =
        unsafe { (library.direct2d)(0, &IID_ID2D1_FACTORY_1, std::ptr::null(), &raw mut factory) };
    made(result, factory)
}

/// The face of Windows 11's icons, whose glyphs a menu's chevron is one of.
const ICONS: &str = "Segoe Fluent Icons";

#[repr(C)]
struct PixelFormat {
    format: u32,
    alpha: u32,
}

#[repr(C)]
struct RenderTargetProperties {
    kind: u32,
    pixel: PixelFormat,
    dpi_x: f32,
    dpi_y: f32,
    usage: u32,
    level: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Colour {
    red: f32,
    green: f32,
    blue: f32,
    alpha: f32,
}

/// `D2D1_POINT_2F`, passed by value: a structure, so each platform's calling
/// convention places it as the SDK's does.
#[repr(C)]
struct Point {
    x: f32,
    y: f32,
}

/// `DWRITE_TEXT_RANGE`, passed by value.
#[repr(C)]
struct Range {
    start: u32,
    length: u32,
}

#[repr(C)]
struct Trimming {
    granularity: u32,
    delimiter: u32,
    count: u32,
}

#[repr(C)]
#[derive(Default)]
struct TextMetrics {
    left: f32,
    top: f32,
    width: f32,
    trailing: f32,
    height: f32,
    layout_width: f32,
    layout_height: f32,
    depth: u32,
    lines: u32,
}

/// The two factories' entry points, found once per process.
struct Library {
    direct2d: CreateDirect2d,
    write: CreateWrite,
}

/// An entry point of a library in the system folder. A library named by a
/// bare name is looked for only there, so none planted beside the executable
/// or on the search path is taken.
fn entry(library: &str, name: &[u8]) -> Option<Found> {
    let library = wide(library);
    // SAFETY: the name is NUL-terminated; the flag limits the search to the
    // system folder; a module that is loaded stays loaded for the process.
    let module = unsafe {
        LoadLibraryExW(
            library.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return None;
    }
    // SAFETY: the module was just loaded and the name is NUL-terminated.
    unsafe { GetProcAddress(module, name.as_ptr()) }
}

fn library() -> Option<&'static Library> {
    static LOADED: OnceLock<Option<Library>> = OnceLock::new();
    LOADED
        .get_or_init(|| {
            let direct2d = entry("d2d1.dll", b"D2D1CreateFactory\0")?;
            let write = entry("dwrite.dll", b"DWriteCreateFactory\0")?;
            Some(Library {
                // SAFETY: `D2D1CreateFactory` has this signature (`um/d2d1.h`).
                direct2d: unsafe { std::mem::transmute::<Found, CreateDirect2d>(direct2d) },
                // SAFETY: `DWriteCreateFactory` has this signature
                // (`um/dwrite.h`).
                write: unsafe { std::mem::transmute::<Found, CreateWrite>(write) },
            })
        })
        .as_ref()
}

fn made(result: Hresult, object: Object) -> Option<Com> {
    if result < 0 { None } else { Com::new(object) }
}

/// What a surface's text is drawn onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backing {
    /// A control's own device context, its face already drawn: the text is
    /// set in its ink over it.
    Opaque,
    /// A picture with an alpha channel, whose backdrop only the compositor
    /// knows: what is wanted of the text is how much of each pixel it covers.
    Clear,
}

/// Where a run of text stands in its box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Setting {
    /// From the top left, wrapped within the box's width; a word longer than
    /// the line is broken.
    Wrapped,
    /// On one line in the middle of the box: a button's label.
    Centred,
    /// On one line from the left, in the middle of the box's height, what
    /// does not fit ending in an ellipsis: a menu's row.
    Row,
    /// Against the right of the box, in the middle of its height: a glyph,
    /// as WinUI sets one in a column as wide as it is.
    Glyph,
    /// On one line from the top left, nothing trimmed: a line measured for
    /// its width.
    Line,
}

/// Whether the access key a `&` marks in a label is underlined: once a key
/// has been used, or always where the person has Windows show them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keys {
    Shown,
    Hidden,
}

/// A run of text as a surface asks for it: in which style - `None` is the
/// icons' face - with which words, set how.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Run<'a> {
    pub(crate) style: Option<Type>,
    pub(crate) label: &'a str,
    pub(crate) setting: Setting,
    pub(crate) keys: Keys,
}

/// A label's text with its access key taken out: the key's place, and
/// whether a doubled `&` stood for itself.
fn keyed(label: &str) -> (Vec<u16>, Option<u32>) {
    let mut units = Vec::with_capacity(label.len());
    let mut key = None;
    let mut characters = label.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '&' {
            match characters.next() {
                Some('&') => units.push(u16::from(b'&')),
                Some(next) => {
                    if key.is_none() {
                        key = u32::try_from(units.len()).ok();
                    }
                    let mut buffer = [0u16; 2];
                    units.extend_from_slice(next.encode_utf16(&mut buffer));
                }
                None => {}
            }
        } else {
            let mut buffer = [0u16; 2];
            units.extend_from_slice(character.encode_utf16(&mut buffer));
        }
    }
    (units, key)
}

fn float(value: i32) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

fn whole(value: f32) -> i32 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a length on a screen, rounded up, is within an i32"
    )]
    let whole = value.ceil() as i32;
    whole
}

/// Segoe UI Variable as one typographic family: `IDWriteFactory6` and the
/// system's fonts under the typographic family model.
struct Typographic {
    factory: Com,
    collection: Com,
}

impl Typographic {
    fn new(write: &Com) -> Option<Typographic> {
        let factory = write.query(&IID_IDWRITE_FACTORY_6).ok()?;
        let mut collection: Object = std::ptr::null_mut();
        // SAFETY: `IDWriteFactory6::GetSystemFontCollection`, entry 51.
        let system: unsafe extern "system" fn(Object, i32, u32, *mut Object) -> Hresult =
            unsafe { factory.slot(51) };
        // SAFETY: no downloadable font; the typographic family model is 0;
        // the place is valid.
        let result = unsafe { system(factory.object(), 0, 0, &raw mut collection) };
        let collection = made(result, collection)?;
        Some(Typographic {
            factory,
            collection,
        })
    }

    /// A format of the family at `weight` and `size`, its optical size set
    /// from the size.
    fn format(&self, weight: u16, size: f32) -> Option<Com> {
        let family = wide(VARIABLE);
        let locale = wide("");
        let axes = [Axis {
            tag: WEIGHT,
            value: f32::from(weight),
        }];
        let mut format: Object = std::ptr::null_mut();
        // SAFETY: `IDWriteFactory6::CreateTextFormat`, entry 54.
        let create: unsafe extern "system" fn(
            Object,
            *const u16,
            Object,
            *const Axis,
            u32,
            f32,
            *const u16,
            *mut Object,
        ) -> Hresult = unsafe { self.factory.slot(54) };
        // SAFETY: both strings are NUL-terminated and the axes one value,
        // each copied by the call; the collection is live.
        let result = unsafe {
            create(
                self.factory.object(),
                family.as_ptr(),
                self.collection.object(),
                axes.as_ptr(),
                1,
                size,
                locale.as_ptr(),
                &raw mut format,
            )
        };
        let format = made(result, format)?;
        // SAFETY: `IDWriteTextFormat3::SetAutomaticFontAxes`, entry 42.
        let automatic: unsafe extern "system" fn(Object, u32) -> Hresult =
            unsafe { format.slot(42) };
        // SAFETY: the format is live; 1 is the optical size axis.
        (unsafe { automatic(format.object(), 1) } >= 0).then_some(format)
    }
}

/// The text of one painted surface: its factories, a format for each style
/// of Windows 11's type ramp at the monitor's scale and the person's text
/// size, and the render target it draws through.
pub(crate) struct Writer {
    dpi: u32,
    /// Effective pixels to pixels.
    scale: f32,
    backing: Backing,
    // Declared before what made them, so they are let go first.
    target: Com,
    caption: Com,
    body: Com,
    subtitle: Com,
    glyphs: Com,
    write: Com,
    _direct2d: Com,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer")
            .field("dpi", &self.dpi)
            .field("backing", &self.backing)
            .finish_non_exhaustive()
    }
}

impl Writer {
    /// The text of a surface on a monitor of `dpi`; `None` where Windows
    /// cannot give DirectWrite or Direct2D, which the surface then measures
    /// and draws without.
    pub(crate) fn new(dpi: u32, text: TextScale, backing: Backing) -> Option<Writer> {
        let library = library()?;
        let mut direct2d: Object = std::ptr::null_mut();
        // SAFETY: the identifier is the interface's own and the place valid;
        // a factory for one thread, the one that owns the surface.
        let result = unsafe {
            (library.direct2d)(0, &IID_ID2D1_FACTORY, std::ptr::null(), &raw mut direct2d)
        };
        let direct2d = made(result, direct2d)?;
        let mut write: Object = std::ptr::null_mut();
        // SAFETY: as above; the shared factory, whose font cache every
        // process of the session uses.
        let result = unsafe { (library.write)(0, &IID_IDWRITE_FACTORY, &raw mut write) };
        let write = made(result, write)?;
        let format = |face: &str, weight: u16, size: f32| -> Option<Com> {
            let face = wide(face);
            let locale = wide("");
            let mut format: Object = std::ptr::null_mut();
            // SAFETY: `IDWriteFactory::CreateTextFormat`, entry 15.
            let create: unsafe extern "system" fn(
                Object,
                *const u16,
                Object,
                u32,
                u32,
                u32,
                f32,
                *const u16,
                *mut Object,
            ) -> Hresult = unsafe { write.slot(15) };
            // SAFETY: both strings are NUL-terminated and copied by the call;
            // a null collection is the system's; style normal is 0 and
            // stretch normal 5; the locale is the user's default.
            let result = unsafe {
                create(
                    write.object(),
                    face.as_ptr(),
                    std::ptr::null_mut(),
                    u32::from(weight),
                    0,
                    5,
                    size,
                    locale.as_ptr(),
                    &raw mut format,
                )
            };
            made(result, format)
        };
        let typographic = Typographic::new(&write)?;
        let style = |style: Type| typographic.format(style.weight(), text.size(style.size()));
        let (caption, body, subtitle) = (
            style(Type::Caption)?,
            style(Type::Body)?,
            style(Type::Subtitle)?,
        );
        let glyphs = format(ICONS, 400, 12.0)?;
        let dpi_float = float(i32::try_from(dpi).unwrap_or(96));
        let properties = RenderTargetProperties {
            // Direct2D's software renderer: the hardware one holds 26 MB
            // more for the same text.
            kind: 1,
            pixel: PixelFormat {
                // B8G8R8A8, what a 32-bit device-independent bitmap and a
                // device context take; premultiplied alpha where the
                // coverage is wanted, ignored where the face is opaque.
                format: 87,
                alpha: match backing {
                    Backing::Opaque => 3,
                    Backing::Clear => 1,
                },
            },
            dpi_x: dpi_float,
            dpi_y: dpi_float,
            usage: 0,
            level: 0,
        };
        let mut target: Object = std::ptr::null_mut();
        // SAFETY: `ID2D1Factory::CreateDCRenderTarget`, entry 16.
        let create: unsafe extern "system" fn(
            Object,
            *const RenderTargetProperties,
            *mut Object,
        ) -> Hresult = unsafe { direct2d.slot(16) };
        // SAFETY: the properties and the place are valid for the call.
        let result = unsafe { create(direct2d.object(), &raw const properties, &raw mut target) };
        let target = made(result, target)?;
        // SAFETY: `ID2D1RenderTarget::SetTextAntialiasMode`, entry 34.
        let antialias: unsafe extern "system" fn(Object, u32) = unsafe { target.slot(34) };
        // SAFETY: the target is live. Greys, as WinUI draws text, and as
        // text over a backdrop with an alpha channel has to be.
        unsafe { antialias(target.object(), 2) };
        Some(Writer {
            dpi,
            scale: dpi_float / 96.0,
            backing,
            target,
            caption,
            body,
            subtitle,
            glyphs,
            write,
            _direct2d: direct2d,
        })
    }

    fn format(&self, style: Option<Type>) -> &Com {
        match style {
            Some(Type::Caption) => &self.caption,
            Some(Type::Body) => &self.body,
            Some(Type::Subtitle) => &self.subtitle,
            None => &self.glyphs,
        }
    }

    /// A layout of `text` in `style`, or in the icons' face with `None`,
    /// within `width` by `height` effective pixels.
    fn layout(
        &self,
        style: Option<Type>,
        text: &[u16],
        width: f32,
        height: f32,
        setting: Setting,
    ) -> Option<Com> {
        let mut layout: Object = std::ptr::null_mut();
        // SAFETY: `IDWriteFactory::CreateTextLayout`, entry 18.
        let create: unsafe extern "system" fn(
            Object,
            *const u16,
            u32,
            Object,
            f32,
            f32,
            *mut Object,
        ) -> Hresult = unsafe { self.write.slot(18) };
        // SAFETY: the text is `len` units, read during the call; the format
        // is live.
        let result = unsafe {
            create(
                self.write.object(),
                text.as_ptr(),
                u32::try_from(text.len()).unwrap_or_default(),
                self.format(style).object(),
                width.max(0.0),
                height.max(0.0),
                &raw mut layout,
            )
        };
        let layout = made(result, layout)?;
        // `IDWriteTextFormat`'s setters, which a layout inherits: text
        // alignment 3, paragraph alignment 4, word wrapping 5, trimming 9.
        let (align, middle, wrap) = match setting {
            // Leading, top, and breaking a word too long for the line.
            Setting::Wrapped => (0, 0, 2),
            // Centred across and down, on one line.
            Setting::Centred => (2, 2, 1),
            Setting::Row => (0, 2, 1),
            // Trailing, down the middle.
            Setting::Glyph => (1, 2, 1),
            Setting::Line => (0, 0, 1),
        };
        for (entry, value) in [(3, align), (4, middle), (5, wrap)] {
            // SAFETY: entries 3 to 5 each take one enumeration by value.
            let set: unsafe extern "system" fn(Object, u32) -> Hresult =
                unsafe { layout.slot(entry) };
            // SAFETY: the layout is live; each value is one its enumeration
            // has.
            unsafe { set(layout.object(), value) };
        }
        if setting == Setting::Row {
            self.trim(&layout, style);
        }
        Some(layout)
    }

    /// Ends what does not fit on a row in an ellipsis, as WinUI trims a menu
    /// item's text.
    fn trim(&self, layout: &Com, style: Option<Type>) {
        let mut sign: Object = std::ptr::null_mut();
        // SAFETY: `IDWriteFactory::CreateEllipsisTrimmingSign`, entry 20.
        let create: unsafe extern "system" fn(Object, Object, *mut Object) -> Hresult =
            unsafe { self.write.slot(20) };
        // SAFETY: the format is live and the place valid.
        let result = unsafe {
            create(
                self.write.object(),
                self.format(style).object(),
                &raw mut sign,
            )
        };
        let Some(sign) = made(result, sign) else {
            return;
        };
        let trimming = Trimming {
            // By character, as the ellipsis is placed after the last whole
            // character that fits.
            granularity: 1,
            delimiter: 0,
            count: 0,
        };
        // SAFETY: `IDWriteTextFormat::SetTrimming`, entry 9.
        let set: unsafe extern "system" fn(Object, *const Trimming, Object) -> Hresult =
            unsafe { layout.slot(9) };
        // SAFETY: the structure outlives the call; the layout holds its own
        // reference to the sign.
        unsafe { set(layout.object(), &raw const trimming, sign.object()) };
    }

    fn underline(layout: &Com, key: u32) {
        // SAFETY: `IDWriteTextLayout::SetUnderline`, entry 36, taking a
        // `BOOL` and a range by value.
        let set: unsafe extern "system" fn(Object, i32, Range) -> Hresult =
            unsafe { layout.slot(36) };
        // SAFETY: the layout is live; a range past the text changes nothing.
        unsafe {
            set(
                layout.object(),
                1,
                Range {
                    start: key,
                    length: 1,
                },
            )
        };
    }

    fn metrics(layout: &Com) -> TextMetrics {
        let mut metrics = TextMetrics::default();
        // SAFETY: `IDWriteTextLayout::GetMetrics`, entry 60.
        let measure: unsafe extern "system" fn(Object, *mut TextMetrics) -> Hresult =
            unsafe { layout.slot(60) };
        // SAFETY: the layout is live and the place valid.
        unsafe { measure(layout.object(), &raw mut metrics) };
        metrics
    }

    /// Draws `layout` with `ink` at `origin` on the device context bound to
    /// `area`, with `before` drawn first.
    fn draw(
        &self,
        dc: HDC,
        area: &RECT,
        layout: &Com,
        ink: Colour,
        before: Option<Colour>,
    ) -> bool {
        // SAFETY: `ID2D1DCRenderTarget::BindDC`, entry 57.
        let bind: unsafe extern "system" fn(Object, HDC, *const RECT) -> Hresult =
            unsafe { self.target.slot(57) };
        // SAFETY: the context is the caller's, alive for the call, and the
        // rectangle valid.
        if unsafe { bind(self.target.object(), dc, area) } < 0 {
            return false;
        }
        // SAFETY: `ID2D1RenderTarget::BeginDraw`, entry 48.
        let begin: unsafe extern "system" fn(Object) = unsafe { self.target.slot(48) };
        // SAFETY: the target is live and bound.
        unsafe { begin(self.target.object()) };
        if let Some(clear) = before {
            // SAFETY: `ID2D1RenderTarget::Clear`, entry 47.
            let fill: unsafe extern "system" fn(Object, *const Colour) =
                unsafe { self.target.slot(47) };
            // SAFETY: the colour outlives the call; the target is drawing.
            unsafe { fill(self.target.object(), &raw const clear) };
        }
        let mut brush: Object = std::ptr::null_mut();
        // SAFETY: `ID2D1RenderTarget::CreateSolidColorBrush`, entry 8.
        let solid: unsafe extern "system" fn(
            Object,
            *const Colour,
            *const c_void,
            *mut Object,
        ) -> Hresult = unsafe { self.target.slot(8) };
        // SAFETY: the colour and the place are valid; no properties.
        let result = unsafe {
            solid(
                self.target.object(),
                &raw const ink,
                std::ptr::null(),
                &raw mut brush,
            )
        };
        if let Some(brush) = made(result, brush) {
            // SAFETY: `ID2D1RenderTarget::DrawTextLayout`, entry 28: the
            // origin by value, in effective pixels at the target's scale.
            let text: unsafe extern "system" fn(Object, Point, Object, Object, u32) =
                unsafe { self.target.slot(28) };
            // SAFETY: the layout and the brush are live; no options.
            unsafe {
                text(
                    self.target.object(),
                    Point { x: 0.0, y: 0.0 },
                    layout.object(),
                    brush.object(),
                    0,
                );
            }
        }
        // SAFETY: `ID2D1RenderTarget::EndDraw`, entry 49; no tags wanted.
        let end: unsafe extern "system" fn(Object, *mut u64, *mut u64) -> Hresult =
            unsafe { self.target.slot(49) };
        // SAFETY: the target is drawing.
        unsafe {
            end(
                self.target.object(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) >= 0
        }
    }

    fn effective(&self, pixels: i32) -> f32 {
        float(pixels) / self.scale
    }

    /// The layout of a run in a `width` by `height` box, its access key
    /// underlined where the run says.
    fn laid(&self, run: &Run<'_>, width: i32, height: i32) -> Option<Com> {
        let unbroken;
        let label = if run.setting == Setting::Wrapped {
            unbroken = hedwig_view::words::unbroken(run.label);
            &unbroken
        } else {
            run.label
        };
        let (text, key) = keyed(label);
        let layout = self.layout(
            run.style,
            &text,
            self.effective(width),
            self.effective(height),
            run.setting,
        )?;
        if let (Keys::Shown, Some(key)) = (run.keys, key) {
            Writer::underline(&layout, key);
        }
        Some(layout)
    }

    /// Sets a run with the brush `ink` in `area` of a control's device
    /// context, its face already drawn there, as WinUI lays a brush with an
    /// alpha over what is beneath. Whether it was drawn.
    pub(crate) fn set(&self, dc: HDC, area: &RECT, run: &Run<'_>, ink: Tint) -> bool {
        let (width, height) = (area.right - area.left, area.bottom - area.top);
        let brush = colour(ink.colour, f32::from(ink.alpha) / 255.0);
        self.laid(run, width, height)
            .is_some_and(|layout| self.draw(dc, area, &layout, brush, None))
    }

    /// How much of each pixel of a `width` by `height` box a run covers, row
    /// by row: what a surface with an alpha channel lays its text over its
    /// backdrop with.
    pub(crate) fn coverage(&self, run: &Run<'_>, width: i32, height: i32) -> Vec<u8> {
        let (Ok(columns), Ok(rows)) = (usize::try_from(width), usize::try_from(height)) else {
            return Vec::new();
        };
        if columns == 0 || rows == 0 || self.backing != Backing::Clear {
            return Vec::new();
        }
        let Some(layout) = self.laid(run, width, height) else {
            return Vec::new();
        };
        let Some(mut section) = crate::draw::Section::new(width, height) else {
            return Vec::new();
        };
        let area = RECT {
            left: 0,
            top: 0,
            right: width,
            bottom: height,
        };
        let clear = colour(Rgb::WHITE, 0.0);
        if !self.draw(
            section.dc(),
            &area,
            &layout,
            colour(Rgb::WHITE, 1.0),
            Some(clear),
        ) {
            return Vec::new();
        }
        // Premultiplied white: each pixel's alpha is how much the text
        // covers it.
        section
            .pixels()
            .iter()
            .map(|pixel| u8::try_from(pixel >> 24).unwrap_or_default())
            .collect()
    }
}

fn colour(rgb: Rgb, alpha: f32) -> Colour {
    Colour {
        red: f32::from(rgb.red) / 255.0,
        green: f32::from(rgb.green) / 255.0,
        blue: f32::from(rgb.blue) / 255.0,
        alpha,
    }
}

impl Measure for Writer {
    fn text(&self, style: Type, text: &str, width: Option<i32>) -> Size {
        // Unbounded, a line is as wide as its text.
        let unbounded = f32::MAX / 4.0;
        let (most, setting, units): (f32, Setting, Vec<u16>) = match width {
            Some(width) => (
                self.effective(width),
                Setting::Wrapped,
                hedwig_view::words::unbroken(text).encode_utf16().collect(),
            ),
            None => (unbounded, Setting::Line, text.encode_utf16().collect()),
        };
        let Some(layout) = self.layout(Some(style), &units, most, unbounded, setting) else {
            return Size::default();
        };
        let metrics = Writer::metrics(&layout);
        Size {
            width: whole(metrics.width * self.scale),
            height: whole(metrics.height * self.scale),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use hedwig_view::arrange::Measure as _;
    use hedwig_view::style::{TextScale, Type};

    use super::{Backing, Keys, Run, Setting, Writer, keyed};

    const KEY: &str = "0E5D4B6E1A2C3F405162738495A6B7C8D9E0F1A2";

    fn on(backing: Backing) -> Writer {
        Writer::new(120, TextScale::DEFAULT, backing).expect("DirectWrite at this desktop")
    }

    /// The card is measured by the layouts it is drawn with, and they are
    /// DirectWrite's, Segoe UI Variable's optical size set from each size: at
    /// 120 dpi the heading is set at optical size 15 (443.5 pixels, where
    /// the Display face's 36 sets 440.7), a caption at 9 (170.7, where the
    /// Small face's 8 sets 173.2), body text at 10.5, the Text face's own
    /// (380.7, 562.4); each rounded up to whole pixels. Drawn so, every
    /// line's ink is as wide as WinUI's dialog sets it.
    #[test]
    fn a_line_is_as_wide_as_directwrite_sets_it() {
        let writer = on(Backing::Opaque);
        let cases = [
            (
                Type::Subtitle,
                "dev/build (coder) asks to sign with gpg",
                444,
            ),
            (Type::Body, KEY, 381),
            (Type::Caption, "You are asked because of", 171),
            (
                Type::Body,
                "For that time, every request to sign with gpg on this connection is served",
                563,
            ),
        ];
        for (style, text, width) in cases {
            assert_eq!(writer.text(style, text, None).width, width, "{text}");
        }
        // One line of body text is DirectWrite's line: 18.62 effective pixels.
        assert_eq!(writer.text(Type::Body, KEY, None).height, 24);
    }

    /// A fingerprint has no space to break at: wrapped within a width it
    /// does not fit, it is broken, never cut or overflowing.
    #[test]
    fn a_word_longer_than_the_line_is_broken() {
        let writer = on(Backing::Opaque);
        let whole = writer.text(Type::Body, KEY, None);
        let wrapped = writer.text(Type::Body, KEY, Some(150));
        assert!(wrapped.width <= 150, "{wrapped:?}");
        // 381 pixels in lines of 150: three lines, each 23.3 pixels.
        assert!(wrapped.height > 2 * whole.height, "{wrapped:?}");
    }

    /// A card's key with its user ID: within a width that holds the
    /// fingerprint and
    /// `(Step H <step-`, DirectWrite breaks after the hyphen inside the
    /// address; joined (`hedwig_view::words::whole`), the line breaks before
    /// `<` and the address is whole on the next. On one line the two are the
    /// same width.
    #[test]
    fn a_user_ids_address_is_kept_whole_on_its_line() {
        let writer = on(Backing::Opaque);
        let fingerprint = "key E7B0E44C4F39F21C212E4BA82FAD7376FA102CE9";
        let user = "Step H <step-h@example.invalid>";
        let fact = format!("{fingerprint} ({user})");
        let width = writer
            .text(Type::Body, &format!("{fingerprint} (Step H <step-"), None)
            .width
            + 2;
        let line = writer.text(Type::Body, "x", None).height;
        let given = writer
            .layout(
                Some(Type::Body),
                &fact.encode_utf16().collect::<Vec<u16>>(),
                writer.effective(width),
                f32::MAX / 4.0,
                Setting::Wrapped,
            )
            .map(|layout| Writer::metrics(&layout).width * writer.scale);
        let set = writer.text(Type::Body, &fact, Some(width));
        let before = writer
            .text(Type::Body, &format!("{fingerprint} (Step H"), None)
            .width;
        assert!(
            given.is_some_and(|given| f64::from(given) > f64::from(before) + 1.0),
            "as given, broken inside the address: {given:?}"
        );
        assert_eq!(set.width, before, "the first line ends before <: {set:?}");
        assert!(set.height < 3 * line, "{set:?}");
    }

    /// A wrapped line breaks between words and nowhere inside one, with
    /// DirectWrite itself. Step J's line (`j-menu.png`) broke as "BROWSER in
    /// /home/" and "hedwig-e1/.bashrc": a line may not break before a slash
    /// even after a space (UAX #14, LB13), so a path is cut wherever it is
    /// given. Set, within a width each word fits on by itself, the path, a
    /// fingerprint and an address with a query each go whole to the next
    /// line; on one line nothing changes; a word wider than its line is still
    /// broken where it must be.
    #[test]
    fn a_wrapped_line_breaks_between_words_and_never_inside_one() {
        let writer = on(Backing::Opaque);
        let line = writer.text(Type::Body, "x", None).height;
        let given = |text: &str, width: i32| {
            writer
                .layout(
                    Some(Type::Body),
                    &text.encode_utf16().collect::<Vec<u16>>(),
                    writer.effective(width),
                    f32::MAX / 4.0,
                    Setting::Wrapped,
                )
                .map(|layout| Writer::metrics(&layout).width * writer.scale)
        };
        let path = "/home/hedwig-e1/.bashrc";
        let whole = format!("BROWSER in {path}");
        let alone = writer.text(Type::Body, path, None).width;
        assert!(
            given(&whole, alone + 2).is_some_and(|given| f64::from(given) + 1.0 < f64::from(alone)),
            "as given, the path is cut"
        );
        for (before, word) in [
            ("BROWSER in", path),
            (
                "logged in with ED25519 key",
                "SHA256:QCQxMQ7xhfkHmiFYutwBkf8hKrX/lRA6l2MniD/TvBE",
            ),
            (
                "Its tools open it at",
                "rfc2217://127.0.0.1:4000?timeout=30",
            ),
        ] {
            let whole = format!("{before} {word}");
            let alone = writer.text(Type::Body, word, None).width;
            let width = alone.max(writer.text(Type::Body, before, None).width) + 2;
            let set = writer.text(Type::Body, &whole, Some(width));
            assert_eq!(set.width, alone, "{whole}: the word whole on its line");
            assert!(set.height < 2 * line + 1, "{whole}: {set:?}");
            assert!(set.height > line, "{whole}: {set:?}");
            assert_eq!(
                writer.text(Type::Body, &whole, Some(10_000)).width,
                writer.text(Type::Body, &whole, None).width,
                "{whole}: on one line it is as it was"
            );
            // A word wider than the line is broken where it must be.
            let narrow = writer.text(Type::Body, word, Some(width / 2));
            assert!(narrow.width <= width / 2 + 1, "{word}: {narrow:?}");
            assert!(narrow.height > line, "{word}: {narrow:?}");
        }
    }

    /// Over a backdrop only the compositor knows, a row's text is how much of
    /// each pixel it covers; the access key's underline is part of it only
    /// while keys are shown.
    #[test]
    fn a_rows_text_is_its_coverage_and_its_key_is_underlined_when_shown() {
        let writer = on(Backing::Clear);
        let (width, height) = (300, 40);
        let run = |keys| Run {
            style: Some(Type::Body),
            label: "&Pause all exposure",
            setting: Setting::Row,
            keys,
        };
        let hidden = writer.coverage(&run(Keys::Hidden), width, height);
        let shown = writer.coverage(&run(Keys::Shown), width, height);
        assert_eq!(hidden.len(), 300 * 40);
        let ink = |cover: &[u8]| cover.iter().map(|alpha| u32::from(*alpha)).sum::<u32>();
        assert!(ink(&hidden) > 0);
        assert!(ink(&shown) > ink(&hidden), "the underline adds ink");
        // Set down the middle of the row: nothing in its top and bottom rows.
        let row = |at: usize| hidden.get(at * 300..(at + 1) * 300).unwrap().to_vec();
        assert!(row(0).iter().all(|alpha| *alpha == 0));
        assert!(row(39).iter().all(|alpha| *alpha == 0));
        // An opaque writer gives no coverage: it draws on a control's face.
        assert_eq!(
            on(Backing::Opaque).coverage(&run(Keys::Hidden), width, height),
            Vec::<u8>::new()
        );
    }

    /// A row too long for the menu ends in an ellipsis inside its box.
    #[test]
    fn a_row_too_long_ends_within_its_box() {
        let writer = on(Backing::Clear);
        let run = Run {
            style: Some(Type::Body),
            label: "Hedwig was started outside this desktop, in session 3, and is still running",
            setting: Setting::Row,
            keys: Keys::Hidden,
        };
        let cover = writer.coverage(&run, 120, 30);
        let last = cover
            .chunks(120)
            .map(|row| row.last().copied().unwrap_or_default());
        assert!(
            last.into_iter().all(|alpha| alpha == 0),
            "nothing reaches the edge"
        );
    }

    #[test]
    fn an_access_key_is_the_letter_after_its_marker() {
        let units = |text: &str| text.encode_utf16().collect::<Vec<u16>>();
        assert_eq!(keyed("&Allow once"), (units("Allow once"), Some(0)));
        assert_eq!(
            keyed("All&ow for 15 minutes"),
            (units("Allow for 15 minutes"), Some(3))
        );
        // A doubled marker is the character itself, as a key's mark can hold.
        assert_eq!(keyed("SHA256:R&&D"), (units("SHA256:R&D"), None));
        assert_eq!(keyed("Refuse"), (units("Refuse"), None));
    }
}
