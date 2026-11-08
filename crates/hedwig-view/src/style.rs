//! The one visual register of the surfaces Hedwig paints itself.
//!
//! The card and the icon's menu are drawn by Hedwig to Windows 11's own
//! measurements, so what they are drawn in is decided here once and by
//! nothing else. [`Appearance`] is what the person has set in Windows, as
//! `hedwig-shell` read it; every colour and size a painted surface uses is a
//! function of it, and is checked without a desktop.
//!
//! The measurements are WinUI's own at the release tag `winui3/release/2.5.1`
//! (`.ext/microsoft-ui-xaml-2.5.1`), each cited where it is used.

/// An opaque colour, as a painted surface hands it to Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rgb {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

impl Rgb {
    pub const BLACK: Rgb = Rgb::new(0, 0, 0);
    pub const WHITE: Rgb = Rgb::new(0xff, 0xff, 0xff);

    pub const fn new(red: u8, green: u8, blue: u8) -> Rgb {
        Rgb { red, green, blue }
    }

    /// The colour as the six hexadecimal digits a person writes it with.
    pub fn hex(self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.red, self.green, self.blue)
    }

    /// What is seen when `over` is drawn on this colour.
    ///
    /// WinUI states most of its control colours as white or black at a low
    /// alpha, drawn over whatever is beneath. A surface painted with opaque
    /// brushes needs the result, so each role is blended here against the
    /// surface it sits on.
    #[must_use]
    pub fn under(self, over: Tint) -> Rgb {
        let blend = |beneath: u8, above: u8| {
            let (beneath, above, alpha) =
                (u32::from(beneath), u32::from(above), u32::from(over.alpha));
            // Rounded to the nearest of 255 steps, as a compositor does.
            let mixed = (above * alpha + beneath * (255 - alpha) + 127) / 255;
            u8::try_from(mixed).unwrap_or(u8::MAX)
        };
        Rgb {
            red: blend(self.red, over.colour.red),
            green: blend(self.green, over.colour.green),
            blue: blend(self.blue, over.colour.blue),
        }
    }
}

/// A colour with the alpha it is drawn at: the form WinUI's resources take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tint {
    pub colour: Rgb,
    pub alpha: u8,
}

impl Tint {
    /// A resource value as WinUI writes it, `0xAARRGGBB`.
    pub const fn argb(value: u32) -> Tint {
        let [alpha, red, green, blue] = value.to_be_bytes();
        Tint {
            colour: Rgb::new(red, green, blue),
            alpha,
        }
    }

    /// `colour` at an opacity WinUI states as a fraction: 0.9 and 0.8 for an
    /// accent fill under the pointer and pressed.
    pub fn at(colour: Rgb, tenths: u8) -> Tint {
        let alpha = (u32::from(tenths.min(10)) * 255 + 5) / 10;
        Tint {
            colour,
            alpha: u8::try_from(alpha).unwrap_or(u8::MAX),
        }
    }
}

/// The person's choice of mode for applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Light,
    Dark,
}

impl Mode {
    /// The mode, from the colour Windows gives for text
    /// (`UIColorType.Foreground`): a light foreground is the dark mode. The
    /// test is Microsoft's own for a Win32 application.
    pub fn of(foreground: Rgb) -> Mode {
        let weight = 5 * u32::from(foreground.green)
            + 2 * u32::from(foreground.red)
            + u32::from(foreground.blue);
        if weight > 8 * 128 {
            Mode::Dark
        } else {
            Mode::Light
        }
    }

    /// The shade of the person's accent a surface fills with in this mode:
    /// an accent button, a selection.
    pub fn fill(self) -> Shade {
        match self {
            Mode::Dark => Shade::Light2,
            Mode::Light => Shade::Dark1,
        }
    }

    /// The shade accent-coloured text takes in this mode.
    pub fn text(self) -> Shade {
        match self {
            Mode::Dark => Shade::Light3,
            Mode::Light => Shade::Dark2,
        }
    }
}

/// One of the seven colours Windows derives from the person's accent. The
/// number is the `UIColorType` Windows is asked for it by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Shade {
    Dark3 = 2,
    Dark2 = 3,
    Dark1 = 4,
    Accent = 5,
    Light1 = 6,
    Light2 = 7,
    Light3 = 8,
}

/// The accent as a surface in the person's mode draws it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Accent {
    /// [`Mode::fill`]'s shade.
    pub fill: Rgb,
    /// [`Mode::text`]'s shade.
    pub text: Rgb,
}

/// The eight colours of a contrast theme, which are the person's own. Each
/// is used only with its pair: window with window text, button face with
/// button text, highlight with highlight text; grey text for what cannot be
/// used, hot light for a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct System {
    pub window: Rgb,
    pub window_text: Rgb,
    pub button_face: Rgb,
    pub button_text: Rgb,
    pub highlight: Rgb,
    pub highlight_text: Rgb,
    pub gray_text: Rgb,
    pub hot_light: Rgb,
}

/// What a painted surface takes its colours from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Colours {
    /// Windows 11's own roles, in the person's mode and accent.
    Theme { mode: Mode, accent: Accent },
    /// The system's eight colours and nothing else: a contrast theme is on,
    /// or the person's mode could not be read, and these are the colours
    /// Windows answers for in either case.
    System(System),
}

/// Whether Windows animates what it shows: the person's setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Motion {
    Animated,
    Still,
}

/// Whether Windows composes acrylic behind a transient surface now. Where it
/// cannot - over Remote Desktop, with the person's transparency effects off,
/// under energy saver - Windows draws its own fallback behind a window, which
/// is not the colour WinUI and Windows' flyouts fall back to, so a surface
/// standing on acrylic fills itself with that colour instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Backdrop {
    Acrylic,
    Solid,
}

/// The person's text size, in hundredths: 100 as Windows ships, to 225.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextScale(u16);

impl TextScale {
    pub const DEFAULT: TextScale = TextScale(100);

    /// The scale from the factor Windows reports, 1 to 2.25. A factor outside
    /// that range is one Windows cannot have set, and is held to it; one that
    /// is no number is the size Windows ships.
    pub fn new(factor: f64) -> TextScale {
        if factor.is_nan() {
            return TextScale::DEFAULT;
        }
        let hundredths = (factor * 100.0).round().clamp(100.0, 225.0);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a whole number clamped to 100..=225 on the line above"
        )]
        let whole = hundredths as u16;
        TextScale(whole)
    }

    pub fn hundredths(self) -> u16 {
        self.0
    }

    /// A type size of the ramp, in effective pixels, at this text size.
    ///
    /// Larger type grows by less: the curve is WinUI's own
    /// (`TextFormatting::GetScaledFontSize`), so a painted line of text and a
    /// WinUI one of the same style are the same size at every setting.
    pub fn size(self, effective: f32) -> f32 {
        let size = effective.max(1.0);
        let factor = f32::from(self.0) / 100.0;
        size + (18.0 - std::f32::consts::E * size.ln()).max(0.0) * (factor - 1.0)
    }
}

/// What the person has set in Windows that a painted surface answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Appearance {
    pub colours: Colours,
    pub text: TextScale,
    pub motion: Motion,
    pub backdrop: Backdrop,
}

/// A type style of Windows 11's ramp, as far as the painted surfaces use it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    /// A fact's name, and what is said beside the point.
    Caption,
    /// Most text, and every control's own.
    Body,
    /// A card's heading: the ramp's subtitle, which is a dialog's title.
    Subtitle,
}

impl Type {
    /// The size in effective pixels at the text size Windows ships.
    pub fn size(self) -> f32 {
        match self {
            Type::Caption => 12.0,
            Type::Body => 14.0,
            Type::Subtitle => 20.0,
        }
    }

    /// The weight on the font's own axis: regular, or semibold for a title.
    pub fn weight(self) -> u16 {
        match self {
            Type::Caption | Type::Body => 400,
            Type::Subtitle => 600,
        }
    }

    /// The face of Segoe UI Variable cut for this size. WinUI sets the
    /// optical size continuously; a surface that names a face takes the one
    /// the design guidance assigns the style.
    pub fn face(self) -> &'static str {
        match self {
            Type::Caption => "Segoe UI Variable Small",
            Type::Body => "Segoe UI Variable Text",
            Type::Subtitle => "Segoe UI Variable Display",
        }
    }
}

/// A length of `effective` pixels as whole pixels on a monitor of `dpi`.
pub fn pixels(effective: f32, dpi: u32) -> i32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a monitor's dots per inch are far below the 24 bits a float holds exactly"
    )]
    let scaled = effective * dpi as f32 / 96.0;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "a length on a screen, rounded, is within an i32"
    )]
    let whole = scaled.round() as i32;
    whole
}

/// A length that is drawn at all: a border of one effective pixel is one
/// pixel on a monitor where rounding would make it none.
pub fn line(effective: f32, dpi: u32) -> i32 {
    pixels(effective, dpi).max(1)
}

/// The state a control is drawn in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    Rest,
    /// The pointer is over it.
    Over,
    Pressed,
    /// It cannot be used now.
    Disabled,
}

/// Which of the two buttons Windows 11 has: the standard one, or the accent
/// one a surface gives its usual answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Standard,
    Accent,
}

/// A control's border, which WinUI draws as a gradient over its first few
/// effective pixels from one edge: `near` at that edge, `far` for the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Edge {
    pub near: Rgb,
    pub far: Rgb,
    /// Where the gradient starts.
    pub from: Side,
    pub stops: Stops,
}

/// The edge of a control its border's gradient starts at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    Top,
    Bottom,
}

/// Where a border's gradient holds its near colour to, and where it has
/// reached its far one, as WinUI's brushes place their stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stops {
    /// A button: 0.33 and 1.0 of three effective pixels.
    Control,
    /// A box text is typed in: 0.5 and 1.0 of two.
    Box,
    /// The same box with the keyboard in it: the accent for two, then the
    /// far colour at once.
    Underline,
}

impl Stops {
    fn span(self) -> (f32, f32) {
        match self {
            Stops::Control => (0.99, 3.0),
            Stops::Box => (1.0, 2.0),
            Stops::Underline => (2.0, 2.0),
        }
    }
}

impl Edge {
    fn flat(colour: Rgb) -> Edge {
        Edge {
            near: colour,
            far: colour,
            from: Side::Top,
            stops: Stops::Control,
        }
    }

    /// The border's colour `distance` effective pixels from the edge the
    /// gradient starts at.
    pub fn at(self, distance: f32) -> Rgb {
        let (hold, reach) = self.stops.span();
        let along = if reach > hold {
            ((distance - hold) / (reach - hold)).clamp(0.0, 1.0)
        } else if distance < hold {
            0.0
        } else {
            1.0
        };
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a fraction of 255, clamped to 0..=255"
        )]
        let alpha = (along * 255.0).round() as u8;
        self.near.under(Tint {
            colour: self.far,
            alpha,
        })
    }
}

/// What a control is drawn in, in one state, over one surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Face {
    pub fill: Rgb,
    pub edge: Edge,
    /// A pixel the text covers wholly.
    pub text: Rgb,
    /// The text's brush as WinUI draws it over the fill, its alpha included:
    /// what text set over the face is drawn with.
    pub ink: Tint,
}

/// The focus visual: two borders drawn outside the control that has the
/// keyboard, the outer two effective pixels thick and the inner one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Focus {
    pub outer: Rgb,
    pub inner: Rgb,
}

/// WinUI's colour resources for one mode, as it states them: most are white
/// or black at a low alpha.
struct Resources {
    base: Rgb,
    layer_alt: Tint,
    card_stroke: Tint,
    text: Tint,
    text_secondary: Tint,
    text_disabled: Tint,
    on_accent: Tint,
    on_accent_pressed: Tint,
    on_accent_disabled: Tint,
    /// A control's fill at rest, under the pointer, pressed and disabled.
    control: [Tint; 4],
    control_stroke: Tint,
    control_stroke_secondary: Tint,
    on_accent_stroke: Tint,
    on_accent_stroke_secondary: Tint,
    accent_disabled: Tint,
    focus_outer: Tint,
    focus_inner: Tint,
    input_active: Tint,
    strong_stroke: Tint,
    /// A scroll bar's thumb at rest.
    strong_fill: Tint,
    /// A menu entry's fill under the pointer and pressed.
    subtle: [Tint; 2],
    divider: Tint,
    /// A flyout's edge (`SurfaceStrokeColorFlyout`).
    flyout_stroke: Tint,
    acrylic: Acrylic,
}

// `Common_themeresources_any.xaml` at `winui3/release/2.5.1`: the dark
// dictionary is lines 5 to 75 and the light one 209 to 279; the acrylic is
// `AcrylicBackgroundFillColorDefaultBrush`, `AcrylicBrush_themeresources.xaml`
// lines 43 and 95.
const DARK: Resources = Resources {
    base: Rgb::new(0x20, 0x20, 0x20),
    layer_alt: Tint::argb(0x0DFF_FFFF),
    card_stroke: Tint::argb(0x1900_0000),
    text: Tint::argb(0xFFFF_FFFF),
    text_secondary: Tint::argb(0xC5FF_FFFF),
    text_disabled: Tint::argb(0x5DFF_FFFF),
    on_accent: Tint::argb(0xFF00_0000),
    on_accent_pressed: Tint::argb(0x8000_0000),
    on_accent_disabled: Tint::argb(0x87FF_FFFF),
    control: [
        Tint::argb(0x0FFF_FFFF),
        Tint::argb(0x15FF_FFFF),
        Tint::argb(0x08FF_FFFF),
        Tint::argb(0x0BFF_FFFF),
    ],
    control_stroke: Tint::argb(0x12FF_FFFF),
    control_stroke_secondary: Tint::argb(0x18FF_FFFF),
    on_accent_stroke: Tint::argb(0x14FF_FFFF),
    on_accent_stroke_secondary: Tint::argb(0x2300_0000),
    accent_disabled: Tint::argb(0x28FF_FFFF),
    focus_outer: Tint::argb(0xFFFF_FFFF),
    focus_inner: Tint::argb(0xB300_0000),
    input_active: Tint::argb(0xB31E_1E1E),
    strong_stroke: Tint::argb(0x8BFF_FFFF),
    strong_fill: Tint::argb(0x8BFF_FFFF),
    subtle: [Tint::argb(0x0FFF_FFFF), Tint::argb(0x0AFF_FFFF)],
    divider: Tint::argb(0x15FF_FFFF),
    flyout_stroke: Tint::argb(0x3300_0000),
    // TintColor #2C2C2C at 0.15, TintLuminosityOpacity 0.96.
    acrylic: Acrylic {
        tint: Tint::argb(0x262C_2C2C),
        luminosity: Tint::argb(0xF52C_2C2C),
        fallback: Rgb::new(0x2C, 0x2C, 0x2C),
    },
};

const LIGHT: Resources = Resources {
    base: Rgb::new(0xF3, 0xF3, 0xF3),
    layer_alt: Tint::argb(0xFFFF_FFFF),
    card_stroke: Tint::argb(0x0F00_0000),
    text: Tint::argb(0xE400_0000),
    text_secondary: Tint::argb(0x9E00_0000),
    text_disabled: Tint::argb(0x5C00_0000),
    on_accent: Tint::argb(0xFFFF_FFFF),
    on_accent_pressed: Tint::argb(0xB3FF_FFFF),
    on_accent_disabled: Tint::argb(0xFFFF_FFFF),
    control: [
        Tint::argb(0xB3FF_FFFF),
        Tint::argb(0x80F9_F9F9),
        Tint::argb(0x4DF9_F9F9),
        Tint::argb(0x4DF9_F9F9),
    ],
    control_stroke: Tint::argb(0x0F00_0000),
    control_stroke_secondary: Tint::argb(0x2900_0000),
    on_accent_stroke: Tint::argb(0x14FF_FFFF),
    on_accent_stroke_secondary: Tint::argb(0x6600_0000),
    accent_disabled: Tint::argb(0x3700_0000),
    focus_outer: Tint::argb(0xE400_0000),
    focus_inner: Tint::argb(0xB3FF_FFFF),
    input_active: Tint::argb(0xFFFF_FFFF),
    strong_stroke: Tint::argb(0x7200_0000),
    strong_fill: Tint::argb(0x7200_0000),
    subtle: [Tint::argb(0x0900_0000), Tint::argb(0x0600_0000)],
    divider: Tint::argb(0x0F00_0000),
    flyout_stroke: Tint::argb(0x0F00_0000),
    // TintColor #FCFCFC at 0, TintLuminosityOpacity 0.85.
    acrylic: Acrylic {
        tint: Tint::argb(0x00FC_FCFC),
        luminosity: Tint::argb(0xD9FC_FCFC),
        fallback: Rgb::new(0xF9, 0xF9, 0xF9),
    },
};

/// Windows 11's colour roles in the person's mode and accent, each blended
/// over the surface it sits on, so a surface painted with opaque brushes
/// draws what a WinUI one composes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    mode: Mode,
    accent: Accent,
}

impl Palette {
    pub fn new(mode: Mode, accent: Accent) -> Palette {
        Palette { mode, accent }
    }

    fn resources(self) -> &'static Resources {
        match self.mode {
            Mode::Dark => &DARK,
            Mode::Light => &LIGHT,
        }
    }

    pub fn mode(self) -> Mode {
        self.mode
    }

    /// Under a dialog's buttons: the dialog's own background.
    pub fn strip(self) -> Rgb {
        self.resources().base
    }

    /// Under a dialog's title and content: the layer WinUI lays over the
    /// background there.
    pub fn content(self) -> Rgb {
        let resources = self.resources();
        resources.base.under(resources.layer_alt)
    }

    /// The line between a dialog's content and its buttons. WinUI draws it as
    /// the content area's lower border, which its layer does not fill, so it
    /// lies over the dialog's own background and not over the layer.
    pub fn separator(self) -> Rgb {
        self.strip().under(self.resources().card_stroke)
    }

    /// Text on `beneath`.
    pub fn text(self, beneath: Rgb) -> Rgb {
        beneath.under(self.resources().text)
    }

    /// Text that says what another text is: a fact's name.
    pub fn quiet(self, beneath: Rgb) -> Rgb {
        beneath.under(self.resources().text_secondary)
    }

    /// The brush of text, and of text that says what another text is, as
    /// WinUI draws each over what is beneath it.
    pub fn inks(self) -> (Tint, Tint) {
        let resources = self.resources();
        (resources.text, resources.text_secondary)
    }

    /// A button of `kind` in `state`, on `beneath`.
    pub fn button(self, kind: Kind, state: State, beneath: Rgb) -> Face {
        let resources = self.resources();
        match kind {
            Kind::Standard => {
                let [rest, over, pressed, disabled] = resources.control;
                let (fill, text) = match state {
                    State::Rest => (rest, resources.text),
                    State::Over => (over, resources.text),
                    State::Pressed => (pressed, resources.text_secondary),
                    State::Disabled => (disabled, resources.text_disabled),
                };
                let fill = beneath.under(fill);
                let plain = beneath.under(resources.control_stroke);
                let edge = match state {
                    // The elevation border: its brighter stop at the top in
                    // the dark mode, its darker at the bottom in the light.
                    State::Rest | State::Over => Edge {
                        near: beneath.under(resources.control_stroke_secondary),
                        far: plain,
                        from: match self.mode {
                            Mode::Dark => Side::Top,
                            Mode::Light => Side::Bottom,
                        },
                        stops: Stops::Control,
                    },
                    State::Pressed | State::Disabled => Edge::flat(plain),
                };
                Face {
                    fill,
                    edge,
                    text: fill.under(text),
                    ink: text,
                }
            }
            Kind::Accent => {
                let accent = self.accent.fill;
                let (fill, text) = match state {
                    State::Rest => (accent, resources.on_accent),
                    State::Over => (beneath.under(Tint::at(accent, 9)), resources.on_accent),
                    State::Pressed => (
                        beneath.under(Tint::at(accent, 8)),
                        resources.on_accent_pressed,
                    ),
                    State::Disabled => (
                        beneath.under(resources.accent_disabled),
                        resources.on_accent_disabled,
                    ),
                };
                let edge = match state {
                    // Its fill runs under its border, whose darker stop is
                    // at the bottom in both modes.
                    State::Rest | State::Over => Edge {
                        near: fill.under(resources.on_accent_stroke_secondary),
                        far: fill.under(resources.on_accent_stroke),
                        from: Side::Bottom,
                        stops: Stops::Control,
                    },
                    State::Pressed | State::Disabled => Edge::flat(fill),
                };
                Face {
                    fill,
                    edge,
                    text: fill.under(text),
                    ink: text,
                }
            }
        }
    }

    /// A box text is typed in, on `beneath`: at rest, or with the keyboard in
    /// it, when its lower edge is the accent.
    pub fn input(self, state: Input, beneath: Rgb) -> Face {
        let resources = self.resources();
        let [rest, ..] = resources.control;
        let (fill, near, stops) = match state {
            Input::Rest => (rest, beneath.under(resources.strong_stroke), Stops::Box),
            Input::Typing => (resources.input_active, self.accent.fill, Stops::Underline),
        };
        let fill = beneath.under(fill);
        Face {
            fill,
            edge: Edge {
                near,
                far: beneath.under(resources.control_stroke),
                from: Side::Bottom,
                stops,
            },
            text: fill.under(resources.text),
            ink: resources.text,
        }
    }

    pub fn focus(self, beneath: Rgb) -> Focus {
        let resources = self.resources();
        Focus {
            outer: beneath.under(resources.focus_outer),
            inner: beneath.under(resources.focus_inner),
        }
    }

    /// The thin thumb that says where in a longer content this is, while the
    /// pointer is not over it: WinUI's panning indicator.
    pub fn indicator(self, beneath: Rgb) -> Rgb {
        beneath.under(self.resources().strong_fill)
    }

    /// What a menu is drawn in. It stands on the acrylic Windows draws
    /// behind it, so each ink is a tint laid over whatever that shows.
    pub fn menu(self) -> MenuInk {
        let resources = self.resources();
        let [over, pressed] = resources.subtle;
        MenuInk {
            text: resources.text,
            words: resources.text_secondary,
            over,
            pressed,
            rule: resources.divider,
            chevron: resources.text_secondary,
            ring: (resources.focus_outer, resources.focus_inner),
            edge: resources.flyout_stroke,
            acrylic: resources.acrylic,
            solid: resources.acrylic.fallback,
        }
    }
}

/// A menu's inks over the acrylic behind it (`MenuFlyout_themeresources.xaml`
/// and the common resources it names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MenuInk {
    /// An item's text (`MenuFlyoutItemForeground`).
    pub text: Tint,
    /// A row of words only, which offers nothing: the secondary text.
    pub words: Tint,
    /// An item's fill under the pointer or the keyboard, and pressed
    /// (`MenuFlyoutItemBackgroundPointerOver`, `...Pressed`).
    pub over: Tint,
    pub pressed: Tint,
    /// A separator (`MenuFlyoutSeparatorBackground`).
    pub rule: Tint,
    /// A submenu's chevron (`MenuFlyoutSubItemChevron`).
    pub chevron: Tint,
    /// The focus visual's outer and inner rings, round the item the
    /// keyboard is on.
    pub ring: (Tint, Tint),
    /// The menu's edge over its backdrop (`MenuFlyoutPresenterBorderBrush`).
    pub edge: Tint,
    /// The acrylic behind the rows.
    pub acrylic: Acrylic,
    /// What the menu is filled with where Windows draws no acrylic at all:
    /// the colour acrylic itself falls back to.
    pub solid: Rgb,
}

/// Acrylic as WinUI composes it over what is behind a window: the backdrop
/// takes `luminosity`'s lightness, then `tint`'s hue and saturation, and a
/// fine noise lies over it. The colours are the effective ones `AcrylicBrush`
/// derives from the Fluent tokens where the luminosity's opacity is stated
/// (`AcrylicBrush.cpp`, `GetEffectiveTintColor` and `GetLuminosityColor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acrylic {
    pub tint: Tint,
    pub luminosity: Tint,
    /// The colour shown where acrylic is not composed.
    pub fallback: Rgb,
}

/// Whether the keyboard is in a box text is typed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Input {
    Rest,
    Typing,
}
