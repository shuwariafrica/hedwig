//! The pixels of a painted control, and the colours Windows 11's roles come
//! to over the surfaces a card has.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_view::paint::{self, Shape};
use hedwig_view::style::{
    Accent, Input, Kind, Mode, Palette, Rgb, Side, State, Stops, Type, line, pixels,
};

fn accent() -> Accent {
    // The shades this desktop's accent gives a dark surface.
    Accent {
        fill: Rgb::new(0x4C, 0xC2, 0xFF),
        text: Rgb::new(0x99, 0xEB, 0xFF),
    }
}

fn dark() -> Palette {
    Palette::new(Mode::Dark, accent())
}

fn light() -> Palette {
    Palette::new(
        Mode::Light,
        Accent {
            fill: Rgb::new(0x00, 0x67, 0xC0),
            text: Rgb::new(0x00, 0x3E, 0x92),
        },
    )
}

/// A dialog's two layers, its line and its text, as WinUI's resources blend
/// in each mode. The dark values are what a WinUI dialog draws at this
/// desktop.
#[test]
fn a_dialogs_layers_are_winuis_resources_blended_in_each_mode() {
    let palette = dark();
    assert_eq!(palette.strip().hex(), "#202020");
    assert_eq!(palette.content().hex(), "#2B2B2B");
    assert_eq!(palette.separator().hex(), "#1D1D1D");
    assert_eq!(palette.text(palette.content()).hex(), "#FFFFFF");
    assert_eq!(palette.quiet(palette.content()).hex(), "#CFCFCF");

    let palette = light();
    assert_eq!(palette.strip().hex(), "#F3F3F3");
    assert_eq!(palette.content().hex(), "#FFFFFF");
    assert_eq!(palette.separator().hex(), "#E5E5E5");
    assert_eq!(palette.text(palette.content()).hex(), "#1B1B1B");
    assert_eq!(palette.quiet(palette.content()).hex(), "#616161");
}

/// A standard button in each state on a dark dialog's strip: the fills a
/// WinUI window draws here, a border brighter at the top while it can be
/// pressed and flat once it is, and text that dims as it is pressed and
/// disabled.
#[test]
fn a_standard_button_has_winuis_states() {
    let (palette, strip) = (dark(), dark().strip());
    let fills = [State::Rest, State::Over, State::Pressed, State::Disabled]
        .map(|state| palette.button(Kind::Standard, state, strip).fill.hex());
    assert_eq!(fills, ["#2D2D2D", "#323232", "#272727", "#2A2A2A"]);
    let rest = palette.button(Kind::Standard, State::Rest, strip);
    assert_eq!(
        (rest.edge.near.hex(), rest.edge.far.hex(), rest.edge.from),
        ("#353535".to_owned(), "#303030".to_owned(), Side::Top)
    );
    assert_eq!(rest.edge.stops, Stops::Control);
    assert_eq!(rest.text.hex(), "#FFFFFF");
    let pressed = palette.button(Kind::Standard, State::Pressed, strip);
    assert_eq!(pressed.edge.near, pressed.edge.far);
    assert_eq!(pressed.text.hex(), "#CECECE");
    let disabled = palette.button(Kind::Standard, State::Disabled, strip);
    assert_eq!(disabled.text.hex(), "#787878");

    // In the light mode the darker stop is at the bottom.
    let (palette, strip) = (light(), light().strip());
    let rest = palette.button(Kind::Standard, State::Rest, strip);
    assert_eq!(rest.fill.hex(), "#FBFBFB");
    assert_eq!(rest.edge.from, Side::Bottom);
    assert_eq!(
        (rest.edge.near.hex(), rest.edge.far.hex()),
        ("#CCCCCC".to_owned(), "#E5E5E5".to_owned())
    );
}

/// The accent button is the person's accent as their mode draws it, at nine
/// and eight tenths under the pointer and pressed, with text that contrasts.
#[test]
fn an_accent_button_is_the_persons_accent() {
    let (palette, strip) = (dark(), dark().strip());
    let fills = [State::Rest, State::Over, State::Pressed, State::Disabled]
        .map(|state| palette.button(Kind::Accent, state, strip).fill.hex());
    assert_eq!(fills, ["#4CC2FF", "#48B2E9", "#43A2D2", "#434343"]);
    let rest = palette.button(Kind::Accent, State::Rest, strip);
    assert_eq!(rest.text, Rgb::BLACK);
    // Its border is drawn over its own fill, darker at the bottom.
    assert_eq!(rest.edge.from, Side::Bottom);
    assert_eq!(
        (rest.edge.near.hex(), rest.edge.far.hex()),
        ("#42A7DC".to_owned(), "#5AC7FF".to_owned())
    );
    let light = light();
    assert_eq!(
        light.button(Kind::Accent, State::Rest, light.strip()).text,
        Rgb::WHITE
    );
}

/// A box text is typed in: a control's fill and a stronger lower edge at
/// rest; with the keyboard in it, a darker fill and the accent beneath.
#[test]
fn a_box_for_typing_shows_where_the_keyboard_is() {
    let (palette, content) = (dark(), dark().content());
    let rest = palette.input(Input::Rest, content);
    assert_eq!(rest.fill.hex(), "#373737");
    assert_eq!(
        (rest.edge.from, rest.edge.stops),
        (Side::Bottom, Stops::Box)
    );
    assert_eq!(rest.edge.near.hex(), "#9F9F9F");
    let typing = palette.input(Input::Typing, content);
    assert_eq!(typing.fill.hex(), "#222222");
    assert_eq!(typing.edge.near, accent().fill);
    assert_eq!(typing.edge.stops, Stops::Underline);
    // The accent holds for two effective pixels, then the border is plain.
    assert_eq!(typing.edge.at(1.9), accent().fill);
    assert_eq!(typing.edge.at(2.1), typing.edge.far);
}

/// An effective pixel is as many pixels as the monitor's scale says, to the
/// nearest whole one, and a border is never none.
#[test]
fn lengths_are_effective_pixels_at_the_monitors_scale() {
    assert_eq!(
        [96, 120, 144, 192].map(|dpi| pixels(24.0, dpi)),
        [24, 30, 36, 48]
    );
    assert_eq!(
        [96, 120, 144, 192].map(|dpi| pixels(11.0, dpi)),
        [11, 14, 17, 22]
    );
    assert_eq!([96, 120, 144, 192].map(|dpi| line(1.0, dpi)), [1, 1, 2, 2]);
    assert_eq!(pixels(0.3, 96), 0);
    assert_eq!(line(0.3, 96), 1);
    assert_eq!(
        [Type::Caption, Type::Body, Type::Subtitle].map(|style| (style.size(), style.weight())),
        [(12.0, 400), (14.0, 400), (20.0, 600)]
    );
}

fn button(focused: bool) -> (paint::Picture, Shape) {
    let (palette, strip) = (dark(), dark().strip());
    // A button 100 by 40 pixels at 125 per cent, with room for its rings.
    let shape = Shape {
        width: 108,
        height: 48,
        inset: 4.0,
        radius: 5.0,
        border: 1.0,
        bottom: 1.0,
        scale: 1.25,
    };
    let face = palette.button(Kind::Standard, State::Rest, strip);
    let focus = focused.then(|| palette.focus(strip));
    (paint::control(&shape, strip, &face, focus), shape)
}

/// The picture of a button: its fill inside, its border one pixel wide with
/// the brighter stop along the top, the surface beneath outside its rounded
/// corners, and a corner's edge in between the two, which is what makes it
/// smooth.
#[test]
fn a_button_is_a_rounded_rectangle_with_a_smooth_edge() {
    let (picture, shape) = button(false);
    assert_eq!((picture.width, picture.height), (108, 48));
    assert_eq!(picture.pixels.len(), 108 * 48);
    let at = |x, y| picture.at(x, y).unwrap().hex();
    assert_eq!(at(54, 24), "#2D2D2D", "the fill");
    assert_eq!(at(54, 4), "#353535", "the top of the border");
    assert_eq!(at(54, 43), "#303030", "the bottom of the border");
    assert_eq!(at(4, 24), "#303030", "the side of the border");
    assert_eq!(at(54, 3), "#202020", "above the button");
    assert_eq!(at(0, 0), "#202020", "outside");
    assert_eq!(at(4, 4), "#202020", "outside the rounded corner");
    // Along the corner's arc a pixel is partly the border and partly what is
    // beneath: neither colour, and between them.
    let corner = picture.at(5, 5).unwrap();
    assert!(corner.red > 0x20 && corner.red < 0x35, "{}", corner.hex());
    // The shape is the same left and right.
    for y in 0..shape.height {
        for x in 0..shape.width / 2 {
            assert_eq!(
                picture.at(x, y),
                picture.at(shape.width - 1 - x, y),
                "{x},{y}"
            );
        }
    }
    assert_eq!(picture.at(108, 0), None);
    assert_eq!(picture.at(0, 48), None);
}

/// With the keyboard on it a control has two rings outside it: one effective
/// pixel of the inner colour against it, two of the outer beyond.
#[test]
fn the_keyboards_place_is_two_rings_outside_the_control() {
    let (picture, _) = button(true);
    let at = |x, y| picture.at(x, y).unwrap().hex();
    assert_eq!(at(54, 24), "#2D2D2D", "the fill is as it was");
    assert_eq!(at(54, 4), "#353535", "and the border");
    assert_eq!(at(54, 1), "#FFFFFF", "the outer ring");
    // The inner ring is a dark line between the white and the button.
    let inner = picture.at(54, 3).unwrap();
    assert!(inner.red < 0x30, "{}", inner.hex());
    // Without the keyboard there is nothing there.
    let (plain, _) = button(false);
    assert_eq!(plain.at(54, 1).unwrap().hex(), "#202020");
}
