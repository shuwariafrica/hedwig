//! The painted surfaces' register: what is read of the person's settings
//! becomes colours and sizes by rules a desktop is not needed to check.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_view::style::{Mode, Rgb, Shade, TextScale, Tint};

/// Microsoft's test for a Win32 application: a light text colour is the dark
/// mode. The two values are the ones Windows gives for `Foreground`.
#[test]
fn the_mode_is_read_from_the_colour_windows_gives_for_text() {
    assert_eq!(Mode::of(Rgb::WHITE), Mode::Dark);
    assert_eq!(Mode::of(Rgb::BLACK), Mode::Light);
    // The boundary of the test itself: 5G + 2R + B against 8 * 128.
    assert_eq!(Mode::of(Rgb::new(128, 128, 128)), Mode::Light);
    assert_eq!(Mode::of(Rgb::new(128, 129, 128)), Mode::Dark);
}

/// WinUI draws an accent fill in `SystemAccentColorLight2` on a dark surface
/// and `SystemAccentColorDark1` on a light one, and accent text in `Light3`
/// and `Dark2`; the numbers are the `UIColorType` each is asked for by.
#[test]
fn each_mode_draws_its_own_shades_of_the_accent() {
    assert_eq!(Mode::Dark.fill(), Shade::Light2);
    assert_eq!(Mode::Dark.text(), Shade::Light3);
    assert_eq!(Mode::Light.fill(), Shade::Dark1);
    assert_eq!(Mode::Light.text(), Shade::Dark2);
    assert_eq!(
        [
            Shade::Dark3,
            Shade::Dark2,
            Shade::Dark1,
            Shade::Accent,
            Shade::Light1,
            Shade::Light2,
            Shade::Light3
        ]
        .map(|shade| shade as i32),
        [2, 3, 4, 5, 6, 7, 8]
    );
}

/// A resource stated as white or black at a low alpha becomes the colour a
/// compositor would show over the surface beneath. The first is a button at
/// rest on a dark dialog, which a WinUI window at this desktop draws as
/// `#2D2D2D`.
#[test]
fn a_low_alpha_resource_is_blended_over_what_is_beneath() {
    let dark = Rgb::new(0x20, 0x20, 0x20);
    assert_eq!(dark.under(Tint::argb(0x0FFF_FFFF)).hex(), "#2D2D2D");
    let light = Rgb::new(0xF3, 0xF3, 0xF3);
    assert_eq!(light.under(Tint::argb(0xB3FF_FFFF)).hex(), "#FBFBFB");
    // Nothing of a clear tint shows, and all of an opaque one.
    assert_eq!(dark.under(Tint::argb(0x00FF_FFFF)), dark);
    assert_eq!(dark.under(Tint::argb(0xFF4C_C2FF)).hex(), "#4CC2FF");
    // An accent fill under the pointer is the fill at nine tenths.
    let accent = Rgb::new(0x4C, 0xC2, 0xFF);
    assert_eq!(dark.under(Tint::at(accent, 9)).hex(), "#48B2E9");
    assert_eq!(dark.under(Tint::at(accent, 8)).hex(), "#43A2D2");
    assert_eq!(Tint::at(accent, 10).alpha, 255);
}

/// The person's text size moves small type by more than large, on WinUI's
/// own curve: `s + max(18 - e ln s, 0) (f - 1)`.
#[test]
fn text_grows_with_the_persons_text_size_on_winuis_curve() {
    let close = |got: f32, expected: f32| (got - expected).abs() < 0.01;
    let shipped = TextScale::new(1.0);
    assert_eq!(shipped, TextScale::DEFAULT);
    for size in [12.0, 14.0, 20.0] {
        assert!(close(shipped.size(size), size));
    }
    let largest = TextScale::new(2.25);
    assert_eq!(largest.hundredths(), 225);
    assert!(close(largest.size(12.0), 26.06), "{}", largest.size(12.0));
    assert!(close(largest.size(14.0), 27.53), "{}", largest.size(14.0));
    assert!(close(largest.size(20.0), 32.32), "{}", largest.size(20.0));
    // Caption, body and subtitle keep their order at every setting.
    let half = TextScale::new(1.5);
    assert!(half.size(12.0) < half.size(14.0) && half.size(14.0) < half.size(20.0));
    // Type too large to grow is left as it is.
    assert!(close(largest.size(800.0), 800.0));
    // A factor Windows cannot have set is held to the range it can.
    assert_eq!(TextScale::new(0.2), TextScale::DEFAULT);
    assert_eq!(TextScale::new(9.0).hundredths(), 225);
    assert_eq!(TextScale::new(f64::NAN), TextScale::DEFAULT);
}

/// An answer's fill becomes another over WinUI's 83 ms, each component
/// stepped linearly from the fill shown when the change began, and is the
/// new fill from then on.
#[test]
fn a_buttons_fill_changes_over_winuis_time() {
    use hedwig_view::motion::{FILL, filled};
    let rest = Rgb {
        red: 0x2D,
        green: 0x2D,
        blue: 0x2D,
    };
    let over = Rgb {
        red: 0x32,
        green: 0x32,
        blue: 0x32,
    };
    assert_eq!(FILL, 83);
    assert_eq!(filled(rest, over, 0), rest);
    let half = filled(rest, over, 41);
    assert!(half.red > rest.red && half.red < over.red, "{half:?}");
    assert_eq!(filled(rest, over, FILL), over);
    assert_eq!(filled(rest, over, 10_000), over);
    // Coming back part of the way through starts from what was shown.
    assert_eq!(filled(half, rest, 0), half);
    assert_eq!(filled(over, rest, FILL), rest);
}
