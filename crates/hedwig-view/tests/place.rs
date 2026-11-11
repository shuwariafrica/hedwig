//! Where the person left the window, kept between openings.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_view::place::{Placement, Unreadable};

fn at(maximised: bool) -> Placement {
    Placement {
        left: 192,
        top: 192,
        right: 1310,
        bottom: 1189,
        maximised,
        dpi: 120,
    }
}

#[test]
fn a_placement_is_written_and_read_back_both_ways() {
    for placement in [at(false), at(true)] {
        let written = placement.written();
        assert_eq!(Placement::read(&written), Ok(placement));
        assert_eq!(Placement::read(&written).unwrap().written(), written);
    }
    assert_eq!(at(true).written(), "192 192 1310 1189 maximised 120");
    // On a monitor left of or above the primary one, the rectangle is less
    // than zero.
    let left = Placement {
        left: -1700,
        right: -600,
        ..at(false)
    };
    assert_eq!(Placement::read(&left.written()), Ok(left));
}

#[test]
fn what_is_not_a_placement_is_refused() {
    for text in [
        "",
        "192 192 1310 1189",
        "192 192 1310 1189 minimised 120",
        "192 192 1310 1189 restored 0",
        "192 192 1310 1189 restored 120 more",
        "192 192 200 1189 restored 120",
        "192 192 1310 200 restored 120",
        "a 192 1310 1189 restored 120",
    ] {
        assert_eq!(Placement::read(text), Err(Unreadable), "{text:?}");
    }
}

#[test]
fn a_placement_on_a_monitor_of_another_scale_keeps_its_size_to_the_eye_from_its_corner() {
    let placement = at(false);
    let larger = placement.scaled(144);
    assert_eq!(
        (
            larger.left,
            larger.top,
            larger.width(),
            larger.height(),
            larger.dpi
        ),
        (192, 192, 1342, 1196, 144)
    );
    assert_eq!(larger.scaled(120), placement);
    assert_eq!(placement.scaled(120), placement);
}
