//! The emblem as Windows draws it: an icon handle made from the view's
//! picture, drawn by Windows over a ground of known colour, matches the
//! picture laid over that ground, so its alpha is read as the view meant it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_shell::icon::Image;
use hedwig_view::emblem::{Badge, Emblem, Ink, Owl};
use hedwig_view::style::{Mode, Rgb};

#[path = "support/drawn.rs"]
mod drawn;
use drawn::{agree, drawn, meant};

/// Every state, at the notification area's size at 100 and 125 per cent
/// and at 48, over the dark taskbar's colour, the light one's and white:
/// what Windows draws is what the view drew, to within 2 in a channel.
#[test]
fn windows_draws_the_emblem_as_the_view_drew_it() {
    for side in [16, 20, 48] {
        for (mode, ground) in [
            (Mode::Dark, Rgb::new(0x20, 0x20, 0x20)),
            (Mode::Light, Rgb::new(0xf3, 0xf3, 0xf3)),
            (Mode::Light, Rgb::new(0xff, 0xff, 0xff)),
        ] {
            for owl in [Owl::Awake, Owl::Dozing, Owl::Absent] {
                for badge in [Badge::Nothing, Badge::Look, Badge::Answer] {
                    let picture = Emblem { owl, badge }.draw(side, Ink::Taskbar(mode));
                    let image = Image::of(&picture).expect("Windows makes the icon");
                    let shown = drawn(image.handle(), side, ground);
                    let result = agree(&shown, &meant(&picture, ground));
                    assert_eq!(result, Ok(()), "{side} {owl:?} {badge:?} over {ground:?}");
                }
            }
        }
    }
}
