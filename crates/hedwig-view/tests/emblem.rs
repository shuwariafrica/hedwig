//! Hedwig's emblem: the owner's logo read whole, drawn at every size Windows
//! asks for, saying the icon's two answers and holding its contrast on either
//! taskbar and under a contrast theme; and the executables' resource built
//! from it.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::text::Commit;
use hedwig_view::emblem::{self, Badge, Emblem, Ink, Owl};
use hedwig_view::glance::Glance;
use hedwig_view::link::{Core, Seen};
use hedwig_view::paint::Canvas;
use hedwig_view::resource::{self, Named, SIDES};
use hedwig_view::style::{Mode, Rgb, System};

const DARK: Rgb = Rgb::new(0x20, 0x20, 0x20);
const LIGHT: Rgb = Rgb::new(0xf3, 0xf3, 0xf3);

fn every() -> Vec<Emblem> {
    [Owl::Awake, Owl::Dozing, Owl::Absent]
        .into_iter()
        .flat_map(|owl| {
            [Badge::Nothing, Badge::Look, Badge::Answer]
                .into_iter()
                .map(move |badge| Emblem { owl, badge })
        })
        .collect()
}

fn luminance(colour: Rgb) -> f64 {
    let level = |value: u8| {
        let unit = f64::from(value) / 255.0;
        if unit <= 0.040_45 {
            unit / 12.92
        } else {
            ((unit + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * level(colour.red) + 0.7152 * level(colour.green) + 0.0722 * level(colour.blue)
}

fn contrast(one: Rgb, other: Rgb) -> f64 {
    let (a, b) = (luminance(one), luminance(other));
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

/// The pixel over `ground`, as the taskbar shows it.
fn over(picture: &Canvas, x: usize, y: usize, ground: Rgb) -> (Rgb, u8) {
    let (colour, alpha) = picture.at(x, y).unwrap();
    let mix = |top: u8, under: u8| {
        let value =
            (u32::from(top) * u32::from(alpha) + u32::from(under) * (255 - u32::from(alpha)) + 127)
                / 255;
        u8::try_from(value).unwrap()
    };
    (
        Rgb::new(
            mix(colour.red, ground.red),
            mix(colour.green, ground.green),
            mix(colour.blue, ground.blue),
        ),
        alpha,
    )
}

/// `N` bytes of `data` from `at`.
fn bytes<const N: usize>(data: &[u8], at: usize) -> [u8; N] {
    data.get(at..at + N).unwrap().try_into().unwrap()
}

fn part(data: &[u8], from: usize, to: usize) -> &[u8] {
    data.get(from..to).unwrap()
}

fn black() -> System {
    System {
        window: Rgb::new(0, 0, 0),
        window_text: Rgb::new(0xff, 0xff, 0xff),
        button_face: Rgb::new(0, 0, 0),
        button_text: Rgb::new(0xff, 0xff, 0xff),
        highlight: Rgb::new(0x1a, 0xeb, 0xff),
        highlight_text: Rgb::new(0, 0, 0),
        gray_text: Rgb::new(0x3f, 0xf2, 0x3f),
        hot_light: Rgb::new(0xff, 0xff, 0x00),
    }
}

/// The emblem is Hedwig's logo, every shape of it read, and the light
/// taskbar's file holds the same shapes.
#[test]
fn every_shape_of_the_owners_logo_is_read() {
    assert_eq!(emblem::read_of_logo(), [(13, 13, true), (13, 13, true)]);
}

/// The share of what is drawn of `picture` that holds 3:1 over `ground`.
fn holding(picture: &Canvas, ground: Rgb) -> f64 {
    let (mut drawn, mut holding) = (0_u32, 0_u32);
    for y in 0..picture.height {
        for x in 0..picture.width {
            let (colour, alpha) = over(picture, x, y, ground);
            if alpha >= 128 {
                drawn += 1;
                if contrast(colour, ground) >= 3.0 {
                    holding += 1;
                }
            }
        }
    }
    f64::from(holding) / f64::from(drawn)
}

/// Windows' guidance for an icon (`app-icon-design`, "Color contrast"): at
/// least half of it passes 3:1 on the light and the dark theme. Held by every
/// state of the owl at the logo's own size, its view box, over the taskbar its
/// ink is for; at the sizes Windows draws it, the share is printed, since
/// there an edge's pixels blend the logo's two colours and pass neither.
#[test]
fn half_the_emblem_holds_three_to_one_on_either_taskbar() {
    for (mode, ground) in [(Mode::Dark, DARK), (Mode::Light, LIGHT)] {
        for owl in [Owl::Awake, Owl::Dozing, Owl::Absent] {
            let emblem = Emblem {
                owl,
                badge: Badge::Nothing,
            };
            let share = holding(&emblem.draw(512, Ink::Taskbar(mode)), ground);
            assert!(share >= 0.5, "{mode:?} {owl:?}: {share:.3}");
            let sizes: Vec<String> = SIDES
                .iter()
                .map(|side| {
                    let share = holding(&emblem.draw(*side, Ink::Taskbar(mode)), ground);
                    format!("{side} {:.0}%", share * 100.0)
                })
                .collect();
            println!(
                "{mode:?} {owl:?}: 512 {:.1}%; {}",
                share * 100.0,
                sizes.join(", ")
            );
        }
    }
}

/// Each state the icon says is a picture of its own at the notification
/// area's sizes, so the person tells them apart at a glance.
#[test]
fn each_state_is_a_picture_of_its_own_at_every_tray_size() {
    for side in [16, 20, 24, 32, 40, 48, 64] {
        for ink in [
            Ink::Taskbar(Mode::Dark),
            Ink::Taskbar(Mode::Light),
            Ink::System(black()),
        ] {
            let pictures: Vec<Vec<u32>> = every()
                .into_iter()
                .map(|emblem| emblem.draw(side, ink).premultiplied())
                .collect();
            for (at, one) in pictures.iter().enumerate() {
                for other in pictures.iter().skip(at + 1) {
                    let differ = one.iter().zip(other).filter(|(a, b)| a != b).count();
                    // At least a pixel and a half of every eight in the side.
                    assert!(differ >= side, "{side} {ink:?}: {differ} differ");
                }
            }
        }
    }
}

/// Absent is the same owl in greys, of the luminance its colours have, so it
/// holds the same contrast; the badge keeps its colour.
#[test]
fn an_absent_core_is_the_dozing_owl_in_greys() {
    for side in [16, 32, 256] {
        let dozing = Emblem {
            owl: Owl::Dozing,
            badge: Badge::Nothing,
        }
        .draw(side, Ink::Taskbar(Mode::Dark));
        let absent = Emblem {
            owl: Owl::Absent,
            badge: Badge::Nothing,
        }
        .draw(side, Ink::Taskbar(Mode::Dark));
        for y in 0..side {
            for x in 0..side {
                let (grey, alpha) = absent.at(x, y).unwrap();
                let (colour, same) = dozing.at(x, y).unwrap();
                assert_eq!(alpha, same);
                // Inside a shape, where no edge blends two colours.
                let inside = [(1, 0), (0, 1), (2, 1), (1, 2)].iter().all(|(dx, dy)| {
                    (x + dx)
                        .checked_sub(1)
                        .zip((y + dy).checked_sub(1))
                        .and_then(|(near_x, near_y)| dozing.at(near_x, near_y))
                        == Some((colour, 255))
                });
                if alpha == 255 && inside {
                    assert!(
                        grey.red == grey.green && grey.green == grey.blue,
                        "{grey:?}"
                    );
                    assert!(
                        (luminance(grey) - luminance(colour)).abs() < 0.01,
                        "{grey:?} for {colour:?}"
                    );
                }
            }
        }
    }
}

/// Something held for the person is a filled disc in WinUI's critical
/// colour for the taskbar's mode; something to look at, a ring in its text
/// colour with nothing inside; each parted from the owl by a clear gap.
#[test]
fn what_waits_is_a_badge_at_the_corner_parted_by_a_gap() {
    let side = 32;
    for (mode, critical) in [
        (Mode::Dark, Rgb::new(0xff, 0x99, 0xa4)),
        (Mode::Light, Rgb::new(0xc4, 0x2b, 0x1c)),
    ] {
        let answer = Emblem {
            owl: Owl::Awake,
            badge: Badge::Answer,
        }
        .draw(side, Ink::Taskbar(mode));
        // The disc's middle: 7/32 of the side in from the corner.
        assert_eq!(answer.at(25, 25), Some((critical, 255)));
        // The gap, just outside the disc towards the owl.
        let (_, gap) = answer.at(17, 25).unwrap();
        assert!(gap < 64, "{gap}");

        let look = Emblem {
            owl: Owl::Awake,
            badge: Badge::Look,
        }
        .draw(side, Ink::Taskbar(mode));
        assert_eq!(look.at(25, 25).unwrap().1, 0, "nothing inside the ring");
        let (ring, alpha) = look.at(31, 25).unwrap();
        assert!(alpha > 128, "{alpha}");
        match mode {
            Mode::Dark => assert_eq!(ring, Rgb::new(0xff, 0xff, 0xff)),
            Mode::Light => assert_eq!(ring, Rgb::new(0, 0, 0)),
        }
    }
}

/// Under a contrast theme the emblem is its colours alone: the owl in the
/// window's text on the window's colour, grey text where no core answers,
/// a badge in the highlight.
#[test]
fn a_contrast_theme_draws_the_emblem_in_its_own_colours() {
    let system = black();
    for emblem in every() {
        let picture = emblem.draw(48, Ink::System(system));
        let owl = match emblem.owl {
            Owl::Absent => system.gray_text,
            Owl::Awake | Owl::Dozing => system.window_text,
        };
        let allowed = [owl, system.window, system.highlight];
        for y in 0..48 {
            for x in 0..48 {
                let (colour, alpha) = picture.at(x, y).unwrap();
                if alpha == 255 && x % 3 == 0 && y % 3 == 0 {
                    // Edges blend; a whole pixel inside a shape is one of
                    // the theme's colours or a blend of two of them.
                    let near = allowed.iter().any(|allowed| {
                        allowed.red.abs_diff(colour.red) < 2
                            && allowed.green.abs_diff(colour.green) < 2
                            && allowed.blue.abs_diff(colour.blue) < 2
                    });
                    let between = allowed.iter().any(|one| {
                        allowed.iter().any(|other| {
                            [
                                (one.red, other.red, colour.red),
                                (one.green, other.green, colour.green),
                            ]
                            .iter()
                            .all(|(a, b, c)| (*a.min(b)..=*a.max(b)).contains(c))
                        })
                    });
                    assert!(near || between, "{emblem:?} at {x},{y}: {colour:?}");
                }
            }
        }
    }
}

/// The icon says the glance's two answers: whether anything reaches the
/// workstation, and whether anything waits.
#[test]
fn the_owl_says_whether_a_core_answers() {
    let off = Glance::of(&Seen { core: Core::Absent });
    assert_eq!(
        Emblem::of(&off),
        Emblem {
            owl: Owl::Absent,
            badge: Badge::Nothing
        }
    );
    let starting = Glance::of(&Seen {
        core: Core::Starting,
    });
    assert_eq!(Emblem::of(&starting).owl, Owl::Dozing);
}

/// The executables' resource: an icon of every size in `SIDES`, each a PNG
/// whose chunks check, the group naming them by number; and version
/// information naming Hedwig and the build, in UK English and Unicode.
#[test]
fn the_resource_holds_the_emblem_at_every_size_and_names_hedwig() {
    let named = Named {
        version: [0, 2, 0],
        release: "0.2.0-alpha.1".to_owned(),
        commit: Commit::try_from("0123456789ab, modified").unwrap(),
        description: "Hedwig icon".to_owned(),
        product: "Hedwig".to_owned(),
        publisher: "Shuwari Africa".to_owned(),
        copyright: "Copyright (c) 2026 the Hedwig contributors".to_owned(),
        file: "hedwig-interface.exe".to_owned(),
    };
    let file = resource::file(&named);
    // Walk the entries: their types and numbers.
    let mut at = 0;
    let mut found = Vec::new();
    while at + 32 <= file.len() {
        let data = u32::from_le_bytes(bytes(&file, at)) as usize;
        let header = u32::from_le_bytes(bytes(&file, at + 4)) as usize;
        assert_eq!(header, 32);
        let kind = u16::from_le_bytes(bytes(&file, at + 10));
        let number = u16::from_le_bytes(bytes(&file, at + 14));
        let body = part(&file, at + header, at + header + data);
        found.push((kind, number, body.to_vec()));
        at += header + data.div_ceil(4) * 4;
    }
    assert_eq!(at, file.len());
    let icons: Vec<&Vec<u8>> = found
        .iter()
        .filter(|(kind, _, _)| *kind == 3)
        .map(|(_, _, body)| body)
        .collect();
    assert_eq!(icons.len(), SIDES.len());
    for (png, side) in icons.iter().zip(SIDES) {
        assert_eq!(part(png, 0, 8), b"\x89PNG\r\n\x1a\n");
        assert_eq!(u32::from_be_bytes(bytes(png, 16)) as usize, side);
        // Every chunk's CRC checks.
        let mut offset = 8;
        while offset < png.len() {
            let length = u32::from_be_bytes(bytes(png, offset)) as usize;
            let sum = u32::from_be_bytes(bytes(png, offset + 8 + length));
            assert_eq!(
                resource::crc(part(png, offset + 4, offset + 8 + length)),
                sum
            );
            offset += 12 + length;
        }
        assert_eq!(offset, png.len());
    }
    // The 256-pixel image is small: the owl's flat colours compress.
    let largest = icons.last().unwrap().len();
    assert!(largest < 40_000, "{largest}");
    let group = found.iter().find(|(kind, _, _)| *kind == 14).unwrap();
    assert_eq!(group.1, resource::ICON);
    assert_eq!(group.2.len(), 6 + 14 * SIDES.len());
    let version = &found.iter().find(|(kind, _, _)| *kind == 16).unwrap().2;
    let (units, _) = version.as_chunks::<2>();
    let text: Vec<u16> = units.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    let text = String::from_utf16_lossy(&text);
    assert!(text.contains("VS_VERSION_INFO") && text.contains("080904b0"));
    // Each string's value follows its key, after the padding that aligns it.
    let value = |key: &str| {
        let start = text.find(&format!("{key}\0")).unwrap() + key.len();
        text.get(start..)
            .unwrap()
            .trim_start_matches('\0')
            .split('\0')
            .next()
            .unwrap()
            .to_owned()
    };
    assert_eq!(value("FileDescription"), "Hedwig icon");
    assert_eq!(value("ProductName"), "Hedwig");
    assert_eq!(value("CompanyName"), "Shuwari Africa");
    assert_eq!(value("OriginalFilename"), "hedwig-interface.exe");
    assert_eq!(value("FileVersion"), "0.2.0-alpha.1");
    assert_eq!(
        value("ProductVersion"),
        "0.2.0-alpha.1 (0123456789ab, modified)"
    );
    assert_eq!(
        value("LegalCopyright"),
        "Copyright (c) 2026 the Hedwig contributors"
    );
}
