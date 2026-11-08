//! Shared by the suites that check an icon as Windows draws it: what
//! Windows draws of an icon handle over a ground, and what the view meant.

use std::ffi::c_void;

use hedwig_view::paint::Canvas;
use hedwig_view::style::Rgb;
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
    DeleteDC, DeleteObject, GdiFlush, SelectObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{DI_NORMAL, DrawIconEx, HICON};

/// What Windows draws of `icon`, `side` pixels square, over `ground`.
pub(crate) fn drawn(icon: HICON, side: usize, ground: Rgb) -> Vec<Rgb> {
    let edge = i32::try_from(side).unwrap();
    let header = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: u32::try_from(size_of::<BITMAPINFOHEADER>()).unwrap(),
            biWidth: edge,
            biHeight: -edge,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..BITMAPINFOHEADER::default()
        },
        ..BITMAPINFO::default()
    };
    // SAFETY: a context of this test's own, let go below.
    let dc = unsafe { CreateCompatibleDC(std::ptr::null_mut()) };
    let mut bits: *mut c_void = std::ptr::null_mut();
    // SAFETY: the header is complete and `bits` a valid place.
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
    assert!(!bitmap.is_null());
    // SAFETY: the bitmap is this test's own; it is deselected below.
    let was = unsafe { SelectObject(dc, bitmap) };
    let count = side * side;
    // SAFETY: the section holds `count` pixels, written only here.
    let pixels = unsafe { std::slice::from_raw_parts_mut(bits.cast::<u32>(), count) };
    let fill = u32::from_be_bytes([0, ground.red, ground.green, ground.blue]);
    pixels.fill(fill);
    // SAFETY: the icon and the context are alive.
    let done = unsafe {
        DrawIconEx(
            dc,
            0,
            0,
            icon,
            edge,
            edge,
            0,
            std::ptr::null_mut(),
            DI_NORMAL,
        )
    };
    assert_ne!(done, 0, "Windows drew the icon");
    // SAFETY: no arguments; GDI finishes what it was drawing.
    unsafe { GdiFlush() };
    let read: Vec<Rgb> = pixels
        .iter()
        .map(|pixel| {
            let [_, red, green, blue] = pixel.to_be_bytes();
            Rgb::new(red, green, blue)
        })
        .collect();
    // SAFETY: the context's own bitmap goes back before both are let go.
    unsafe {
        SelectObject(dc, was);
    }
    // SAFETY: as above.
    unsafe {
        DeleteObject(bitmap);
    }
    // SAFETY: as above.
    unsafe {
        DeleteDC(dc);
    }
    read
}

/// The picture laid over `ground` as the view means it: each colour at its
/// alpha.
pub(crate) fn meant(picture: &Canvas, ground: Rgb) -> Vec<Rgb> {
    (0..picture.height)
        .flat_map(|y| (0..picture.width).map(move |x| (x, y)))
        .map(|(x, y)| {
            let (colour, alpha) = picture.at(x, y).unwrap();
            let mix = |top: u8, under: u8| {
                let sum = u32::from(top) * u32::from(alpha)
                    + u32::from(under) * (255 - u32::from(alpha))
                    + 127;
                u8::try_from(sum / 255).unwrap()
            };
            Rgb::new(
                mix(colour.red, ground.red),
                mix(colour.green, ground.green),
                mix(colour.blue, ground.blue),
            )
        })
        .collect()
}

/// Whether two pictures agree to within 2 in every channel, and where first
/// they do not.
pub(crate) fn agree(got: &[Rgb], want: &[Rgb]) -> Result<(), String> {
    match got.iter().zip(want).position(|(got, want)| {
        got.red.abs_diff(want.red) > 2
            || got.green.abs_diff(want.green) > 2
            || got.blue.abs_diff(want.blue) > 2
    }) {
        Some(at) => Err(format!(
            "at {at}: {:?}, meant {:?}",
            got.get(at),
            want.get(at)
        )),
        None => Ok(()),
    }
}
