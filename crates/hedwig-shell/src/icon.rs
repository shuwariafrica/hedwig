//! The notification-area icon.
//!
//! The shell's own surface, reached through `Shell_NotifyIconW` and nothing
//! else. The icon is identified by this process's window and a number: the
//! shell keeps the person's choice to show or hide it against the
//! executable's path either way, and a registered identifier would refuse to
//! be added at all from a path that moved until the executable is signed.

use std::ffi::c_void;
use std::io;

use hedwig_view::paint::Canvas;
use windows_sys::Win32::Foundation::RECT;
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
    DeleteObject, HBITMAP,
};
use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIIF_INFO, NIIF_RESPECT_QUIET_TIME,
    NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFYICON_VERSION_4, NOTIFYICONDATAW,
    NOTIFYICONIDENTIFIER, Shell_NotifyIconGetRect, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateIconIndirect, DestroyIcon, FindWindowW, HICON, ICONINFO, SM_CXSMICON,
};

use crate::host::{CALLBACK, Host};
use crate::raw::{field, last, size, wide};

/// The icon's number within its window.
const ID: u32 = 1;

/// What an add of the icon gives the shell.
const ICON_ADD: u32 = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;

/// Whether a notification waits for a quiet moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nudge {
    /// Something to look at: Windows drops it while the person has asked not
    /// to be disturbed, and the icon still says it.
    Quiet,
    /// Something is held for the person: Windows shows or keeps it by its own
    /// rules.
    Now,
}

/// An icon handle made from a picture, destroyed when dropped.
#[derive(Debug)]
pub struct Image(HICON);

/// A bitmap of this module's own, deleted when dropped.
struct Bitmap(HBITMAP);

impl Drop for Bitmap {
    fn drop(&mut self) {
        // SAFETY: the bitmap is this value's own and selected nowhere.
        unsafe { DeleteObject(self.0) };
    }
}

impl Image {
    /// The picture as an icon: its colours and alpha as they are, and an
    /// empty mask, which Windows does not read where a colour bitmap has an
    /// alpha channel.
    ///
    /// # Errors
    ///
    /// Windows refused a bitmap or the icon.
    pub fn of(picture: &Canvas) -> io::Result<Image> {
        let width = i32::try_from(picture.width).map_err(io::Error::other)?;
        let height = i32::try_from(picture.height).map_err(io::Error::other)?;
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
        let mut bits: *mut c_void = std::ptr::null_mut();
        // SAFETY: the header is complete, `bits` a valid place, and no
        // context is needed for a section of RGB colours.
        let colour = unsafe {
            CreateDIBSection(
                std::ptr::null_mut(),
                &raw const header,
                DIB_RGB_COLORS,
                &raw mut bits,
                std::ptr::null_mut(),
                0,
            )
        };
        if colour.is_null() || bits.is_null() {
            return last();
        }
        let colour = Bitmap(colour);
        let pixels: Vec<u32> = (0..picture.height)
            .flat_map(|y| (0..picture.width).map(move |x| (x, y)))
            .map(|(x, y)| {
                picture.at(x, y).map_or(0, |(rgb, alpha)| {
                    u32::from_be_bytes([alpha, rgb.red, rgb.green, rgb.blue])
                })
            })
            .collect();
        // SAFETY: the section holds width by height 32-bit pixels, the count
        // of `pixels`, and nothing else writes it.
        unsafe {
            std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u32>(), pixels.len());
        }
        // A one-bit mask, its rows a whole number of 16-bit words, all clear.
        let stride = picture.width.div_ceil(16) * 2;
        let mask_bits = vec![0_u8; stride * picture.height];
        // SAFETY: `mask_bits` holds every row of a one-bit bitmap of this size.
        let mask = unsafe { CreateBitmap(width, height, 1, 1, mask_bits.as_ptr().cast()) };
        if mask.is_null() {
            return last();
        }
        let mask = Bitmap(mask);
        let info = ICONINFO {
            fIcon: 1,
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask.0,
            hbmColor: colour.0,
        };
        // SAFETY: both bitmaps are alive; Windows copies them into the icon.
        let icon = unsafe { CreateIconIndirect(&raw const info) };
        if icon.is_null() {
            return last();
        }
        Ok(Image(icon))
    }

    pub fn handle(&self) -> HICON {
        self.0
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        // SAFETY: the icon is this value's own; the shell keeps a copy of
        // what it was given.
        unsafe { DestroyIcon(self.0) };
    }
}

/// An icon in the notification area, removed when this value is dropped.
#[derive(Debug)]
pub struct Icon<'a> {
    host: &'a Host,
    image: Image,
}

fn data(host: &Host) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: size::<NOTIFYICONDATAW>(),
        hWnd: host.window(),
        uID: ID,
        ..NOTIFYICONDATAW::default()
    }
}

/// The side, in pixels, of the icon the notification area draws on the
/// monitor `host` is on: Windows' small icon at that monitor's scale.
pub fn side(host: &Host) -> usize {
    // SAFETY: the window is alive for as long as `host` is.
    let dpi = unsafe { GetDpiForWindow(host.window()) };
    // SAFETY: no pointers; an unknown metric answers zero.
    let side = unsafe { GetSystemMetricsForDpi(SM_CXSMICON, dpi) };
    usize::try_from(side)
        .ok()
        .filter(|side| *side > 0)
        .unwrap_or(16)
}

/// Whether the shell's taskbar is there to take an icon.
pub fn taskbar() -> bool {
    let class = wide("Shell_TrayWnd");
    // SAFETY: the class name is NUL-terminated; no title is matched.
    !unsafe { FindWindowW(class.as_ptr(), std::ptr::null()) }.is_null()
}

fn notify(message: u32, data: &NOTIFYICONDATAW) -> io::Result<()> {
    // SAFETY: `data` is a complete structure of the size it states.
    if unsafe { Shell_NotifyIconW(message, data) } == 0 {
        return last();
    }
    Ok(())
}

impl<'a> Icon<'a> {
    /// Adds the icon named `name` showing `picture`, its tooltip then saying
    /// `tip`.
    ///
    /// The shell keeps the tooltip an icon is added with as its name - in
    /// its list of notification icons (`InitialTooltip`) and before the
    /// current tooltip in what it tells assistive technology - so `name` is
    /// what stays true of the icon, never a state.
    ///
    /// # Errors
    ///
    /// The shell refused it: a session with no taskbar, one whose taskbar
    /// is not yet up, or one too busy to answer in time. An icon the shell
    /// kept although it refused is taken away, so that the next add is the
    /// one icon there.
    pub fn add(host: &'a Host, name: &str, tip: &str, picture: &Canvas) -> io::Result<Icon<'a>> {
        let image = Image::of(picture)?;
        let mut added = data(host);
        added.uFlags = ICON_ADD;
        added.uCallbackMessage = CALLBACK;
        added.hIcon = image.handle();
        added.szTip = field(name);
        if let Err(refused) = notify(NIM_ADD, &added) {
            let _ = notify(NIM_DELETE, &data(host));
            return Err(refused);
        }
        let icon = Icon { host, image };
        let mut version = data(host);
        version.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        notify(NIM_SETVERSION, &version)?;
        icon.say(tip)?;
        Ok(icon)
    }

    /// Shows `picture` in place of what the icon showed.
    ///
    /// # Errors
    ///
    /// Windows refused the icon, or the shell refused it; the icon keeps
    /// what it showed.
    pub fn show(&mut self, picture: &Canvas) -> io::Result<()> {
        let image = Image::of(picture)?;
        let mut changed = data(self.host);
        changed.uFlags = NIF_ICON;
        changed.hIcon = image.handle();
        notify(NIM_MODIFY, &changed)?;
        self.image = image;
        Ok(())
    }

    /// Changes what the tooltip says.
    pub fn say(&self, tip: &str) -> io::Result<()> {
        let mut changed = data(self.host);
        changed.uFlags = NIF_TIP | NIF_SHOWTIP;
        changed.szTip = field(tip);
        notify(NIM_MODIFY, &changed)
    }

    /// Raises a notification through the icon, which Windows shows as it
    /// shows any other.
    pub fn nudge(&self, title: &str, text: &str, when: Nudge) -> io::Result<()> {
        let mut raised = data(self.host);
        raised.uFlags = NIF_INFO;
        raised.szInfoTitle = field(title);
        raised.szInfo = field(text);
        raised.dwInfoFlags = match when {
            Nudge::Quiet => NIIF_INFO | NIIF_RESPECT_QUIET_TIME,
            Nudge::Now => NIIF_INFO,
        };
        notify(NIM_MODIFY, &raised)
    }

    /// Where the icon is on the screen, for placing what it opens.
    pub fn place(&self) -> Option<(i32, i32, i32, i32)> {
        let identifier = NOTIFYICONIDENTIFIER {
            cbSize: size::<NOTIFYICONIDENTIFIER>(),
            hWnd: self.host.window(),
            uID: ID,
            ..NOTIFYICONIDENTIFIER::default()
        };
        let mut place = RECT::default();
        // SAFETY: both structures are complete and live for the call.
        let found = unsafe { Shell_NotifyIconGetRect(&raw const identifier, &raw mut place) };
        (found >= 0).then_some((place.left, place.top, place.right, place.bottom))
    }
}

impl Drop for Icon<'_> {
    fn drop(&mut self) {
        let _ = notify(NIM_DELETE, &data(self.host));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use hedwig_view::emblem::{Badge, Emblem, Owl};

    use super::{CALLBACK, ICON_ADD, Icon, Image, data, notify, side};
    use crate::host::Host;

    /// An add the shell makes after refusing it - as it does when it answers
    /// too late - leaves an icon nothing owns, and every later add of the
    /// same icon is refused. The refusal takes it away, so the next add is
    /// made, and is the one icon there.
    #[test]
    #[ignore = "needs the desktop's foreground"]
    fn an_icon_the_shell_kept_after_refusing_its_add_is_taken_away() {
        assert!(
            crate::desk::interactive() && super::taskbar(),
            "needs the desktop's foreground"
        );
        let host = Host::new().unwrap();
        let picture = Emblem {
            owl: Owl::Dozing,
            badge: Badge::Nothing,
        }
        .draw(side(&host), crate::settings::ink());
        // The icon the shell kept: added, and owned by nothing.
        let image = Image::of(&picture).unwrap();
        let mut kept = data(&host);
        kept.uFlags = ICON_ADD;
        kept.uCallbackMessage = CALLBACK;
        kept.hIcon = image.handle();
        kept.szTip = crate::raw::field("hedwig probe kept");
        notify(windows_sys::Win32::UI::Shell::NIM_ADD, &kept).unwrap();
        let refused = Icon::add(&host, "hedwig probe", "hedwig probe", &picture);
        println!("an add over an icon the shell kept: {refused:?}");
        assert!(
            refused.is_err(),
            "the shell refuses a second add of one icon"
        );
        let icon = Icon::add(&host, "hedwig probe", "hedwig probe", &picture)
            .expect("added once the kept one is taken away");
        assert!(icon.place().is_some());
    }
}
