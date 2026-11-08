//! A moment as the person's Windows writes one: their time zone, their short
//! date and their time without seconds.

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::Globalization::{
    DATE_SHORTDATE, GetDateFormatEx, GetTimeFormatEx, TIME_NOSECONDS,
};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTimeEx};

/// Milliseconds from 1601, where a file time starts, to 1970.
const EPOCH: u64 = 11_644_473_600_000;

/// `milliseconds` since the Unix epoch, UTC, written as Windows writes a
/// date and a time for this person. Empty where Windows cannot write it.
pub fn written(milliseconds: u64) -> String {
    let ticks = milliseconds.saturating_add(EPOCH).saturating_mul(10_000);
    let file = FILETIME {
        dwLowDateTime: u32::try_from(ticks & 0xffff_ffff).unwrap_or_default(),
        dwHighDateTime: u32::try_from(ticks >> 32).unwrap_or_default(),
    };
    let mut universal = SYSTEMTIME::default();
    // SAFETY: both structures are valid for the call.
    if unsafe { FileTimeToSystemTime(&raw const file, &raw mut universal) } == 0 {
        return String::new();
    }
    let mut local = SYSTEMTIME::default();
    // SAFETY: a null zone is the person's current one; both structures are
    // valid.
    let converted = unsafe {
        SystemTimeToTzSpecificLocalTimeEx(std::ptr::null(), &raw const universal, &raw mut local)
    };
    if converted == 0 {
        return String::new();
    }
    let mut date = [0u16; 128];
    let mut time = [0u16; 128];
    // SAFETY: a null locale is the person's; the buffer's length is given.
    let dated = unsafe {
        GetDateFormatEx(
            std::ptr::null(),
            DATE_SHORTDATE,
            &raw const local,
            std::ptr::null(),
            date.as_mut_ptr(),
            128,
            std::ptr::null(),
        )
    };
    // SAFETY: as above.
    let timed = unsafe {
        GetTimeFormatEx(
            std::ptr::null(),
            TIME_NOSECONDS,
            &raw const local,
            std::ptr::null(),
            time.as_mut_ptr(),
            128,
        )
    };
    let text = |units: &[u16], length: i32| {
        let length = usize::try_from(length.saturating_sub(1)).unwrap_or_default();
        String::from_utf16_lossy(units.get(..length).unwrap_or_default())
    };
    match (dated > 0, timed > 0) {
        (true, true) => format!("{} {}", text(&date, dated), text(&time, timed)),
        (true, false) => text(&date, dated),
        _ => String::new(),
    }
}
