//! The clock Hedwig measures with.
//!
//! It keeps counting while the workstation is asleep, so a deadline the
//! person set - "allow this for fifteen minutes" - passes whether or not the
//! machine was awake for it. It cannot be set, by the person or by time
//! synchronisation.

use std::time::Duration;

use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

/// Time since Windows started, "including the time when the machine was in a
/// sleep state such as standby, hibernate, or connected standby": the
/// performance counter.
pub fn elapsed() -> Duration {
    let mut ticks = 0i64;
    let mut frequency = 0i64;
    // SAFETY: a valid out pointer; the call cannot fail on a supported
    // Windows.
    unsafe { QueryPerformanceCounter(&raw mut ticks) };
    // SAFETY: as above.
    unsafe { QueryPerformanceFrequency(&raw mut frequency) };
    let ticks = u128::from(ticks.cast_unsigned());
    let frequency = u128::from(frequency.cast_unsigned()).max(1);
    Duration::from_nanos(u64::try_from(ticks * 1_000_000_000 / frequency).unwrap_or(u64::MAX))
}
