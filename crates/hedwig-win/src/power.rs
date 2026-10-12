//! What Windows says when the workstation is about to sleep and when it has
//! woken.
//!
//! A process with no window is told by a call made on one of the system's
//! own threads. The registration here is made once and never withdrawn: the
//! function that is called, and what it is given, live as long as the
//! process, so no call can arrive for something that has been released.

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::System::Power::{
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND,
};

/// What Windows said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    /// The workstation is about to sleep. About two seconds remain.
    Sleeping,
    /// The workstation has woken. This is said on every wake, whether or not
    /// anyone is there.
    Woke,
}

impl Turn {
    /// The turn a power event stands for, if it is one of the two.
    pub fn from_event(event: u32) -> Option<Turn> {
        match event {
            PBT_APMSUSPEND => Some(Turn::Sleeping),
            PBT_APMRESUMEAUTOMATIC => Some(Turn::Woke),
            _ => None,
        }
    }
}

type Told = Box<dyn Fn(Turn) + Send + Sync>;

/// # Safety
///
/// `context` is the pointer [`watch`] registered: a `Told` that is never
/// freed.
unsafe extern "system" fn called(
    context: *const c_void,
    event: u32,
    _setting: *const c_void,
) -> u32 {
    // SAFETY: by this function's contract the pointer is to a live `Told`.
    let told = unsafe { &*context.cast::<Told>() };
    if let Some(turn) = Turn::from_event(event) {
        told(turn);
    }
    0
}

/// Has `told` called, for the rest of this process's life, each time the
/// workstation is about to sleep and each time it has woken. It is called on
/// a thread of the system's, so it should do no more than pass the word on.
pub fn watch(told: impl Fn(Turn) + Send + Sync + 'static) -> io::Result<()> {
    let told: Told = Box::new(told);
    let told: &'static Told = Box::leak(Box::new(told));
    let recipient: &'static DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS =
        Box::leak(Box::new(DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(called),
            Context: std::ptr::from_ref(told).cast_mut().cast(),
        }));
    let mut registration = std::ptr::null_mut();
    // SAFETY: `recipient` and what it points at are never freed, which is
    // what `called` requires; `registration` is a valid place for the handle,
    // which is kept by the system and never used here.
    let failed = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            std::ptr::from_ref(recipient).cast_mut().cast(),
            &raw mut registration,
        )
    };
    if failed != 0 {
        return Err(io::Error::from_raw_os_error(failed.cast_signed()));
    }
    Ok(())
}
