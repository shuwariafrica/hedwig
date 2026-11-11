//! What Windows hints of whether the workstation reaches a network.
//!
//! The hint is Windows' own summary, told by a call on one of the system's
//! threads whenever it changes. Like [`crate::power`], the registration is
//! made once and never withdrawn, so no call can arrive for something that
//! has been released.

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::NetworkManagement::IpHelper::NotifyNetworkConnectivityHintChange;
use windows_sys::Win32::Networking::WinSock::{
    NL_NETWORK_CONNECTIVITY_HINT, NL_NETWORK_CONNECTIVITY_LEVEL_HINT,
    NetworkConnectivityLevelHintNone, NetworkConnectivityLevelHintUnknown,
};

/// What Windows hinted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Some network: the local one, the internet, or one Windows keeps to
    /// itself.
    Some,
    /// None at all.
    None,
}

impl Reach {
    /// The reach a connectivity level stands for; `None` for a level Windows
    /// says it does not know.
    pub fn from_level(level: NL_NETWORK_CONNECTIVITY_LEVEL_HINT) -> Option<Reach> {
        if level == NetworkConnectivityLevelHintUnknown {
            None
        } else if level == NetworkConnectivityLevelHintNone {
            Some(Reach::None)
        } else {
            Some(Reach::Some)
        }
    }
}

type Told = Box<dyn Fn(Reach) + Send + Sync>;

/// # Safety
///
/// `context` is the pointer [`watch`] registered: a `Told` that is never
/// freed.
unsafe extern "system" fn called(context: *const c_void, hint: NL_NETWORK_CONNECTIVITY_HINT) {
    // SAFETY: by this function's contract the pointer is to a live `Told`.
    let told = unsafe { &*context.cast::<Told>() };
    if let Some(reach) = Reach::from_level(hint.ConnectivityLevel) {
        told(reach);
    }
}

/// Has `told` called, for the rest of this process's life, with what Windows
/// hints now and each time that changes. It is called on a thread of the
/// system's, so it should do no more than pass the word on.
///
/// # Errors
///
/// What the system said when the registration was refused.
pub fn watch(told: impl Fn(Reach) + Send + Sync + 'static) -> io::Result<()> {
    let told: Told = Box::new(told);
    let told: &'static Told = Box::leak(Box::new(told));
    let mut registration = std::ptr::null_mut();
    // SAFETY: the context is a `Told` that is never freed, which is what
    // `called` requires; `registration` is a valid place for the handle,
    // which is kept by the system and never used here.
    let failed = unsafe {
        NotifyNetworkConnectivityHintChange(
            Some(called),
            std::ptr::from_ref(told).cast(),
            true,
            &raw mut registration,
        )
    };
    if failed != 0 {
        return Err(io::Error::from_raw_os_error(failed.cast_signed()));
    }
    Ok(())
}
