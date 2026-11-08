//! A reference to a COM object, and a call through its table by place: the
//! interfaces the shell uses that `windows-sys` does not declare.

use std::ffi::c_void;
use std::io;

use windows_sys::core::{GUID, HRESULT};

pub(crate) type Object = *mut c_void;

/// A failed call as an error, its `HRESULT` kept.
pub(crate) fn check(result: HRESULT) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::from_raw_os_error(result))
    } else {
        Ok(())
    }
}

/// A reference this crate holds to a COM object, released when dropped.
pub(crate) struct Com(Object);

impl Com {
    pub(crate) fn new(object: Object) -> Option<Com> {
        (!object.is_null()).then_some(Com(object))
    }

    /// The reference a call answered with, where it succeeded and gave one.
    pub(crate) fn taken(result: HRESULT, object: Object) -> io::Result<Com> {
        check(result)?;
        Com::new(object).ok_or_else(|| io::Error::other("Windows answered success and no object"))
    }

    pub(crate) fn object(&self) -> Object {
        self.0
    }

    /// The function at `index` of the object's table.
    ///
    /// # Safety
    ///
    /// The object's interface has an entry at `index`, and `F` is its exact
    /// signature.
    pub(crate) unsafe fn slot<F: Copy>(&self, index: usize) -> F {
        // SAFETY: a COM object begins with a pointer to its table.
        let table = unsafe { *self.0.cast::<*const usize>() };
        // SAFETY: the caller names an entry the table has.
        let place = unsafe { table.add(index) };
        // SAFETY: as above; the entry is a function's address.
        let function = unsafe { *place };
        // SAFETY: the caller names the entry's signature, the size of a
        // pointer.
        unsafe { std::mem::transmute_copy::<usize, F>(&function) }
    }

    /// The object's `interface`, as a reference of its own.
    pub(crate) fn query(&self, interface: &GUID) -> io::Result<Com> {
        type Query = unsafe extern "system" fn(Object, *const GUID, *mut Object) -> HRESULT;
        // SAFETY: entry 0 of every table is `IUnknown::QueryInterface`.
        let query: Query = unsafe { self.slot(0) };
        let mut found = std::ptr::null_mut();
        // SAFETY: the object is alive and both pointers valid for the call.
        let result = unsafe { query(self.0, interface, &raw mut found) };
        Com::taken(result, found)
    }

    /// Another reference to the same object, counted.
    pub(crate) fn share(&self) -> Com {
        type AddRef = unsafe extern "system" fn(Object) -> u32;
        // SAFETY: entry 1 of every table is `IUnknown::AddRef`.
        let add: AddRef = unsafe { self.slot(1) };
        // SAFETY: the object is alive; the reference counted here is the
        // returned value's own.
        unsafe { add(self.0) };
        Com(self.0)
    }

    /// Gives this reference to the caller of a method that returns one.
    pub(crate) fn into_raw(self) -> Object {
        std::mem::ManuallyDrop::new(self).0
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: entry 2 of every table is `IUnknown::Release`.
        let release: unsafe extern "system" fn(Object) -> u32 = unsafe { self.slot(2) };
        // SAFETY: the reference is this value's own and is not used after.
        unsafe { release(self.0) };
    }
}
