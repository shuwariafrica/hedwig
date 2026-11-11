//! Direct2D effects as `Windows.UI.Composition` takes a graph of them.
//!
//! The compositor reads a graph through `IGraphicsEffectD2D1Interop`: each
//! node names a Direct2D effect, its properties as the Windows Runtime's
//! values and its sources, which are other nodes or named parameters filled
//! in by a brush. WinUI's nodes are classes of its own; these are this
//! crate's, immutable once made and counted atomically, so any thread may
//! hold them.

use std::ffi::c_void;
use std::io;
use std::mem::offset_of;
use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::core::{GUID, HRESULT, HSTRING};

use crate::com::{Com, Object, check};

// The Windows Runtime's activation factories and strings, from the library
// Windows resolves them from.
#[link(name = "combase.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    #[link_name = "RoGetActivationFactory"]
    fn activation_factory(class: HSTRING, interface: *const GUID, factory: *mut Object) -> HRESULT;
    #[link_name = "WindowsCreateString"]
    fn create_string(source: *const u16, length: u32, string: *mut HSTRING) -> HRESULT;
    #[link_name = "WindowsDeleteString"]
    fn delete_string(string: HSTRING) -> HRESULT;
}

const UNKNOWN: GUID = GUID::from_u128(0x0000_0000_0000_0000_c000_0000_0000_0046);
const INSPECTABLE: GUID = GUID::from_u128(0xaf86_e2e0_b12d_4c6a_9c5a_d7aa_6510_1e90);
/// `IAgileObject`: what is immutable and atomically counted may be called
/// from any thread.
const AGILE: GUID = GUID::from_u128(0x94ea_2b94_e9cc_49e0_c0ff_ee64_ca8f_5b90);
/// `Windows.Graphics.Effects.IGraphicsEffect` and `IGraphicsEffectSource`.
const GRAPHICS_EFFECT: GUID = GUID::from_u128(0xcb51_c0ce_8fe6_4636_b202_861f_aa07_d8f3);
const GRAPHICS_EFFECT_SOURCE: GUID = GUID::from_u128(0x2d8f_9ddc_4339_4eb9_9216_f9de_b756_58a2);
/// `IGraphicsEffectD2D1Interop` (`windows.graphics.effects.interop.h`).
const D2D1_INTEROP: GUID = GUID::from_u128(0x2fc5_7384_a068_44d7_a331_3098_2fcf_7177);
/// `Windows.Foundation.IPropertyValueStatics`.
const PROPERTY_VALUE_STATICS: GUID = GUID::from_u128(0x629b_dbc8_d932_4ff4_96b9_8d96_c5c1_e858);
/// `Windows.UI.Composition.ICompositionEffectSourceParameterFactory`.
const SOURCE_PARAMETER_FACTORY: GUID = GUID::from_u128(0xb3d9_f276_aba3_4724_acf3_d039_7464_db1c);

const NO_INTERFACE: HRESULT = 0x8000_4002_u32.cast_signed();
const INVALID_ARGUMENT: HRESULT = 0x8007_0057_u32.cast_signed();
const POINTER: HRESULT = 0x8000_4003_u32.cast_signed();

/// The first slot of a Windows Runtime interface's own methods: after
/// `IUnknown`'s three and `IInspectable`'s three.
const OWN: usize = 6;
// `IPropertyValueStatics`, in the order of `windows.foundation.h`.
const CREATE_UINT32: usize = OWN + 5;
const CREATE_SINGLE: usize = OWN + 8;
const CREATE_SINGLE_ARRAY: usize = OWN + 27;

// Direct2D's built-in effects (`d2d1effects.h`) and the indices and values
// of the properties used here.
pub(crate) const FLOOD: GUID = GUID::from_u128(0x61c2_3c20_ae69_4d8e_94cf_5007_8df6_38f2);
pub(crate) const BLEND: GUID = GUID::from_u128(0x81c5_b77b_13f8_4cdd_ad20_c890_547a_c65d);
pub(crate) const COMPOSITE: GUID = GUID::from_u128(0x48fc_9f51_f6ac_48f1_8b58_3b28_ac46_f76d);
pub(crate) const BORDER: GUID = GUID::from_u128(0x2a2d_49c0_4acf_43c7_8c6a_7c4a_2787_4d27);
pub(crate) const OPACITY: GUID = GUID::from_u128(0x811d_79a4_de28_4454_8094_c646_85f8_bd4c);
pub(crate) const BLEND_MODE_COLOR: u32 = 22;
pub(crate) const BLEND_MODE_LUMINOSITY: u32 = 23;
pub(crate) const COMPOSITE_SOURCE_OVER: u32 = 0;
pub(crate) const BORDER_WRAP: u32 = 1;

fn same(one: &GUID, other: &GUID) -> bool {
    one.data1 == other.data1
        && one.data2 == other.data2
        && one.data3 == other.data3
        && one.data4 == other.data4
}

/// A string the Windows Runtime reads, deleted when dropped.
pub(crate) struct Text(HSTRING);

impl Text {
    pub(crate) fn new(text: &str) -> io::Result<Text> {
        let units: Vec<u16> = text.encode_utf16().collect();
        let length = u32::try_from(units.len()).map_err(io::Error::other)?;
        let mut made: HSTRING = std::ptr::null_mut();
        // SAFETY: the units outlive the call, which copies them.
        check(unsafe { create_string(units.as_ptr(), length, &raw mut made) })?;
        Ok(Text(made))
    }

    pub(crate) fn handle(&self) -> HSTRING {
        self.0
    }
}

impl Drop for Text {
    fn drop(&mut self) {
        // SAFETY: the string is this value's own and not used after.
        unsafe { delete_string(self.0) };
    }
}

/// An activation factory or statics object of a Windows Runtime class.
pub(crate) fn factory(class: &str, interface: &GUID) -> io::Result<Com> {
    let class = Text::new(class)?;
    let mut found = std::ptr::null_mut();
    // SAFETY: the name is a live string and both pointers valid for the call.
    let result = unsafe { activation_factory(class.handle(), interface, &raw mut found) };
    Com::taken(result, found)
}

/// A value of a property, as Direct2D types it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Value {
    UInt32(u32),
    Single(f32),
    /// A colour, red, green, blue and alpha from 0 to 1, unmultiplied.
    Vector4([f32; 4]),
}

/// What makes effects and their sources: the Windows Runtime's values and the
/// compositor's named parameters.
pub(crate) struct Maker {
    values: Com,
    parameters: Com,
}

impl Maker {
    pub(crate) fn new() -> io::Result<Maker> {
        Ok(Maker {
            values: factory("Windows.Foundation.PropertyValue", &PROPERTY_VALUE_STATICS)?,
            parameters: factory(
                "Windows.UI.Composition.CompositionEffectSourceParameter",
                &SOURCE_PARAMETER_FACTORY,
            )?,
        })
    }

    fn value(&self, value: Value) -> io::Result<Com> {
        let mut made = std::ptr::null_mut();
        let result = match value {
            Value::UInt32(number) => {
                type Create = unsafe extern "system" fn(Object, u32, *mut Object) -> HRESULT;
                // SAFETY: `CreateUInt32` is at this place with this signature.
                let create: Create = unsafe { self.values.slot(CREATE_UINT32) };
                // SAFETY: the statics object is alive; the place is valid.
                unsafe { create(self.values.object(), number, &raw mut made) }
            }
            Value::Single(number) => {
                type Create = unsafe extern "system" fn(Object, f32, *mut Object) -> HRESULT;
                // SAFETY: `CreateSingle` is at this place with this signature.
                let create: Create = unsafe { self.values.slot(CREATE_SINGLE) };
                // SAFETY: as above.
                unsafe { create(self.values.object(), number, &raw mut made) }
            }
            Value::Vector4(numbers) => {
                type Create =
                    unsafe extern "system" fn(Object, u32, *const f32, *mut Object) -> HRESULT;
                // SAFETY: `CreateSingleArray` is at this place with this
                // signature.
                let create: Create = unsafe { self.values.slot(CREATE_SINGLE_ARRAY) };
                // SAFETY: the four numbers outlive the call, which copies them.
                unsafe { create(self.values.object(), 4, numbers.as_ptr(), &raw mut made) }
            }
        };
        Com::taken(result, made)
    }

    /// A source the brush fills in by `name`.
    pub(crate) fn parameter(&self, name: &str) -> io::Result<Com> {
        type Create = unsafe extern "system" fn(Object, HSTRING, *mut Object) -> HRESULT;
        let name = Text::new(name)?;
        // SAFETY: `Create` is the factory's first method.
        let create: Create = unsafe { self.parameters.slot(OWN) };
        let mut made = std::ptr::null_mut();
        // SAFETY: the factory and the string are alive for the call.
        let result = unsafe { create(self.parameters.object(), name.handle(), &raw mut made) };
        Com::taken(result, made)?.query(&GRAPHICS_EFFECT_SOURCE)
    }

    /// The Direct2D effect `id` with `properties` in their indices' order,
    /// over `sources` in their inputs' order.
    pub(crate) fn effect(
        &self,
        id: GUID,
        properties: &[Value],
        sources: Vec<Com>,
    ) -> io::Result<Com> {
        let properties = properties
            .iter()
            .map(|value| self.value(*value))
            .collect::<io::Result<Vec<_>>>()?;
        let effect = Box::new(Effect {
            table: &EFFECT,
            interop: &INTEROP,
            count: AtomicU32::new(1),
            id,
            properties,
            sources,
        });
        let object = Box::into_raw(effect).cast::<c_void>();
        Com::new(object).ok_or_else(|| io::Error::other("no effect"))
    }
}

/// One node of a graph, answering two interfaces from two tables.
#[repr(C)]
struct Effect {
    /// `IGraphicsEffect`, which also serves as `IGraphicsEffectSource`, whose
    /// table it begins with.
    table: &'static EffectTable,
    interop: &'static InteropTable,
    count: AtomicU32,
    id: GUID,
    properties: Vec<Com>,
    sources: Vec<Com>,
}

type Method<A> = unsafe extern "system" fn(Object, A) -> HRESULT;

#[repr(C)]
struct Unknown {
    query: unsafe extern "system" fn(Object, *const GUID, *mut Object) -> HRESULT,
    add: unsafe extern "system" fn(Object) -> u32,
    release: unsafe extern "system" fn(Object) -> u32,
}

#[repr(C)]
struct EffectTable {
    unknown: Unknown,
    iids: unsafe extern "system" fn(Object, *mut u32, *mut *mut GUID) -> HRESULT,
    class_name: Method<*mut HSTRING>,
    trust: Method<*mut i32>,
    name: Method<*mut HSTRING>,
    set_name: Method<HSTRING>,
}

#[repr(C)]
struct InteropTable {
    unknown: Unknown,
    effect_id: Method<*mut GUID>,
    mapping: unsafe extern "system" fn(Object, *const u16, *mut u32, *mut i32) -> HRESULT,
    property_count: Method<*mut u32>,
    property: unsafe extern "system" fn(Object, u32, *mut Object) -> HRESULT,
    source: unsafe extern "system" fn(Object, u32, *mut Object) -> HRESULT,
    source_count: Method<*mut u32>,
}

static EFFECT: EffectTable = EffectTable {
    unknown: Unknown {
        query: query_effect,
        add: add_effect,
        release: release_effect,
    },
    iids,
    class_name,
    trust,
    name,
    set_name,
};

static INTEROP: InteropTable = InteropTable {
    unknown: Unknown {
        query: query_interop,
        add: add_interop,
        release: release_interop,
    },
    effect_id,
    mapping,
    property_count,
    property,
    source,
    source_count,
};

/// The node behind an `IGraphicsEffect` pointer.
///
/// # Safety
///
/// `this` is a pointer this module gave out for the node's first table, and
/// the node is alive.
unsafe fn from_effect<'a>(this: Object) -> &'a Effect {
    // SAFETY: the first table is the node's first field.
    unsafe { &*this.cast::<Effect>() }
}

/// The node behind an `IGraphicsEffectD2D1Interop` pointer.
///
/// # Safety
///
/// As `from_effect`, for the second table.
unsafe fn from_interop<'a>(this: Object) -> &'a Effect {
    // SAFETY: the second table is the node's `interop` field.
    let node = unsafe { this.byte_sub(offset_of!(Effect, interop)) };
    // SAFETY: the caller vouches the node is alive.
    unsafe { &*node.cast::<Effect>() }
}

/// Answers `interface` from `node`.
///
/// # Safety
///
/// `node` is alive and was boxed by this module; `out` is valid to write.
unsafe fn answer(node: &Effect, interface: *const GUID, out: *mut Object) -> HRESULT {
    if out.is_null() {
        return POINTER;
    }
    // SAFETY: the caller's interface identifier is valid to read.
    let wanted = unsafe { &*interface };
    let pointer: Object = if [
        UNKNOWN,
        INSPECTABLE,
        GRAPHICS_EFFECT,
        GRAPHICS_EFFECT_SOURCE,
        AGILE,
    ]
    .iter()
    .any(|known| same(known, wanted))
    {
        std::ptr::from_ref(&node.table).cast_mut().cast()
    } else if same(&D2D1_INTEROP, wanted) {
        std::ptr::from_ref(&node.interop).cast_mut().cast()
    } else {
        // SAFETY: the caller vouches `out` may be written.
        unsafe { out.write(std::ptr::null_mut()) };
        return NO_INTERFACE;
    };
    node.count.fetch_add(1, Ordering::Relaxed);
    // SAFETY: as above.
    unsafe { out.write(pointer) };
    0
}

/// Counts one reference less, and frees the node with the last.
///
/// # Safety
///
/// `node` was boxed by this module and the caller's reference is counted.
unsafe fn let_go(node: &Effect) -> u32 {
    let left = node.count.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: the last reference is gone, so nothing else reads the node;
        // it was made by `Box::into_raw`.
        drop(unsafe { Box::from_raw(std::ptr::from_ref(node).cast_mut()) });
    }
    left
}

unsafe extern "system" fn query_effect(
    this: Object,
    interface: *const GUID,
    out: *mut Object,
) -> HRESULT {
    // SAFETY: Windows calls through the first table with its pointer.
    let node = unsafe { from_effect(this) };
    // SAFETY: the node is alive; the caller's pointers are valid.
    unsafe { answer(node, interface, out) }
}

unsafe extern "system" fn add_effect(this: Object) -> u32 {
    // SAFETY: as in `query_effect`.
    let node = unsafe { from_effect(this) };
    node.count.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn release_effect(this: Object) -> u32 {
    // SAFETY: as in `query_effect`.
    let node = unsafe { from_effect(this) };
    // SAFETY: the caller's reference is counted.
    unsafe { let_go(node) }
}

unsafe extern "system" fn query_interop(
    this: Object,
    interface: *const GUID,
    out: *mut Object,
) -> HRESULT {
    // SAFETY: Windows calls through the second table with its pointer.
    let node = unsafe { from_interop(this) };
    // SAFETY: as in `query_effect`.
    unsafe { answer(node, interface, out) }
}

unsafe extern "system" fn add_interop(this: Object) -> u32 {
    // SAFETY: as in `query_interop`.
    let node = unsafe { from_interop(this) };
    node.count.fetch_add(1, Ordering::Relaxed) + 1
}

unsafe extern "system" fn release_interop(this: Object) -> u32 {
    // SAFETY: as in `query_interop`.
    let node = unsafe { from_interop(this) };
    // SAFETY: the caller's reference is counted.
    unsafe { let_go(node) }
}

unsafe extern "system" fn iids(_: Object, count: *mut u32, list: *mut *mut GUID) -> HRESULT {
    if count.is_null() || list.is_null() {
        return POINTER;
    }
    // SAFETY: both places are the caller's to have written; an empty list
    // needs no allocation for the caller to free.
    unsafe { count.write(0) };
    // SAFETY: as above.
    unsafe { list.write(std::ptr::null_mut()) };
    0
}

unsafe extern "system" fn class_name(_: Object, name: *mut HSTRING) -> HRESULT {
    if name.is_null() {
        return POINTER;
    }
    // SAFETY: the place is the caller's; a null string is the empty one.
    unsafe { name.write(std::ptr::null_mut()) };
    0
}

unsafe extern "system" fn trust(_: Object, level: *mut i32) -> HRESULT {
    if level.is_null() {
        return POINTER;
    }
    // SAFETY: the place is the caller's; `BaseTrust`.
    unsafe { level.write(0) };
    0
}

unsafe extern "system" fn name(_: Object, name: *mut HSTRING) -> HRESULT {
    // A node needs a name only for a property animated by name, and none is.
    // SAFETY: as in `class_name`.
    unsafe { class_name(std::ptr::null_mut(), name) }
}

unsafe extern "system" fn set_name(_: Object, _: HSTRING) -> HRESULT {
    0
}

unsafe extern "system" fn effect_id(this: Object, id: *mut GUID) -> HRESULT {
    if id.is_null() {
        return POINTER;
    }
    // SAFETY: as in `query_interop`.
    let node = unsafe { from_interop(this) };
    // SAFETY: the place is the caller's.
    unsafe { id.write(node.id) };
    0
}

unsafe extern "system" fn mapping(_: Object, _: *const u16, _: *mut u32, _: *mut i32) -> HRESULT {
    // No property is known by name: none is animated.
    INVALID_ARGUMENT
}

unsafe extern "system" fn property_count(this: Object, count: *mut u32) -> HRESULT {
    if count.is_null() {
        return POINTER;
    }
    // SAFETY: as in `query_interop`.
    let node = unsafe { from_interop(this) };
    // SAFETY: the place is the caller's.
    unsafe { count.write(u32::try_from(node.properties.len()).unwrap_or_default()) };
    0
}

/// Gives the caller a counted reference to the `index`th of `list`.
///
/// # Safety
///
/// `out` is valid to write.
unsafe fn give(list: &[Com], index: u32, out: *mut Object) -> HRESULT {
    if out.is_null() {
        return POINTER;
    }
    let Some(found) = usize::try_from(index)
        .ok()
        .and_then(|index| list.get(index))
    else {
        // SAFETY: the caller vouches `out` may be written.
        unsafe { out.write(std::ptr::null_mut()) };
        return INVALID_ARGUMENT;
    };
    // SAFETY: as above; the reference given is counted by `share`.
    unsafe { out.write(found.share().into_raw()) };
    0
}

unsafe extern "system" fn property(this: Object, index: u32, value: *mut Object) -> HRESULT {
    // SAFETY: as in `query_interop`.
    let node = unsafe { from_interop(this) };
    // SAFETY: the caller's place is valid to write.
    unsafe { give(&node.properties, index, value) }
}

unsafe extern "system" fn source(this: Object, index: u32, value: *mut Object) -> HRESULT {
    // SAFETY: as in `query_interop`.
    let node = unsafe { from_interop(this) };
    // SAFETY: as in `property`.
    unsafe { give(&node.sources, index, value) }
}

unsafe extern "system" fn source_count(this: Object, count: *mut u32) -> HRESULT {
    if count.is_null() {
        return POINTER;
    }
    // SAFETY: as in `query_interop`.
    let node = unsafe { from_interop(this) };
    // SAFETY: the place is the caller's.
    unsafe { count.write(u32::try_from(node.sources.len()).unwrap_or_default()) };
    0
}
