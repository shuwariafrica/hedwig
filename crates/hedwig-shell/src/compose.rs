//! The icon's menu composed as WinUI composes its menu flyout.
//!
//! A level is a window with no surface of its own, larger than the menu by
//! the room its shadow takes. `Windows.UI.Composition` draws everything in
//! it: WinUI's theme shadow in the menu's rounded shape beneath it; the menu,
//! clipped to WinUI's rounded corner; within it the
//! backdrop - acrylic as WinUI's recipe composes it over what is behind the
//! window, or the colour it falls back to - and over that the rows, a
//! picture `hedwig-view` computes, drawn onto a drawing surface by Direct2D
//! over a Direct3D device. What a menu opens is made when it opens and let
//! go, the libraries with it, when it closes.

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE, HWND, POINT, RECT};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::{GUID, HRESULT};

use hedwig_view::arrange::Rect;
use hedwig_view::menu::{CAST_WITHIN, Cast, Shadow};
use hedwig_view::paint::Canvas;
use hedwig_view::style::{Acrylic, Rgb, Tint};

use crate::com::{Com, Object, check};
use crate::effect::{self, Maker, Value};
use crate::raw::wide;

/// The first slot of a Windows Runtime interface's own methods.
const OWN: usize = 6;

// Interfaces, from `windows.ui.composition.h`, `windows.ui.composition.interop.h`
// and `d3d11.h` of the Windows SDK, 10.0.28000.0.
const ACTIVATION_FACTORY: GUID = GUID::from_u128(0x0000_0035_0000_0000_c000_0000_0000_0046);
const COMPOSITOR: GUID = GUID::from_u128(0xb403_ca50_7f8c_4e83_985f_cc45_0600_36d8);
const COMPOSITOR_2: GUID = GUID::from_u128(0x7350_81dc_5e24_45da_a38f_e32c_c349_a9a0);
const COMPOSITOR_3: GUID = GUID::from_u128(0xc9dd_8ef0_6eb1_4e3c_a658_675d_9c64_d4ab);
const COMPOSITOR_5: GUID = GUID::from_u128(0x48ea_31ad_7fcd_4076_a79c_90cc_4b85_2c9b);
const COMPOSITOR_6: GUID = GUID::from_u128(0x7a38_b2bd_cec8_4eeb_830f_d8d0_7aed_ebc3);
const DESKTOP_INTEROP: GUID = GUID::from_u128(0x29e6_91fa_4567_4dca_b319_d0f2_07eb_6807);
const COMPOSITOR_INTEROP: GUID = GUID::from_u128(0x2529_7d5c_3ad4_4c9c_b5cf_e36a_3851_2330);
const TARGET: GUID = GUID::from_u128(0xa1be_a8ba_d726_4663_8129_6b5e_7927_ffa6);
const VISUAL: GUID = GUID::from_u128(0x117e_202d_a859_4c89_873b_c2aa_5667_88e3);
const CONTAINER: GUID = GUID::from_u128(0x02f6_bc74_ed20_4773_afe6_d49b_4a93_db32);
const SPRITE_2: GUID = GUID::from_u128(0x588c_9664_997a_4850_91fe_53cb_58f8_1ce9);
const BRUSH: GUID = GUID::from_u128(0xab0d_7608_30c0_40e9_b568_b60a_6bd1_fb46);
const SHADOW: GUID = GUID::from_u128(0x329e_52e2_4335_49cc_b14a_3778_2d10_f0c4);
const CLIP: GUID = GUID::from_u128(0x1ccd_2a52_cfc7_4ace_9983_146b_b8eb_6a3c);
const GEOMETRY: GUID = GUID::from_u128(0xe985_217c_6a17_4207_abd8_5fd3_dd61_2a9d);
const SURFACE: GUID = GUID::from_u128(0x1527_540d_42c7_47a6_a408_668f_79a9_0dfb);
const SURFACE_INTEROP: GUID = GUID::from_u128(0xfd04_e6e3_fe0c_4c3c_ab19_a076_01a5_76ee);
const DXGI_DEVICE: GUID = GUID::from_u128(0x54ec_77fa_1377_44e6_8c32_88fd_5f44_c84c);
const D2D_DEVICE_CONTEXT: GUID = GUID::from_u128(0xe8f7_fe7a_191c_466d_ad95_9756_78bd_a998);

// Slots, counted from the SDK's headers.
const ACTIVATE_INSTANCE: usize = OWN;
const CREATE_COLOR_BRUSH_WITH_COLOR: usize = OWN + 2;
const CREATE_CONTAINER_VISUAL: usize = OWN + 3;
const CREATE_EFFECT_FACTORY: usize = OWN + 5;
const CREATE_SPRITE_VISUAL: usize = OWN + 16;
const CREATE_SURFACE_BRUSH_WITH_SURFACE: usize = OWN + 18;
const CREATE_DROP_SHADOW: usize = OWN + 4;
const CREATE_HOST_BACKDROP_BRUSH: usize = OWN;
const CREATE_ROUNDED_RECTANGLE_GEOMETRY: usize = OWN + 14;
const CREATE_GEOMETRIC_CLIP_WITH_GEOMETRY: usize = OWN + 1;
const CREATE_DESKTOP_WINDOW_TARGET: usize = 3;
const CREATE_GRAPHICS_DEVICE: usize = 5;
const CREATE_DRAWING_SURFACE: usize = OWN;
const SET_CLIP: usize = OWN + 9;
const SET_OFFSET: usize = OWN + 15;
const SET_SIZE: usize = OWN + 30;
const GET_CHILDREN: usize = OWN;
const INSERT_AT_TOP: usize = OWN + 3;
const SET_BRUSH: usize = OWN + 1;
const SET_SHADOW: usize = OWN + 1;
const SET_BLUR_RADIUS: usize = OWN + 1;
const SET_SHADOW_COLOR: usize = OWN + 3;
const SET_SHADOW_OFFSET: usize = OWN + 7;
const SET_MASK: usize = OWN + 5;
const SET_ROOT: usize = OWN + 1;
const SET_CORNER_RADIUS: usize = OWN + 1;
const SET_GEOMETRY_SIZE: usize = OWN + 5;
const SET_HORIZONTAL_ALIGNMENT: usize = OWN + 3;
const SET_STRETCH: usize = OWN + 5;
const SET_VERTICAL_ALIGNMENT: usize = OWN + 9;
const CREATE_BRUSH: usize = OWN;
const LOAD_STATUS: usize = OWN + 2;
const SET_SOURCE_PARAMETER: usize = OWN + 1;
const BEGIN_DRAW: usize = 3;
const END_DRAW: usize = 4;
// `ID2D1Factory1` and `ID2D1RenderTarget` (`d2d1_1.h`, `d2d1.h`).
const CREATE_DEVICE: usize = 17;
const CREATE_BITMAP: usize = 4;
const DRAW_BITMAP: usize = 26;
const PUSH_AXIS_ALIGNED_CLIP: usize = 45;
const POP_AXIS_ALIGNED_CLIP: usize = 46;
const CLEAR: usize = 47;

/// `CompositionStretch.None`: the rows one pixel to one pixel.
const STRETCH_NONE: i32 = 0;
/// `DirectXPixelFormat.B8G8R8A8UIntNormalized` and
/// `DirectXAlphaMode.Premultiplied`: the picture's own layout.
const B8G8R8A8: i32 = 87;
const PREMULTIPLIED: i32 = 1;
const DQTYPE_THREAD_CURRENT: i32 = 2;
const DQTAT_COM_NONE: i32 = 0;
const D3D_DRIVER_TYPE_WARP: i32 = 5;
const D3D11_CREATE_DEVICE_BGRA_SUPPORT: u32 = 32;
const D3D11_SDK_VERSION: u32 = 7;
const D2D1_ALPHA_MODE_PREMULTIPLIED: u32 = 1;
const D2D1_ANTIALIAS_MODE_ALIASED: u32 = 1;
const D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR: u32 = 0;

/// `CompositionEffectFactoryLoadStatus.Success` and `.Pending`.
const LOADED: i32 = 0;
const PENDING: i32 = 2;
/// WinUI's acrylic recipe lays its noise at this opacity
/// (`AcrylicBrush.h`, `sc_noiseOpacity`).
const NOISE_OPACITY: f32 = 0.02;
/// The noise tile's side, as WinUI's asset's.
const NOISE: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct Color {
    a: u8,
    r: u8,
    g: u8,
    b: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Vector2 {
    x: f32,
    y: f32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Vector3 {
    x: f32,
    y: f32,
    z: f32,
}

#[repr(C)]
struct QueueOptions {
    size: u32,
    thread: i32,
    apartment: i32,
}

/// `D2D1_BITMAP_PROPERTIES`.
#[repr(C)]
struct BitmapProperties {
    format: u32,
    alpha: u32,
    dpi_x: f32,
    dpi_y: f32,
}

/// `D2D_RECT_F`.
#[repr(C)]
struct RectF {
    left: f32,
    top: f32,
    right: f32,
    bottom: f32,
}

/// `D2D_SIZE_U`.
#[repr(C)]
#[derive(Clone, Copy)]
struct SizeU {
    width: u32,
    height: u32,
}

type Make = unsafe extern "system" fn(Object, *mut Object) -> HRESULT;
type MakeWith<T> = unsafe extern "system" fn(Object, T, *mut Object) -> HRESULT;
type Set<T> = unsafe extern "system" fn(Object, T) -> HRESULT;
type CreateQueue = unsafe extern "system" fn(QueueOptions, *mut Object) -> HRESULT;
type CreateGraphics = unsafe extern "system" fn(Object, Object, *mut Object) -> HRESULT;
type Status = unsafe extern "system" fn(Object, *mut i32) -> HRESULT;
type Parameter = unsafe extern "system" fn(Object, *mut c_void, Object) -> HRESULT;
type CreateSurface = unsafe extern "system" fn(Object, Vector2, i32, i32, *mut Object) -> HRESULT;
type BeginDraw =
    unsafe extern "system" fn(Object, *const RECT, *const GUID, *mut Object, *mut POINT) -> HRESULT;
type EndDraw = unsafe extern "system" fn(Object) -> HRESULT;
type CreateBitmap = unsafe extern "system" fn(
    Object,
    SizeU,
    *const c_void,
    u32,
    *const BitmapProperties,
    *mut Object,
) -> HRESULT;
type Clip = unsafe extern "system" fn(Object, *const RectF, u32);
type Unclip = unsafe extern "system" fn(Object);
type Clear = unsafe extern "system" fn(Object, *const c_void);
type DrawBitmap = unsafe extern "system" fn(Object, Object, *const RectF, f32, u32, *const RectF);
type CreateDevice = unsafe extern "system" fn(
    Object,
    i32,
    HMODULE,
    u32,
    *const i32,
    u32,
    u32,
    *mut Object,
    *mut i32,
    *mut Object,
) -> HRESULT;

fn make(object: &Com, slot: usize) -> io::Result<Com> {
    // SAFETY: each caller names a slot that makes an object, with this
    // signature, from the interface's header.
    let method: Make = unsafe { object.slot(slot) };
    let mut made = std::ptr::null_mut();
    // SAFETY: the object is alive and the place valid.
    let result = unsafe { method(object.object(), &raw mut made) };
    Com::taken(result, made)
}

fn make_with<T>(object: &Com, slot: usize, argument: T) -> io::Result<Com> {
    // SAFETY: as in `make`, for a method taking one argument of `T`.
    let method: MakeWith<T> = unsafe { object.slot(slot) };
    let mut made = std::ptr::null_mut();
    // SAFETY: as in `make`.
    let result = unsafe { method(object.object(), argument, &raw mut made) };
    Com::taken(result, made)
}

fn set<T>(object: &Com, slot: usize, value: T) -> io::Result<()> {
    // SAFETY: each caller names a setter's slot taking `T`.
    let set: Set<T> = unsafe { object.slot(slot) };
    // SAFETY: the object is alive; `T` is passed by value.
    check(unsafe { set(object.object(), value) })
}

fn colour(tint: Tint) -> Color {
    Color {
        a: tint.alpha,
        r: tint.colour.red,
        g: tint.colour.green,
        b: tint.colour.blue,
    }
}

fn vector(tint: Tint) -> Value {
    let unit = |value: u8| f32::from(value) / 255.0;
    Value::Vector4([
        unit(tint.colour.red),
        unit(tint.colour.green),
        unit(tint.colour.blue),
        unit(tint.alpha),
    ])
}

/// A library of the system folder, loaded while a menu is open.
struct Library(HMODULE);

impl Library {
    fn load(name: &str) -> io::Result<Library> {
        let name = wide(name);
        // SAFETY: the name is NUL-terminated; only the system folder is
        // searched, so nothing planted beside the executable is taken.
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Library(module))
    }

    /// The entry point `name`, as the address it is.
    fn entry(&self, name: &[u8]) -> io::Result<*const c_void> {
        // SAFETY: the module is loaded and the name NUL-terminated.
        let found = unsafe { GetProcAddress(self.0, name.as_ptr()) };
        found
            .map(|function| function as *const c_void)
            .ok_or_else(io::Error::last_os_error)
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: the reference to the module is this value's own; whatever
        // else still uses the library keeps it loaded.
        unsafe { FreeLibrary(self.0) };
    }
}

/// How far within the menu the shape that casts its shadow stands, in this
/// monitor's pixels: never less than one.
pub(crate) fn within(scale: f32) -> i32 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "one effective pixel at a monitor's scale, rounded"
    )]
    let pixels = (CAST_WITHIN * scale).round() as i32;
    pixels.max(1)
}

/// What a menu's backdrop is: acrylic, or the colour shown where Windows
/// composes none.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Backdrop {
    Acrylic(Acrylic),
    Solid(Rgb),
}

/// What the levels of one open menu are composed with.
pub(crate) struct Composer {
    // Let go in this order: what is composed, the devices, the compositor,
    // the thread's queue, then the libraries.
    backdrop: Com,
    graphics: Com,
    _direct2d: Com,
    _device: Com,
    compositor_6: Com,
    compositor_5: Com,
    compositor_2: Com,
    desktop: Com,
    compositor: Com,
    _queue: Com,
    _direct3d: Library,
    _messaging: Library,
    scale: f32,
}

impl Composer {
    /// A visual that casts `cast`, and its drop shadow, in this monitor's
    /// pixels.
    fn caster(&self, cast: Cast) -> io::Result<(Com, Com)> {
        let caster = make(&self.compositor, CREATE_SPRITE_VISUAL)?;
        let drop_shadow = make(&self.compositor_2, CREATE_DROP_SHADOW)?;
        set(&drop_shadow, SET_BLUR_RADIUS, cast.blur * self.scale)?;
        // The shadow's darkness is carried in its colour's alpha, as WinUI
        // carries it: its own opacity changes nothing a capture shows
        // (measured).
        set(
            &drop_shadow,
            SET_SHADOW_COLOR,
            Color {
                a: cast.alpha,
                r: 0,
                g: 0,
                b: 0,
            },
        )?;
        set(
            &drop_shadow,
            SET_SHADOW_OFFSET,
            Vector3 {
                x: 0.0,
                y: cast.drop * self.scale,
                z: 0.0,
            },
        )?;
        set(
            &caster.query(&SPRITE_2)?,
            SET_SHADOW,
            drop_shadow.query(&SHADOW)?.object(),
        )?;
        Ok((caster, drop_shadow))
    }

    /// A composition on this thread for a menu at `scale`, its levels standing
    /// on `backdrop`.
    pub(crate) fn new(backdrop: Backdrop, scale: f32) -> io::Result<Composer> {
        let messaging = Library::load("CoreMessaging.dll")?;
        let create_queue = messaging.entry(b"CreateDispatcherQueueController\0")?;
        // SAFETY: `CreateDispatcherQueueController` has this signature
        // (`dispatcherqueue.h`).
        let create_queue =
            unsafe { std::mem::transmute::<*const c_void, CreateQueue>(create_queue) };
        let mut queue = std::ptr::null_mut();
        // SAFETY: the options are passed by value; the place is valid. A
        // compositor needs a dispatcher queue on its thread.
        let result = unsafe {
            create_queue(
                QueueOptions {
                    size: crate::raw::size::<QueueOptions>(),
                    thread: DQTYPE_THREAD_CURRENT,
                    apartment: DQTAT_COM_NONE,
                },
                &raw mut queue,
            )
        };
        let queue = Com::taken(result, queue)?;
        let factory = effect::factory("Windows.UI.Composition.Compositor", &ACTIVATION_FACTORY)?;
        let compositor = make(&factory, ACTIVATE_INSTANCE)?.query(&COMPOSITOR)?;
        drop(factory);
        let interop = compositor.query(&COMPOSITOR_INTEROP)?;

        let direct3d = Library::load("d3d11.dll")?;
        let create_device = direct3d.entry(b"D3D11CreateDevice\0")?;
        // SAFETY: `D3D11CreateDevice` has this signature (`d3d11.h`).
        let create_device =
            unsafe { std::mem::transmute::<*const c_void, CreateDevice>(create_device) };
        // WARP alone: a hardware device's driver keeps its modules and about
        // 6 MB of private memory loaded for as long as the presence runs.
        let mut device = std::ptr::null_mut();
        // SAFETY: no adapter, software module or feature levels are named;
        // the places are valid. Composition needs BGRA.
        let result = unsafe {
            create_device(
                std::ptr::null_mut(),
                D3D_DRIVER_TYPE_WARP,
                std::ptr::null_mut(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                std::ptr::null(),
                0,
                D3D11_SDK_VERSION,
                &raw mut device,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        let device = Com::taken(result, device)?;
        // Composition draws a surface through Direct2D over that device, as
        // WinUI and Microsoft's own `windows-canvas` do.
        let factory = crate::write::device_factory()
            .ok_or_else(|| io::Error::other("no Direct2D factory"))?;
        let dxgi = device.query(&DXGI_DEVICE)?;
        let direct2d = make_with(&factory, CREATE_DEVICE, dxgi.object())?;
        drop((factory, dxgi));
        // SAFETY: `CreateGraphicsDevice` is at this place with this signature.
        let create_graphics: CreateGraphics = unsafe { interop.slot(CREATE_GRAPHICS_DEVICE) };
        let mut graphics = std::ptr::null_mut();
        // SAFETY: the compositor and the device are alive; the place is valid.
        let result =
            unsafe { create_graphics(interop.object(), direct2d.object(), &raw mut graphics) };
        let graphics = Com::taken(result, graphics)?;

        let mut composer = Composer {
            backdrop: compositor.share(),
            graphics,
            _direct2d: direct2d,
            _device: device,
            compositor_6: compositor.query(&COMPOSITOR_6)?,
            compositor_5: compositor.query(&COMPOSITOR_5)?,
            compositor_2: compositor.query(&COMPOSITOR_2)?,
            desktop: compositor.query(&DESKTOP_INTEROP)?,
            compositor,
            _queue: queue,
            _direct3d: direct3d,
            _messaging: messaging,
            scale,
        };
        composer.backdrop = match backdrop {
            Backdrop::Acrylic(acrylic) => composer.acrylic(acrylic)?,
            Backdrop::Solid(fill) => composer.fill(Tint {
                colour: fill,
                alpha: 0xff,
            })?,
        };
        Ok(composer)
    }

    fn fill(&self, tint: Tint) -> io::Result<Com> {
        make_with(
            &self.compositor,
            CREATE_COLOR_BRUSH_WITH_COLOR,
            colour(tint),
        )?
        .query(&BRUSH)
    }

    /// Acrylic, as WinUI's recipe composes it over a backdrop the shell has
    /// already blurred (`AcrylicBrush.cpp`): the backdrop takes the
    /// luminosity colour's lightness, then the tint's hue and saturation,
    /// and the noise lies over that.
    fn acrylic(&self, acrylic: Acrylic) -> io::Result<Com> {
        let maker = Maker::new()?;
        let luminous = maker.effect(
            effect::BLEND,
            &[Value::UInt32(effect::BLEND_MODE_LUMINOSITY)],
            vec![
                maker.parameter("Backdrop")?,
                maker.effect(effect::FLOOD, &[vector(acrylic.luminosity)], Vec::new())?,
            ],
        )?;
        let tinted = maker.effect(
            effect::BLEND,
            &[Value::UInt32(effect::BLEND_MODE_COLOR)],
            vec![
                luminous,
                maker.effect(effect::FLOOD, &[vector(acrylic.tint)], Vec::new())?,
            ],
        )?;
        let noise = maker.effect(
            effect::OPACITY,
            &[Value::Single(NOISE_OPACITY)],
            vec![maker.effect(
                effect::BORDER,
                &[
                    Value::UInt32(effect::BORDER_WRAP),
                    Value::UInt32(effect::BORDER_WRAP),
                ],
                vec![maker.parameter("Noise")?],
            )?],
        )?;
        let graph = maker.effect(
            effect::COMPOSITE,
            &[Value::UInt32(effect::COMPOSITE_SOURCE_OVER)],
            vec![tinted, noise],
        )?;
        let factory = make_with(&self.compositor, CREATE_EFFECT_FACTORY, graph.object())?;
        // SAFETY: `LoadStatus` is at this place with this signature.
        let status: Status = unsafe { factory.slot(LOAD_STATUS) };
        let mut loaded = 0;
        // SAFETY: the factory is alive; the place is valid.
        check(unsafe { status(factory.object(), &raw mut loaded) })?;
        // `Success`, or `Pending` while the compositor still loads the graph,
        // which the brush shows once it has; `EffectTooComplex` and `Other`
        // refuse it.
        if loaded != LOADED && loaded != PENDING {
            return Err(io::Error::other(format!(
                "the acrylic graph did not load: {loaded}"
            )));
        }
        let brush = make(&factory, CREATE_BRUSH)?;
        let host = make(
            &self.compositor.query(&COMPOSITOR_3)?,
            CREATE_HOST_BACKDROP_BRUSH,
        )?
        .query(&BRUSH)?;
        let noise = self.noise()?;
        for (name, source) in [("Backdrop", &host), ("Noise", &noise)] {
            let name = effect::Text::new(name)?;
            // SAFETY: `SetSourceParameter` is at this place with this
            // signature.
            let parameter: Parameter = unsafe { brush.slot(SET_SOURCE_PARAMETER) };
            // SAFETY: the brush, the string and the source are alive.
            check(unsafe { parameter(brush.object(), name.handle(), source.object()) })?;
        }
        brush.query(&BRUSH)
    }

    /// The noise acrylic lays over its tint: a tile of the six greys of
    /// WinUI's asset, each pixel the sum of five bits of a hash of its place,
    /// so its levels fall as the asset's nearly do.
    fn noise(&self) -> io::Result<Com> {
        let pixels: Vec<u32> = (0..NOISE * NOISE)
            .map(|at| {
                let mut seed = u64::try_from(at).unwrap_or_default();
                seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
                seed = (seed ^ (seed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                seed = (seed ^ (seed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                seed ^= seed >> 31;
                let grey = (seed & 0x1f).count_ones() * 0x33;
                0xff00_0000 | grey << 16 | grey << 8 | grey
            })
            .collect();
        let surface = self.surface(NOISE, NOISE)?;
        put(&surface, &pixels, NOISE, NOISE)?;
        let brush = make_with(
            &self.compositor,
            CREATE_SURFACE_BRUSH_WITH_SURFACE,
            surface.query(&SURFACE)?.object(),
        )?;
        set(&brush, SET_STRETCH, STRETCH_NONE)?;
        brush.query(&BRUSH)
    }

    fn surface(&self, width: usize, height: usize) -> io::Result<Com> {
        // SAFETY: `CreateDrawingSurface` is at this place with this signature.
        let create: CreateSurface = unsafe { self.graphics.slot(CREATE_DRAWING_SURFACE) };
        let size = Vector2 {
            x: float(width),
            y: float(height),
        };
        let mut made = std::ptr::null_mut();
        // SAFETY: the device is alive; the size is passed by value.
        let result = unsafe {
            create(
                self.graphics.object(),
                size,
                B8G8R8A8,
                PREMULTIPLIED,
                &raw mut made,
            )
        };
        Com::taken(result, made)
    }

    fn visual(object: &Com) -> io::Result<Com> {
        object.query(&VISUAL)
    }

    fn rounded(&self, radius: f32) -> io::Result<(Com, Com)> {
        let geometry = make(&self.compositor_5, CREATE_ROUNDED_RECTANGLE_GEOMETRY)?;
        set(
            &geometry,
            SET_CORNER_RADIUS,
            Vector2 {
                x: radius,
                y: radius,
            },
        )?;
        let general = geometry.query(&GEOMETRY)?;
        let clip = make_with(
            &self.compositor_6,
            CREATE_GEOMETRIC_CLIP_WITH_GEOMETRY,
            general.object(),
        )?
        .query(&CLIP)?;
        Ok((geometry, clip))
    }
}

/// Puts `pixels`, `0xAARRGGBB` premultiplied and `width` by `height`, on a
/// drawing surface of that size, replacing what it held.
fn put(surface: &Com, pixels: &[u32], width: usize, height: usize) -> io::Result<()> {
    if pixels.len() < width * height {
        return Err(io::Error::other("a picture smaller than its surface"));
    }
    let interop = surface.query(&SURFACE_INTEROP)?;
    // SAFETY: `BeginDraw` is at this place with this signature.
    let begin: BeginDraw = unsafe { interop.slot(BEGIN_DRAW) };
    let (mut context, mut at) = (std::ptr::null_mut(), POINT::default());
    // SAFETY: a null rectangle asks for the whole surface; the places are
    // valid.
    let result = unsafe {
        begin(
            interop.object(),
            std::ptr::null(),
            &D2D_DEVICE_CONTEXT,
            &raw mut context,
            &raw mut at,
        )
    };
    let context = Com::taken(result, context)?;
    let drawn = draw(&context, at, pixels, width, height);
    drop(context);
    // SAFETY: `EndDraw` is at this place with this signature.
    let end: EndDraw = unsafe { interop.slot(END_DRAW) };
    // SAFETY: drawing began above.
    let ended = check(unsafe { end(interop.object()) });
    drawn.and(ended)
}

/// Draws `pixels` at `at` through `context`, where the surface's update
/// begins: its area cleared, then the picture copied in pixel for pixel.
fn draw(context: &Com, at: POINT, pixels: &[u32], width: usize, height: usize) -> io::Result<()> {
    let size = SizeU {
        width: u32::try_from(width).map_err(io::Error::other)?,
        height: u32::try_from(height).map_err(io::Error::other)?,
    };
    let properties = BitmapProperties {
        format: u32::try_from(B8G8R8A8).unwrap_or_default(),
        alpha: D2D1_ALPHA_MODE_PREMULTIPLIED,
        dpi_x: 96.0,
        dpi_y: 96.0,
    };
    // SAFETY: `CreateBitmap` is at this place with this signature.
    let create: CreateBitmap = unsafe { context.slot(CREATE_BITMAP) };
    let mut bitmap = std::ptr::null_mut();
    // SAFETY: the pixels cover the size, row after row of `width`, and outlive
    // the call, which copies them.
    let result = unsafe {
        create(
            context.object(),
            size,
            pixels.as_ptr().cast(),
            size.width * 4,
            &raw const properties,
            &raw mut bitmap,
        )
    };
    let bitmap = Com::taken(result, bitmap)?;
    let left = signed_float(at.x);
    let top = signed_float(at.y);
    let place = RectF {
        left,
        top,
        right: left + float(width),
        bottom: top + float(height),
    };
    // SAFETY: each is at its place in `ID2D1RenderTarget` with its signature.
    let clip: Clip = unsafe { context.slot(PUSH_AXIS_ALIGNED_CLIP) };
    // SAFETY: as above.
    let unclip: Unclip = unsafe { context.slot(POP_AXIS_ALIGNED_CLIP) };
    // SAFETY: as above.
    let clear: Clear = unsafe { context.slot(CLEAR) };
    // SAFETY: as above.
    let draw: DrawBitmap = unsafe { context.slot(DRAW_BITMAP) };
    // SAFETY: the context is drawing; the rectangle outlives the call.
    unsafe {
        clip(
            context.object(),
            &raw const place,
            D2D1_ANTIALIAS_MODE_ALIASED,
        );
    }
    // SAFETY: a null colour clears to clear black, within the clip.
    unsafe { clear(context.object(), std::ptr::null()) };
    // SAFETY: the bitmap is the context's own; the rectangle outlives the call.
    unsafe {
        draw(
            context.object(),
            bitmap.object(),
            &raw const place,
            1.0,
            D2D1_BITMAP_INTERPOLATION_MODE_NEAREST_NEIGHBOR,
            std::ptr::null(),
        );
    }
    // SAFETY: balances the clip pushed above.
    unsafe { unclip(context.object()) };
    Ok(())
}

fn float(value: usize) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

fn signed_float(value: i32) -> f32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "a length on a screen is far below the 24 bits a float holds exactly"
    )]
    let float = value as f32;
    float
}

/// Where the menu stands within its level's window, and how large.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Place {
    pub(crate) left: i32,
    pub(crate) top: i32,
    pub(crate) width: i32,
    pub(crate) height: i32,
}

/// One level's composition: what its window shows.
pub(crate) struct Frame {
    // Let go before the target, which is let go last.
    rows: Com,
    /// The rows' surface and its brush, and the picture's size.
    surface: Option<(Com, Com, usize, usize)>,
    /// What casts each shadow - one visual and its drop shadow for each - the
    /// menu's shape, `within` pixels smaller on every side, its mask, redrawn
    /// as the menu's size changes; none without a shadow.
    casters: Vec<(Com, Com)>,
    mask: Option<(Com, Com, i32, i32)>,
    within: i32,
    corner: f32,
    /// How far within the menu's edge its fill begins: WinUI lays its stroke
    /// over what is behind the window, not over the fill.
    edge: f32,
    backdrop: Com,
    /// The fill's own corner, within the stroke.
    inner: Com,
    _inner_clip: Com,
    body: Com,
    geometry: Com,
    _clip: Com,
    _root: Com,
    _target: Com,
}

impl Frame {
    /// The composition of `window`, a menu with corners of `corner` pixels
    /// within it, its fill `edge` pixels within its edge; casting `shadow`
    /// from a shape `within` pixels within the menu, where it casts one.
    pub(crate) fn new(
        composer: &Composer,
        window: HWND,
        (corner, edge): (f32, i32),
        (shadow, within): (Option<Shadow>, i32),
    ) -> io::Result<Frame> {
        type Target = unsafe extern "system" fn(Object, HWND, i32, *mut Object) -> HRESULT;
        let edge = signed_float(edge);
        // SAFETY: `CreateDesktopWindowTarget` is at this place with this
        // signature.
        let create: Target = unsafe { composer.desktop.slot(CREATE_DESKTOP_WINDOW_TARGET) };
        let mut target = std::ptr::null_mut();
        // SAFETY: the window is this thread's own; its composition is its
        // only content, beneath nothing (FALSE).
        let result = unsafe { create(composer.desktop.object(), window, 0, &raw mut target) };
        let target = Com::taken(result, target)?.query(&TARGET)?;

        let root = Composer::visual(&make(&composer.compositor, CREATE_CONTAINER_VISUAL)?)?;
        let children = |container: &Com| make(&container.query(&CONTAINER)?, GET_CHILDREN);
        let insert = |into: &Com, visual: &Com| -> io::Result<()> {
            set(
                &children(into)?,
                INSERT_AT_TOP,
                Composer::visual(visual)?.object(),
            )
        };
        // The ambient shadow beneath the directional one, as WinUI layers
        // them.
        let casts = shadow
            .into_iter()
            .flat_map(|shadow| shadow.ambient.into_iter().chain([shadow.directional]));
        let mut casters = Vec::new();
        for cast in casts {
            let (caster, drop_shadow) = composer.caster(cast)?;
            insert(&root, &caster)?;
            casters.push((Composer::visual(&caster)?, drop_shadow));
        }
        let (geometry, clip) = composer.rounded(corner)?;
        let body = Composer::visual(&make(&composer.compositor, CREATE_CONTAINER_VISUAL)?)?;
        set(&body, SET_CLIP, clip.object())?;
        let backdrop = make(&composer.compositor, CREATE_SPRITE_VISUAL)?;
        set(&backdrop, SET_BRUSH, composer.backdrop.object())?;
        let (inner, inner_clip) = composer.rounded((corner - edge).max(0.0))?;
        set(&Composer::visual(&backdrop)?, SET_CLIP, inner_clip.object())?;
        let rows = make(&composer.compositor, CREATE_SPRITE_VISUAL)?;
        insert(&body, &backdrop)?;
        insert(&body, &rows)?;
        insert(&root, &body)?;
        set(&target, SET_ROOT, root.object())?;
        Ok(Frame {
            rows,
            surface: None,
            casters,
            mask: None,
            within,
            corner,
            edge,
            backdrop,
            inner,
            _inner_clip: inner_clip,
            body,
            geometry,
            _clip: clip,
            _root: root,
            _target: target,
        })
    }

    /// Shows the menu at `place` within the window, its rows the picture
    /// `pixels`, `width` by `height`, from its top left.
    pub(crate) fn show(
        &mut self,
        composer: &Composer,
        place: Place,
        pixels: &[u32],
        (width, height): (usize, usize),
    ) -> io::Result<()> {
        let size = Vector2 {
            x: signed_float(place.width),
            y: signed_float(place.height),
        };
        let offset = Vector3 {
            x: signed_float(place.left),
            y: signed_float(place.top),
            z: 0.0,
        };
        set(&self.body, SET_OFFSET, offset)?;
        set(&self.body, SET_SIZE, size)?;
        set(&self.geometry, SET_GEOMETRY_SIZE, size)?;
        let within = Vector2 {
            x: (size.x - 2.0 * self.edge).max(0.0),
            y: (size.y - 2.0 * self.edge).max(0.0),
        };
        let fill = Composer::visual(&self.backdrop)?;
        set(
            &fill,
            SET_OFFSET,
            Vector3 {
                x: self.edge,
                y: self.edge,
                z: 0.0,
            },
        )?;
        set(&fill, SET_SIZE, within)?;
        set(&self.inner, SET_GEOMETRY_SIZE, within)?;
        if !self.casters.is_empty() {
            // The shape that casts the shadow stands `within` the menu on
            // every side, as WinUI's does, so the menu covers the shadow's
            // innermost pixel.
            let (width, height) = (
                (place.width - 2 * self.within).max(1),
                (place.height - 2 * self.within).max(1),
            );
            let within = signed_float(self.within);
            let at = Vector3 {
                x: offset.x + within,
                y: offset.y + within,
                z: 0.0,
            };
            let cast = Vector2 {
                x: signed_float(width),
                y: signed_float(height),
            };
            let remade = !matches!(self.mask, Some((_, _, w, h)) if w == width && h == height);
            if remade {
                self.mask = Some(self.mask(composer, width, height)?);
            }
            for (caster, shadow) in &self.casters {
                set(caster, SET_OFFSET, at)?;
                set(caster, SET_SIZE, cast)?;
                if remade && let Some((_, brush, ..)) = &self.mask {
                    set(shadow, SET_MASK, brush.object())?;
                }
            }
        }
        if !matches!(self.surface, Some((_, _, w, h)) if w == width && h == height) {
            let surface = composer.surface(width, height)?;
            let brush = make_with(
                &composer.compositor,
                CREATE_SURFACE_BRUSH_WITH_SURFACE,
                surface.query(&SURFACE)?.object(),
            )?;
            set(&brush, SET_STRETCH, STRETCH_NONE)?;
            set(&brush, SET_HORIZONTAL_ALIGNMENT, 0.0f32)?;
            set(&brush, SET_VERTICAL_ALIGNMENT, 0.0f32)?;
            let brush = brush.query(&BRUSH)?;
            set(&self.rows, SET_BRUSH, brush.object())?;
            set(
                &Composer::visual(&self.rows)?,
                SET_SIZE,
                Vector2 {
                    x: float(width),
                    y: float(height),
                },
            )?;
            self.surface = Some((surface, brush, width, height));
        }
        if let Some((surface, ..)) = &self.surface {
            put(surface, pixels, width, height)?;
        }
        Ok(())
    }

    /// The menu's shape, `width` by `height` with its corner, as the alpha
    /// the shadow takes its shape from: a surface and its brush.
    fn mask(
        &self,
        composer: &Composer,
        width: i32,
        height: i32,
    ) -> io::Result<(Com, Com, i32, i32)> {
        let (across, down) = (
            usize::try_from(width).map_err(io::Error::other)?,
            usize::try_from(height).map_err(io::Error::other)?,
        );
        let mut shape = Canvas::clear(across, down);
        shape.fill(
            Rect {
                left: 0,
                top: 0,
                width,
                height,
            },
            self.corner,
            Tint::argb(0xFF00_0000),
        );
        let surface = composer.surface(across, down)?;
        put(&surface, &shape.premultiplied(), across, down)?;
        let brush = make_with(
            &composer.compositor,
            CREATE_SURFACE_BRUSH_WITH_SURFACE,
            surface.query(&SURFACE)?.object(),
        )?
        .query(&BRUSH)?;
        Ok((surface, brush, width, height))
    }
}
