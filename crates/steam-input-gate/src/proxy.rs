//! Search-order proxy delivery.
//!
//! The payload is normally deployed as a file in Steam's own install directory
//! under a name Steam resolves through the default DLL search order, so Steam
//! loads it itself and WSGM never injects. The vector is only a door: once the
//! image is mapped, `DllMain` starts the same server thread and the same
//! process-wide hooks the injected build installed, so everything downstream of
//! delivery is unchanged.
//!
//! Two properties make this safe, both verified against a live client:
//! no module in `steam.exe` hardens the search order (nothing imports or
//! resolves `SetDefaultDllDirectories`/`AddDllDirectory`; the single
//! `SetDllDirectoryA` reference cannot displace the application directory), and
//! nothing in Steam's directory statically imports XInput or DirectInput, so a
//! missing export degrades a `GetProcAddress` to NULL instead of failing a load.
//!
//! ## The self-recursion hazard
//!
//! `LOAD_LIBRARY_SEARCH_SYSTEM32` does NOT protect against loading ourselves.
//! The loader keys already-loaded modules by BASE NAME, so once this image is
//! resident as `xinput1_4.dll`, a bare-name load of `"xinput1_4.dll"` returns
//! THIS module no matter what search flags are passed - no search happens at
//! all. Every real system module must therefore be resolved by FULL SYSTEM32
//! PATH, and the result checked against our own handle before it is used.

use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use windows_sys::Win32::Foundation::{ERROR_DEVICE_NOT_CONNECTED, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExW};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

use super::blocking;

/// Which file name Steam loaded this payload under.
///
/// Reported out of band (a debug string at load) rather than over the pipe: the
/// wire `Response` is a fixed 24-byte struct with no spare field, and the host
/// does not need it - it already knows which vector it deployed, and learns
/// whether the vector took from the pipe existing at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Vector {
    /// Loaded under the payload's own name, i.e. injected rather than proxied.
    Injected,
    /// Loaded as a proxy for `XInput1_4.dll`.
    XInput14,
    /// Loaded as a proxy for `dinput8.dll`.
    DInput8,
    /// Loaded under a name this build does not recognise.
    Unknown,
}

impl Vector {
    /// The name used in the load-time diagnostic line.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Vector::Injected => "injected",
            Vector::XInput14 => "XInput1_4.dll",
            Vector::DInput8 => "dinput8.dll",
            Vector::Unknown => "unknown",
        }
    }
}

/// Classifies the vector from the payload's own module file name.
///
/// Case-insensitive because the deployed name comes from whatever the managed
/// side wrote and from the loader's own casing, neither of which is guaranteed.
pub(crate) fn classify_vector(file_name: &str) -> Vector {
    if file_name.eq_ignore_ascii_case("xinput1_4.dll") {
        Vector::XInput14
    } else if file_name.eq_ignore_ascii_case("dinput8.dll") {
        Vector::DInput8
    } else if file_name.eq_ignore_ascii_case("steam_input_gate.dll") {
        Vector::Injected
    } else {
        Vector::Unknown
    }
}

/// This module's own handle, recorded once the server thread has pinned it.
///
/// Stored as a `usize` because `HMODULE` is a raw pointer and this is only ever
/// compared for identity, never dereferenced.
static SELF_MODULE: AtomicUsize = AtomicUsize::new(0);

/// Records the payload's own module handle for the self-identity guard.
pub(crate) fn record_self_module(module: HMODULE) {
    SELF_MODULE.store(module as usize, Ordering::Release);
}

/// True when `module` is this very image.
///
/// Fails CLOSED while the handle is still unknown: before the server thread has
/// recorded it, every candidate is treated as possibly-us, so no hook is ever
/// installed onto our own forwarders during startup.
fn is_self(module: HMODULE) -> bool {
    let recorded = SELF_MODULE.load(Ordering::Acquire);
    recorded == 0 || recorded == module as usize
}

/// Loads a system module by FULL System32 path, never by base name.
///
/// Returns null when the module cannot be loaded, or when it resolves to this
/// image - see the self-recursion note at the top of this file.
pub(crate) unsafe fn load_system32_module(name: &str) -> HMODULE {
    let mut buffer = [0u16; 260];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return null_mut();
    }
    let mut path: Vec<u16> = buffer[..length].to_vec();
    path.push(std::path::MAIN_SEPARATOR as u16);
    path.extend(name.encode_utf16());
    path.push(0);
    let module = unsafe { LoadLibraryExW(path.as_ptr(), null_mut(), 0) };
    if module.is_null() || is_self(module) {
        return null_mut();
    }
    module
}

/// Caches the real `System32\XInput1_4.dll` this proxy forwards to.
static REAL_XINPUT: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
/// Caches the real `System32\dinput8.dll` this proxy forwards to.
static REAL_DINPUT8: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// Resolves and caches a real system module.
///
/// Resolution is LAZY on purpose. Steam can call through a forwarder before the
/// server thread has run, and `DllMain` must not load libraries under the loader
/// lock, so the first call through any export is what pulls the real DLL in.
unsafe fn real_module(cache: &AtomicPtr<c_void>, name: &str) -> HMODULE {
    let cached = cache.load(Ordering::Acquire);
    if !cached.is_null() {
        return cached.cast();
    }
    let module = unsafe { load_system32_module(name) };
    if !module.is_null() {
        cache.store(module.cast(), Ordering::Release);
    }
    module
}

/// Resolves an export of a real system module, caching the address.
///
/// `export` is either a NUL-terminated name or an ordinal cast to a pointer,
/// matching `GetProcAddress`'s own overloading.
unsafe fn real_export(
    slot: &AtomicPtr<c_void>,
    module_cache: &AtomicPtr<c_void>,
    module_name: &str,
    export: *const u8,
) -> *mut c_void {
    let cached = slot.load(Ordering::Acquire);
    if !cached.is_null() {
        return cached;
    }
    let module = unsafe { real_module(module_cache, module_name) };
    if module.is_null() {
        return null_mut();
    }
    let address = unsafe { GetProcAddress(module, export) };
    match address {
        Some(function) => {
            let pointer = function as *mut c_void;
            slot.store(pointer, Ordering::Release);
            pointer
        }
        None => null_mut(),
    }
}

/// File name of the real XInput module this proxy stands in front of.
const XINPUT_MODULE: &str = "XInput1_4.dll";
/// File name of the real DirectInput module this proxy stands in front of.
const DINPUT8_MODULE: &str = "dinput8.dll";

/// `E_FAIL`, returned by the DirectInput forwarders when the real module is
/// unreachable. Failing the call is correct: the alternative is pretending an
/// interface was created and handing the caller an uninitialised pointer.
const E_FAIL: i32 = -2_147_467_259;

/// Declares a proxy export that forwards to the real system DLL, optionally
/// denying the call while a lease is held.
///
/// The `true` variants are the four entry points the injected build already
/// detours (`XInputGetState`, ordinal 100, `XInputGetCapabilities`, ordinal
/// 108). The gate lives HERE, in the forwarder, as well as in the detour: when
/// Steam loaded us as the XInput proxy its calls reach this code first, so
/// blocking stays correct even if the hook onto the real module never lands.
macro_rules! proxy_export {
    (
        $(#[$meta:meta])*
        $gate:literal, $vis_name:ident, $slot:ident, $module_cache:ident, $module:ident,
        $export:expr, ($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty, $fallback:expr
    ) => {
        /// Cached address of the real export this thunk forwards to.
        static $slot: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

        $(#[$meta])*
        #[unsafe(no_mangle)]
        #[allow(non_snake_case)]
        pub unsafe extern "system" fn $vis_name($($arg: $ty),*) -> $ret {
            if $gate && blocking() {
                return $fallback;
            }
            let target = unsafe { real_export(&$slot, &$module_cache, $module, $export) };
            if target.is_null() {
                return $fallback;
            }
            let original: unsafe extern "system" fn($($ty),*) -> $ret =
                unsafe { core::mem::transmute(target) };
            unsafe { original($($arg),*) }
        }
    };
}

proxy_export!(
    /// `XInputGetState` - gated; the injected build detours this same entry.
    true, XInputGetState, XINPUT_GET_STATE, REAL_XINPUT, XINPUT_MODULE,
    c"XInputGetState".as_ptr().cast(),
    (user: u32, state: *mut c_void) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// `XInputGetCapabilities` - gated.
    true, XInputGetCapabilities, XINPUT_GET_CAPABILITIES, REAL_XINPUT, XINPUT_MODULE,
    c"XInputGetCapabilities".as_ptr().cast(),
    (user: u32, flags: u32, caps: *mut c_void) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// `XInputSetState` - pass-through. Rumble is not input, and blocking it
    /// would leave a game's force feedback dead while a WSGM panel is open.
    false, XInputSetState, XINPUT_SET_STATE, REAL_XINPUT, XINPUT_MODULE,
    c"XInputSetState".as_ptr().cast(),
    (user: u32, vibration: *mut c_void) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// `XInputGetBatteryInformation` - pass-through.
    false, XInputGetBatteryInformation, XINPUT_BATTERY, REAL_XINPUT, XINPUT_MODULE,
    c"XInputGetBatteryInformation".as_ptr().cast(),
    (user: u32, device: u8, battery: *mut c_void) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// `XInputGetKeystroke` - pass-through.
    false, XInputGetKeystroke, XINPUT_KEYSTROKE, REAL_XINPUT, XINPUT_MODULE,
    c"XInputGetKeystroke".as_ptr().cast(),
    (user: u32, reserved: u32, keystroke: *mut c_void) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// `XInputGetAudioDeviceIds` - pass-through.
    false, XInputGetAudioDeviceIds, XINPUT_AUDIO, REAL_XINPUT, XINPUT_MODULE,
    c"XInputGetAudioDeviceIds".as_ptr().cast(),
    (
        user: u32,
        render_id: *mut u16,
        render_count: *mut u32,
        capture_id: *mut u16,
        capture_count: *mut u32,
    ) -> u32,
    ERROR_DEVICE_NOT_CONNECTED
);

/// Cached address of the real `XInputEnable`.
static XINPUT_ENABLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// `XInputEnable` - pass-through. It returns nothing, so it cannot use
/// `proxy_export!`, whose fallback is a return value.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn XInputEnable(enable: i32) {
    let target = unsafe {
        real_export(
            &XINPUT_ENABLE,
            &REAL_XINPUT,
            XINPUT_MODULE,
            c"XInputEnable".as_ptr().cast(),
        )
    };
    if target.is_null() {
        return;
    }
    let original: unsafe extern "system" fn(i32) = unsafe { core::mem::transmute(target) };
    unsafe { original(enable) }
}

proxy_export!(
    /// Ordinal 100, `XInputGetStateEx` - gated. This is the entry that reports
    /// the Guide button, which the named `XInputGetState` masks off. The real
    /// DLL exports it NONAME, so `build.rs` places this thunk at its ordinal.
    true, wsgm_xinput_ordinal_100, XINPUT_STATE_EX, REAL_XINPUT, XINPUT_MODULE,
    100usize as *const u8,
    (user: u32, state: *mut c_void) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// Ordinal 101, `XInputWaitForGuideButton` - pass-through.
    false, wsgm_xinput_ordinal_101, XINPUT_WAIT_GUIDE, REAL_XINPUT, XINPUT_MODULE,
    101usize as *const u8,
    (user: u32, flags: u32, state: *mut c_void) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// Ordinal 102, `XInputCancelGuideButtonWait` - pass-through.
    false, wsgm_xinput_ordinal_102, XINPUT_CANCEL_GUIDE, REAL_XINPUT, XINPUT_MODULE,
    102usize as *const u8,
    (user: u32) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// Ordinal 103, `XInputPowerOffController` - pass-through.
    false, wsgm_xinput_ordinal_103, XINPUT_POWER_OFF, REAL_XINPUT, XINPUT_MODULE,
    103usize as *const u8,
    (user: u32) -> u32, ERROR_DEVICE_NOT_CONNECTED
);
proxy_export!(
    /// Ordinal 108, `XInputGetCapabilitiesEx` - gated.
    true, wsgm_xinput_ordinal_108, XINPUT_CAPS_EX, REAL_XINPUT, XINPUT_MODULE,
    108usize as *const u8,
    (reserved: u32, user: u32, flags: u32, caps: *mut c_void) -> u32,
    ERROR_DEVICE_NOT_CONNECTED
);

proxy_export!(
    /// `DirectInput8Create` - pass-through. The DirectInput vector is a door
    /// into the process, not an interception point: Steam Input reads HID
    /// directly, and those hooks are installed process-wide regardless of which
    /// name the loader used to map this image.
    false, DirectInput8Create, DINPUT8_CREATE, REAL_DINPUT8, DINPUT8_MODULE,
    c"DirectInput8Create".as_ptr().cast(),
    (
        instance: *mut c_void,
        version: u32,
        interface_id: *const c_void,
        out: *mut *mut c_void,
        outer: *mut c_void,
    ) -> i32,
    E_FAIL
);
proxy_export!(
    /// `DllCanUnloadNow` - pass-through.
    false, DllCanUnloadNow, DINPUT8_CAN_UNLOAD, REAL_DINPUT8, DINPUT8_MODULE,
    c"DllCanUnloadNow".as_ptr().cast(), () -> i32, E_FAIL
);
proxy_export!(
    /// `DllGetClassObject` - pass-through.
    false, DllGetClassObject, DINPUT8_GET_CLASS, REAL_DINPUT8, DINPUT8_MODULE,
    c"DllGetClassObject".as_ptr().cast(),
    (class_id: *const c_void, interface_id: *const c_void, out: *mut *mut c_void) -> i32,
    E_FAIL
);
proxy_export!(
    /// `DllRegisterServer` - pass-through.
    false, DllRegisterServer, DINPUT8_REGISTER, REAL_DINPUT8, DINPUT8_MODULE,
    c"DllRegisterServer".as_ptr().cast(), () -> i32, E_FAIL
);
proxy_export!(
    /// `DllUnregisterServer` - pass-through.
    false, DllUnregisterServer, DINPUT8_UNREGISTER, REAL_DINPUT8, DINPUT8_MODULE,
    c"DllUnregisterServer".as_ptr().cast(), () -> i32, E_FAIL
);
proxy_export!(
    /// `GetdfDIJoystick` - pass-through.
    false, GetdfDIJoystick, DINPUT8_JOYSTICK_FORMAT, REAL_DINPUT8, DINPUT8_MODULE,
    c"GetdfDIJoystick".as_ptr().cast(), () -> *mut c_void, null_mut()
);

/// Version of the proxy contract this build implements.
pub(crate) const PROXY_MARKER_VERSION: u32 = 1;

/// Ownership marker.
///
/// The managed deployer treats the presence of this export as proof that a file
/// sitting in Steam's directory is WSGM's own, so it can replace a stale copy
/// without ever overwriting a foreign `XInput1_4.dll` - ValvePlug's, Special K's,
/// or anything else that claimed the same name first.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn WsgmSteamInputGateProxy() -> u32 {
    PROXY_MARKER_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_vector_recognises_each_deployed_name_case_insensitively() {
        assert_eq!(classify_vector("XInput1_4.dll"), Vector::XInput14);
        assert_eq!(classify_vector("xinput1_4.dll"), Vector::XInput14);
        assert_eq!(classify_vector("dinput8.dll"), Vector::DInput8);
        assert_eq!(classify_vector("DInput8.DLL"), Vector::DInput8);
    }

    #[test]
    fn classify_vector_reports_the_payloads_own_name_as_injected() {
        assert_eq!(classify_vector("steam_input_gate.dll"), Vector::Injected);
    }

    #[test]
    fn classify_vector_reports_an_unrecognised_name_rather_than_guessing() {
        assert_eq!(classify_vector("winmm.dll"), Vector::Unknown);
        assert_eq!(classify_vector(""), Vector::Unknown);
    }

    #[test]
    fn every_vector_has_a_distinct_label_for_the_load_diagnostic() {
        let labels = [
            Vector::Injected.label(),
            Vector::XInput14.label(),
            Vector::DInput8.label(),
            Vector::Unknown.label(),
        ];
        for (index, label) in labels.iter().enumerate() {
            assert!(!label.is_empty());
            assert!(!labels[..index].contains(label));
        }
    }

    #[test]
    fn an_unknown_self_module_fails_closed_so_no_hook_lands_on_our_own_exports() {
        // Before the server thread records the handle every candidate must be
        // treated as possibly-us: hooking our own forwarder would recurse.
        SELF_MODULE.store(0, Ordering::Release);
        assert!(is_self(0x1234 as HMODULE));
    }
}
