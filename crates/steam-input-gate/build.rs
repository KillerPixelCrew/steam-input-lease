//! Emits the linker directives that give the payload its proxy export table.
//!
//! When Steam loads this DLL as a search-order proxy (see `src/proxy.rs`) it
//! resolves some XInput entry points by ORDINAL ONLY: the real
//! `System32\XInput1_4.dll` exports its named functions at fixed low ordinals
//! and 100, 101, 102, 103, 104, 108 and 109 as NONAME. Ordinal 100
//! (`XInputGetStateEx`) is the one that reports the Guide button the named
//! `XInputGetState` masks off. Every public name needs an explicit ordinal too:
//! otherwise link.exe starts Rust's automatic exports above 100, and unrelated
//! functions can accidentally occupy XInput's undocumented 104/109 slots.
//!
//! One authoritative `.def` file is passed to link.exe. Adding `/EXPORT:`
//! directives alongside rustc's automatic cdylib export list does not reassign
//! duplicate names: link.exe keeps the automatic ordinals and fills 104/109 with
//! whichever unrelated symbols come next. The `.def` replaces that list and is
//! verified from the finished PE by `eng/build-steam-input-lease.ps1 -Validate`.
//!
//! Ordinals 104 and 109 are deliberately left empty. Their signatures are
//! undocumented, and no binary in Steam's directory statically imports XInput or
//! DirectInput (verified with `dumpbin /imports`) - every load is
//! `LoadLibrary` + `GetProcAddress`, so an unresolved export returns NULL and the
//! caller degrades. Leaving them out is strictly safer than forwarding through a
//! guessed signature, which would corrupt the stack on the one call that used it.
//!
//! The same image remains the `dinput8.dll` fallback. Steam resolves that route
//! by name, so its six named exports live at 200+ rather than collide with
//! XInput's ordinal contract. The ownership marker follows them.

/// Named exports and their deliberate ordinals. The XInput entries match the
/// System32 DLL; DirectInput and the WSGM marker live outside its reserved range.
const NAMED_EXPORTS: &[(u16, &str)] = &[
    (1, "DllMain"),
    (2, "XInputGetState"),
    (3, "XInputSetState"),
    (4, "XInputGetCapabilities"),
    (5, "XInputEnable"),
    (7, "XInputGetBatteryInformation"),
    (8, "XInputGetKeystroke"),
    (10, "XInputGetAudioDeviceIds"),
    (200, "DirectInput8Create"),
    (201, "DllCanUnloadNow"),
    (202, "DllGetClassObject"),
    (203, "DllRegisterServer"),
    (204, "DllUnregisterServer"),
    (205, "GetdfDIJoystick"),
    (206, "WsgmSteamInputGateProxy"),
];

/// Ordinal-only exports of the real `XInput1_4.dll`, paired with the internal
/// thunk each one is satisfied by. This list must cover every ordinal Steam
/// resolves dynamically; the finished PE is checked by the validation script.
const XINPUT_ORDINALS: &[(u16, &str)] = &[
    (100, "wsgm_xinput_ordinal_100"),
    (101, "wsgm_xinput_ordinal_101"),
    (102, "wsgm_xinput_ordinal_102"),
    (103, "wsgm_xinput_ordinal_103"),
    (108, "wsgm_xinput_ordinal_108"),
];

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    let mut definition = String::from("LIBRARY steam_input_gate\nEXPORTS\n");
    for (ordinal, name) in NAMED_EXPORTS {
        definition.push_str(&format!("  {name} @{ordinal}\n"));
    }
    for (ordinal, thunk) in XINPUT_ORDINALS {
        definition.push_str(&format!(
            "  wsgm_ord_{ordinal}={thunk} @{ordinal} NONAME\n"
        ));
    }
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set"))
        .join("steam_input_gate.def");
    std::fs::write(&path, definition).expect("write proxy export definition");
    println!("cargo::rustc-cdylib-link-arg=/DEF:{}", path.display());
}
