//! Emits the linker directives that give the payload its proxy export table.
//!
//! When Steam loads this DLL as a search-order proxy (see `src/proxy.rs`) it
//! resolves some XInput entry points by ORDINAL ONLY: the real
//! `System32\XInput1_4.dll` exports 100, 101, 102, 103, 104, 108 and 109 as
//! NONAME, and ordinal 100 (`XInputGetStateEx`) is the one that reports the
//! Guide button the named `XInputGetState` masks off. `#[unsafe(no_mangle)]`
//! can only produce name exports, so those seven have to come from `/EXPORT:`
//! directives carrying an explicit ordinal.
//!
//! `/EXPORT:` is used rather than a `.def` file on purpose: these directives are
//! unioned with the export spec rustc already emits for an MSVC cdylib, whereas
//! a second `/DEF:` competes with it.
//!
//! Ordinals 104 and 109 are deliberately NOT forwarded. Their signatures are
//! undocumented, and no binary in Steam's directory statically imports XInput or
//! DirectInput (verified with `dumpbin /imports`) - every load is
//! `LoadLibrary` + `GetProcAddress`, so an unresolved export returns NULL and the
//! caller degrades. Leaving them out is strictly safer than forwarding through a
//! guessed signature, which would corrupt the stack on the one call that used it.

/// Ordinal-only exports of the real `XInput1_4.dll`, paired with the internal
/// thunk each one is satisfied by. A missing export makes Steam's load of the
/// proxy fail, so this list must stay a superset of what Steam imports.
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
    for (ordinal, thunk) in XINPUT_ORDINALS {
        // NONAME matches the real DLL: the entry exists at its ordinal and is
        // absent from the name table, so an import by ordinal resolves and an
        // import by name fails exactly as it does against System32's copy.
        println!(
            "cargo::rustc-cdylib-link-arg=/EXPORT:wsgm_ord_{ordinal}={thunk},@{ordinal},NONAME"
        );
    }
}
