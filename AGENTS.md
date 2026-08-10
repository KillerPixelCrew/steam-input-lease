# Steam Input lease native library

This Rust workspace injects the Steam Input gate and provides the pipe-backed lease, C ABI, and
user-facing launch-option CLI used only by WSGM.

- Change the ABI end-to-end: Rust → `include\steam_input_lease.h` → `bindings\SteamInterop.Net` →
  `src\WSGM\SteamInterop` → callers, then bump `sil_abi_version()`.
- Build through `eng\build-steam-input-lease.ps1`; never hand-copy artifacts into the generated
  WSGM staging directory.
- This workspace intentionally has no `cargo fmt` gate. Do not reformat untouched Rust; validation is
  `cargo clippy -- -D warnings` and `cargo test` through the build script.
- The gate must not call Steam's in-process library manager or turn recovery/probing failure into a
  destructive Steam state change.
