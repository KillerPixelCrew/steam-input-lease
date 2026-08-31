# Steam Input lease native library

This Rust workspace delivers the Steam Input gate as a proxy DLL and provides the pipe-backed
lease, the C ABI, the .NET binding, and a diagnostic CLI.

**This is a standalone, publicly consumable library (MIT).** It was extracted from WSGM, which is
still its primary consumer, but it is no longer WSGM-internal — treat the C ABI and the .NET
binding as public surface with outside users.

- **The ABI is a compatibility promise, not an internal handshake.** `sil_abi_version()` exists so
  a consumer can refuse a mismatched library at runtime. Changing the ABI end-to-end
  (Rust → `include\steam_input_lease.h` → `bindings\SteamInterop.Net` → callers) and bumping that
  version is still the mechanism, but a break now costs every consumer, not just one. Prefer
  additive change; when a break is unavoidable, bump the version and say so in the release notes.
- The gate DLL is loaded by `steam.exe` through the Windows DLL search order. It must resolve the
  real system module by FULL `System32` path, keep its forwarders blocked until the worker has
  cached the complete forwarding table, and never enter the loader through a proxy forwarder.
  `docs`-level rationale lives in `README.md`; the constraints that cost a Steam cold-boot hang are
  commented at the code that enforces them.
- The gate must not call Steam's in-process library manager, and must never turn a recovery or
  probing failure into a destructive Steam state change.
- This workspace intentionally has no `cargo fmt` gate. Do not reformat untouched Rust; validation
  is `cargo clippy --all-targets -- -D warnings` and `cargo test`.
- `steam-input-lease.exe` and `steam-input-test-target` are development/diagnostic tools. Consumers
  ship `steam_input_gate.dll` and `steam_input_lease_ffi.dll`.
