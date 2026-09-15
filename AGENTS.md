# Steam Input Lease contributor guide

## Scope and sources of truth

This repository is a standalone Windows library for temporarily leasing controller access away from
Steam Input. It ships a Rust API, a stable C ABI, a .NET binding, the Steam-loaded gate DLL, and a
console launcher that doubles as the diagnostic tool. WSGM is its primary consumer, but none of the
public surfaces are WSGM-internal.

Read `README.md` before changing the gate, protocol, recovery, ABI, packaging, or deployment
contract. In particular, preserve the constraints documented under Proxy delivery, Lease lifecycle,
Controller recovery, Compatibility, and Security. Comments that record live Steam failures explain
load-bearing behavior; do not simplify them away without equivalent evidence.

When externally observable behavior changes, update the code and every relevant public document
together. A public ABI change also updates the native header and bindings as described below. Do not
use this file as a substitute for documenting the public contract.

## Repository map

- `crates/steam-input-lease-core`: fixed-width pipe protocol, capabilities, and pipe naming.
- `crates/steam-input-recovery`: build-independent Steam RTTI/vtable/instruction analysis and
  live-object election.
- `crates/steam-input-lease`: client, lease lifetime, process wrapper, recovery, and opt-in
  injection.
- `crates/steam-input-gate`: proxy exports, hook engine, pipe server, recovery, and startup trace.
- `crates/steam-input-lease-ffi`: stable C ABI.
- `crates/steam-input-lease-cli`: console launcher and diagnostics; with the gate, the standalone
  download.
- `crates/steam-input-test-target`: isolated lifecycle-test target; never a production target.
- `include/steam_input_lease.h`: public C contract.
- `bindings/SteamInterop.Net`: canonical .NET binding.
- `samples/SteamInterop.CSharpExample`: managed usage and packaging check.
- `scripts/build.ps1`: safe build, test, documentation, and packaging gate, including the standalone
  zip; lifecycle injection and finished-DLL export inspection remain separate checks.
- `scripts/test-lifecycle.ps1`: isolated injection, fake-HID gate, lease/release, status, and
  process-tree test. It does not prove live Steam recovery.

Consumers normally redistribute `steam_input_gate.dll`, `steam_input_lease_ffi.dll`, and optionally
the managed binding. The standalone download ships the gate as `XInput1_4.dll` beside the launcher,
for users who copy both into Steam's folder by hand, with `packaging/standalone/README.txt` as its
install and usage guide. Keep that file consistent with the README's Standalone use section. The
test target is a development tool.

## Compatibility contracts

The package version, pipe protocol version, proxy ownership-marker contract, and C ABI version are
separate contracts. Do not assume they advance together.

Prefer additive public changes. An ABI or layout change must be updated end to end:

1. Rust types and exports in `crates/steam-input-lease-ffi`.
2. `include/steam_input_lease.h`.
3. `bindings/SteamInterop.Net`, including `NativeMethods.ExpectedAbiVersion`.
4. README ABI examples and tables, plus release notes or a changelog when one exists.
5. ABI layout tests and affected consumers.

The managed binding must check `sil_abi_version()` before any other native operation. Keep FFI
by-value ABI records C-layout and fixed-width where promised, and keep pointer-bearing options and
opaque handles explicit about ownership, lifetime, and platform width.

Protocol changes must update both host and gate through `steam-input-lease-core`, preserve exact
request/response layout, and advance `PROTOCOL_VERSION` when compatibility requires it.

The workspace version in `Cargo.toml`, the managed package version, and user-facing version text
must remain consistent when publishing a release.

All public Rust APIs remain documented; the library crates use `#![deny(missing_docs)]`. Preserve
the managed XML-documentation contract as well.

## Gate and loader invariants

The gate is loaded into `steam.exe` through the Windows DLL search order. Its loader behavior is a
correctness and startup-safety boundary.

- `DllMain` records the image handle and tries to pin the image before doing anything else. If
  pinning fails, it returns success with proxy forwarders still blocked and starts no worker. Only a
  pinned image disables thread callbacks and starts the worker. Allocation, module resolution,
  hooks, pipe setup, and file I/O stay off the loader path.
- Never return `FALSE` from process attach.
- Resolve real proxy modules by their full `System32` path and reject the gate's own image.
- Proxy calls remain on disconnected fallbacks until one full resolution attempt has completed and
  every required forwarding target is cached.
- `crates/steam-input-gate/build.rs` is the authoritative export map. Preserve the documented named
  exports and ordinals; ordinals 104 and 109 intentionally remain empty.
- Required export failure rejects a proxy vector. Missing optional named exports or undocumented
  ordinals must not reject the whole vector.
- Install hooks only on the first lease, as one queued operation. A hook failure leaves the proxy
  pass-through and is not retried continuously.
- The payload is pinned for the lifetime of Steam. Never add an ordinary unload or manual-unmap path
  without a complete quiesce protocol.

Detour bodies are latency-sensitive and must not acquire unbounded work. Preserve allocation-free
hot paths, bounded handle-table probing, and the thread-local probe bypass.

## Lease, recovery, and security invariants

A lease is owned by one named-pipe connection. Explicit release and connection EOF must each remove
that ownership exactly once; concurrent clients are reference-counted, and final release restores
pass-through immediately.

Temporary pass-through claims use separate pipe ownership and override blocking without consuming
any block lease. The final claim's release or EOF restores blocking only when block leases remain.
Serialize ownership transitions on pipe workers; detours keep their allocation-free atomic reads.
Keep support and active-override status bits distinct from the owned block-lease count.

Recovery is reported separately from lease release. A recovery failure must not make an already
released lease appear held or failed.

Wrapped launches remove `SDL_GAMECONTROLLER_IGNORE_DEVICES` from the child's environment only
after acquiring a lease. Preserve all other environment entries, the caller's environment, command
arguments, working directory, and job ownership. A lease failure must not change an unleased launch.

The default client connects only to a resident payload. Injection remains explicit opt-in and must
never become an implicit fallback. Ordinary builds and tests must not inject into real Steam.

The launcher fails open: when `run_wrapped` returns an error, it runs the program once through
`run_unleased`, whose environment is unchanged. The launcher injects only with `--inject`.

Recovery remains semantic and build-independent:

- Do not introduce Steam version tables, fixed RVAs, or hard-coded object offsets.
- Image and layout resolution must be unique and validated; missing or ambiguous structural evidence
  fails closed. The live-object scan may retain several valid candidates, but election observes
  progress and must choose exactly one before writing.
- Preserve the SDL repair before Steam discovery for SDL-backed controllers.
- Recovery/probing failure must never become a destructive Steam state change.

Keep target discovery scoped to the caller's Windows session. The control pipe always rejects remote
clients. It attempts an explicit DACL for System, Administrators, and the token's owner and user,
but uses Windows' default local pipe security descriptor if that descriptor cannot be built, as the
README documents. Keep the user ACE: an elevated Steam's token is owned by Administrators, and
without it no unelevated program could connect. Clients open the pipe with identification-level
impersonation and refuse a server that is not the target process. A deployer must prove ownership
through `WsgmSteamInputGateProxy` before replacing a proxy name and must not overwrite another
program's DLL.

The startup trace goes beside the gate's own image unless WSGM's `<name>.wsgm-shim` stamp sits beside
it, which selects `%LOCALAPPDATA%\WSGM`. The stamp only chooses between those two directories; it
never names a path and never proves ownership.

## Validation

For focused Rust work, run the affected tests first. Before completing a code change, use the
Windows x64 MSVC target and run the relevant full gates:

```powershell
cargo test --workspace --target x86_64-pc-windows-msvc
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
$previousRustDocFlags = $env:RUSTDOCFLAGS
try {
    $env:RUSTDOCFLAGS = '-D warnings'
    cargo doc --workspace --no-deps --target x86_64-pc-windows-msvc
} finally {
    $env:RUSTDOCFLAGS = $previousRustDocFlags
}
```

The preferred complete safe build and packaging gate is:

```powershell
.\scripts\build.ps1
```

`-SkipTests` builds the same artifacts without the Cargo test run, for handing a build to manual
testing before the tests run.

Changes to lease lifetime, injection, job handling, hooks, or recovery also require:

```powershell
.\scripts\test-lifecycle.ps1 -Profile release
```

That script must continue to target only `steam-input-test-target.exe`; it must not touch Steam or a
real controller.

Changes to the proxy or `build.rs` require inspection of the finished DLL export table against the
README contract. Changes that depend on Steam startup, controller rediscovery, or a new Steam layout
additionally need explicit attended live-client validation; automated success alone cannot prove
those paths.

There is deliberately no `cargo fmt` gate. Do not reformat untouched Rust or mix broad formatting
with a functional change.

Build outputs under `target/`, `artifacts/`, and managed `bin/` or `obj/` directories are generated
and must not be committed.
