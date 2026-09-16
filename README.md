# Steam Input Lease

A Windows library that temporarily stops the running Steam client from opening, polling or
enumerating HID and XInput controllers, so a controller-sensitive application (usually SDL3) can
take direct control while Steam Input is running.

It changes controller access inside the Steam process only. It does not inject into the game,
disable the Steam Overlay, restart or terminate Steam, install a driver, hide a controller from
Windows, or stop any other application from opening controllers.

Blocking is scoped to a lease, and a lease is an open named-pipe connection, so if your process
crashes, blocking ends with it. The gate is a proxy DLL that Steam loads itself from its own install
directory, so nothing writes into the Steam process. It is pass-through whenever no lease is held
and installs no hook until the first lease is taken. The first lease closes Steam's existing HID
handles and denies new access, concurrent leases are reference-counted, and releasing the last lease
restores pass-through and asks Steam to rediscover controllers without restarting it.

It ships as a Rust API, a stable C ABI (version 4), a .NET 8 binding and a console launcher that
works without writing any code. Injection
through remote `LoadLibraryW` still exists, but only as an explicit opt-in for a launch wrapper on a
machine where the proxy is not deployed, and for this repository's own tests. A client left at its
defaults cannot inject.

> [!IMPORTANT]
> `0.1.0` enables and disables blocking dynamically but never unloads the payload DLL. That is
> deliberate. See [Payload lifetime](#payload-lifetime).

Contents: [Standalone use](#standalone-use) · [Quick start](#quick-start) ·
[How it works](#how-it-works) · [Proxy delivery](#proxy-delivery) ·
[Lease lifecycle](#lease-lifecycle) · [Rust](#rust) · [C ABI](#c-abi) · [C#](#c) ·
[Launcher](#launcher) · [Building and testing](#building-and-testing) ·
[Internals](#internals) · [Controller recovery](#controller-recovery) ·
[Payload lifetime](#payload-lifetime) · [Compatibility](#compatibility) · [Security](#security) ·
[Troubleshooting](#troubleshooting) · [Repository and artifact layout](#repository-and-artifact-layout)

## Standalone use

No code is needed. The download, `steam-input-lease-<version>-win-x64.zip`, holds two files that go
into Steam's folder:

```text
XInput1_4.dll            the gate, already under the name Steam loads
steam-input-lease.exe    the launcher your games start through
```

WSGM deploys this same gate itself. With WSGM installed you do not need these files, and WSGM treats
a gate it finds in Steam's folder as its own.

### Install

1. Exit Steam completely (Steam > Exit, not just closing the window).
2. Copy `XInput1_4.dll` and `steam-input-lease.exe` into Steam's folder, next to `steam.exe`. That is
   usually `C:\Program Files (x86)\Steam`.
3. If Steam's folder already has an `XInput1_4.dll` (ValvePlug and Special K use the same name), keep
   that file and rename ours to `dinput8.dll` instead. If both names are taken, the gate cannot sit
   beside that other program.
4. Start Steam. It loads the gate on startup, and the gate stays out of the way until a launch asks
   for a lease.

To check it, open a terminal in Steam's folder and run:

```text
.\steam-input-lease.exe --status
```

`Gate active; leases=0 ...` means Steam loaded it.

### Steam games

Open the game's Properties, and under General > Launch Options enter:

```text
"C:\Program Files (x86)\Steam\steam-input-lease.exe" -- %command%
```

Use your own Steam path. Options you already had go after `%command%`.

### Non-Steam games added to Steam

A shortcut made with Add a Non-Steam Game takes the same line. Leave Target pointing at the game and
put the line above into its Launch Options.

### Outside Steam

Steam still has to be running. Make a Windows shortcut whose target is the launcher followed by the
game and its arguments:

```text
"C:\Program Files (x86)\Steam\steam-input-lease.exe" -- "D:\Games\Example\game.exe" --any-arguments
```

### What happens

When the game starts, the launcher takes a lease and Steam stops reading your controllers, so the
game can open them directly. When the game and every process it started have exited, Steam gets them
back and looks for them again. A console window stays open behind the game for as long as it runs;
that is the launcher waiting.

If no lease can be taken, for example because Steam has not restarted since the gate was copied in,
the game starts anyway without one. The launcher returns the game's exit code.

### Logs

- `steam-input-lease.log` beside the launcher records the last launch, including why no lease was
  taken.
- `steam-input-gate-<steam-pid>.log` beside the gate is its startup trace for one Steam run. The
  newest eight are kept.

### Uninstall

Exit Steam, delete `XInput1_4.dll` (or `dinput8.dll`), `steam-input-lease.exe` and the
`steam-input-*.log` files from Steam's folder, and remove the launch options.

## Quick start

For applications that take leases themselves, two files matter:

```text
steam_input_gate.dll        the payload; deployed into Steam's directory as XInput1_4.dll
steam_input_lease_ffi.dll   the C ABI your application loads (or the .NET binding over it)
```

1. Deploy the payload before Steam starts. Copy `steam_input_gate.dll` into Steam's install
   directory as `XInput1_4.dll`. If another program already owns that name, and ValvePlug and
   Special K use the same vector, use `dinput8.dll` instead. Steam maps the file on its next cold
   start; a running Steam does not pick it up.
2. Take a lease from your application through the Rust crate, the C ABI or the .NET binding. The
   default client connects to the payload Steam already loaded and never injects.
3. Release when your controller-sensitive surface closes. Dropping the handle is enough, and an
   explicit release also reports the outcome.

Deployment is the consumer's job. This library ships the DLL and its ownership marker, and the
consumer copies, updates and parks it. WSGM's `Core\SteamInputShim.cs` is the reference deployer,
and its rules are under [Deploying the proxy](#deploying-the-proxy). A per-game launch wrapper can
use `steam-input-lease.exe` as it is; see [Launcher](#launcher).

## How it works

```mermaid
flowchart LR
    Steam[Steam client<br/>steam.exe]
    Gate[steam_input_gate.dll<br/>deployed as XInput1_4.dll]
    Pipe[Named pipe<br/>SteamInputGate-PID]
    Host[steam-input-lease<br/>host library]
    CLI[Launcher<br/>steam-input-lease.exe]
    ABI[steam_input_lease_ffi.dll<br/>C ABI]
    DotNet[SteamInputLease.dll<br/>.NET binding]
    Game[Game / SDL3 app]

    Steam -->|LoadLibrary by search order| Gate
    CLI --> Host
    DotNet --> ABI --> Host
    Host <-->|request + lease lifetime| Pipe
    Pipe <--> Gate
    Gate -->|hooks HID and XInput inside, on first lease| Steam
    Host -.->|opt-in only: remote LoadLibraryW| Gate
    Host -->|CreateProcessW + job object| Game
```

1. Steam starts and maps the proxy from its own directory. `DllMain` records the image, pins it and
   starts one worker thread; the worker resolves the real System32 module, releases the forwarders
   and opens the control pipe.
2. The host finds `steam.exe` in the caller's Windows session and connects to
   `\\.\pipe\SteamInputGate-<pid>`. A default client fails with `PayloadUnavailable` when nothing
   answers; only a client that opted in to injection loads `steam_input_gate.dll` through remote
   `LoadLibraryW` and retries.
3. `AcquireLease` installs the hooks if this is the first lease the process has seen, then
   increments the global lease count. On the zero-to-one transition the payload finds, cancels I/O
   on, and closes Steam's existing HID handles.
4. While the count is nonzero, HID opens, HID I/O and XInput queries are denied inside Steam.
5. `ReleaseLease`, pipe EOF or handle disposal decrements the count. At one-to-zero the hooks become
   pass-through immediately and controller rediscovery is requested.

Protocol version `1`. Requests are 8 bytes and responses 24: fixed-width `#[repr(C)]` structs shared
by the host, payload and C ABI. A payload whose hook installation fails answers the acquire with
`HookInstallFailed` instead of granting a lease.

While a lease is held, Steam sees the same class of failures it would see if the controller had been
unplugged, and the controller stays available to everything else. The HID boundary is
controller-agnostic: any HID handle Steam owns can be gated, not just Valve hardware. XInput state
and capability queries are gated both in the proxy forwarders and across the supported system XInput
DLLs.

## Proxy delivery

Everything in this section came out of working against a live client, most of it from Steam hanging
on a cold boot. The constraints are also commented at the code that enforces them
(`crates/steam-input-gate/src/proxy.rs`, `DllMain`, `build.rs`).

Two properties of Steam make a search-order proxy safe, and I checked both on the live client.
Nothing in `steam.exe` hardens the search order: no `SetDefaultDllDirectories` and no
`AddDllDirectory`, and the lone `SetDllDirectoryA` in `SteamUI.dll` cannot displace the application
directory. And nothing in Steam's directory statically imports XInput or DirectInput, so a missing
export degrades a `GetProcAddress` to NULL instead of failing a load.

### Vectors

The payload classifies itself from the file name Steam loaded it under:

| File name | Vector | Forwards to |
| --- | --- | --- |
| `XInput1_4.dll` | primary | `System32\XInput1_4.dll` |
| `dinput8.dll` | fallback, when the primary name is owned by another program | `System32\dinput8.dll` |
| `steam_input_gate.dll` | injected (opt-in and tests) | nothing; no forwarders are served |
| anything else | unknown; forwarding stays blocked | |

The DirectInput vector is a door into the process, not an interception point. Steam Input reads HID
directly, and those hooks are installed process-wide whichever name mapped the image.

### Process attach

`DllMain` does exactly four things, in this order, and never returns `FALSE`. This image is Steam's
`XInput1_4.dll`, so a `FALSE` would make Steam's own `LoadLibraryW` fail, which is worse than any
race the pin guards against.

1. Record its own module handle from the `HINSTANCE` the loader passed in. Until this is known the
   self-identity guard fails closed. Before this ordering existed, every XInput call re-ran a full
   `LoadLibraryExW` of the real module and cached nothing, which is a loader-transaction storm on
   Steam's startup thread, and it hung Steam on every cold boot.
2. Pin the image with `GET_MODULE_HANDLE_EX_FLAG_PIN`, on the loader thread, before any worker
   exists. SDL may `FreeLibrary` XInput right after resolving its exports.
3. `DisableThreadLibraryCalls`.
4. Start the worker thread. All allocation, module resolution, hook installation and pipe setup
   happen there, after the loader lock is released.

### The bootstrap block

Every proxy export starts blocked. Until the worker has cached every required forwarding target, a
call returns its disconnected fallback (`ERROR_DEVICE_NOT_CONNECTED`, `E_FAIL`, or nothing) without
allocating, resolving an export or entering the Windows loader. The worker loads the real module by
full System32 path exactly once, attempts every target, verifies the required table, makes a single
release store, and posts the ordinary `WM_DEVICECHANGE` rediscovery notification so Steam
re-enumerates. A failed initialization is cached and stays blocked, and no Steam call can retry it.
That is the startup property that makes ValvePlug safe, kept while adding dynamic blocking.

The full-path rule stands on its own. The loader keys loaded modules by base name, so once this
image is resident as `xinput1_4.dll`, a bare-name load of `"xinput1_4.dll"` returns this image
regardless of search flags. Every real module is resolved by full path and compared against the
recorded handle, and a self-load is released with `FreeLibrary` and never cached.

Only the exports Steam calls every frame are required for a vector to be usable (`XInputGetState`,
`XInputGetCapabilities`, `XInputSetState`, and `DirectInput8Create`). The undocumented ordinals are
optional because some Windows SKUs lack them, and a missing one costs only its own slot.

### Export map

`build.rs` writes one authoritative `.def` file so the proxy's ordinals match the real
`XInput1_4.dll`. rustc's automatic cdylib ordinals once placed `DirectInput8Create` at XInput's
undocumented ordinal 104 and `DllRegisterServer` at 109, where a dynamic ordinal lookup would have
called an incompatible signature.

| Ordinal | Export | Gated while leased |
| ---: | --- | --- |
| 1 | `DllMain` | |
| 2 | `XInputGetState` | yes |
| 3 | `XInputSetState` | no, rumble is not input |
| 4 | `XInputGetCapabilities` | yes |
| 5 | `XInputEnable` | no |
| 7, 8, 10 | `XInputGetBatteryInformation`, `XInputGetKeystroke`, `XInputGetAudioDeviceIds` | no |
| 100 (NONAME) | `XInputGetStateEx`, reports the Guide button the named entry masks | yes |
| 101, 102, 103 (NONAME) | guide-button wait and cancel, power off | no |
| 108 (NONAME) | `XInputGetCapabilitiesEx` | yes |
| 104, 109 | deliberately empty | |
| 200–205 | `DirectInput8Create`, `DllCanUnloadNow`, `DllGetClassObject`, `DllRegisterServer`, `DllUnregisterServer`, `GetdfDIJoystick` | no |
| 206 | `WsgmSteamInputGateProxy`, the ownership marker, returns the proxy contract version (1) | |

The gate lives in the forwarder as well as in the detour. When Steam loaded the proxy as its XInput,
calls reach this code first, so blocking stays correct even if the hook onto the real module never
lands.

### Hooks are installed on the first lease

As a proxy, the image is mapped during Steam's own startup. MinHook's `MH_ApplyQueued` suspends
every thread in the process, and doing that while Steam's client-verification pass held the loader
hung Steam on the first cold boot after an install. So `ensure_hooks_installed` runs from the first
`AcquireLease` instead: idempotent, serialized, and remembering a failure so a broken environment is
not retried on every acquire. The recovery layout warm-up, a sweep of Steam's address space, starts
only then, for the same reason.

### Startup trace

Every mapped payload writes a per-process trace, `steam-input-gate-<steam-pid>.log`, keeping the
newest eight. A standalone gate writes it beside its own DLL. A gate WSGM deployed writes it to
`%LOCALAPPDATA%\WSGM`, where WSGM reads it; WSGM marks its deployments with a `<name>.wsgm-shim` stamp
beside the proxy. The stamp only chooses between those two directories. `DllMain` and the proxy
exports only update atomics; the worker writes the file after the loader lock is released, so
tracing cannot become a startup dependency. Per-pid names keep a failed boot's trace intact when
Steam is later started by hand for comparison. Debug builds honour `WSGM_STEAM_INPUT_TRACE_DIR`,
and release builds deliberately do not.

The trace records the attach-to-worker delay, which `DllMain` phases ran (attach, self-record, pin
result, worker request), the detected vector, forwarding initialization start and end, how many
startup calls received the bootstrap fallback, the export-resolution counts, the startup
rediscovery, and `control pipe listening`. A missing file means the worker never reached its first
phase, and a last line at `forwarding initialization started` localizes a stall inside that load.

### Control pipe

`\\.\pipe\SteamInputGate-<pid>` rejects remote clients and carries an explicit DACL granting full
access to System, Administrators, and the owner and user of Steam's token only, so a read-only open
cannot consume a pipe instance and worker. If token lookup or SDDL conversion fails, the pipe falls
back to the default descriptor rather than refusing blocking, and the trace says which was used.

The user entry matters when Steam runs elevated. An elevated token is owned by
`BUILTIN\Administrators`, which is deny-only in the same user's normal processes, so without it only
elevated programs could take a lease.

| Client | Can connect |
| --- | --- |
| Any program the same user runs at normal (medium) integrity | yes |
| Elevated programs, and services running as SYSTEM | yes |
| Another user account at normal integrity | no |
| Low-integrity or AppContainer (sandboxed) processes | no |
| Another machine | no |

A service runs in session 0, and the client looks for Steam only in its own session, so a service
still needs its own way to reach the signed-in user's Steam.

Clients open the pipe with identification-level impersonation only, so the server can never act as
the client, and check with `GetNamedPipeServerProcessId` that the server is the target process. A
program that creates `SteamInputGate-<pid>` before the gate does is refused with a `Protocol` error
instead of being trusted with a lease.

### Deploying the proxy

The consumer owns deployment. These are the rules the live client taught, and the ones WSGM's
deployer follows:

- **Prove ownership before touching a file.** The payload exports `WsgmSteamInputGateProxy`, and a
  deployer has to find that marker in a file before replacing it, because other programs claim the
  same names.
- **Never move onto a mapped image.** `REPLACE_EXISTING` fails against a DLL Steam has loaded. A
  stale payload is replaced on the next cold start, and disabling parks the file aside (WSGM renames
  it to `.dlld`) instead of deleting it.
- **Deploy before Steam starts.** The proxy is loaded at process start, so a deployment while Steam
  runs takes effect on the next cold start.
- **Never inject to shortcut the above.** The default client's `PayloadUnavailable` is the correct
  answer when the proxy is not resident.

## Lease lifecycle

| State | Leases | Hook behavior | Next transition |
| --- | ---: | --- | --- |
| Not mapped | | Steam started without the proxy, or it is not deployed | Redeploy and cold-start Steam; a default client reports `PayloadUnavailable` |
| Bootstrapping | | Proxy exports return their disconnected fallback | Worker caches the required forwarding targets and opens the pipe |
| Resident idle, no hooks | 0 | Forwarders pass through; no detour installed | First `AcquireLease` installs the hooks |
| Blocking | ≥1 | HID and XInput denied | More clients increment |
| Final release | 1 → 0 | Pass-through is immediate | Payload requests rediscovery |
| Resident idle | 0 | Hooks installed but inert | Ready for the next lease |

Every acquired connection owns exactly one increment. After its first response the payload worker
blocks on a read, so an explicit `ReleaseLease` gets a response, and a clean close, a crash or a
killed process all produce EOF. Either way the count drops exactly once. Blocking persists until the
last concurrent client releases.

### Release timing

Release returns as soon as blocking is lifted and Steam has been asked to rediscover, not once
controllers are actually back. The payload issues a required follow-up discovery request about 2.2
seconds later on its own timer thread, so a caller that enumerates immediately may still see nothing
for roughly a second. The caller does not wait for it.

The exception is a legacy payload that does not advertise `CAPABILITY_INTERNAL_RECOVERY`. There the
host runs the two-pass recovery itself, and `release()` blocks for roughly 4.5 seconds.

## Rust

```toml
[dependencies]
steam-input-lease = { git = "https://github.com/KillerPixelCrew/steam-input-lease" }
```

The default client targets the current-session `steam.exe`, connects only to a payload Steam already
loaded, and waits up to 10 seconds for its pipe.

```rust
use steam_input_lease::Client;

fn main() -> Result<(), steam_input_lease::Error> {
    let client = Client::default();
    let lease = client.acquire()?;
    println!("blocked; leases={}, revoked handles={}",
        lease.status().lease_count, lease.status().last_revoked_handle_count);

    // Controller-sensitive work here.

    let released = lease.release()?;
    println!("remaining leases={}", released.status.lease_count);
    if let Some(error) = released.recovery.error() {
        // Blocking is lifted either way; Steam just was not asked to look again.
        eprintln!("controller recovery did not run: {error}");
    }
    Ok(())
}
```

| `ClientOptions` field | Default | Meaning |
| --- | --- | --- |
| `target_name` | `steam.exe` | Executable name in the caller's Windows session |
| `payload_path` | `steam_input_gate.dll` beside the executable | Consulted only when `allow_injection` is set |
| `connect_timeout` | 10 s | Wait for the payload pipe, resident or freshly injected |
| `allow_injection` | `false` | Whether the client may inject when no resident payload answers |

Or wrap a whole process tree, created suspended, assigned to a job object, then resumed, so
descendants cannot escape the wait:

```rust
let run = Client::default().run_wrapped([r"D:\Games\Example\game.exe", "--direct-input"])?;
println!("root exit code: {}", run.exit_code);
if let Err(error) = run.release {
    eprintln!("release handshake failed after the process tree exited: {error}");
}
```

`run_unleased` runs a command the same way without a lease and with the environment unchanged. It is
the fail-open path after `run_wrapped` returns an error, which always means the target never
started.

Job creation, assignment and thread resume are all required before the target can run. If accounting
fails only after resume, the library terminates the untrackable job and reports
`ERROR_PROCESS_ABORTED` as the process result. It does not return a pre-start error that could make
a fail-open caller launch the same target twice.

The wrapped child receives a copy of the caller's environment without
`SDL_GAMECONTROLLER_IGNORE_DEVICES`. Steam sets that exclusion for games that use Steam Input, and
keeping it while a lease blocks Steam would also hide the direct controller from SDL. Only the
child's copy is filtered, with a case-insensitive variable-name match, and Steam app and overlay
variables, other SDL hints, the working directory and the arguments are all preserved. A caller that
acquires a lease and launches its own child has to apply the same exclusion removal after
acquisition succeeds.

`Lease::release` is the observable path: it sends `ReleaseLease` and waits for the response.

`Client::acquire_pass_through` temporarily overrides all block leases without consuming them. The C
API exposes `sil_client_acquire_pass_through`, `sil_pass_through_release` and
`sil_pass_through_destroy`, and .NET exposes `SteamInputClient.AcquirePassThrough()` and the
disposable `SteamInputPassThrough` claim. Each claim owns a separate pipe. The final claim's release
or EOF restores blocking only if block leases remain. Overlapping claims keep pass-through active,
and game wrappers may acquire or release their own leases during a handoff without losing ownership.
Callers have to stop conflicting input capture and manage physical visibility before forwarding a
Steam action. This primitive does not touch HidHide and does not detect Steam surface closure.

Wire commands 4 and 5 add acquire and release pass-through without changing existing layouts or
command values. Status bit 1 advertises support and bit 2 reports an active override, while bit 0
keeps its internal-recovery meaning. Lease count remains the number of owned block leases even while
pass-through overrides them. Older gates reject the new acquire command without changing state.
Controller rediscovery stays asynchronous, so a granted claim is not proof Steam has already
enumerated the controller. These additive C exports preserve ABI version 3 and require the matching
client DLL when called.

Dropping a `Lease` closes the pipe and is crash-safe, but reports neither status nor recovery
outcome. An `Err` from release means the release handshake failed. Recovery is reported separately in
`ReleaseOutcome::recovery`, because closing the pipe has already lifted blocking by the time recovery
runs, and a recovery failure must not present a released lease as a failed one.

| `RecoveryOutcome` | Meaning |
| --- | --- |
| `NotRequired` | The target is not Steam |
| `Scheduled` | The payload will schedule discovery on its own timer |
| `Completed(RescanResult)` | The host ran guarded two-pass recovery inline |
| `Unavailable(Error)` | Recovery could not run; blocking was still lifted |

| Method | Purpose |
| --- | --- |
| `Client::acquire` | Take a lease; injects only when `allow_injection` is set |
| `Client::run_wrapped` | Hold a lease around a child process tree |
| `Client::ensure_payload` | Reach the payload without taking a lease; injects only when opted in |
| `Client::status` | Query a loaded payload; never injects |
| `Client::process_id` | Resolve the target pid |
| `Client::rescan` | Guarded two-pass discovery, no lease change |
| `Client::check_recovery` | Prove the current Steam build is resolvable; read-only |

| `Error` variant | Meaning |
| --- | --- |
| `TargetNotFound` | No matching process in this Windows session |
| `AmbiguousTarget` | More than one same-name target exists in this session; no target was chosen |
| `PayloadUnavailable` | No payload pipe answered within the deadline. For a default client the context names the likely causes: the proxy is not deployed, Steam has not cold-started since deployment, or the consumer's Steam Input management is off |
| `PayloadNotFound` | Injection was opted in, but the DLL at `payload_path` is absent |
| `ArchitectureMismatch` | Host and target architectures differ (injection path) |
| `Protocol` | Pipe message, version or result validation failed |
| `UnsupportedSteamBuild` | Analysis could not prove a unique safe recovery target |
| `Windows` | A Win32 call failed; the source carries its OS code |
| `Message` | A validated lifecycle condition failed |

## C ABI

Header: [`include/steam_input_lease.h`](include/steam_input_lease.h). Load
`steam_input_lease_ffi.dll`. The payload reaches Steam through deployment rather than through this
library, unless `allow_injection` is set.

```c
SilClient* client = NULL;
SilLease* lease = NULL;
SilStatus status = {0};
SilReleaseOutcome outcome = {0};
SilClientOptions options = {0};   /* all defaults: steam.exe, 10 s, no injection */

if (sil_abi_version() != 4) {
    fprintf(stderr, "incompatible Steam Input Lease ABI\n");
    return 1;
}
if (sil_client_create(&options, &client) != SIL_OK) {
    fprintf(stderr, "%s\n", sil_last_error_message());
    return 1;
}
if (sil_client_acquire(client, &lease, &status) == SIL_OK) {
    /* Controller-sensitive work. */
    sil_lease_release(lease, &outcome);   /* consumes the lease */
    lease = NULL;
    if (outcome.recovery == SIL_RECOVERY_UNAVAILABLE) {
        /* Blocking was lifted; Steam just was not asked to look again. */
        fprintf(stderr, "%s\n", outcome.recovery_message);
    }
}
sil_lease_destroy(lease);   /* crash-safe close; accepts NULL */
sil_client_destroy(client);
```

`SilClientOptions` carries `target_name`, `payload_path` (consulted only when injecting),
`connect_timeout_ms` (zero means 10 s) and `allow_injection` (non-zero opts in). A zeroed struct is
the production configuration.

| Export | Purpose |
| --- | --- |
| `sil_abi_version` | ABI version of the loaded DLL, currently 4 |
| `sil_last_error_message` | Borrowed thread-local UTF-8 error text |
| `sil_client_create` / `sil_client_destroy` | Client lifetime |
| `sil_client_ensure_payload` | Reach the payload without leasing; injects only when opted in |
| `sil_client_status` | Query a loaded payload; never injects |
| `sil_client_acquire` | Take a lease |
| `sil_lease_release` | Explicit release; consumes the lease |
| `sil_lease_destroy` | Crash-safe close; accepts `NULL` |
| `sil_client_rescan` | Guarded two-pass discovery |
| `sil_client_check_recovery` | Prove the Steam build is resolvable |
| `sil_client_run_wrapped` | Hold a lease around a child process tree |

| Result | Value | Meaning |
| --- | ---: | --- |
| `SIL_OK` | 0 | Success |
| `SIL_ERROR` | 1 | Validated native operation failed |
| `SIL_PANIC` | 2 | A Rust panic was caught at the boundary |

`SilStatus` carries a `capabilities` bitset, where `SIL_CAPABILITY_INTERNAL_RECOVERY` means the
payload runs its own recovery on final release.

`sil_lease_release` returning `SIL_OK` means blocking was lifted. `SilReleaseOutcome::recovery`
separately reports whether Steam was also asked to rediscover controllers:
`SIL_RECOVERY_NOT_REQUIRED`, `SIL_RECOVERY_SCHEDULED`, `SIL_RECOVERY_COMPLETED` (with `rescan`
populated) or `SIL_RECOVERY_UNAVAILABLE` (with a UTF-8 `recovery_message`). The reason travels inside
the struct because `sil_last_error_message()` reports failed calls only, and this call succeeded.

Ownership: create one `SilClient*` and destroy it once. Consume each `SilLease*` exactly once.
`sil_lease_release` consumes it even when it returns an error, including a `NULL` `outcome`, which
closes the lease without a report; only a `NULL` lease is left untouched. `sil_lease_destroy` is the non-reporting close path.

Error lifetime: `sil_last_error_message()` returns a borrowed, NUL-terminated, thread-local pointer
that is never `NULL`. Copy it before the next ABI call on that thread; a successful call also resets
it to an empty string. Never modify or free it.

ABI history: version 2 changed `sil_lease_release` to report a `SilReleaseOutcome`. Version 3 added
the release output to `sil_client_run_wrapped`. Version 4 added `allow_injection` and made proxy
delivery the default, so `payload_path` governs only the opt-in injection path. The ABI
intentionally has no detach or unload call.

## C#

The binding targets `net8.0-windows10.0.17763.0` and wraps each opaque handle (client, lease and
pass-through claim) in a `SafeHandle`.
It calls `sil_abi_version()` before every other native entry point used to create a client and
refuses any version other than ABI 4.

```csharp
using SteamInterop;

using var client = new SteamInputClient();   // steam.exe, 10 s, AllowInjection = false

using SteamInputBlockLease lease = client.Acquire();
Console.WriteLine($"Revoked: {lease.InitialStatus.LastRevokedHandleCount}");

// Controller-sensitive work.

SteamInputReleaseOutcome released = lease.Release();
Console.WriteLine($"Leases after release: {released.Status.LeaseCount}");
if (!released.RecoveryRequested)
{
    // Blocking is lifted either way; Steam just was not asked to look again.
    Console.Error.WriteLine(released.RecoveryMessage);
}
```

A launch wrapper that has to work on a machine without the deployed proxy opts in explicitly:

```csharp
using var client = new SteamInputClient(new SteamInputClientOptions
{
    PayloadPath = Path.Combine(AppContext.BaseDirectory, "steam_input_gate.dll"),
    ConnectTimeout = TimeSpan.FromSeconds(10),
    AllowInjection = true,
});

SteamInputWrappedRun run = client.RunWrapped(@"D:\Games\Example\game.exe", "--direct-input");
uint exitCode = run.ExitCode;
if (!run.Release.RecoveryRequested)
{
    Console.Error.WriteLine(run.Release.RecoveryMessage);
}
```

| Member | Notes |
| --- | --- |
| `SteamInputClient` | `IDisposable`; `Acquire`, `RunWrapped`, `EnsurePayload`, `GetStatus`, `Rescan`, `CheckRecovery` |
| `SteamInputClientOptions` | `TargetName`, `PayloadPath`, `ConnectTimeout`, `AllowInjection` (all `init`; `AllowInjection` defaults to `false`; `ConnectTimeout` must be positive and is rounded up to whole milliseconds, because the native zero means the 10 s default) |
| `SteamInputBlockLease` | `InitialStatus`, `Release()`, `Dispose()`; obtained only from `Acquire()` |
| `SteamInputStatus` | `readonly record struct (ushort Capabilities, uint LeaseCount, uint HidHandleCount, uint LastRevokedHandleCount)` plus `SupportsInternalRecovery` |
| `SteamControllerRescanResult` | `(double PreviousDeadline, uint ScanCountBefore, uint ScanCountAfter)` |
| `SteamInputLeaseException` | Carries `int NativeResult` |

`Release()` performs the explicit handshake and consumes the managed lease. `Dispose()` closes the
crash-safe pipe if `Release()` was not called.

The binding is available as a project reference or as the generated local NuGet package. Build the
Cargo release artifacts first, because the package's native assets are conditional on
`target\x86_64-pc-windows-msvc\release\*.dll` existing. The build script creates and verifies those
x64 images before packing, so use it rather than `dotnet pack`.

```powershell
.\scripts\build.ps1
dotnet add package SteamInputLease --version 0.1.0 --source .\artifacts\packages
```

## Launcher

`steam-input-lease.exe` is the launcher from [Standalone use](#standalone-use) and the diagnostic
front end. Like the library defaults, it connects only to a gate Steam already loaded unless
`--inject` asks for injection.

```text
steam-input-lease.exe -- program.exe arguments
steam-input-lease.exe --status
steam-input-lease.exe --rescan
steam-input-lease.exe --target-name process.exe --inject --payload D:\path\steam_input_gate.dll -- command.exe args...
```

| Option | Behavior |
| --- | --- |
| `--` | Ends launcher options; the rest is the program and its arguments |
| `--status` | Queries an already loaded gate; never injects |
| `--rescan` | Guarded two-pass discovery without changing leases |
| `--inject` | Injects `steam_input_gate.dll` when no gate answers; for tests and diagnostics |
| `--payload PATH` | The DLL `--inject` loads, instead of the one beside the launcher |
| `--target-name NAME` | Overrides `steam.exe`; for diagnostics and tests |
| `--help`, `-h` | Prints usage |

A launch without `--inject` waits two seconds for the gate's pipe, because a resident gate keeps its
pipe for as long as Steam runs. With `--inject` it keeps the library's ten seconds for a fresh
payload to start its server. When no lease can be taken, the program still runs through
`run_unleased`, with its environment unchanged. Each launch rewrites `steam-input-lease.log` beside
the launcher.

`--status` and `--rescan` take precedence over a program given on the same line. There is no flag
for `check_recovery`; use the Rust, C or C# API.

Exit codes: a launch returns the program's full exit code, including NTSTATUS crash codes like
`0xC0000005`. `--status`, `--rescan` and `--help` return `0`, and errors return `1`.

## Building and testing

```powershell
cargo build --workspace --release --target x86_64-pc-windows-msvc
dotnet build .\bindings\SteamInterop.Net\SteamInterop.Net.csproj -c Release
```

Quality gates:

```powershell
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo test --workspace --target x86_64-pc-windows-msvc
$env:RUSTDOCFLAGS = '-D warnings'; cargo doc --workspace --no-deps --target x86_64-pc-windows-msvc; Remove-Item Env:RUSTDOCFLAGS
```

The library crates use `#![deny(missing_docs)]`, so undocumented public API is a compile error.
There is deliberately no `cargo fmt` gate.

The proxy export map is part of the contract. A consumer's release build should inspect the finished
`steam_input_gate.dll` with `dumpbin /exports` and fail if the ordinals above have drifted. WSGM's
`eng\build-steam-input-lease.ps1 -Validate` does exactly that.

### Isolated injection test

```powershell
.\scripts\test-lifecycle.ps1 -Profile release
```

`-Profile` defaults to `debug`. The test touches neither Steam nor a real controller. It starts
`steam-input-test-target.exe` as a TCP-controlled process, injects the gate into it through the
launcher's `--inject` path, then checks that opening a deliberately nonexistent HID-style path:

1. fails with an ordinary error, not blocked, before any lease;
2. fails with `433` (`ERROR_NO_SUCH_DEVICE`) while a lease is held;
3. returns to the ordinary not-blocked error after release.

It also asserts that the wrapped child's exit code is propagated exactly (`23`), that a delayed
descendant is included in the job lifetime after its root exits, and that the resident payload still
answers a non-injecting `--status` query. Steps 1 and 3 assert only that the result is not the
blocked error, not a specific code. Loaded under its own file name the payload serves no forwarders,
so this test covers the hooks and the lease protocol rather than the proxy bootstrap; that half is
covered by the export-map check and by running against a live Steam.

The wrapped-child check also supplies an SDL controller exclusion and verifies that the child loses
it while keeping `SteamAppId`, with the caller's environment unchanged.

### Package

```powershell
.\scripts\build.ps1
```

Builds the workspace and the managed project, then writes the portable layout to
`artifacts\win-x64`, the NuGet package to `artifacts\packages`, and the standalone download to
`artifacts\steam-input-lease-<version>-win-x64.zip`. The native target is explicitly
`x86_64-pc-windows-msvc`, so the `-Runtime` parameter is constrained to `win-x64` and does not
cross-compile. `-SkipTests` leaves out the Cargo test run so a build can go to manual testing first;
clippy, the documentation build and packaging still run.

The shipped C# sample (`samples\SteamInterop.CSharpExample`) reads `SIL_TARGET_NAME` and
`SIL_PAYLOAD_PATH` from the environment. Supplying a custom target selects diagnostic mode and
enables injection for that target, while the production Steam defaults stay non-injecting. With no
arguments the sample calls `EnsurePayload()`, and otherwise it wraps its arguments with
`RunWrapped`.

## Internals

### Opt-in injection

When a client has `allow_injection` set and a 20 ms probe finds no resident pipe, the host opens the
target with the rights needed for remote `LoadLibraryW`, verifies architecture with
`IsWow64Process2`, resolves the target's `kernel32.dll` base through Toolhelp, and computes the
remote `LoadLibraryW` address from the local export's module-relative offset, so it never assumes
ASLR picked the same base twice. The UTF-16 payload path is written with `VirtualAllocEx` and
`WriteProcessMemory`, a remote thread calls `LoadLibraryW`, and the remote memory is freed
afterwards. The payload then runs the same `DllMain` and worker as the proxy, classifies its vector
as injected, skips forwarding and opens its pipe. Nothing else differs between the two delivery
paths.

### Hook coverage

| Boundary | Hooked | Blocked behavior |
| --- | --- | --- |
| Proxy forwarders | `XInputGetState`, `XInputGetCapabilities`, ordinals 100 and 108 | `ERROR_DEVICE_NOT_CONNECTED`, before the call reaches the real module |
| Win32 opens | `CreateFileW`, `CreateFileA`, `CreateFile2` | HID paths fail with `ERROR_NO_SUCH_DEVICE` |
| Native opens | `NtCreateFile`, `NtOpenFile` | HID paths fail with `STATUS_DEVICE_NOT_CONNECTED` |
| Native HID I/O | `NtReadFile`, `NtWriteFile`, `NtDeviceIoControlFile` | Known HID handles complete as disconnected |
| Handle lifetime | `NtClose` | Drops closed handles from the table |
| XInput | `XInputGetState`/ordinal 100, `XInputGetCapabilities`/ordinal 108 | `ERROR_DEVICE_NOT_CONNECTED` |

XInput is hooked, where present, in `xinput1_4`, `xinput1_3`, `xinput1_2`, `xinput1_1` and
`xinput9_1_0`, and never in the proxy's own image, which the self-identity guard excludes. Required
hooks are all queued before `MH_ApplyQueued`, so initialization cannot leave a partially enabled
gate. XInput exports are optional because not every DLL exposes every entry point.

### Existing handle discovery

The open hooks cannot see handles Steam opened before the first lease. On the zero-to-one transition
the payload enumerates this process's handle table via
`NtQueryInformationProcess(ProcessHandleInformation)`, falling back to the system-wide
`NtQuerySystemInformation` sweep only where that class is unavailable. It keeps `File` objects,
skips disk and pipe handles (probing those could block on unrelated Steam IPC), identifies HID
handles with `HidD_GetAttributes` under a thread-local probe bypass, then cancels pending I/O and
closes them.

Closing is necessary, not just tidy. Denying I/O alone would leave Steam holding a
share-incompatible handle that stops the SDL3 application opening the controller at all.

### Handle table

Detour bodies never allocate. Classifications live in a fixed 4096-slot open-addressing table behind
an `RwLock`, with key `0` empty and key `1` a tombstone, and probing bounded to 16 slots so no detour
can degrade into a full-table walk. The HID count is maintained atomically for status reporting.
`NtClose` takes only a shared lock unless the handle is actually tracked.

## Controller recovery

Restoring pass-through is not enough to make Steam notice a controller again. Its controller I/O
thread has to be told to run discovery.

Everything is resolved from the loaded `steamclient64.dll` at runtime. There is no Steam version
table, no fixed RVA and no hardcoded object-field offset anywhere in the production implementation.
The `steam-input-recovery` crate:

1. validates the loaded PE32+ image and its sections;
2. locates the MSVC RTTI name `.?AVCHIDIOThread@CSteamController@@`;
3. recovers the primary and secondary vtables through its complete-object locators;
4. decodes the first virtual methods with an x64 instruction decoder and identifies the scheduler by
   semantics: it loads a double deadline, increments a counter through the same object base, then
   stores the deadline back;
5. derives the deadline and counter offsets from those decoded operands;
6. finds the live object in private memory carrying that vtable pair.

Every stage of the image analysis has to be unique. Anything missing or ambiguous fails closed, and
no internal field is written. Before writing, both vtables and the field's alignment and
plausibility are re-verified.

### Electing the live object

Step 6 can legitimately match more than one address. Revoking Steam's HID handles makes it tear down
and rebuild its controller I/O thread, and the freed heap block keeps the class vtables and a
plausible deadline until the allocator hands that memory out again. Such a block is byte for byte a
valid object, so no structural check can reject it.

Only the object a live thread owns keeps scheduling discovery. When several candidates survive
validation, both the host and the payload sample each candidate's deadline and counter, post the
same device-change notification used as the unknown-build fallback so the running thread has a
reason to reschedule, and re-sample for up to 1.5 seconds. Exactly one candidate moving elects it;
no movement, or movement in several, still fails closed. The election never writes to Steam, and the
deadline is compared as raw bits so a field holding NaN in both samples is not mistaken for
movement.

The deadline is then set to the IEEE-754 bits of `-1.0`, which makes the HID thread schedule
discovery on its next loop. Recovery is two-pass because closing Steam's handle can leave queued
zombie-controller cleanup, and the second request, issued about 2.2 seconds later, makes the
post-cleanup state durable. The payload issues it on a shared timer thread rather than making the
caller wait.

### SDL-backed non-Valve controllers

Steam Controllers and SDL-backed controllers do not fail in the same layer. Valve devices are
rediscovered directly by Steam's controller I/O thread. For a non-Valve device such as a DualSense,
an I/O failure can first make SDL HIDAPI retain a dead joystick record. Raw HID enumeration still
sees the physical device, but `SDL_GetJoysticks` gives Steam an empty snapshot, so a Steam-only
discovery request cannot restore it.

On final release the payload therefore repairs the layers in order:

1. find Steam's message-only `SDL_HIDAPI_DEVICE_DETECTION` window and verify that its owner is the
   current Steam process;
2. synchronously send that window a `WM_DEVICECHANGE` / `DBT_DEVICEARRIVAL` event carrying a
   `DBT_DEVTYP_DEVICEINTERFACE` header, which advances SDL's HID device-change generation;
3. resolve the public `SDL_UpdateJoysticks` export from the already loaded `SDL3.dll` and call it
   twice: the first pass can discard the failed retained record and reset SDL's cached generation,
   and the second re-enumerates and adds the controller;
4. run the existing build-independent Steam discovery request, including its delayed second pass.

The message is sent from inside Steam and handled synchronously because its `LPARAM` points to
process-local memory. It is never posted or broadcast to arbitrary windows. The SDL bridge uses only
a window-class name and an exported function name; it contains no SDL RVA, private object offset,
PDB dependency or version profile. If the Steam layout cannot be proven, the payload still performs
the SDL bridge and then falls back to the non-invasive Steam-window device-change notification.

## Payload lifetime

`0.1.0` distinguishes two meanings of "off". Functionally off, meaning `lease_count == 0`, every
hook forwards and Steam is no longer blocked, is fully supported. Structurally unloaded, meaning the
image, hooks and threads removed from Steam, is not.

At process attach the payload pins itself with `GetModuleHandleExW` and
`GET_MODULE_HANDLE_EX_FLAG_PIN`. A pinned module cannot be unpinned for the life of the process.
That is what stops a hook trampoline or a detached worker executing after the image is unmapped, and
it is why protocol version 1 has no `Shutdown`, `Detach` or `FreeLibrary` operation. A deployer that
disables the proxy parks the file aside, and the copy Steam already mapped stays resident until
Steam restarts.

Do not manually unmap the payload. Doing so can leave instruction pointers, hook targets or server
threads referencing freed memory, and crash Steam. A clean unload would need a full quiesce protocol
(reject new acquisitions, drain to zero leases, stop accepting clients, join every worker, disable
hooks, drain executing detours, remove trampolines, then remote `FreeLibrary`), and an already
loaded pinned payload cannot be converted into a safely unloadable one in place.

## Compatibility

- Windows only, and current production use assumes the x64 Steam client.
- Proxy delivery depends on Steam loading `XInput1_4.dll` or `dinput8.dll` by bare name and not
  hardening its search order. Both hold on the live client, and a Steam build that changes either
  simply never loads the payload, with a default client reporting `PayloadUnavailable`.
- The HID and XInput gate itself does not depend on any Steam offset.
- Recovery contains no build table and no fixed RVAs, so routine Steam updates that move code,
  vtables or object fields are re-resolved automatically.
- SDL-backed controller repair likewise contains no SDL code address. It finds the process-local
  detection window and resolves `SDL_UpdateJoysticks` by name.
- A substantial Valve refactor can still break recovery: stripping RTTI, renaming or replacing
  `CHIDIOThread`, changing its inheritance, or rewriting the scheduler so the validated instruction
  semantics disappear.
- Protocol version `1` stays compatible with older payloads. One that does not advertise internal
  recovery triggers host-side recovery on explicit release.

When Valve changes something structural, fix the semantic resolver rather than adding a
build-specific offset profile. Check both that the scan counter advances and that a real block and
release controller cycle works before shipping such a change.

## Security

This project hooks APIs inside Steam by design, and delivers that code as a file in Steam's own
directory.

- Deploying the proxy requires write access to Steam's install directory. The deployer, not this
  library, decides when that happens, and it has to prove ownership of any file it replaces and must
  not overwrite a foreign DLL.
- Replacing `steam_input_gate.dll` changes code that runs inside Steam. Build and distribute it from
  a trusted source.
- A default client never writes into the Steam process. The opt-in injection path performs remote
  `LoadLibraryW`, which endpoint-security products may flag or block, and which a lower-integrity
  process cannot perform against a higher-integrity Steam.
- The host does not bypass access controls, elevate itself or disable security software.
- Process discovery is restricted to the caller's Windows session, so a service or a second
  signed-in user cannot become the target.
- The payload pipe rejects remote clients and carries a DACL scoped to System, Administrators, and
  the owner and user of Steam's token. Clients allow only identification-level impersonation and
  refuse a pipe served by any process other than the target. See [Control pipe](#control-pipe).

The production library creates no network service. The localhost TCP listener exists only in
`steam-input-test-target` during the isolated test.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `target process is not running: steam.exe` | Steam is not in your session, or the diagnostic target name is wrong |
| `multiple ... processes run in this Windows session` | Stop the duplicate diagnostic target, or address it through a single uniquely named executable; name-based discovery refuses ambiguity |
| `no resident Steam Input payload answered` | The proxy is not deployed under a free vector, or Steam has not cold-started since it was deployed, or the deployer parked it because its management setting is off. Check for `steam-input-gate-<pid>.log` beside the gate, or in `%LOCALAPPDATA%\WSGM` for a gate WSGM deployed |
| `the payload pipe for process N is served by process M` | Another program created the gate's pipe name first. Close process M and restart Steam |
| `could not connect to payload pipe: Access is denied` | The client is sandboxed, runs at low integrity, or runs as a different user than Steam. See [Control pipe](#control-pipe) |
| Trace file missing for the running Steam pid | Steam never mapped the payload: wrong directory, wrong name, or the name belongs to another program |
| Trace ends at `forwarding initialization started` | The real System32 module could not be loaded on the worker; every export stays on its fallback |
| Trace shows `missing-required` above zero | The vector was refused; the named exports Steam calls every frame did not resolve |
| `payload not found` | Injection was opted in but the DLL is absent; keep `steam_input_gate.dll` beside the exe or set `--payload` / `payload_path` |
| `OpenProcess failed`, architecture mismatch | Injection path only; run at a compatible integrity level and do not mix x86 and x64 artifacts |
| `HookInstallFailed` on acquire | MinHook could not detour the process; the payload stays a pass-through forwarder and will not retry |
| `--status` says not loaded | The proxy is not resident (see above), and `--status` never injects |
| DLL cannot be overwritten | A loaded payload is locked and pinned; replace it on the next cold start, and build to a separate output directory |

**Unsupported Steam layout** means the resolver could not uniquely prove the RTTI, vtables,
scheduler fields or live object. HID and XInput pass-through is still restored, but no internal
discovery is written. The error text names the stage that failed. Treat ambiguity as a resolver bug
or a Valve structural change, and never substitute unvalidated offsets.

**Controller does not reappear:**

1. Confirm the final status reports `leases=0`.
2. Run `steam-input-lease.exe --rescan` and check the scan counter advances.
3. Confirm Windows still enumerates the controller's HID interface. Steam cannot rediscover hardware
   that is asleep or absent at the OS level.
4. Wake or reconnect the controller and let the normal Windows hotplug fire.
5. Check Steam's `logs\controller.txt` for open and close transitions.

Release returns before rediscovery completes, so give it a second before concluding it failed.

## Repository and artifact layout

| Package | Output | Responsibility |
| --- | --- | --- |
| `steam-input-lease-core` | rlib | Wire protocol, capability flags, pipe naming |
| `steam-input-recovery` | rlib | Build-independent RTTI, vtable and instruction resolver; live-object election |
| `steam-input-lease` | rlib | Discovery, pipe client, leases, process wrapper, opt-in injection |
| `steam-input-gate` | `steam_input_gate.dll` | Proxy forwarders and export map, hook engine, pipe server, startup trace |
| `steam-input-lease-ffi` | `steam_input_lease_ffi.dll` | Stable C ABI |
| `steam-input-lease-cli` | `steam-input-lease.exe` | Console launcher and diagnostics; part of the standalone download |
| `SteamInterop.Net` | `SteamInputLease.dll` | .NET 8 `SafeHandle` binding |
| `steam-input-test-target` | test exe | Isolated injection validation target |

```text
steam-input-lease/                artifacts/                        (after build.ps1)
├── crates/                       ├── steam-input-lease-0.1.0-win-x64.zip
│   ├── steam-input-gate/         ├── standalone/win-x64/           (the zip's contents)
│   ├── steam-input-lease/        │   ├── XInput1_4.dll
│   ├── steam-input-lease-cli/    │   ├── steam-input-lease.exe
│   ├── steam-input-lease-core/   │   └── LICENSE-MIT, README.txt, THIRD_PARTY_LICENSES.md
│   ├── steam-input-lease-ffi/    ├── packages/
│   ├── steam-input-recovery/     │   └── SteamInputLease.0.1.0.nupkg
│   └── steam-input-test-target/  └── win-x64/
├── bindings/SteamInterop.Net/        ├── steam-input-lease.exe
├── include/steam_input_lease.h       ├── steam_input_gate.dll
├── packaging/standalone/README.txt   ├── steam_input_lease_ffi.dll
├── samples/                          │
└── scripts/                          ├── LICENSE-MIT, README.md, THIRD_PARTY_LICENSES.md
                                      ├── include/
                                      ├── managed/
                                      └── native/
```

The standalone download is for people dropping the gate into Steam's folder. Its `README.txt` comes
from `packaging\standalone\README.txt` and covers only installing and using it; keep it in step with
[Standalone use](#standalone-use). In `win-x64/`, the root
copies support direct launcher use, and `native/` and `managed/` support embedding and
redistribution. A consumer ships `steam_input_gate.dll` and `steam_input_lease_ffi.dll`.

## Credits

The blocking model, the start-blocked proxy and the process-attach pin were informed by SpecialKO's
ValvePlug. The payload uses MinHook through the `minhook-sys` crate, and the resolver uses the
`iced-x86` decoder.

Project code is under [`LICENSE-MIT`](LICENSE-MIT). Third-party terms are in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).
