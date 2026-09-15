//! Startup-only diagnostics for the resident proxy.
//!
//! `DllMain` and proxy exports only touch atomics. File creation and writes happen
//! on the gate worker after the loader lock is released, so tracing cannot become
//! another Steam startup dependency. One small file is written per Steam process,
//! beside the gate's own image or in WSGM's log directory when WSGM deployed it,
//! and survives a later manual restart for comparison.

use std::fmt::Display;
use std::fs::{File, OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use windows_sys::Win32::System::SystemInformation::GetTickCount64;

const ATTACH_ENTERED: u32 = 1 << 0;
const SELF_RECORDED: u32 = 1 << 1;
const PIN_SUCCEEDED: u32 = 1 << 2;
const PIN_FAILED: u32 = 1 << 3;
const WORKER_REQUESTED: u32 = 1 << 4;
const WORKER_CREATE_FAILED: u32 = 1 << 5;

static ATTACH_TICK: AtomicU64 = AtomicU64::new(0);
static DLLMAIN_MARKS: AtomicU32 = AtomicU32::new(0);
static BOOTSTRAP_FALLBACK_CALLS: AtomicU32 = AtomicU32::new(0);
static MISSING_REQUIRED_EXPORTS: AtomicUsize = AtomicUsize::new(0);
static MISSING_OPTIONAL_EXPORTS: AtomicUsize = AtomicUsize::new(0);

/// How many per-pid traces survive in the log directory.
const TRACE_RETENTION: usize = 8;

/// Extension of the deployment stamp WSGM writes beside a proxy it deployed,
/// `XInput1_4.dll` becoming `XInput1_4.wsgm-shim`.
const WSGM_DEPLOYMENT_STAMP_EXTENSION: &str = "wsgm-shim";

/// Records entry into the process-attach path without allocation or I/O.
pub(crate) fn mark_attach_entered() {
    let tick = unsafe { GetTickCount64() };
    let _ = ATTACH_TICK.compare_exchange(0, tick, Ordering::Relaxed, Ordering::Relaxed);
    DLLMAIN_MARKS.fetch_or(ATTACH_ENTERED, Ordering::Release);
}

/// Records that the loader-provided module identity was published.
pub(crate) fn mark_self_recorded() {
    DLLMAIN_MARKS.fetch_or(SELF_RECORDED, Ordering::Release);
}

/// Records whether synchronous process-attach pinning succeeded.
pub(crate) fn mark_pin_result(succeeded: bool) {
    DLLMAIN_MARKS.fetch_or(
        if succeeded { PIN_SUCCEEDED } else { PIN_FAILED },
        Ordering::Release,
    );
}

/// Records that `DllMain` is about to ask Windows for the gate worker.
pub(crate) fn mark_worker_requested() {
    DLLMAIN_MARKS.fetch_or(WORKER_REQUESTED, Ordering::Release);
}

/// Records that Windows refused to create the gate worker.
pub(crate) fn mark_worker_create_failed() {
    DLLMAIN_MARKS.fetch_or(WORKER_CREATE_FAILED, Ordering::Release);
}

/// Records how many forwarding-table entries did not resolve, split by whether the
/// vector can survive without them. A non-zero optional count is normal on SKUs
/// missing an undocumented ordinal; a non-zero required count means the vector was
/// refused and every export stays on its fallback.
pub(crate) fn mark_exports_resolved(missing_required: usize, missing_optional: usize) {
    MISSING_REQUIRED_EXPORTS.store(missing_required, Ordering::Release);
    MISSING_OPTIONAL_EXPORTS.store(missing_optional, Ordering::Release);
}

/// Counts an export call that returned its disconnected fallback before forwarding
/// was released. No trace file or lock is touched from the caller's thread.
pub(crate) fn record_bootstrap_fallback() {
    BOOTSTRAP_FALLBACK_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Reads the startup fallback-call count for a worker-side trace snapshot.
pub(crate) fn bootstrap_fallback_calls() -> u32 {
    BOOTSTRAP_FALLBACK_CALLS.load(Ordering::Relaxed)
}

/// Worker-owned startup trace file. A missing file means the worker never reached
/// this point or the user profile directory was unavailable.
pub(crate) struct StartupTrace {
    file: Option<File>,
    worker_started: Instant,
}

impl StartupTrace {
    /// Opens the per-process trace for the gate loaded from `image` and writes the
    /// atomically captured loader phases.
    pub(crate) fn open(image: &Path) -> Self {
        let worker_started = Instant::now();
        let file = trace_path(image).and_then(|path| {
            if let Some(parent) = path.parent() {
                if create_dir_all(parent).is_err() {
                    return None;
                }
                // The new file does not exist yet, so leave room for it. This
                // keeps the post-open total at TRACE_RETENTION rather than
                // retaining eight old files plus the one being created.
                prune_old_traces(parent, TRACE_RETENTION.saturating_sub(1));
            }
            OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(path)
                .ok()
        });
        let mut trace = Self {
            file,
            worker_started,
        };
        let attach_tick = ATTACH_TICK.load(Ordering::Acquire);
        let worker_tick = unsafe { GetTickCount64() };
        let attach_to_worker = worker_tick.saturating_sub(attach_tick);
        trace.log(format_args!(
            "trace v1 pid={} attach-to-worker={} ms",
            std::process::id(),
            attach_to_worker
        ));
        let marks = DLLMAIN_MARKS.load(Ordering::Acquire);
        trace.log(format_args!(
            "DllMain attach={} self-recorded={} pin-succeeded={} pin-failed={} worker-requested={} worker-create-failed={}",
            marks & ATTACH_ENTERED != 0,
            marks & SELF_RECORDED != 0,
            marks & PIN_SUCCEEDED != 0,
            marks & PIN_FAILED != 0,
            marks & WORKER_REQUESTED != 0,
            marks & WORKER_CREATE_FAILED != 0,
        ));
        trace
    }

    /// Appends the forwarding-table resolution counts. Called after
    /// `initialize_forwarding`, so a missing ordinal is visible in a pasted trace
    /// rather than only as a silent fallback.
    pub(crate) fn log_export_resolution(&mut self) {
        self.log(format_args!(
            "forwarding exports missing-required={} missing-optional={}",
            MISSING_REQUIRED_EXPORTS.load(Ordering::Acquire),
            MISSING_OPTIONAL_EXPORTS.load(Ordering::Acquire),
        ));
    }

    /// Appends one worker-side startup phase. It deliberately avoids synchronous
    /// disk flushes that could perturb the cold-start timing being measured.
    pub(crate) fn log(&mut self, message: impl Display) {
        let Some(file) = self.file.as_mut() else {
            return;
        };
        let elapsed = self.worker_started.elapsed().as_millis();
        let _ = writeln!(file, "{elapsed:>6} ms {message}");
    }
}

#[cfg(test)]
fn trace_path(_image: &Path) -> Option<PathBuf> {
    None
}

/// Chooses the trace directory for a gate loaded from `image`.
///
/// A standalone gate writes beside its own image, which is where someone who
/// dropped it into Steam's folder looks. A gate WSGM deployed writes to WSGM's
/// log directory, where WSGM reads it back; WSGM says so by keeping its
/// deployment stamp beside the proxy. The stamp only chooses between these two
/// fixed directories. It never names a path and never proves ownership.
fn trace_directory(
    image: &Path,
    wsgm_managed: bool,
    local_app_data: Option<PathBuf>,
) -> Option<PathBuf> {
    if wsgm_managed {
        local_app_data.map(|path| path.join("WSGM"))
    } else {
        image
            .parent()
            .filter(|directory| !directory.as_os_str().is_empty())
            .map(Path::to_path_buf)
    }
}

/// Whether WSGM's deployment stamp sits beside `image`.
#[cfg(not(test))]
fn wsgm_managed(image: &Path) -> bool {
    image
        .with_extension(WSGM_DEPLOYMENT_STAMP_EXTENSION)
        .is_file()
}

/// The directory override exists only for `scripts/test-lifecycle.ps1` and is
/// compiled out of a release build on purpose. In a shipped DLL it would be an
/// elevated create-and-truncate at a path any same-user process can choose through
/// `HKCU\Environment`, and it would silently disagree with `StartupTracePath` on
/// the C# side, which hard-codes `Log.Directory` - the path WSGM tells the user to
/// look in is the whole remote-diagnosis contract in `docs\steam-input.md`.
#[cfg(all(not(test), debug_assertions))]
fn trace_directory_override() -> Option<PathBuf> {
    std::env::var_os("WSGM_STEAM_INPUT_TRACE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(all(not(test), not(debug_assertions)))]
fn trace_directory_override() -> Option<PathBuf> {
    None
}

/// Keeps the newest few per-pid traces and deletes the rest.
///
/// `wsgm.log` is capped and rotated; this trace is always-on and lands in the same
/// directory the user is asked to open and paste from, so without a cap it buries
/// the file they actually need. Retained deliberately per-pid (not overwritten):
/// `docs\steam-input.md` asks the reader to compare a failed cold boot against a
/// manual start, which needs both files present.
#[cfg(test)]
fn prune_old_traces(_directory: &std::path::Path, _keep: usize) {}

#[cfg(not(test))]
fn prune_old_traces(directory: &std::path::Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut traces: Vec<(std::time::SystemTime, PathBuf)> = entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("steam-input-gate-") && name.ends_with(".log"))
        })
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    if traces.len() <= keep {
        return;
    }
    traces.sort_by_key(|b| std::cmp::Reverse(b.0));
    for (_, path) in traces.into_iter().skip(keep) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(not(test))]
fn trace_path(image: &Path) -> Option<PathBuf> {
    let directory = trace_directory_override().or_else(|| {
        trace_directory(
            image,
            wsgm_managed(image),
            std::env::var_os("LOCALAPPDATA").map(PathBuf::from),
        )
    })?;
    Some(directory.join(format!("steam-input-gate-{}.log", std::process::id())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_standalone_gate_traces_beside_its_own_image() {
        assert_eq!(
            trace_directory(
                Path::new(r"C:\Steam\XInput1_4.dll"),
                false,
                Some(PathBuf::from(r"C:\Users\someone\AppData\Local")),
            ),
            Some(PathBuf::from(r"C:\Steam"))
        );
    }

    #[test]
    fn a_wsgm_deployed_gate_traces_to_the_wsgm_log_directory() {
        assert_eq!(
            trace_directory(
                Path::new(r"C:\Steam\XInput1_4.dll"),
                true,
                Some(PathBuf::from(r"C:\Users\someone\AppData\Local")),
            ),
            Some(PathBuf::from(r"C:\Users\someone\AppData\Local\WSGM"))
        );
        assert_eq!(
            trace_directory(Path::new(r"C:\Steam\XInput1_4.dll"), true, None),
            None
        );
    }

    #[test]
    fn an_image_without_a_directory_has_no_trace_directory() {
        assert_eq!(trace_directory(Path::new(""), false, None), None);
    }

    #[test]
    fn the_wsgm_stamp_sits_beside_the_proxy_under_its_own_stem() {
        assert_eq!(
            Path::new(r"C:\Steam\XInput1_4.dll").with_extension(WSGM_DEPLOYMENT_STAMP_EXTENSION),
            PathBuf::from(r"C:\Steam\XInput1_4.wsgm-shim")
        );
        assert_eq!(
            Path::new(r"C:\Steam\dinput8.dll").with_extension(WSGM_DEPLOYMENT_STAMP_EXTENSION),
            PathBuf::from(r"C:\Steam\dinput8.wsgm-shim")
        );
    }
}
