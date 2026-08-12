//! Reusable host-side API for dynamically leasing Steam Input access.
//!
//! The injected payload is process-global and dormant while no leases exist.
//! A [`Lease`] blocks Steam's HID/XInput access until it is explicitly released
//! or its named-pipe handle is closed.
//!
//! # Lifecycle
//!
//! [`Client::acquire`] first connects to an existing payload or injects
//! `steam_input_gate.dll` through remote `LoadLibraryW`. Each payload connection
//! represents one lease. Dropping a [`Lease`] closes that connection, which is
//! the crash-safe release path; [`Lease::release`] additionally waits for an
//! explicit response. A payload advertising
//! [`CAPABILITY_INTERNAL_RECOVERY`] schedules the follow-up discovery request on
//! its own timer, so release returns before controllers reappear. Only a legacy
//! payload without that capability makes release run the guarded two-pass
//! recovery inline, which takes several seconds.
//!
//! # Platform and compatibility
//!
//! This crate is Windows-only. Host and target architectures must match. The
//! internal Steam discovery fields are derived at runtime from Valve's MSVC
//! RTTI and the loaded HID worker's instruction semantics. Resolution and live
//! object discovery are fail-closed; unknown layouts are never written.

#![cfg_attr(not(windows), allow(dead_code))]
#![deny(missing_docs)]

#[cfg(not(windows))]
compile_error!("steam-input-lease only supports Windows");

use std::ffi::{OsStr, c_void};
use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use steam_input_lease_core::{Command, Request, Response};
use steam_input_recovery::{
    RecoveryLayout, SchedulerSample, find_vtable_pairs, resolve_recovery_layout,
    select_progressing_candidate,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BAD_LENGTH, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, FALSE, HANDLE, HWND,
    INVALID_HANDLE_VALUE, LPARAM, TRUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JobObjectBasicAccountingInformation, QueryInformationJobObject,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_GUARD,
    PAGE_NOACCESS, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx, VirtualQueryEx,
};
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, CreateRemoteThread,
    GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess, GetExitCodeThread, INFINITE,
    IsWow64Process2, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_INFORMATION,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    ResumeThread, STARTUPINFOW, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_DEVICECHANGE,
};

pub use steam_input_lease_core::CAPABILITY_INTERNAL_RECOVERY;

const MODULE_SNAPSHOT_LIMIT: usize = 512 * 1024 * 1024;
const PROCESS_SCAN_CHUNK: usize = 1024 * 1024;

// Bounded retries for a toolhelp module snapshot taken while Steam's loader
// list is changing, and the linearly increasing pause between them.
const MODULE_SNAPSHOT_ATTEMPTS: u32 = 5;
const MODULE_SNAPSHOT_RETRY_DELAY: Duration = Duration::from_millis(10);

// Not exposed by the selected windows-sys API surface; value from the SDK.
const DBT_DEVNODES_CHANGED: usize = 0x0007;

// How long the live-object election watches Steam's scheduler fields, and how
// often it looks. The nudge makes the running thread reschedule well inside
// this budget; the timeout only bounds the case where Steam never moves, which
// ends in the same fail-closed error the election replaced.
const LIVE_ELECTION_TIMEOUT: Duration = Duration::from_millis(1500);
const LIVE_ELECTION_INTERVAL: Duration = Duration::from_millis(125);

// EnumWindows carries no user state through this crate's callback, so the
// target process is published for the duration of one enumeration. Elections
// are serialized by the callers that resolve recovery.
static NOTIFY_TARGET: AtomicU32 = AtomicU32::new(0);

/// Configuration used to locate Steam and inject the payload.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    /// Executable name of the target process in the caller's Windows session.
    /// The production default is `steam.exe`.
    pub target_name: String,
    /// Absolute or relative path of the injected `steam_input_gate.dll`.
    pub payload_path: PathBuf,
    /// Maximum time to wait for the payload pipe after successful injection.
    pub connect_timeout: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        let payload_path = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."))
            .join("steam_input_gate.dll");
        Self {
            target_name: "steam.exe".into(),
            payload_path,
            connect_timeout: Duration::from_secs(10),
        }
    }
}

/// Snapshot returned by the injected payload.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Status {
    /// Capability bitset reported by the payload.
    pub capabilities: u16,
    /// Number of active block leases across all clients.
    pub lease_count: u32,
    /// Number of HID handles currently known to the payload.
    pub hid_handle_count: u32,
    /// Number of handles revoked by the most recent zero-to-one transition.
    pub last_revoked_handle_count: u32,
}

impl From<Response> for Status {
    fn from(value: Response) -> Self {
        Self {
            capabilities: value.capabilities,
            lease_count: value.lease_count,
            hid_handle_count: value.hid_handle_count,
            last_revoked_handle_count: value.last_revoked_handle_count,
        }
    }
}

/// Diagnostics from Steam's guarded controller-discovery transition.
#[derive(Clone, Copy, Debug, Default)]
pub struct RescanResult {
    /// Scan deadline value observed before the first recovery request.
    pub previous_deadline: f64,
    /// Discovery counter observed before the first recovery request.
    pub scan_count_before: u32,
    /// Discovery counter observed after the second recovery request.
    pub scan_count_after: u32,
}

/// What happened to controller recovery during an explicit release.
///
/// Recovery is a separate concern from releasing the lease: blocking is lifted
/// by closing the pipe, and only *telling Steam to look for controllers again*
/// can fail afterwards. Reporting that as a release failure hid a successful
/// release behind an error, so it is carried here instead.
#[derive(Debug)]
pub enum RecoveryOutcome {
    /// The target is not Steam, so no controller recovery applies.
    NotRequired,
    /// The payload advertises internal recovery and scheduled discovery on its
    /// own timer. Controllers reappear shortly after release returns.
    Scheduled,
    /// The host ran the guarded two-pass recovery inline before returning.
    Completed(RescanResult),
    /// Recovery could not run. Blocking is still lifted and Steam keeps
    /// working; it has simply not been asked to rediscover controllers, so a
    /// controller may stay missing until Steam notices by itself.
    Unavailable(Error),
}

impl RecoveryOutcome {
    /// Whether Steam was successfully asked to rediscover controllers.
    #[must_use]
    pub const fn requested(&self) -> bool {
        matches!(self, Self::Scheduled | Self::Completed(_))
    }

    /// The error explaining why recovery could not run, if it could not.
    #[must_use]
    pub const fn error(&self) -> Option<&Error> {
        match self {
            Self::Unavailable(error) => Some(error),
            _ => None,
        }
    }
}

/// Result of a completed [`Client::run_wrapped`]: the target ran to completion,
/// and the final release either happened or failed afterwards.
#[derive(Debug)]
pub struct WrappedRun {
    /// Exit code of the launched root process.
    pub exit_code: u32,
    /// The final release handshake. An `Err` here is deliberately NOT a run
    /// failure — the game already exited, and reporting it as one made the
    /// wrapper start the finished game a second time — but the caller should
    /// report it, because a lease that did not recover leaves Steam without the
    /// controller until the process dies.
    pub release: std::result::Result<ReleaseOutcome, Error>,
}

/// Result of an explicit release. Blocking has been lifted whenever this is
/// returned; [`ReleaseOutcome::recovery`] reports what happened afterwards.
#[derive(Debug)]
pub struct ReleaseOutcome {
    /// Payload status from the release handshake.
    pub status: Status,
    /// Whether and how Steam was asked to rediscover controllers.
    pub recovery: RecoveryOutcome,
}

/// Errors produced while locating Steam, injecting, communicating, launching,
/// or requesting guarded controller recovery.
#[derive(Debug)]
pub enum Error {
    /// No matching process exists in the caller's Windows session.
    TargetNotFound(String),
    /// Injection was required, but the configured payload path does not exist.
    PayloadNotFound(PathBuf),
    /// The host executable and target process use different architectures.
    ArchitectureMismatch,
    /// The target payload rejected or returned an incompatible wire message.
    Protocol(String),
    /// Runtime analysis could not prove a safe Steam recovery target.
    UnsupportedSteamBuild(String),
    /// A Win32 operation failed and supplied an OS error code.
    Windows {
        /// Human-readable name of the failed operation.
        operation: &'static str,
        /// Error captured immediately through `GetLastError`.
        source: io::Error,
    },
    /// A library validation or lifecycle operation failed without a dedicated
    /// error variant.
    Message(String),
}

impl Error {
    fn windows(operation: &'static str) -> Self {
        Self::Windows {
            operation,
            source: io::Error::last_os_error(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetNotFound(name) => {
                write!(formatter, "target process is not running: {name}")
            }
            Self::PayloadNotFound(path) => {
                write!(formatter, "payload not found: {}", path.display())
            }
            Self::ArchitectureMismatch => {
                formatter.write_str("the library and target process have different architectures")
            }
            Self::Protocol(message)
            | Self::UnsupportedSteamBuild(message)
            | Self::Message(message) => formatter.write_str(message),
            Self::Windows { operation, source } => write!(formatter, "{operation}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Windows { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Result type returned by the host library.
pub type Result<T> = std::result::Result<T, Error>;

/// Reusable connection/injection configuration.
#[derive(Clone, Debug)]
pub struct Client {
    options: ClientOptions,
}

impl Default for Client {
    fn default() -> Self {
        Self::new(ClientOptions::default())
    }
}

impl Client {
    /// Creates a reusable client from explicit process and payload options.
    #[must_use]
    pub const fn new(options: ClientOptions) -> Self {
        Self { options }
    }

    /// Returns the immutable options used by this client.
    #[must_use]
    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// Locates the configured target in the caller's Windows session.
    ///
    /// # Errors
    /// [`Error::TargetNotFound`] when no process of that name runs in the
    /// caller's session. Steam is simply not running; the caller should treat
    /// the lease as unavailable rather than retry immediately.
    pub fn process_id(&self) -> Result<u32> {
        find_process(&self.options.target_name)
            .ok_or_else(|| Error::TargetNotFound(self.options.target_name.clone()))
    }

    /// Ensures that the payload is loaded, without acquiring a block lease.
    ///
    /// # Errors
    /// Everything [`Client::acquire`] can return except that no lease is taken:
    /// [`Error::TargetNotFound`], [`Error::PayloadNotFound`],
    /// [`Error::ArchitectureMismatch`], [`Error::Windows`], [`Error::Message`]
    /// or [`Error::Protocol`]. Nothing in Steam has been changed on failure.
    pub fn ensure_payload(&self) -> Result<Status> {
        let process_id = self.process_id()?;
        let pipe = self.connect_or_inject(process_id)?;
        exchange(pipe.raw(), Command::QueryStatus).map(Status::from)
    }

    /// Queries an already loaded payload. This never injects.
    ///
    /// # Errors
    /// [`Error::TargetNotFound`] when Steam is not running, [`Error::Windows`]
    /// when the payload pipe does not answer within the short fixed probe
    /// timeout, or [`Error::Protocol`] for an incompatible payload. A failure
    /// means "no usable payload right now", never that blocking changed.
    pub fn status(&self) -> Result<Status> {
        let process_id = self.process_id()?;
        let pipe = connect_pipe(process_id, Duration::from_millis(500))?;
        exchange(pipe.raw(), Command::QueryStatus).map(Status::from)
    }

    /// Acquires a crash-safe Steam Input block lease.
    ///
    /// # Errors
    /// [`Error::TargetNotFound`] when Steam is not running,
    /// [`Error::PayloadNotFound`] when injection was required but
    /// `steam_input_gate.dll` is missing beside the caller,
    /// [`Error::ArchitectureMismatch`] for a bitness mismatch,
    /// [`Error::Windows`] for a failed Win32 step, [`Error::Message`] when the
    /// payload loaded but its control pipe never appeared, or
    /// [`Error::Protocol`] for an incompatible payload. No lease exists in any
    /// of those cases, so the caller should fail open and run without one.
    pub fn acquire(&self) -> Result<Lease> {
        let process_id = self.process_id()?;
        let pipe = self.connect_or_inject(process_id)?;
        let response = exchange(pipe.raw(), Command::AcquireLease)?;
        Ok(Lease {
            pipe: Some(pipe),
            process_id,
            target_is_steam: self.options.target_name.eq_ignore_ascii_case("steam.exe"),
            acquired_status: response.into(),
        })
    }

    /// Runs a command while a lease is held and waits for its process tree.
    ///
    /// The command is started suspended, assigned to a Windows job object, and
    /// then resumed so quickly spawned descendants are included in the wait.
    /// Release is attempted even when process creation or waiting fails.
    ///
    /// Returns the root process exit code and the final release handshake.
    ///
    /// # Errors
    /// [`Error::Message`] for an empty command, everything [`Client::acquire`]
    /// can return, and [`Error::Windows`] when `CreateProcessW` fails. An error
    /// means the target NEVER STARTED, so the caller may safely launch it
    /// itself; a failed release after a completed run is deliberately not an
    /// error, or the caller would start a finished game a second time — it is
    /// reported through [`WrappedRun::release`] instead so the caller can still
    /// log that Steam was left without controller recovery.
    pub fn run_wrapped<I, S>(&self, command: I) -> Result<WrappedRun>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let arguments: Vec<Vec<u16>> = command
            .into_iter()
            .map(|part| part.as_ref().encode_wide().collect())
            .collect();
        if arguments.is_empty() {
            return Err(Error::Message("the wrapped command is empty".into()));
        }
        let lease = self.acquire()?;
        let launched = launch_and_wait(&arguments);
        let released = lease.release();
        match (launched, released) {
            // An error from this function means the target never ran, because that
            // is what the caller does about it: WSGM.Launch fails open by launching
            // the command itself. A release handshake that fails AFTER the game has
            // already exited must therefore not surface as an error — Steam quits
            // during play often enough, and reporting it made the wrapper start the
            // finished game a second time. Blocking is lifted either way: the lease
            // is an open pipe connection that Windows drops with this process.
            (Ok(exit_code), release) => Ok(WrappedRun { exit_code, release }),
            (Err(launch_error), _) => Err(launch_error),
        }
    }

    /// Requests Steam's internal discovery twice to survive stale cleanup.
    ///
    /// This method does not acquire or release a block lease. It validates the
    /// runtime-resolved Steam object layout before writing the deadline.
    ///
    /// # Errors
    /// [`Error::TargetNotFound`] when Steam is not running,
    /// [`Error::UnsupportedSteamBuild`] when the layout or the live
    /// `CHIDIOThread` could not be proven, or [`Error::Windows`] for a failed
    /// read/write. Resolution is fail-closed, so a failure means the guarded
    /// deadline write was skipped for that pass and controllers may stay
    /// missing until Steam notices by itself; nothing else is ever written.
    pub fn rescan(&self) -> Result<RescanResult> {
        rescan_steam_controllers(self.process_id()?)
    }

    /// Validates that the host can resolve the current Steam build's controller
    /// discovery target without changing controller state or acquiring a lease.
    /// This is the authoritative compatibility probe when the injected payload's
    /// in-process resolver is unavailable.
    ///
    /// # Errors
    /// [`Error::TargetNotFound`], [`Error::UnsupportedSteamBuild`] when the
    /// build's layout or live `CHIDIOThread` cannot be proven, or
    /// [`Error::Windows`]. This probe writes nothing, so a failure is a
    /// heads-up for the log and never a reason to abandon a lease.
    pub fn check_recovery(&self) -> Result<()> {
        resolve_remote_recovery(self.process_id()?).map(|_| ())
    }

    // The initial probe only has to cover the window in which a resident payload
    // has momentarily no free pipe instance: the server accepts a connection,
    // spawns a worker, then loops back to CreateNamedPipeW. That gap is one
    // CreateNamedPipeW plus one CreateThread, so a handful of retries is ample.
    // Concluding "not injected" too early costs a redundant re-injection.
    fn connect_or_inject(&self, process_id: u32) -> Result<OwnedHandle> {
        if let Ok(pipe) = connect_pipe(process_id, Duration::from_millis(20)) {
            return Ok(pipe);
        }
        if !self.options.payload_path.is_file() {
            return Err(Error::PayloadNotFound(self.options.payload_path.clone()));
        }
        inject_payload(process_id, &self.options.payload_path)?;
        connect_pipe(process_id, self.options.connect_timeout).map_err(|_| {
            Error::Message(
                "the payload loaded, but its control pipe did not become available".into(),
            )
        })
    }
}

/// An active lease. Closing the underlying pipe is the crash-safe release path.
#[derive(Debug)]
pub struct Lease {
    pipe: Option<OwnedHandle>,
    process_id: u32,
    target_is_steam: bool,
    acquired_status: Status,
}

impl Lease {
    /// Returns the payload status captured when this lease was acquired.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.acquired_status
    }

    /// Explicitly releases this lease.
    ///
    /// An error means the release *handshake* failed. Recovery is reported
    /// through [`ReleaseOutcome::recovery`] instead of as an error, because
    /// closing the pipe has already lifted blocking by the time recovery is
    /// attempted: a recovery failure must not present a released lease as a
    /// failed one.
    ///
    /// This returns once blocking has been lifted and Steam has been asked to
    /// rediscover controllers, not once rediscovery has finished: the payload
    /// issues its follow-up discovery request on its own timer. A caller that
    /// enumerates controllers immediately may therefore still observe none for
    /// roughly a second.
    ///
    /// For legacy payloads without internal recovery capability, the host runs
    /// the same guarded two-pass recovery before returning, which blocks the
    /// caller for roughly four and a half seconds. Dropping the lease
    /// without calling this method still closes the pipe and releases blocking,
    /// which remains the crash-safe path, but reports neither status nor
    /// recovery outcome.
    ///
    /// # Errors
    /// [`Error::Windows`] when the release handshake could not be written or
    /// read, or [`Error::Protocol`] for an incompatible response. Blocking has
    /// been lifted in both cases because the pipe is already closed, so a
    /// caller must log the failure and continue rather than retry the release.
    /// A recovery failure is never reported here; see
    /// [`ReleaseOutcome::recovery`].
    pub fn release(mut self) -> Result<ReleaseOutcome> {
        let pipe = self.pipe.take().expect("lease pipe must exist");
        let response = exchange(pipe.raw(), Command::ReleaseLease);
        drop(pipe);
        let response = response?;
        let recovery = if !self.target_is_steam {
            RecoveryOutcome::NotRequired
        } else if response.has_internal_recovery() {
            RecoveryOutcome::Scheduled
        } else {
            match rescan_steam_controllers(self.process_id) {
                Ok(result) => RecoveryOutcome::Completed(result),
                Err(error) => RecoveryOutcome::Unavailable(error),
            }
        };
        Ok(ReleaseOutcome {
            status: response.into(),
            recovery,
        })
    }
}

#[derive(Debug)]
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    unsafe fn from_raw(handle: HANDLE) -> Self {
        Self(handle)
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn wide_nul(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn wide_slice_to_string(value: &[u16]) -> String {
    let length = value
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..length])
}

fn wide_eq_ignore_ascii_case(wide: &[u16], ascii: &str) -> bool {
    // The `unit < 128` test is required rather than cosmetic: without it a
    // non-ASCII code unit could alias onto an ASCII byte once truncated by
    // `as u8` and false-match a name that selects an injection target.
    let length = wide.iter().position(|&unit| unit == 0).unwrap_or(wide.len());
    length == ascii.len()
        && wide[..length]
            .iter()
            .zip(ascii.bytes())
            .all(|(&unit, byte)| unit < 128 && (unit as u8).eq_ignore_ascii_case(&byte))
}

fn find_process(process_name: &str) -> Option<u32> {
    // Restrict discovery to the caller's interactive session so a service or
    // second signed-in user cannot accidentally become the injection target.
    unsafe {
        let mut current_session = 0;
        if ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session) == FALSE {
            return None;
        }
        let snapshot = OwnedHandle::from_raw(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if snapshot.raw() == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot.raw(), &mut entry) == FALSE {
            return None;
        }
        loop {
            let mut candidate_session = 0;
            if wide_eq_ignore_ascii_case(&entry.szExeFile, process_name)
                && ProcessIdToSessionId(entry.th32ProcessID, &mut candidate_session) != FALSE
                && candidate_session == current_session
            {
                return Some(entry.th32ProcessID);
            }
            if Process32NextW(snapshot.raw(), &mut entry) == FALSE {
                return None;
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RemoteModule {
    base: usize,
    size: usize,
}

fn remote_module(process_id: u32, module_name: &str) -> Option<RemoteModule> {
    // Toolhelp module snapshots can transiently return ERROR_BAD_LENGTH while
    // the loader list changes, so retry that documented condition. Enumerating
    // the fresh snapshot can fail for the same reason, so it retries too.
    // Retries back off: without a pause every attempt lands inside the same
    // loader mutation, and the caller then reports steamclient64.dll missing
    // from a Steam that has plainly loaded it.
    unsafe {
        for attempt in 0..MODULE_SNAPSHOT_ATTEMPTS {
            if attempt > 0 {
                thread::sleep(MODULE_SNAPSHOT_RETRY_DELAY * attempt);
            }
            let snapshot = OwnedHandle::from_raw(CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                process_id,
            ));
            if snapshot.raw() == INVALID_HANDLE_VALUE {
                if io::Error::last_os_error().raw_os_error() == Some(ERROR_BAD_LENGTH as i32) {
                    continue;
                }
                return None;
            }
            let mut entry: MODULEENTRY32W = zeroed();
            entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
            if Module32FirstW(snapshot.raw(), &mut entry) == FALSE {
                continue;
            }
            loop {
                if wide_slice_to_string(&entry.szModule).eq_ignore_ascii_case(module_name) {
                    return Some(RemoteModule {
                        base: entry.modBaseAddr as usize,
                        size: entry.modBaseSize as usize,
                    });
                }
                if Module32NextW(snapshot.raw(), &mut entry) == FALSE {
                    break;
                }
            }
            return None;
        }
        None
    }
}

fn remote_module_base(process_id: u32, module_name: &str) -> Option<usize> {
    remote_module(process_id, module_name).map(|module| module.base)
}

unsafe fn read_remote<T: Copy>(process: HANDLE, address: usize) -> Result<T> {
    // Read through ReadProcessMemory rather than dereferencing a foreign
    // address. Exact byte counts are required for every guarded object field.
    let mut value: T = unsafe { zeroed() };
    let mut transferred = 0;
    if unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            (&mut value as *mut T).cast(),
            size_of::<T>(),
            &mut transferred,
        )
    } == FALSE
        || transferred != size_of::<T>()
    {
        return Err(Error::windows("ReadProcessMemory failed"));
    }
    Ok(value)
}

struct RemoteRecoveryTarget {
    process: OwnedHandle,
    hid_thread: usize,
    deadline_offset: usize,
    counter_offset: usize,
    primary_vtable: usize,
    secondary_vtable: usize,
    secondary_object_offset: usize,
}

/// Single definition of "the resolved address still holds Steam's live
/// `CHIDIOThread`". Both embedded vtable slots must still match the pair the
/// address was identified by, and the deadline field must still read as a
/// plausible scheduling value; anything else means the object was freed and its
/// storage reused.
unsafe fn hid_thread_is_live(
    process: HANDLE,
    hid_thread: usize,
    primary_vtable: usize,
    secondary_vtable: usize,
    secondary_object_offset: usize,
    deadline_offset: usize,
) -> bool {
    unsafe {
        read_remote::<usize>(process, hid_thread).is_ok_and(|value| value == primary_vtable)
            && read_remote::<usize>(process, hid_thread + secondary_object_offset)
                .is_ok_and(|value| value == secondary_vtable)
            && read_remote::<f64>(process, hid_thread + deadline_offset).is_ok_and(|value| {
                value.is_finite() && (value == -1.0 || (0.0..1.0e12).contains(&value))
            })
    }
}

fn validate_remote_hid_thread(target: &RemoteRecoveryTarget) -> bool {
    unsafe {
        hid_thread_is_live(
            target.process.raw(),
            target.hid_thread,
            target.primary_vtable,
            target.secondary_vtable,
            target.secondary_object_offset,
            target.deadline_offset,
        )
    }
}

fn memory_is_readable(memory: &MEMORY_BASIC_INFORMATION) -> bool {
    memory.State == MEM_COMMIT
        && memory.Protect & PAGE_GUARD == 0
        && memory.Protect & PAGE_NOACCESS == 0
}

unsafe fn snapshot_remote_module(process: HANDLE, module: RemoteModule) -> Result<Vec<u8>> {
    if module.size == 0 || module.size > MODULE_SNAPSHOT_LIMIT {
        return Err(Error::UnsupportedSteamBuild(
            "steamclient64.dll reported an implausible image size".into(),
        ));
    }
    let mut image = vec![0u8; module.size];
    let end = module.base.saturating_add(module.size);
    let mut address = module.base;
    while address < end {
        let mut memory: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        if unsafe {
            VirtualQueryEx(
                process,
                address as *const c_void,
                &mut memory,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0
        {
            address = address.saturating_add(0x1000);
            continue;
        }
        let region_start = (memory.BaseAddress as usize).max(address);
        let region_end = (memory.BaseAddress as usize)
            .saturating_add(memory.RegionSize)
            .min(end);
        if region_end <= region_start {
            address = address.saturating_add(0x1000);
            continue;
        }
        if memory_is_readable(&memory) {
            let destination = region_start - module.base;
            let length = region_end - region_start;
            let mut transferred = 0;
            unsafe {
                ReadProcessMemory(
                    process,
                    region_start as *const c_void,
                    image[destination..destination + length].as_mut_ptr().cast(),
                    length,
                    &mut transferred,
                );
            }
        }
        address = region_end;
    }
    Ok(image)
}

unsafe fn find_remote_hid_thread(
    process: HANDLE,
    process_id: u32,
    steamclient: RemoteModule,
    layout: RecoveryLayout,
) -> Result<usize> {
    let primary = steamclient.base + layout.primary_vtable_rva as usize;
    let secondary = steamclient.base + layout.secondary_vtable_rva as usize;
    let pair_size = layout.secondary_object_offset as usize + size_of::<usize>();

    let mut candidates = Vec::new();
    let mut buffer = vec![0u8; PROCESS_SCAN_CHUNK];
    let mut address = 0x1_0000usize;
    while address < usize::MAX / 2 {
        let mut memory: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        if unsafe {
            VirtualQueryEx(
                process,
                address as *const c_void,
                &mut memory,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        } == 0
        {
            break;
        }
        let region_start = memory.BaseAddress as usize;
        let region_end = region_start.saturating_add(memory.RegionSize);
        if memory_is_readable(&memory) && memory.Type == MEM_PRIVATE {
            let mut chunk_start = region_start;
            while chunk_start < region_end {
                let chunk_end = chunk_start
                    .saturating_add(PROCESS_SCAN_CHUNK)
                    .min(region_end);
                let length = chunk_end - chunk_start;
                let mut transferred = 0;
                if unsafe {
                    ReadProcessMemory(
                        process,
                        chunk_start as *const c_void,
                        buffer.as_mut_ptr().cast(),
                        length,
                        &mut transferred,
                    )
                } != FALSE
                {
                    // Only the bytes this read actually delivered may be
                    // matched. Everything past `transferred` is still the
                    // previous chunk's contents, and a candidate manufactured
                    // from that stale data would be an address this code later
                    // hands to WriteProcessMemory inside Steam.
                    candidates.extend(find_vtable_pairs(
                        &buffer[..transferred],
                        chunk_start,
                        primary,
                        secondary,
                        layout.secondary_object_offset as usize,
                    ));
                }
                if chunk_end == region_end {
                    break;
                }
                chunk_start = chunk_end.saturating_sub(pair_size.saturating_sub(1));
            }
        }
        if region_end <= address {
            break;
        }
        address = region_end;
    }

    candidates.retain(|&candidate| unsafe {
        hid_thread_is_live(
            process,
            candidate,
            primary,
            secondary,
            layout.secondary_object_offset as usize,
            layout.discovery_deadline_offset as usize,
        )
    });
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [candidate] => Ok(*candidate),
        [] => Err(Error::UnsupportedSteamBuild(
            "runtime RTTI resolved, but Steam's live CHIDIOThread object was not found".into(),
        )),
        _ => unsafe { elect_running_hid_thread(process, process_id, &candidates, layout) },
    }
}

/// Separates the running HID thread from abandoned look-alikes by watching
/// which candidate keeps scheduling discovery.
///
/// Closing Steam's HID handles makes it tear its HID thread down and build a
/// new one, and the freed block keeps the class vtables and a plausible
/// deadline until the allocator hands that memory out again. Structural checks
/// cannot tell the two apart because the abandoned copy is byte-for-byte a
/// valid object; only the live one still moves.
///
/// Steam is nudged with the same device-change notification the payload uses as
/// its compatibility fallback, so the running thread is given a reason to
/// reschedule instead of leaving this to a quiet moment. Nothing is written to
/// Steam here, and an election that stays ambiguous returns the same
/// fail-closed error as before.
unsafe fn elect_running_hid_thread(
    process: HANDLE,
    process_id: u32,
    candidates: &[usize],
    layout: RecoveryLayout,
) -> Result<usize> {
    let deadline_offset = layout.discovery_deadline_offset as usize;
    let counter_offset = layout.discovery_counter_offset as usize;
    let Some(before) =
        (unsafe { sample_candidates(process, candidates, deadline_offset, counter_offset) })
    else {
        return Err(unreadable_candidates(candidates));
    };
    notify_device_change(process_id);

    let deadline = Instant::now() + LIVE_ELECTION_TIMEOUT;
    let mut last = before.clone();
    while Instant::now() < deadline {
        thread::sleep(LIVE_ELECTION_INTERVAL);
        let Some(after) =
            (unsafe { sample_candidates(process, candidates, deadline_offset, counter_offset) })
        else {
            return Err(unreadable_candidates(candidates));
        };
        if let Some(index) = select_progressing_candidate(&before, &after) {
            return Ok(candidates[index]);
        }
        last = after;
    }
    // The election gave up. Embed each candidate's first→last scheduler reading
    // so wsgm.log distinguishes the two failure modes without a debugger: all
    // "still" means the rebuilt HID thread had not resumed discovery inside the
    // window (a timing problem), while two or more "MOVED" means genuinely live
    // look-alikes that these two fields cannot separate (needs another field).
    Err(ambiguous_candidates(candidates, &before, &last))
}

/// Reads the scheduler fields of every candidate. A candidate that cannot be
/// read at all abandons the election: an unreadable address must never be
/// treated as a candidate that merely stood still.
unsafe fn sample_candidates(
    process: HANDLE,
    candidates: &[usize],
    deadline_offset: usize,
    counter_offset: usize,
) -> Option<Vec<SchedulerSample>> {
    candidates
        .iter()
        .map(|&candidate| unsafe {
            Some(SchedulerSample {
                deadline_bits: read_remote::<f64>(process, candidate + deadline_offset)
                    .ok()?
                    .to_bits(),
                counter: read_remote::<u32>(process, candidate + counter_offset).ok()?,
            })
        })
        .collect()
}

fn ambiguous_candidates(
    candidates: &[usize],
    before: &[SchedulerSample],
    after: &[SchedulerSample],
) -> Error {
    Error::UnsupportedSteamBuild(format!(
        "runtime RTTI resolved, but {} live CHIDIOThread candidates were ambiguous \
         and none could be elected by observing discovery scheduling [{}]",
        candidates.len(),
        describe_candidate_movement(candidates, before, after),
    ))
}

/// A candidate address that read cleanly at RTTI resolution became unreadable
/// mid-election. Distinguished from the ambiguous case because the cure is
/// different: an unreadable candidate is a torn-down object, not a look-alike.
fn unreadable_candidates(candidates: &[usize]) -> Error {
    Error::UnsupportedSteamBuild(format!(
        "runtime RTTI resolved, but a CHIDIOThread candidate among {} became unreadable \
         during the discovery-scheduling election",
        candidates.len()
    ))
}

/// Renders each candidate's first→last scheduler reading for the log. `MOVED`
/// marks a candidate whose deadline or counter changed across the window; all
/// `still` points at timing, two or more `MOVED` at a missing discriminator.
fn describe_candidate_movement(
    candidates: &[usize],
    before: &[SchedulerSample],
    after: &[SchedulerSample],
) -> String {
    candidates
        .iter()
        .enumerate()
        .map(|(index, address)| match (before.get(index), after.get(index)) {
            (Some(b), Some(a)) => {
                let moved = b.deadline_bits != a.deadline_bits || b.counter != a.counter;
                format!(
                    "{address:#x}: deadline {:#018x}->{:#018x} counter {}->{} {}",
                    b.deadline_bits,
                    a.deadline_bits,
                    b.counter,
                    a.counter,
                    if moved { "MOVED" } else { "still" },
                )
            }
            _ => format!("{address:#x}: unsampled"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Posts the device-change notification Windows sends on any device arrival to
/// the target's own top-level windows. Best effort by design: it only gives
/// Steam a reason to run discovery, and every failure simply leaves the
/// election to whatever Steam does on its own schedule.
fn notify_device_change(process_id: u32) {
    NOTIFY_TARGET.store(process_id, Ordering::Release);
    unsafe { EnumWindows(Some(notify_target_window), 0) };
}

unsafe extern "system" fn notify_target_window(window: HWND, _: LPARAM) -> i32 {
    let mut owner = 0;
    unsafe { GetWindowThreadProcessId(window, &mut owner) };
    if owner == NOTIFY_TARGET.load(Ordering::Acquire) {
        unsafe { PostMessageW(window, WM_DEVICECHANGE, DBT_DEVNODES_CHANGED, 0) };
    }
    TRUE
}

fn resolve_remote_recovery(process_id: u32) -> Result<RemoteRecoveryTarget> {
    let steamclient = remote_module(process_id, "steamclient64.dll").ok_or_else(|| {
        Error::UnsupportedSteamBuild("steamclient64.dll is not loaded in Steam".into())
    })?;
    unsafe {
        let process = OwnedHandle::from_raw(OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            FALSE,
            process_id,
        ));
        if process.raw().is_null() {
            return Err(Error::windows(
                "could not open Steam for controller discovery",
            ));
        }
        let image = snapshot_remote_module(process.raw(), steamclient)?;
        let layout = resolve_recovery_layout(steamclient.base, &image).map_err(|error| {
            Error::UnsupportedSteamBuild(format!(
                "steamclient runtime recovery resolution failed: {error}"
            ))
        })?;
        drop(image);
        let hid_thread = find_remote_hid_thread(process.raw(), process_id, steamclient, layout)?;
        Ok(RemoteRecoveryTarget {
            process,
            hid_thread,
            deadline_offset: layout.discovery_deadline_offset as usize,
            counter_offset: layout.discovery_counter_offset as usize,
            primary_vtable: steamclient.base + layout.primary_vtable_rva as usize,
            secondary_vtable: steamclient.base + layout.secondary_vtable_rva as usize,
            secondary_object_offset: layout.secondary_object_offset as usize,
        })
    }
}

fn request_internal_scan(target: &RemoteRecoveryTarget) -> Result<RescanResult> {
    // The live object pair and both field offsets have already been derived
    // from this module's RTTI and worker instructions. Re-check the fields on
    // every request and perform only the final aligned eight-byte write here.
    if !validate_remote_hid_thread(target) {
        return Err(Error::UnsupportedSteamBuild(
            "Steam's CHIDIOThread object is no longer valid at the resolved address".into(),
        ));
    }
    unsafe {
        let mut result = RescanResult {
            previous_deadline: read_remote(
                target.process.raw(),
                target.hid_thread + target.deadline_offset,
            )?,
            scan_count_before: read_remote(
                target.process.raw(),
                target.hid_thread + target.counter_offset,
            )?,
            scan_count_after: 0,
        };
        let schedule = -1.0f64;
        let mut transferred = 0;
        if WriteProcessMemory(
            target.process.raw(),
            (target.hid_thread + target.deadline_offset) as *mut c_void,
            (&schedule as *const f64).cast(),
            size_of::<f64>(),
            &mut transferred,
        ) == FALSE
            || transferred != size_of::<f64>()
        {
            return Err(Error::windows(
                "could not request Steam controller discovery",
            ));
        }
        thread::sleep(Duration::from_millis(2200));
        result.scan_count_after = read_remote(
            target.process.raw(),
            target.hid_thread + target.counter_offset,
        )
        .unwrap_or(result.scan_count_before);
        Ok(result)
    }
}

fn rescan_steam_controllers(process_id: u32) -> Result<RescanResult> {
    // Steam may execute stale zombie cleanup after the first rediscovery. The
    // second complete request is therefore part of recovery, not a retry.
    let target = resolve_remote_recovery(process_id)?;
    let first = request_internal_scan(&target)?;
    let second = request_internal_scan(&target)?;
    Ok(RescanResult {
        previous_deadline: first.previous_deadline,
        scan_count_before: first.scan_count_before,
        scan_count_after: second.scan_count_after,
    })
}

fn same_architecture(target: HANDLE) -> bool {
    unsafe {
        let mut self_machine = 0;
        let mut self_native = 0;
        let mut target_machine = 0;
        let mut target_native = 0;
        IsWow64Process2(GetCurrentProcess(), &mut self_machine, &mut self_native) != FALSE
            && IsWow64Process2(target, &mut target_machine, &mut target_native) != FALSE
            && self_machine == target_machine
            && self_native == target_native
    }
}

fn inject_payload(process_id: u32, payload: &Path) -> Result<()> {
    // Resolve LoadLibraryW by module-relative offset rather than assuming ASLR
    // selected the same kernel32 base in both processes.
    unsafe {
        let access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ;
        let process = OwnedHandle::from_raw(OpenProcess(access, FALSE, process_id));
        if process.raw().is_null() {
            return Err(Error::windows("OpenProcess failed"));
        }
        if !same_architecture(process.raw()) {
            return Err(Error::ArchitectureMismatch);
        }

        let remote_kernel32 = remote_module_base(process_id, "kernel32.dll")
            .ok_or_else(|| Error::Message("could not locate kernel32.dll in the target".into()))?;
        let kernel32_name = wide_nul("kernel32.dll");
        let local_kernel32 = GetModuleHandleW(kernel32_name.as_ptr());
        let load_library_name = b"LoadLibraryW\0";
        let local_load_library = GetProcAddress(local_kernel32, load_library_name.as_ptr());
        let Some(local_load_library) = local_load_library else {
            return Err(Error::Message("could not locate LoadLibraryW".into()));
        };
        let remote_address =
            remote_kernel32 + local_load_library as usize - local_kernel32 as usize;

        let absolute = payload.canonicalize().map_err(|source| Error::Windows {
            operation: "could not resolve payload path",
            source,
        })?;
        let payload_wide = wide_nul(absolute.as_os_str());
        let bytes = payload_wide.len() * size_of::<u16>();
        let remote_path = VirtualAllocEx(
            process.raw(),
            null(),
            bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if remote_path.is_null() {
            return Err(Error::windows("VirtualAllocEx failed"));
        }

        // `remote_path` is the string the remote LoadLibraryW dereferences, so
        // it may only be decommitted once that thread is known to be gone.
        // Freeing it after a timed-out or unobservable wait would fault inside
        // Steam; leaking one page in the target is strictly cheaper.
        let mut remote_path_is_idle = true;
        let mut inject = || {
            if WriteProcessMemory(
                process.raw(),
                remote_path,
                payload_wide.as_ptr().cast(),
                bytes,
                null_mut(),
            ) == FALSE
            {
                return Err(Error::windows("WriteProcessMemory failed"));
            }
            let start: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(remote_address);
            let thread_handle = OwnedHandle::from_raw(CreateRemoteThread(
                process.raw(),
                null(),
                0,
                Some(start),
                remote_path,
                0,
                null_mut(),
            ));
            if thread_handle.raw().is_null() {
                return Err(Error::windows("CreateRemoteThread failed"));
            }
            remote_path_is_idle = false;
            match WaitForSingleObject(thread_handle.raw(), 10_000) {
                WAIT_OBJECT_0 => {
                    remote_path_is_idle = true;
                    let mut module = 0;
                    if GetExitCodeThread(thread_handle.raw(), &mut module) == FALSE || module == 0 {
                        Err(Error::Message(
                            "the target did not load steam_input_gate.dll".into(),
                        ))
                    } else {
                        Ok(())
                    }
                }
                WAIT_TIMEOUT => Err(Error::Message("payload injection timed out".into())),
                _ => Err(Error::windows("waiting for payload injection failed")),
            }
        };
        let result = inject();
        if remote_path_is_idle {
            VirtualFreeEx(process.raw(), remote_path, 0, MEM_RELEASE);
        }
        result
    }
}

fn connect_pipe(process_id: u32, timeout: Duration) -> Result<OwnedHandle> {
    // Short polling permits a fast resident-payload path while also covering
    // the asynchronous server startup that follows LoadLibraryW injection.
    let name = steam_input_lease_core::pipe_name(process_id);
    let deadline = Instant::now() + timeout;
    loop {
        unsafe {
            let handle = CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
            if handle != INVALID_HANDLE_VALUE {
                return Ok(OwnedHandle::from_raw(handle));
            }
            let error = io::Error::last_os_error();
            let code = error.raw_os_error().unwrap_or_default() as u32;
            if code != ERROR_PIPE_BUSY && code != ERROR_FILE_NOT_FOUND {
                return Err(Error::Windows {
                    operation: "could not connect to payload pipe",
                    source: error,
                });
            }
            if Instant::now() >= deadline {
                return Err(Error::Windows {
                    operation: "timed out connecting to payload pipe",
                    source: error,
                });
            }
            if code == ERROR_FILE_NOT_FOUND {
                // WaitNamedPipeW returns immediately when no instance of the
                // pipe exists, so it provides no backoff on this path.
                thread::sleep(Duration::from_millis(5));
            } else {
                // ERROR_PIPE_BUSY: an instance exists but every one is taken,
                // which is the case WaitNamedPipeW actually blocks for.
                WaitNamedPipeW(name.as_ptr(), 100);
            }
        }
    }
}

fn exchange(pipe: HANDLE, command: Command) -> Result<Response> {
    // Message-mode pipes normally preserve boundaries, but byte counts and all
    // protocol header fields are still validated before accepting a response.
    unsafe {
        let request = Request::new(command);
        let mut transferred = 0;
        if WriteFile(
            pipe,
            (&request as *const Request).cast(),
            size_of::<Request>() as u32,
            &mut transferred,
            null_mut(),
        ) == FALSE
            || transferred != size_of::<Request>() as u32
        {
            return Err(Error::windows("could not send command to payload"));
        }
        let mut response: Response = zeroed();
        if ReadFile(
            pipe,
            (&mut response as *mut Response).cast(),
            size_of::<Response>() as u32,
            &mut transferred,
            null_mut(),
        ) == FALSE
            || transferred != size_of::<Response>() as u32
        {
            return Err(Error::windows("could not read payload response"));
        }
        if !response.is_valid() {
            return Err(Error::Protocol(
                "the payload rejected the command or uses a different protocol version".into(),
            ));
        }
        Ok(response)
    }
}

fn quote_argument(value: &[u16]) -> Vec<u16> {
    // Implement the CommandLineToArgvW-compatible backslash/quote rules used by
    // CreateProcessW when lpApplicationName is null.
    if value.is_empty() {
        return vec![b'"' as u16, b'"' as u16];
    }
    if !value
        .iter()
        .any(|unit| matches!(*unit, 0x20 | 0x09 | 0x0a | 0x0b | 0x22))
    {
        return value.to_vec();
    }
    let mut result = vec![b'"' as u16];
    let mut backslashes = 0usize;
    for &unit in value {
        if unit == b'\\' as u16 {
            backslashes += 1;
        } else if unit == b'"' as u16 {
            result.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            result.push(unit);
            backslashes = 0;
        } else {
            result.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            backslashes = 0;
            result.push(unit);
        }
    }
    result.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    result.push(b'"' as u16);
    result
}

fn launch_and_wait(arguments: &[Vec<u16>]) -> Result<u32> {
    let mut command_line = Vec::new();
    for argument in arguments {
        if !command_line.is_empty() {
            command_line.push(b' ' as u16);
        }
        command_line.extend(quote_argument(argument));
    }
    command_line.push(0);

    unsafe {
        let mut startup: STARTUPINFOW = zeroed();
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        let mut process: PROCESS_INFORMATION = zeroed();
        if CreateProcessW(
            null(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            FALSE,
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
            null(),
            null(),
            &startup,
            &mut process,
        ) == FALSE
        {
            return Err(Error::windows("could not start wrapped process"));
        }
        let process_handle = OwnedHandle::from_raw(process.hProcess);
        let thread_handle = OwnedHandle::from_raw(process.hThread);
        // Assign before ResumeThread so descendants created immediately by a
        // launcher cannot escape the job/process-tree lifetime.
        let job_raw = CreateJobObjectW(null(), null());
        let job = (!job_raw.is_null()).then(|| OwnedHandle::from_raw(job_raw));
        let assigned = job
            .as_ref()
            .is_some_and(|job| AssignProcessToJobObject(job.raw(), process_handle.raw()) != FALSE);
        ResumeThread(thread_handle.raw());
        drop(thread_handle);

        if assigned {
            loop {
                let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = zeroed();
                if QueryInformationJobObject(
                    job.as_ref().unwrap().raw(),
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    null_mut(),
                ) == FALSE
                    || accounting.ActiveProcesses == 0
                {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
        } else {
            WaitForSingleObject(process_handle.raw(), INFINITE);
        }

        // The tree has already run and exited by here, so an unreadable exit code
        // is reported as zero rather than as an error: the caller treats an error
        // as "the target never started" and would run it again.
        let mut exit_code = 0;
        if GetExitCodeProcess(process_handle.raw(), &mut exit_code) == FALSE {
            exit_code = 0;
        }
        Ok(exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_command_line_quoting_matches_command_line_to_argv_rules() {
        assert_eq!(
            String::from_utf16_lossy(&quote_argument(&wide_nul("plain")[..5])),
            "plain"
        );
        assert_eq!(
            String::from_utf16_lossy(&quote_argument(
                &"two words".encode_utf16().collect::<Vec<_>>()
            )),
            "\"two words\""
        );
        assert_eq!(
            String::from_utf16_lossy(&quote_argument(
                &r#"a\"b"#.encode_utf16().collect::<Vec<_>>()
            )),
            "\"a\\\\\\\"b\""
        );
    }
}
