#![cfg(windows)]

//! Stable C ABI consumed by the C# binding and other native callers.
//!
//! No Rust-owned layout crosses the ABI: callers receive opaque client/lease
//! handles and fixed-width `#[repr(C)]` value structures. All fallible exports
//! return `0` on success, `1` for a reported operation error, or `2` when a
//! panic was caught at the ABI boundary. Detailed UTF-8 error text is stored
//! per thread and exposed by [`sil_last_error_message`].
//!
//! UTF-16 input strings use Windows encoding and must be NUL-terminated. Lease
//! ownership is linear: [`sil_lease_release`] and [`sil_lease_destroy`] both
//! consume their handle.

#![deny(missing_docs)]

use std::cell::RefCell;
use std::ffi::{CString, OsString, c_char};
use std::os::windows::ffi::OsStringExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::ptr::null_mut;
use std::time::Duration;

use steam_input_lease::{
    Client, ClientOptions, Lease, RecoveryOutcome, ReleaseOutcome, RescanResult, Status,
};

const SIL_OK: i32 = 0;
const SIL_ERROR: i32 = 1;
const SIL_PANIC: i32 = 2;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::new("").unwrap());
}

/// Options accepted by [`sil_client_create`]. Null string fields select the
/// corresponding Rust default.
#[repr(C)]
pub struct SilClientOptions {
    /// Optional NUL-terminated UTF-16 target executable name.
    pub target_name: *const u16,
    /// Optional NUL-terminated UTF-16 payload path.
    pub payload_path: *const u16,
    /// Pipe connection timeout in milliseconds; zero selects the default.
    pub connect_timeout_ms: u32,
}

/// Fixed-width payload status returned across the C ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SilStatus {
    /// Capability bitset defined by `steam-input-lease-core`.
    pub capabilities: u16,
    /// Reserved for ABI-compatible extension and currently always zero.
    pub reserved: u16,
    /// Number of active process-global leases.
    pub lease_count: u32,
    /// Number of HID handles known to the payload.
    pub hid_handle_count: u32,
    /// Handles revoked during the latest blocking transition.
    pub last_revoked_handle_count: u32,
}

impl From<Status> for SilStatus {
    fn from(value: Status) -> Self {
        Self {
            capabilities: value.capabilities,
            reserved: 0,
            lease_count: value.lease_count,
            hid_handle_count: value.hid_handle_count,
            last_revoked_handle_count: value.last_revoked_handle_count,
        }
    }
}

/// Fixed-width diagnostics returned by [`sil_client_rescan`].
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SilRescanResult {
    /// Deadline value observed before scheduling the first scan.
    pub previous_deadline: f64,
    /// Steam discovery counter before the first scan.
    pub scan_count_before: u32,
    /// Steam discovery counter after the second scan.
    pub scan_count_after: u32,
}

impl From<RescanResult> for SilRescanResult {
    fn from(value: RescanResult) -> Self {
        Self {
            previous_deadline: value.previous_deadline,
            scan_count_before: value.scan_count_before,
            scan_count_after: value.scan_count_after,
        }
    }
}

/// Controller recovery did not apply: the target is not Steam.
pub const SIL_RECOVERY_NOT_REQUIRED: u32 = 0;
/// The payload scheduled discovery on its own timer.
pub const SIL_RECOVERY_SCHEDULED: u32 = 1;
/// The host ran the guarded two-pass recovery inline; `rescan` is populated.
pub const SIL_RECOVERY_COMPLETED: u32 = 2;
/// Recovery could not run; `recovery_message` explains why. Blocking was still
/// lifted, so the release itself succeeded.
pub const SIL_RECOVERY_UNAVAILABLE: u32 = 3;

/// Bytes reserved for the UTF-8 recovery message, including its terminator.
const SIL_RECOVERY_MESSAGE_CAPACITY: usize = 256;

/// Outcome of [`sil_lease_release`].
///
/// Returning `SIL_OK` means blocking was lifted. Whether Steam was asked to
/// rediscover controllers is reported by `recovery`, so a caller can tell a
/// released-but-unrecovered lease from a failed release.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SilReleaseOutcome {
    /// Payload status captured by the release handshake.
    pub status: SilStatus,
    /// One of the `SIL_RECOVERY_*` constants.
    pub recovery: u32,
    /// Reserved for ABI-compatible extension and currently always zero.
    pub reserved: u32,
    /// Populated only when `recovery` is [`SIL_RECOVERY_COMPLETED`].
    pub rescan: SilRescanResult,
    /// NUL-terminated UTF-8 reason, empty unless `recovery` is
    /// [`SIL_RECOVERY_UNAVAILABLE`]. Carried in the struct rather than through
    /// the thread-local error slot, which reports failed calls only.
    pub recovery_message: [c_char; SIL_RECOVERY_MESSAGE_CAPACITY],
}

impl Default for SilReleaseOutcome {
    fn default() -> Self {
        Self {
            status: SilStatus::default(),
            recovery: SIL_RECOVERY_NOT_REQUIRED,
            reserved: 0,
            rescan: SilRescanResult::default(),
            recovery_message: [0; SIL_RECOVERY_MESSAGE_CAPACITY],
        }
    }
}

impl From<ReleaseOutcome> for SilReleaseOutcome {
    fn from(value: ReleaseOutcome) -> Self {
        let mut outcome = Self {
            status: value.status.into(),
            ..Self::default()
        };
        match value.recovery {
            RecoveryOutcome::NotRequired => {}
            RecoveryOutcome::Scheduled => outcome.recovery = SIL_RECOVERY_SCHEDULED,
            RecoveryOutcome::Completed(result) => {
                outcome.recovery = SIL_RECOVERY_COMPLETED;
                outcome.rescan = result.into();
            }
            RecoveryOutcome::Unavailable(error) => {
                outcome.recovery = SIL_RECOVERY_UNAVAILABLE;
                write_fixed_utf8(&mut outcome.recovery_message, &error.to_string());
            }
        }
        outcome
    }
}

/// Copies `text` into a fixed NUL-terminated UTF-8 buffer.
///
/// Truncation respects UTF-8 boundaries so the message never ends in a partial
/// code point, and interior NULs are replaced so the whole message survives the
/// C string representation.
fn write_fixed_utf8(buffer: &mut [c_char], text: &str) {
    let sanitized = text.replace('\0', " ");
    let limit = buffer.len() - 1;
    let mut end = sanitized.len().min(limit);
    while end > 0 && !sanitized.is_char_boundary(end) {
        end -= 1;
    }
    for (slot, byte) in buffer.iter_mut().zip(sanitized[..end].bytes()) {
        *slot = byte as c_char;
    }
    buffer[end] = 0;
}

/// Opaque C handle owning one Rust [`Client`].
pub struct SilClient(Client);
/// Opaque C handle owning one active Rust [`Lease`].
pub struct SilLease(Option<Lease>);

fn set_last_error(message: impl AsRef<str>) {
    let sanitized = message.as_ref().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(sanitized).unwrap_or_default();
    });
}

fn ffi_call(operation: impl FnOnce() -> Result<(), String>) -> i32 {
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => {
            set_last_error("");
            SIL_OK
        }
        Ok(Err(error)) => {
            set_last_error(error);
            SIL_ERROR
        }
        Err(_) => {
            set_last_error("Rust panic crossed the Steam Input Lease ABI boundary");
            SIL_PANIC
        }
    }
}

unsafe fn read_utf16(pointer: *const u16) -> Result<OsString, String> {
    if pointer.is_null() {
        return Err("required UTF-16 string pointer was null".into());
    }
    let mut length = 0usize;
    while length < 32_768 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    if length == 32_768 {
        return Err("UTF-16 string exceeds 32767 code units".into());
    }
    Ok(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(pointer, length)
    }))
}

unsafe fn client_ref<'a>(client: *mut SilClient) -> Result<&'a Client, String> {
    unsafe { client.as_ref() }
        .map(|value| &value.0)
        .ok_or_else(|| "client handle was null".into())
}

#[unsafe(no_mangle)]
/// Returns the version of the exported C ABI, currently `2`.
///
/// Version `2` changed `sil_lease_release` to report a [`SilReleaseOutcome`]
/// instead of a bare [`SilStatus`], so a recovery failure no longer presents a
/// released lease as a failed one.
pub extern "C" fn sil_abi_version() -> u32 {
    2
}

#[unsafe(no_mangle)]
/// Returns a borrowed pointer to the calling thread's latest UTF-8 error.
///
/// The pointer remains valid until another ABI operation on the same thread
/// replaces the message. The caller must not free or modify it.
pub extern "C" fn sil_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

#[unsafe(no_mangle)]
/// Creates an opaque client handle.
///
/// # Safety
/// `options` may be null; otherwise it must reference a valid options struct.
/// `output` must be writable and provided UTF-16 strings NUL-terminated.
pub unsafe extern "C" fn sil_client_create(
    options: *const SilClientOptions,
    output: *mut *mut SilClient,
) -> i32 {
    ffi_call(|| {
        if output.is_null() {
            return Err("client output pointer was null".into());
        }
        unsafe { *output = null_mut() };
        let mut resolved = ClientOptions::default();
        if let Some(options) = unsafe { options.as_ref() } {
            if !options.target_name.is_null() {
                resolved.target_name = unsafe { read_utf16(options.target_name)? }
                    .to_string_lossy()
                    .into_owned();
            }
            if !options.payload_path.is_null() {
                resolved.payload_path = PathBuf::from(unsafe { read_utf16(options.payload_path)? });
            }
            if options.connect_timeout_ms != 0 {
                resolved.connect_timeout = Duration::from_millis(options.connect_timeout_ms.into());
            }
        }
        unsafe { *output = Box::into_raw(Box::new(SilClient(Client::new(resolved)))) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Destroys a client created by [`sil_client_create`].
///
/// # Safety
/// `client` must be null or a live handle returned by `sil_client_create`, and
/// must not be destroyed more than once.
pub unsafe extern "C" fn sil_client_destroy(client: *mut SilClient) {
    if !client.is_null() {
        drop(unsafe { Box::from_raw(client) });
    }
}

#[unsafe(no_mangle)]
/// Ensures the target payload is loaded, then writes its status.
///
/// # Safety
/// `client` must be live and `status` must be writable.
pub unsafe extern "C" fn sil_client_ensure_payload(
    client: *mut SilClient,
    status: *mut SilStatus,
) -> i32 {
    ffi_call(|| {
        if status.is_null() {
            return Err("status output pointer was null".into());
        }
        let value = unsafe { client_ref(client)? }
            .ensure_payload()
            .map_err(|error| error.to_string())?;
        unsafe { *status = value.into() };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Queries an already loaded payload without injecting it.
///
/// # Safety
/// `client` must be live and `status` must be writable.
pub unsafe extern "C" fn sil_client_status(client: *mut SilClient, status: *mut SilStatus) -> i32 {
    ffi_call(|| {
        if status.is_null() {
            return Err("status output pointer was null".into());
        }
        let value = unsafe { client_ref(client)? }
            .status()
            .map_err(|error| error.to_string())?;
        unsafe { *status = value.into() };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Acquires a process-global block lease and returns its initial status.
///
/// On failure `*lease` is set to null. On success the returned handle must be
/// consumed exactly once by [`sil_lease_release`] or [`sil_lease_destroy`].
///
/// # Safety
/// `client` must be live; `lease` and `status` must be writable.
pub unsafe extern "C" fn sil_client_acquire(
    client: *mut SilClient,
    lease: *mut *mut SilLease,
    status: *mut SilStatus,
) -> i32 {
    ffi_call(|| {
        if lease.is_null() || status.is_null() {
            return Err("lease or status output pointer was null".into());
        }
        unsafe { *lease = null_mut() };
        let value = unsafe { client_ref(client)? }
            .acquire()
            .map_err(|error| error.to_string())?;
        unsafe {
            *status = value.status().into();
            *lease = Box::into_raw(Box::new(SilLease(Some(value))));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Explicitly releases and consumes a lease, waiting for the payload's release
/// and recovery-scheduling response.
///
/// `SIL_OK` means blocking was lifted; inspect `outcome->recovery` to learn
/// whether Steam was also asked to rediscover controllers. The handle is
/// consumed in every case, so callers must not subsequently pass it to
/// [`sil_lease_destroy`].
///
/// # Safety
/// `lease` must be a live, uniquely owned handle and `outcome` writable.
pub unsafe extern "C" fn sil_lease_release(
    lease: *mut SilLease,
    outcome: *mut SilReleaseOutcome,
) -> i32 {
    ffi_call(|| {
        if lease.is_null() || outcome.is_null() {
            return Err("lease handle or outcome output pointer was null".into());
        }
        let mut lease = unsafe { Box::from_raw(lease) };
        let value = lease
            .0
            .take()
            .ok_or_else(|| "lease was already released".to_string())?
            .release()
            .map_err(|error| error.to_string())?;
        unsafe { *outcome = value.into() };
        Ok(())
    })
}

/// Crash-safe release: drops the pipe without waiting for explicit recovery.
///
/// # Safety
/// `lease` must be null or a live, uniquely owned handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sil_lease_destroy(lease: *mut SilLease) {
    if !lease.is_null() {
        drop(unsafe { Box::from_raw(lease) });
    }
}

#[unsafe(no_mangle)]
/// Requests the guarded two-pass Steam discovery without changing leases.
///
/// # Safety
/// `client` must be live and `result` must be writable.
pub unsafe extern "C" fn sil_client_rescan(
    client: *mut SilClient,
    result: *mut SilRescanResult,
) -> i32 {
    ffi_call(|| {
        if result.is_null() {
            return Err("rescan output pointer was null".into());
        }
        let value = unsafe { client_ref(client)? }
            .rescan()
            .map_err(|error| error.to_string())?;
        unsafe { *result = value.into() };
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Validates the guarded host-side Steam recovery resolver without changing
/// leases or writing into the target process.
///
/// # Safety
/// `client` must be a live client handle.
pub unsafe extern "C" fn sil_client_check_recovery(client: *mut SilClient) -> i32 {
    ffi_call(|| {
        unsafe { client_ref(client) }?
            .check_recovery()
            .map_err(|error| error.to_string())?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
/// Runs an argument vector while a lease is held and writes the process code.
///
/// The call is synchronous and waits for the launched Windows process tree and
/// final release handshake before returning.
///
/// # Safety
/// `client` must be live, `argv` must hold `argc` valid NUL-terminated UTF-16
/// pointers, and `exit_code` must be writable.
pub unsafe extern "C" fn sil_client_run_wrapped(
    client: *mut SilClient,
    argc: usize,
    argv: *const *const u16,
    exit_code: *mut u32,
) -> i32 {
    ffi_call(|| {
        if argv.is_null() || exit_code.is_null() || argc == 0 {
            return Err("wrapped argv or exit-code output was invalid".into());
        }
        let pointers = unsafe { std::slice::from_raw_parts(argv, argc) };
        let mut arguments = Vec::with_capacity(argc);
        for &pointer in pointers {
            arguments.push(unsafe { read_utf16(pointer)? });
        }
        let value = unsafe { client_ref(client)? }
            .run_wrapped(arguments)
            .map_err(|error| error.to_string())?;
        unsafe { *exit_code = value };
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn public_abi_structs_have_fixed_layout() {
        assert_eq!(size_of::<SilStatus>(), 16);
        assert_eq!(size_of::<SilRescanResult>(), 16);
        assert_eq!(size_of::<SilReleaseOutcome>(), 296);
        assert_eq!(align_of::<SilReleaseOutcome>(), 8);
    }

    #[test]
    fn a_recovery_message_longer_than_the_buffer_stays_a_valid_c_string() {
        let mut buffer = [0 as c_char; SIL_RECOVERY_MESSAGE_CAPACITY];
        write_fixed_utf8(&mut buffer, &"a".repeat(1000));
        assert_eq!(buffer[SIL_RECOVERY_MESSAGE_CAPACITY - 1], 0);
        let bytes: Vec<u8> = buffer
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| byte as u8)
            .collect();
        assert_eq!(bytes.len(), SIL_RECOVERY_MESSAGE_CAPACITY - 1);
    }

    #[test]
    fn truncation_never_splits_a_utf8_code_point() {
        // The buffer boundary lands mid-character, so a byte-wise copy would
        // leave a partial code point that no UTF-8 decoder can read.
        let mut buffer = [0 as c_char; 8];
        write_fixed_utf8(&mut buffer, "aa€€€");
        let bytes: Vec<u8> = buffer
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| byte as u8)
            .collect();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "aa€");
    }

    #[test]
    fn an_interior_nul_does_not_truncate_the_recovery_message() {
        let mut buffer = [0 as c_char; SIL_RECOVERY_MESSAGE_CAPACITY];
        write_fixed_utf8(&mut buffer, "before\0after");
        let bytes: Vec<u8> = buffer
            .iter()
            .take_while(|&&byte| byte != 0)
            .map(|&byte| byte as u8)
            .collect();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), "before after");
    }

    #[test]
    fn last_error_is_always_nul_terminated() {
        set_last_error("hello");
        let pointer = sil_last_error_message();
        assert!(!pointer.is_null());
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(pointer) }.to_bytes(),
            b"hello"
        );
    }
}
