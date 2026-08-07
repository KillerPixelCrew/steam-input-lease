//! Injected process-local Steam Input gate.
//!
//! Hook bodies never allocate. Controller handles are tracked in a fixed-size
//! table, and blocking is controlled by the named-pipe lease count.
//!
//! The DLL installs hooks once, then leaves them in pass-through mode whenever
//! the lease count is zero. Each accepted pipe client receives a worker thread;
//! keeping an acquire connection open owns one lease, so EOF is a crash-safe
//! release signal.
//!
//! The current implementation deliberately pins itself after startup because
//! asynchronous hook and server code cannot safely execute from an unmapped
//! image. Consequently, this version supports dynamic enable/disable but not
//! dynamic DLL unloading. A future detach protocol must quiesce every worker
//! and detour before removing that pinning strategy.

#![cfg(windows)]
#![deny(missing_docs)]

use std::cell::Cell;
use std::ffi::c_void;
use std::mem::{size_of, transmute_copy, zeroed};
use std::ptr::{null, null_mut};
use std::sync::atomic::{
    AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use std::sync::{Condvar, Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use minhook_sys::{
    MH_ApplyQueued, MH_CreateHook, MH_ERROR_ALREADY_CREATED, MH_Initialize, MH_OK,
    MH_QueueEnableHook, MH_Uninitialize,
};
use steam_input_lease_core::{
    CAPABILITY_INTERNAL_RECOVERY, Command, PROTOCOL_MAGIC, PROTOCOL_VERSION, Request, Response,
    ResultCode,
};
use steam_input_recovery::{
    RecoveryLayout, SchedulerSample, find_vtable_pairs, resolve_recovery_layout,
    select_progressing_candidate,
};
use windows_sys::Win32::Devices::HumanInterfaceDevice::{HIDD_ATTRIBUTES, HidD_GetAttributes};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_DEVICE_NOT_CONNECTED, ERROR_NO_SUCH_DEVICE, ERROR_SUCCESS, FALSE,
    GetLastError, HANDLE, HINSTANCE, HMODULE, HWND, INVALID_HANDLE_VALUE, LPARAM, SetLastError,
    TRUE,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CREATEFILE2_EXTENDED_PARAMETERS, FILE_TYPE_DISK, FILE_TYPE_PIPE, FILE_TYPE_UNKNOWN,
    GetFileType, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::IO::CancelIoEx;
use windows_sys::Win32::System::LibraryLoader::{
    DisableThreadLibraryCalls, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
    GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleHandleExW, GetModuleHandleW, GetProcAddress,
    LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_PRIVATE, MEMORY_BASIC_INFORMATION, PAGE_GUARD, PAGE_NOACCESS, VirtualQuery,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateThread, GetCurrentProcess, GetCurrentProcessId, SetEvent,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_DEVICECHANGE,
};

// Win32/NT constants that windows-sys does not expose through the selected API
// surface. Values come from the Windows SDK headers used by the archived POC.
const DLL_PROCESS_ATTACH: u32 = 1;
const DBT_DEVNODES_CHANGED: usize = 0x0007;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const STATUS_DEVICE_NOT_CONNECTED: i32 = 0xC000_009Du32 as i32;
const SYSTEM_EXTENDED_HANDLE_INFORMATION: u32 = 64;
const OBJECT_TYPE_INFORMATION: u32 = 2;

// PROCESSINFOCLASS::ProcessHandleInformation. Neither windows-sys nor the
// Windows SDK declares this class or its structures, so the layout is declared
// here and asserted below. Verified empirically: the header is
// { usize NumberOfHandles; usize Reserved; } followed by 40-byte entries, and
// 16 + 40 * NumberOfHandles equals the kernel's reported return length exactly.
const PROCESS_HANDLE_INFORMATION: i32 = 51;

const MODULE_SNAPSHOT_LIMIT: usize = 512 * 1024 * 1024;
const PROCESS_SCAN_CHUNK: usize = 1024 * 1024;
const HANDLE_QUERY_LIMIT: usize = 1024 * 1024 * 1024;

// Minimal NT structure layouts required by the native Nt* hooks and system
// handle enumeration. Their field order and pointer-sized members must remain
// ABI-identical to the Windows definitions.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SystemHandleEntryEx {
    object: *mut c_void,
    process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

// This stride walks kernel-supplied memory, so a layout drift must not compile.
const _: () = assert!(size_of::<SystemHandleEntryEx>() == 40);

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessHandleEntry {
    handle_value: HANDLE,   // 0
    handle_count: usize,    // 8
    pointer_count: usize,   // 16
    granted_access: u32,    // 24
    object_type_index: u32, // 28 - note u32, wider than SystemHandleEntryEx's u16
    handle_attributes: u32, // 32
    reserved: u32,          // 36
}
const _: () = assert!(size_of::<ProcessHandleEntry>() == 40);

type NtQuerySystemInformationFn = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;
type NtQueryObjectFn = unsafe extern "system" fn(HANDLE, u32, *mut c_void, u32, *mut u32) -> i32;
type NtQueryInformationProcessFn =
    unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> i32;
type IoApcRoutine = Option<unsafe extern "system" fn(*mut c_void, *mut IoStatusBlock, u32)>;
type NtReadFileFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    IoApcRoutine,
    *mut c_void,
    *mut IoStatusBlock,
    *mut c_void,
    u32,
    *mut i64,
    *mut u32,
) -> i32;
type NtWriteFileFn = NtReadFileFn;
type NtDeviceIoControlFileFn = unsafe extern "system" fn(
    HANDLE,
    HANDLE,
    IoApcRoutine,
    *mut c_void,
    *mut IoStatusBlock,
    u32,
    *mut c_void,
    u32,
    *mut c_void,
    u32,
) -> i32;
type NtCloseFn = unsafe extern "system" fn(HANDLE) -> i32;
type NtCreateFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut ObjectAttributes,
    *mut IoStatusBlock,
    *mut i64,
    u32,
    u32,
    u32,
    u32,
    *mut c_void,
    u32,
) -> i32;
type NtOpenFileFn = unsafe extern "system" fn(
    *mut HANDLE,
    u32,
    *mut ObjectAttributes,
    *mut IoStatusBlock,
    u32,
    u32,
) -> i32;

type CreateFileWFn = unsafe extern "system" fn(
    *const u16,
    u32,
    u32,
    *const SECURITY_ATTRIBUTES,
    u32,
    u32,
    HANDLE,
) -> HANDLE;
type CreateFileAFn = unsafe extern "system" fn(
    *const u8,
    u32,
    u32,
    *const SECURITY_ATTRIBUTES,
    u32,
    u32,
    HANDLE,
) -> HANDLE;
type CreateFile2Fn = unsafe extern "system" fn(
    *const u16,
    u32,
    u32,
    u32,
    *const CREATEFILE2_EXTENDED_PARAMETERS,
) -> HANDLE;

type XInputGetStateFn = unsafe extern "system" fn(u32, *mut c_void) -> u32;
type XInputGetStateExFn = XInputGetStateFn;
type XInputGetCapabilitiesFn = unsafe extern "system" fn(u32, u32, *mut c_void) -> u32;
type XInputGetCapabilitiesExFn = unsafe extern "system" fn(u32, u32, u32, *mut c_void) -> u32;

// Original/trampoline addresses are published once during hook installation.
// Atomic pointers avoid references to mutable statics inside concurrently
// executing detours.
static NT_QUERY_SYSTEM_INFORMATION: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_QUERY_OBJECT: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_QUERY_INFORMATION_PROCESS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_READ_FILE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_WRITE_FILE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_DEVICE_IO_CONTROL_FILE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_CLOSE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_CREATE_FILE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static NT_OPEN_FILE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CREATE_FILE_W: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CREATE_FILE_A: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CREATE_FILE_2: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

static XINPUT_GET_STATE: [AtomicPtr<c_void>; 5] = [const { AtomicPtr::new(null_mut()) }; 5];
static XINPUT_GET_STATE_EX: [AtomicPtr<c_void>; 5] = [const { AtomicPtr::new(null_mut()) }; 5];
static XINPUT_GET_CAPABILITIES: [AtomicPtr<c_void>; 5] = [const { AtomicPtr::new(null_mut()) }; 5];
static XINPUT_GET_CAPABILITIES_EX: [AtomicPtr<c_void>; 5] =
    [const { AtomicPtr::new(null_mut()) }; 5];

// Process-global observable state returned through every protocol response.
static LEASE_COUNT: AtomicI32 = AtomicI32::new(0);
static HID_HANDLE_COUNT: AtomicI32 = AtomicI32::new(0);
static LAST_REVOKED_HANDLE_COUNT: AtomicI32 = AtomicI32::new(0);
static RECOVERY_LAYOUT: OnceLock<RuntimeRecoveryLayout> = OnceLock::new();
static RECOVERY_LAYOUT_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
const RECOVERY_LAYOUT_MAX_ATTEMPTS: u32 = 4;
static HID_THREAD_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static HID_THREAD_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
const HID_THREAD_MAX_ATTEMPTS: u32 = 3;

// How long the live-object election watches the scheduler fields, and how often
// it looks. Bounded because it runs on a pipe worker: an election that never
// separates the candidates ends in the same "no address" answer it replaced.
const LIVE_ELECTION_TIMEOUT: Duration = Duration::from_millis(1500);
const LIVE_ELECTION_INTERVAL: Duration = Duration::from_millis(125);

/// Deadline shared with the rescan timer thread, and the condvar used to re-arm
/// it. `None` deadline means idle.
type RescanTimer = (Mutex<Option<Instant>>, Condvar);

static RESCAN_TIMER: OnceLock<&'static RescanTimer> = OnceLock::new();
static RESCAN_TIMER_STARTED: AtomicBool = AtomicBool::new(false);
const SECOND_DISCOVERY_DELAY: Duration = Duration::from_millis(2200);

#[derive(Clone, Copy, Debug)]
struct RuntimeRecoveryLayout {
    module_base: usize,
    layout: RecoveryLayout,
}

thread_local! {
    static INTERNAL_HID_PROBE: Cell<bool> = const { Cell::new(false) };
}

// Saves and restores INTERNAL_HID_PROBE so the flag survives nesting. The probe
// is set only around HidD_GetAttributes, which is a plain extern "system" call
// that cannot unwind, so the restore always runs.
struct ProbeGuard(bool);

impl ProbeGuard {
    fn enter() -> Self {
        let previous = INTERNAL_HID_PROBE.with(Cell::get);
        INTERNAL_HID_PROBE.with(|probe| probe.set(true));
        Self(previous)
    }
}

impl Drop for ProbeGuard {
    fn drop(&mut self) {
        INTERNAL_HID_PROBE.with(|probe| probe.set(self.0));
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum HandleClass {
    Unknown = 0,
    Hid = 1,
    Other = 2,
}

#[derive(Clone, Copy)]
struct HandleSlot {
    key: usize,
    classification: HandleClass,
}

// Open-addressing table used instead of a HashMap so detours never allocate.
// Key 0 is empty and key 1 is a tombstone; real Windows handles are larger.
const EMPTY_HANDLE_SLOT: HandleSlot = HandleSlot {
    key: 0,
    classification: HandleClass::Unknown,
};
const HANDLE_TABLE_SIZE: usize = 4096;
const TOMBSTONE: usize = 1;
const HANDLE_PROBE_LIMIT: usize = 16;
static HANDLE_TABLE: RwLock<[HandleSlot; HANDLE_TABLE_SIZE]> =
    RwLock::new([EMPTY_HANDLE_SLOT; HANDLE_TABLE_SIZE]);

fn blocking() -> bool {
    LEASE_COUNT.load(Ordering::Acquire) > 0
}

unsafe fn load_function<T: Copy>(slot: &AtomicPtr<c_void>) -> T {
    // Each caller uses the exact function type associated with its slot. Slots
    // are non-null before MinHook applies any queued detour.
    let pointer = slot.load(Ordering::Acquire);
    unsafe { transmute_copy(&pointer) }
}

fn handle_hash(mut value: usize) -> usize {
    value >>= 2;
    value ^= value >> 17;
    value = value.wrapping_mul(0xed5a_d4bb);
    value ^= value >> 11;
    value % HANDLE_TABLE_SIZE
}

fn lookup_handle(handle: HANDLE) -> HandleClass {
    let key = handle as usize;
    if key <= TOMBSTONE || handle == INVALID_HANDLE_VALUE {
        return HandleClass::Other;
    }
    let table = HANDLE_TABLE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let start = handle_hash(key);
    for offset in 0..HANDLE_PROBE_LIMIT {
        let slot = table[(start + offset) % HANDLE_TABLE_SIZE];
        if slot.key == 0 {
            break;
        }
        if slot.key == key {
            return slot.classification;
        }
    }
    HandleClass::Unknown
}

fn remember_handle(handle: HANDLE, classification: HandleClass) {
    let key = handle as usize;
    if key <= TOMBSTONE || handle == INVALID_HANDLE_VALUE {
        return;
    }
    let mut table = HANDLE_TABLE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let start = handle_hash(key);
    let mut insertion = None;
    for offset in 0..HANDLE_PROBE_LIMIT {
        let index = (start + offset) % HANDLE_TABLE_SIZE;
        let slot = &mut table[index];
        if slot.key == key {
            if slot.classification != classification {
                if slot.classification == HandleClass::Hid {
                    HID_HANDLE_COUNT.fetch_sub(1, Ordering::AcqRel);
                }
                if classification == HandleClass::Hid {
                    HID_HANDLE_COUNT.fetch_add(1, Ordering::AcqRel);
                }
                slot.classification = classification;
            }
            return;
        }
        if slot.key == TOMBSTONE && insertion.is_none() {
            insertion = Some(index);
        } else if slot.key == 0 {
            insertion.get_or_insert(index);
            break;
        }
    }
    if let Some(index) = insertion {
        table[index] = HandleSlot {
            key,
            classification,
        };
        if classification == HandleClass::Hid {
            HID_HANDLE_COUNT.fetch_add(1, Ordering::AcqRel);
        }
    }
}

// Invoked from nt_close_detour on EVERY NtClose in the process, so the common
// case - a close of a handle the table never tracked - must not take the global
// write lock. A read-lock scan settles that case; the write lock is taken only
// when the key is actually present. The early break on `slot.key == 0` is sound
// because no slot ever transitions back to 0: the table starts all-zero, inserts
// only write 0->key or TOMBSTONE->key, and removals only write key->TOMBSTONE.
//
// The table is invalidated only via the hooked ntdll!NtClose, so a close that
// bypasses it (for example DuplicateHandle with DUPLICATE_CLOSE_SOURCE, if it
// does not route through NtClose - unconfirmed) could leave a stale entry.
fn forget_handle(handle: HANDLE) {
    let key = handle as usize;
    if key <= TOMBSTONE || handle == INVALID_HANDLE_VALUE {
        return;
    }
    let start = handle_hash(key);
    {
        let table = HANDLE_TABLE
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut present = false;
        for offset in 0..HANDLE_PROBE_LIMIT {
            let slot = table[(start + offset) % HANDLE_TABLE_SIZE];
            if slot.key == 0 {
                break;
            }
            if slot.key == key {
                present = true;
                break;
            }
        }
        if !present {
            return;
        }
    }
    let mut table = HANDLE_TABLE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for offset in 0..HANDLE_PROBE_LIMIT {
        let slot = &mut table[(start + offset) % HANDLE_TABLE_SIZE];
        if slot.key == 0 {
            break;
        }
        if slot.key == key {
            if slot.classification == HandleClass::Hid {
                HID_HANDLE_COUNT.fetch_sub(1, Ordering::AcqRel);
            }
            *slot = HandleSlot {
                key: TOMBSTONE,
                classification: HandleClass::Unknown,
            };
            break;
        }
    }
}

fn is_file_object(handle: HANDLE) -> bool {
    let pointer = NT_QUERY_OBJECT.load(Ordering::Acquire);
    if pointer.is_null() {
        return false;
    }
    let function: NtQueryObjectFn = unsafe { transmute_copy(&pointer) };
    let mut buffer = [0usize; 128];
    let mut returned = 0;
    let status = unsafe {
        function(
            handle,
            OBJECT_TYPE_INFORMATION,
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            &mut returned,
        )
    };
    if status < 0 {
        return false;
    }
    let name = unsafe { &*(buffer.as_ptr().cast::<UnicodeString>()) };
    if name.buffer.is_null() || name.length != 8 {
        return false;
    }
    let units = unsafe { std::slice::from_raw_parts(name.buffer, 4) };
    wide_ascii_eq(units, &[b'F' as u16, b'i' as u16, b'l' as u16, b'e' as u16])
}

fn wide_ascii_eq(left: &[u16], right: &[u16]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&left, &right)| (left as u8).eq_ignore_ascii_case(&(right as u8)))
}

fn probe_handle(handle: HANDLE) -> HandleClass {
    if !is_file_object(handle) {
        return HandleClass::Other;
    }
    probe_file_handle(handle)
}

// The system-handle table already gives each entry its object-type index. Once
// a File entry identifies that index for this boot, the revocation sweep can
// skip NtQueryObject for every other process handle and probe just File handles.
fn probe_file_handle(handle: HANDLE) -> HandleClass {
    // Never send HidD_GetAttributes to disk or pipe handles: a synchronous
    // named pipe can block indefinitely waiting for an unrelated peer.
    unsafe { SetLastError(ERROR_SUCCESS) };
    let file_type = unsafe { GetFileType(handle) };
    if file_type == FILE_TYPE_DISK
        || file_type == FILE_TYPE_PIPE
        || (file_type == FILE_TYPE_UNKNOWN && unsafe { GetLastError() } != ERROR_SUCCESS)
    {
        return HandleClass::Other;
    }

    let mut attributes = HIDD_ATTRIBUTES {
        Size: size_of::<HIDD_ATTRIBUTES>() as u32,
        ..unsafe { zeroed() }
    };
    let _probe = ProbeGuard::enter();
    let is_hid = unsafe { HidD_GetAttributes(handle, &mut attributes) };
    if is_hid {
        HandleClass::Hid
    } else {
        HandleClass::Other
    }
}

fn classify_handle(handle: HANDLE) -> HandleClass {
    let current = lookup_handle(handle);
    if current != HandleClass::Unknown {
        return current;
    }
    // probe_handle may reach HidD_GetAttributes, a synchronous device ioctl on a
    // file object another Steam thread may already be blocked on, so it can queue
    // behind that thread's I/O. The OBJECT_TYPE_INFORMATION (not name) query and
    // the FILE_TYPE filter inside already defend the two known cases; a future
    // edit must not widen the probe set.
    let classification = probe_handle(handle);
    remember_handle(handle, classification);
    classification
}

// HidD_GetAttributes internally performs device-control I/O. The INTERNAL_HID_PROBE
// check keeps our own classification probe from being denied by the file I/O
// detours while blocking is active.
fn should_deny(handle: HANDLE) -> bool {
    blocking() && !INTERNAL_HID_PROBE.with(Cell::get) && classify_handle(handle) == HandleClass::Hid
}

unsafe fn wide_has_hid_prefix(path: *const u16) -> bool {
    if path.is_null() {
        return false;
    }
    let expected = [
        b'\\' as u16,
        b'\\' as u16,
        0,
        b'\\' as u16,
        b'h' as u16,
        b'i' as u16,
        b'd' as u16,
    ];
    for (index, &unit) in expected.iter().enumerate() {
        let actual = unsafe { *path.add(index) };
        if index == 2 {
            if actual != b'?' as u16 && actual != b'.' as u16 {
                return false;
            }
        } else if !(actual as u8).eq_ignore_ascii_case(&(unit as u8)) {
            return false;
        }
    }
    true
}

unsafe fn narrow_has_hid_prefix(path: *const u8) -> bool {
    if path.is_null() {
        return false;
    }
    let expected = [b'\\', b'\\', 0, b'\\', b'h', b'i', b'd'];
    for (index, &unit) in expected.iter().enumerate() {
        let actual = unsafe { *path.add(index) };
        if index == 2 {
            if actual != b'?' && actual != b'.' {
                return false;
            }
        } else if !actual.eq_ignore_ascii_case(&unit) {
            return false;
        }
    }
    true
}

unsafe fn native_has_hid_prefix(attributes: *mut ObjectAttributes) -> bool {
    let Some(attributes) = (unsafe { attributes.as_ref() }) else {
        return false;
    };
    let Some(name) = (unsafe { attributes.object_name.as_ref() }) else {
        return false;
    };
    if name.buffer.is_null() {
        return false;
    }
    let units = unsafe { std::slice::from_raw_parts(name.buffer, name.length as usize / 2) };
    const NATIVE: [u16; 7] = [
        b'\\' as u16,
        b'?' as u16,
        b'?' as u16,
        b'\\' as u16,
        b'h' as u16,
        b'i' as u16,
        b'd' as u16,
    ];
    const DOS: [u16; 7] = [
        b'\\' as u16,
        b'\\' as u16,
        b'?' as u16,
        b'\\' as u16,
        b'h' as u16,
        b'i' as u16,
        b'd' as u16,
    ];
    (units.len() >= NATIVE.len() && wide_ascii_eq(&units[..NATIVE.len()], &NATIVE))
        || (units.len() >= DOS.len() && wide_ascii_eq(&units[..DOS.len()], &DOS))
}

unsafe extern "system" fn create_file_w_detour(
    path: *const u16,
    desired_access: u32,
    share_mode: u32,
    security: *const SECURITY_ATTRIBUTES,
    disposition: u32,
    flags: u32,
    template: HANDLE,
) -> HANDLE {
    // Deny new HID opens only while leased; otherwise call the trampoline and
    // remember successful HID handles for subsequent I/O classification.
    let hid = unsafe { wide_has_hid_prefix(path) };
    if hid && blocking() {
        unsafe { SetLastError(ERROR_NO_SUCH_DEVICE) };
        return INVALID_HANDLE_VALUE;
    }
    let original: CreateFileWFn = unsafe { load_function(&CREATE_FILE_W) };
    let result = unsafe {
        original(
            path,
            desired_access,
            share_mode,
            security,
            disposition,
            flags,
            template,
        )
    };
    if hid && result != INVALID_HANDLE_VALUE {
        remember_handle(result, HandleClass::Hid);
    }
    result
}

unsafe extern "system" fn create_file_a_detour(
    path: *const u8,
    desired_access: u32,
    share_mode: u32,
    security: *const SECURITY_ATTRIBUTES,
    disposition: u32,
    flags: u32,
    template: HANDLE,
) -> HANDLE {
    let hid = unsafe { narrow_has_hid_prefix(path) };
    if hid && blocking() {
        unsafe { SetLastError(ERROR_NO_SUCH_DEVICE) };
        return INVALID_HANDLE_VALUE;
    }
    let original: CreateFileAFn = unsafe { load_function(&CREATE_FILE_A) };
    let result = unsafe {
        original(
            path,
            desired_access,
            share_mode,
            security,
            disposition,
            flags,
            template,
        )
    };
    if hid && result != INVALID_HANDLE_VALUE {
        remember_handle(result, HandleClass::Hid);
    }
    result
}

unsafe extern "system" fn create_file_2_detour(
    path: *const u16,
    desired_access: u32,
    share_mode: u32,
    disposition: u32,
    parameters: *const CREATEFILE2_EXTENDED_PARAMETERS,
) -> HANDLE {
    let hid = unsafe { wide_has_hid_prefix(path) };
    if hid && blocking() {
        unsafe { SetLastError(ERROR_NO_SUCH_DEVICE) };
        return INVALID_HANDLE_VALUE;
    }
    let original: CreateFile2Fn = unsafe { load_function(&CREATE_FILE_2) };
    let result = unsafe { original(path, desired_access, share_mode, disposition, parameters) };
    if hid && result != INVALID_HANDLE_VALUE {
        remember_handle(result, HandleClass::Hid);
    }
    result
}

unsafe fn denied_io(status: *mut IoStatusBlock, event: HANDLE) -> i32 {
    // Complete the NT request synchronously with the same disconnected status
    // Steam already handles for physical controller removal.
    if let Some(status) = unsafe { status.as_mut() } {
        status.status = STATUS_DEVICE_NOT_CONNECTED as isize;
        status.information = 0;
    }
    if !event.is_null() {
        unsafe { SetEvent(event) };
    }
    STATUS_DEVICE_NOT_CONNECTED
}

unsafe extern "system" fn nt_read_file_detour(
    file: HANDLE,
    event: HANDLE,
    apc: IoApcRoutine,
    context: *mut c_void,
    status: *mut IoStatusBlock,
    buffer: *mut c_void,
    length: u32,
    offset: *mut i64,
    key: *mut u32,
) -> i32 {
    if should_deny(file) {
        return unsafe { denied_io(status, event) };
    }
    let original: NtReadFileFn = unsafe { load_function(&NT_READ_FILE) };
    unsafe {
        original(
            file, event, apc, context, status, buffer, length, offset, key,
        )
    }
}

unsafe extern "system" fn nt_write_file_detour(
    file: HANDLE,
    event: HANDLE,
    apc: IoApcRoutine,
    context: *mut c_void,
    status: *mut IoStatusBlock,
    buffer: *mut c_void,
    length: u32,
    offset: *mut i64,
    key: *mut u32,
) -> i32 {
    if should_deny(file) {
        return unsafe { denied_io(status, event) };
    }
    let original: NtWriteFileFn = unsafe { load_function(&NT_WRITE_FILE) };
    unsafe {
        original(
            file, event, apc, context, status, buffer, length, offset, key,
        )
    }
}

unsafe extern "system" fn nt_device_io_control_file_detour(
    file: HANDLE,
    event: HANDLE,
    apc: IoApcRoutine,
    context: *mut c_void,
    status: *mut IoStatusBlock,
    control_code: u32,
    input: *mut c_void,
    input_length: u32,
    output: *mut c_void,
    output_length: u32,
) -> i32 {
    if should_deny(file) {
        return unsafe { denied_io(status, event) };
    }
    let original: NtDeviceIoControlFileFn = unsafe { load_function(&NT_DEVICE_IO_CONTROL_FILE) };
    unsafe {
        original(
            file,
            event,
            apc,
            context,
            status,
            control_code,
            input,
            input_length,
            output,
            output_length,
        )
    }
}

unsafe extern "system" fn nt_close_detour(handle: HANDLE) -> i32 {
    forget_handle(handle);
    let original: NtCloseFn = unsafe { load_function(&NT_CLOSE) };
    unsafe { original(handle) }
}

unsafe fn denied_open(file: *mut HANDLE, status: *mut IoStatusBlock) -> i32 {
    if let Some(file) = unsafe { file.as_mut() } {
        *file = INVALID_HANDLE_VALUE;
    }
    if let Some(status) = unsafe { status.as_mut() } {
        status.status = STATUS_DEVICE_NOT_CONNECTED as isize;
        status.information = 0;
    }
    STATUS_DEVICE_NOT_CONNECTED
}

unsafe extern "system" fn nt_create_file_detour(
    file: *mut HANDLE,
    desired_access: u32,
    attributes: *mut ObjectAttributes,
    status: *mut IoStatusBlock,
    allocation_size: *mut i64,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *mut c_void,
    ea_length: u32,
) -> i32 {
    let hid = unsafe { native_has_hid_prefix(attributes) };
    if hid && blocking() {
        return unsafe { denied_open(file, status) };
    }
    let original: NtCreateFileFn = unsafe { load_function(&NT_CREATE_FILE) };
    let result = unsafe {
        original(
            file,
            desired_access,
            attributes,
            status,
            allocation_size,
            file_attributes,
            share_access,
            create_disposition,
            create_options,
            ea_buffer,
            ea_length,
        )
    };
    if hid && result >= 0 && !file.is_null() {
        remember_handle(unsafe { *file }, HandleClass::Hid);
    }
    result
}

unsafe extern "system" fn nt_open_file_detour(
    file: *mut HANDLE,
    desired_access: u32,
    attributes: *mut ObjectAttributes,
    status: *mut IoStatusBlock,
    share_access: u32,
    open_options: u32,
) -> i32 {
    let hid = unsafe { native_has_hid_prefix(attributes) };
    if hid && blocking() {
        return unsafe { denied_open(file, status) };
    }
    let original: NtOpenFileFn = unsafe { load_function(&NT_OPEN_FILE) };
    let result = unsafe {
        original(
            file,
            desired_access,
            attributes,
            status,
            share_access,
            open_options,
        )
    };
    if hid && result >= 0 && !file.is_null() {
        remember_handle(unsafe { *file }, HandleClass::Hid);
    }
    result
}

macro_rules! xinput_detours {
    // XInput is loaded through several side-by-side system DLLs. Generate one
    // detour set per module because each export requires its own trampoline.
    ($state:ident, $state_ex:ident, $caps:ident, $caps_ex:ident, $index:expr) => {
        unsafe extern "system" fn $state(user: u32, output: *mut c_void) -> u32 {
            if blocking() {
                ERROR_DEVICE_NOT_CONNECTED
            } else {
                let original: XInputGetStateFn =
                    unsafe { load_function(&XINPUT_GET_STATE[$index]) };
                unsafe { original(user, output) }
            }
        }
        unsafe extern "system" fn $state_ex(user: u32, output: *mut c_void) -> u32 {
            if blocking() {
                ERROR_DEVICE_NOT_CONNECTED
            } else {
                let original: XInputGetStateExFn =
                    unsafe { load_function(&XINPUT_GET_STATE_EX[$index]) };
                unsafe { original(user, output) }
            }
        }
        unsafe extern "system" fn $caps(user: u32, flags: u32, output: *mut c_void) -> u32 {
            if blocking() {
                ERROR_DEVICE_NOT_CONNECTED
            } else {
                let original: XInputGetCapabilitiesFn =
                    unsafe { load_function(&XINPUT_GET_CAPABILITIES[$index]) };
                unsafe { original(user, flags, output) }
            }
        }
        unsafe extern "system" fn $caps_ex(
            reserved: u32,
            user: u32,
            flags: u32,
            output: *mut c_void,
        ) -> u32 {
            if blocking() {
                ERROR_DEVICE_NOT_CONNECTED
            } else {
                let original: XInputGetCapabilitiesExFn =
                    unsafe { load_function(&XINPUT_GET_CAPABILITIES_EX[$index]) };
                unsafe { original(reserved, user, flags, output) }
            }
        }
    };
}

xinput_detours!(
    xinput_state_0,
    xinput_state_ex_0,
    xinput_caps_0,
    xinput_caps_ex_0,
    0
);
xinput_detours!(
    xinput_state_1,
    xinput_state_ex_1,
    xinput_caps_1,
    xinput_caps_ex_1,
    1
);
xinput_detours!(
    xinput_state_2,
    xinput_state_ex_2,
    xinput_caps_2,
    xinput_caps_ex_2,
    2
);
xinput_detours!(
    xinput_state_3,
    xinput_state_ex_3,
    xinput_caps_3,
    xinput_caps_ex_3,
    3
);
xinput_detours!(
    xinput_state_4,
    xinput_state_ex_4,
    xinput_caps_4,
    xinput_caps_ex_4,
    4
);

fn procedure(module: HMODULE, name: *const u8) -> *mut c_void {
    unsafe { GetProcAddress(module, name) }
        .map_or(null_mut(), |function| function as *const () as *mut c_void)
}

unsafe fn queue_hook(
    target: *mut c_void,
    detour: *mut c_void,
    original: &AtomicPtr<c_void>,
    required: bool,
) -> bool {
    // Required hooks make initialization fail atomically. Optional hooks cover
    // exports/ordinals absent from some XInput versions.
    if target.is_null() {
        return !required;
    }
    let mut trampoline = null_mut();
    let status = unsafe { MH_CreateHook(target, detour, &mut trampoline) };
    if status == MH_ERROR_ALREADY_CREATED || status != MH_OK {
        return !required;
    }
    original.store(trampoline, Ordering::Release);
    unsafe { MH_QueueEnableHook(target) == MH_OK }
}

unsafe fn install_xinput_module(index: usize, module_name: &str) {
    let wide: Vec<u16> = module_name.encode_utf16().chain(Some(0)).collect();
    let module = unsafe { LoadLibraryExW(wide.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
    if module.is_null() {
        return;
    }
    let (state, state_ex, caps, caps_ex): (*mut c_void, *mut c_void, *mut c_void, *mut c_void) =
        match index {
            0 => (
                xinput_state_0 as _,
                xinput_state_ex_0 as _,
                xinput_caps_0 as _,
                xinput_caps_ex_0 as _,
            ),
            1 => (
                xinput_state_1 as _,
                xinput_state_ex_1 as _,
                xinput_caps_1 as _,
                xinput_caps_ex_1 as _,
            ),
            2 => (
                xinput_state_2 as _,
                xinput_state_ex_2 as _,
                xinput_caps_2 as _,
                xinput_caps_ex_2 as _,
            ),
            3 => (
                xinput_state_3 as _,
                xinput_state_ex_3 as _,
                xinput_caps_3 as _,
                xinput_caps_ex_3 as _,
            ),
            _ => (
                xinput_state_4 as _,
                xinput_state_ex_4 as _,
                xinput_caps_4 as _,
                xinput_caps_ex_4 as _,
            ),
        };
    unsafe {
        queue_hook(
            procedure(module, c"XInputGetState".as_ptr().cast()),
            state,
            &XINPUT_GET_STATE[index],
            false,
        );
        queue_hook(
            procedure(module, 100usize as *const u8),
            state_ex,
            &XINPUT_GET_STATE_EX[index],
            false,
        );
        queue_hook(
            procedure(module, c"XInputGetCapabilities".as_ptr().cast()),
            caps,
            &XINPUT_GET_CAPABILITIES[index],
            false,
        );
        queue_hook(
            procedure(module, 108usize as *const u8),
            caps_ex,
            &XINPUT_GET_CAPABILITIES_EX[index],
            false,
        );
    }
}

unsafe fn install_hooks() -> bool {
    // Queue every required hook before applying any of them, preventing a
    // partially active gate when one target cannot be patched.
    if unsafe { MH_Initialize() } != MH_OK {
        return false;
    }
    let kernel32_name: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
    let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
    let kernel32 = unsafe { GetModuleHandleW(kernel32_name.as_ptr()) };
    let ntdll = unsafe { GetModuleHandleW(ntdll_name.as_ptr()) };
    if kernel32.is_null() || ntdll.is_null() {
        unsafe { MH_Uninitialize() };
        return false;
    }

    NT_QUERY_SYSTEM_INFORMATION.store(
        procedure(ntdll, c"NtQuerySystemInformation".as_ptr().cast()),
        Ordering::Release,
    );
    NT_QUERY_OBJECT.store(
        procedure(ntdll, c"NtQueryObject".as_ptr().cast()),
        Ordering::Release,
    );
    // Optional: absence forces the system-wide fallback in the revocation sweep,
    // so it must NOT fail installation.
    NT_QUERY_INFORMATION_PROCESS.store(
        procedure(ntdll, c"NtQueryInformationProcess".as_ptr().cast()),
        Ordering::Release,
    );
    if NT_QUERY_SYSTEM_INFORMATION
        .load(Ordering::Acquire)
        .is_null()
        || NT_QUERY_OBJECT.load(Ordering::Acquire).is_null()
    {
        unsafe { MH_Uninitialize() };
        return false;
    }

    let mut success = true;
    unsafe {
        success &= queue_hook(
            procedure(kernel32, c"CreateFileW".as_ptr().cast()),
            create_file_w_detour as _,
            &CREATE_FILE_W,
            true,
        );
        success &= queue_hook(
            procedure(kernel32, c"CreateFileA".as_ptr().cast()),
            create_file_a_detour as _,
            &CREATE_FILE_A,
            true,
        );
        success &= queue_hook(
            procedure(kernel32, c"CreateFile2".as_ptr().cast()),
            create_file_2_detour as _,
            &CREATE_FILE_2,
            true,
        );
        success &= queue_hook(
            procedure(ntdll, c"NtReadFile".as_ptr().cast()),
            nt_read_file_detour as _,
            &NT_READ_FILE,
            true,
        );
        success &= queue_hook(
            procedure(ntdll, c"NtWriteFile".as_ptr().cast()),
            nt_write_file_detour as _,
            &NT_WRITE_FILE,
            true,
        );
        success &= queue_hook(
            procedure(ntdll, c"NtDeviceIoControlFile".as_ptr().cast()),
            nt_device_io_control_file_detour as _,
            &NT_DEVICE_IO_CONTROL_FILE,
            true,
        );
        success &= queue_hook(
            procedure(ntdll, c"NtClose".as_ptr().cast()),
            nt_close_detour as _,
            &NT_CLOSE,
            true,
        );
        success &= queue_hook(
            procedure(ntdll, c"NtCreateFile".as_ptr().cast()),
            nt_create_file_detour as _,
            &NT_CREATE_FILE,
            true,
        );
        success &= queue_hook(
            procedure(ntdll, c"NtOpenFile".as_ptr().cast()),
            nt_open_file_detour as _,
            &NT_OPEN_FILE,
            true,
        );
    }
    if !success {
        unsafe { MH_Uninitialize() };
        return false;
    }

    for (index, name) in [
        "xinput1_4.dll",
        "xinput1_3.dll",
        "xinput1_2.dll",
        "xinput1_1.dll",
        "xinput9_1_0.dll",
    ]
    .iter()
    .enumerate()
    {
        unsafe { install_xinput_module(index, name) };
    }
    if unsafe { MH_ApplyQueued() } != MH_OK {
        unsafe { MH_Uninitialize() };
        return false;
    }
    true
}

// Both NT handle queries reply with a pointer-sized count and reserved field
// followed by a packed array of fixed-size entries, and report the space they
// need through STATUS_INFO_LENGTH_MISMATCH. The reply is allocated as `u64`
// elements rather than bytes because the callers reinterpret that array in
// place: its entries have pointer-sized fields, and `Vec<u8>` guarantees only
// byte alignment.
fn query_until_sized(
    initial: usize,
    mut query: impl FnMut(*mut c_void, u32, &mut u32) -> i32,
) -> Option<Vec<u64>> {
    let mut capacity = initial;
    let mut buffer = Vec::<u64>::new();
    for _ in 0..6 {
        // Vec::resize ABORTS the process on allocation failure, and the
        // system-wide reply is sized by handles this process does not own.
        // Giving up costs at most one skipped revocation; aborting kills Steam.
        if capacity > HANDLE_QUERY_LIMIT {
            return None;
        }
        buffer.clear();
        buffer.resize(capacity.div_ceil(size_of::<u64>()), 0);
        let length = u32::try_from(size_of_val(buffer.as_slice())).unwrap_or(u32::MAX);
        let mut required = 0;
        let status = query(buffer.as_mut_ptr().cast(), length, &mut required);
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return (status >= 0).then_some(buffer);
        }
        capacity = if required as usize > capacity {
            required as usize + (1usize << 16)
        } else {
            capacity * 2
        };
    }
    None
}

/// Reinterprets the tail of a handle-information reply as its entry array,
/// clamping the reported count to what the buffer can actually hold.
///
/// # Safety
/// `buffer` must have been filled by a query whose reply is a pointer-sized
/// count and reserved field followed by a packed array of `T`.
unsafe fn handle_entries<T>(buffer: &[u64]) -> &[T] {
    const { assert!(size_of::<T>() != 0) };
    let bytes = size_of_val(buffer);
    let entries_offset = size_of::<usize>() * 2;
    if bytes < entries_offset {
        return &[];
    }
    let count = unsafe { *buffer.as_ptr().cast::<usize>() };
    let maximum = (bytes - entries_offset) / size_of::<T>();
    unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(entries_offset).cast::<T>(),
            count.min(maximum),
        )
    }
}

// Per-process handle enumeration. Preferred over the system-wide sweep because
// the system-wide query sizes its buffer to every handle on the machine - a
// hundreds-of-megabyte allocation set by unrelated processes, and Rust ABORTS
// on allocation failure. This asks only for this process's handles. Returns
// (handle, object_type_index) pairs; None on any failure so the caller can fall
// back to the system-wide path rather than silently skipping revocation.
fn process_handle_entries() -> Option<Vec<(HANDLE, u32)>> {
    let query_pointer = NT_QUERY_INFORMATION_PROCESS.load(Ordering::Acquire);
    if query_pointer.is_null() {
        return None;
    }
    let query: NtQueryInformationProcessFn = unsafe { transmute_copy(&query_pointer) };
    let buffer = query_until_sized(64usize << 10, |data, length, required| unsafe {
        query(
            GetCurrentProcess(),
            PROCESS_HANDLE_INFORMATION,
            data,
            length,
            required,
        )
    })?;
    // An empty reply is treated as failure so the caller falls back rather than
    // accepting a no-op revocation: this process always owns handles, so zero
    // entries means the reply was not understood, not that there is nothing to
    // revoke.
    let entries: Vec<_> = unsafe { handle_entries::<ProcessHandleEntry>(&buffer) }
        .iter()
        .map(|entry| (entry.handle_value, entry.object_type_index))
        .collect();
    (!entries.is_empty()).then_some(entries)
}

// System-wide handle enumeration, retained as the fallback for builds where
// NtQueryInformationProcess(ProcessHandleInformation) is unavailable. Widens the
// u16 object_type_index to u32 to match the per-process path.
fn system_handle_entries() -> Option<Vec<(HANDLE, u32)>> {
    let query_pointer = NT_QUERY_SYSTEM_INFORMATION.load(Ordering::Acquire);
    if query_pointer.is_null() {
        return None;
    }
    let query: NtQuerySystemInformationFn = unsafe { transmute_copy(&query_pointer) };
    let buffer = query_until_sized(1usize << 20, |data, length, required| unsafe {
        query(SYSTEM_EXTENDED_HANDLE_INFORMATION, data, length, required)
    })?;
    let current_process = unsafe { GetCurrentProcessId() } as usize;
    let entries: Vec<_> = unsafe { handle_entries::<SystemHandleEntryEx>(&buffer) }
        .iter()
        .filter(|entry| entry.process_id == current_process)
        .map(|entry| (entry.handle_value as HANDLE, entry.object_type_index as u32))
        .collect();
    (!entries.is_empty()).then_some(entries)
}

fn discover_and_revoke_hid_handles() {
    // Existing handles predate the CreateFile hooks. Enumerate the process
    // handle table, classify file handles carefully, cancel pending I/O, then
    // close Steam's HID handles so another application can obtain them. Falling
    // back rather than returning early is a safety requirement: revocation must
    // never silently no-op, or Steam would keep its controller handles while the
    // caller believes it holds a lease.
    LAST_REVOKED_HANDLE_COUNT.store(0, Ordering::Release);
    let Some(entries) = process_handle_entries().or_else(system_handle_entries) else {
        return;
    };
    let close: NtCloseFn = unsafe { load_function(&NT_CLOSE) };
    let mut file_type_index = None;
    for (handle, object_type_index) in entries {
        if let Some(index) = file_type_index {
            if object_type_index != index {
                continue;
            }
        } else if is_file_object(handle) {
            file_type_index = Some(object_type_index);
        } else {
            continue;
        }

        let classification = probe_file_handle(handle);
        remember_handle(handle, classification);
        if classification == HandleClass::Hid {
            unsafe { CancelIoEx(handle, null()) };
            forget_handle(handle);
            if unsafe { close(handle) } >= 0 {
                LAST_REVOKED_HANDLE_COUNT.fetch_add(1, Ordering::AcqRel);
            }
        }
    }
}

unsafe fn read_current<T: Copy>(address: usize) -> Option<T> {
    let mut value: T = unsafe { zeroed() };
    let mut transferred = 0;
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const c_void,
            (&mut value as *mut T).cast(),
            size_of::<T>(),
            &mut transferred,
        )
    } != FALSE;
    (ok && transferred == size_of::<T>()).then_some(value)
}

fn memory_is_readable(memory: &MEMORY_BASIC_INFORMATION) -> bool {
    memory.State == MEM_COMMIT
        && memory.Protect & PAGE_GUARD == 0
        && memory.Protect & PAGE_NOACCESS == 0
}

fn current_module_size(base: usize) -> Option<usize> {
    // Read SizeOfImage from the mapped PE32+ headers. The shared resolver will
    // independently validate every header field before it trusts a section.
    unsafe {
        if read_current::<u16>(base)? != 0x5a4d {
            return None;
        }
        let nt_offset = read_current::<u32>(base + 0x3c)? as usize;
        if nt_offset > 0x10_000 || read_current::<u32>(base + nt_offset)? != 0x0000_4550 {
            return None;
        }
        let optional = base + nt_offset + 24;
        if read_current::<u16>(optional)? != 0x20b {
            return None;
        }
        let size = read_current::<u32>(optional + 56)? as usize;
        (size != 0 && size <= MODULE_SNAPSHOT_LIMIT).then_some(size)
    }
}

fn snapshot_current_range(base: usize, size: usize) -> Vec<u8> {
    let mut snapshot = vec![0u8; size];
    let end = base.saturating_add(size);
    let mut address = base;
    while address < end {
        let mut memory: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        if unsafe {
            VirtualQuery(
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
            let destination = region_start - base;
            let length = region_end - region_start;
            let mut transferred = 0;
            unsafe {
                ReadProcessMemory(
                    GetCurrentProcess(),
                    region_start as *const c_void,
                    snapshot[destination..destination + length]
                        .as_mut_ptr()
                        .cast(),
                    length,
                    &mut transferred,
                );
            }
        }
        address = region_end;
    }
    snapshot
}

fn resolve_runtime_recovery_layout() -> Option<RuntimeRecoveryLayout> {
    let name: Vec<u16> = "steamclient64.dll".encode_utf16().chain(Some(0)).collect();
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return None;
    }
    let base = module as usize;
    let image = snapshot_current_range(base, current_module_size(base)?);
    let layout = resolve_recovery_layout(base, &image).ok()?;
    Some(RuntimeRecoveryLayout {
        module_base: base,
        layout,
    })
}

// Caches only successful resolves. A OnceLock<Option<..>> would let one early
// failure - the payload injected before steamclient64.dll is loaded - report
// capabilities 0 for the life of the Steam process. Attempts are bounded because
// a failed attempt on a loaded-but-unrecognised build costs a large module
// snapshot. Two threads racing may both resolve; set() ignores the loser, which
// is cheaper than a lock.
fn runtime_recovery_layout(ignore_budget: bool) -> Option<&'static RuntimeRecoveryLayout> {
    if let Some(layout) = RECOVERY_LAYOUT.get() {
        return Some(layout);
    }
    if !ignore_budget && RECOVERY_LAYOUT_ATTEMPTS.load(Ordering::Acquire) >= RECOVERY_LAYOUT_MAX_ATTEMPTS
    {
        return None;
    }
    match resolve_runtime_recovery_layout() {
        Some(resolved) => {
            let _ = RECOVERY_LAYOUT.set(resolved);
            RECOVERY_LAYOUT.get()
        }
        None => {
            RECOVERY_LAYOUT_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
            None
        }
    }
}

fn validate_hid_thread(runtime: &RuntimeRecoveryLayout, address: usize) -> bool {
    if address == 0 {
        return false;
    }
    unsafe {
        let primary = read_current::<usize>(address);
        let secondary =
            read_current::<usize>(address + runtime.layout.secondary_object_offset as usize);
        let deadline =
            read_current::<f64>(address + runtime.layout.discovery_deadline_offset as usize);
        primary == Some(runtime.module_base + runtime.layout.primary_vtable_rva as usize)
            && secondary == Some(runtime.module_base + runtime.layout.secondary_vtable_rva as usize)
            && deadline.is_some_and(|value| {
                value.is_finite() && (value == -1.0 || (0.0..1.0e12).contains(&value))
            })
    }
}

fn find_hid_thread(runtime: &RuntimeRecoveryLayout, ignore_budget: bool) -> Option<usize> {
    let cached = HID_THREAD_ADDRESS.load(Ordering::Acquire);
    if validate_hid_thread(runtime, cached) {
        return Some(cached);
    }
    HID_THREAD_ADDRESS.store(0, Ordering::Release);
    // Bound repeated full sweeps. A zero-candidate or ambiguous result leaves the
    // cache at 0, and response() resolves capabilities on every reply, so an
    // unbounded sweep would repeat on every poll. Not a permanent latch: the
    // object legitimately may not exist yet if Steam has not constructed
    // CHIDIOThread. The counter is reset on every lease acquire, and controller
    // recovery passes ignore_budget so it is never answered from a spent one.
    if !ignore_budget && HID_THREAD_ATTEMPTS.load(Ordering::Acquire) >= HID_THREAD_MAX_ATTEMPTS {
        return None;
    }

    let secondary_offset = runtime.layout.secondary_object_offset as usize;
    let primary = runtime.module_base + runtime.layout.primary_vtable_rva as usize;
    let secondary = runtime.module_base + runtime.layout.secondary_vtable_rva as usize;
    let pair_size = secondary_offset + size_of::<usize>();
    let mut candidates = Vec::new();
    // One reused buffer instead of a fresh zeroed Vec per chunk. Every scan MUST
    // slice to `transferred`: stale bytes from a previous, larger chunk live past
    // a short read, and letting the matcher see them could manufacture a false
    // candidate at a bogus address, defeating the "exactly one candidate" check
    // and naming a wrong address for the -1.0 store.
    let mut buffer = vec![0u8; PROCESS_SCAN_CHUNK];
    let mut address = 0x1_0000usize;
    while address < usize::MAX / 2 {
        let mut memory: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        if unsafe {
            VirtualQuery(
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
                        GetCurrentProcess(),
                        chunk_start as *const c_void,
                        buffer.as_mut_ptr().cast(),
                        length,
                        &mut transferred,
                    )
                } != FALSE
                {
                    candidates.extend(find_vtable_pairs(
                        &buffer[..transferred],
                        chunk_start,
                        primary,
                        secondary,
                        secondary_offset,
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
    candidates.retain(|&candidate| validate_hid_thread(runtime, candidate));
    candidates.sort_unstable();
    candidates.dedup();
    let elected = match candidates.as_slice() {
        [address] => Some(*address),
        [] => None,
        several => elect_running_hid_thread(runtime, several),
    };
    if let Some(address) = elected {
        HID_THREAD_ADDRESS.store(address, Ordering::Release);
        HID_THREAD_ATTEMPTS.store(0, Ordering::Release);
        Some(address)
    } else {
        HID_THREAD_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
        None
    }
}

/// Separates the running HID thread from abandoned look-alikes by watching
/// which candidate keeps scheduling discovery.
///
/// Revoking Steam's HID handles makes it rebuild its HID thread, and the freed
/// block keeps the class vtables and a plausible deadline until the allocator
/// reuses that memory. The copy is structurally a valid object, so only
/// movement in the scheduler fields tells the two apart. Steam is nudged with
/// the same device-change notification used as the unknown-build fallback so
/// the live thread has a reason to reschedule promptly.
///
/// Returns `None` unless exactly one candidate moves, which keeps the caller
/// fail-closed: this address later receives the deadline store.
fn elect_running_hid_thread(
    runtime: &RuntimeRecoveryLayout,
    candidates: &[usize],
) -> Option<usize> {
    let before = sample_candidates(runtime, candidates)?;
    unsafe { EnumWindows(Some(notify_window), 0) };

    let deadline = Instant::now() + LIVE_ELECTION_TIMEOUT;
    while Instant::now() < deadline {
        thread::sleep(LIVE_ELECTION_INTERVAL);
        let after = sample_candidates(runtime, candidates)?;
        if let Some(index) = select_progressing_candidate(&before, &after) {
            return Some(candidates[index]);
        }
    }
    None
}

/// Reads the scheduler fields of every candidate. A candidate that cannot be
/// read abandons the election: an unreadable address must never be mistaken for
/// one that merely stood still.
fn sample_candidates(
    runtime: &RuntimeRecoveryLayout,
    candidates: &[usize],
) -> Option<Vec<SchedulerSample>> {
    candidates
        .iter()
        .map(|&candidate| unsafe {
            Some(SchedulerSample {
                deadline_bits: read_current::<f64>(
                    candidate + runtime.layout.discovery_deadline_offset as usize,
                )?
                .to_bits(),
                counter: read_current::<u32>(
                    candidate + runtime.layout.discovery_counter_offset as usize,
                )?,
            })
        })
        .collect()
}

fn resolve_discovery_deadline(ignore_budget: bool) -> Option<usize> {
    let runtime = runtime_recovery_layout(ignore_budget)?;
    let hid_thread = find_hid_thread(runtime, ignore_budget)?;
    Some(hid_thread + runtime.layout.discovery_deadline_offset as usize)
}

fn payload_capabilities() -> u16 {
    if resolve_discovery_deadline(false).is_some() {
        CAPABILITY_INTERNAL_RECOVERY
    } else {
        0
    }
}

fn request_internal_discovery(ignore_budget: bool) -> bool {
    let Some(deadline) = resolve_discovery_deadline(ignore_budget) else {
        return false;
    };
    if !deadline.is_multiple_of(align_of::<AtomicU64>()) {
        return false;
    }
    // CHIDIOThread interprets -1.0 as a request to schedule discovery roughly
    // one second later. The field is aligned and updated as one 64-bit value.
    let atomic = unsafe { AtomicU64::from_ptr(deadline as *mut u64) };
    atomic.store((-1.0f64).to_bits(), Ordering::SeqCst);
    true
}

unsafe extern "system" fn notify_window(window: HWND, _: LPARAM) -> i32 {
    let mut owner = 0;
    unsafe { GetWindowThreadProcessId(window, &mut owner) };
    if owner == unsafe { GetCurrentProcessId() } {
        unsafe { PostMessageW(window, WM_DEVICECHANGE, DBT_DEVNODES_CHANGED, 0) };
    }
    TRUE
}

// The second discovery request must land ~2.2 s after the first so it follows
// Steam's queued zombie-controller cleanup. It is deliberately NOT performed on
// the pipe worker thread: blocking is already released when it is scheduled, so
// making the client wait for it only adds latency. One permanent timer thread
// serves every release; re-arming overwrites the deadline instead of stacking.
//
// Safety: the image is pinned in server_thread before any client thread can
// exist, so this detached thread can never execute unmapped code. This mutex is
// touched only by pipe worker threads and the timer thread - NO detour may ever
// take it.
fn schedule_second_discovery() -> bool {
    let state =
        *RESCAN_TIMER.get_or_init(|| Box::leak(Box::new((Mutex::new(None), Condvar::new()))));
    // Report a spawn failure instead of arming a condvar nothing waits on: a
    // silently dropped second pass leaves controllers in the post-cleanup zombie
    // state after every release, and the response still advertises internal
    // recovery, so the host would skip its own two-pass fallback. The flag is
    // cleared again on failure so a later release can retry - caching the
    // failure would downgrade every future release over one transient shortage.
    if !RESCAN_TIMER_STARTED.load(Ordering::Acquire)
        && RESCAN_TIMER_STARTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        && thread::Builder::new()
            .name("steam-input-gate-rescan".into())
            .spawn(move || rescan_timer_loop(state))
            .is_err()
    {
        RESCAN_TIMER_STARTED.store(false, Ordering::Release);
        return false;
    }
    let (lock, condvar) = state;
    let mut deadline = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    *deadline = Some(Instant::now() + SECOND_DISCOVERY_DELAY);
    condvar.notify_one();
    true
}

fn rescan_timer_loop(state: &'static RescanTimer) {
    let (lock, condvar) = state;
    let mut armed = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    loop {
        match *armed {
            None => {
                armed = condvar
                    .wait(armed)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            Some(at) => {
                let now = Instant::now();
                if now < at {
                    armed = condvar
                        .wait_timeout(armed, at - now)
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .0;
                    continue;
                }
                *armed = None;
                drop(armed);
                // A new lease may have been taken during the window. Never ask
                // Steam to rediscover controllers while blocking is active; the
                // eventual release arms its own deferred request.
                if !blocking() {
                    request_internal_discovery(true);
                }
                armed = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
    }
}

fn notify_controller_rescan() {
    // A lease that was just released may have provoked Steam into replacing
    // CHIDIOThread, so the cached address is exactly the one most likely to be
    // stale here. Blocking is already off, and a new lease taken in the meantime
    // will run its own recovery on release, so leave that case entirely alone.
    if blocking() {
        return;
    }
    // Restoring controllers must never be answered from the negative cache:
    // status polls taken during the lease can spend the sweep budget, and the
    // crash-safe drop path has no host-side recovery to fall back on. The budget
    // still bounds those polls; only recovery itself overrides it.
    if request_internal_discovery(true) {
        if !schedule_second_discovery() {
            // The second pass is part of recovery, not a retry, so perform it on
            // this worker when no timer thread exists. The client waits, which is
            // the pre-timer behaviour and still preferable to skipping it.
            thread::sleep(SECOND_DISCOVERY_DELAY);
            if !blocking() {
                request_internal_discovery(true);
            }
        }
        return;
    }
    // Unknown Steam builds receive the non-invasive compatibility fallback.
    unsafe { EnumWindows(Some(notify_window), 0) };
    let name: Vec<u16> = "SDL3.dll".encode_utf16().chain(Some(0)).collect();
    let sdl = unsafe { GetModuleHandleW(name.as_ptr()) };
    if !sdl.is_null() {
        let pointer = procedure(sdl, c"SDL_UpdateJoysticks".as_ptr().cast());
        if !pointer.is_null() {
            let update: unsafe extern "C" fn() = unsafe { transmute_copy(&pointer) };
            unsafe { update() };
        }
    }
}

fn response(result: ResultCode) -> Response {
    Response {
        magic: PROTOCOL_MAGIC,
        version: PROTOCOL_VERSION,
        capabilities: payload_capabilities(),
        result: result as u32,
        lease_count: LEASE_COUNT.load(Ordering::Acquire).max(0) as u32,
        hid_handle_count: HID_HANDLE_COUNT.load(Ordering::Acquire).max(0) as u32,
        last_revoked_handle_count: LAST_REVOKED_HANDLE_COUNT.load(Ordering::Acquire).max(0) as u32,
    }
}

unsafe extern "system" fn client_thread(parameter: *mut c_void) -> u32 {
    let pipe = parameter as HANDLE;
    let mut request: Request = unsafe { zeroed() };
    let mut transferred = 0;
    let read = unsafe {
        ReadFile(
            pipe,
            (&mut request as *mut Request).cast(),
            size_of::<Request>() as u32,
            &mut transferred,
            null_mut(),
        )
    } != FALSE;
    let valid = read
        && transferred == size_of::<Request>() as u32
        && request.magic == PROTOCOL_MAGIC
        && request.version == PROTOCOL_VERSION;

    let mut lease = false;
    let result = if !valid {
        ResultCode::InvalidRequest
    } else if request.command == Command::AcquireLease as u16 {
        let leases = LEASE_COUNT.fetch_add(1, Ordering::AcqRel) + 1;
        lease = true;
        if leases == 1 {
            // A fresh acquire is the natural retry point for the bounded caches.
            HID_THREAD_ATTEMPTS.store(0, Ordering::Release);
            RECOVERY_LAYOUT_ATTEMPTS.store(0, Ordering::Release);
            discover_and_revoke_hid_handles();
        }
        ResultCode::Ok
    } else if request.command == Command::QueryStatus as u16 {
        ResultCode::Ok
    } else {
        ResultCode::InvalidRequest
    };

    let initial = response(result);
    unsafe {
        WriteFile(
            pipe,
            (&initial as *const Response).cast(),
            size_of::<Response>() as u32,
            &mut transferred,
            null_mut(),
        )
    };

    if lease {
        // This blocking read is intentional: the pipe's lifetime is the lease.
        // Explicit Release gives a response; EOF still decrements the count.
        let mut release: Request = unsafe { zeroed() };
        let explicit = unsafe {
            ReadFile(
                pipe,
                (&mut release as *mut Request).cast(),
                size_of::<Request>() as u32,
                &mut transferred,
                null_mut(),
            )
        } != FALSE
            && transferred == size_of::<Request>() as u32
            && release.magic == PROTOCOL_MAGIC
            && release.version == PROTOCOL_VERSION
            && release.command == Command::ReleaseLease as u16;

        let remaining = LEASE_COUNT.fetch_sub(1, Ordering::AcqRel) - 1;
        if remaining == 0 {
            notify_controller_rescan();
        }
        if explicit {
            let released = response(ResultCode::Ok);
            unsafe {
                WriteFile(
                    pipe,
                    (&released as *const Response).cast(),
                    size_of::<Response>() as u32,
                    &mut transferred,
                    null_mut(),
                )
            };
        }
    }

    unsafe {
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    0
}

unsafe extern "system" fn server_thread(_: *mut c_void) -> u32 {
    let mut pinned: HMODULE = null_mut();
    // Pinning prevents the Windows loader from unmapping code still referenced
    // by hook trampolines or detached worker threads. See the module-level note.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            server_thread as *const () as *const u16,
            &mut pinned,
        )
    };
    if !unsafe { install_hooks() } {
        return 1;
    }
    // Warm RECOVERY_LAYOUT and HID_THREAD_ADDRESS so the first acquire's
    // response() costs a few reads instead of a full address-space sweep. It runs
    // on its own thread because the control pipe must not wait for it: the sweep
    // can take seconds, and a host querying status uses a short fixed timeout and
    // never injects, so serialising the two would make a loaded payload look
    // absent. Placed after install_hooks so the trampolines are live.
    let _ = thread::Builder::new()
        .name("steam-input-gate-warmup".into())
        .spawn(|| {
            let _ = resolve_discovery_deadline(false);
        });

    let pipe_name = steam_input_lease_core::pipe_name(unsafe { GetCurrentProcessId() });
    loop {
        let pipe = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                size_of::<Response>() as u32,
                size_of::<Request>() as u32,
                0,
                null(),
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return 2;
        }
        let connected = unsafe { ConnectNamedPipe(pipe, null_mut()) } != FALSE
            || unsafe { GetLastError() } == 535; // ERROR_PIPE_CONNECTED
        if !connected {
            unsafe { CloseHandle(pipe) };
            continue;
        }
        let worker = unsafe { CreateThread(null(), 0, Some(client_thread), pipe, 0, null_mut()) };
        if worker.is_null() {
            unsafe {
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
            }
            continue;
        }
        unsafe { CloseHandle(worker) };
    }
}

#[unsafe(no_mangle)]
/// Windows loader entry point.
///
/// # Safety
/// Called only by the Windows loader with its documented `DllMain` arguments.
pub unsafe extern "system" fn DllMain(instance: HINSTANCE, reason: u32, _: *mut c_void) -> i32 {
    if reason == DLL_PROCESS_ATTACH {
        // Keep loader-lock work minimal. All allocation, hook installation, and
        // pipe setup occurs asynchronously on server_thread.
        unsafe { DisableThreadLibraryCalls(instance) };
        let worker =
            unsafe { CreateThread(null(), 0, Some(server_thread), null_mut(), 0, null_mut()) };
        if !worker.is_null() {
            unsafe { CloseHandle(worker) };
        }
    }
    TRUE
}
