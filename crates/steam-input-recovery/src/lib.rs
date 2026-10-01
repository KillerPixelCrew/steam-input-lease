//! Runtime discovery of Steam's internal controller-rescan fields.
//!
//! Steam does not expose a public API that asks its HID thread to enumerate
//! controllers again. The relevant private object layout changes between
//! Steam builds, so this crate deliberately contains no build-number table or
//! fixed RVAs. Instead it resolves the `CSteamController::CHIDIOThread` MSVC
//! RTTI in the loaded `steamclient64.dll` image, follows its complete-object
//! locators to the class vtables, and semantically inspects virtual methods for
//! the discovery scheduler's deadline/counter instruction sequence.
//!
//! This crate only analyzes caller-supplied snapshots and readings, and contains
//! no Win32 calls of its own. [`resolve_recovery_layout`] derives the layout
//! from an image snapshot, [`find_live_hid_threads`] scans live memory for the
//! objects carrying it, and [`elect_running_hid_thread`] picks the running one
//! when several survive. The host and the payload run the same scan and
//! election; each supplies only a [`ProcessMemory`] reader for its view of
//! Steam, and keeps writing the result to itself, where the appropriate Win32
//! APIs and ownership rules are known.

#![deny(missing_docs)]
// clippy 1.98 added `chunks_exact_to_as_chunks`, which fires on the three 8-byte
// scan loops below. The suggested `as_chunks::<8>()` splits the slice into an
// array prefix plus a remainder, so adopting it would reshape loops whose index
// arithmetic is tied to a byte offset in a snapshot of Steam's private memory —
// a live-verified path (docs\steam-input.md) with nothing to gain from the
// rewrite. Suppressed rather than "cleaned up": see the root AGENTS.md rule
// against refactoring verified mechanisms without re-verification.
// `unknown_lints` keeps the same source buildable on the current 1.94 toolchain,
// where the newer lint name does not exist yet; it can be removed once the
// repository's minimum Rust toolchain includes that lint.
#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use core::fmt;
use std::thread;
use std::time::{Duration, Instant};

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

const HID_THREAD_RTTI_NAME: &[u8] = b".?AVCHIDIOThread@CSteamController@@\0";
const TYPE_DESCRIPTOR_NAME_OFFSET: usize = 16;
const COMPLETE_OBJECT_LOCATOR_SIZE: usize = 24;
const MAX_SECONDARY_OFFSET: u32 = 0x100;
const MAX_VTABLE_METHODS: usize = 8;
const MAX_METHOD_BYTES: usize = 0x20_000;
const MAX_FIELD_OFFSET: u64 = 0x20_000;

/// Module-relative values needed to find and trigger Steam's HID discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryLayout {
    /// RVA of the HID-thread primary vtable.
    pub primary_vtable_rva: u32,
    /// RVA of the HID-thread `CThread` secondary vtable.
    pub secondary_vtable_rva: u32,
    /// Offset of the secondary base subobject inside the complete HID object.
    pub secondary_object_offset: u32,
    /// RVA of the virtual worker method that schedules controller discovery.
    pub worker_method_rva: u32,
    /// Offset of the discovery deadline from the complete HID object.
    pub discovery_deadline_offset: u32,
    /// Offset of the discovery counter from the complete HID object.
    pub discovery_counter_offset: u32,
}

/// Why a module snapshot could not be resolved safely.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// The supplied bytes are not a supported loaded PE32+ image.
    InvalidPe(&'static str),
    /// The expected Valve RTTI type name was absent or occurred more than once.
    RttiNameCount(usize),
    /// No valid complete-object locator referenced the RTTI type descriptor.
    CompleteObjectLocatorNotFound,
    /// A required primary or secondary vtable could not be proven unique.
    VtableNotUnique(&'static str),
    /// No unique virtual method contained the guarded scheduler semantics.
    SchedulerNotUnique(usize),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPe(reason) => write!(formatter, "invalid steamclient PE image: {reason}"),
            Self::RttiNameCount(count) => write!(
                formatter,
                "CHIDIOThread RTTI name was expected once, but occurred {count} times"
            ),
            Self::CompleteObjectLocatorNotFound => {
                formatter.write_str("CHIDIOThread RTTI has no valid MSVC complete-object locator")
            }
            Self::VtableNotUnique(kind) => {
                write!(formatter, "CHIDIOThread {kind} vtable was not unique")
            }
            Self::SchedulerNotUnique(count) => write!(
                formatter,
                "controller discovery scheduler was expected once, but matched {count} methods"
            ),
        }
    }
}

impl std::error::Error for ResolveError {}

#[derive(Clone, Copy, Debug)]
struct PeSection {
    start: u32,
    end: u32,
    executable: bool,
}

#[derive(Clone, Copy, Debug)]
struct VtableCandidate {
    object_offset: u32,
    vtable_rva: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SchedulerFields {
    deadline_from_secondary: u32,
    counter_from_secondary: u32,
}

/// One observation of a candidate object's discovery scheduler fields.
///
/// The deadline is kept as raw bits deliberately: this value is only ever
/// compared for change, and `f64` equality would report "unchanged" for a
/// field that holds NaN in both observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerSample {
    /// Raw bits of the discovery deadline.
    pub deadline_bits: u64,
    /// Value of the discovery counter.
    pub counter: u32,
}

/// Picks the one candidate whose scheduler fields advanced between two
/// observations of the same candidate list.
///
/// Several addresses can carry the class vtables at once: a freed heap block
/// keeps them until the allocator reuses it, so a rebuilt HID thread leaves a
/// look-alike behind. Only the object a live thread owns keeps rescheduling
/// discovery, so movement in the deadline or the counter is what separates the
/// real object from an abandoned copy.
///
/// Returns `None` unless exactly one candidate moved, which keeps the caller
/// fail-closed: no movement at all, or movement in several candidates, is not
/// proof of which object may be written to. `before` and `after` must describe
/// the same candidates in the same order.
#[must_use]
pub fn select_progressing_candidate(
    before: &[SchedulerSample],
    after: &[SchedulerSample],
) -> Option<usize> {
    if before.is_empty() || before.len() != after.len() {
        return None;
    }
    let mut progressing = None;
    for (index, (first, second)) in before.iter().zip(after).enumerate() {
        if first != second {
            if progressing.is_some() {
                return None;
            }
            progressing = Some(index);
        }
    }
    progressing
}

// Win32 MEM_COMMIT, MEM_PRIVATE, PAGE_NOACCESS and PAGE_GUARD. This crate has no
// windows-sys dependency, so the documented SDK values are spelled out here.
const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x2_0000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;

/// Returns whether a queried memory region can be read without faulting.
///
/// `state` and `protect` are the region's `MEMORY_BASIC_INFORMATION` `State`
/// and `Protect` values. Only committed regions that are neither no-access nor
/// guard pages qualify.
#[must_use]
pub const fn memory_is_readable(state: u32, protect: u32) -> bool {
    state == MEM_COMMIT && protect & PAGE_GUARD == 0 && protect & PAGE_NOACCESS == 0
}

// How long the live-object election watches the scheduler fields, and how often
// it looks. The nudge makes the running thread reschedule well inside this
// budget. The timeout stays bounded because the payload runs the election on a
// pipe worker: an election that never separates the candidates ends in the same
// fail-closed answer it replaced.
const LIVE_ELECTION_TIMEOUT: Duration = Duration::from_millis(1500);
const LIVE_ELECTION_INTERVAL: Duration = Duration::from_millis(125);

/// Spacing between the two discovery requests of one recovery.
///
/// The second request must land after Steam's queued zombie-controller cleanup,
/// which the first request can trigger, so the post-cleanup state is durable.
pub const SECOND_DISCOVERY_DELAY: Duration = Duration::from_millis(2200);

// Bytes requested per read while scanning private memory for live objects.
const PROCESS_SCAN_CHUNK: usize = 1024 * 1024;

/// One region of a process's address space, as `VirtualQuery` reports it in
/// `MEMORY_BASIC_INFORMATION`.
#[derive(Clone, Copy, Debug)]
pub struct MemoryRegion {
    /// `BaseAddress`, where the region begins.
    pub base: usize,
    /// `RegionSize`, the region's length in bytes.
    pub size: usize,
    /// `State`, such as `MEM_COMMIT`.
    pub state: u32,
    /// `Protect`, the region's page protection.
    pub protect: u32,
    /// `Type`, such as `MEM_PRIVATE`.
    pub kind: u32,
}

/// Read access to one process's memory: the payload's own, or Steam's through
/// a host process handle.
///
/// The live-object scan and election are the same on both sides; only how they
/// reach Steam's memory differs, and that is all an implementation supplies.
pub trait ProcessMemory {
    /// Describes the region containing `address`, or `None` when the query
    /// fails, which ends a scan.
    fn query(&self, address: usize) -> Option<MemoryRegion>;

    /// Copies up to `buffer.len()` bytes from `address` and returns how many
    /// were copied. A partial copy stops at the first unreadable page, and the
    /// bytes it delivered are as valid as a full read's.
    fn read(&self, address: usize, buffer: &mut [u8]) -> usize;
}

fn read_exact<const N: usize>(memory: &impl ProcessMemory, address: usize) -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    (memory.read(address, &mut bytes) == N).then_some(bytes)
}

fn read_pointer(memory: &impl ProcessMemory, address: usize) -> Option<usize> {
    read_exact(memory, address).map(usize::from_ne_bytes)
}

/// Single definition of "this address still holds Steam's live `CHIDIOThread`"
/// for `layout` loaded at `module_base`.
///
/// Both embedded vtable slots must match the resolved pair, and the deadline
/// field must read as a plausible scheduling value; anything else means the
/// object was freed and its storage reused.
#[must_use]
pub fn hid_thread_is_live(
    memory: &impl ProcessMemory,
    module_base: usize,
    layout: &RecoveryLayout,
    address: usize,
) -> bool {
    let primary = module_base + layout.primary_vtable_rva as usize;
    let secondary = module_base + layout.secondary_vtable_rva as usize;
    read_pointer(memory, address) == Some(primary)
        && read_pointer(memory, address + layout.secondary_object_offset as usize)
            == Some(secondary)
        && read_exact(memory, address + layout.discovery_deadline_offset as usize)
            .map(f64::from_ne_bytes)
            .is_some_and(|value| {
                value.is_finite() && (value == -1.0 || (0.0..1.0e12).contains(&value))
            })
}

/// Scans the private memory of `memory` for live `CHIDIOThread` objects of
/// `layout` loaded at `module_base`, returning their addresses sorted and
/// without duplicates.
///
/// More than one address can survive; [`elect_running_hid_thread`] separates
/// them. Reads never dereference: an object freed under the scan only shortens
/// a read.
#[must_use]
pub fn find_live_hid_threads(
    memory: &impl ProcessMemory,
    module_base: usize,
    layout: &RecoveryLayout,
) -> Vec<usize> {
    let secondary_offset = layout.secondary_object_offset as usize;
    let primary = module_base + layout.primary_vtable_rva as usize;
    let secondary = module_base + layout.secondary_vtable_rva as usize;
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
        let Some(region) = memory.query(address) else {
            break;
        };
        let region_start = region.base;
        let region_end = region_start.saturating_add(region.size);
        if memory_is_readable(region.state, region.protect) && region.kind == MEM_PRIVATE {
            let mut chunk_start = region_start;
            while chunk_start < region_end {
                let chunk_end = chunk_start
                    .saturating_add(PROCESS_SCAN_CHUNK)
                    .min(region_end);
                let length = chunk_end - chunk_start;
                // Never trust the count past the request; slicing beyond the buffer would
                // panic, which inside Steam is a crash.
                let transferred = memory
                    .read(chunk_start, &mut buffer[..length])
                    .min(length);
                candidates.extend(find_vtable_pairs(
                    &buffer[..transferred],
                    chunk_start,
                    primary,
                    secondary,
                    secondary_offset,
                ));
                // A partial copy still delivered `transferred` bytes, which were
                // matched above; continue past the unreadable page rather than
                // skipping the rest of the chunk.
                match next_scan_start(
                    chunk_start,
                    chunk_end,
                    region_end,
                    transferred,
                    pair_size.saturating_sub(1),
                ) {
                    Some(next) => chunk_start = next,
                    None => break,
                }
            }
        }
        if region_end <= address {
            break;
        }
        address = region_end;
    }
    candidates.retain(|&candidate| hid_thread_is_live(memory, module_base, layout, candidate));
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

/// Separates the running HID thread from abandoned look-alikes by watching
/// which of `candidates` keeps scheduling discovery.
///
/// Revoking Steam's HID handles makes it tear its HID thread down and build a
/// new one, and the freed block keeps the class vtables and a plausible
/// deadline until the allocator hands that memory out again. The copy is
/// structurally a valid object, so only movement in the scheduler fields tells
/// the two apart. `nudge` should post Steam the device-change notification used
/// as the unknown-build fallback, so the live thread has a reason to reschedule
/// promptly.
///
/// A candidate that cannot be read abandons the election: an unreadable address
/// must never be mistaken for one that merely stood still. Nothing is written,
/// and only [`Election::Elected`] names a candidate, whose address later
/// receives the deadline store.
pub fn elect_running_hid_thread(
    memory: &impl ProcessMemory,
    layout: &RecoveryLayout,
    candidates: &[usize],
    nudge: impl FnOnce(),
) -> Election {
    let deadline_offset = layout.discovery_deadline_offset as usize;
    let counter_offset = layout.discovery_counter_offset as usize;
    elect_progressing_candidate(
        || {
            candidates
                .iter()
                .map(|&candidate| {
                    Some(SchedulerSample {
                        deadline_bits: u64::from_ne_bytes(read_exact(
                            memory,
                            candidate + deadline_offset,
                        )?),
                        counter: u32::from_ne_bytes(read_exact(
                            memory,
                            candidate + counter_offset,
                        )?),
                    })
                })
                .collect()
        },
        nudge,
    )
}

/// Outcome of [`elect_progressing_candidate`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Election {
    /// Exactly one candidate moved. The value is its index in the sampled list.
    Elected(usize),
    /// A candidate could not be read, which abandons the election.
    Unreadable,
    /// The observation window closed without exactly one candidate moving.
    Ambiguous {
        /// The observation taken before the nudge.
        before: Vec<SchedulerSample>,
        /// The last observation inside the window, or `None` when the window
        /// closed before a second observation was taken.
        last: Option<Vec<SchedulerSample>>,
    },
}

/// Watches a candidate list for the one object that keeps scheduling discovery.
///
/// `sample` reads every candidate's scheduler fields in a fixed order and
/// returns `None` when any candidate cannot be read: an unreadable address must
/// never be mistaken for one that merely stood still. `nudge` runs once, after
/// the first observation, to give the live thread a reason to reschedule. The
/// candidates are then re-sampled every 125 milliseconds for up to 1.5 seconds,
/// and the first observation that [`select_progressing_candidate`] resolves
/// elects its candidate.
///
/// Nothing here writes to the observed process. Only [`Election::Elected`]
/// names a candidate, so every other outcome keeps the caller fail-closed.
pub fn elect_progressing_candidate(
    mut sample: impl FnMut() -> Option<Vec<SchedulerSample>>,
    nudge: impl FnOnce(),
) -> Election {
    let Some(before) = sample() else {
        return Election::Unreadable;
    };
    nudge();

    let deadline = Instant::now() + LIVE_ELECTION_TIMEOUT;
    let mut last = None;
    while Instant::now() < deadline {
        thread::sleep(LIVE_ELECTION_INTERVAL);
        let Some(after) = sample() else {
            return Election::Unreadable;
        };
        if let Some(index) = select_progressing_candidate(&before, &after) {
            return Election::Elected(index);
        }
        last = Some(after);
    }
    Election::Ambiguous { before, last }
}

/// Finds the addresses in a memory snapshot that begin an object carrying both
/// halves of a resolved vtable pair.
///
/// `absolute_start` is the address `bytes[0]` was read from, so returned values
/// are absolute. A match requires the pointer-sized word at an offset to equal
/// `primary` and the word `secondary_offset` beyond it to equal `secondary`.
///
/// Only eight-byte-aligned addresses are considered: a C++ object begins with a
/// vtable pointer, and the MSVC x64 allocator never places one less aligned.
/// `secondary_offset` itself carries no alignment guarantee, so the second word
/// is copied out rather than read in place.
///
/// This performs no dereferencing of its own; the caller supplies the bytes and
/// remains responsible for reading them safely.
#[must_use]
pub fn find_vtable_pairs(
    bytes: &[u8],
    absolute_start: usize,
    primary: usize,
    secondary: usize,
    secondary_offset: usize,
) -> Vec<usize> {
    let required = secondary_offset.saturating_add(size_of::<usize>());
    // A null primary would match every aligned word of any zeroed page, turning
    // a caller that failed to resolve the module into a flood of bogus
    // candidates instead of a clean no-match.
    if primary == 0 || bytes.len() < required {
        return Vec::new();
    }
    let primary = primary as u64;
    let secondary = secondary as u64;
    let start = absolute_start.wrapping_neg() % 8;
    let last = bytes.len() - required;
    let mut addresses = Vec::new();
    for (index, chunk) in bytes[start..].chunks_exact(8).enumerate() {
        let offset = start + index * 8;
        if offset > last {
            break;
        }
        if u64::from_le_bytes(chunk.try_into().unwrap_or_default()) != primary {
            continue;
        }
        let mut slot = [0u8; 8];
        slot.copy_from_slice(&bytes[offset + secondary_offset..offset + secondary_offset + 8]);
        if u64::from_le_bytes(slot) == secondary {
            addresses.push(absolute_start + offset);
        }
    }
    addresses
}

/// Page size assumed when stepping over an unreadable page during a scan.
pub const SCAN_PAGE_SIZE: usize = 0x1000;

/// Returns where a chunked scan of `[.., region_end)` continues after reading
/// `[chunk_start, chunk_end)`, or `None` when the region is finished.
///
/// A complete read continues `overlap` bytes before `chunk_end`, so a pattern
/// that straddles two chunks is still seen. A short read (`transferred` less
/// than the chunk) stopped at the first unreadable page; the scan resumes at the
/// page after it, so the readable remainder of the chunk is still examined
/// instead of being skipped with the rest of the chunk. A pattern cannot straddle
/// an unreadable page, so no overlap is needed there.
#[must_use]
pub fn next_scan_start(
    chunk_start: usize,
    chunk_end: usize,
    region_end: usize,
    transferred: usize,
    overlap: usize,
) -> Option<usize> {
    let next = if transferred < chunk_end - chunk_start {
        let failed_at = chunk_start + transferred;
        (failed_at / SCAN_PAGE_SIZE + 1).saturating_mul(SCAN_PAGE_SIZE)
    } else if chunk_end >= region_end {
        return None;
    } else {
        chunk_end.saturating_sub(overlap).max(chunk_start + 1)
    };
    (next < region_end).then_some(next)
}

/// Resolves controller recovery from a snapshot of a *loaded* PE image.
///
/// `module_base` must be the runtime base represented by absolute pointers in
/// `image`. The byte slice is indexed by RVA and should be `SizeOfImage` bytes
/// long; unreadable pages may be zero-filled. The resolver never dereferences
/// addresses from the snapshot.
///
/// # Errors
///
/// Every failure means the layout could not be proven from this image, and the
/// caller must fall back rather than act on a guess:
///
/// - [`ResolveError::InvalidPe`] — the bytes are not a supported loaded PE32+ image.
/// - [`ResolveError::RttiNameCount`] — the Valve RTTI type name was absent, or
///   occurred more than once so no single class could be selected.
/// - [`ResolveError::CompleteObjectLocatorNotFound`] — no valid complete-object
///   locator referenced the RTTI type descriptor.
/// - [`ResolveError::VtableNotUnique`] — a required primary or secondary vtable
///   could not be proven unique.
/// - [`ResolveError::SchedulerNotUnique`] — no unique virtual method carried the
///   guarded scheduler semantics.
///
/// A Steam update that moves any of these is expected to surface here as an error,
/// not as a wrong address.
pub fn resolve_recovery_layout(
    module_base: usize,
    image: &[u8],
) -> Result<RecoveryLayout, ResolveError> {
    let sections = parse_pe_sections(image)?;
    let type_descriptor_rva = find_unique(image, HID_THREAD_RTTI_NAME)
        .map_err(ResolveError::RttiNameCount)?
        .checked_sub(TYPE_DESCRIPTOR_NAME_OFFSET)
        .ok_or(ResolveError::InvalidPe("RTTI type descriptor underflow"))?;
    let type_descriptor_rva = u32::try_from(type_descriptor_rva)
        .map_err(|_| ResolveError::InvalidPe("RTTI RVA exceeds 32 bits"))?;

    let locators = find_complete_object_locators(image, type_descriptor_rva);
    if locators.is_empty() {
        return Err(ResolveError::CompleteObjectLocatorNotFound);
    }

    let mut vtables: Vec<VtableCandidate> = Vec::new();
    for (locator_rva, object_offset) in locators {
        let absolute = (module_base as u64)
            .checked_add(locator_rva as u64)
            .ok_or(ResolveError::InvalidPe("module address overflow"))?;
        for reference in find_u64(image, absolute) {
            let Some(vtable_rva) = reference.checked_add(8) else {
                continue;
            };
            let Ok(vtable_rva) = u32::try_from(vtable_rva) else {
                continue;
            };
            if vtable_has_executable_entry(module_base, image, &sections, vtable_rva) {
                let candidate = VtableCandidate {
                    object_offset,
                    vtable_rva,
                };
                if !vtables.iter().any(|value| {
                    value.object_offset == candidate.object_offset
                        && value.vtable_rva == candidate.vtable_rva
                }) {
                    vtables.push(candidate);
                }
            }
        }
    }

    let primary = unique_vtable(&vtables, 0, "primary")?;
    let scheduler_matches = find_scheduler_layouts(module_base, image, &sections, &vtables, primary);

    if scheduler_matches.len() != 1 {
        return Err(ResolveError::SchedulerNotUnique(scheduler_matches.len()));
    }
    Ok(scheduler_matches[0])
}

fn find_scheduler_layouts(
    module_base: usize,
    image: &[u8],
    sections: &[PeSection],
    vtables: &[VtableCandidate],
    primary: VtableCandidate,
) -> Vec<RecoveryLayout> {
    let mut scheduler_matches = Vec::new();
    for secondary in vtables
        .iter()
        .copied()
        .filter(|value| value.object_offset != 0)
    {
        for index in 0..MAX_VTABLE_METHODS {
            let Some(pointer_rva) = (secondary.vtable_rva as usize).checked_add(index * 8) else {
                continue;
            };
            let Some(method) = read_u64(image, pointer_rva) else {
                continue;
            };
            let Some(method_rva) = method.checked_sub(module_base as u64) else {
                continue;
            };
            let Ok(method_rva) = u32::try_from(method_rva) else {
                continue;
            };
            if !rva_is_executable(sections, method_rva) {
                continue;
            }
            if let Some(fields) = analyze_scheduler_method(module_base, image, sections, method_rva)
            {
                let Some(deadline) = secondary
                    .object_offset
                    .checked_add(fields.deadline_from_secondary)
                else {
                    continue;
                };
                let Some(counter) = secondary
                    .object_offset
                    .checked_add(fields.counter_from_secondary)
                else {
                    continue;
                };
                let layout = RecoveryLayout {
                    primary_vtable_rva: primary.vtable_rva,
                    secondary_vtable_rva: secondary.vtable_rva,
                    secondary_object_offset: secondary.object_offset,
                    worker_method_rva: method_rva,
                    discovery_deadline_offset: deadline,
                    discovery_counter_offset: counter,
                };
                if !scheduler_matches.contains(&layout) {
                    scheduler_matches.push(layout);
                }
            }
        }
    }
    scheduler_matches
}

fn parse_pe_sections(image: &[u8]) -> Result<Vec<PeSection>, ResolveError> {
    if read_u16(image, 0) != Some(0x5a4d) {
        return Err(ResolveError::InvalidPe("DOS signature is missing"));
    }
    let nt_offset = read_u32(image, 0x3c)
        .map(|value| value as usize)
        .ok_or(ResolveError::InvalidPe("DOS header is truncated"))?;
    if read_u32(image, nt_offset) != Some(0x0000_4550) {
        return Err(ResolveError::InvalidPe("NT signature is missing"));
    }
    let section_count = read_u16(image, nt_offset + 6)
        .ok_or(ResolveError::InvalidPe("COFF header is truncated"))?
        as usize;
    let optional_size = read_u16(image, nt_offset + 20)
        .ok_or(ResolveError::InvalidPe("COFF header is truncated"))?
        as usize;
    let optional = nt_offset + 24;
    if read_u16(image, optional) != Some(0x20b) {
        return Err(ResolveError::InvalidPe("image is not PE32+"));
    }
    let declared_size = read_u32(image, optional + 56)
        .ok_or(ResolveError::InvalidPe("optional header is truncated"))?
        as usize;
    if declared_size > image.len() {
        return Err(ResolveError::InvalidPe(
            "snapshot is shorter than SizeOfImage",
        ));
    }
    let section_table = optional
        .checked_add(optional_size)
        .ok_or(ResolveError::InvalidPe("section table overflow"))?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = section_table
            .checked_add(index * 40)
            .ok_or(ResolveError::InvalidPe("section offset overflow"))?;
        let virtual_size = read_u32(image, offset + 8)
            .ok_or(ResolveError::InvalidPe("section table is truncated"))?;
        let start = read_u32(image, offset + 12)
            .ok_or(ResolveError::InvalidPe("section table is truncated"))?;
        let raw_size = read_u32(image, offset + 16)
            .ok_or(ResolveError::InvalidPe("section table is truncated"))?;
        let characteristics = read_u32(image, offset + 36)
            .ok_or(ResolveError::InvalidPe("section table is truncated"))?;
        let end = start.saturating_add(virtual_size.max(raw_size));
        if start < end && (end as usize) <= declared_size {
            sections.push(PeSection {
                start,
                end,
                executable: characteristics & 0x2000_0000 != 0,
            });
        }
    }
    if !sections.iter().any(|section| section.executable) {
        return Err(ResolveError::InvalidPe("image has no executable section"));
    }
    Ok(sections)
}

fn find_complete_object_locators(image: &[u8], type_descriptor_rva: u32) -> Vec<(u32, u32)> {
    let mut result = Vec::new();
    let limit = image.len().saturating_sub(COMPLETE_OBJECT_LOCATOR_SIZE);
    // `pTypeDescriptor` is the only field of a locator that is specific to this
    // class, so it decides candidacy; the remaining fields merely confirm.
    for (index, word) in image.chunks_exact(4).enumerate() {
        if u32::from_le_bytes(word.try_into().unwrap_or_default()) != type_descriptor_rva {
            continue;
        }
        let field = index * 4;
        if field < 12 {
            continue;
        }
        let offset = field - 12;
        if offset >= limit {
            continue;
        }
        let Some(locator_rva) = u32::try_from(offset).ok() else {
            break;
        };
        if read_u32(image, offset) != Some(1)
            || read_u32(image, offset + 8) != Some(0)
            || read_u32(image, offset + 20) != Some(locator_rva)
        {
            continue;
        }
        let Some(object_offset) = read_u32(image, offset + 4) else {
            continue;
        };
        let Some(class_descriptor) = read_u32(image, offset + 16) else {
            continue;
        };
        if object_offset <= MAX_SECONDARY_OFFSET
            && (class_descriptor as usize) < image.len()
            && !result.contains(&(locator_rva, object_offset))
        {
            result.push((locator_rva, object_offset));
        }
    }
    result
}

fn unique_vtable(
    candidates: &[VtableCandidate],
    object_offset: u32,
    kind: &'static str,
) -> Result<VtableCandidate, ResolveError> {
    let matches: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.object_offset == object_offset)
        .collect();
    if matches.len() == 1 {
        Ok(matches[0])
    } else {
        Err(ResolveError::VtableNotUnique(kind))
    }
}

fn vtable_has_executable_entry(
    module_base: usize,
    image: &[u8],
    sections: &[PeSection],
    vtable_rva: u32,
) -> bool {
    read_u64(image, vtable_rva as usize)
        .and_then(|pointer| pointer.checked_sub(module_base as u64))
        .and_then(|rva| u32::try_from(rva).ok())
        .is_some_and(|rva| rva_is_executable(sections, rva))
}

fn rva_is_executable(sections: &[PeSection], rva: u32) -> bool {
    sections
        .iter()
        .any(|section| section.executable && section.start <= rva && rva < section.end)
}

fn executable_end(sections: &[PeSection], rva: u32) -> Option<u32> {
    sections
        .iter()
        .find(|section| section.executable && section.start <= rva && rva < section.end)
        .map(|section| section.end)
}

fn analyze_scheduler_method(
    module_base: usize,
    image: &[u8],
    sections: &[PeSection],
    method_rva: u32,
) -> Option<SchedulerFields> {
    let section_end = executable_end(sections, method_rva)? as usize;
    let start = method_rva as usize;
    let end = section_end
        .min(start.checked_add(MAX_METHOD_BYTES)?)
        .min(image.len());
    if start >= end {
        return None;
    }
    let mut decoder = Decoder::with_ip(
        64,
        &image[start..end],
        (module_base as u64).checked_add(method_rva as u64)?,
        DecoderOptions::NONE,
    );
    let mut instructions = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        let terminal = instruction.mnemonic() == Mnemonic::Ret;
        instructions.push(instruction);
        if terminal {
            break;
        }
    }

    let mut matches = Vec::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let Some((base, counter)) = incremented_memory(instruction) else {
            continue;
        };
        if base == Register::None || counter > MAX_FIELD_OFFSET {
            continue;
        }
        let following_end = (index + 9).min(instructions.len());
        for store in &instructions[index + 1..following_end] {
            let Some((store_base, deadline)) = movsd_store(store) else {
                continue;
            };
            if store_base != base || deadline > MAX_FIELD_OFFSET || deadline % 8 != 0 {
                continue;
            }
            let previous_start = index.saturating_sub(48);
            let loaded_before = instructions[previous_start..index]
                .iter()
                .any(|candidate| movsd_load(candidate) == Some((base, deadline)));
            if !loaded_before {
                continue;
            }
            let Ok(deadline) = u32::try_from(deadline) else {
                continue;
            };
            let Ok(counter) = u32::try_from(counter) else {
                continue;
            };
            let fields = SchedulerFields {
                deadline_from_secondary: deadline,
                counter_from_secondary: counter,
            };
            if !matches.contains(&fields) {
                matches.push(fields);
            }
        }
    }
    if matches.len() == 1 {
        matches.first().copied()
    } else {
        None
    }
}

fn incremented_memory(instruction: &Instruction) -> Option<(Register, u64)> {
    let is_increment = instruction.mnemonic() == Mnemonic::Inc
        || (instruction.mnemonic() == Mnemonic::Add
            && instruction.op_count() >= 2
            && matches!(
                instruction.op1_kind(),
                OpKind::Immediate8
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64
            )
            && instruction.immediate(1) == 1);
    if !is_increment || instruction.op0_kind() != OpKind::Memory {
        return None;
    }
    simple_memory(instruction)
}

fn movsd_load(instruction: &Instruction) -> Option<(Register, u64)> {
    if instruction.mnemonic() == Mnemonic::Movsd
        && instruction.op0_kind() == OpKind::Register
        && instruction.op1_kind() == OpKind::Memory
    {
        simple_memory(instruction)
    } else {
        None
    }
}

fn movsd_store(instruction: &Instruction) -> Option<(Register, u64)> {
    if instruction.mnemonic() == Mnemonic::Movsd
        && instruction.op0_kind() == OpKind::Memory
        && instruction.op1_kind() == OpKind::Register
    {
        simple_memory(instruction)
    } else {
        None
    }
}

fn simple_memory(instruction: &Instruction) -> Option<(Register, u64)> {
    (instruction.memory_index() == Register::None && !instruction.is_ip_rel_memory_operand())
        .then_some((
            instruction.memory_base(),
            instruction.memory_displacement64(),
        ))
}

/// Calls `on_hit` with the offset of every occurrence of `needle` in `haystack`.
///
/// Endian-independent: `from_le_bytes` places `chunk[i]` in bit lane `8 * i`, so
/// `trailing_zeros() / 8` is the correct lane index on any host. This crate is
/// not Windows-gated, so do not switch to `from_ne_bytes`.
#[inline]
fn for_each_byte(haystack: &[u8], needle: u8, mut on_hit: impl FnMut(usize)) {
    let broadcast = u64::from_le_bytes([needle; 8]);
    let mut base = 0usize;
    let mut chunks = haystack.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap_or_default()) ^ broadcast;
        let mut mask = word.wrapping_sub(0x0101_0101_0101_0101) & !word & 0x8080_8080_8080_8080;
        while mask != 0 {
            let lane = (mask.trailing_zeros() / 8) as usize;
            // The borrow taken by a matching lane propagates into the next one,
            // so a lane holding exactly `needle ^ 1` is flagged without being a
            // match. The mask never misses a real match, so re-testing the byte
            // is what makes it exact - and this must be exact, because a hit
            // whose first byte was never compared could otherwise be reported
            // as the unique occurrence.
            if chunk[lane] == needle {
                on_hit(base + lane);
            }
            mask &= mask - 1;
        }
        base += 8;
    }
    for (index, &byte) in chunks.remainder().iter().enumerate() {
        if byte == needle {
            on_hit(base + index);
        }
    }
}

/// Counts every occurrence of `needle`, returning `Err(count)` unless there is
/// exactly one.
///
/// Resolution is fail-closed: an RTTI name that appears more than once must
/// never silently resolve to whichever copy was seen first, so this deliberately
/// has no early exit.
fn find_unique(haystack: &[u8], needle: &[u8]) -> Result<usize, usize> {
    let Some((&first, rest)) = needle.split_first() else {
        return Err(0);
    };
    if haystack.len() < needle.len() {
        return Err(0);
    }
    let limit = haystack.len() - needle.len();
    let mut count = 0usize;
    let mut found = 0usize;
    for_each_byte(haystack, first, |offset| {
        if offset <= limit && haystack[offset + 1..offset + needle.len()] == *rest {
            if count == 0 {
                found = offset;
            }
            count += 1;
        }
    });
    if count == 1 { Ok(found) } else { Err(count) }
}

fn find_u64(haystack: &[u8], value: u64) -> Vec<usize> {
    let bytes = value.to_le_bytes();
    (0..haystack.len().saturating_sub(7))
        .step_by(8)
        .filter(|&offset| haystack[offset..offset + 8] == bytes)
        .collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod scan_tests {
    use super::{SCAN_PAGE_SIZE, next_scan_start};

    #[test]
    fn a_complete_read_overlaps_into_the_next_chunk() {
        assert_eq!(next_scan_start(0x10000, 0x20000, 0x40000, 0x10000, 15), Some(0x20000 - 15));
    }

    #[test]
    fn a_complete_read_of_the_last_chunk_ends_the_region() {
        assert_eq!(next_scan_start(0x30000, 0x40000, 0x40000, 0x10000, 15), None);
    }

    #[test]
    fn a_short_read_resumes_after_the_unreadable_page_instead_of_skipping_the_chunk() {
        let start = 0x10000;
        let transferred = 3 * SCAN_PAGE_SIZE;
        assert_eq!(
            next_scan_start(start, 0x20000, 0x40000, transferred, 15),
            Some(start + transferred + SCAN_PAGE_SIZE)
        );
    }

    #[test]
    fn a_failed_read_steps_one_page() {
        assert_eq!(next_scan_start(0x10000, 0x20000, 0x40000, 0, 15), Some(0x11000));
    }

    #[test]
    fn a_short_read_near_the_region_end_finishes() {
        assert_eq!(next_scan_start(0x3F000, 0x40000, 0x40000, 0, 15), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BASE: usize = 0x0001_8000_0000;

    fn put_u16(image: &mut [u8], offset: usize, value: u16) {
        image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(image: &mut [u8], offset: usize, value: u32) {
        image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(image: &mut [u8], offset: usize, value: u64) {
        image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn synthetic_loaded_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x5000];
        put_u16(&mut image, 0, 0x5a4d);
        put_u32(&mut image, 0x3c, 0x80);
        put_u32(&mut image, 0x80, 0x0000_4550);
        put_u16(&mut image, 0x86, 2);
        put_u16(&mut image, 0x94, 0xf0);
        put_u16(&mut image, 0x98, 0x20b);
        put_u32(&mut image, 0x98 + 56, 0x5000);

        let section_table = 0x188;
        put_u32(&mut image, section_table + 8, 0x1000);
        put_u32(&mut image, section_table + 12, 0x1000);
        put_u32(&mut image, section_table + 16, 0x1000);
        put_u32(&mut image, section_table + 36, 0x6000_0020);
        put_u32(&mut image, section_table + 40 + 8, 0x2000);
        put_u32(&mut image, section_table + 40 + 12, 0x2000);
        put_u32(&mut image, section_table + 40 + 16, 0x2000);
        put_u32(&mut image, section_table + 40 + 36, 0x4000_0040);

        let type_descriptor = 0x2ff0;
        image[type_descriptor + TYPE_DESCRIPTOR_NAME_OFFSET
            ..type_descriptor + TYPE_DESCRIPTOR_NAME_OFFSET + HID_THREAD_RTTI_NAME.len()]
            .copy_from_slice(HID_THREAD_RTTI_NAME);
        for (locator, object_offset) in [(0x2100, 0), (0x2120, 8)] {
            put_u32(&mut image, locator, 1);
            put_u32(&mut image, locator + 4, object_offset);
            put_u32(&mut image, locator + 12, type_descriptor as u32);
            put_u32(&mut image, locator + 16, 0x2200);
            put_u32(&mut image, locator + 20, locator as u32);
        }
        put_u64(&mut image, 0x2300, (TEST_BASE + 0x2100) as u64);
        put_u64(&mut image, 0x2308, (TEST_BASE + 0x1100) as u64);
        image[0x1100] = 0xc3;

        put_u64(&mut image, 0x2400, (TEST_BASE + 0x2120) as u64);
        put_u64(&mut image, 0x2408, (TEST_BASE + 0x1200) as u64);
        put_u64(&mut image, 0x2410, (TEST_BASE + 0x1210) as u64);
        put_u64(&mut image, 0x2418, (TEST_BASE + 0x1300) as u64);
        image[0x1200] = 0xc3;
        image[0x1210] = 0xc3;
        let scheduler = [
            0xf2, 0x41, 0x0f, 0x10, 0x87, 0x80, 0x00, 0x00, 0x00, 0x90, 0x90, 0x41, 0xff, 0x87,
            0xa0, 0x00, 0x00, 0x00, 0xf2, 0x41, 0x0f, 0x11, 0x87, 0x80, 0x00, 0x00, 0x00, 0xc3,
        ];
        image[0x1300..0x1300 + scheduler.len()].copy_from_slice(&scheduler);
        image
    }

    #[test]
    fn complete_layout_is_resolved_without_build_offsets() {
        assert_eq!(
            resolve_recovery_layout(TEST_BASE, &synthetic_loaded_image()).unwrap(),
            RecoveryLayout {
                primary_vtable_rva: 0x2308,
                secondary_vtable_rva: 0x2408,
                secondary_object_offset: 8,
                worker_method_rva: 0x1300,
                discovery_deadline_offset: 0x88,
                discovery_counter_offset: 0xa8,
            }
        );
    }

    #[test]
    fn scheduler_fields_are_derived_from_instruction_semantics() {
        // movsd xmm0,[r15+80h]; inc dword ptr [r15+0A0h];
        // movsd [r15+80h],xmm0; ret. The unrelated NOPs stand in for the
        // comparisons and branches that occur between these operations.
        let bytes = [
            0xf2, 0x41, 0x0f, 0x10, 0x87, 0x80, 0x00, 0x00, 0x00, 0x90, 0x90, 0x41, 0xff, 0x87,
            0xa0, 0x00, 0x00, 0x00, 0xf2, 0x41, 0x0f, 0x11, 0x87, 0x80, 0x00, 0x00, 0x00, 0xc3,
        ];
        let mut image = vec![0; 0x2000];
        image[0x1000..0x1000 + bytes.len()].copy_from_slice(&bytes);
        let sections = [PeSection {
            start: 0x1000,
            end: 0x1100,
            executable: true,
        }];
        assert_eq!(
            analyze_scheduler_method(TEST_BASE, &image, &sections, 0x1000),
            Some(SchedulerFields {
                deadline_from_secondary: 0x80,
                counter_from_secondary: 0xa0,
            })
        );
    }

    #[test]
    fn ambiguous_names_are_rejected() {
        assert_eq!(find_unique(b"abc abc", b"abc"), Err(2));
    }

    fn vtable_pair_window() -> Vec<u8> {
        // Object 16 bytes into the window: primary at +0, secondary at +24.
        let mut bytes = vec![0u8; 96];
        put_u64(&mut bytes, 16, 0x1111_2222_3333_4440);
        put_u64(&mut bytes, 40, 0x5555_6666_7777_8880);
        bytes
    }

    #[test]
    fn vtable_pairs_are_found_at_their_absolute_address() {
        let bytes = vtable_pair_window();
        assert_eq!(
            find_vtable_pairs(&bytes, 0x4000, 0x1111_2222_3333_4440, 0x5555_6666_7777_8880, 24),
            vec![0x4010]
        );
    }

    #[test]
    fn vtable_pairs_require_both_halves() {
        let bytes = vtable_pair_window();
        assert!(
            find_vtable_pairs(&bytes, 0x4000, 0x1111_2222_3333_4440, 0xdead_beef_dead_beef, 24)
                .is_empty()
        );
    }

    #[test]
    fn vtable_pairs_skip_misaligned_addresses() {
        // The same bytes read from an address 4 modulo 8 place the primary word
        // at a misaligned address, which cannot begin a C++ object.
        let bytes = vtable_pair_window();
        assert!(
            find_vtable_pairs(&bytes, 0x4004, 0x1111_2222_3333_4440, 0x5555_6666_7777_8880, 24)
                .is_empty()
        );
    }

    #[test]
    fn vtable_pairs_reject_a_window_shorter_than_the_pair() {
        let bytes = vec![0u8; 16];
        assert!(find_vtable_pairs(&bytes, 0x4000, 0x1111, 0x2222, 24).is_empty());
    }

    #[test]
    fn vtable_pairs_reject_a_null_primary_over_zeroed_memory() {
        // Without the guard every 8-aligned word of this page would match.
        let bytes = vec![0u8; 4096];
        assert!(find_vtable_pairs(&bytes, 0x4000, 0, 0, 24).is_empty());
    }

    fn sample(deadline: f64, counter: u32) -> SchedulerSample {
        SchedulerSample {
            deadline_bits: deadline.to_bits(),
            counter,
        }
    }

    #[test]
    fn the_only_candidate_that_reschedules_discovery_is_selected() {
        let before = [sample(1000.0, 7), sample(940.0, 5)];
        let after = [sample(1000.0, 7), sample(1200.0, 5)];
        assert_eq!(select_progressing_candidate(&before, &after), Some(1));
    }

    #[test]
    fn a_moving_counter_alone_identifies_the_live_candidate() {
        let before = [sample(1000.0, 7), sample(940.0, 5)];
        let after = [sample(1000.0, 8), sample(940.0, 5)];
        assert_eq!(select_progressing_candidate(&before, &after), Some(0));
    }

    #[test]
    fn candidates_that_all_stand_still_stay_ambiguous() {
        let before = [sample(1000.0, 7), sample(940.0, 5)];
        assert_eq!(select_progressing_candidate(&before, &before), None);
    }

    #[test]
    fn several_moving_candidates_stay_ambiguous() {
        let before = [sample(1000.0, 7), sample(940.0, 5)];
        let after = [sample(1100.0, 7), sample(1200.0, 5)];
        assert_eq!(select_progressing_candidate(&before, &after), None);
    }

    #[test]
    fn a_deadline_holding_nan_in_both_observations_is_not_movement() {
        // f64 equality would call this a change and elect a dead candidate.
        let before = [sample(f64::NAN, 1), sample(500.0, 1)];
        let after = [sample(f64::NAN, 1), sample(600.0, 1)];
        assert_eq!(select_progressing_candidate(&before, &after), Some(1));
    }

    #[test]
    fn the_election_ends_at_the_first_observation_with_one_moving_candidate() {
        let mut observations = [
            vec![sample(1000.0, 7), sample(940.0, 5)],
            vec![sample(1000.0, 7), sample(1200.0, 5)],
        ]
        .into_iter();
        let mut nudged = false;
        let outcome = elect_progressing_candidate(|| observations.next(), || nudged = true);
        assert_eq!(outcome, Election::Elected(1));
        assert!(nudged);
    }

    #[test]
    fn an_unreadable_first_observation_abandons_the_election_before_the_nudge() {
        let mut nudged = false;
        let outcome = elect_progressing_candidate(|| None, || nudged = true);
        assert_eq!(outcome, Election::Unreadable);
        assert!(!nudged);
    }

    #[test]
    fn a_candidate_that_becomes_unreadable_abandons_the_election() {
        let mut observations = [vec![sample(1000.0, 7), sample(940.0, 5)]].into_iter();
        let outcome = elect_progressing_candidate(|| observations.next(), || {});
        assert_eq!(outcome, Election::Unreadable);
    }

    #[test]
    fn only_committed_accessible_regions_are_readable() {
        const PAGE_READWRITE: u32 = 0x04;
        const MEM_RESERVE: u32 = 0x2000;
        assert!(memory_is_readable(MEM_COMMIT, PAGE_READWRITE));
        assert!(!memory_is_readable(MEM_RESERVE, PAGE_READWRITE));
        assert!(!memory_is_readable(MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD));
        assert!(!memory_is_readable(MEM_COMMIT, PAGE_NOACCESS));
    }

    #[test]
    fn mismatched_or_empty_observations_are_rejected() {
        let before = [sample(1000.0, 7)];
        assert_eq!(select_progressing_candidate(&before, &[]), None);
        assert_eq!(select_progressing_candidate(&[], &[]), None);
    }

    #[test]
    fn find_unique_counts_occurrences() {
        assert_eq!(find_unique(b"xxabcxx", b"abc"), Ok(2));
        assert_eq!(find_unique(b"xxxxxxx", b"abc"), Err(0));
        assert_eq!(find_unique(b"abc abc abc", b"abc"), Err(3));
        assert_eq!(find_unique(b"ab", b"abc"), Err(0));
        assert_eq!(find_unique(b"", b"abc"), Err(0));
        assert_eq!(find_unique(b"abc", b"abc"), Ok(0));
    }

    #[test]
    fn find_unique_matches_at_both_extremes() {
        let mut haystack = vec![b'.'; 64];
        haystack[0..3].copy_from_slice(b"abc");
        assert_eq!(find_unique(&haystack, b"abc"), Ok(0));

        let mut haystack = vec![b'.'; 64];
        haystack[61..64].copy_from_slice(b"abc");
        assert_eq!(find_unique(&haystack, b"abc"), Ok(61));
    }

    #[test]
    fn find_unique_rejects_a_trailing_needle_prefix() {
        let mut haystack = vec![b'.'; 64];
        haystack[62..64].copy_from_slice(b"ab");
        assert_eq!(find_unique(&haystack, b"abc"), Err(0));
    }

    #[test]
    fn find_unique_rejects_first_byte_hits_that_do_not_match() {
        // Every position carries the needle's first byte, so the whole scan
        // reaches the comparison and only one position may survive it.
        let mut haystack = vec![b'a'; 1024];
        haystack[500..503].copy_from_slice(b"abc");
        assert_eq!(find_unique(&haystack, b"abc"), Ok(500));
    }

    #[test]
    fn find_unique_rejects_a_borrow_flagged_lane() {
        // 'c' is 'b' ^ 1, so the lane after a matching 'b' is flagged by the
        // word-at-a-time search without holding the needle's first byte. If
        // that flag were trusted, the trailing "aa" would make this resolve to
        // offset 7, where no needle begins.
        assert_eq!(find_unique(b"xxxxxxbcaa", b"baa"), Err(0));
        assert_eq!(find_unique(b"xxxxxbccaa", b"baa"), Err(0));
    }

    #[test]
    fn find_unique_spans_chunk_boundaries_and_the_tail() {
        for start in 0..16usize {
            let mut haystack = vec![b'.'; 45];
            haystack[start..start + 5].copy_from_slice(b"abcde");
            assert_eq!(find_unique(&haystack, b"abcde"), Ok(start));
        }
        let mut haystack = vec![b'.'; 45];
        haystack[40..45].copy_from_slice(b"abcde");
        assert_eq!(find_unique(&haystack, b"abcde"), Ok(40));
    }

    #[test]
    fn complete_object_locators_are_found_in_ascending_order() {
        let image = synthetic_loaded_image();
        assert_eq!(
            find_complete_object_locators(&image, 0x2ff0),
            vec![(0x2100, 0), (0x2120, 8)]
        );
    }
}
