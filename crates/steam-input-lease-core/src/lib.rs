//! Shared wire protocol between the controller library and injected payload.
//!
//! The protocol intentionally consists only of fixed-width `#[repr(C)]`
//! structures. This keeps the Rust host, Rust payload, archived C++ proof of
//! concept, and C ABI interoperable. Numeric command/result fields are used on
//! the wire so malformed input cannot create an invalid Rust enum discriminant.

#![deny(missing_docs)]

/// Four-byte signature identifying Steam Input Lease requests and responses.
pub const PROTOCOL_MAGIC: u32 = 0x5349_4754; // "SIGT"
/// Current named-pipe protocol version.
pub const PROTOCOL_VERSION: u16 = 1;
/// Response capability indicating guarded internal Steam controller recovery.
pub const CAPABILITY_INTERNAL_RECOVERY: u16 = 1 << 0;

/// Commands accepted by the injected payload's named-pipe server.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Increment the process-global lease count and begin blocking if this is
    /// the first lease.
    AcquireLease = 1,
    /// Read payload state without changing the lease count.
    QueryStatus = 2,
    /// Explicitly release a previously acquired lease connection.
    ReleaseLease = 3,
}

/// Result values returned in [`Response::result`].
///
/// Only states the payload can actually report are listed. A payload whose hook
/// installation fails never serves the pipe at all, so that condition reaches
/// the host as an unavailable pipe rather than as a result code; value `2` stays
/// reserved for it should the payload ever answer in a degraded state.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultCode {
    /// The request completed successfully.
    Ok = 0,
    /// The request header, protocol version, or command was invalid.
    InvalidRequest = 1,
    /// The payload could not install its hooks, so no lease can be granted.
    /// Hooks are installed on the first acquire rather than at load, so this is
    /// the first point at which that failure can be reported.
    HookInstallFailed = 2,
}

/// Fixed-size request header sent from a host client to the payload.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Request {
    /// Must equal [`PROTOCOL_MAGIC`].
    pub magic: u32,
    /// Must equal [`PROTOCOL_VERSION`].
    pub version: u16,
    /// Numeric value of a [`Command`].
    pub command: u16,
}

impl Request {
    /// Constructs a valid request for `command`.
    #[must_use]
    pub const fn new(command: Command) -> Self {
        Self {
            magic: PROTOCOL_MAGIC,
            version: PROTOCOL_VERSION,
            command: command as u16,
        }
    }
}

/// Fixed-size response returned by the injected payload.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Response {
    /// Must equal [`PROTOCOL_MAGIC`].
    pub magic: u32,
    /// Must equal [`PROTOCOL_VERSION`].
    pub version: u16,
    /// Bitset of payload capabilities such as
    /// [`CAPABILITY_INTERNAL_RECOVERY`].
    pub capabilities: u16,
    /// Numeric value of a [`ResultCode`].
    pub result: u32,
    /// Number of currently active block leases in the target process.
    pub lease_count: u32,
    /// Number of HID handles known to the payload's fixed handle table.
    pub hid_handle_count: u32,
    /// HID handles closed when blocking was most recently activated.
    pub last_revoked_handle_count: u32,
}

impl Response {
    /// Returns `true` when the response has a compatible header and successful
    /// result code.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.magic == PROTOCOL_MAGIC
            && self.version == PROTOCOL_VERSION
            && self.result == ResultCode::Ok as u32
    }

    /// Returns whether the payload will run its own two-pass Steam recovery
    /// when the final lease is released.
    #[must_use]
    pub const fn has_internal_recovery(self) -> bool {
        self.capabilities & CAPABILITY_INTERNAL_RECOVERY != 0
    }
}

/// Builds the NUL-terminated Windows named-pipe path for `process_id`.
#[must_use]
pub fn pipe_name(process_id: u32) -> Vec<u16> {
    format!(r"\\.\pipe\SteamInputGate-{process_id}")
        .encode_utf16()
        .chain(Some(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_layout_remains_compatible_with_cpp_poc() {
        assert_eq!(size_of::<Request>(), 8);
        assert_eq!(size_of::<Response>(), 24);
    }

    #[test]
    fn pipe_name_is_nul_terminated() {
        let name = pipe_name(42);
        assert_eq!(name.last(), Some(&0));
        assert_eq!(
            String::from_utf16_lossy(&name[..name.len() - 1]),
            r"\\.\pipe\SteamInputGate-42"
        );
    }
}
