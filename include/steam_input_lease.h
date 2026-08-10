/**
 * @file steam_input_lease.h
 * @brief Stable C ABI for the Steam Input Lease Rust library.
 *
 * All strings are NUL-terminated UTF-16 strings using Windows code units.
 * Client and lease handles are opaque and must be consumed by the matching
 * destroy/release functions. Fallible functions return SIL_OK on success and
 * preserve a thread-local UTF-8 message retrievable through
 * sil_last_error_message() on failure.
 */

#ifndef STEAM_INPUT_LEASE_H
#define STEAM_INPUT_LEASE_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define SIL_API __declspec(dllimport)
#else
#define SIL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Operation completed successfully. */
#define SIL_OK 0
/** A validated native operation failed; inspect sil_last_error_message(). */
#define SIL_ERROR 1
/** The ABI boundary caught an unexpected Rust panic. */
#define SIL_PANIC 2

/** Payload performs guarded internal recovery after the final lease. */
#define SIL_CAPABILITY_INTERNAL_RECOVERY (1u << 0)

/** Opaque reusable client configuration handle. */
typedef struct SilClient SilClient;
/** Opaque uniquely owned active lease handle. */
typedef struct SilLease SilLease;

/** Options passed to sil_client_create(). */
typedef struct SilClientOptions {
    /** Target executable name, or NULL to use "steam.exe". */
    const uint16_t* target_name;
    /** Payload DLL path, or NULL to use the executable-directory default. */
    const uint16_t* payload_path;
    /** Pipe startup timeout in milliseconds, or zero for the default. */
    uint32_t connect_timeout_ms;
} SilClientOptions;

/** Process-global payload status snapshot. */
typedef struct SilStatus {
    /** SIL_CAPABILITY_* bitset. */
    uint16_t capabilities;
    /** Reserved for future ABI-compatible extension; currently zero. */
    uint16_t reserved;
    /** Number of active block leases. */
    uint32_t lease_count;
    /** Number of HID handles known to the payload. */
    uint32_t hid_handle_count;
    /** Handles closed during the most recent blocking transition. */
    uint32_t last_revoked_handle_count;
} SilStatus;

/** Diagnostics from guarded two-pass Steam controller discovery. */
typedef struct SilRescanResult {
    /** Deadline observed before the first discovery request. */
    double previous_deadline;
    /** Discovery counter before the first request. */
    uint32_t scan_count_before;
    /** Discovery counter after the second request. */
    uint32_t scan_count_after;
} SilRescanResult;

/** Controller recovery did not apply: the target is not Steam. */
#define SIL_RECOVERY_NOT_REQUIRED 0u
/** The payload scheduled discovery on its own timer. */
#define SIL_RECOVERY_SCHEDULED 1u
/** The host ran guarded two-pass recovery inline; rescan is populated. */
#define SIL_RECOVERY_COMPLETED 2u
/** Recovery could not run; recovery_message explains why. Blocking was still
 *  lifted, so the release itself succeeded. */
#define SIL_RECOVERY_UNAVAILABLE 3u

/** Bytes reserved for the UTF-8 recovery message, including its terminator. */
#define SIL_RECOVERY_MESSAGE_CAPACITY 256

/**
 * Outcome of sil_lease_release(). SIL_OK means blocking was lifted; `recovery`
 * separately reports whether Steam was also asked to rediscover controllers,
 * so a released-but-unrecovered lease is distinguishable from a failed release.
 */
typedef struct SilReleaseOutcome {
    /** Payload status captured by the release handshake. */
    SilStatus status;
    /** One of the SIL_RECOVERY_* constants. */
    uint32_t recovery;
    /** Reserved for future ABI-compatible extension; currently zero. */
    uint32_t reserved;
    /** Populated only when recovery == SIL_RECOVERY_COMPLETED. */
    SilRescanResult rescan;
    /** NUL-terminated UTF-8 reason; empty unless recovery is
     *  SIL_RECOVERY_UNAVAILABLE. Carried here rather than through
     *  sil_last_error_message(), which reports failed calls only. */
    char recovery_message[SIL_RECOVERY_MESSAGE_CAPACITY];
} SilReleaseOutcome;

/**
 * @return The C ABI version, currently 2.
 *
 * Version 2 changed sil_lease_release() to report a SilReleaseOutcome instead
 * of a bare SilStatus, so a recovery failure no longer presents a released
 * lease as a failed one.
 */
SIL_API uint32_t sil_abi_version(void);

/**
 * Returns the calling thread's latest NUL-terminated UTF-8 error message.
 * The borrowed pointer remains valid until the next ABI call on that thread;
 * it must not be modified or freed.
 */
SIL_API const char* sil_last_error_message(void);

/**
 * Creates a reusable client. @p options may be NULL to use every default.
 * On success, @p output receives a handle owned by the caller.
 */
SIL_API int32_t sil_client_create(
    const SilClientOptions* options,
    SilClient** output);

/** Destroys @p client. Passing NULL is allowed. */
SIL_API void sil_client_destroy(SilClient* client);

/** Loads the payload when necessary and writes its current status. */
SIL_API int32_t sil_client_ensure_payload(
    SilClient* client,
    SilStatus* status);

/** Queries an already loaded payload without injecting. */
SIL_API int32_t sil_client_status(
    SilClient* client,
    SilStatus* status);

/**
 * Acquires one block lease. On success, @p lease must be consumed exactly once
 * by sil_lease_release() or sil_lease_destroy().
 */
SIL_API int32_t sil_client_acquire(
    SilClient* client,
    SilLease** lease,
    SilStatus* status);

/**
 * Explicitly releases and consumes @p lease, waits for the payload's release
 * and recovery-scheduling response, and writes @p outcome. The lease is
 * consumed even if this function returns an error.
 */
SIL_API int32_t sil_lease_release(
    SilLease* lease,
    SilReleaseOutcome* outcome);

/**
 * Crash-safe release that consumes @p lease by closing its pipe. Passing NULL
 * is allowed. No synchronous recovery status is returned.
 */
SIL_API void sil_lease_destroy(SilLease* lease);

/** Runs guarded two-pass Steam discovery without changing the lease count. */
SIL_API int32_t sil_client_rescan(
    SilClient* client,
    SilRescanResult* result);

/**
 * Validates the host-side dynamic Steam recovery resolver without changing
 * leases or writing into the target process.
 */
SIL_API int32_t sil_client_check_recovery(SilClient* client);

/**
 * Adds a Steam library folder to the live client, injecting the payload if
 * needed. The payload calls the client's own AddLibraryFolder in-process, so
 * Steam adopts, persists, mounts and scans the folder with no restart. `path`
 * is a NUL-terminated UTF-16 folder path (e.g. L"E:\\SteamLibrary"). Returns
 * SIL_OK on success; the reason is in sil_last_error_message() on failure.
 */
SIL_API int32_t sil_client_add_library(SilClient* client, const uint16_t* path);

/**
 * Runs an executable/argument vector under a lease, waits for its Windows job
 * process tree, releases the lease, then writes the root process exit code.
 */
SIL_API int32_t sil_client_run_wrapped(
    SilClient* client,
    size_t argc,
    const uint16_t* const* argv,
    uint32_t* exit_code);

/*
 * The ABI intentionally has no detach/unload call. The injected payload is
 * pinned for hook/thread safety and remains mapped in pass-through mode after
 * the final lease.
 */

#ifdef __cplusplus
}
#endif

#endif
