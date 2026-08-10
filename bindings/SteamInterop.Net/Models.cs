namespace SteamInterop;

/// <summary>Configuration for locating a target process and injected Rust payload.</summary>
/// <remarks>
/// The production defaults target the current-session <c>steam.exe</c> and a
/// payload beside the managed application's executable. Host and target
/// architectures and integrity levels must match.
/// </remarks>
public sealed class SteamInputClientOptions
{
    /// <summary>Gets the executable name of the process receiving the payload.</summary>
    public string TargetName { get; init; } = "steam.exe";

    /// <summary>Gets the path to <c>steam_input_gate.dll</c>.</summary>
    public string PayloadPath { get; init; } = Path.Combine(AppContext.BaseDirectory, "steam_input_gate.dll");

    /// <summary>Gets the maximum control-pipe startup wait after injection.</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(10);
}

/// <summary>A process-wide payload status snapshot.</summary>
/// <param name="Capabilities">Payload capability bitset.</param>
/// <param name="LeaseCount">Number of active block leases.</param>
/// <param name="HidHandleCount">Number of HID handles known to the payload.</param>
/// <param name="LastRevokedHandleCount">Handles closed by the latest block transition.</param>
public readonly record struct SteamInputStatus(
    ushort Capabilities,
    uint LeaseCount,
    uint HidHandleCount,
    uint LastRevokedHandleCount)
{
    /// <summary>Whether the payload supports guarded internal Steam recovery.</summary>
    public bool SupportsInternalRecovery => (Capabilities & 1) != 0;

    internal static SteamInputStatus FromNative(NativeMethods.Status value) => new(
        value.Capabilities,
        value.LeaseCount,
        value.HidHandleCount,
        value.LastRevokedHandleCount);
}

/// <summary>Diagnostics from Steam's guarded two-pass controller discovery.</summary>
/// <param name="PreviousDeadline">Deadline observed before the first request.</param>
/// <param name="ScanCountBefore">Discovery counter before recovery.</param>
/// <param name="ScanCountAfter">Discovery counter after the second request.</param>
public readonly record struct SteamControllerRescanResult(
    double PreviousDeadline,
    uint ScanCountBefore,
    uint ScanCountAfter);

/// <summary>Whether and how Steam was asked to rediscover controllers after a
/// lease was released.</summary>
public enum SteamControllerRecovery
{
    /// <summary>The target is not Steam, so no controller recovery applies.</summary>
    NotRequired = 0,

    /// <summary>The payload scheduled discovery on its own timer. Controllers
    /// reappear shortly after the release returns.</summary>
    Scheduled = 1,

    /// <summary>The host ran the guarded two-pass recovery inline.</summary>
    Completed = 2,

    /// <summary>Recovery could not run. Blocking was still lifted, so Steam
    /// keeps working; it has simply not been told to look for controllers
    /// again, and one may stay missing until Steam notices by itself.</summary>
    Unavailable = 3,
}

/// <summary>Result of an explicit release. Blocking has been lifted whenever
/// this is returned.</summary>
/// <param name="Status">Payload status from the release handshake.</param>
/// <param name="Recovery">Whether and how Steam was asked to rediscover controllers.</param>
/// <param name="Rescan">Scan-counter observations, present only when <paramref name="Recovery"/> is <see cref="SteamControllerRecovery.Completed"/>.</param>
/// <param name="RecoveryMessage">Why recovery could not run, or <see langword="null"/>.</param>
public readonly record struct SteamInputReleaseOutcome(
    SteamInputStatus Status,
    SteamControllerRecovery Recovery,
    SteamControllerRescanResult? Rescan,
    string? RecoveryMessage)
{
    /// <summary>Whether Steam was successfully asked to rediscover controllers.</summary>
    public bool RecoveryRequested =>
        Recovery is SteamControllerRecovery.Scheduled or SteamControllerRecovery.Completed;
}

/// <summary>An error reported by the native Rust library.</summary>
public sealed class SteamInputLeaseException : Exception
{
    /// <summary>Creates an exception from the native ABI result.</summary>
    /// <param name="message">UTF-8 error message copied from the native thread.</param>
    /// <param name="nativeResult">Nonzero native ABI result code.</param>
    public SteamInputLeaseException(string message, int nativeResult)
        : base(message) => NativeResult = nativeResult;

    /// <summary>The nonzero native ABI result code.</summary>
    public int NativeResult { get; }
}
