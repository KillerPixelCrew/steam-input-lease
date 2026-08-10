using System.Runtime.InteropServices;

namespace SteamInterop;

/// <summary>
/// Loads and controls the process-global Steam Input gate. Instances are cheap;
/// active leases are reference-counted inside Steam.
/// </summary>
public sealed class SteamInputClient : IDisposable
{
    private readonly ClientHandle _handle;

    /// <summary>Creates a client with optional process and payload overrides.</summary>
    /// <param name="options">Options to use, or <see langword="null"/> for defaults.</param>
    /// <exception cref="SteamInputLeaseException">Native client creation failed.</exception>
    /// <exception cref="OverflowException">The timeout cannot be represented in milliseconds.</exception>
    public SteamInputClient(SteamInputClientOptions? options = null)
    {
        options ??= new SteamInputClientOptions();
        nint targetName = Marshal.StringToCoTaskMemUni(options.TargetName);
        nint payloadPath = Marshal.StringToCoTaskMemUni(options.PayloadPath);
        try
        {
            var nativeOptions = new NativeMethods.ClientOptions
            {
                TargetName = targetName,
                PayloadPath = payloadPath,
                ConnectTimeoutMilliseconds = checked((uint)options.ConnectTimeout.TotalMilliseconds),
            };
            NativeMethods.ThrowIfFailed(
                NativeMethods.sil_client_create(in nativeOptions, out nint client));
            _handle = new ClientHandle(client);
        }
        finally
        {
            Marshal.FreeCoTaskMem(targetName);
            Marshal.FreeCoTaskMem(payloadPath);
        }
    }

    /// <summary>Loads the payload when necessary and returns its current status.</summary>
    /// <returns>The process-global status after the payload is available.</returns>
    /// <exception cref="SteamInputLeaseException">Process discovery, injection, or IPC failed.</exception>
    public SteamInputStatus EnsurePayload()
    {
        NativeMethods.ThrowIfFailed(
            NativeMethods.sil_client_ensure_payload(_handle, out var status));
        return SteamInputStatus.FromNative(status);
    }

    /// <summary>Queries an already loaded payload without injecting.</summary>
    /// <returns>The process-global status.</returns>
    /// <exception cref="SteamInputLeaseException">The target or payload pipe is unavailable.</exception>
    public SteamInputStatus GetStatus()
    {
        NativeMethods.ThrowIfFailed(
            NativeMethods.sil_client_status(_handle, out var status));
        return SteamInputStatus.FromNative(status);
    }

    /// <summary>Acquires one reference-counted, crash-safe block lease.</summary>
    /// <returns>A uniquely owned lease whose pipe lifetime controls blocking.</returns>
    /// <exception cref="SteamInputLeaseException">Injection or lease acquisition failed.</exception>
    public SteamInputBlockLease Acquire()
    {
        NativeMethods.ThrowIfFailed(
            NativeMethods.sil_client_acquire(_handle, out nint lease, out var status));
        return new SteamInputBlockLease(new LeaseHandle(lease), SteamInputStatus.FromNative(status));
    }

    /// <summary>Runs the guarded two-pass Steam controller discovery.</summary>
    /// <returns>Steam's scan-counter observations around both requests.</returns>
    /// <remarks>This does not change the active lease count.</remarks>
    /// <exception cref="SteamInputLeaseException">The Steam layout is unsupported or remote access failed.</exception>
    public SteamControllerRescanResult Rescan()
    {
        NativeMethods.ThrowIfFailed(
            NativeMethods.sil_client_rescan(_handle, out var result));
        return new SteamControllerRescanResult(
            result.PreviousDeadline,
            result.ScanCountBefore,
            result.ScanCountAfter);
    }

    /// <summary>Validates host-side controller recovery for the current Steam
    /// build without acquiring a lease or changing controller state.</summary>
    /// <exception cref="SteamInputLeaseException">The current Steam build cannot be safely resolved.</exception>
    public void CheckRecovery() => NativeMethods.ThrowIfFailed(
        NativeMethods.sil_client_check_recovery(_handle));

    /// <summary>Adds a Steam library folder to the LIVE client, injecting the
    /// payload if needed: the payload calls the client's own
    /// <c>AddLibraryFolder</c> in-process, so Steam adopts, persists, mounts and
    /// scans the folder with no restart and no config-file editing.</summary>
    /// <param name="path">The library folder, e.g. <c>E:\SteamLibrary</c>.</param>
    /// <exception cref="SteamInputLeaseException">The folder could not be added
    /// (Steam not running, an incompatible Steam build, or a rejected add).</exception>
    public void AddLibraryFolder(string path) => NativeMethods.ThrowIfFailed(
        NativeMethods.sil_client_add_library(_handle, path));

    /// <summary>Runs a process tree while Steam Input is blocked.</summary>
    /// <param name="arguments">Executable followed by its individual arguments.</param>
    /// <returns>The root process exit code after synchronous lease recovery.</returns>
    /// <remarks>
    /// The root process starts suspended, is assigned to a Windows job object,
    /// and is then resumed. Release is attempted even when launch/wait fails.
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="arguments"/> is null.</exception>
    /// <exception cref="ArgumentException">No executable was supplied.</exception>
    /// <exception cref="SteamInputLeaseException">The native lifecycle failed.</exception>
    public uint RunWrapped(params string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        if (arguments.Length == 0)
        {
            throw new ArgumentException("At least one command argument is required.", nameof(arguments));
        }

        nint pointerArray = Marshal.AllocCoTaskMem(arguments.Length * IntPtr.Size);
        var strings = new nint[arguments.Length];
        try
        {
            for (int index = 0; index < arguments.Length; index++)
            {
                strings[index] = Marshal.StringToCoTaskMemUni(arguments[index]);
                Marshal.WriteIntPtr(pointerArray, index * IntPtr.Size, strings[index]);
            }
            NativeMethods.ThrowIfFailed(NativeMethods.sil_client_run_wrapped(
                _handle,
                checked((nuint)arguments.Length),
                pointerArray,
                out uint exitCode));
            return exitCode;
        }
        finally
        {
            foreach (nint value in strings)
            {
                if (value != 0)
                {
                    Marshal.FreeCoTaskMem(value);
                }
            }
            Marshal.FreeCoTaskMem(pointerArray);
        }
    }

    /// <summary>Releases the native client configuration handle.</summary>
    public void Dispose() => _handle.Dispose();
}

/// <summary>
/// Holds one block lease. Call <see cref="Release"/> for a synchronous release
/// and recovery-scheduling handshake; disposal still closes the crash-safe pipe.
/// </summary>
public sealed class SteamInputBlockLease : IDisposable
{
    private LeaseHandle? _handle;

    internal SteamInputBlockLease(LeaseHandle handle, SteamInputStatus initialStatus)
    {
        _handle = handle;
        InitialStatus = initialStatus;
    }

    /// <summary>Gets the status captured immediately after acquiring the lease.</summary>
    public SteamInputStatus InitialStatus { get; }

    /// <summary>Synchronously releases the lease and requests controller recovery.</summary>
    /// <returns>The release status plus what happened to controller recovery.</returns>
    /// <remarks>
    /// This throws only when the release handshake itself fails. Closing the
    /// pipe has already lifted blocking by the time recovery is attempted, so a
    /// recovery failure is reported through
    /// <see cref="SteamInputReleaseOutcome.Recovery"/> rather than as an
    /// exception. The lease is consumed either way.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">The lease was already released or disposed.</exception>
    /// <exception cref="SteamInputLeaseException">The explicit release handshake failed.</exception>
    public SteamInputReleaseOutcome Release()
    {
        LeaseHandle handle = Interlocked.Exchange(ref _handle, null)
            ?? throw new ObjectDisposedException(nameof(SteamInputBlockLease));
        using (handle)
        {
            NativeMethods.ThrowIfFailed(
                NativeMethods.sil_lease_release(handle.Take(), out var outcome));
            return FromNative(outcome);
        }
    }

    private static unsafe SteamInputReleaseOutcome FromNative(NativeMethods.ReleaseOutcome outcome)
    {
        var recovery = (SteamControllerRecovery)outcome.Recovery;
        SteamControllerRescanResult? rescan = recovery == SteamControllerRecovery.Completed
            ? new SteamControllerRescanResult(
                outcome.Rescan.PreviousDeadline,
                outcome.Rescan.ScanCountBefore,
                outcome.Rescan.ScanCountAfter)
            : null;

        string? message = null;
        if (recovery == SteamControllerRecovery.Unavailable)
        {
            var bytes = new ReadOnlySpan<byte>(
                outcome.RecoveryMessage, NativeMethods.RecoveryMessageCapacity);
            int length = bytes.IndexOf((byte)0);
            message = System.Text.Encoding.UTF8.GetString(
                length < 0 ? bytes : bytes[..length]);
        }
        return new SteamInputReleaseOutcome(
            SteamInputStatus.FromNative(outcome.Status), recovery, rescan, message);
    }

    /// <summary>Closes the crash-safe pipe when explicit release was not used.</summary>
    /// <remarks>
    /// The payload treats EOF as release. Unlike <see cref="Release"/>, disposal
    /// cannot return recovery status to the caller.
    /// </remarks>
    public void Dispose() => Interlocked.Exchange(ref _handle, null)?.Dispose();
}
