using System;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace SteamInterop;

/// <summary>A temporary override of block leases, owned by a crash-safe pipe.</summary>
public sealed class SteamInputPassThrough : IDisposable
{
    private PassThroughHandle? _handle;

    internal SteamInputPassThrough(PassThroughHandle handle, SteamInputStatus status)
    {
        _handle = handle;
        InitialStatus = status;
    }

    /// <summary>Gets the status captured when pass-through was granted.</summary>
    public SteamInputStatus InitialStatus { get; }

    /// <summary>Ends this claim and restores blocking if leases remain and no other claim overrides them.</summary>
    /// <returns>The remaining payload status.</returns>
    /// <exception cref="ObjectDisposedException">The claim was already released or disposed.</exception>
    /// <exception cref="SteamInputLeaseException">Acknowledgement failed; the claim is consumed regardless.</exception>
    public SteamInputStatus Release()
    {
        var handle = Interlocked.Exchange(ref _handle, null)
            ?? throw new ObjectDisposedException(nameof(SteamInputPassThrough));
        using (handle)
        {
            NativeMethods.ThrowIfFailed(NativeMethods.sil_pass_through_release(handle.Take(), out var status));
            return SteamInputStatus.FromNative(status);
        }
    }

    /// <summary>Closes the claim without waiting for acknowledgement.</summary>
    public void Dispose() => Interlocked.Exchange(ref _handle, null)?.Dispose();
}

internal sealed class PassThroughHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal PassThroughHandle(nint value) : base(ownsHandle: true) => SetHandle(value);

    internal nint Take()
    {
        nint value = handle;
        SetHandleAsInvalid();
        return value;
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.sil_pass_through_destroy(handle);
        return true;
    }
}
