using System;

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

    /// <summary>Closes the claim without waiting for acknowledgement.</summary>
    public void Dispose()
    {
        ConsumableHandle.Close(ref _handle);
    }

    /// <summary>Ends this claim and restores blocking if leases remain and no other claim overrides them.</summary>
    /// <returns>The remaining payload status.</returns>
    /// <exception cref="ObjectDisposedException">The claim was already released or disposed.</exception>
    /// <exception cref="SteamInputLeaseException">Acknowledgement failed; the claim is consumed regardless.</exception>
    public SteamInputStatus Release()
    {
        return ConsumableHandle.Consume(
            ref _handle,
            nameof(SteamInputPassThrough),
            static claim =>
            {
                NativeMethods.ThrowIfFailed(NativeMethods.sil_pass_through_release(claim, out var status));
                return SteamInputStatus.FromNative(status);
            });
    }
}

internal sealed class PassThroughHandle : ConsumableHandle
{
    internal PassThroughHandle(nint value) : base(value)
    {
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.sil_pass_through_destroy(handle);
        return true;
    }
}
