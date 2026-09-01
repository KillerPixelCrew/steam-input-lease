using System;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace SteamInterop;

internal static class NativeMethods
{
    // The native library exposes only cdecl functions, opaque handles, and
    // fixed-width sequential structs. No Rust or managed object layout crosses
    // this boundary.
    private const string Library = "steam_input_lease_ffi";
    internal const uint ExpectedAbiVersion = 4;
    private static int _abiValidated;

    [StructLayout(LayoutKind.Sequential)]
    internal struct ClientOptions
    {
        internal nint TargetName;
        internal nint PayloadPath;
        internal uint ConnectTimeoutMilliseconds;

        // ABI 4. Non-zero lets the client inject the payload when no resident
        // one answers; zero restricts it to a payload Steam loaded itself from
        // its own directory. WSGM leaves this zero everywhere, so its own
        // surfaces cannot write into the Steam process at all.
        internal uint AllowInjection;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Status
    {
        internal ushort Capabilities;
        internal ushort Reserved;
        internal uint LeaseCount;
        internal uint HidHandleCount;
        internal uint LastRevokedHandleCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct RescanResult
    {
        internal double PreviousDeadline;
        internal uint ScanCountBefore;
        internal uint ScanCountAfter;
    }

    internal const int RecoveryMessageCapacity = 256;

    // Blittable by design: the inline UTF-8 message is a fixed byte array, so
    // this struct needs no custom marshaller at the native boundary.
    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct ReleaseOutcome
    {
        internal Status Status;
        internal uint Recovery;
        internal uint Reserved;
        internal RescanResult Rescan;
        internal fixed byte RecoveryMessage[RecoveryMessageCapacity];
    }

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern uint sil_abi_version();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern nint sil_last_error_message();

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_client_create(in ClientOptions options, out nint client);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void sil_client_destroy(nint client);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_client_ensure_payload(ClientHandle client, out Status status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_client_status(ClientHandle client, out Status status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_client_acquire(ClientHandle client, out nint lease, out Status status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_lease_release(nint lease, out ReleaseOutcome outcome);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void sil_lease_destroy(nint lease);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_client_rescan(ClientHandle client, out RescanResult result);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_client_check_recovery(ClientHandle client);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int sil_client_run_wrapped(
        ClientHandle client,
        nuint argumentCount,
        nint arguments,
        out uint exitCode,
        out ReleaseOutcome release);

    internal static void ThrowIfFailed(int result)
    {
        if (result == 0)
        {
            return;
        }

        string message = Marshal.PtrToStringUTF8(sil_last_error_message())
            ?? "The native Steam Input Lease operation failed.";
        throw new SteamInputLeaseException(message, result);
    }

    internal static void EnsureCompatibleAbi()
    {
        if (Volatile.Read(ref _abiValidated) != 0)
        {
            return;
        }

        // This MUST be the first native operation made by a managed client. A
        // different ABI may use different struct sizes, so even asking it for
        // an error string or creating a client would already be unsafe.
        uint actual = sil_abi_version();
        if (actual != ExpectedAbiVersion)
        {
            throw new NotSupportedException(
                $"Steam Input Lease ABI {actual} is incompatible; this binding requires ABI {ExpectedAbiVersion}.");
        }

        Volatile.Write(ref _abiValidated, 1);
    }
}

internal sealed class ClientHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private ClientHandle() : base(ownsHandle: true) { }

    internal ClientHandle(nint value) : base(ownsHandle: true) => SetHandle(value);

    protected override bool ReleaseHandle()
    {
        NativeMethods.sil_client_destroy(handle);
        return true;
    }
}

internal sealed class LeaseHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal LeaseHandle(nint value) : base(ownsHandle: true) => SetHandle(value);

    internal nint Take()
    {
        // Explicit native release consumes the opaque allocation. Invalidating
        // first prevents SafeHandle finalization from destroying it twice.
        nint value = handle;
        SetHandleAsInvalid();
        return value;
    }

    protected override bool ReleaseHandle()
    {
        NativeMethods.sil_lease_destroy(handle);
        return true;
    }
}
