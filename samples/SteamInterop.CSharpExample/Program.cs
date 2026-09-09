using SteamInterop;
using System.Diagnostics;

var options = new SteamInputClientOptions();
if (Environment.GetEnvironmentVariable("SIL_TARGET_NAME") is { Length: > 0 } targetName)
{
    // A custom target is an explicit diagnostic/test mode. It opts into
    // injection because such a target cannot have loaded Steam's resident
    // search-order proxy on its own.
    options = new SteamInputClientOptions
    {
        TargetName = targetName,
        PayloadPath = Environment.GetEnvironmentVariable("SIL_PAYLOAD_PATH")
            ?? Path.Combine(AppContext.BaseDirectory, "steam_input_gate.dll"),
        AllowInjection = true,
    };
}

if (args is ["--verify-pass-through"])
{
    string target = Environment.GetEnvironmentVariable("SIL_TEST_TARGET")
        ?? throw new InvalidOperationException("The isolated lifecycle harness is required.");
    if (!string.Equals(Path.GetFileName(target), "steam-input-test-target.exe", StringComparison.OrdinalIgnoreCase))
    {
        throw new InvalidOperationException("Only the isolated test target is allowed.");
    }
    string port = Environment.GetEnvironmentVariable("SIL_TEST_PORT")
        ?? throw new InvalidOperationException("The harness port is required.");
    using var testClient = new SteamInputClient(new SteamInputClientOptions
    {
        TargetName = "steam-input-test-target.exe",
        AllowInjection = false,
    });
    void Probe(bool blocked)
    {
        var deadline = Stopwatch.StartNew();
        while (true)
        {
            var start = new ProcessStartInfo(target) { UseShellExecute = false, CreateNoWindow = true };
            start.ArgumentList.Add("--probe-client");
            start.ArgumentList.Add(port);
            start.ArgumentList.Add(blocked ? "--expect-blocked" : "--expect-open");
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Probe did not start.");
            if (!process.WaitForExit(5000))
            {
                process.Kill();
                throw new InvalidOperationException("Probe timed out.");
            }
            if (process.ExitCode == 0) return;
            if (deadline.Elapsed > TimeSpan.FromSeconds(5)) throw new InvalidOperationException("Controller state did not converge.");
            Thread.Sleep(20);
        }
    }
    using var first = testClient.Acquire();
    using var second = testClient.Acquire();
    Probe(true);
    using var handoff = testClient.AcquirePassThrough();
    if (!handoff.InitialStatus.SupportsPassThrough || !handoff.InitialStatus.IsPassThroughActive
        || handoff.InitialStatus.LeaseCount != 2) throw new InvalidOperationException("Invalid handoff status.");
    Probe(false);
    using var overlapping = testClient.AcquirePassThrough();
    handoff.Release();
    handoff.Dispose();
    Probe(false);
    overlapping.Dispose();
    Probe(true);
    try
    {
        overlapping.Release();
        throw new InvalidOperationException("Disposed claim was released twice.");
    }
    catch (ObjectDisposedException) { }
    first.Release();
    second.Release();
    Probe(false);
    Console.WriteLine("Managed pass-through ownership verified.");
    return;
}

using var client = new SteamInputClient(options);

if (args.Length == 0)
{
    SteamInputStatus status = client.EnsurePayload();
    Console.WriteLine($"Payload ready; leases={status.LeaseCount}, HID handles={status.HidHandleCount}");
    return;
}

SteamInputWrappedRun run = client.RunWrapped(args);
Console.WriteLine(
    $"Wrapped process tree exited with code {run.ExitCode}; recovery={run.Release.Recovery}.");
Environment.ExitCode = unchecked((int)run.ExitCode);
