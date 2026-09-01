using SteamInterop;

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
