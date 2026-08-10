using SteamInterop;

var options = new SteamInputClientOptions();
if (Environment.GetEnvironmentVariable("SIL_TARGET_NAME") is { Length: > 0 } targetName)
{
    options = new SteamInputClientOptions
    {
        TargetName = targetName,
        PayloadPath = Environment.GetEnvironmentVariable("SIL_PAYLOAD_PATH")
            ?? Path.Combine(AppContext.BaseDirectory, "steam_input_gate.dll"),
    };
}

using var client = new SteamInputClient(options);

if (args.Length == 0)
{
    SteamInputStatus status = client.EnsurePayload();
    Console.WriteLine($"Payload ready; leases={status.LeaseCount}, HID handles={status.HidHandleCount}");
    return;
}

uint exitCode = client.RunWrapped(args);
Console.WriteLine($"Wrapped process tree exited with code {exitCode}; Steam Input restored.");
Environment.ExitCode = unchecked((int)exitCode);
