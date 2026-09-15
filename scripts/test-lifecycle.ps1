<#
.SYNOPSIS
Runs the isolated payload injection and lease lifecycle test.

.DESCRIPTION
Builds the workspace, launches the dedicated TCP-controlled test target,
injects the Rust gate into that process, and verifies a fake HID open returns
the normal Windows error before/after a lease and ERROR_NO_SUCH_DEVICE while
blocked. It also checks wrapped-child exit-code propagation and final status.
Steam and real controller devices are never targeted by this script.

.PARAMETER Profile
Cargo profile to build and test: debug or release.
#>
[CmdletBinding()]
param(
    [ValidateSet('debug', 'release')]
    [string]$Profile = 'debug'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$rustTarget = 'x86_64-pc-windows-msvc'
$output = Join-Path $workspace 'target'
if ($Profile -eq 'release') {
    $output = Join-Path $output "$rustTarget\release"
    cargo build --workspace --release --target $rustTarget --manifest-path (Join-Path $workspace 'Cargo.toml')
} else {
    $output = Join-Path $output "$rustTarget\debug"
    cargo build --workspace --target $rustTarget --manifest-path (Join-Path $workspace 'Cargo.toml')
}
if ($LASTEXITCODE -ne 0) {
    throw "Cargo build failed with exit code $LASTEXITCODE"
}

$launcher = Join-Path $output 'steam-input-lease.exe'
$payload = Join-Path $output 'steam_input_gate.dll'
$target = Join-Path $output 'steam-input-test-target.exe'
$port = Get-Random -Minimum 40000 -Maximum 60000
$traceDirectory = Join-Path ([System.IO.Path]::GetTempPath()) `
    "wsgm-steam-input-test-$PID-$([Guid]::NewGuid().ToString('N'))"
$resolvedTraceDirectory = [System.IO.Path]::GetFullPath($traceDirectory)
$resolvedTempDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
if (-not $resolvedTraceDirectory.StartsWith(
        $resolvedTempDirectory,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to create test trace directory outside the system temp directory"
}
New-Item -ItemType Directory -Path $resolvedTraceDirectory | Out-Null
$previousTraceDirectory = $env:WSGM_STEAM_INPUT_TRACE_DIR
$env:WSGM_STEAM_INPUT_TRACE_DIR = $resolvedTraceDirectory
# The server performs CreateFileW inside the injected process when a tiny local
# TCP client asks it to probe the deliberately nonexistent HID-style path.
$targetProcess = $null
try {
    $targetProcess = Start-Process -FilePath $target -ArgumentList '--serve', $port -WindowStyle Hidden -PassThru
    # Poll for readiness instead of assuming a fixed bind time: on a loaded or
    # cold machine a slow listener would otherwise surface as a gate failure and
    # blame the injected payload for a harness race.
    $ready = $false
    for ($attempt = 1; $attempt -le 50; $attempt++) {
        Start-Sleep -Milliseconds 100
        try {
            & $target --probe-client $port --expect-open
        }
        catch {
            # PowerShell 7.4+ turns a non-zero native exit into a terminating
            # error under $ErrorActionPreference = 'Stop'; the retry decides.
            continue
        }
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
    }
    if (-not $ready) {
        throw "Test target did not answer an unblocked probe within 5s (not listening, or the fake HID path was blocked before acquiring a lease)"
    }

    & $launcher --target-name steam-input-test-target.exe --inject --payload $payload -- $target --probe-client $port --expect-blocked
    if ($LASTEXITCODE -ne 0) {
        throw "Rust payload did not gate the fake HID path while leased"
    }

    $previousSilTestTarget = $env:SIL_TEST_TARGET
    $previousSilTestPort = $env:SIL_TEST_PORT
    try {
        $env:SIL_TEST_TARGET = $target
        $env:SIL_TEST_PORT = [string]$port
        cargo test -p steam-input-lease --test pass_through --target $rustTarget `
            --manifest-path (Join-Path $workspace 'Cargo.toml') -- --ignored
        if ($LASTEXITCODE -ne 0) {
            throw "Pass-through ownership lifecycle failed"
        }
        $managedProject = Join-Path $workspace 'samples/SteamInterop.CSharpExample/SteamInterop.CSharpExample.csproj'
        dotnet build $managedProject --configuration Release --warnaserror
        if ($LASTEXITCODE -ne 0) { throw "Managed lifecycle sample build failed" }
        $managedOutput = Join-Path $workspace 'samples/SteamInterop.CSharpExample/bin/Release/net8.0-windows10.0.17763.0'
        Copy-Item -LiteralPath (Join-Path $output 'steam_input_lease_ffi.dll') -Destination $managedOutput -Force
        dotnet (Join-Path $managedOutput 'SteamInterop.CSharpExample.dll') --verify-pass-through
        if ($LASTEXITCODE -ne 0) { throw "Managed pass-through lifecycle failed" }
    } finally {
        $env:SIL_TEST_TARGET = $previousSilTestTarget
        $env:SIL_TEST_PORT = $previousSilTestPort
    }

    & $target --probe-client $port --expect-open
    if ($LASTEXITCODE -ne 0) {
        throw "Fake HID path remained blocked after releasing the lease"
    }

    & $launcher --target-name steam-input-test-target.exe --inject --payload $payload -- $target --child
    if ($LASTEXITCODE -ne 23) {
        throw "Wrapper returned $LASTEXITCODE; expected child exit code 23"
    }

    $previousSdlExclusion = $env:SDL_GAMECONTROLLER_IGNORE_DEVICES
    $previousSteamAppId = $env:SteamAppId
    try {
        $env:SDL_GAMECONTROLLER_IGNORE_DEVICES = '0x28de/0x1205'
        $env:SteamAppId = '1234'
        & $launcher --target-name steam-input-test-target.exe --inject --payload $payload -- `
            "$env:SystemRoot\System32\cmd.exe" /d /c `
            'if defined SDL_GAMECONTROLLER_IGNORE_DEVICES (exit /b 41) else if "%SteamAppId%"=="1234" (exit /b 0) else (exit /b 42)'
        if ($LASTEXITCODE -ne 0) {
            throw "Wrapped child did not receive the expected controller environment: $LASTEXITCODE"
        }
        if ($env:SDL_GAMECONTROLLER_IGNORE_DEVICES -ne '0x28de/0x1205') {
            throw 'Wrapped launch modified the caller controller environment'
        }
    }
    finally {
        $env:SDL_GAMECONTROLLER_IGNORE_DEVICES = $previousSdlExclusion
        $env:SteamAppId = $previousSteamAppId
    }

    # The root exits immediately after spawning a delayed descendant. A wrapper
    # that waits only for the root returns before this marker exists; a real job
    # tree wait returns only after the descendant has written it and exited.
    $descendantMarker = Join-Path $resolvedTraceDirectory 'descendant-completed.txt'
    & $launcher --target-name steam-input-test-target.exe --inject --payload $payload -- `
        $target --child-tree $descendantMarker
    if ($LASTEXITCODE -ne 23) {
        throw "Process-tree wrapper returned $LASTEXITCODE; expected root exit code 23"
    }
    if (-not (Test-Path -LiteralPath $descendantMarker -PathType Leaf)) {
        throw "Wrapper returned before its delayed descendant completed"
    }

    & $launcher --target-name steam-input-test-target.exe --status
    if ($LASTEXITCODE -ne 0) {
        throw "Payload status query returned $LASTEXITCODE"
    }

    # The temp-directory override is deliberately compiled out of shipped
    # release DLLs. Validate the isolated trace only for the debug payload;
    # release still exercises the complete lease/job lifecycle above without
    # reading or deleting the user's real %LOCALAPPDATA% trace.
    if ($Profile -eq 'debug') {
        $trace = Get-ChildItem -LiteralPath $resolvedTraceDirectory `
            -Filter 'steam-input-gate-*.log' | Select-Object -First 1
        if ($null -eq $trace) {
            throw "Injected payload did not produce its isolated startup trace"
        }
        $traceContent = Get-Content -LiteralPath $trace.FullName -Raw
        if ($traceContent -notmatch 'control pipe listening') {
            throw "Startup trace did not reach control-pipe readiness"
        }
    }
} finally {
    if ($null -ne $targetProcess) {
        $targetProcess.Refresh()
        if (-not $targetProcess.HasExited) {
            Stop-Process -Id $targetProcess.Id
        }
        # Bounded: a Stop-Process that could not reach the target (protected or
        # elevated) must not wedge the script in cleanup with no diagnostic.
        if (-not $targetProcess.WaitForExit(5000)) {
            Write-Warning "Test target $($targetProcess.Id) did not exit within 5s after Stop-Process"
        }
    }
    $env:WSGM_STEAM_INPUT_TRACE_DIR = $previousTraceDirectory
    Remove-Item -LiteralPath $resolvedTraceDirectory -Recurse -Force
}
