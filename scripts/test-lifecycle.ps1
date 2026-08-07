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
param(
    [ValidateSet('debug', 'release')]
    [string]$Profile = 'debug'
)

$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$output = Join-Path $workspace 'target'
if ($Profile -eq 'release') {
    $output = Join-Path $output 'release'
    cargo build --workspace --release --manifest-path (Join-Path $workspace 'Cargo.toml')
} else {
    $output = Join-Path $output 'debug'
    cargo build --workspace --manifest-path (Join-Path $workspace 'Cargo.toml')
}
if ($LASTEXITCODE -ne 0) {
    throw "Cargo build failed with exit code $LASTEXITCODE"
}

$launcher = Join-Path $output 'steam-input-lease.exe'
$payload = Join-Path $output 'steam_input_gate.dll'
$target = Join-Path $output 'steam-input-test-target.exe'
$port = Get-Random -Minimum 40000 -Maximum 60000
# The server performs CreateFileW inside the injected process when a tiny local
# TCP client asks it to probe the deliberately nonexistent HID-style path.
$targetProcess = Start-Process -FilePath $target -ArgumentList '--serve', $port -WindowStyle Hidden -PassThru
try {
    Start-Sleep -Milliseconds 300
    & $target --probe-client $port --expect-open
    if ($LASTEXITCODE -ne 0) {
        throw "Fake HID path was unexpectedly blocked before acquiring a lease"
    }

    & $launcher --target-name steam-input-test-target.exe --payload $payload -- $target --probe-client $port --expect-blocked
    if ($LASTEXITCODE -ne 0) {
        throw "Rust payload did not gate the fake HID path while leased"
    }

    & $target --probe-client $port --expect-open
    if ($LASTEXITCODE -ne 0) {
        throw "Fake HID path remained blocked after releasing the lease"
    }

    & $launcher --target-name steam-input-test-target.exe --payload $payload -- $target --child
    if ($LASTEXITCODE -ne 23) {
        throw "Wrapper returned $LASTEXITCODE; expected child exit code 23"
    }

    & $launcher --target-name steam-input-test-target.exe --status
    if ($LASTEXITCODE -ne 0) {
        throw "Payload status query returned $LASTEXITCODE"
    }
} finally {
    $targetProcess.Refresh()
    if (-not $targetProcess.HasExited) {
        Stop-Process -Id $targetProcess.Id
    }
    $targetProcess.WaitForExit()
}
