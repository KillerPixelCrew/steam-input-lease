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
    # Bounded: a Stop-Process that could not reach the target (protected or
    # elevated) must not wedge the script in cleanup with no diagnostic.
    if (-not $targetProcess.WaitForExit(5000)) {
        Write-Warning "Test target $($targetProcess.Id) did not exit within 5s after Stop-Process"
    }
}
