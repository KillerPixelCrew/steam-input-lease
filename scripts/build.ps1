<#
.SYNOPSIS
Builds and packages all release surfaces.

.DESCRIPTION
Builds the complete Cargo workspace and .NET binding, then creates a portable
artifact directory and a win-x64 NuGet package. Native DLLs are copied both
beside the CLI (for direct execution) and under native/ (for embedding).

.PARAMETER Runtime
Artifact directory label. The build target is explicitly
x86_64-pc-windows-msvc and the produced PE headers are verified as x64, so the
value is constrained to win-x64.

.OUTPUTS
artifacts/<Runtime> and artifacts/packages/SteamInputLease.<version>.nupkg.
#>
[CmdletBinding()]
param(
    [ValidateSet('win-x64')]
    [string]$Runtime = 'win-x64'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$workspace = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $workspace 'Cargo.toml'
$rustTarget = 'x86_64-pc-windows-msvc'

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory)]
        [string]$FailureMessage
    )

    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)"
    }
}

function Assert-X64PortableExecutable {
    param([Parameter(Mandatory)][string]$Path)

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    $stream = [System.IO.File]::OpenRead($resolved)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        if ($stream.Length -lt 64) {
            throw "PE image is too short: $resolved"
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0 -or $peOffset + 6 -gt $stream.Length) {
            throw "PE header offset is invalid: $resolved"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "PE signature is invalid: $resolved"
        }
        if ($reader.ReadUInt16() -ne 0x8664) {
            throw "Expected an x64 PE image: $resolved"
        }
    } finally {
        $stream.Dispose()
    }
}

# Safe, non-Steam verification gates. The lifecycle injection test remains a
# separate explicit command because packaging must not start any process.
Invoke-Checked cargo @(
    'test', '--workspace', '--target', $rustTarget, '--manifest-path', $manifest
) 'Cargo tests failed'
Invoke-Checked cargo @(
    'clippy', '--workspace', '--all-targets', '--target', $rustTarget,
    '--manifest-path', $manifest, '--', '-D', 'warnings'
) 'Cargo clippy failed'
$previousRustDocFlags = $env:RUSTDOCFLAGS
try {
    $env:RUSTDOCFLAGS = '-D warnings'
    Invoke-Checked cargo @(
        'doc', '--workspace', '--no-deps', '--target', $rustTarget,
        '--manifest-path', $manifest
    ) 'Cargo documentation build failed'
} finally {
    $env:RUSTDOCFLAGS = $previousRustDocFlags
}
Invoke-Checked cargo @(
    'package', '--workspace', '--allow-dirty', '--manifest-path', $manifest
) 'Cargo source packaging failed'

# Native host library, injected payload, ABI library, CLI, and test target.
Invoke-Checked cargo @(
    'build', '--workspace', '--release', '--target', $rustTarget,
    '--manifest-path', $manifest
) 'Cargo release build failed'

$managedProject = Join-Path $workspace 'bindings\SteamInterop.Net\SteamInterop.Net.csproj'
$sampleProject = Join-Path $workspace 'samples\SteamInterop.CSharpExample\SteamInterop.CSharpExample.csproj'
# Building after Cargo makes the conditional native runtime assets available to
# the managed project and eventual NuGet package.
Invoke-Checked dotnet @('build', $managedProject, '-c', 'Release', '--nologo') `
    '.NET release build failed'
Invoke-Checked dotnet @('build', $sampleProject, '-c', 'Release', '--nologo') `
    '.NET sample build failed'

$artifactRoot = Join-Path $workspace "artifacts\$Runtime"
$native = Join-Path $artifactRoot 'native'
$managed = Join-Path $artifactRoot 'managed'
$include = Join-Path $artifactRoot 'include'
New-Item -ItemType Directory -Force -Path $artifactRoot,$native,$managed,$include | Out-Null

$release = Join-Path $workspace "target\$rustTarget\release"
Assert-X64PortableExecutable (Join-Path $release 'steam-input-lease.exe')
Assert-X64PortableExecutable (Join-Path $release 'steam_input_gate.dll')
Assert-X64PortableExecutable (Join-Path $release 'steam_input_lease_ffi.dll')
# Root copies support the CLI/default payload lookup. Structured copies support
# applications that embed only the native or managed layers.
Copy-Item -Force -LiteralPath (Join-Path $release 'steam-input-lease.exe') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_gate.dll') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_lease_ffi.dll') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_gate.dll') -Destination $native
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_lease_ffi.dll') -Destination $native
Copy-Item -Force -LiteralPath (Join-Path $workspace 'include\steam_input_lease.h') -Destination $include

$managedOutput = Join-Path $workspace `
    'bindings\SteamInterop.Net\bin\Release\net8.0-windows10.0.17763.0'
Copy-Item -Force -LiteralPath (Join-Path $managedOutput 'SteamInputLease.dll') -Destination $managed
Copy-Item -Force -LiteralPath (Join-Path $managedOutput 'SteamInputLease.xml') -Destination $managed
Copy-Item -Force -LiteralPath (Join-Path $workspace 'LICENSE-MIT') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $workspace 'THIRD_PARTY_LICENSES.md') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $workspace 'README.md') -Destination $artifactRoot

$packages = Join-Path $workspace 'artifacts\packages'
New-Item -ItemType Directory -Force -Path $packages | Out-Null
Invoke-Checked dotnet @(
    'pack', $managedProject, '-c', 'Release', '-o', $packages, '--no-build', '--nologo'
) '.NET package build failed'

Write-Output "Built Steam Input Lease artifacts at $artifactRoot"
