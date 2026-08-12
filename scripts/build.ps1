<#
.SYNOPSIS
Builds and packages all release surfaces.

.DESCRIPTION
Builds the complete Cargo workspace and .NET binding, then creates a portable
artifact directory and a win-x64 NuGet package. Native DLLs are copied both
beside the CLI (for direct execution) and under native/ (for embedding).

.PARAMETER Runtime
Artifact directory label. This script currently builds the active Rust target,
so the value is constrained to win-x64; widen the ValidateSet only when the
shell/toolchain target is changed accordingly.

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

# Native host library, injected payload, ABI library, CLI, and test target.
cargo build --workspace --release --manifest-path $manifest
if ($LASTEXITCODE -ne 0) {
    throw "Cargo release build failed with exit code $LASTEXITCODE"
}

$managedProject = Join-Path $workspace 'bindings\SteamInterop.Net\SteamInterop.Net.csproj'
# Building after Cargo makes the conditional native runtime assets available to
# the managed project and eventual NuGet package.
dotnet build $managedProject -c Release --nologo
if ($LASTEXITCODE -ne 0) {
    throw ".NET release build failed with exit code $LASTEXITCODE"
}

$artifactRoot = Join-Path $workspace "artifacts\$Runtime"
$native = Join-Path $artifactRoot 'native'
$managed = Join-Path $artifactRoot 'managed'
$include = Join-Path $artifactRoot 'include'
New-Item -ItemType Directory -Force -Path $artifactRoot,$native,$managed,$include | Out-Null

$release = Join-Path $workspace 'target\release'
# Root copies support the CLI/default payload lookup. Structured copies support
# applications that embed only the native or managed layers.
Copy-Item -Force -LiteralPath (Join-Path $release 'steam-input-lease.exe') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_gate.dll') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_lease_ffi.dll') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_gate.dll') -Destination $native
Copy-Item -Force -LiteralPath (Join-Path $release 'steam_input_lease_ffi.dll') -Destination $native
Copy-Item -Force -LiteralPath (Join-Path $workspace 'include\steam_input_lease.h') -Destination $include

$managedOutput = Join-Path $workspace 'bindings\SteamInterop.Net\bin\Release\net8.0'
Copy-Item -Force -LiteralPath (Join-Path $managedOutput 'SteamInputLease.dll') -Destination $managed
Copy-Item -Force -LiteralPath (Join-Path $managedOutput 'SteamInputLease.xml') -Destination $managed
Copy-Item -Force -LiteralPath (Join-Path $workspace 'LICENSE-MIT') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $workspace 'THIRD_PARTY_LICENSES.md') -Destination $artifactRoot
Copy-Item -Force -LiteralPath (Join-Path $workspace 'README.md') -Destination $artifactRoot

$packages = Join-Path $workspace 'artifacts\packages'
New-Item -ItemType Directory -Force -Path $packages | Out-Null
dotnet pack $managedProject -c Release -o $packages --nologo
if ($LASTEXITCODE -ne 0) {
    throw ".NET package build failed with exit code $LASTEXITCODE"
}

Write-Output "Built Steam Input Lease artifacts at $artifactRoot"
