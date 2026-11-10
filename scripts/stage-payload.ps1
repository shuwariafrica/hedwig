#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Lays out what hedwig-setup carries - hedwig.exe, hedwig-interface.exe,
    hedwig-window.exe and the window's runtime - from a release build, in the
    folder HEDWIG_PAYLOAD then names.

.DESCRIPTION
    The window's build stages the Windows App Runtime beside it through
    windows-reactor-setup, which downloads two NuGet packages without checking
    them and carries on when a download or an extraction fails. Until it
    verifies and fails itself, this script refuses a payload unless:

    - each package in the crate's download folder has the SHA-256 tools.json
      pins for the version the locked crate takes;
    - every file and folder of the extracted runtime that the crate's own list
      names, and WebView2's core library, is in the build's folder.

    Run after `cargo build --release` for the target and before anything runs
    from its folder, then build hedwig-setup with HEDWIG_PAYLOAD set to
    -Destination.

.PARAMETER Build
    The release build's folder: target\<triple>\release.

.PARAMETER Destination
    The payload folder; emptied first.

.PARAMETER ReactorSetup
    The locked windows-reactor-setup's source folder. Found by cargo metadata
    when not given.

.PARAMETER Cache
    The folder windows-reactor-setup downloads into. Taken from LOCALAPPDATA,
    as the crate takes it, when not given.

.EXAMPLE
    ./scripts/stage-payload.ps1 -Build target/x86_64-pc-windows-msvc/release -Destination target/payload-x64

.OUTPUTS
    The payload: Destination, Files and Bytes.
#>
[CmdletBinding(SupportsShouldProcess)]
[OutputType([pscustomobject])]
param(
    [Parameter(Mandatory)]
    [string] $Build,

    [Parameter(Mandatory)]
    [string] $Destination,

    [string] $ReactorSetup,

    [string] $Cache,

    [string] $Manifest = (Join-Path -Path $PSScriptRoot -ChildPath 'tools.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-ReactorSetup {
    <#
    .SYNOPSIS
        Emits the source folder of the windows-reactor-setup Cargo.lock
        locks, read from cargo metadata.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $json = & cargo metadata --format-version 1 --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed (exit code $LASTEXITCODE)"
    }
    $packages = @(($json -join "`n" | ConvertFrom-Json).packages | Where-Object { $_.name -eq 'windows-reactor-setup' })
    if ($packages.Count -ne 1) {
        throw "Cargo.lock locks $($packages.Count) windows-reactor-setup packages; expected one."
    }
    Split-Path -Path $packages[0].manifest_path -Parent
}

function Get-ReactorCache {
    <#
    .SYNOPSIS
        Emits the folder windows-reactor-setup downloads into under the given
        LOCALAPPDATA, and throws where there is none.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string] $LocalAppData
    )

    if (-not $LocalAppData) {
        throw 'LOCALAPPDATA is not set, so the folder windows-reactor-setup downloads into is unknown: give -Cache.'
    }
    Join-Path -Path $LocalAppData -ChildPath 'windows-reactor-setup' 'temp'
}

function Get-RuntimeVersion {
    <#
    .SYNOPSIS
        Reads the NuGet package versions windows-reactor-setup downloads from
        its source: RuntimeVersion and WebViewVersion.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $ReactorSetup
    )

    $source = Get-Content -LiteralPath (Join-Path -Path $ReactorSetup -ChildPath 'src' 'lib.rs') -Raw
    $read = {
        param($Constant)
        if ($source -notmatch "const $Constant`: &str = `"([^`"]+)`";") {
            throw ("windows-reactor-setup at $ReactorSetup no longer declares $Constant; " +
                'read how it stages the runtime again.')
        }
        $Matches[1]
    }
    [pscustomobject] @{
        RuntimeVersion = & $read 'RUNTIME_VER'
        WebViewVersion = & $read 'WEBVIEW2_VER'
    }
}

function Assert-RuntimePackage {
    <#
    .SYNOPSIS
        Throws unless the package windows-reactor-setup downloaded has the
        SHA-256 tools.json pins for its name and version.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Manifest,

        [Parameter(Mandatory)]
        [string] $Cache,

        [Parameter(Mandatory)]
        [string] $Package,

        [Parameter(Mandatory)]
        [string] $Version
    )

    $pin = (Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json).tools |
        Where-Object { $_.set -eq 'runtime' -and $_.tool -eq $Package -and $_.version -eq $Version }
    if (-not $pin) {
        throw ("tools.json pins no $Package $Version. " +
            "Check its SHA-512 against nuget.org's catalog, then pin its SHA-256.")
    }
    $file = Join-Path -Path $Cache -ChildPath "$Package.$Version.nupkg"
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "$file is missing: windows-reactor-setup did not download $Package $Version."
    }
    $found = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    if ($found -ne $pin.sha256) {
        throw "$file has SHA-256 $found, not the pinned $($pin.sha256)."
    }
}

function Get-RuntimeEntry {
    <#
    .SYNOPSIS
        Emits the names of the extracted runtime's files and folders that
        windows-reactor-setup's list names, compared as it compares them,
        ignoring case.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $ReactorSetup,

        [Parameter(Mandatory)]
        [string] $Extracted
    )

    if (-not (Test-Path -LiteralPath $Extracted -PathType Container)) {
        throw "$Extracted is missing: windows-reactor-setup did not extract the runtime."
    }
    $listed = Get-Content -LiteralPath (Join-Path -Path $ReactorSetup -ChildPath 'assets' 'runtime.txt') |
        ForEach-Object { $_.Trim() } | Where-Object { $_ }
    $names = [Collections.Generic.HashSet[string]]::new([string[]] $listed, [StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem -LiteralPath $Extracted | Where-Object { $names.Contains($_.Name) } | ForEach-Object { $_.Name }
}

function Publish-Payload {
    <#
    .SYNOPSIS
        Checks the build's runtime, copies the three executables and the
        runtime into an emptied folder, and emits the payload.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Build,

        [Parameter(Mandatory)]
        [string] $Destination,

        [Parameter(Mandatory)]
        [string] $ReactorSetup,

        [Parameter(Mandatory)]
        [string] $Cache,

        [Parameter(Mandatory)]
        [string] $Manifest
    )

    $versions = Get-RuntimeVersion -ReactorSetup $ReactorSetup
    $packages = @{
        'Microsoft.WindowsAppSDK.Runtime' = $versions.RuntimeVersion
        'Microsoft.Web.WebView2'          = $versions.WebViewVersion
    }
    foreach ($package in $packages.Keys) {
        Assert-RuntimePackage -Manifest $Manifest -Cache $Cache -Package $package -Version $packages[$package]
    }
    $runtime = "Microsoft.WindowsAppSDK.Runtime-$($versions.RuntimeVersion)"
    $extracted = Join-Path -Path $Cache -ChildPath $runtime '.msix_extract'
    $entries = @(Get-RuntimeEntry -ReactorSetup $ReactorSetup -Extracted $extracted) + 'Microsoft.Web.WebView2.Core.dll'
    $programs = 'hedwig.exe', 'hedwig-interface.exe', 'hedwig-window.exe'
    # Names compare as Windows compares them, whatever file system holds the build.
    $built = @{}
    foreach ($item in Get-ChildItem -LiteralPath $Build) {
        $built[$item.Name.ToLowerInvariant()] = $item.FullName
    }
    $missing = @($programs + $entries | Where-Object { -not $built.ContainsKey($_.ToLowerInvariant()) })
    if ($missing.Count -gt 0) {
        throw "$Build lacks $($missing.Count) of what setup carries: $($missing -join ', ')"
    }
    if (-not $PSCmdlet.ShouldProcess($Destination, "Lay out the payload from $Build")) {
        return
    }
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction Ignore
    $null = New-Item -ItemType Directory -Force -Path $Destination
    foreach ($name in $programs + $entries) {
        Copy-Item -LiteralPath $built[$name.ToLowerInvariant()] -Destination $Destination -Recurse -Force
    }
    $files = @(Get-ChildItem -LiteralPath $Destination -Recurse -File)
    [pscustomobject] @{
        Destination = $Destination
        Files       = $files.Count
        Bytes       = ($files | Measure-Object -Property Length -Sum).Sum
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $payload = @{
        Build        = [IO.Path]::GetFullPath($Build)
        Destination  = [IO.Path]::GetFullPath($Destination)
        ReactorSetup = if ($ReactorSetup) { [IO.Path]::GetFullPath($ReactorSetup) } else { Find-ReactorSetup }
        Cache        = if ($Cache) { $Cache } else { Get-ReactorCache -LocalAppData $env:LOCALAPPDATA }
        Manifest     = $Manifest
    }
    Publish-Payload @payload
}
