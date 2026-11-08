#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Fetches the gate tools, or the release's submission tool, that tools.json
    pins for this platform, and emits the folders to put first on PATH and on
    PSModulePath.

.DESCRIPTION
    Every file is pinned by version and SHA-256 in tools.json beside this
    script, and nothing is installed: everything is written under -Path, and a
    download already there with the pinned hash is not fetched again.

    A pin's version, and for a GitHub release asset its SHA-256, is moved by
    Renovate. A module's SHA-256 is not: after Renovate moves a module's
    version this script refuses the new file and names its hash, which is
    pinned once checked against the SHA-512 the PowerShell Gallery publishes
    for that version.

.PARAMETER Set
    gate: the tools CI's gates run, the same versions a contributor runs.
    winget: what the winget submission runs.

.PARAMETER Path
    Where the tools are kept. Defaults to target/tools in the repository,
    which `cargo clean` removes.

.EXAMPLE
    ./scripts/fetch-tools.ps1 -Set gate | ForEach-Object {
        $current = [Environment]::GetEnvironmentVariable($_.Name)
        [Environment]::SetEnvironmentVariable($_.Name, $_.Value + [IO.Path]::PathSeparator + $current)
    }

    Fetches the gate tools and puts them first for this session.

.OUTPUTS
    Up to two objects: Name, the variable (Path or PSModulePath), and Value,
    the folder to put first in it.
#>
[CmdletBinding(SupportsShouldProcess)]
[OutputType([pscustomobject])]
param(
    [Parameter(Mandatory)]
    [ValidateSet('gate', 'winget')]
    [string[]] $Set,

    [ValidateNotNullOrEmpty()]
    [string] $Path = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'target', 'tools')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ToolPlatform {
    <#
    .SYNOPSIS
        Names this machine as tools.json's platforms do: windows-x64,
        windows-arm64, linux-x64.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $os = if ($IsWindows) { 'windows' } elseif ($IsLinux) { 'linux' } elseif ($IsMacOS) { 'macos' } else { 'unknown' }
    $architecture = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
        'X64' { 'x64' }
        'Arm64' { 'arm64' }
        default { $_.ToString().ToLowerInvariant() }
    }
    "$os-$architecture"
}

function Get-ToolPin {
    <#
    .SYNOPSIS
        Emits the pins in a tools.json for the sets named that serve a
        platform; a pin for platform any serves every one.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Manifest,

        [Parameter(Mandatory)]
        [string[]] $Set,

        [Parameter(Mandatory)]
        [string] $Platform
    )

    $pins = (Get-Content -LiteralPath $Manifest -Raw | ConvertFrom-Json).tools
    $pins | Where-Object { $_.set -in $Set -and ($_.platforms -contains $Platform -or $_.platforms -contains 'any') }
}

function Resolve-PinText {
    <#
    .SYNOPSIS
        Expands {version} to a pin's version and {number} to it without a
        leading v.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Text,

        [Parameter(Mandatory)]
        [string] $Version
    )

    $Text.Replace('{version}', $Version).Replace('{number}', ($Version -replace '^v', ''))
}

function Resolve-PinUri {
    <#
    .SYNOPSIS
        Emits where a pin's file is published.
    #>
    [CmdletBinding()]
    [OutputType([uri])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Pin
    )

    switch ($Pin.datasource) {
        'github-release-attachments' {
            $file = Resolve-PinText -Text $Pin.file -Version $Pin.version
            [uri] "https://github.com/$($Pin.package)/releases/download/$($Pin.version)/$file"
        }
        'nuget' {
            [uri] "$($Pin.registry)package/$($Pin.package)/$($Pin.version)"
        }
        default {
            throw "Pin '$($Pin.tool)' names datasource '$($Pin.datasource)', which this script cannot fetch."
        }
    }
}

function Save-VerifiedFile {
    <#
    .SYNOPSIS
        Puts the file a URI serves at a path, keeping it only when its SHA-256
        is the one pinned, and emits the path.

    .DESCRIPTION
        A file already at the path with the pinned hash is kept as it is. A
        download is written beside the path and moved into place only once
        verified, so the path never holds a file that failed the check.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [uri] $Uri,

        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [ValidatePattern('^[0-9A-Fa-f]{64}$')]
        [string] $Sha256
    )

    if ((Test-Path -LiteralPath $Path -PathType Leaf) -and
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -eq $Sha256) {
        return $Path
    }
    if (-not $PSCmdlet.ShouldProcess($Path, "Download $Uri")) {
        return
    }
    $null = New-Item -ItemType Directory -Force -Path (Split-Path -Path $Path -Parent)
    $partial = "$Path.partial"
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $partial -MaximumRetryCount 3 -RetryIntervalSec 2
        $found = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash
        if ($found -ne $Sha256) {
            throw "$Uri has SHA-256 $found, not the pinned $Sha256. Check the file at its source before pinning it."
        }
        Move-Item -LiteralPath $partial -Destination $Path -Force
    } finally {
        # Absent once moved into place: only a failed download leaves it.
        Remove-Item -LiteralPath $partial -Force -ErrorAction Ignore
    }
    $Path
}

function Expand-ToolArchive {
    <#
    .SYNOPSIS
        Extracts an archive into an empty folder: a zip by PowerShell, a tar
        archive by the tar on PATH.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string] $Archive,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    if (-not $PSCmdlet.ShouldProcess($Destination, "Extract $Archive")) {
        return
    }
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction Ignore
    $null = New-Item -ItemType Directory -Force -Path $Destination
    if ($Archive.EndsWith('.zip') -or $Archive.EndsWith('.nupkg')) {
        # Expand-Archive takes only a .zip name; a .nupkg is a zip.
        $zip = "$Destination.zip"
        Copy-Item -LiteralPath $Archive -Destination $zip -Force
        try {
            Expand-Archive -LiteralPath $zip -DestinationPath $Destination
        } finally {
            Remove-Item -LiteralPath $zip -Force -ErrorAction Ignore
        }
        return
    }
    if (-not (Get-Command -Name 'tar' -CommandType Application -ErrorAction Ignore)) {
        throw "No tar on PATH to extract $Archive."
    }
    & tar -xf $Archive -C $Destination
    if ($LASTEXITCODE -ne 0) {
        throw "tar could not extract $Archive (exit code $LASTEXITCODE)"
    }
}

function Install-Tool {
    <#
    .SYNOPSIS
        Lays out one verified download as the folder it serves from: a program
        in bin, a module in modules\<name>\<version>.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Pin,

        [Parameter(Mandatory)]
        [string] $Download,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $staging = Join-Path -Path $Path -ChildPath 'staging' -AdditionalChildPath $Pin.tool
    if ($Pin.datasource -eq 'nuget') {
        $modules = Join-Path -Path $Path -ChildPath 'modules'
        $folder = Join-Path -Path $modules -ChildPath $Pin.package -AdditionalChildPath $Pin.version
        if ($PSCmdlet.ShouldProcess($folder, "Lay out $($Pin.package) $($Pin.version)")) {
            Expand-ToolArchive -Archive $Download -Destination $staging
            # A package's own records, which no module loads.
            $records = '[Content_Types].xml', '_rels', 'package', "$($Pin.package).nuspec"
            foreach ($record in $records) {
                $path = Join-Path -Path $staging -ChildPath $record
                Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Ignore
            }
            Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction Ignore
            $null = New-Item -ItemType Directory -Force -Path (Split-Path -Path $folder -Parent)
            Move-Item -LiteralPath $staging -Destination $folder
        }
        return [pscustomobject] @{ Name = 'PSModulePath'; Value = $modules }
    }

    $bin = Join-Path -Path $Path -ChildPath 'bin'
    $program = Join-Path -Path $bin -ChildPath ($Pin.tool + $(if ($IsWindows) { '.exe' } else { '' }))
    if ($PSCmdlet.ShouldProcess($program, "Lay out $($Pin.tool) $($Pin.version)")) {
        $null = New-Item -ItemType Directory -Force -Path $bin
        $source = $Download
        if ($Pin.PSObject.Properties.Name -contains 'member') {
            Expand-ToolArchive -Archive $Download -Destination $staging
            $source = Join-Path -Path $staging -ChildPath (Resolve-PinText -Text $Pin.member -Version $Pin.version)
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "$Download holds no $($Pin.member)"
            }
        }
        Copy-Item -LiteralPath $source -Destination $program -Force
        if (-not $IsWindows) {
            $mode = 'UserRead, UserWrite, UserExecute, GroupRead, GroupExecute, OtherRead, OtherExecute'
            [IO.File]::SetUnixFileMode($program, [IO.UnixFileMode] $mode)
        }
        Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Ignore
    }
    [pscustomobject] @{ Name = 'Path'; Value = $bin }
}

function Save-Tool {
    <#
    .SYNOPSIS
        Fetches and lays out every pin of the sets named for this platform,
        emitting each folder to put first once.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Manifest,

        [Parameter(Mandatory)]
        [string[]] $Set,

        [Parameter(Mandatory)]
        [string] $Platform,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $pins = @(Get-ToolPin -Manifest $Manifest -Set $Set -Platform $Platform)
    if ($pins.Count -eq 0) {
        throw "tools.json pins nothing in set $($Set -join ', ') for $Platform."
    }
    $downloads = Join-Path -Path $Path -ChildPath 'downloads'
    $folders = foreach ($pin in $pins) {
        $download = @{
            Uri    = Resolve-PinUri -Pin $pin
            Path   = Join-Path -Path $downloads -ChildPath (Resolve-PinText -Text $pin.file -Version $pin.version)
            Sha256 = $pin.sha256
        }
        $saved = Save-VerifiedFile @download
        if ($saved) {
            Install-Tool -Pin $pin -Download $saved -Path $Path
        }
    }
    $folders | Sort-Object -Property Name, Value -Unique
}

if ($MyInvocation.InvocationName -ne '.') {
    $tools = @{
        Manifest = Join-Path -Path $PSScriptRoot -ChildPath 'tools.json'
        Set      = $Set
        Platform = Get-ToolPlatform
        Path     = [IO.Path]::GetFullPath($Path)
    }
    Save-Tool @tools
}
