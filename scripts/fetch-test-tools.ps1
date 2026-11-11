#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Fetches the third-party programs the suites run against, and emits the
    environment variable that tells the suites where each one is.

.DESCRIPTION
    Each artifact is pinned by version and SHA-256, and nothing is installed:
    everything is written under -Path, and an artifact already there and
    verified is not fetched again.

    HEDWIG_GNUPG    GnuPG's own Windows build, laid out from the wixlib GnuPG
                    publishes as an installation's folder (the one holding bin).
    HEDWIG_ADB      adb.exe of Android platform-tools' current release.
    HEDWIG_ADB_OUTDATED
                    adb.exe of platform-tools 34.0.5, the last whose server
                    lists no devices in protocol buffers.
    HEDWIG_PYSERIAL pyserial's release wheel, which the serial suite puts on
                    PYTHONPATH for the workstation's own Python.

    To move a pin, verify the new release at its source - GnuPG's signature by
    its dist signing key 6DAA6E64A76D2840571B4902528897B826403ADA, the SHA-1
    Google's repository2-3.xml states, the SHA-256 PyPI publishes - and record
    the SHA-256 of the file verified.

.PARAMETER Path
    Where the artifacts are kept. Defaults to target\test-tools in the
    repository, which `cargo clean` removes.

.EXAMPLE
    ./scripts/fetch-test-tools.ps1 | ForEach-Object { Set-Item -Path "Env:$($_.Name)" -Value $_.Value }

    Fetches every artifact and points this session's suites at them.

.OUTPUTS
    One object per artifact: Name, the environment variable, and Value, the
    path it names.
#>
[CmdletBinding(SupportsShouldProcess)]
[OutputType([pscustomobject])]
param(
    [ValidateNotNullOrEmpty()]
    [string] $Path = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'target', 'test-tools')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SystemProgram {
    <#
    .SYNOPSIS
        Emits the path of a program in Windows' own system folder.

    .DESCRIPTION
        Never the one a search path finds first: Git for Windows puts its own
        tar and curl there, and its GNU tar reads no cabinet.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    Join-Path -Path ([Environment]::SystemDirectory) -ChildPath $Name
}

function Invoke-Curl {
    <#
    .SYNOPSIS
        Runs Windows' own curl.exe with the arguments given.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]] $Argument
    )

    & (Get-SystemProgram -Name 'curl.exe') @Argument
}

function Invoke-Download {
    <#
    .SYNOPSIS
        Downloads a URI to a file, throwing when curl does not succeed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uri] $Uri,

        [Parameter(Mandatory)]
        [string] $OutFile
    )

    # -4: Google's download host has answered a workstation's IPv6 route with
    # 404; every host here serves IPv4.
    $arguments = @(
        '-4', '--silent', '--show-error', '--fail', '--location', '--retry', '3'
        '--output', $OutFile, $Uri.AbsoluteUri
    )
    Invoke-Curl -Argument $arguments
    if ($LASTEXITCODE -ne 0) {
        throw "curl could not download $Uri (exit code $LASTEXITCODE)"
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
    $folder = Split-Path -Path $Path -Parent
    $null = New-Item -ItemType Directory -Force -Path $folder
    $partial = "$Path.partial"
    try {
        Invoke-Download -Uri $Uri -OutFile $partial
        $found = (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash
        if ($found -ne $Sha256) {
            throw "$Uri has SHA-256 $found, not the pinned $Sha256"
        }
        Move-Item -LiteralPath $partial -Destination $Path -Force
    } finally {
        # Absent once moved into place: only a failed download leaves it.
        Remove-Item -LiteralPath $partial -Force -ErrorAction Ignore
    }
    $Path
}

function Expand-PlatformTool {
    <#
    .SYNOPSIS
        Lays out a platform-tools archive in a folder of its own and emits the
        path to its adb.exe.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Archive,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    $adb = Join-Path -Path $Destination -ChildPath 'platform-tools' -AdditionalChildPath 'adb.exe'
    if (Test-Path -LiteralPath $adb -PathType Leaf) {
        return $adb
    }
    if (-not $PSCmdlet.ShouldProcess($Destination, "Expand $Archive")) {
        return
    }
    # Expanded beside the destination and renamed into place, so an
    # interrupted run never leaves a destination that looks complete; what an
    # interrupted run left, if anything, goes first.
    $staging = "$Destination.partial"
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction Ignore
    Expand-Archive -LiteralPath $Archive -DestinationPath $staging
    $expanded = Join-Path -Path $staging -ChildPath 'platform-tools' -AdditionalChildPath 'adb.exe'
    if (-not (Test-Path -LiteralPath $expanded -PathType Leaf)) {
        throw "$Archive holds no platform-tools\adb.exe"
    }
    Move-Item -LiteralPath $staging -Destination $Destination
    $adb
}

function Expand-GnuPG {
    <#
    .SYNOPSIS
        Lays out GnuPG's wixlib as an installation's bin folder and emits the
        folder that holds bin.

    .DESCRIPTION
        The wixlib is a cabinet whose files are numbered rather than named:
        each program is named by its own version resource, each library by the
        name the programs import it under.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Wixlib,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    $needed = 'gpg.exe', 'gpg-agent.exe', 'gpgconf.exe', 'gpg-connect-agent.exe', 'scdaemon.exe', 'keyboxd.exe'
    $gpgconf = Join-Path -Path $Destination -ChildPath 'bin' -AdditionalChildPath 'gpgconf.exe'
    if (Test-Path -LiteralPath $gpgconf -PathType Leaf) {
        return $Destination
    }
    if (-not $PSCmdlet.ShouldProcess($Destination, "Lay out $Wixlib")) {
        return
    }
    # Laid out beside the destination and renamed into place, as
    # Expand-PlatformTool does; what an interrupted run left goes first.
    $staging = "$Destination.partial"
    $cabinet = "$Destination.cabinet"
    Remove-Item -LiteralPath $staging, $cabinet -Recurse -Force -ErrorAction Ignore
    $bin = Join-Path -Path $staging -ChildPath 'bin'
    $null = New-Item -ItemType Directory -Force -Path $bin, $cabinet
    try {
        & (Get-SystemProgram -Name 'tar.exe') -xf $Wixlib -C $cabinet
        if ($LASTEXITCODE -ne 0) {
            throw "tar could not read the cabinet $Wixlib (exit code $LASTEXITCODE)"
        }
        $libraries = @{
            'libassuan'    = 'libassuan-9.dll'
            'libgcrypt'    = 'libgcrypt-20.dll'
            'libgpg-error' = 'libgpg-error-0.dll'
            'libksba'      = 'libksba-8.dll'
            'libnpth'      = 'libnpth-0.dll'
            'libntbtls'    = 'libntbtls-0.dll'
            'zlib1.dll'    = 'zlib1.dll'
        }
        foreach ($file in Get-ChildItem -LiteralPath $cabinet -File) {
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
                continue
            }
            $named = $file.VersionInfo.OriginalFilename
            # SQLite's library carries no version resource; it is the one large
            # library that names itself.
            if (-not $named -and $bytes.Length -gt 1MB -and
                [Text.Encoding]::ASCII.GetString($bytes).Contains('libsqlite3-0.dll')) {
                $named = 'libsqlite3-0.dll'
            }
            $internal = $file.VersionInfo.InternalName
            if ($internal -and $libraries.ContainsKey($internal)) {
                $named = $libraries[$internal]
            }
            if (-not $named) {
                continue
            }
            $into = Join-Path -Path $bin -ChildPath $named
            # The cabinet holds two builds of gpgconf; the signed one is the
            # installation's.
            if ((Test-Path -LiteralPath $into) -and
                (Get-AuthenticodeSignature -LiteralPath $file.FullName).Status -ne 'Valid') {
                continue
            }
            Copy-Item -LiteralPath $file.FullName -Destination $into -Force
        }
        foreach ($program in $needed) {
            if (-not (Test-Path -LiteralPath (Join-Path -Path $bin -ChildPath $program))) {
                throw "$program was not in the cabinet $Wixlib"
            }
        }
        Move-Item -LiteralPath $staging -Destination $Destination
    } finally {
        # The staging folder is absent once renamed into place.
        Remove-Item -LiteralPath $cabinet, $staging -Recurse -Force -ErrorAction Ignore
    }
    $Destination
}

function Save-TestTool {
    <#
    .SYNOPSIS
        Fetches and lays out every artifact under a folder, emitting one object
        per artifact: Name, its environment variable, and Value, its path.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $downloads = Join-Path -Path $Path -ChildPath 'downloads'

    $gnupg = @{
        Uri    = 'https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.5.24_20260923.wixlib'
        Path   = Join-Path -Path $downloads -ChildPath 'gnupg-w32-2.5.24_20260923.wixlib'
        Sha256 = '4E4600B3D28B6507E2433D59C69BA6C33D4DA158F2C8DA1E12F948B68A97EBDA'
    }
    $wixlib = Save-VerifiedFile @gnupg
    $folder = if ($wixlib) {
        Expand-GnuPG -Wixlib $wixlib -Destination (Join-Path -Path $Path -ChildPath 'gnupg-2.5.24')
    }
    if ($folder) {
        [pscustomobject] @{ Name = 'HEDWIG_GNUPG'; Value = $folder }
    }

    $platformTools = @(
        @{
            Variable = 'HEDWIG_ADB'
            Version  = '37.0.1'
            File     = 'platform-tools_r37.0.1-win.zip'
            Sha256   = '45F4D63113E895EBDE0C90F194099A4676B6AC653BD28D54314A9E022BBC1A99'
        }
        @{
            Variable = 'HEDWIG_ADB_OUTDATED'
            Version  = '34.0.5'
            File     = 'platform-tools_r34.0.5-windows.zip'
            Sha256   = '3F8320152704377DE150418A3C4C9D07D16D80A6C0D0D8F7289C22C499E33571'
        }
    )
    foreach ($release in $platformTools) {
        $download = @{
            Uri    = "https://dl.google.com/android/repository/$($release.File)"
            Path   = Join-Path -Path $downloads -ChildPath $release.File
            Sha256 = $release.Sha256
        }
        $archive = Save-VerifiedFile @download
        $adb = if ($archive) {
            $destination = Join-Path -Path $Path -ChildPath "platform-tools-$($release.Version)"
            Expand-PlatformTool -Archive $archive -Destination $destination
        }
        if ($adb) {
            [pscustomobject] @{ Name = $release.Variable; Value = $adb }
        }
    }

    $wheel = 'pyserial-3.5-py2.py3-none-any.whl'
    $pypi = 'https://files.pythonhosted.org/packages'
    $pyserial = @{
        Uri    = "$pypi/07/bc/587a445451b253b285629263eb51c2d8e9bcea4fc97826266d186f96f558/$wheel"
        Path   = Join-Path -Path $Path -ChildPath $wheel
        Sha256 = 'C4451DB6BA391CA6CA299FB3EC7BAE67A5C55DDE170964C7A14CEEFEC02F2CF0'
    }
    $saved = Save-VerifiedFile @pyserial
    if ($saved) {
        [pscustomobject] @{ Name = 'HEDWIG_PYSERIAL'; Value = $saved }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $IsWindows) {
        throw 'The suites these programs serve run on Windows only; run this script on Windows.'
    }
    Save-TestTool -Path ([IO.Path]::GetFullPath($Path))
}
