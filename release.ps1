#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates and pushes the signed tag that publishes a release.

.DESCRIPTION
    Cargo has no hook for deriving the package version, so Cargo.toml is
    authoritative and the tag is checked against it. Bump Cargo.toml, run
    `cargo update -w`, commit, then run this.

    Every check runs before anything is tagged: a clean working tree, Cargo.toml
    and Cargo.lock both at the version, a remote pointing at the repository, a
    branch level with that remote after a fetch, and no existing tag. -WhatIf
    runs all of them, the fetch included, and stops short of the tag.

    MAIN_REPO_OWNER and MAIN_REPO_NAME name a fork to release from instead.

.PARAMETER Version
    Semantic version without the leading 'v'. Pre-release classifiers are
    alpha.N, beta.N and rc.N, case-sensitive: 1.2.3, 1.2.3-rc.2.

.EXAMPLE
    ./release.ps1 0.2.0 -WhatIf

.OUTPUTS
    An object naming the tag pushed and the remote it went to.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Git {
    <#
    .SYNOPSIS
        Runs git in a repository and emits its standard output lines, throwing
        on a non-zero exit with git's standard error in the message.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Repository,

        [Parameter(Mandatory)]
        [string[]] $Argument
    )

    $diagnostics = [System.Collections.Generic.List[string]]::new()
    & git -C $Repository @Argument 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $diagnostics.Add($_.ToString())
        } else {
            $_
        }
    }
    if ($LASTEXITCODE -ne 0) {
        $failure = @{
            Message      = "git $($Argument -join ' ') failed with exit code ${LASTEXITCODE}: $($diagnostics -join ' ')"
            ErrorId      = 'GitCommandFailed'
            Category     = 'InvalidResult'
            TargetObject = $Argument
        }
        Write-Error @failure -ErrorAction Stop
    }
}

function Get-ManifestVersion {
    <#
    .SYNOPSIS
        Reads the package version from Cargo.toml: the first top-level
        `version = "..."` line, which is the [package] table's.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $manifest = Join-Path -Path $Path -ChildPath 'Cargo.toml'
    $line = Select-String -LiteralPath $manifest -Pattern '^version = "(.*)"$' -CaseSensitive |
        Select-Object -First 1
    if (-not $line) {
        $refusal = @{
            Message      = "$manifest declares no package version."
            ErrorId      = 'ManifestVersionMissing'
            Category     = 'ObjectNotFound'
            TargetObject = $manifest
        }
        Write-Error @refusal -ErrorAction Stop
    }
    $line.Matches[0].Groups[1].Value
}

function Get-LockfileVersion {
    <#
    .SYNOPSIS
        Reads the version Cargo.lock records for a package, from the line that
        follows its `name = "..."` entry.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $lockfile = Join-Path -Path $Path -ChildPath 'Cargo.lock'
    $lines = @(Get-Content -LiteralPath $lockfile)
    $index = [Array]::IndexOf($lines, "name = `"$Name`"")
    if ($index -ge 0 -and $index + 1 -lt $lines.Count -and $lines[$index + 1] -cmatch '^version = "(.*)"$') {
        return $Matches[1]
    }
    $refusal = @{
        Message      = "$lockfile records no version for package '$Name'."
        ErrorId      = 'LockfileVersionMissing'
        Category     = 'ObjectNotFound'
        TargetObject = $lockfile
    }
    Write-Error @refusal -ErrorAction Stop
}

function Find-ReleaseRemote {
    <#
    .SYNOPSIS
        Emits the name of the first git remote whose URL is the repository's on
        GitHub, over HTTPS or SSH; emits nothing when none is.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Repository,

        [Parameter(Mandatory)]
        [string] $Owner,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $urls = @(
        "https://github.com/$Owner/$Name"
        "https://github.com/$Owner/$Name.git"
        "git@github.com:$Owner/$Name.git"
    )
    foreach ($remote in Invoke-Git -Repository $Repository -Argument 'remote') {
        $remoteUrls = Invoke-Git -Repository $Repository -Argument 'remote', 'get-url', '--all', $remote
        if ($remoteUrls | Where-Object { $urls -contains $_ }) {
            return $remote
        }
    }
}

function Publish-ReleaseTag {
    <#
    .SYNOPSIS
        Checks that the repository is ready to release a version, then creates
        the signed annotated tag v<Version> and pushes it.

    .PARAMETER Path
        Root of the repository: the directory holding Cargo.toml and Cargo.lock.

    .PARAMETER Name
        The package name, which is also the GitHub repository name.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        # The options replace the default IgnoreCase, so the match is case-sensitive.
        [ValidatePattern(@'
^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)
(-(alpha|beta|rc)\.([1-9][0-9]*))?
(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$
'@,
            Options = 'IgnorePatternWhitespace',
            ErrorMessage = "Version '{0}' is not valid. See Get-Help ./release.ps1 for allowed formats."
        )]
        [string] $Version,

        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Owner,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $changes = Invoke-Git -Repository $Path -Argument 'status', '--porcelain'
    if ($changes) {
        $refusal = @{
            Message      = "Commit or stash these changes before creating a release tag: $($changes -join '; ')"
            ErrorId      = 'WorkingTreeDirty'
            Category     = 'InvalidOperation'
            TargetObject = $Path
        }
        Write-Error @refusal -ErrorAction Stop
    }

    # Checked here because in CI a mismatch, or a lockfile left stale for
    # --locked, surfaces only after the whole matrix has run.
    $manifestVersion = Get-ManifestVersion -Path $Path
    if ($manifestVersion -cne $Version) {
        $refusal = @{
            Message      = "Cargo.toml declares version '$manifestVersion', not '$Version'. Update and commit it first."
            ErrorId      = 'ManifestVersionMismatch'
            Category     = 'InvalidData'
            TargetObject = $manifestVersion
        }
        Write-Error @refusal -ErrorAction Stop
    }
    $lockfileVersion = Get-LockfileVersion -Path $Path -Name $Name
    if ($lockfileVersion -cne $Version) {
        $refusal = @{
            Message      = "Cargo.lock records '$lockfileVersion', not '$Version'. Run 'cargo update -w' and commit."
            ErrorId      = 'LockfileVersionMismatch'
            Category     = 'InvalidData'
            TargetObject = $lockfileVersion
        }
        Write-Error @refusal -ErrorAction Stop
    }

    $tag = "v$Version"

    $remote = Find-ReleaseRemote -Repository $Path -Owner $Owner -Name $Name
    if (-not $remote) {
        $refusal = @{
            Message      = "No git remote points to $Owner/$Name. Add one and try again."
            ErrorId      = 'RemoteNotFound'
            Category     = 'ObjectNotFound'
            TargetObject = "$Owner/$Name"
        }
        Write-Error @refusal -ErrorAction Stop
    }

    $branch = Invoke-Git -Repository $Path -Argument 'rev-parse', '--abbrev-ref', 'HEAD'
    if ($branch -eq 'HEAD') {
        $refusal = @{
            Message      = 'Detached HEAD is not supported. Check out a branch with an upstream tracking branch.'
            ErrorId      = 'DetachedHead'
            Category     = 'InvalidOperation'
            TargetObject = $Path
        }
        Write-Error @refusal -ErrorAction Stop
    }

    $upstreamQuery = 'for-each-ref', '--format=%(upstream:remotename)', "refs/heads/$branch"
    $upstreamRemote = Invoke-Git -Repository $Path -Argument $upstreamQuery
    if (-not $upstreamRemote) {
        $refusal = @{
            Message      = "Branch '$branch' has no upstream. Push it with -u before releasing."
            ErrorId      = 'UpstreamMissing'
            Category     = 'ObjectNotFound'
            TargetObject = $branch
        }
        Write-Error @refusal -ErrorAction Stop
    }
    if ($upstreamRemote -ne $remote) {
        $refusal = @{
            Message      = "Upstream for '$branch' is on '$upstreamRemote', but must be on '$remote'."
            ErrorId      = 'UpstreamMismatch'
            Category     = 'InvalidOperation'
            TargetObject = $branch
        }
        Write-Error @refusal -ErrorAction Stop
    }

    Write-Information "Fetching from '$remote'..."
    $null = Invoke-Git -Repository $Path -Argument 'fetch', '--prune', $remote
    $null = Invoke-Git -Repository $Path -Argument 'fetch', '--tags', '--prune', $remote

    $counts = Invoke-Git -Repository $Path -Argument 'rev-list', '--left-right', '--count', 'HEAD...@{u}'
    $ahead, $behind = $counts -split '\s+'
    if ([int] $behind -gt 0) {
        $refusal = @{
            Message      = "Branch '$branch' is behind its upstream by $behind commit(s). Pull or rebase first."
            ErrorId      = 'BranchBehind'
            Category     = 'InvalidOperation'
            TargetObject = $branch
        }
        Write-Error @refusal -ErrorAction Stop
    }
    if ([int] $ahead -gt 0) {
        $refusal = @{
            Message      = "Branch '$branch' has $ahead unpushed commit(s). Push first."
            ErrorId      = 'BranchAhead'
            Category     = 'InvalidOperation'
            TargetObject = $branch
        }
        Write-Error @refusal -ErrorAction Stop
    }

    if (Invoke-Git -Repository $Path -Argument 'tag', '--list', $tag) {
        $refusal = @{
            Message      = "Tag '$tag' already exists locally."
            ErrorId      = 'TagExistsLocally'
            Category     = 'ResourceExists'
            TargetObject = $tag
        }
        Write-Error @refusal -ErrorAction Stop
    }
    if (Invoke-Git -Repository $Path -Argument 'ls-remote', '--tags', $remote, "refs/tags/$tag") {
        $refusal = @{
            Message      = "Tag '$tag' already exists on remote '$remote'."
            ErrorId      = 'TagExistsOnRemote'
            Category     = 'ResourceExists'
            TargetObject = $tag
        }
        Write-Error @refusal -ErrorAction Stop
    }

    if ($PSCmdlet.ShouldProcess($remote, "Create signed tag $tag and push it")) {
        Write-Information "Creating signed tag $tag"
        # --sign fails when no signing key is configured, which is the intent.
        $null = Invoke-Git -Repository $Path -Argument 'tag', '--sign', '--annotate', $tag, '-m', "Release version $tag"
        $null = Invoke-Git -Repository $Path -Argument 'push', $remote, $tag
        [pscustomobject] @{
            Tag    = $tag
            Remote = $remote
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    # Progress narration shows by default, since signing may raise a pinentry
    # prompt that is otherwise unexplained; -InformationAction still governs.
    if (-not $PSBoundParameters.ContainsKey('InformationAction')) {
        $InformationPreference = 'Continue'
    }
    $release = @{
        Version = $Version
        Path    = $PSScriptRoot
        Owner   = if ($env:MAIN_REPO_OWNER) { $env:MAIN_REPO_OWNER } else { 'shuwariafrica' }
        Name    = if ($env:MAIN_REPO_NAME) { $env:MAIN_REPO_NAME } else { 'hedwig' }
    }
    Publish-ReleaseTag @release
}
