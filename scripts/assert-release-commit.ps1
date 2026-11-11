#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Admits a commit for release only where it is on main's first-parent line
    and every crate of the workspace states the release's version there.

.DESCRIPTION
    A commit reached only through a merge's second parent is one of a branch
    main merged, whose tree main never held at that point; it is refused, as
    is a commit main does not reach at all. At the commit itself, the root
    manifest's [workspace.package] version, each member's version - inherited
    from the workspace or stated - and the version Cargo.lock records for
    each member must all be the release's.

    The release workflow runs it against the pushed tag's commit, with main's
    whole history fetched.

.PARAMETER Commit
    The commit to admit, by any name git resolves.

.PARAMETER Version
    The release's version, without the leading 'v'.

.PARAMETER Branch
    The branch whose first-parent line the commit must be on.

.PARAMETER Path
    The repository.

.OUTPUTS
    The commit admitted, by its full name, and the version.

.EXAMPLE
    ./scripts/assert-release-commit.ps1 -Commit v0.2.0-alpha.1 -Version 0.2.0-alpha.1
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Commit,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Version,

    [ValidateNotNullOrEmpty()]
    [string] $Branch = 'origin/main',

    [ValidateNotNullOrEmpty()]
    [string] $Path = (Split-Path -Path $PSScriptRoot -Parent)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Git {
    <#
    .SYNOPSIS
        Runs git in the repository and emits its standard output lines,
        throwing on a non-zero exit with git's standard error in the message.
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

function Deny-Release {
    <#
    .SYNOPSIS
        Refuses the release with a message and an error identifier a caller
        can tell apart.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Message,
        [Parameter(Mandatory)] [string] $ErrorId,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Target
    )

    $refusal = @{
        Message      = $Message
        ErrorId      = $ErrorId
        Category     = 'InvalidData'
        TargetObject = $Target
    }
    Write-Error @refusal -ErrorAction Stop
}

function Get-TableValue {
    <#
    .SYNOPSIS
        Emits the string value of `Key` in the TOML table `Table` of a
        manifest's lines, or nothing where the table does not set it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string[]] $Line,
        [Parameter(Mandatory)] [string] $Table,
        [Parameter(Mandatory)] [string] $Key
    )

    $current = ''
    foreach ($text in $Line) {
        if ($text -cmatch '^\s*\[([^\]]+)\]\s*$') {
            $current = $Matches[1].Trim()
        } elseif ($current -ceq $Table -and $text -cmatch "^\s*$([regex]::Escape($Key))\s*=\s*(.+?)\s*$") {
            return $Matches[1]
        }
    }
}

function Assert-ReleaseCommit {
    <#
    .SYNOPSIS
        Admits Commit for the release of Version, or refuses it saying why.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Commit,
        [Parameter(Mandatory)] [string] $Version,
        [Parameter(Mandatory)] [string] $Branch,
        [Parameter(Mandatory)] [string] $Path
    )

    $resolved = Invoke-Git -Repository $Path -Argument 'rev-parse', '--verify', "$Commit^{commit}"
    $line = Invoke-Git -Repository $Path -Argument 'rev-list', '--first-parent', $Branch
    if ($line -notcontains $resolved) {
        Deny-Release -ErrorId 'NotOnFirstParentLine' -Target $resolved -Message (
            "$Commit ($resolved) is not on ${Branch}'s first-parent line: a commit of a merged branch " +
            'is released only as the merge that took it.')
    }

    $root = @(Invoke-Git -Repository $Path -Argument 'show', "${resolved}:Cargo.toml")
    $stated = Get-TableValue -Line $root -Table 'workspace.package' -Key 'version'
    if ($stated -cne "`"$Version`"") {
        Deny-Release -ErrorId 'ManifestVersionMismatch' -Target 'Cargo.toml' -Message (
            "Cargo.toml's [workspace.package] states version $stated at $resolved, not `"$Version`".")
    }

    $joined = $root -join "`n"
    if ($joined -notmatch '(?s)\[workspace\][^\[]*?members\s*=\s*\[(?<members>[^\]]*)\]') {
        Deny-Release -ErrorId 'MembersMissing' -Target 'Cargo.toml' -Message (
            "Cargo.toml names no workspace members at $resolved.")
    }
    $members = [regex]::Matches($Matches.members, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }
    $lock = @(Invoke-Git -Repository $Path -Argument 'show', "${resolved}:Cargo.lock")
    foreach ($member in $members) {
        $manifest = @(Invoke-Git -Repository $Path -Argument 'show', "${resolved}:$member/Cargo.toml")
        $name = Get-TableValue -Line $manifest -Table 'package' -Key 'name'
        $inherited = Get-TableValue -Line $manifest -Table 'package' -Key 'version.workspace'
        $own = Get-TableValue -Line $manifest -Table 'package' -Key 'version'
        if ($inherited -cne 'true' -and $own -cne "`"$Version`"") {
            Deny-Release -ErrorId 'MemberVersionMismatch' -Target $member -Message (
                "$member states version $own at $resolved, and does not inherit the workspace's.")
        }
        $index = [Array]::IndexOf($lock, "name = $name")
        $locked = if ($index -ge 0 -and $index + 1 -lt $lock.Count) { $lock[$index + 1] } else { '' }
        if ($locked -cne "version = `"$Version`"") {
            Deny-Release -ErrorId 'LockfileVersionMismatch' -Target $member -Message (
                "Cargo.lock records $name at '$locked' at $resolved, not version `"$Version`". " +
                "Run 'cargo update -w' and commit.")
        }
    }

    [pscustomobject] @{
        Commit  = $resolved
        Version = $Version
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $release = @{
        Commit  = $Commit
        Version = $Version
        Branch  = $Branch
        Path    = $Path
    }
    Assert-ReleaseCommit @release
}
