#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates and pushes a signed git release tag.

.DESCRIPTION
    Cargo has no hook for deriving the package version, so Cargo.toml is
    authoritative and the tag is checked against it rather than the other way
    round. Bump Cargo.toml, run `cargo update -w`, commit, then run this.

    Allowed pre-release classifiers, case-sensitive: alpha.N, beta.N, rc.N.

.PARAMETER Version
    Semantic version to release, without the leading 'v'. For example 1.2.3,
    1.2.3-alpha.1, 1.2.3-rc.2.

.EXAMPLE
    ./release.ps1 0.1.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string] $Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoOwner = if ($env:MAIN_REPO_OWNER) { $env:MAIN_REPO_OWNER } else { 'shuwariafrica' }
$RepoName = if ($env:MAIN_REPO_NAME) { $env:MAIN_REPO_NAME } else { 'hedwig' }

function Fail([string] $Message) {
    Write-Host "Error: $Message" -ForegroundColor Red
    exit 1
}

function Info([string] $Message) {
    Write-Host $Message -ForegroundColor Yellow
}

function Git-Output {
    $output = & git @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "git $($args -join ' ') failed: $output"
    }
    return ($output | Out-String).Trim()
}

$semver = '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)' +
          '(-(alpha|beta|rc)\.([1-9][0-9]*))?' +
          '(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if ($Version -cnotmatch $semver) {
    Fail "Version '$Version' is not valid. See Get-Help ./release.ps1 for allowed formats."
}

if (Git-Output status --porcelain) {
    & git status
    Fail 'Commit or stash your changes before creating a release tag.'
}

# Checked here because in CI a mismatch, or a lockfile left stale for --locked,
# surfaces only after the whole matrix has run.
$manifestVersion = (Select-String -Path Cargo.toml -Pattern '^version = "(.*)"' |
    Select-Object -First 1).Matches.Groups[1].Value
if ($manifestVersion -cne $Version) {
    Fail "Cargo.toml declares version '$manifestVersion', not '$Version'. Update and commit it first."
}

$lockVersion = (Get-Content Cargo.lock |
    Select-String -Pattern "^name = `"$RepoName`"$" -Context 0, 1).Context.PostContext[0]
if ($lockVersion -cne "version = `"$Version`"") {
    Fail "Cargo.lock does not record version '$Version'. Run 'cargo update -w' and commit."
}

$tag = "v$Version"

$remoteUrls = @(
    "https://github.com/$RepoOwner/$RepoName",
    "https://github.com/$RepoOwner/$RepoName.git",
    "git@github.com:$RepoOwner/$RepoName.git"
)
$remote = & git remote | Where-Object {
    (& git remote get-url --all $_) | Where-Object { $remoteUrls -contains $_ }
} | Select-Object -First 1
if (-not $remote) {
    Fail "No git remote points to $RepoOwner/$RepoName. Add one and try again."
}

$branch = Git-Output rev-parse --abbrev-ref HEAD
if ($branch -eq 'HEAD') {
    Fail 'Detached HEAD is not supported. Check out a branch with an upstream tracking branch.'
}

& git rev-parse --abbrev-ref --symbolic-full-name '@{u}' *> $null
if ($LASTEXITCODE -ne 0) {
    Fail "Branch '$branch' has no upstream. Push it with -u before releasing."
}
$upstream = Git-Output rev-parse --abbrev-ref --symbolic-full-name '@{u}'
if ($upstream.Split('/')[0] -ne $remote) {
    Fail "Upstream for '$branch' is '$($upstream.Split('/')[0])', but must be '$remote'."
}

Info "Fetching from '$remote'..."
& git fetch --prune $remote *> $null
& git fetch --tags --prune $remote *> $null

$counts = (Git-Output rev-list --left-right --count 'HEAD...@{u}') -split '\s+'
if ([int]$counts[1] -gt 0) {
    Fail "Branch '$branch' is behind its upstream by $($counts[1]) commit(s). Pull or rebase first."
}
if ([int]$counts[0] -gt 0) {
    Fail "Branch '$branch' has $($counts[0]) unpushed commit(s). Push first."
}

& git show-ref --tags --verify --quiet "refs/tags/$tag"
if ($LASTEXITCODE -eq 0) {
    Fail "Tag '$tag' already exists locally."
}
if (Git-Output ls-remote --tags $remote "refs/tags/$tag") {
    Fail "Tag '$tag' already exists on remote '$remote'."
}

Info "Creating signed tag $tag"
# --sign fails when no signing key is configured, which is the intent.
& git tag --sign --annotate $tag -m "Release version $tag"
if ($LASTEXITCODE -ne 0) { Fail "Could not create signed tag '$tag'." }

& git push $remote $tag
if ($LASTEXITCODE -ne 0) { Fail "Could not push tag '$tag' to '$remote'." }

Write-Host "Pushed $tag to $remote." -ForegroundColor Green
