#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Runs PSScriptAnalyzer over every PowerShell file the repository tracks, and
    any folder named, each file in a fresh process, and fails on any finding or
    on a file the analyser never completed.

.DESCRIPTION
    PSScriptAnalyzer 1.25.0 can throw a NullReferenceException on, or hang
    over, a file it analyses cleanly on another run, when PSUseCorrectCasing
    runs beside the other rules. Each file is therefore analysed in a process
    of its own, in two passes - every rule but that one, then that one alone -
    bounded by -TimeoutSeconds, and an attempt that throws or times out is made
    again, up to -Attempts in all. A completed attempt's findings are the
    verdict; a file with no completed attempt is reported with every attempt's
    outcome, apart from findings.

    Run on Windows: the analyser resolves aliases from the session it runs in,
    and PowerShell defines aliases such as ls, cat and sort on Windows alone.

    Inside GitHub Actions each finding is an annotation on its line, and the
    job summary has a row per file.

.PARAMETER Path
    Folders whose .ps1, .psm1 and .psd1 files are analysed beside the tracked
    ones, such as the run blocks export-run-blocks.ps1 wrote.

.PARAMETER Attempts
    Attempts per file before it counts as not analysed.

.PARAMETER TimeoutSeconds
    How long one attempt may run.

.EXAMPLE
    ./scripts/lint-powershell.ps1 -Path target/run-blocks

.OUTPUTS
    One object per file: Path, Findings (the analyser's records), and
    Attempts (each attempt's outcome: Completed, Threw or TimedOut).

    Exit status 0 when every file completed with no finding, 1 when a
    completed file has findings, 2 when a file never completed.
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [string[]] $Path = @(),

    [ValidateRange(1, 10)]
    [int] $Attempts = 3,

    [ValidateRange(10, 3600)]
    [int] $TimeoutSeconds = 300
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-PowerShellFile {
    <#
    .SYNOPSIS
        Emits the full path of every PowerShell file git tracks under a
        repository root, then of every one under each folder named.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [string[]] $Folder = @()
    )

    $tracked = & git -C $Root ls-files -- '*.ps1' '*.psm1' '*.psd1'
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed in $Root (exit code $LASTEXITCODE)"
    }
    foreach ($file in $tracked) {
        Join-Path -Path $Root -ChildPath $file
    }
    foreach ($name in $Folder) {
        Get-ChildItem -LiteralPath $name -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1' |
            ForEach-Object { $_.FullName }
    }
}

function Invoke-AnalyserProcess {
    <#
    .SYNOPSIS
        Analyses one file in a fresh pwsh and emits Outcome (Completed, Threw,
        TimedOut), the findings as JSON, and what it wrote to standard error.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $File,

        [Parameter(Mandatory)]
        [string] $Settings,

        [Parameter(Mandatory)]
        [string] $Version,

        [Parameter(Mandatory)]
        [int] $TimeoutSeconds
    )

    $quoted = { param($Text) "'" + $Text.Replace("'", "''") + "'" }
    $child = @(
        'Set-StrictMode -Version Latest'
        "`$ErrorActionPreference = 'Stop'"
        "`$PSStyle.OutputRendering = 'PlainText'"
        "Import-Module -Name PSScriptAnalyzer -RequiredVersion $(& $quoted $Version)"
        "`$settings = Import-PowerShellDataFile -LiteralPath $(& $quoted $Settings)"
        # PSScriptAnalyzer 1.25.0 runs every rule at once, and PSUseCorrectCasing among the others
        # throws or hangs on some runs; alone it does neither. One pass until a release fixes it.
        "`$rest = `$settings.Clone()"
        "`$rest.ExcludeRules = @('PSUseCorrectCasing')"
        "`$casing = @{ IncludeRules = @('PSUseCorrectCasing'); Severity = `$settings.Severity }"
        "if (`$settings.Rules.ContainsKey('PSUseCorrectCasing')) {"
        "    `$casing.Rules = @{ PSUseCorrectCasing = `$settings.Rules.PSUseCorrectCasing }"
        '}'
        "`$path = $(& $quoted $File)"
        "`$found = @(Invoke-ScriptAnalyzer -Path `$path -Settings `$rest)"
        "`$found += @(Invoke-ScriptAnalyzer -Path `$path -Settings `$casing)"
        "`$found | Select-Object -Property Line, Column, RuleName, Severity, Message |"
        '    ConvertTo-Json -AsArray -Compress -Depth 2'
    ) -join [Environment]::NewLine

    $start = [Diagnostics.ProcessStartInfo]::new((Get-Process -Id $PID).Path)
    foreach ($argument in '-NoProfile', '-NonInteractive', '-Command', $child) {
        $start.ArgumentList.Add($argument)
    }
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.UseShellExecute = $false
    $process = [Diagnostics.Process]::Start($start)
    try {
        # Closed at once, so the child never waits on whatever input its parent was given.
        $process.StandardInput.Close()
        # Both streams are read while the child runs, so neither fills and
        # stalls it.
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            return [pscustomobject] @{ Outcome = 'TimedOut'; Json = ''; Error = "no answer in $TimeoutSeconds s" }
        }
        $process.WaitForExit()
        $outcome = if ($process.ExitCode -eq 0) { 'Completed' } else { 'Threw' }
        [pscustomobject] @{ Outcome = $outcome; Json = $output.Result; Error = $errors.Result.Trim() }
    } finally {
        $process.Dispose()
    }
}

function Test-PowerShellFile {
    <#
    .SYNOPSIS
        Analyses one file until an attempt completes or the attempts run out,
        and emits Path, Findings and Attempts.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $File,

        [Parameter(Mandatory)]
        [string] $Settings,

        [Parameter(Mandatory)]
        [string] $Version,

        [Parameter(Mandatory)]
        [int] $Attempts,

        [Parameter(Mandatory)]
        [int] $TimeoutSeconds
    )

    $made = [Collections.Generic.List[pscustomobject]]::new()
    foreach ($attempt in 1..$Attempts) {
        $analysis = @{
            File           = $File
            Settings       = $Settings
            Version        = $Version
            TimeoutSeconds = $TimeoutSeconds
        }
        $result = Invoke-AnalyserProcess @analysis
        $made.Add([pscustomobject] @{ Attempt = $attempt; Outcome = $result.Outcome; Error = $result.Error })
        if ($result.Outcome -eq 'Completed') {
            $findings = @(if ($result.Json.Trim()) { $result.Json | ConvertFrom-Json })
            return [pscustomobject] @{ Path = $File; Findings = $findings; Attempts = $made.ToArray() }
        }
    }
    [pscustomobject] @{ Path = $File; Findings = $null; Attempts = $made.ToArray() }
}

function Write-AnalyserReport {
    <#
    .SYNOPSIS
        Writes each file's verdict as GitHub Actions annotations and a job
        summary row, or as warnings outside GitHub Actions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [pscustomobject] $Verdict,

        [Parameter(Mandatory)]
        [string] $Root
    )

    begin {
        $actions = [bool] $env:GITHUB_ACTIONS
        $rows = [Collections.Generic.List[string]]::new()
    }
    process {
        $relative = [IO.Path]::GetRelativePath($Root, $Verdict.Path).Replace('\', '/')
        $tries = ($Verdict.Attempts | ForEach-Object { $_.Outcome }) -join ', '
        if ($null -eq $Verdict.Findings) {
            $reasons = ($Verdict.Attempts | ForEach-Object {
                    "$($_.Outcome): $($_.Error -replace '\s+', ' ')"
                }) -join ' | '
            $title = 'title=PSScriptAnalyzer did not complete'
            $line = "::error file=$relative,$title::$($Verdict.Attempts.Count) attempts. $reasons"
            if ($actions) { Write-Output $line } else { Write-Warning $line }
            $rows.Add("| $relative | not analysed | $tries |")
            return
        }
        foreach ($finding in $Verdict.Findings) {
            $at = "file=$relative,line=$($finding.Line),col=$($finding.Column)"
            $line = "::error $at,title=$($finding.RuleName)::$($finding.Message)"
            if ($actions) { Write-Output $line } else { Write-Warning $line }
        }
        $rows.Add("| $relative | $(@($Verdict.Findings).Count) findings | $tries |")
    }
    end {
        if ($actions -and $env:GITHUB_STEP_SUMMARY) {
            $summary = @('| File | Verdict | Attempts |', '| --- | --- | --- |') + $rows
            Add-Content -LiteralPath $env:GITHUB_STEP_SUMMARY -Value $summary -Encoding utf8
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not $IsWindows) {
        throw 'Run this on Windows: the analyser checks aliases against the session it runs in.'
    }
    $root = [IO.Path]::GetFullPath((Join-Path -Path $PSScriptRoot -ChildPath '..'))
    $manifest = Join-Path -Path $PSScriptRoot -ChildPath 'tools.json'
    $pins = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).tools
    $test = @{
        Settings       = Join-Path -Path $root -ChildPath 'PSScriptAnalyzerSettings.psd1'
        Version        = ($pins | Where-Object { $_.tool -eq 'PSScriptAnalyzer' }).version
        Attempts       = $Attempts
        TimeoutSeconds = $TimeoutSeconds
    }
    $verdicts = foreach ($file in Get-PowerShellFile -Root $root -Folder $Path) {
        Test-PowerShellFile -File $file @test
    }
    $verdicts | Write-AnalyserReport -Root $root
    $verdicts
    if ($verdicts | Where-Object { $null -eq $_.Findings }) {
        exit 2
    }
    if ($verdicts | Where-Object { @($_.Findings).Count -gt 0 }) {
        exit 1
    }
}
