#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Writes every run: block of the repository's workflows to a file of its own,
    named for its workflow, job and step, so ShellCheck, shfmt and
    PSScriptAnalyzer check them as they check any script.

.DESCRIPTION
    A block's shell is its step's shell:, else its job's defaults, else its
    workflow's defaults. A block with none of these is refused: a runner's
    default differs between Linux and Windows. bash blocks are written as
    .sh, pwsh blocks as .ps1; any other shell is refused.

    Needs yq on PATH (fetch-tools.ps1 -Set gate pins it), which reads each
    workflow with its anchors expanded.

.PARAMETER Destination
    The folder to write into; emptied first. Keep it inside the repository,
    where .shellcheckrc and .editorconfig apply.

.EXAMPLE
    ./scripts/export-run-blocks.ps1 -Destination target/run-blocks

.OUTPUTS
    One object per block: Workflow, Job, Step, Shell and the File written.
#>
[CmdletBinding(SupportsShouldProcess)]
[OutputType([pscustomobject])]
param(
    [Parameter(Mandatory)]
    [string] $Destination,

    [string] $Workflows = (Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '.github', 'workflows')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-Workflow {
    <#
    .SYNOPSIS
        Reads a workflow file with its anchors expanded and emits it as a
        hashtable.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $json = & yq --output-format=json 'explode(.)' $Path
    if ($LASTEXITCODE -ne 0) {
        throw "yq could not read $Path (exit code $LASTEXITCODE)"
    }
    ($json -join "`n") | ConvertFrom-Json -AsHashtable
}

function Get-Setting {
    <#
    .SYNOPSIS
        Emits the value at a path of keys in nested hashtables, or nothing
        where any key is absent.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object] $Table,

        [Parameter(Mandatory)]
        [string[]] $Key
    )

    $value = $Table
    foreach ($name in $Key) {
        if ($value -isnot [System.Collections.IDictionary] -or -not $value.Contains($name)) {
            return
        }
        $value = $value[$name]
    }
    $value
}

function Get-RunBlock {
    <#
    .SYNOPSIS
        Emits Job, Step, Shell and Script for each run: block in a workflow,
        a step inside a parallel: group named by its group's index and its own.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [hashtable] $Workflow,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $workflowShell = Get-Setting -Table $Workflow -Key 'defaults', 'run', 'shell'
    $jobs = Get-Setting -Table $Workflow -Key 'jobs'
    if (-not $jobs) {
        return
    }
    foreach ($job in $jobs.Keys) {
        $jobShell = Get-Setting -Table $jobs[$job] -Key 'defaults', 'run', 'shell'
        $steps = @(Get-Setting -Table $jobs[$job] -Key 'steps')
        $flat = for ($index = 0; $index -lt $steps.Count; $index++) {
            $group = Get-Setting -Table $steps[$index] -Key 'parallel'
            if ($group) {
                $inner = @($group)
                for ($member = 0; $member -lt $inner.Count; $member++) {
                    [pscustomobject] @{ Step = "$index.$member"; Body = $inner[$member] }
                }
            } else {
                [pscustomobject] @{ Step = "$index"; Body = $steps[$index] }
            }
        }
        foreach ($step in $flat) {
            $script = Get-Setting -Table $step.Body -Key 'run'
            if ($null -eq $script) {
                continue
            }
            $shell = @(Get-Setting -Table $step.Body -Key 'shell'; $jobShell; $workflowShell) |
                Where-Object { $_ } | Select-Object -First 1
            if (-not $shell) {
                throw "$Name, job $job, step $($step.Step) declares no shell; set shell: or the job's defaults."
            }
            [pscustomobject] @{ Job = $job; Step = $step.Step; Shell = $shell; Script = $script }
        }
    }
}

function Export-RunBlock {
    <#
    .SYNOPSIS
        Writes every run: block of the workflows in a folder into another,
        emitting what it wrote.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Workflows,

        [Parameter(Mandatory)]
        [string] $Destination
    )

    if (-not (Get-Command -Name 'yq' -CommandType Application -ErrorAction Ignore)) {
        throw 'No yq on PATH; ./scripts/fetch-tools.ps1 -Set gate fetches the pinned one.'
    }
    if (-not $PSCmdlet.ShouldProcess($Destination, 'Write the workflows'' run blocks')) {
        return
    }
    Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction Ignore
    $null = New-Item -ItemType Directory -Force -Path $Destination
    $files = Get-ChildItem -LiteralPath $Workflows -File | Where-Object { $_.Extension -in '.yml', '.yaml' }
    foreach ($file in $files) {
        $name = $file.BaseName
        foreach ($block in Get-RunBlock -Workflow (ConvertFrom-Workflow -Path $file.FullName) -Name $file.Name) {
            $where = "$($file.Name), job $($block.Job), step $($block.Step)"
            $extension = switch ($block.Shell) {
                'bash' { 'sh' }
                'pwsh' { 'ps1' }
                default { throw "$where runs under '$_'; declare bash or pwsh." }
            }
            $path = Join-Path -Path $Destination -ChildPath "$name.$($block.Job).$($block.Step).$extension"
            # LF endings and a final newline, as the block ends in the workflow.
            $text = $block.Script.Replace("`r`n", "`n").TrimEnd("`n") + "`n"
            [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
            [pscustomobject] @{
                Workflow = $file.Name
                Job      = $block.Job
                Step     = $block.Step
                Shell    = $block.Shell
                File     = $path
            }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Export-RunBlock -Workflows ([IO.Path]::GetFullPath($Workflows)) -Destination ([IO.Path]::GetFullPath($Destination))
}
