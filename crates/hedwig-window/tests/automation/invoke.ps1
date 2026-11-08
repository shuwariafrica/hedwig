#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Presses, or with -Expand expands, the first enabled control named Name in
    one process's windows, through UI Automation, as assistive technology
    does.

.DESCRIPTION
    Pressing takes the invoke pattern; expanding takes the expand-collapse
    pattern, which an expander's header has. Fails when no such control is
    found.

.PARAMETER ProcessId
    The process whose windows are searched.

.PARAMETER Name
    The control's name, as UI Automation reads it.

.PARAMETER Expand
    Expands the control instead of pressing it.

.OUTPUTS
    A line saying what was pressed or expanded.
#>
[CmdletBinding()]
[OutputType([string])]
param(
    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int] $ProcessId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $Name,

    [switch] $Expand
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$root = [Windows.Automation.AutomationElement]::RootElement
$process = [Windows.Automation.PropertyCondition]::new(
    [Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
$named = [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty, $Name)
foreach ($window in $root.FindAll([Windows.Automation.TreeScope]::Children, $process)) {
    foreach ($found in $window.FindAll([Windows.Automation.TreeScope]::Descendants, $named)) {
        $pattern = $null
        if ($Expand) {
            if ($found.TryGetCurrentPattern([Windows.Automation.ExpandCollapsePattern]::Pattern, [ref] $pattern)) {
                $pattern.Expand()
                "expanded `"$Name`""
                exit 0
            }
        } elseif ($found.Current.IsEnabled -and
            $found.TryGetCurrentPattern([Windows.Automation.InvokePattern]::Pattern, [ref] $pattern)) {
            $pattern.Invoke()
            "pressed `"$Name`" ($($found.Current.ControlType.ProgrammaticName))"
            exit 0
        }
    }
}
throw "nothing named `"$Name`" in process $ProcessId"
