#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Sets the text of the first edit control named Name in one process's
    windows, through UI Automation's value pattern.

.DESCRIPTION
    A WinUI text box takes the value pattern as a paste, which is how the
    window's suite types into it. Fails when no such control is found.

.PARAMETER ProcessId
    The process whose windows are searched.

.PARAMETER Name
    The control's name, as UI Automation reads it.

.PARAMETER Text
    What the control is set to.

.OUTPUTS
    A line saying which control was typed into.
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

    [Parameter(Mandatory)]
    [AllowEmptyString()]
    [string] $Text
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$root = [Windows.Automation.AutomationElement]::RootElement
$process = [Windows.Automation.PropertyCondition]::new(
    [Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
$named = [Windows.Automation.AndCondition]::new(
    [Windows.Automation.PropertyCondition]::new([Windows.Automation.AutomationElement]::NameProperty, $Name),
    [Windows.Automation.PropertyCondition]::new(
        [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Edit))
foreach ($window in $root.FindAll([Windows.Automation.TreeScope]::Children, $process)) {
    $found = $window.FindFirst([Windows.Automation.TreeScope]::Descendants, $named)
    if ($null -eq $found) { continue }
    $found.GetCurrentPattern([Windows.Automation.ValuePattern]::Pattern).SetValue($Text)
    "typed into `"$Name`""
    exit 0
}
throw "no box named `"$Name`" in process $ProcessId"
