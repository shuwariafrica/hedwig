#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Lists what UI Automation reads of one process's top-level window.

.DESCRIPTION
    One line per element of the control view, indented by its depth: its
    control type, its name, whether it takes the keyboard, its heading level
    where it has one, and its bounding rectangle; then a line naming the
    element that has the keyboard. The window's suite reads the window
    through it as assistive technology does.

.PARAMETER ProcessId
    The process whose window is read.

.PARAMETER Depth
    How many levels below the window are listed.

.OUTPUTS
    One string per line.
#>
[CmdletBinding()]
[OutputType([string])]
param(
    [Parameter(Mandatory)]
    [ValidateRange(1, [int]::MaxValue)]
    [int] $ProcessId,

    [ValidateRange(0, 64)]
    [int] $Depth = 12
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

function Get-ElementLine {
    <#
    .SYNOPSIS
        Emits the line of one element and of each element beneath it, down
        to the depth asked for.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [Windows.Automation.AutomationElement] $Element,

        [Parameter(Mandatory)]
        [int] $Level,

        [Parameter(Mandatory)]
        [int] $Deepest
    )

    if ($Level -gt $Deepest) { return }
    $current = $Element.Current
    $rectangle = $current.BoundingRectangle
    $box = if ($rectangle.IsEmpty) {
        '-'
    } else {
        '{0},{1} {2}x{3}' -f [int] $rectangle.X, [int] $rectangle.Y, [int] $rectangle.Width, [int] $rectangle.Height
    }
    $type = $current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
    $heading = $Element.GetCurrentPropertyValue([Windows.Automation.AutomationElement]::HeadingLevelProperty)
    $said = if ($heading -eq [Windows.Automation.AutomationHeadingLevel]::None) { '' } else { " heading=$heading" }
    '{0}{1} "{2}" focusable={3}{4} [{5}]' -f ('  ' * $Level), $type, $current.Name, $current.IsKeyboardFocusable,
    $said, $box
    $child = $walker.GetFirstChild($Element)
    while ($null -ne $child) {
        Get-ElementLine -Element $child -Level ($Level + 1) -Deepest $Deepest
        $child = $walker.GetNextSibling($child)
    }
}

$walker = [Windows.Automation.TreeWalker]::ControlViewWalker
$condition = [Windows.Automation.PropertyCondition]::new(
    [Windows.Automation.AutomationElement]::ProcessIdProperty, $ProcessId)
$root = [Windows.Automation.AutomationElement]::RootElement
$window = $root.FindFirst([Windows.Automation.TreeScope]::Children, $condition)
if ($null -eq $window) { throw "no window for process $ProcessId" }
Get-ElementLine -Element $window -Level 0 -Deepest $Depth
$focused = [Windows.Automation.AutomationElement]::FocusedElement
if ($null -ne $focused) {
    $type = $focused.Current.ControlType.ProgrammaticName -replace '^ControlType\.', ''
    'keyboard: {0} "{1}" in process {2}' -f $type, $focused.Current.Name, $focused.Current.ProcessId
}
