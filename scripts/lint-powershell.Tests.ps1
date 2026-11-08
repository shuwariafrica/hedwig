#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester hands BeforeAll and BeforeEach variables to It blocks, unseen by the analyser.')]
param()

BeforeAll {
    # Dot-sourcing defines the functions and analyses nothing.
    . (Join-Path -Path $PSScriptRoot -ChildPath 'lint-powershell.ps1')

    $manifest = Join-Path -Path $PSScriptRoot -ChildPath 'tools.json'
    $pins = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).tools
    $analyser = @{
        Settings = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath 'PSScriptAnalyzerSettings.psd1'
        Version  = ($pins | Where-Object { $_.tool -eq 'PSScriptAnalyzer' }).version
    }
}

Describe 'Test-PowerShellFile' {
    BeforeEach {
        $outcomes = [Collections.Generic.Queue[pscustomobject]]::new()
        Mock Invoke-AnalyserProcess { $outcomes.Dequeue() }
        $test = @{ File = 'a.ps1'; Settings = 's.psd1'; Version = '1.0.0'; Attempts = 3; TimeoutSeconds = 10 }
    }

    It 'analyses again after a throw and takes the completed attempt''s findings' {
        $outcomes.Enqueue([pscustomobject] @{ Outcome = 'Threw'; Json = ''; Error = 'NullReferenceException' })
        $json = '[{"Line":3,"RuleName":"R","Message":"m"}]'
        $outcomes.Enqueue([pscustomobject] @{ Outcome = 'Completed'; Json = $json; Error = '' })

        $verdict = Test-PowerShellFile @test

        @($verdict.Findings).Count | Should -Be 1
        $verdict.Findings[0].RuleName | Should -BeExactly 'R'
        $verdict.Attempts.Outcome | Should -Be @('Threw', 'Completed')
    }

    It 'reports a file no attempt completed, with every attempt''s outcome, apart from findings' {
        foreach ($outcome in 'TimedOut', 'Threw', 'TimedOut') {
            $outcomes.Enqueue([pscustomobject] @{ Outcome = $outcome; Json = ''; Error = 'e' })
        }

        $verdict = Test-PowerShellFile @test

        $verdict.Findings | Should -BeNullOrEmpty
        $null -eq $verdict.Findings | Should -BeTrue
        $verdict.Attempts.Outcome | Should -Be @('TimedOut', 'Threw', 'TimedOut')
    }

    It 'takes a completed attempt with no output as no findings' {
        $outcomes.Enqueue([pscustomobject] @{ Outcome = 'Completed'; Json = ''; Error = '' })

        $verdict = Test-PowerShellFile @test

        $null -eq $verdict.Findings | Should -BeFalse
        @($verdict.Findings).Count | Should -Be 0
        Should -Invoke Invoke-AnalyserProcess -Times 1 -Exactly
    }
}

Describe 'Invoke-AnalyserProcess' {
    BeforeAll {
        $file = Join-Path -Path $TestDrive -ChildPath 'a script.ps1'
        Set-Content -LiteralPath $file -Value "Write-Host 'shown'"
    }

    It 'reports the analyser''s findings from a fresh process' {
        $result = Invoke-AnalyserProcess -File $file @analyser -TimeoutSeconds 300

        $result.Outcome | Should -BeExactly 'Completed'
        ($result.Json | ConvertFrom-Json).RuleName | Should -Contain 'PSAvoidUsingWriteHost'
    }

    It 'ends a process that does not answer in time and says so' {
        $result = Invoke-AnalyserProcess -File $file @analyser -TimeoutSeconds 0

        $result.Outcome | Should -BeExactly 'TimedOut'
    }

    It 'reports a process that throws' {
        $result = Invoke-AnalyserProcess -File $file -Settings $analyser.Settings -Version '0.0.1' -TimeoutSeconds 300

        $result.Outcome | Should -BeExactly 'Threw'
        $result.Error | Should -Not -BeNullOrEmpty
    }
}

Describe 'Write-AnalyserReport' {
    BeforeEach {
        $root = Join-Path -Path $TestDrive -ChildPath 'repository'
        $summary = Join-Path -Path $TestDrive -ChildPath "summary $(New-Guid).md"
        $verdicts = @(
            [pscustomobject] @{
                Path     = Join-Path -Path $root -ChildPath 'scripts' -AdditionalChildPath 'a.ps1'
                Findings = @(
                    [pscustomobject] @{ Line = 4; Column = 2; RuleName = 'PSAvoidUsingWriteHost'; Message = 'm' }
                )
                Attempts = @([pscustomobject] @{ Outcome = 'Completed'; Error = '' })
            }
            [pscustomobject] @{
                Path     = Join-Path -Path $root -ChildPath 'b.ps1'
                Findings = $null
                Attempts = @([pscustomobject] @{ Outcome = 'TimedOut'; Error = 'no answer' })
            }
        )
    }

    It 'annotates each finding on its line and each file not analysed, and summarises both' {
        $env:GITHUB_ACTIONS = 'true'
        $env:GITHUB_STEP_SUMMARY = $summary
        try {
            $lines = $verdicts | Write-AnalyserReport -Root $root
        } finally {
            Remove-Item -Path Env:GITHUB_ACTIONS, Env:GITHUB_STEP_SUMMARY
        }

        $lines[0] | Should -BeExactly '::error file=scripts/a.ps1,line=4,col=2,title=PSAvoidUsingWriteHost::m'
        $expected = '::error file=b.ps1,title=PSScriptAnalyzer did not complete::1 attempts. TimedOut: no answer'
        $lines[1] | Should -BeExactly $expected
        Get-Content -LiteralPath $summary | Should -Contain '| b.ps1 | not analysed | TimedOut |'
    }
}

Describe 'Get-PowerShellFile' {
    It 'emits the files git tracks and those under each folder named, nothing untracked' {
        $root = Join-Path -Path $TestDrive -ChildPath 'tracked'
        $blocks = Join-Path -Path $TestDrive -ChildPath 'blocks'
        $null = New-Item -ItemType Directory -Force -Path $root, $blocks
        & git -C $root init --quiet
        Set-Content -LiteralPath (Join-Path -Path $root -ChildPath 'tracked.ps1') -Value '1'
        Set-Content -LiteralPath (Join-Path -Path $root -ChildPath 'untracked.ps1') -Value '1'
        Set-Content -LiteralPath (Join-Path -Path $blocks -ChildPath 'ci.test.3.ps1') -Value '1'
        & git -C $root add -- tracked.ps1

        $files = Get-PowerShellFile -Root $root -Folder $blocks | ForEach-Object { Split-Path -Path $_ -Leaf }

        $files | Should -Be @('tracked.ps1', 'ci.test.3.ps1')
    }
}

Describe 'The script' {
    It 'refuses to run anywhere but Windows' -Skip:$IsWindows {
        { & (Join-Path -Path $PSScriptRoot -ChildPath 'lint-powershell.ps1') } | Should -Throw '*Run this on Windows*'
    }
}
