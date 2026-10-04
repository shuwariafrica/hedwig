#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    $script = Join-Path -Path $PSScriptRoot -ChildPath 'fetch-test-tools.ps1'
    # Dot-sourcing defines the functions and fetches nothing.
    . $script

    function Get-TextSha256 {
        param([string] $Text)

        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))
    }
}

Describe 'Save-VerifiedFile' {
    BeforeEach {
        # What the download mock writes and the call under test checks; one
        # object, since a test changes what is served. TestDrive lasts the
        # whole Describe, so each test has a folder of its own.
        $fixture = [pscustomobject] @{
            Folder = Join-Path -Path $TestDrive -ChildPath "test tools $(New-Guid)"
            Served = 'the artifact as served'
        }
        $file = @{
            Uri    = 'https://example.org/artifact.zip'
            Path   = Join-Path -Path $fixture.Folder -ChildPath 'artifact.zip'
            Sha256 = Get-TextSha256 -Text $fixture.Served
        }
        Mock Invoke-Download {
            Set-Content -LiteralPath $OutFile -Value $fixture.Served -NoNewline
        } -ParameterFilter { $Uri -ceq $file.Uri }
    }

    It 'downloads a missing file and keeps it when its SHA-256 is the pinned one' {
        Save-VerifiedFile @file | Should -BeExactly $file.Path

        Get-Content -LiteralPath $file.Path -Raw | Should -BeExactly $fixture.Served
        Should -Invoke Invoke-Download -Times 1 -Exactly
    }

    It 'keeps a file already verified without downloading it again' {
        $null = New-Item -ItemType Directory -Force -Path $fixture.Folder
        Set-Content -LiteralPath $file.Path -Value $fixture.Served -NoNewline

        Save-VerifiedFile @file | Should -BeExactly $file.Path

        Should -Invoke Invoke-Download -Times 0 -Exactly
    }

    It 'replaces a file whose SHA-256 is not the pinned one' {
        $null = New-Item -ItemType Directory -Force -Path $fixture.Folder
        Set-Content -LiteralPath $file.Path -Value 'an earlier release' -NoNewline

        Save-VerifiedFile @file | Should -BeExactly $file.Path

        Get-Content -LiteralPath $file.Path -Raw | Should -BeExactly $fixture.Served
    }

    It 'refuses a download whose SHA-256 is not the pinned one and keeps nothing of it' {
        $fixture.Served = 'not what was pinned'

        { Save-VerifiedFile @file } | Should -Throw "*has SHA-256 *, not the pinned $($file.Sha256)"

        Test-Path -LiteralPath $file.Path | Should -BeFalse
        Test-Path -LiteralPath "$($file.Path).partial" | Should -BeFalse
    }

    It 'keeps nothing of a download that fails part way' {
        Mock Invoke-Download {
            Set-Content -LiteralPath $OutFile -Value 'the first half' -NoNewline
            throw 'curl could not download https://example.org/artifact.zip (exit code 18)'
        } -ParameterFilter { $Uri -ceq $file.Uri }

        { Save-VerifiedFile @file } | Should -Throw '*exit code 18*'

        Test-Path -LiteralPath $file.Path | Should -BeFalse
        Test-Path -LiteralPath "$($file.Path).partial" | Should -BeFalse
    }

    It 'writes nothing under -WhatIf' {
        Save-VerifiedFile @file -WhatIf | Should -BeNullOrEmpty

        Test-Path -LiteralPath $fixture.Folder | Should -BeFalse
        Should -Invoke Invoke-Download -Times 0 -Exactly
    }
}

Describe 'Invoke-Download' {
    It 'asks curl for the URI over IPv4, failing on an HTTP error, into the file named' {
        $download = @{
            Uri     = 'https://example.org/artifact.zip'
            OutFile = Join-Path -Path $TestDrive -ChildPath 'artifact.zip'
        }
        Mock Invoke-Curl { $global:LASTEXITCODE = 0 }

        Invoke-Download @download

        Should -Invoke Invoke-Curl -Times 1 -Exactly -ParameterFilter {
            $Argument -ccontains '-4' -and $Argument -ccontains '--fail' -and
            $Argument[-1] -ceq $download.Uri -and
            $Argument[[array]::IndexOf($Argument, '--output') + 1] -ceq $download.OutFile
        }
    }

    It 'throws when curl exits with a failure, naming the URI and the status' {
        $download = @{
            Uri     = 'https://example.org/missing.zip'
            OutFile = Join-Path -Path $TestDrive -ChildPath 'missing.zip'
        }
        Mock Invoke-Curl { $global:LASTEXITCODE = 22 }

        { Invoke-Download @download } | Should -Throw "*$($download.Uri)*exit code 22*"
    }
}

Describe 'Save-TestTool' {
    BeforeEach {
        Mock Save-VerifiedFile { $Path }
        Mock Expand-GnuPG { $Destination }
        Mock Expand-PlatformTool {
            Join-Path -Path $Destination -ChildPath 'platform-tools' -AdditionalChildPath 'adb.exe'
        }
    }

    It 'emits the variable each suite reads, naming what was laid out for it' {
        $root = Join-Path -Path $TestDrive -ChildPath 'test tools'

        $emitted = @(Save-TestTool -Path $root)

        $emitted.Name | Should -Be @('HEDWIG_GNUPG', 'HEDWIG_ADB', 'HEDWIG_ADB_OUTDATED', 'HEDWIG_PYSERIAL')
        $emitted.Value | Should -Be @(
            Join-Path -Path $root -ChildPath 'gnupg-2.5.24'
            Join-Path -Path $root -ChildPath 'platform-tools-37.0.1' -AdditionalChildPath 'platform-tools', 'adb.exe'
            Join-Path -Path $root -ChildPath 'platform-tools-34.0.5' -AdditionalChildPath 'platform-tools', 'adb.exe'
            Join-Path -Path $root -ChildPath 'pyserial-3.5-py2.py3-none-any.whl'
        )
    }

    It 'emits nothing for an artifact it did not lay out' {
        Mock Save-VerifiedFile { } -ParameterFilter { $Path -like '*.wixlib' }

        $emitted = @(Save-TestTool -Path (Join-Path -Path $TestDrive -ChildPath 'test tools'))

        $emitted.Name | Should -Not -Contain 'HEDWIG_GNUPG'
        Should -Invoke Expand-GnuPG -Times 0 -Exactly
    }

    It 'pins every download by SHA-256' {
        $null = Save-TestTool -Path (Join-Path -Path $TestDrive -ChildPath 'test tools')

        Should -Invoke Save-VerifiedFile -Times 4 -Exactly -ParameterFilter { $Sha256 -match '^[0-9A-F]{64}$' }
    }
}

Describe 'The script' {
    It 'refuses to run anywhere but Windows' -Skip:$IsWindows {
        { & $script -Path (Join-Path -Path $TestDrive -ChildPath 'test tools') } | Should -Throw '*Windows only*'
    }
}
