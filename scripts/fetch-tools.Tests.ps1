#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester hands BeforeAll and BeforeEach variables to It blocks, unseen by the analyser.')]
param()

BeforeAll {
    # Dot-sourcing defines the functions and fetches nothing.
    . (Join-Path -Path $PSScriptRoot -ChildPath 'fetch-tools.ps1') -Set gate
    $manifest = Join-Path -Path $PSScriptRoot -ChildPath 'tools.json'

    function Get-TextSha256 {
        param([string] $Text)

        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))
    }

    function Write-Zip {
        param([string] $Path, [hashtable] $Entries)

        $folder = "$Path.contents"
        foreach ($name in $Entries.Keys) {
            $file = Join-Path -Path $folder -ChildPath $name
            $null = New-Item -ItemType Directory -Force -Path (Split-Path -Path $file -Parent)
            Set-Content -LiteralPath $file -Value $Entries[$name] -NoNewline
        }
        Compress-Archive -Path (Join-Path -Path $folder -ChildPath '*') -DestinationPath "$Path.zip" -Force
        Move-Item -LiteralPath "$Path.zip" -Destination $Path -Force
        $Path
    }
}

Describe 'Get-ToolPin' {
    BeforeAll {
        $fixture = Join-Path -Path $TestDrive -ChildPath 'tools.json'
        @{
            tools = @(
                @{ set = 'gate'; tool = 'a'; platforms = @('linux-x64') }
                @{ set = 'gate'; tool = 'b'; platforms = @('windows-x64', 'windows-arm64') }
                @{ set = 'gate'; tool = 'm'; platforms = @('any') }
                @{ set = 'winget'; tool = 'k'; platforms = @('linux-x64') }
                @{ set = 'runtime'; tool = 'r'; platforms = @('windows-x64') }
            )
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $fixture
    }

    It 'emits the pins of the sets named that serve the platform, a pin for any among them' {
        (Get-ToolPin -Manifest $fixture -Set gate -Platform 'windows-arm64').tool | Should -Be @('b', 'm')
    }

    It 'emits the pins of every set named' {
        (Get-ToolPin -Manifest $fixture -Set gate, winget -Platform 'linux-x64').tool | Should -Be @('a', 'm', 'k')
    }
}

Describe 'Resolve-PinText' {
    It 'expands {version} as pinned and {number} without its leading v' {
        Resolve-PinText -Text 'x-{version}_{number}.zip' -Version 'v1.2.3' | Should -BeExactly 'x-v1.2.3_1.2.3.zip'
    }
}

Describe 'Resolve-PinUri' {
    It 'names a GitHub release asset by its repository, tag and file' {
        $pin = [pscustomobject] @{
            datasource = 'github-release-attachments'
            package    = 'o/r'
            version    = 'v2.0.0'
            file       = 't_{number}.tar.gz'
        }
        $expected = 'https://github.com/o/r/releases/download/v2.0.0/t_2.0.0.tar.gz'
        (Resolve-PinUri -Pin $pin).AbsoluteUri | Should -BeExactly $expected
    }

    It 'names a NuGet package by its registry, name and version' {
        $pin = [pscustomobject] @{
            datasource = 'nuget'
            registry   = 'https://www.powershellgallery.com/api/v2/'
            package    = 'Pester'
            version    = '6.2.0'
        }
        $expected = 'https://www.powershellgallery.com/api/v2/package/Pester/6.2.0'
        (Resolve-PinUri -Pin $pin).AbsoluteUri | Should -BeExactly $expected
    }

    It 'refuses a datasource it cannot fetch' {
        $pin = [pscustomobject] @{ tool = 'r'; datasource = 'unknown' }
        { Resolve-PinUri -Pin $pin } | Should -Throw "*datasource 'unknown'*"
    }
}

Describe 'Save-VerifiedFile' {
    BeforeEach {
        $fixture = [pscustomobject] @{ Served = 'the tool as served' }
        $file = @{
            Uri    = 'https://example.org/tool.zip'
            Path   = Join-Path -Path $TestDrive -ChildPath "downloads $(New-Guid)" -AdditionalChildPath 'tool.zip'
            Sha256 = Get-TextSha256 -Text $fixture.Served
        }
        Mock Invoke-WebRequest { Set-Content -LiteralPath $OutFile -Value $fixture.Served -NoNewline }
    }

    It 'keeps a download whose SHA-256 is the pinned one' {
        Save-VerifiedFile @file | Should -BeExactly $file.Path
        Get-Content -LiteralPath $file.Path -Raw | Should -BeExactly $fixture.Served
    }

    It 'does not fetch a file already there with the pinned SHA-256' {
        $null = Save-VerifiedFile @file
        $null = Save-VerifiedFile @file
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
    }

    It 'refuses a download whose SHA-256 is another, naming it, and keeps nothing of it' {
        $fixture.Served = 'a replaced asset'
        $other = Get-TextSha256 -Text $fixture.Served

        { Save-VerifiedFile @file } | Should -Throw "*has SHA-256 $other, not the pinned $($file.Sha256)*"

        Test-Path -LiteralPath $file.Path | Should -BeFalse
        Test-Path -LiteralPath "$($file.Path).partial" | Should -BeFalse
    }

    It 'writes nothing under -WhatIf' {
        Save-VerifiedFile @file -WhatIf | Should -BeNullOrEmpty
        Test-Path -LiteralPath $file.Path | Should -BeFalse
    }
}

Describe 'Install-Tool' {
    BeforeEach {
        $root = Join-Path -Path $TestDrive -ChildPath "tools $(New-Guid)"
        $null = New-Item -ItemType Directory -Force -Path $root
    }

    It 'lays out the member a zip names as the tool in bin, and emits bin for Path' {
        $entries = @{ 'inner/tool.exe' = 'program'; 'README' = 'docs' }
        $zip = Write-Zip -Path (Join-Path -Path $root -ChildPath 'a.zip') -Entries $entries
        $pin = [pscustomobject] @{
            tool       = 'tool'
            datasource = 'github-release-attachments'
            version    = 'v1'
            member     = 'inner/tool.exe'
        }

        $folder = Install-Tool -Pin $pin -Download $zip -Path $root

        $folder.Name | Should -BeExactly 'Path'
        $program = Join-Path -Path $folder.Value -ChildPath ('tool' + $(if ($IsWindows) { '.exe' } else { '' }))
        Get-Content -LiteralPath $program -Raw | Should -BeExactly 'program'
    }

    It 'refuses an archive that lacks the member named' {
        $zip = Write-Zip -Path (Join-Path -Path $root -ChildPath 'b.zip') -Entries @{ 'other' = 'x' }
        $pin = [pscustomobject] @{
            tool       = 'tool'
            datasource = 'github-release-attachments'
            version    = 'v1'
            member     = 'tool.exe'
        }

        { Install-Tool -Pin $pin -Download $zip -Path $root } | Should -Throw '*holds no tool.exe'
    }

    It 'lays out a package as a module folder without the package''s own records' {
        $entries = @{
            'M.psd1'              = '@{ ModuleVersion = ''1.0.0'' }'
            'M.nuspec'            = 'nuspec'
            '[Content_Types].xml' = 'types'
            '_rels/.rels'         = 'rels'
        }
        $package = Write-Zip -Path (Join-Path -Path $root -ChildPath 'M.1.0.0.nupkg') -Entries $entries
        $pin = [pscustomobject] @{ tool = 'M'; datasource = 'nuget'; package = 'M'; version = '1.0.0' }

        $folder = Install-Tool -Pin $pin -Download $package -Path $root

        $folder.Name | Should -BeExactly 'PSModulePath'
        $module = Join-Path -Path $folder.Value -ChildPath 'M' -AdditionalChildPath '1.0.0'
        (Get-ChildItem -LiteralPath $module -Force).Name | Should -Be @('M.psd1')
    }
}

Describe 'Save-Tool' {
    It 'refuses a platform tools.json pins nothing for' {
        $empty = Join-Path -Path $TestDrive -ChildPath 'empty.json'
        '{ "tools": [] }' | Set-Content -LiteralPath $empty

        { Save-Tool -Manifest $empty -Set gate -Platform 'linux-riscv64' -Path $TestDrive } |
            Should -Throw '*pins nothing in set gate for linux-riscv64*'
    }
}

Describe 'tools.json' {
    It 'pins every file by a SHA-256' {
        $pins = (Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json).tools
        $pins | Where-Object { $_.sha256 -notmatch '^[0-9a-f]{64}$' } | Should -BeNullOrEmpty
    }

    It 'gives every gate tool a pin for <_>' -ForEach @('linux-x64', 'windows-x64', 'windows-arm64') {
        $tools = (Get-ToolPin -Manifest $manifest -Set gate -Platform $_).tool | Sort-Object -Unique
        $tools | Should -Be @('actionlint', 'Pester', 'PSScriptAnalyzer', 'shellcheck', 'shfmt', 'yq', 'zizmor')
    }
}
