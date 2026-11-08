#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester hands BeforeAll and BeforeEach variables to It blocks, unseen by the analyser.')]
param()

BeforeAll {
    # Dot-sourcing defines the functions and lays out nothing.
    . (Join-Path -Path $PSScriptRoot -ChildPath 'stage-payload.ps1') -Build $TestDrive -Destination $TestDrive

    function Write-Fixture {
        param([string] $Path, [string] $Text = 'x')

        $null = New-Item -ItemType Directory -Force -Path (Split-Path -Path $Path -Parent)
        Set-Content -LiteralPath $Path -Value $Text -NoNewline
    }

    function Get-TextSha256 {
        param([string] $Text)

        [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text)))
    }
}

Describe 'Publish-Payload' {
    BeforeEach {
        $root = Join-Path -Path $TestDrive -ChildPath "fixture $(New-Guid)"
        $crate = Join-Path -Path $root -ChildPath 'windows-reactor-setup-0.100.0'
        $source = Join-Path -Path $crate -ChildPath 'src' 'lib.rs'
        Write-Fixture -Path $source -Text @'
const RUNTIME_VER: &str = "2.4.0";
const WEBVIEW2_VER: &str = "1.0.1";
'@
        $list = Join-Path -Path $crate -ChildPath 'assets' 'runtime.txt'
        Write-Fixture -Path $list -Text "a.dll`nb.dll`nsub`nlisted-but-absent.dll`n"

        $cache = Join-Path -Path $root -ChildPath 'cache'
        $runtimePackage = Join-Path -Path $cache -ChildPath 'Microsoft.WindowsAppSDK.Runtime.2.4.0.nupkg'
        Write-Fixture -Path $runtimePackage -Text 'runtime'
        Write-Fixture -Path (Join-Path -Path $cache -ChildPath 'Microsoft.Web.WebView2.1.0.1.nupkg') -Text 'webview'
        $extracted = Join-Path -Path $cache -ChildPath 'Microsoft.WindowsAppSDK.Runtime-2.4.0' '.msix_extract'
        foreach ($name in 'A.dll', 'B.dll', 'sub/x.dat', 'AppxManifest.xml') {
            Write-Fixture -Path (Join-Path -Path $extracted -ChildPath $name)
        }

        $manifest = Join-Path -Path $root -ChildPath 'tools.json'
        $pin = { param($Tool, $Version, $Text) @{ set = 'runtime'; tool = $Tool; version = $Version; sha256 = $Text } }
        @{
            tools = @(
                & $pin 'Microsoft.WindowsAppSDK.Runtime' '2.4.0' (Get-TextSha256 'runtime').ToLowerInvariant()
                & $pin 'Microsoft.Web.WebView2' '1.0.1' (Get-TextSha256 'webview').ToLowerInvariant()
            )
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifest

        $build = Join-Path -Path $root -ChildPath 'release'
        foreach ($name in 'hedwig.exe', 'hedwig-interface.exe', 'hedwig-window.exe', 'a.dll', 'b.dll', 'sub/x.dat',
            'Microsoft.Web.WebView2.Core.dll', 'hedwig.pdb', 'deps/unrelated.rlib') {
            Write-Fixture -Path (Join-Path -Path $build -ChildPath $name)
        }

        $payload = @{
            Build        = $build
            Destination  = Join-Path -Path $root -ChildPath 'payload'
            ReactorSetup = $crate
            Cache        = $cache
            Manifest     = $manifest
        }
    }

    It 'lays out the three executables and the runtime the crate lists, and nothing else of the build' {
        $result = Publish-Payload @payload

        $result.Files | Should -Be 7
        $files = Get-ChildItem -LiteralPath $payload.Destination -Recurse -File | ForEach-Object {
            [IO.Path]::GetRelativePath($payload.Destination, $_.FullName).Replace('\', '/')
        } | Sort-Object
        $files | Should -Be @(
            'a.dll', 'b.dll', 'hedwig-interface.exe', 'hedwig-window.exe', 'hedwig.exe'
            'Microsoft.Web.WebView2.Core.dll', 'sub/x.dat'
        )
    }

    It 'refuses a build missing a runtime file the crate extracted and lists, naming it' {
        Remove-Item -LiteralPath (Join-Path -Path $payload.Build -ChildPath 'b.dll')

        { Publish-Payload @payload } | Should -Throw '*lacks 1 of what setup carries: B.dll'
        Test-Path -LiteralPath $payload.Destination | Should -BeFalse
    }

    It 'refuses a build missing one of the executables' {
        Remove-Item -LiteralPath (Join-Path -Path $payload.Build -ChildPath 'hedwig-window.exe')

        { Publish-Payload @payload } | Should -Throw '*hedwig-window.exe*'
    }

    It 'refuses a package whose SHA-256 is not the pinned one' {
        Write-Fixture -Path $runtimePackage -Text 'replaced'

        { Publish-Payload @payload } | Should -Throw '*Runtime.2.4.0.nupkg has SHA-256 *, not the pinned *'
    }

    It 'refuses a package the crate never downloaded' {
        Remove-Item -LiteralPath (Join-Path -Path $payload.Cache -ChildPath 'Microsoft.Web.WebView2.1.0.1.nupkg')

        { Publish-Payload @payload } | Should -Throw '*did not download Microsoft.Web.WebView2 1.0.1*'
    }

    It 'refuses a version of the runtime tools.json does not pin' {
        Set-Content -LiteralPath $source -Value @'
const RUNTIME_VER: &str = "2.5.0";
const WEBVIEW2_VER: &str = "1.0.1";
'@

        { Publish-Payload @payload } | Should -Throw '*pins no Microsoft.WindowsAppSDK.Runtime 2.5.0*'
    }

    It 'refuses a crate that no longer declares the versions it downloads' {
        Set-Content -LiteralPath $source -Value 'fn main() {}'

        { Publish-Payload @payload } | Should -Throw '*no longer declares RUNTIME_VER*'
    }

    It 'writes nothing under -WhatIf' {
        Publish-Payload @payload -WhatIf | Should -BeNullOrEmpty
        Test-Path -LiteralPath $payload.Destination | Should -BeFalse
    }
}

Describe 'Get-ReactorCache' {
    It 'names the folder the crate downloads into under LOCALAPPDATA' {
        $local = Join-Path -Path $TestDrive -ChildPath 'Local App Data'
        $expected = Join-Path -Path $local -ChildPath 'windows-reactor-setup' 'temp'

        Get-ReactorCache -LocalAppData $local | Should -BeExactly $expected
    }

    It 'asks for -Cache where LOCALAPPDATA is not set' {
        { Get-ReactorCache -LocalAppData '' } | Should -Throw '*LOCALAPPDATA is not set*give -Cache.'
    }
}
