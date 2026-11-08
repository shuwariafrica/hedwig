#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester hands BeforeAll and BeforeEach variables to It blocks, unseen by the analyser.')]
param()

BeforeAll {
    # Dot-sourcing defines the functions and admits nothing.
    . (Join-Path -Path $PSScriptRoot -ChildPath 'assert-release-commit.ps1') -Commit HEAD -Version 0.0.0

    # The fixture's git reads none of the person's configuration: no signing
    # key, hook or default branch of theirs takes part.
    $kept = @{ Global = $env:GIT_CONFIG_GLOBAL; NoSystem = $env:GIT_CONFIG_NOSYSTEM }
    $env:GIT_CONFIG_GLOBAL = Join-Path -Path $TestDrive -ChildPath 'gitconfig'
    Set-Content -LiteralPath $env:GIT_CONFIG_GLOBAL -Value @(
        '[user]', '    name = Fixture', '    email = fixture@example.invalid', '[init]', '    defaultBranch = main'
    )
    $env:GIT_CONFIG_NOSYSTEM = '1'

    function Invoke-Fixture {
        param([string] $Repository, [string[]] $Argument)

        $said = & git -C $Repository @Argument 2>&1
        if ($LASTEXITCODE -ne 0) { throw "git $Argument failed: $said" }
        $said
    }

    # A workspace of two members at `Version`, with what differs from that
    # set by name: the root's version, a member's own, or the lock's.
    function Write-Workspace {
        param(
            [string] $Repository,
            [string] $Version,
            [string] $Root = $Version,
            [string] $Member = '',
            [string] $Locked = $Version
        )

        $null = New-Item -ItemType Directory -Force -Path (Join-Path -Path $Repository -ChildPath 'crates' 'one'),
        (Join-Path -Path $Repository -ChildPath 'crates' 'two')
        Set-Content -LiteralPath (Join-Path -Path $Repository -ChildPath 'Cargo.toml') -Value @(
            '[workspace]', 'members = [', '    "crates/one",', '    "crates/two",', ']', '',
            '[workspace.package]', "version = `"$Root`"", '', '[workspace.dependencies]', 'zeroize = "1.9"'
        )
        Set-Content -LiteralPath (Join-Path -Path $Repository -ChildPath 'crates' 'one' 'Cargo.toml') -Value @(
            '[package]', 'name = "one"', 'version.workspace = true'
        )
        $two = if ($Member) { "version = `"$Member`"" } else { 'version.workspace = true' }
        Set-Content -LiteralPath (Join-Path -Path $Repository -ChildPath 'crates' 'two' 'Cargo.toml') -Value @(
            '[package]', 'name = "two"', $two, '', '[dependencies]', 'zeroize.workspace = true'
        )
        Set-Content -LiteralPath (Join-Path -Path $Repository -ChildPath 'Cargo.lock') -Value @(
            'version = 4', '', '[[package]]', 'name = "one"', "version = `"$Version`"", '',
            '[[package]]', 'name = "two"', "version = `"$Locked`"", '',
            '[[package]]', 'name = "zeroize"', 'version = "1.9.0"'
        )
    }

    function Save-Commit {
        param([string] $Repository, [string] $Message)

        $null = Invoke-Fixture $Repository 'add', '--all'
        $null = Invoke-Fixture $Repository 'commit', '--quiet', '--message', $Message
        Invoke-Fixture $Repository 'rev-parse', 'HEAD'
    }
}

AfterAll {
    $env:GIT_CONFIG_GLOBAL = $kept.Global
    $env:GIT_CONFIG_NOSYSTEM = $kept.NoSystem
}

Describe 'Assert-ReleaseCommit' {
    BeforeEach {
        # main: first, then a merge of a branch whose one commit main never
        # held on its own line.
        $repository = Join-Path -Path $TestDrive -ChildPath "release repository $(New-Guid)"
        $null = New-Item -ItemType Directory -Path $repository
        $null = Invoke-Fixture $repository 'init', '--quiet'
        Write-Workspace -Repository $repository -Version '0.2.0-alpha.1'
        $first = Save-Commit $repository 'first'
        $null = Invoke-Fixture $repository 'switch', '--quiet', '--create', 'lane'
        Add-Content -LiteralPath (Join-Path -Path $repository -ChildPath 'Cargo.toml') -Value '# lane'
        $merged = Save-Commit $repository 'on the lane'
        $null = Invoke-Fixture $repository 'switch', '--quiet', 'main'
        $null = Invoke-Fixture $repository 'merge', '--quiet', '--no-ff', '--message', 'merge the lane', 'lane'
        $merge = Invoke-Fixture $repository 'rev-parse', 'HEAD'
        $release = @{ Version = '0.2.0-alpha.1'; Branch = 'main'; Path = $repository }
    }

    It 'admits <Case>' -TestCases @(
        @{ Case = 'the merge main took'; Pick = 'merge' }
        @{ Case = 'an earlier commit main made itself'; Pick = 'first' }
    ) {
        $commit = Get-Variable -Name $Pick -ValueOnly

        $admitted = Assert-ReleaseCommit @release -Commit $commit

        $admitted.Commit | Should -BeExactly $commit
        $admitted.Version | Should -BeExactly '0.2.0-alpha.1'
    }

    It 'refuses a commit reachable only through a merge''s second parent' {
        $refused = "*($merged) is not on main's first-parent line*"
        { Assert-ReleaseCommit @release -Commit $merged } |
            Should -Throw -ErrorId 'NotOnFirstParentLine*' -ExpectedMessage $refused
    }

    It 'refuses a commit main does not reach' {
        $null = Invoke-Fixture $repository 'switch', '--quiet', '--create', 'elsewhere', $first
        Add-Content -LiteralPath (Join-Path -Path $repository -ChildPath 'Cargo.lock') -Value '# elsewhere'
        $elsewhere = Save-Commit $repository 'elsewhere'

        { Assert-ReleaseCommit @release -Commit $elsewhere } | Should -Throw -ErrorId 'NotOnFirstParentLine*'
    }

    It 'refuses where <Case>' -TestCases @(
        @{
            Case    = 'the workspace states another version'
            Root    = '0.1.0'
            Member  = ''
            Locked  = '0.2.0-alpha.1'
            ErrorId = 'ManifestVersionMismatch'
        }
        @{
            Case    = 'a member states another version'
            Root    = '0.2.0-alpha.1'
            Member  = '0.1.0'
            Locked  = '0.2.0-alpha.1'
            ErrorId = 'MemberVersionMismatch'
        }
        @{
            Case    = 'the lock records another version'
            Root    = '0.2.0-alpha.1'
            Member  = ''
            Locked  = '0.1.0'
            ErrorId = 'LockfileVersionMismatch'
        }
    ) {
        Write-Workspace -Repository $repository -Version '0.2.0-alpha.1' -Root $Root -Member $Member -Locked $Locked
        $changed = Save-Commit $repository 'versions'

        { Assert-ReleaseCommit @release -Commit $changed } | Should -Throw -ErrorId "$ErrorId*"
    }

    It 'admits a member that states the version itself' {
        Write-Workspace -Repository $repository -Version '0.2.0-alpha.1' -Member '0.2.0-alpha.1'
        $stated = Save-Commit $repository 'stated'

        (Assert-ReleaseCommit @release -Commit $stated).Commit | Should -BeExactly $stated
    }

    It 'stops where git cannot name the commit' {
        { Assert-ReleaseCommit @release -Commit 'no-such-tag' } | Should -Throw -ErrorId 'GitCommandFailed*'
    }
}
