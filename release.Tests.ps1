#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Dot-sourcing defines the functions without releasing anything; the
    # version is bound only because the script declares it mandatory.
    . (Join-Path -Path $PSScriptRoot -ChildPath 'release.ps1') -Version '0.0.0'

    function Initialize-Crate {
        param([string] $ManifestVersion, [string] $LockfileVersion)

        $manifest = @(
            '[package]'
            'name = "hedwig"'
            "version = `"$ManifestVersion`""
            ''
            '[dependencies.windows-sys]'
            'version = "0.61"'
        )
        $lockfile = @(
            'version = 4'
            ''
            '[[package]]'
            'name = "hedwig"'
            "version = `"$LockfileVersion`""
            ''
            '[[package]]'
            'name = "zeroize"'
            'version = "1.9.0"'
        )
        Set-Content -LiteralPath (Join-Path -Path $fakeGit.Repository -ChildPath 'Cargo.toml') -Value $manifest
        Set-Content -LiteralPath (Join-Path -Path $fakeGit.Repository -ChildPath 'Cargo.lock') -Value $lockfile
    }
}

Describe 'Publish-ReleaseTag' {
    BeforeEach {
        # State the git mock reads and records. Never $script:-scoped: the mock
        # also answers a copy of release.ps1, whose script scope is its own.
        $fakeGit = [pscustomobject] @{
            Repository = Join-Path -Path $TestDrive -ChildPath 'hedwig checkout'
            # What git prints for each invocation in a repository ready to
            # release 1.2.3. Each test overrides the answer that makes its
            # check fail.
            Output     = @{}
            # The one invocation, if any, that exits 128 with a diagnostic.
            Failure    = $null
            Calls      = [System.Collections.Generic.List[string]]::new()
        }
        $null = New-Item -ItemType Directory -Force -Path $fakeGit.Repository

        $release = @{
            Version           = '1.2.3'
            Path              = $fakeGit.Repository
            Owner             = 'shuwariafrica'
            Name              = 'hedwig'
            InformationAction = 'Ignore'
        }
        Initialize-Crate -ManifestVersion $release.Version -LockfileVersion $release.Version

        $fakeGit.Output['status --porcelain'] = @()
        $fakeGit.Output['remote'] = @('fork', 'origin')
        $fakeGit.Output['remote get-url --all fork'] = @('git@github.com:someone/hedwig.git')
        $fakeGit.Output['remote get-url --all origin'] = @('git@github.com:shuwariafrica/hedwig.git')
        $fakeGit.Output['rev-parse --abbrev-ref HEAD'] = @('main')
        $fakeGit.Output['for-each-ref --format=%(upstream:remotename) refs/heads/main'] = @('origin')
        $fakeGit.Output['fetch --prune origin'] = @()
        $fakeGit.Output['fetch --tags --prune origin'] = @()
        $fakeGit.Output['rev-list --left-right --count HEAD...@{u}'] = @("0`t0")
        $fakeGit.Output['tag --list v1.2.3'] = @()
        $fakeGit.Output['ls-remote --tags origin refs/tags/v1.2.3'] = @()
        $fakeGit.Output['tag --sign --annotate v1.2.3 -m Release version v1.2.3'] = @()
        $fakeGit.Output['push origin v1.2.3'] = @()

        Mock git {
            if ($args[0] -cne '-C' -or $args[1] -cne $fakeGit.Repository) {
                throw "git was not pointed at the fixture repository: $args"
            }
            $command = $args[2..($args.Count - 1)] -join ' '
            $fakeGit.Calls.Add($command)
            if ($command -ceq $fakeGit.Failure) {
                Write-Error -Message 'fatal: simulated failure' -ErrorAction Continue
                $global:LASTEXITCODE = 128
                return
            }
            if (-not $fakeGit.Output.ContainsKey($command)) {
                throw "unexpected git invocation: $command"
            }
            $global:LASTEXITCODE = 0
            $fakeGit.Output[$command]
        }
    }

    It 'runs every check in order, then tags and pushes the release' {
        $result = Publish-ReleaseTag @release

        $result.Tag | Should -BeExactly 'v1.2.3'
        $result.Remote | Should -BeExactly 'origin'
        $fakeGit.Calls | Should -Be @(
            'status --porcelain'
            'remote'
            'remote get-url --all fork'
            'remote get-url --all origin'
            'rev-parse --abbrev-ref HEAD'
            'for-each-ref --format=%(upstream:remotename) refs/heads/main'
            'fetch --prune origin'
            'fetch --tags --prune origin'
            'rev-list --left-right --count HEAD...@{u}'
            'tag --list v1.2.3'
            'ls-remote --tags origin refs/tags/v1.2.3'
            'tag --sign --annotate v1.2.3 -m Release version v1.2.3'
            'push origin v1.2.3'
        )
    }

    It 'runs every check under -WhatIf but creates and pushes nothing' {
        $result = Publish-ReleaseTag @release -WhatIf

        $result | Should -BeNullOrEmpty
        $fakeGit.Calls[-1] | Should -BeExactly 'ls-remote --tags origin refs/tags/v1.2.3'
    }

    It 'passes -WhatIf from the script to the release, which checks its own checkout' {
        $copy = Join-Path -Path $fakeGit.Repository -ChildPath 'release.ps1'
        Copy-Item -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'release.ps1') -Destination $copy

        $result = & $copy 1.2.3 -WhatIf -InformationAction Ignore

        $result | Should -BeNullOrEmpty
        $fakeGit.Calls[-1] | Should -BeExactly 'ls-remote --tags origin refs/tags/v1.2.3'
    }

    It 'accepts the pre-release and build forms <Version>' -TestCases @(
        @{ Version = '0.1.0-alpha.1' }
        @{ Version = '10.20.30-rc.12+build.7' }
    ) {
        Initialize-Crate -ManifestVersion $Version -LockfileVersion $Version
        $fakeGit.Output["tag --list v$Version"] = @()
        $fakeGit.Output["ls-remote --tags origin refs/tags/v$Version"] = @()
        $fakeGit.Output["tag --sign --annotate v$Version -m Release version v$Version"] = @()
        $fakeGit.Output["push origin v$Version"] = @()
        $release.Version = $Version

        (Publish-ReleaseTag @release).Tag | Should -BeExactly "v$Version"
    }

    It 'rejects the version string <Version> before touching git' -TestCases @(
        @{ Version = '1.2' }
        @{ Version = 'v1.2.3' }
        @{ Version = '01.2.3' }
        @{ Version = '1.2.3-RC.1' }
        @{ Version = '1.2.3-rc.0' }
        @{ Version = '1.2.3-preview.1' }
        @{ Version = '1.2.3 ' }
    ) {
        $release.Version = $Version

        { Publish-ReleaseTag @release } | Should -Throw -ErrorId 'ParameterArgumentValidationError*'
        $fakeGit.Calls | Should -BeNullOrEmpty
    }

    It 'refuses a dirty working tree before reading the crate' {
        $fakeGit.Output['status --porcelain'] = @(' M src/lib.rs', '?? notes.txt')

        { Publish-ReleaseTag @release } |
            Should -Throw -ErrorId 'WorkingTreeDirty*' -ExpectedMessage '*M src/lib.rs; ?? notes.txt'
        $fakeGit.Calls | Should -Be @('status --porcelain')
    }

    It 'refuses when Cargo.toml declares <ManifestVersion> and Cargo.lock <LockfileVersion>' -TestCases @(
        @{
            ManifestVersion = '1.2.2'
            LockfileVersion = '1.2.3'
            ErrorId         = 'ManifestVersionMismatch'
        }
        @{
            ManifestVersion = '1.2.3'
            LockfileVersion = '1.2.2'
            ErrorId         = 'LockfileVersionMismatch'
        }
        @{
            ManifestVersion = '1.2.3-RC.1'
            LockfileVersion = '1.2.3'
            ErrorId         = 'ManifestVersionMismatch'
        }
    ) {
        Initialize-Crate -ManifestVersion $ManifestVersion -LockfileVersion $LockfileVersion

        { Publish-ReleaseTag @release } | Should -Throw -ErrorId "$ErrorId*"
        $fakeGit.Calls | Should -Be @('status --porcelain')
    }

    It 'refuses when <File> holds no version for the package' -TestCases @(
        @{ File = 'Cargo.toml'; ErrorId = 'ManifestVersionMissing' }
        @{ File = 'Cargo.lock'; ErrorId = 'LockfileVersionMissing' }
    ) {
        Set-Content -LiteralPath (Join-Path -Path $fakeGit.Repository -ChildPath $File) -Value '[package]'

        { Publish-ReleaseTag @release } | Should -Throw -ErrorId "$ErrorId*"
    }

    It 'refuses when no remote points at the repository' {
        $fakeGit.Output['remote get-url --all origin'] = @('git@github.com:shuwariafrica/hedwig-fork.git')

        { Publish-ReleaseTag @release } | Should -Throw -ErrorId 'RemoteNotFound*'
        $fakeGit.Calls | Should -Not -Contain 'fetch --prune origin'
    }

    It 'refuses when <Case>' -TestCases @(
        @{
            Case    = 'HEAD is detached'
            Command = 'rev-parse --abbrev-ref HEAD'
            Output  = @('HEAD')
            ErrorId = 'DetachedHead'
        }
        @{
            Case    = 'the branch has no upstream'
            Command = 'for-each-ref --format=%(upstream:remotename) refs/heads/main'
            Output  = @()
            ErrorId = 'UpstreamMissing'
        }
        @{
            Case    = 'the upstream is another remote'
            Command = 'for-each-ref --format=%(upstream:remotename) refs/heads/main'
            Output  = @('fork')
            ErrorId = 'UpstreamMismatch'
        }
    ) {
        $fakeGit.Output[$Command] = $Output

        { Publish-ReleaseTag @release } | Should -Throw -ErrorId "$ErrorId*"
        $fakeGit.Calls | Should -Not -Contain 'fetch --prune origin'
    }

    It 'refuses when <Case>' -TestCases @(
        @{
            Case    = 'the branch is behind its upstream'
            Command = 'rev-list --left-right --count HEAD...@{u}'
            Output  = @("0`t2")
            ErrorId = 'BranchBehind'
        }
        @{
            Case    = 'the branch has unpushed commits'
            Command = 'rev-list --left-right --count HEAD...@{u}'
            Output  = @("1`t0")
            ErrorId = 'BranchAhead'
        }
        @{
            Case    = 'the tag exists locally'
            Command = 'tag --list v1.2.3'
            Output  = @('v1.2.3')
            ErrorId = 'TagExistsLocally'
        }
        @{
            Case    = 'the tag exists on the remote'
            Command = 'ls-remote --tags origin refs/tags/v1.2.3'
            Output  = @("0123456789abcdef`trefs/tags/v1.2.3")
            ErrorId = 'TagExistsOnRemote'
        }
    ) {
        $fakeGit.Output[$Command] = $Output

        { Publish-ReleaseTag @release } | Should -Throw -ErrorId "$ErrorId*"
        $fakeGit.Calls | Should -Not -Contain 'push origin v1.2.3'
    }

    It 'stops at a git command that exits non-zero: <Command>' -TestCases @(
        @{ Command = 'status --porcelain' }
        @{ Command = 'remote get-url --all fork' }
        @{ Command = 'fetch --prune origin' }
        @{ Command = 'fetch --tags --prune origin' }
        @{ Command = 'tag --sign --annotate v1.2.3 -m Release version v1.2.3' }
        @{ Command = 'push origin v1.2.3' }
    ) {
        $fakeGit.Failure = $Command

        { Publish-ReleaseTag @release } |
            Should -Throw -ErrorId 'GitCommandFailed*' -ExpectedMessage '*exit code 128: fatal: simulated failure'
        $fakeGit.Calls[-1] | Should -BeExactly $Command
    }
}

Describe 'release.ps1' {
    It 'demands a version when run without one' {
        $pwsh = (Get-Process -Id $PID).Path
        $releaseScript = Join-Path -Path $PSScriptRoot -ChildPath 'release.ps1'
        $output = & $pwsh -NoProfile -NonInteractive -File $releaseScript 2>&1

        $LASTEXITCODE | Should -Not -Be 0
        ($output -join "`n") | Should -BeLike '*Version*'
    }
}
