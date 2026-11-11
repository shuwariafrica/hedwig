#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '',
    Justification = 'Pester hands BeforeAll and BeforeEach variables to It blocks, unseen by the analyser.')]
param()

BeforeAll {
    $folder = Join-Path -Path $PSScriptRoot -ChildPath '..' -AdditionalChildPath '.github', 'workflows'

    function Read-Workflow {
        param([string] $Name)

        $json = & yq --output-format=json 'explode(.)' (Join-Path -Path $folder -ChildPath $Name)
        if ($LASTEXITCODE -ne 0) {
            throw "yq could not read $Name (exit code $LASTEXITCODE)"
        }
        ($json -join "`n") | ConvertFrom-Json -AsHashtable
    }
}

Describe 'ci.yml' {
    BeforeAll {
        $jobs = (Read-Workflow 'ci.yml').jobs
    }

    # A job missing from gate's needs is run and never required.
    It 'makes gate need every other job' {
        $others = @($jobs.Keys | Where-Object { $_ -ne 'gate' } | Sort-Object)
        @($jobs['gate'].needs | Sort-Object) | Should -Be $others
    }

    It 'runs gate whatever became of the jobs it needs' {
        $jobs['gate']['if'] | Should -BeExactly '${{ always() }}'
    }
}

Describe 'release.yml' {
    BeforeAll {
        $text = Get-Content -LiteralPath (Join-Path -Path $folder -ChildPath 'release.yml') -Raw
        $jobs = (Read-Workflow 'release.yml').jobs
    }

    # Signing arrives with the organisation's release key; until then no job
    # holds a key or a secret of the organisation's.
    It 'reads no secret' {
        $text | Should -Not -Match 'secrets\.'
    }

    It 'publishes with its own token, writing contents and attesting' {
        $permissions = $jobs['publish'].permissions
        foreach ($scope in 'contents', 'id-token', 'attestations') {
            $permissions[$scope] | Should -BeExactly 'write' -Because "the publishing job's token needs $scope"
        }
        $publish = @($jobs['publish'].steps | Where-Object { $_.name -eq 'Publish the release' })
        $publish.env.GH_TOKEN | Should -BeExactly '${{ github.token }}'
    }

    It 'admits only a commit on main''s first-parent line, with main''s history fetched' {
        $steps = $jobs['tag'].steps
        ($steps | Where-Object { $_.name -eq 'Check out' }).with['fetch-depth'] | Should -Be 0
        ($steps | Where-Object { $_.name -eq 'Verify the commit' }).run | Should -Match 'assert-release-commit\.ps1'
    }

    It 'admits only the commit the run builds, which the tag names when the run starts' {
        $verify = $jobs['tag'].steps | Where-Object { $_.name -eq 'Verify the tag' }
        $verify.run | Should -Match '"\$\{commit\}" != "\$\{GITHUB_SHA\}"'
    }
}

Describe 'every workflow' {
    It '<_> bounds every job''s time and grants every job its permissions' -ForEach @(
        Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath '..' '.github' 'workflows') -File |
            ForEach-Object { $_.Name }
    ) {
        $workflow = Read-Workflow $_
        $workflow.Contains('permissions') | Should -BeTrue -Because 'the workflow sets the token''s default'
        foreach ($name in $workflow.jobs.Keys) {
            $job = $workflow.jobs[$name]
            $job.Contains('permissions') | Should -BeTrue -Because "job $name names what its token may do"
            if (-not $job.Contains('uses')) {
                $job.Contains('timeout-minutes') | Should -BeTrue -Because "job $name is bounded"
            }
        }
    }
}
