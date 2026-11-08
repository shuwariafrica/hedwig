#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '6.0.0' }

BeforeAll {
    # Dot-sourcing defines the functions and writes nothing.
    . (Join-Path -Path $PSScriptRoot -ChildPath 'export-run-blocks.ps1') -Destination $TestDrive

    function Export-Fixture {
        param([string] $Workflow)

        $folder = Join-Path -Path $TestDrive -ChildPath "workflows $(New-Guid)"
        $null = New-Item -ItemType Directory -Force -Path $folder
        Set-Content -LiteralPath (Join-Path -Path $folder -ChildPath 'w.yml') -Value $Workflow
        Export-RunBlock -Workflows $folder -Destination (Join-Path -Path $TestDrive -ChildPath "blocks $(New-Guid)")
    }
}

Describe 'Export-RunBlock' {
    It 'writes each block under the shell its step, job or workflow declares, an aliased step under its job''s' {
        $blocks = Export-Fixture -Workflow @'
on: push
defaults:
  run:
    shell: bash
jobs:
  first:
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@v7
      - &shared
        name: Shared
        run: printf 'one\n'
      - name: Own shell
        shell: pwsh
        run: Get-Date
  second:
    runs-on: windows-2025-vs2026
    defaults:
      run:
        shell: pwsh
    steps:
      - *shared
      - run: Get-Item .
  called:
    uses: ./.github/workflows/other.yml
'@

        $blocks | ForEach-Object { "$($_.Job).$($_.Step).$($_.Shell)" } |
            Should -Be @('first.1.bash', 'first.2.pwsh', 'second.0.pwsh', 'second.1.pwsh')
        Get-Content -LiteralPath $blocks[0].File -Raw | Should -BeExactly "printf 'one\n'`n"
        Split-Path -Path $blocks[1].File -Leaf | Should -BeExactly 'w.first.2.ps1'
    }

    It 'writes each step of a parallel group, named by the group and its place in it' {
        $blocks = Export-Fixture -Workflow @'
on: push
jobs:
  only:
    runs-on: ubuntu-26.04
    defaults:
      run:
        shell: bash
    steps:
      - parallel:
          - run: printf 'a\n'
          - run: printf 'b\n'
'@

        $blocks.Step | Should -Be @('0.0', '0.1')
    }

    It 'refuses a block that declares no shell' {
        { Export-Fixture -Workflow @'
on: push
jobs:
  only:
    runs-on: ubuntu-26.04
    steps:
      - run: echo
'@ } | Should -Throw '*job only, step 0 declares no shell*'
    }

    It 'refuses a shell it does not check' {
        { Export-Fixture -Workflow @'
on: push
jobs:
  only:
    runs-on: windows-2025-vs2026
    steps:
      - shell: cmd
        run: echo
'@ } | Should -Throw "*runs under 'cmd'*"
    }
}
