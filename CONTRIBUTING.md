# Contributing

## Setting up

Install [rustup](https://rustup.rs); `rust-toolchain.toml` supplies the toolchain, components and
both targets. The workspace builds only on Windows, and its scripts need PowerShell 7.

The suites run real programs: Git for Windows' own shell as a remote's, installed where its
installer puts it, and GnuPG's own Windows build, Android's platform-tools and pyserial, which
`scripts/fetch-test-tools.ps1` fetches into `target\test-tools`, each pinned by version and
SHA-256. It emits the variables the suites read; set them in the session that runs the tests:

```powershell
./scripts/fetch-test-tools.ps1 | ForEach-Object { Set-Item -Path "Env:$($_.Name)" -Value $_.Value }
```

## The crates

| crate | what it is |
|---|---|
| `hedwig-model` | the model, the gate, the written form and the control protocol; no call to Windows |
| `hedwig-win` | every call to Windows the core, the client and `hedwig.exe` make |
| `hedwig-core` | the core, its relays, its store and the supervisor |
| `hedwig-client` | finding, speaking to, installing and removing a running Hedwig |
| `hedwig` | `hedwig.exe`: the supervisor, the core, removal and a channel's askpass |
| `hedwig-view` | what the interface shows and offers, decided from what the core said; draws nothing |
| `hedwig-shell` | the interface's calls to Windows: the icon, its menu, the cards and setup's question |
| `hedwig-interface` | `hedwig-interface.exe`: the icon, its menu and cards, and removal from Settings |
| `hedwig-window` | `hedwig-window.exe`: the window, drawn by WinUI 3, with its runtime staged beside it |
| `hedwig-setup` | `hedwig-setup.exe`, carrying the other three executables and the window's runtime |
| `hedwig-support` | the stand-ins and harness the process suites drive; never shipped |

## Before opening a pull request

The Rust checks, as CI runs them on each architecture:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings
cargo clippy --workspace --all-targets --locked --target aarch64-pc-windows-msvc -- -D warnings
cargo build --workspace --release --locked --target x86_64-pc-windows-msvc
cargo test --workspace --release --locked --target x86_64-pc-windows-msvc --no-fail-fast
cargo doc --workspace --no-deps --locked --target x86_64-pc-windows-msvc
cargo deny check
```

Always pass `--target`: a host whose default toolchain is GNU would otherwise build against the
wrong ABI. Build before testing: the suites run the executables the build leaves beside them. CI
runs `cargo doc` with `RUSTDOCFLAGS` set to `-D warnings`.

The scripts and the workflows, with the tools `scripts/tools.json` pins, which
`scripts/fetch-tools.ps1` lays out under `target\tools`:

```powershell
./scripts/fetch-tools.ps1 -Set gate | ForEach-Object {
    $current = [Environment]::GetEnvironmentVariable($_.Name)
    [Environment]::SetEnvironmentVariable($_.Name, $_.Value + [IO.Path]::PathSeparator + $current)
}
./scripts/export-run-blocks.ps1 -Destination target/run-blocks
$shell = @(git ls-files '*.sh') + (Get-ChildItem target/run-blocks -Filter *.sh).FullName
shellcheck --severity=style @shell
shfmt --diff @shell
./scripts/lint-powershell.ps1 -Path target/run-blocks
Invoke-Pester -Path (git ls-files '*.Tests.ps1')
actionlint -shellcheck= -pyflakes=
zizmor .github
```

`export-run-blocks.ps1` writes every workflow `run:` block out as a script of its declared shell,
so ShellCheck, shfmt and PSScriptAnalyzer check them as they check the repository's own scripts;
a block declares its shell through `shell:` or its job's `defaults`. ShellCheck and shfmt read
`.shellcheckrc` and `.editorconfig`, PSScriptAnalyzer `PSScriptAnalyzerSettings.psd1`, and
actionlint `.github/actionlint.yaml`. zizmor checks with `GH_TOKEN` set that each pinned action's
commit is its own.

## The suites a hosted runner cannot run

A test marked ignored needs something not every machine has, and its marking says which: an SSH
server on loopback, GnuPG for Windows installed and registered, a COM port, a TPM, a session at
medium integrity, or the desktop's foreground, which the interface's suites take for a few seconds
each. CI runs the two whose need its runners meet, an elevated session and a listener on every
address that Windows Firewall does not ask about. Run one by name where you have what it needs:

```powershell
cargo test --release --locked --target x86_64-pc-windows-msvc -p hedwig-shell --test menu -- --ignored
```

The suites leave nothing of yours touched: every GnuPG home they make has no card reader, every
ADB server they start listens on a port of its own with USB off, and every `Run` value they write
is named for the run and taken back.

## Building setup

`hedwig-setup` carries whatever folder `HEDWIG_PAYLOAD` names at build, and nothing without it.
`scripts/stage-payload.ps1` lays that folder out from a release build, checking the window's
runtime against its pins in `tools.json`:

```powershell
./scripts/stage-payload.ps1 -Build target/x86_64-pc-windows-msvc/release -Destination target/payload-x64
$env:HEDWIG_PAYLOAD = (Resolve-Path target/payload-x64).Path
cargo build -p hedwig-setup --release --locked --target x86_64-pc-windows-msvc
```

## Constraints the tooling does not enforce

- A crate that ships opens with `#![forbid(unsafe_code)]` unless it is `hedwig-win` or
  `hedwig-shell`; a call to Windows goes there, behind a safe function, its `unsafe` block stating
  its safety argument.
- Imports are grouped `std`, external crates, then `crate`, separated by blank lines.
- Never set `RUSTFLAGS` in the environment, even empty: it replaces the flags in
  `.cargo/config.toml` (static CRT, Control Flow Guard, CET) without warning.
- Every executable's build script links its version resource through
  `hedwig_view::resource::link`, which names the build's commit.

## Commit messages

A bracket tag at the start of the subject sets the release label. Tags stack and are matched
across every commit in a pull request; any other bracket is a scope and is ignored.

| tag | label |
|---|---|
| `[breaking]`, `[major]` | breaking |
| `[feat]`, `[feature]`, `[minor]` | feature |
| `[fix]` | defect |
| `[task]` | task |
| `[dependencies]` | dependencies |

## Releasing

1. Set `version` under `[workspace.package]` in `Cargo.toml`, run `cargo update -w`, and commit
   both files; the release is made from main once that commit is merged.
2. Write the release's notes: what it carries, and what of that is not yet accepted. They become
   the signed tag's message and the published release's own words.
3. Run `./release.ps1 <version> -NotesPath <notes>` from a clean main level with its upstream; it
   pushes a signed `v<version>` tag. A pre-release's version is `<major>.<minor>.<patch>-alpha.<n>`
   and needs its notes. `-WhatIf` runs every check without tagging.
4. The release workflow admits the tag only on a commit of main's first-parent line whose crates
   and lock state its version, runs every check of CI on it, and publishes the downloads with
   their checksums and provenance.
