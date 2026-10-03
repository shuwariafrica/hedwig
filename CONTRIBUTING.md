# Contributing

## Setting up

Install [rustup](https://rustup.rs); `rust-toolchain.toml` supplies the toolchain, components and
both targets. The workspace builds only on Windows, and its scripts need PowerShell 7.

The suites run real programs - GnuPG's own Windows build, Android's platform-tools, pyserial -
which `scripts/fetch-test-tools.ps1` fetches into `target\test-tools`, each pinned by version and
SHA-256. It emits the variables the suites read; set them in the session that runs the tests:

```powershell
./scripts/fetch-test-tools.ps1 | ForEach-Object { Set-Item -Path "Env:$($_.Name)" -Value $_.Value }
```

## The crates

| crate | what it is |
|---|---|
| `hedwig-model` | the model, the gate, the written form and the control protocol; no call to Windows |
| `hedwig-win` | every call to Windows the other crates make, and the only crate that ships `unsafe` |
| `hedwig-core` | the core, its relays, its store and the supervisor |
| `hedwig-client` | finding, speaking to, installing and removing a running Hedwig |
| `hedwig` | `hedwig.exe`: the supervisor, the core, removal and a channel's askpass |
| `hedwig-support` | the stand-ins and harness the process suites drive; never shipped |

## Before opening a pull request

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings
cargo clippy --workspace --all-targets --locked --target aarch64-pc-windows-msvc -- -D warnings
cargo build --workspace --release --locked --target x86_64-pc-windows-msvc
cargo test --workspace --release --locked --target x86_64-pc-windows-msvc
cargo doc --workspace --no-deps --locked
Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1
Invoke-Pester
```

Always pass `--target`: a host whose default toolchain is GNU would otherwise build against the
wrong ABI. Build before testing: the suites run the `hedwig.exe` the build leaves beside them.
`cargo doc` runs with `RUSTDOCFLAGS` set to `-D warnings` in CI. Pester must be version 6.

The suites need no privileges and leave nothing of yours touched: every GnuPG home they make has
no card reader, every ADB server they start listens on a port of its own with USB off, and every
`Run` value they write is named for the run and taken back. A test marked ignored needs something
a hosted runner lacks - an SSH server on loopback, a registered GnuPG for Windows, a COM port, an
elevated session - and its marking says which; run it by name where you have that:

```powershell
cargo test --release --locked --target x86_64-pc-windows-msvc -p hedwig-support --test prompts -- --ignored
```

Every workflow `run:` block declares its shell, through `shell:` or its job's `defaults`, and CI
checks each one with ShellCheck and shfmt (`.shellcheckrc`, `.editorconfig`) or PSScriptAnalyzer.

## Constraints the tooling does not enforce

- A crate that ships opens with `#![forbid(unsafe_code)]` unless it is `hedwig-win`; a call to
  Windows goes there, behind a safe function, its `unsafe` block stating its safety argument.
- Imports are grouped `std`, external crates, then `crate`, separated by blank lines.
- Never set `RUSTFLAGS` in the environment: it replaces the flags in `.cargo/config.toml` (static
  CRT, Control Flow Guard, CET) without warning.

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
   both files.
2. Run `./release.ps1 <version>` from a clean tree level with its upstream; it pushes a signed
   `v<version>` tag. `-WhatIf` runs every check without tagging.
3. CI builds both architectures from the tag and publishes the release, with checksums,
   signatures and a provenance attestation, only when every required check passes.
