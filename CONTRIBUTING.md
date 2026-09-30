# Contributing

## Setting up

Install [rustup](https://rustup.rs); `rust-toolchain.toml` supplies the toolchain, components and
both targets. The crate builds only on Windows.

## Before opening a pull request

```powershell
cargo fmt --all --check
cargo clippy --locked --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo clippy --locked --all-targets --target aarch64-pc-windows-msvc -- -D warnings
cargo test --release --locked --target x86_64-pc-windows-msvc
Invoke-ScriptAnalyzer -Path . -Recurse -Settings PSScriptAnalyzerSettings.psd1
Invoke-Pester
```

Always pass `--target`: a host whose default toolchain is GNU would otherwise build against the
wrong ABI. The tests need no privileges but open loopback ports and query process tokens; they
run only on a machine of the target's architecture. Pester must be version 6.

Code must build on the `rust-version` declared in `Cargo.toml`; CI checks it.

Every workflow `run:` block declares its shell, through `shell:` or its job's `defaults`, and CI
checks each one with ShellCheck and shfmt (`.shellcheckrc`, `.editorconfig`) or PSScriptAnalyzer.

## Constraints the tooling does not enforce

- `unsafe` lives only under `src/win/`; a new module beside it opens with
  `#![forbid(unsafe_code)]`, as the existing ones do.
- Imports are grouped `std`, external crates, then `crate`, separated by blank lines.
- Never set `RUSTFLAGS` in the environment: it replaces the flags in `.cargo/config.toml` (static
  CRT, Control Flow Guard, CET, the embedded manifest) without warning.

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

1. Set `version` in `Cargo.toml`, run `cargo update -w`, and commit both files.
2. Run `./release.ps1 <version>` from a clean tree level with its upstream; it pushes a signed
   `v<version>` tag. `-WhatIf` runs every check without tagging.
3. CI builds both architectures from the tag and publishes the release, with checksums,
   signatures and a provenance attestation, only when every required check passes.
