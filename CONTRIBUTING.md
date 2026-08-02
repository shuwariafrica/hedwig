# Contributing

## Getting set up

Install [rustup](https://rustup.rs); `rust-toolchain.toml` supplies the
toolchain, components and both targets on the first cargo command.

The crate is Windows-only and does not compile elsewhere. Formatting and
`cargo-deny` are the only checks that run on other platforms.

## The checks CI runs

```powershell
cargo build --release --locked --target x86_64-pc-windows-msvc
cargo test --locked --target x86_64-pc-windows-msvc
cargo clippy --locked --all-targets --target x86_64-pc-windows-msvc -- -D warnings
cargo fmt --all --check
```

Naming the target explicitly is what pins the MSVC ABI rather than inheriting
whatever the host defaults to. Substitute `aarch64-pc-windows-msvc` for the
other architecture: the cross-build works from an x64 machine if Visual Studio's
ARM64 tools are installed, though only a native runner executes the tests.

CI additionally runs the suite on beta and on the MSRV declared in
`Cargo.toml`, and `cargo doc` with warnings denied.

Imports are grouped `std`, then external crates, then `crate`, separated by blank
lines. `rustfmt` sorts within a group but cannot enforce the grouping on stable,
so keep to it by hand.

`.cargo/config.toml` carries the static CRT, Control Flow Guard, CET and the
embedded `app.manifest`. Setting `RUSTFLAGS` in the environment replaces those
flags rather than adding to them, and does so silently — losing the mitigations
without a warning.

## Tests

The suite uses real loopback sockets and real process tokens rather than mocks,
because what is under test is Windows' behaviour: half-close semantics on
`TcpStream`, the TCP connection table's attribution of a socket to a process,
and `CreateRestrictedToken`. They are ordinary unit tests and need no
privileges, but they do open ports and query processes.

`unwrap` and `expect` are denied outside `#[cfg(test)]`, so library code returns
errors rather than panicking on anything reachable from a relayed connection.

## Commit messages

Bracket tags at the start of the subject drive release labelling. Reserved tags
are types; any other bracket is a scope and is ignored for labelling:

| tag | label |
|---|---|
| `[breaking]`, `[major]` | breaking |
| `[feat]`, `[feature]`, `[minor]` | feature |
| `[fix]` | defect |
| `[task]` | task |
| `[dependencies]` | dependencies |

Tags stack, and they are matched across every commit in a pull request:
`[breaking][feat] relay: ...` earns both labels.

## Releasing

1. Bump `version` in `Cargo.toml`, run `cargo update -w` so `Cargo.lock`
   follows, and commit both.
2. Run `./release.ps1 <version>`. It refuses to tag unless the working tree is
   clean, the branch is level with its upstream, and `Cargo.toml` and
   `Cargo.lock` both declare that version; then it pushes a signed `v<version>`
   tag.
3. The tag builds both architectures, and publishes only if the whole matrix is
   green. Binaries, `SHA256SUMS`, a detached OpenPGP signature for each, and a
   build provenance attestation are attached to the release automatically —
   nothing is built or hashed by hand.
