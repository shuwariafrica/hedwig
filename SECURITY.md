# Security policy

## Reporting a vulnerability

Use **Security → Report a vulnerability** on this repository. Please do not open
a public issue for anything that affects the confidentiality of agent access.

Expect an acknowledgement within five working days.

## Supported versions

The most recent release only. Fixes are shipped as a new version, not as patches
to older tags.

## Scope

In scope: anything that lets a principal reach gpg-agent through the relay that
could not reach it without the relay installed. Concretely, the peer admission
policy, the nonce handshake and its ordering, socket-file parsing, and the
autostart entry.

Out of scope, being accepted properties of the design rather than defects:

- Any process running as the user can read the nonce file and speak to gpg-agent
  directly, with or without this tool installed. The relay's admission policy is
  calibrated to that same set, so it neither widens nor narrows it.
- Administrators and SYSTEM can read the nonce file, debug the relay or replace
  it.
- A compromised remote host can request signatures for the life of a forwarded
  connection, bounded only by the card's touch policy.

A report restating one of these is not a vulnerability report. A report showing
that the relay *widens* one of them is.

## Verifying a release

Every release asset carries a detached OpenPGP signature from the Shuwari Africa
publishing key, `Shuwari Dev Team <developers@shuwari.africa>`:

```
9E65E1F33DB1D6615CA7DDEF5CBF5337934574A8
```

That fingerprint is the trust anchor. Fetch the key from a keyserver rather than
from the release it authenticates, then verify the asset you downloaded, or
`SHA256SUMS` to cover all of them at once:

```
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 9E65E1F33DB1D6615CA7DDEF5CBF5337934574A8
gpg --verify hedwig-x64.exe.asc hedwig-x64.exe
```

Binaries are not Authenticode-signed; expect a SmartScreen warning on direct
download.

Every release also carries a GitHub build provenance attestation:

```
gh attestation verify hedwig-x64.exe --repo shuwariafrica/hedwig
```
