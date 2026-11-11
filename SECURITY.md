# Security policy

## Reporting a vulnerability

Use **Security, Report a vulnerability** on this repository, never a public issue, for anything
that would let something reach what a workstation holds beyond what its person granted.
Expect an acknowledgement within five working days.

## Supported versions

The most recent release only. A fix ships as the next release.

## What Hedwig promises

- A remote reaches only what a grant lends it, decided request by request by the person's grants
  and rules within any limit their organisation sets; what those leave to the person is asked of
  them, and refused while nothing can ask them.
- Hedwig's control pipe admits the person's own processes alone: their account, at medium
  integrity or above, not restricted to less, and not in an application container.
- GnuPG's socket file is answered on a remote's behalf only to a listener whose own token could
  read that file, so a process learns nothing from Hedwig that it could not read itself.
- Hedwig writes on a remote only what the person consented to, each write named first, and takes
  it back when the consent ends or Hedwig is removed.
- Hedwig runs as the person and is never elevated; setup refuses to run elevated.

A report that Hedwig breaks one of these is in scope, and so is any flaw in how it reads what a
remote or a client sends: GnuPG's Assuan, the SSH agent's protocol, ADB, a channel's prompts, the
control protocol, and the files Hedwig keeps.

Out of scope, being properties of what Hedwig lends rather than defects:

- A process running as the person reaches their gpg-agent, SSH agent and ADB server with or
  without Hedwig.
- Administrators and SYSTEM can read what the person holds, and replace Hedwig.
- A remote granted a key can ask for signatures with it for as long as the grant serves it, each
  decided as the grant says. The control that survives a compromised remote is the card's own: a
  key whose card asks for a touch signs nothing without one.

## Verifying a release

Every release lists the SHA-256 of each file in `SHA256SUMS` and carries GitHub's attestation of
where each file was built; the README shows the commands that check both. A release cannot be
changed once it is published, and its tag is signed by the maintainer who made it. Release files
carry no OpenPGP signature, and no Authenticode signature, so SmartScreen warns once, at setup.
