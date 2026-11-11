# Hedwig

Hedwig lends what your Windows workstation holds to a remote you reach over SSH, with nothing of
Hedwig's installed on the remote:

- **GnuPG**: `gpg` and `git commit -S` on the remote sign and decrypt with your workstation's
  keys, those on a smart card included. One key on two YubiKeys signs from whichever is plugged
  in, with nothing to redo when you swap them.
- **Your SSH agent**: `ssh` and `git` on the remote log in and sign with the keys your agent
  holds, Windows' own OpenSSH agent or gpg-agent's.
- **ADB**: `adb` on the remote reaches the Android devices plugged into the workstation, through
  your own ADB server, so an app built on the remote is installed and debugged on the device on
  your desk.

Hedwig opens its own connection to each remote you grant, with your `ssh` client and your
`ssh_config`, and carries over it only what the grant lends. Before each connection it asks the
remote's own tools where each part goes and says what is in the way; with your consent it writes
what those tools need there, each write named before you consent and taken back when consent ends.
A request the grant leaves to you is put to you by a card beside Hedwig's icon in the
notification area, and Hedwig's window shows what is reachable from where and what each remote
has done.

Hedwig serves Linux remotes. It is before its first stable release: each release's notes say what
it carries and what of that is not yet accepted.

## Installing

Hedwig runs on Windows 11, x64 or ARM64. Download `hedwig-setup-x64.exe`, or
`hedwig-setup-arm64.exe`, from the [releases page](https://github.com/shuwariafrica/hedwig/releases)
and verify it (below).

Run setup as yourself, never as administrator: it installs for your account alone, and refuses an
elevated start before it writes anything. Hedwig's files carry no Authenticode signature, so
SmartScreen warns once, at setup. It asks one question - whether to install, and whether Hedwig
and its icon then start when you sign in - and opens Hedwig's window when Hedwig answers. Running
setup again over an installed Hedwig updates it and asks nothing.

Hedwig is installed in `%LOCALAPPDATA%\Programs\ShuwariAfrica\Hedwig` and keeps its own files in
`%LOCALAPPDATA%\ShuwariAfrica\Hedwig`.

A script installs with `hedwig-setup-x64.exe --quiet`, adding `--at-logon` to start Hedwig and its
icon at sign-in. Setup writes what it did, or why it could not, to its output, and exits:

| status | meaning |
|---|---|
| 0 | installed and running |
| 2 | an argument setup does not take |
| 10 | started elevated |
| 11 | the program folder cannot hold Hedwig |
| 12 | the setup file is damaged, or carries no Hedwig |
| 13 | a file could not be placed |
| 14 | a program still uses Hedwig's files; close it and try again |
| 15 | the Hedwig running could not be stopped |
| 16 | Windows' list of your applications could not be written |
| 17 | Hedwig could not be started |
| 18 | Hedwig did not answer |
| 19 | Hedwig answered as another version |
| 20 | setup's question was cancelled |

### Verifying a download

Each release lists the SHA-256 of every file in `SHA256SUMS`, and GitHub attests where each was
built. Check the file you downloaded, here setup for x64 from the release tagged `<tag>`:

```powershell
(Get-FileHash hedwig-setup-x64.exe -Algorithm SHA256).Hash   # compare with its line in SHA256SUMS
gh attestation verify hedwig-setup-x64.exe --repo shuwariafrica/hedwig --signer-workflow shuwariafrica/hedwig/.github/workflows/release.yml
gh release verify-asset <tag> hedwig-setup-x64.exe --repo shuwariafrica/hedwig
```

The release's tag is signed by the maintainer who made it, and a release cannot be changed once it
is published. Release files are not yet signed with OpenPGP.

## Lending to a remote

The window's first run shows what this workstation has to lend - its GnuPG and the keys it offers,
your SSH agent, your ADB server and its devices - with a first grant made ready. A grant names
what it lends and the remote, as `ssh` reaches it (the host name you would type after `ssh`), and
when Hedwig holds the connection: when a request needs it, while the remote runs, or always. It
says what the remote can do with what is lent before you make it.

Hedwig's connection takes what your `ssh_config` says for the host but for the few options Hedwig
sets itself, and is tagged `hedwig`. The forwards your configuration declares for the host ride it
too, so a forward meant for your own sessions alone goes under
`Match originalhost <host> !tagged hedwig`.

Everything a remote can then do is bounded by what you granted, and what the grant leaves to you
is asked of you at the card. A card's own controls still hold: a key whose card asks for a touch
signs nothing while you are away from it.

## Hedwig without its icon and window

`hedwig-x64.exe` and `hedwig-arm64.exe` are Hedwig's core alone, the `hedwig.exe` setup installs,
with no icon, window or setup. It has no commands for people yet; without the icon, a request that
needs your answer is refused, since nothing can put it to you.

## Removing

Remove Hedwig from Settings, Apps, Installed apps. It shows what Hedwig wrote on each remote, takes
that back first, and says what it could not reach; your settings go with Hedwig, so export them
from the window first to keep them. A script removes it with
`& "$env:LOCALAPPDATA\Programs\ShuwariAfrica\Hedwig\hedwig.exe" remove --quiet`.

## Building from source

[CONTRIBUTING.md](CONTRIBUTING.md) sets up the toolchain and the suites and lists the checks a pull
request runs.

## Licence

MIT.
