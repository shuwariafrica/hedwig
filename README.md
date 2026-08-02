# hedwig

hedwig makes a service on your Windows workstation reachable from a remote host,
over an SSH connection you already have.

The service it carries is gpg-agent. A remote Linux host can then sign your git
commits with an OpenPGP key that never leaves a YubiKey plugged into the Windows
machine in front of you.

On Linux this needs no software at all: gpg-agent listens on a Unix socket and
`ssh -R` forwards it. On Windows there is no socket to forward - gpg-agent writes
a file holding a TCP port and a secret nonce, and `ssh.exe` would forward the
21 bytes of that file rather than a connection to the agent. hedwig is the
endpoint that is missing: it listens on one fixed loopback port and performs the
port-and-nonce handshake the forwarded connection cannot.

Works with any remote you reach over OpenSSH - VMs, servers, and
[Coder](https://coder.com) workspaces over `coder ssh`.

## Installing

Download `hedwig-x64.exe`, or `hedwig-arm64.exe` on Windows on ARM, from the
[releases page](https://github.com/shuwariafrica/hedwig/releases).

### Verifying the download

The binaries carry no Authenticode signature, so Windows will warn about them.
Verify the OpenPGP signature published beside each one instead:

```powershell
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 9E65E1F33DB1D6615CA7DDEF5CBF5337934574A8
gpg --verify hedwig-x64.exe.asc hedwig-x64.exe
```

### Putting it on PATH

`hedwig install` records the path it is run from, so the binary must live
somewhere stable rather than in a downloads folder you might later clear out:

```powershell
$dir = "$env:LOCALAPPDATA\Programs\hedwig"
New-Item -ItemType Directory -Force $dir | Out-Null
Move-Item hedwig-x64.exe "$dir\hedwig.exe" -Force

$p = [Environment]::GetEnvironmentVariable('Path','User')
if (($p -split ';') -notcontains $dir) {
    [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';') + ';' + $dir), 'User')
}
```

### Starting it

Open a new terminal, then register autostart and start it. Neither step needs
Administrator:

```powershell
hedwig install
```

It runs as you, from logon, and holds the port for as long as you are signed in.

## Forwarding gpg-agent

Three things have to line up: hedwig running on the workstation, an `ssh_config`
stanza that forwards to it, and a remote host that leaves the socket path alone.

### On the workstation

In `~/.ssh/config`, add the forward to every host you sign on. The remote path
contains your numeric uid on that host (`id -u` there):

```
Host devbox
    HostName 192.0.2.10
    RemoteForward /run/user/1000/gnupg/S.gpg-agent 127.0.0.1:47470
```

For a Coder workspace the stanza attaches to the generated host pattern -
`coder config-ssh` writes `coder.*`, so:

```
Host coder.*
    RemoteForward /run/user/1000/gnupg/S.gpg-agent 127.0.0.1:47470
```

Put the override *above* the `coder config-ssh` managed block; OpenSSH takes the
first value it sees per option, and `RemoteForward` entries accumulate across
matching stanzas anyway.

### On each remote host

1. `sshd` must allow socket forwarding and replace stale sockets. In
   `/etc/ssh/sshd_config` (or a drop-in under `/etc/ssh/sshd_config.d/`):

   ```
   StreamLocalBindUnlink yes
   ```

   Then reload sshd. `AllowStreamLocalForwarding` must not be `no`/`local`
   (default is `yes`). Without `StreamLocalBindUnlink`, the first dropped
   connection leaves a stale socket file that blocks every later one.

2. The remote must not run its own gpg-agent, or it will fight for the socket
   path. In `~/.gnupg/gpg.conf` on the remote:

   ```
   no-autostart
   ```

   and stop anything already running: `gpgconf --kill gpg-agent`. On distros with
   systemd socket activation for gpg-agent, also
   `systemctl --user disable --now gpg-agent.socket gpg-agent-extra.socket gpg-agent-browser.socket gpg-agent-ssh.socket`.

3. Import your public key and tell git which key signs. The secret half stays on
   the YubiKey; only the public key travels:

   ```
   gpg --import your-public-key.asc
   git config --global user.signingkey <your-fingerprint>
   git config --global commit.gpgsign true
   ```

### Checking the chain

`hedwig status` walks the whole path and stops at the first broken link:

```
gpgconf:      C:\Program Files (x86)\GnuPG\bin\gpgconf.exe
socket file:  C:\Users\you\AppData\Local\gnupg\S.gpg-agent.extra (agent port 51522)
relay:        listening on 127.0.0.1:47470 (pid 9184)
agent:        OK Pleased to meet you
connection:   restricted mode
chain OK: client -> relay -> nonce handshake -> gpg-agent (extra)
```

Its exit status is the verdict, so it can be used in a script.

### Signing

```
ssh devbox
cd some-repo
git commit -S -m "signed from the remote, key never left the YubiKey"
git log --show-signature -1
```

The PIN prompt, when the card session needs one, appears on the **Windows**
desktop rather than in the SSH session.

`gpg -K` on the remote shows nothing. The forwarded socket is GnuPG's
*restricted* socket, which permits signing and decryption but not key listing or
key management. That is deliberate; signing with an explicit key works.

### From a Linux workstation instead

hedwig is not needed - gpg-agent already listens on a real Unix socket. The
remote-host setup above is identical, and the client stanza differs only in the
local endpoint, which `gpgconf --list-dirs agent-extra-socket` prints:

```
Host devbox
    RemoteForward /run/user/1000/gnupg/S.gpg-agent /run/user/1000/gnupg/S.gpg-agent.extra
```

Everything else is the same on both platforms, so a team can publish one runbook
plus this one-line difference.

## Options

```
--port <n>          loopback port to listen on              [default: 47470]
--socket <name>     agent socket to relay: extra|agent      [default: extra]
--socketdir <path>  GnuPG socket directory                  [default: ask gpgconf]
--log-file <path>   append a line per connection and error
--verbose           log to stderr as well
```

The flags given to `install` are baked into the autostart entry, so pass them
there rather than only to `serve`.

`--socket agent` relays the unrestricted socket: the remote end can then also
export file-based secret keys, change passphrases and administer the card. Only
use it if you need remote key management and accept that trade.

hedwig owns its port exclusively, so where two people are signed in at once -
fast user switching, or a Server 2025 session host - give each user a distinct
`--port` and match it in their `RemoteForward`. Without that the second user's
relay cannot start. Their traffic is never mixed up regardless: hedwig refuses
any client not running as its own user.

## What forwarding grants the remote host

While the SSH connection is up, anything that can open the forwarded socket on
the remote host - including root - can request signatures and decryptions with
every key the agent can reach. A fingerprint is enough; no secret material
travels.

The forward dies with the connection, and the restricted socket bars key export
and card administration, but nothing there bounds signing. The only control that
survives a compromised remote is the card's own touch policy:

```
ykman openpgp keys set-touch sig cached
```

With touch off and the PIN cached, nothing limits the rate or count of remote
signatures. Prefer per-host `ssh_config` stanzas over wildcards, and add the
forward only to hosts that warrant it.

## Troubleshooting

| symptom | cause and fix |
|---|---|
| remote: `can't connect to the agent` | Forward not up (reconnect ssh), or a local agent owns the socket path - apply step 2 above. |
| remote: `Warning: remote port forwarding failed` | Stale socket and `StreamLocalBindUnlink` not set (step 1), or `/run/user/<uid>/gnupg` missing - run `gpgconf --create-socketdir` on the remote. |
| remote: `signing failed: No secret key` | Public key not imported on the remote, or `user.signingkey` not set to your fingerprint. |
| `status`: `relay ... unreachable` | Not running: `hedwig install`, or run `hedwig serve --verbose` in a terminal to watch it. |
| `status`: `is not this user's relay` | Something else holds the port. Stop it, or move hedwig to another `--port`. |
| `status`: `relaying to the wrong socket` | The port serves a different `--socket` than `status` was asked to expect; align the flags. |
| PIN prompt seems to hang the remote command | It is waiting on the Windows desktop pinentry. |
| `No such device` right after swapping YubiKeys | USB re-enumeration takes a few seconds; if it persists, `gpgconf --kill scdaemon` and retry. |

Two YubiKeys carrying the same key need no reconfiguration between swaps: gpg
addresses card keys by keygrip, so whichever card is present is used regardless
of the serial recorded in the key stubs.

## Building from source

An alternative to downloading a release; the install steps above are otherwise
unchanged. Needs [rustup](https://rustup.rs), which takes the toolchain from
`rust-toolchain.toml` on the first build:

```powershell
cargo build --release   # target\release\hedwig.exe, ~400 KB
```

The binary links the CRT statically and imports only DLLs that ship with Windows,
so there is nothing to install alongside it.

## Removing hedwig

```powershell
hedwig uninstall                        # remove the autostart entry
Stop-Process -Name hedwig -Force        # stop the running process
$dir = "$env:LOCALAPPDATA\Programs\hedwig"
$p = [Environment]::GetEnvironmentVariable('Path','User')
[Environment]::SetEnvironmentVariable('Path',
    (($p -split ';' | Where-Object { $_ -and $_ -ne $dir }) -join ';'), 'User')
Remove-Item -Recurse -Force $dir
```

`uninstall` only removes the autostart entry; the running process and the `PATH`
entry are separate and are cleared by the remaining steps.

Dependencies: [`windows-sys`](https://crates.io/crates/windows-sys) and
[`zeroize`](https://crates.io/crates/zeroize). MIT licence.
