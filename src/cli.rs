#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

pub(crate) const DEFAULT_PORT: u16 = 47470;

pub(crate) const USAGE: &str = "\
hedwig - forward the Windows gpg-agent to Linux hosts over `ssh -R`

usage:
  hedwig serve     [options]      run the relay in the foreground
  hedwig install   [options]      register per-user autostart and start the relay
  hedwig uninstall                remove the autostart entry
  hedwig status    [options]      check the whole chain and report
  hedwig version
  hedwig help

options:
  --port <n>          loopback TCP port to listen on            [default: 47470]
  --socket <name>     gpg-agent socket to relay to: extra|agent [default: extra]
  --socketdir <path>  GnuPG socket directory                    [default: ask gpgconf]
  --log-file <path>   append log lines to this file
  --verbose           log every connection to stderr

`extra` relays to S.gpg-agent.extra (restricted: signing and decryption, no key
export, no card administration). `agent` relays to the unrestricted socket and
grants the remote end everything the local user can ask of the agent.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocketChoice {
    Extra,
    Agent,
}

impl SocketChoice {
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            SocketChoice::Extra => "S.gpg-agent.extra",
            SocketChoice::Agent => "S.gpg-agent",
        }
    }
    /// `GETINFO restricted` answers OK on the extra socket and ERR on the
    /// unrestricted one; status uses this to detect relaying to the wrong socket.
    pub(crate) fn expects_restricted(self) -> bool {
        matches!(self, SocketChoice::Extra)
    }
}

impl fmt::Display for SocketChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SocketChoice::Extra => "extra",
            SocketChoice::Agent => "agent",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) port: u16,
    pub(crate) socket: SocketChoice,
    pub(crate) socketdir: Option<PathBuf>,
    pub(crate) log_file: Option<PathBuf>,
    pub(crate) verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            port: DEFAULT_PORT,
            socket: SocketChoice::Extra,
            socketdir: None,
            log_file: None,
            verbose: false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Cmd {
    Serve(Config),
    Install(Config),
    Uninstall,
    Status(Config),
    Version,
    Help,
}

pub(crate) fn parse(args: &[OsString]) -> Result<Cmd, String> {
    let mut it = args.iter();
    let Some(sub) = it.next() else {
        return Ok(Cmd::Help);
    };
    // Held as a constructor so a new subcommand cannot silently fall through
    // to one of these.
    let build: fn(Config) -> Cmd = match text_of(sub, "command")? {
        "version" | "--version" | "-V" => return no_more_args(it, Cmd::Version),
        "help" | "--help" | "-h" => return no_more_args(it, Cmd::Help),
        "uninstall" => return no_more_args(it, Cmd::Uninstall),
        "serve" => Cmd::Serve,
        "install" => Cmd::Install,
        "status" => Cmd::Status,
        other => return Err(format!("unknown command '{other}'")),
    };
    let mut cfg = Config::default();
    while let Some(arg) = it.next() {
        match text_of(arg, "option")? {
            "--port" => {
                let v = text_of(value_of(&mut it, "--port")?, "--port")?;
                cfg.port = v
                    .parse::<u16>()
                    .ok()
                    .filter(|p| *p != 0)
                    .ok_or_else(|| format!("--port needs a number in 1..=65535, got '{v}'"))?;
            }
            "--socket" => {
                cfg.socket = match text_of(value_of(&mut it, "--socket")?, "--socket")? {
                    "extra" => SocketChoice::Extra,
                    "agent" => SocketChoice::Agent,
                    v => return Err(format!("--socket must be 'extra' or 'agent', got '{v}'")),
                };
            }
            "--socketdir" => cfg.socketdir = Some(PathBuf::from(value_of(&mut it, "--socketdir")?)),
            "--log-file" => cfg.log_file = Some(PathBuf::from(value_of(&mut it, "--log-file")?)),
            "--verbose" => cfg.verbose = true,
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    Ok(build(cfg))
}

fn value_of<'a>(
    it: &mut impl Iterator<Item = &'a OsString>,
    opt: &str,
) -> Result<&'a OsString, String> {
    it.next().ok_or_else(|| format!("{opt} needs a value"))
}

fn text_of<'a>(value: &'a OsStr, what: &str) -> Result<&'a str, String> {
    value
        .to_str()
        .ok_or_else(|| format!("{what} is not valid text: '{}'", value.to_string_lossy()))
}

fn no_more_args<'a>(mut it: impl Iterator<Item = &'a OsString>, cmd: Cmd) -> Result<Cmd, String> {
    match it.next() {
        None => Ok(cmd),
        Some(a) => Err(format!("unexpected argument '{}'", a.to_string_lossy())),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn p(args: &[&str]) -> Result<Cmd, String> {
        parse(&args.iter().map(OsString::from).collect::<Vec<_>>())
    }

    #[test]
    fn no_args_is_help() {
        assert_eq!(p(&[]), Ok(Cmd::Help));
    }

    #[test]
    fn serve_defaults() {
        assert_eq!(p(&["serve"]), Ok(Cmd::Serve(Config::default())));
    }

    #[test]
    fn all_options() {
        let cmd = p(&[
            "serve",
            "--port",
            "5000",
            "--socket",
            "agent",
            "--socketdir",
            r"C:\x",
            "--log-file",
            r"C:\l.txt",
            "--verbose",
        ])
        .unwrap();
        assert_eq!(
            cmd,
            Cmd::Serve(Config {
                port: 5000,
                socket: SocketChoice::Agent,
                socketdir: Some(PathBuf::from(r"C:\x")),
                log_file: Some(PathBuf::from(r"C:\l.txt")),
                verbose: true,
            })
        );
    }

    #[test]
    fn port_zero_rejected() {
        assert!(p(&["serve", "--port", "0"]).is_err());
    }

    #[test]
    fn port_overflow_rejected() {
        assert!(p(&["serve", "--port", "65536"]).is_err());
    }

    #[test]
    fn port_missing_value_rejected() {
        assert!(p(&["serve", "--port"]).is_err());
    }

    #[test]
    fn bad_socket_rejected() {
        assert!(p(&["serve", "--socket", "browser"]).is_err());
    }

    #[test]
    fn unknown_command_rejected() {
        assert!(p(&["frobnicate"]).is_err());
    }

    #[test]
    fn unknown_option_rejected() {
        assert!(p(&["serve", "--frob"]).is_err());
    }

    #[test]
    fn uninstall_takes_no_options() {
        assert!(p(&["uninstall", "--port", "1"]).is_err());
        assert_eq!(p(&["uninstall"]), Ok(Cmd::Uninstall));
    }

    #[test]
    fn version_forms() {
        assert_eq!(p(&["version"]), Ok(Cmd::Version));
        assert_eq!(p(&["--version"]), Ok(Cmd::Version));
        assert_eq!(p(&["-V"]), Ok(Cmd::Version));
    }
}
