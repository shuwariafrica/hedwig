#![forbid(unsafe_code)]

use std::ffi::{OsStr, OsString};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use crate::cli::{Config, DEFAULT_PORT, SocketChoice};
use crate::win::CREATE_NO_WINDOW;
use crate::win::registry;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "hedwig";

pub(crate) fn install(cfg: &Config) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let command_line = command_line(exe.as_os_str(), cfg);
    registry::set_current_user_string(RUN_KEY, RUN_VALUE, &command_line)?;
    println!("autostart registered: {}", command_line.to_string_lossy());
    Command::new(&exe)
        .args(serve_args(cfg))
        .creation_flags(CREATE_NO_WINDOW)
        // Otherwise the relay inherits this terminal and writes into it long
        // after install has returned.
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("relay not started: {e}"))?;
    // The spawned process exits on a busy port; only a probe proves a relay
    // is actually serving.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, cfg.port);
    match std::net::TcpStream::connect_timeout(&addr.into(), std::time::Duration::from_secs(3)) {
        Ok(_) => println!("relay is listening on {addr}"),
        Err(e) => return Err(format!("no relay is listening on {addr} after start: {e}")),
    }
    println!("run 'hedwig status' to verify the chain");
    Ok(())
}

pub(crate) fn uninstall() -> Result<(), String> {
    registry::delete_current_user_value(RUN_KEY, RUN_VALUE)?;
    println!("autostart entry removed");
    println!("a running relay keeps running; end it with: taskkill /im hedwig.exe");
    Ok(())
}

fn serve_args(cfg: &Config) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["serve".into()];
    if cfg.port != DEFAULT_PORT {
        args.push("--port".into());
        args.push(cfg.port.to_string().into());
    }
    if cfg.socket != SocketChoice::Extra {
        args.push("--socket".into());
        args.push(cfg.socket.to_string().into());
    }
    if let Some(dir) = &cfg.socketdir {
        args.push("--socketdir".into());
        args.push(dir.clone().into_os_string());
    }
    if let Some(f) = &cfg.log_file {
        args.push("--log-file".into());
        args.push(f.clone().into_os_string());
    }
    args
}

/// A space cannot occur inside a multi-byte sequence, so scanning the encoded
/// form for one is equivalent to scanning the decoded string.
fn command_line(exe: &OsStr, cfg: &Config) -> OsString {
    let mut line = OsString::from("\"");
    line.push(exe);
    line.push("\"");
    for arg in serve_args(cfg) {
        if arg.as_encoded_bytes().contains(&b' ') {
            line.push(" \"");
            line.push(&arg);
            line.push("\"");
        } else {
            line.push(" ");
            line.push(&arg);
        }
    }
    line
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_config_serializes_to_bare_serve() {
        assert_eq!(
            serve_args(&Config::default()),
            vec![OsString::from("serve")]
        );
    }

    #[test]
    fn non_default_options_are_passed_through() {
        let cfg = Config {
            port: 5000,
            socket: SocketChoice::Agent,
            socketdir: Some(PathBuf::from(r"C:\some dir\gnupg")),
            log_file: None,
            verbose: false,
        };
        assert_eq!(
            serve_args(&cfg),
            [
                "serve",
                "--port",
                "5000",
                "--socket",
                "agent",
                "--socketdir",
                r"C:\some dir\gnupg"
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn command_line_quotes_paths_with_spaces() {
        let cfg = Config {
            socketdir: Some(PathBuf::from(r"C:\some dir\gnupg")),
            ..Config::default()
        };
        assert_eq!(
            command_line(OsStr::new(r"C:\Program Files\hedwig.exe"), &cfg),
            OsString::from(
                r#""C:\Program Files\hedwig.exe" serve --socketdir "C:\some dir\gnupg""#
            )
        );
    }
}
