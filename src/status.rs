#![forbid(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

use crate::cli::Config;
use crate::gpgconf;
use crate::socketfile;
use crate::win::peer;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Walks the chain a remote signing request traverses, stopping at the first
/// broken link. The exit status is the verdict; the printed lines locate the
/// break.
pub(crate) fn run(cfg: &Config) -> Result<(), String> {
    let gpgconf_path = gpgconf::locate_gpgconf();
    match &gpgconf_path {
        Some(p) => println!("gpgconf:      {}", p.display()),
        None => println!("gpgconf:      not found"),
    }
    let socket_dir = gpgconf::socket_dir(cfg.socketdir.as_deref(), gpgconf_path.as_deref())
        .map_err(|e| e.to_string())?;
    let socket_file = socket_dir.join(cfg.socket.file_name());
    match socketfile::read_from(&socket_file) {
        Err(socketfile::ReadError::Io(e)) => println!(
            "socket file:  {} unreadable ({e}) - the relay will launch gpg-agent on demand",
            socket_file.display()
        ),
        Err(socketfile::ReadError::Parse(e)) => {
            return Err(format!("socket file:  {}: {e}", socket_file.display()));
        }
        Ok((port, _nonce)) => println!(
            "socket file:  {} (agent port {port})",
            socket_file.display()
        ),
    }

    let relay_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, cfg.port);
    let mut stream = TcpStream::connect_timeout(&relay_addr.into(), TIMEOUT).map_err(|e| {
        format!("relay:        {relay_addr} unreachable ({e}) - is 'hedwig serve' running?")
    })?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    let our_end = match stream.local_addr().map_err(|e| e.to_string())? {
        SocketAddr::V4(a) => a,
        a @ SocketAddr::V6(_) => return Err(format!("unexpected local address {a}")),
    };
    let relay_pid = peer::verify_same_user(&stream, our_end)
        .map_err(|e| format!("relay:        {relay_addr} is not this user's relay: {e}"))?;
    println!("relay:        listening on {relay_addr} (pid {relay_pid})");

    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let greeting = read_line(&mut reader)?;
    if !greeting.starts_with("OK") {
        return Err(format!("agent:        unexpected greeting '{greeting}'"));
    }
    println!("agent:        {greeting}");

    stream
        .write_all(b"GETINFO restricted\n")
        .map_err(|e| e.to_string())?;
    let restricted = read_line(&mut reader)?.starts_with("OK");
    let expected = cfg.socket.expects_restricted();
    println!(
        "connection:   {} mode",
        if restricted {
            "restricted"
        } else {
            "UNRESTRICTED"
        }
    );
    if restricted != expected {
        return Err(format!(
            "the relay answers as {} but --socket {} expects {}: it is relaying to the wrong socket",
            if restricted {
                "restricted"
            } else {
                "unrestricted"
            },
            cfg.socket,
            if expected {
                "restricted"
            } else {
                "unrestricted"
            },
        ));
    }
    let _ = stream.write_all(b"BYE\n");
    println!(
        "chain OK: client -> relay -> nonce handshake -> gpg-agent ({})",
        cfg.socket
    );
    Ok(())
}

fn read_line(reader: &mut impl BufRead) -> Result<String, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| format!("agent read: {e}"))?;
    if line.is_empty() {
        return Err("agent closed the connection".into());
    }
    Ok(line.trim_end().to_string())
}
