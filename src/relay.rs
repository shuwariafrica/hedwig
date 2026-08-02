#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::path::Path;
use std::time::Duration;

use zeroize::Zeroize;

use crate::gpgconf;
use crate::logging::Logger;
use crate::socketfile;
use crate::win::peer;

const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the finishing side waits for the opposite pump to notice.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// One accepted client, handled to completion. Order is load-bearing:
/// 1. the client is identity-checked before anything else happens;
/// 2. the agent endpoint is identity-checked before the nonce is sent;
/// 3. any failure closes the client connection with nothing written to it.
pub(crate) fn handle_client(
    client: TcpStream,
    listen_addr: SocketAddrV4,
    socket_file: &Path,
    gpgconf_path: Option<&Path>,
    log: &Logger,
) {
    let client_pid = match peer::verify_same_user(&client, listen_addr) {
        Ok(pid) => pid,
        Err(e) => {
            log.error(&format!("client rejected: {e}"));
            return;
        }
    };
    let agent = match connect_to_agent(socket_file, gpgconf_path, log) {
        Ok(agent) => agent,
        Err(e) => {
            log.error(&format!("agent unreachable: {e}"));
            return;
        }
    };
    log.info(&format!("relaying for pid {client_pid}"));
    let _ = client.set_nodelay(true);
    let _ = agent.set_nodelay(true);
    splice(client, agent, log);
}

/// The socket file is re-read on every call because the agent rewrites it with
/// a new port and nonce at every start. A single `gpgconf --launch gpg-agent`
/// retry covers a stopped agent and a stale file alike.
fn connect_to_agent(
    socket_file: &Path,
    gpgconf_path: Option<&Path>,
    log: &Logger,
) -> std::io::Result<TcpStream> {
    match attempt_agent_connection(socket_file) {
        Ok(agent) => Ok(agent),
        Err(first) => {
            let gpgconf_path = gpgconf_path.ok_or_else(|| {
                other(format!(
                    "{first}; gpgconf not found, cannot launch gpg-agent"
                ))
            })?;
            log.info(&format!("{first}; launching gpg-agent"));
            gpgconf::launch_agent(gpgconf_path)?;
            attempt_agent_connection(socket_file)
        }
    }
}

fn attempt_agent_connection(socket_file: &Path) -> std::io::Result<TcpStream> {
    let (port, nonce) = socketfile::read_from(socket_file)
        .map_err(|e| other(format!("{}: {e}", socket_file.display())))?;
    let agent_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut agent = TcpStream::connect_timeout(&agent_addr.into(), AGENT_CONNECT_TIMEOUT)
        .map_err(|e| other(format!("connect to agent at {agent_addr}: {e}")))?;
    let our_end = match agent.local_addr()? {
        SocketAddr::V4(a) => a,
        a @ SocketAddr::V6(_) => return Err(other(format!("unexpected local address {a}"))),
    };
    peer::verify_same_user(&agent, our_end)
        .map_err(|e| other(format!("listener on {agent_addr} rejected: {e}")))?;
    agent.write_all(nonce.as_bytes())?;
    Ok(agent)
}

fn splice(client: TcpStream, agent: TcpStream, log: &Logger) {
    let client_read = match client.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log.error(&format!("clone failed: {e}"));
            return;
        }
    };
    let agent_write = match agent.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log.error(&format!("clone failed: {e}"));
            return;
        }
    };
    let client_end = match client.try_clone() {
        Ok(s) => s,
        Err(e) => {
            log.error(&format!("clone failed: {e}"));
            return;
        }
    };
    let (relayed, count) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new().spawn(move || {
        let n = pump(client_read, agent_write, Shutdown::Write).unwrap_or(0);
        let _ = relayed.send(n);
    });
    if let Err(e) = spawned {
        log.error(&format!("cannot start relay thread: {e}"));
        return;
    }
    let to_client = pump(agent, client, Shutdown::Write).unwrap_or(0);
    let _ = client_end.shutdown(Shutdown::Both);
    // Windows will not unblock a recv that is already pending, so a client
    // that ignores the close cannot be woken. Waiting on a channel rather
    // than joining bounds that to one detached thread, instead of stranding
    // this thread and its connection slot with it.
    let to_agent = count.recv_timeout(DRAIN_TIMEOUT).unwrap_or(0);
    log.info(&format!(
        "connection closed: {to_agent} bytes to agent, {to_client} to client"
    ));
}

/// Copies until EOF or error, then half-closes the write side so the opposite
/// pump drains and terminates. PKDECRYPT results pass through here, so the
/// buffer is zeroised when the pump ends.
fn pump(mut from: TcpStream, mut to: TcpStream, on_end: Shutdown) -> std::io::Result<u64> {
    let mut buf = [0u8; 8192];
    let mut total = 0u64;
    let result = loop {
        match from.read(&mut buf) {
            Ok(0) => break Ok(total),
            #[allow(clippy::indexing_slicing, reason = "read returns at most buf.len()")]
            Ok(n) => match to.write_all(&buf[..n]) {
                Ok(()) => total += n as u64,
                Err(e) => break Err(e),
            },
            Err(e) => break Err(e),
        }
    };
    buf.zeroize();
    let _ = to.shutdown(on_end);
    if result.is_err() {
        let _ = from.shutdown(Shutdown::Both);
    }
    result
}

fn other(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::TcpListener;

    /// Splice must move bytes both ways and propagate EOF so neither side
    /// hangs. Uses real loopback sockets: the pump's contract is about
    /// `TcpStream` half-close behaviour, which mocks cannot exercise.
    #[test]
    fn splice_moves_bytes_and_propagates_eof() {
        let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut end_a = TcpStream::connect(listener_a.local_addr().unwrap()).unwrap();
        let (side_a, _) = listener_a.accept().unwrap();
        let mut end_b = TcpStream::connect(listener_b.local_addr().unwrap()).unwrap();
        let (side_b, _) = listener_b.accept().unwrap();

        let log = Logger::new(false, None).unwrap();
        let spliced = std::thread::spawn(move || splice(side_a, side_b, &log));

        end_a.write_all(b"to-b").unwrap();
        let mut got = [0u8; 4];
        end_b.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"to-b");

        end_b.write_all(b"to-a").unwrap();
        end_a.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"to-a");

        drop(end_a);
        let mut rest = Vec::new();
        end_b.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
        drop(end_b);
        spliced.join().unwrap();
    }

    /// A client is under no obligation to close when the agent does. Bounded by
    /// a timeout because the failure being guarded against is an unbounded wait.
    #[test]
    fn agent_closing_first_does_not_strand_the_relay_thread() {
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let agent_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(client_listener.local_addr().unwrap()).unwrap();
        let (client_side, _) = client_listener.accept().unwrap();
        let agent = TcpStream::connect(agent_listener.local_addr().unwrap()).unwrap();
        let (agent_side, _) = agent_listener.accept().unwrap();

        let (finished, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let log = Logger::new(false, None).unwrap();
            splice(client_side, agent_side, &log);
            let _ = finished.send(());
        });

        drop(agent);
        wait.recv_timeout(Duration::from_secs(10))
            .expect("splice must not wait on a client that never closes");
        drop(client);
    }

    /// The whole relayed path in one test: peer admission, socket-file parse,
    /// agent connect, listener admission, nonce handshake, splice. The fake
    /// agent asserts the nonce arrives before any client byte does.
    #[test]
    fn relays_a_connection_after_the_nonce_handshake() {
        const GREETING: &[u8] = b"OK Pleased to meet you\n";
        let nonce = [0x5Au8; 16];

        let agent_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let agent_port = agent_listener.local_addr().unwrap().port();

        let dir = std::env::temp_dir().join(format!("hedwig-relay-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_file = dir.join("S.gpg-agent.extra");
        let mut contents = format!("{agent_port}\n").into_bytes();
        contents.extend_from_slice(&nonce);
        std::fs::write(&socket_file, &contents).unwrap();

        let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(relay_addr) = relay_listener.local_addr().unwrap() else {
            unreachable!("bound to 127.0.0.1")
        };
        let mut client = TcpStream::connect(relay_addr).unwrap();
        let (server_side, _) = relay_listener.accept().unwrap();

        let relaying = {
            let socket_file = socket_file.clone();
            std::thread::spawn(move || {
                let log = Logger::new(false, None).unwrap();
                handle_client(server_side, relay_addr, &socket_file, None, &log);
            })
        };

        let (mut agent_side, _) = agent_listener.accept().unwrap();
        let mut delivered = [0u8; 16];
        agent_side.read_exact(&mut delivered).unwrap();
        assert_eq!(
            delivered, nonce,
            "the nonce must precede any client traffic"
        );

        agent_side.write_all(GREETING).unwrap();
        let mut greeting = vec![0u8; GREETING.len()];
        client.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, GREETING);

        client.write_all(b"BYE\n").unwrap();
        let mut request = [0u8; 4];
        agent_side.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"BYE\n");

        drop(client);
        drop(agent_side);
        relaying.join().unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A socket file naming a port nothing listens on must not leave the client
    /// holding a half-open connection.
    #[test]
    fn unreachable_agent_closes_the_client() {
        let dir = std::env::temp_dir().join(format!("hedwig-dead-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let socket_file = dir.join("S.gpg-agent.extra");
        // Bound and dropped, so the port is known to have no listener.
        let dead_port = {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            probe.local_addr().unwrap().port()
        };
        let mut contents = format!("{dead_port}\n").into_bytes();
        contents.extend_from_slice(&[0u8; 16]);
        std::fs::write(&socket_file, &contents).unwrap();

        let relay_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let SocketAddr::V4(relay_addr) = relay_listener.local_addr().unwrap() else {
            unreachable!("bound to 127.0.0.1")
        };
        let mut client = TcpStream::connect(relay_addr).unwrap();
        let (server_side, _) = relay_listener.accept().unwrap();

        let log = Logger::new(false, None).unwrap();
        handle_client(server_side, relay_addr, &socket_file, None, &log);

        let mut anything = Vec::new();
        client.read_to_end(&mut anything).unwrap();
        assert!(
            anything.is_empty(),
            "nothing may be written to a client that was never relayed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pump_reports_bytes_copied() {
        let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut end_a = TcpStream::connect(listener_a.local_addr().unwrap()).unwrap();
        let (side_a, _) = listener_a.accept().unwrap();
        let mut end_b = TcpStream::connect(listener_b.local_addr().unwrap()).unwrap();
        let (side_b, _) = listener_b.accept().unwrap();

        end_a.write_all(b"12345").unwrap();
        drop(end_a);
        let copied = pump(side_a, side_b, Shutdown::Write).unwrap();
        assert_eq!(copied, 5);
        let mut got = Vec::new();
        end_b.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"12345");
    }
}
