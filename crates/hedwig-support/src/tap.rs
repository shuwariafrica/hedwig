//! A recorder between a client and a server on this workstation's loopback,
//! for known-answer vectors taken from a real exchange: `child tap <listen>
//! <to> <file>` carries every connection to `<listen>` on to `<to>` and
//! appends what passed to `<file>`, one read to a line: the connection's
//! number, `>` from the client or `<` from the server, and the bytes in
//! hexadecimal, or `end` where that side closed.

use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

type Log = Arc<Mutex<std::fs::File>>;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut hex, byte| {
        let _ = write!(hex, "{byte:02x}");
        hex
    })
}

fn copy(mut from: TcpStream, mut to: TcpStream, number: usize, way: char, log: &Log) {
    let mut buffer = vec![0u8; 65536];
    loop {
        match from.read(&mut buffer) {
            Ok(0) | Err(_) => {
                if let Ok(mut file) = log.lock() {
                    let _ = writeln!(file, "{number} {way} end");
                }
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            Ok(read) => {
                let bytes = buffer.get(..read).unwrap_or_default();
                if let Ok(mut file) = log.lock() {
                    let _ = writeln!(file, "{number} {way} {}", hex(bytes));
                }
                if to.write_all(bytes).is_err() {
                    let _ = from.shutdown(Shutdown::Both);
                    return;
                }
            }
        }
    }
}

/// Records every connection to `listen` carried on to `to`, until the process
/// is ended.
///
/// # Errors
///
/// What the system said of the file or the listener.
pub fn tap(listen: u16, to: u16, file: &Path) -> io::Result<()> {
    let log: Log = Arc::new(Mutex::new(
        OpenOptions::new().create(true).append(true).open(file)?,
    ));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, listen))?;
    for (number, client) in listener.incoming().enumerate() {
        let client = client?;
        let server = TcpStream::connect((Ipv4Addr::LOCALHOST, to))?;
        let (client_reader, server_reader) = (client.try_clone()?, server.try_clone()?);
        let (one, other) = (Arc::clone(&log), Arc::clone(&log));
        thread::spawn(move || copy(client_reader, server, number, '>', &one));
        thread::spawn(move || copy(server_reader, client, number, '<', &other));
    }
    Ok(())
}
