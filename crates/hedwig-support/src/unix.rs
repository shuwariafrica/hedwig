//! A Unix-domain socket listener on the workstation, standing in for the
//! socket a remote's SSH server binds for a forward: Git for Windows' own
//! `git credential-cache` connects to one as Linux's `git` does, and each
//! connection is carried to a loopback port as `ssh -R` carries it, each
//! side's end passed on as the other's.
//!
//! Rust's standard library has no stable Unix-domain socket on Windows
//! (`windows_unix_domain_sockets`, unstable), so the suite calls Winsock.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::Path;
use std::thread;

use windows_sys::Win32::Networking::WinSock::{
    AF_UNIX, INVALID_SOCKET, SD_SEND, SOCK_STREAM, SOCKADDR, SOCKADDR_UN, SOCKET, WSADATA,
    WSAGetLastError, WSAStartup, accept, bind, closesocket, listen, recv, send, shutdown, socket,
};

/// A listening Unix-domain socket, closed when dropped.
#[derive(Debug)]
pub struct Listener(SOCKET);

/// One accepted connection, closed when dropped.
#[derive(Debug)]
pub struct Stream(SOCKET);

fn failed() -> io::Error {
    // SAFETY: reads this thread's last Winsock error; no argument.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

impl Listener {
    /// Binds `path`, which must not exist, and listens.
    ///
    /// # Errors
    ///
    /// What Winsock said; a path longer than `sun_path` holds is refused.
    pub fn bind(path: &Path) -> io::Result<Listener> {
        let mut data: WSADATA = WSADATA::default();
        // SAFETY: `data` is writable; Winsock counts each start, and the
        // standard library's own start does the same.
        if unsafe { WSAStartup(0x0202, &raw mut data) } != 0 {
            return Err(failed());
        }
        let bytes = path.to_string_lossy().into_owned().into_bytes();
        let mut address = SOCKADDR_UN {
            sun_family: AF_UNIX,
            sun_path: [0; 108],
        };
        if bytes.len() >= address.sun_path.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        for (at, byte) in address.sun_path.iter_mut().zip(bytes) {
            *at = i8::from_ne_bytes([byte]);
        }
        // SAFETY: plain arguments.
        let made = unsafe { socket(i32::from(AF_UNIX), SOCK_STREAM, 0) };
        if made == INVALID_SOCKET {
            return Err(failed());
        }
        let listener = Listener(made);
        let size = i32::try_from(size_of::<SOCKADDR_UN>()).unwrap_or(i32::MAX);
        // SAFETY: the address is a whole `SOCKADDR_UN` of `size` bytes.
        if unsafe { bind(made, (&raw const address).cast::<SOCKADDR>(), size) } != 0 {
            return Err(failed());
        }
        // SAFETY: a bound socket.
        if unsafe { listen(made, 8) } != 0 {
            return Err(failed());
        }
        Ok(listener)
    }

    /// The next connection.
    ///
    /// # Errors
    ///
    /// What Winsock said.
    pub fn accept(&self) -> io::Result<Stream> {
        // SAFETY: a listening socket; the peer's address is not asked for.
        let accepted = unsafe { accept(self.0, std::ptr::null_mut(), std::ptr::null_mut()) };
        if accepted == INVALID_SOCKET {
            return Err(failed());
        }
        Ok(Stream(accepted))
    }

    /// Carries every connection to `to` on this workstation's loopback, as a
    /// forward's far end, until the listener is dropped.
    pub fn forward(self, to: SocketAddr) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            while let Ok(stream) = self.accept() {
                thread::spawn(move || {
                    if let Ok(onward) = TcpStream::connect(to) {
                        carry(stream, onward);
                    }
                });
            }
        })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // SAFETY: the socket this value owns, closed once.
        unsafe { closesocket(self.0) };
    }
}

impl Stream {
    fn shut(&self) {
        // SAFETY: the socket this value owns.
        unsafe { shutdown(self.0, SD_SEND) };
    }
}

impl Read for &Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = i32::try_from(buffer.len()).unwrap_or(i32::MAX);
        // SAFETY: `buffer` is writable for `length` bytes.
        let read = unsafe { recv(self.0, buffer.as_mut_ptr(), length, 0) };
        usize::try_from(read).map_err(|_| failed())
    }
}

impl Write for &Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let length = i32::try_from(buffer.len()).unwrap_or(i32::MAX);
        // SAFETY: `buffer` is readable for `length` bytes.
        let sent = unsafe { send(self.0, buffer.as_ptr(), length, 0) };
        usize::try_from(sent).map_err(|_| failed())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: the socket this value owns, closed once.
        unsafe { closesocket(self.0) };
    }
}

/// Carries `stream` and `onward` both ways, each end passed on.
fn carry(stream: Stream, onward: TcpStream) {
    let stream = std::sync::Arc::new(stream);
    let Ok(back) = onward.try_clone() else {
        return;
    };
    let reading = std::sync::Arc::clone(&stream);
    let up = thread::spawn(move || {
        let mut onward = onward;
        let mut buffer = [0u8; 4096];
        loop {
            match (&*reading).read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if onward
                        .write_all(buffer.get(..read).unwrap_or_default())
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
        let _ = onward.shutdown(Shutdown::Write);
    });
    let mut back = back;
    let mut buffer = [0u8; 4096];
    loop {
        match back.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if (&*stream)
                    .write_all(buffer.get(..read).unwrap_or_default())
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    stream.shut();
    let _ = up.join();
}
