//! `holding <port>` listens on that loopback port as a source's holder would,
//! telling each connection how many bytes every connection before it sent,
//! then reading it to its end: so a suite can ask afterwards whether anything
//! reached it.
//!
//! It needs nothing but the standard library, so it starts under a token
//! lowered to low integrity or restricted, where a program that loads the
//! window manager's library does not.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;

fn main() -> ExitCode {
    let port = std::env::args()
        .nth(1)
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(0);
    let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) else {
        return ExitCode::from(2);
    };
    let mut received = 0usize;
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = writeln!(stream, "{received}");
        let mut buffer = [0u8; 4096];
        while let Ok(read @ 1..) = stream.read(&mut buffer) {
            received += read;
        }
    }
    ExitCode::SUCCESS
}
