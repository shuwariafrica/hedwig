#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::cli::Config;
use crate::gpgconf;
use crate::logging::Logger;
use crate::relay;
use crate::win::net;

/// A hostile same-user process gains nothing by flooding (it can talk to the
/// agent directly), so the cap only bounds resource use.
const MAX_INFLIGHT: usize = 64;

/// Releases the slot however the thread ends. A decrement written as the last
/// statement of the thread body is skipped by a panic, which would retire one
/// of `MAX_INFLIGHT` permanently.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub(crate) fn run(cfg: &Config) -> Result<(), String> {
    let log = Arc::new(
        Logger::new(cfg.verbose, cfg.log_file.as_deref()).map_err(|e| format!("log file: {e}"))?,
    );
    let gpgconf_path = gpgconf::locate_gpgconf();
    if gpgconf_path.is_none() {
        log.error("gpgconf.exe not found; a stopped gpg-agent will not be relaunched");
    }
    let socket_dir = gpgconf::socket_dir(cfg.socketdir.as_deref(), gpgconf_path.as_deref())
        .map_err(|e| e.to_string())?;
    let socket_file = socket_dir.join(cfg.socket.file_name());
    let listener = net::bind_loopback_exclusive(cfg.port).map_err(|e| {
        format!(
            "cannot listen on 127.0.0.1:{}: {e} (another instance, or another program, holds the port)",
            cfg.port
        )
    })?;
    let listen_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, cfg.port);
    log.info(&format!(
        "hedwig {} listening on {listen_addr}, relaying to {}",
        crate::version(),
        socket_file.display()
    ));
    if !cfg.socket.expects_restricted() {
        log.error(
            "relaying the UNRESTRICTED agent socket: a forwarded remote host can \
             export file-based secret keys, change passphrases and administer cards",
        );
    }
    let inflight = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _) = match listener.accept() {
            Ok(x) => x,
            Err(e) => {
                log.error(&format!("accept: {e}"));
                continue;
            }
        };
        if inflight.load(Ordering::Relaxed) >= MAX_INFLIGHT {
            log.error("connection dropped: too many concurrent connections");
            continue;
        }
        inflight.fetch_add(1, Ordering::Relaxed);
        let slot = Slot(Arc::clone(&inflight));
        let task_log = Arc::clone(&log);
        let socket_file: PathBuf = socket_file.clone();
        let gpgconf_path = gpgconf_path.clone();
        // thread::spawn panics when the OS refuses a thread; the accept loop
        // has to outlive that. A refusal drops the closure, and the slot with it.
        let spawned = std::thread::Builder::new().spawn(move || {
            let _slot = slot;
            relay::handle_client(
                stream,
                listen_addr,
                &socket_file,
                gpgconf_path.as_deref(),
                &task_log,
            );
        });
        if let Err(e) = spawned {
            log.error(&format!("connection dropped: cannot start a thread: {e}"));
        }
    }
}
