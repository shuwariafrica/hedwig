//! What serves a workstation service: each connection admitted at the
//! forward's end, carried to a TCP service the workstation reaches and back,
//! byte for byte.
//!
//! A connection reaches the service first - a listener on this workstation
//! let have it only where it is the person's or a service an administrator
//! installed ([`hedwig_model::holder`]) - and only then asks to be served: its
//! opening is
//! the one request it makes. Until the deciding thread's word, what the
//! remote sends is held, a bounded amount of it; served, that and everything
//! after it is carried both ways, each direction on its own thread, an end's
//! close passed on to the other.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use hedwig_model::capability::ServiceHost;
use hedwig_model::holder::SourceHolder;
use hedwig_model::text::Port;
use hedwig_model::trail::Failure;
use hedwig_win::endpoint::owner;

use crate::relay::{Event, QUEUED, Reach, Relayed, Settle};

/// A service a capability's source names: the host it is on and its port.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Service {
    pub host: ServiceHost,
    pub port: Port,
}

/// The addresses `service` is tried at, in order: the workstation's loopback
/// in both families, or what the system's resolver says of the host's name.
///
/// # Errors
///
/// [`Failure::NoAddress`] where the resolver has no address for the name.
fn addresses(service: &Service) -> Result<Vec<SocketAddr>, Failure> {
    let port = service.port.number();
    match &service.host {
        ServiceHost::Workstation => Ok(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ]),
        ServiceHost::Named(host) => {
            let found: Vec<SocketAddr> = (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|_| Failure::NoAddress)?
                .collect();
            if found.is_empty() {
                Err(Failure::NoAddress)
            } else {
                Ok(found)
            }
        }
    }
}

/// Whether the process listening at the other end of `upstream`, where it
/// is one on this workstation, may be given the remote's connection, and
/// what it is: the person's, or one the service control manager runs a
/// service in ([`SourceHolder::admitted`]). One elsewhere is the network's,
/// which the grant acknowledged, and has no holder here.
pub fn admitted(upstream: &TcpStream) -> (Result<(), Failure>, Option<SourceHolder>) {
    let Ok(local) = owner(upstream) else {
        return (Err(Failure::Unreachable), None);
    };
    let Some(listener) = local else {
        // Not in the table: the other end is on another host, or it closed.
        let elsewhere = !upstream
            .peer_addr()
            .is_ok_and(|peer| peer.ip().is_loopback());
        let admission = if elsewhere {
            Ok(())
        } else {
            Err(Failure::Unreachable)
        };
        return (admission, None);
    };
    match crate::holder::of(listener) {
        Some(holder) => (holder.admitted(), Some(holder)),
        None => (Err(Failure::Unreachable), None),
    }
}

/// A connection to `service` that may be carried to, or why there is none:
/// [`Failure::NoAddress`], [`Failure::Unreachable`] where nothing accepts at
/// any address, or what [`admitted`] refused; with what held the last address
/// that accepted.
pub fn reach(service: &Service) -> Reach<TcpStream> {
    let addresses = match addresses(service) {
        Ok(addresses) => addresses,
        Err(failure) => return Reach::failed(failure),
    };
    let mut last = Reach::failed(Failure::Unreachable);
    for address in addresses {
        let Ok(upstream) = TcpStream::connect_timeout(&address, crate::PATIENCE) else {
            continue;
        };
        match admitted(&upstream) {
            (Ok(()), holder) => {
                return Reach {
                    result: Ok(upstream),
                    holder,
                };
            }
            (Err(failure), holder) => {
                let _ = upstream.shutdown(Shutdown::Both);
                last = Reach {
                    result: Err(failure),
                    holder,
                };
            }
        }
    }
    last
}

/// Lets the reader of the remote's end take no more than [`HELD`] bytes
/// before the connection is decided, so what is held for it is bounded and
/// the rest waits in the channel.
#[derive(Debug, Default)]
pub(crate) struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    pub(crate) fn open(&self) {
        if let Ok(mut open) = self.open.lock() {
            *open = true;
        }
        self.opened.notify_all();
    }

    fn is_open(&self) -> bool {
        self.open.lock().is_ok_and(|open| *open)
    }

    fn wait(&self) {
        let Ok(mut open) = self.open.lock() else {
            return;
        };
        while !*open {
            match self.opened.wait(open) {
                Ok(next) => open = next,
                Err(_) => return,
            }
        }
    }
}

/// The most a connection's reader takes of what the remote sends before the
/// opening is decided. Invariant: bounded by bytes rather than by reads, so a
/// remote that leaves after many small writes - pyserial's negotiation is
/// five - is seen to leave before the decision, and nothing is opened for it.
pub(crate) const HELD: usize = 32 * 1024;

pub(crate) fn read_gated(mut from: TcpStream, events: &SyncSender<Event>, gate: &Gate) {
    let mut buffer = [0u8; 8192];
    let mut held = 0usize;
    loop {
        let open = gate.is_open();
        if !open && held >= HELD {
            gate.wait();
        }
        // Before the word no read takes past the bound.
        let room = if open || held >= HELD {
            buffer.len()
        } else {
            (HELD - held).min(buffer.len())
        };
        let event = match from.read(buffer.get_mut(..room).unwrap_or_default()) {
            Ok(0) | Err(_) => Event::ClientClosed,
            Ok(read) => Event::Client(buffer.get(..read).unwrap_or_default().to_vec()),
        };
        if let Event::Client(bytes) = &event {
            held = held.saturating_add(bytes.len());
        }
        let last = matches!(event, Event::ClientClosed);
        if events.send(event).is_err() || last {
            break;
        }
    }
}

/// Carries one admitted connection to `service`. `tell` reaches the deciding
/// thread. Returns where the deciding thread settles the connection's
/// opening; the connection itself runs on threads of its own.
pub fn carry(
    client: TcpStream,
    service: Service,
    tell: impl Fn(Relayed) + Send + 'static,
) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events.clone()));
    let held = Arc::clone(&settle);
    thread::spawn(move || {
        run(&client, &service, &tell, &events, &queue, &held);
        tell(Relayed::Ended);
    });
    settle
}

fn run(
    client: &TcpStream,
    service: &Service,
    tell: &impl Fn(Relayed),
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Settle,
) {
    let reached = reach(service);
    reached.tell(tell);
    let Ok(upstream) = reached.result else {
        crate::relay::wait(queue, settle);
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let gate = Arc::new(Gate::default());
    let Ok(reader) = client.try_clone() else {
        return;
    };
    {
        let (events, gate) = (events.clone(), Arc::clone(&gate));
        thread::spawn(move || read_gated(reader, &events, &gate));
    }
    let mut early = Vec::new();
    let word = loop {
        if let Some(word) = settle.take() {
            break Some(word);
        }
        match queue.recv() {
            Ok(Event::Client(bytes)) => early.extend_from_slice(&bytes),
            Ok(Event::ClientClosed) | Err(_) => break None,
            Ok(_) => {}
        }
    };
    if word != Some(Ok(())) {
        // Refused, or the remote gave up first: nothing reaches the service
        // and nothing is written back.
        gate.open();
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        return;
    }
    splice(client, upstream, &early, &gate, queue);
}

/// Carries a served connection both ways until both ends have closed.
fn splice(
    client: &TcpStream,
    mut upstream: TcpStream,
    early: &[u8],
    gate: &Gate,
    queue: &Receiver<Event>,
) {
    let (Ok(from), Ok(to)) = (upstream.try_clone(), client.try_clone()) else {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
        return;
    };
    let back = thread::spawn(move || copy_back(from, to));
    let mut carried = early.is_empty() || upstream.write_all(early).is_ok();
    gate.open();
    while carried {
        match queue.recv() {
            Ok(Event::Client(bytes)) => carried = upstream.write_all(&bytes).is_ok(),
            Ok(Event::ClientClosed) | Err(_) => {
                let _ = upstream.shutdown(Shutdown::Write);
                break;
            }
            Ok(_) => {}
        }
    }
    if !carried {
        let _ = client.shutdown(Shutdown::Both);
        let _ = upstream.shutdown(Shutdown::Both);
    }
    let _ = back.join();
    let _ = client.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
}

/// What the service sends, to the remote, until the service closes; then
/// the remote is told no more is coming.
fn copy_back(mut from: TcpStream, mut to: TcpStream) {
    let copied: io::Result<u64> = io::copy(&mut from, &mut to);
    if copied.is_ok() {
        let _ = to.shutdown(Shutdown::Write);
    } else {
        let _ = to.shutdown(Shutdown::Both);
        let _ = from.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

    use std::net::TcpListener;
    use std::time::Duration;

    use super::*;

    /// Before the decision the reader takes [`HELD`] bytes and no more,
    /// whatever the remote sends; once the gate opens it takes the rest.
    #[test]
    fn the_reader_takes_a_bounded_amount_until_the_connection_is_decided() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let sent = vec![7u8; 1 << 20];
        let writing = thread::spawn(move || {
            remote.write_all(&sent).unwrap();
            remote.shutdown(Shutdown::Write).unwrap();
        });
        let (events, queue) = mpsc::sync_channel(64);
        let gate = Arc::new(Gate::default());
        let reading = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || read_gated(accepted, &events, &gate))
        };
        writing.join().unwrap();
        thread::sleep(Duration::from_millis(300));
        let held: Vec<Event> = queue.try_iter().collect();
        let taken: usize = held
            .iter()
            .map(|event| match event {
                Event::Client(bytes) => bytes.len(),
                other => panic!("{other:?}"),
            })
            .sum();
        assert_eq!(taken, HELD);
        gate.open();
        let mut rest = 0;
        for event in &queue {
            match event {
                Event::Client(bytes) => rest += bytes.len(),
                Event::ClientClosed => break,
                other => panic!("{other:?}"),
            }
        }
        reading.join().unwrap();
        assert_eq!(taken + rest, 1 << 20);
    }

    /// A remote that writes many small pieces and leaves before the decision
    /// is seen to leave: the bound is what is held, not how many reads.
    #[test]
    fn a_remote_that_leaves_after_many_small_writes_is_seen_to_leave() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut remote = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        remote.set_nodelay(true).unwrap();
        let (events, queue) = mpsc::sync_channel(256);
        let gate = Arc::new(Gate::default());
        let reading = {
            let gate = Arc::clone(&gate);
            thread::spawn(move || read_gated(accepted, &events, &gate))
        };
        for _ in 0..16 {
            remote.write_all(&[0xff, 0xfd, 0x2c]).unwrap();
            thread::sleep(Duration::from_millis(20));
        }
        remote.shutdown(Shutdown::Both).unwrap();
        drop(remote);
        thread::sleep(Duration::from_millis(300));
        let held: Vec<Event> = queue.try_iter().collect();
        gate.open();
        reading.join().unwrap();
        assert!(held.len() > QUEUED, "{} reads", held.len());
        assert!(matches!(held.last(), Some(Event::ClientClosed)), "{held:?}");
    }
}
