//! What serves a serial capability: each connection admitted at the
//! forward's end is given the workstation's serial port as RFC 2217
//! ([`crate::rfc2217`]) for as long as it lasts.
//!
//! The port is not touched before the connection's opening is served: an
//! opened port drives DTR and RTS as its driver and DCB say ("Enables the
//! DTR line when the device is opened", `DCB`), which resets a board wired
//! for automatic reset, and a refused request must change nothing on the
//! workstation. So the connection reaches only the port's listing first,
//! asks to be served, and opens the port once served; a port another program
//! holds is found then, and the connection ends.
//!
//! Three threads carry a served connection: one reads the remote and drives
//! the line in the order the remote asked, one reads the line, and one waits
//! for the line's modem and error events. The port is closed when the last of
//! them lets it go.

use std::io::{self, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_model::protocol::{SerialPort, Usb};
use hedwig_model::text::{PortName, Words};
use hedwig_model::trail::Failure;
use hedwig_win::serial::{
    CE_BREAK, CE_FRAME, CE_OVERRUN, CE_RXPARITY, EV_BREAK, EV_CTS, EV_DSR, EV_ERR, EV_RING,
    EV_RLSD, MS_CTS_ON, MS_DSR_ON, MS_RING_ON, MS_RLSD_ON, PURGE_RXABORT, PURGE_RXCLEAR,
    PURGE_TXABORT, PURGE_TXCLEAR,
};

use crate::relay::{Event, QUEUED, Relayed, Settle};
use crate::rfc2217::{Notices, Session, Stop};
use crate::service::{Gate, read_gated};

/// How many data bits a character has, as RFC 2217 numbers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    None,
    Odd,
    Even,
    Mark,
    Space,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopBits {
    One,
    Two,
    OneAndAHalf,
}

/// What holds back what the workstation sends to the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    None,
    XonXoff,
    /// CTS.
    Hardware,
    Dsr,
}

/// What holds back what the board sends to the workstation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    None,
    XonXoff,
    /// RTS, raised and lowered by the driver as its buffer fills.
    Hardware,
    /// DTR, likewise.
    Dtr,
}

/// A serial port's settings, as RFC 2217 sets and reports them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub baud: u32,
    /// Five to eight.
    pub size: u8,
    pub parity: Parity,
    pub stop: StopBits,
    pub outbound: Outbound,
    pub inbound: Inbound,
}

/// The lines the workstation drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    Dtr,
    Rts,
    Break,
}

/// The lines the board drives, as RFC 2217 places them in NOTIFY-MODEMSTATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four lines RFC 2217 names, one to a field"
)]
pub struct Modem {
    pub cts: bool,
    pub dsr: bool,
    pub ri: bool,
    pub cd: bool,
}

/// What the line reports of itself, as RFC 2217 places it in
/// NOTIFY-LINESTATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the conditions RFC 2217 names, one to a field"
)]
pub struct Status {
    pub overrun: bool,
    pub parity: bool,
    pub framing: bool,
    pub broken: bool,
    /// Bytes received and not yet read.
    pub waiting: u32,
    /// Bytes written and not yet sent.
    pub unsent: u32,
}

/// What the line's driver signalled; neither where the wait was ended by
/// [`Line::cancel`] or returned empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Changed {
    /// A modem line changed.
    pub modem: bool,
    /// A line error or a break arrived.
    pub line: bool,
}

/// The workstation's side of one opened serial port. Every method may be
/// called from any of the connection's threads while the others block in
/// [`Line::read`] or [`Line::wait`].
pub trait Line: Send + Sync {
    /// Writes every byte, waiting while flow control holds the line.
    ///
    /// # Errors
    ///
    /// The port went away, or the write was cancelled.
    fn write(&self, bytes: &[u8]) -> io::Result<()>;
    /// What arrived, as soon as anything has; `Ok(0)` where nothing arrived
    /// within the line's own patience.
    ///
    /// # Errors
    ///
    /// The port went away, or the read was cancelled.
    fn read(&self, into: &mut [u8]) -> io::Result<usize>;
    /// # Errors
    ///
    /// The port went away.
    fn geometry(&self) -> io::Result<Geometry>;
    /// # Errors
    ///
    /// The driver does not take these settings; the port keeps its last.
    fn set_geometry(&self, geometry: &Geometry) -> io::Result<()>;
    /// What DTR and RTS are now.
    ///
    /// # Errors
    ///
    /// The port went away.
    fn signals(&self) -> io::Result<(bool, bool)>;
    /// Raises or lowers a line. Every call reaches the driver, a repeat of
    /// the present state included.
    ///
    /// # Errors
    ///
    /// The driver does not let it be driven: handshaking holds it.
    fn signal(&self, signal: Signal, on: bool) -> io::Result<()>;
    /// # Errors
    ///
    /// The port went away.
    fn modem(&self) -> io::Result<Modem>;
    /// What the line reports and clears: errors are reported once.
    ///
    /// # Errors
    ///
    /// The port went away.
    fn status(&self) -> io::Result<Status>;
    /// Waits for a modem or line event.
    ///
    /// # Errors
    ///
    /// The port went away.
    fn wait(&self) -> io::Result<Changed>;
    /// # Errors
    ///
    /// The port went away.
    fn purge(&self, received: bool, unsent: bool) -> io::Result<()>;
    /// Ends every read, write and wait on the line, now and later.
    fn cancel(&self);
}

/// The workstation's serial ports: what the core lists, checks and opens.
pub trait Lines: Send + Sync {
    /// Every serial port the workstation has now.
    fn list(&self) -> Vec<SerialPort>;
    /// Has `told` called, for the rest of the process's life, whenever the
    /// ports may have changed. It should do no more than pass the word on.
    fn watch(&self, told: Box<dyn Fn() + Send + Sync>);
    /// Whether `port` is among them now.
    fn present(&self, port: &PortName) -> bool;
    /// The port, opened for one connection alone, and the USB device behind
    /// it where it is one.
    ///
    /// # Errors
    ///
    /// [`Failure::Absent`] where it is not there, [`Failure::Busy`] where
    /// another program holds it, [`Failure::Mismatched`] where what opened
    /// is no serial port.
    fn open(&self, port: &PortName) -> Result<(Arc<dyn Line>, Option<Usb>), Failure>;
}

/// A serial capability's source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serial {
    pub port: PortName,
}

/// What a served connection is told by the threads that share its socket.
struct Shared {
    socket: Mutex<TcpStream>,
    notices: Arc<Mutex<Notices>>,
    suspended: Mutex<bool>,
    resumed: Condvar,
    over: AtomicBool,
    /// Why the session ended, where it was not the remote closing.
    ending: Mutex<Option<Ending>>,
}

/// Why a served session ended other than by the remote closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Breach(crate::rfc2217::Breach),
    /// The line failed under a read, a write or a wait: the port went.
    Lost,
}

impl Shared {
    fn send(&self, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        self.socket
            .lock()
            .is_ok_and(|mut socket| socket.write_all(bytes).is_ok())
    }

    fn end(&self, line: &dyn Line) {
        self.over.store(true, Ordering::SeqCst);
        self.resumed.notify_all();
        line.cancel();
        if let Ok(socket) = self.socket.lock() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }

    fn over(&self) -> bool {
        self.over.load(Ordering::SeqCst)
    }

    /// Ends the session for `ending`, where nothing ended it first.
    fn fail(&self, ending: Ending, line: &dyn Line) {
        if !self.over()
            && let Ok(mut held) = self.ending.lock()
            && held.is_none()
        {
            *held = Some(ending);
        }
        self.end(line);
    }

    fn suspend(&self, suspended: bool) {
        if let Ok(mut held) = self.suspended.lock() {
            *held = suspended;
        }
        self.resumed.notify_all();
    }

    /// Waits while the remote has asked that nothing be sent to it.
    fn wait_resumed(&self) {
        let Ok(mut suspended) = self.suspended.lock() else {
            return;
        };
        while *suspended && !self.over() {
            match self.resumed.wait(suspended) {
                Ok(next) => suspended = next,
                Err(_) => return,
            }
        }
    }
}

/// Carries one admitted connection to `serial`. `tell` reaches the deciding
/// thread. Returns where the deciding thread settles the opening.
pub fn carry(
    client: TcpStream,
    serial: Serial,
    lines: Arc<dyn Lines>,
    tell: impl Fn(Relayed) + Send + 'static,
) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events.clone()));
    let held = Arc::clone(&settle);
    thread::spawn(move || {
        run(
            client,
            &serial,
            lines.as_ref(),
            &tell,
            &events,
            &queue,
            &held,
        );
        tell(Relayed::Ended);
    });
    settle
}

fn run(
    client: TcpStream,
    serial: &Serial,
    lines: &dyn Lines,
    tell: &impl Fn(Relayed),
    events: &SyncSender<Event>,
    queue: &Receiver<Event>,
    settle: &Settle,
) {
    let reached = if lines.present(&serial.port) {
        Ok(())
    } else {
        Err(Failure::Absent)
    };
    tell(Relayed::Reached(reached));
    if reached.is_err() {
        crate::relay::wait(queue, settle);
        let _ = client.shutdown(Shutdown::Both);
        return;
    }
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
        gate.open();
        let _ = client.shutdown(Shutdown::Both);
        return;
    }
    let opened = lines.open(&serial.port);
    tell(Relayed::Opened(
        opened
            .as_ref()
            .map(|(_, usb)| *usb)
            .map_err(|failure| *failure),
    ));
    let Ok((line, _)) = opened else {
        gate.open();
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    let ending = serve(client, &line, early, &gate, queue);
    // The port closes with its last handle, before the deciding thread is
    // told it is free.
    drop(line);
    match ending {
        Some(Ending::Breach(breach)) => tell(Relayed::Broke(breach)),
        Some(Ending::Lost) => tell(Relayed::Lost(if lines.present(&serial.port) {
            Failure::Unreachable
        } else {
            Failure::Absent
        })),
        None => {}
    }
    tell(Relayed::Released);
}

/// Serves the opened port to the remote until either ends, and says why it
/// ended where the remote did not end it.
fn serve(
    client: TcpStream,
    line: &Arc<dyn Line>,
    early: Vec<u8>,
    gate: &Gate,
    queue: &Receiver<Event>,
) -> Option<Ending> {
    let notices = Arc::new(Mutex::new(Notices::default()));
    let Ok((session, greeting)) = Session::open(line.as_ref(), Arc::clone(&notices)) else {
        gate.open();
        let _ = client.shutdown(Shutdown::Both);
        line.cancel();
        return Some(Ending::Lost);
    };
    let shared = Arc::new(Shared {
        socket: Mutex::new(client),
        notices,
        suspended: Mutex::new(false),
        resumed: Condvar::new(),
        over: AtomicBool::new(false),
        ending: Mutex::new(None),
    });
    if !shared.send(&greeting) {
        shared.end(line.as_ref());
        gate.open();
        return None;
    }
    let reading = {
        let (shared, line) = (Arc::clone(&shared), Arc::clone(line));
        thread::spawn(move || from_line(&shared, line.as_ref()))
    };
    let waiting = {
        let (shared, line) = (Arc::clone(&shared), Arc::clone(line));
        thread::spawn(move || events_of(&shared, line.as_ref()))
    };
    from_remote(session, &shared, line.as_ref(), early, gate, queue);
    shared.end(line.as_ref());
    let _ = reading.join();
    let _ = waiting.join();
    shared.ending.lock().ok().and_then(|ending| *ending)
}

/// What the remote sends, applied to the line in order; a held raise of DTR
/// applied when the next thing arrives or its time is up.
fn from_remote(
    mut session: Session,
    shared: &Shared,
    line: &dyn Line,
    early: Vec<u8>,
    gate: &Gate,
    queue: &Receiver<Event>,
) {
    gate.open();
    let mut bytes = early;
    loop {
        let answered = session.receive(&bytes, line);
        shared.suspend(session.suspended());
        if !answer(shared, line, answered) {
            return;
        }
        match next(&mut session, shared, line, queue) {
            Some(more) => bytes = more,
            None => return,
        }
    }
}

/// What the remote sends next, applying a held raise of DTR whose time
/// runs out meanwhile; `None` once the remote has closed.
fn next(
    session: &mut Session,
    shared: &Shared,
    line: &dyn Line,
    queue: &Receiver<Event>,
) -> Option<Vec<u8>> {
    loop {
        let event = match session.holding() {
            Some(until) => {
                let wait = until.saturating_duration_since(Instant::now());
                match queue.recv_timeout(wait) {
                    Ok(event) => event,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if !answer(shared, line, session.expire(line)) {
                            return None;
                        }
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return None,
                }
            }
            None => queue.recv().ok()?,
        };
        match event {
            Event::Client(bytes) => return Some(bytes),
            Event::ClientClosed => {
                let _ = session.expire(line);
                return None;
            }
            _ => {}
        }
    }
}

/// Sends what the session answered; `false` where the connection is over,
/// having said why where the remote did not end it.
fn answer(shared: &Shared, line: &dyn Line, answered: Result<Vec<u8>, Stop>) -> bool {
    match answered {
        Ok(bytes) => shared.send(&bytes),
        Err(Stop::Breach(breach)) => {
            shared.fail(Ending::Breach(breach), line);
            false
        }
        Err(Stop::Line(_)) => {
            shared.fail(Ending::Lost, line);
            false
        }
    }
}

/// What the board sends, to the remote, until the connection is over.
fn from_line(shared: &Shared, line: &dyn Line) {
    let mut buffer = [0u8; 4096];
    while !shared.over() {
        shared.wait_resumed();
        match line.read(&mut buffer) {
            Ok(0) => {}
            Ok(read) => {
                let escaped = crate::rfc2217::escape(buffer.get(..read).unwrap_or_default());
                if !shared.send(&escaped) {
                    break;
                }
            }
            Err(_) => {
                shared.fail(Ending::Lost, line);
                break;
            }
        }
    }
    shared.end(line);
}

/// The line's modem and error events, as the remote's masks ask for them.
fn events_of(shared: &Shared, line: &dyn Line) {
    while !shared.over() {
        let Ok(changed) = line.wait() else {
            shared.fail(Ending::Lost, line);
            break;
        };
        let mut told = Vec::new();
        if changed.modem
            && let Ok(modem) = line.modem()
            && let Ok(mut notices) = shared.notices.lock()
        {
            told.extend(notices.modem(modem).unwrap_or_default());
        }
        if changed.line
            && let Ok(status) = line.status()
            && let Ok(notices) = shared.notices.lock()
        {
            told.extend(notices.line(status).unwrap_or_default());
        }
        if !shared.send(&told) {
            break;
        }
    }
    shared.end(line);
}

/// The longest a raise of DTR waits for the remote's next command: pyserial,
/// the client every tool here is built on, gives up on an answer after three
/// seconds (`_network_timeout`, `rfc2217.py:410`), so no command it sends in
/// sequence is further apart.
pub const HOLD: Duration = Duration::from_secs(3);

/// The workstation's own serial ports, through Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct Windows;

impl Lines for Windows {
    fn watch(&self, told: Box<dyn Fn() + Send + Sync>) {
        // A workstation whose device maps cannot be watched still lists its
        // ports when asked.
        let _ = hedwig_win::serial::watch(told);
    }

    fn list(&self) -> Vec<SerialPort> {
        let names = hedwig_win::serial::present().unwrap_or_default();
        let described = hedwig_win::serial::described(true).unwrap_or_default();
        let mut ports: Vec<SerialPort> =
            names
                .iter()
                .filter_map(|name| PortName::try_from(name.to_string_lossy().as_ref()).ok())
                .map(|port| {
                    let device = described.iter().find(|device| {
                        device.port.as_ref().is_some_and(|named| {
                            named.to_string_lossy().eq_ignore_ascii_case(port.as_str())
                        })
                    });
                    SerialPort {
                        name: device.and_then(|device| device.friendly.as_ref()).and_then(
                            |friendly| Words::try_from(friendly.to_string_lossy().as_ref()).ok(),
                        ),
                        usb: device.and_then(|device| {
                            device
                                .hardware
                                .iter()
                                .find_map(|id| usb(&id.to_string_lossy()))
                        }),
                        port,
                    }
                })
                .collect();
        ports.sort_by(|one, other| one.port.cmp(&other.port));
        ports
    }

    fn present(&self, port: &PortName) -> bool {
        hedwig_win::serial::present().is_ok_and(|names| {
            names
                .iter()
                .any(|name| name.to_string_lossy().eq_ignore_ascii_case(port.as_str()))
        })
    }

    fn open(&self, port: &PortName) -> Result<(Arc<dyn Line>, Option<Usb>), Failure> {
        use hedwig_win::serial::{ComPort, OpenError};
        let opened = ComPort::open(port.as_str()).map_err(|error| match error {
            OpenError::Absent => Failure::Absent,
            OpenError::Busy => Failure::Busy,
            OpenError::NotSerial => Failure::Mismatched,
            OpenError::Other(_) => Failure::Unreachable,
        })?;
        let state = opened.state().map_err(|_| Failure::Mismatched)?;
        let line: Arc<dyn Line> = Arc::new(Com {
            port: opened,
            dtr: AtomicBool::new(state.dtr == DTR_ENABLE),
            rts: AtomicBool::new(state.rts == RTS_ENABLE),
        });
        let usb = self
            .list()
            .into_iter()
            .find(|listed| listed.port.same(port))
            .and_then(|listed| listed.usb);
        Ok((line, usb))
    }
}

/// A USB device's vendor and product, read from a hardware identifier that
/// carries `VID_` and `PID_` fields: `USB\VID_0E8D&PID_2000&REV_0100`.
pub fn usb(hardware: &str) -> Option<Usb> {
    let upper = hardware.to_ascii_uppercase();
    let field = |key: &str| {
        let at = upper.find(key)? + key.len();
        let digits = upper.get(at..at + 4)?;
        u16::from_str_radix(digits, 16).ok()
    };
    Some(Usb {
        vendor: field("VID_")?,
        product: field("PID_")?,
    })
}

const DTR_ENABLE: u8 = 1;
const DTR_HANDSHAKE: u8 = 2;
const RTS_ENABLE: u8 = 1;
const RTS_HANDSHAKE: u8 = 2;

/// An opened COM port, and DTR and RTS as last driven: `EscapeCommFunction`
/// changes a line without the DCB saying so, and a DCB applied after would
/// otherwise set the line back.
struct Com {
    port: hedwig_win::serial::ComPort,
    dtr: AtomicBool,
    rts: AtomicBool,
}

impl Line for Com {
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        self.port.write(bytes)
    }

    fn read(&self, into: &mut [u8]) -> io::Result<usize> {
        self.port.read(into)
    }

    fn geometry(&self) -> io::Result<Geometry> {
        let state = self.port.state()?;
        Ok(Geometry {
            baud: state.baud,
            size: state.size,
            parity: match state.parity {
                1 => Parity::Odd,
                2 => Parity::Even,
                3 => Parity::Mark,
                4 => Parity::Space,
                _ => Parity::None,
            },
            stop: match state.stop {
                1 => StopBits::OneAndAHalf,
                2 => StopBits::Two,
                _ => StopBits::One,
            },
            outbound: if state.out_x {
                Outbound::XonXoff
            } else if state.out_cts {
                Outbound::Hardware
            } else if state.out_dsr {
                Outbound::Dsr
            } else {
                Outbound::None
            },
            inbound: if state.in_x {
                Inbound::XonXoff
            } else if state.rts == RTS_HANDSHAKE {
                Inbound::Hardware
            } else if state.dtr == DTR_HANDSHAKE {
                Inbound::Dtr
            } else {
                Inbound::None
            },
        })
    }

    fn set_geometry(&self, geometry: &Geometry) -> io::Result<()> {
        let mut state = self.port.state()?;
        state.baud = geometry.baud;
        state.size = geometry.size;
        state.parity = match geometry.parity {
            Parity::None => 0,
            Parity::Odd => 1,
            Parity::Even => 2,
            Parity::Mark => 3,
            Parity::Space => 4,
        };
        state.stop = match geometry.stop {
            StopBits::One => 0,
            StopBits::OneAndAHalf => 1,
            StopBits::Two => 2,
        };
        state.out_x = geometry.outbound == Outbound::XonXoff;
        state.out_cts = geometry.outbound == Outbound::Hardware;
        state.out_dsr = geometry.outbound == Outbound::Dsr;
        state.in_x = geometry.inbound == Inbound::XonXoff;
        state.rts = if geometry.inbound == Inbound::Hardware {
            RTS_HANDSHAKE
        } else {
            u8::from(self.rts.load(Ordering::SeqCst))
        };
        state.dtr = if geometry.inbound == Inbound::Dtr {
            DTR_HANDSHAKE
        } else {
            u8::from(self.dtr.load(Ordering::SeqCst))
        };
        self.port.set_state(state)
    }

    fn signals(&self) -> io::Result<(bool, bool)> {
        Ok((
            self.dtr.load(Ordering::SeqCst),
            self.rts.load(Ordering::SeqCst),
        ))
    }

    fn signal(&self, signal: Signal, on: bool) -> io::Result<()> {
        use hedwig_win::serial::Escape;
        let dtr = |on| if on { Escape::SetDtr } else { Escape::ClearDtr };
        match signal {
            Signal::Dtr => {
                self.port.escape(dtr(on))?;
                self.dtr.store(on, Ordering::SeqCst);
            }
            Signal::Rts => {
                self.port
                    .escape(if on { Escape::SetRts } else { Escape::ClearRts })?;
                self.rts.store(on, Ordering::SeqCst);
                // "Some Windows USB-CDC adapters using usbser.sys only emit
                // the SET_CONTROL_LINE_STATE request when both DTR and RTS are
                // written in the same operation" (esp-pylib's `set_rts`), so
                // DTR is written again as it stands.
                self.port.escape(dtr(self.dtr.load(Ordering::SeqCst)))?;
            }
            Signal::Break => {
                self.port.escape(if on {
                    Escape::SetBreak
                } else {
                    Escape::ClearBreak
                })?;
            }
        }
        Ok(())
    }

    fn modem(&self) -> io::Result<Modem> {
        let bits = self.port.modem()?;
        Ok(Modem {
            cts: bits & MS_CTS_ON != 0,
            dsr: bits & MS_DSR_ON != 0,
            ri: bits & MS_RING_ON != 0,
            cd: bits & MS_RLSD_ON != 0,
        })
    }

    fn status(&self) -> io::Result<Status> {
        let errors = self.port.errors()?;
        Ok(Status {
            overrun: errors.errors & CE_OVERRUN != 0,
            parity: errors.errors & CE_RXPARITY != 0,
            framing: errors.errors & CE_FRAME != 0,
            broken: errors.errors & CE_BREAK != 0,
            waiting: errors.waiting,
            unsent: errors.unsent,
        })
    }

    fn wait(&self) -> io::Result<Changed> {
        let mask = self.port.wait()?;
        Ok(Changed {
            modem: mask & (EV_CTS | EV_DSR | EV_RLSD | EV_RING) != 0,
            line: mask & (EV_ERR | EV_BREAK) != 0,
        })
    }

    fn purge(&self, received: bool, unsent: bool) -> io::Result<()> {
        let mut flags = 0;
        if received {
            flags |= PURGE_RXCLEAR | PURGE_RXABORT;
        }
        if unsent {
            flags |= PURGE_TXCLEAR | PURGE_TXABORT;
        }
        self.port.purge(flags)
    }

    fn cancel(&self) {
        self.port.cancel();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;

    /// Hardware identifiers as this workstation's ports class lists them
    /// (measured 2026-10-01), and others carrying the same fields.
    #[test]
    fn a_usb_device_s_vendor_and_product_are_read_from_its_hardware_identifier() {
        use hedwig_model::protocol::Usb;
        for (id, found) in [
            (
                r"USB\VID_0E8D&PID_2000&REV_0100",
                Some(Usb {
                    vendor: 0x0E8D,
                    product: 0x2000,
                }),
            ),
            (
                r"USB\VID_303A&PID_1001&MI_00",
                Some(Usb {
                    vendor: 0x303A,
                    product: 0x1001,
                }),
            ),
            (
                r"FTDIBUS\COMPORT&VID_0403&PID_6001",
                Some(Usb {
                    vendor: 0x0403,
                    product: 0x6001,
                }),
            ),
            (
                r"BTHENUM\{00001101-0000-1000-8000-00805f9b34fb}_VID&000105d6_PID&000a",
                None,
            ),
            (r"USB\VID_0E8D", None),
            (r"USB\VID_ZZZZ&PID_2000", None),
        ] {
            assert_eq!(usb(id), found, "{id}");
        }
    }

    #[test]
    fn the_workstation_s_lines_list_what_windows_lists_and_open_none_it_lacks() {
        let listed = Windows.list();
        assert_eq!(
            listed.len(),
            hedwig_win::serial::present().unwrap_or_default().len()
        );
        let unused = (1..=255)
            .map(|number| PortName::try_from(format!("COM{number}").as_str()).unwrap())
            .rfind(|port| !listed.iter().any(|listed| listed.port.same(port)))
            .unwrap();
        assert!(!Windows.present(&unused));
        assert!(matches!(Windows.open(&unused), Err(Failure::Absent)));
    }
}
