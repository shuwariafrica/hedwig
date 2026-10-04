//! Serial ports of the suite's own, standing in where the workstation has
//! no COM port: what the core opens through [`hedwig_core::serial::Lines`]
//! when the suite, or a core run by hand, is given them in place of
//! Windows'.
//!
//! Two wirings. [`Wiring::Loop`] is pyserial's `loop://`: what is written
//! is read back, RTS reaches CTS and DTR reaches DSR. [`Wiring::Board`] is
//! the reset circuit an ESP32 development board carries between a USB-UART
//! bridge and the chip: EN is driven low only while RTS is on and DTR off,
//! IO0 only while DTR is on and RTS off. When EN has been released for
//! `settle` the chip boots, into its download mode where IO0 is low then,
//! and says so in a line esptool's own boot-log reader takes
//! (`loader.py:766-775`); what is written to it is kept and never answered.
//!
//! Every open, close, setting, line change and boot is written to the
//! bench's log as it happens, one line each, with the milliseconds since the
//! bench was made: what the suite and a run by hand read back.

use std::collections::{BTreeSet, VecDeque};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use hedwig_core::serial::{
    Changed, Geometry, Inbound, Line, Lines, Modem, Outbound, Parity, Signal, Status, StopBits,
};
use hedwig_model::protocol::{SerialPort, Usb};
use hedwig_model::text::{PortName, Words};
use hedwig_model::trail::Failure;

/// What the bench's ports are wired to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wiring {
    Loop,
    Board { settle: Duration },
}

/// What the chip says when it boots into its download mode, and otherwise:
/// the text an ESP32's ROM prints, which esptool's regular expression
/// `boot:(0x[0-9a-fA-F]+)(.*waiting for download)?` reads.
pub const DOWNLOAD: &[u8] = b"rst:0x1 (POWERON_RESET),boot:0x3 (DOWNLOAD_BOOT(UART0/UART1/SDIO_REI_REO_V2))\r\nwaiting for download\r\n";
pub const NORMAL: &[u8] = b"rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)\r\n";

/// The bench: its ports, their wiring, which are open, and its log.
pub struct Bench {
    ports: Vec<PortName>,
    wiring: Wiring,
    usb: Option<Usb>,
    open: Arc<Mutex<BTreeSet<String>>>,
    unplugged: Arc<Mutex<BTreeSet<String>>>,
    log: Arc<Log>,
    /// Who the core asked to be told when the ports may have changed.
    watching: Mutex<Vec<Box<dyn Fn() + Send + Sync>>>,
}

struct Log {
    began: Instant,
    file: Mutex<Option<File>>,
    lines: Mutex<Vec<String>>,
}

impl Log {
    fn say(&self, what: &str) {
        let line = format!("{} {what}", self.began.elapsed().as_millis());
        if let Ok(mut file) = self.file.lock()
            && let Some(file) = file.as_mut()
        {
            let _ = writeln!(file, "{line}");
            let _ = file.flush();
        }
        if let Ok(mut lines) = self.lines.lock() {
            lines.push(line);
        }
    }
}

impl Bench {
    /// A bench with `ports`, logging to `log` where one is named.
    ///
    /// # Errors
    ///
    /// The log could not be made.
    pub fn new(ports: &[&str], wiring: Wiring, log: Option<&Path>) -> io::Result<Bench> {
        let file = log.map(File::create).transpose()?;
        Ok(Bench {
            ports: ports
                .iter()
                .filter_map(|port| PortName::try_from(*port).ok())
                .collect(),
            wiring,
            usb: match wiring {
                Wiring::Loop => None,
                // A CP210x bridge, as a development board carries.
                Wiring::Board { .. } => Some(Usb {
                    vendor: 0x10C4,
                    product: 0xEA60,
                }),
            },
            open: Arc::new(Mutex::new(BTreeSet::new())),
            unplugged: Arc::new(Mutex::new(BTreeSet::new())),
            watching: Mutex::new(Vec::new()),
            log: Arc::new(Log {
                began: Instant::now(),
                file: Mutex::new(file),
                lines: Mutex::new(Vec::new()),
            }),
        })
    }

    /// The bench's ports as behind `usb` instead.
    #[must_use]
    pub fn over(mut self, usb: Option<Usb>) -> Bench {
        self.usb = usb;
        self
    }

    /// Every line logged so far.
    pub fn logged(&self) -> Vec<String> {
        self.log
            .lines
            .lock()
            .map(|lines| lines.clone())
            .unwrap_or_default()
    }

    /// Takes `port` away, as a board unplugged: it is no longer present, and
    /// whatever has it open fails.
    pub fn unplug(&self, port: &str) {
        if let Ok(mut unplugged) = self.unplugged.lock() {
            unplugged.insert(port.to_ascii_uppercase());
        }
        self.log
            .say(&format!("unplugged {}", port.to_ascii_uppercase()));
        self.moved();
    }

    /// Puts back `port` taken away by [`Bench::unplug`].
    pub fn plug(&self, port: &str) {
        if let Ok(mut unplugged) = self.unplugged.lock() {
            unplugged.remove(&port.to_ascii_uppercase());
        }
        self.log
            .say(&format!("plugged {}", port.to_ascii_uppercase()));
        self.moved();
    }

    /// Tells the core the ports may have changed, as Windows does.
    fn moved(&self) {
        if let Ok(watching) = self.watching.lock() {
            for told in watching.iter() {
                told();
            }
        }
    }

    /// Holds `port` as another program would, until the guard is dropped.
    pub fn hold(&self, port: &str) -> Held {
        if let Ok(mut open) = self.open.lock() {
            open.insert(port.to_ascii_uppercase());
        }
        Held {
            port: port.to_ascii_uppercase(),
            open: Arc::clone(&self.open),
        }
    }
}

/// A port held as another program would hold it.
pub struct Held {
    port: String,
    open: Arc<Mutex<BTreeSet<String>>>,
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Ok(mut open) = self.open.lock() {
            open.remove(&self.port);
        }
    }
}

impl Lines for Bench {
    fn watch(&self, told: Box<dyn Fn() + Send + Sync>) {
        if let Ok(mut watching) = self.watching.lock() {
            watching.push(told);
        }
    }

    fn list(&self) -> Vec<SerialPort> {
        self.ports
            .iter()
            .filter(|port| self.present(port))
            .map(|port| SerialPort {
                port: port.clone(),
                name: Words::try_from("Hedwig's bench").ok(),
                usb: self.usb,
            })
            .collect()
    }

    fn present(&self, port: &PortName) -> bool {
        let gone = self
            .unplugged
            .lock()
            .is_ok_and(|unplugged| unplugged.contains(&port.as_str().to_ascii_uppercase()));
        !gone && self.ports.iter().any(|known| known.same(port))
    }

    fn open(&self, port: &PortName) -> Result<(Arc<dyn Line>, Option<Usb>), Failure> {
        if !self.present(port) {
            return Err(Failure::Absent);
        }
        let name = port.as_str().to_ascii_uppercase();
        {
            let Ok(mut open) = self.open.lock() else {
                return Err(Failure::Unreachable);
            };
            if !open.insert(name.clone()) {
                return Err(Failure::Busy);
            }
        }
        self.log.say(&format!("opened {name}"));
        let line: Arc<dyn Line> = Arc::new(Wired {
            name,
            wiring: self.wiring,
            open: Arc::clone(&self.open),
            unplugged: Arc::clone(&self.unplugged),
            log: Arc::clone(&self.log),
            state: Mutex::new(State {
                geometry: Geometry {
                    baud: 9600,
                    size: 8,
                    parity: Parity::None,
                    stop: StopBits::One,
                    outbound: Outbound::None,
                    inbound: Inbound::None,
                },
                dtr: false,
                rts: false,
                incoming: VecDeque::new(),
                written: 0,
                changed: Changed::default(),
                released: None,
                io0: Vec::new(),
                cancelled: false,
            }),
            woken: Condvar::new(),
        });
        Ok((line, self.usb))
    }
}

struct State {
    geometry: Geometry,
    dtr: bool,
    rts: bool,
    incoming: VecDeque<u8>,
    written: usize,
    changed: Changed,
    /// When EN was last released and the chip has not yet booted.
    released: Option<Instant>,
    /// When IO0 changed since, and to low or not.
    io0: Vec<(Instant, bool)>,
    cancelled: bool,
}

struct Wired {
    name: String,
    wiring: Wiring,
    open: Arc<Mutex<BTreeSet<String>>>,
    unplugged: Arc<Mutex<BTreeSet<String>>>,
    log: Arc<Log>,
    state: Mutex<State>,
    woken: Condvar,
}

impl Wired {
    fn gone(&self) -> bool {
        self.unplugged
            .lock()
            .is_ok_and(|unplugged| unplugged.contains(&self.name))
    }

    fn state(&self) -> io::Result<std::sync::MutexGuard<'_, State>> {
        if self.gone() {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        self.state
            .lock()
            .map_err(|_| io::Error::other("the bench is poisoned"))
    }

    /// Boots the chip where EN has been released for long enough, sampling
    /// IO0 as it stood when the chip came out of reset.
    fn boot(&self, state: &mut State) {
        let Wiring::Board { settle } = self.wiring else {
            return;
        };
        let Some(released) = state.released else {
            return;
        };
        let at = released + settle;
        if Instant::now() < at {
            return;
        }
        let low = state
            .io0
            .iter()
            .rev()
            .find(|(when, _)| *when <= at)
            .is_some_and(|(_, low)| *low);
        state.released = None;
        state.io0.clear();
        let (said, mode) = if low {
            (DOWNLOAD, "download")
        } else {
            (NORMAL, "normal")
        };
        state.incoming.extend(said);
        self.log.say(&format!("booted {mode}"));
        self.woken.notify_all();
    }

    fn en_low(state: &State) -> bool {
        state.rts && !state.dtr
    }

    fn io0_low(state: &State) -> bool {
        state.dtr && !state.rts
    }
}

impl Line for Wired {
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        let mut state = self.state()?;
        if state.cancelled {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        state.written += bytes.len();
        match self.wiring {
            Wiring::Loop => {
                state.incoming.extend(bytes);
                self.woken.notify_all();
            }
            Wiring::Board { .. } => self.log.say(&format!("wrote {}", bytes.len())),
        }
        Ok(())
    }

    fn read(&self, into: &mut [u8]) -> io::Result<usize> {
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut state = self.state()?;
        loop {
            self.boot(&mut state);
            if state.cancelled || self.gone() {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if !state.incoming.is_empty() {
                let mut read = 0;
                for slot in into.iter_mut() {
                    let Some(byte) = state.incoming.pop_front() else {
                        break;
                    };
                    *slot = byte;
                    read += 1;
                }
                return Ok(read);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(0);
            }
            let wait = (deadline - now).min(Duration::from_millis(5));
            state = self
                .woken
                .wait_timeout(state, wait)
                .map_err(|_| io::Error::other("the bench is poisoned"))?
                .0;
        }
    }

    fn geometry(&self) -> io::Result<Geometry> {
        Ok(self.state()?.geometry)
    }

    fn set_geometry(&self, geometry: &Geometry) -> io::Result<()> {
        if !(5..=8).contains(&geometry.size) || geometry.baud == 0 {
            return Err(io::Error::other("no driver takes that"));
        }
        self.state()?.geometry = *geometry;
        self.log.say(&format!("baud {}", geometry.baud));
        Ok(())
    }

    fn signals(&self) -> io::Result<(bool, bool)> {
        let state = self.state()?;
        Ok((state.dtr, state.rts))
    }

    fn signal(&self, signal: Signal, on: bool) -> io::Result<()> {
        let mut state = self.state()?;
        self.boot(&mut state);
        let en_low = Wired::en_low(&state);
        match signal {
            Signal::Dtr => state.dtr = on,
            Signal::Rts => state.rts = on,
            Signal::Break => {}
        }
        let word = match signal {
            Signal::Dtr => "dtr",
            Signal::Rts => "rts",
            Signal::Break => "break",
        };
        self.log
            .say(&format!("{word} {}", if on { "on" } else { "off" }));
        if self.wiring == Wiring::Loop {
            state.changed.modem = true;
        } else {
            let now = Instant::now();
            if en_low && !Wired::en_low(&state) {
                state.released = Some(now);
                state.io0.clear();
            } else if Wired::en_low(&state) {
                state.released = None;
            }
            let low = Wired::io0_low(&state);
            state.io0.push((now, low));
        }
        self.woken.notify_all();
        Ok(())
    }

    fn modem(&self) -> io::Result<Modem> {
        let state = self.state()?;
        Ok(match self.wiring {
            Wiring::Loop => Modem {
                cts: state.rts,
                dsr: state.dtr,
                ri: false,
                cd: false,
            },
            Wiring::Board { .. } => Modem::default(),
        })
    }

    fn status(&self) -> io::Result<Status> {
        let state = self.state()?;
        Ok(Status {
            waiting: u32::try_from(state.incoming.len()).unwrap_or(u32::MAX),
            ..Status::default()
        })
    }

    fn wait(&self) -> io::Result<Changed> {
        let mut state = self.state()?;
        loop {
            if state.cancelled || self.gone() {
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            if state.changed != Changed::default() {
                return Ok(std::mem::take(&mut state.changed));
            }
            state = self
                .woken
                .wait_timeout(state, Duration::from_millis(250))
                .map_err(|_| io::Error::other("the bench is poisoned"))?
                .0;
        }
    }

    fn purge(&self, received: bool, _unsent: bool) -> io::Result<()> {
        let mut state = self.state()?;
        if received {
            state.incoming.clear();
        }
        Ok(())
    }

    fn cancel(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.cancelled = true;
        }
        self.woken.notify_all();
    }
}

impl Drop for Wired {
    fn drop(&mut self) {
        if let Ok(mut open) = self.open.lock() {
            open.remove(&self.name);
        }
        let written = self.state.lock().map_or(0, |state| state.written);
        self.log
            .say(&format!("closed {} after {written} bytes", self.name));
    }
}
