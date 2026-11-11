//! RFC 2217's access server, the side Hedwig is: Telnet (RFC 854, 855)
//! carrying a serial port's data, its settings and its control lines, read
//! from whatever a remote sends. Total and bounded: nothing a remote sends is
//! kept beyond a subnegotiation's first [`KEPT`] bytes, every byte either
//! advances the decoder or ends the connection with a [`Breach`], and no input
//! makes the server send more than a few bytes per command it reads.
//!
//! Data is carried as binary whatever the remote negotiates: the far end is a
//! serial line, and no tool that reaches one speaks the network virtual
//! terminal's line endings.

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::serial::{Geometry, Inbound, Line, Modem, Outbound, Parity, Signal, Status, StopBits};

pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250;
pub const SE: u8 = 240;

pub const BINARY: u8 = 0;
pub const SGA: u8 = 3;
pub const COM_PORT: u8 = 44;

pub const SIGNATURE: u8 = 0;
pub const SET_BAUDRATE: u8 = 1;
pub const SET_DATASIZE: u8 = 2;
pub const SET_PARITY: u8 = 3;
pub const SET_STOPSIZE: u8 = 4;
pub const SET_CONTROL: u8 = 5;
pub const NOTIFY_LINESTATE: u8 = 6;
pub const NOTIFY_MODEMSTATE: u8 = 7;
pub const FLOWCONTROL_SUSPEND: u8 = 8;
pub const FLOWCONTROL_RESUME: u8 = 9;
pub const SET_LINESTATE_MASK: u8 = 10;
pub const SET_MODEMSTATE_MASK: u8 = 11;
pub const PURGE_DATA: u8 = 12;
/// What the server adds to a command's number to answer it.
pub const ANSWER: u8 = 100;

/// How much of a subnegotiation is kept: the option, the command and the
/// longest value a command has, the baud rate's four bytes. A signature's text
/// is counted and dropped.
pub const KEPT: usize = 6;

/// What Hedwig says it is when asked for its signature.
pub const SIGNED: &[u8] = b"Hedwig";

/// Why a remote's connection was ended: what it sent breaks RFC 854, 855 or
/// 2217 in a way no further byte mends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breach {
    /// IAC followed by a byte that is no Telnet command, or by SE outside a
    /// subnegotiation.
    Undefined(u8),
    /// Inside a subnegotiation, IAC followed by something other than IAC or
    /// SE.
    Unterminated(u8),
    /// A subnegotiation with no option.
    Empty,
    /// A COM-PORT-OPTION command whose value is not the length the command's
    /// value has.
    Malformed { command: u8, length: usize },
    /// A command only the server sends.
    ServerCommand(u8),
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Breach::Undefined(byte) => {
                write!(f, "IAC was followed by {byte}, which is no Telnet command")
            }
            Breach::Unterminated(byte) => {
                write!(
                    f,
                    "a subnegotiation held IAC followed by {byte}, neither IAC nor SE"
                )
            }
            Breach::Empty => f.write_str("a subnegotiation named no option"),
            Breach::Malformed { command, length } => write!(
                f,
                "COM-PORT-OPTION command {command} came with {length} bytes of value"
            ),
            Breach::ServerCommand(command) => write!(
                f,
                "COM-PORT-OPTION command {command} is the access server's to send"
            ),
        }
    }
}

impl std::error::Error for Breach {}

/// Why a session cannot go on.
#[derive(Debug)]
pub enum Stop {
    Breach(Breach),
    /// The line failed: the port went away.
    Line(std::io::Error),
}

/// One thing the decoder read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    Data(u8),
    Verb {
        verb: u8,
        option: u8,
    },
    /// A subnegotiation: its first [`KEPT`] bytes, and how many it had.
    Sub {
        kept: Vec<u8>,
        length: usize,
    },
    /// Any other Telnet command, which is read and does nothing.
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    #[default]
    Data,
    Iac,
    Verb(u8),
    Sub,
    SubIac,
}

/// RFC 854's reader: one byte at a time, so a command split across reads is
/// read as one.
#[derive(Debug, Default)]
struct Decoder {
    mode: Mode,
    kept: Vec<u8>,
    length: usize,
}

impl Decoder {
    fn feed(&mut self, byte: u8) -> Result<Option<Item>, Breach> {
        let (mode, item) = match (self.mode, byte) {
            (Mode::Data, IAC) => (Mode::Iac, None),
            (Mode::Data, byte) => (Mode::Data, Some(Item::Data(byte))),
            (Mode::Iac, IAC) => (Mode::Data, Some(Item::Data(IAC))),
            (Mode::Iac, SB) => {
                self.kept.clear();
                self.length = 0;
                (Mode::Sub, None)
            }
            (Mode::Iac, verb @ (WILL | WONT | DO | DONT)) => (Mode::Verb(verb), None),
            // NOP, DM, BRK, IP, AO, AYT, EC, EL, GA: nothing a serial line
            // has, and an answer to AYT would be read as the board's data.
            (Mode::Iac, 241..=249) => (Mode::Data, Some(Item::Command)),
            (Mode::Iac, byte) => return Err(Breach::Undefined(byte)),
            (Mode::Verb(verb), option) => (Mode::Data, Some(Item::Verb { verb, option })),
            (Mode::Sub, IAC) => (Mode::SubIac, None),
            (Mode::Sub, byte) => {
                self.keep(byte);
                (Mode::Sub, None)
            }
            (Mode::SubIac, IAC) => {
                self.keep(IAC);
                (Mode::Sub, None)
            }
            (Mode::SubIac, SE) => {
                if self.length == 0 {
                    return Err(Breach::Empty);
                }
                let kept = std::mem::take(&mut self.kept);
                (
                    Mode::Data,
                    Some(Item::Sub {
                        kept,
                        length: self.length,
                    }),
                )
            }
            (Mode::SubIac, byte) => return Err(Breach::Unterminated(byte)),
        };
        self.mode = mode;
        Ok(item)
    }

    fn keep(&mut self, byte: u8) {
        if self.kept.len() < KEPT {
            self.kept.push(byte);
        }
        self.length = self.length.saturating_add(1);
    }
}

/// RFC 1143's states for one side of one option, as far as a server that
/// never turns an option off on its own needs them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Q {
    #[default]
    No,
    Yes,
    WantYes,
}

/// What the line's events are told to the remote by: the masks the remote
/// set and the modem state last told it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notices {
    modem_mask: u8,
    line_mask: u8,
    /// CTS, DSR, RI and CD as last told, without the deltas.
    last: Option<u8>,
    /// COM-PORT-OPTION is agreed in one direction or the other, so the
    /// remote reads what it is told.
    agreed: bool,
}

impl Default for Notices {
    /// The masks RFC 2217 starts with: every modem change told, no line
    /// state.
    fn default() -> Self {
        Notices {
            modem_mask: 255,
            line_mask: 0,
            last: None,
            agreed: false,
        }
    }
}

impl Notices {
    /// NOTIFY-MODEMSTATE for a change the line signalled, where the mask lets
    /// any of it through.
    pub fn modem(&mut self, modem: Modem) -> Option<Vec<u8>> {
        if !self.agreed {
            return None;
        }
        let value = self.state(modem) & self.modem_mask;
        (value != 0).then(|| sub(NOTIFY_MODEMSTATE + ANSWER, &[value]))
    }

    /// NOTIFY-MODEMSTATE whatever the mask: asked for, or the first after the
    /// option is agreed, which pyserial needs before it reads CTS or DSR at
    /// all (`rfc2217.py:925-931`).
    fn told(&mut self, modem: Modem) -> Vec<u8> {
        let value = self.state(modem);
        sub(NOTIFY_MODEMSTATE + ANSWER, &[value])
    }

    fn state(&mut self, modem: Modem) -> u8 {
        let lines = u8::from(modem.cts) << 4
            | u8::from(modem.dsr) << 5
            | u8::from(modem.ri) << 6
            | u8::from(modem.cd) << 7;
        let changed = lines ^ self.last.unwrap_or(0);
        // CTS, DSR and CD report any change; RI only its trailing edge.
        let trailing = changed & !lines & 0b0100_0000;
        let deltas = ((changed >> 4) & 0b1011) | (trailing >> 4);
        self.last = Some(lines);
        lines | deltas
    }

    /// NOTIFY-LINESTATE for errors the line signalled, where the mask lets any
    /// of them through.
    pub fn line(&self, status: Status) -> Option<Vec<u8>> {
        if !self.agreed {
            return None;
        }
        let value = line_state(status) & self.line_mask;
        (value != 0).then(|| sub(NOTIFY_LINESTATE + ANSWER, &[value]))
    }
}

/// NOTIFY-LINESTATE's bits for what the line reports.
fn line_state(status: Status) -> u8 {
    let empty = status.unsent == 0;
    u8::from(status.waiting > 0)
        | u8::from(status.overrun) << 1
        | u8::from(status.parity) << 2
        | u8::from(status.framing) << 3
        | u8::from(status.broken) << 4
        | u8::from(empty) << 5
        | u8::from(empty) << 6
}

/// `IAC SB COM-PORT-OPTION <command> <value> IAC SE`, IAC doubled in the
/// value.
fn sub(command: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![IAC, SB, COM_PORT, command];
    out.extend(escape(value));
    out.extend([IAC, SE]);
    out
}

/// Bytes as Telnet carries them: IAC doubled.
pub fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 64);
    for byte in bytes {
        out.push(*byte);
        if *byte == IAC {
            out.push(IAC);
        }
    }
    out
}

/// One remote's session with one opened port.
#[derive(Debug)]
pub struct Session {
    decoder: Decoder,
    /// Whether the server does BINARY, SGA and COM-PORT-OPTION.
    us: [Q; 3],
    /// Whether the remote does.
    him: [Q; 3],
    notices: Arc<Mutex<Notices>>,
    suspended: bool,
    lines: Lines,
    /// A raise of DTR that waits for the next command, and until when.
    held: Option<Instant>,
}

/// The lines the workstation drives, as the remote last set them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lines {
    dtr: bool,
    rts: bool,
    brk: bool,
}

fn slot(option: u8) -> Option<usize> {
    match option {
        BINARY => Some(0),
        SGA => Some(1),
        COM_PORT => Some(2),
        _ => None,
    }
}

impl Session {
    /// A session with `line`, and what the server sends first: that it will
    /// and would have the remote do BINARY and COM-PORT-OPTION.
    ///
    /// # Errors
    ///
    /// The line cannot say what DTR and RTS are.
    pub fn open(line: &dyn Line, notices: Arc<Mutex<Notices>>) -> Result<(Session, Vec<u8>), Stop> {
        let (dtr, rts) = line.signals().map_err(Stop::Line)?;
        let session = Session {
            decoder: Decoder::default(),
            us: [Q::WantYes, Q::No, Q::WantYes],
            him: [Q::WantYes, Q::No, Q::WantYes],
            notices,
            suspended: false,
            lines: Lines {
                dtr,
                rts,
                brk: false,
            },
            held: None,
        };
        let greeting = vec![
            IAC, WILL, BINARY, IAC, DO, BINARY, IAC, WILL, COM_PORT, IAC, DO, COM_PORT,
        ];
        Ok((session, greeting))
    }

    /// Whether the remote asked that nothing more be sent until it resumes.
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// Until when a raise of DTR waits for the next command.
    pub fn holding(&self) -> Option<Instant> {
        self.held
    }

    /// Applies a raise of DTR that waited and whose time is up.
    ///
    /// # Errors
    ///
    /// The line failed.
    pub fn expire(&mut self, line: &dyn Line) -> Result<Vec<u8>, Stop> {
        self.release(line)?;
        Ok(Vec::new())
    }

    fn release(&mut self, line: &dyn Line) -> Result<(), Stop> {
        if self.held.take().is_some() {
            line.signal(Signal::Dtr, true).map_err(Stop::Line)?;
        }
        Ok(())
    }

    /// Reads what the remote sent, drives the line with it in order, and
    /// returns what is answered.
    ///
    /// # Errors
    ///
    /// [`Stop::Breach`] where the remote broke the protocol, [`Stop::Line`]
    /// where the line failed; either ends the connection.
    pub fn receive(&mut self, bytes: &[u8], line: &dyn Line) -> Result<Vec<u8>, Stop> {
        let mut out = Vec::new();
        let mut data = Vec::new();
        for byte in bytes {
            let Some(item) = self.decoder.feed(*byte).map_err(Stop::Breach)? else {
                continue;
            };
            if let Item::Data(byte) = item {
                data.push(byte);
                continue;
            }
            if !data.is_empty() {
                self.release(line)?;
                line.write(&data).map_err(Stop::Line)?;
                data.clear();
            }
            self.item(item, line, &mut out)?;
        }
        if !data.is_empty() {
            self.release(line)?;
            line.write(&data).map_err(Stop::Line)?;
        }
        Ok(out)
    }

    fn item(&mut self, item: Item, line: &dyn Line, out: &mut Vec<u8>) -> Result<(), Stop> {
        match item {
            Item::Data(_) | Item::Command => self.release(line),
            Item::Verb { verb, option } => {
                self.release(line)?;
                self.negotiate(verb, option, line, out)
            }
            Item::Sub { kept, length } => match kept.split_first() {
                Some((&COM_PORT, rest)) => self.command(rest, length - 1, line, out),
                // Another option's subnegotiation: none is agreed, so none is
                // read.
                Some(_) | None => self.release(line),
            },
        }
    }

    fn negotiate(
        &mut self,
        verb: u8,
        option: u8,
        line: &dyn Line,
        out: &mut Vec<u8>,
    ) -> Result<(), Stop> {
        let agreed_before = self.agreed();
        let side = match verb {
            WILL | WONT => &mut self.him,
            _ => &mut self.us,
        };
        match (verb, slot(option).and_then(|at| side.get_mut(at))) {
            (WILL, Some(q)) => answer_q(q, true, DO, option, out),
            (WONT, Some(q)) => answer_q(q, false, DONT, option, out),
            (DO, Some(q)) => answer_q(q, true, WILL, option, out),
            (DONT, Some(q)) => answer_q(q, false, WONT, option, out),
            (WILL, None) => out.extend([IAC, DONT, option]),
            (DO, None) => out.extend([IAC, WONT, option]),
            // Refusing what is already off needs no answer.
            _ => {}
        }
        if !agreed_before && self.agreed() {
            let modem = line.modem().map_err(Stop::Line)?;
            if let Ok(mut notices) = self.notices.lock() {
                notices.agreed = true;
                out.extend(notices.told(modem));
            }
        }
        Ok(())
    }

    fn agreed(&self) -> bool {
        self.us.get(2) == Some(&Q::Yes) || self.him.get(2) == Some(&Q::Yes)
    }

    #[allow(clippy::too_many_lines, reason = "one arm per COM-PORT-OPTION command")]
    fn command(
        &mut self,
        kept: &[u8],
        length: usize,
        line: &dyn Line,
        out: &mut Vec<u8>,
    ) -> Result<(), Stop> {
        let Some((&command, value)) = kept.split_first() else {
            return Err(Stop::Breach(Breach::Empty));
        };
        let length = length.saturating_sub(1);
        let fits = |expected: &[usize]| {
            if expected.contains(&length) {
                Ok(())
            } else {
                Err(Stop::Breach(Breach::Malformed { command, length }))
            }
        };
        match command {
            SIGNATURE => {
                self.release(line)?;
                if length == 0 {
                    out.extend(sub(SIGNATURE, SIGNED));
                }
                Ok(())
            }
            SET_BAUDRATE => {
                fits(&[4])?;
                self.release(line)?;
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(value.get(..4).unwrap_or(&[0; 4]));
                let asked = u32::from_be_bytes(bytes);
                let geometry = Session::set(line, |geometry| {
                    (asked != 0).then_some(Geometry {
                        baud: asked,
                        ..geometry
                    })
                })?;
                out.extend(sub(SET_BAUDRATE + ANSWER, &geometry.baud.to_be_bytes()));
                Ok(())
            }
            SET_DATASIZE | SET_PARITY | SET_STOPSIZE => {
                fits(&[1])?;
                self.release(line)?;
                let asked = value.first().copied().unwrap_or(0);
                let geometry = Session::set(line, |geometry| match command {
                    SET_DATASIZE => (5..=8).contains(&asked).then_some(Geometry {
                        size: asked,
                        ..geometry
                    }),
                    SET_PARITY => parity_of(asked).map(|parity| Geometry { parity, ..geometry }),
                    _ => stop_of(asked).map(|stop| Geometry { stop, ..geometry }),
                })?;
                let value = match command {
                    SET_DATASIZE => geometry.size,
                    SET_PARITY => parity_code(geometry.parity),
                    _ => stop_code(geometry.stop),
                };
                out.extend(sub(command + ANSWER, &[value]));
                Ok(())
            }
            SET_CONTROL => {
                fits(&[1])?;
                let asked = value.first().copied().unwrap_or(0);
                self.control(asked, line, out)
            }
            NOTIFY_LINESTATE | NOTIFY_MODEMSTATE => {
                fits(&[0, 1])?;
                self.release(line)?;
                if command == NOTIFY_LINESTATE {
                    let status = line.status().map_err(Stop::Line)?;
                    out.extend(sub(NOTIFY_LINESTATE + ANSWER, &[line_state(status)]));
                } else {
                    let modem = line.modem().map_err(Stop::Line)?;
                    if let Ok(mut notices) = self.notices.lock() {
                        out.extend(notices.told(modem));
                    }
                }
                Ok(())
            }
            FLOWCONTROL_SUSPEND | FLOWCONTROL_RESUME => {
                fits(&[0])?;
                self.release(line)?;
                self.suspended = command == FLOWCONTROL_SUSPEND;
                Ok(())
            }
            SET_LINESTATE_MASK | SET_MODEMSTATE_MASK => {
                fits(&[1])?;
                self.release(line)?;
                let mask = value.first().copied().unwrap_or(0);
                if let Ok(mut notices) = self.notices.lock() {
                    if command == SET_LINESTATE_MASK {
                        notices.line_mask = mask;
                    } else {
                        notices.modem_mask = mask;
                    }
                }
                out.extend(sub(command + ANSWER, &[mask]));
                Ok(())
            }
            PURGE_DATA => {
                fits(&[1])?;
                self.release(line)?;
                let asked = value.first().copied().unwrap_or(0);
                let purged = match asked {
                    1..=3 => {
                        line.purge(asked & 1 != 0, asked & 2 != 0)
                            .map_err(Stop::Line)?;
                        asked
                    }
                    _ => 0,
                };
                out.extend(sub(PURGE_DATA + ANSWER, &[purged]));
                Ok(())
            }
            ANSWER..=112 => Err(Stop::Breach(Breach::ServerCommand(command))),
            // "Available for Future Use": read, and nothing done.
            _ => self.release(line),
        }
    }

    /// The line set as `change` would have it, or left as it is where
    /// `change` declines or the driver refuses; what the line now has.
    fn set(
        line: &dyn Line,
        change: impl FnOnce(Geometry) -> Option<Geometry>,
    ) -> Result<Geometry, Stop> {
        let geometry = line.geometry().map_err(Stop::Line)?;
        match change(geometry) {
            Some(changed) if line.set_geometry(&changed).is_ok() => Ok(changed),
            _ => line.geometry().map_err(Stop::Line),
        }
    }

    fn control(&mut self, asked: u8, line: &dyn Line, out: &mut Vec<u8>) -> Result<(), Stop> {
        // A raise of DTR while RTS is raised, which the next command usually
        // follows with RTS lowered: esptool's reset into its bootloader,
        // whose two writes must reach the board together.
        if asked == 8 && self.lines.rts && !self.lines.dtr && self.held.is_none() {
            let geometry = line.geometry().map_err(Stop::Line)?;
            if geometry.inbound != Inbound::Dtr {
                self.lines.dtr = true;
                self.held = Some(Instant::now() + crate::serial::HOLD);
                out.extend(sub(SET_CONTROL + ANSWER, &[8]));
                return Ok(());
            }
        }
        self.release(line)?;
        let signal = match asked {
            5 | 6 => Some((Signal::Break, asked == 5)),
            8 | 9 => Some((Signal::Dtr, asked == 8)),
            11 | 12 => Some((Signal::Rts, asked == 11)),
            _ => None,
        };
        if let Some((signal, on)) = signal {
            if line.signal(signal, on).is_ok() {
                match signal {
                    Signal::Break => self.lines.brk = on,
                    Signal::Dtr => self.lines.dtr = on,
                    Signal::Rts => self.lines.rts = on,
                }
            }
            let state = match signal {
                Signal::Break => {
                    if self.lines.brk {
                        5
                    } else {
                        6
                    }
                }
                Signal::Dtr => {
                    if self.lines.dtr {
                        8
                    } else {
                        9
                    }
                }
                Signal::Rts => {
                    if self.lines.rts {
                        11
                    } else {
                        12
                    }
                }
            };
            out.extend(sub(SET_CONTROL + ANSWER, &[state]));
            return Ok(());
        }
        let answered = match asked {
            4 => Some(if self.lines.brk { 5 } else { 6 }),
            7 => Some(if self.lines.dtr { 8 } else { 9 }),
            10 => Some(if self.lines.rts { 11 } else { 12 }),
            0 | 1 | 2 | 3 | 17 | 19 => {
                let geometry = Session::set(line, |geometry| {
                    let (outbound, inbound) = match asked {
                        1 => (Outbound::None, Inbound::None),
                        2 => (Outbound::XonXoff, Inbound::XonXoff),
                        3 => (Outbound::Hardware, Inbound::Hardware),
                        19 => (Outbound::Dsr, Inbound::Dtr),
                        // 0 asks; 17, DCD, is no flow control Windows has.
                        _ => return None,
                    };
                    Some(Geometry {
                        outbound,
                        inbound,
                        ..geometry
                    })
                })?;
                Some(outbound_code(geometry.outbound))
            }
            13..=16 | 18 => {
                let geometry = Session::set(line, |geometry| {
                    let inbound = match asked {
                        14 => Inbound::None,
                        15 => Inbound::XonXoff,
                        16 => Inbound::Hardware,
                        18 => Inbound::Dtr,
                        _ => return None,
                    };
                    Some(Geometry {
                        inbound,
                        ..geometry
                    })
                })?;
                Some(inbound_code(geometry.inbound))
            }
            _ => None,
        };
        if let Some(value) = answered {
            out.extend(sub(SET_CONTROL + ANSWER, &[value]));
        }
        Ok(())
    }
}

/// Moves one side of one option as the other end asked, answering only where
/// RFC 854 says to: a request to enter a state already entered is not
/// acknowledged, nor the answer to a request of the server's own.
fn answer_q(q: &mut Q, yes: bool, reply: u8, option: u8, out: &mut Vec<u8>) {
    match (*q, yes) {
        (Q::No, true) => {
            *q = Q::Yes;
            out.extend([IAC, reply, option]);
        }
        (Q::WantYes, true) => *q = Q::Yes,
        (Q::Yes, false) => {
            *q = Q::No;
            out.extend([IAC, reply, option]);
        }
        (Q::WantYes, false) => *q = Q::No,
        (Q::Yes, true) | (Q::No, false) => {}
    }
}

fn parity_of(code: u8) -> Option<Parity> {
    match code {
        1 => Some(Parity::None),
        2 => Some(Parity::Odd),
        3 => Some(Parity::Even),
        4 => Some(Parity::Mark),
        5 => Some(Parity::Space),
        _ => None,
    }
}

fn parity_code(parity: Parity) -> u8 {
    match parity {
        Parity::None => 1,
        Parity::Odd => 2,
        Parity::Even => 3,
        Parity::Mark => 4,
        Parity::Space => 5,
    }
}

fn stop_of(code: u8) -> Option<StopBits> {
    match code {
        1 => Some(StopBits::One),
        2 => Some(StopBits::Two),
        3 => Some(StopBits::OneAndAHalf),
        _ => None,
    }
}

fn stop_code(stop: StopBits) -> u8 {
    match stop {
        StopBits::One => 1,
        StopBits::Two => 2,
        StopBits::OneAndAHalf => 3,
    }
}

fn outbound_code(outbound: Outbound) -> u8 {
    match outbound {
        Outbound::None => 1,
        Outbound::XonXoff => 2,
        Outbound::Hardware => 3,
        Outbound::Dsr => 19,
    }
}

fn inbound_code(inbound: Inbound) -> u8 {
    match inbound {
        Inbound::None => 14,
        Inbound::XonXoff => 15,
        Inbound::Hardware => 16,
        Inbound::Dtr => 18,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic, reason = "tests")]

    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::serial::{
        Changed, Geometry, Inbound, Line, Modem, Outbound, Parity, Signal, Status, StopBits,
    };

    /// What the session did to the line, in order.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Did {
        Wrote(Vec<u8>),
        Set(Geometry),
        Signal(Signal, bool),
        Purged(bool, bool),
    }

    /// A line that records what it is told and refuses what it is set to.
    struct Recorder {
        did: Mutex<Vec<Did>>,
        geometry: Mutex<Geometry>,
        signals: (bool, bool),
        modem: Modem,
        refuses_baud: Option<u32>,
        holds_rts: bool,
    }

    impl Recorder {
        fn new(signals: (bool, bool)) -> Recorder {
            Recorder {
                did: Mutex::new(Vec::new()),
                geometry: Mutex::new(Geometry {
                    baud: 9600,
                    size: 8,
                    parity: Parity::None,
                    stop: StopBits::One,
                    outbound: Outbound::None,
                    inbound: Inbound::None,
                }),
                signals,
                modem: Modem {
                    cts: true,
                    dsr: false,
                    ri: false,
                    cd: true,
                },
                refuses_baud: None,
                holds_rts: false,
            }
        }

        fn did(&self) -> Vec<Did> {
            self.did.lock().unwrap().clone()
        }

        fn written(&self) -> Vec<u8> {
            self.did()
                .into_iter()
                .filter_map(|did| match did {
                    Did::Wrote(bytes) => Some(bytes),
                    _ => None,
                })
                .flatten()
                .collect()
        }
    }

    impl Line for Recorder {
        fn write(&self, bytes: &[u8]) -> io::Result<()> {
            self.did.lock().unwrap().push(Did::Wrote(bytes.to_vec()));
            Ok(())
        }
        fn read(&self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn geometry(&self) -> io::Result<Geometry> {
            Ok(*self.geometry.lock().unwrap())
        }
        fn set_geometry(&self, geometry: &Geometry) -> io::Result<()> {
            if Some(geometry.baud) == self.refuses_baud {
                return Err(io::Error::other("the driver refuses that rate"));
            }
            *self.geometry.lock().unwrap() = *geometry;
            self.did.lock().unwrap().push(Did::Set(*geometry));
            Ok(())
        }
        fn signals(&self) -> io::Result<(bool, bool)> {
            Ok(self.signals)
        }
        fn signal(&self, signal: Signal, on: bool) -> io::Result<()> {
            if self.holds_rts && signal == Signal::Rts {
                return Err(io::Error::other("handshaking holds RTS"));
            }
            self.did.lock().unwrap().push(Did::Signal(signal, on));
            Ok(())
        }
        fn modem(&self) -> io::Result<Modem> {
            Ok(self.modem)
        }
        fn status(&self) -> io::Result<Status> {
            Ok(Status {
                framing: true,
                waiting: 3,
                ..Status::default()
            })
        }
        fn wait(&self) -> io::Result<Changed> {
            Ok(Changed::default())
        }
        fn purge(&self, received: bool, unsent: bool) -> io::Result<()> {
            self.did.lock().unwrap().push(Did::Purged(received, unsent));
            Ok(())
        }
        fn cancel(&self) {}
    }

    fn opened(line: &Recorder) -> (Session, Vec<u8>) {
        Session::open(line, Arc::new(Mutex::new(Notices::default()))).unwrap()
    }

    /// Exactly what pyserial 3.5's `Serial.open` sends for an `rfc2217://`
    /// port at 115,200 baud, 8N1, no flow control, DTR and RTS on
    /// (`rfc2217.py:429-497`), ending with the purges `open` ends with.
    fn pyserial_opens() -> Vec<u8> {
        let mut sent = vec![
            IAC, DO, 1, IAC, WILL, SGA, IAC, DO, SGA, IAC, DO, COM_PORT, IAC, WILL, COM_PORT,
        ];
        sent.extend(sub(SET_BAUDRATE, &115_200u32.to_be_bytes()));
        sent.extend(sub(SET_DATASIZE, &[8]));
        sent.extend(sub(SET_PARITY, &[1]));
        sent.extend(sub(SET_STOPSIZE, &[1]));
        sent.extend(sub(SET_CONTROL, &[1]));
        sent.extend(sub(SET_CONTROL, &[8]));
        sent.extend(sub(SET_CONTROL, &[11]));
        sent.extend(sub(PURGE_DATA, &[1]));
        sent.extend(sub(PURGE_DATA, &[2]));
        sent
    }

    #[test]
    fn pyserial_s_opening_is_answered_as_it_waits_for_and_reaches_the_line_in_order() {
        let line = Recorder::new((false, false));
        let (mut session, greeting) = opened(&line);
        assert_eq!(
            greeting,
            [
                IAC, WILL, BINARY, IAC, DO, BINARY, IAC, WILL, COM_PORT, IAC, DO, COM_PORT
            ]
        );
        let answered = session.receive(&pyserial_opens(), &line).unwrap();
        let mut expected = vec![IAC, WONT, 1, IAC, DO, SGA, IAC, WILL, SGA];
        // CTS and CD on, each newly: their deltas with them.
        expected.extend(sub(
            NOTIFY_MODEMSTATE + ANSWER,
            &[0x10 | 0x80 | 0x01 | 0x08],
        ));
        expected.extend(sub(SET_BAUDRATE + ANSWER, &115_200u32.to_be_bytes()));
        expected.extend(sub(SET_DATASIZE + ANSWER, &[8]));
        expected.extend(sub(SET_PARITY + ANSWER, &[1]));
        expected.extend(sub(SET_STOPSIZE + ANSWER, &[1]));
        expected.extend(sub(SET_CONTROL + ANSWER, &[1]));
        expected.extend(sub(SET_CONTROL + ANSWER, &[8]));
        expected.extend(sub(SET_CONTROL + ANSWER, &[11]));
        expected.extend(sub(PURGE_DATA + ANSWER, &[1]));
        expected.extend(sub(PURGE_DATA + ANSWER, &[2]));
        assert_eq!(answered, expected);
        let did = line.did();
        assert!(matches!(did.first(), Some(Did::Set(geometry)) if geometry.baud == 115_200));
        assert_eq!(
            did.get(5..).unwrap(),
            [
                Did::Signal(Signal::Dtr, true),
                Did::Signal(Signal::Rts, true),
                Did::Purged(true, false),
                Did::Purged(false, true),
            ]
        );
        // pyserial answers the greeting, which asks nothing more of the server.
        let answered = session
            .receive(&[IAC, DO, BINARY, IAC, WILL, BINARY], &line)
            .unwrap();
        assert!(answered.is_empty(), "{answered:?}");
    }

    #[test]
    fn a_command_split_at_any_byte_is_read_as_one() {
        let mut sent = pyserial_opens();
        sent.extend([b'h', IAC, IAC, b'i']);
        let whole = {
            let line = Recorder::new((false, false));
            let (mut session, _) = opened(&line);
            session.receive(&sent, &line).unwrap()
        };
        for at in 0..=sent.len() {
            let line = Recorder::new((false, false));
            let (mut session, _) = opened(&line);
            let (first, second) = sent.split_at(at);
            let mut answered = session.receive(first, &line).unwrap();
            answered.extend(session.receive(second, &line).unwrap());
            assert_eq!(answered, whole, "split at {at}");
            assert_eq!(line.written(), b"h\xffi", "split at {at}");
        }
    }

    /// `SplitMix64`: varied inputs, the same every run.
    struct Seeded(u64);

    impl Seeded {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn byte(&mut self) -> u8 {
            self.next().to_le_bytes()[0]
        }

        fn below(&mut self, bound: u64) -> usize {
            usize::try_from(self.next() % bound).unwrap()
        }
    }

    #[test]
    fn data_is_carried_unchanged_both_ways_whatever_its_bytes() {
        let mut seeded = Seeded(2217);
        for round in 0..200 {
            let length = seeded.below(600);
            let mut data: Vec<u8> = (0..length).map(|_| seeded.byte()).collect();
            if round % 3 == 0 {
                data.extend([IAC, IAC, IAC]);
            }
            // The board's bytes, escaped for the remote and read back by a
            // Telnet reader, are the board's bytes.
            let mut decoder = Decoder::default();
            let back: Vec<u8> = escape(&data)
                .into_iter()
                .filter_map(|byte| match decoder.feed(byte).unwrap() {
                    Some(Item::Data(byte)) => Some(byte),
                    None => None,
                    other => panic!("{other:?}"),
                })
                .collect();
            assert_eq!(back, data);
            // The remote's bytes, escaped as pyserial sends them, reach the
            // line as they were.
            let line = Recorder::new((false, false));
            let (mut session, _) = opened(&line);
            assert_eq!(
                session.receive(&escape(&data), &line).unwrap(),
                Vec::<u8>::new()
            );
            assert_eq!(line.written(), data);
        }
    }

    #[test]
    fn each_breach_ends_the_session_naming_what_broke() {
        let cases: [(&[u8], Breach); 7] = [
            (&[IAC, 0x41], Breach::Undefined(0x41)),
            (&[IAC, SE], Breach::Undefined(SE)),
            (
                &[IAC, SB, COM_PORT, 1, IAC, 0x41],
                Breach::Unterminated(0x41),
            ),
            (&[IAC, SB, IAC, SE], Breach::Empty),
            (
                &[IAC, SB, COM_PORT, SET_BAUDRATE, 0, 1, IAC, SE],
                Breach::Malformed {
                    command: SET_BAUDRATE,
                    length: 2,
                },
            ),
            (
                &[IAC, SB, COM_PORT, SET_CONTROL, IAC, SE],
                Breach::Malformed {
                    command: SET_CONTROL,
                    length: 0,
                },
            ),
            (
                &[IAC, SB, COM_PORT, SET_CONTROL + ANSWER, 8, IAC, SE],
                Breach::ServerCommand(SET_CONTROL + ANSWER),
            ),
        ];
        for (sent, breach) in cases {
            let line = Recorder::new((false, false));
            let (mut session, _) = opened(&line);
            match session.receive(sent, &line) {
                Err(Stop::Breach(found)) => assert_eq!(found, breach, "{sent:?}"),
                other => panic!("{sent:?}: {other:?}"),
            }
            assert_ne!(breach.to_string(), "");
        }
    }

    #[test]
    fn whatever_a_remote_sends_is_read_in_bounded_memory_and_answered_little() {
        let mut seeded = Seeded(854);
        let telnet = [IAC, SB, SE, WILL, DO, COM_PORT];
        for _ in 0..2000 {
            let length = seeded.below(300);
            let sent: Vec<u8> = (0..length)
                .map(|_| {
                    if seeded.next().is_multiple_of(4) {
                        telnet.get(seeded.below(6)).copied().unwrap_or(IAC)
                    } else {
                        seeded.byte()
                    }
                })
                .collect();
            let line = Recorder::new((true, true));
            let (mut session, _) = opened(&line);
            if let Ok(answered) = session.receive(&sent, &line) {
                assert!(answered.len() <= 4 * sent.len() + 16, "{sent:?}");
            }
            assert!(session.decoder.kept.len() <= KEPT);
        }
        // A subnegotiation that never ends keeps nothing beyond its first
        // bytes.
        let line = Recorder::new((false, false));
        let (mut session, _) = opened(&line);
        let mut endless = vec![IAC, SB, COM_PORT, SIGNATURE];
        endless.extend(vec![b'x'; 1 << 20]);
        assert_eq!(session.receive(&endless, &line).unwrap(), Vec::<u8>::new());
        assert_eq!(session.decoder.kept.len(), KEPT);
        assert_eq!(line.did(), Vec::<Did>::new());
    }

    #[test]
    fn negotiation_answers_a_change_alone_so_no_two_ends_loop() {
        let line = Recorder::new((false, false));
        let (mut session, _) = opened(&line);
        let mut receive = |sent: &[u8]| session.receive(sent, &line).unwrap();
        assert_eq!(receive(&[IAC, DO, SGA]), [IAC, WILL, SGA]);
        assert_eq!(receive(&[IAC, DO, SGA]), Vec::<u8>::new());
        assert_eq!(receive(&[IAC, DONT, SGA]), [IAC, WONT, SGA]);
        assert_eq!(receive(&[IAC, DONT, SGA]), Vec::<u8>::new());
        assert_eq!(receive(&[IAC, WILL, 24]), [IAC, DONT, 24]);
        assert_eq!(receive(&[IAC, DO, 1]), [IAC, WONT, 1]);
        assert_eq!(receive(&[IAC, WONT, 24, IAC, DONT, 1]), Vec::<u8>::new());
        // NOP, AYT and the rest are read and do nothing: an answer to AYT
        // would be read as the board's data.
        assert_eq!(receive(&[IAC, 241, IAC, 246, IAC, 249]), Vec::<u8>::new());
    }

    #[test]
    fn a_setting_is_answered_with_what_the_line_has_after_it() {
        let mut line = Recorder::new((false, false));
        line.refuses_baud = Some(3_000_000);
        let (mut session, _) = opened(&line);
        let nine_six = 9600u32.to_be_bytes();
        let cases: Vec<(Vec<u8>, Vec<u8>)> = vec![
            // The driver refuses it.
            (
                sub(SET_BAUDRATE, &3_000_000u32.to_be_bytes()),
                sub(SET_BAUDRATE + ANSWER, &nine_six),
            ),
            // Zero asks.
            (
                sub(SET_BAUDRATE, &[0; 4]),
                sub(SET_BAUDRATE + ANSWER, &nine_six),
            ),
            (sub(SET_DATASIZE, &[0]), sub(SET_DATASIZE + ANSWER, &[8])),
            // Values RFC 2217 leaves for future use.
            (sub(SET_DATASIZE, &[9]), sub(SET_DATASIZE + ANSWER, &[8])),
            (sub(SET_PARITY, &[6]), sub(SET_PARITY + ANSWER, &[1])),
            (sub(SET_PARITY, &[3]), sub(SET_PARITY + ANSWER, &[3])),
            (sub(SET_STOPSIZE, &[3]), sub(SET_STOPSIZE + ANSWER, &[3])),
            // DCD flow control: no DCB has it.
            (sub(SET_CONTROL, &[17]), sub(SET_CONTROL + ANSWER, &[1])),
            (sub(SET_CONTROL, &[3]), sub(SET_CONTROL + ANSWER, &[3])),
            (sub(SET_CONTROL, &[0]), sub(SET_CONTROL + ANSWER, &[3])),
            (sub(SET_CONTROL, &[13]), sub(SET_CONTROL + ANSWER, &[16])),
            (sub(SET_CONTROL, &[15]), sub(SET_CONTROL + ANSWER, &[15])),
            (sub(SET_CONTROL, &[19]), sub(SET_CONTROL + ANSWER, &[19])),
            (sub(SET_CONTROL, &[5]), sub(SET_CONTROL + ANSWER, &[5])),
            (sub(SET_CONTROL, &[4]), sub(SET_CONTROL + ANSWER, &[5])),
            (sub(SET_CONTROL, &[7]), sub(SET_CONTROL + ANSWER, &[9])),
            (sub(PURGE_DATA, &[3]), sub(PURGE_DATA + ANSWER, &[3])),
            (sub(PURGE_DATA, &[9]), sub(PURGE_DATA + ANSWER, &[0])),
            (
                sub(SET_MODEMSTATE_MASK, &[0x10]),
                sub(SET_MODEMSTATE_MASK + ANSWER, &[0x10]),
            ),
            // Data waiting, a framing error, nothing unsent.
            (
                sub(NOTIFY_LINESTATE, &[]),
                sub(NOTIFY_LINESTATE + ANSWER, &[0b0110_1001]),
            ),
            (sub(SIGNATURE, &[]), sub(SIGNATURE, SIGNED)),
            (sub(SIGNATURE, b"client"), Vec::new()),
            (sub(FLOWCONTROL_SUSPEND, &[]), Vec::new()),
            (sub(42, &[1, 2, 3]), Vec::new()),
            (sub(SET_CONTROL, &[99]), Vec::new()),
        ];
        for (asked, answer) in cases {
            assert_eq!(session.receive(&asked, &line).unwrap(), answer, "{asked:?}");
        }
        assert!(session.suspended());
        session
            .receive(&sub(FLOWCONTROL_RESUME, &[]), &line)
            .unwrap();
        assert!(!session.suspended());
        // A line handshaking holds is answered as it stands.
        let mut held = Recorder::new((false, false));
        held.holds_rts = true;
        let (mut session, _) = opened(&held);
        assert_eq!(
            session.receive(&sub(SET_CONTROL, &[11]), &held).unwrap(),
            sub(SET_CONTROL + ANSWER, &[12])
        );
    }

    #[test]
    fn a_raise_of_dtr_while_rts_is_raised_reaches_the_line_with_the_next_command() {
        // esptool's reset into its bootloader, as esp-pylib writes it through
        // pyserial: DTR off; RTS on and DTR again; then DTR on; RTS off and
        // DTR again; then DTR off (`serial_reset.py:111-123,296-329`).
        let line = Recorder::new((true, true));
        let (mut session, _) = opened(&line);
        for value in [9, 11, 9] {
            session.receive(&sub(SET_CONTROL, &[value]), &line).unwrap();
        }
        let answered = session.receive(&sub(SET_CONTROL, &[8]), &line).unwrap();
        assert_eq!(answered, sub(SET_CONTROL + ANSWER, &[8]));
        assert!(session.holding().is_some());
        let before = line.did().len();
        session.receive(&sub(SET_CONTROL, &[12]), &line).unwrap();
        assert_eq!(
            line.did().get(before..).unwrap(),
            [
                Did::Signal(Signal::Dtr, true),
                Did::Signal(Signal::Rts, false)
            ]
        );
        assert!(session.holding().is_none());
        // A raise followed by anything else reaches the line before it.
        let line = Recorder::new((false, true));
        let (mut session, _) = opened(&line);
        session.receive(&sub(SET_CONTROL, &[8]), &line).unwrap();
        session.receive(b"x", &line).unwrap();
        assert_eq!(
            line.did(),
            [Did::Signal(Signal::Dtr, true), Did::Wrote(b"x".to_vec())]
        );
        // One whose time runs out reaches it alone.
        let line = Recorder::new((false, true));
        let (mut session, _) = opened(&line);
        session.receive(&sub(SET_CONTROL, &[8]), &line).unwrap();
        assert_eq!(line.did(), Vec::<Did>::new());
        session.expire(&line).unwrap();
        assert_eq!(line.did(), [Did::Signal(Signal::Dtr, true)]);
        // With RTS lowered there is nothing to wait for.
        let line = Recorder::new((false, false));
        let (mut session, _) = opened(&line);
        session.receive(&sub(SET_CONTROL, &[8]), &line).unwrap();
        assert_eq!(line.did(), [Did::Signal(Signal::Dtr, true)]);
        assert!(session.holding().is_none());
    }

    #[test]
    fn modem_changes_are_told_with_their_deltas_as_the_mask_lets_them() {
        let mut notices = Notices::default();
        let off = Modem::default();
        let on = Modem {
            cts: true,
            dsr: true,
            ri: true,
            cd: true,
        };
        // Before the option is agreed nothing is told.
        assert_eq!(notices.modem(on), None);
        notices.agreed = true;
        assert_eq!(
            notices.modem(on),
            Some(sub(NOTIFY_MODEMSTATE + ANSWER, &[0xF0 | 0b1011]))
        );
        // RI's delta is its trailing edge alone.
        assert_eq!(
            notices.modem(off),
            Some(sub(NOTIFY_MODEMSTATE + ANSWER, &[0b1111]))
        );
        notices.modem_mask = 0x20;
        assert_eq!(notices.modem(Modem { cts: true, ..off }), None);
        assert_eq!(
            notices.modem(Modem { dsr: true, ..off }),
            Some(sub(NOTIFY_MODEMSTATE + ANSWER, &[0x20]))
        );
        // Line state is told only where the remote's mask asks for it.
        let status = Status {
            overrun: true,
            ..Status::default()
        };
        assert_eq!(notices.line(status), None);
        notices.line_mask = 0x02;
        assert_eq!(
            notices.line(status),
            Some(sub(NOTIFY_LINESTATE + ANSWER, &[0x02]))
        );
    }
}
