//! What a remote's own tool cannot be given through Hedwig, said where the
//! person meets it - the catalogue a capability is defined from, and the
//! row of one that runs into it - with what would change it.
//!
//! A limit is said, never worked around with a forward that seems to work.

use std::fmt;

use crate::capability::{Capability, ServicePort, Source};
use crate::protocol::Usb;

/// One thing a remote's tool cannot be given, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Beyond {
    /// An iPhone or iPad at the workstation, for Xcode on a macOS remote.
    AppleDevice,
    /// A board whose port is its chip's own USB, which esptool on a remote
    /// cannot tell from a UART bridge.
    ChipUsb,
    /// A program that chooses its debug port each run, which no definition
    /// can name.
    PortPerRun,
}

/// Espressif's USB vendor, and the product its chips' USB-Serial/JTAG
/// peripheral gives (`esp_pylib/constants.py:19,22`).
pub const ESPRESSIF: u16 = 0x303A;
pub const USB_SERIAL_JTAG: u16 = 0x1001;

/// The products a chip's USB-OTG port gives: the chip's image id, for each
/// chip esptool 5.4.0 drives over USB-OTG (`IMAGE_CHIP_ID` of its targets
/// `esp32s2`, `esp32s3`, `esp32p4`, `esp32e22` and `esp32s31`, and
/// `loader.py:1340-1344`).
pub const USB_OTG: [u16; 5] = [2, 9, 18, 31, 32];

impl Beyond {
    /// Every limit, in the order a surface lists them.
    pub const ALL: [Beyond; 3] = [Beyond::AppleDevice, Beyond::ChipUsb, Beyond::PortPerRun];

    /// The limit a capability as defined runs into before any remote uses
    /// it: a service whose port is not stated, which a program that chooses
    /// it each run leaves unstatable.
    pub fn of_capability(capability: &Capability) -> Option<Beyond> {
        match &capability.source {
            Source::Service {
                port: ServicePort::Unstated,
                ..
            } => Some(Beyond::PortPerRun),
            _ => None,
        }
    }

    /// The limit a serial port runs into, by the USB device behind it.
    pub fn of_port(usb: Option<Usb>) -> Option<Beyond> {
        let usb = usb?;
        let chip = usb.vendor == ESPRESSIF
            && (usb.product == USB_SERIAL_JTAG || USB_OTG.contains(&usb.product));
        chip.then_some(Beyond::ChipUsb)
    }

    /// What would change it, each in words.
    pub fn reopens(self) -> &'static [&'static str] {
        match self {
            Beyond::AppleDevice => &[
                "Xcode on a macOS remote reading a device through anything but its own \
                 /var/run/usbmuxd",
                "Apple's usbmuxd giving a client a device without the workstation's pairing \
                 record",
                "a documented, unprivileged way to point a macOS remote's device services at \
                 another host",
            ],
            Beyond::ChipUsb => &[
                "esptool learning a remote port's USB mode from something other than the \
                 identifiers of a port on its own machine",
            ],
            Beyond::PortPerRun => &["the program started at a port it is told"],
        }
    }
}

impl fmt::Display for Beyond {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Beyond::AppleDevice => f.write_str(
                "an iPhone or iPad at this workstation cannot be lent to a remote: Xcode on a \
                 macOS remote reads only that Mac's own usbmuxd, and Apple's usbmuxd hands any \
                 client the workstation's pairing record, which keeps the device's trust after a \
                 grant ends",
            ),
            Beyond::ChipUsb => f.write_str(
                "this board's port is its chip's own USB, which esptool tells from a UART bridge \
                 only by the identifiers of a port on its own machine; through any remote port it \
                 cannot reset the board into its bootloader, nor take the steps it takes for such \
                 a port, as it does locally; the board's console is served as any port's",
            ),
            Beyond::PortPerRun => f.write_str(
                "a program that chooses its debug port each run cannot be carried, since no \
                 definition can name the port; started at a port it is told, it is a service \
                 like any other",
            ),
        }
    }
}
