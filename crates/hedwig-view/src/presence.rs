//! Whether this desktop can show the person anything, and what.
//!
//! The core refuses what nobody would see, and counts an attached interface
//! as seeing unless it says otherwise. The interface says what its desktop
//! takes whenever that changes: nothing while it is locked, its session
//! disconnected, or the shell reports nobody there; only the card while an
//! application fills the screen, since Windows then holds its notifications
//! back; nothing while the person is presenting or an application holds the
//! display exclusively, since the card is not shown over either.

use hedwig_model::trail::Presence;

use crate::card::Desk;

/// What Windows tells the interface about its session and its desktop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Locked,
    Unlocked,
    Disconnected,
    Connected,
    /// What the shell reports the desktop will take now.
    Desk(Desk),
}

/// The facts presence is read from. Each is asked of Windows at start, then
/// kept in step by its notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desktop {
    pub locked: bool,
    pub disconnected: bool,
    pub desk: Desk,
}

impl Default for Desktop {
    fn default() -> Desktop {
        Desktop {
            locked: false,
            disconnected: false,
            desk: Desk::Open,
        }
    }
}

impl Desktop {
    pub fn apply(&mut self, change: Change) -> Presence {
        match change {
            Change::Locked => self.locked = true,
            Change::Unlocked => self.locked = false,
            Change::Disconnected => self.disconnected = true,
            Change::Connected => self.disconnected = false,
            Change::Desk(desk) => self.desk = desk,
        }
        self.presence()
    }

    /// A desktop at which the person is presenting, or whose display an
    /// application holds exclusively, takes nothing from Hedwig while the
    /// person is there: engaged, never away, so a refusal says where they
    /// were.
    pub fn presence(self) -> Presence {
        if self.locked || self.disconnected {
            return Presence::Away;
        }
        match self.desk {
            Desk::Open => Presence::Present,
            Desk::Filled => Presence::CardOnly,
            Desk::Presenting | Desk::Exclusive => Presence::Engaged,
            Desk::Away => Presence::Away,
        }
    }
}
