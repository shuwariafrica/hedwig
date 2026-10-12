//! What passes between the processes of one hedwig.
//!
//! A supervisor runs the core as its child and keeps one record where a
//! client looks for it: [`Running`]. The two speak over the core's standard
//! input and output, one [`Order`] or [`Report`] to a line. None of this is
//! the control channel - that is [`crate::protocol`] - and a client only ever
//! reads the record.

use crate::text::PipeName;
use crate::trail::{Breakdown, Timestamp};

/// The folder Hedwig keeps its files in, inside the one Windows resolves for
/// the person's local application data, under the vendor's segment.
pub const FOLDER: &str = r"ShuwariAfrica\Hedwig";

/// The name of the record, in the folder Hedwig keeps its files in.
pub const RECORD: &str = "running.json";

/// Why a Hedwig process ended, as the status it exits with. The supervisor
/// reads it to decide whether to run another core; a client reads it, inside
/// a [`Breakdown`], to say why none answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Exit {
    /// The person stopped hedwig. Nothing is started again until they ask.
    Stopped,
    /// The command line named no role this build has.
    Usage,
    /// A supervisor of this person's already holds the record.
    AlreadyRunning,
    /// The folder Hedwig keeps its files in could not be resolved, or a file
    /// in it could not be written. The core never runs without recording.
    Storage,
    /// The line from the supervisor closed, or carried something that is not
    /// an [`Order`].
    Link,
    /// The control pipe could not be created.
    Pipe,
    /// Hedwig was removed and left something on a remote it could not reach,
    /// which the removal named.
    Unreached,
}

impl Exit {
    pub const ALL: [Exit; 7] = [
        Exit::Stopped,
        Exit::Usage,
        Exit::AlreadyRunning,
        Exit::Storage,
        Exit::Link,
        Exit::Pipe,
        Exit::Unreached,
    ];

    pub const fn status(self) -> u8 {
        match self {
            Exit::Stopped => 0,
            Exit::Usage => 2,
            Exit::AlreadyRunning => 3,
            Exit::Storage => 4,
            Exit::Link => 5,
            Exit::Pipe => 6,
            Exit::Unreached => 7,
        }
    }

    /// The exit this status names, if it is one of Hedwig's own. A status that
    /// is not - a panic's 101, an access violation - is a breakdown with no
    /// name here.
    pub fn from_status(status: u32) -> Option<Exit> {
        Exit::ALL
            .into_iter()
            .find(|exit| u32::from(exit.status()) == status)
    }

    /// Whether the supervisor runs another core after this one. It does not
    /// after the person's stop, cannot while another supervisor holds the
    /// record, and never sees a removal's status from a core.
    pub const fn restarts(self) -> bool {
        !matches!(self, Exit::Stopped | Exit::AlreadyRunning | Exit::Unreached)
    }
}

/// One process, named so that a later process given the same number is not
/// mistaken for it: the number, and the moment the system created it as a
/// count of 100-nanosecond intervals since 1601.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instance {
    pub process: u32,
    pub created: u64,
}

/// Where a supervisor's core stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreState {
    /// Started, and not yet listening.
    Starting,
    Serving {
        pipe: PipeName,
        process: u32,
    },
    /// The last core broke down and another will be started. `said` is the
    /// last line it wrote before it ended.
    Restarting {
        cause: Breakdown,
        said: String,
    },
}

/// The record a client reads to find the person's hedwig. It stays when the
/// supervisor named in it ends, and counts only while that supervisor holds
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Running {
    pub supervisor: Instance,
    pub core: CoreState,
}

/// What a supervisor tells the core it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Start. Sent once the core is in its supervisor's job, so nothing it
    /// starts can be outside it. `after` is how the core before it ended.
    Begin { after: Option<Breakdown> },
    /// Answer [`Report::Pong`] from the thread that decides everything.
    Ping,
}

/// What a core tells its supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// The control pipe is listening under this name.
    Ready {
        pipe: PipeName,
    },
    Pong,
}

/// One line of the core's diagnostics: when, from which part of the core,
/// and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub at: Timestamp,
    pub from: String,
    pub said: String,
}
