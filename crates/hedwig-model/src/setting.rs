//! What a person sets beyond grants and rules: each setting's values, the
//! scope its statements are made at, and what ships.
//!
//! Every one is a choice ([`crate::scope::choose`]) except the longest
//! allowance, which is a limit the person holds over their own quick
//! gestures. What ships is stated here once, as the last thing each choice
//! falls to.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32};

use crate::policy::{Keys, Selector, Used};
use crate::refusal::Refusal;
use crate::remote::{RemoteId, Remotes, Sets};
use crate::scope::{Audience, Specific, Strict};
use crate::text::Name;

/// The scope of a setting with no remote in it: one value for this
/// workstation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Workstation;

impl Specific for Workstation {
    fn specificity(&self, _: &Self) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}

/// The scope of a choice the person makes for one run of the core or for
/// this workstation: the run's is the nearer, and ends with the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Span {
    Workstation,
    Run,
}

impl Specific for Span {
    fn specificity(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Which statement a choice came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Said<S> {
    /// No source says anything; what ships.
    Ships,
    /// The organisation's starting point.
    Start { audience: Audience, scope: S },
    /// The person's own statement.
    Person(S),
}

/// A setting's value where it is asked about, and the statement it came
/// from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled<V, S> {
    pub value: V,
    pub said: Said<S>,
}

/// How many requests from one remote, within how long, the person wants
/// brought to their attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Burst {
    pub requests: NonZeroU8,
    pub seconds: NonZeroU32,
}

/// When volume from a remote is brought to the person's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Threshold {
    /// No volume from these remotes is a burst: volume is the work there.
    Never,
    At(Burst),
}

impl Threshold {
    /// What ships: no threshold. No record gives a rate that is ordinary, so
    /// none is invented.
    pub const SHIPS: Threshold = Threshold::Never;
}

impl Strict for Threshold {
    /// A threshold reached at a lower rate is the stricter; of two at one
    /// rate, the one reached by fewer requests.
    fn strictness(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Threshold::Never, Threshold::Never) => Ordering::Equal,
            (Threshold::Never, Threshold::At(_)) => Ordering::Less,
            (Threshold::At(_), Threshold::Never) => Ordering::Greater,
            (Threshold::At(this), Threshold::At(that)) => {
                let rate = |burst: &Burst, over: &Burst| {
                    u64::from(burst.requests.get()) * u64::from(over.seconds.get())
                };
                rate(that, this)
                    .cmp(&rate(this, that))
                    .then_with(|| that.requests.cmp(&this.requests))
            }
        }
    }
}

/// How loudly something reaches the person, quietest first. Whatever is set,
/// every condition stays on its row and in what needs the person: `Shown` is
/// the least there is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Volume {
    Shown,
    /// Announced once when it appears, on one surface.
    Announced,
    /// Put to the person on every attending surface at once.
    Interrupts,
}

impl Strict for Volume {
    fn strictness(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

/// The volume of a condition that waits for a look.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Waits {
    Shown,
    Announced,
}

impl From<Waits> for Volume {
    fn from(waits: Waits) -> Volume {
        match waits {
            Waits::Shown => Volume::Shown,
            Waits::Announced => Volume::Announced,
        }
    }
}

/// A condition whose volume the person chooses per remote. What holds a
/// remote up - a held request, a channel's prompt - is not among them: it
/// always interrupts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Condition {
    /// A request was served without asking.
    Served,
    /// Readiness failed.
    Unready,
    /// A channel stopped for a reason only the person can fix.
    Stopped,
    /// A channel stopped because the host presented another key.
    HostKeyChanged,
    /// A refusal the person did not make.
    Refused,
    /// A remote's job told the person something.
    Noticed,
}

impl Condition {
    pub const EVERY: [Condition; 6] = [
        Condition::Served,
        Condition::Unready,
        Condition::Stopped,
        Condition::HostKeyChanged,
        Condition::Refused,
        Condition::Noticed,
    ];

    /// What ships. A served request is shown on the glance and the row;
    /// everything else that waits is announced once.
    pub fn ships(self) -> Volume {
        match self {
            Condition::Served => Volume::Shown,
            Condition::Unready
            | Condition::Stopped
            | Condition::HostKeyChanged
            | Condition::Refused
            | Condition::Noticed => Volume::Announced,
        }
    }
}

/// A condition and the volume chosen for it. Only a changed host key can be
/// made to interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Heard {
    Served(Waits),
    Unready(Waits),
    Stopped(Waits),
    HostKeyChanged(Volume),
    Refused(Waits),
    /// A remote's notice waits for a look, as any of its words does: one
    /// that interrupted would reach every surface at once, as only what holds
    /// a remote up does, with a remote's words.
    Noticed(Waits),
}

impl Heard {
    pub fn condition(self) -> Condition {
        match self {
            Heard::Served(_) => Condition::Served,
            Heard::Unready(_) => Condition::Unready,
            Heard::Stopped(_) => Condition::Stopped,
            Heard::HostKeyChanged(_) => Condition::HostKeyChanged,
            Heard::Refused(_) => Condition::Refused,
            Heard::Noticed(_) => Condition::Noticed,
        }
    }

    pub fn volume(self) -> Volume {
        match self {
            Heard::Served(waits)
            | Heard::Unready(waits)
            | Heard::Stopped(waits)
            | Heard::Refused(waits)
            | Heard::Noticed(waits) => waits.into(),
            Heard::HostKeyChanged(volume) => volume,
        }
    }
}

/// Whether a held request's card is shown over an application that fills the
/// screen. Where it is not, the request goes by the icon's notification, and
/// where Windows holds that back too it is refused as reaching nobody.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FullScreen {
    NotShown,
    Shown,
}

impl FullScreen {
    /// What ships: that application is usually the terminal the request came
    /// from.
    pub const SHIPS: FullScreen = FullScreen::Shown;
}

impl Strict for FullScreen {
    fn strictness(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

/// The lengths "allow for a time" offers on a held request, in seconds. One
/// list for the workstation, since every attending surface offers them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Lengths(BTreeSet<NonZeroU32>);

impl Lengths {
    /// What ships: a minute, a quarter of an hour and an hour - a rebase, a
    /// working burst, a release.
    pub fn ships() -> Lengths {
        [60, 900, 3600].into_iter().collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = NonZeroU32> {
        self.0.iter().copied()
    }
}

impl FromIterator<u32> for Lengths {
    /// Zero is no length and is passed over.
    fn from_iter<I: IntoIterator<Item = u32>>(seconds: I) -> Lengths {
        Lengths(seconds.into_iter().filter_map(NonZeroU32::new).collect())
    }
}

impl FromIterator<NonZeroU32> for Lengths {
    fn from_iter<I: IntoIterator<Item = NonZeroU32>>(seconds: I) -> Lengths {
        Lengths(seconds.into_iter().collect())
    }
}

impl Strict for Lengths {
    /// The list whose longest length is shorter is the stricter; of two that
    /// reach as far, the one that offers fewer.
    fn strictness(&self, other: &Self) -> Ordering {
        let reach = |lengths: &Lengths| lengths.0.last().copied();
        reach(other)
            .cmp(&reach(self))
            .then_with(|| other.0.len().cmp(&self.0.len()))
    }
}

/// The longest an allowance may last, shortest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Longest {
    /// No allowance at all: "allow for a time" is not offered there.
    Nothing,
    Seconds(NonZeroU32),
}

impl Longest {
    pub fn admits(self, seconds: NonZeroU32) -> bool {
        match self {
            Longest::Nothing => false,
            Longest::Seconds(most) => seconds <= most,
        }
    }
}

/// What a cap on allowances covers: requests from these remotes that use
/// these keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapScope {
    pub remotes: Remotes,
    pub key: Keys,
}

impl CapScope {
    pub fn covers(&self, remote: &RemoteId, sets: &Sets<'_>, used: Option<Used<'_>>) -> bool {
        self.remotes.covers(remote, sets) && self.key.covers(used)
    }
}

/// A refusal the person expects from one remote - "I know this remote asks
/// while I am away" - put away for good: it is recorded and counted as ever,
/// and no longer brought to their attention.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Expected {
    pub remote: RemoteId,
    pub refusal: Refusal,
}

/// How a channel's client notices that its link has died: it asks the server
/// for an answer after `every` seconds with nothing heard, and gives up after
/// `missed` go unanswered. There is no "never": a link nobody watches would
/// show as up while nothing reaches the remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Keepalive {
    pub every: NonZeroU16,
    pub missed: NonZeroU8,
}

impl Keepalive {
    /// What ships: a dead link is noticed within 45 seconds. The count is
    /// OpenSSH's own default; the interval is chosen, not derived.
    pub const SHIPS: Keepalive = Keepalive {
        every: NonZeroU16::MIN.saturating_add(14),
        missed: NonZeroU8::MIN.saturating_add(2),
    };

    /// The longest a dead link goes unnoticed, in seconds.
    pub fn notices_within(self) -> u32 {
        u32::from(self.every.get()) * u32::from(self.missed.get())
    }
}

impl Strict for Keepalive {
    /// The one that notices a dead link sooner is the stricter: it keeps what
    /// the person is shown nearer the truth.
    fn strictness(&self, other: &Self) -> Ordering {
        other
            .notices_within()
            .cmp(&self.notices_within())
            .then_with(|| other.every.cmp(&self.every))
    }
}

/// The waits before a lost channel is opened again: `first` after the first
/// attempt that fails, doubling with each that fails after it, never longer
/// than `longest`. A channel that stayed up for [`SETTLED`] seconds is opened
/// again at once. With `longest` below `first`, every wait is `longest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Returns {
    pub first: NonZeroU32,
    pub longest: NonZeroU32,
}

/// Seconds a channel must have been up for its loss to be taken as the link's
/// and not the remote's refusal to hold it: the minute Windows requires of a
/// program before it restarts it, and the supervisor's own. Invariant: it
/// separates a loss from a loop, which no person's preference changes.
pub const SETTLED: u32 = 60;

impl Returns {
    /// What ships: the pace the supervisor restarts a core at, a second
    /// doubling to a minute.
    pub const SHIPS: Returns = Returns {
        first: NonZeroU32::MIN,
        longest: NonZeroU32::MIN.saturating_add(59),
    };

    /// The wait, in seconds, after `failed` attempts in a row that did not
    /// settle; none after a channel that did.
    ///
    /// ```
    /// use hedwig_model::setting::Returns;
    ///
    /// let waits: Vec<u32> = (0..9).map(|failed| Returns::SHIPS.wait(failed)).collect();
    /// assert_eq!(waits, [0, 1, 2, 4, 8, 16, 32, 60, 60]);
    /// ```
    pub fn wait(self, failed: u32) -> u32 {
        if failed == 0 {
            return 0;
        }
        self.first
            .get()
            .saturating_mul(2u32.saturating_pow(failed.saturating_sub(1).min(31)))
            .min(self.longest.get())
    }
}

impl Strict for Returns {
    /// The one that asks less of the remote's server is the stricter: the
    /// longer waits.
    fn strictness(&self, other: &Self) -> Ordering {
        self.longest
            .cmp(&other.longest)
            .then_with(|| self.first.cmp(&other.first))
    }
}

/// How often, in seconds, a route's platform is asked which of its remotes
/// are running, while a grant follows their lives. A listing that has not
/// answered by the next is ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cadence(pub NonZeroU32);

impl Cadence {
    /// What ships: once a minute. A workspace takes longer than that to be
    /// made and started, and sixty listings an hour is a small part of what a
    /// platform lets one person ask (GitHub's REST limit is 5,000 an hour).
    pub const SHIPS: Cadence = Cadence(NonZeroU32::MIN.saturating_add(59));
}

impl Strict for Cadence {
    /// Asking the platform less often is the stricter.
    fn strictness(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

/// The routes a statement about listing is made for: one route, or every
/// route that lists.
pub type Routes = Selector<Name>;

impl Specific for &Routes {
    fn specificity(&self, other: &Self) -> Option<Ordering> {
        let rank = |routes: &Routes| match routes {
            Selector::Every => 0,
            Selector::Only(_) => 1,
        };
        Some(rank(self).cmp(&rank(other)))
    }
}

/// Whether Windows starts Hedwig when the person logs on at a desktop. The
/// person's `Run` value is kept in step with it, so the entry they see under
/// Startup in Settings and Task Manager is this setting and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Autostart {
    /// Started only when the person asks: nothing is registered.
    Off,
    AtLogon,
}

impl Autostart {
    /// What ships: nothing runs that the person did not start.
    pub const SHIPS: Autostart = Autostart::Off;
}

/// How many days of activity the trail keeps. The trail never keeps more than
/// [`crate::trail::CEILING`] entries, whatever this says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Keep(pub NonZeroU16);

impl Keep {
    /// What ships: thirty days, a month's review, keeping less about the
    /// person than a longer horizon would.
    pub const SHIPS: Keep = Keep(NonZeroU16::MIN.saturating_add(29));
}

impl Strict for Keep {
    /// Keeping less about the person is the stricter.
    fn strictness(&self, other: &Self) -> Ordering {
        other.cmp(self)
    }
}

/// What the core writes beside the trail about what went wrong, in its own
/// bounded files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Diagnostics {
    Off,
    /// Every error a waiting thread met that is not an entry, and a channel
    /// client's standard error when its channel ends otherwise than as asked.
    Faults,
    /// Those, and every line a channel's client writes to standard error as
    /// it writes it.
    Detail,
}

impl Diagnostics {
    /// What ships: the fault is kept when it happens.
    pub const SHIPS: Diagnostics = Diagnostics::Faults;
}

impl Strict for Diagnostics {
    /// Writing less is the stricter.
    fn strictness(&self, other: &Self) -> Ordering {
        other.cmp(self)
    }
}

/// A choice an organisation's limit may have moved, and the audience of the
/// limit that did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounded<V, S = Workstation> {
    pub settled: Settled<V, S>,
    pub held: Option<Audience>,
}

impl Strict for Autostart {
    fn strictness(&self, other: &Self) -> Ordering {
        other.cmp(self)
    }
}
