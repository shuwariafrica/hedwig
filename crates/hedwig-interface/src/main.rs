//! Hedwig's interface: an icon in the notification area, and what it opens.
//!
//! One thread runs the message loop and owns everything on the screen; one
//! reads the core's frames and wakes it. What the icon, the card and the menu
//! show is `hedwig_view`'s function of what the core last said; nothing here
//! decides what to show. The interface starts with no window. It is a client
//! of the core's control channel like any other, and never runs its command
//! line.
//!
//! `hedwig-interface tray` is what Windows starts at logon, and
//! `hedwig-interface remove` what Settings runs to remove Hedwig.
//! `--folder <dir>` attends the Hedwig that keeps its files there in place
//! of the person's own, and the icon says which.

#![forbid(unsafe_code)]
#![windows_subsystem = "windows"]

mod remove;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use hedwig_client::{Standing, connect, look};
use hedwig_model::frame::{Frames, Line};
use hedwig_model::process::RECORD;
use hedwig_model::protocol::{Answer, FromCore, Needs, Request, Served, Settings};
use hedwig_model::refusal::Refusal;
use hedwig_model::setting::FullScreen;
use hedwig_model::text::{PipeName, Secret};
use hedwig_model::trail::{Icon as IconShown, Missing, Presence};
use hedwig_model::wire::{line, read};
use hedwig_shell::card::Shown;
use hedwig_shell::host::{Host, Told, Waker};
use hedwig_shell::icon::{self, Icon, Nudge};
use hedwig_shell::menu::Menu;
use hedwig_shell::record::{self, Watch};
use hedwig_shell::{desk, settings, window};
use hedwig_view::act::Act;
use hedwig_view::card::{self, Card, Deck, Does, Subject, Why};
use hedwig_view::emblem::{Emblem, Ink};
use hedwig_view::glance::{self, Announcement, Entry, Glance};
use hedwig_view::link::{self, Attached, Core, Effect, Event, Link, Place, Seen};
use hedwig_view::menu::Opened;
use hedwig_view::presence::Change;
use hedwig_view::style::Appearance;
use hedwig_view::words::{self, Keyrings};
use hedwig_win::Signal;
use hedwig_win::pipe::{Moved, Pipe};
use zeroize::Zeroizing;

/// The longest the loop waits for Windows when nothing is due sooner.
const IDLE: Duration = Duration::from_secs(3600);
/// Hedwig's own programs, beside this one where an install puts them.
const HEDWIG: &str = "hedwig.exe";
const WINDOW: &str = "hedwig-window.exe";

type Place4 = Option<(i32, i32, i32, i32)>;

/// Why the interface ended, as the status it exits with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exit {
    /// The person closed it, or the session ended.
    Ended = 0,
    Usage = 2,
    /// This session has no desktop: an SSH logon, where the command line is
    /// the whole of the interface.
    NoDesktop = 4,
    /// Windows refused the window the interface lives in.
    Shell = 5,
}

/// What another thread leaves for the loop.
enum Arrived {
    /// A frame, or the end of the connection it came on, with which
    /// connection that was; a frame with when it was read.
    Frame(u64, Box<FromCore>, Instant),
    Closed(u64),
    /// Something done off the loop's thread has finished: the record is to
    /// be read again, and where it failed, the person told why.
    Done(Option<String>),
    /// The record, read again because it changed or the supervisor it named
    /// ended.
    Looked(Standing),
}

/// Reads the record whenever it changes or the supervisor it names ends,
/// and leaves what it says for the loop, until the loop has gone.
fn watcher(folder: &Path, mut watch: Watch, arrived: &Sender<Arrived>, waker: Waker) {
    loop {
        let standing = look(folder).ok();
        watch.follow(standing.as_ref().and_then(link::supervisor));
        if let Some(standing) = standing {
            if arrived.send(Arrived::Looked(standing)).is_err() {
                return;
            }
            waker.wake();
        }
        if watch.wait().is_none() {
            return;
        }
    }
}

/// Ends the record's watch when the loop that reads what it leaves ends.
struct Stopping(record::Stop);

impl Drop for Stopping {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// One connection to the core: the pipe, and what stops its reader.
struct Connection {
    pipe: Arc<Pipe>,
    stop: Arc<Signal>,
    /// Which connection this is, so what an earlier one's reader leaves
    /// behind is not taken for this one's.
    turn: u64,
}

fn reader(pipe: &Pipe, stop: &Signal, turn: u64, arrived: &Sender<Arrived>, waker: Waker) {
    let mut frames = Frames::default();
    let closed = loop {
        let parsed = match frames.line() {
            Some(Line::Text(text)) => Some(read::<FromCore>(text).ok()),
            Some(Line::NotText) => Some(None),
            None => None,
        };
        match parsed {
            Some(Some(frame)) => {
                frames.erase();
                let at = Instant::now();
                if arrived
                    .send(Arrived::Frame(turn, Box::new(frame), at))
                    .is_err()
                {
                    return;
                }
                waker.wake();
                continue;
            }
            // Something that is not a frame: nothing after it can be trusted.
            Some(None) => break true,
            None => {}
        }
        let Ok(room) = frames.room() else {
            break true;
        };
        match pipe.read(room, Some(stop)) {
            Ok(Moved::Bytes(count)) => frames.filled(count),
            Ok(Moved::Stopped) => break false,
            _ => break true,
        }
    };
    if closed && arrived.send(Arrived::Closed(turn)).is_ok() {
        waker.wake();
    }
}

/// What the link left to be said, which no surface shows by itself.
enum Say {
    Raised(Needs),
    Served(Served),
    Undone,
}

struct Interface<'a> {
    folder: &'a Path,
    link: Link,
    core: Option<Connection>,
    turns: u64,
    arrived: Sender<Arrived>,
    waker: Waker,
    said: Vec<Say>,
}

impl Interface<'_> {
    fn hang(&mut self) {
        if let Some(line) = self.core.take() {
            // The reader stops; the pipe closes when it lets go of it.
            let _ = line.stop.raise();
        }
    }

    /// Hands the link an event and carries out what it asks for.
    fn step(&mut self, event: Event) {
        let mut pending = vec![event];
        while let Some(event) = pending.pop() {
            for effect in self.link.handle(event) {
                match effect {
                    Effect::Look => pending.extend(look(self.folder).ok().map(Event::Looked)),
                    Effect::Open(name) => pending.push(self.open(&name)),
                    Effect::Send(frame) => {
                        // A frame can carry what the person typed: its text
                        // is erased once written.
                        let mut text = Zeroizing::new(line(&frame));
                        text.push('\n');
                        let sent = self
                            .core
                            .as_ref()
                            .map(|line| line.pipe.write(text.as_bytes(), None));
                        if !matches!(sent, Some(Ok(Moved::Bytes(_)))) {
                            self.hang();
                            pending.push(Event::Closed);
                        }
                    }
                    Effect::Hang => self.hang(),
                    Effect::Raised(needs) => self.said.push(Say::Raised(needs)),
                    Effect::Served(served) => self.said.push(Say::Served(served)),
                    Effect::Undone(_) => self.said.push(Say::Undone),
                    // What is shown is brought up to date after every event.
                    Effect::Render => {}
                }
            }
        }
    }

    fn open(&mut self, name: &PipeName) -> Event {
        self.hang();
        let (pipe, stop) = match (connect(name), Signal::new()) {
            (Ok(pipe), Ok(stop)) => (Arc::new(pipe), Arc::new(stop)),
            (Err(refused), _) => return Event::Unopened(refused.to_string()),
            (_, Err(error)) => return Event::Unopened(error.to_string()),
        };
        self.turns += 1;
        let turn = self.turns;
        let (arrived, waker) = (self.arrived.clone(), self.waker);
        let (reading, stopping) = (Arc::clone(&pipe), Arc::clone(&stop));
        thread::spawn(move || reader(&reading, &stopping, turn, &arrived, waker));
        self.core = Some(Connection { pipe, stop, turn });
        Event::Opened
    }

    fn current(&self, turn: u64) -> bool {
        self.core.as_ref().is_some_and(|line| line.turn == turn)
    }

    /// Runs `work` off the loop's thread; when it is done the record is read
    /// again, and what it says went wrong is said.
    fn aside(&self, work: impl FnOnce() -> Option<String> + Send + 'static) {
        let (arrived, waker) = (self.arrived.clone(), self.waker);
        thread::spawn(move || {
            if arrived.send(Arrived::Done(work())).is_ok() {
                waker.wake();
            }
        });
    }
}

/// A program of Hedwig's beside this one.
fn sibling(name: &str) -> Option<PathBuf> {
    let path = std::env::current_exe().ok()?.with_file_name(name);
    path.exists().then_some(path)
}

/// A confirmation on the screen, the card it was made from, and the act it
/// confirms.
struct Asking {
    shown: Shown,
    card: Card,
    act: Act,
    near: Place4,
}

/// The open menu, the entries its rows are, and where it was asked for.
struct Opens {
    _menu: Menu,
    entries: Vec<Entry>,
    at: (i32, i32),
    opened: Opened,
}

/// What the interface has on the screen besides the icon.
struct Surfaces<'h> {
    host: &'h Host,
    title: String,
    /// Milliseconds are counted from here, for the card's settling.
    epoch: Instant,
    deck: Deck,
    /// The card on the screen, and the card it was made from.
    card: Option<(Shown, Card)>,
    /// Whether the card has been put on the screen: it is made whatever the
    /// desktop takes, and raised once the desktop takes it.
    raised: bool,
    /// What assistive technology was last told has come up, so each subject
    /// is announced once however often its card is made.
    announced: Option<Subject>,
    /// What the desktop takes, as the shell last said.
    desk: card::Desk,
    /// When its answers come on.
    arm_at: Option<Instant>,
    /// The person put the card aside: it comes back with the next thing to
    /// answer, or when they ask for it.
    aside: bool,
    menu: Option<Opens>,
    /// The confirmation of an act the person chose, while it is asked. The
    /// loop goes on meanwhile: a held request arriving is carded.
    asking: Option<Asking>,
    /// Windows' own signals of a changed setting, held while a painted
    /// surface is on the screen.
    watch: Option<settings::Watch>,
    /// What the person had set when a surface was last made: a signal after
    /// which it reads the same changes nothing on the screen.
    made: Option<Appearance>,
    /// The refusal last said, so each is said once.
    refusal: Option<(Place, Refusal)>,
    /// Why the icon cannot be shown, while the person is to be told: from
    /// when it has been missing for `glance::UNSEEN_AFTER` until they close
    /// the notice or the icon is added.
    unseen: Option<Missing>,
}

/// What an answer from the card does.
#[derive(Debug, PartialEq, Eq)]
enum Answered {
    Send(Request),
    /// Open the window: the notice's usual answer.
    Open,
}

fn settle() -> Duration {
    Duration::from_millis(u64::from(desk::settle()))
}

impl<'h> Surfaces<'h> {
    fn new(host: &'h Host, title: String) -> Surfaces<'h> {
        Surfaces {
            host,
            title,
            epoch: Instant::now(),
            deck: Deck::default(),
            card: None,
            raised: false,
            announced: None,
            desk: card::Desk::Open,
            arm_at: None,
            aside: false,
            menu: None,
            asking: None,
            watch: None,
            made: None,
            refusal: None,
            unseen: None,
        }
    }

    /// The person's appearance, read as a surface is about to be shown and
    /// held by nothing at rest but what it was.
    fn appearance(&mut self) -> Appearance {
        let appearance = settings::read();
        self.made = Some(appearance);
        appearance
    }

    /// Windows signalled that a setting changed: the surfaces are made again
    /// where what they answer to reads otherwise. Windows signals more than
    /// it changes - measured, the colours' event as the menu takes the
    /// foreground - and a surface made again loses the person's place in it.
    fn changed(&mut self, seen: &Seen, icon: Place4) {
        if self.made != Some(settings::read()) {
            self.repaint(seen, icon);
        }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// How long the loop may wait before something here is due.
    fn wait(&self) -> Duration {
        self.arm_at
            .map_or(IDLE, |at| at.saturating_duration_since(Instant::now()))
    }

    fn painted(&mut self) {
        let shown = self.card.is_some() || self.menu.is_some() || self.asking.is_some();
        if shown && self.watch.is_none() {
            self.watch = settings::Watch::new(self.host).ok();
        } else if !shown {
            self.watch = None;
        }
    }

    /// Brings the card in step with what the core says waits.
    fn card(&mut self, seen: &Seen, icon: Place4) {
        let now = self.now();
        let (attention, rows, settings, keyrings) = match seen.attached() {
            Some(attached) => (
                attached.attention.as_deref().unwrap_or_default(),
                attached.rows.as_deref().unwrap_or_default(),
                attached.settings.as_deref(),
                attached.keyrings(),
            ),
            None => (&[][..], &[][..], None, Keyrings::default()),
        };
        let contacts = settings.map_or(&[][..], |settings| &settings.workstation.contacts[..]);
        let own = self.unseen.map(Subject::Unseen);
        if self.deck.settle_with(attention, own.as_ref(), now) {
            self.aside = false;
        }
        let why = Why {
            rows,
            contacts,
            keyrings,
        };
        let wanted = match self.deck.showing() {
            Some(Subject::Unseen(unseen)) => {
                let behind = attention
                    .iter()
                    .filter(|needs| Subject::of(&needs.attention).is_some())
                    .count();
                Some(Card::unseen(
                    *unseen,
                    u32::try_from(behind).unwrap_or(u32::MAX),
                ))
            }
            _ => self.deck.card(attention, why),
        };
        let same = matches!(
            (&self.card, &wanted),
            (Some((_, shown)), Some(card)) if shown == card
        );
        if !same {
            let near = self.near(icon);
            self.make(wanted, near);
        }
        self.show(settings);
        self.painted();
    }

    /// Puts the card on the screen once the desktop takes it, settling from
    /// then, and tells assistive technology of each subject once.
    fn show(&mut self, settings: Option<&Settings>) {
        let Some((shown, card)) = &self.card else {
            return;
        };
        let over = card
            .from
            .as_ref()
            .map_or(FullScreen::SHIPS, |remote| card::over(remote, settings));
        if self.raised || self.aside || !card::raise(self.desk, over) {
            return;
        }
        if shown.raise().is_ok() {
            self.raised = true;
            self.arm_at = Some(Instant::now() + settle());
            if self.announced.as_ref() != Some(&card.subject) {
                shown.announce();
                self.announced = Some(card.subject.clone());
            }
        }
    }

    /// Where a card is made: where the one it replaces is, or by the icon.
    fn near(&self, icon: Place4) -> Place4 {
        self.card
            .as_ref()
            .and_then(|(shown, _)| shown.place())
            .or(icon)
    }

    fn make(&mut self, card: Option<Card>, near: Place4) {
        // One card at a time: the old one goes before the new one is made.
        self.card = None;
        self.raised = false;
        self.arm_at = None;
        let Some(card) = card else {
            return;
        };
        let appearance = self.appearance();
        let Ok(shown) = Shown::new(&self.title, &card, &appearance, near) else {
            return;
        };
        self.card = Some((shown, card));
    }

    /// The answers come on once the card has settled.
    fn tick(&mut self) {
        if self.raised
            && self.arm_at.is_some_and(|at| at <= Instant::now())
            && self.deck.armed(self.now(), desk::settle())
            && let Some((shown, _)) = &self.card
        {
            shown.arm(true);
            self.arm_at = None;
        }
    }

    /// What the card's `place`th answer does: the request it makes, what was
    /// typed taken into a secret and erased from the box. The card goes with
    /// it, and is made again, settling again, while the core still says it
    /// waits; the notice goes for good.
    fn answer(&mut self, place: u16) -> Option<Answered> {
        if !self.raised || self.arm_at.is_some() || !self.deck.armed(self.now(), desk::settle()) {
            return None;
        }
        let (shown, card) = self.card.take()?;
        let choice = card.choices.into_iter().nth(usize::from(place))?;
        match (choice.does, card.subject) {
            (Does::Send(request), _) => Some(Answered::Send(request)),
            (Does::Typed(prompt), _) => Some(Answered::Send(Request::Answer {
                prompt,
                answer: Answer::Text(Secret::from(shown.take_typed()?)),
            })),
            (Does::Proceed, Subject::Unseen(_)) => {
                self.unseen = None;
                Some(Answered::Open)
            }
            (Does::Cancel, Subject::Unseen(_)) => {
                self.unseen = None;
                None
            }
            // A confirmation's answers arrive as `Told::Confirmed`.
            (Does::Proceed | Does::Cancel | Does::Install(_) | Does::Save | Does::Copy, _) => None,
        }
    }

    /// The card was brought forward by the keyboard: its answers went off
    /// and come back once it has settled again.
    fn forward(&mut self) -> Option<(String, Act)> {
        self.arm_at = Some(Instant::now() + settle());
        None
    }

    /// The person put the card aside without an answer.
    fn put_aside(&mut self) -> Option<(String, Act)> {
        self.aside = true;
        None
    }

    /// The person asked for the card: it comes forward with the keyboard.
    fn bring(&mut self) {
        if let Some((shown, _)) = &self.card {
            self.aside = false;
            self.raised = true;
            shown.bring();
            self.arm_at = Some(Instant::now() + settle());
        }
    }

    fn openmenu(&mut self, seen: &Seen, at: (i32, i32), opened: Opened, icon: Place4) {
        self.menu = None;
        let entries = glance::menu(seen, Instant::now());
        let appearance = self.appearance();
        if let Ok(menu) = Menu::open(&self.title, &entries, &appearance, at, icon, opened) {
            self.menu = Some(Opens {
                _menu: menu,
                entries,
                at,
                opened,
            });
        }
        self.painted();
    }

    /// The act of the row chosen, with the words it was chosen by.
    fn picked(&mut self, group: Option<u16>, entry: u16) -> Option<(String, Act)> {
        let opens = self.menu.take()?;
        self.painted();
        let mut entries = opens.entries;
        let chosen = match group {
            None => entries.into_iter().nth(usize::from(entry))?,
            Some(group) => match entries.swap_remove(usize::from(group)) {
                Entry::Group { entries, .. } => entries.into_iter().nth(usize::from(entry))?,
                _ => return None,
            },
        };
        match chosen {
            Entry::Act { label, act, .. } => Some((label, act)),
            _ => None,
        }
    }

    /// Puts the act the person chose to them before it is done, in place of
    /// any confirmation already asked: one at a time, the latest choice.
    fn ask(&mut self, verb: &str, consequence: &str, act: Act, near: Place4) {
        self.asking = None;
        let card = Card::confirming(verb, consequence);
        let appearance = self.appearance();
        if let Ok(shown) = Shown::new(&self.title, &card, &appearance, near) {
            shown.ask();
            self.asking = Some(Asking {
                shown,
                card,
                act,
                near,
            });
        }
        self.painted();
    }

    /// The act confirmed, where the person said to go ahead; the confirmation
    /// goes either way.
    fn confirmed(&mut self, yes: bool) -> Option<Act> {
        let asking = self.asking.take()?;
        self.painted();
        yes.then_some(asking.act)
    }

    /// A setting of the person's changed, or the card is on a monitor of
    /// another scale: what is painted is made again where it is.
    fn repaint(&mut self, seen: &Seen, icon: Place4) {
        if let Some((shown, card)) = self.card.take() {
            let near = shown.place().or(icon);
            drop(shown);
            self.make(Some(card), near);
            self.show(
                seen.attached()
                    .and_then(|attached| attached.settings.as_deref()),
            );
        }
        if let Some(opens) = self.menu.take() {
            self.openmenu(seen, opens.at, opens.opened, icon);
        }
        if let Some(asking) = self.asking.take() {
            drop(asking.shown);
            let appearance = self.appearance();
            if let Ok(shown) = Shown::new(&self.title, &asking.card, &appearance, asking.near) {
                shown.ask();
                self.asking = Some(Asking { shown, ..asking });
            }
        }
    }
}

fn announce(icon: Option<&Icon<'_>>, said: &Announcement) {
    if let Some(icon) = icon {
        let when = if said.now { Nudge::Now } else { Nudge::Quiet };
        let _ = icon.nudge(said.title(), said.text(), when);
    }
}

/// Says what the last events left to say, and a refusal of an act made from
/// the icon or the card, which leave nothing on the screen that could show
/// it.
fn tell(interface: &mut Interface<'_>, surfaces: &mut Surfaces<'_>, icon: Option<&Icon<'_>>) {
    let seen = interface.link.seen();
    let contacts = seen
        .attached()
        .and_then(|attached| attached.settings.as_ref())
        .map_or(&[][..], |settings| &settings.workstation.contacts[..]);
    let keyrings = seen.attached().map(Attached::keyrings).unwrap_or_default();
    for said in std::mem::take(&mut interface.said) {
        match said {
            Say::Raised(needs) => {
                // What the card answers is the card's to bring up, with an
                // alert for assistive technology. Where the card cannot be
                // shown, the core has been told what the desktop takes and
                // refuses what nobody else can be asked about.
                if Subject::of(&needs.attention).is_none() {
                    announce(icon, &Announcement::of(&needs, contacts, keyrings));
                }
            }
            Say::Served(served) => announce(icon, &Announcement::served(&served, keyrings)),
            Say::Undone => announce(
                icon,
                &Announcement::said(
                    "Hedwig did not do that",
                    "Hedwig is not running, and nothing was kept to do later.",
                ),
            ),
        }
    }
    let refused = seen
        .attached()
        .and_then(|attached| attached.refused.clone())
        .filter(|(place, _)| matches!(place, Place::Tray | Place::Card));
    if refused != surfaces.refusal {
        if let Some((_, refusal)) = &refused {
            announce(
                icon,
                &Announcement::said("Hedwig did not do that", &words::refusal(refusal, contacts)),
            );
        }
        surfaces.refusal = refused;
    }
}

/// Carries out what the person chose from the menu, the icon or one of its
/// notifications.
fn act(
    interface: &mut Interface<'_>,
    surfaces: &mut Surfaces<'_>,
    icon: Option<&Icon<'_>>,
    label: &str,
    act: Act,
) -> Option<Exit> {
    let verb = label.trim_end_matches("...");
    let not_done = |text: &str| announce(icon, &Announcement::said("Hedwig did not do that", text));
    match act {
        Act::Answer => surfaces.bring(),
        // Defining is the window's: the presence offers it nowhere, and an
        // act to define opens the window where it is done.
        Act::Open(_) | Act::Define(_) => {
            // The window is its own executable, beside this one. The person
            // asked for it, so the foreground their act gave this process is
            // handed on; a window already open is brought forward by the
            // start, which then ends.
            let mut command = sibling(WINDOW).map(Command::new);
            if let Some(command) = &mut command
                && hedwig_client::folder().ok().as_deref() != Some(interface.folder)
            {
                command.arg("--folder").arg(interface.folder);
            }
            match command.map(|mut command| command.spawn()) {
                Some(Ok(started)) => {
                    window::allow(started.id());
                }
                Some(Err(error)) => not_done(&error.to_string()),
                None => not_done("Hedwig's window is not installed beside this icon."),
            }
        }
        Act::Start => match sibling(HEDWIG) {
            Some(program) => {
                let mut arguments = vec![OsString::from("supervise")];
                if hedwig_client::folder().ok().as_deref() != Some(interface.folder) {
                    arguments.extend([OsString::from("--folder"), interface.folder.into()]);
                }
                interface.aside(move || {
                    hedwig_client::launch(&program, &arguments)
                        .err()
                        .map(|error| error.to_string())
                });
            }
            None => not_done("hedwig.exe is not beside this icon to be started."),
        },
        Act::Retry => interface.step(Event::Retry),
        Act::Leave => return Some(Exit::Ended),
        Act::Send(request) => interface.step(Event::Wish(Place::Tray, request)),
        Act::Confirm {
            ref consequence, ..
        }
        | Act::Stop {
            ref consequence, ..
        } => {
            let consequence = consequence.clone();
            let near = icon.and_then(Icon::place);
            surfaces.ask(verb, &consequence, act, near);
        }
    }
    None
}

/// Carries out an act the person confirmed.
fn carry(interface: &mut Interface<'_>, act: Act) {
    match act {
        Act::Confirm { request, .. } => interface.step(Event::Wish(Place::Tray, request)),
        Act::Stop { .. } if matches!(interface.link.seen().core, Core::Attached(_)) => {
            interface.step(Event::Wish(Place::Tray, Request::Stop));
        }
        Act::Stop { .. } => {
            // No core answers: its supervisor is ended instead.
            let folder = interface.folder.to_path_buf();
            interface.aside(move || match look(&folder) {
                Ok(standing) => hedwig_client::stop(&standing)
                    .err()
                    .map(|error| error.to_string()),
                Err(error) => Some(error.to_string()),
            });
        }
        _ => {}
    }
}

/// What another thread left: frames of the connection that is current, and
/// what was done aside.
fn drain(interface: &mut Interface<'_>, receiver: &Receiver<Arrived>, icon: Option<&Icon<'_>>) {
    while let Ok(arrived) = receiver.try_recv() {
        match arrived {
            Arrived::Frame(turn, frame, at) if interface.current(turn) => {
                interface.step(Event::Frame(*frame, at));
            }
            Arrived::Closed(turn) if interface.current(turn) => {
                interface.hang();
                interface.step(Event::Closed);
            }
            Arrived::Done(failed) => {
                if let Some(failed) = failed {
                    announce(icon, &Announcement::said("Hedwig did not do that", &failed));
                }
                if let Ok(standing) = look(interface.folder) {
                    interface.step(Event::Looked(standing));
                }
            }
            Arrived::Looked(standing) => interface.step(Event::Looked(standing)),
            Arrived::Frame(..) | Arrived::Closed(_) => {}
        }
    }
}

/// The icon on the taskbar, and what it shows: the emblem, in which ink, at
/// which size.
struct Tray<'h> {
    icon: Icon<'h>,
    face: (Emblem, Ink, usize),
}

/// The icon says what the core last said, its emblem drawn again only when
/// what it shows, what it stands on or its size changed. With no shell to
/// hold it - a taskbar not yet up - it is added when the shell says it is.
fn glanced<'h>(
    host: &'h Host,
    tray: &mut Option<Tray<'h>>,
    seen: &Seen,
    label: Option<&str>,
    ink: Ink,
) {
    let glance = Glance::of(seen);
    let (name, tip) = match label {
        Some(label) => (
            format!("{label}: Hedwig"),
            format!("{label}: {}", glance.tip()),
        ),
        None => ("Hedwig".to_owned(), glance.tip().to_owned()),
    };
    let face = (Emblem::of(&glance), ink, icon::side(host));
    let draw = |(emblem, ink, side): (Emblem, Ink, usize)| emblem.draw(side, ink);
    match tray {
        Some(tray) => {
            let _ = tray.icon.say(&tip);
            if tray.face != face && tray.icon.show(&draw(face)).is_ok() {
                tray.face = face;
            }
        }
        None => {
            *tray = Icon::add(host, &name, &tip, &draw(face))
                .ok()
                .map(|icon| Tray { icon, face });
        }
    }
}

/// Runs the presence; `open` where the person started it, who is shown the
/// window.
#[allow(
    clippy::too_many_lines,
    reason = "the one loop, owning every window, that dispatches all the presence is told"
)]
fn run(folder: &Path, label: Option<&str>, open: bool) -> Exit {
    let Ok(host) = Host::new() else {
        return Exit::Shell;
    };
    let (sender, receiver) = mpsc::channel();
    let mut interface = Interface {
        folder,
        link: Link::default(),
        core: None,
        turns: 0,
        arrived: sender,
        waker: host.waker(),
        said: Vec::new(),
    };
    let title = label.map_or_else(|| "Hedwig".to_owned(), |label| format!("Hedwig ({label})"));
    host.serve(folder);
    let mut surfaces = Surfaces::new(&host, title);
    let mut desktop = desk::desktop();
    surfaces.desk = desktop.desk;
    interface.step(Event::Presence(desktop.presence()));
    if let Ok(standing) = look(folder) {
        interface.step(Event::Looked(standing));
    }
    // A Hedwig started from a terminal or at logon, a core started again and
    // a supervisor that ended are each seen without the person asking. The
    // folder is the core's to make; it is made here where Hedwig has never
    // run, so it can be watched.
    let _stop = std::fs::create_dir_all(folder)
        .and_then(|()| Watch::new(folder, RECORD))
        .ok()
        .map(|(watch, stop)| {
            let (folder, arrived, waker) = (
                folder.to_path_buf(),
                interface.arrived.clone(),
                interface.waker,
            );
            thread::spawn(move || watcher(&folder, watch, &arrived, waker));
            Stopping(stop)
        });
    let mut tray: Option<Tray<'_>> = None;
    // Adds the shell has refused since the icon was last there, and when it
    // is added again.
    let mut refused: u32 = 0;
    let mut again: Option<Instant> = None;
    let mut missing = glance::Missing::default();
    let mut ink = settings::ink();
    if open {
        act(&mut interface, &mut surfaces, None, "", Act::Open(None));
    }
    loop {
        if tray.is_none() && again.is_none_or(|at| at <= Instant::now()) {
            glanced(&host, &mut tray, interface.link.seen(), label, ink);
            // Refused while the taskbar is there, it is added again on a
            // schedule; with no taskbar, when the shell says one was made.
            again = match &tray {
                Some(_) => {
                    refused = 0;
                    None
                }
                None if icon::taskbar() => {
                    let wait = glance::added_again(refused);
                    refused = refused.saturating_add(1);
                    Some(Instant::now() + wait)
                }
                None => Some(Instant::now() + Duration::from_secs(3600)),
            };
        } else if tray.is_some() {
            glanced(&host, &mut tray, interface.link.seen(), label, ink);
        }
        // An icon missing for longer than any taskbar takes to start is told
        // to the person once, until it is there again.
        // The core is told when the person is, and when the icon is back, so
        // the window and the command line say it while it is so.
        if tray.is_some() {
            if missing.shown() {
                interface.step(Event::Icon(IconShown::Shown));
            }
            surfaces.unseen = None;
        } else {
            let why = if icon::taskbar() {
                Missing::Refused
            } else {
                Missing::NoTaskbar
            };
            if let Some(unseen) = missing.missing(Instant::now(), why) {
                surfaces.unseen = Some(unseen);
                interface.step(Event::Icon(IconShown::Missing(unseen)));
            }
        }
        let icon = tray.as_ref().map(|tray| &tray.icon);
        let place = icon.and_then(Icon::place);
        surfaces.card(interface.link.seen(), place);
        tell(&mut interface, &mut surfaces, icon);
        // The taskbar was made again: the icon is gone, to be added anew.
        let mut taskbar = false;
        let wait = [again.filter(|_| tray.is_none()), missing.due()]
            .into_iter()
            .flatten()
            .fold(surfaces.wait(), |wait, at| {
                wait.min(at.saturating_duration_since(Instant::now()))
            });
        for told in host.told(wait) {
            let seen = interface.link.seen();
            let chosen = match told {
                Told::End => {
                    interface.hang();
                    return Exit::Ended;
                }
                Told::Woken => {
                    drain(&mut interface, &receiver, icon);
                    None
                }
                Told::Session(change) => {
                    let presence: Presence = desktop.apply(change);
                    interface.step(Event::Presence(presence));
                    None
                }
                // An application began or stopped filling the screen.
                Told::Desk => {
                    interface.step(Event::Presence(desktop.apply(Change::Desk(desk::desk()))));
                    surfaces.desk = desktop.desk;
                    None
                }
                Told::Taskbar => {
                    taskbar = true;
                    None
                }
                // A click on the icon, or on one of its notifications, does
                // the menu's default.
                Told::Chosen | Told::Nudged => Some((String::new(), glance::chosen(seen))),
                Told::Menu { at, opened } => {
                    surfaces.openmenu(seen, at, opened, place);
                    None
                }
                Told::Picked(group, entry) => surfaces.picked(group, entry),
                Told::Dismissed => {
                    surfaces.menu = None;
                    surfaces.painted();
                    None
                }
                Told::Answered(answer) => match surfaces.answer(answer) {
                    Some(Answered::Send(request)) => {
                        interface.step(Event::Wish(Place::Card, request));
                        None
                    }
                    Some(Answered::Open) => Some((String::new(), Act::Open(None))),
                    None => None,
                },
                Told::Aside => surfaces.put_aside(),
                // The window asked for the card, as a click on the icon would.
                Told::Bring => Some((String::new(), Act::Answer)),
                Told::Open => Some((String::new(), Act::Open(None))),
                Told::Confirmed(answer) => {
                    if let Some(confirmed) = surfaces.confirmed(answer.is_some()) {
                        carry(&mut interface, confirmed);
                    }
                    None
                }
                Told::Forward => surfaces.forward(),
                // Presentation settings turned on or off arrive as a changed
                // setting.
                Told::Settings => {
                    ink = settings::ink();
                    interface.step(Event::Presence(desktop.apply(Change::Desk(desk::desk()))));
                    surfaces.desk = desktop.desk;
                    surfaces.changed(interface.link.seen(), place);
                    None
                }
            };
            if let Some((label, chosen)) = chosen
                && let Some(exit) = act(&mut interface, &mut surfaces, icon, &label, chosen)
            {
                interface.hang();
                return exit;
            }
        }
        if taskbar {
            tray = None;
            again = None;
            refused = 0;
            ink = settings::ink();
        }
        surfaces.tick();
    }
}

/// One presence for each person, desktop and hedwig. A start that finds
/// another holding it asks that one for the window, unless it is the start at
/// logon, and ends.
fn start(folder: &Path, label: Option<&str>, tray: bool) -> Exit {
    match window::claim_presence(folder) {
        Ok(Some(_presence)) => run(folder, label, !tray),
        Ok(None) => {
            if !tray {
                window::open_window(folder);
            }
            Exit::Ended
        }
        Err(_) => Exit::Shell,
    }
}

fn main() -> ExitCode {
    let mut folder = None;
    let mut tray = false;
    let mut removing = false;
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        match (argument.to_str(), &folder) {
            // Started at logon: no window.
            (Some("tray"), _) if !removing => tray = true,
            // Removed from Settings' Installed apps.
            (Some("remove"), _) if !tray => removing = true,
            (Some("--folder"), None) => match arguments.next() {
                Some(given) => folder = Some(PathBuf::from(given)),
                None => return ExitCode::from(Exit::Usage as u8),
            },
            _ => return ExitCode::from(Exit::Usage as u8),
        }
    }
    if !desk::interactive() {
        return ExitCode::from(Exit::NoDesktop as u8);
    }
    if removing {
        return ExitCode::from(remove::remove(folder));
    }
    let exit = match folder {
        Some(folder) => {
            let label = folder
                .file_name()
                .map(|name| name.to_string_lossy().into_owned());
            start(&folder, label.as_deref(), tray)
        }
        None => match hedwig_client::folder() {
            Ok(folder) => start(&folder, None, tray),
            Err(_) => Exit::Usage,
        },
    };
    ExitCode::from(exit as u8)
}

#[cfg(test)]
#[path = "../../hedwig-view/tests/common/mod.rs"]
mod common;

/// The loop's own part, at this desktop, against the model's stand-in core:
/// what it shows, when it takes an answer, and what an answer or a row of the
/// menu asks of the core.
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

    use std::time::{Duration, Instant};

    use hedwig_model::capability::{Exposure, Operation};
    use hedwig_model::config::{Activation, Change};
    use hedwig_model::policy::{Keys, Mode, RuleScope, Selector};
    use hedwig_model::protocol::{Decision, Notice, Request, Topic};
    use hedwig_model::remote::{Granted, Remotes};
    use hedwig_model::trail::Missing as Unseen;
    use hedwig_shell::desk;
    use hedwig_shell::host::{Host, Told};
    use hedwig_view::act::Act;
    use hedwig_view::card::Subject;
    use hedwig_view::link::{Event, Place};
    use hedwig_view::menu::Opened;

    use super::common::Bench;
    use super::common::support::{grant, remote, terms};
    use super::{Answered, Surfaces};

    /// A held request to sign from a host whose rule asks first.
    fn held() -> Bench {
        let mut bench = Bench::attached();
        let host = remote("ssh", "build.example");
        bench.feed(Event::Wish(
            Place::Window,
            Request::Change(Change::Grant {
                grant: grant("gpg", Granted::One(host.clone())),
                terms: terms(Activation::OnRequest, Exposure::NONE),
            }),
        ));
        bench.feed(Event::Wish(
            Place::Window,
            Request::Change(Change::Rule {
                scope: RuleScope {
                    remotes: Remotes::Every,
                    capability: Selector::Every,
                    operation: Selector::Only(Operation::Sign),
                    key: Keys::Every,
                },
                mode: Mode::Confirm,
            }),
        ));
        let connection = bench.desk.channel_up(&host, "linux");
        bench.desk.asks(connection, "gpg", Operation::Sign);
        for topic in [Topic::Status, Topic::Exposure, Topic::Attention] {
            bench.notice(Notice::Stale(topic));
        }
        bench
    }

    fn pump(host: &Host, surfaces: &mut Surfaces<'_>, until: Instant) {
        while Instant::now() < until {
            host.told(until.saturating_duration_since(Instant::now()));
            surfaces.tick();
        }
    }

    #[test]
    #[ignore = "needs the desktop's foreground"]
    fn a_held_request_is_carded_armed_after_settling_and_answered() {
        assert!(desk::interactive(), "needs the desktop's foreground");
        let host = Host::new().unwrap();
        let mut bench = held();
        let mut surfaces = Surfaces::new(&host, "hedwig probe".to_owned());
        surfaces.card(bench.link.seen(), None);
        let (_, card) = surfaces.card.as_ref().expect("a card for the held request");
        let Some(Subject::Request(request)) = surfaces.deck.showing().cloned() else {
            unreachable!("the request is what the card shows")
        };
        assert_eq!(card.heading, "build.example (ssh) asks to sign with gpg");

        // No answer is taken before the card has settled.
        assert_eq!(surfaces.answer(0), None);
        let settled = Instant::now() + Duration::from_millis(u64::from(desk::settle()) + 100);
        pump(&host, &mut surfaces, settled);
        assert_eq!(surfaces.arm_at, None, "armed once settled");

        // The same card made again - a setting changed - settles again.
        surfaces.repaint(bench.link.seen(), None);
        assert!(surfaces.arm_at.is_some());
        assert_eq!(surfaces.answer(0), None);
        pump(
            &host,
            &mut surfaces,
            Instant::now() + Duration::from_millis(u64::from(desk::settle()) + 100),
        );

        // The first answer is the usual one, for the request shown.
        let Some(Answered::Send(answer)) = surfaces.answer(0) else {
            unreachable!("taken once settled")
        };
        assert_eq!(
            answer,
            Request::Decide {
                request,
                decision: Decision::Once
            }
        );
        bench.feed(Event::Wish(Place::Card, answer));
        assert_eq!(bench.seen().refused, None);
        surfaces.card(bench.link.seen(), None);
        assert!(surfaces.card.is_none(), "answered, nothing waits");
    }

    /// The icon the taskbar will not show is told by a notice made, raised
    /// and settled as the card is, after the held request it waits behind;
    /// "Open Hedwig" opens the window and the notice goes for good.
    #[test]
    #[ignore = "needs the desktop's foreground"]
    fn an_icon_the_taskbar_will_not_show_is_told_by_a_notice_after_the_card() {
        assert!(desk::interactive(), "needs the desktop's foreground");
        let host = Host::new().unwrap();
        let mut bench = held();
        let mut surfaces = Surfaces::new(&host, "hedwig probe".to_owned());
        surfaces.unseen = Some(Unseen::Refused);
        surfaces.card(bench.link.seen(), None);
        let Some(Subject::Request(request)) = surfaces.deck.showing().cloned() else {
            unreachable!("the held request comes first")
        };
        let settled = || Instant::now() + Duration::from_millis(u64::from(desk::settle()) + 100);
        pump(&host, &mut surfaces, settled());
        let Some(Answered::Send(answer)) = surfaces.answer(0) else {
            unreachable!("the request is answered")
        };
        assert!(matches!(answer, Request::Decide { request: asked, .. } if asked == request));
        bench.feed(Event::Wish(Place::Card, answer));

        surfaces.card(bench.link.seen(), None);
        let (_, card) = surfaces
            .card
            .as_ref()
            .expect("the notice, once nothing waits");
        assert_eq!(card.subject, Subject::Unseen(Unseen::Refused));
        assert_eq!(card.heading, "Windows' taskbar does not show Hedwig's icon");
        assert!(surfaces.raised, "raised as the card is");
        assert_eq!(surfaces.answer(0), None, "not before it has settled");
        pump(&host, &mut surfaces, settled());
        assert_eq!(surfaces.answer(0), Some(Answered::Open));
        assert_eq!(surfaces.unseen, None);
        surfaces.card(bench.link.seen(), None);
        assert!(surfaces.card.is_none(), "closed for good");
    }

    #[test]
    #[ignore = "needs the desktop's foreground"]
    fn a_row_of_the_menu_is_its_act() {
        assert!(desk::interactive(), "needs the desktop's foreground");
        let host = Host::new().unwrap();
        let bench = held();
        let mut surfaces = Surfaces::new(&host, "hedwig probe".to_owned());
        surfaces.openmenu(bench.link.seen(), (400, 400), Opened::Pointer, None);
        assert!(surfaces.menu.is_some() && surfaces.watch.is_some());
        let rows: Vec<String> = surfaces
            .menu
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .map(|entry| format!("{entry:?}"))
            .collect();
        let pause = rows
            .iter()
            .position(|row| row.contains("Pause all exposure"))
            .unwrap();
        let (label, act) = surfaces
            .picked(None, u16::try_from(pause).unwrap())
            .expect("the row's act");
        assert_eq!(label, "Pause all exposure");
        assert_eq!(act, Act::Send(Request::Pause(Remotes::Every)));
        assert!(surfaces.menu.is_none() && surfaces.watch.is_none());
    }

    /// Windows signals a changed setting more often than one changes: a
    /// signal after which the person's appearance reads the same leaves the
    /// menu and the card as they are, and one after which it differs makes
    /// them again, the menu in the place of the open one and never told as
    /// dismissed.
    #[test]
    #[allow(
        clippy::used_underscore_binding,
        reason = "the menu is held for its life; the test reads which window it is"
    )]
    #[ignore = "needs the desktop's foreground"]
    fn a_setting_signalled_but_unchanged_leaves_the_surfaces_as_they_are() {
        assert!(desk::interactive(), "needs the desktop's foreground");
        let host = Host::new().unwrap();
        let bench = held();
        let mut surfaces = Surfaces::new(&host, "hedwig probe".to_owned());
        surfaces.card(bench.link.seen(), None);
        pump(
            &host,
            &mut surfaces,
            Instant::now() + Duration::from_millis(u64::from(desk::settle()) + 100),
        );
        surfaces.openmenu(bench.link.seen(), (400, 400), Opened::Pointer, None);
        let window = |surfaces: &Surfaces<'_>| surfaces.menu.as_ref().unwrap()._menu.window();
        let first = window(&surfaces);
        assert!(surfaces.arm_at.is_none(), "the card has settled");

        surfaces.changed(bench.link.seen(), None);
        assert_eq!(window(&surfaces), first, "the same menu");
        assert!(surfaces.arm_at.is_none(), "the card is not made again");

        // The appearance reads otherwise than when the surfaces were made.
        surfaces.made = None;
        surfaces.changed(bench.link.seen(), None);
        let menu = &surfaces.menu.as_ref().unwrap()._menu;
        assert_ne!(menu.window(), first, "made again");
        assert!(menu.is_open(), "standing in the first one's place");
        assert!(
            surfaces.arm_at.is_some(),
            "the card made again settles again"
        );
        let told = host.told(Duration::from_millis(200));
        assert!(
            !told.iter().any(|told| matches!(told, Told::Dismissed)),
            "{told:?}"
        );
    }

    /// A card made while the desktop takes none is kept off the screen,
    /// with its answers off, and raised once the desktop takes it: settling
    /// from then, and announced to assistive technology once, however often
    /// it is made again.
    #[test]
    #[ignore = "needs the desktop's foreground"]
    fn a_card_is_raised_once_the_desktop_takes_it_and_announced_once() {
        assert!(desk::interactive(), "needs the desktop's foreground");
        let host = Host::new().unwrap();
        let bench = held();
        let mut surfaces = Surfaces::new(&host, "hedwig probe".to_owned());
        surfaces.desk = hedwig_view::card::Desk::Presenting;
        surfaces.card(bench.link.seen(), None);
        assert!(surfaces.card.is_some(), "made");
        assert!(!surfaces.raised && surfaces.arm_at.is_none() && surfaces.announced.is_none());
        pump(
            &host,
            &mut surfaces,
            Instant::now() + Duration::from_millis(u64::from(desk::settle()) + 100),
        );
        assert_eq!(
            surfaces.answer(0),
            None,
            "no answer from a card nobody sees"
        );

        surfaces.desk = hedwig_view::card::Desk::Open;
        surfaces.card(bench.link.seen(), None);
        assert!(surfaces.raised && surfaces.arm_at.is_some());
        let showing = surfaces.deck.showing().cloned();
        assert_eq!(surfaces.announced, showing);
        assert_eq!(surfaces.answer(0), None, "settling from when it was raised");

        // Made again on a changed setting: raised again, its subject already
        // announced.
        surfaces.repaint(bench.link.seen(), None);
        assert!(surfaces.raised);
        assert_eq!(surfaces.announced, showing);
    }

    /// Stopping Hedwig from the menu is asked first, by a dialog that leaves
    /// the loop running: the held request is carded while it is asked, and
    /// the answer decides whether the act is carried out.
    #[test]
    #[ignore = "needs the desktop's foreground"]
    fn a_confirmation_is_asked_while_the_loop_goes_on() {
        assert!(desk::interactive(), "needs the desktop's foreground");
        let host = Host::new().unwrap();
        let bench = held();
        let mut surfaces = Surfaces::new(&host, "hedwig probe".to_owned());
        let ask = |surfaces: &mut Surfaces<'_>| {
            surfaces.openmenu(bench.link.seen(), (400, 400), Opened::Pointer, None);
            let stop = surfaces
                .menu
                .as_ref()
                .unwrap()
                .entries
                .iter()
                .position(|entry| format!("{entry:?}").contains("Stop Hedwig..."))
                .unwrap();
            let (label, act) = surfaces
                .picked(None, u16::try_from(stop).unwrap())
                .expect("the row's act");
            let Act::Stop { consequence } = &act else {
                unreachable!("{act:?}")
            };
            let consequence = consequence.clone();
            surfaces.ask(label.trim_end_matches("..."), &consequence, act, None);
            consequence
        };

        ask(&mut surfaces);
        assert!(surfaces.asking.is_some() && surfaces.watch.is_some());
        // The loop goes on: what the core holds is carded meanwhile.
        surfaces.card(bench.link.seen(), None);
        assert!(
            surfaces.card.is_some(),
            "carded while the confirmation is asked"
        );
        assert!(surfaces.asking.is_some());
        // "Cancel": nothing is done, and the card stays.
        assert_eq!(surfaces.confirmed(false), None);
        assert!(surfaces.asking.is_none() && surfaces.card.is_some());

        // Asked again, and remade where it stands when a setting changes.
        let consequence = ask(&mut surfaces);
        surfaces.repaint(bench.link.seen(), None);
        assert!(surfaces.asking.is_some());
        assert_eq!(surfaces.confirmed(true), Some(Act::Stop { consequence }));
        assert!(
            surfaces.asking.is_none() && surfaces.watch.is_some(),
            "the card is still up"
        );
        surfaces.card = None;
        surfaces.painted();
        assert!(surfaces.watch.is_none());
    }
}
