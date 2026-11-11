//! `hedwig-interface.exe remove`: Hedwig removed from Settings' Installed
//! apps, which runs the entry's command.
//!
//! The removal is `hedwig_client::install`'s, the one a deployer's quiet
//! removal runs too; this is its surface. It asks the core what Hedwig wrote
//! on each remote and reads the person's settings, offers to save them, and
//! goes on only when the person says to: Hedwig's icon is started where it
//! is not running, so a remote that asks for something while it is taken
//! back asks the person there; then what Hedwig wrote is taken back, Hedwig
//! removes itself, and what is left on a remote it could not reach is said
//! and can be copied. Its status is the quiet removal's: 0 where everything
//! was taken back, 7 where something was left or Hedwig could not be asked
//! what it wrote.

use std::ffi::OsString;
use std::path::PathBuf;

use hedwig_client::install::{Place, Removed, SetupError, finish, removed_status, withdraw};
use hedwig_client::{Session, Standing, launch, look};
use hedwig_model::config::Document;
use hedwig_model::install::Starts;
use hedwig_model::process::{CoreState, Exit};
use hedwig_model::protocol::{Reply, Request, Withdrawal};
use hedwig_model::trail::ClientKind;
use hedwig_shell::pick::{Dialog, Purpose};
use hedwig_shell::question::Question;
use hedwig_view::card::{Card, Does};
use hedwig_view::{removal, trial};

/// The status where the person cancelled.
const CANCELLED: u8 = 20;

/// What the core said before anything was taken: what Hedwig wrote on each
/// remote, and the person's settings.
struct Asked {
    written: Vec<Withdrawal>,
    document: Option<Document>,
}

/// What is known, once taking back is over, of what Hedwig left on the
/// remotes.
enum Left {
    /// What is left on each remote.
    Known(Vec<Withdrawal>),
    /// Hedwig could not be asked what it wrote, so nothing was taken back.
    Unasked,
}

/// What removal puts to the person, apart from the steps it takes, so its
/// course can be followed with nobody at the desktop.
trait Person {
    /// The place of the answer to `card` that goes ahead, or `None` for the
    /// safe one.
    fn ask(&mut self, card: &Card) -> Option<usize>;

    /// What `work` returned, run while `card` is shown; `None` where the
    /// card could not be shown.
    fn during<T: Send + 'static>(
        &mut self,
        card: &Card,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T>;

    /// Where `document` was saved, or `None` where nothing was.
    fn save(&mut self, document: &Document) -> Option<String>;

    fn copy(&mut self, text: &str);
}

impl Person for Question {
    fn ask(&mut self, card: &Card) -> Option<usize> {
        Question::ask(self, card).ok().flatten()
    }

    fn during<T: Send + 'static>(
        &mut self,
        card: &Card,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        Question::during(self, card, work).ok()
    }

    /// Writes the person's settings where they choose, as the window exports
    /// them.
    fn save(&mut self, document: &Document) -> Option<String> {
        let words = trial::EXPORT;
        let dialog = Dialog {
            purpose: Purpose::Write,
            title: words.title,
            name: words.name,
            kinds: words.kinds,
            extension: words.extension,
        };
        let path = self.choose(&dialog).ok().flatten()?;
        std::fs::write(&path, trial::written(document)).ok()?;
        Some(path.display().to_string())
    }

    fn copy(&mut self, text: &str) {
        let _ = Question::copy(self, text);
    }
}

/// What removal does to the core, the remotes and the workstation. Each step
/// runs on a thread of its own while a card is shown.
trait Steps: Clone + Send + 'static {
    /// Starts Hedwig where it does not run, and asks it.
    fn ask(&self) -> Result<Asked, String>;

    /// Starts Hedwig's icon where it does not run, so a remote that needs
    /// the person while it is taken back asks there.
    fn start_icon(&self);

    fn withdraw(&self) -> Result<Removed, SetupError>;

    /// Where the program that removed Hedwig was set aside.
    fn finish(&self) -> Result<PathBuf, SetupError>;

    /// Keeps the Hedwig a removal stopped after taking back: started again
    /// where `finish` stopped it, and its removal ended.
    fn keep(&self) -> Result<(), String>;
}

/// The installation removed, and the folder its Hedwig keeps its files in.
#[derive(Clone)]
struct Installed {
    place: Place,
    data: PathBuf,
}

impl Installed {
    /// Starts Hedwig where it does not run, and greets it as the interface.
    fn session(&self) -> Result<Session, String> {
        if !matches!(
            look(&self.data).map_err(|error| error.to_string())?,
            Standing::Known(_)
        ) {
            let program = self.place.program.join(Starts::Hedwig.program());
            launch(&program, &role(&self.place, "supervise")).map_err(|error| error.to_string())?;
        }
        let Standing::Known(running) = look(&self.data).map_err(|error| error.to_string())? else {
            return Err("Hedwig did not start".to_owned());
        };
        let CoreState::Serving { pipe, .. } = running.core else {
            return Err("Hedwig did not start".to_owned());
        };
        let mut session = Session::open(&pipe).map_err(|error| error.to_string())?;
        session
            .greet(ClientKind::Interface)
            .map_err(|error| error.to_string())?
            .map_err(|refusal| refusal.to_string())?;
        Ok(session)
    }
}

impl Steps for Installed {
    fn ask(&self) -> Result<Asked, String> {
        let mut session = self.session()?;
        let written = match session.ask(Request::Withdrawal) {
            Ok(Ok(Reply::Withdrawal(written))) => written,
            Ok(Ok(other)) => return Err(format!("Hedwig answered {other:?}")),
            Ok(Err(refusal)) => return Err(refusal.to_string()),
            Err(error) => return Err(error.to_string()),
        };
        let document = match session.ask(Request::Export) {
            Ok(Ok(Reply::Document(document))) => Some(*document),
            _ => None,
        };
        Ok(Asked { written, document })
    }

    fn start_icon(&self) {
        // Ending at once where the icon is already running.
        let icon = self.place.program.join(Starts::Icon.program());
        let _ = hedwig_client::detach(&icon, &role(&self.place, "tray"));
    }

    fn withdraw(&self) -> Result<Removed, SetupError> {
        withdraw(&self.place, ClientKind::Interface)
    }

    fn finish(&self) -> Result<PathBuf, SetupError> {
        finish(&self.place)
    }

    fn keep(&self) -> Result<(), String> {
        match self.session()?.ask(Request::Restore) {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(refusal)) => Err(refusal.to_string()),
            Err(error) => Err(error.to_string()),
        }
    }
}

fn role(place: &Place, role: &str) -> Vec<OsString> {
    let mut arguments = vec![OsString::from(role)];
    if let Some(data) = &place.data {
        arguments.push("--folder".into());
        arguments.push(data.clone().into_os_string());
    }
    arguments
}

/// The answer the person chose on `card`, or `None` for the safe one.
fn chosen<'a>(person: &mut impl Person, card: &'a Card) -> Option<&'a Does> {
    person
        .ask(card)
        .and_then(|place| card.choices.get(place))
        .map(|choice| &choice.does)
}

/// Runs the removal of the Hedwig whose files are in `folder`, or the
/// person's own; the status it ends with.
pub(crate) fn remove(folder: Option<PathBuf>) -> u8 {
    let Ok(mut question) = Question::new("Remove Hedwig") else {
        return Exit::Usage.status();
    };
    let place = match Place::resolve(folder.clone()) {
        Ok(place) => place,
        Err(error) => {
            let _ = question.ask(&removal::not_removed(&error.to_string(), false));
            return Exit::Storage.status();
        }
    };
    let data = match folder.map_or_else(hedwig_client::folder, Ok) {
        Ok(data) => data,
        Err(error) => {
            let _ = question.ask(&removal::not_removed(&error.to_string(), false));
            return Exit::Storage.status();
        }
    };
    removing(&mut question, &Installed { place, data })
}

/// The removal's course, from asking the core to the last card; the status
/// it ends with.
fn removing(person: &mut impl Person, steps: &impl Steps) -> u8 {
    let asking = steps.clone();
    let withdrawn = match person.during(&removal::asking(), move || asking.ask()) {
        Some(Ok(asked)) => {
            let mut saved = None;
            loop {
                let card =
                    removal::before(&asked.written, asked.document.is_some(), saved.as_deref());
                match chosen(person, &card) {
                    Some(Does::Save) => {
                        if let Some(document) = &asked.document {
                            saved = person.save(document).or(saved);
                        }
                    }
                    Some(Does::Proceed) => break,
                    _ => return CANCELLED,
                }
            }
            steps.start_icon();
            let working = steps.clone();
            match person.during(&removal::taking_back(&asked.written), move || {
                working.withdraw()
            }) {
                Some(Ok(removed)) => Left::Known(removed.left),
                Some(Err(error)) => {
                    let card = removal::unasked(&error.to_string());
                    if !matches!(chosen(person, &card), Some(Does::Proceed)) {
                        return CANCELLED;
                    }
                    Left::Known(asked.written)
                }
                None => return Exit::Usage.status(),
            }
        }
        Some(Err(why)) => {
            let card = removal::unasked(&why);
            if !matches!(chosen(person, &card), Some(Does::Proceed)) {
                return CANCELLED;
            }
            Left::Unasked
        }
        None => return Exit::Usage.status(),
    };
    // Why `finish` last failed, with the status removal ends with for it.
    let mut failed: Option<(String, u8)> = None;
    let aside = loop {
        if let Some((why, status)) = failed.take() {
            let card = removal::not_removed(&why, true);
            match chosen(person, &card) {
                Some(Does::Proceed) => {}
                // The person keeps Hedwig rather than finish now: nothing is
                // removed, as when they cancel.
                Some(Does::Send(Request::Restore)) => {
                    let keeping = steps.clone();
                    match person.during(&removal::keeping(), move || keeping.keep()) {
                        Some(Ok(())) => return CANCELLED,
                        Some(Err(why)) => {
                            failed = Some((why, status));
                            continue;
                        }
                        None => return Exit::Usage.status(),
                    }
                }
                _ => return status,
            }
        }
        let finishing = steps.clone();
        match person.during(&removal::removing(), move || finishing.finish()) {
            Some(Ok(aside)) => break aside,
            Some(Err(error)) => failed = Some((error.to_string(), error.status())),
            None => return Exit::Usage.status(),
        }
    };
    let named = aside
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    match withdrawn {
        Left::Known(left) => {
            let card = removal::removed(&left, &named);
            while let Some(Does::Copy) = chosen(person, &card) {
                person.copy(&removal::left_text(&left));
            }
            removed_status(&Removed { left }).status()
        }
        Left::Unasked => {
            person.ask(&removal::removed_unasked(&named));
            Exit::Unreached.status()
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "tests")]
mod tests {
    use std::collections::VecDeque;

    use hedwig_model::protocol::Written;
    use hedwig_model::remote::RemoteId;
    use hedwig_model::text::{Address, Name, RemotePath};
    use hedwig_model::trail::Write;

    use super::*;

    /// A person who answers each card by the label of the answer they choose,
    /// in turn, and with the safe answer once their answers run out; and the
    /// heading and facts of each card they were shown.
    struct Scripted {
        answers: VecDeque<&'static str>,
        shown: Vec<(String, Vec<(&'static str, String)>)>,
        copied: Vec<String>,
    }

    impl Scripted {
        fn new(answers: &[&'static str]) -> Scripted {
            Scripted {
                answers: answers.iter().copied().collect(),
                shown: Vec::new(),
                copied: Vec::new(),
            }
        }

        fn last(&self) -> &(String, Vec<(&'static str, String)>) {
            self.shown.last().expect("a card was shown")
        }
    }

    impl Person for Scripted {
        fn ask(&mut self, card: &Card) -> Option<usize> {
            self.shown.push((card.heading.clone(), card.facts.clone()));
            let label = self.answers.pop_front()?;
            let place = card.choices.iter().position(|choice| choice.label == label);
            assert!(place.is_some(), "{:?} offers no {label:?}", card.heading);
            place
        }

        fn during<T: Send + 'static>(
            &mut self,
            card: &Card,
            work: impl FnOnce() -> T + Send + 'static,
        ) -> Option<T> {
            self.shown.push((card.heading.clone(), card.facts.clone()));
            Some(work())
        }

        fn save(&mut self, _: &Document) -> Option<String> {
            None
        }

        fn copy(&mut self, text: &str) {
            self.copied.push(text.to_owned());
        }
    }

    /// An installation whose core, where it can be asked, says Hedwig wrote
    /// `no-autostart` on one remote, and which removes itself at the end.
    #[derive(Clone, Copy)]
    enum Installation {
        /// The core cannot be asked what Hedwig wrote.
        Unasked,
        /// Taking back cannot reach the remote.
        Unreached,
        /// Taking back reaches the remote.
        Reached,
    }

    fn written() -> Vec<Withdrawal> {
        vec![Withdrawal {
            remote: RemoteId {
                route: Name::try_from("ssh").expect("a name"),
                address: Address::try_from("dev@build-7.example").expect("an address"),
            },
            left: vec![Written {
                write: Write::NoAutostart,
                place: RemotePath::try_from("/home/dev/.gnupg/common.conf").expect("a path"),
                made: None,
            }],
            surveying: false,
            ended: None,
        }]
    }

    impl Steps for Installation {
        fn ask(&self) -> Result<Asked, String> {
            if let Installation::Unasked = self {
                return Err("the Hedwig placed did not answer: no record".to_owned());
            }
            Ok(Asked {
                written: written(),
                document: None,
            })
        }

        fn start_icon(&self) {}

        fn withdraw(&self) -> Result<Removed, SetupError> {
            if let Installation::Unreached = self {
                return Err(SetupError::Unanswered(
                    "the remote needs an answer Hedwig could not ask".to_owned(),
                ));
            }
            let mut left = written();
            for remote in &mut left {
                remote.left.clear();
            }
            Ok(Removed { left })
        }

        fn finish(&self) -> Result<PathBuf, SetupError> {
            Ok(PathBuf::from("hedwig-removed-4120.exe"))
        }

        fn keep(&self) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn a_removal_whose_taking_back_failed_names_what_is_left_and_ends_with_7() {
        let mut person = Scripted::new(&["Remove Hedwig", "Remove anyway", "Copy what is left"]);

        let status = removing(&mut person, &Installation::Unreached);

        assert_eq!(status, Exit::Unreached.status());
        let (heading, facts) = person.last();
        assert_eq!(
            heading,
            "Hedwig is removed, and some remotes still hold what it wrote"
        );
        assert_eq!(
            facts,
            &[(
                "Left on",
                "dev@build-7.example (ssh): no-autostart in /home/dev/.gnupg/common.conf; \
                 not taken back: Hedwig could not connect to it"
                    .to_owned()
            )]
        );
        assert_eq!(
            person.copied,
            ["dev@build-7.example (ssh)\n  no-autostart in /home/dev/.gnupg/common.conf\n"]
        );
    }

    #[test]
    fn a_removal_that_took_everything_back_says_so_and_ends_with_0() {
        let mut person = Scripted::new(&["Remove Hedwig"]);

        let status = removing(&mut person, &Installation::Reached);

        assert_eq!(status, Exit::Stopped.status());
        let (heading, facts) = person.last();
        assert_eq!(heading, "Hedwig is removed");
        assert!(facts.is_empty(), "{facts:?}");
        assert!(person.copied.is_empty(), "{:?}", person.copied);
    }

    #[test]
    fn a_removal_that_could_not_ask_what_was_written_says_nothing_was_taken_back_and_ends_with_7() {
        let mut person = Scripted::new(&["Remove anyway"]);

        let status = removing(&mut person, &Installation::Unasked);

        let (heading, facts) = person.last();
        assert_eq!(
            heading,
            "Hedwig is removed, and nothing on your remotes was taken back"
        );
        assert!(facts.is_empty(), "{facts:?}");
        assert_eq!(status, Exit::Unreached.status());
    }
}
