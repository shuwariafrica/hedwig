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
//! was taken back, 7 where something was left.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use hedwig_client::install::{Place, finish, removed_status, withdraw};
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

/// Starts Hedwig where it does not run, and greets it as the interface.
fn session(place: &Place, data: &Path) -> Result<Session, String> {
    if !matches!(
        look(data).map_err(|error| error.to_string())?,
        Standing::Known(_)
    ) {
        let program = place.program.join(Starts::Hedwig.program());
        launch(&program, &role(place, "supervise")).map_err(|error| error.to_string())?;
    }
    let Standing::Known(running) = look(data).map_err(|error| error.to_string())? else {
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

/// Starts Hedwig where it does not run, and asks it.
fn ask_core(place: &Place, data: &Path) -> Result<Asked, String> {
    let mut session = session(place, data)?;
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

/// Keeps the Hedwig a removal stopped after taking back: started again where
/// `finish` stopped it, and its removal ended.
fn keep(place: &Place, data: &Path) -> Result<(), String> {
    match session(place, data)?.ask(Request::Restore) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(refusal)) => Err(refusal.to_string()),
        Err(error) => Err(error.to_string()),
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
fn chosen<'a>(question: &mut Question, card: &'a Card) -> Option<&'a Does> {
    question
        .ask(card)
        .ok()
        .flatten()
        .and_then(|place| card.choices.get(place))
        .map(|choice| &choice.does)
}

/// Writes the person's settings where they choose, as the window exports
/// them; where they were written, or `None` where nothing was.
fn save(question: &Question, document: &Document) -> Option<String> {
    let words = trial::EXPORT;
    let dialog = Dialog {
        purpose: Purpose::Write,
        title: words.title,
        name: words.name,
        kinds: words.kinds,
        extension: words.extension,
    };
    let path = question.choose(&dialog).ok().flatten()?;
    std::fs::write(&path, trial::written(document)).ok()?;
    Some(path.display().to_string())
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
    let asked = {
        let (place, data) = (place.clone(), data.clone());
        question.during(&removal::asking(), move || ask_core(&place, &data))
    };
    let withdrawn = match asked {
        Ok(Ok(asked)) => {
            let mut saved = None;
            loop {
                let card =
                    removal::before(&asked.written, asked.document.is_some(), saved.as_deref());
                match chosen(&mut question, &card) {
                    Some(Does::Save) => {
                        if let Some(document) = &asked.document {
                            saved = save(&question, document).or(saved);
                        }
                    }
                    Some(Does::Proceed) => break,
                    _ => return CANCELLED,
                }
            }
            // A remote that needs the person while it is taken back asks
            // through the icon: started here where it is not running, and
            // ending at once where it is.
            let icon = place.program.join(Starts::Icon.program());
            let _ = hedwig_client::detach(&icon, &role(&place, "tray"));
            let working = place.clone();
            match question.during(&removal::taking_back(&asked.written), move || {
                withdraw(&working, ClientKind::Interface)
            }) {
                Ok(Ok(removed)) => removed.left,
                Ok(Err(error)) => {
                    let card = removal::unasked(&error.to_string());
                    if !matches!(chosen(&mut question, &card), Some(Does::Proceed)) {
                        return CANCELLED;
                    }
                    Vec::new()
                }
                Err(_) => return Exit::Usage.status(),
            }
        }
        Ok(Err(why)) => {
            let card = removal::unasked(&why);
            if !matches!(chosen(&mut question, &card), Some(Does::Proceed)) {
                return CANCELLED;
            }
            Vec::new()
        }
        Err(_) => return Exit::Usage.status(),
    };
    // Why `finish` last failed, with the status removal ends with for it.
    let mut failed: Option<(String, u8)> = None;
    let aside = loop {
        if let Some((why, status)) = failed.take() {
            let card = removal::not_removed(&why, true);
            match chosen(&mut question, &card) {
                Some(Does::Proceed) => {}
                // The person keeps Hedwig rather than finish now: nothing is
                // removed, as when they cancel.
                Some(Does::Send(Request::Restore)) => {
                    let (place, data) = (place.clone(), data.clone());
                    match question.during(&removal::keeping(), move || keep(&place, &data)) {
                        Ok(Ok(())) => return CANCELLED,
                        Ok(Err(why)) => {
                            failed = Some((why, status));
                            continue;
                        }
                        Err(_) => return Exit::Usage.status(),
                    }
                }
                _ => return status,
            }
        }
        let working = place.clone();
        match question.during(&removal::removing(), move || finish(&working)) {
            Ok(Ok(aside)) => break aside,
            Ok(Err(error)) => failed = Some((error.to_string(), error.status())),
            Err(_) => return Exit::Usage.status(),
        }
    };
    let left = hedwig_client::install::Removed { left: withdrawn };
    let named = aside
        .file_name()
        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
    let card = removal::removed(&left.left, &named);
    while let Some(Does::Copy) = chosen(&mut question, &card) {
        let _ = question.copy(&removal::left_text(&left.left));
    }
    removed_status(&left).status()
}
