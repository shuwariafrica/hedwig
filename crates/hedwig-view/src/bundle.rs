//! What a supporter is given, as the person sees it before it is saved: the
//! core's one document (`Request::Bundle`), each part said with how much of
//! it there is and what in it names the person, and the file it is saved as.
//!
//! Nothing leaves the workstation by Hedwig's hand: the person saves the file
//! where they choose and sends it themselves.

use std::collections::BTreeSet;

use hedwig_model::protocol::Bundle;
use hedwig_model::wire::page;

use crate::trial::Dialog;

/// Where the bundle is saved.
pub const SAVE: Dialog = Dialog {
    title: "Save what Hedwig knows, for a supporter",
    name: "hedwig-support.json",
    kinds: &[
        ("Hedwig support bundle (*.json)", "*.json"),
        ("All files (*.*)", "*.*"),
    ],
    extension: "json",
};

/// The heading the bundle is shown under.
pub const HEADING: &str = "What a supporter receives";

fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// Each part of `bundle`, a line each, in the order it is in the file; then
/// what in it names the person, and what it never holds.
pub fn contents(bundle: &Bundle) -> Vec<String> {
    let mut lines = vec![format!(
        "Hedwig {} ({}), running from {}, on Windows {}.",
        bundle.version, bundle.commit, bundle.program, bundle.windows
    )];
    let remotes: BTreeSet<String> = bundle
        .exposure
        .iter()
        .filter_map(|row| row.remote.as_ref().map(ToString::to_string))
        .collect();
    lines.push(if remotes.is_empty() {
        "What is reachable: nothing is granted.".to_owned()
    } else {
        format!(
            "What is reachable, line by line, from {}: {}.",
            plural(remotes.len(), "remote", "remotes"),
            remotes.into_iter().collect::<Vec<_>>().join(", ")
        )
    });
    lines.push(format!(
        "What needs you: {}.",
        plural(bundle.attention.len(), "item", "items")
    ));
    lines.push(
        "Every setting, with the statement it comes from and what your organisation states."
            .to_owned(),
    );
    lines.push(format!(
        "What happened: the newest {}.",
        plural(bundle.activity.len(), "entry", "entries")
    ));
    lines.push(format!(
        "What Hedwig wrote down about what went wrong: {}.",
        plural(bundle.diagnostics.len(), "line", "lines")
    ));
    lines.push(if bundle.set_aside.is_empty() {
        "No file was set aside.".to_owned()
    } else {
        format!(
            "Files set aside because they could not be read: {}.",
            bundle
                .set_aside
                .iter()
                .map(|aside| format!("{} ({} bytes)", aside.name, aside.bytes))
                .collect::<Vec<_>>()
                .join(", ")
        )
    });
    lines.push(
        "It names your remotes, your keys by fingerprint, your account and the folders Hedwig \
         runs from. It holds no passphrase, answer, PIN or key."
            .to_owned(),
    );
    lines
}

/// The file's text: the bundle as the core's written form writes a page.
pub fn written(bundle: &Bundle) -> String {
    let mut text = page(bundle);
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}
