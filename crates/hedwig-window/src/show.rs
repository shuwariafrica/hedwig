//! What the window draws, from `hedwig_view` and nothing else, in WinUI's
//! own controls at WinUI's type ramp: a title 28, a subtitle 20 and body
//! text 14 in the person's theme, set by WinUI.
//!
//! The window is one page organised around grants: what needs the person,
//! each remote with the grants it reaches and, behind a disclosure, that
//! remote's settings, then this workstation's settings with export and
//! import. First run is the same page with nothing granted yet.

use windows_reactor::{
    AutomationExt, AutomationHeadingLevel, Border, Button, CheckBox, ChildrenControl, ComboBox,
    ContentControl, ContentDialog, CornerRadius, Expander, ExpanderSlot, FontWeight, Grid,
    GridChildExt, GridLength, HorizontalAlignment, InfoBar, InfoBarSeverity, KeyedView,
    LayoutControl, Orientation, ProgressRing, RadioButtons, ScrollViewer, SlotView, SlotsControl,
    StackPanel, TextBlock, TextBox, TextWrapping, ThemeBrush, Thickness, ToggleSwitch, View,
    ViewContext, WindowBackdrop, WindowVisuals,
};

use hedwig_model::protocol::Request;
use hedwig_model::remote::RemoteId;
use hedwig_model::text::{Name, SshKey};
use hedwig_view::act::Act;
use hedwig_view::define;
use hedwig_view::exposure::{
    self, Board, First, Group, KeyLine, Keying, Lending, Line, Need, Policy, Shown,
};
use hedwig_view::grant::{self, Aim, Form};
use hedwig_view::setting::{Choice, Entry, Place, Section, Setting, Sheet, Wide};
use hedwig_view::trial::Outcome;
use hedwig_view::words;

use crate::window::{Asking, At, Edit, Gathering, Message, Window, hosts_key, key};

type Context = ViewContext<Window>;

/// The header of this workstation's disclosure, which a definition begun
/// from elsewhere opens.
pub(crate) const WORKSTATION: &str = "This workstation: settings, export and import";

/// What a remote's activity disclosure is headed with.
const ACTIVITY: &str = "What happened on ";

/// The remote, by its heading, whose activity a disclosure's header names.
pub(crate) fn reviewed(header: &str) -> Option<&str> {
    header.strip_prefix(ACTIVITY)
}

fn text(words: impl Into<String>) -> TextBlock {
    TextBlock::new()
        .text(words)
        .text_wrapping(TextWrapping::Wrap)
}

fn caption(words: impl Into<String>) -> View {
    text(words).font_size(12.0).opacity(0.7).into()
}

fn title(words: &str) -> View {
    text(words)
        .font_size(28.0)
        .font_weight(FontWeight::SEMI_BOLD)
        .automation_heading_level(AutomationHeadingLevel::Level1)
        .into()
}

fn subtitle(words: &str) -> View {
    text(words)
        .font_size(20.0)
        .font_weight(FontWeight::SEMI_BOLD)
        .automation_heading_level(AutomationHeadingLevel::Level2)
        .into()
}

fn strong(words: &str) -> View {
    text(words).font_weight(FontWeight::SEMI_BOLD).into()
}

fn column(spacing: f64, items: Vec<(String, View)>) -> View {
    StackPanel::new().spacing(spacing).keyed_children(
        items
            .into_iter()
            .map(|(key, view)| KeyedView::new(key, view)),
    )
}

fn row(items: Vec<(String, View)>) -> View {
    StackPanel::new()
        .orientation(Orientation::Horizontal)
        .spacing(8.0)
        .keyed_children(
            items
                .into_iter()
                .map(|(key, view)| KeyedView::new(key, view)),
        )
}

/// A card: WinUI's card fill and stroke, its control corner and 16 inside.
fn card(content: View) -> View {
    Border::new()
        .background(ThemeBrush::CardBackground)
        .border_brush(ThemeBrush::CardStroke)
        .border_thickness(Thickness::uniform(1.0))
        .corner_radius(CornerRadius::uniform(4.0))
        .padding(Thickness::uniform(16.0))
        .content(content)
}

fn button(label: &str, message: impl Fn() -> Message + 'static, context: &Context) -> View {
    Button::new()
        .on_click(context.callback(move |()| message()))
        .content(label.to_owned())
}

/// Each act as a button, in equal columns whose labels wrap, so nothing is
/// cut at any width or text size; one the core would refuse is the words why,
/// beneath.
fn answers<'a>(
    shown: impl IntoIterator<Item = &'a Shown>,
    at: impl Fn(&str) -> At,
    context: &Context,
) -> View {
    let shown: Vec<&Shown> = shown.into_iter().collect();
    let offered: Vec<&str> = shown
        .iter()
        .filter_map(|act| match act {
            Shown::Offered { label, .. } => Some(label.as_str()),
            Shown::Withheld { .. } => None,
        })
        .collect();
    let mut items = Vec::new();
    if let [label] = offered.as_slice() {
        let at = at(label);
        items.push((
            "offered".to_owned(),
            button(label, move || Message::Chose(at.clone()), context),
        ));
    } else if !offered.is_empty() {
        let buttons: Vec<KeyedView> = offered
            .iter()
            .zip(0..)
            .map(|(label, place)| {
                let at = at(label);
                KeyedView::new(
                    (*label).to_owned(),
                    Button::new()
                        .grid_column(place)
                        .horizontal_alignment(HorizontalAlignment::Stretch)
                        .on_click(context.callback(move |()| Message::Chose(at.clone())))
                        .content(text(*label)),
                )
            })
            .collect();
        items.push((
            "offered".to_owned(),
            Grid::new()
                .columns(offered.iter().map(|_| GridLength::STAR))
                .column_spacing(8.0)
                .keyed_children(buttons),
        ));
    }
    for act in shown {
        if let Shown::Withheld { label, why } = act {
            items.push((label.clone(), caption(format!("{label}: not now - {why}"))));
        }
    }
    column(4.0, items)
}

/// Whether an act puts away what needs the person: the bar's own close
/// button, as WinUI puts a bar away.
fn puts_away(act: &Shown) -> bool {
    matches!(
        act,
        Shown::Offered {
            act: Act::Send(Request::PutAway(_)),
            ..
        }
    )
}

fn need(need: &Need, context: &Context) -> View {
    let sentence = need.sentence.clone();
    let at = |label: &str| At::Need {
        sentence: sentence.clone(),
        label: label.to_owned(),
    };
    let buttons = answers(need.acts.iter().filter(|act| !puts_away(act)), at, context);
    let away = need.acts.iter().find_map(|act| match act {
        Shown::Offered { label, .. } if puts_away(act) => Some(at(label)),
        _ => None,
    });
    let bar = InfoBar::new()
        .is_open(true)
        .is_closable(away.is_some())
        .severity(InfoBarSeverity::Warning)
        .message(need.sentence.clone());
    let bar = match away {
        Some(away) => bar.on_closed(context.callback(move |()| Message::Chose(away.clone()))),
        None => bar,
    };
    column(
        4.0,
        vec![("bar".to_owned(), bar.into()), ("acts".to_owned(), buttons)],
    )
}

/// Where a policy's chosen key is kept.
pub(crate) fn policy_key(line: &Line, policy: &Policy) -> String {
    format!(
        "{}/{}/{}",
        line.remote
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default(),
        line.capability,
        policy.when
    )
}

/// Giving one key its own rule: the keys a statement can name that none
/// does yet, chosen from a list, then that key's rules.
fn key_rules(window: &Window, line: &Line, policy: &Policy, context: &Context) -> View {
    let kept = policy_key(line, policy);
    let chosen = window
        .keyed
        .get(&kept)
        .copied()
        .filter(|at| *at < policy.keys.len());
    let owned = kept.clone();
    let mut items = vec![(
        "choose".to_owned(),
        ComboBox::new()
            .items_source(policy.keys.iter().map(|rule| rule.key.clone()))
            .selected_index(chosen)
            .placeholder_text("Give one key its own rule")
            .automation_name("Give one key its own rule")
            .on_selection_changed(context.callback(move |at: Option<usize>| {
                at.map_or(Message::Nothing, |at| Message::KeyChosen {
                    policy: owned.clone(),
                    at,
                })
            }))
            .into(),
    )];
    if let Some(rule) = chosen.and_then(|at| policy.keys.get(at)) {
        let (remote, capability, when, key) = (
            line.remote.clone(),
            line.capability.clone(),
            policy.when.clone(),
            rule.key.clone(),
        );
        items.push((
            "rules".to_owned(),
            answers(
                &rule.changes,
                |label| At::KeyRule {
                    remote: remote.clone(),
                    capability: capability.clone(),
                    when: when.clone(),
                    key: key.clone(),
                    label: label.to_owned(),
                },
                context,
            ),
        ));
    }
    column(4.0, items)
}

fn policy(window: &Window, line: &Line, policy: &Policy, context: &Context) -> View {
    let (remote, capability, when) = (
        line.remote.clone(),
        line.capability.clone(),
        policy.when.clone(),
    );
    let changes = answers(
        &policy.changes,
        |label| At::Policy {
            remote: remote.clone(),
            capability: capability.clone(),
            when: when.clone(),
            label: label.to_owned(),
        },
        context,
    );
    column(
        4.0,
        vec![
            (
                "mode".to_owned(),
                text(format!("{}: {}", capitalised(&policy.when), policy.now)).into(),
            ),
            (
                "because".to_owned(),
                caption(format!("Because of {}", policy.because)),
            ),
            ("changes".to_owned(), changes),
            (
                "keys".to_owned(),
                if policy.keys.is_empty() {
                    column(0.0, Vec::new())
                } else {
                    key_rules(window, line, policy, context)
                },
            ),
        ],
    )
}

fn capitalised(words: &str) -> String {
    let mut chars = words.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn line(window: &Window, line: &Line, context: &Context) -> View {
    let mut items = vec![
        (
            "name".to_owned(),
            strong(&format!("{}: {}", line.capability, line.state)),
        ),
        (
            "exposes".to_owned(),
            text(format!("Lets it {}", line.exposes)).into(),
        ),
        ("through".to_owned(), caption(capitalised(&line.through))),
    ];
    for (at, answers) in line.answers.iter().enumerate() {
        items.push((format!("answers{at}"), text(answers.clone()).into()));
    }
    if let Some(opened_at) = &line.opened_at {
        items.push((
            "opened-at".to_owned(),
            caption(format!("{}.", capitalised(opened_at))),
        ));
    }
    if let Some(hold) = &line.hold {
        items.push(("port-held".to_owned(), text(format!("{hold}.")).into()));
    }
    for (at, beyond) in line.beyond.iter().enumerate() {
        items.push((format!("beyond{at}"), text(beyond.clone()).into()));
    }
    if let Some(last) = &line.last {
        items.push(("last".to_owned(), caption(format!("Last: {last}"))));
    }
    for (at, holding) in line.holds.iter().enumerate() {
        items.push((format!("hold{at}"), caption(format!("Held: {holding}"))));
    }
    for (at, caution) in line.cautions.iter().enumerate() {
        items.push((
            format!("caution{at}"),
            text(format!("Also: {caution}")).into(),
        ));
    }
    for (at, turned) in line.turned.iter().enumerate() {
        let sentence = words::begun(turned.clone(), &line.capability);
        items.push((format!("turned{at}"), text(format!("{sentence}.")).into()));
    }
    for (at, written) in line.written.iter().enumerate() {
        items.push((
            format!("written{at}"),
            caption(format!("Hedwig wrote there, with your consent: {written}")),
        ));
    }
    for (at, carried) in line.carried.iter().enumerate() {
        items.push((format!("carried{at}"), caption(carried.clone())));
    }
    if let Some(lending) = &line.lending {
        items.push(("lending".to_owned(), lent(line, lending, context)));
    }
    if let Some(keys) = &line.keys {
        items.push(("keys".to_owned(), keys_lent(window, line, keys, context)));
    }
    if let Some(proof) = &line.proof {
        items.push(("proof".to_owned(), text(proof.clone()).into()));
    }
    for (at, held) in line.held.iter().enumerate() {
        items.push((
            format!("held{at}"),
            text(format!("Made, and held: {held}")).into(),
        ));
    }
    if let Some(refused) = &line.refused {
        items.push((
            "refused".to_owned(),
            InfoBar::new()
                .is_open(true)
                .is_closable(false)
                .severity(InfoBarSeverity::Error)
                .message(format!("Not done: {refused}"))
                .into(),
        ));
    }
    for (at, decides) in line.policy.iter().enumerate() {
        items.push((
            format!("policy{at}"),
            policy(window, line, decides, context),
        ));
    }
    let (remote, capability) = (line.remote.clone(), line.capability.clone());
    items.push((
        "acts".to_owned(),
        answers(
            &line.acts,
            |label| At::Line {
                remote: remote.clone(),
                capability: capability.clone(),
                label: label.to_owned(),
            },
            context,
        ),
    ));
    card(column(8.0, items))
}

/// What a grant lends of its source's devices: each device, with a box that
/// lends it or takes it back where that is the person's to change here, and
/// lending every device, or no longer.
fn lent(line: &Line, lending: &Lending, context: &Context) -> View {
    let mut items = vec![("lends".to_owned(), text(capitalised(&lending.lends)).into())];
    if let Some(listing) = &lending.listing {
        items.push(("listing".to_owned(), caption(listing.clone())));
    }
    for device in &lending.devices {
        let view: View = match &device.act {
            Some(Shown::Offered { .. }) => {
                let at = At::Device {
                    remote: line.remote.clone(),
                    capability: line.capability.clone(),
                    device: device.label.clone(),
                };
                let lent = device.lent;
                CheckBox::new()
                    .is_checked(lent)
                    // The box shows what is lent: a change the person makes is
                    // the act, carried out or asked first. WinUI also reports
                    // the box set back to what is lent, after a cancel or the
                    // core's answer, which is no act.
                    .on_is_checked_changed(context.callback(move |on: bool| {
                        if on == lent {
                            Message::Nothing
                        } else {
                            Message::Chose(at.clone())
                        }
                    }))
                    .content(device.label.clone())
            }
            Some(Shown::Withheld { label, why }) => caption(format!("{label}: not now - {why}")),
            None if device.lent => text(format!("{}: lent", device.label)).into(),
            None => text(device.label.clone()).into(),
        };
        items.push((format!("device-{}", device.label), view));
    }
    let (remote, capability) = (line.remote.clone(), line.capability.clone());
    items.push((
        "acts".to_owned(),
        answers(
            &lending.acts,
            |label| At::Line {
                remote: remote.clone(),
                capability: capability.clone(),
                label: label.to_owned(),
            },
            context,
        ),
    ));
    column(4.0, items)
}

/// The hosts `key` may log in to on a line, as the view writes them.
pub(crate) fn hosts_now(
    shown: &exposure::Window,
    remote: Option<&RemoteId>,
    capability: &Name,
    key: &SshKey,
) -> Option<String> {
    let Board::Exposure { groups, .. } = &shown.board else {
        return None;
    };
    groups
        .iter()
        .flat_map(|group| &group.lines)
        .find(|line| line.remote.as_ref() == remote && line.capability == *capability)?
        .keys
        .as_ref()?
        .keys
        .iter()
        .find(|line| line.key == *key)?
        .hosts
        .clone()
}

/// One key on a grant's line: a box that lends it or takes it back, where
/// it may be used, the hosts it may log in to, typed and set, and lending it
/// for anything.
fn key_lent(window: &Window, line: &Line, one: &KeyLine, context: &Context) -> View {
    let (remote, capability, key) = (
        line.remote.clone(),
        line.capability.clone(),
        one.key.clone(),
    );
    let view: View = match &one.act {
        Some(Shown::Offered { .. }) => {
            let at = At::Key {
                remote: remote.clone(),
                capability: capability.clone(),
                key: key.clone(),
            };
            let lent = one.lent;
            CheckBox::new()
                .is_checked(lent)
                // The box shows what is lent: a change the person makes is
                // the act; WinUI also reports the box set back, which is
                // no act.
                .on_is_checked_changed(context.callback(move |on: bool| {
                    if on == lent {
                        Message::Nothing
                    } else {
                        Message::Chose(at.clone())
                    }
                }))
                .content(one.label.clone())
        }
        Some(Shown::Withheld { label, why }) => caption(format!("{label}: not now - {why}")),
        None if one.lent => text(format!("{}: lent", one.label)).into(),
        None => text(one.label.clone()).into(),
    };
    let mut parts = vec![("key".to_owned(), view)];
    if let Some(toward) = &one.toward {
        parts.push(("toward".to_owned(), caption(capitalised(toward))));
    }
    if let Some(hosts) = &one.hosts {
        let typed_key = hosts_key(remote.as_ref(), &capability, &key);
        let shown = window
            .typing
            .get(&typed_key)
            .and_then(|typed| typed.first().cloned())
            .unwrap_or_else(|| hosts.clone());
        let owned = typed_key.clone();
        parts.push((
            "hosts".to_owned(),
            TextBox::new()
                .text(shown)
                .accepts_return(true)
                .text_wrapping(TextWrapping::Wrap)
                .placeholder_text(
                    "Any host. Or only the hosts whose keys you paste, one to a line, as \
                     ssh-keyscan or a known_hosts line prints them",
                )
                .automation_name("Hosts it may log in to")
                .on_text_changed(context.callback(move |text: String| Message::Typing {
                    key: owned.clone(),
                    field: 0,
                    text,
                }))
                .into(),
        ));
        let (remote, capability, key) = (remote.clone(), capability.clone(), key.clone());
        parts.push((
            "restrict".to_owned(),
            button(
                "Lend it only for logging in to these hosts",
                move || Message::Restrict {
                    remote: remote.clone(),
                    capability: capability.clone(),
                    key: key.clone(),
                },
                context,
            ),
        ));
        if let Some((_, why)) = window
            .invalid
            .as_ref()
            .filter(|(invalid, _)| *invalid == typed_key)
        {
            parts.push((
                "invalid".to_owned(),
                text(why.clone())
                    .foreground(ThemeBrush::SystemCritical)
                    .into(),
            ));
        }
    }
    if let Some(anywhere) = &one.anywhere {
        let (remote, capability) = (line.remote.clone(), line.capability.clone());
        parts.push((
            "anywhere".to_owned(),
            answers(
                std::slice::from_ref(anywhere),
                |label| At::Line {
                    remote: remote.clone(),
                    capability: capability.clone(),
                    label: label.to_owned(),
                },
                context,
            ),
        ));
    }
    column(4.0, parts)
}

/// What a grant lends of an agent's keys: what its own prompts cannot say;
/// each key with a box that lends it or takes it back, where it may be used,
/// and the hosts it may log in to, typed and set; lending every key; asking
/// the agent which keys it holds. What answers for the agent is the line's.
fn keys_lent(window: &Window, line: &Line, keys: &Keying, context: &Context) -> View {
    let mut items = vec![("lends".to_owned(), text(capitalised(&keys.lends)).into())];
    items.push(("asks".to_owned(), caption(keys.asks)));
    if let Some(listing) = &keys.listing {
        items.push(("listing".to_owned(), caption(listing.clone())));
    }
    for one in &keys.keys {
        items.push((
            format!("key-{}", one.key),
            key_lent(window, line, one, context),
        ));
    }
    let (remote, capability) = (line.remote.clone(), line.capability.clone());
    items.push((
        "acts".to_owned(),
        answers(
            &keys.acts,
            |label| At::Line {
                remote: remote.clone(),
                capability: capability.clone(),
                label: label.to_owned(),
            },
            context,
        ),
    ));
    column(4.0, items)
}

/// The text each field of a typed setting starts from.
pub(crate) fn fields(sheet: &Sheet, wanted: &str) -> Option<Vec<String>> {
    let all = sheet
        .workstation
        .iter()
        .map(|setting| (None, setting))
        .chain(sheet.remotes.iter().flat_map(|section| {
            section
                .settings
                .iter()
                .map(move |setting| (Some(section.of.to_string()), setting))
        }))
        .chain(sheet.routes.iter().flat_map(|section| {
            section
                .settings
                .iter()
                .map(move |setting| (Some(section.of.to_string()), setting))
        }));
    for (section, setting) in all {
        if key(section.as_deref(), setting.name) == wanted {
            return setting.entry.as_ref().map(Entry::now);
        }
    }
    None
}

/// What a typed setting has chosen rather than typed, after its `field`
/// fields: its place is kept as text with what is typed (`Entry::now`).
fn picked(
    field: usize,
    choice: &Choice,
    typed: Option<&Vec<String>>,
    key: &str,
    context: &Context,
) -> View {
    let chosen = typed
        .and_then(|typed| typed.get(field))
        .and_then(|at| at.parse().ok())
        .unwrap_or(choice.chosen);
    let owned = key.to_owned();
    column(
        4.0,
        vec![
            ("label".to_owned(), caption(choice.label)),
            (
                "box".to_owned(),
                ComboBox::new()
                    .items_source(choice.options.iter().cloned())
                    .selected_index(Some(chosen))
                    .automation_name(choice.label)
                    .on_selection_changed(context.callback(move |at: Option<usize>| {
                        at.map_or(Message::Nothing, |at| Message::Typing {
                            key: owned.clone(),
                            field,
                            text: at.to_string(),
                        })
                    }))
                    .into(),
            ),
        ],
    )
}

fn entry(window: &Window, entry: &Entry, key: &str, context: &Context) -> View {
    let typed = window.typing.get(key);
    let mut items: Vec<(String, View)> = entry
        .fields
        .iter()
        .enumerate()
        .map(|(field, (label, now))| {
            let shown = typed
                .and_then(|typed| typed.get(field))
                .unwrap_or(now)
                .clone();
            let owned = key.to_owned();
            (
                format!("field{field}"),
                column(
                    4.0,
                    vec![
                        ("label".to_owned(), caption(*label)),
                        (
                            "box".to_owned(),
                            TextBox::new()
                                .text(shown)
                                .automation_name(*label)
                                .on_text_changed(context.callback(move |text: String| {
                                    Message::Typing {
                                        key: owned.clone(),
                                        field,
                                        text,
                                    }
                                }))
                                .into(),
                        ),
                    ],
                ),
            )
        })
        .collect();
    if let Some(choice) = &entry.choice {
        items.push((
            "choice".to_owned(),
            picked(entry.fields.len(), choice, typed, key, context),
        ));
    }
    let widths: &[(Wide, &str)] = match entry.place {
        Place::Remote(_) => &[
            (Wide::This, "Set for this remote"),
            (Wide::Every, "Set for every remote"),
        ],
        Place::Route(_) => &[
            (Wide::This, "Set for this route"),
            (Wide::Every, "Set for every route"),
        ],
        Place::Workstation => &[(Wide::This, "Set")],
    };
    let buttons = widths
        .iter()
        .map(|(wide, label)| {
            let (owned, wide) = (key.to_owned(), *wide);
            (
                (*label).to_owned(),
                button(
                    label,
                    move || Message::SetTyped {
                        key: owned.clone(),
                        wide,
                    },
                    context,
                ),
            )
        })
        .collect();
    items.push(("set".to_owned(), row(buttons)));
    if let Some((_, why)) = window
        .invalid
        .as_ref()
        .filter(|(invalid, _)| invalid == key)
    {
        items.push((
            "invalid".to_owned(),
            text(why.clone())
                .foreground(ThemeBrush::SystemCritical)
                .into(),
        ));
    }
    column(8.0, items)
}

fn setting(window: &Window, section: Option<&str>, setting: &Setting, context: &Context) -> View {
    let name = setting.name;
    let at = |label: &str| At::Setting {
        section: section.map(str::to_owned),
        name,
        label: label.to_owned(),
    };
    let mut items = vec![
        ("name".to_owned(), strong(setting.name)),
        ("value".to_owned(), text(capitalised(&setting.value)).into()),
        ("said".to_owned(), caption(format!("From {}", setting.said))),
    ];
    for (place, holding) in setting.holds.iter().enumerate() {
        items.push((format!("hold{place}"), caption(format!("Held: {holding}"))));
    }
    if let Some(beside) = &setting.beside {
        items.push(("beside".to_owned(), caption(beside.clone())));
    }
    if !setting.choices.is_empty() {
        items.push(("choices".to_owned(), answers(&setting.choices, at, context)));
    }
    if let Some(clear) = &setting.clear {
        items.push((
            "clear".to_owned(),
            answers(std::slice::from_ref(clear), at, context),
        ));
    }
    if let Some(typed) = &setting.entry {
        items.push((
            "entry".to_owned(),
            entry(window, typed, &key(section, name), context),
        ));
    }
    card(column(4.0, items))
}

fn settings<T: ToString>(window: &Window, section: &Section<T>, context: &Context) -> View {
    let of = section.of.to_string();
    column(
        8.0,
        section
            .settings
            .iter()
            .enumerate()
            .map(|(at, one)| {
                (
                    format!("{at}{}", one.name),
                    setting(window, Some(&of), one, context),
                )
            })
            .collect(),
    )
}

/// A disclosure the person opens and closes; it stays as they left it
/// whatever the core says meanwhile.
fn disclosure(window: &Window, header: &str, inside: View, context: &Context) -> View {
    let key = header.to_owned();
    Expander::new()
        .is_expanded(window.expanded.contains(header))
        .on_is_expanded_changed(context.callback(move |open: bool| Message::Expanded {
            key: key.clone(),
            open,
        }))
        .slots([
            SlotView::new(ExpanderSlot::Header, header.to_owned()),
            SlotView::new(ExpanderSlot::Content, inside),
        ])
}

fn group(window: &Window, group: &Group, context: &Context) -> View {
    let mut items: Vec<(String, View)> = vec![("heading".to_owned(), subtitle(&group.heading))];
    for (at, one) in group.lines.iter().enumerate() {
        items.push((
            format!("line{at}{}", one.capability),
            line(window, one, context),
        ));
    }
    if let Some(section) = window.sheet.as_ref().and_then(|sheet| {
        sheet
            .remotes
            .iter()
            .find(|section| section.of.to_string() == group.heading)
    }) {
        items.push((
            "settings".to_owned(),
            disclosure(
                window,
                &format!("Settings for {}", group.heading),
                settings(window, section, context),
                context,
            ),
        ));
    }
    // What happened on a remote; a grant no remote has met has no history.
    if group.lines.iter().any(|line| line.remote.is_some()) {
        items.push((
            "activity".to_owned(),
            disclosure(
                window,
                &format!("{ACTIVITY}{}", group.heading),
                activity(window, &group.heading, context),
                context,
            ),
        ));
    }
    column(12.0, items)
}

/// One remote's activity, newest first, while its disclosure is open.
fn activity(window: &Window, remote: &str, context: &Context) -> View {
    let mut items = Vec::new();
    match window.activity(remote) {
        None => items.push((
            "asking".to_owned(),
            caption(format!("Reading what happened on {remote}.")),
        )),
        Some((said, earlier)) => {
            if said.is_empty() {
                items.push((
                    "none".to_owned(),
                    caption(format!("Nothing has happened on {remote} yet.")),
                ));
            }
            for (place, one) in said.into_iter().enumerate() {
                let entry: View = text(one.text).into();
                match one.at {
                    Some((remote, capability, seq)) if !one.acts.is_empty() => {
                        let at = |label: &str| At::Entry {
                            remote: remote.clone(),
                            capability: capability.clone(),
                            seq,
                            label: label.to_owned(),
                        };
                        items.push((
                            format!("entry{place}"),
                            column(
                                4.0,
                                vec![
                                    ("text".to_owned(), entry),
                                    ("acts".to_owned(), answers(&one.acts, at, context)),
                                ],
                            ),
                        ));
                    }
                    _ => items.push((format!("entry{place}"), entry)),
                }
            }
            if earlier {
                items.push((
                    "earlier".to_owned(),
                    button("Show what happened before", || Message::Earlier, context),
                ));
            }
        }
    }
    column(4.0, items)
}

fn chosen<T>(choices: &[grant::Choice<T>]) -> Option<usize> {
    choices.iter().position(|choice| choice.chosen)
}

/// Which remotes the grant is to, as the form asks.
fn remotes(form: &Form, context: &Context, items: &mut Vec<(String, View)>) {
    items.extend([
        ("aim-label".to_owned(), caption("To which remotes")),
        (
            "aim".to_owned(),
            RadioButtons::new()
                .items_source([
                    "Every remote on a route",
                    "One remote, or a pattern such as team-*",
                    "The remotes in a set",
                ])
                .selected_index(Some(match form.aim {
                    Aim::Route => 0,
                    Aim::Named => 1,
                    Aim::Set => 2,
                }))
                .automation_name("To which remotes")
                .on_selection_changed(context.callback(|at: Option<usize>| {
                    Message::Edit(Edit::Aim(match at {
                        Some(1) => Aim::Named,
                        Some(2) => Aim::Set,
                        _ => Aim::Route,
                    }))
                }))
                .into(),
        ),
    ]);
    if form.aim == Aim::Set {
        items.push((
            "set".to_owned(),
            ComboBox::new()
                .items_source(form.sets.iter().map(|choice| choice.label.clone()))
                .selected_index(chosen(&form.sets))
                .placeholder_text("Choose a set")
                .automation_name("Set")
                .on_selection_changed(context.callback(|at: Option<usize>| {
                    at.map_or(Message::Nothing, |at| Message::Edit(Edit::Set(at)))
                }))
                .into(),
        ));
    } else {
        items.push((
            "route".to_owned(),
            ComboBox::new()
                .items_source(form.routes.iter().map(|choice| choice.label.clone()))
                .selected_index(chosen(&form.routes))
                .placeholder_text("Choose a route")
                .automation_name("Route")
                .on_selection_changed(context.callback(|at: Option<usize>| {
                    at.map_or(Message::Nothing, |at| Message::Edit(Edit::Route(at)))
                }))
                .into(),
        ));
    }
    if form.aim == Aim::Named {
        items.push((
            "typed".to_owned(),
            TextBox::new()
                .text(form.typed.clone())
                .placeholder_text("A remote's name, or a pattern")
                .automation_name("Remote or pattern")
                .on_text_changed(context.callback(|text: String| Message::Edit(Edit::Typed(text))))
                .into(),
        ));
        if let Some(why) = &form.unnamed {
            items.push(("unnamed".to_owned(), caption(why.clone())));
        }
    }
}

/// When Hedwig connects, whether it may write, and what the person names.
fn terms(form: &Form, context: &Context, items: &mut Vec<(String, View)>) {
    items.push((
        "activation-label".to_owned(),
        caption("When Hedwig connects"),
    ));
    items.push((
        "activation".to_owned(),
        RadioButtons::new()
            .items_source(
                form.activations
                    .iter()
                    .map(|choice| capitalised(&choice.label)),
            )
            .selected_index(chosen(&form.activations))
            .automation_name("When Hedwig connects")
            .on_selection_changed(context.callback(|at: Option<usize>| {
                at.map_or(Message::Nothing, |at| Message::Edit(Edit::Activation(at)))
            }))
            .into(),
    ));
    // Consent is asked only where there is something to write, and what it
    // writes is said before it is given.
    if let Some(writable) = &form.writable {
        items.push((
            "writes".to_owned(),
            row(vec![
                (
                    "switch".to_owned(),
                    ToggleSwitch::new()
                        .is_on(form.writes)
                        .automation_name("Let Hedwig write the remote tool's own configuration")
                        .on_toggled(context.callback(|on: bool| Message::Edit(Edit::Writes(on))))
                        .into(),
                ),
                (
                    "words".to_owned(),
                    text("Let Hedwig write the remote tool's own configuration").into(),
                ),
            ]),
        ));
        items.push((
            "writable".to_owned(),
            caption(format!(
                "On each remote, where it is missing and never over what you set, {writable}. \
                 Each is marked as Hedwig's, and taken back when you withdraw the grant."
            )),
        ));
    }
    if let Some(lending) = &form.lending {
        lends(lending, context, items);
    }
    if let Some(keying) = &form.keying {
        keys(keying, context, items);
    }
    for choice in &form.exposes {
        let word = choice.value;
        items.push((
            format!("exposes-{word}"),
            CheckBox::new()
                .is_checked(choice.chosen)
                .on_is_checked_changed(
                    context.callback(move |on: bool| Message::Edit(Edit::Acknowledge(word, on))),
                )
                .content(format!("I understand this lets them {}", choice.label)),
        ));
    }
}

/// Which devices the grant lends: none until the person names one, every
/// device only as a choice of its own.
fn lends(lending: &grant::Lending, context: &Context, items: &mut Vec<(String, View)>) {
    items.push(("lends-label".to_owned(), caption("Which devices it lends")));
    items.push(("lends".to_owned(), text(capitalised(&lending.lends)).into()));
    if let Some(listing) = &lending.listing {
        items.push(("listing".to_owned(), caption(listing.clone())));
    }
    for (at, choice) in lending.devices.iter().enumerate() {
        let view: View = if lending.every || choice.value.is_none() {
            // Under every device each is lent and none is named; one with no
            // serial is lent only so.
            text(if choice.chosen {
                format!("{}: lent", choice.label)
            } else {
                choice.label.clone()
            })
            .into()
        } else {
            CheckBox::new()
                .is_checked(choice.chosen)
                .on_is_checked_changed(
                    context.callback(move |on: bool| Message::Edit(Edit::Lend(at, on))),
                )
                .content(choice.label.clone())
        };
        items.push((format!("device{at}"), view));
    }
    items.push((
        "every".to_owned(),
        CheckBox::new()
            .is_checked(lending.every)
            .on_is_checked_changed(context.callback(|on: bool| Message::Edit(Edit::Every(on))))
            .content(
                "Every device, now and later - your own phone among them whenever it is attached",
            ),
    ));
}

/// Which keys the grant lends: none until the person names one, every key
/// only as a choice of its own; each lent key where it may be used; the
/// agent asked which keys it holds only when the person asks.
fn keys(keying: &grant::Keying, context: &Context, items: &mut Vec<(String, View)>) {
    items.push(("keys-label".to_owned(), caption("Which keys it lends")));
    items.push((
        "keys-lend".to_owned(),
        text(capitalised(&keying.lends)).into(),
    ));
    // It begins with the capability's name, kept as written.
    if let Some(answering) = &keying.answering {
        items.push((
            "keys-answering".to_owned(),
            caption(format!("{answering}.")),
        ));
    }
    items.push(("keys-asks".to_owned(), caption(keying.asks)));
    if let Some(listing) = &keying.listing {
        items.push(("keys-listing".to_owned(), caption(listing.clone())));
    }
    if keying.ask {
        items.push((
            "keys-ask".to_owned(),
            button(
                "Ask your agent which keys it holds",
                || Message::Edit(Edit::AskKeys),
                context,
            ),
        ));
    }
    for (at, choice) in keying.keys.iter().enumerate() {
        let view: View = if keying.every {
            text(format!("{}: lent", choice.label)).into()
        } else {
            CheckBox::new()
                .is_checked(choice.chosen)
                .on_is_checked_changed(
                    context.callback(move |on: bool| Message::Edit(Edit::LendKey(at, on))),
                )
                .content(choice.label.clone())
        };
        items.push((format!("key{at}"), view));
        if let Some(hosts) = &choice.hosts {
            items.push((
                format!("key{at}-hosts"),
                TextBox::new()
                    .text(hosts.clone())
                    .accepts_return(true)
                    .text_wrapping(TextWrapping::Wrap)
                    .placeholder_text(
                        "Any host. Or only the hosts whose keys you paste, one to a line, as \
                         ssh-keyscan or a known_hosts line prints them",
                    )
                    .automation_name("Hosts it may log in to")
                    .on_text_changed(
                        context.callback(move |text: String| Message::Edit(Edit::Hosts(at, text))),
                    )
                    .into(),
            ));
        }
        if let Some(invalid) = &choice.invalid {
            items.push((
                format!("key{at}-invalid"),
                text(invalid.clone())
                    .foreground(ThemeBrush::SystemCritical)
                    .into(),
            ));
        }
    }
    items.push((
        "keys-every".to_owned(),
        CheckBox::new()
            .is_checked(keying.every)
            .on_is_checked_changed(context.callback(|on: bool| Message::Edit(Edit::Every(on))))
            .content("Every key your agent holds, now and later, for anything"),
    ));
}

fn form(window: &Window, form: &Form, context: &Context) -> View {
    let mut items: Vec<(String, View)> = vec![
        ("capability-label".to_owned(), caption("What to grant")),
        (
            "capability".to_owned(),
            ComboBox::new()
                .items_source(form.capabilities.iter().map(|choice| choice.label.clone()))
                .selected_index(chosen(&form.capabilities))
                .placeholder_text("Choose a capability")
                .automation_name("What to grant")
                .on_selection_changed(context.callback(|at: Option<usize>| {
                    at.map_or(Message::Nothing, |at| Message::Edit(Edit::Capability(at)))
                }))
                .into(),
        ),
    ];
    if let Some(opened_at) = &form.opened_at {
        items.push(("opened-at".to_owned(), caption(format!("{opened_at}."))));
    }
    if let Some(beyond) = &form.beyond {
        items.push(("beyond".to_owned(), text(beyond.clone()).into()));
    }
    if !form.defines.is_empty() {
        let buttons = form
            .defines
            .iter()
            .enumerate()
            .map(|(at, (label, _))| {
                (
                    format!("define{at}"),
                    button(label, move || Message::DefineFromGrant(at), context),
                )
            })
            .collect();
        items.push((
            "defines-label".to_owned(),
            caption("Or define what you would grant, which nothing here is yet"),
        ));
        items.push(("defines".to_owned(), row(buttons)));
    }
    remotes(form, context, &mut items);
    terms(form, context, &mut items);
    if let Some((_, refused)) = &form.refused {
        items.push((
            "refused".to_owned(),
            text(refused.clone())
                .foreground(ThemeBrush::SystemCritical)
                .into(),
        ));
    }
    let mut buttons = Vec::new();
    match &form.ready {
        Ok(label) => buttons.push((
            "submit".to_owned(),
            button(label, || Message::Submit, context),
        )),
        Err(owed) => items.push(("owed".to_owned(), caption(owed.clone()))),
    }
    if let Some((label, _)) = &form.completes {
        buttons.push((
            "completes".to_owned(),
            button(label, || Message::Complete, context),
        ));
    }
    if window.draft.is_some() {
        buttons.push((
            "discard".to_owned(),
            button("Discard this grant", || Message::Discard, context),
        ));
    }
    items.push(("buttons".to_owned(), row(buttons)));
    card(column(8.0, items))
}

fn first(window: &Window, first: &First, context: &Context) -> Vec<(String, View)> {
    let mut items = vec![(
        "title".to_owned(),
        title("Nothing of yours is reachable from a remote yet"),
    )];
    match &first.has {
        None => items.push((
            "looking".to_owned(),
            row(vec![
                (
                    "ring".to_owned(),
                    ProgressRing::new().is_active(true).into(),
                ),
                (
                    "words".to_owned(),
                    text("Looking at what this workstation has.").into(),
                ),
            ]),
        )),
        Some(has) => {
            items.push(("has-heading".to_owned(), subtitle("This workstation has")));
            if has.is_empty() {
                items.push((
                    "nothing".to_owned(),
                    text("Nothing Hedwig can expose answers on this workstation yet.").into(),
                ));
            }
            for (at, one) in has.iter().enumerate() {
                items.push((format!("has{at}"), text(one.clone()).into()));
            }
        }
    }
    if !first.cards.is_empty() {
        items.push((
            "cards-heading".to_owned(),
            subtitle("Cards Hedwig has read"),
        ));
        for (at, card) in first.cards.iter().enumerate() {
            items.push((format!("card{at}"), text(card.clone()).into()));
        }
    }
    items.push(("grant-heading".to_owned(), subtitle("Your first grant")));
    if let Some(made) = window.form() {
        items.push(("form".to_owned(), form(window, &made, context)));
    }
    // A definition begun from the grant - its browser, its serial port, a
    // preset's port - stands beneath the grant it was begun from.
    if let Some(defining_now) = window.definition() {
        items.push(("defining".to_owned(), defining(&defining_now, context)));
    }
    items.push((
        "import".to_owned(),
        row(vec![
            (
                "words".to_owned(),
                text("Or bring what you set on another workstation:").into(),
            ),
            (
                "button".to_owned(),
                button("Import a configuration...", || Message::Import, context),
            ),
        ]),
    ));
    items.push((
        "workstation".to_owned(),
        disclosure(
            window,
            WORKSTATION,
            workstation(window, Importing::Above, context),
            context,
        ),
    ));
    items
}

/// Whether this workstation's section offers importing: the first run offers
/// it above, on a line of its own.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Importing {
    Here,
    Above,
}

/// One field of a definition: its label, what it takes, and why what is in it
/// cannot be used, beneath it.
fn defining_field(field: &define::Field, context: &Context) -> View {
    let key = field.key;
    let mut items = vec![("label".to_owned(), caption(field.label))];
    let input: View = match &field.input {
        define::Input::Text { typed, lines } => TextBox::new()
            .text(typed.clone())
            .accepts_return(*lines)
            .text_wrapping(if *lines {
                TextWrapping::Wrap
            } else {
                TextWrapping::NoWrap
            })
            .automation_name(field.label)
            .on_text_changed(context.callback(move |text: String| {
                Message::Defining(define::Edit::Typed {
                    key: key.to_owned(),
                    text,
                })
            }))
            .into(),
        define::Input::Choice { options, chosen } => RadioButtons::new()
            .items_source(options.iter().cloned())
            .selected_index(Some(*chosen))
            .automation_name(field.label)
            .on_selection_changed(context.callback(move |at: Option<usize>| {
                at.map_or(Message::Nothing, |at| {
                    Message::Defining(define::Edit::Chose {
                        key: key.to_owned(),
                        at,
                    })
                })
            }))
            .into(),
        // Each option is sent as its value, so a list read again never moves
        // what is chosen to another port.
        define::Input::Pick { options, chosen } => {
            let values: Vec<String> = options.iter().map(|option| option.value.clone()).collect();
            ComboBox::new()
                .items_source(options.iter().map(|option| option.label.clone()))
                .selected_index(*chosen)
                .placeholder_text("Choose one")
                .automation_name(field.label)
                .on_selection_changed(context.callback(move |at: Option<usize>| {
                    at.and_then(|at| values.get(at).cloned())
                        .map_or(Message::Nothing, |text| {
                            Message::Defining(define::Edit::Typed {
                                key: key.to_owned(),
                                text,
                            })
                        })
                }))
                .into()
        }
    };
    items.push(("input".to_owned(), input));
    if let Some(hint) = field.hint {
        items.push(("hint".to_owned(), caption(capitalised(hint))));
    }
    for (at, note) in field.notes.iter().enumerate() {
        items.push((format!("note{at}"), text(note.clone()).into()));
    }
    if let Some(label) = field.again {
        items.push((
            "again".to_owned(),
            button(label, || Message::PortsAgain, context),
        ));
    }
    if let Some(invalid) = &field.invalid {
        items.push((
            "invalid".to_owned(),
            text(invalid.clone())
                .foreground(ThemeBrush::SystemCritical)
                .into(),
        ));
    }
    column(4.0, items)
}

/// The definition being made or changed, field by field.
fn defining(form: &define::Form, context: &Context) -> View {
    let mut items = vec![("heading".to_owned(), strong(&form.heading))];
    if !form.starts.is_empty() {
        items.push(("start-label".to_owned(), caption("Start from")));
        items.push((
            "start".to_owned(),
            ComboBox::new()
                .items_source(form.starts.iter().cloned())
                .placeholder_text("Nothing: every field empty")
                .automation_name("Start from")
                .on_selection_changed(context.callback(|at: Option<usize>| {
                    at.map_or(Message::Nothing, |at| {
                        Message::Defining(define::Edit::From(at))
                    })
                }))
                .into(),
        ));
    }
    for field in &form.fields {
        items.push((
            format!("field-{}", field.key),
            defining_field(field, context),
        ));
    }
    if let Some(refused) = &form.refused {
        items.push((
            "refused".to_owned(),
            text(format!("Not done: {refused}"))
                .foreground(ThemeBrush::SystemCritical)
                .into(),
        ));
    }
    let mut buttons = Vec::new();
    match &form.ready {
        Ok(Shown::Offered { label, .. } | Shown::Withheld { label, .. }) => buttons.push((
            "submit".to_owned(),
            button(label, || Message::DefineSubmit, context),
        )),
        Err(owed) => items.push(("owed".to_owned(), caption(owed.clone()))),
    }
    buttons.push((
        "discard".to_owned(),
        button("Discard", || Message::DefineDiscard, context),
    ));
    items.push(("buttons".to_owned(), row(buttons)));
    card(column(8.0, items))
}

/// Each name defined outside the person's configuration, by whose it is,
/// and each name two sources define differently.
fn outside(definitions: &define::Definitions, items: &mut Vec<(String, View)>) {
    for (kind, names) in &definitions.outside {
        // By whose they are, in the order first met.
        let mut whose: Vec<(&str, Vec<String>)> = Vec::new();
        for name in names {
            match whose.iter_mut().find(|(by, _)| *by == name.by) {
                Some((_, these)) => these.push(name.name.to_string()),
                None => whose.push((&name.by, vec![name.name.to_string()])),
            }
        }
        if !whose.is_empty() {
            items.push((
                format!("outside-{}", kind.noun()),
                caption(format!(
                    "Each {} defined outside your configuration, which you can start from: {}",
                    kind.noun(),
                    whose
                        .iter()
                        .map(|(by, these)| format!("{} ({by})", these.join(", ")))
                        .collect::<Vec<_>>()
                        .join("; ")
                )),
            ));
        }
    }
    for (at, elsewhere) in definitions
        .outside
        .iter()
        .flat_map(|(_, names)| names)
        .filter_map(|name| Some((&name.name, name.beyond.as_ref()?)))
        .enumerate()
    {
        items.push((
            format!("outside-beyond{at}"),
            caption(format!("{}: {}", elsewhere.0, elsewhere.1)),
        ));
    }
    if !definitions.beyond.is_empty() {
        items.push((
            "beyond-heading".to_owned(),
            caption("What no definition can give a remote's tool"),
        ));
        for (at, beyond) in definitions.beyond.iter().enumerate() {
            items.push((format!("beyond{at}"), caption(beyond.clone())));
        }
    }
    for (at, collision) in definitions.collisions.iter().enumerate() {
        items.push((
            format!("collision{at}"),
            InfoBar::new()
                .is_open(true)
                .is_closable(false)
                .severity(InfoBarSeverity::Warning)
                .message(collision.clone())
                .into(),
        ));
    }
}

/// What the person has defined, each with changing and removing it; what is
/// defined outside their configuration by name; and defining another.
fn definitions(window: &Window, context: &Context) -> View {
    let mut items = vec![("heading".to_owned(), strong("What you have defined"))];
    let Some(definitions) = window.definitions() else {
        return column(8.0, items);
    };
    for defined in &definitions.own {
        let (kind, name) = (defined.kind, defined.name.clone());
        let label = match &defined.remove {
            Shown::Offered { label, .. } | Shown::Withheld { label, .. } => label.clone(),
        };
        let at = At::Defined {
            kind,
            name: name.clone(),
            label: label.clone(),
        };
        let mut lines = vec![
            (
                "name".to_owned(),
                strong(&format!("{}: your {}", defined.name, kind.noun())),
            ),
            ("says".to_owned(), text(defined.says.clone()).into()),
        ];
        if let Some(beyond) = &defined.beyond {
            lines.push(("beyond".to_owned(), text(beyond.clone()).into()));
        }
        if let Some(refused) = &defined.refused {
            lines.push((
                "refused".to_owned(),
                text(format!("Not done: {refused}"))
                    .foreground(ThemeBrush::SystemCritical)
                    .into(),
            ));
        }
        let changing = name.clone();
        lines.push((
            "acts".to_owned(),
            row(vec![
                (
                    "change".to_owned(),
                    button(
                        &format!("Change {name}..."),
                        move || Message::Define {
                            kind,
                            name: Some(changing.clone()),
                        },
                        context,
                    ),
                ),
                (
                    "remove".to_owned(),
                    button(&label, move || Message::Chose(at.clone()), context),
                ),
            ]),
        ));
        items.push((
            format!("{}-{}", kind.noun(), defined.name),
            card(column(4.0, lines)),
        ));
    }
    if definitions.own.is_empty() {
        items.push((
            "none".to_owned(),
            caption("Nothing yet: what you define is used like what Hedwig ships."),
        ));
    }
    outside(&definitions, &mut items);
    if let Some(form) = window.definition() {
        items.push(("form".to_owned(), defining(&form, context)));
    } else {
        let buttons = define::Kind::ALL
            .into_iter()
            .map(|kind| {
                (
                    kind.noun().to_owned(),
                    button(
                        &format!("Define a {}...", kind.noun()),
                        move || Message::Define { kind, name: None },
                        context,
                    ),
                )
            })
            .collect();
        items.push(("define".to_owned(), row(buttons)));
    }
    column(8.0, items)
}

fn workstation(window: &Window, importing: Importing, context: &Context) -> View {
    let mut items = Vec::new();
    if let Some(sheet) = &window.sheet {
        for (at, one) in sheet.workstation.iter().enumerate() {
            items.push((format!("ws{at}"), setting(window, None, one, context)));
        }
        for section in &sheet.routes {
            items.push((
                format!("route-{}", section.of),
                column(
                    8.0,
                    vec![
                        (
                            "heading".to_owned(),
                            strong(&format!("Route {}", section.of)),
                        ),
                        ("settings".to_owned(), settings(window, section, context)),
                    ],
                ),
            ));
        }
        for (at, contact) in sheet.contacts.iter().enumerate() {
            items.push((format!("contact{at}"), text(contact.clone()).into()));
        }
        for (at, unread) in sheet.unread.iter().enumerate() {
            items.push((format!("unread{at}"), text(unread.clone()).into()));
        }
    }
    items.push(("defined".to_owned(), definitions(window, context)));
    let mut files = vec![(
        "export".to_owned(),
        button("Export your configuration...", || Message::Export, context),
    )];
    if importing == Importing::Here {
        files.push((
            "import".to_owned(),
            button("Import a configuration...", || Message::Import, context),
        ));
    }
    files.push((
        "bundle".to_owned(),
        button(
            "Gather what a supporter needs...",
            || Message::MakeBundle,
            context,
        ),
    ));
    items.push(("files".to_owned(), row(files)));
    column(12.0, items)
}

/// What a supporter would be given, shown before it is saved: a line for
/// each part, then saving it or putting it away.
fn bundle(contents: Option<Vec<String>>, context: &Context) -> View {
    let mut items = Vec::new();
    match contents {
        None => items.push((
            "asking".to_owned(),
            row(vec![
                (
                    "ring".to_owned(),
                    ProgressRing::new().is_active(true).into(),
                ),
                (
                    "words".to_owned(),
                    text("Asking Hedwig for what a supporter needs.").into(),
                ),
            ]),
        )),
        Some(lines) => {
            items.push(("heading".to_owned(), subtitle(hedwig_view::bundle::HEADING)));
            for (at, line) in lines.into_iter().enumerate() {
                items.push((format!("line{at}"), text(line).into()));
            }
            items.push((
                "buttons".to_owned(),
                row(vec![
                    (
                        "save".to_owned(),
                        button("Save it...", || Message::SaveBundle, context),
                    ),
                    (
                        "cancel".to_owned(),
                        button("Cancel", || Message::CancelBundle, context),
                    ),
                ]),
            ));
        }
    }
    card(column(8.0, items))
}

fn exposure(
    window: &Window,
    needs: &[Need],
    groups: &[Group],
    context: &Context,
) -> Vec<(String, View)> {
    let mut items = vec![("title".to_owned(), title("What of yours is reachable"))];
    for (at, one) in needs.iter().enumerate() {
        items.push((format!("need{at}"), need(one, context)));
    }
    match window.form() {
        Some(made) => {
            items.push(("grant-heading".to_owned(), subtitle("A new grant")));
            items.push(("form".to_owned(), form(window, &made, context)));
        }
        None => items.push((
            "begin".to_owned(),
            button("Make a grant", || Message::Begin, context),
        )),
    }
    for (at, one) in groups.iter().enumerate() {
        items.push((
            format!("group{at}{}", one.heading),
            group(window, one, context),
        ));
    }
    items.push((
        "workstation".to_owned(),
        disclosure(
            window,
            WORKSTATION,
            workstation(window, Importing::Here, context),
            context,
        ),
    ));
    items
}

fn import(outcome: Option<Outcome>, context: &Context) -> View {
    let mut items = Vec::new();
    match outcome {
        None => items.push((
            "asking".to_owned(),
            row(vec![
                (
                    "ring".to_owned(),
                    ProgressRing::new().is_active(true).into(),
                ),
                (
                    "words".to_owned(),
                    text("Asking Hedwig what importing this file would do.").into(),
                ),
            ]),
        )),
        Some(outcome) => {
            items.push(("heading".to_owned(), subtitle(outcome.heading())));
            match &outcome {
                Outcome::Refused(why) => items.push(("why".to_owned(), text(why.clone()).into())),
                Outcome::Would { changes, .. } => {
                    for (at, change) in changes.iter().enumerate() {
                        items.push((format!("change{at}"), text(change.clone()).into()));
                    }
                }
            }
            let mut buttons = Vec::new();
            if let Outcome::Would { changes, .. } = &outcome
                && !changes.is_empty()
            {
                buttons.push((
                    "make".to_owned(),
                    button("Import it", || Message::MakeImport, context),
                ));
            }
            buttons.push((
                "cancel".to_owned(),
                button("Cancel", || Message::CancelImport, context),
            ));
            items.push(("buttons".to_owned(), row(buttons)));
        }
    }
    card(column(8.0, items))
}

/// A change that can let more through, asked in WinUI's dialog. Its answers
/// are the dialog's content, "Cancel" first, because WinUI gives the keyboard
/// to the content's first control before any button of its own
/// (`ContentDialog::SetInitialFocusElement`, WinUI 2.4.0); they stand where
/// WinUI's own layer of answers would, laid out as it lays them: the dialog's
/// fill beneath a line, 24 inside, equal columns 8 apart, "Cancel" at the
/// right. The layer reaches over the 24 the content is inset by and the 1 of
/// WinUI's own line beneath it, and draws that line on its own fill, where
/// WinUI's lies.
fn confirm(asking: &Asking, context: &Context) -> View {
    let answer = |label: &str, column: i32, yes: bool| {
        KeyedView::new(
            label.to_owned(),
            Button::new()
                .grid_column(column)
                .horizontal_alignment(HorizontalAlignment::Stretch)
                .on_click(context.callback(move |()| Message::Confirmed(yes)))
                .content(text(label)),
        )
    };
    let answers = Grid::new()
        .columns([GridLength::STAR, GridLength::STAR])
        .column_spacing(8.0)
        .keyed_children([answer("Cancel", 1, false), answer(&asking.answer, 0, true)]);
    let line = Border::new().height(1.0).background(ThemeBrush::CardStroke);
    let layer = Border::new()
        .background(ThemeBrush::SolidBackground)
        .margin(Thickness::new(-24.0, 24.0, -24.0, -25.0))
        .content(column(
            0.0,
            vec![
                ("line".to_owned(), line.into()),
                (
                    "answers".to_owned(),
                    Border::new()
                        .padding(Thickness::uniform(24.0))
                        .content(answers),
                ),
            ],
        ));
    ContentDialog::new()
        .title(format!("{}?", asking.verb))
        .is_open(asking.open())
        // Only ESCAPE closes it of itself.
        .on_closed(context.callback(|_| Message::Confirmed(false)))
        .content(column(
            0.0,
            vec![
                ("says".to_owned(), text(asking.consequence.clone()).into()),
                ("answers".to_owned(), layer),
            ],
        ))
}

/// What the page shows beneath its heads, by what the core has said.
fn board(window: &Window, context: &Context) -> Vec<(String, View)> {
    let mut board: Vec<(String, View)> = Vec::new();
    match &window.shown.board {
        Board::Off { sentence, act } => {
            board.push(("sentence".to_owned(), title(sentence)));
            let label = match act {
                Some(Act::Start) => Some("Start Hedwig"),
                Some(Act::Retry) => Some("Try again"),
                _ => None,
            };
            if let Some(label) = label {
                board.push((
                    "act".to_owned(),
                    button(label, || Message::Chose(At::Off), context),
                ));
            }
        }
        Board::Asking => board.push((
            "asking".to_owned(),
            row(vec![
                (
                    "ring".to_owned(),
                    ProgressRing::new().is_active(true).into(),
                ),
                (
                    "words".to_owned(),
                    text("Asking Hedwig what is reachable from where.").into(),
                ),
            ]),
        )),
        Board::First(made) => board.extend(first(window, made, context)),
        Board::Exposure { needs, groups } => board.extend(exposure(window, needs, groups, context)),
    }
    board
}

/// `placed` where the window was made where the person left it, which its
/// first size would undo.
pub(crate) fn window(window: &Window, placed: bool, context: &mut Context) -> View {
    let visuals = WindowVisuals::new().backdrop(WindowBackdrop::Mica);
    context.window_visuals(if placed {
        visuals
    } else {
        visuals.client_size(880.0, 760.0)
    });
    let context = &*context;
    let mut items: Vec<(String, View)> = window
        .shown
        .heads
        .iter()
        .enumerate()
        .map(|(at, head)| (format!("head{at}"), need(head, context)))
        .collect();
    if let Some(said) = &window.said {
        items.push((
            "said".to_owned(),
            InfoBar::new()
                .is_open(true)
                .is_closable(true)
                .severity(InfoBarSeverity::Informational)
                .message(said.clone())
                .on_closed(context.callback(|()| Message::Dismiss))
                .into(),
        ));
    }
    if let Some(refused) = &window.shown.refused
        && window.form().is_none_or(|form| form.refused.is_none())
    {
        items.push((
            "refused".to_owned(),
            InfoBar::new()
                .is_open(true)
                .is_closable(false)
                .severity(InfoBarSeverity::Error)
                .title("Hedwig did not do that")
                .message(refused.clone())
                .into(),
        ));
    }
    let held = window.held();
    if !held.is_empty() {
        items.push((
            "held".to_owned(),
            InfoBar::new()
                .is_open(true)
                .is_closable(false)
                .severity(InfoBarSeverity::Warning)
                .title("Made, and held")
                .message(held.join(". "))
                .into(),
        ));
    }
    if window.importing.is_some() {
        items.push(("import".to_owned(), import(window.outcome(), context)));
    }
    if window.bundling == Gathering::Shown {
        let contents = window
            .bundled()
            .map(|bundle| hedwig_view::bundle::contents(&bundle));
        items.push(("bundle".to_owned(), bundle(contents, context)));
    }
    items.extend(board(window, context));
    if let Some(asking) = &window.asking {
        items.push(("confirm".to_owned(), confirm(asking, context)));
    }
    ScrollViewer::new().content(
        Border::new()
            .padding(Thickness::new(32.0, 24.0, 32.0, 32.0))
            .content(column(16.0, items)),
    )
}
