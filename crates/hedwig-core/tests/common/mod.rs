//! A folder of the suite's own, gone afterwards.

#![allow(dead_code, reason = "each suite uses a different part")]
#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test support")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use hedwig_core::store::Places;

static NEXT: AtomicU32 = AtomicU32::new(0);

pub(crate) struct Folder(PathBuf);

impl Folder {
    pub(crate) fn new(purpose: &str) -> Folder {
        let mut drawn = [0u8; 4];
        hedwig_win::random::fill(&mut drawn).unwrap();
        let path = std::env::temp_dir().join(format!(
            "hedwig-design-{purpose}-{}-{}-{:08x}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            u32::from_le_bytes(drawn)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Folder(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn places(&self) -> Places {
        Places::at(self.0.clone()).unwrap()
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What a Linux remote's readiness reports when every far end in `serving`
/// is free: a socket's path with nothing at it, a port nothing listens on.
pub(crate) fn placing(serving: &[hedwig_model::trail::Serving]) -> hedwig_core::dispatch::Told {
    use hedwig_core::survey::{Answer, At, Dialect, Place, Report};
    use hedwig_model::trail::Binding;
    let answers = serving
        .iter()
        .map(|serving| {
            let answer = match &serving.binding {
                Binding::Socket(path) | Binding::SocketFile { file: path, .. } => Answer {
                    place: Some(Place {
                        path: path.as_str().as_bytes().to_vec(),
                        at: Some(At::Free),
                        ..Place::default()
                    }),
                    ..Answer::default()
                },
                Binding::Port(port) => Answer {
                    listeners: [(*port, false)].into_iter().collect(),
                    ..Answer::default()
                },
            };
            (serving.capability.clone(), answer)
        })
        .collect();
    hedwig_core::dispatch::Told::Surveyed {
        report: Ok(Report {
            dialect: Dialect::Posix,
            kernel: hedwig_model::text::Kernel::try_from("Linux").unwrap(),
            shell: b"/bin/bash".to_vec(),
            answers,
            issued: None,
        }),
        theirs: Vec::new(),
    }
}

/// `step`, with every read of a `GnuPG` source it asks for answered as a
/// source holding no keys answers, and what the core did next added: for a
/// suite about something other than the keys.
pub(crate) fn keyed(
    core: &mut hedwig_core::dispatch::Core,
    mut step: hedwig_core::dispatch::Step,
    now: hedwig_core::dispatch::Now,
) -> hedwig_core::dispatch::Step {
    use hedwig_core::dispatch::{Effect, Input, Told};
    loop {
        let mut reads = Vec::new();
        step.effects.retain(|effect| match effect {
            Effect::Read {
                connection,
                sources,
            } => {
                reads.push((*connection, sources.clone()));
                false
            }
            _ => true,
        });
        if reads.is_empty() {
            return step;
        }
        for (connection, sources) in reads {
            let read = sources
                .into_iter()
                .map(|(capability, _)| (capability, Ok(hedwig_core::keys::Read::default())))
                .collect();
            let next = core.step(
                Input::Channel {
                    connection,
                    told: Told::Read { read },
                },
                now,
            );
            step.entries.extend(next.entries);
            step.effects.extend(next.effects);
        }
    }
}
