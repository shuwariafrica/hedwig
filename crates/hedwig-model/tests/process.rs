//! What passes between Hedwig's own processes: the statuses they exit with,
//! the record a client looks for, and the lines between a supervisor and the
//! core it runs.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::process::{CoreState, Exit, Instance, Order, Report, Running};
use hedwig_model::text::PipeName;
use hedwig_model::trail::Breakdown;
use hedwig_model::wire::{line, read};

/// A status names one exit and an exit one status; only the person's stop
/// and a record already held leave nothing to start again.
#[test]
fn every_exit_has_its_own_status_and_says_whether_another_core_follows() {
    for exit in Exit::ALL {
        assert_eq!(Exit::from_status(u32::from(exit.status())), Some(exit));
    }
    let mut statuses: Vec<u8> = Exit::ALL.iter().map(|exit| exit.status()).collect();
    statuses.dedup();
    assert_eq!(statuses.len(), Exit::ALL.len());
    assert_eq!(Exit::Stopped.status(), 0);

    // A panic, an access violation and a forced end are not Hedwig's own
    // exits, so they are breakdowns.
    for status in [101, 0xc000_0005, 0xc000_013a, 1] {
        assert_eq!(Exit::from_status(status), None);
    }
    let follows: Vec<Exit> = Exit::ALL
        .into_iter()
        .filter(|exit| exit.restarts())
        .collect();
    assert_eq!(
        follows,
        [Exit::Usage, Exit::Storage, Exit::Link, Exit::Pipe]
    );
}

/// The record is one line of the written form, so a script reads it with
/// what it already has.
#[test]
fn the_record_reads_as_it_is_specified() {
    let record = Running {
        supervisor: Instance {
            process: 4100,
            created: 134_037_216_000_000_000,
        },
        core: CoreState::Serving {
            pipe: PipeName::try_from("hedwig.9f86d081884c7d659a2feaa0c55ad015").unwrap(),
            process: 4200,
        },
    };
    let text = r#"{"supervisor":{"process":4100,"created":134037216000000000},"core":{"serving":{"pipe":"hedwig.9f86d081884c7d659a2feaa0c55ad015","process":4200}}}"#;
    assert_eq!(line(&record), text);
    assert_eq!(read::<Running>(text), Ok(record.clone()));

    let restarting = Running {
        core: CoreState::Restarting {
            cause: Breakdown::Exited { status: 4 },
            said: "the trail could not be written".to_owned(),
        },
        ..record
    };
    assert_eq!(
        line(&restarting),
        r#"{"supervisor":{"process":4100,"created":134037216000000000},"core":{"restarting":{"cause":{"exited":{"status":4}},"said":"the trail could not be written"}}}"#
    );
    // A record that names anything but a pipe of the core's own form is not
    // read at all.
    let tampered = text.replace(
        "hedwig.9f86d081884c7d659a2feaa0c55ad015",
        "openssh-ssh-agent",
    );
    assert_eq!(
        read::<Running>(&tampered).unwrap_err().to_string(),
        "core.serving.pipe is not accepted: it is not `hedwig.` and thirty-two hexadecimal digits"
    );
}

#[test]
fn the_lines_between_a_supervisor_and_its_core_read_as_they_are_specified() {
    assert_eq!(
        line(&Order::Begin { after: None }),
        r#"{"begin":{"after":null}}"#
    );
    assert_eq!(
        line(&Order::Begin {
            after: Some(Breakdown::Hung)
        }),
        r#"{"begin":{"after":"hung"}}"#
    );
    assert_eq!(line(&Order::Ping), r#""ping""#);
    assert_eq!(line(&Report::Pong), r#""pong""#);
    assert_eq!(
        read::<Report>(r#"{"ready":{"pipe":"hedwig.9f86d081884c7d659a2feaa0c55ad015"}}"#),
        Ok(Report::Ready {
            pipe: PipeName::try_from("hedwig.9f86d081884c7d659a2feaa0c55ad015").unwrap()
        })
    );
    assert!(read::<Order>(r#""pong""#).is_err());
}
