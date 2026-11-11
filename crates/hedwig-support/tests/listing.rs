//! A route's listing run for real: Windows' own command processor stands for
//! a platform's program, found on the search path as any lister is, run in a
//! job of its own, its output read whole and its errors kept as the account.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "tests"
)]

use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use hedwig_core::dispatch::Input;
use hedwig_core::listing::Listings;
use hedwig_core::run::Message;
use hedwig_model::remote::Lister;
use hedwig_model::text::{Address, Name, Program, Verbatim, Words};
use hedwig_win::start::Environment;

const WAIT: Duration = Duration::from_secs(20);

fn listings() -> (Listings, Receiver<Message>) {
    let (messages, told) = mpsc::channel();
    let search = std::env::var_os("PATH").unwrap();
    (Listings::new(search, Environment::own(), messages), told)
}

/// A lister that has the command processor run `command`.
fn lister(program: &str, command: &str, header: u8) -> Lister {
    Lister {
        program: Program::try_from(program).unwrap(),
        arguments: vec![
            Verbatim::try_from("/d").unwrap(),
            Verbatim::try_from("/c").unwrap(),
            Verbatim::try_from(command).unwrap(),
        ],
        header,
    }
}

fn listed(told: &Receiver<Message>) -> (Name, Result<Vec<Address>, Words>) {
    match told.recv_timeout(WAIT).expect("the listing answers") {
        Message::Input(Input::Listed { route, listed }) => (route, listed),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_listing_is_read_whole_after_its_heading() {
    let (mut listings, told) = listings();
    let route = Name::try_from("lab").unwrap();
    let command = "echo NAME& echo dev/build& echo.& echo dev/web";
    listings.list(route.clone(), lister("cmd", command, 1));
    let (said, found) = listed(&told);
    assert_eq!(said, route);
    let expected: Vec<Address> = ["dev/build", "dev/web"]
        .into_iter()
        .map(|address| Address::try_from(address).unwrap())
        .collect();
    assert_eq!(found, Ok(expected));
}

/// A listing that fails is its last error line; one that prints what is
/// not an address is refused whole, naming the line; one whose program is
/// on no folder says so.
#[test]
fn a_listing_that_cannot_be_read_says_why() {
    let (mut listings, told) = listings();
    let route = Name::try_from("lab").unwrap();
    let failing = "echo HTTP 401: Bad credentials 1>&2& exit /b 1";
    listings.list(route.clone(), lister("cmd", failing, 0));
    let (_, found) = listed(&told);
    assert_eq!(
        found,
        Err(Words::try_from("HTTP 401: Bad credentials").unwrap())
    );

    listings.list(
        route.clone(),
        lister("cmd", "echo dev/build& echo two words", 0),
    );
    let (_, found) = listed(&told);
    let account = found.unwrap_err();
    assert!(
        account.as_str().starts_with("line 2 of the listing"),
        "{account}"
    );

    listings.list(route, lister("no-such-lister", "list", 0));
    let (_, found) = listed(&told);
    assert_eq!(
        found,
        Err(Words::try_from("no-such-lister is not in any folder on the search path").unwrap())
    );
}

/// A listing ended for overrunning is ended with what it started, and says
/// nothing afterwards.
#[test]
fn a_listing_ended_says_nothing() {
    let (mut listings, told) = listings();
    let route = Name::try_from("lab").unwrap();
    listings.list(route.clone(), lister("cmd", "ping -n 30 127.0.0.1 >NUL", 0));
    std::thread::sleep(Duration::from_millis(500));
    listings.end(&route);
    assert!(
        told.recv_timeout(Duration::from_secs(3)).is_err(),
        "an ended listing is not heard from"
    );
}
