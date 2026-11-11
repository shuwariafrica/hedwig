//! One policy admits a connection at every door, on what was read of the
//! process at its other end.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]

use hedwig_model::config::Configuration;
use hedwig_model::gate::{Admitted, Door, World};
use hedwig_model::refusal::Refusal;
use hedwig_model::text::Location;
use hedwig_model::trail::{ChannelEnd, ConnectionId, Event, Peer, Seq};

mod support;
use support::{DESKTOP, OVER_SSH, Trail, catalogue, remote};

/// A process in the job of `channel`, or in none.
fn peer(channel: Option<ConnectionId>) -> Peer {
    Peer {
        origin: OVER_SSH,
        program: Some(Location::try_from(r"C:\Windows\System32\OpenSSH\ssh.exe").unwrap()),
        channel,
    }
}

/// Every door, against every thing that can be read of a process: nothing,
/// a process in no channel, one in the door's own channel, one in another,
/// and one in a channel that is over.
#[test]
fn a_connection_is_admitted_by_the_channel_it_comes_from() {
    let catalogue = catalogue();
    let configuration = Configuration::default();
    let (build, lab) = (remote("ssh", "build"), remote("ssh", "lab"));
    let mut trail = Trail::started();
    let first = trail.open(&build, "linux");
    let second = trail.open(&lab, "linux");
    let over = trail.open(&remote("ssh", "old"), "linux");
    trail.push(Event::Down {
        connection: over,
        end: ChannelEnd::Closed,
    });
    let never = ConnectionId(Seq(9_000));
    let state = trail.state();
    let world = World {
        catalogue: &catalogue,
        configuration: &configuration,
        state: &state,
    };
    let stranger = Refusal::NoChannel {
        process: OVER_SSH.process,
        program: peer(None).program,
    };

    // A forward's end admits the processes of its own channel and no other.
    let door = Door::Forward(first);
    assert_eq!(
        world.admit(door, Some(&peer(Some(first)))),
        Ok(Admitted::Remote(build.clone()))
    );
    for outside in [None, Some(second), Some(over), Some(never)] {
        assert_eq!(
            world.admit(door, Some(&peer(outside))),
            Err(stranger.clone()),
            "{outside:?}"
        );
    }
    assert_eq!(world.admit(door, None), Err(Refusal::Unattributable));
    for gone in [over, never] {
        assert_eq!(
            world.admit(Door::Forward(gone), Some(&peer(Some(gone)))),
            Err(Refusal::UnknownConnection(gone))
        );
    }

    // The control pipe refuses nobody it could read, and says whose process
    // it is.
    assert_eq!(
        world.admit(Door::Control, Some(&Peer::from(DESKTOP))),
        Ok(Admitted::Person)
    );
    assert_eq!(
        world.admit(Door::Control, Some(&peer(Some(second)))),
        Ok(Admitted::Remote(lab))
    );
    for ended in [over, never] {
        assert_eq!(
            world.admit(Door::Control, Some(&peer(Some(ended)))),
            Ok(Admitted::Person)
        );
    }
    assert_eq!(
        world.admit(Door::Control, None),
        Err(Refusal::Unattributable)
    );
}

/// The refusal names the program as well as the process, because the number
/// means nothing once the process has gone.
#[test]
fn a_refusal_at_a_forwards_end_names_the_program() {
    let named = Refusal::NoChannel {
        process: 7312,
        program: Some(Location::try_from(r"C:\Users\dev\bin\probe.exe").unwrap()),
    };
    assert_eq!(
        named.to_string(),
        r"C:\Users\dev\bin\probe.exe, process 7312, connected without belonging to the channel Hedwig started there"
    );
    let unnamed = Refusal::NoChannel {
        process: 7312,
        program: None,
    };
    assert_eq!(
        unnamed.to_string(),
        "process 7312 connected without belonging to the channel Hedwig started there"
    );
    assert!(named.raises_attention() && unnamed.raises_attention());
}
