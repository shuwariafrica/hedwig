//! Reading the process at the other end of a connection.
//!
//! Each kind of connection finds the process its own way - the control pipe
//! names its client, a loopback connection is looked up in the system's
//! table - and what is read of the process then is the same: where it
//! stands, the program it runs, and the channel whose job it is in. The
//! model's one policy decides on that and on nothing else.

use std::net::TcpStream;
use std::sync::Arc;

use hedwig_model::text::Location;
use hedwig_model::trail::{ConnectionId, Origin, Peer};
use hedwig_win::endpoint::owner;
use hedwig_win::process::{Job, Process};

use crate::channel::Jobs;
use crate::serve::integrity;

/// The channel whose job holds `process`, asked of the kernel now.
fn channel(process: &Process, jobs: &Jobs) -> Option<ConnectionId> {
    // The jobs are taken out first, so nothing is asked of the system while
    // the deciding thread could be waiting to start or end a channel.
    let live: Vec<(ConnectionId, Arc<Job>)> = jobs
        .lock()
        .map(|jobs| {
            jobs.iter()
                .map(|(connection, job)| (*connection, Arc::clone(job)))
                .collect()
        })
        .unwrap_or_default();
    live.into_iter()
        .find(|(_, job)| job.includes(process).unwrap_or(false))
        .map(|(connection, _)| connection)
}

fn place(process: &Process, jobs: &Jobs) -> (Option<Location>, Option<ConnectionId>) {
    let program = process
        .program()
        .ok()
        .and_then(|program| Location::try_from(program.to_string_lossy().as_ref()).ok());
    (program, channel(process, jobs))
}

/// The program the process numbered `process` runs and the channel it is in.
/// Neither is known of a process Windows does not let this one ask about.
pub fn placed(process: u32, jobs: &Jobs) -> (Option<Location>, Option<ConnectionId>) {
    Process::open(process).map_or((None, None), |process| place(&process, jobs))
}

/// What is read of whatever connected to a forward's end: the process the
/// system's table of connections names as the owner of the other end, its
/// standing from its own token, its program and its channel. `None` when the
/// table names nobody, the process has gone, or its token cannot be read.
pub fn knocker(stream: &TcpStream, jobs: &Jobs) -> Option<Peer> {
    let number = owner(stream).ok()??;
    let process = Process::open(number).ok()?;
    let standing = process.token().ok()?.standing().ok()?;
    let (program, channel) = place(&process, jobs);
    Some(Peer {
        origin: Origin {
            process: number,
            logon: standing.logon,
            session: standing.session,
            integrity: integrity(standing.integrity),
        },
        program,
        channel,
    })
}
