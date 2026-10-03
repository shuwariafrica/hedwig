//! Who holds a source on this workstation, read once per reach after the
//! core's own connection is made and before any of a remote's bytes are sent.

use std::sync::OnceLock;

use hedwig_model::holder::{Reading, Rights, SignedIn, SourceHolder, Standing, whose};
use hedwig_model::text::{Location, ServiceName};
use hedwig_win::holder::read;
use hedwig_win::services::services_in;
use hedwig_win::token::{Sid, Token};

/// The account the core runs as, read once: the person, whose own pipe
/// descriptor a holder's token is checked against.
fn person() -> Option<&'static Sid> {
    static PERSON: OnceLock<Option<Sid>> = OnceLock::new();
    PERSON
        .get_or_init(|| Token::own().and_then(|token| token.user()).ok())
        .as_ref()
}

/// `process` as the core can read it, which holds a source; `None` where
/// neither its program nor its session can be read, so it has gone.
pub fn of(process: u32) -> Option<SourceHolder> {
    let person = person()?;
    let read = read(process, person);
    let program = Location::try_from(read.program?.as_str()).ok()?;
    let session = read.session?;
    let token = read.token.map(|token| Reading {
        standing: match token.standing {
            hedwig_win::holder::Standing::Person => Standing::Person,
            hedwig_win::holder::Standing::Confined => Standing::Confined,
            hedwig_win::holder::Standing::Another => Standing::Another,
        },
        logon: token.logon,
        signed_in: if token.over_the_network {
            SignedIn::OverTheNetwork
        } else {
            SignedIn::Locally
        },
        rights: if token.elevated {
            Rights::Administrator
        } else {
            Rights::Standard
        },
    });
    // A list that cannot be read names no service, so the holder fails
    // closed.
    let whose = whose(token, || {
        services_in(process)
            .unwrap_or_default()
            .iter()
            .filter_map(|name| ServiceName::try_from(name.as_str()).ok())
            .collect()
    });
    Some(SourceHolder {
        program,
        session,
        whose,
    })
}
