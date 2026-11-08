//! What choosing something on a surface does.

use hedwig_model::protocol::Request;
use hedwig_model::remote::RemoteId;

use crate::define::Draft;

/// An act a surface offers. Every one that reaches the core is a request the
/// core answers; none is carried out by the surface itself.
#[derive(Debug, PartialEq, Eq)]
pub enum Act {
    /// Bring up what is waiting for an answer.
    Answer,
    /// Open the window, at a remote when one is named.
    Open(Option<RemoteId>),
    /// Start hedwig.
    Start,
    /// Read the record again and try the core once more.
    Retry,
    /// Close the icon. Hedwig keeps running.
    Leave,
    /// Carried out at once: it reduces what is reachable, asks more of the
    /// person, or only looks.
    Send(Request),
    /// Put to the person first, with what it will do: it widens what is
    /// reachable, or ends something they would have to set up again.
    Confirm {
        request: Request,
        consequence: String,
        /// What carries it out where it is put to the person: the act in a
        /// couple of words, a button that is never cut. The whole label is
        /// the question asked.
        answer: String,
    },
    /// Stop Hedwig, once the person has confirmed what that ends.
    Stop { consequence: String },
    /// Begin defining what the work in hand needs, filled in from it.
    Define(Box<Draft>),
}
