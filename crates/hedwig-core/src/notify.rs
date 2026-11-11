//! What serves a notices capability: the remote's own `curl`, which
//! `HEDWIG_NOTIFY` names, posts what a job there says; the core keeps it for
//! the person, as that remote's words, and answers at once.
//!
//! The post is read as the browser relay reads one, its body bounded by the
//! longest remark. Nothing waits on the person: a notice is kept whether or
//! not anyone is there, and `curl` is told only whether it was.

use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use hedwig_model::refusal::Refusal;
use hedwig_model::text::{REMARK, Remark};

use crate::browse::{Malformed, request};
use crate::relay::{Event, QUEUED, Relayed, Settle};

/// What `curl` is told. `-f` makes every answer but the first a failed
/// command, with the status in its words, so a hook knows its notice was not
/// kept and why: `413` too long, `429` too fast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Kept,
    Malformed,
    TooLong,
    Refused,
    TooMany,
}

impl Answer {
    pub fn bytes(self) -> &'static [u8] {
        match self {
            Answer::Kept => b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n",
            Answer::Malformed => {
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Answer::TooLong => {
                b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Answer::Refused => {
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
            Answer::TooMany => {
                b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            }
        }
    }

    /// The answer for how the deciding thread settled the notice.
    pub fn of(word: Option<&Result<(), Refusal>>) -> Answer {
        match word {
            Some(Ok(())) => Answer::Kept,
            Some(Err(Refusal::Hushed { .. })) => Answer::TooMany,
            Some(Err(_)) | None => Answer::Refused,
        }
    }
}

/// Reads `curl`'s post and cleans what it says into a remark.
///
/// # Errors
///
/// [`Malformed`], saying why it is not a notice.
pub fn said(client: &mut TcpStream) -> Result<Remark, Malformed> {
    let text = request(client, REMARK)?;
    Remark::cleaned(&text).map_err(|_| Malformed::Text)
}

/// Carries one admitted connection: reads the notice, tells the deciding
/// thread, and answers `curl` with its word. Returns where that word is put.
pub fn carry(client: TcpStream, tell: impl Fn(Relayed) + Send + 'static) -> Arc<Settle> {
    let (events, queue) = mpsc::sync_channel(QUEUED);
    let settle = Arc::new(Settle::new(events));
    let held = Arc::clone(&settle);
    thread::spawn(move || {
        run(client, &tell, &queue, &held);
        tell(Relayed::Ended);
    });
    settle
}

fn run(mut client: TcpStream, tell: &impl Fn(Relayed), queue: &Receiver<Event>, settle: &Settle) {
    let answer = |client: &mut TcpStream, answer: Answer| {
        let _ = client.write_all(answer.bytes());
        let _ = client.shutdown(Shutdown::Both);
    };
    let _ = client.set_read_timeout(Some(crate::PATIENCE));
    let remark = match said(&mut client) {
        Ok(remark) => remark,
        Err(malformed) => {
            tell(Relayed::Misread(malformed));
            let refused = if malformed == Malformed::Long {
                Answer::TooLong
            } else {
                Answer::Malformed
            };
            return answer(&mut client, refused);
        }
    };
    tell(Relayed::Says(remark));
    let word = crate::relay::wait(queue, settle);
    answer(&mut client, Answer::of(word.as_ref()));
}
