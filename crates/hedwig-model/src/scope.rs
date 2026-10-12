//! The three kinds of statement, who makes them, and the one way each kind
//! resolves.
//!
//! A statement about how Hedwig behaves is a choice, a limit or a set. A
//! choice is one value preferred among several: [`choose`] gives the nearest
//! source that says anything, and inside that source the most specific
//! statement. A limit is a bound in the order the thing already has:
//! [`at_least`] and [`at_most`] hold a choice at every limit that covers it,
//! however widely the limit was stated. A set is admitted whole or refused:
//! [`admitted`]. Nothing else in the model decides between two statements.

use std::cmp::Ordering;

use crate::capability::Exposure;

/// Whom an organisation states something for: everyone who signs in at this
/// machine, or this person wherever the statement follows them. Of the two
/// the person's is the nearer to the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Audience {
    Machine,
    Person,
}

/// Where a choice comes from, farthest from the work first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// What ships: the last thing a choice falls to.
    Ships,
    /// The organisation's starting point, which the person may replace.
    Start(Audience),
    /// The person's own statements, and what they said on a connection.
    Person,
}

/// Who holds a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Holder {
    /// Whoever answers for the organisation, over everyone in scope.
    Organisation(Audience),
    /// The person with time to think, over what the same person can loosen
    /// in one gesture mid-work.
    Person,
}

/// A scope, compared with another that covers the same thing.
pub trait Specific {
    /// `Greater` when this is the more specific of the two, `Equal` when
    /// they select equally narrowly, and `None` when each is specific where
    /// the other is not: a statement naming a key against one naming a
    /// remote.
    fn specificity(&self, other: &Self) -> Option<Ordering>;
}

/// A value a choice can take, ordered by how much it asks of the person or
/// keeps from a remote. `Greater` is the stricter.
pub trait Strict {
    fn strictness(&self, other: &Self) -> Ordering;
}

impl<T: Strict + ?Sized> Strict for &T {
    fn strictness(&self, other: &Self) -> Ordering {
        (**self).strictness(other)
    }
}

/// One source's answer: of the statements that cover the subject, those that
/// no other is more specific than, and of those the strictest.
///
/// The order the statements come in changes nothing.
pub fn nearest<S, V>(covering: &(impl Iterator<Item = (S, V)> + Clone)) -> Option<(S, V)>
where
    S: Specific + Ord,
    V: Strict,
{
    covering
        .clone()
        .filter(|(scope, _)| {
            !covering
                .clone()
                .any(|(other, _)| other.specificity(scope) == Some(Ordering::Greater))
        })
        .max_by(|(scope, value), (other, against)| {
            value.strictness(against).then_with(|| scope.cmp(other))
        })
}

/// A choice: the nearest source that says anything decides - the person,
/// then what the organisation starts this person with, then what it starts
/// this machine with. `None` is every source silent, and what ships decides.
///
/// A narrower statement may be the laxer one, and a person's statement,
/// however wide, is never relaxed by a starting point, however narrow.
pub fn choose<S, V>(
    person: &(impl Iterator<Item = (S, V)> + Clone),
    for_person: &(impl Iterator<Item = (S, V)> + Clone),
    for_machine: &(impl Iterator<Item = (S, V)> + Clone),
) -> Option<(Tier, S, V)>
where
    S: Specific + Ord,
    V: Strict,
{
    let from = |tier: Tier| move |(scope, value)| (tier, scope, value);
    nearest(person)
        .map(from(Tier::Person))
        .or_else(|| nearest(for_person).map(from(Tier::Start(Audience::Person))))
        .or_else(|| nearest(for_machine).map(from(Tier::Start(Audience::Machine))))
}

/// A limit from below: `chosen` held at every floor that covers it. The
/// second value is the limit that moved the choice, and `None` when the
/// choice was already inside them all and is left as it was made.
pub fn at_least<V, L>(chosen: V, floors: impl IntoIterator<Item = (L, V)>) -> (V, Option<L>)
where
    V: Ord + Copy,
    L: Ord,
{
    let strictest = floors
        .into_iter()
        .max_by(|(limit, floor), (other, against)| {
            floor.cmp(against).then_with(|| limit.cmp(other))
        });
    match strictest {
        Some((limit, floor)) if floor > chosen => (floor, Some(limit)),
        _ => (chosen, None),
    }
}

/// A limit from above: `chosen` held at every ceiling that covers it.
pub fn at_most<V, L>(chosen: V, ceilings: impl IntoIterator<Item = (L, V)>) -> (V, Option<L>)
where
    V: Ord + Copy,
    L: Ord,
{
    let strictest = ceilings
        .into_iter()
        .min_by(|(limit, most), (other, against)| most.cmp(against).then_with(|| limit.cmp(other)));
    match strictest {
        Some((limit, most)) if most < chosen => (most, Some(limit)),
        _ => (chosen, None),
    }
}

/// A set: `exposure` is admitted whole or refused, never trimmed to what a
/// limit would allow. Each limit comes with the members it withholds here.
///
/// # Errors
///
/// The limit that withholds a member of `exposure`, and the members it
/// withholds.
pub fn admitted<L: Ord>(
    exposure: Exposure,
    withheld: impl IntoIterator<Item = (L, Exposure)>,
) -> Result<(), (L, Exposure)> {
    withheld
        .into_iter()
        .filter(|(_, members)| !exposure.common(*members).is_empty())
        .min_by(|(limit, _), (other, _)| limit.cmp(other))
        .map_or(Ok(()), |(limit, members)| {
            Err((limit, exposure.common(members)))
        })
}
