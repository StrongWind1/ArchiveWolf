//! The plan: every search that what is known allows, what each costs and what it rests on,
//! in the order that finds the keys soonest.

use std::collections::HashSet;

use super::headers::Special;
use super::pool::Pool;
use super::proof::worth_of;
use super::search::FILTER_SPAN;
use super::search::MARGIN;
use super::search::Search;
use crate::formats::zip::known::claim::Certainty;
use crate::formats::zip::known::claim::Claim;
use crate::formats::zip::known::claim::Form;
use crate::formats::zip::known::claim::Origin;
use crate::formats::zip::known::claim::Run;
use crate::formats::zip::known::claim::count_as_f64;
use crate::formats::zip::known::claim::expected_candidates;
use crate::formats::zip::known::header::CheckBytes;
use crate::formats::zip::known::set::ByteSet;

/// The most attempts a plan holds. What is beyond is counted and not listed.
pub(crate) const ATTEMPTS_MAX: usize = 10_000;

/// For how many attempts at the head of a plan the candidates are counted while the plan is
/// built. The count of the others is taken from their length until they start.
const COUNTED: usize = 12;

/// The kind of search an attempt runs: a path from knowledge to keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Path {
    /// A run of eight or more known bytes.
    Run,
    /// A run with one byte of which nothing is known: 256 searches.
    ShortRun,
    /// The encryption headers of the Info-ZIP family: the seed of their generator, then the
    /// keys from the headers alone.
    Header,
    /// The encryption headers of a writer that encrypts them once: the seed of their
    /// generator, then a run of twelve.
    HeaderOnce,
}

impl Path {
    /// Every path, in the order of the design.
    pub(crate) const ALL: [Self; 4] = [Self::Run, Self::ShortRun, Self::Header, Self::HeaderOnce];

    /// The name of the path, as `--only` takes it and the events give it.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::ShortRun => "short-run",
            Self::Header => "header",
            Self::HeaderOnce => "header-once",
        }
    }

    /// The path of a name.
    #[must_use]
    pub(crate) fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|path| path.as_str() == name)
    }
}

/// One search of the plan: one entry, one run, the filters that go with it, and an estimate.
#[derive(Debug, Clone)]
pub(crate) struct Attempt {
    /// The entry, by its place in the pool.
    pub target: usize,
    /// The kind of search.
    pub path: Path,
    /// Where the claim behind it comes from.
    pub origin: Origin,
    /// How sure the claim is, with the check bytes that go into the search.
    pub certainty: Certainty,
    /// The claim in the words of a plan.
    pub what: String,
    /// Everything the search takes as known of the entry.
    pub form: Form,
    /// The run it starts from.
    pub run: Run,
    /// The candidates of one search of it: counted when `counted` says so, from its length
    /// otherwise.
    pub candidates: f64,
    /// Whether the candidates were counted by the reduction.
    pub counted: bool,
    /// How likely the search is to find the keys: what orders the plan.
    pub chance: f64,
    /// What the keys that pass the filters cost behind the search, in seconds of one thread:
    /// their proofs, or the question whether each has a short password.
    pub behind: f64,
    /// Whether so little is known of the entry that only keys of a password of six bytes or
    /// fewer can be proved, and no other key is put to the proof.
    pub short_only: bool,
    /// The header path it is, when it is one: then it has no run of its own, and its
    /// candidates stand for the time its searches of seeds take.
    pub special: Option<Special>,
}

impl Attempt {
    /// How many candidates all its searches have together.
    #[must_use]
    pub(crate) fn work(&self) -> f64 {
        self.candidates * count_as_f64(self.run.searches)
    }

    /// The time it takes to its end, at a rate of candidates a second on a count of threads.
    #[must_use]
    pub(crate) fn seconds(&self, rate: f64, threads: usize) -> f64 {
        self.work() / rate.max(1.0) + self.behind / f64::from(u32::try_from(threads.max(1)).unwrap_or(1))
    }

    /// What is known of each byte of its run.
    #[must_use]
    pub(crate) fn run_cells(&self) -> Vec<ByteSet> {
        (self.run.at..self.run.end()).map(|position| self.form.get(position).unwrap_or(ByteSet::ANY)).collect()
    }

    /// The runs it stands for, one for each choice of its bytes that have alternatives, in a
    /// fixed order: the last such byte changes first.
    pub(crate) fn runs(&self) -> impl Iterator<Item = Vec<u8>> + use<> {
        let cells = self.run_cells();
        let choices: Vec<Vec<u8>> = cells.iter().map(|set| set.values().collect()).collect();
        let mut at: Vec<usize> = vec![0; choices.len()];
        let mut done = choices.iter().any(Vec::is_empty);
        std::iter::from_fn(move || {
            if done {
                return None;
            }
            let run: Vec<u8> = choices.iter().zip(&at).filter_map(|(values, index)| values.get(*index).copied()).collect();
            // the next choice, as an odometer turns
            done = true;
            for (index, values) in at.iter_mut().zip(&choices).rev() {
                if *index + 1 < values.len() {
                    *index += 1;
                    done = false;
                    break;
                }
                *index = 0;
            }
            Some(run)
        })
    }
}

/// What a plan is built under.
#[derive(Debug, Clone, Default)]
pub(crate) struct Limits {
    /// Runs through a byte of which nothing is known are taken: `--deep`.
    pub deep: bool,
    /// Only claims that are certain or derived: `--no-guess`.
    pub no_guess: bool,
    /// Only these paths, when any is named: `--only`.
    pub only: Vec<Path>,
    /// Only these entries, when any is named: `--entry`.
    pub entries: Option<HashSet<usize>>,
}

/// An entry of which something is known that no search can start from, and what is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Short {
    /// The entry, by its place in the pool.
    pub target: usize,
    /// The longest stretch of known bytes it has, with its check bytes.
    pub known: u64,
}

/// A plan: the attempts in the order they run, and what was left out of it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Plan {
    /// The attempts, the one that finds the keys soonest for its chance first.
    pub attempts: Vec<Attempt>,
    /// How many more there were than a plan holds.
    pub beyond: usize,
    /// The entries no search can start from.
    pub short: Vec<Short>,
}

/// How likely a claim is to be true, by how sure it is and where it is from. The numbers
/// order the plan and are never printed (section 9.3 of the design).
fn chance(origin: Origin, certainty: Certainty) -> f64 {
    match (certainty, origin) {
        (Certainty::Certain, _) => 0.99,
        (Certainty::Derived, _) => 0.95,
        (Certainty::Likely, _) => 0.6,
        // the user knows more than a table does
        (Certainty::Guess, Origin::User) => 0.5,
        (Certainty::Guess, _) => 0.15,
    }
}

/// The check bytes a search of a claim takes, of the ways the header of an entry may end.
///
/// The first way that gives a run is taken. A later way is taken as well when it is what is
/// left of an earlier one without a byte that may be wrong, or says something else of the last
/// byte: the search that is tried when the first fails. A way that only adds a guessed byte
/// to one that is taken already is left out, since it can find nothing the other does not.
fn check_ways(ways: &[CheckBytes], gives_run: impl Fn(&CheckBytes) -> bool) -> Vec<&CheckBytes> {
    let mut taken: Vec<&CheckBytes> = Vec::new();
    for way in ways {
        if !gives_run(way) {
            continue;
        }
        let adds_to_one = taken.iter().any(|earlier| earlier.form.merged(&way.form).is_some() && earlier.count < way.count);
        if !adds_to_one {
            taken.push(way);
        }
    }
    taken
}

/// Build the plan: every claim of every entry becomes the searches it allows.
///
/// `claims` are those that do not come from the headers of an entry alone: the copies in the
/// directory and what the user gave. `rate` is how many candidates the machine searches in a
/// second.
pub(crate) fn build(pool: &Pool, claims: &[(usize, Claim)], special: Vec<Attempt>, limits: &Limits, rate: f64, threads: usize) -> Plan {
    let mut plan = Plan { attempts: special, ..Plan::default() };
    // the runs that are planned, by entry: where each starts and what it holds
    let mut seen: Vec<(usize, i64, Vec<ByteSet>)> = Vec::new();

    for (index, target) in pool.targets.iter().enumerate() {
        if limits.entries.as_ref().is_some_and(|entries| !entries.contains(&index)) {
            continue;
        }
        // what the method says for certain goes into every search of the entry
        let mut base = Form::new();
        let mut sources: Vec<(Origin, Certainty, &str, usize, &Form)> = Vec::new();
        for claim in &target.facts.claims {
            if claim.origin == Origin::Method && claim.certainty >= Certainty::Derived {
                for form in &claim.forms {
                    base = base.merged(form).unwrap_or(base);
                }
            }
            sources.extend(claim.forms.iter().enumerate().map(|(rank, form)| (claim.origin, claim.certainty, claim.what.as_str(), rank, form)));
        }
        sources.extend(claims.iter().filter(|(target, _)| *target == index).flat_map(|(_, claim)| claim.forms.iter().enumerate().map(|(rank, form)| (claim.origin, claim.certainty, claim.what.as_str(), rank, form))));

        // what is known in a row without any claim: the check bytes, and what the method says
        let mut longest = target.facts.checks.first().and_then(|way| base.merged(&way.form)).map_or(0, |known| known.stretches().iter().map(|&(_, len)| len).max().unwrap_or(0));
        let mut made = false;
        for (origin, certainty, what, rank, form) in sources {
            let Some(with_base) = form.merged(&base) else { continue };
            let run_of = |way: &CheckBytes| with_base.merged(&way.form).and_then(|merged| merged.best_run(limits.deep).map(|run| (merged, run)));
            if let Some(first) = target.facts.checks.first().and_then(|way| with_base.merged(&way.form)) {
                longest = longest.max(first.stretches().iter().map(|&(_, len)| len).max().unwrap_or(0));
            }
            for way in check_ways(&target.facts.checks, |way| run_of(way).is_some()) {
                let Some((merged, run)) = run_of(way) else { continue };
                let certainty = certainty.min(way.certainty);
                let path = if run.holes > 0 { Path::ShortRun } else { Path::Run };
                if (limits.no_guess && certainty < Certainty::Derived) || (!limits.only.is_empty() && !limits.only.contains(&path)) {
                    continue;
                }
                let cells: Vec<ByteSet> = (run.at..run.end()).map(|position| merged.get(position).unwrap_or(ByteSet::ANY)).collect();
                made = true;
                if seen.iter().any(|(of, at, planned)| *of == index && adds_little(*at, planned, run.at, &cells)) {
                    continue;
                }
                seen.push((index, run.at, cells));
                // the forms of a claim are in the order of how usual they are: each is half as
                // likely as the one before it, as far as the plan is concerned
                let usual = 0.5_f64.powi(i32::try_from(rank.min(16)).unwrap_or(16));
                let chance = chance(origin, certainty.max(Certainty::Guess)) * usual * if way.certainty == Certainty::Guess { 0.5 } else { 1.0 };
                let (behind, short_only) = behind(pool, index, &merged, &run);
                let attempt = Attempt { target: index, path, origin, certainty, what: what.to_owned(), form: merged, run, candidates: expected_candidates(run.len), counted: false, chance, behind, short_only, special: None };
                if plan.attempts.len() < ATTEMPTS_MAX {
                    plan.attempts.push(attempt);
                } else {
                    plan.beyond += 1;
                }
            }
        }
        if !made {
            plan.short.push(Short { target: index, known: longest });
        }
    }

    // the order that finds the keys soonest on average: cost divided by chance, smallest first
    let key = |attempt: &Attempt| attempt.seconds(rate, threads) / attempt.chance;
    plan.attempts.sort_by(|a, b| key(a).total_cmp(&key(b)).then(b.certainty.cmp(&a.certainty)).then(a.target.cmp(&b.target)));

    // the candidates of the first attempts are counted, which can change their order
    for attempt in plan.attempts.iter_mut().take(COUNTED) {
        count(pool, attempt);
    }
    plan.attempts.sort_by(|a, b| key(a).total_cmp(&key(b)).then(b.certainty.cmp(&a.certainty)).then(a.target.cmp(&b.target)));
    plan
}

/// What a search costs behind its candidates, in seconds of one thread, and whether it can
/// prove only keys of a short password.
///
/// A key has 96 bits. What is known beside the run of a search leaves two to the power of the
/// bits that are missing as keys that pass every filter. When the proofs of all the entries
/// together would not make such a key proved, each is asked whether it has a password of six
/// bytes or fewer, which
/// takes ten nanoseconds; otherwise each is put to the proof, which is a pass over a stored
/// entry and the head of a packed one.
fn behind(pool: &Pool, index: usize, form: &Form, run: &Run) -> (f64, bool) {
    let Some(target) = pool.targets.get(index) else { return (0.0, false) };
    let bits = form.clipped(-12, run.at.saturating_add(FILTER_SPAN)).bits();
    let others = pool.targets.len().saturating_sub(1).min(64);
    let others_bits = 8.0 * f64::from(u32::try_from(others).unwrap_or(0));
    let passing = (96.0 - bits).exp2();
    // every entry the keys decrypt to its CRC-32 speaks for them, as a search counts it
    let proofs: f64 = pool.targets.iter().take(65).map(worth_of).sum();
    let short_only = bits + others_bits + proofs < 96.0 + MARGIN;
    let each = if short_only {
        11e-9
    } else if target.entry.compression_method == 0 {
        // a wrong key is known by the check bytes of the other entries before the pass over this one
        2e-9 * count_as_f64(target.stream_len()) * (-others_bits).exp2() + 50e-9
    } else {
        1e-6
    };
    (passing * each, short_only)
}

/// Whether a run adds too little to one that is planned already to be a search of its own:
/// it holds the planned run, byte for byte, and does not leave half as few candidates. Such a
/// run can find nothing the planned one does not, and costs nearly as much.
fn adds_little(planned_at: i64, planned: &[ByteSet], at: i64, cells: &[ByteSet]) -> bool {
    let Some(offset) = planned_at.checked_sub(at).and_then(|offset| usize::try_from(offset).ok()) else { return false };
    let holds = cells.get(offset..offset.saturating_add(planned.len())).is_some_and(|shared| shared == planned);
    holds && expected_candidates(cells.len() as u64) > 0.5 * expected_candidates(planned.len() as u64)
}

/// Count the candidates of an attempt with the reduction, when it is one search. An attempt
/// of several searches keeps the count that its length gives: each of them would have to be
/// reduced.
pub(crate) fn count(pool: &Pool, attempt: &mut Attempt) {
    if attempt.counted || attempt.run.searches != 1 || attempt.special.is_some() {
        return;
    }
    let Some(run) = attempt.runs().next() else { return };
    if let Some(search) = Search::new(pool, attempt.target, &attempt.form, attempt.run.at, &run, 1) {
        attempt.candidates = count_as_f64(search.candidates() as u64);
        attempt.counted = true;
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::formats::zip::known::claim::Cells;

    fn pool(fixtures: &[&str]) -> Pool {
        let paths: Vec<PathBuf> = fixtures.iter().map(|name| PathBuf::from(format!("tests/fixtures/zip-crypto/{name}"))).collect();
        Pool::read(&paths, &|_| None).unwrap()
    }

    #[test]
    fn the_name_of_a_stored_entry_makes_an_attempt_and_a_packed_one_none() {
        // `advice.jpg` is packed and `spiral.svg` stored: the row of XML gives a run of twenty
        let pool = pool(&["bkcrack-src_secrets.zip"]);
        let plan = build(&pool, &[], Vec::new(), &Limits::default(), 10_000.0, 16);
        // the plain start of an XML file, the same behind a byte order mark, and with the other quote
        assert_eq!(plan.attempts.iter().map(|attempt| attempt.run.len).collect::<Vec<_>>(), [20, 23, 20]);
        let first = &plan.attempts[0];
        assert_eq!((first.target, first.path, first.origin, first.certainty), (1, Path::Run, Origin::Name, Certainty::Likely));
        assert_eq!((first.run.at, first.run.searches, first.what.as_str()), (-1, 1, "signature of an XML file"));
        assert!(first.counted && first.candidates > 100_000.0 && first.candidates < 2_000_000.0);
        // the packed entry has its check byte and nothing else
        assert_eq!(plan.short, [Short { target: 0, known: 1 }]);
        assert_eq!(plan.beyond, 0);
    }

    #[test]
    fn a_claim_of_the_user_is_planned_before_a_guess_of_the_tool_that_costs_as_much() {
        let pool = pool(&["bkcrack-src_secrets.zip"]);
        let user = Claim::new(Origin::User, Certainty::Certain, "matched file", Form::bytes(0, &[0x41; 600]));
        let plan = build(&pool, &[(1, user)], Vec::new(), &Limits::default(), 10_000.0, 16);
        assert_eq!((plan.attempts[0].origin, plan.attempts[0].certainty, plan.attempts[0].run.len), (Origin::User, Certainty::Certain, 601));
        // only what is certain or derived
        let sure = build(&pool, &[], Vec::new(), &Limits { no_guess: true, ..Limits::default() }, 10_000.0, 16);
        assert!(sure.attempts.is_empty());
        // only one entry, and only one path
        let one = build(&pool, &[], Vec::new(), &Limits { entries: Some(HashSet::from([0])), ..Limits::default() }, 10_000.0, 16);
        assert!(one.attempts.is_empty() && one.short.len() == 1);
        assert!(build(&pool, &[], Vec::new(), &Limits { only: vec![Path::ShortRun], ..Limits::default() }, 10_000.0, 16).attempts.is_empty());
    }

    #[test]
    fn a_hole_is_planned_only_when_asked_and_is_a_short_run() {
        let pool = pool(&["bkcrack-src_secrets.zip"]);
        // six bytes of the packed entry: with its check byte seven in a row
        let six = Claim::new(Origin::User, Certainty::Guess, "bytes given on the command line", Form::bytes(0, b"sixsix"));
        let limits = Limits { entries: Some(HashSet::from([0])), ..Limits::default() };
        let plain = build(&pool, &[(0, six.clone())], Vec::new(), &limits, 10_000.0, 16);
        assert!(plain.attempts.is_empty());
        assert_eq!(plain.short, [Short { target: 0, known: 7 }]);
        let deep = build(&pool, &[(0, six)], Vec::new(), &Limits { deep: true, ..limits }, 10_000.0, 16);
        assert_eq!(deep.attempts.len(), 1);
        assert_eq!((deep.attempts[0].path, deep.attempts[0].run.searches, deep.attempts[0].run.len), (Path::ShortRun, 256, 8));
        assert!(!deep.attempts[0].counted);
        assert_eq!(deep.attempts[0].runs().count(), 256);
    }

    #[test]
    fn the_runs_of_an_attempt_are_every_choice_of_its_alternatives_in_a_fixed_order() {
        let pool = pool(&["bkcrack-src_secrets.zip"]);
        let mut form = Form::bytes(0, b"GIF8");
        assert!(form.add(4, Cells::Sets(vec![ByteSet::from_values([b'7', b'9'])])) && form.add(5, Cells::Bytes(b"a_and_more".to_vec())));
        let claim = Claim::new(Origin::User, Certainty::Guess, "two ways", form);
        let plan = build(&pool, &[(1, claim)], Vec::new(), &Limits { entries: Some(HashSet::from([1])), only: vec![Path::Run], ..Limits::default() }, 10_000.0, 16);
        let attempt = plan.attempts.iter().find(|attempt| attempt.origin == Origin::User).unwrap();
        let runs: Vec<Vec<u8>> = attempt.runs().collect();
        assert_eq!(runs.len(), 2);
        assert_eq!((&runs[0][1..], &runs[1][1..]), (&b"GIF87a_and_more"[..], &b"GIF89a_and_more"[..]));
        assert_eq!(attempt.run.searches, 2);
        assert!((attempt.work() - 2.0 * attempt.candidates).abs() < 1e-6);
    }

    #[test]
    fn a_path_has_one_name() {
        assert_eq!(Path::ALL.map(Path::as_str), ["run", "short-run", "header", "header-once"]);
        assert!(Path::ALL.into_iter().all(|path| Path::named(path.as_str()) == Some(path)) && Path::named("guess").is_none());
    }
}
