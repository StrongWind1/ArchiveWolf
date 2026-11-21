//! `attack zip-crypto`: the keys of a ZIP archive under traditional encryption, without the
//! password.
//!
//! The command reads the archives, gathers everything that is known of their encrypted
//! streams, builds a plan of searches with what each costs, prints it, and runs it under a
//! budget. Keys are a result only when they decrypt an entry to the CRC-32 its archive
//! stores. No password is guessed or tested: the password plays no part.

mod catalogue;
mod deflate;
mod headers;
mod pack;
mod packed;
mod plan;
mod pool;
mod proof;
mod report;
mod search;
pub mod seed;
mod speed;
mod state;
mod user;
mod write;

use std::collections::HashSet;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use archivewolf_zip_crypto::Keys;
use archivewolf_zip_crypto::short_passwords;
use rayon::iter::IntoParallelRefIterator as _;
use rayon::iter::ParallelIterator as _;
use serde_json::json;

use self::plan::Attempt;
use self::plan::Limits;
use self::plan::Path;
use self::plan::Plan;
use self::pool::Pool;
use self::pool::Target;
use self::proof::Proof;
use self::proof::after_header;
use self::proof::prove;
use self::report::Voice;
use self::report::grouped;
use self::report::span;
use self::report::whole;
use self::search::Control;
use self::search::Found;
use self::search::MARGIN;
use self::search::Search;
use self::speed::Speed;
use self::state::State;
use self::user::Given;
use super::Budget;
use super::budget::enough_for;
use super::budget::in_words;
use crate::cli::ExitStatus;
use crate::formats::zip::known::claim::Claim;
use crate::formats::zip::known::directory::copies;
use crate::formats::zip::known::types;
use crate::formats::zip::known::types::Row;
use crate::line::Tag;
use crate::output::sanitize;

/// How often the line of a running search is redrawn on a terminal, and written elsewhere.
const REDRAW: Duration = Duration::from_millis(250);
const WRITE: Duration = Duration::from_secs(10);

/// A plan that takes longer than this is one the user is told to keep the state of.
const LONG: Duration = Duration::from_mins(30);

/// How much of a search lies between two writes of the state, in time at the measured speed.
const KEEP: Duration = Duration::from_secs(10);

/// What the command line gives the attack.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// The archives. Their entries of `zip-crypto` are one pool.
    pub archives: Vec<PathBuf>,
    /// `--known`: files, folders and archives that may hold content of the archives.
    pub known: Vec<PathBuf>,
    /// `--bytes ENTRY[@POS]=HEX`.
    pub bytes: Vec<String>,
    /// `--text ENTRY[@POS]=STR`.
    pub text: Vec<String>,
    /// `--text16 ENTRY[@POS]=STR`.
    pub text16: Vec<String>,
    /// `--starts ENTRY=STR`.
    pub starts: Vec<String>,
    /// `--ends ENTRY=STR`.
    pub ends: Vec<String>,
    /// `--class ENTRY=CLASS`.
    pub class: Vec<String>,
    /// `--type ENTRY=TYPE`.
    pub kinds: Vec<String>,
    /// `--catalogue FILE`: a list of files that exist elsewhere.
    pub catalogue: Option<PathBuf>,
    /// `--keys X Y Z`: keys from an earlier run, as three words in hex.
    pub keys: Option<[u32; 3]>,
    /// `--entry PATTERN`: only attempts on these entries.
    pub entries: Vec<String>,
    /// `--only PATH,...`: only these paths.
    pub only: Vec<String>,
    /// `--no-guess`: only claims that are certain or derived.
    pub no_guess: bool,
    /// `--deep`: also the attempts that take hours.
    pub deep: bool,
    /// `--plan`: print the plan and stop.
    pub plan: bool,
    /// `--budget TIME`: for the whole command.
    pub budget: Option<Budget>,
    /// `--attempt-budget TIME`: for one attempt.
    pub attempt_budget: Option<Budget>,
    /// `--threads N`.
    pub threads: Option<usize>,
    /// `--slice K/N`: this machine's part of every search.
    pub slice: Option<(u32, u32)>,
    /// `-o FILE`: write the archive without its password.
    pub output: Option<PathBuf>,
    /// `--json`: the result as one JSON object.
    pub json: bool,
    /// `--state FILE`, with `--resume` or without.
    pub state: Option<StateFile>,
    /// `-v`, `-vv`.
    pub verbose: u8,
    /// `-q`: only the result.
    pub quiet: bool,
}

/// Where a run keeps how far its searches came.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateFile {
    /// `--state FILE`.
    pub path: PathBuf,
    /// `--resume`: the file is there, and the run goes on from it.
    pub resume: bool,
}

/// The budget of the command when none is given: fifteen minutes, which the longest path
/// that needs nothing from the user fits in on the reference machine (section 9.5 of the
/// design).
pub const DEFAULT_BUDGET: Budget = Budget::Limit(Duration::from_mins(15));

/// How sure a result is (section 11.2 of the design).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    /// The keys decrypt an entry to its stored CRC-32, and enough speaks for them.
    Proved,
    /// Keys pass every filter, and nothing proves them.
    Unproved,
    /// Every attempt that ran ended without keys.
    None,
    /// Nothing in the plan fit the budget, or nothing was known.
    NotRun,
}

impl Status {
    /// The word of the JSON object.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Proved => "proved",
            Self::Unproved => "unproved",
            Self::None => "none",
            Self::NotRun => "not-run",
        }
    }
}

/// What keys do to an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opens {
    /// They decrypt it to its CRC-32.
    Proved,
    /// Its check byte fits, and the entry is of a method the tool does not unpack.
    Fits,
    /// They do not open it: another password, or none of `zip-crypto`.
    No,
}

impl Opens {
    /// The word of the JSON object.
    const fn as_str(self) -> &'static str {
        match self {
            Self::Proved => "proved",
            Self::Fits => "fits",
            Self::No => "no",
        }
    }
}

/// What keys do to one entry.
fn opens(pool: &Pool, target: &Target, keys: Keys) -> Opens {
    match pool.source(target).map(|source| prove(source, target, keys)) {
        Some(Proof::Holds(_)) => Opens::Proved,
        Some(Proof::CannotSay) if after_header(target, keys).is_some() => Opens::Fits,
        _ => Opens::No,
    }
}

/// The type the user gave for the entries, from `--type ENTRY=TYPE`.
fn kinds(items: &[String]) -> anyhow::Result<Vec<(String, &'static Row)>> {
    items
        .iter()
        .map(|item| {
            let (pattern, name) = item.rsplit_once('=').ok_or_else(|| anyhow::anyhow!("--type {item}: the form is ENTRY=TYPE"))?;
            let row = types::by_type(name).ok_or_else(|| {
                let known: Vec<&str> = types::rows().iter().map(|row| row.name.as_str()).collect();
                anyhow::anyhow!("--type {item}: {name} is no type of the table. The types are: {}", known.join(", "))
            })?;
            Ok((pattern.to_owned(), row))
        })
        .collect()
}

/// The paths `--only` names.
fn only(items: &[String]) -> anyhow::Result<Vec<Path>> {
    items
        .iter()
        .flat_map(|item| item.split(','))
        .map(|name| {
            Path::named(name).ok_or_else(|| {
                let known: Vec<&str> = Path::ALL.iter().map(|path| path.as_str()).collect();
                anyhow::anyhow!("--only {name}: no such path. The paths are: {}", known.join(", "))
            })
        })
        .collect()
}

/// A span of time that is exact, from seconds.
fn words(time: Duration) -> String {
    in_words(time)
}

/// One run of the command.
struct Run<'a> {
    options: &'a Options,
    voice: Voice,
    pool: Pool,
    speed: Speed,
    started: Instant,
    budget: Budget,
    stop: AtomicBool,
    /// What is kept for a run that goes on from this one, when `--state` names a file.
    state: Option<State>,
    /// Whether it was said that the state could not be written.
    state_failed: AtomicBool,
    /// What the searches of the run did while they searched: candidates brought to their end,
    /// and the time that took, in nanoseconds. The rate that is kept is held against it.
    searched: AtomicU64,
    searching: AtomicU64,
}

/// Where a search stands in what is kept: the name of its attempt, which of the searches of
/// that attempt it is, and the candidate it starts from when a run before left it there.
#[derive(Debug, Clone, Copy)]
struct Place<'a> {
    attempt: &'a str,
    search: u64,
    from: Option<u64>,
}

impl Run<'_> {
    /// The time the budget leaves. `None` for no limit.
    fn left(&self) -> Option<Duration> {
        match self.budget {
            Budget::Limit(limit) => Some(limit.saturating_sub(self.started.elapsed())),
            Budget::Unlimited => None,
        }
    }

    /// The part of the candidates of a search that this machine takes.
    fn part(&self, candidates: usize) -> (usize, usize) {
        match self.options.slice {
            Some((part, of)) => {
                let (part, of) = (usize::try_from(part).unwrap_or(1), usize::try_from(of).unwrap_or(1).max(1));
                (candidates / of * (part - 1), if part == of { candidates } else { candidates / of * part })
            },
            None => (0, candidates),
        }
    }

    /// Write to the state, when one is kept. A state that cannot be written does not end a
    /// search that runs: it is said once.
    fn keep(&self, write: impl FnOnce(&State) -> anyhow::Result<()>) {
        if let Some(state) = &self.state
            && let Err(error) = write(state)
            && !self.state_failed.swap(true, Ordering::Relaxed)
        {
            self.voice.say(&format!("      the state is not kept from here on: {error:#}"));
        }
    }

    /// Run the candidates `from` to `until - 1` of a search. With a state, in stretches of
    /// about ten seconds, each of which is searched to its end before the state says so: what
    /// the state names as the next candidate has nothing unsearched in front of it.
    fn stretches(&self, search: &Search<'_>, control: &Control<'_>, from: usize, until: usize, place: Option<Place<'_>>) -> search::Outcome {
        let Some(place) = place.filter(|_| self.state.is_some()) else { return search.run(control, from, until) };
        // the candidates of ten seconds at the measured speed, and no fewer than every thread has work for
        let stretch = usize::try_from(whole(KEEP.as_secs_f64() * self.speed.rate)).unwrap_or(usize::MAX).max(control.threads.max(1) * 64);
        let mut all = search::Outcome::default();
        let mut at = from;
        loop {
            let end = at.saturating_add(stretch).min(until);
            all.add(search.run(control, at, end));
            self.keep(|state| state.left(place.attempt, &all.unproved));
            if all.proved.is_some() || all.stopped || end >= until {
                return all;
            }
            at = end;
            self.keep(|state| state.came_to(place.attempt, place.search, at as u64));
        }
    }

    /// Run one search with its progress shown, and say how it ended.
    fn search(&self, search: &Search<'_>, number: &str, rate: f64, place: Option<Place<'_>>) -> search::Outcome {
        let (from, until) = self.part(search.candidates());
        let total = (until - from) as u64;
        // a search that goes on starts where the state says, within the part of this machine
        let begin = place.and_then(|place| place.from).map_or(from, |next| usize::try_from(next).unwrap_or(until).clamp(from, until));
        if begin > from {
            self.voice.say(&format!("      going on from candidate {} of {}: what lies in front of it was searched by a run before", grouped(begin as u64 + 1), grouped(search.candidates() as u64)));
        }
        if let Some(place) = place {
            self.keep(|state| state.came_to(place.attempt, place.search, begin as u64));
        }
        let done = AtomicU64::new((begin - from) as u64);
        let finished = AtomicBool::new(false);
        let control = Control { kernel: self.speed.kernel, threads: self.speed.threads, stop: &self.stop, done: &done, short_password: true };
        if search.short_only() {
            self.voice.say("      too little is known of the entry for a proof to tell the keys from those that fit by chance: only the keys of a password of six bytes or fewer are found");
        }
        let started = Instant::now();
        let (voice, redraws) = (self.voice, self.voice.redraws());
        std::thread::scope(|scope| {
            drop(scope.spawn(|| {
                let pause = if redraws { REDRAW } else { WRITE };
                let mut waited = Duration::ZERO;
                // the count when the search started, and when it last moved: the time between
                // the two is time of search, and a proof at its end is not in it
                let first = done.load(Ordering::Relaxed);
                let mut last = (first, Duration::ZERO);
                while !finished.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                    waited += Duration::from_millis(50);
                    let so_far = done.load(Ordering::Relaxed);
                    if so_far != last.0 {
                        last = (so_far, started.elapsed());
                    }
                    if waited >= pause && !finished.load(Ordering::Relaxed) {
                        waited = Duration::ZERO;
                        voice.progress(&report::search_line(so_far, total, started.elapsed(), rate), false);
                        voice.event(&json!({ "event": "progress", "id": number, "stage": "search", "done": so_far, "total": total, "elapsed_s": started.elapsed().as_secs_f64(), "to_end_s": f64::from(u32::try_from(total.saturating_sub(so_far)).unwrap_or(u32::MAX)) / rate.max(1.0) }));
                    }
                }
                let _ = self.searched.fetch_add(last.0.saturating_sub(first), Ordering::Relaxed);
                let _ = self.searching.fetch_add(u64::try_from(last.1.as_nanos()).unwrap_or(u64::MAX), Ordering::Relaxed);
            }));
            let outcome = self.stretches(search, &control, begin, until, place);
            finished.store(true, Ordering::Relaxed);
            if redraws {
                voice.progress(&report::search_line(outcome.candidates, total, started.elapsed(), rate), true);
            }
            outcome
        })
    }

    /// Run one attempt: every search it stands for, to the first proved keys or to its end.
    /// Returns the keys it proved, and the keys it found and could not prove.
    fn attempt(&self, attempt: &Attempt, number: usize, of: usize, name: Option<&str>) -> (Option<Found>, Vec<Found>) {
        let label = format!("[{number}/{of}]");
        let Some(target) = self.pool.targets.get(attempt.target) else { return (None, Vec::new()) };
        self.voice.say(&format!("{label} {}", report::attempt_head(&self.pool, attempt)));
        self.voice.event(&json!({ "event": "attempt-start", "id": number, "budget_left_s": self.left().map(|left| left.as_secs_f64()) }));
        if let Some(special) = attempt.special {
            let started = Instant::now();
            let (proved, unproved) = self.header_path(special);
            let outcome = match (&proved, self.stop.load(Ordering::Relaxed), unproved.is_empty()) {
                (Some(found), _, _) => {
                    let on = found.proved_on.and_then(|index| self.pool.targets.get(index)).unwrap_or(target);
                    self.voice.say(&format!("      keys found; proof: decrypts {} to its CRC-32 ({} bits speak for the keys, {} are asked for)", on.name, whole(found.bits), whole(96.0 + MARGIN)));
                    "keys"
                },
                (None, true, _) => "stopped",
                (None, false, true) => {
                    self.voice.say(&format!("{label} {}: no keys, after {}. {}", target.name, words(started.elapsed()), report::why_nothing(attempt)));
                    "none"
                },
                (None, false, false) => "unproved",
            };
            self.voice.event(&json!({ "event": "attempt-end", "id": number, "outcome": outcome }));
            return (proved, unproved);
        }

        let started = Instant::now();
        // what a run before left of this attempt: the keys it found, and where it stood
        let point = name.zip(self.state.as_ref()).and_then(|(name, state)| state.point(name));
        let mut unproved = name.zip(self.state.as_ref()).map(|(name, state)| state.left_by(name)).unwrap_or_default();
        let (mut searched, mut fitting, mut runs) = (0_u64, 0_u64, 0_u64);
        for (index, run) in (0_u64..).zip(attempt.runs()) {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            // the searches of the attempt that a run before brought to their end
            let from = match point {
                Some((search, _)) if index < search => {
                    runs += 1;
                    continue;
                },
                Some((search, next)) if index == search => Some(next),
                _ => None,
            };
            let Some(search) = Search::new(&self.pool, attempt.target, &attempt.form, attempt.run.at, &run, attempt.run.searches) else {
                self.voice.say("      the entry does not hold these bytes at this position: not searched");
                break;
            };
            runs += 1;
            if attempt.run.searches == 1 {
                self.voice.say(&format!("      reduction: {}, {} candidates; the run and what stands beside it are worth {} bits", report::run_words(attempt), grouped(search.candidates() as u64), whole(search.bits())));
            } else if runs == 1 || runs.is_multiple_of(16) {
                self.voice.say(&format!("      search {} of {}: {} candidates", grouped(runs), grouped(attempt.run.searches), grouped(search.candidates() as u64)));
            }
            let outcome = self.search(&search, &number.to_string(), self.speed.rate, name.map(|attempt| Place { attempt, search: index, from }));
            searched += outcome.candidates;
            fitting += outcome.fitting;
            self.voice.most(&format!("      {} keys fit the eight bytes of the window, {} of them passed every filter and were put to the proof", grouped(outcome.fitting), grouped(outcome.put_to_proof)));
            unproved.extend(outcome.unproved);
            if let Some(found) = outcome.proved {
                self.voice.say(&format!("      keys found at candidate {} of {}", grouped(found.candidate as u64 + 1), grouped(search.candidates() as u64)));
                let on = found.proved_on.and_then(|index| self.pool.targets.get(index)).unwrap_or(target);
                self.voice.say(&format!("      proof: decrypts {} to its CRC-32 ({} bits speak for the keys, {} are asked for)", on.name, whole(found.bits), whole(96.0 + MARGIN)));
                self.voice.event(&json!({ "event": "attempt-end", "id": number, "outcome": "keys", "candidate": found.candidate + 1 }));
                return (Some(found), unproved);
            }
            if outcome.stopped {
                break;
            }
        }

        let time = words(started.elapsed());
        if self.stop.load(Ordering::Relaxed) {
            self.voice.say(&format!("{label} {}: stopped after {} candidates and {time}", target.name, grouped(searched)));
            self.voice.event(&json!({ "event": "attempt-end", "id": number, "outcome": "stopped", "candidates": searched }));
        } else if unproved.is_empty() {
            let part = if self.options.slice.is_some() { " of this part" } else { "" };
            self.voice.say(&format!("{label} {}: no keys. All {} candidates{part} tried in {time}. {}", target.name, grouped(searched), report::why_nothing(attempt)));
            self.voice.event(&json!({ "event": "attempt-end", "id": number, "outcome": "none", "candidates": searched, "fitting": fitting }));
        } else {
            self.voice.say(&format!("{label} {}: {} that nothing proves. All {} candidates tried in {time}.", target.name, if unproved.len() == 1 { "keys".to_owned() } else { format!("{} keys", unproved.len()) }, grouped(searched)));
            self.voice.event(&json!({ "event": "attempt-end", "id": number, "outcome": "unproved", "candidates": searched, "keys": unproved.len() }));
        }
        (None, unproved)
    }

    /// Run the plan: each attempt that fits what is left of the budget, in its order, to the
    /// first proved keys.
    fn plan(&self, plan: &mut Plan) -> Ran {
        let mut ran = Ran::default();
        let of = plan.attempts.len();
        let per_attempt = match self.options.attempt_budget {
            Some(Budget::Limit(limit)) => Some(limit),
            _ => None,
        };
        let share = self.options.slice.map_or(1.0, |(_, of)| f64::from(of.max(1)));
        for (index, attempt) in plan.attempts.iter_mut().enumerate() {
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            // an attempt that a run before brought to its end without keys is not run again
            let name = self.state.as_ref().map(|_| state::name(attempt));
            if let Some((state, name)) = self.state.as_ref().zip(name.as_deref())
                && state.has_ended(name)
            {
                ran.before += 1;
                ran.unproved.extend(state.left_by(name).into_iter().map(|found| (found, index)));
                let target = self.pool.targets.get(attempt.target).map_or("", |target| target.name.as_str());
                self.voice.say(&format!("[{}/{of}] {target}: {}: a run before brought it to its end without keys: not run again", index + 1, attempt.what));
                self.voice.event(&json!({ "event": "attempt-end", "id": index + 1, "outcome": "ended-before" }));
                continue;
            }
            // the estimate is of the candidates as the reduction counts them
            plan::count(&self.pool, attempt);
            let needs = Duration::try_from_secs_f64(attempt.seconds(self.speed.rate, self.speed.threads) / share).unwrap_or(Duration::MAX);
            let limit = [self.left(), per_attempt].into_iter().flatten().min();
            if limit.is_some_and(|limit| needs > limit) {
                ran.not_started += 1;
                let name = self.pool.targets.get(attempt.target).map_or("", |target| target.name.as_str());
                self.voice.say(&format!("[{}/{of}] {name}: not started. It takes {} to its end, and {} are left: --budget {} would run it", index + 1, span(needs.as_secs_f64()), limit.map_or_else(String::new, words), enough_for(needs.saturating_add(self.started.elapsed()))));
                self.voice.event(&json!({ "event": "attempt-end", "id": index + 1, "outcome": "not-started", "estimate_s": needs.as_secs_f64() }));
                continue;
            }
            ran.started += 1;
            let (proved, unproved) = self.attempt(attempt, index + 1, of, name.as_deref());
            if let Some(name) = name.as_deref() {
                self.keep(|state| state.left(name, &unproved));
                match proved {
                    Some(found) => self.keep(|state| state.found(found.keys)),
                    // an attempt that was stopped has not ended: it goes on
                    None if !self.stop.load(Ordering::Relaxed) => self.keep(|state| state.ended(name)),
                    None => {},
                }
            }
            ran.unproved.extend(unproved.into_iter().map(|found| (found, index)));
            if let Some(found) = proved {
                ran.proved = Some((found, index));
                break;
            }
        }
        ran
    }
}

/// What running a plan came to.
#[derive(Debug, Default)]
struct Ran {
    /// Proved keys, with the attempt that found them.
    proved: Option<(Found, usize)>,
    /// Keys nothing proves, each with its attempt.
    unproved: Vec<(Found, usize)>,
    /// How many attempts were started, and how many were not because of the budget.
    started: usize,
    not_started: usize,
    /// How many were not run again, because a run before brought them to their end.
    before: usize,
}

/// What is known of the entries beyond their own headers: copies in the archives, and what the
/// user gives. Each claim with the entry it is of, by its place in the pool.
fn known(run: &Run<'_>) -> anyhow::Result<Vec<(usize, Claim)>> {
    let options = run.options;
    let mut claims: Vec<(usize, Claim)> = Vec::new();
    for (number, archive) in run.pool.archives.iter().enumerate() {
        for (entry, claim) in copies(&archive.source, &archive.entries) {
            claims.extend(run.pool.targets.iter().position(|target| target.archive == number && target.index == entry).map(|target| (target, claim)));
        }
    }
    let given = Given { known: &options.known, bytes: &options.bytes, text: &options.text, text16: &options.text16, starts: &options.starts, ends: &options.ends, class: &options.class };
    let from_user = user::claims(&run.pool, &given)?;
    for note in &from_user.notes {
        run.voice.say(note);
    }
    claims.extend(from_user.claims);
    // a file that is the content of a packed entry: packed the way the writer did
    let mut notes = Vec::new();
    claims.extend(packed::claims(&run.pool, &from_user.packed, &mut notes));
    for note in &notes {
        run.voice.say(note);
    }

    for line in report::claim_lines(&run.pool, &claims) {
        run.voice.more(&line);
    }
    Ok(claims)
}

/// The lines of the result for keys: the keys as every tool takes them, the two lines of
/// modes 46400 and 46410, and the password when it is short.
fn key_lines(keys: Keys) -> Vec<String> {
    let mut lines = vec![format!("keys {keys}")];
    for form in 0..=1 {
        lines.push(format!("{}*{form}*{:08x}*{:08x}*{:08x}$/zip$", Tag::Zip4, keys.x, keys.y, keys.z));
    }
    if let Some(password) = short_passwords(keys, 6).into_iter().next() {
        lines.push(format!("password {}", password_text(&password)));
    }
    lines
}

/// A password as a line shows it: as it is when every byte is a printable character of
/// ASCII, and in the `$HEX[...]` form of hashcat otherwise.
fn password_text(password: &[u8]) -> String {
    if password.iter().all(|byte| (0x20..0x7f).contains(byte)) && !password.is_empty() { String::from_utf8_lossy(password).into_owned() } else { format!("$HEX[{}]", hex::encode(password)) }
}

/// Write one line of the result to standard output. A reader that has closed it gets no more,
/// and that is no failure.
fn out(line: &str) {
    drop(writeln!(std::io::stdout(), "{}", sanitize(line)));
}

/// Say what keys do to every entry of the pool, and print the result.
fn result(run: &Run<'_>, status: Status, keys: Option<Keys>, found_on: Option<(&Attempt, Option<usize>)>, bits: Option<f64>) -> ExitStatus {
    let voice = run.voice;
    let opened: Vec<Opens> = keys.map_or_else(Vec::new, |keys| run.pool.targets.par_iter().map(|target| opens(&run.pool, target, keys)).collect());
    let count = |how: Opens| opened.iter().filter(|opens| **opens == how).count();

    if let Some(keys) = keys {
        if let Some((attempt, proved_on)) = found_on {
            let target = run.pool.targets.get(attempt.target);
            voice.say(&format!("keys found on {} ({}, {}, {})", target.map_or("", |target| target.name.as_str()), target.map_or("", |target| target.facts.layout.label()), attempt.what, report::run_words(attempt)));
            let on = proved_on.and_then(|index| run.pool.targets.get(index)).or(target);
            match status {
                Status::Proved => voice.say(&format!("proved: decrypts {} to its CRC-32", on.map_or("", |target| target.name.as_str()))),
                _ => voice.say(&format!("not proved: {} bits speak for these keys and {} are asked for. They pass every filter; give more of what is known, or another archive under the same password, to prove them", whole(bits.unwrap_or(0.0)), whole(96.0 + MARGIN))),
            }
        }
        let total = run.pool.targets.len();
        voice.say(&format!(
            "the keys open {} of {} encrypted entries{}",
            grouped((count(Opens::Proved) + count(Opens::Fits)) as u64),
            grouped(total as u64),
            if count(Opens::Fits) > 0 { format!(" ({} of them by their check byte alone: their method is not unpacked)", count(Opens::Fits)) } else { String::new() }
        ));
        let closed: Vec<&str> = run.pool.targets.iter().zip(&opened).filter(|(_, opens)| **opens == Opens::No).map(|(target, _)| target.name.as_str()).collect();
        if !closed.is_empty() {
            let shown: Vec<&str> = closed.iter().take(8).copied().collect();
            voice.say(&format!("not opened: {}{} (another password)", shown.join(", "), if closed.len() > shown.len() { format!(" and {} more", closed.len() - shown.len()) } else { String::new() }));
        }
        let _ = keys;
    }

    // the archive without its password: every entry the keys open, when the keys are proved
    let mut wrote = None;
    if let (Some(output), Some(keys)) = (&run.options.output, keys) {
        if status == Status::Proved {
            match written(run, keys, &opened, output) {
                Ok(written) => {
                    voice.say(&format!(
                        "wrote {}: {} decrypted and still packed{}",
                        output.display(),
                        if written.decrypted == 1 { "1 entry".to_owned() } else { format!("{} entries", grouped(written.decrypted as u64)) },
                        if written.left > 0 { format!(", {} copied as they are", grouped(written.left as u64)) } else { String::new() }
                    ));
                    wrote = Some(written);
                },
                Err(error) => {
                    eprintln!("archivewolf: {}", sanitize(&format!("{error:#}")));
                    return ExitStatus::NothingDone;
                },
            }
        } else {
            voice.say(&format!("{} is not written: the keys are not proved", output.display()));
        }
    }

    let lines = keys.map_or_else(Vec::new, key_lines);
    if run.options.json {
        let entries: Vec<serde_json::Value> = run.pool.targets.iter().zip(&opened).map(|(target, opens)| json!({ "entry": target.name, "opened": opens.as_str() })).collect();
        let password = keys.and_then(|keys| short_passwords(keys, 6).into_iter().next()).map(|password| password_text(&password));
        let object = json!({
            "status": status.as_str(),
            "keys": keys.map(|keys| [format!("{:08x}", keys.x), format!("{:08x}", keys.y), format!("{:08x}", keys.z)]),
            "bits": bits,
            "entry": found_on.and_then(|(attempt, _)| run.pool.targets.get(attempt.target)).map(|target| target.name.as_str()),
            "claim": found_on.map(|(attempt, _)| attempt.what.as_str()),
            "path": found_on.map(|(attempt, _)| attempt.path.as_str()),
            "lines": lines.iter().filter(|line| line.starts_with(Tag::Zip4.as_str())).collect::<Vec<_>>(),
            "password": password,
            "opens": count(Opens::Proved) + count(Opens::Fits),
            "encrypted": run.pool.targets.len(),
            "entries": entries,
            "written": wrote.map(|written| json!({ "path": run.options.output.as_ref().map(|path| path.display().to_string()), "decrypted": written.decrypted, "left": written.left })),
        });
        voice.event(&json!({ "event": "result", "status": status.as_str(), "keys": object.get("keys"), "entry": object.get("entry"), "opens": object.get("opens"), "encrypted": object.get("encrypted") }));
        out(&object.to_string());
    } else {
        for line in &lines {
            out(line);
        }
    }
    match status {
        Status::Proved => ExitStatus::Success,
        _ => ExitStatus::NoResult,
    }
}

/// Write the one archive of the run without its password: every entry the keys open is
/// decrypted, and the others are copied as they are.
fn written(run: &Run<'_>, keys: Keys, opened: &[Opens], output: &std::path::Path) -> anyhow::Result<write::Written> {
    let archive = run.pool.archives.first().ok_or_else(|| anyhow::anyhow!("no archive to write"))?;
    let open: HashSet<usize> = run.pool.targets.iter().zip(opened).filter(|(target, opens)| target.archive == 0 && **opens != Opens::No).map(|(target, _)| target.index).collect();
    write::write(&archive.source, &|index| open.contains(&index).then_some(keys), output)
}

/// `attack zip-crypto`: find the keys of the archives, or say what was tried and why that was
/// not enough.
///
/// An error is a command that could not start: a path that is no ZIP archive, an option that
/// is not what it has to be, or no entry of `zip-crypto` in any archive.
pub fn run(options: &Options) -> anyhow::Result<ExitStatus> {
    let voice = Voice::new(options.quiet, options.verbose, options.json);
    if let Some(output) = &options.output {
        // the place of the copy is looked at before a search that can take minutes
        anyhow::ensure!(options.archives.len() == 1, "-o writes one archive without its password: {} are given. The keys of one open the others: run the command once, and again for each with --keys", options.archives.len());
        super::rar_13::check_output(output)?;
    }
    let kinds = kinds(&options.kinds)?;
    let paths = only(&options.only)?;
    if let Some((part, of)) = options.slice {
        anyhow::ensure!(part >= 1 && part <= of, "--slice {part}/{of}: the part is a number from 1 to {of}");
    }

    let kind_of = |name: &str| kinds.iter().find(|(pattern, _)| types::fits(&pattern.to_ascii_lowercase(), &name.to_ascii_lowercase()) || name.to_ascii_lowercase().rsplit('/').next().is_some_and(|last| types::fits(&pattern.to_ascii_lowercase(), last))).map(|(_, row)| *row);
    let pool = Pool::read(&options.archives, &kind_of)?;
    if pool.targets.is_empty() {
        let left: Vec<String> = pool.left_out.iter().map(|left| format!("{}: {}", left.name, left.why)).collect();
        anyhow::bail!("no entry of zip-crypto to work on in {}{}: `archivewolf info` says what is encrypted and how", if options.archives.len() == 1 { "the archive" } else { "the archives" }, if left.is_empty() { String::new() } else { format!(" ({})", left.join("; ")) });
    }

    // the place of the state is looked at, and the state read, before anything is measured or
    // searched. A run that only prints its plan, or that is given its keys, keeps none
    let state = match &options.state {
        Some(file) if !options.plan && options.keys.is_none() => Some(State::open(&file.path, &pool, options.slice, file.resume)?),
        _ => None,
    };

    let threads = options.threads.filter(|threads| *threads > 0).unwrap_or_else(|| std::thread::available_parallelism().map_or(1, std::num::NonZero::get));
    let speed = speed::speed(threads, || voice.say("measuring the speed of this machine: two seconds, once"));
    let mut run = Run { options, voice, pool, speed, started: Instant::now(), budget: options.budget.unwrap_or(DEFAULT_BUDGET), stop: AtomicBool::new(false), state, state_failed: AtomicBool::new(false), searched: AtomicU64::new(0), searching: AtomicU64::new(0) };

    // keys a run before proved: the state holds the result, and nothing is searched
    if let Some(keys) = run.state.as_ref().and_then(State::proved) {
        run.voice.say(&format!("keys {keys}: found by a run before, as the state says: not searched for"));
        let opens_any = run.pool.targets.iter().any(|target| opens(&run.pool, target, keys) == Opens::Proved);
        return Ok(result(&run, if opens_any { Status::Proved } else { Status::None }, Some(keys), None, None));
    }

    // keys from an earlier run: nothing is searched
    if let Some([x, y, z]) = options.keys {
        let keys = Keys::new(x, y, z);
        let opens_any = run.pool.targets.iter().any(|target| opens(&run.pool, target, keys) == Opens::Proved);
        run.voice.say(&format!("keys {keys}: given, not searched for"));
        return Ok(result(&run, if opens_any { Status::Proved } else { Status::None }, Some(keys), None, None));
    }

    // the entries that a list of known files names: for the user to find, not for a search
    if let Some(path) = &options.catalogue {
        let listed = catalogue::read(path, &run.pool)?;
        for line in report::catalogue_lines(&run.pool, path, &listed) {
            run.voice.say(&line);
        }
        run.voice.event(&report::catalogue_event(&run.pool, &listed));
    }
    let claims = known(&run)?;

    let entries: Option<HashSet<usize>> = if options.entries.is_empty() { None } else { Some(options.entries.iter().flat_map(|pattern| run.pool.named(pattern)).collect()) };
    if let Some(entries) = &entries {
        anyhow::ensure!(!entries.is_empty(), "--entry {}: no entry of zip-crypto has such a name", options.entries.join(", "));
    }
    let limits = Limits { deep: options.deep, no_guess: options.no_guess, only: paths, entries };
    let special = headers::attempts(&run.pool, &limits);
    let mut plan = plan::build(&run.pool, &claims, special, &limits, run.speed.rate, run.speed.threads);

    for line in report::plan_lines(&run.pool, &plan, &run.speed, run.budget, options.slice) {
        run.voice.say(&line);
    }
    run.voice.event(&report::plan_event(&run.pool, &plan, &run.speed, run.budget));
    if options.plan {
        return Ok(ExitStatus::Success);
    }
    if plan.attempts.is_empty() {
        return Ok(result(&run, Status::NotRun, None, None, None));
    }

    // a plan of hours is worth keeping: a run that is given no state starts from nothing again
    let whole_plan: f64 = plan.attempts.iter().map(|attempt| attempt.seconds(run.speed.rate, run.speed.threads)).sum();
    if run.state.is_none() && whole_plan > LONG.as_secs_f64() && run.left().is_none_or(|left| left > LONG) {
        run.voice.say("the plan takes long: --state FILE keeps how far it came, and --resume goes on from there after a stop");
    }

    run.voice.say("");
    run.started = Instant::now();
    let ran = run.plan(&mut plan);
    // what the searches of a long run did says more of the machine than two seconds did
    if let Some(rate) = speed::observed(run.speed.rate, run.searched.load(Ordering::Relaxed), Duration::from_nanos(run.searching.load(Ordering::Relaxed))) {
        run.voice.say(&format!("the speed that was kept, {} candidates a second, is not what this run did: {} are kept from now on", grouped(whole(run.speed.rate)), grouped(whole(rate))));
        speed::keep(run.speed.kernel, run.speed.threads, rate);
    }
    run.voice.say("");
    if let Some((found, attempt)) = ran.proved {
        return Ok(result(&run, Status::Proved, Some(found.keys), plan.attempts.get(attempt).map(|attempt| (attempt, found.proved_on)), Some(found.bits)));
    }

    // keys that nothing proves: one set of them is a result of its own kind, several are none
    let mut unproved = ran.unproved;
    unproved.sort_by(|a, b| b.0.bits.total_cmp(&a.0.bits));
    unproved.dedup_by_key(|(found, _)| found.keys);
    match unproved.as_slice() {
        [(found, attempt)] => Ok(result(&run, Status::Unproved, Some(found.keys), plan.attempts.get(*attempt).map(|attempt| (attempt, found.proved_on)), Some(found.bits))),
        [] => {
            if ran.started + ran.before == 0 {
                run.voice.say(&format!("nothing was searched: none of the {} attempts of the plan fits the budget of {}", grouped(plan.attempts.len() as u64), run.budget));
                Ok(result(&run, Status::NotRun, None, None, None))
            } else {
                run.voice.say(&format!("no keys: {} of {} attempts ran to their end without them{}", grouped((ran.started + ran.before) as u64), grouped(plan.attempts.len() as u64), if ran.not_started > 0 { format!(", and {} did not fit the budget", ran.not_started) } else { String::new() }));
                run.voice.say("what would help most: one file that is in the archive, in any version (--known)");
                Ok(result(&run, Status::None, None, None, None))
            }
        },
        several => {
            run.voice.say(&format!("{} keys pass every filter and nothing tells them apart: more of what is known of an entry, or another archive under the same password, would", several.len()));
            for (found, _) in several.iter().take(8) {
                run.voice.say(&format!("  keys {}   {} bits", found.keys, whole(found.bits)));
            }
            Ok(result(&run, Status::None, None, None, None))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lines_of_a_result_are_the_keys_the_two_lines_of_the_modes_and_a_short_password() {
        let long = Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31);
        assert_eq!(key_lines(long), ["keys c4490e28 b414a23d 91404b31", "$zip$4$*0*c4490e28*b414a23d*91404b31$/zip$", "$zip$4$*1*c4490e28*b414a23d*91404b31$/zip$"]);
        let short = key_lines(Keys::from_password(b"pass"));
        assert_eq!((short.len(), short[3].as_str()), (4, "password pass"));
        assert_eq!(key_lines(Keys::from_password(b"\xff\x00a"))[3], "password $HEX[ff0061]");
        assert_eq!(key_lines(Keys::from_password(b""))[3], "password $HEX[]");
        for line in &key_lines(long)[1..] {
            assert!(Tag::of(line).is_some_and(|(tag, _)| tag == Tag::Zip4), "{line}");
        }
    }

    #[test]
    fn an_option_that_names_what_is_not_there_is_refused_with_what_is() {
        let fault = |options: Options| format!("{:#}", run(&options).unwrap_err());
        let archive = vec![PathBuf::from("tests/fixtures/zip-crypto/bkcrack-src_secrets.zip")];
        assert!(fault(Options { archives: archive.clone(), kinds: vec!["a=nonsense".to_owned()], ..Options::default() }).contains("is no type of the table. The types are: png, jpg"));
        assert!(fault(Options { archives: archive.clone(), kinds: vec!["png".to_owned()], ..Options::default() }).contains("the form is ENTRY=TYPE"));
        assert!(fault(Options { archives: archive.clone(), only: vec!["run,guess".to_owned()], ..Options::default() }).contains("no such path. The paths are: run, short-run, header, header-once"));
        assert!(fault(Options { archives: archive, slice: Some((3, 2)), ..Options::default() }).contains("the part is a number from 1 to 2"));
        assert!(fault(Options { archives: vec![PathBuf::from("tests/fixtures/zip-winzip/aes256.zip")], ..Options::default() }).contains("no entry of zip-crypto to work on in the archive"));
    }
}
