//! What the user sees: the plan before anything is searched, one block for each attempt while
//! it runs, and the result.
//!
//! All of it goes to standard error as plain lines, without time and without colour. Standard
//! output is the result and nothing else. With `--json` and `-v` the same is said as a stream
//! of events, one object on a line, and no text.

use std::io::IsTerminal as _;
use std::io::Write as _;
use std::time::Duration;

use serde_json::Value;
use serde_json::json;

use super::catalogue::Catalogue;
use super::plan::Attempt;
use super::plan::Path;
use super::plan::Plan;
use super::pool::Pool;
use super::pool::Target;
use super::speed::Speed;
use crate::attack::Budget;
use crate::attack::budget::about;
use crate::formats::zip::known::claim::Certainty;
use crate::formats::zip::known::method::Layout;
use crate::formats::zip::known::writer::Writer;
use crate::output::sanitize;

/// How many attempts a plan lists before it counts the rest.
const LISTED: usize = 12;

/// How many entries the lists below the plan name.
const NAMED: usize = 8;

/// Who is spoken to, and how much.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Voice {
    quiet: bool,
    verbose: u8,
    events: bool,
    terminal: bool,
}

impl Voice {
    /// The voice of a run: `-q` says nothing but the result, `-v` and `-vv` say more, and
    /// `--json` with `-v` says everything as events.
    #[must_use]
    pub(crate) fn new(quiet: bool, verbose: u8, json: bool) -> Self {
        Self { quiet, verbose, events: json && verbose > 0 && !quiet, terminal: std::io::stderr().is_terminal() }
    }

    /// Whether lines of the text are written at all.
    const fn speaks(self) -> bool {
        !self.quiet && !self.events
    }

    /// One line. It can hold a name out of an archive, so it is made safe for a terminal.
    pub(crate) fn say(self, line: &str) {
        if self.speaks() {
            eprintln!("{}", sanitize(line));
        }
    }

    /// One line that `-v` asks for.
    pub(crate) fn more(self, line: &str) {
        if self.verbose >= 1 {
            self.say(line);
        }
    }

    /// One line that `-vv` asks for.
    pub(crate) fn most(self, line: &str) {
        if self.verbose >= 2 {
            self.say(line);
        }
    }

    /// One event, when events are what is asked for.
    pub(crate) fn event(self, event: &Value) {
        if self.events {
            eprintln!("{event}");
        }
    }

    /// Whether the progress of a search is redrawn in place.
    #[must_use]
    pub(crate) const fn redraws(self) -> bool {
        self.terminal && self.speaks()
    }

    /// The line of a search that is running: redrawn in place on a terminal, written as one
    /// more line otherwise.
    pub(crate) fn progress(self, line: &str, last: bool) {
        if !self.speaks() {
            return;
        }
        let mut stderr = std::io::stderr().lock();
        if self.terminal {
            drop(write!(stderr, "\r{}\x1b[K{}", sanitize(line), if last { "\n" } else { "" }));
            drop(stderr.flush());
        } else {
            drop(writeln!(stderr, "{}", sanitize(line)));
        }
    }
}

/// A count with a comma between every three digits.
#[must_use]
pub(crate) fn grouped(count: u64) -> String {
    let digits = count.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// A count that an estimate gave, as a whole number.
#[must_use]
pub(crate) fn whole(count: f64) -> u64 {
    if count.is_finite() && count > 0.0 { Duration::from_secs_f64(count.min(1e18)).as_secs() } else { 0 }
}

/// A span of time that is an estimate, from seconds.
#[must_use]
pub(crate) fn span(seconds: f64) -> String {
    about(Duration::try_from_secs_f64(seconds.max(0.0)).unwrap_or(Duration::MAX))
}

/// `count` things, with the word in its singular or its plural.
fn things(count: usize, one: &str, many: &str) -> String {
    if count == 1 { format!("1 {one}") } else { format!("{} {many}", grouped(count as u64)) }
}

/// The line of a search that is running.
#[must_use]
pub(crate) fn search_line(done: u64, total: u64, elapsed: Duration, rate: f64) -> String {
    const WIDTH: u64 = 30;
    let total = total.max(1);
    let filled = (done.min(total) * WIDTH / total).min(WIDTH);
    let bar: String = (0..WIDTH)
        .map(|at| match at.cmp(&filled) {
            std::cmp::Ordering::Less => '=',
            std::cmp::Ordering::Equal => '>',
            std::cmp::Ordering::Greater => ' ',
        })
        .collect();
    let to_end = f64::from(u32::try_from(total.saturating_sub(done)).unwrap_or(u32::MAX)) / rate.max(1.0);
    format!("      search  [{bar}] {:3} %   {} of {}   {} so far, at most {} more", done.min(total) * 100 / total, grouped(done), grouped(total), crate::attack::budget::in_words(elapsed), span(to_end))
}

/// What the claim of an attempt is, with its entry: the head of its block. A header path is
/// of an archive, and has that in front.
#[must_use]
pub(crate) fn attempt_head(pool: &Pool, attempt: &Attempt) -> String {
    let target = pool.targets.get(attempt.target);
    if attempt.special.is_some() {
        let archive = target.and_then(|target| pool.archives.get(target.archive)).map_or_else(String::new, |archive| archive.path.display().to_string());
        return format!("{archive}: {}", attempt.what);
    }
    format!("{}: {}", target.map_or("", |target| target.name.as_str()), attempt.what)
}

/// The line of a search of seeds, or of the stages that follow it, while it runs.
#[must_use]
pub(crate) fn stage_line(label: &str, done: u64, total: u64, elapsed: Duration) -> String {
    let total = total.max(1);
    format!("      {label}: {:3} %, {} so far", done.min(total).saturating_mul(100) / total, crate::attack::budget::in_words(elapsed))
}

/// How long the run of an attempt is, in words.
#[must_use]
pub(crate) fn run_words(attempt: &Attempt) -> String {
    if attempt.special.is_some() {
        return "no known bytes".to_owned();
    }
    let length = format!("{} bytes in a row", grouped(attempt.run.len));
    match (attempt.path, attempt.run.searches) {
        (Path::ShortRun, searches) => format!("{length}, one of them not known: {} searches", grouped(searches)),
        (_, 1) => length,
        (_, searches) => format!("{length}, in {} alternatives", grouped(searches)),
    }
}

/// The lines of the plan (section 13.1 of the design).
#[must_use]
pub(crate) fn plan_lines(pool: &Pool, plan: &Plan, speed: &Speed, budget: Budget, slice: Option<(u32, u32)>) -> Vec<String> {
    let mut lines = Vec::new();
    for (number, archive) in pool.archives.iter().enumerate() {
        let entries = pool.targets.iter().filter(|target| target.archive == number).count();
        let writer = if archive.writer == Writer::Unknown { String::new() } else { format!(", written by {}", archive.writer.label()) };
        lines.push(format!("{}: {} under zip-crypto{writer}", archive.path.display(), things(entries, "entry", "entries")));
    }
    for left in &pool.left_out {
        lines.push(format!("  left out: {}: {}", left.name, left.why));
    }

    lines.push(String::new());
    lines.push("what is known".to_owned());
    lines.extend(known_lines(pool, plan));

    lines.push(String::new());
    let part = slice.map_or_else(String::new, |(part, of)| format!(", part {part} of {of} of every search (the other parts run elsewhere)"));
    lines.push(format!("the plan, budget {budget}{part}; {} candidates a second on {} with the {} kernel", grouped(whole(speed.rate)), things(speed.threads, "thread", "threads"), speed.kernel.name()));
    if plan.attempts.is_empty() {
        lines.push("  nothing: no entry has eight known bytes in a row".to_owned());
    }
    let share = slice.map_or(1.0, |(_, of)| f64::from(of.max(1)));
    for (number, attempt) in plan.attempts.iter().enumerate().take(LISTED) {
        let count = if attempt.special.is_some() {
            "a search of seeds".to_owned()
        } else if attempt.counted {
            format!("{} candidates", grouped(whole(attempt.work())))
        } else {
            format!("about {} candidates", grouped(whole(attempt.work())))
        };
        let short = if attempt.short_only { ", for a password of six bytes or fewer" } else { "" };
        lines.push(format!("  {:2}  {}   {}, {count}   {}   {}{short}", number + 1, attempt_head(pool, attempt), run_words(attempt), span(attempt.seconds(speed.rate, speed.threads) / share), attempt.certainty));
    }
    let rest = plan.attempts.len().saturating_sub(LISTED) + plan.beyond;
    if rest > 0 {
        lines.push(format!("      ... {} more, not needed unless these fail", grouped(rest as u64)));
    }

    let short = short_lines(pool, plan);
    if !short.is_empty() {
        lines.push(String::new());
        lines.push("not in the plan".to_owned());
        lines.extend(short);
    }
    let elsewhere = elsewhere_lines(pool);
    if !elsewhere.is_empty() {
        lines.push(String::new());
        lines.push("likely to exist elsewhere (find one, pass it with --known, and the rest is seconds)".to_owned());
        lines.extend(elsewhere);
    }
    lines.push(String::new());
    lines.push(format!("what would help most: {}", help_most(pool, plan)));
    lines
}

/// What is known of the entries, by kind, each with how many entries it holds for.
fn known_lines(pool: &Pool, plan: &Plan) -> Vec<String> {
    let mut lines = Vec::new();
    let count = |pick: &dyn Fn(&Target) -> bool| pool.targets.iter().filter(|target| pick(target)).count();
    let mut row = |entries: usize, what: &str, certainty: &str| {
        if entries > 0 {
            lines.push(format!("  {:16} {what:58} {certainty}", things(entries, "entry", "entries")));
        }
    };
    for (bytes, certainty) in [(2, Certainty::Derived), (1, Certainty::Certain), (1, Certainty::Derived), (1, Certainty::Likely)] {
        let entries = count(&|target| target.facts.checks.first().is_some_and(|way| way.count == bytes && way.certainty == certainty));
        row(entries, if bytes == 2 { "2 check bytes" } else { "1 check byte" }, certainty.as_str());
    }
    let typed = |target: &Target, layout: fn(Layout) -> bool| layout(target.facts.layout) && target.facts.kind.is_some() && !target.facts.kind_unused;
    row(count(&|target| typed(target, |layout| layout == Layout::Stored)), "stored, type known from the name", "likely");
    row(count(&|target| typed(target, |layout| matches!(layout, Layout::StoredBlocks { .. }))), "Deflate, did not pack: content starts at 5, type known", "likely");
    row(count(&|target| matches!(target.facts.layout, Layout::StoredBlocks { .. })), "Deflate, did not pack: the head of the first block", "derived");
    // an attempt on the encryption headers is one on the archive: it starts from no entry
    let attempted = |target: usize| plan.attempts.iter().any(|attempt| attempt.target == target && attempt.special.is_none());
    let given = pool.targets.iter().enumerate().filter(|(index, _)| plan.attempts.iter().any(|attempt| attempt.target == *index && attempt.origin == crate::formats::zip::known::claim::Origin::User)).count();
    row(given, "bytes from --known or the command line", "see the plan");
    let nothing = pool.targets.iter().enumerate().filter(|(index, _)| !attempted(*index)).count();
    row(nothing, "nothing a search can start from", "");
    lines
}

/// The entries no search can start from, with what is missing.
fn short_lines(pool: &Pool, plan: &Plan) -> Vec<String> {
    let mut lines = Vec::new();
    for short in plan.short.iter().take(NAMED) {
        let Some(target) = pool.targets.get(short.target) else { continue };
        let kind = target.facts.kind.map_or_else(String::new, |row| format!("{}, ", row.what));
        let state = if target.facts.kind_unused { format!("{kind}packed: its content does not show in its stream") } else { format!("{kind}{}, {} known in a row", target.facts.layout.label(), things(usize::try_from(short.known).unwrap_or(usize::MAX), "byte", "bytes")) };
        lines.push(format!("  {}   {state}", target.name));
        if target.facts.layout != Layout::Packed {
            let missing = 8_u64.saturating_sub(short.known);
            if missing > 0 {
                lines.push(format!(
                    "      {} of its start are enough (--starts {}=...); one fewer with --deep, which takes hours",
                    things(usize::try_from(missing).unwrap_or(8), "more byte", "more bytes"),
                    target.entry.filename.rsplit(|byte| *byte == b'/').next().map_or_else(String::new, |name| String::from_utf8_lossy(name).into_owned())
                ));
            }
        }
    }
    if plan.short.len() > NAMED {
        lines.push(format!("  ... and {} more", grouped((plan.short.len() - NAMED) as u64)));
    }
    lines
}

/// The entries that are most likely files other people have as well: programs, libraries,
/// fonts and licence texts, with their size and CRC-32 (section 6.4 of the design).
fn elsewhere_lines(pool: &Pool) -> Vec<String> {
    const KINDS: [&str; 16] = [".dll", ".exe", ".so", ".sys", ".jar", ".ttf", ".otf", ".woff", ".woff2", ".msi", ".deb", ".rpm", ".iso", ".apk", ".dylib", ".class"];
    const NAMES: [&str; 6] = ["license", "licence", "copying", "notice", "readme", "authors"];
    let public = |target: &Target| {
        let name = String::from_utf8_lossy(&target.entry.filename).to_ascii_lowercase();
        let last = name.rsplit('/').next().unwrap_or(&name).to_owned();
        KINDS.iter().any(|kind| last.ends_with(kind)) || NAMES.iter().any(|known| last.starts_with(known))
    };
    pool.targets.iter().filter(|target| public(target) && target.entry.uncompressed_size > 0).take(NAMED).map(|target| format!("  {}   {} bytes   CRC-32 {:08x}", target.name, grouped(target.entry.uncompressed_size), target.entry.crc32)).collect()
}

/// What a list of known files says of the entries (section 6.4 of the design): each entry
/// that is in it, with the name and the hashes the list has for it.
#[must_use]
pub(crate) fn catalogue_lines(pool: &Pool, path: &std::path::Path, listed: &Catalogue) -> Vec<String> {
    let entries = pool.targets.iter().enumerate().filter(|(index, _)| listed.known.iter().any(|known| known.target == *index)).count();
    let passed_over = if listed.passed_over > 0 { format!(" ({} of them could not be read as a row)", grouped(listed.passed_over)) } else { String::new() };
    let mut lines = vec![format!(
        "--catalogue {}: {} read{passed_over}; {}",
        path.display(),
        things(usize::try_from(listed.rows).unwrap_or(usize::MAX), "row", "rows"),
        if entries == 0 { "no entry of the archive is in it".to_owned() } else { format!("{} in it", if entries == 1 { "1 entry is".to_owned() } else { format!("{} entries are", grouped(entries as u64)) }) }
    )];
    for known in &listed.known {
        let Some(target) = pool.targets.get(known.target) else { continue };
        let name = known.name.as_ref().map_or_else(String::new, |name| format!("   known as {name:?}"));
        let hash = |label: &str, value: Option<&String>| value.map_or_else(String::new, |value| format!("   {label} {value}"));
        lines.push(format!("  {}{name}{}{}", target.name, hash("SHA-1", known.sha1.as_ref()), hash("MD5", known.md5.as_ref())));
    }
    if entries > 0 {
        lines.push("  find one of these files, pass it with --known, and the rest is seconds".to_owned());
    }
    lines
}

/// The same as an event.
#[must_use]
pub(crate) fn catalogue_event(pool: &Pool, listed: &Catalogue) -> Value {
    let known: Vec<Value> = listed.known.iter().map(|known| json!({ "entry": pool.targets.get(known.target).map(|target| target.name.as_str()), "name": known.name, "sha1": known.sha1, "md5": known.md5 })).collect();
    json!({ "event": "catalogue", "rows": listed.rows, "passed_over": listed.passed_over, "known": known })
}

/// The one thing that would shorten the plan most.
fn help_most(pool: &Pool, plan: &Plan) -> &'static str {
    let sure_and_quick = plan.attempts.first().is_some_and(|attempt| attempt.certainty >= Certainty::Derived && attempt.work() < 100_000.0);
    if sure_and_quick {
        "nothing: the first attempt is sure and short"
    } else if pool.targets.iter().all(|target| target.facts.layout == Layout::Packed) {
        "one file that is in the archive, stored in a second archive under the same password, or found and given with --known"
    } else {
        "one file that is in the archive, in any version (--known)"
    }
}

/// Every claim that was made, entry by entry, for `-v` (section 13.5 of the design).
#[must_use]
pub(crate) fn claim_lines(pool: &Pool, claims: &[(usize, crate::formats::zip::known::claim::Claim)]) -> Vec<String> {
    let mut lines = vec!["claims".to_owned()];
    for (index, target) in pool.targets.iter().enumerate() {
        lines.push(format!("  {} ({}, {} bytes of stream)", target.name, target.facts.layout.label(), grouped(target.stream_len())));
        for way in &target.facts.checks {
            lines.push(format!("      header     {:9} {}", way.certainty.as_str(), way.what()));
        }
        for claim in target.facts.claims.iter().chain(claims.iter().filter(|(of, _)| *of == index).map(|(_, claim)| claim)) {
            let run = claim.forms.iter().flat_map(crate::formats::zip::known::claim::Form::stretches).map(|(_, len)| len).max().unwrap_or(0);
            let forms = if claim.forms.len() == 1 { String::new() } else { format!(", in {} forms", grouped(claim.forms.len() as u64)) };
            lines.push(format!("      {:10} {:9} {}: {} known in a row{forms}", claim.origin.as_str(), claim.certainty.as_str(), claim.what, things(usize::try_from(run).unwrap_or(usize::MAX), "byte", "bytes")));
        }
        if target.facts.kind_unused {
            lines.push("      name                 the type of the entry is known, and the entry is packed: its content does not show in its stream".to_owned());
        }
    }
    lines
}

/// The plan as one event.
#[must_use]
pub(crate) fn plan_event(pool: &Pool, plan: &Plan, speed: &Speed, budget: Budget) -> Value {
    let budget = match budget {
        Budget::Limit(time) => json!(time.as_secs()),
        Budget::Unlimited => Value::Null,
    };
    let attempts: Vec<Value> = plan
        .attempts
        .iter()
        .enumerate()
        .map(|(number, attempt)| {
            json!({
                "id": number + 1,
                "entry": pool.targets.get(attempt.target).map(|target| target.name.as_str()),
                "path": attempt.path.as_str(),
                "source": attempt.origin.as_str(),
                "certainty": attempt.certainty.as_str(),
                "run": attempt.run.len,
                "searches": attempt.run.searches,
                "candidates": whole(attempt.work()),
                "estimate_s": attempt.seconds(speed.rate, speed.threads),
                "short_password_only": attempt.short_only,
            })
        })
        .collect();
    json!({ "event": "plan", "archives": pool.archives.iter().map(|archive| archive.path.display().to_string()).collect::<Vec<_>>(), "budget_s": budget, "rate": speed.rate, "kernel": speed.kernel.name(), "threads": speed.threads, "attempts": attempts })
}

/// Why an attempt that found nothing found nothing, by how sure its claim was (section 13.3 of
/// the design).
#[must_use]
pub(crate) fn why_nothing(attempt: &Attempt) -> &'static str {
    match attempt.certainty {
        Certainty::Guess => "The claim was a guess, and the guess was wrong.",
        Certainty::Likely => "The claim holds for most files of this kind, and this one is an exception.",
        Certainty::Derived => "The claim follows from how the writer of the archive behaves: this entry was written otherwise.",
        Certainty::Certain => "The claim was certain: the entry is not what the directory of the archive says.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_is_grouped_in_threes() {
        assert_eq!([0, 7, 999, 1000, 61_204, 1_056_075, u64::MAX].map(grouped), ["0", "7", "999", "1,000", "61,204", "1,056,075", "18,446,744,073,709,551,615"]);
        assert_eq!((whole(2311.4), whole(-1.0), whole(f64::NAN)), (2311, 0, 0));
        assert_eq!((things(1, "entry", "entries"), things(2145, "entry", "entries")), ("1 entry".to_owned(), "2,145 entries".to_owned()));
    }

    #[test]
    fn the_line_of_a_search_says_how_far_it_is_and_how_long_at_most() {
        let line = search_line(718, 2311, Duration::from_millis(1200), 600.0);
        assert!(line.contains("[=========>                    ]"), "{line}");
        assert!(line.contains(" 31 %   718 of 2,311   1 second so far, at most about 3 seconds more"), "{line}");
        let done = search_line(2311, 2311, Duration::from_secs(4), 600.0);
        assert!(done.contains("[==============================] 100 %") && done.contains("at most under a second more"), "{done}");
        assert!(search_line(0, 0, Duration::ZERO, 0.0).contains("  0 %"));
    }

    #[test]
    fn a_span_of_an_estimate_is_said_in_words() {
        assert_eq!((span(0.2), span(58.0), span(4.0 * 3600.0), span(-3.0)), ("under a second".to_owned(), "about 58 seconds".to_owned(), "about 4 hours".to_owned(), "under a second".to_owned()));
        assert!(span(f64::INFINITY).starts_with("about "));
    }
}
