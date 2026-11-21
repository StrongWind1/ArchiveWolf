//! The header paths in the plan and at work: from the encryption headers of an archive to
//! its keys, with no known byte of any file.
//!
//! Two kinds of writers are open to them. The Info-ZIP family fills its headers from
//! `rand()` and encrypts them twice: the seed is found from the first byte of each header,
//! for the `rand()` of each C library that `zip` is built against, and the attack of Stay
//! gives the keys from the headers alone. SharpZipLib and DotNetZip
//! fill theirs from `System.Random` and encrypt them once: on the runtimes whose generator
//! can be predicted the seed gives every header byte, and a header is then a run of twelve.
//! A third kind seeds the generator of its C library from a clock for each entry and
//! encrypts once, as the `ZipArchive` library and zip utils do: the clock at each entry gives
//! every header, and the headers together leave the search a handful of candidates.

use std::ops::Range;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use super::Run;
use super::plan::Attempt;
use super::plan::Limits;
use super::plan::Path;
use super::pool::Pool;
use super::proof::Proof;
use super::proof::prove;
use super::report;
use super::report::grouped;
use super::search::Found;
use super::search::Search;
use super::seed;
use super::seed::Generator as _;
use super::seed::borland;
use super::seed::bsd;
use super::seed::clocked;
use super::seed::dotnet;
use super::seed::fpc;
use super::seed::glibc;
use super::seed::msvcrt;
use super::seed::musl;
use super::seed::netfx;
use super::seed::stay;
use crate::formats::zip::encryption::FLAG_DATA_DESCRIPTOR;
use crate::formats::zip::known::claim::Certainty;
use crate::formats::zip::known::claim::Form;
use crate::formats::zip::known::claim::Origin;
use crate::formats::zip::known::claim::Run as KnownRun;
use crate::formats::zip::known::claim::expected_candidates;
use crate::formats::zip::known::set::ByteSet;
use crate::formats::zip::known::writer::HeaderMark;
use crate::formats::zip::known::writer::Writer;
use crate::formats::zip::known::writer::header_mark;

/// The fewest entries the keys follow from by the headers of the Info-ZIP family (section
/// 8.3 of the design).
const INFO_ZIP_ENTRIES: usize = stay::MIN_ENTRIES;

/// The fewest entries that leave one seed of .NET and not a thousand (section 8.5).
const DOT_NET_ENTRIES: usize = 5;

/// The most entries the attack of Stay is given. Each is a filter of its own, and nine
/// leave one guess after the third stage.
const STAY_ENTRIES: usize = 9;

/// How many headers of the sequence of Free Pascal an archive is looked for in: the encrypted
/// entries that the zip plugin of Double Commander can have written before it, in one run.
const FPC_HEADERS: usize = 1 << 17;

/// The most seeds that are followed up when a search leaves several.
const SEEDS_MAX: usize = 6;

/// What `zip` seeds with in place of a process number where it has none to ask for, on
/// Windows and DOS, and what minizip seeds with everywhere: the digits of pi.
const NO_PROCESS: u32 = 0xbb40_e64e;

/// The first second of the year 2000, in seconds of Unix time: no archive of `zip` 3.0 is
/// older, so no seed that is a time is below it.
const YEAR_2000: u64 = 946_684_800;

/// How far a process number moves a seed from the time it was made of: process numbers are
/// below 2^22 on Linux and below 100,000 on macOS.
const PROCESS_BITS: u32 = 22;

/// How many values of a clock one block of a search for it holds: the answers of a block are
/// put to the keys before the next block is searched.
const CLOCK_BLOCK: u64 = 1 << 18;

/// The most answers of one pass of a search for a clock that are put to the keys. A pass that
/// leaves more says too little of the clock to be worth its time.
const ANSWERS_MAX: usize = 400;

/// The most entries of one group, and of all groups, that the tree of a clock is made of.
const GROUP_ENTRIES: usize = 8;
const TREE_ENTRIES: usize = 96;

/// The fewest groups for which a clock is looked for through all the time there is, and
/// not only around the times the archive itself names.
const GROUPS_FOR_ALL: usize = 5;

/// The passes over a clock of few values: how many steps of it behind the first group the
/// other groups are looked for, the fewest groups the pass is run with, and what it is in the
/// words of the progress. A group that may lie anywhere has four headers that fit the first
/// byte, and a candidate key agrees with one of them more often than not: a dozen groups and
/// more make up for that, and three do when they lie close together.
const FEW_VALUES_PASSES: [(u64, usize, &str); 4] = [(32, FEW_VALUES_GROUPS, "entries within 32 ms of the first"), (128, 4, "entries within 128 ms of the first"), (512, 7, "entries within half a second of the first"), (u64::MAX, 13, "entries at any time")];

/// The fewest groups any of those passes is run with.
const FEW_VALUES_GROUPS: usize = 3;

/// What the search for a clock was measured to take when it finds none, in seconds, for an
/// archive of six groups whose entries are a few years old: every pass of every writer. With
/// a clock it ends in a few seconds at most.
const CLOCKED_SECONDS: f64 = 30.0;

/// The DOS date and time of an entry as seconds of Unix time, as if the clock that set them
/// ran on UTC. `None` for a date that is none.
fn seconds_of(date: u16, time: u16) -> Option<u64> {
    let (year, month, day) = (1980 + i64::from(date >> 9), i64::from((date >> 5) & 15), i64::from(date & 31));
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // the days since 1970, by the count of days in eras of 400 years that start in March
    let years = if month <= 2 { year - 1 } else { year };
    let (era, of_era) = (years.div_euclid(400), years.rem_euclid(400));
    let of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let days = era * 146_097 + of_era * 365 + of_era / 4 - of_era / 100 + of_year - 719_468;
    u64::try_from(days * 86_400 + i64::from(time >> 11) * 3600 + i64::from((time >> 5) & 63) * 60 + i64::from(time & 31) * 2).ok()
}

/// One pass of a search for a clock: the values the first group is looked for at, and how
/// many steps of the clock may lie between one group and the next.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pass {
    clocks: Range<u64>,
    gap: usize,
    /// What the values are, for the line of the progress.
    what: &'static str,
}

/// The passes of the search for the clock of a writer, in the order they are run: the times
/// an archive names itself first, with few steps between two groups before many.
///
/// `newest` is the latest time an entry was changed at and `modified` the time the file of
/// the archive was last written, both in seconds of Unix time, and `now` the time it is.
fn passes(writer: clocked::Writer, groups: usize, newest: Option<u64>, modified: Option<u64>, now: u64) -> Vec<Pass> {
    const HOUR: u64 = 3600;
    const DAY: u64 = 24 * HOUR;
    if !writer.by_the_second() {
        // the count of a timer says nothing of the day: every count there is
        let mut passes = vec![Pass { clocks: 0..clocked::INTERRUPTS, gap: 2, what: "every count of the timer, groups next to each other" }];
        if groups >= GROUPS_FOR_ALL {
            passes.push(Pass { clocks: 0..clocked::INTERRUPTS, gap: 32, what: "every count of the timer, groups up to half a second apart" });
        }
        return passes;
    }
    let mut passes = Vec::new();
    let end = now + DAY;
    // a file that was not copied since was last written when its last entry was
    if let Some(modified) = modified.filter(|modified| (YEAR_2000..end).contains(modified)) {
        passes.push(Pass { clocks: modified.saturating_sub(HOUR)..modified + 2, gap: 64, what: "the hour before the file of the archive was last written" });
    }
    // an archive is written after its newest entry was last changed, and the time of the
    // entry is that of a clock up to fourteen hours ahead of UTC
    let from = newest.map_or(YEAR_2000, |newest| newest.saturating_sub(15 * HOUR)).clamp(YEAR_2000, end);
    let near = if newest.is_some() { (from + 4 * DAY + 15 * HOUR).min(end) } else { from };
    if newest.is_some() {
        passes.push(Pass { clocks: from..near, gap: 4, what: "the days after the newest entry was changed, groups next to each other" });
        passes.push(Pass { clocks: from..near, gap: 64, what: "the days after the newest entry was changed, groups up to a minute apart" });
    }
    if groups >= GROUPS_FOR_ALL && near < end {
        passes.push(Pass { clocks: near..end, gap: 4, what: "every second since, groups next to each other" });
    }
    passes
}

/// A C library whose `rand()` the `zip` of Info-ZIP fills its headers from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Library {
    /// glibc: the `zip` of most Linux systems.
    Glibc,
    /// The C library of macOS.
    MacOs,
    /// musl: the `zip` of Alpine Linux.
    Musl,
    /// The C runtime of Windows.
    Windows,
    /// The C runtime of Borland, which the oldest versions of WinRAR were built with.
    Borland,
    /// The same, with each byte put through the table of the CRC-32 as WinRAR 3.20 does.
    BorlandMixed,
}

impl Library {
    /// Every library, in the order they are searched.
    const ALL: [Self; 6] = [Self::Glibc, Self::MacOs, Self::Musl, Self::Windows, Self::Borland, Self::BorlandMixed];

    const fn label(self) -> &'static str {
        match self {
            Self::Glibc => "glibc",
            Self::MacOs => "macOS",
            Self::Musl => "musl",
            Self::Windows => "Windows",
            Self::Borland => "Borland",
            Self::BorlandMixed => "Borland as WinRAR 3.20 reads it",
        }
    }

    /// Every seed that gives the first byte of every header, among all 2^32, when up to
    /// `spare` headers were drawn and not written.
    fn seeds(self, first: &[u8], spare: usize, control: seed::Control<'_>) -> Vec<u32> {
        match (self, spare) {
            (Self::Glibc, 0) => glibc::seeds(first, control),
            (Self::MacOs, 0) => seed::seeds::<bsd::Rand>(first, control),
            (Self::Musl, 0) => seed::seeds::<musl::Rand>(first, control),
            (Self::Windows, 0) => seed::seeds::<msvcrt::Rand>(first, control),
            (Self::Borland, 0) => seed::seeds::<borland::Rand>(first, control),
            (Self::BorlandMixed, 0) => seed::seeds::<borland::Mixed>(first, control),
            (Self::Glibc, _) => glibc::seeds_with_gaps(first, spare, control),
            (Self::MacOs, _) => seed::seeds_with_gaps::<bsd::Rand>(first, spare, control),
            (Self::Musl, _) => seed::seeds_with_gaps::<musl::Rand>(first, spare, control),
            (Self::Windows, _) => seed::seeds_with_gaps::<msvcrt::Rand>(first, spare, control),
            (Self::Borland, _) => seed::seeds_with_gaps::<borland::Rand>(first, spare, control),
            (Self::BorlandMixed, _) => seed::seeds_with_gaps::<borland::Mixed>(first, spare, control),
        }
    }

    /// The header that each entry has among those drawn after a seed, by its number.
    fn places(self, seed: u32, first: &[u8], spare: usize) -> Option<Vec<usize>> {
        let count = first.len() + spare;
        let headers = match self {
            Self::Glibc => glibc::drawn(seed, count),
            Self::MacOs => seed::drawn::<bsd::Rand>(seed, count),
            Self::Musl => seed::drawn::<musl::Rand>(seed, count),
            Self::Windows => seed::drawn::<msvcrt::Rand>(seed, count),
            Self::Borland => seed::drawn::<borland::Rand>(seed, count),
            Self::BorlandMixed => seed::drawn::<borland::Mixed>(seed, count),
        };
        seed::places(&headers, first, spare)
    }

    /// The seed that stands for every seed of the same values.
    fn stream_of(self, seed: u32) -> u32 {
        match self {
            Self::Glibc => seed,
            Self::MacOs => bsd::Rand::stream_of(seed),
            Self::Musl => musl::Rand::stream_of(seed),
            Self::Windows => msvcrt::Rand::stream_of(seed),
            Self::Borland => borland::Rand::stream_of(seed),
            Self::BorlandMixed => borland::Mixed::stream_of(seed),
        }
    }

    /// The ten bytes `zip` drew for each of its first entries after this seed.
    fn header_bytes(self, seed: u32, entries: usize) -> Vec<[u8; glibc::HEADER_BYTES]> {
        match self {
            Self::Glibc => glibc::header_bytes(seed, entries),
            Self::MacOs => seed::header_bytes::<bsd::Rand>(seed, entries),
            Self::Musl => seed::header_bytes::<musl::Rand>(seed, entries),
            Self::Windows => seed::header_bytes::<msvcrt::Rand>(seed, entries),
            Self::Borland => seed::header_bytes::<borland::Rand>(seed, entries),
            Self::BorlandMixed => seed::header_bytes::<borland::Mixed>(seed, entries),
        }
    }
}

/// Whether a seed can be made of a time of this century: `zip` seeds with the time
/// exclusive-or a process number, or exclusive-or a constant where it has none. A seed that
/// fits the headers by chance is such a seed in two cases of five.
fn is_a_time(seed: u32) -> bool {
    made_of(seed).is_some()
}

/// What a seed that can be made of a time is made of, in the words of a note.
fn made_of(seed: u32) -> Option<&'static str> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(u64::MAX, |since| since.as_secs());
    let times = YEAR_2000..=now.saturating_add(1 << PROCESS_BITS);
    if times.contains(&u64::from(seed)) {
        Some("It is the time the archive was written, exclusive-or the number of the process that wrote it")
    } else if times.contains(&u64::from(seed ^ NO_PROCESS)) {
        Some("It is the time the archive was written, exclusive-or the constant that minizip and the library of zip take where zip takes a process number")
    } else {
        None
    }
}

/// The seeds to follow up: one for each stream of values of each library, and those that
/// can be made of a time in front, since the true seed is. Seeds that give one stream are
/// one seed here, the one that can be made of a time when one of them can.
fn candidates(found: &[(Library, Vec<u32>)]) -> Vec<(Library, u32)> {
    let mut seeds: Vec<(Library, u32)> = Vec::new();
    for (library, of_library) in found {
        let mut streams: Vec<u32> = of_library.iter().map(|&seed| library.stream_of(seed)).collect();
        streams.sort_unstable();
        streams.dedup();
        for stream in streams {
            let of_stream = || of_library.iter().copied().filter(|seed| library.stream_of(*seed) == stream);
            seeds.extend(of_stream().find(|seed| is_a_time(*seed)).or_else(|| of_stream().next()).map(|seed| (*library, seed)));
        }
    }
    // stable: among the seeds that can be a time, and among those that cannot, the order of the libraries stays
    seeds.sort_by_key(|(_, seed)| !is_a_time(*seed));
    seeds
}

/// The rate the times below were measured at, in candidates a second: they are taken as
/// candidates of that rate, so that a plan scales them with the speed of its machine.
const MEASURED_RATE: f64 = 19_600.0;

/// What the searches of the header paths took on the machine they were measured on, in
/// seconds: all seeds of glibc and of macOS and the attack of Stay with five entries or more,
/// the same with four, and all thread seeds of .NET.
const INFO_ZIP_SECONDS: f64 = 5.0;
const INFO_ZIP_FOUR_SECONDS: f64 = 30.0;
const DOT_NET_SECONDS: f64 = 14.0;

/// A header path of one archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Special {
    /// The Info-ZIP family: the seed of `rand()`, then the keys from the headers.
    InfoZip {
        /// The archive, by its place in the pool.
        archive: usize,
    },
    /// SharpZipLib and DotNetZip: the seed of `System.Random`, then a run of twelve.
    DotNet {
        /// The archive, by its place in the pool.
        archive: usize,
    },
    /// A writer that seeds from a clock for each entry: the clock, then the keys from the
    /// headers.
    Clocked {
        /// The archive, by its place in the pool.
        archive: usize,
    },
}

/// How one pass of the search for a clock ended.
struct ClockedEnd {
    /// The keys that were proved, and the clock at the first group that gave them.
    proved: Option<(Found, u64)>,
    /// Keys that were found and not proved.
    unproved: Vec<Found>,
    /// How many candidates the headers left the search that found the keys.
    candidates: u64,
    /// Whether more clocks fit the headers than are put to the keys.
    too_many: bool,
}

/// The entries of an archive in the order their writer wrote them: as they lie in the file.
fn written(pool: &Pool, archive: usize) -> Vec<usize> {
    let mut order: Vec<usize> = pool.targets.iter().enumerate().filter(|(_, target)| target.archive == archive).map(|(index, _)| index).collect();
    order.sort_by_key(|&index| pool.targets.get(index).map_or(0, |target| target.start));
    order
}

/// The header paths that the archives of a pool allow, as attempts of a plan.
#[must_use]
pub(crate) fn attempts(pool: &Pool, limits: &Limits) -> Vec<Attempt> {
    let mut attempts = Vec::new();
    for (number, archive) in pool.archives.iter().enumerate() {
        let order = written(pool, number);
        if limits.entries.as_ref().is_some_and(|entries| !order.iter().any(|index| entries.contains(index))) {
            continue;
        }
        let Some(&first) = order.first() else { continue };
        let headers: Vec<[u8; 12]> = order.iter().filter_map(|&index| pool.targets.get(index)).map(|target| target.header).collect();
        // entries with one header: a generator that a clock seeded for each of them, which that of Info-ZIP is not
        let shared = headers.windows(2).any(|pair| pair.first().and_then(|header| header.first_chunk::<10>()) == pair.last().and_then(|header| header.first_chunk::<10>()));
        let mut paths: Vec<(Special, Path, Certainty, f64, f64, String)> = Vec::new();
        match archive.writer {
            Writer::InfoZip | Writer::WinRar if order.len() >= INFO_ZIP_ENTRIES => {
                let seconds = if order.len() == INFO_ZIP_ENTRIES { INFO_ZIP_FOUR_SECONDS } else { INFO_ZIP_SECONDS };
                paths.push((Special::InfoZip { archive: number }, Path::Header, Certainty::Likely, 0.8, seconds, format!("encryption headers of {} entries of one run: the seed of their generator, then the keys from the headers", grouped(order.len() as u64))));
            },
            // the headers of Info-ZIP are also those of minizip and of what is built on it, which
            // leave no mark of their own in the directory: a writer that is not known is asked
            // the same question, as a guess that costs the seed searches when it is wrong
            Writer::Unknown if order.len() >= INFO_ZIP_ENTRIES && !shared => {
                let seconds = if order.len() == INFO_ZIP_ENTRIES { INFO_ZIP_FOUR_SECONDS } else { INFO_ZIP_SECONDS };
                paths.push((Special::InfoZip { archive: number }, Path::Header, Certainty::Guess, 0.15, seconds, format!("encryption headers of {} entries: whether the generator of a C library filled them, as zip and minizip do, then the keys from the headers", grouped(order.len() as u64))));
            },
            Writer::SharpZipLib | Writer::DotNetZip if order.len() >= DOT_NET_ENTRIES => {
                let seconds = DOT_NET_SECONDS + expected_candidates(12) / MEASURED_RATE;
                paths.push((Special::DotNet { archive: number }, Path::HeaderOnce, Certainty::Guess, 0.3, seconds, format!("encryption headers of {} entries, encrypted once: the seed of their generator, then a run of twelve", grouped(order.len() as u64))));
            },
            _ => {},
        }
        // a writer that seeds for each entry leaves no mark in the directory either, and the
        // ZipArchive library on Windows leaves those of yeka/zip, whose headers are one constant
        let groups = 1 + headers.windows(2).filter(|pair| pair.first().and_then(|header| header.first_chunk::<10>()) != pair.last().and_then(|header| header.first_chunk::<10>())).count();
        if matches!(archive.writer, Writer::Unknown | Writer::Yeka) && groups >= 2 && header_mark(&headers) != Some(HeaderMark::Constant) {
            let chance = if shared { 0.5 } else { 0.05 };
            paths.push((
                Special::Clocked { archive: number },
                Path::HeaderOnce,
                Certainty::Guess,
                chance,
                CLOCKED_SECONDS,
                format!("encryption headers of {} entries, encrypted once: whether a clock seeded their generator for each entry, as the ZipArchive library and zip utils do, then the keys from the headers", grouped(order.len() as u64)),
            ));
        }
        // a library of .NET that makes a generator for every entry and leaves no mark of its
        // own in the directory, as Aspose.ZIP does: the question of SharpZipLib and DotNetZip,
        // asked as a guess
        if archive.writer == Writer::Unknown && order.len() >= DOT_NET_ENTRIES && header_mark(&headers) != Some(HeaderMark::Constant) {
            let seconds = DOT_NET_SECONDS + expected_candidates(12) / MEASURED_RATE;
            let chance = if shared { 0.3 } else { 0.05 };
            paths.push((
                Special::DotNet { archive: number },
                Path::HeaderOnce,
                Certainty::Guess,
                chance,
                seconds,
                format!("encryption headers of {} entries, encrypted once: whether a library of .NET made a generator for each entry, as Aspose.ZIP does, then a run of twelve", grouped(order.len() as u64)),
            ));
        }
        for (special, path, certainty, chance, seconds, what) in paths {
            if (limits.no_guess && certainty < Certainty::Derived) || (!limits.only.is_empty() && !limits.only.contains(&path)) {
                continue;
            }
            attempts.push(Attempt { target: first, path, origin: Origin::Method, certainty, what, form: Form::new(), run: KnownRun { at: -12, len: 12, searches: 1, holes: 0 }, candidates: seconds * MEASURED_RATE, counted: true, chance, behind: 0.0, short_only: false, special: Some(special) });
        }
    }
    attempts
}

impl Run<'_> {
    /// Run a search of seeds or of the stages of Stay with its progress shown: `work` gets
    /// the control it advances, and `total` is what it counts to.
    fn counted<T>(&self, label: &str, total: u64, work: impl FnOnce(seed::Control<'_>) -> T) -> T {
        let done = AtomicU64::new(0);
        let finished = AtomicBool::new(false);
        let started = Instant::now();
        let (voice, redraws) = (self.voice, self.voice.redraws());
        std::thread::scope(|scope| {
            drop(scope.spawn(|| {
                let pause = if redraws { super::REDRAW } else { super::WRITE };
                let mut waited = Duration::ZERO;
                while !finished.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(50));
                    waited += Duration::from_millis(50);
                    if waited >= pause && !finished.load(Ordering::Relaxed) {
                        waited = Duration::ZERO;
                        voice.progress(&report::stage_line(label, done.load(Ordering::Relaxed), total, started.elapsed()), false);
                    }
                }
            }));
            let result = work(seed::Control { stop: &self.stop, done: &done, threads: self.speed.threads });
            finished.store(true, Ordering::Relaxed);
            if redraws {
                voice.progress(&report::stage_line(label, total, total, started.elapsed()), true);
            }
            result
        })
    }

    /// Put keys that the headers gave to the proof, on the first entry that can give one.
    /// `bits` is what the headers themselves are worth.
    fn proved_by_headers(&self, keys: archivewolf_zip_crypto::Keys, order: &[usize], bits: f64) -> Found {
        for &index in order {
            let Some((target, source)) = self.pool.targets.get(index).and_then(|target| Some((target, self.pool.source(target)?))) else { continue };
            if let Proof::Holds(proof) = prove(source, target, keys) {
                return Found { keys, candidate: 0, bits: bits + proof, proved_on: Some(index) };
            }
        }
        Found { keys, candidate: 0, bits, proved_on: None }
    }

    /// A header path of one archive: what it proved, and what it found and could not prove.
    pub(super) fn header_path(&self, special: Special) -> (Option<Found>, Vec<Found>) {
        match special {
            Special::InfoZip { archive } => self.info_zip(archive),
            Special::DotNet { archive } => self.dot_net(archive),
            Special::Clocked { archive } => self.clocked(archive),
        }
    }

    /// A writer that seeds from a clock for each entry: for each such writer the clock at
    /// every group of entries with one header, and from the headers the keys.
    fn clocked(&self, archive: usize) -> (Option<Found>, Vec<Found>) {
        let order = written(&self.pool, archive);
        let entry = |index: usize| self.pool.targets.get(index).map(|target| &target.entry);
        let newest = order.iter().filter_map(|&index| entry(index)).filter_map(|entry| seconds_of(entry.last_mod_date, entry.last_mod_time)).max();
        let since_epoch = |time: std::time::SystemTime| time.duration_since(std::time::UNIX_EPOCH).ok().map(|since| since.as_secs());
        let modified = self.pool.archives.get(archive).and_then(|archive| std::fs::metadata(&archive.path).ok()?.modified().ok()).and_then(since_epoch);
        let now = since_epoch(std::time::SystemTime::now()).unwrap_or(u64::MAX / 2);
        let mut unproved = Vec::new();
        let (mut one_group, mut few_groups) = (false, false);
        for writer in clocked::Writer::ALL {
            // the groups of entries with one header, as far as the writer draws it
            let mut groups: Vec<Vec<usize>> = Vec::new();
            for &index in &order {
                let Some(target) = self.pool.targets.get(index) else { continue };
                let same = groups.last().and_then(|group| group.first()).and_then(|&of_group| self.pool.targets.get(of_group)).is_some_and(|of_group| of_group.header.get(..writer.random()) == target.header.get(..writer.random()));
                match groups.last_mut() {
                    Some(group) if same => group.push(index),
                    _ => groups.push(vec![index]),
                }
            }
            if groups.len() < 2 {
                one_group = true;
                continue;
            }
            // a clock of few values: every one of them is tried, and nothing is searched for.
            // Entries that were written shortly after the first are asked for before those
            // at any time of the second, which say less and take more groups to tell
            if let Some(values) = writer.values() {
                // the library of ComponentOne names version 4.5 in the directory and writes a
                // data descriptor behind every encrypted entry: an archive without those marks
                // is not asked, since each pass costs a search of its own for every value
                if !order.iter().filter_map(|&index| entry(index)).all(|entry| entry.made_by == 45 && entry.flags & FLAG_DATA_DESCRIPTOR != 0) {
                    continue;
                }
                if groups.len() < FEW_VALUES_GROUPS {
                    few_groups = true;
                }
                for (within, needed, what) in FEW_VALUES_PASSES {
                    if groups.len() < needed {
                        continue;
                    }
                    let ended = self.counted(&format!("clock search, {}, {what}", writer.label()), values, |control| self.every_clock(writer, &groups, values, within.min(values - 1), control));
                    unproved.extend(ended.unproved);
                    if let Some((found, clock)) = ended.proved {
                        self.voice.say(&format!(
                            "      the archive was written by {}, which seeds its generator from the millisecond of the clock for every entry: its first entry was written at millisecond {clock} of a second. Each of the {} groups of entries that were written within one millisecond has one of a thousand headers, and the headers together left the search {} of its candidates",
                            writer.label(),
                            grouped(groups.len() as u64),
                            grouped(ended.candidates)
                        ));
                        return (Some(found), unproved);
                    }
                    if self.stop.load(Ordering::Relaxed) {
                        return (None, unproved);
                    }
                }
                continue;
            }
            let headers: Vec<[u8; 12]> = groups.iter().filter_map(|group| group.first()).filter_map(|&index| self.pool.targets.get(index)).map(|target| target.header).collect();
            for pass in passes(writer, groups.len(), newest, modified, now) {
                let total = pass.clocks.end - pass.clocks.start;
                // what a pass leaves when the writer is another: each group behind the first is
                // at one of the steps the gap allows, and fits one time in 256. A pass that is
                // bound to leave more answers than are put to the keys is not run
                let fitting = f64::from(u32::try_from(pass.gap).unwrap_or(u32::MAX)) / 256.0;
                let expected = (1..groups.len()).fold(f64::from(u32::try_from(total).unwrap_or(u32::MAX)), |left, _| left * fitting);
                if expected > f64::from(u32::try_from(ANSWERS_MAX).unwrap_or(u32::MAX)) {
                    self.voice.most(&format!("      {}, {}: not searched, the {} groups of entries say too little of so many clocks", writer.label(), pass.what, grouped(groups.len() as u64)));
                    continue;
                }
                let ended = self.counted(&format!("clock search, {}, {}", writer.label(), pass.what), total, |control| self.clocked_pass(writer, &groups, &headers, &pass, control));
                unproved.extend(ended.unproved);
                if let Some((found, clock)) = ended.proved {
                    let at = if writer.by_the_second() {
                        format!("its first entry was written at second {} of Unix time", grouped(clock))
                    } else {
                        let running = Duration::from_millis(u64::from(netfx::tick_count(clock)));
                        format!("the machine had been running for {} days {} hours when its first entry was written, or that and a multiple of 49.7 days", running.as_secs() / 86_400, running.as_secs() % 86_400 / 3600)
                    };
                    self.voice.say(&format!(
                        "      the archive was written by {}, which seeds its generator from a clock for every entry: {at}. The clock gives the header of each of the {} groups of entries that were written within one step of it, and the headers together left the search {} of its candidates",
                        writer.label(),
                        grouped(groups.len() as u64),
                        grouped(ended.candidates)
                    ));
                    return (Some(found), unproved);
                }
                if self.stop.load(Ordering::Relaxed) {
                    return (None, unproved);
                }
                if ended.too_many {
                    self.voice.most(&format!("      {}, {}: more than {} clocks fit the headers, which say too little to go on with them", writer.label(), pass.what, grouped(ANSWERS_MAX as u64)));
                }
            }
        }
        if one_group {
            self.voice.say("      all entries have one header for some writers that seed from a clock: they were written within one step of it, and two steps are needed to find it by");
        }
        if few_groups {
            self.voice.say(&format!("      the entries were written within fewer than {FEW_VALUES_GROUPS} milliseconds that differ: too few for the zip library of ComponentOne, whose thousand headers are told apart by the headers of the other entries"));
        }
        self.voice.say("      no clock of the ZipArchive library, of the zip library of ComponentOne or of zip utils gives the headers: the archive was not written by one of them, or at another time than the times it names");
        (None, unproved)
    }

    /// A clock of few values: each of them at the first group, and against it every value at
    /// each other group that gives the same first byte of the stream, which all headers share.
    /// The search for the keys runs on the header of the first group over the candidates that
    /// one header of every other group agrees with: for a wrong value none is left.
    ///
    /// `within` is how many steps of the clock behind the first group the others are looked
    /// for: all of them, when it is one less than the clock has values.
    fn every_clock(&self, writer: clocked::Writer, groups: &[Vec<usize>], values: u64, within: u64, control: seed::Control<'_>) -> ClockedEnd {
        let mut end = ClockedEnd { proved: None, unproved: Vec::new(), candidates: 0, too_many: false };
        // the first entry of each group: its place in the pool, its header and its time
        let firsts: Vec<(usize, [u8; 12], u16)> = groups.iter().filter_map(|group| group.first()).filter_map(|&index| self.pool.targets.get(index).map(|target| (index, target.header, target.entry.last_mod_time))).take(clocked::MAX_GROUPS).collect();
        let Some((&(index, written, time), others)) = firsts.split_first() else { return end };
        let first_byte = |header: &[u8]| header.first().copied().unwrap_or_default();
        // the first byte the generator gives at every value
        let firsts_of: Vec<u8> = (0..values).map(|clock| first_byte(&writer.plain(clock))).collect();
        for clock in 0..values {
            if self.stop.load(Ordering::Relaxed) {
                return end;
            }
            let _ = control.done.fetch_add(1, Ordering::Relaxed);
            let known = writer.header(clock, time);
            let stream = first_byte(&known) ^ first_byte(&written);
            let alternatives: Vec<Vec<([u8; 12], [u8; 12])>> =
                others.iter().map(|&(_, other, other_time)| (0..values).zip(&firsts_of).filter(|(value, byte)| (1..=within).contains(&((value + values - clock) % values)) && **byte ^ first_byte(&other) == stream).map(|(value, _)| (writer.header(value, other_time), other)).collect()).collect();
            if alternatives.iter().any(Vec::is_empty) {
                continue;
            }
            let Some(mut search) = Search::new(&self.pool, index, &Form::bytes(-12, &known), -12, &known, 1) else { continue };
            let tree = clocked::Tree::of_alternatives((known, written), &alternatives);
            let at = search.index();
            search.keep_only(self.speed.threads, |candidate| tree.allows(candidate, at));
            if search.candidates() == 0 {
                continue;
            }
            let done = AtomicU64::new(0);
            let keys = super::search::Control { kernel: self.speed.kernel, threads: self.speed.threads, stop: &self.stop, done: &done, short_password: true };
            let outcome = search.run(&keys, 0, search.candidates());
            end.unproved.extend(outcome.unproved);
            if let Some(found) = outcome.proved {
                end.proved = Some((found, clock));
                end.candidates = search.candidates() as u64;
                return end;
            }
        }
        end
    }

    /// One pass of the search for a clock: block by block, and every answer of a block put to
    /// the keys before the next block is searched.
    fn clocked_pass(&self, writer: clocked::Writer, groups: &[Vec<usize>], headers: &[[u8; 12]], pass: &Pass, control: seed::Control<'_>) -> ClockedEnd {
        let mut end = ClockedEnd { proved: None, unproved: Vec::new(), candidates: 0, too_many: false };
        let mut answers = 0;
        let mut from = pass.clocks.start;
        while from < pass.clocks.end && !self.stop.load(Ordering::Relaxed) {
            let until = (from + CLOCK_BLOCK).min(pass.clocks.end);
            let found = clocked::clocks(writer, headers, from..until, pass.gap, control);
            if found.len() >= clocked::FOUND_MAX {
                end.too_many = true;
                return end;
            }
            for clocks in found {
                answers += 1;
                if answers > ANSWERS_MAX {
                    end.too_many = true;
                    return end;
                }
                let Some((outcome, candidates)) = self.keys_at(writer, groups, &clocks) else { continue };
                end.unproved.extend(outcome.unproved);
                if let (Some(found), Some(&clock)) = (outcome.proved, clocks.first()) {
                    end.proved = Some((found, clock));
                    end.candidates = candidates;
                    return end;
                }
                if self.stop.load(Ordering::Relaxed) {
                    return end;
                }
            }
            from = until;
        }
        end
    }

    /// The search for the keys with a clock at each group: the run of twelve that the header
    /// of the first entry is, over the candidates that the headers of the other entries
    /// leave. With it, how many candidates that were. `None` when they leave none.
    fn keys_at(&self, writer: clocked::Writer, groups: &[Vec<usize>], clocks: &[u64]) -> Option<(crate::attack::zip_crypto::search::Outcome, u64)> {
        // every entry of the groups that have a clock, before and after encryption: entries of
        // one group differ in their time, behind what the generator gave
        let mut entries: Vec<(usize, [u8; 12], [u8; 12])> = Vec::new();
        for (group, &clock) in groups.iter().zip(clocks) {
            let mut of_group: Vec<[u8; 12]> = Vec::new();
            for target in group.iter().filter_map(|&index| self.pool.targets.get(index).map(|target| (index, target))) {
                let (index, target) = target;
                if of_group.len() < GROUP_ENTRIES && entries.len() < TREE_ENTRIES && !of_group.contains(&target.header) {
                    of_group.push(target.header);
                    entries.push((index, writer.header(clock, target.entry.last_mod_time), target.header));
                }
            }
        }
        let (&(index, known, header), others) = entries.split_first()?;
        let mut search = Search::new(&self.pool, index, &Form::bytes(-12, &known), -12, &known, 1)?;
        let others: Vec<([u8; 12], [u8; 12])> = others.iter().map(|&(_, plain, written)| (plain, written)).collect();
        let tree = clocked::Tree::new((known, header), &others);
        let at = search.index();
        search.keep_only(self.speed.threads, |candidate| tree.allows(candidate, at));
        if search.candidates() == 0 {
            return None;
        }
        let done = AtomicU64::new(0);
        let control = super::search::Control { kernel: self.speed.kernel, threads: self.speed.threads, stop: &self.stop, done: &done, short_password: true };
        Some((search.run(&control, 0, search.candidates()), search.candidates() as u64))
    }

    /// The attack of Stay on entries whose headers are known as the generator gave them, and
    /// the proof of the keys it gives: the keys that are proved, with those that are not put
    /// to `unproved`.
    fn keys_from_headers(&self, entries: &[stay::Entry], order: &[usize], unproved: &mut Vec<Found>) -> Option<Found> {
        let recovery = self.counted("keys from the headers", stay::RECOVER_TOTAL, |control| stay::recover(entries, control))?;
        self.voice.most(&format!("      the four stages left {:?} guesses", recovery.left));
        if self.stop.load(Ordering::Relaxed) {
            return None;
        }
        // the keys give ten header bytes of every entry that was used: 72 bits each beyond the first byte
        let bits = 72.0 * f64::from(u32::try_from(entries.len()).unwrap_or(0));
        for keys in recovery.keys {
            let found = self.proved_by_headers(keys, order, bits);
            if found.proved_on.is_some() {
                return Some(found);
            }
            unproved.push(found);
        }
        None
    }

    /// The Info-ZIP family: every seed of `rand()` that gives the first byte of every
    /// header, then the attack of Stay on the headers. In front of the seeds, the one sequence
    /// of a generator that is never seeded.
    fn info_zip(&self, archive: usize) -> (Option<Found>, Vec<Found>) {
        let order = written(&self.pool, archive);
        let headers: Vec<[u8; 12]> = order.iter().filter_map(|&index| self.pool.targets.get(index)).map(|target| target.header).collect();
        let first: Vec<u8> = headers.iter().map(|header| header.first().copied().unwrap_or_default()).collect();

        // first with every entry taken for the next header its writer drew, then with headers
        // that were drawn for files the writer gave up: a file `zip` cannot read to its end
        // leaves a header and no entry
        let spare = seed::spare_for(headers.len());
        let mut unproved = Vec::new();
        let mut tried: Vec<(Library, u32)> = Vec::new();

        // the generator of Free Pascal as it starts, with no seed: Abbrevia never seeds it, and
        // in the zip plugin of Double Commander nothing else does. The sequence is one, and
        // what is looked for is the place of the archive in it
        if let Some(before) = fpc::drawn_before(0, &first, FPC_HEADERS) {
            let earlier = if before == 0 { "no encrypted entry".to_owned() } else { format!("{} encrypted entries", grouped(before as u64)) };
            self.voice.say(&format!(
                "      the first byte of the header of all {} entries is that of the generator of Free Pascal as it starts, with no seed: Abbrevia draws its headers from it in the zip plugin of Double Commander, which had written {earlier} before these since it was loaded",
                grouped(headers.len() as u64)
            ));
            let entries: Vec<stay::Entry> = fpc::headers(0, before, headers.len()).iter().zip(&headers).map(|(random, header)| stay::Entry { random: *random, header: *header }).take(STAY_ENTRIES).collect();
            if let Some(found) = self.keys_from_headers(&entries, &order, &mut unproved) {
                return (Some(found), unproved);
            }
            if self.stop.load(Ordering::Relaxed) {
                return (None, unproved);
            }
        }
        for spare in [0, spare].into_iter().take(if spare > 0 { 2 } else { 1 }) {
            if spare > 0 {
                self.voice.say(&format!("      no keys with every entry at the next header of the generator: searching again with up to {spare} headers that were drawn and not written, as zip leaves them for a file it gives up"));
            }
            // the headers do not say which C library their writer was built against: every one is searched
            let mut found = Vec::new();
            for library in Library::ALL {
                found.push((library, self.counted(&format!("seed search, {}", library.label()), 1 << 32, |control| library.seeds(&first, spare, control))));
                if self.stop.load(Ordering::Relaxed) {
                    return (None, unproved);
                }
            }
            for (library, seed) in candidates(&found).into_iter().take(SEEDS_MAX) {
                if tried.contains(&(library, library.stream_of(seed))) {
                    continue;
                }
                tried.push((library, library.stream_of(seed)));
                let Some(places) = library.places(seed, &first, spare) else { continue };
                let time = made_of(seed).unwrap_or("It is not made of a time of this century, so it may fit by chance");
                self.voice.say(&format!("      seed {} of the generator of {}: it gives the first byte of the header of all {} entries. {time}", grouped(u64::from(seed)), library.label(), grouped(headers.len() as u64)));
                // the entries in front of which a header was drawn and not written
                let behind_gap: Vec<&str> = places.windows(2).zip(order.iter().skip(1)).filter(|(pair, _)| pair.first().zip(pair.last()).is_some_and(|(before, at)| at - before > 1)).filter_map(|(_, &index)| self.pool.targets.get(index)).map(|target| target.name.as_str()).collect();
                if !behind_gap.is_empty() {
                    let skipped = places.last().map_or(0, |last| last + 1 - places.len());
                    self.voice.say(&format!("      the writer drew {} more than the archive has entries: in front of {}", if skipped == 1 { "1 header".to_owned() } else { format!("{skipped} headers") }, behind_gap.join(", ")));
                }
                let drawn = library.header_bytes(seed, places.last().map_or(0, |last| last + 1));
                let entries: Vec<stay::Entry> = places.iter().zip(&headers).filter_map(|(&place, header)| Some(stay::Entry { random: *drawn.get(place)?, header: *header })).take(STAY_ENTRIES).collect();
                if let Some(found) = self.keys_from_headers(&entries, &order, &mut unproved) {
                    return (Some(found), unproved);
                }
                if self.stop.load(Ordering::Relaxed) {
                    return (None, unproved);
                }
            }
        }
        if !self.stop.load(Ordering::Relaxed) {
            if tried.is_empty() {
                self.voice.say("      no seed of the generator of glibc, of macOS, of musl, of Windows or of Borland gives the first byte of every header: the archive was not written in one run by a program that fills its headers as zip does from one of them");
            } else if unproved.is_empty() {
                self.voice.say("      the headers give no keys: they were not all encrypted under one password in one run");
            }
        }
        (None, unproved)
    }

    /// The run of twelve that a header gives once its bytes are known as they were before
    /// encryption: eleven bytes of the generator and the check byte behind them, searched on
    /// the entry at `index` of the pool.
    fn run_of_twelve(&self, index: usize, known: &[u8; dotnet::HEADER_BYTES]) -> Option<crate::attack::zip_crypto::search::Outcome> {
        let target = self.pool.targets.get(index)?;
        let form = target.facts.checks.first().and_then(|way| Form::bytes(-12, known).merged(&way.form.clipped(-1, 0)))?;
        let run: Vec<u8> = (-12..0).filter_map(|position| form.get(position).and_then(ByteSet::only)).collect();
        let search = Search::new(&self.pool, index, &form, -12, &run, 1)?;
        self.voice.say(&format!("      reduction: 12 bytes in a row, {} candidates", grouped(search.candidates() as u64)));
        Some(self.search(&search, "header", self.speed.rate, None))
    }

    /// The .NET Framework: the generator of every entry is seeded with the clock of Windows,
    /// which stands still between two interrupts of its timer, so entries that were written
    /// between two interrupts have one header. `None` when the headers do not show that: the
    /// archive is then of another runtime, and another search is the one to run.
    fn net_framework(&self, order: &[usize]) -> Option<(Option<Found>, Vec<Found>)> {
        // the groups of entries with one header, by the first entry of each
        let mut groups: Vec<(usize, [u8; 12])> = Vec::new();
        for &index in order {
            let header = self.pool.targets.get(index)?.header;
            if groups.last().is_none_or(|(_, last)| last.first_chunk::<10>() != header.first_chunk::<10>()) {
                groups.push((index, header));
            }
        }
        // entries that share a header are the mark of the clock: without one the archive is of a runtime that seeds each entry by itself
        if groups.len() == order.len() {
            return None;
        }
        if groups.len() < netfx::MIN_GROUPS {
            self.voice.say(&format!(
                "      entries share their headers, as on the .NET Framework, where a clock seeds the generator: the {} entries were written within {} steps of that clock, and {} are needed to find it by",
                grouped(order.len() as u64),
                grouped(groups.len() as u64),
                netfx::MIN_GROUPS
            ));
            return Some((None, Vec::new()));
        }
        let headers: Vec<[u8; 12]> = groups.iter().map(|(_, header)| *header).collect();
        let &(index, _) = groups.first()?;
        let mut unproved = Vec::new();
        // one wrong clock in 65,536 of those that fit the first bytes gives the same first
        // three bytes in every header as the right one: the search for the keys finds none
        // with it, and the search for the clock goes on behind it
        let mut from = 0;
        for _ in 0..SEEDS_MAX {
            let clocks = self.counted("clock search", netfx::INTERRUPTS - from, |control| netfx::clocks(&headers, from..netfx::INTERRUPTS, control));
            if self.stop.load(Ordering::Relaxed) {
                return Some((None, unproved));
            }
            let Some((interrupt, counts)) = clocks.first() else {
                if from == 0 {
                    self.voice.say("      entries share their headers, as on the .NET Framework, and no count of the clock of Windows in a year of running gives the headers of every group: the timer of the machine did not run at its usual 64 interrupts a second, or the entries were written more than half a second apart");
                }
                return Some((None, unproved));
            };
            let Some(&count) = counts.first() else { return Some((None, unproved)) };
            let running = Duration::from_millis(u64::from(count));
            self.voice.say(&format!(
                "      the clock of the machine: it had been running for {} days {} hours when the first entry was written, or that and a multiple of 49.7 days. The clock gives eleven bytes of the header of each of the {} groups of entries that were written between two steps of it",
                running.as_secs() / 86_400,
                running.as_secs() % 86_400 / 3600,
                grouped(groups.len() as u64)
            ));
            if let Some(outcome) = self.run_of_twelve(index, &dotnet::header_bytes(netfx::seed_at(count))) {
                unproved.extend(outcome.unproved);
                if let Some(found) = outcome.proved {
                    return Some((Some(found), unproved));
                }
            }
            self.voice.say("      no keys with that clock: it gives the first bytes of every header and is not the clock. Searching on behind it");
            from = interrupt + 1;
        }
        Some((None, unproved))
    }

    fn dot_net(&self, archive: usize) -> (Option<Found>, Vec<Found>) {
        let order = written(&self.pool, archive);
        if let Some(ended) = self.net_framework(&order) {
            return ended;
        }
        let first: Vec<u8> = order.iter().filter_map(|&index| self.pool.targets.get(index)).map(|target| target.header.first().copied().unwrap_or_default()).collect();
        let found = self.counted("seed search", u64::from(dotnet::THREAD_SEEDS), |control| dotnet::thread_seeds(&first, 0..dotnet::THREAD_SEEDS, dotnet::POSITIONS, control));
        if self.stop.load(Ordering::Relaxed) {
            return (None, Vec::new());
        }
        if found.is_empty() {
            self.voice.say("      no seed gives the first byte of every header: the archive was written on a runtime whose generator cannot be predicted (.NET 6 or later, or the .NET Framework), or its entries were not written one after the other");
            return (None, Vec::new());
        }
        let mut unproved = Vec::new();
        for seed in found.iter().take(SEEDS_MAX) {
            self.voice.say(&format!("      seed {} of the generator of the thread, with {} made before the first entry: it gives eleven bytes of every header", grouped(u64::from(seed.thread_seed.unsigned_abs())), seed.position));
            let Some((&index, known)) = order.first().zip(seed.headers(1).into_iter().next()) else { continue };
            let Some(outcome) = self.run_of_twelve(index, &known) else { continue };
            unproved.extend(outcome.unproved);
            if let Some(found) = outcome.proved {
                return (Some(found), unproved);
            }
        }
        (None, unproved)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn pool(fixture: &str) -> Pool {
        Pool::read(&[PathBuf::from(format!("tests/fixtures/zip-crypto/{fixture}"))], &|_| None).unwrap()
    }

    #[test]
    fn a_writer_that_is_not_known_is_asked_whether_a_clock_seeded_it() {
        let asked = |fixture: &str, limits: &Limits| -> Vec<(Option<Special>, Path, Certainty)> { attempts(&pool(fixture), limits).iter().map(|attempt| (attempt.special, attempt.path, attempt.certainty)).collect() };
        let (info_zip, clocked) = ((Some(Special::InfoZip { archive: 0 }), Path::Header, Certainty::Guess), (Some(Special::Clocked { archive: 0 }), Path::HeaderOnce, Certainty::Guess));
        // and whether a library of .NET made a generator for each entry, which leaves no mark either
        let dot_net = (Some(Special::DotNet { archive: 0 }), Path::HeaderOnce, Certainty::Guess);
        // the ZipArchive library, one entry a second: no mark of its own in the directory, and
        // on Windows the marks of yeka/zip, which its headers take back
        for fixture in ["gen_ziparchive_glibc.zip", "gen_ziparchive_win.zip"] {
            assert_eq!(pool(fixture).archives[0].writer, Writer::Unknown, "{fixture}");
            assert_eq!(asked(fixture, &Limits::default()), [info_zip, clocked, dot_net], "{fixture}");
            assert!(asked(fixture, &Limits { no_guess: true, ..Limits::default() }).is_empty());
        }
        // zip utils: entries of one step of its clock have one header, which a generator that
        // is seeded once for a run never gives, so the question of Info-ZIP is not asked
        assert_eq!(asked("gen_ziputils_win.zip", &Limits::default()), [clocked, dot_net]);
        // the libraries of Aspose and of ComponentOne are such writers without a mark
        assert_eq!(asked("gen_aspose_net5.zip", &Limits::default()), [info_zip, clocked, dot_net]);
        assert_eq!(asked("gen_c1zip_net8.zip", &Limits::default()), [info_zip, clocked, dot_net]);
        let aspose = attempts(&pool("gen_aspose_net5.zip"), &Limits::default());
        assert!(aspose[2].what.starts_with("encryption headers of 10 entries, encrypted once: whether a library of .NET made a generator for each entry, as Aspose.ZIP does"), "{}", aspose[2].what);
        let utils = attempts(&pool("gen_ziputils_win.zip"), &Limits::default());
        assert!(utils[0].what.starts_with("encryption headers of 16 entries, encrypted once: whether a clock seeded their generator for each entry") && utils[0].chance > 0.4, "{}", utils[0].what);
        // the constant of yeka/zip is no clock, and a family that is known is not asked
        assert!(asked("gen_yeka_a.zip", &Limits::default()).iter().all(|(special, ..)| *special != Some(Special::Clocked { archive: 0 })));
        assert_eq!(asked("gen_infozip_six.zip", &Limits::default()).len(), 1);
    }

    #[test]
    fn the_time_of_an_entry_is_read_as_seconds_and_the_passes_start_at_the_times_an_archive_names() {
        // 2026-11-20 22:45:32, the DOS time and date of the entries of gen_ziparchive_win.zip
        assert_eq!(seconds_of(0x5d74, 0xb5b0), Some(1_795_214_732));
        assert_eq!(seconds_of(0x0021, 0), Some(315_532_800));
        assert_eq!((seconds_of(0, 0), seconds_of(0x5da0, 0)), (None, None));

        let (hour, day) = (3600, 86_400);
        let (newest, modified, now) = (1_795_214_732, 1_795_232_760, 1_800_000_000);
        let archive = clocked::Writer::zip_archive(clocked::Runtime::Windows);
        let of_archive = passes(archive, 14, Some(newest), Some(modified), now);
        // the hour before the file was last written, then the days after the newest entry
        // with few steps between two groups and with many, then every second since
        let ranges: Vec<(Range<u64>, usize)> = of_archive.iter().map(|pass| (pass.clocks.clone(), pass.gap)).collect();
        let near = newest + 4 * day;
        assert_eq!(ranges, [(modified - hour..modified + 2, 64), (newest - 15 * hour..near, 4), (newest - 15 * hour..near, 64), (near..now + day, 4)]);
        // the true time of that archive, 1,795,232,739, is in the first two
        assert!(ranges[0].0.contains(&1_795_232_739) && ranges[1].0.contains(&1_795_232_739));
        // few groups say too little for all the time there is, and a file time of the future says nothing
        assert_eq!(passes(archive, 4, Some(newest), Some(now + 2 * day), now).len(), 2);
        // without a time of an entry: all the time since 2000, for groups enough
        let all = passes(archive, 6, None, None, now);
        assert_eq!(all.iter().map(|pass| (pass.clocks.clone(), pass.gap)).collect::<Vec<_>>(), [(YEAR_2000..now + day, 4)]);
        // the count of a timer is not a time: every count, groups next to each other first
        let utils = passes(clocked::Writer::zip_utils(clocked::DESKTOP), 7, Some(newest), Some(modified), now);
        assert_eq!(utils.iter().map(|pass| (pass.clocks.clone(), pass.gap)).collect::<Vec<_>>(), [(0..clocked::INTERRUPTS, 2), (0..clocked::INTERRUPTS, 32)]);
        assert_eq!(passes(clocked::Writer::zip_utils(clocked::DESKTOP), 3, None, None, now).len(), 1);
    }

    #[test]
    fn an_archive_of_a_family_with_weak_headers_gets_its_header_path() {
        let six = pool("gen_infozip_six.zip");
        let attempts = attempts(&six, &Limits::default());
        assert_eq!(attempts.len(), 1);
        assert_eq!((attempts[0].path, attempts[0].special, attempts[0].certainty), (Path::Header, Some(Special::InfoZip { archive: 0 }), Certainty::Likely));
        assert!(attempts[0].what.starts_with("encryption headers of 6 entries of one run"));
        // four seconds on the machine the times were measured on, and longer with four entries
        assert!((attempts[0].seconds(MEASURED_RATE, 16) - INFO_ZIP_SECONDS).abs() < 1e-9);
        let four = pool("gen_infozip_four.zip");
        assert!((super::attempts(&four, &Limits::default())[0].seconds(MEASURED_RATE, 16) - INFO_ZIP_FOUR_SECONDS).abs() < 1e-9);

        let sharp = pool("gen_sharpziplib_net5.zip");
        let attempts = super::attempts(&sharp, &Limits::default());
        assert_eq!((attempts[0].path, attempts[0].special, attempts[0].certainty), (Path::HeaderOnce, Some(Special::DotNet { archive: 0 }), Certainty::Guess));
        assert_eq!(super::attempts(&pool("gen_dotnetzip_net5.zip"), &Limits::default()).len(), 1);

        // too few entries, a writer whose headers say nothing, and a path that is not asked for
        assert!(super::attempts(&pool("gen_infozip_store_multi.zip"), &Limits::default()).is_empty());
        assert!(super::attempts(&pool("bkcrack-src_secrets.zip"), &Limits::default()).is_empty());
        assert!(super::attempts(&six, &Limits { only: vec![Path::Run], ..Limits::default() }).is_empty());
        assert!(super::attempts(&six, &Limits { no_guess: true, ..Limits::default() }).is_empty());
        assert_eq!(super::attempts(&six, &Limits { only: vec![Path::Header], ..Limits::default() }).len(), 1);
    }

    #[test]
    fn a_writer_that_left_no_mark_is_asked_as_a_guess() {
        // minizip: made by version 0 and no data descriptor, where zip says 3.0 and has one
        let minizip = pool("gen_minizip_glibc.zip");
        let asked = attempts(&minizip, &Limits::default());
        // and whether a clock seeded it for each entry or a library of .NET wrote it, which are
        // the other writers without marks
        assert_eq!(asked.len(), 3);
        assert_eq!((asked[2].path, asked[2].special, asked[2].certainty), (Path::HeaderOnce, Some(Special::DotNet { archive: 0 }), Certainty::Guess));
        assert_eq!((asked[1].path, asked[1].special, asked[1].certainty), (Path::HeaderOnce, Some(Special::Clocked { archive: 0 }), Certainty::Guess));
        assert!(asked[1].chance < asked[0].chance);
        assert_eq!((asked[0].path, asked[0].special, asked[0].certainty), (Path::Header, Some(Special::InfoZip { archive: 0 }), Certainty::Guess));
        assert!(asked[0].what.starts_with("encryption headers of 6 entries: whether the generator of a C library filled them"), "{}", asked[0].what);
        assert!(attempts(&minizip, &Limits { no_guess: true, ..Limits::default() }).is_empty());
        // zip leaves its marks whatever C library it was built against, and WinRAR from 4.20
        // on leaves its own. WinRAR 2.90 leaves none and is asked as a guess
        assert_eq!(pool("gen_winrar_723.zip").archives[0].writer, Writer::WinRar);
        let old = attempts(&pool("gen_winrar_290.zip"), &Limits::default());
        assert_eq!((old[0].special, old[0].certainty), (Some(Special::InfoZip { archive: 0 }), Certainty::Guess));
        for fixture in ["gen_infozip_musl.zip", "gen_infozip_win.zip", "gen_infozip_official.zip", "gen_infozip_cygwin.zip", "gen_winrar_723.zip"] {
            let of_zip = attempts(&pool(fixture), &Limits::default());
            assert_eq!((of_zip.len(), of_zip[0].certainty), (1, Certainty::Likely), "{fixture}");
        }
    }

    #[test]
    fn the_seeds_to_follow_up_are_one_for_each_stream_and_those_made_of_a_time_first() {
        let found = vec![
            (Library::Glibc, vec![17, 1_526_274_454]),
            // two streams of macOS, each under two seeds: one of the four is a time of 2018
            (Library::MacOs, vec![586_298_518, 1_526_274_454, 2_733_782_165, 3_673_758_101]),
            (Library::Musl, vec![]),
            // one stream of Windows under its two seeds, neither of which is made of a time
            (Library::Windows, vec![0x1000_0000, 0x9000_0000]),
        ];
        assert_eq!(candidates(&found), [(Library::Glibc, 1_526_274_454), (Library::MacOs, 1_526_274_454), (Library::Glibc, 17), (Library::MacOs, 586_298_518), (Library::Windows, 0x1000_0000)]);
        assert!(candidates(&[]).is_empty());

        // a time with a process number over it, a time with the constant of minizip over it, and neither
        assert!(made_of(1_526_274_454).is_some_and(|words| words.ends_with("the number of the process that wrote it")));
        assert!(made_of(3_493_857_940).is_some_and(|words| words.contains("the constant that minizip")));
        assert!(made_of(17).is_none() && !is_a_time(586_298_518) && is_a_time(1_797_846_278));
        assert_eq!(Library::ALL.map(Library::label), ["glibc", "macOS", "musl", "Windows", "Borland", "Borland as WinRAR 3.20 reads it"]);
    }

    #[test]
    fn the_entries_of_an_archive_are_taken_in_the_order_they_lie_in_the_file() {
        let six = pool("gen_infozip_six.zip");
        let order = written(&six, 0);
        assert_eq!(order.len(), 6);
        let starts: Vec<u64> = order.iter().map(|&index| six.targets[index].start).collect();
        assert!(starts.is_sorted() && starts.first() < starts.last());
        assert!(written(&six, 1).is_empty());
    }
}
