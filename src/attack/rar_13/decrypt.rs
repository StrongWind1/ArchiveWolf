//! RAR 1.3/1.4 key recovery and plaintext-archive output.
//!
//! No archive tool can be handed a raw key, so the recovery path is: find the
//! 3-byte key, show it, and write a copy of the archive with every entry
//! decrypted and its password flag cleared. That copy is one any tool that
//! reads RAR 1.3 unpacks without a password.
//!
//! A key is tested by decrypting an entry, unpacking it when it is
//! compressed, and comparing `Checksum14` of the result with the header.
//! The checksum is 16 bits and the key space is 2^23, so one entry leaves
//! about 128 keys standing. Every further encrypted entry divides that by
//! 65,536. When more than one key survives all entries, the keys are
//! indistinguishable by anything stored in the archive, and the only
//! remaining evidence is whether the decrypted content is recognisable.
//!
//! The search has to test every key before it can tell one from the keys
//! that pass a checksum by chance, so its cost is the cost of one test times
//! 2^23. The first pass over the keys is therefore made on the entry that is
//! cheapest to test, its time is measured before it starts, and it is held
//! to a budget. What one test may unpack is held to what the packed bytes
//! can give and to a limit, whatever the header claims.

use std::io::Write as _;
use std::ops::Range;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context as _;
use rayon::prelude::IntoParallelIterator as _;
use rayon::prelude::ParallelIterator as _;

use super::content::starts_as_named;
use super::crack::GroupSums;
use super::crack::KEY_SPACE;
use super::crack::LANES;
use super::crack::Rar13State;
use super::crack::checksum14;
use super::crack::keys_in;
use super::sweep::Clock;
use super::sweep::Notes;
use super::sweep::Oracle;
use super::sweep::Progress;
use super::sweep::Rate;
use super::sweep::Swept;
use super::sweep::measure;
use super::sweep::percent;
use super::sweep::sweep;
use super::sweep::work_of_a_pass;
use crate::attack::budget::Budget;
use crate::attack::budget::about;
use crate::attack::budget::enough_for;
use crate::formats::limits::MAX_DECODE_BUFFER;
use crate::formats::rar::encryption::RarEncryption;
use crate::formats::rar::headers::RAR1_SIGNATURE;
use crate::formats::rar::unpack15::Unpack15;
use crate::formats::source::Source;

/// File header flag: entry is encrypted.
const LHD_PASSWORD: u8 = 0x04;
/// Shortest ASCII content the text test will vouch for.
const MIN_TEXT_LEN: usize = 8;
/// Shortest content with code-page letters the text test will vouch for.
const MIN_CODEPAGE_TEXT_LEN: usize = 64;

/// The most bytes that one packed byte of a compressed entry unpacks to.
///
/// This is a property of the RAR 1.5 stream and of no decoder in particular:
/// every step of it takes at least one bit, and gives one literal or one
/// match, and no match is longer than 267 bytes. An entry whose header
/// claims more than this for the packed bytes it has is unpacked by no key.
const MOST_UNPACKED_PER_BYTE: usize = 8 * 267;

/// The bytes of an entry that a pass over the keys takes between two looks at
/// the clock: so many of a stored entry under every key of a group, or the
/// keys that it takes to read so many packed bytes of a compressed one.
const PIECE: usize = 4096;

/// What testing one key on a compressed entry costs for each packed byte the
/// decoder reads, in the cost of one byte of a stored entry.
///
/// The two are measured before a search starts, on the entry it is made on.
/// This number only ranks the entries, to choose that one: a byte through
/// the decoder takes some 18 ns, and a byte of a stored entry under one key
/// of a group well under 1 ns.
const PACKED_BYTE_COST: u64 = 128;
/// What a compressed entry costs for each key before the first byte, in
/// packed bytes: the decoder is reset.
const PACKED_ENTRY_COST: u64 = 16;
/// The bytes that one packed byte unpacks to under a wrong key, at least:
/// the decoder stops at the unpacked size, so an entry that claims less than
/// this for each packed byte is not read to its end.
const WRONG_KEY_EXPANSION: usize = 2;
/// What the copy of a 64 KiB window costs, in bytes of a stored entry.
const WINDOW_COST: u64 = 1 << 16;

/// What the threads of a search keep together for the keys they are testing,
/// at most, as long as one thread can hold what one key takes: a search runs
/// on fewer threads when its entries are so large that all of them would
/// keep more.
const SEARCH_MEMORY: u64 = 1 << 30;

/// How much of an entry is decrypted at a time when the copy of the archive is written.
const COPY_PIECE: usize = 1 << 16;

/// One file entry of a RAR 1.4 archive.
struct Entry {
    /// Offset of the flags byte in the archive.
    flags_pos: usize,
    /// Packed data range in the archive.
    data: Range<usize>,
    name: Vec<u8>,
    method: u8,
    checksum: u16,
    unp_size: usize,
    encrypted: bool,
    /// Whole entry is present in this volume.
    complete: bool,
}

impl Entry {
    const fn stored(&self) -> bool {
        self.method == 0
    }

    /// Encrypted, complete and non-empty: its checksum constrains the key.
    const fn checkable(&self) -> bool {
        self.encrypted && self.complete && self.unp_size > 0 && self.data.start < self.data.end
    }

    /// Its packed bytes can be as much unpacked as its header says: all of a
    /// stored entry is there, and a compressed one does not claim more than
    /// a stream of its length gives. No key passes an entry that fails this.
    const fn satisfiable(&self) -> bool {
        let packed = self.data.end.saturating_sub(self.data.start);
        self.unp_size <= if self.stored() { packed } else { packed.saturating_mul(MOST_UNPACKED_PER_BYTE) }
    }

    /// Compressed, and more unpacked than is unpacked for one key.
    fn over_limit(&self) -> bool {
        !self.stored() && wide(self.unp_size) > MAX_DECODE_BUFFER
    }

    /// Its name as a note shows it.
    fn label(&self, index: usize) -> String {
        if self.name.is_empty() { format!("entry {}", index + 1) } else { String::from_utf8_lossy(&self.name).into_owned() }
    }
}

/// A size in memory as a 64-bit number.
fn wide(size: usize) -> u64 {
    u64::try_from(size).unwrap_or(u64::MAX)
}

/// Parsed RAR 1.4 archive layout.
struct Layout {
    solid: bool,
    entries: Vec<Entry>,
}

/// Outcome of a key recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// Exactly one key satisfies every encrypted entry. It is the key.
    Unique([u8; 3]),
    /// Several keys satisfy every checksum; one alone passes a further test.
    Selected {
        /// The key that passes.
        key: [u8; 3],
        /// Number of keys that satisfy every checksum.
        equivalent: usize,
        /// The test that singled it out.
        by: Selection,
    },
    /// Several keys satisfy every checksum and none can be singled out.
    Ambiguous(Vec<[u8; 3]>),
    /// No key satisfies the entry checksums: the archive is damaged, or its entries are not
    /// encrypted with the RAR 1.3 scheme.
    NoKey,
    /// The search did not reach its end: its estimate was over the budget and it was not
    /// started, or the budget ended it. In words, with the way to raise the budget.
    Stopped(String),
}

/// What singled one key out of several checksum-equivalent ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Selection {
    /// Only this key makes every compressed stream end at its packed size.
    StreamLength,
    /// Only this key decrypts every entry to text or its expected file signature.
    Content,
}

/// What a search is given besides the archive.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Run {
    /// The time it may take.
    pub(crate) budget: Budget,
    /// Where it says what it does.
    pub(crate) notes: Notes,
}

/// The bytes of the archive, which the key search holds in memory.
fn held(source: &Source) -> anyhow::Result<&[u8]> {
    source.held().context("the key search needs its archive in memory")
}

/// The layout of the archive as the parser of the analysis reads it: there is one reader of
/// this generation, so the search tests the entries that `info` lists.
fn parse_layout(source: &Source) -> anyhow::Result<Layout> {
    anyhow::ensure!(held(source)?.starts_with(RAR1_SIGNATURE), "not an archive of RAR 1.3 or 1.4");
    let archive = crate::formats::rar::rar1::parse(source, 0)?;
    let len = source.len();
    let place = |offset: u64| usize::try_from(offset.min(len)).unwrap_or(usize::MAX);
    let entries = archive
        .entries
        .iter()
        .map(|entry| Entry {
            // the flags are the eighteenth byte of a file header
            flags_pos: place(entry.header_offset.saturating_add(17)),
            data: place(entry.data_offset)..place(entry.data_offset.saturating_add(entry.packed)),
            name: entry.name.clone(),
            method: entry.method,
            checksum: u16::try_from(entry.crc32 & 0xFFFF).unwrap_or(0),
            unp_size: usize::try_from(entry.unpacked.unwrap_or(0)).unwrap_or(usize::MAX),
            encrypted: entry.encryption != RarEncryption::None,
            complete: entry.data_is_inside(len) && !entry.is_split(),
        })
        .collect();
    Ok(Layout { solid: archive.solid, entries })
}

/// What a walk through the archive with one key does with an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// Nothing: the entry says nothing about the key, or cannot be unpacked.
    Skip,
    /// Unpack it to keep the window of a solid archive in step. Its own
    /// checksum says nothing about the key.
    Feed {
        /// Continue from the member before it.
        solid: bool,
    },
    /// Decrypt it, unpack it and compare its checksum.
    Test {
        /// Continue from the member before it.
        solid: bool,
    },
}

/// The steps of a walk, one for each entry, and the encrypted entries it has
/// to leave out.
struct Plan {
    steps: Vec<Step>,
    /// Entries whose checksum would be tested if they could be unpacked: over
    /// the limit, or members of a solid archive behind one that is not unpacked.
    left_out: Vec<usize>,
}

impl Plan {
    /// Entries whose checksum is tested.
    fn tested(&self) -> usize {
        self.steps.iter().filter(|step| matches!(step, Step::Test { .. })).count()
    }
}

/// Decide what a walk does with each entry. A key plays no part in this.
///
/// In a solid archive a compressed member starts from the window and the
/// tables the member before it left, so one that is not unpacked (it is not
/// whole in this volume, or over the limit) takes the later ones with it.
/// Stored entries stand by themselves.
fn plan_for(layout: &Layout) -> Plan {
    let mut steps = Vec::with_capacity(layout.entries.len());
    let mut left_out = Vec::new();
    let mut chained = false;
    let mut gap = false;
    for (index, entry) in layout.entries.iter().enumerate() {
        let step = if entry.stored() {
            if entry.checkable() { Step::Test { solid: false } } else { Step::Skip }
        } else if layout.solid && gap {
            if entry.checkable() {
                left_out.push(index);
            }
            Step::Skip
        } else if !entry.complete || entry.over_limit() || !entry.satisfiable() {
            gap = true;
            if entry.checkable() {
                left_out.push(index);
            }
            Step::Skip
        } else if entry.checkable() {
            let solid = layout.solid && chained;
            chained = true;
            Step::Test { solid }
        } else if layout.solid {
            let solid = chained;
            chained = true;
            Step::Feed { solid }
        } else {
            Step::Skip
        };
        steps.push(step);
    }
    Plan { steps, left_out }
}

/// Per-thread scratch space for testing keys.
struct Scratch {
    decoder: Unpack15,
    body: Vec<u8>,
}

impl Scratch {
    fn new() -> Self {
        Self { decoder: Unpack15::new(), body: Vec::new() }
    }
}

/// Plaintext of one entry under a candidate key.
struct Plain<'a> {
    bytes: &'a [u8],
    /// The packed stream ended where the header says it does: a stored entry,
    /// or a compressed one whose decoder stopped within the final byte.
    exact_length: bool,
}

/// Decrypt and unpack one entry with `key`, returning its plaintext when the
/// header checksum matches. `solid` continues the decoder's previous member.
///
/// This is the one place that asks the decoder for anything, and it asks for
/// no more than the packed bytes can give and no more than the limit: the
/// decoder keeps what it unpacks, so that is what a key can cost in memory.
fn entry_plaintext<'a>(data: &[u8], entry: &Entry, key: [u8; 3], solid: bool, scratch: &'a mut Scratch) -> Option<Plain<'a>> {
    if !entry.satisfiable() || entry.over_limit() {
        return None;
    }
    let packed = data.get(entry.data.clone())?;
    if entry.encrypted {
        Rar13State::new(key).decrypt_into(packed, &mut scratch.body);
    } else {
        scratch.body.clear();
        scratch.body.extend_from_slice(packed);
    }
    let (bytes, exact_length): (&[u8], bool) = if entry.stored() {
        (scratch.body.get(..entry.unp_size)?, true)
    } else {
        let decoded = scratch.decoder.decode(&scratch.body, entry.unp_size, solid).ok()?;
        (scratch.decoder.member(), decoded.consumed + 1 >= scratch.body.len())
    };
    (checksum14(bytes) == entry.checksum).then_some(Plain { bytes, exact_length })
}

/// How a walk through the archive with one key ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Walked {
    /// Every tested entry gave its checksum.
    Passed,
    /// One did not.
    Failed,
    /// The clock ran out first.
    Stopped,
}

/// Whether `key` gives one entry its checksum. `solid` continues the decoder's
/// previous member.
///
/// A stored entry is decrypted and summed as its bytes go by: nothing of it
/// is copied, however large it is.
fn entry_passes(data: &[u8], entry: &Entry, key: [u8; 3], solid: bool, scratch: &mut Scratch) -> bool {
    if entry.stored() && entry.encrypted {
        let cipher = data.get(entry.data.clone()).and_then(|packed| packed.get(..entry.unp_size));
        return cipher.is_some_and(|cipher| Rar13State::new(key).checksum_of(cipher) == entry.checksum);
    }
    entry_plaintext(data, entry, key, solid, scratch).is_some()
}

/// What a walk shows of each tested entry that passes: the entry and its plaintext.
type Visit<'v> = &'v mut dyn FnMut(&Entry, &Plain<'_>);

/// Walk the archive with `key` until a tested entry fails its checksum or the
/// clock runs out. With `visit`, the plaintext of every tested entry is kept
/// long enough to be shown to it.
fn walk(data: &[u8], layout: &Layout, plan: &Plan, key: [u8; 3], scratch: &mut Scratch, clock: &Clock, mut visit: Option<Visit<'_>>) -> Walked {
    for (entry, step) in layout.entries.iter().zip(&plan.steps) {
        let (solid, tested) = match *step {
            Step::Skip => continue,
            Step::Feed { solid } => (solid, false),
            Step::Test { solid } => (solid, true),
        };
        if clock.out() {
            return Walked::Stopped;
        }
        let passed = match visit.as_mut() {
            Some(visit) if tested => entry_plaintext(data, entry, key, solid, scratch).map(|opened| visit(entry, &opened)).is_some(),
            _ => entry_passes(data, entry, key, solid, scratch),
        };
        if tested && !passed {
            return Walked::Failed;
        }
    }
    Walked::Passed
}

/// Whether `key` decrypts every checkable entry to its header checksum.
#[cfg(test)]
pub(crate) fn key_matches(source: &Source, key: [u8; 3]) -> anyhow::Result<bool> {
    let data = held(source)?;
    let layout = parse_layout(source)?;
    let plan = plan_for(&layout);
    if plan.tested() == 0 {
        return Ok(false);
    }
    Ok(walk(data, &layout, &plan, key, &mut Scratch::new(), &Clock::until(None), None) == Walked::Passed)
}

/// An entry that a key can be tested on by itself, with no other entry
/// unpacked for that key first: what a pass over the key space is made on.
struct Probe<'a> {
    data: &'a [u8],
    index: usize,
    entry: &'a Entry,
    /// The decoder as the unencrypted members in front of it leave it, when
    /// it is a member of a solid archive that has such members.
    base: Option<Unpack15>,
}

impl Probe<'_> {
    /// Whether `key` gives the entry its checksum.
    fn passes(&self, key: [u8; 3], scratch: &mut Scratch) -> bool {
        if let Some(base) = &self.base {
            scratch.decoder.clone_from(base);
        }
        entry_passes(self.data, self.entry, key, self.base.is_some(), scratch)
    }

    /// What testing one key on it costs, in bytes of a stored entry.
    ///
    /// A stored entry is decrypted and summed, byte for byte. A compressed
    /// one is unpacked, and under a wrong key the decoder reads packed bytes
    /// until they end or it has the unpacked size together.
    fn cost(&self) -> u64 {
        if self.entry.stored() {
            return wide(self.entry.unp_size);
        }
        let read = self.entry.data.len().min(self.entry.unp_size / WRONG_KEY_EXPANSION);
        let unpacking = PACKED_BYTE_COST.saturating_mul(PACKED_ENTRY_COST.saturating_add(wide(read)));
        // a member that starts from a window is given a copy of it for every key
        unpacking.saturating_add(if self.base.is_some() { WINDOW_COST } else { 0 })
    }

    /// The entry and its size, as the note before a pass names it.
    fn described(&self) -> String {
        let bytes = |count: usize| format!("{count} byte{}", if count == 1 { "" } else { "s" });
        let label = self.entry.label(self.index);
        if self.entry.stored() { format!("{label} (stored, {})", bytes(self.entry.unp_size)) } else { format!("{label} (compressed, {} that unpack to {})", bytes(self.entry.data.len()), self.entry.unp_size) }
    }
}

impl Oracle for Probe<'_> {
    type Scratch = Scratch;

    fn scratch(&self) -> Scratch {
        Scratch::new()
    }

    /// A byte of a stored entry under one key, or one key on a compressed entry.
    fn work_per_key(&self) -> u64 {
        if self.entry.stored() { wide(self.entry.unp_size).max(1) } else { 1 }
    }

    fn group(&self, group: u32, scratch: &mut Scratch, clock: &Clock, did: &mut dyn FnMut(u64), passed: &mut Vec<[u8; 3]>) {
        if !self.entry.stored() {
            // one key at a time, and as many between two looks at the clock as read a
            // piece of packed bytes: a small entry is not held up by the clock, and a
            // large one is left after the key it is on
            let stride = wide((PIECE / self.entry.data.len().max(1)).clamp(1, LANES));
            let mut tested = 0;
            for key in keys_in(group) {
                if self.passes(key, scratch) {
                    passed.push(key);
                }
                tested += 1;
                if tested == stride {
                    did(tested);
                    tested = 0;
                    if clock.out() {
                        return;
                    }
                }
            }
            if tested > 0 {
                did(tested);
            }
            return;
        }
        // all keys of the group at once, with nothing copied and nothing kept
        let mut left = self.data.get(self.entry.data.clone()).and_then(|packed| packed.get(..self.entry.unp_size)).unwrap_or_default();
        let mut sums = GroupSums::new(group);
        loop {
            let (piece, rest) = left.split_at(left.len().min(PIECE));
            sums.absorb(piece);
            left = rest;
            if left.is_empty() {
                passed.extend(sums.keys_with(self.entry.checksum));
            }
            did(wide(piece.len()).saturating_mul(wide(LANES)));
            if left.is_empty() || clock.out() {
                return;
            }
        }
    }
}

/// The entries a key can be tested on by itself, in the order of the archive.
/// `None` when the clock ran out.
///
/// Every tested stored entry is one. So is every tested compressed entry of
/// an archive that is not solid. Of a solid archive it is the first tested
/// compressed member alone: the later ones start from what that one unpacks
/// to, which is not known before the key is.
fn probes_of<'a>(data: &'a [u8], layout: &'a Layout, plan: &Plan, clock: &Clock) -> Option<Vec<Probe<'a>>> {
    let mut probes = Vec::new();
    // the solid chain up to its first tested member: the unencrypted members
    // in front of it unpack the same under every key, and are unpacked here
    let mut front = Scratch::new();
    let mut fed = false;
    let mut open = true;
    for (index, (entry, step)) in layout.entries.iter().zip(&plan.steps).enumerate() {
        match *step {
            Step::Skip => {},
            Step::Feed { solid } => {
                if open {
                    if clock.out() {
                        return None;
                    }
                    let _ = entry_plaintext(data, entry, [0; 3], solid, &mut front);
                    fed = true;
                }
            },
            Step::Test { .. } if entry.stored() || !layout.solid => probes.push(Probe { data, index, entry, base: None }),
            Step::Test { .. } => {
                if open {
                    // a member of no bytes: the decoder drops all but its window, and a
                    // key is tested from a copy of that
                    let base = fed.then(|| {
                        let _ = front.decoder.decode(&[], 0, true);
                        front.decoder.clone()
                    });
                    probes.push(Probe { data, index, entry, base });
                }
                open = false;
            },
        }
    }
    Some(probes)
}

/// Keep the keys that `test` passes, in their order, testing on all threads.
/// `None` when a test says the clock ran out.
fn keep(keys: Vec<[u8; 3]>, test: impl Fn([u8; 3], &mut Scratch) -> Option<bool> + Sync) -> Option<Vec<[u8; 3]>> {
    let tested: Vec<([u8; 3], Option<bool>)> = keys.into_par_iter().map_init(Scratch::new, |scratch, key| (key, test(key, scratch))).collect();
    tested.iter().all(|(_, passed)| passed.is_some()).then(|| tested.iter().filter(|(_, passed)| *passed == Some(true)).map(|(key, _)| *key).collect())
}

/// Text, long enough that a wrong key cannot produce it by chance: either
/// pure printable ASCII, or a longer run with no control bytes that is mostly
/// ASCII (DOS code-page text keeps its letters above 0x7f).
fn is_text(data: &[u8]) -> bool {
    let ascii = data.iter().filter(|&&b| matches!(b, b'\t' | b'\n' | b'\r' | 0x1a | 0x20..=0x7e)).count();
    if ascii == data.len() {
        return data.len() >= MIN_TEXT_LEN;
    }
    let high = data.iter().filter(|&&b| b >= 0x80).count();
    data.len() >= MIN_CODEPAGE_TEXT_LEN && ascii + high == data.len() && ascii * 5 >= data.len() * 3
}

/// What a checksum-valid key looks like beyond the checksum.
struct Evidence {
    /// Every compressed stream ends at its packed size.
    exact_length: bool,
    /// Every entry decrypts to plain text or to the file signature its name implies.
    recognisable: bool,
}

/// `None` when the clock ran out.
fn evidence(data: &[u8], layout: &Layout, plan: &Plan, key: [u8; 3], clock: &Clock) -> Option<Evidence> {
    let mut exact_length = true;
    let mut recognisable = true;
    let mut look = |entry: &Entry, plain: &Plain<'_>| {
        exact_length &= plain.exact_length;
        recognisable &= starts_as_named(&entry.name, plain.bytes) || is_text(plain.bytes);
    };
    let walked = walk(data, layout, plan, key, &mut Scratch::new(), clock, Some(&mut look));
    let passed = walked == Walked::Passed;
    (walked != Walked::Stopped).then_some(Evidence { exact_length: passed && exact_length, recognisable: passed && recognisable })
}

/// `count` of a thing, in words.
fn counted(count: usize, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The two ways to give a search that needs `needed` more time, as a search that stopped says them.
fn more_time(needed: Duration) -> String {
    format!("raise it with --budget {}, or lift it with --budget none", enough_for(needed))
}

/// What a search says that was not started because its first pass takes `estimate`, which
/// is over its budget.
///
/// Not starting is the choice: no key is known before the last key is tested, since the
/// keys that pass a checksum by chance are told from the key only when all of them are
/// there. A search that its budget ends has used the time for nothing.
fn not_started(label: &str, estimate: Duration, threads: usize, budget: Budget) -> String {
    format!("not searched: testing {KEY_SPACE} keys on {label} takes {} on {} and the budget is {budget}, and a search that stops before the last key finds none ({})", about(estimate), counted(threads, "thread", "threads"), more_time(estimate))
}

/// What a search says that its budget ended `elapsed` after its start, with `tested` keys
/// tested in the first pass.
fn stopped_in_the_pass(budget: Budget, tested: u64, elapsed: Duration) -> String {
    // what the whole pass takes at the pace it had, or twice the time when it had none
    let needed = match tested {
        0 => elapsed.saturating_mul(2),
        _ => Duration::from_nanos(u64::try_from(elapsed.as_nanos().saturating_mul(u128::from(KEY_SPACE)) / u128::from(tested)).unwrap_or(u64::MAX)),
    };
    format!("the budget of {budget} ended the search with {tested} of {KEY_SPACE} keys tested ({}%) ({})", percent(tested), more_time(needed))
}

/// What a search says that its budget ended `elapsed` after its start, before the first
/// pass: the unencrypted members in front of a solid archive were being unpacked.
fn stopped_before_the_pass(budget: Budget, elapsed: Duration) -> String {
    format!("the budget of {budget} ended the search before a key was tested: the unencrypted members at the front of the solid archive were still being unpacked ({})", more_time(elapsed.saturating_mul(2)))
}

/// What a search says that its budget ended `elapsed` after its start, when every key was
/// tested on the first entry and `keys` of them were being tested on the others.
fn stopped_after_the_pass(budget: Budget, label: &str, keys: usize, elapsed: Duration) -> String {
    format!("the budget of {budget} ended the search: every key was tested on {label}, and the {keys} that passed were still being tested on the other entries ({})", more_time(elapsed.saturating_mul(2)))
}

/// The entry the first pass is made on: the cheapest to test, and the first
/// of them in the archive when several cost the same.
fn cheapest<'a, 'b>(probes: &'b [Probe<'a>]) -> Option<&'b Probe<'a>> {
    probes.iter().min_by_key(|probe| probe.cost())
}

/// The keys of `passed` that give every tested entry its checksum. `None`
/// when the clock ran out.
///
/// While more than one key is left, they are first tested on the entries that
/// stand by themselves, the cheapest first: each takes all wrong keys but one
/// in 65,536 with it. What is left is walked through every entry in the order
/// of the archive, as an archive tool unpacks them.
fn narrow(data: &[u8], layout: &Layout, plan: &Plan, probes: &[Probe<'_>], oracle: usize, passed: Vec<[u8; 3]>, clock: &Clock) -> Option<Vec<[u8; 3]>> {
    let mut keys = passed;
    let mut others: Vec<&Probe<'_>> = probes.iter().filter(|probe| probe.index != oracle).collect();
    others.sort_by_key(|probe| probe.cost());
    for probe in others {
        if keys.len() <= 1 {
            break;
        }
        keys = keep(keys, |key, scratch| (!clock.out()).then(|| probe.passes(key, scratch)))?;
    }
    keep(keys, |key, scratch| match walk(data, layout, plan, key, scratch, clock, None) {
        Walked::Passed => Some(true),
        Walked::Failed => Some(false),
        Walked::Stopped => None,
    })
}

/// What the keys that give every tested entry its checksum come to. `None`
/// when the clock ran out.
fn decide(data: &[u8], layout: &Layout, plan: &Plan, keys: Vec<[u8; 3]>, clock: &Clock) -> Option<Recovery> {
    Some(match keys.as_slice() {
        [] => Recovery::NoKey,
        [key] => Recovery::Unique(*key),
        _ => {
            // Several keys pass the 16-bit checksum. Narrow by stream length
            // first (a wrong key rarely stops decoding on the last byte), then
            // by content. Each step is only trusted when it leaves one key.
            let mut scored: Vec<([u8; 3], Evidence)> = Vec::with_capacity(keys.len());
            for &key in &keys {
                scored.push((key, evidence(data, layout, plan, key, clock)?));
            }
            let has_compressed = layout.entries.iter().zip(&plan.steps).any(|(entry, step)| matches!(step, Step::Test { .. }) && !entry.stored());
            let exact: Vec<[u8; 3]> = scored.iter().filter(|(_, ev)| ev.exact_length).map(|(key, _)| *key).collect();
            let readable: Vec<[u8; 3]> = scored.iter().filter(|(_, ev)| ev.recognisable && (ev.exact_length || exact.is_empty())).map(|(key, _)| *key).collect();
            match (exact.as_slice(), readable.as_slice()) {
                ([key], _) if has_compressed => Recovery::Selected { key: *key, equivalent: keys.len(), by: Selection::StreamLength },
                (_, [key]) => Recovery::Selected { key: *key, equivalent: keys.len(), by: Selection::Content },
                _ => Recovery::Ambiguous(if exact.is_empty() { keys } else { exact }),
            }
        },
    })
}

/// Recover the key of a RAR 1.4 archive by exhaustive search.
///
/// Returns `None` when the archive has no encrypted entry, and otherwise how
/// the search ended and how many encrypted entries it could not test.
pub(crate) fn recover_key(source: &Source, run: Run) -> anyhow::Result<Option<(Recovery, usize)>> {
    recover(source, run, SEARCH_MEMORY, |oracle| measure(oracle))
}

/// The threads a search runs on: all `threads` there are, unless the entries
/// are so large that what the threads keep would together be over `memory`.
///
/// For the key it is testing on a compressed entry, a thread keeps the packed
/// bytes decrypted and what they unpack to. A stored entry is tested with
/// nothing kept, and the plan holds no compressed entry over the limit.
fn workers_for(layout: &Layout, plan: &Plan, threads: usize, memory: u64) -> usize {
    let unpacked = layout.entries.iter().zip(&plan.steps).filter(|(entry, step)| !entry.stored() && **step != Step::Skip);
    let most = unpacked.map(|(entry, _)| wide(entry.data.len()).saturating_add(wide(entry.unp_size))).max().unwrap_or(0);
    // nothing unpacked is nothing kept, and no reason for fewer threads
    memory.checked_div(most).map_or(threads, |fit| usize::try_from(fit).unwrap_or(usize::MAX).clamp(1, threads.max(1)))
}

/// [`recover_key`], with `memory` for what the threads keep and the rate of
/// the first pass taken from `gauge`.
fn recover(source: &Source, run: Run, memory: u64, gauge: impl Fn(&Probe<'_>) -> Rate + Sync) -> anyhow::Result<Option<(Recovery, usize)>> {
    let started = Instant::now();
    let data = held(source)?;
    let layout = parse_layout(source)?;
    if !layout.entries.iter().any(|e| e.encrypted) {
        return Ok(None);
    }

    // An entry that no key satisfies leaves no key to search for.
    if let Some((index, entry)) = layout.entries.iter().enumerate().find(|(_, entry)| entry.checkable() && !entry.satisfiable()) {
        run.notes.say(&format!("{} is not what its header says: {} do not unpack to {} under any key, so no key is searched for", entry.label(index), counted(entry.data.len(), "packed byte", "packed bytes"), entry.unp_size));
        return Ok(Some((Recovery::NoKey, 0)));
    }

    let plan = plan_for(&layout);
    let search = || search(data, &layout, &plan, run, started, &gauge);
    let threads = rayon::current_num_threads();
    let workers = workers_for(&layout, &plan, threads, memory);
    if workers >= threads {
        return search();
    }
    let pool = rayon::ThreadPoolBuilder::new().num_threads(workers).build().map_err(|error| anyhow::anyhow!("cannot start the threads of the search: {error}"))?;
    pool.install(search)
}

/// The search of [`recover`], on the threads of the pool it is called in.
fn search(data: &[u8], layout: &Layout, plan: &Plan, run: Run, started: Instant, gauge: &(impl Fn(&Probe<'_>) -> Rate + Sync)) -> anyhow::Result<Option<(Recovery, usize)>> {
    let Run { budget, notes } = run;
    let left_out = plan.left_out.len();
    for &index in &plan.left_out {
        if let Some(entry) = layout.entries.get(index) {
            let why = if entry.over_limit() { format!("it unpacks to {} bytes, and no more than {MAX_DECODE_BUFFER} are unpacked for a key", entry.unp_size) } else { "it is a member of a solid archive behind one that is not unpacked".to_owned() };
            notes.say(&format!("{} is not tested: {why}", entry.label(index)));
        }
    }

    let clock = Clock::until(match budget {
        Budget::Limit(limit) => started.checked_add(limit),
        Budget::Unlimited => None,
    });
    let Some(probes) = probes_of(data, layout, plan, &clock) else { return Ok(Some((Recovery::Stopped(stopped_before_the_pass(budget, started.elapsed())), left_out))) };
    let Some(oracle) = cheapest(&probes) else {
        anyhow::bail!("{}", if left_out == 0 { "no complete encrypted entry to test keys against" } else { "no encrypted entry is left to test keys against: none can be unpacked within the limit" });
    };
    let label = oracle.entry.label(oracle.index);
    let standing = match (probes.len(), plan.tested()) {
        (1, 1) => "the only entry a key can be tested on".to_owned(),
        (1, _) => "the first compressed entry of a solid archive: the later ones unpack only after it".to_owned(),
        (several, _) => format!("the cheapest of the {several} entries a key can be tested on by itself"),
    };
    notes.say(&format!("testing {KEY_SPACE} keys on {}, {standing}", oracle.described()));

    // What the pass takes, from a moment of it, before it starts.
    let rate = gauge(oracle);
    let estimate = rate.time_for(work_of_a_pass(oracle));
    let on_threads = counted(rate.threads, "thread", "threads");
    match budget {
        Budget::Limit(limit) if estimate > limit => return Ok(Some((Recovery::Stopped(not_started(&label, estimate, rate.threads, budget)), left_out))),
        Budget::Limit(_) => notes.say(&format!("this takes {} on {on_threads}; the budget is {budget}", about(estimate))),
        Budget::Unlimited => notes.say(&format!("this takes {} on {on_threads}; there is no budget", about(estimate))),
    }

    let progress = Progress::start(notes, oracle.work_per_key(), estimate);
    let passed = match sweep(oracle, &clock, &progress) {
        Swept::All(passed) => passed,
        Swept::Stopped { tested } => return Ok(Some((Recovery::Stopped(stopped_in_the_pass(budget, tested, started.elapsed())), left_out))),
    };
    notes.say(&format!("{KEY_SPACE} of {KEY_SPACE} keys tested: {} the checksum of {label}", counted(passed.len(), "passes", "pass")));

    let in_the_pass = passed.len();
    let recovery = narrow(data, layout, plan, &probes, oracle.index, passed, &clock).and_then(|keys| {
        if plan.tested() > 1 {
            notes.say(&format!("{} tested on all {} entries: {} every checksum", counted(in_the_pass, "key", "keys"), plan.tested(), counted(keys.len(), "passes", "pass")));
        }
        decide(data, layout, plan, keys, &clock)
    });
    let recovery = recovery.unwrap_or_else(|| Recovery::Stopped(stopped_after_the_pass(budget, &label, in_the_pass, started.elapsed())));
    Ok(Some((recovery, left_out)))
}

/// Write a copy of the archive with every encrypted entry decrypted by `key`
/// and its password flag cleared. Returns the number of entries decrypted.
///
/// The copy goes to a file that is created for it. A file that exists at
/// `output_path` is left as it is, and so is the target of a symbolic link
/// there: both are an error.
pub(crate) fn write_plaintext_archive(source: &Source, key: [u8; 3], output_path: &Path) -> anyhow::Result<usize> {
    let data = held(source)?;
    let layout = parse_layout(source)?;
    let encrypted: Vec<&Entry> = layout.entries.iter().filter(|entry| entry.encrypted).collect();
    if encrypted.is_empty() {
        return Ok(0);
    }

    // The copy is written as it is read: what stands between the encrypted entries as it is,
    // the flags of each with the password flag cleared, and its data decrypted a piece at a
    // time. Nothing of the archive is held a second time.
    let mut file = std::io::BufWriter::new(std::fs::OpenOptions::new().write(true).create_new(true).open(output_path)?);
    let mut at = 0_usize;
    for entry in &encrypted {
        // the entries stand in the order of the archive, each header in front of its data
        let (Some(before), Some(&flags), Some(header), Some(body)) = (data.get(at..entry.flags_pos), data.get(entry.flags_pos), data.get(entry.flags_pos.saturating_add(1)..entry.data.start), data.get(entry.data.clone())) else {
            anyhow::bail!("an entry of the archive does not lie behind the one before it");
        };
        file.write_all(before)?;
        file.write_all(&[flags & !LHD_PASSWORD])?;
        file.write_all(header)?;
        let mut cipher = Rar13State::new(key);
        for piece in body.chunks(COPY_PIECE) {
            let mut plain = piece.to_vec();
            cipher.decrypt_in_place(&mut plain);
            file.write_all(&plain)?;
        }
        at = entry.data.end;
    }
    file.write_all(data.get(at..).unwrap_or_default())?;
    file.flush()?;
    Ok(encrypted.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RAR 1.4 signature.
    const RAR1_SIG: &[u8] = b"RE~^";
    /// Minimum file header size.
    const RAR1_MIN_FILE_HEAD: usize = 21;
    /// Main header flag: solid archive.
    const MHD_SOLID: u8 = 0x08;
    /// File header flag: entry continues from the previous volume.
    const LHD_SPLIT_BEFORE: u8 = 0x01;

    /// The archive in memory, as the search is handed it.
    fn src(data: &[u8]) -> Source {
        Source::from_bytes(data.to_vec())
    }
    use crate::attack::rar_13::crack::key_from_password;

    /// A search with no limit that notes nothing.
    const QUIET: Run = Run { budget: Budget::Unlimited, notes: Notes { quiet: true } };
    /// The key the password "password" gives.
    const KEY: [u8; 3] = [0x73, 0x1f, 0x3d];
    /// The group of [`KEY`].
    const KEY_GROUP: u32 = 0x3d1f;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/rar-13/{name}")).unwrap()
    }

    /// One entry of an archive that a test builds.
    #[derive(Clone)]
    struct Member {
        name: String,
        method: u8,
        flags: u8,
        unp_size: u32,
        checksum: u16,
        packed: Vec<u8>,
    }

    fn encrypt(key: [u8; 3], plain: &[u8]) -> Vec<u8> {
        let [mut k0, mut k1, k2] = key;
        let mut cipher = plain.to_vec();
        for byte in &mut cipher {
            k1 = k1.wrapping_add(k2);
            k0 = k0.wrapping_add(k1);
            *byte = byte.wrapping_add(k0);
        }
        cipher
    }

    /// Text of `len` bytes.
    fn text(len: usize) -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog.\r\n".iter().copied().cycle().take(len).collect()
    }

    /// A stored entry of `plain`, encrypted with `key`.
    fn stored(name: &str, plain: &[u8], key: [u8; 3]) -> Member {
        Member { name: name.to_owned(), method: 0, flags: LHD_PASSWORD, unp_size: u32::try_from(plain.len()).unwrap(), checksum: checksum14(plain), packed: encrypt(key, plain) }
    }

    /// A compressed, encrypted entry that claims to unpack `packed` to `unp_size` bytes.
    fn claims(name: &str, packed: Vec<u8>, unp_size: u32) -> Member {
        Member { name: name.to_owned(), method: 3, flags: LHD_PASSWORD, unp_size, checksum: 0x1234, packed }
    }

    /// The entries of an archive, as they are in it.
    fn members_of(data: &[u8]) -> Vec<Member> {
        let layout = parse_layout(&src(data)).unwrap();
        layout.entries.iter().map(|entry| Member { name: String::from_utf8(entry.name.clone()).unwrap(), method: entry.method, flags: data[entry.flags_pos], unp_size: u32::try_from(entry.unp_size).unwrap(), checksum: entry.checksum, packed: data[entry.data.clone()].to_vec() }).collect()
    }

    /// A RAR 1.4 archive of `members`.
    fn archive(solid: bool, members: &[Member]) -> Vec<u8> {
        let mut data = RAR1_SIG.to_vec();
        data.extend_from_slice(&7u16.to_le_bytes());
        data.push(if solid { MHD_SOLID } else { 0 });
        for member in members {
            data.extend_from_slice(&u32::try_from(member.packed.len()).unwrap().to_le_bytes());
            data.extend_from_slice(&member.unp_size.to_le_bytes());
            data.extend_from_slice(&member.checksum.to_le_bytes());
            data.extend_from_slice(&u16::try_from(RAR1_MIN_FILE_HEAD + member.name.len()).unwrap().to_le_bytes());
            data.extend_from_slice(&[0, 0, 0, 0, 0, member.flags, 2, u8::try_from(member.name.len()).unwrap(), member.method]);
            data.extend_from_slice(member.name.as_bytes());
            data.extend_from_slice(&member.packed);
        }
        data
    }

    /// The index of the entry the first pass over `data` is made on, and of all the entries a
    /// key can be tested on by itself.
    fn first_pass(data: &[u8]) -> (Option<usize>, Vec<usize>) {
        let layout = parse_layout(&src(data)).unwrap();
        let plan = plan_for(&layout);
        let probes = probes_of(data, &layout, &plan, &Clock::until(None)).unwrap();
        (cheapest(&probes).map(|probe| probe.index), probes.iter().map(|probe| probe.index).collect())
    }

    /// The solid fixture with its first member not encrypted: the unencrypted archive it was
    /// made from, with the two later members encrypted as the fixture has them.
    fn solid_behind_an_unencrypted_member() -> Vec<u8> {
        let mut members = members_of(&fixture("rar14-solid-password.rar"));
        members[0] = members_of(&std::fs::read("tests/fixtures/unencrypted/rar14-solid.rar").unwrap()).swap_remove(0);
        archive(true, &members)
    }

    #[test]
    fn reject_non_rar1() {
        assert!(recover_key(&src(b"PK\x03\x04xxx"), QUIET).is_err());
        assert!(key_matches(&src(b"PK\x03\x04xxx"), [0; 3]).is_err());
    }

    /// What a key decrypts to counts when it is text, or starts as the name of its entry says:
    /// the signatures are those of the attack's own table.
    #[test]
    fn content_is_recognised_as_text_or_by_the_signature_its_name_implies() {
        let mut picture = b"GIF89a".to_vec();
        picture.extend((0..90_u8).map(|n| n.wrapping_mul(37) ^ 0x80));
        let recognised = |name: &str| {
            let data = archive(false, &[stored(name, &picture, KEY)]);
            let layout = parse_layout(&src(&data)).unwrap();
            evidence(&data, &layout, &plan_for(&layout), KEY, &Clock::until(None)).unwrap().recognisable
        };
        assert!(recognised("LOGO.GIF"));
        assert!(!recognised("LOGO.BIN"), "bytes that are no text under a name that implies nothing");
        assert!(!recognised("LOGO.PNG"), "and under a name that implies another start");

        let data = archive(false, &[stored("NOTE.BIN", &text(80), KEY)]);
        let layout = parse_layout(&src(&data)).unwrap();
        assert!(evidence(&data, &layout, &plan_for(&layout), KEY, &Clock::until(None)).unwrap().recognisable, "text is text under any name");
    }

    #[test]
    fn text_test() {
        assert!(is_text(b"Hello, this is a normal text file.\r\n"));
        assert!(!is_text(b"short"));
        assert!(!is_text(&[0xFFu8; 50]));
        assert!(!is_text(&[]));
        let mut dos = b"Plain text with a few code-page letters ".repeat(2);
        dos.extend_from_slice(&[0x9d, 0xe2, 0xae, 0xa0]);
        assert!(is_text(&dos));
        dos.push(0x01);
        assert!(!is_text(&dos));
    }

    #[test]
    fn password_key_matches_every_fixture() {
        let key = key_from_password(b"password");
        assert_eq!(key, KEY);
        for name in ["rar14-password-stored.rar", "rar14-password-compressed.rar", "rar14-solid-password.rar", "README_password=password.rar", "edge_rars_STOREPWD.RAR"] {
            assert!(key_matches(&src(&fixture(name)), key).unwrap(), "{name}: true key rejected");
            assert!(!key_matches(&src(&fixture(name)), key_from_password(b"wrong")).unwrap(), "{name}: wrong key accepted");
        }
    }

    #[test]
    fn plaintext_archive_has_no_encrypted_entries() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("out.rar");
        let data = fixture("rar14-solid-password.rar");
        assert_eq!(write_plaintext_archive(&src(&data), key_from_password(b"password"), &out).unwrap(), 3);
        let written = std::fs::read(&out).unwrap();
        assert_eq!(written.len(), data.len());
        assert!(parse_layout(&src(&written)).unwrap().entries.iter().all(|e| !e.encrypted));
    }

    // -----------------------------------------------------------------------
    // The entry the first pass is made on
    // -----------------------------------------------------------------------

    #[test]
    fn the_first_pass_is_made_on_the_cheapest_entry_wherever_it_is_in_the_archive() {
        let small = stored("SMALL.TXT", &text(60), KEY);
        let large = stored("LARGE.TXT", &text(200_000), KEY);
        assert_eq!(first_pass(&archive(false, &[large.clone(), small.clone()])), (Some(1), vec![0, 1]));
        assert_eq!(first_pass(&archive(false, &[small.clone(), large.clone()])), (Some(0), vec![0, 1]));
        assert_eq!(first_pass(&archive(false, &[large.clone(), small.clone(), large.clone()])), (Some(1), vec![0, 1, 2]));
        // of two that cost the same, the first
        assert_eq!(first_pass(&archive(false, &[large.clone(), small.clone(), small.clone()])).0, Some(1));
        assert_eq!(first_pass(&archive(false, &[large])).0, Some(0));

        // a compressed entry is unpacked for every key: 83 packed bytes cost more than 2,000
        // stored ones, and less than 100,000
        let compressed = members_of(&fixture("rar14-password-compressed.rar")).swap_remove(0);
        assert_eq!((compressed.method, compressed.packed.len(), compressed.unp_size), (3, 83, 87));
        assert_eq!(first_pass(&archive(false, &[compressed.clone(), stored("A.TXT", &text(2000), KEY)])).0, Some(1));
        assert_eq!(first_pass(&archive(false, &[compressed.clone(), stored("A.TXT", &text(100_000), KEY)])).0, Some(0));
        assert_eq!(first_pass(&archive(false, &[stored("A.TXT", &text(100_000), KEY), compressed.clone()])).0, Some(1));

        // of two compressed entries, the one the decoder reads less of under a wrong key:
        // fewer packed bytes, or packed bytes that are not read to their end
        let readme = members_of(&fixture("README_password=password.rar")).swap_remove(0);
        assert_eq!(first_pass(&archive(false, &[readme.clone(), compressed.clone()])).0, Some(1));
        assert_eq!(first_pass(&archive(false, &[readme, claims("SHORT.BIN", vec![0x55; 5000], 20)])).0, Some(1));
        assert_eq!(first_pass(&archive(false, &[compressed, small])).0, Some(1));
    }

    #[test]
    fn the_cost_of_an_entry_is_what_one_key_takes_on_it() {
        let data = archive(false, &[stored("A.TXT", &text(5000), KEY), claims("B.BIN", vec![0; 300], 100_000), claims("C.BIN", vec![0; 300], 100)]);
        let layout = parse_layout(&src(&data)).unwrap();
        let plan = plan_for(&layout);
        let costs: Vec<u64> = probes_of(&data, &layout, &plan, &Clock::until(None)).unwrap().iter().map(Probe::cost).collect();
        // a stored byte is one; a packed byte is 128, with 16 more for the entry, and no
        // more packed bytes are read than give the unpacked size at two for one
        assert_eq!(costs, [5000, 128 * (16 + 300), 128 * (16 + 50)]);
    }

    #[test]
    fn a_solid_archive_is_tested_first_on_a_stored_entry_or_on_its_first_compressed_member() {
        // three compressed members: only the first can be unpacked without the others
        let solid = fixture("rar14-solid-password.rar");
        let layout = parse_layout(&src(&solid)).unwrap();
        assert!(layout.solid);
        assert_eq!(plan_for(&layout).steps, [Step::Test { solid: false }, Step::Test { solid: true }, Step::Test { solid: true }]);
        assert_eq!(first_pass(&solid), (Some(0), vec![0]));

        // the same entries in an archive that is not solid stand each by itself, and the
        // smallest is the one to test first
        let members = members_of(&solid);
        let apart = archive(false, &members);
        assert_eq!(plan_for(&parse_layout(&src(&apart)).unwrap()).steps, [Step::Test { solid: false }; 3]);
        assert_eq!(first_pass(&apart), (Some(2), vec![0, 1, 2]));

        // a stored entry of a solid archive stands by itself, wherever it is
        let small = stored("SMALL.TXT", &text(60), KEY);
        let with_stored = archive(true, &[members[0].clone(), members[1].clone(), small.clone(), members[2].clone()]);
        assert_eq!(first_pass(&with_stored), (Some(2), vec![0, 2]));
        assert_eq!(plan_for(&parse_layout(&src(&with_stored)).unwrap()).steps, [Step::Test { solid: false }, Step::Test { solid: true }, Step::Test { solid: false }, Step::Test { solid: true }]);
        assert!(key_matches(&src(&with_stored), KEY).unwrap());
        // and a large one does not take the first pass from the first compressed member
        let large = stored("LARGE.BIN", &text(4_000_000), KEY);
        assert_eq!(first_pass(&archive(true, &[large, members[0].clone()])), (Some(1), vec![0, 1]));
    }

    #[test]
    fn a_solid_member_behind_unencrypted_ones_is_tested_from_the_window_they_leave() {
        let data = solid_behind_an_unencrypted_member();
        let layout = parse_layout(&src(&data)).unwrap();
        let plan = plan_for(&layout);
        assert_eq!(plan.steps, [Step::Feed { solid: false }, Step::Test { solid: true }, Step::Test { solid: true }]);
        assert!(key_matches(&src(&data), KEY).unwrap());
        assert!(!key_matches(&src(&data), [0x73, 0x1f, 0x3c]).unwrap());

        // the first encrypted member is the one entry to test first, and a key is tested on
        // it with nothing else unpacked for that key
        let probes = probes_of(&data, &layout, &plan, &Clock::until(None)).unwrap();
        assert_eq!(probes.iter().map(|probe| probe.index).collect::<Vec<_>>(), [1]);
        let probe = &probes[0];
        assert!(probe.base.is_some());
        // 37 packed bytes, and the window that is copied for each key
        assert_eq!(probe.cost(), 128 * (16 + 37) + 65536);
        let mut scratch = Scratch::new();
        for _ in 0..3 {
            assert!(probe.passes(KEY, &mut scratch));
            assert!(!probe.passes([0x73, 0x1f, 0x3c], &mut scratch));
            assert!(!probe.passes([0x75, 0x1f, 0x3d], &mut scratch));
        }
        let mut passed = Vec::new();
        probe.group(KEY_GROUP, &mut scratch, &Clock::until(None), &mut |_| {}, &mut passed);
        assert!(passed.contains(&KEY), "{passed:?}");

        // the member in front is unpacked once, before any key, and under the clock like
        // all the rest: a search that the budget ends there says so
        let stopped = Clock::until(Some(Instant::now()));
        assert!(probes_of(&data, &layout, &plan, &stopped).is_none());
        let run = Run { budget: Budget::Limit(Duration::from_secs(1)), notes: Notes { quiet: true } };
        let early = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
        let Some((Recovery::Stopped(why), 0)) = search(&data, &layout, &plan, run, early, &|_: &Probe<'_>| Rate::UNMEASURED).unwrap() else { panic!("not stopped") };
        assert!(why.starts_with("the budget of 1 second ended the search before a key was tested: the unencrypted members at the front of the solid archive were still being unpacked (raise it with --budget "), "{why}");
        // an archive with nothing to unpack before the first key has its entries whatever the clock says
        let all_encrypted = fixture("rar14-solid-password.rar");
        let layout = parse_layout(&src(&all_encrypted)).unwrap();
        assert!(probes_of(&all_encrypted, &layout, &plan_for(&layout), &stopped).is_some());
    }

    #[test]
    fn a_search_runs_on_fewer_threads_when_its_entries_are_large() {
        let small = stored("SMALL.TXT", &text(24), KEY);
        let compressed = members_of(&fixture("rar14-password-compressed.rar")).swap_remove(0);
        let threads_for = |members: &[Member], solid: bool, memory: u64| {
            let data = archive(solid, members);
            let layout = parse_layout(&src(&data)).unwrap();
            workers_for(&layout, &plan_for(&layout), 16, memory)
        };
        // a stored entry is tested with nothing kept, however large it is
        assert_eq!(threads_for(&[stored("LARGE.TXT", &text(300_000), KEY)], false, 1), 16);
        // a compressed one keeps its 83 packed bytes and the 87 they unpack to, for each thread
        assert_eq!(threads_for(&[small.clone(), compressed.clone()], false, 16 * 170), 16);
        assert_eq!(threads_for(&[small.clone(), compressed.clone()], false, 16 * 170 - 1), 15);
        assert_eq!(threads_for(&[small.clone(), compressed.clone()], false, 2 * 170), 2);
        // one thread at the least, whatever one key takes
        assert_eq!(threads_for(&[small.clone(), compressed.clone()], false, 1), 1);
        // an entry that is over the limit is not unpacked, and so keeps nothing
        assert_eq!(threads_for(&[small.clone(), claims("OVER.BIN", vec![0; 100_000], 200 << 20)], false, 1 << 20), 16);
        assert_eq!(SEARCH_MEMORY / (2 * MAX_DECODE_BUFFER), 4, "the largest entry that is unpacked still has four threads");

        // held to two threads, a search finds the key as it does on all of them
        let run = Run { budget: Budget::Unlimited, notes: Notes { quiet: true } };
        let tiny = stored("TINY.TXT", b"key?", KEY);
        let data = archive(false, &[compressed, tiny]);
        assert_eq!(recover(&src(&data), run, 2 * 170, |oracle| measure(oracle)).unwrap(), Some((Recovery::Unique(KEY), 0)));
    }

    #[test]
    fn a_compressed_member_that_is_not_unpacked_takes_the_later_members_of_a_solid_archive_with_it() {
        let small = stored("SMALL.TXT", &text(60), KEY);
        let mut cut = claims("CUT.BIN", vec![0; 50], 500);
        cut.flags |= LHD_SPLIT_BEFORE;
        let whole = claims("WHOLE.BIN", vec![0; 50], 500);

        // the member that continues from another volume cannot be unpacked, so the member
        // behind it starts from a window nobody has: it is left out, and said to be
        let data = archive(true, &[cut.clone(), whole.clone(), small.clone()]);
        let plan_of = |data: &[u8]| plan_for(&parse_layout(&src(data)).unwrap());
        assert_eq!(plan_of(&data).steps, [Step::Skip, Step::Skip, Step::Test { solid: false }]);
        assert_eq!(plan_of(&data).left_out, [1]);
        assert_eq!(first_pass(&data), (Some(2), vec![2]));

        // in an archive that is not solid it stands by itself
        let data = archive(false, &[cut, whole.clone(), small.clone()]);
        assert_eq!(plan_of(&data).steps, [Step::Skip, Step::Test { solid: false }, Step::Test { solid: false }]);
        assert!(plan_of(&data).left_out.is_empty());

        // a member over the limit is the same gap, and is itself left out
        let over = claims("OVER.BIN", vec![0; 100_000], 200 << 20);
        let data = archive(true, &[whole.clone(), over.clone(), whole.clone(), small.clone()]);
        assert_eq!(plan_of(&data).steps, [Step::Test { solid: false }, Step::Skip, Step::Skip, Step::Test { solid: false }]);
        assert_eq!(plan_of(&data).left_out, [1, 2]);
        let data = archive(false, &[whole.clone(), over, whole, small]);
        assert_eq!(plan_of(&data).steps, [Step::Test { solid: false }, Step::Skip, Step::Test { solid: false }, Step::Test { solid: false }]);
        assert_eq!(plan_of(&data).left_out, [1]);
    }

    // -----------------------------------------------------------------------
    // What one key can cost
    // -----------------------------------------------------------------------

    #[test]
    fn a_header_that_claims_more_than_the_packed_bytes_can_give_asks_nothing_of_the_decoder() {
        // 4 KiB that claim 4 GiB, as in an archive built to exhaust memory
        let data = archive(false, &[claims("BOMB.BIN", vec![0xa5; 4096], u32::MAX)]);
        let layout = parse_layout(&src(&data)).unwrap();
        let entry = &layout.entries[0];
        assert!(entry.checkable() && !entry.satisfiable());
        let mut scratch = Scratch::new();
        assert!(entry_plaintext(&data, entry, KEY, false, &mut scratch).is_none());
        assert!(scratch.body.is_empty() && scratch.decoder.member().is_empty(), "nothing was decrypted and nothing unpacked");

        // no key can satisfy it, so none is searched for: the answer is there at once
        let started = Instant::now();
        assert_eq!(recover_key(&src(&data), QUIET).unwrap(), Some((Recovery::NoKey, 0)));
        assert!(started.elapsed() < Duration::from_secs(10), "a search was run: {:?}", started.elapsed());

        // the most a packed byte gives is the line: on it an entry is unpacked, over it not
        let most = u32::try_from(50 * MOST_UNPACKED_PER_BYTE).unwrap();
        let on_the_line = archive(false, &[claims("A.BIN", vec![0; 50], most), claims("B.BIN", vec![0; 50], most + 1)]);
        let layout = parse_layout(&src(&on_the_line)).unwrap();
        assert_eq!(layout.entries.iter().map(Entry::satisfiable).collect::<Vec<_>>(), [true, false]);

        // a stored entry holds what it has: one that claims a byte more is satisfied by no key
        let mut short = stored("SHORT.TXT", &text(60), KEY);
        short.unp_size += 1;
        let data = archive(false, &[stored("FIRST.TXT", &text(60), KEY), short]);
        assert_eq!(parse_layout(&src(&data)).unwrap().entries.iter().map(Entry::satisfiable).collect::<Vec<_>>(), [true, false]);
        assert_eq!(recover_key(&src(&data), QUIET).unwrap(), Some((Recovery::NoKey, 0)));
    }

    #[test]
    fn an_entry_over_the_limit_is_not_unpacked_for_any_key() {
        // 100 KB can be 200 MiB unpacked, and that is more than is unpacked for one key
        let over = claims("OVER.BIN", vec![0x11; 100_000], 200 << 20);
        let alone = archive(false, std::slice::from_ref(&over));
        let layout = parse_layout(&src(&alone)).unwrap();
        let entry = &layout.entries[0];
        assert!(entry.checkable() && entry.satisfiable() && entry.over_limit());
        let mut scratch = Scratch::new();
        assert!(entry_plaintext(&alone, entry, KEY, false, &mut scratch).is_none());
        assert!(scratch.body.is_empty() && scratch.decoder.member().is_empty());

        // nothing else to test a key on: the archive cannot be searched
        let error = recover_key(&src(&alone), QUIET).unwrap_err().to_string();
        assert!(error.contains("none can be unpacked within the limit"), "{error}");

        // the limit is the one the crate has for output that is kept, to the byte
        let at = |unp_size: u64| Entry { flags_pos: 0, data: 0..1 << 20, name: Vec::new(), method: 3, checksum: 0, unp_size: usize::try_from(unp_size).unwrap(), encrypted: true, complete: true }.over_limit();
        assert!(!at(MAX_DECODE_BUFFER) && at(MAX_DECODE_BUFFER + 1));
        // a stored entry is never unpacked
        assert!(!Entry { flags_pos: 0, data: 0..1 << 30, name: Vec::new(), method: 0, checksum: 0, unp_size: 1 << 30, encrypted: true, complete: true }.over_limit());
    }

    #[test]
    fn garbage_unpacks_to_no_more_than_the_most_a_packed_byte_gives() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        let mut random = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        };
        let mut decoder = Unpack15::new();
        let mut most = 0;
        let mut streams: Vec<Vec<u8>> = (1..600).map(|len| (0..=len % 97).map(|_| random()).collect()).collect();
        // and streams of one byte over and over, which repeat a match or a literal
        streams.extend((0..=255u8).map(|byte| vec![byte; 64]));
        for stream in &streams {
            // a size nothing reaches, so the decoder goes on until the stream ends
            let line = stream.len() * MOST_UNPACKED_PER_BYTE;
            assert!(decoder.decode(stream, line + 1, false).is_err());
            assert!(decoder.member().len() <= line);
            most = most.max(decoder.member().len() / stream.len());
        }
        // the line is not so far off that it says nothing
        assert!(most >= 8, "{most}");
    }

    // -----------------------------------------------------------------------
    // The pass over the keys
    // -----------------------------------------------------------------------

    #[test]
    fn a_group_of_keys_on_a_stored_entry_passes_the_keys_that_pass_one_by_one() {
        // an entry of more than one piece, and one of less
        for len in [3 * PIECE + 17, 87] {
            let data = archive(false, &[stored("A.TXT", &text(len), KEY)]);
            let layout = parse_layout(&src(&data)).unwrap();
            let plan = plan_for(&layout);
            let probes = probes_of(&data, &layout, &plan, &Clock::until(None)).unwrap();
            let probe = &probes[0];
            assert_eq!(probe.work_per_key(), u64::try_from(len).unwrap());

            let mut scratch = Scratch::new();
            let mut found = 0;
            for group in [KEY_GROUP, 0, 0x8001, 0xffff, 0x1234, 0x3d1e] {
                let mut passed = Vec::new();
                let mut work = 0;
                probe.group(group, &mut scratch, &Clock::until(None), &mut |did| work += did, &mut passed);
                let one_by_one: Vec<[u8; 3]> = keys_in(group).filter(|&key| probe.passes(key, &mut scratch)).collect();
                assert_eq!(passed, one_by_one, "group {group:#x}");
                assert_eq!(work, probe.work_per_key() * 128);
                found += passed.len();
                assert_eq!(passed.contains(&KEY), group == KEY_GROUP);
            }
            assert!(found >= 1);
        }
    }

    #[test]
    fn a_group_is_left_when_the_clock_is_out_and_passes_nothing_it_has_not_finished() {
        let stopped = Clock::until(Some(Instant::now()));
        assert!(stopped.out());

        // a stored entry: one piece of it is done, for every key of the group
        let data = archive(false, &[stored("A.TXT", &text(3 * PIECE), KEY)]);
        let layout = parse_layout(&src(&data)).unwrap();
        let plan = plan_for(&layout);
        let probes = probes_of(&data, &layout, &plan, &Clock::until(None)).unwrap();
        let mut scratch = Scratch::new();
        let (mut passed, mut pieces) = (Vec::new(), Vec::new());
        probes[0].group(KEY_GROUP, &mut scratch, &stopped, &mut |did| pieces.push(did), &mut passed);
        assert_eq!(pieces, [128 * 4096]);
        assert!(passed.is_empty());

        // a compressed entry of 12 KB: one key is done
        let data = fixture("rar14-solid-password.rar");
        let layout = parse_layout(&src(&data)).unwrap();
        let plan = plan_for(&layout);
        let probes = probes_of(&data, &layout, &plan, &Clock::until(None)).unwrap();
        let mut pieces = Vec::new();
        probes[0].group(KEY_GROUP, &mut scratch, &stopped, &mut |did| pieces.push(did), &mut passed);
        assert_eq!(pieces, [1]);
        assert!(passed.is_empty());

        // one of 83 bytes: as many keys as read a piece of packed bytes between them
        let data = fixture("rar14-password-compressed.rar");
        let layout = parse_layout(&src(&data)).unwrap();
        let plan = plan_for(&layout);
        let probes = probes_of(&data, &layout, &plan, &Clock::until(None)).unwrap();
        let mut pieces = Vec::new();
        probes[0].group(KEY_GROUP, &mut scratch, &stopped, &mut |did| pieces.push(did), &mut passed);
        assert_eq!(pieces, [49]);
        assert!(!passed.contains(&KEY), "the key is the 58th of its group");
        // and with time, all 128, the key among them
        let mut pieces = Vec::new();
        passed.clear();
        probes[0].group(KEY_GROUP, &mut scratch, &Clock::until(None), &mut |did| pieces.push(did), &mut passed);
        assert_eq!(pieces, [49, 49, 30]);
        assert!(passed.contains(&KEY));
    }

    #[test]
    fn the_key_is_found_on_the_small_entry_and_holds_on_the_large_one() {
        // every key is tested on the 24 bytes, and those that pass on the 200,000; the entry
        // over the limit is left out of the test, and the result says that one was
        let small = stored("SMALL.TXT", &text(24), KEY);
        let large = stored("LARGE.TXT", &text(200_000), KEY);
        let over = claims("OVER.BIN", vec![0x11; 100_000], 200 << 20);
        assert_eq!(recover_key(&src(&archive(false, &[over, large, small.clone()])), QUIET).unwrap(), Some((Recovery::Unique(KEY), 1)));

        // a large entry that is under another key leaves no key for both
        let other = stored("OTHER.TXT", &text(200_000), [0x11, 0x23, 0x45]);
        assert_eq!(recover_key(&src(&archive(false, &[other, small])), QUIET).unwrap(), Some((Recovery::NoKey, 0)));
    }

    // -----------------------------------------------------------------------
    // The budget
    // -----------------------------------------------------------------------

    /// One megabyte, stored: more than any machine tests 2^23 keys on in a second.
    fn megabyte() -> Vec<u8> {
        archive(false, &[stored("BIG.BIN", &text(1 << 20), KEY)])
    }

    #[test]
    fn a_search_that_is_measured_to_take_longer_than_its_budget_is_not_started() {
        let run = Run { budget: Budget::Limit(Duration::from_secs(1)), notes: Notes { quiet: true } };
        let started = Instant::now();
        let Some((Recovery::Stopped(why), 0)) = recover_key(&src(&megabyte()), run).unwrap() else { panic!("searched") };
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
        assert!(why.starts_with("not searched: testing 8388608 keys on BIG.BIN takes about "), "{why}");
        assert!(why.contains(" and the budget is 1 second, and a search that stops before the last key finds none (raise it with --budget "), "{why}");
        assert!(why.ends_with(", or lift it with --budget none)"), "{why}");

        // the budget it names is one the command line takes, and it is over the estimate
        let named = why.split("--budget ").nth(1).and_then(|rest| rest.split(',').next()).unwrap();
        assert!(matches!(named.parse(), Ok(Budget::Limit(time)) if time > Duration::from_secs(1)), "{named}");
    }

    #[test]
    fn a_budget_that_ends_in_the_first_pass_stops_the_search_there() {
        // started all the same, as when the measurement was too low
        let run = Run { budget: Budget::Limit(Duration::from_secs(1)), notes: Notes { quiet: true } };
        let started = Instant::now();
        let Some((Recovery::Stopped(why), 0)) = recover(&src(&megabyte()), run, SEARCH_MEMORY, |_| Rate::UNMEASURED).unwrap() else { panic!("not stopped") };
        let took = started.elapsed();
        assert!(took >= Duration::from_secs(1) && took < Duration::from_secs(20), "{took:?}");

        let tested: u64 = why.strip_prefix("the budget of 1 second ended the search with ").and_then(|rest| rest.split(' ').next()).and_then(|count| count.parse().ok()).unwrap_or_else(|| panic!("{why}"));
        assert!(tested < u64::from(KEY_SPACE), "{why}");
        assert!(why.contains(&format!("{tested} of 8388608 keys tested ({}%) (raise it with --budget ", percent(tested))), "{why}");
        assert!(why.ends_with(", or lift it with --budget none)"), "{why}");
    }

    #[test]
    fn a_clock_that_is_out_ends_the_tests_on_the_other_entries() {
        let data = archive(false, &[stored("A.TXT", &text(600), KEY), stored("B.TXT", &text(60), KEY)]);
        let layout = parse_layout(&src(&data)).unwrap();
        let plan = plan_for(&layout);
        let probes = probes_of(&data, &layout, &plan, &Clock::until(None)).unwrap();
        let keys = vec![KEY, [0x75, 0x1f, 0x3d], [0x73, 0x1f, 0x3c]];

        let running = Clock::until(None);
        assert_eq!(walk(&data, &layout, &plan, KEY, &mut Scratch::new(), &running, None), Walked::Passed);
        assert_eq!(walk(&data, &layout, &plan, [0x75, 0x1f, 0x3d], &mut Scratch::new(), &running, None), Walked::Failed);
        assert_eq!(narrow(&data, &layout, &plan, &probes, 1, keys.clone(), &running), Some(vec![KEY]));
        assert_eq!(decide(&data, &layout, &plan, vec![KEY], &running), Some(Recovery::Unique(KEY)));
        assert_eq!(decide(&data, &layout, &plan, Vec::new(), &running), Some(Recovery::NoKey));

        let stopped = Clock::until(Some(Instant::now()));
        assert_eq!(walk(&data, &layout, &plan, KEY, &mut Scratch::new(), &stopped, None), Walked::Stopped);
        assert_eq!(narrow(&data, &layout, &plan, &probes, 1, keys.clone(), &stopped), None);
        assert_eq!(decide(&data, &layout, &plan, keys, &stopped), None);
        // one key is the key with no further look at the archive, and so at no clock
        assert_eq!(decide(&data, &layout, &plan, vec![KEY], &stopped), Some(Recovery::Unique(KEY)));
    }

    #[test]
    fn a_search_that_stopped_says_how_far_it_got_and_how_to_give_it_more_time() {
        let ten_minutes = Budget::Limit(Duration::from_mins(10));
        assert_eq!(
            not_started("A.BIN", Duration::from_mins(80), 16, ten_minutes),
            "not searched: testing 8388608 keys on A.BIN takes about 1 hour 20 minutes on 16 threads and the budget is 10 minutes, and a search that stops before the last key finds none (raise it with --budget 2h, or lift it with --budget none)"
        );
        assert_eq!(
            not_started("A.BIN", Duration::from_secs(45), 1, Budget::Limit(Duration::from_secs(30))),
            "not searched: testing 8388608 keys on A.BIN takes about 45 seconds on 1 thread and the budget is 30 seconds, and a search that stops before the last key finds none (raise it with --budget 70s, or lift it with --budget none)"
        );
        // a quarter in ten minutes: forty for all of it, and half as much again to be sure
        assert_eq!(stopped_in_the_pass(ten_minutes, 2_097_152, Duration::from_mins(10)), "the budget of 10 minutes ended the search with 2097152 of 8388608 keys tested (25%) (raise it with --budget 60m, or lift it with --budget none)");
        assert_eq!(stopped_in_the_pass(ten_minutes, 0, Duration::from_mins(10)), "the budget of 10 minutes ended the search with 0 of 8388608 keys tested (0%) (raise it with --budget 30m, or lift it with --budget none)");
        assert_eq!(stopped_before_the_pass(ten_minutes, Duration::from_mins(10)), "the budget of 10 minutes ended the search before a key was tested: the unencrypted members at the front of the solid archive were still being unpacked (raise it with --budget 30m, or lift it with --budget none)");
        assert_eq!(
            stopped_after_the_pass(ten_minutes, "A.TXT", 145, Duration::from_mins(10)),
            "the budget of 10 minutes ended the search: every key was tested on A.TXT, and the 145 that passed were still being tested on the other entries (raise it with --budget 30m, or lift it with --budget none)"
        );
    }
}
