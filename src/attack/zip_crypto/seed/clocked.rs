//! Writers that seed a generator from a clock for every entry, and encrypt the header once.
//!
//! - **The `ZipArchive` library of Artpol** calls `srand(time(NULL))` in front of every
//!   entry and draws ten bytes: bits 6 to 13 of a value of `rand()`, or its low byte when
//!   those are zero. The two bytes of the DOS time follow (`ZipCrc32Cryptograph.cpp`,
//!   `InitEncode`). The DWF Toolkit of Autodesk carries the same code.
//! - **zip utils of Lucian Wischik**, and `XZip` which is made of it, calls
//!   `srand(GetTickCount() ^ GetDesktopWindow())` in front of every entry: it tests a flag
//!   before it seeds and never sets it. It draws eleven bytes, bits 7 to 14 of a value each,
//!   and the high byte of the DOS time follows (`zip.cpp`, `TZip::Add`).
//! - **The zip library of ComponentOne** (`C1.Zip`, `C1.C1Zip`) makes a `new
//!   Random(DateTime.Now.Millisecond)` of .NET in front of every entry and draws ten bytes
//!   as the `ZipArchive` library does, bits 6 to 13 of a value or its low byte. The two bytes
//!   of the DOS time follow. Its clock has a thousand values, on every runtime: a generator
//!   of .NET that is given a seed is the same one everywhere.
//!
//! What follows from seeding for each entry:
//!
//! - **Entries that are written within one step of the clock have one header**, before and
//!   after encryption: they are one *group*, and a group is one seed. The clock of `time()`
//!   steps once a second, and the count of `GetTickCount()` at every interrupt of the timer
//!   of Windows, as [`super::netfx`] has it.
//! - **A guess of the clock at each group gives every header as it was before encryption.**
//!   All headers are encrypted from the same keys, so two headers that start with the same
//!   bytes are encrypted with the same stream as far as they are equal and at the first
//!   byte they differ in: there they differ exactly as the generator's bytes do. That is a
//!   test of two guesses that needs no key, and [`clocks`] asks it of every pair of groups.
//! - **The headers are a tree of known bytes that grows from one state of the keys.** The
//!   search of the known-plaintext attack starts from the candidates for the third key that
//!   one run of twelve bytes leaves, four million of them. A [`Tree`] drops every candidate
//!   that the other headers contradict: with a dozen headers a wrong clock is left with no
//!   candidate at all, and the right one with a handful, so that the keys are found in the
//!   time it takes to look at the candidates and not in the minutes it takes to search them.

use std::ops::Range;
use std::sync::LazyLock;

use archivewolf_zip_crypto::Keys;

use super::Control;
use super::Generator as _;
use super::dotnet;
use super::glibc;
use super::header_byte;
use super::msvcrt;
use super::netfx;
use super::spread;

/// The most bytes of a header that a writer of this kind takes from its generator.
pub const BYTES: usize = 11;

/// The most groups that are held against a clock.
pub const MAX_GROUPS: usize = 24;

/// How many values of the clock one piece of the search holds.
const PIECE: u64 = 1 << 13;

/// The most answers of one search that are kept.
pub const FOUND_MAX: usize = 1 << 12;

/// How many interrupts of the timer the count of `GetTickCount()` has before it starts
/// again: 2^32 milliseconds, 49.7 days, at 15.625 ms an interrupt.
pub const INTERRUPTS: u64 = 274_877_907;

/// The C library a writer is built against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    /// glibc.
    Glibc,
    /// The C runtime of Windows.
    Windows,
}

/// The handle of the desktop window in the session a user works in, on every Windows from 7
/// on: what `GetDesktopWindow()` gives a program there. A program that runs as a service
/// has a desktop of its own, with a handle that is not known beforehand.
pub const DESKTOP: u32 = 0x0001_0010;

/// The program a writer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Program {
    /// The `ZipArchive` library of Artpol: the clock is the time in seconds.
    ZipArchive(Runtime),
    /// zip utils: the clock is the number of the interrupt of the timer of Windows.
    ZipUtils,
    /// The zip library of ComponentOne: the clock is a count of milliseconds, of which the
    /// place in its second is what seeds.
    ComponentOne,
}

/// A writer that seeds for every entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Writer {
    program: Program,
    /// The handle of the desktop window, which zip utils seeds with beside the count of
    /// its clock. Nothing to the `ZipArchive` library.
    window: u32,
}

impl Writer {
    /// Every writer, in the order they are searched.
    pub const ALL: [Self; 4] = [Self::zip_archive(Runtime::Windows), Self::zip_archive(Runtime::Glibc), Self::zip_utils(DESKTOP), Self::component_one()];

    /// The `ZipArchive` library of Artpol, built against a C library.
    #[must_use]
    pub const fn zip_archive(runtime: Runtime) -> Self {
        Self { program: Program::ZipArchive(runtime), window: 0 }
    }

    /// zip utils in a session whose desktop window has the handle `window`.
    #[must_use]
    pub const fn zip_utils(window: u32) -> Self {
        Self { program: Program::ZipUtils, window }
    }

    /// The zip library of ComponentOne.
    #[must_use]
    pub const fn component_one() -> Self {
        Self { program: Program::ComponentOne, window: 0 }
    }

    /// How many values the clock of the writer has, when they are so few that every one of
    /// them is tried: the milliseconds of a second for the library of ComponentOne. `None`
    /// for a clock that is searched for.
    #[must_use]
    pub const fn values(self) -> Option<u64> {
        match self.program {
            Program::ComponentOne => Some(1000),
            Program::ZipArchive(_) | Program::ZipUtils => None,
        }
    }

    /// The writer in the words of a report.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self.program {
            Program::ZipArchive(Runtime::Windows) => "the ZipArchive library on Windows",
            Program::ZipArchive(Runtime::Glibc) => "the ZipArchive library on glibc",
            Program::ZipUtils => "zip utils",
            Program::ComponentOne => "the zip library of ComponentOne",
        }
    }

    /// Whether the clock of the writer is the time in seconds. The other clock is the count
    /// of the interrupts of a timer, which says nothing of the day.
    #[must_use]
    pub const fn by_the_second(self) -> bool {
        matches!(self.program, Program::ZipArchive(_))
    }

    /// How many bytes of a header the writer takes from its generator.
    #[must_use]
    pub const fn random(self) -> usize {
        match self.program {
            Program::ZipArchive(_) | Program::ComponentOne => 10,
            Program::ZipUtils => 11,
        }
    }

    /// What the writer seeds with at a value of the clock.
    #[must_use]
    pub const fn seed(self, clock: u64) -> u32 {
        match self.program {
            Program::ZipArchive(_) => {
                let [a, b, c, d, ..] = clock.to_le_bytes();
                u32::from_le_bytes([a, b, c, d])
            },
            Program::ZipUtils => netfx::tick_count(clock) ^ self.window,
            Program::ComponentOne => {
                let [a, b, c, d, ..] = (clock % 1000).to_le_bytes();
                u32::from_le_bytes([a, b, c, d])
            },
        }
    }

    /// The bytes the writer draws for a header after a seed, before it encrypts them. Only
    /// the first [`Self::random`] of them are drawn.
    #[must_use]
    pub fn drawn(self, seed: u32) -> [u8; BYTES] {
        let mut bytes = [0_u8; BYTES];
        match self.program {
            Program::ZipArchive(Runtime::Glibc) => {
                let mut rand = glibc::Rand::new(seed);
                for slot in bytes.iter_mut().take(self.random()) {
                    *slot = picked(rand.rand());
                }
            },
            Program::ZipArchive(Runtime::Windows) => {
                let mut rand = msvcrt::Rand::seeded(seed);
                for slot in bytes.iter_mut().take(self.random()) {
                    *slot = picked(rand.rand());
                }
            },
            Program::ZipUtils => {
                let mut rand = msvcrt::Rand::seeded(seed);
                for slot in &mut bytes {
                    *slot = header_byte(rand.rand());
                }
            },
            Program::ComponentOne => {
                let mut random = dotnet::Random::new(seed.cast_signed());
                for slot in bytes.iter_mut().take(self.random()) {
                    *slot = picked(random.sample().cast_unsigned());
                }
            },
        }
        bytes
    }

    /// The bytes of a header at a value of the clock, before encryption.
    #[must_use]
    pub fn plain(self, clock: u64) -> [u8; BYTES] {
        self.drawn(self.seed(clock))
    }

    /// The whole header of an entry at a value of the clock, before encryption: what the
    /// generator gave, and behind it the DOS time of the entry, both of its bytes for a
    /// writer that draws ten and the high one for a writer that draws eleven.
    #[must_use]
    pub fn header(self, clock: u64, time: u16) -> [u8; 12] {
        let mut header = [0_u8; 12];
        for (slot, byte) in header.iter_mut().zip(self.plain(clock)) {
            *slot = byte;
        }
        let [low, high] = time.to_le_bytes();
        let [.., before_last, last] = &mut header;
        if self.random() == 10 {
            *before_last = low;
        }
        *last = high;
        header
    }
}

/// The byte the `ZipArchive` library takes of a value of `rand()`, and the library of
/// ComponentOne of a value of its generator: bits 6 to 13, and the low byte when those are
/// zero.
const fn picked(value: u32) -> u8 {
    let [byte, ..] = (value >> 6).to_le_bytes();
    if byte == 0 { value.to_le_bytes()[0] } else { byte }
}

/// Whether two headers can have been encrypted from the same keys: `plain` and `other` are
/// what the generator gave for each, `written` and `other_written` the headers as they stand
/// in the archive. As far as both pairs are equal the stream is the same, and at the first
/// byte one of them differs in, both differ by the same.
fn pair(plain: &[u8; BYTES], written: &[u8; 12], other: &[u8; BYTES], other_written: &[u8; 12], random: usize) -> bool {
    for (((a, b), c), d) in plain.iter().zip(other).zip(written).zip(other_written).take(random) {
        if a != b || c != d {
            return a ^ b == c ^ d;
        }
    }
    // two groups are two headers
    false
}

/// Go on from the last group that has a place: every value of the clock within the gap that
/// every earlier group agrees with, and from there the groups behind it. A sequence that
/// reaches the last group is given to `each`. A place is a value of the clock, counted from
/// the start of `plains`.
fn follow(plains: &[[u8; BYTES]], headers: &[[u8; 12]], random: usize, gap: usize, places: &mut Vec<usize>, each: &mut impl FnMut(&[usize])) {
    let Some(header) = headers.get(places.len()) else {
        each(places);
        return;
    };
    let Some(&last) = places.last() else { return };
    for step in 1..=gap {
        let Some(plain) = plains.get(last + step) else { return };
        let agrees = places.iter().zip(headers).all(|(&place, earlier)| plains.get(place).is_some_and(|of_earlier| pair(of_earlier, earlier, plain, header, random)));
        if agrees {
            places.push(last + step);
            follow(plains, headers, random, gap, places, each);
            let _ = places.pop();
        }
    }
}

/// The value of the clock at every group, for every sequence of values that starts in
/// `clocks` and that no two headers contradict.
///
/// `headers` has the header of each group as it stands in the archive, in the order the
/// groups were written, two or more. Up to `gap` steps of the clock may lie between one group
/// and the next, and only the first [`MAX_GROUPS`] groups are looked at: an answer has a
/// value for each of those. `control.done` is advanced by one for every value of the clock:
/// the total is the length of the range.
///
/// An answer is not yet the clock. Two groups say eight bits of each other, and a generator
/// whose values are a line in its seed says less: a [`Tree`] of the headers tells which
/// answer the keys can stand behind. No more than [`FOUND_MAX`] answers are kept, those with
/// the earliest start.
#[must_use]
pub fn clocks(writer: Writer, headers: &[[u8; 12]], clocks: Range<u64>, gap: usize, control: Control<'_>) -> Vec<Vec<u64>> {
    let headers = headers.get(..headers.len().min(MAX_GROUPS)).unwrap_or_default();
    if headers.len() < 2 || clocks.start >= clocks.end {
        return Vec::new();
    }
    let random = writer.random();
    let reach = (gap * (headers.len() - 1)) as u64;
    let pieces = (clocks.end - clocks.start).div_ceil(PIECE);
    let mut found = spread(pieces, control, |piece, found: &mut Vec<Vec<u64>>| {
        let from = clocks.start + piece * PIECE;
        let to = (from + PIECE).min(clocks.end);
        // what the generator gives at every value of the piece, and as far behind it as the groups can reach
        let plains: Vec<[u8; BYTES]> = (from..to + reach).map(|clock| writer.plain(clock)).collect();
        let mut places = Vec::with_capacity(headers.len());
        for start in 0..usize::try_from(to - from).unwrap_or(0) {
            places.clear();
            places.push(start);
            follow(&plains, headers, random, gap, &mut places, &mut |places| {
                if found.len() < FOUND_MAX {
                    found.push(places.iter().map(|&place| from + place as u64).collect());
                }
            });
        }
        control.advance(to - from);
    });
    found.sort_unstable();
    found.truncate(FOUND_MAX);
    found
}

/// How many values bits 2 to 15 of a third key can have.
const LOW: usize = 1 << 14;

/// What a [`Tree`] steps the third key with.
struct Tables {
    /// The table of the CRC-32.
    crc: [u32; 256],
    /// The entry of the table that has a top byte, by the byte.
    by_top: [u8; 256],
    /// Bits 2 to 9 of a third key that has a stream byte, when its bits 10 to 15 are known:
    /// a list for each stream byte and each value of the six bits.
    lows: Vec<Vec<u8>>,
    /// The bytes a third key can step with to reach a stream byte: for each stream byte and
    /// each value of bits 10 to 23 of the key before the step, the entries from `starts` of
    /// the two at and behind it.
    steps: Vec<u8>,
    starts: Vec<u32>,
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let crc: [u32; 256] = std::array::from_fn(|byte| {
        let mut keys = Keys::new(0, 0, 0);
        // the first key after a byte, from a first key of zero, is the entry of the byte
        keys.update(u8::try_from(byte).unwrap_or_default());
        keys.x
    });
    let mut by_top = [0_u8; 256];
    for (byte, entry) in (0_u8..=255).zip(&crc) {
        if let Some(slot) = by_top.get_mut((entry >> 24) as usize) {
            *slot = byte;
        }
    }
    // the values of bits 2 to 15 that give each stream byte: 64 for each
    let mut values: Vec<Vec<u16>> = vec![Vec::new(); 256];
    for value in 0..LOW {
        let third = u32::try_from(value << 2).unwrap_or_default();
        if let Some(of_byte) = values.get_mut(usize::from(Keys::new(0, 0, third).stream_byte())) {
            of_byte.push(u16::try_from(value).unwrap_or_default());
        }
    }
    let mut lows: Vec<Vec<u8>> = vec![Vec::new(); 256 << 6];
    for (stream, of_byte) in values.iter().enumerate() {
        for &value in of_byte {
            if let Some(list) = lows.get_mut((stream << 6) | usize::from(value >> 8)) {
                list.push(value.to_le_bytes()[0]);
            }
        }
    }
    // a step: bits 2 to 15 behind it are bits 10 to 23 in front of it, exclusive-or bits 2 to
    // 15 of the table entry of the byte. Counted first, then filled, so that the lists lie
    // in one piece of memory
    let entries: Vec<usize> = crc.iter().map(|entry| ((entry >> 2) as usize) & (LOW - 1)).collect();
    let mut starts = vec![0_u32; (256 << 14) + 1];
    for (stream, of_byte) in values.iter().enumerate() {
        for &value in of_byte {
            for &entry in &entries {
                if let Some(count) = starts.get_mut(((stream << 14) | (usize::from(value) ^ entry)) + 1) {
                    *count += 1;
                }
            }
        }
    }
    let mut total = 0_u32;
    for start in &mut starts {
        total += *start;
        *start = total;
    }
    let mut steps = vec![0_u8; total as usize];
    let mut filled = starts.clone();
    for (stream, of_byte) in values.iter().enumerate() {
        for &value in of_byte {
            for (byte, &entry) in (0_u8..=255).zip(&entries) {
                if let Some(next) = filled.get_mut((stream << 14) | (usize::from(value) ^ entry)) {
                    if let Some(slot) = steps.get_mut(*next as usize) {
                        *slot = byte;
                    }
                    *next += 1;
                }
            }
        }
    }
    Tables { crc, by_top, lows, steps, starts }
});

impl Tables {
    /// The entry of the CRC table for a byte.
    fn crc(&self, byte: u8) -> u32 {
        self.crc.get(usize::from(byte)).copied().unwrap_or_default()
    }

    /// The bytes a third key can step with to a key that has the stream byte `stream`.
    fn steps(&self, stream: u8, third: u32) -> &[u8] {
        let at = (usize::from(stream) << 14) | ((third >> 10) as usize & (LOW - 1));
        let (Some(&from), Some(&to)) = (self.starts.get(at), self.starts.get(at + 1)) else { return &[] };
        self.steps.get(from as usize..to as usize).unwrap_or_default()
    }

    /// Bits 2 to 9 that a third key with the stream byte `stream` can have, when its bits 10
    /// to 31 are those of `third`.
    fn lows(&self, stream: u8, third: u32) -> &[u8] {
        self.lows.get((usize::from(stream) << 6) | ((third >> 10) as usize & 0x3f)).map_or(&[], Vec::as_slice)
    }
}

/// The headers of an archive as a tree of known bytes: every header is encrypted from the
/// keys after the password, and two headers have the keys in common for as long as their
/// bytes are the same.
///
/// The third key steps with the top byte of the second, which is not known, so a third key
/// in front of a byte can go on to 256 others: the stream byte of the next byte leaves one
/// of them on average, and none more than a third of the time. A third key that cannot go
/// on along every header to its last byte is not the key.
#[derive(Debug, Clone)]
pub struct Tree {
    /// The stream bytes of the header the search runs on.
    first: [u8; 12],
    /// What is held against it, group by group: the stream bytes of every header a group
    /// may have, and how many bytes each has in common with the first, before and after
    /// encryption. One of them is the header of the group.
    others: Vec<Vec<([u8; 12], usize)>>,
}

impl Tree {
    /// The tree of a header and of the others that are held against it: each as it was
    /// before encryption and as it stands in the archive.
    #[must_use]
    pub fn new(first: ([u8; 12], [u8; 12]), others: &[([u8; 12], [u8; 12])]) -> Self {
        let groups: Vec<Vec<([u8; 12], [u8; 12])>> = others.iter().map(|other| vec![*other]).collect();
        Self::of_alternatives(first, &groups)
    }

    /// The tree of a header and of groups of which the header is not known for certain: each
    /// group is the headers it may have been before encryption, with the header as it stands
    /// in the archive. A candidate has to go on along one of them in every group.
    #[must_use]
    pub fn of_alternatives(first: ([u8; 12], [u8; 12]), groups: &[Vec<([u8; 12], [u8; 12])>]) -> Self {
        let stream = |(plain, written): ([u8; 12], [u8; 12])| -> [u8; 12] { std::array::from_fn(|at| plain.get(at).copied().unwrap_or_default() ^ written.get(at).copied().unwrap_or_default()) };
        let others = groups
            .iter()
            .map(|group| {
                group
                    .iter()
                    .map(|&(plain, written)| {
                        let common = plain.iter().zip(first.0).zip(written.iter().zip(first.1)).take_while(|((a, b), (c, d))| *a == b && *c == d).count();
                        (stream((plain, written)), common)
                    })
                    .collect()
            })
            .collect();
        Self { first: stream(first), others }
    }

    /// Whether a candidate can be the third key in front of byte `index` of the first
    /// header: `candidate` has bits 2 to 31 of it.
    ///
    /// The key is walked back along the first header to the keys after the password, by the
    /// stream bytes of that header, and from every key on that way each other header is
    /// walked forward from where it leaves the first.
    #[must_use]
    pub fn allows(&self, candidate: u32, index: usize) -> bool {
        let mut way = [0_u32; 12];
        let index = index.min(11);
        if let Some(slot) = way.get_mut(index) {
            *slot = candidate & !3;
        }
        self.back(&TABLES, index, index, &mut way)
    }

    /// Walk back from the key in front of byte `at`: every key in front of the byte before
    /// it that has its stream byte. `way` holds the keys from `at` to `index`.
    fn back(&self, tables: &Tables, at: usize, index: usize, way: &mut [u32; 12]) -> bool {
        let Some(&third) = way.get(at) else { return false };
        let Some(before) = at.checked_sub(1) else {
            return self.others.iter().all(|group| {
                group.iter().any(|(stream, common)| {
                    let from = (*common).min(index);
                    way.get(from).is_some_and(|&key| forward(tables, stream, key, from + 1))
                })
            });
        };
        // the step that led here took the table entry with the top byte of this key: what is
        // left is the key before it, eight bits down. Its bits 8 and 9 were bits 0 and 1 here,
        // which a candidate does not have
        let entry = tables.crc(tables.by_top.get((third >> 24) as usize).copied().unwrap_or_default());
        let high = ((third ^ entry) << 8) & 0xffff_fc00;
        let Some(&stream) = self.first.get(before) else { return false };
        for &low in tables.lows(stream, high) {
            if let Some(slot) = way.get_mut(before) {
                *slot = high | (u32::from(low) << 2);
            }
            if self.back(tables, before, index, way) {
                return true;
            }
        }
        false
    }
}

/// Whether a third key can go on along a header to its last byte: `third` is the key in
/// front of byte `next - 1`, of which bits 8 to 31 count, and `stream` the stream bytes of
/// the header.
fn forward(tables: &Tables, stream: &[u8; 12], third: u32, next: usize) -> bool {
    let Some(&wanted) = stream.get(next) else { return true };
    tables.steps(wanted, third).iter().any(|&byte| forward(tables, stream, (third >> 8) ^ tables.crc(byte), next + 1))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;

    /// The fixture `gen_ziparchive_glibc.zip`: fourteen entries of the `ZipArchive` library on
    /// glibc under the password `ziparchive-on-glibc`, one a second. The time in front of
    /// each, as the program that called the library printed it, and their headers. The DOS
    /// time of every entry is B839.
    pub(crate) const GLIBC_TIMES: [u64; 14] = [1_795_236_980, 1_795_236_981, 1_795_236_982, 1_795_236_983, 1_795_236_984, 1_795_236_986, 1_795_236_987, 1_795_236_988, 1_795_236_989, 1_795_236_990, 1_795_236_991, 1_795_236_992, 1_795_236_993, 1_795_236_994];
    pub(crate) const ZIPARCHIVE_GLIBC: [[u8; 12]; 14] = [
        [0x51, 0x71, 0xdc, 0x76, 0x9a, 0x6f, 0x4d, 0xcd, 0x3c, 0xdc, 0x95, 0x95],
        [0x2d, 0x34, 0xe7, 0x70, 0xa2, 0x9d, 0x65, 0x93, 0xf5, 0xfd, 0x2d, 0x13],
        [0x1a, 0x69, 0xdf, 0xf9, 0x4f, 0x57, 0x17, 0x9e, 0x27, 0x37, 0xdc, 0x20],
        [0xa9, 0x17, 0xbe, 0xe4, 0xe7, 0x3e, 0x88, 0x36, 0x67, 0x56, 0xae, 0x89],
        [0x59, 0x1f, 0x15, 0x77, 0x23, 0x8d, 0x44, 0x5d, 0x26, 0x71, 0xb8, 0x18],
        [0x63, 0xe9, 0xc6, 0xa1, 0x05, 0x26, 0xe0, 0x9f, 0xac, 0x57, 0xe4, 0x6c],
        [0xfa, 0xd2, 0x95, 0x65, 0x64, 0x03, 0xff, 0xbf, 0xc3, 0xe5, 0x3c, 0x5a],
        [0xd4, 0xc8, 0x91, 0xd5, 0x9a, 0xa1, 0xba, 0x49, 0x4d, 0xf3, 0xba, 0x32],
        [0x96, 0x4a, 0x66, 0x18, 0x25, 0x56, 0xa7, 0xd6, 0x3d, 0x1a, 0x51, 0x01],
        [0x9f, 0x8e, 0x7f, 0xcc, 0x23, 0x4a, 0xb1, 0xa8, 0x9d, 0x9f, 0x7c, 0x0a],
        [0xf0, 0x89, 0xa5, 0xb4, 0x85, 0xa5, 0xf0, 0x95, 0x7b, 0x0a, 0x63, 0xb7],
        [0x3e, 0x7b, 0xab, 0x51, 0x19, 0x56, 0xab, 0x04, 0xfa, 0x7d, 0xaa, 0x56],
        [0x69, 0xd5, 0xa9, 0x8d, 0x6b, 0x4a, 0x8d, 0xf8, 0xc2, 0xbc, 0x3f, 0x93],
        [0x51, 0xde, 0xe5, 0x0d, 0x2f, 0x5a, 0x41, 0xdc, 0xcb, 0xff, 0x18, 0x8c],
    ];

    /// The fixture `gen_ziparchive_win.zip`: the same of the library on Windows Server 2022,
    /// under the password `ziparchive-on-windows`. The DOS time of every entry is B5B0.
    pub(crate) const WIN_TIMES: [u64; 14] = [1_795_232_739, 1_795_232_741, 1_795_232_742, 1_795_232_743, 1_795_232_744, 1_795_232_745, 1_795_232_746, 1_795_232_747, 1_795_232_748, 1_795_232_749, 1_795_232_751, 1_795_232_752, 1_795_232_753, 1_795_232_754];
    pub(crate) const ZIPARCHIVE_WIN: [[u8; 12]; 14] = [
        [0x23, 0x79, 0x91, 0x81, 0x5a, 0x1a, 0xfa, 0xa9, 0xc7, 0x8c, 0xc4, 0xc1],
        [0x23, 0xc9, 0xff, 0xf4, 0x8b, 0xc7, 0x4b, 0xfa, 0xb0, 0x2e, 0xa0, 0x6c],
        [0x23, 0x71, 0x3e, 0xf0, 0x27, 0x11, 0x86, 0xd9, 0x37, 0xd4, 0xa9, 0x7c],
        [0x23, 0x19, 0xbd, 0xe5, 0x78, 0x1f, 0x28, 0x37, 0xeb, 0xfd, 0xe2, 0xf3],
        [0x23, 0xc1, 0xcd, 0x27, 0x6a, 0xb0, 0xda, 0x4f, 0xac, 0x7f, 0x73, 0xbd],
        [0x23, 0x69, 0xc3, 0xca, 0xbf, 0xd8, 0x10, 0x62, 0x4a, 0x21, 0x7e, 0xb3],
        [0x23, 0x11, 0x50, 0x18, 0xb4, 0x53, 0x7f, 0x5b, 0x14, 0x63, 0x94, 0x47],
        [0x23, 0xb9, 0x60, 0xa2, 0x08, 0x98, 0x2e, 0xe8, 0x9c, 0x57, 0x60, 0xc2],
        [0x23, 0x61, 0x59, 0x42, 0x76, 0x9f, 0x19, 0x43, 0x94, 0xb1, 0x3a, 0xf1],
        [0x23, 0x09, 0xdc, 0x0a, 0xca, 0x7f, 0x4f, 0xd8, 0x37, 0xca, 0x2e, 0x09],
        [0x23, 0x59, 0x8d, 0xfb, 0x48, 0xdc, 0x41, 0xe3, 0xbe, 0x05, 0xf6, 0xd6],
        [0x23, 0x01, 0x36, 0x2c, 0x45, 0x2a, 0xdd, 0xd2, 0xcd, 0xaa, 0xfa, 0xad],
        [0x22, 0x14, 0x13, 0x38, 0xe2, 0xbb, 0xb7, 0xdc, 0xd0, 0xd2, 0x86, 0x20],
        [0x22, 0xec, 0xf5, 0x18, 0x7d, 0x09, 0xef, 0x68, 0xbc, 0xe6, 0x45, 0x8a],
    ];

    /// The fixture `gen_ziputils_win.zip`: sixteen entries of zip utils on Windows Server
    /// 2022 under the password `ziputils-on-windows`, written within seven steps of the
    /// clock: the headers, the step each entry was written in, the interrupt of the timer at
    /// each step, and the handle of the desktop window in the session of the program, which
    /// ran as a service does. The high byte of the DOS time of every entry is 1D.
    pub(crate) const ZIPUTILS_WIN: [[u8; 12]; 16] = [
        [0xba, 0xb5, 0x18, 0xd0, 0xd7, 0xfe, 0x83, 0x41, 0x68, 0x41, 0x67, 0x44],
        [0xba, 0xb5, 0x18, 0xd0, 0xd7, 0xfe, 0x83, 0x41, 0x68, 0x41, 0x67, 0x44],
        [0xb4, 0x41, 0x1f, 0x69, 0x74, 0x6c, 0x6e, 0x8e, 0xdf, 0x64, 0xe3, 0xb9],
        [0xb4, 0x41, 0x1f, 0x69, 0x74, 0x6c, 0x6e, 0x8e, 0xdf, 0x64, 0xe3, 0xb9],
        [0xb4, 0x41, 0x1f, 0x69, 0x74, 0x6c, 0x6e, 0x8e, 0xdf, 0x64, 0xe3, 0xb9],
        [0xb4, 0x82, 0x50, 0x5a, 0x75, 0x3f, 0x78, 0x4c, 0xae, 0x81, 0xf2, 0x1c],
        [0xb4, 0x82, 0x50, 0x5a, 0x75, 0x3f, 0x78, 0x4c, 0xae, 0x81, 0xf2, 0x1c],
        [0xb4, 0x82, 0x50, 0x5a, 0x75, 0x3f, 0x78, 0x4c, 0xae, 0x81, 0xf2, 0x1c],
        [0xb4, 0xc2, 0xc1, 0x5a, 0x7f, 0x3d, 0x5e, 0xa4, 0xf9, 0x83, 0xb4, 0x50],
        [0xb4, 0xc2, 0xc1, 0x5a, 0x7f, 0x3d, 0x5e, 0xa4, 0xf9, 0x83, 0xb4, 0x50],
        [0xbb, 0x8a, 0x5c, 0x10, 0x82, 0x80, 0x05, 0x7b, 0x48, 0x74, 0x38, 0x70],
        [0xbb, 0x8a, 0x5c, 0x10, 0x82, 0x80, 0x05, 0x7b, 0x48, 0x74, 0x38, 0x70],
        [0xbb, 0x8a, 0x5c, 0x10, 0x82, 0x80, 0x05, 0x7b, 0x48, 0x74, 0x38, 0x70],
        [0xb8, 0xd5, 0xa5, 0x80, 0xbd, 0x4b, 0x62, 0x42, 0x2c, 0x44, 0x48, 0xd3],
        [0xb8, 0xd5, 0xa5, 0x80, 0xbd, 0x4b, 0x62, 0x42, 0x2c, 0x44, 0x48, 0xd3],
        [0xbf, 0x7e, 0x24, 0x8d, 0x0a, 0x8f, 0x03, 0x18, 0xc3, 0xb4, 0xbf, 0x00],
    ];
    pub(crate) const UTILS_STEPS: [usize; 16] = [0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 6];
    pub(crate) const UTILS_INTERRUPTS: [u64; 7] = [102_084_997, 102_084_998, 102_084_999, 102_085_000, 102_085_001, 102_085_002, 102_085_003];
    pub(crate) const SERVICE_WINDOW: u32 = 0x03c2_0044;

    fn hex(bytes: &[u8]) -> String {
        hex::encode(bytes)
    }

    /// The header of an entry before encryption and as a writer leaves it under a password,
    /// with the third key in front of each of its bytes.
    fn encrypted(plain: [u8; 12], password: &[u8]) -> ([u8; 12], [u32; 12]) {
        let mut keys = Keys::from_password(password);
        let (mut header, mut thirds) = ([0_u8; 12], [0_u32; 12]);
        for ((slot, third), byte) in header.iter_mut().zip(&mut thirds).zip(plain) {
            *third = keys.z;
            *slot = byte ^ keys.stream_byte();
            keys.update(byte);
        }
        (header, thirds)
    }

    /// The headers that a writer makes for groups at these values of its clock, under a
    /// password, before and after encryption.
    fn written(writer: Writer, clocks: &[u64], password: &[u8]) -> Vec<([u8; 12], [u8; 12])> {
        clocks
            .iter()
            .zip(0_u16..)
            .map(|(&clock, number)| {
                let plain = writer.header(clock, 0xb839_u16.wrapping_add(number * 0x0123));
                (plain, encrypted(plain, password).0)
            })
            .collect()
    }

    fn control<'a>(stop: &'a AtomicBool, done: &'a AtomicU64) -> Control<'a> {
        Control { stop, done, threads: std::thread::available_parallelism().map_or(1, std::num::NonZero::get) }
    }

    #[test]
    fn the_bytes_are_those_the_real_writers_wrote() {
        // the ZipArchive library on glibc and on the runtime of Windows, and zip utils: each
        // is a header of an archive of the real program, decrypted with its password
        assert_eq!(hex(&Writer::zip_archive(Runtime::Glibc).plain(1_795_233_815)[..10]), "9226c9be2104e150c80c");
        assert_eq!(hex(&Writer::zip_archive(Runtime::Glibc).plain(GLIBC_TIMES[0])[..10]), "fc9aceaf3ff325eec4d9");
        assert_eq!(hex(&Writer::zip_archive(Runtime::Glibc).plain(GLIBC_TIMES[13])[..10]), "fc35500a8bbb09c10688");
        assert_eq!(hex(&Writer::zip_archive(Runtime::Windows).plain(WIN_TIMES[0])[..10]), "10fec6049e960e7321c1");
        assert_eq!(hex(&Writer::zip_archive(Runtime::Windows).plain(1_795_233_987)[..10]), "50b885f74cb22379d972");
        // a second byte whose bits 6 to 13 were zero: the low byte stands for it
        assert_eq!(hex(&Writer::zip_archive(Runtime::Windows).plain(1_795_233_992)[..10]), "5022f94f72e41694e391");
        // zip utils on Windows Server 2022, in a session whose desktop window was 03C20044:
        // the count of the clock was 1,595,078,078 at its first entry, which is interrupt
        // 102,084,997 of the timer, and 1,595,078,171 at its last
        let utils = Writer::zip_utils(SERVICE_WINDOW);
        assert_eq!(netfx::tick_count(UTILS_INTERRUPTS[0]), 1_595_078_078);
        assert_eq!(hex(&utils.plain(UTILS_INTERRUPTS[0])[..4]), "99e30115");
        assert_eq!(hex(&utils.plain(UTILS_INTERRUPTS[6])[..4]), "9c041040");
        // and under Wine, where the handle is 00010020 and the clock counts every millisecond
        // at a count of 37,282,188
        assert_eq!(hex(&Writer::zip_utils(0x0001_0020).drawn(0x0238_e18c ^ 0x0001_0020)), "fcce68352f05f032036e2f");
    }

    #[test]
    fn every_header_of_the_fixtures_is_what_the_writer_gives_at_its_clock_under_the_password() {
        for (runtime, times, headers, time, password) in [(Runtime::Glibc, &GLIBC_TIMES, &ZIPARCHIVE_GLIBC, 0xb839, &b"ziparchive-on-glibc"[..]), (Runtime::Windows, &WIN_TIMES, &ZIPARCHIVE_WIN, 0xb5b0, b"ziparchive-on-windows")] {
            for (&clock, header) in times.iter().zip(headers) {
                assert_eq!(encrypted(Writer::zip_archive(runtime).header(clock, time), password).0, *header, "{runtime:?} at {clock}");
            }
        }
        let utils = Writer::zip_utils(SERVICE_WINDOW);
        for (&step, header) in UTILS_STEPS.iter().zip(&ZIPUTILS_WIN) {
            assert_eq!(encrypted(utils.header(UTILS_INTERRUPTS[step], 0x1d00), b"ziputils-on-windows").0, *header, "step {step}");
        }
    }

    #[test]
    fn the_clocks_of_the_fixtures_are_among_the_answers_and_their_keys_pass_the_tree() {
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        for (runtime, times, headers, time, password) in [(Runtime::Glibc, &GLIBC_TIMES, &ZIPARCHIVE_GLIBC, 0xb839, &b"ziparchive-on-glibc"[..]), (Runtime::Windows, &WIN_TIMES, &ZIPARCHIVE_WIN, 0xb5b0, b"ziparchive-on-windows")] {
            let writer = Writer::zip_archive(runtime);
            let found = clocks(writer, headers, times[0] - 2000..times[0] + 100, 4, control(&stop, &done));
            assert!(found.contains(&times.to_vec()), "{runtime:?}");
            let all: Vec<([u8; 12], [u8; 12])> = times.iter().zip(headers).map(|(&clock, &header)| (writer.header(clock, time), header)).collect();
            let (first, others) = all.split_first().unwrap();
            let (_, thirds) = encrypted(first.0, password);
            assert!((7..12).all(|index| Tree::new(*first, others).allows(thirds[index], index)), "{runtime:?}");
        }
        // zip utils: one header for each step of the clock
        let utils = Writer::zip_utils(SERVICE_WINDOW);
        let mut of_steps: Vec<[u8; 12]> = ZIPUTILS_WIN.to_vec();
        of_steps.dedup();
        assert_eq!(of_steps.len(), UTILS_INTERRUPTS.len());
        // the values of this generator are a line in its seed, so the first and the last step
        // fit one interrupt off as well: four answers, of which the tree leaves the true one
        let found = clocks(utils, &of_steps, UTILS_INTERRUPTS[0] - 50_000..UTILS_INTERRUPTS[0] + 100, 2, control(&stop, &done));
        assert!(found.contains(&UTILS_INTERRUPTS.to_vec()) && found.len() <= 8, "{found:?}");
        // and not with the handle of the desktop a user works at, which this session did not have
        assert!(clocks(Writer::zip_utils(DESKTOP), &of_steps, UTILS_INTERRUPTS[0] - 50_000..UTILS_INTERRUPTS[0] + 100, 2, control(&stop, &done)).is_empty());
        let all: Vec<([u8; 12], [u8; 12])> = UTILS_INTERRUPTS.iter().zip(&of_steps).map(|(&clock, &header)| (utils.header(clock, 0x1d00), header)).collect();
        let (first, others) = all.split_first().unwrap();
        let (_, thirds) = encrypted(first.0, b"ziputils-on-windows");
        assert!((7..12).all(|index| Tree::new(*first, others).allows(thirds[index], index)));
    }

    #[test]
    fn the_time_of_the_entry_stands_behind_what_the_generator_gave() {
        // both bytes of it behind ten, as the header of the real archive has them
        let archive = Writer::zip_archive(Runtime::Windows);
        assert_eq!(hex(&archive.header(1_795_233_987, 0xb8c3)), "50b885f74cb22379d972c3b8");
        // and the high byte behind eleven
        let utils = Writer::zip_utils(DESKTOP);
        assert_eq!(utils.header(1000, 0x20d0)[..11], utils.plain(1000));
        assert_eq!(utils.header(1000, 0x20d0)[11], 0x20);
        // interrupt 1000 is at a count of 15,625
        assert_eq!((netfx::tick_count(1000), utils.seed(1000)), (15_625, 0x3d09 ^ 0x0001_0010));
        assert!(archive.by_the_second() && !utils.by_the_second());
    }

    #[test]
    fn the_library_of_component_one_draws_from_a_generator_of_the_millisecond() {
        // the first three headers of an archive that C1.Zip 8.0 wrote on .NET 10, decrypted
        // with its password: the generators of the milliseconds 182, 184 and 193, which are
        // those the program that called the library printed, or a millisecond later
        let writer = Writer::component_one();
        assert_eq!(hex(&writer.plain(182)[..10]), "5c1b7a9c7436e6be27c6");
        assert_eq!(hex(&writer.plain(184)[..10]), "0509fc64bb47454cbfa9");
        assert_eq!(hex(&writer.plain(193)[..10]), "ffb9c5ebfb13754de728");
        // the clock counts on and the seed starts again with every second
        assert_eq!((writer.seed(182), writer.seed(1182), writer.seed(999), writer.seed(1000)), (182, 182, 999, 0));
        assert_eq!(writer.plain(1182), writer.plain(182));
        // both bytes of the time behind the ten, and all its values are tried
        assert_eq!(hex(&writer.header(182, 0x6c22)), "5c1b7a9c7436e6be27c6226c");
        assert_eq!((writer.values(), writer.random(), writer.by_the_second()), (Some(1000), 10, false));
        assert_eq!(Writer::zip_utils(DESKTOP).values(), None);
    }

    #[test]
    fn a_tree_of_alternatives_keeps_the_key_when_one_of_each_group_is_its_header() {
        let writer = Writer::component_one();
        let password = b"some password";
        let clocks = [182_u64, 184, 193, 207, 232];
        let headers = written(writer, &clocks, password);
        let (first, others) = headers.split_first().unwrap();
        let (_, thirds) = encrypted(first.0, password);
        // each group with its header among three others that it is not
        let groups: Vec<Vec<([u8; 12], [u8; 12])>> = others.iter().zip(&clocks[1..]).map(|(&(plain, header), &clock)| vec![(writer.header(clock + 400, 0x1111), header), (plain, header), (writer.header(clock + 77, 0x2222), header), (writer.header(clock + 500, 0x3333), header)]).collect();
        let tree = Tree::of_alternatives(*first, &groups);
        assert!((7..12).all(|index| tree.allows(thirds[index], index)));
        // without the header of one group among its alternatives the key is dropped
        let mut without = groups.clone();
        let _ = without[2].remove(1);
        assert!(!Tree::of_alternatives(*first, &without).allows(thirds[11], 11));
        // and a group with no alternative at all allows nothing
        without[2].clear();
        assert!(!Tree::of_alternatives(*first, &without).allows(thirds[11], 11));
    }

    #[test]
    fn two_headers_agree_where_they_first_differ() {
        let (first, other) = ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0], [1, 2, 9, 4, 5, 6, 7, 8, 9, 10, 0]);
        let header = |stream: [u8; 3], plain: &[u8; BYTES]| -> [u8; 12] {
            let mut header = [0x33_u8; 12];
            for ((slot, key), byte) in header.iter_mut().zip(stream).zip(plain) {
                *slot = key ^ byte;
            }
            header
        };
        // one stream as far as the bytes are equal and at the first that differs
        assert!(pair(&first, &header([0x10, 0x20, 0x30], &first), &other, &header([0x10, 0x20, 0x30], &other), 10));
        // another stream at the byte that differs
        assert!(!pair(&first, &header([0x10, 0x20, 0x30], &first), &other, &header([0x10, 0x20, 0x31], &other), 10));
        // headers that differ where the bytes of the generator do not
        assert!(!pair(&first, &header([0x10, 0x20, 0x30], &first), &other, &header([0x10, 0x21, 0x30], &other), 10));
        // one header twice is one group, not two
        assert!(!pair(&first, &header([0x10, 0x20, 0x30], &first), &first, &header([0x10, 0x20, 0x30], &first), 10));
    }

    #[test]
    fn the_clock_of_each_group_is_among_the_answers_for_the_seconds_around_it() {
        for runtime in [Runtime::Glibc, Runtime::Windows] {
            let writer = Writer::zip_archive(runtime);
            // entries of fourteen seconds, with one second in which none was started
            let headers: Vec<[u8; 12]> = written(writer, &GLIBC_TIMES, b"a password of some length").into_iter().map(|(_, header)| header).collect();
            let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
            let found = clocks(writer, &headers, GLIBC_TIMES[0] - 800..GLIBC_TIMES[0] + 200, 4, control(&stop, &done));
            assert!(found.contains(&GLIBC_TIMES.to_vec()), "{runtime:?}");
            assert_eq!(done.load(Ordering::Relaxed), 1000);
            // a gap that is too short for the second without an entry finds nothing there
            let found = clocks(writer, &headers, GLIBC_TIMES[0]..GLIBC_TIMES[0] + 1, 1, control(&stop, &done));
            assert!(found.is_empty(), "{runtime:?}");
            // one group is no sequence
            assert!(clocks(writer, &headers[..1], GLIBC_TIMES[0] - 800..GLIBC_TIMES[0] + 200, 4, control(&stop, &done)).is_empty());
            // and the headers of one writer are not those of the other
            let other = Writer::zip_archive(if runtime == Runtime::Glibc { Runtime::Windows } else { Runtime::Glibc });
            assert!(!clocks(other, &headers, GLIBC_TIMES[0] - 800..GLIBC_TIMES[0] + 200, 4, control(&stop, &done)).contains(&GLIBC_TIMES.to_vec()), "{runtime:?}");
        }
    }

    #[test]
    fn the_interrupt_of_each_group_is_among_the_answers_for_zip_utils() {
        let writer = Writer::zip_utils(DESKTOP);
        let interrupts: Vec<u64> = [0_u64, 1, 2, 4, 5, 7, 8, 9, 12, 13, 14, 16].iter().map(|step| 21_000_000 + step).collect();
        let headers: Vec<[u8; 12]> = written(writer, &interrupts, b"another password").into_iter().map(|(_, header)| header).collect();
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let found = clocks(writer, &headers, 20_990_000..21_010_000, 4, control(&stop, &done));
        assert_eq!(found, [interrupts]);
        // with another handle of the desktop window the seeds are others
        assert!(clocks(Writer::zip_utils(SERVICE_WINDOW), &headers, 20_990_000..21_010_000, 4, control(&stop, &done)).is_empty());
    }

    #[test]
    fn a_tree_keeps_the_third_key_and_drops_what_the_other_headers_contradict() {
        let writer = Writer::zip_archive(Runtime::Glibc);
        let password = b"a password of some length";
        let headers = written(writer, &GLIBC_TIMES, password);
        let (first, others) = headers.split_first().unwrap();
        let (_, thirds) = encrypted(first.0, password);
        let tree = Tree::new(*first, others);
        // the key in front of every byte the search may start from
        for (index, third) in thirds.iter().enumerate().skip(7) {
            assert!(tree.allows(*third, index), "{index}");
        }
        // keys that differ from the true one in bits 16 to 27: with nothing held against the
        // first header a part of them goes back to some key after the password, and with
        // thirteen headers held against it none does
        let alone = Tree::new(*first, &[]);
        let changed = |tree: &Tree| (1..1_u32 << 12).filter(|change| tree.allows(thirds[11] ^ (change << 16), 11)).count();
        assert!(changed(&alone) > 100, "{}", changed(&alone));
        assert_eq!(changed(&tree), 0);
        // headers that were written a second later than they are held to be: one of them
        // contradicts the key four times in five, and thirteen do
        let wrong: Vec<([u8; 12], [u8; 12])> = others.iter().zip(&GLIBC_TIMES[1..]).map(|(&(_, header), &clock)| (writer.header(clock + 1, 0xb839), header)).collect();
        assert!(!Tree::new(*first, &wrong).allows(thirds[11], 11));
    }

    #[test]
    fn entries_of_one_second_are_branches_of_one_header() {
        // the ZipArchive library gives every entry of a second the same ten bytes and its own
        // time behind them: the tree follows the first header for ten bytes and then each
        let writer = Writer::zip_archive(Runtime::Windows);
        let password = b"pw";
        let headers: Vec<([u8; 12], [u8; 12])> = (0..20_u16)
            .map(|number| {
                let plain = writer.header(1_795_233_987, 0x4000 + number * 0x0821);
                (plain, encrypted(plain, password).0)
            })
            .collect();
        let (first, others) = headers.split_first().unwrap();
        let (_, thirds) = encrypted(first.0, password);
        let tree = Tree::new(*first, others);
        assert!(tree.others.iter().flatten().all(|(_, common)| *common == 10));
        assert!(tree.allows(thirds[11], 11) && tree.allows(thirds[8], 8));
        // every other key in front of the last byte that has its stream byte, with bits 16
        // to 23 as they come. A step of the third key takes any entry of the CRC table, and
        // the table is linear, so one step tells no more of the key than six bits: the
        // entries of a second leave one key in 64 and not fewer
        let stream = Keys::new(0, 0, thirds[11]).stream_byte();
        let same_stream: Vec<u32> = (0..1_u32 << 14).map(|value| value << 2).filter(|low| Keys::new(0, 0, *low).stream_byte() == stream && *low != thirds[11] & 0xfffc).collect();
        assert_eq!(same_stream.len(), 63);
        let alone = Tree::new(*first, &[]);
        let kept = |tree: &Tree| same_stream.iter().flat_map(|low| (0..256_u32).map(move |middle| (thirds[11] & 0xff00_0000) | (middle << 16) | low)).filter(|key| tree.allows(*key, 11)).count();
        let (of_tree, of_first) = (kept(&tree), kept(&alone));
        assert!(of_first > 1000 && of_tree * 16 < of_first, "{of_tree} of {of_first}");
    }
}
