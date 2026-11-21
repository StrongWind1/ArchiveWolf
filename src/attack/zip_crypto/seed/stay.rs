//! Stay's attack on the encryption headers of the Info-ZIP family: from the ten bytes the
//! generator gave for each header and the twelve bytes that stand in the archive, to the
//! keys every entry starts from (Stay 2001, section 5).
//!
//! The writer encrypts the ten bytes under the keys after the password, and the result again
//! under the same keys ([`super::infozip`]). What is known of each header byte is therefore
//! the exclusive-or of two stream bytes, one of each pass. The attack guesses the keys piece
//! by piece and tests each piece on every entry at once: the keys at the start are the same
//! for all entries, so each entry is a filter of its own.
//!
//! **What is guessed.** Call the keys at the start X, Y and Z. All three are updated by
//! steps that part into what the keys give and what the bytes give:
//!
//! - X after some bytes is X after as many zero bytes, exclusive-or a word that the bytes
//!   alone decide, since the CRC-32 is linear. Y takes the low byte of X, so a stage needs
//!   the low byte of X after one more zero byte: eight bits of X.
//! - Y after some bytes is Y after as many steps with a zero byte, plus a word that the low
//!   bytes of X alone decide. Z takes the top byte of Y, which is the sum of the two top
//!   bytes and a carry from below that nobody knows: a stage needs the top byte of the first
//!   and tries both carries, in both passes.
//! - Z after some bytes is Z after as many zero bytes, exclusive-or a word that the top bytes
//!   of Y alone decide. The stream byte comes from bits 2 to 15 of Z.
//!
//! A [`Guess`] holds those pieces. Each of the four stages adds the pieces of one more step
//! and tests the next header byte of every entry: with the carries open, an entry is worth
//! six bits a stage. Where a piece can be looked up from the first entry instead of guessed,
//! it is: that is what makes the stages fast. The end finds the low 24 bits of Y and runs
//! the keys over every header as the writer did.

use std::ops::Range;
use std::sync::OnceLock;

use archivewolf_zip_crypto::Keys;
use archivewolf_zip_crypto::MULT;
use archivewolf_zip_crypto::MULT_INV;
use archivewolf_zip_crypto::StreamPairs;
use archivewolf_zip_crypto::crc32;
use archivewolf_zip_crypto::crc32_inv;
use archivewolf_zip_crypto::stream_byte;

use super::Control;
use super::glibc::HEADER_BYTES;
use super::infozip;
use super::infozip::HEADER_LEN;
use super::spread;

/// The guesses of stage 1: the first byte of the key stream, eight bits of X and the top
/// byte of Y, as the bits 16 to 23, 8 to 15 and 0 to 7 of a number below this.
pub const STAGE1_SPACE: u32 = 1 << 24;
/// The guesses stage 2 adds to each guess it is given: eight more bits of X, the next top
/// byte of Y and bits 0 to 1 of Z, as the bits 10 to 17, 2 to 9 and 0 to 1.
pub const STAGE2_SPACE: u32 = 1 << 18;
/// The guesses stage 3 adds: the top byte of Z, eight more bits of X and a top byte of Y, as
/// the bits 16 to 23, 8 to 15 and 0 to 7.
pub const STAGE3_SPACE: u32 = 1 << 24;
/// The guesses stage 4 adds: the last eight bits of X and a top byte of Y, as the bits 8 to
/// 15 and 0 to 7.
pub const STAGE4_SPACE: u32 = 1 << 16;
/// The guesses of the end: the low 24 bits of Y after one step with a zero byte.
pub const FINISH_SPACE: u32 = 1 << 24;

/// The fewest entries [`recover`] runs on. With four, some fifteen thousand guesses pass the
/// first stage and sixty thousand the second. With three it is 2^20 and 2^28, which the
/// stages as they are built here do not hold (design, section 8.3).
pub const MIN_ENTRIES: usize = 4;

/// What [`recover`] counts to: this for each of the four stages and for the end.
pub const RECOVER_TOTAL: u64 = 5 * STAGE_UNITS;
/// What one stage is worth in the count of [`recover`].
const STAGE_UNITS: u64 = 1 << 24;

/// What the attack knows of one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Entry {
    /// The ten bytes the generator gave for the header of the entry, before the writer
    /// encrypted them ([`super::glibc::header_bytes`]).
    pub random: [u8; HEADER_BYTES],
    /// The twelve bytes of the encryption header as they stand in the archive.
    pub header: [u8; HEADER_LEN],
}

impl Entry {
    /// The byte the generator gave at the position `at`.
    fn random(&self, at: usize) -> u8 {
        self.random.get(at).copied().unwrap_or_default()
    }

    /// The exclusive-or of the stream bytes of the two passes at the position `at`: what the
    /// header byte in the archive differs from the byte of the generator by.
    fn streams(&self, at: usize) -> u8 {
        self.random(at) ^ self.header.get(at).copied().unwrap_or_default()
    }
}

/// What is guessed of the keys every entry starts from. A stage fills what it adds, and what
/// no stage has added yet is zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Guess {
    /// The first byte of the key stream: the stream byte of Z itself.
    pub stream: u8,
    /// The low byte of X after one, two, three and four zero bytes. Stage `n` adds the byte
    /// `n - 1`, and the four give X.
    pub x: [u8; 4],
    /// The top byte of Y after one, two, three and four steps with a zero byte. Stage `n`
    /// adds the byte `n - 1`.
    pub y: [u8; 4],
    /// Z after one zero byte: bits 2 to 15 from stage 1, bits 0 to 23 from stage 2, and all
    /// of it from stage 3.
    pub z: u32,
}

/// How [`recover`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    /// How many guesses each of the four stages left.
    pub left: [usize; 4],
    /// The keys every entry starts from: the keys after the password. One, when the headers
    /// are those of one run of the writer under one password.
    pub keys: Vec<Keys>,
}

/// The low byte of a word.
const fn low(word: u32) -> u8 {
    word.to_le_bytes()[0]
}

/// The top byte of a word.
const fn top(word: u32) -> u8 {
    word.to_le_bytes()[3]
}

/// Bits 2 to 15 of a third key: all of it that its stream byte comes from.
const STREAM_BITS: u32 = 0xfffc;

/// The two passes over the header of one entry, as far as the bytes decide them: after some
/// bytes, what each pass has added to the three keys of the guess.
#[derive(Debug, Clone, Copy)]
struct Trail {
    /// What the bytes add to X, in the first pass and in the second.
    x: [u32; 2],
    /// What the low bytes of X add to Y.
    y: [u32; 2],
    /// What the top bytes of Y add to Z.
    z: [u32; 2],
    /// The stream byte the first pass made at this position: the second pass encrypts the
    /// byte of the generator exclusive-or this one.
    stream: u8,
}

impl Trail {
    /// The passes before the first byte. `stream` is the first byte of the key stream.
    const fn start(stream: u8) -> Self {
        Self { x: [0; 2], y: [0; 2], z: [0; 2], stream }
    }

    /// One byte on in both passes, as far as the low byte `x` of the guess decides it: the
    /// byte `random` of the generator goes into the first pass, and what the first pass made
    /// of it into the second.
    fn step(&self, random: u8, x: u8) -> Step {
        let [x_first, x_second] = self.x;
        let [y_first, y_second] = self.y;
        let (x_first, x_second) = (crc32(x_first, random), crc32(x_second, random ^ self.stream));
        let y_first = y_first.wrapping_add(u32::from(x ^ low(x_first))).wrapping_mul(MULT);
        let y_second = y_second.wrapping_add(u32::from(x ^ low(x_second))).wrapping_mul(MULT);
        Step { x: [x_first, x_second], y: [y_first, y_second], z: self.z }
    }
}

/// A step of both passes before the top byte of Y went into Z.
#[derive(Debug, Clone, Copy)]
struct Step {
    /// What the bytes add to X after the step.
    x: [u32; 2],
    /// What the low bytes of X add to Y after the step.
    y: [u32; 2],
    /// What the top bytes of Y added to Z before the step.
    z: [u32; 2],
}

impl Step {
    /// What the top bytes of Y add to Z after the step, when `y` is the top byte of the
    /// guess: for each pass, without the carry from the low bits of Y and with it.
    fn ways(&self, y: u8) -> Ways {
        let [y_first, y_second] = self.y.map(|added| y.wrapping_add(top(added)));
        let [z_first, z_second] = self.z;
        Ways { first: [crc32(z_first, y_first), crc32(z_first, y_first.wrapping_add(1))], second: [crc32(z_second, y_second), crc32(z_second, y_second.wrapping_add(1))] }
    }

    /// The passes after the step, for every choice of the carries that gives the header byte:
    /// `key` is what the guess says of Z at that position, and `wanted` the exclusive-or of
    /// the two stream bytes there.
    fn trails(&self, y: u8, key: u32, wanted: u8) -> impl Iterator<Item = Trail> + use<> {
        let (x, y_added) = (self.x, self.y);
        self.ways(y).pairs().into_iter().filter(move |&[first, second]| stream_byte(key ^ first) ^ stream_byte(key ^ second) == wanted).map(move |[first, second]| Trail { x, y: y_added, z: [first, second], stream: stream_byte(key ^ first) })
    }
}

/// What a step can add to Z: for each pass, without the carry and with it.
#[derive(Debug, Clone, Copy)]
struct Ways {
    /// The first pass.
    first: [u32; 2],
    /// The second pass.
    second: [u32; 2],
}

impl Ways {
    /// The four choices of the two carries: what the first pass adds, and the second.
    const fn pairs(&self) -> [[u32; 2]; 4] {
        let ([a, b], [c, d]) = (self.first, self.second);
        [[a, c], [a, d], [b, c], [b, d]]
    }

    /// Whether some choice of the carries gives the header byte: the stream bytes of the two
    /// passes, from what the guess says of Z at that position, differ by `wanted`.
    fn fits(&self, key: u32, wanted: u8) -> bool {
        let [a, b] = self.first.map(|added| stream_byte(key ^ added));
        let [c, d] = self.second.map(|added| stream_byte(key ^ added) ^ wanted);
        a == c || a == d || b == c || b == d
    }
}

/// The passes over the header of `entry` after `depth` bytes under `guess`, for every choice
/// of the carries that gives the header bytes so far. None when the guess does not fit the
/// entry.
fn trails(entry: &Entry, guess: &Guess, depth: usize) -> Vec<Trail> {
    let mut trails = vec![Trail::start(guess.stream)];
    let mut key = guess.z;
    for (at, (&x, &y)) in guess.x.iter().zip(&guess.y).enumerate().take(depth) {
        trails = trails.iter().flat_map(|trail| trail.step(entry.random(at), x).trails(y, key, entry.streams(at + 1))).collect();
        key = crc32(key, 0);
    }
    trails
}

/// The parts of a range of numbers that share their bits from `bits` up: the shared part,
/// and the range of what is below it.
fn split(range: Range<u32>, bits: u32) -> impl Iterator<Item = (u32, Range<u32>)> {
    let highs = if range.is_empty() { 0..0 } else { range.start >> bits..((range.end - 1) >> bits) + 1 };
    highs.map(move |high| {
        let base = high << bits;
        (high, range.start.max(base) - base..(range.end - base).min(1 << bits))
    })
}

/// A range of guesses, cut to the guesses there are.
fn cut(space: Range<u32>, size: u32) -> Range<u32> {
    space.start.min(size)..space.end.min(size)
}

/// Run a stage: `work` for every one of `guesses` guesses and every piece of `space`, on the
/// threads of `control`, and what was found in order and once.
///
/// The count of `control` is advanced by `units` over the whole stage, spread evenly over
/// its work, or by one for every guess and every number of `space` when no units are given.
fn over<T, F>(guesses: usize, space: Range<u32>, piece: u32, units: Option<u64>, control: Control<'_>, work: F) -> Vec<T>
where
    T: Send + Ord,
    F: Fn(usize, Range<u32>, &mut Vec<T>) + Sync,
{
    let guesses = u64::try_from(guesses).unwrap_or(u64::MAX);
    let width = u64::from(space.end.saturating_sub(space.start));
    let items = guesses.saturating_mul(width);
    let units = units.unwrap_or(items);
    if items == 0 {
        // a stage with nothing to do is done at once, and its units count all the same
        if !control.stopped() {
            control.advance(units);
        }
        return Vec::new();
    }
    let per_guess = width.div_ceil(u64::from(piece));
    let share = |item: u64| u64::try_from(u128::from(item) * u128::from(units) / u128::from(items)).unwrap_or(u64::MAX);
    let at = |offset: u64| space.start.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX));
    let mut found = spread(guesses.saturating_mul(per_guess), control, |number, found| {
        let (guess, part) = (number / per_guess, number % per_guess);
        let from = part * u64::from(piece);
        let to = (from + u64::from(piece)).min(width);
        work(usize::try_from(guess).unwrap_or(usize::MAX), at(from)..at(to), found);
        control.advance(share(guess * width + to) - share(guess * width + from));
    });
    found.sort_unstable();
    found.dedup();
    found
}

/// Stage 1: every guess of the first byte of the key stream, eight bits of X and the top byte
/// of Y in `space` that the second header byte of every entry fits, each with the bits 2 to
/// 15 of Z that it fits with. In order.
///
/// `space` is a range of [`STAGE1_SPACE`]. The bits of Z are not guessed: they are looked up
/// from the first entry, 256 values for a guess, and tested on the others. With nine entries
/// 32 guesses are left of the whole space, with four some fifteen thousand.
///
/// `control.done` is advanced by one for every number of `space`: the total is its length.
#[must_use]
pub fn stage1(entries: &[Entry], space: Range<u32>, control: Control<'_>) -> Vec<Guess> {
    stage1_counted(entries, space, None, control)
}

/// [`stage1`], counting `units` over the stage when they are given.
fn stage1_counted(entries: &[Entry], space: Range<u32>, units: Option<u64>, control: Control<'_>) -> Vec<Guess> {
    let Some((first, rest)) = entries.split_first() else { return Vec::new() };
    // made by the first piece of work that is started: a stage that is stopped makes none
    let pairs = OnceLock::new();
    over(1, cut(space, STAGE1_SPACE), 1 << 8, units, control, |_, range, found| {
        let pairs = pairs.get_or_init(|| StreamPairs::new(first.streams(1)));
        for guess in range {
            let [y, x, stream, _] = guess.to_le_bytes();
            let start = Trail::start(stream);
            let ways = start.step(first.random(0), x).ways(y);
            // the second entry turns down 63 values of 64: what it needs is worked out once
            let second = rest.first().map(|entry| (start.step(entry.random(0), x).ways(y), entry.streams(1)));
            for [added, other] in ways.pairs() {
                for &value in pairs.of(added ^ other) {
                    let z = u32::from(value) ^ (added & STREAM_BITS);
                    if second.is_none_or(|(ways, wanted)| ways.fits(z, wanted)) && rest.iter().skip(1).all(|entry| start.step(entry.random(0), x).ways(y).fits(z, entry.streams(1))) {
                        found.push(Guess { stream, x: [x, 0, 0, 0], y: [y, 0, 0, 0], z });
                    }
                }
            }
        }
    })
}

/// Stage 2: for every guess stage 1 left, every guess of eight more bits of X, the next top
/// byte of Y and bits 0 to 1 of Z in `space` that the third header byte of every entry fits,
/// each with the bits 16 to 23 of Z that it fits with. In order.
///
/// `space` is a range of [`STAGE2_SPACE`]. The bits 16 to 23 are looked up from the first
/// entry, about one value for each choice of the carries.
///
/// `control.done` is advanced by one for every guess and every number of `space`: the total
/// is the count of guesses times the length of `space`.
#[must_use]
pub fn stage2(entries: &[Entry], guesses: &[Guess], space: Range<u32>, control: Control<'_>) -> Vec<Guess> {
    stage2_counted(entries, guesses, space, None, control)
}

/// [`stage2`], counting `units` over the stage when they are given.
fn stage2_counted(entries: &[Entry], guesses: &[Guess], space: Range<u32>, units: Option<u64>, control: Control<'_>) -> Vec<Guess> {
    let Some((first, rest)) = entries.split_first() else { return Vec::new() };
    let pairs = OnceLock::new();
    over(guesses.len(), cut(space, STAGE2_SPACE), 1 << 12, units, control, |number, range, found| {
        let Some(base) = guesses.get(number) else { return };
        let pairs = pairs.get_or_init(|| StreamPairs::new(first.streams(2)));
        let [x_base, ..] = base.x;
        let [y_base, ..] = base.y;
        let first_trails = trails(first, base, 1);
        let rest_trails: Vec<(Entry, Vec<Trail>)> = rest.iter().map(|entry| (*entry, trails(entry, base, 1))).collect();
        // the second entry turns down 63 values of 64: what it needs is worked out once
        let (second, others) = rest_trails.split_first().map_or((None, &[][..]), |(second, others)| (Some(second), others));
        let (mut steps, mut ways, mut second_steps, mut second_ways) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (x, range) in split(range, 10) {
            let x = low(x);
            steps.clear();
            steps.extend(first_trails.iter().map(|trail| trail.step(first.random(1), x)));
            second_steps.clear();
            second_steps.extend(second.iter().flat_map(|(entry, trails)| trails.iter().map(|trail| trail.step(entry.random(1), x))));
            for (y, low_bits) in split(range, 2) {
                let y = low(y);
                ways.clear();
                ways.extend(steps.iter().map(|step| step.ways(y)));
                second_ways.clear();
                second_ways.extend(second_steps.iter().map(|step: &Step| step.ways(y)));
                for bits in low_bits {
                    let z = base.z | bits;
                    // what the guess says of Z one byte on, but for what bits 16 to 23 add to it
                    let known = crc32(z, 0);
                    for [added, other] in ways.iter().flat_map(Ways::pairs) {
                        let from = known ^ added;
                        for &value in pairs.of_low_bits(added ^ other, from) {
                            let z = z | ((u32::from(value) ^ (from & STREAM_BITS)) >> 8 << 16);
                            let key = crc32(z, 0);
                            let second_fits = second.is_none_or(|(entry, _)| second_ways.iter().any(|ways: &Ways| ways.fits(key, entry.streams(2))));
                            if second_fits && others.iter().all(|(entry, trails)| trails.iter().any(|trail| trail.step(entry.random(1), x).ways(y).fits(key, entry.streams(2)))) {
                                found.push(Guess { x: [x_base, x, 0, 0], y: [y_base, y, 0, 0], z, ..*base });
                            }
                        }
                    }
                }
            }
        }
    })
}

/// Stage 3: for every guess stage 2 left, every guess of the top byte of Z, eight more bits
/// of X and a top byte of Y in `space` that the fourth header byte of every entry fits. In
/// order.
///
/// `space` is a range of [`STAGE3_SPACE`]. Z is whole with its top byte, and has to give the
/// first byte of the key stream, which turns down 255 top bytes of 256 at once.
///
/// `control.done` is advanced by one for every guess and every number of `space`: the total
/// is the count of guesses times the length of `space`.
#[must_use]
pub fn stage3(entries: &[Entry], guesses: &[Guess], space: Range<u32>, control: Control<'_>) -> Vec<Guess> {
    stage3_counted(entries, guesses, space, None, control)
}

/// [`stage3`], counting `units` over the stage when they are given.
fn stage3_counted(entries: &[Entry], guesses: &[Guess], space: Range<u32>, units: Option<u64>, control: Control<'_>) -> Vec<Guess> {
    over(guesses.len(), cut(space, STAGE3_SPACE), 1 << 16, units, control, |number, range, found| {
        let Some(base) = guesses.get(number) else { return };
        let [x_first, x_second, ..] = base.x;
        let [y_first, y_second, ..] = base.y;
        // most top bytes are turned down before the passes are needed
        let mut passes = None;
        for (high, range) in split(range, 16) {
            let z = base.z | (high << 24);
            if stream_byte(crc32_inv(z, 0)) != base.stream {
                continue;
            }
            let passes = passes.get_or_insert_with(|| entries.iter().map(|entry| (*entry, trails(entry, base, 2))).collect::<Vec<_>>());
            sweep(passes, 2, crc32(crc32(z, 0), 0), range, |x, y| found.push(Guess { x: [x_first, x_second, x, 0], y: [y_first, y_second, y, 0], z, ..*base }));
        }
    })
}

/// Stage 4: for every guess stage 3 left, every guess of the last eight bits of X and a top
/// byte of Y in `space` that the fifth header byte of every entry fits. In order.
///
/// `space` is a range of [`STAGE4_SPACE`].
///
/// `control.done` is advanced by one for every guess and every number of `space`: the total
/// is the count of guesses times the length of `space`.
#[must_use]
pub fn stage4(entries: &[Entry], guesses: &[Guess], space: Range<u32>, control: Control<'_>) -> Vec<Guess> {
    stage4_counted(entries, guesses, space, None, control)
}

/// [`stage4`], counting `units` over the stage when they are given.
fn stage4_counted(entries: &[Entry], guesses: &[Guess], space: Range<u32>, units: Option<u64>, control: Control<'_>) -> Vec<Guess> {
    over(guesses.len(), cut(space, STAGE4_SPACE), 1 << 12, units, control, |number, range, found| {
        let Some(base) = guesses.get(number) else { return };
        let [x_first, x_second, x_third, _] = base.x;
        let [y_first, y_second, y_third, _] = base.y;
        let passes: Vec<(Entry, Vec<Trail>)> = entries.iter().map(|entry| (*entry, trails(entry, base, 3))).collect();
        let key = crc32(crc32(crc32(base.z, 0), 0), 0);
        sweep(&passes, 3, key, range, |x, y| found.push(Guess { x: [x_first, x_second, x_third, x], y: [y_first, y_second, y_third, y], ..*base }));
    })
}

/// Call `found` for every low byte of X and top byte of Y in `space`, the first as its bits 8
/// to 15 and the second as its bits 0 to 7, that take the passes of every entry one byte on:
/// from the position `at`, with `key` what the guess says of Z after it.
fn sweep(passes: &[(Entry, Vec<Trail>)], at: usize, key: u32, space: Range<u32>, mut found: impl FnMut(u8, u8)) {
    let Some(((first, first_trails), rest)) = passes.split_first() else { return };
    let (random, wanted) = (first.random(at), first.streams(at + 1));
    let mut steps = Vec::with_capacity(first_trails.len());
    for (x, range) in split(space, 8) {
        let x = low(x);
        // the first entry turns down 63 guesses of 64: what it needs is worked out once
        steps.clear();
        steps.extend(first_trails.iter().map(|trail| trail.step(random, x)));
        for y in range {
            let y = low(y);
            if steps.iter().any(|step: &Step| step.ways(y).fits(key, wanted)) && rest.iter().all(|(entry, trails)| trails.iter().any(|trail| trail.step(entry.random(at), x).ways(y).fits(key, entry.streams(at + 1)))) {
                found(x, y);
            }
        }
    }
}

/// The end: for every guess stage 4 left, the keys that it gives with the low 24 bits of Y
/// in `space` and that turn the ten bytes of every entry into its header, encrypted twice as
/// the writer did. In order.
///
/// `space` is a range of [`FINISH_SPACE`]: the low 24 bits of Y after one step with a zero
/// byte, whose top byte and the three after it the guess holds. X and Z follow from the
/// guess as it is.
///
/// `control.done` is advanced by one for every guess and every number of `space`: the total
/// is the count of guesses times the length of `space`.
#[must_use]
pub fn finish(entries: &[Entry], guesses: &[Guess], space: Range<u32>, control: Control<'_>) -> Vec<Keys> {
    finish_counted(entries, guesses, space, None, control)
}

/// [`finish`], counting `units` over the end when they are given.
fn finish_counted(entries: &[Entry], guesses: &[Guess], space: Range<u32>, units: Option<u64>, control: Control<'_>) -> Vec<Keys> {
    over(guesses.len(), cut(space, FINISH_SPACE), 1 << 16, units, control, |number, range, found| {
        let Some(base) = guesses.get(number) else { return };
        // X after one zero byte, from its low byte after one to four: each byte of it is the
        // low byte some zero bytes on, exclusive-or what the bytes below it have become
        let [x_first, x_later @ ..] = base.x;
        let mut x_moved = u32::from(x_first);
        for (zeros, byte) in (1_u32..).zip(x_later) {
            let below = (0..zeros).fold(x_moved, |word, _| crc32(word, 0));
            x_moved |= u32::from(low(below) ^ byte) << (8 * zeros);
        }
        let (x, z) = (crc32_inv(x_moved, 0), crc32_inv(base.z, 0));
        let [y_first, y_second, y_third, y_fourth] = base.y;
        for bits in range {
            let first = (u32::from(y_first) << 24) | bits;
            let second = first.wrapping_mul(MULT).wrapping_add(1);
            let third = second.wrapping_mul(MULT).wrapping_add(1);
            let fourth = third.wrapping_mul(MULT).wrapping_add(1);
            if top(second) != y_second || top(third) != y_third || top(fourth) != y_fourth {
                continue;
            }
            let keys = Keys::new(x, first.wrapping_sub(1).wrapping_mul(MULT_INV), z);
            if entries.iter().all(|entry| infozip::fits(keys, &entry.random, &entry.header)) {
                found.push(keys);
            }
        }
    })
}

/// The whole attack: the four stages over all their guesses and the end, on the headers of
/// at least [`MIN_ENTRIES`] entries. None when there are fewer.
///
/// The entries are those of one run of the writer under one password, each with the bytes
/// its seed gives ([`super::glibc`]). On nine entries the attack takes seconds and leaves 32,
/// 4, 1 and 1 guesses after its stages; on four it leaves some sixty thousand after the
/// second (design, section 8.3).
///
/// `control.done` is advanced to [`RECOVER_TOTAL`]: a fifth of it for each stage and for the
/// end, spread evenly over the work of each. The stages do not take the same time, so the
/// count says how far the attack is and not how long it has left.
#[must_use]
pub fn recover(entries: &[Entry], control: Control<'_>) -> Option<Recovery> {
    if entries.len() < MIN_ENTRIES {
        return None;
    }
    let units = Some(STAGE_UNITS);
    let first = stage1_counted(entries, 0..STAGE1_SPACE, units, control);
    let second = stage2_counted(entries, &first, 0..STAGE2_SPACE, units, control);
    let third = stage3_counted(entries, &second, 0..STAGE3_SPACE, units, control);
    let fourth = stage4_counted(entries, &third, 0..STAGE4_SPACE, units, control);
    let keys = finish_counted(entries, &fourth, 0..FINISH_SPACE, units, control);
    Some(Recovery { left: [first.len(), second.len(), third.len(), fourth.len()], keys })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::attack::zip_crypto::seed::glibc;
    use crate::attack::zip_crypto::seed::glibc::tests::NINE_SEED;
    use crate::attack::zip_crypto::seed::infozip::tests::SIX_HEADERS;
    use crate::attack::zip_crypto::seed::infozip::tests::SIX_KEYS;
    use crate::attack::zip_crypto::seed::infozip::tests::SIX_SEED;

    /// The encryption headers of the nine entries of the archive that the design measured
    /// (section 8.2), in archive order. Its seed is [`NINE_SEED`].
    const NINE_HEADERS: [[u8; HEADER_LEN]; 9] = [
        [0x19, 0xd7, 0x6e, 0xe6, 0xf5, 0xf9, 0xcd, 0xaf, 0x7c, 0xc3, 0x89, 0xdf],
        [0x7b, 0xfa, 0x2d, 0x1d, 0x46, 0xed, 0xfd, 0x64, 0xaa, 0x26, 0x07, 0x36],
        [0x7f, 0xdf, 0xcf, 0x96, 0xdf, 0x67, 0xaf, 0x43, 0x4d, 0x3a, 0x13, 0x3a],
        [0x75, 0xda, 0x25, 0x35, 0xfd, 0x4b, 0xbb, 0x69, 0x42, 0x30, 0x2f, 0xc0],
        [0xba, 0xac, 0x74, 0x8e, 0x4a, 0x11, 0x02, 0x30, 0xb2, 0x38, 0xab, 0xc3],
        [0xd6, 0xf0, 0x4e, 0x00, 0x25, 0x00, 0xc7, 0x52, 0xe8, 0xe9, 0x1c, 0xa0],
        [0xea, 0x71, 0xe9, 0x75, 0xb7, 0xbf, 0x08, 0x35, 0xf9, 0xb9, 0xf1, 0x24],
        [0xf9, 0xe8, 0x69, 0xa6, 0x8d, 0xfb, 0xdf, 0xf7, 0x3b, 0xb6, 0xcb, 0xb7],
        [0x09, 0xaa, 0x5b, 0xc8, 0x46, 0x0d, 0x8a, 0xaa, 0xa4, 0x2e, 0x30, 0xa2],
    ];

    /// The keys the measured attack found for it, which are those of its password.
    const NINE_KEYS: Keys = Keys::new(0x5dd2_af4d, 0x589d_03b4, 0x3cf5_ffa4);

    /// A guess from the first byte of the key stream, the four bytes of X and of Y with the
    /// first on top, and Z.
    const fn guess(stream: u8, x: u32, y: u32, z: u32) -> Guess {
        Guess { stream, x: x.to_be_bytes(), y: y.to_be_bytes(), z }
    }

    /// What the measured attack left after stage 1 on the nine entries: the first byte of
    /// the key stream is `1f` in all 32, and these are the bytes of X and of Y and Z.
    const AFTER_STAGE1: [(u8, u8, u32); 32] = [
        (0x67, 0x6e, 0x112c),
        (0x67, 0x6e, 0x912c),
        (0x67, 0xee, 0x120c),
        (0x67, 0xee, 0x920c),
        (0x77, 0x6e, 0x120c),
        (0x77, 0x6e, 0x920c),
        (0x77, 0xee, 0x112c),
        (0x77, 0xee, 0x912c),
        (0x7d, 0x10, 0x7ea0),
        (0x7d, 0x10, 0xfea0),
        (0x7d, 0x11, 0x7ea0),
        (0x7d, 0x11, 0xfea0),
        (0x7d, 0x90, 0x7d80),
        (0x7d, 0x90, 0xfd80),
        (0x7d, 0x91, 0x7d80),
        (0x7d, 0x91, 0xfd80),
        (0x82, 0x6e, 0x120c),
        (0x82, 0x6e, 0x920c),
        (0x82, 0xee, 0x112c),
        (0x82, 0xee, 0x912c),
        (0x88, 0x10, 0x7ea0),
        (0x88, 0x10, 0xfea0),
        (0x88, 0x11, 0x7ea0),
        (0x88, 0x11, 0xfea0),
        (0x88, 0x90, 0x7d80),
        (0x88, 0x90, 0xfd80),
        (0x88, 0x91, 0x7d80),
        (0x88, 0x91, 0xfd80),
        (0x92, 0x6e, 0x112c),
        (0x92, 0x6e, 0x912c),
        (0x92, 0xee, 0x120c),
        (0x92, 0xee, 0x920c),
    ];
    /// After stage 2,
    const AFTER_STAGE2: [Guess; 4] = [guess(0x1f, 0x82e3_0000, 0x6ebd_0000, 0x0007_920e), guess(0x1f, 0x82e3_0000, 0x6ebd_0000, 0x0087_920e), guess(0x1f, 0x82e3_0000, 0xeebd_0000, 0x003f_112e), guess(0x1f, 0x82e3_0000, 0xeebd_0000, 0x00bf_112e)];
    /// after stage 3,
    const AFTER_STAGE3: [Guess; 1] = [guess(0x1f, 0x82e3_1000, 0x6ebd_6200, 0xd187_920e)];
    /// and after stage 4.
    const AFTER_STAGE4: [Guess; 1] = [guess(0x1f, 0x82e3_1069, 0x6ebd_62c9, 0xd187_920e)];

    /// The first `count` entries of the recorded archive, as the attack takes them.
    fn entries(count: usize) -> Vec<Entry> {
        glibc::header_bytes(NINE_SEED, count).into_iter().zip(NINE_HEADERS).map(|(random, header)| Entry { random, header }).collect()
    }

    fn after_stage1() -> Vec<Guess> {
        AFTER_STAGE1.iter().map(|&(x, y, z)| Guess { stream: 0x1f, x: [x, 0, 0, 0], y: [y, 0, 0, 0], z }).collect()
    }

    /// A search on `threads` threads, with what it counted.
    fn run<T>(threads: usize, search: impl FnOnce(Control<'_>) -> T) -> (T, u64) {
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let found = search(Control { stop: &stop, done: &done, threads });
        (found, done.load(Ordering::Relaxed))
    }

    #[test]
    fn the_right_keys_fit_every_stage() {
        // the pieces of the recorded keys, worked out from the keys themselves
        let entries = entries(9);
        let right = AFTER_STAGE4[0];
        assert_eq!(right.stream, NINE_KEYS.stream_byte());
        assert_eq!(right.z, crc32(NINE_KEYS.z, 0));
        let mut x = NINE_KEYS.x;
        let mut y = NINE_KEYS.y;
        for (x_byte, y_byte) in right.x.into_iter().zip(right.y) {
            x = crc32(x, 0);
            y = y.wrapping_mul(MULT).wrapping_add(1);
            assert_eq!((x_byte, y_byte), (low(x), top(y)));
        }
        // and the passes of every entry go through all four steps under them
        for entry in &entries {
            for depth in 0..=4 {
                assert!(!trails(entry, &right, depth).is_empty());
            }
            assert!(trails(entry, &Guess { stream: right.stream ^ 1, ..right }, 4).is_empty());
        }
    }

    #[test]
    fn a_range_is_split_at_its_high_bits() {
        assert_eq!(split(0x1fe..0x402, 8).collect::<Vec<_>>(), [(1, 0xfe..0x100), (2, 0..0x100), (3, 0..0x100), (4, 0..2)]);
        assert_eq!(split(0x105..0x107, 8).collect::<Vec<_>>(), [(1, 5..7)]);
        assert_eq!(split(7..7, 8).count(), 0);
        assert_eq!(split(0..1 << 24, 16).count(), 256);
    }

    #[test]
    fn stage_1_leaves_the_recorded_guesses() {
        let entries = entries(9);
        // the first byte of the key stream and the bits of X of the right guess with every top
        // byte of Y, and half of the guesses behind them, which hold none that is left
        let space = 0x1f_8200..0x1f_8380;
        let recorded: Vec<Guess> = after_stage1().into_iter().filter(|guess| guess.x[0] == 0x82).collect();
        assert_eq!(recorded.len(), 4);
        assert_eq!(run(3, |control| stage1(&entries, space.clone(), control)), (recorded, 0x180));
        // a slice past the guesses there are, and no entries
        assert_eq!(run(2, |control| stage1(&entries, STAGE1_SPACE..STAGE1_SPACE + 5, control)), (Vec::new(), 0));
        assert_eq!(run(2, |control| stage1(&[], space.clone(), control)), (Vec::new(), 0));
    }

    #[test]
    fn stage_2_leaves_the_recorded_guesses() {
        let entries = entries(9);
        // the bits of X of the right guess with every top byte of Y and both low bits of Z, and
        // some of the guesses behind them, which hold none that is left
        let space = 0xe3 << 10..(0xe4 << 10) + 0x100;
        assert_eq!(run(3, |control| stage2(&entries, &after_stage1(), space.clone(), control)), (AFTER_STAGE2.to_vec(), 32 * 0x500));
        assert_eq!(run(2, |control| stage2(&entries, &[], space.clone(), control)), (Vec::new(), 0));
    }

    #[test]
    fn stage_3_leaves_the_recorded_guess() {
        let entries = entries(9);
        // the top byte of Z of the right guess, sixteen values of the bits of X around the right ones
        let space = 0xd1_0800..0xd1_1800;
        for threads in [1, 3] {
            assert_eq!(run(threads, |control| stage3(&entries, &AFTER_STAGE2, space.clone(), control)), (AFTER_STAGE3.to_vec(), 4 << 12));
        }
        // another top byte of Z
        assert_eq!(run(2, |control| stage3(&entries, &AFTER_STAGE2, 0xd0_0800..0xd0_1800, control)).0, []);
    }

    #[test]
    fn stage_4_leaves_the_recorded_guess() {
        let entries = entries(9);
        let space = 0x6000..0x7000;
        for threads in [1, 3] {
            assert_eq!(run(threads, |control| stage4(&entries, &AFTER_STAGE3, space.clone(), control)), (AFTER_STAGE4.to_vec(), 0x1000));
        }
        assert_eq!(run(2, |control| stage4(&entries, &AFTER_STAGE3, 0x7000..0x8000, control)).0, []);
    }

    #[test]
    fn the_end_gives_the_keys() {
        let entries = entries(9);
        let low_bits = NINE_KEYS.y.wrapping_mul(MULT).wrapping_add(1) & 0x00ff_ffff;
        let space = low_bits.saturating_sub(5000)..low_bits + 5000;
        let width = u64::from(space.end - space.start);
        for threads in [1, 3] {
            assert_eq!(run(threads, |control| finish(&entries, &AFTER_STAGE4, space.clone(), control)), (vec![NINE_KEYS], width));
        }
        assert_eq!(run(2, |control| finish(&entries, &AFTER_STAGE4, low_bits + 1..low_bits + 5000, control)).0, []);
        // a guess that is wrong in one bit of X gives no keys
        let wrong = Guess { x: [0x82, 0xe3, 0x10, 0x68], ..AFTER_STAGE4[0] };
        assert_eq!(run(2, |control| finish(&entries, &[wrong], space.clone(), control)).0, []);
    }

    #[test]
    fn too_few_entries_are_not_attacked_and_a_stopped_attack_finds_nothing() {
        assert_eq!(run(2, |control| recover(&entries(MIN_ENTRIES - 1), control)), (None, 0));
        let (stop, done) = (AtomicBool::new(true), AtomicU64::new(0));
        let control = Control { stop: &stop, done: &done, threads: 2 };
        assert_eq!(recover(&entries(9), control), Some(Recovery { left: [0; 4], keys: Vec::new() }));
        assert_eq!(done.load(Ordering::Relaxed), 0);
    }

    /// The whole attack on the first `count` entries: what it has to leave after each stage
    /// (design, section 8.3), and the keys.
    fn whole_attack(count: usize, left: [usize; 4]) {
        let started = std::time::Instant::now();
        let (recovery, done) = run(16, |control| recover(&entries(count), control));
        eprintln!("{count} entries: {:.1} s", started.elapsed().as_secs_f64());
        assert_eq!(recovery, Some(Recovery { left, keys: vec![NINE_KEYS] }));
        assert_eq!(done, RECOVER_TOTAL);
    }

    #[test]
    #[ignore = "the whole attack: seconds with optimisation, minutes without"]
    fn the_whole_attack_on_nine_entries() {
        whole_attack(9, [32, 4, 1, 1]);
    }

    #[test]
    #[ignore = "the whole attack: seconds with optimisation, minutes without"]
    fn the_whole_attack_on_six_entries() {
        whole_attack(6, [40, 4, 1, 1]);
    }

    #[test]
    #[ignore = "the whole attack: seconds with optimisation, minutes without"]
    fn the_whole_attack_on_five_entries() {
        whole_attack(5, [312, 24, 2, 2]);
    }

    #[test]
    #[ignore = "the whole attack: half a minute with optimisation, an hour without"]
    fn the_whole_attack_on_four_entries() {
        whole_attack(4, [15_304, 61_364, 236, 5]);
    }

    /// The whole attack on another archive: the fixture of six entries, from its seed and its
    /// headers to the keys of its password.
    #[test]
    #[ignore = "the whole attack: seconds with optimisation, minutes without"]
    fn the_whole_attack_on_the_fixture_of_six_entries() {
        let entries: Vec<Entry> = glibc::header_bytes(SIX_SEED, SIX_HEADERS.len()).into_iter().zip(SIX_HEADERS).map(|(random, header)| Entry { random, header }).collect();
        let (recovery, done) = run(16, |control| recover(&entries, control));
        assert_eq!(recovery.map(|recovery| recovery.keys), Some(vec![SIX_KEYS]));
        assert_eq!(done, RECOVER_TOTAL);
    }
}
