//! The `rand()` of glibc, the bytes Info-ZIP draws from it for its encryption headers, and the
//! search for the seed it was given.
//!
//! Info-ZIP seeds the generator once in a run, with the time exclusive-or the process number
//! on Unix, and draws ten bytes for every encrypted entry, in the order the entries are
//! written (`crypt.c` of Zip 3.0, `crypthead`). It encrypts them twice from the same keys,
//! so the first byte of every header in the archive is the first of its ten bytes as the
//! generator gave it. The first header bytes of an archive are therefore every tenth output
//! of one sequence, and a seed that gives them all is the seed.

use std::ops::Range;

use super::Control;
use super::spread;

/// How many bytes Info-ZIP draws for one header. The other two of the twelve are check bytes.
pub const HEADER_BYTES: usize = 10;

/// A window of seeds is what shares its bits from this one up with a time stamp: Info-ZIP on
/// Unix seeds with the time exclusive-or the process number, and a process number of Linux
/// is below 2^22.
pub const WINDOW_BITS: u32 = 22;

/// The modulus of the generator that fills the state from the seed, 2^31 - 1,
const MODULUS: u32 = 0x7fff_ffff;
/// and its multiplier.
const MULTIPLIER: u32 = 16_807;
/// How many words the state holds: the generator is the one glibc calls `TYPE_3`.
const DEGREE: usize = 31;
/// A new word is the sum of the one that leaves the state and the one this far behind it.
const SEPARATION: usize = 3;
/// How many words `srand()` draws and drops after it has filled the state.
const DROPPED: usize = 310;

/// How many seeds one vector of the search holds. Measured: with sixteen a seed takes 3.2 ns
/// on one thread, with eight 11 ns, and with 32 or more a little longer again.
const LANES: usize = 16;
/// The same as a number to count seeds with.
const LANES_STEP: u32 = 16;
/// How many seeds a thread tests between two looks at the stop flag. A power of two, so that
/// no piece of the search holds both the seeds 2^31 - 1 and 2^31.
const PIECE: u64 = 1 << 16;
/// One above the largest seed.
const SEEDS: u64 = 1 << 32;

/// The generator behind `rand()` of glibc, as `srand()` leaves it.
///
/// It is the additive generator `r[n] = r[n - 31] + r[n - 3]` over words of 32 bits, whose
/// first 31 words come from the seed by a multiplication modulo 2^31 - 1, and `rand()` is a
/// word without its lowest bit (`random_r.c` of glibc, `__srandom_r` and `__random_r`).
#[derive(Debug, Clone, Copy)]
pub struct Rand {
    /// The last 31 words of the sequence, as a ring.
    state: [u32; DEGREE],
    /// Where in the ring the oldest word lies, which the next word replaces.
    at: usize,
}

impl Rand {
    /// The generator after `srand(seed)`.
    #[must_use]
    pub fn new(seed: u32) -> Self {
        // glibc takes the seed 0 as 1
        let seed = if seed == 0 { 1 } else { seed };
        let mut state = [0_u32; DEGREE];
        let mut residue = residue(seed);
        for (index, word) in state.iter_mut().enumerate() {
            if index == 0 {
                *word = seed;
            } else {
                residue = residue * u64::from(MULTIPLIER) % u64::from(MODULUS);
                *word = low_word(residue);
            }
        }
        Self::from_state(state)
    }

    /// The generator whose first 31 words are `state`, after the words `srand()` drops.
    fn from_state(state: [u32; DEGREE]) -> Self {
        // the words 31 to 33 are the words 0 to 2 again, so the ring starts at word 34
        let mut rand = Self { state, at: SEPARATION };
        for _ in 0..DROPPED {
            let _ = rand.word();
        }
        rand
    }

    /// The next word of the sequence.
    fn word(&mut self) -> u32 {
        let behind = (self.at + DEGREE - SEPARATION) % DEGREE;
        let sum = self.state.get(self.at).copied().unwrap_or_default().wrapping_add(self.state.get(behind).copied().unwrap_or_default());
        if let Some(oldest) = self.state.get_mut(self.at) {
            *oldest = sum;
        }
        self.at = (self.at + 1) % DEGREE;
        sum
    }

    /// The next value of `rand()`: 31 bits.
    pub fn rand(&mut self) -> u32 {
        self.word() >> 1
    }

    /// The next byte as Info-ZIP draws it: `(rand() >> 7) & 0xff`.
    pub fn header_byte(&mut self) -> u8 {
        header_byte(self.word())
    }
}

/// The byte Info-ZIP makes of the output that the word `word` gives: bits 7 to 14 of the
/// output, which are bits 8 to 15 of the word.
const fn header_byte(word: u32) -> u8 {
    word.to_le_bytes()[1]
}

/// The seed as glibc computes with it: a signed word, here as its residue modulo 2^31 - 1.
///
/// `__srandom_r` multiplies by Schrage's method, which gives the product modulo 2^31 - 1 for
/// a negative word as well, in the range from 0.
fn residue(seed: u32) -> u64 {
    i64::from(seed.cast_signed()).rem_euclid(i64::from(MODULUS)).unsigned_abs()
}

/// The low 32 bits of a number.
fn low_word(value: u64) -> u32 {
    let [a, b, c, d, ..] = value.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

/// The ten bytes Info-ZIP drew for each of the first `entries` encrypted entries it wrote in
/// a run that was seeded with `seed`, before it encrypted them.
#[must_use]
pub fn header_bytes(seed: u32, entries: usize) -> Vec<[u8; HEADER_BYTES]> {
    let mut rand = Rand::new(seed);
    (0..entries).map(|_| std::array::from_fn(|_| rand.header_byte())).collect()
}

/// Whether `seed` gives the first header byte of every entry: `first` holds the first byte of
/// the encryption header of each entry, in the order the entries lie in the archive.
#[must_use]
pub fn fits(seed: u32, first: &[u8]) -> bool {
    let mut rand = Rand::new(seed);
    first.iter().all(|&byte| {
        let drawn = rand.header_byte();
        for _ in 1..HEADER_BYTES {
            let _ = rand.word();
        }
        drawn == byte
    })
}

/// The window a time stamp lies in: its bits from [`WINDOW_BITS`] up, which a seed made of
/// that time and a process number shares with it.
#[must_use]
pub const fn window_of(time: u32) -> u32 {
    time >> WINDOW_BITS
}

/// Every seed in `seeds` that gives the first header byte of every entry, in rising order.
///
/// `first` holds the first byte of the encryption header of each entry, in the order the
/// entries lie in the archive, which has to be the order they were written in. Each entry is
/// 8 bits of test against the 32 bits of the seed: five entries leave the right seed alone
/// (design, section 8.2). With no entry there is nothing to test, and nothing is returned.
///
/// The range is cut to the seeds there are, `0..2^32`. `control.done` is advanced by one for
/// every seed tested: the total is the length of the range.
#[must_use]
pub fn seeds_in(first: &[u8], seeds: Range<u64>, control: Control<'_>) -> Vec<u32> {
    let (start, end) = (seeds.start, seeds.end.min(SEEDS));
    if first.is_empty() || start >= end {
        return Vec::new();
    }
    let search = Search::new(first);
    let first_piece = start / PIECE;
    let pieces = (end - 1) / PIECE - first_piece + 1;
    let mut found = spread(pieces, control, |piece, found| {
        let from = ((first_piece + piece) * PIECE).max(start);
        let to = ((first_piece + piece + 1) * PIECE).min(end);
        search.scan(from, to, found);
        control.advance(to - from);
    });
    found.sort_unstable();
    found
}

/// Every seed that gives the first header byte of every entry, among all 2^32.
///
/// As [`seeds_in`] over all seeds: the total of `control.done` is 2^32.
#[must_use]
pub fn seeds(first: &[u8], control: Control<'_>) -> Vec<u32> {
    seeds_in(first, 0..SEEDS, control)
}

/// The first byte of each of the first `draws` headers that `zip` draws after `seed`.
#[must_use]
pub fn drawn(seed: u32, draws: usize) -> Vec<u8> {
    let mut rand = Rand::new(seed);
    (0..draws)
        .map(|_| {
            let first = rand.header_byte();
            for _ in 1..HEADER_BYTES {
                let _ = rand.word();
            }
            first
        })
        .collect()
}

/// Every seed that gives the first header byte of every entry when up to `spare` headers
/// were drawn and not written ([`super::places`]), among all 2^32, in rising order. The
/// total of `control.done` is 2^32.
#[must_use]
pub fn seeds_with_gaps(first: &[u8], spare: usize, control: Control<'_>) -> Vec<u32> {
    if first.is_empty() {
        return Vec::new();
    }
    let search = Search { spare, ..Search::new(first) };
    let mut found = spread(SEEDS / PIECE, control, |piece, found| {
        search.scan(piece * PIECE, (piece + 1) * PIECE, found);
        control.advance(PIECE);
    });
    found.sort_unstable();
    found
}

/// The seeds of the first of `windows` that holds any, in rising order.
///
/// A window is what [`window_of`] gives for a time stamp: the 2^22 seeds that the time makes
/// with every process number. The windows are searched in the order given, and the search
/// ends with the first that holds a seed for the first header bytes `first`, which are as
/// for [`seeds_in`]. Nothing is returned when no window holds one.
///
/// `control.done` is advanced by one for every seed tested: the total is 2^22 for each
/// window, and it is not reached when a window before the last holds a seed.
#[must_use]
pub fn seeds_in_windows(first: &[u8], windows: &[u32], control: Control<'_>) -> Vec<u32> {
    seeds_in_windows_of(first, windows, WINDOW_BITS, control)
}

/// [`seeds_in_windows`] for windows of 2^`bits` seeds.
fn seeds_in_windows_of(first: &[u8], windows: &[u32], bits: u32, control: Control<'_>) -> Vec<u32> {
    for &window in windows {
        let start = u64::from(window) << bits;
        let found = seeds_in(first, start..start + (1 << bits), control);
        if !found.is_empty() || control.stopped() {
            return found;
        }
    }
    Vec::new()
}

/// The seed search over one list of first header bytes: what it needs of the generator,
/// worked out once.
///
/// The test of a seed needs bits 8 to 15 of one word of the sequence for each entry. A word
/// is a sum of the 31 words the state starts with, each taken a fixed number of times, and
/// its low 16 bits follow from theirs. Of those 31, the first is the seed itself and the
/// word `j` is the seed times `16807^j` modulo 2^31 - 1, so from one seed to the next each
/// of them grows by a constant modulo 2^31 - 1. The search keeps the 30 residues of several
/// seeds side by side, adds the constants, and keeps the sum for the first entry up to date
/// with them: a seed costs 30 additions with their reductions, and no multiplication.
#[derive(Debug)]
struct Search<'a> {
    /// The first header byte of each entry.
    first: &'a [u8],
    /// `16807^j` modulo 2^31 - 1, for the words `j` from 1 to 30.
    powers: [u32; DEGREE - 1],
    /// What a residue grows by from one vector of seeds to the next, less the modulus.
    steps: [u32; DEGREE - 1],
    /// How often each of the 31 first words is in the word that gives the first header byte
    /// of the first entry, modulo 2^32.
    counts: [u32; DEGREE],
    /// The same for the second entry.
    counts_second: [u32; DEGREE],
    /// What the sum for the first entry grows by from one vector to the next when no residue
    /// passes the modulus.
    drift: u32,
    /// How many headers may have been drawn and not written: none in the search that takes
    /// every entry for the next header.
    spare: usize,
}

impl<'a> Search<'a> {
    /// The search for the seed that gives the first header bytes `first`.
    fn new(first: &'a [u8]) -> Self {
        let mut powers = [0_u32; DEGREE - 1];
        let mut power = 1_u64;
        for slot in &mut powers {
            power = power * u64::from(MULTIPLIER) % u64::from(MODULUS);
            *slot = low_word(power);
        }
        let steps = powers.map(|power| low_word(u64::from(power) * u64::from(LANES_STEP) % u64::from(MODULUS)).wrapping_sub(MODULUS));

        // a state of one word that is 1 and thirty that are 0 gives the count of that word
        let mut counts = [0_u32; DEGREE];
        let mut counts_second = [0_u32; DEGREE];
        for (index, (count, count_second)) in counts.iter_mut().zip(&mut counts_second).enumerate() {
            let mut rand = Rand::from_state(std::array::from_fn(|word| u32::from(word == index)));
            *count = rand.word();
            for _ in 1..HEADER_BYTES {
                let _ = rand.word();
            }
            *count_second = rand.word();
        }

        // the seed itself grows by the count of lanes, and each residue by its step: a residue
        // that passes the modulus loses 2^31 - 1, which is one more in its low 16 bits
        let [of_seed, of_residues @ ..] = counts;
        let drift = of_residues.iter().zip(&steps).fold(of_seed.wrapping_mul(LANES_STEP), |sum, (&count, &step)| sum.wrapping_add(count.wrapping_mul(step.wrapping_add(MODULUS))));
        Self { first, powers, steps, counts, counts_second, drift, spare: 0 }
    }

    /// Put the seeds from `from` to `to - 1` that give every first header byte into `found`.
    /// The range holds no step of the seed as glibc computes with it, other than from 0 to 1.
    fn scan(&self, from: u64, to: u64, found: &mut Vec<u32>) {
        let [of_seed, of_residues @ ..] = self.counts;
        let wanted = self.first.first().copied().unwrap_or_default();

        // the residues of the first words of each lane's seed, and the sum for the first entry
        let lane_seeds: [u64; LANES] = std::array::from_fn(|lane| from + u64::try_from(lane).unwrap_or_default());
        let mut residues = [[0_u32; LANES]; DEGREE - 1];
        let mut sums: [u32; LANES] = lane_seeds.map(|seed| of_seed.wrapping_mul(low_word(seed)));
        for ((row, &power), &count) in residues.iter_mut().zip(&self.powers).zip(&of_residues) {
            for ((word, sum), &seed) in row.iter_mut().zip(&mut sums).zip(&lane_seeds) {
                *word = low_word(residue(low_word(seed)) * u64::from(power) % u64::from(MODULUS));
                *sum = sum.wrapping_add(count.wrapping_mul(*word));
            }
        }

        let mut base = from;
        while base < to {
            // seldom: one seed in 256 gives the first byte of the first entry
            if sums.iter().any(|&sum| header_byte(sum) == wanted) {
                for (lane, &sum) in (0_u64..).zip(&sums) {
                    let seed = base + lane;
                    if header_byte(sum) == wanted && seed < to && seed != 0 && (self.spare > 0 || self.second_fits(seed, lane, &residues)) {
                        let seed = low_word(seed);
                        if self.fits(seed) {
                            found.push(seed);
                        }
                    }
                }
            }
            for ((row, &step), &count) in residues.iter_mut().zip(&self.steps).zip(&of_residues) {
                for (word, sum) in row.iter_mut().zip(&mut sums) {
                    // negative, which is bit 31, when the residue stays below the modulus
                    let moved = word.wrapping_add(step);
                    let below = (moved >> 31).wrapping_neg();
                    *word = moved.wrapping_add(MODULUS & below);
                    *sum = sum.wrapping_add(count & !below);
                }
            }
            for sum in &mut sums {
                *sum = sum.wrapping_add(self.drift);
            }
            base += u64::from(LANES_STEP);
        }

        // the seed 0 is the seed 1 to glibc, which the residues above do not know
        if from == 0 && self.fits(0) {
            found.push(0);
        }
    }

    /// Whether a seed gives the first header byte of every entry, with the headers that may
    /// have been drawn and not written.
    fn fits(&self, seed: u32) -> bool {
        if self.spare == 0 { fits(seed, self.first) } else { super::places(&drawn(seed, self.first.len() + self.spare), self.first, self.spare).is_some() }
    }

    /// Whether the seed in `lane` gives the first header byte of the second entry, from the
    /// residues of its first words. True when there is no second entry.
    fn second_fits(&self, seed: u64, lane: u64, residues: &[[u32; LANES]; DEGREE - 1]) -> bool {
        let Some(&wanted) = self.first.get(1) else { return true };
        let [of_seed, of_residues @ ..] = self.counts_second;
        let lane = usize::try_from(lane).unwrap_or_default();
        let sum = residues.iter().zip(&of_residues).fold(of_seed.wrapping_mul(low_word(seed)), |sum, (row, &count)| sum.wrapping_add(count.wrapping_mul(row.get(lane).copied().unwrap_or_default())));
        header_byte(sum) == wanted
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;
    use crate::attack::zip_crypto::seed::infozip::tests::FOUR_HEADERS;
    use crate::attack::zip_crypto::seed::infozip::tests::FOUR_SEED;
    use crate::attack::zip_crypto::seed::infozip::tests::SIX_HEADERS;
    use crate::attack::zip_crypto::seed::infozip::tests::SIX_SEED;

    /// The first twelve values of `rand()` after `srand(seed)`, from glibc 2.41 itself
    /// (`srand` and `rand` of `libc.so.6`, called through Python's `ctypes`).
    const GLIBC: [(u32, [u32; 12]); 9] = [
        (0, [1_804_289_383, 846_930_886, 1_681_692_777, 1_714_636_915, 1_957_747_793, 424_238_335, 719_885_386, 1_649_760_492, 596_516_649, 1_189_641_421, 1_025_202_362, 1_350_490_027]),
        (1, [1_804_289_383, 846_930_886, 1_681_692_777, 1_714_636_915, 1_957_747_793, 424_238_335, 719_885_386, 1_649_760_492, 596_516_649, 1_189_641_421, 1_025_202_362, 1_350_490_027]),
        (2, [1_505_335_290, 1_738_766_719, 190_686_788, 260_874_575, 747_983_061, 906_156_498, 1_502_820_864, 142_559_277, 1_261_608_745, 1_380_759_627, 2_127_304_342, 635_050_179]),
        (42, [71_876_166, 708_592_740, 1_483_128_881, 907_283_241, 442_951_012, 537_146_758, 1_366_999_021, 1_854_614_940, 647_800_535, 53_523_743, 783_815_874, 1_643_643_143]),
        (0x6b04_6a18, [1_216_154_864, 1_926_292_292, 1_676_059_919, 790_836_239, 1_057_073_781, 2_042_236_773, 1_855_329_648, 1_640_447_822, 1_568_389_827, 882_517_408, 569_687_433, 410_461_886]),
        (0x7fff_ffff, [1_065_668_062, 2_142_264_300, 1_066_566_375, 1_064_012_770, 2_141_034_222, 1_065_509_725, 2_135_810_236, 2_139_491_828, 2_138_030_783, 2_133_535_487, 1_063_823_214, 1_062_867_731]),
        (0x8000_0000, [1_336_741_213, 1_210_407_648, 1_447_044_896, 337_392_383, 82_502_902, 538_660_432, 1_313_908_778, 370_221_063, 344_413_073, 1_896_089_129, 2_044_477_265, 1_711_647_701]),
        (0x8000_0001, [1_081_815_585, 5_219_348, 1_080_917_272, 1_083_470_877, 6_449_426, 1_081_973_922, 11_673_412, 7_991_820, 9_452_865, 13_948_161, 1_083_660_433, 1_084_615_916]),
        (0xffff_ffff, [254_925_627, 1_205_188_300, 366_127_624, 1_401_405_153, 76_053_476, 1_604_170_158, 1_302_235_366, 362_229_243, 334_960_208, 1_882_140_968, 960_816_832, 627_031_785]),
    ];

    /// The first byte of the encryption header of each of the nine entries of the archive
    /// that the design measured (section 8.2), in archive order,
    pub(crate) const NINE_FIRST: [u8; 9] = [0x19, 0x7b, 0x7f, 0x75, 0xba, 0xd6, 0xea, 0xf9, 0x09];
    /// the seed that gives them, found once by the search over all seeds, which found no
    /// other,
    pub(crate) const NINE_SEED: u32 = 1_795_451_416;
    /// and what the design says of it: the time stamp of the archive, exclusive-or a process
    /// number.
    const NINE_TIME: u32 = 1_795_202_130;
    const NINE_PROCESS: u32 = 325_194;

    /// A search on `threads` threads, with what it counted.
    fn run<T>(threads: usize, search: impl FnOnce(Control<'_>) -> T) -> (T, u64) {
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let found = search(Control { stop: &stop, done: &done, threads });
        (found, done.load(Ordering::Relaxed))
    }

    #[test]
    fn a_seed_is_found_when_a_header_was_drawn_and_not_written() {
        // six entries of a run of seven draws: the third header left no entry
        let seed = 1_591_806_450;
        let all = drawn(seed, 7);
        let first: Vec<u8> = all.iter().enumerate().filter(|(draw, _)| *draw != 2).map(|(_, byte)| *byte).collect();
        assert!(!fits(seed, &first));
        assert_eq!(super::super::places(&drawn(seed, first.len() + 3), &first, 3), Some(vec![0, 1, 3, 4, 5, 6]));
        // the search that takes every entry for the next header passes the seed over, and the one that allows for three does not
        let piece = u64::from(seed) / PIECE * PIECE;
        let mut found = Vec::new();
        Search::new(&first).scan(piece, piece + PIECE, &mut found);
        assert!(found.is_empty());
        Search { spare: 3, ..Search::new(&first) }.scan(piece, piece + PIECE, &mut found);
        assert_eq!(found, [seed]);
    }

    #[test]
    fn the_generator_gives_what_glibc_gives() {
        for (seed, values) in GLIBC {
            let mut rand = Rand::new(seed);
            assert_eq!(values.map(|_| rand.rand()), values, "seed {seed:#x}");
        }
        // far into the sequence: the thousandth value
        let mut rand = Rand::new(NINE_SEED);
        assert_eq!((0..1000).map(|_| rand.rand()).last(), Some(49_026_744));
    }

    #[test]
    fn the_header_bytes_are_bits_7_to_14_of_ten_values_an_entry() {
        let mut rand = Rand::new(42);
        let values: Vec<u32> = (0..30).map(|_| rand.rand()).collect();
        let bytes = header_bytes(42, 3);
        assert_eq!(bytes.len(), 3);
        for (drawn, value) in bytes.iter().flatten().zip(&values) {
            assert_eq!(u32::from(*drawn), (value >> 7) & 0xff);
        }
        // the first header byte of each recorded entry is the first of its ten
        let recorded = header_bytes(NINE_SEED, 9);
        assert_eq!(recorded.iter().map(|bytes| bytes[0]).collect::<Vec<_>>(), NINE_FIRST);
        assert!(fits(NINE_SEED, &NINE_FIRST));
        assert!(!fits(NINE_SEED + 1, &NINE_FIRST));
    }

    #[test]
    fn the_seed_of_the_recorded_archive_is_its_time_and_a_process_number() {
        assert_eq!(NINE_SEED, NINE_TIME ^ NINE_PROCESS);
        const { assert!(NINE_PROCESS < 1 << WINDOW_BITS) };
        assert_eq!(window_of(NINE_SEED), window_of(NINE_TIME));
    }

    /// The search against the generator itself, seed by seed, where the seed as glibc
    /// computes with it makes a step: at 0, around 2^31 - 1 and 2^31, and at the end.
    #[test]
    fn the_search_finds_what_the_generator_gives_seed_by_seed() {
        for start in [0_u64, 0x7fff_fc00, 0xffff_f800, 3 * PIECE - 100, u64::from(NINE_SEED) - 1000] {
            let range = start..(start + 2048).min(SEEDS);
            // the first header byte of two entries for every seed, from the generator
            let drawn: Vec<(u32, [u8; 2])> = range.clone().map(|seed| u32::try_from(seed).unwrap()).map(|seed| (seed, header_bytes(seed, 2))).map(|(seed, bytes)| (seed, [bytes[0][0], bytes[1][0]])).collect();
            // one byte and two bytes: enough seeds fit to see every one of them
            for first in [&[0x00_u8][..], &[0xff], &[0x19, 0x7b], &[0x00, 0x00]] {
                let slow: Vec<u32> = drawn.iter().filter(|(_, bytes)| bytes.starts_with(first)).map(|&(seed, _)| seed).collect();
                let (fast, done) = run(3, |control| seeds_in(first, range.clone(), control));
                assert_eq!(fast, slow, "from {start:#x} for {first:02x?}");
                assert_eq!(done, range.end - range.start);
            }
        }
        // the seeds 0 and 1 are one seed to glibc
        let zero = header_bytes(0, 2).iter().map(|bytes| bytes[0]).collect::<Vec<_>>();
        assert_eq!(run(1, |control| seeds_in(&zero, 0..16, control)).0, [0, 1]);
    }

    #[test]
    fn the_seed_of_the_recorded_archive_is_found_in_a_slice_of_its_window() {
        let seed = u64::from(NINE_SEED);
        for threads in [1, 4] {
            let (found, done) = run(threads, |control| seeds_in(&NINE_FIRST, seed - 20_000..seed + 20_000, control));
            assert_eq!(found, [NINE_SEED]);
            assert_eq!(done, 40_000);
        }
        // a slice that does not hold it finds nothing
        assert_eq!(run(4, |control| seeds_in(&NINE_FIRST, seed + 1..seed + 20_000, control)), (Vec::new(), 19_999));
        // nothing to test, nothing to search, and a range past the last seed
        assert_eq!(run(1, |control| seeds_in(&[], 0..1000, control)), (Vec::new(), 0));
        assert_eq!(run(1, |control| seeds_in(&NINE_FIRST, 1000..1000, control)), (Vec::new(), 0));
        assert_eq!(run(1, |control| seeds_in(&NINE_FIRST, SEEDS - 10..SEEDS + 10, control)), (Vec::new(), 10));
    }

    /// The seeds of the two fixtures of Info-ZIP, each in a slice of the window of its time.
    #[test]
    fn the_seeds_of_the_fixtures_are_found_in_a_slice_of_their_window() {
        const TIME: u32 = 1_795_212_702;
        for (seed, headers) in [(SIX_SEED, &SIX_HEADERS[..]), (FOUR_SEED, &FOUR_HEADERS[..])] {
            let first: Vec<u8> = headers.iter().map(|header| header[0]).collect();
            assert_eq!(window_of(seed), window_of(TIME));
            assert!(seed ^ TIME < 1 << WINDOW_BITS);
            let (found, _) = run(4, |control| seeds_in(&first, u64::from(seed) - 9000..u64::from(seed) + 9000, control));
            assert_eq!(found, [seed]);
        }
    }

    /// The windows are tried in order, and the first that holds a seed ends the search: with
    /// windows of 2^12 seeds, which the search goes through in no time.
    #[test]
    fn the_windows_are_searched_in_order_until_one_holds_a_seed() {
        let bits = 12;
        let window = NINE_SEED >> bits;
        let (found, done) = run(2, |control| seeds_in_windows_of(&NINE_FIRST, &[window - 1, window, window + 1], bits, control));
        assert_eq!(found, [NINE_SEED]);
        assert_eq!(done, 2 << bits);
        // windows that do not hold the seed find nothing
        assert_eq!(run(2, |control| seeds_in_windows_of(&NINE_FIRST, &[window + 1, window - 1], bits, control)), (Vec::new(), 2 << bits));
        assert_eq!(run(2, |control| seeds_in_windows_of(&NINE_FIRST, &[], bits, control)), (Vec::new(), 0));
        // a window past the last seed is no window
        assert_eq!(run(2, |control| seeds_in_windows(&NINE_FIRST, &[1 << (32 - WINDOW_BITS)], control)), (Vec::new(), 0));
    }

    /// The one search of a whole window in the default run: 2^22 seeds, on every thread there
    /// is, which takes a fraction of a second without optimisation.
    #[test]
    fn the_seed_of_the_recorded_archive_is_found_in_the_window_of_its_time() {
        let threads = std::thread::available_parallelism().map_or(4, usize::from);
        let (found, done) = run(threads, |control| seeds_in_windows(&NINE_FIRST, &[window_of(NINE_TIME)], control));
        assert_eq!(found, [NINE_SEED]);
        assert_eq!(done, 1 << WINDOW_BITS);
    }

    #[test]
    #[ignore = "searches three windows of 2^22 seeds, which takes seconds without optimisation"]
    fn the_seed_of_the_recorded_archive_is_found_in_no_other_window() {
        let window = window_of(NINE_TIME);
        // a window that does not hold the seed finds nothing
        assert_eq!(run(16, |control| seeds_in_windows(&NINE_FIRST, &[window + 1], control)), (Vec::new(), 1 << WINDOW_BITS));
        // the windows are tried in order, and the first that holds a seed ends the search
        let (found, done) = run(16, |control| seeds_in_windows(&NINE_FIRST, &[window - 1, window, window + 1], control));
        assert_eq!(found, [NINE_SEED]);
        assert_eq!(done, 2 << WINDOW_BITS);
    }

    #[test]
    #[ignore = "searches all 2^32 seeds, twice"]
    fn the_seed_of_the_recorded_archive_is_the_only_one_among_all() {
        let started = std::time::Instant::now();
        let (found, done) = run(16, |control| seeds(&NINE_FIRST, control));
        eprintln!("all 2^32 seeds: {:.1} s", started.elapsed().as_secs_f64());
        assert_eq!(found, [NINE_SEED]);
        assert_eq!(done, SEEDS);
        // with four entries one wrong seed fits as well (design, section 8.2)
        let (found, _) = run(16, |control| seeds(&NINE_FIRST[..4], control));
        assert_eq!(found.len(), 2);
        assert!(found.contains(&NINE_SEED));
    }

    #[test]
    fn a_search_that_is_stopped_ends_early() {
        let (stop, done) = (AtomicBool::new(true), AtomicU64::new(0));
        let control = Control { stop: &stop, done: &done, threads: 2 };
        assert_eq!(seeds(&NINE_FIRST, control), Vec::<u32>::new());
        assert_eq!(seeds_in_windows(&NINE_FIRST, &[window_of(NINE_TIME)], control), Vec::<u32>::new());
        assert_eq!(done.load(Ordering::Relaxed), 0);
    }
}
