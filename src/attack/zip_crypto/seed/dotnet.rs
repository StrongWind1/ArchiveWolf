//! `System.Random` of .NET, how the runtimes from .NET Core 2.1 to .NET 5 seed one that is
//! given no seed, and the search for the one number the headers of an archive then follow
//! from.
//!
//! DotNetZip, and SharpZipLib from 0.86 to 1.3.0, make a `new Random()` for every entry, fill
//! twelve bytes from it, put the check byte over the last and encrypt the header once. On
//! those runtimes the seed of such a generator is the next output of a generator that is kept
//! for each thread, which is itself seeded with one number of 31 bits (`Random.cs` of
//! `release/5.0`, `GenerateSeed`). The seeds of all entries written on one thread follow from
//! that number, and with them the first eleven bytes of every header before it was
//! encrypted: known bytes at the positions -12 to -2, in every entry.
//!
//! The test of a thread seed needs no key. The first byte of the key stream is the same for
//! every entry under one password, so the first header bytes of two entries differ by what
//! the first bytes of their generators differ by.

use std::ops::Range;

use super::Control;
use super::spread;

/// The largest value of the generator, which is also its modulus: 2^31 - 1.
const MBIG: i32 = i32::MAX;
/// The constant the seed is taken from.
const MSEED: i32 = 161_803_398;
/// The modulus as an unsigned number.
const MODULUS: u64 = 0x7fff_ffff;
/// How many words the state has. The word 0 is not used.
const WORDS: usize = 56;

/// The first value of the generator seeded with 0,
const FIRST_OF_ZERO: u64 = 1_559_595_546;
/// and what it grows by, modulo 2^31 - 1, when the absolute value of the seed grows by one.
/// The two words of the state that make the first value are sums and differences of the
/// words the seed is spread into, and the one word of the state that is not reduced modulo
/// 2^31 - 1 is not among them: so the first value is this line in the seed.
const FIRST_SLOPE: u64 = MODULUS - 1_025_583_828;

/// How many bytes of a header come from the generator and stay: the twelfth is overwritten
/// with the check byte.
pub const HEADER_BYTES: usize = 11;

/// How many places of the first entry in the sequence of its thread the measured search
/// tried: the count of `new Random()` that the thread made before it wrote the first entry,
/// from 0 to 7 (design, section 8.5).
pub const POSITIONS: u32 = 8;

/// How many seeds the generator of a thread can have: it is seeded with a value of another
/// generator, which is at least 0 and below 2^31 - 1.
pub const THREAD_SEEDS: u32 = 0x7fff_ffff;

/// How many thread seeds one vector of the search holds. Measured: with sixteen a seed takes
/// 49 ns on one thread at eight places, with eight 62 ns, and with 32 no less.
const LANES: usize = 16;
/// The same as a number to count seeds with.
const LANES_STEP: u32 = 16;
/// How many thread seeds a thread tests between two looks at the stop flag.
const PIECE: u32 = 1 << 12;

/// The generator behind `System.Random(int)`: the subtractive generator of Knuth as the .NET
/// Framework and .NET to version 5 have it, and later versions for a seed that is given
/// (`Random.cs` of `release/5.0`; `Net5CompatSeedImpl` from .NET 6).
#[derive(Debug, Clone, Copy)]
pub struct Random {
    /// The 55 words of the state, in the places 1 to 55.
    state: [i32; WORDS],
    /// The place of the word the next value is made at,
    next: usize,
    /// and of the word that is subtracted from it.
    next_p: usize,
}

impl Random {
    /// The generator of `new Random(seed)`.
    #[must_use]
    pub fn new(seed: i32) -> Self {
        let mut state = [0_i32; WORDS];
        let subtraction = if seed == i32::MIN { i32::MAX } else { seed.abs() };
        let mut mj = MSEED.wrapping_sub(subtraction);
        put(&mut state, WORDS - 1, mj);
        let mut mk = 1_i32;
        let mut place = 0;
        for _ in 1..WORDS - 1 {
            place = (place + 21) % (WORDS - 1);
            put(&mut state, place, mk);
            mk = reduced(mj.wrapping_sub(mk));
            mj = word(&state, place);
        }
        for _ in 0..4 {
            for place in 1..WORDS {
                let other = 1 + (place + 30) % (WORDS - 1);
                let difference = word(&state, place).wrapping_sub(word(&state, other));
                put(&mut state, place, reduced(difference));
            }
        }
        Self { state, next: 0, next_p: 21 }
    }

    /// The next value: `Next()`, at least 0 and below 2^31 - 1.
    pub fn sample(&mut self) -> i32 {
        self.next = following(self.next);
        self.next_p = following(self.next_p);
        let value = sampled(word(&self.state, self.next), word(&self.state, self.next_p));
        put(&mut self.state, self.next, value);
        value
    }

    /// The next byte as `NextBytes` fills them: the low eight bits of a value.
    pub fn byte(&mut self) -> u8 {
        self.sample().to_le_bytes()[0]
    }
}

/// The word of a state at `place`.
fn word<T: Copy + Default>(state: &[T; WORDS], place: usize) -> T {
    state.get(place).copied().unwrap_or_default()
}

/// Set the word of a state at `place`.
fn put<T>(state: &mut [T; WORDS], place: usize, value: T) {
    if let Some(slot) = state.get_mut(place) {
        *slot = value;
    }
}

/// The place after `place` in the ring of the places 1 to 55.
const fn following(place: usize) -> usize {
    if place >= WORDS - 1 { 1 } else { place + 1 }
}

/// A difference of two words as the generator keeps it: a negative one has the modulus added.
const fn reduced(difference: i32) -> i32 {
    difference.wrapping_add(MBIG & (difference >> 31))
}

/// The value the generator makes of the words at its two places.
const fn sampled(at_next: i32, at_next_p: i32) -> i32 {
    let difference = at_next.wrapping_sub(at_next_p);
    reduced(if difference == MBIG { difference - 1 } else { difference })
}

/// The first value of `new Random(seed)`, without the generator.
///
/// It is the same as `Random::new(seed).sample()` for every seed: the search needs the first
/// byte of the generator of every entry, and this is one multiplication in place of the 275
/// steps that set a generator up.
#[must_use]
pub fn first_sample(seed: i32) -> i32 {
    let subtraction = if seed == i32::MIN { MODULUS } else { u64::from(seed.unsigned_abs()) };
    i32::try_from(first_value(subtraction)).unwrap_or_default()
}

/// The first value of a generator whose seed has the absolute value `subtraction`.
const fn first_value(subtraction: u64) -> u64 {
    folded(FIRST_OF_ZERO + FIRST_SLOPE * subtraction)
}

/// A number below 2^62, modulo 2^31 - 1.
const fn folded(value: u64) -> u64 {
    // 2^31 is 1 modulo 2^31 - 1, so the bits from 31 up are added to those below
    let once = (value & MODULUS) + (value >> 31);
    let twice = (once & MODULUS) + (once >> 31);
    if twice >= MODULUS { twice - MODULUS } else { twice }
}

/// The seeds of the generators of `entries` entries that one thread wrote one after the
/// other: the values of the generator of the thread, which was seeded with `thread_seed`,
/// from the one at `position` on.
#[must_use]
pub fn entry_seeds(thread_seed: i32, position: u32, entries: usize) -> Vec<i32> {
    let mut thread = Random::new(thread_seed);
    for _ in 0..position {
        let _ = thread.sample();
    }
    (0..entries).map(|_| thread.sample()).collect()
}

/// The first eleven bytes of the header of an entry before it was encrypted, from the seed
/// of the generator that was made for the entry.
#[must_use]
pub fn header_bytes(entry_seed: i32) -> [u8; HEADER_BYTES] {
    let mut random = Random::new(entry_seed);
    std::array::from_fn(|_| random.byte())
}

/// Whether the entries whose first header bytes are `first`, in the order they were written,
/// can come from the thread seed `thread_seed` with the first entry at `position`: every
/// entry after the first differs from the first by what their generators differ by.
#[must_use]
pub fn fits(thread_seed: i32, position: u32, first: &[u8]) -> bool {
    let seeds = entry_seeds(thread_seed, position, first.len());
    let mut pairs = seeds.iter().zip(first).map(|(&seed, &byte)| Random::new(seed).byte() ^ byte);
    pairs.next().is_none_or(|key_stream| pairs.all(|other| other == key_stream))
}

/// A thread seed that gives the first header byte of every entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Found {
    /// The seed of the generator of the thread that wrote the entries.
    pub thread_seed: i32,
    /// How many generators the thread made before the one of the first entry.
    pub position: u32,
}

impl Found {
    /// The seed of the generator of each of the first `entries` entries.
    #[must_use]
    pub fn entry_seeds(self, entries: usize) -> Vec<i32> {
        entry_seeds(self.thread_seed, self.position, entries)
    }

    /// The first eleven bytes of the header of each of the first `entries` entries before it
    /// was encrypted. The twelfth byte of a header is the check byte.
    #[must_use]
    pub fn headers(self, entries: usize) -> Vec<[u8; HEADER_BYTES]> {
        self.entry_seeds(entries).into_iter().map(header_bytes).collect()
    }
}

/// Every thread seed in `seeds` that gives the first header byte of every entry, with the
/// first entry at one of the first `positions` places of the sequence of its thread. In
/// rising order of the seed, then of the place.
///
/// `first` holds the first byte of the encryption header of each entry, in the order the
/// entries lie in the archive, which has to be the order one thread wrote them in. Each
/// entry after the first is 8 bits of test against the 31 bits of the seed and the places:
/// six entries leave the right seed alone, and with four about a thousand fit (design,
/// section 8.5). With fewer than two entries there is nothing to test, and nothing is
/// returned.
///
/// The seeds are those below [`THREAD_SEEDS`]: the range is cut to them, and a slice of them
/// is a share of the search for one machine of several. `control.done` is advanced by one for
/// every thread seed tested at all its places: the total is the length of the range.
#[must_use]
pub fn thread_seeds(first: &[u8], seeds: Range<u32>, positions: u32, control: Control<'_>) -> Vec<Found> {
    let (start, end) = (seeds.start, seeds.end.min(THREAD_SEEDS));
    if first.len() < 2 || positions == 0 || start >= end {
        return Vec::new();
    }
    let pieces = u64::from((end - start).div_ceil(PIECE));
    let mut found = spread(pieces, control, |piece, found| {
        let from = start.saturating_add(u32::try_from(piece).unwrap_or(u32::MAX).saturating_mul(PIECE));
        let to = from.saturating_add(PIECE).min(end);
        scan(first, from..to, positions, found);
        control.advance(u64::from(to - from));
    });
    found.sort_unstable();
    found
}

/// The words of the same place in the generators of several seeds.
type Lanes = [i32; LANES];

/// Put every thread seed in `seeds` that fits at one of the `positions` into `found`.
///
/// The generators of [`LANES`] thread seeds are set up side by side, with the steps of
/// [`Random::new`] on every lane. Each gives the seeds of the entries at the places wanted,
/// and the first byte of each of those is one multiplication ([`first_sample`]).
fn scan(first: &[u8], seeds: Range<u32>, positions: u32, found: &mut Vec<Found>) {
    let mut bytes = first.iter().map(|byte| byte ^ first.first().copied().unwrap_or_default()).skip(1);
    // what the first bytes of the second and the third entry differ from that of the first by
    let Some(second) = bytes.next() else { return };
    let third = bytes.next();
    let places = usize::try_from(positions).unwrap_or(usize::MAX);
    let mut firsts: Vec<[u8; LANES]> = Vec::with_capacity(places.saturating_add(2));

    let mut base = seeds.start;
    while base < seeds.end {
        // a lane past the range holds the one seed no range holds
        let mut following = base;
        let lane_seeds: Lanes = std::array::from_fn(|_| {
            let seed = i32::try_from(following).unwrap_or(i32::MAX);
            following = following.saturating_add(1);
            seed
        });
        let mut state = set_up(lane_seeds);
        firsts.clear();
        for number in 1..=places.saturating_add(2) {
            firsts.push(next_values(&mut state, number).map(|seed| first_value(u64::from(seed.unsigned_abs())).to_le_bytes()[0]));
        }
        for (position, window) in (0..positions).zip(firsts.windows(3)) {
            let [here, next, after] = window else { continue };
            let fit = here.iter().zip(next).zip(after).map(|((here, next), after)| here ^ next == second && third.is_none_or(|third| here ^ after == third));
            for (seed, fit) in lane_seeds.into_iter().zip(fit) {
                // seldom, and then the generators themselves decide
                if fit && seed.unsigned_abs() < seeds.end && fits(seed, position, first) {
                    found.push(Found { thread_seed: seed, position });
                }
            }
        }
        base = base.saturating_add(LANES_STEP);
    }
}

/// The states of `new Random(seed)` for the seed of every lane. The seeds are not negative.
fn set_up(seeds: Lanes) -> [Lanes; WORDS] {
    let mut state = [[0_i32; LANES]; WORDS];
    let mut mj = seeds.map(|seed| MSEED.wrapping_sub(seed));
    put(&mut state, WORDS - 1, mj);
    let mut mk = [1_i32; LANES];
    let mut place = 0;
    for _ in 1..WORDS - 1 {
        place = (place + 21) % (WORDS - 1);
        put(&mut state, place, mk);
        let previous = mk;
        subtract(&mut mj, &mk);
        mk = mj;
        mj = previous;
    }
    for _ in 0..4 {
        mix(&mut state);
    }
    state
}

/// One of the four rounds that end the set-up: every word from 1 to 55 has the word 31
/// places on in the ring subtracted from it, in rising order.
///
/// The round is three runs of words that do not read what the same run writes: the words 1
/// to 24 read the words 32 to 55 of the round before, the words 25 to 48 read the words 1 to
/// 24 of this round, and the words 49 to 55 read the words 25 to 31 of this round.
fn mix(state: &mut [Lanes; WORDS]) {
    let (low, high) = state.split_at_mut(32);
    for (word, other) in low.iter_mut().skip(1).zip(high.iter()) {
        subtract(word, other);
    }
    let (low, high) = state.split_at_mut(25);
    for (word, other) in high.iter_mut().zip(low.iter().skip(1)) {
        subtract(word, other);
    }
    let (low, high) = state.split_at_mut(49);
    for (word, other) in high.iter_mut().zip(low.iter().skip(25)) {
        subtract(word, other);
    }
}

/// Subtract `other` from `word` on every lane, as the generator keeps a difference.
fn subtract(word: &mut Lanes, other: &Lanes) {
    for (word, other) in word.iter_mut().zip(other) {
        *word = reduced(word.wrapping_sub(*other));
    }
}

/// The value with the number `number`, from 1, of the generator of every lane. The values
/// have to be asked for in order.
fn next_values(state: &mut [Lanes; WORDS], number: usize) -> Lanes {
    let next = (number - 1) % (WORDS - 1) + 1;
    let next_p = (number + 20) % (WORDS - 1) + 1;
    let other = word(state, next_p);
    let mut values = word(state, next);
    for (value, other) in values.iter_mut().zip(&other) {
        *value = sampled(*value, *other);
    }
    put(state, next, values);
    values
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use archivewolf_zip_crypto::Keys;

    use super::*;

    /// `new System.Random(seed).Next()` and the twelve bytes of `NextBytes` for five seeds, as
    /// the .NET 9 runtime printed them (`rngcheck` of the experiment).
    const DOTNET: [(i32, i32, [u8; 12]); 5] = [
        (0, 1_559_595_546, [0x1a, 0x0c, 0x46, 0x6f, 0x5d, 0x75, 0xe4, 0xd8, 0xad, 0x67, 0x65, 0xd5]),
        (1, 534_011_718, [0x46, 0xd0, 0x86, 0x82, 0x40, 0x97, 0xe4, 0xa3, 0x95, 0xcf, 0xff, 0x46]),
        (123_456_789, 1_091_672_793, [0xd9, 0x14, 0x8e, 0x81, 0x5f, 0x13, 0x89, 0x58, 0x63, 0x49, 0x83, 0xf7]),
        (-5, 726_643_700, [0xf4, 0xdd, 0x85, 0xcf, 0xce, 0x1e, 0xe2, 0xd1, 0x31, 0x71, 0x65, 0x09]),
        (i32::MAX, 1_559_595_546, [0x1a, 0x0c, 0x4c, 0x6f, 0x5d, 0x73, 0xe4, 0xd8, 0xad, 0x5b, 0x65, 0xd5]),
    ];

    /// The encryption headers of the six entries of `gen_sharpziplib_net5.zip`, written by
    /// SharpZipLib 1.3.0 on .NET 5, in archive order,
    pub(crate) const SHARP_NET5: [[u8; 12]; 6] = [
        [0x5a, 0xde, 0x62, 0xcc, 0x4b, 0xd4, 0xdb, 0x06, 0xce, 0xea, 0x89, 0xeb],
        [0x18, 0xd0, 0xc4, 0x75, 0x7b, 0xc8, 0x88, 0x1a, 0x51, 0xaa, 0x99, 0x95],
        [0x9e, 0x5b, 0xd9, 0x40, 0x17, 0x8a, 0x45, 0x8e, 0x88, 0x5a, 0xd9, 0xad],
        [0x4c, 0x23, 0x26, 0xae, 0xcf, 0x7e, 0x66, 0x06, 0xa3, 0xd1, 0x93, 0x1d],
        [0xc7, 0xd6, 0x14, 0x87, 0x7c, 0x3a, 0xcc, 0x43, 0x26, 0xb9, 0xf0, 0x5d],
        [0x53, 0x24, 0xde, 0xac, 0x13, 0x61, 0x27, 0xa5, 0xa7, 0x1d, 0x8b, 0xcc],
    ];
    /// the thread seed the measured search found for it, the only one among all,
    const SHARP_NET5_SEED: i32 = 513_587_410;
    /// and the seeds of the generators of its entries.
    const SHARP_NET5_ENTRY_SEEDS: [i32; 6] = [1_630_103_928, 1_441_357_998, 898_741_052, 988_593_767, 2_027_448_482, 1_498_234_630];

    /// The same for `gen_dotnetzip_net5.zip`, written by DotNetZip 1.16.0 on .NET 5.
    pub(crate) const DOTNETZIP_NET5: [[u8; 12]; 6] = [
        [0x23, 0x98, 0xb5, 0xbe, 0x6b, 0xdc, 0xda, 0xa4, 0x2f, 0xde, 0x6d, 0x34],
        [0xa6, 0x9a, 0x6a, 0x16, 0xf0, 0xac, 0x7c, 0xbb, 0xec, 0x93, 0x20, 0xc0],
        [0x60, 0xb1, 0x19, 0xc0, 0x5c, 0xbf, 0x09, 0x94, 0x6c, 0x7c, 0xf3, 0x44],
        [0xd3, 0x76, 0x52, 0xe4, 0x62, 0xf1, 0x72, 0x8d, 0x74, 0x2a, 0x03, 0x92],
        [0xfc, 0x29, 0x1b, 0x50, 0xa7, 0x0a, 0xd1, 0xb2, 0x77, 0x7a, 0x42, 0xbf],
        [0x0b, 0x76, 0xf9, 0xae, 0xc7, 0x10, 0x63, 0x2e, 0x96, 0xa3, 0x3d, 0xf2],
    ];
    const DOTNETZIP_NET5_SEED: i32 = 2_017_255_694;
    const DOTNETZIP_NET5_ENTRY_SEEDS: [i32; 6] = [996_455_252, 1_882_230_927, 1_281_067_710, 1_343_675_264, 1_090_251_658, 136_200_192];

    /// The headers of `gen_sharpziplib_net9.zip`: the same program on .NET 9, where a
    /// generator that is given no seed takes 256 bits from the system.
    pub(crate) const SHARP_NET9: [[u8; 12]; 6] = [
        [0xd6, 0x95, 0x4b, 0xc0, 0x90, 0xc8, 0x7c, 0xee, 0x41, 0xc1, 0xa3, 0x36],
        [0x85, 0xc6, 0xd6, 0x9f, 0x90, 0x06, 0x42, 0xcf, 0x65, 0xbe, 0x2c, 0x86],
        [0x93, 0x6f, 0x6a, 0x4a, 0x1b, 0xd6, 0xa8, 0xb3, 0x11, 0xaf, 0x82, 0x44],
        [0xce, 0x4d, 0x88, 0x75, 0xc9, 0x1f, 0xf7, 0xb3, 0xf5, 0x78, 0xba, 0xfb],
        [0x43, 0x5b, 0x09, 0x7f, 0x26, 0x1c, 0x74, 0x49, 0xc0, 0xa6, 0x7f, 0x49],
        [0x16, 0x72, 0xd2, 0xb7, 0x5a, 0x84, 0xf7, 0x29, 0xd3, 0xbc, 0x3c, 0xe9],
    ];

    /// The keys of the password of all three archives, `Tr0ub4dor&3xyz`, as bkcrack found
    /// them from the predicted header of one entry (design, section 8.5).
    const KEYS: Keys = Keys::new(0x9f15_e5d8, 0x9569_12eb, 0xfbf5_8431);

    /// The first byte of each header.
    fn first_bytes(headers: &[[u8; 12]]) -> Vec<u8> {
        headers.iter().map(|header| header[0]).collect()
    }

    /// A search on `threads` threads, with what it counted.
    fn run<T>(threads: usize, search: impl FnOnce(Control<'_>) -> T) -> (T, u64) {
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let found = search(Control { stop: &stop, done: &done, threads });
        (found, done.load(Ordering::Relaxed))
    }

    #[test]
    fn the_generator_gives_what_dotnet_gives() {
        for (seed, value, bytes) in DOTNET {
            assert_eq!(Random::new(seed).sample(), value, "seed {seed}");
            let mut random = Random::new(seed);
            assert_eq!(bytes.map(|_| random.byte()), bytes, "seed {seed}");
        }
        // the seeds the runtime gave the generators of the recorded entries, and their bytes
        assert_eq!(entry_seeds(SHARP_NET5_SEED, 0, 6), SHARP_NET5_ENTRY_SEEDS);
        assert_eq!(entry_seeds(DOTNETZIP_NET5_SEED, 0, 6), DOTNETZIP_NET5_ENTRY_SEEDS);
        assert_eq!(entry_seeds(SHARP_NET5_SEED, 2, 4), SHARP_NET5_ENTRY_SEEDS[2..]);
        assert_eq!(header_bytes(1_630_103_928), [0x47, 0xed, 0x31, 0x27, 0x6b, 0xe2, 0x53, 0x54, 0x9d, 0x2f, 0x9c]);
        assert_eq!(header_bytes(136_200_192), [0x16, 0x24, 0x41, 0xe7, 0x39, 0x0e, 0x65, 0x00, 0xec, 0xc9, 0x9c]);
        assert_eq!(Keys::from_password(b"Tr0ub4dor&3xyz"), KEYS);
    }

    #[test]
    fn the_first_value_is_a_line_in_the_seed() {
        let edges = [0, 1, -1, 2, MSEED - 1, MSEED, MSEED + 1, i32::MAX - 1, i32::MAX, i32::MIN, i32::MIN + 1, SHARP_NET5_SEED, -DOTNETZIP_NET5_SEED];
        // a spread over all seeds: an odd step, so that every residue of a small modulus is met
        let spread = (0..4000_i32).map(|step| i32::MIN.wrapping_add(step.wrapping_mul(1_073_741_827)));
        for seed in edges.into_iter().chain(spread) {
            assert_eq!(first_sample(seed), Random::new(seed).sample(), "seed {seed}");
        }
        for value in [0, 1, MODULUS - 1, MODULUS, MODULUS + 1, 2 * MODULUS, (1 << 62) - 1, 0x1234_5678_9abc_def0] {
            assert_eq!(folded(value), value % MODULUS, "{value}");
        }
    }

    #[test]
    fn the_generators_side_by_side_are_the_generator() {
        let last = i32::MAX - i32::try_from(LANES).unwrap() + 1;
        // the ends, around the constant the seed is taken from, and a spread over all seeds
        let spread = (1..60).map(|step| step * 35_000_011);
        for base in [0, 5, MSEED - 3, last].into_iter().chain(spread) {
            let seeds: Lanes = std::array::from_fn(|lane| base + i32::try_from(lane).unwrap());
            let mut state = set_up(seeds);
            let mut single = seeds.map(Random::new);
            // past the first round of the ring, where the places wrap
            for number in 1..=70 {
                let values = next_values(&mut state, number);
                assert_eq!(values.to_vec(), single.iter_mut().map(Random::sample).collect::<Vec<_>>(), "from {base}, value {number}");
            }
        }
    }

    #[test]
    fn the_seed_of_the_recorded_archives_is_found_in_a_slice_that_holds_it() {
        for (headers, seed) in [(&SHARP_NET5, SHARP_NET5_SEED), (&DOTNETZIP_NET5, DOTNETZIP_NET5_SEED)] {
            let first = first_bytes(headers);
            let at = seed.unsigned_abs();
            for threads in [1, 4] {
                let (found, done) = run(threads, |control| thread_seeds(&first, at - 1000..at + 1001, POSITIONS, control));
                assert_eq!(found, [Found { thread_seed: seed, position: 0 }]);
                assert_eq!(done, 2001);
            }
            // the header bytes the seed gives are those the keys of the archive decrypt
            let found = Found { thread_seed: seed, position: 0 };
            for (predicted, written) in found.headers(6).iter().zip(headers) {
                let mut keys = KEYS;
                let plain = written.map(|byte| keys.decrypt(byte));
                assert_eq!(plain[..HEADER_BYTES], predicted[..]);
            }
            // the archive written on .NET 9 gives no seed in the same slice
            assert_eq!(run(4, |control| thread_seeds(&first_bytes(&SHARP_NET9), at - 1000..at + 1001, POSITIONS, control)).0, []);
        }
    }

    #[test]
    fn a_first_entry_further_into_the_sequence_is_found_at_its_place() {
        // the last four entries of the archive: two generators were made before theirs
        let first = first_bytes(&SHARP_NET5[2..]);
        let at = SHARP_NET5_SEED.unsigned_abs();
        let (found, _) = run(2, |control| thread_seeds(&first, at - 20..at + 20, POSITIONS, control));
        assert_eq!(found, [Found { thread_seed: SHARP_NET5_SEED, position: 2 }]);
        assert_eq!(found[0].entry_seeds(4), SHARP_NET5_ENTRY_SEEDS[2..]);
        // and is not found when fewer places are searched
        assert_eq!(run(2, |control| thread_seeds(&first, at - 20..at + 20, 2, control)).0, []);
        assert!(fits(SHARP_NET5_SEED, 2, &first));
        assert!(!fits(SHARP_NET5_SEED, 1, &first));
    }

    /// The search against the generators themselves, seed by seed and place by place, with
    /// two and three entries: enough seeds fit to see every one of them.
    #[test]
    fn the_search_finds_what_the_generators_give_seed_by_seed() {
        const PLACES: u32 = 3;
        for start in [0_u32, THREAD_SEEDS - 200, 1_000_003] {
            let range = start..start.saturating_add(200).min(THREAD_SEEDS);
            // the first byte of the generator of every entry that a seed can give at these places
            let drawn: Vec<(i32, Vec<u8>)> = range.clone().map(|seed| i32::try_from(seed).unwrap()).map(|seed| (seed, entry_seeds(seed, 0, 5).into_iter().map(|seed| Random::new(seed).byte()).collect())).collect();
            for first in [&[0x5a_u8, 0x18][..], &[0x00, 0x00, 0x00], &[0x23, 0xa6, 0x60]] {
                let fits_at = |bytes: &[u8], position: u32| bytes.iter().skip(usize::try_from(position).unwrap()).zip(first).map(|(drawn, written)| drawn ^ written).collect::<Vec<_>>().windows(2).all(|pair| pair.first() == pair.last());
                let slow: Vec<Found> = drawn.iter().flat_map(|(seed, bytes)| (0..PLACES).filter(|&position| fits_at(bytes, position)).map(|position| Found { thread_seed: *seed, position })).collect();
                let (fast, done) = run(3, |control| thread_seeds(first, range.clone(), PLACES, control));
                assert_eq!(fast, slow, "from {start} for {first:02x?}");
                assert!(slow.iter().all(|found| fits(found.thread_seed, found.position, first)));
                assert_eq!(done, u64::from(range.end - range.start));
            }
        }
    }

    #[test]
    fn nothing_to_test_finds_nothing() {
        assert_eq!(run(1, |control| thread_seeds(&[0x5a], 0..1000, POSITIONS, control)), (Vec::new(), 0));
        assert_eq!(run(1, |control| thread_seeds(&[0x5a, 0x18], 0..1000, 0, control)), (Vec::new(), 0));
        assert_eq!(run(1, |control| thread_seeds(&[0x5a, 0x18], 1000..1000, POSITIONS, control)), (Vec::new(), 0));
        // a range past the last seed is cut to the seeds there are
        assert_eq!(run(1, |control| thread_seeds(&first_bytes(&SHARP_NET5), THREAD_SEEDS - 10..u32::MAX, POSITIONS, control)), (Vec::new(), 10));
        // a search that was stopped
        let (stop, done) = (AtomicBool::new(true), AtomicU64::new(0));
        assert_eq!(thread_seeds(&first_bytes(&SHARP_NET5), 0..THREAD_SEEDS, POSITIONS, Control { stop: &stop, done: &done, threads: 2 }), []);
        assert_eq!(done.load(Ordering::Relaxed), 0);
    }

    #[test]
    #[ignore = "searches all 2^31 thread seeds at eight places"]
    fn the_seed_of_a_recorded_archive_is_the_only_one_among_all() {
        let started = std::time::Instant::now();
        let (found, done) = run(16, |control| thread_seeds(&first_bytes(&SHARP_NET5), 0..THREAD_SEEDS, POSITIONS, control));
        eprintln!("all thread seeds at {POSITIONS} places: {:.1} s", started.elapsed().as_secs_f64());
        assert_eq!(found, [Found { thread_seed: SHARP_NET5_SEED, position: 0 }]);
        assert_eq!(done, u64::from(THREAD_SEEDS));
    }
}
