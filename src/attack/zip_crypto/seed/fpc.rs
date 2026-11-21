//! The `Random()` of Free Pascal, which Abbrevia fills its encryption headers from in the
//! zip plugin of Double Commander.
//!
//! Abbrevia makes a header as Info-ZIP does: ten bytes of a generator, encrypted twice from
//! the keys after the password, and two check bytes (`AbDfCryS.pas`, `CreateHeader`). Each
//! of the ten is `Random(256)`.
//!
//! - **The generator of Free Pascal 3.2 is the Mersenne Twister.** `Random(256)` is the top
//!   byte of its next word (`system.inc`, `random` and `genrand_MT19937`).
//! - **It starts from `RandSeed`, which is zero until a program calls `Randomize`.** Abbrevia
//!   never does, and neither does the plugin. The plugin is a library of its own, with a
//!   run-time library of its own, so nothing the program around it does reaches its seed.
//! - **So the headers of the plugin are one sequence, the same on every machine.** The first
//!   encrypted entry it writes after it is loaded gets the first ten bytes, the next entry
//!   the next ten, in whatever archive.
//!
//! What is not known of an archive is how many encrypted entries the plugin had written
//! before, in the same run of Double Commander. The first byte of every header stands in
//! the archive as it was drawn, as with Info-ZIP ([`super::infozip`]), and tells it.

/// How many bytes of an encryption header come from the generator.
pub const HEADER_BYTES: usize = 10;

/// How many words the generator holds.
const WORDS: usize = 624;

/// How far apart the two words lie that a new word is made of.
const APART: usize = 397;

/// The generator of Free Pascal after its seed was set: MT19937, seeded from one word.
#[derive(Debug, Clone)]
pub struct Rand {
    state: [u32; WORDS],
    /// The next word to give out, or [`WORDS`] when all are used.
    at: usize,
}

impl Rand {
    /// The generator as a value of `RandSeed` leaves it.
    #[must_use]
    pub fn new(seed: u32) -> Self {
        let mut state = [0_u32; WORDS];
        let mut last = seed;
        for (index, word) in (0_u32..).zip(&mut state) {
            if index > 0 {
                last = 1_812_433_253_u32.wrapping_mul(last ^ (last >> 30)).wrapping_add(index);
            }
            *word = last;
        }
        Self { state, at: WORDS }
    }

    /// Make the next 624 words from the last.
    fn refill(&mut self) {
        for index in 0..WORDS {
            let word = |at: usize| self.state.get(at % WORDS).copied().unwrap_or_default();
            let mixed = (word(index) & 0x8000_0000) | (word(index + 1) & 0x7fff_ffff);
            let next = word(index + APART) ^ (mixed >> 1) ^ if mixed & 1 == 1 { 0x9908_b0df } else { 0 };
            if let Some(slot) = self.state.get_mut(index) {
                *slot = next;
            }
        }
        self.at = 0;
    }

    /// The next word of the generator.
    pub fn word(&mut self) -> u32 {
        if self.at >= WORDS {
            self.refill();
        }
        let mut word = self.state.get(self.at).copied().unwrap_or_default();
        self.at += 1;
        word ^= word >> 11;
        word ^= (word << 7) & 0x9d2c_5680;
        word ^= (word << 15) & 0xefc6_0000;
        word ^ (word >> 18)
    }

    /// The next `Random(256)`: the top byte of a word.
    pub fn byte(&mut self) -> u8 {
        self.word().to_be_bytes()[0]
    }
}

/// The ten bytes of each of `count` headers that are drawn after a seed, behind `before`
/// headers that were drawn in front of them.
#[must_use]
pub fn headers(seed: u32, before: usize, count: usize) -> Vec<[u8; HEADER_BYTES]> {
    let mut rand = Rand::new(seed);
    for _ in 0..before * HEADER_BYTES {
        let _ = rand.word();
    }
    (0..count).map(|_| std::array::from_fn(|_| rand.byte())).collect()
}

/// How many headers were drawn in front of those of an archive: `first` has the first byte
/// of each of its headers, in the order they were written, and the answer is the smallest
/// count below `most` after which the generator gives them all. `None` when there is none.
///
/// Each header is eight bits of test. Four leave one count in 2^32 that fits by chance.
#[must_use]
pub fn drawn_before(seed: u32, first: &[u8], most: usize) -> Option<usize> {
    if first.is_empty() {
        return None;
    }
    let mut rand = Rand::new(seed);
    // the first byte of every header that can be asked for
    let drawn: Vec<u8> = (0..most + first.len())
        .map(|_| {
            let byte = rand.byte();
            for _ in 1..HEADER_BYTES {
                let _ = rand.word();
            }
            byte
        })
        .collect();
    drawn.windows(first.len()).take(most).position(|window| window == first)
}

#[cfg(test)]
pub(crate) mod tests {
    use archivewolf_zip_crypto::Keys;

    use super::*;
    use crate::attack::zip_crypto::seed::infozip;

    /// The fixtures `gen_doublecmd_first.zip` and `gen_doublecmd_second.zip`: six entries
    /// each, written one archive after the other by the zip plugin of Double Commander
    /// 1.1.22 in one load of it, under the password `doublecmd-headers`.
    pub(crate) const FIRST_HEADERS: [[u8; 12]; 6] = [
        [0x8c, 0xdc, 0x8c, 0xb9, 0xa6, 0x25, 0x6f, 0x4a, 0xa9, 0x44, 0xfc, 0x02],
        [0xa5, 0xab, 0x0b, 0x5b, 0x30, 0xcf, 0x89, 0xf3, 0x33, 0x29, 0x59, 0xe8],
        [0xca, 0xd3, 0xfd, 0x38, 0x3f, 0xea, 0xf5, 0xe2, 0xed, 0x75, 0x6a, 0x4d],
        [0x16, 0x2c, 0xc4, 0xba, 0x07, 0x37, 0x94, 0xa9, 0x33, 0xd1, 0x86, 0xd1],
        [0xfa, 0x01, 0x37, 0xa4, 0xe5, 0xbb, 0xe9, 0xb2, 0x04, 0x57, 0x77, 0x22],
        [0xa3, 0x3d, 0x63, 0x61, 0x33, 0xeb, 0x2a, 0x95, 0x79, 0xa3, 0xe0, 0x78],
    ];
    pub(crate) const SECOND_HEADERS: [[u8; 12]; 6] = [
        [0x43, 0xaa, 0x8c, 0x99, 0xf7, 0xdd, 0xa3, 0x74, 0x74, 0x22, 0x2e, 0x37],
        [0x9e, 0xb7, 0x72, 0x7d, 0xe9, 0xcb, 0x1d, 0x12, 0xed, 0xfb, 0x9a, 0xeb],
        [0x5c, 0x15, 0xfc, 0xc5, 0x5c, 0xf4, 0x74, 0xdb, 0x57, 0xc4, 0x5e, 0x9f],
        [0xab, 0x2b, 0x1c, 0xdf, 0x4a, 0x95, 0x2f, 0x18, 0x3d, 0x49, 0xae, 0x2a],
        [0x91, 0xe1, 0xdc, 0x68, 0x0d, 0x29, 0xf5, 0xf3, 0xed, 0x51, 0x1b, 0x58],
        [0x29, 0x75, 0x74, 0xf0, 0x74, 0xba, 0xf9, 0xe6, 0xc0, 0x3d, 0x66, 0x7e],
    ];

    #[test]
    fn the_generator_gives_the_words_of_the_mersenne_twister() {
        // the first word after the seed 5489, and the ten thousandth, which the C++ standard
        // names for this generator
        let mut rand = Rand::new(5489);
        assert_eq!(rand.word(), 3_499_211_612);
        let mut last = 0;
        for _ in 1..10_000 {
            last = rand.word();
        }
        assert_eq!(last, 4_123_659_995);
        // and the first after a seed of zero, which is where a program of Free Pascal starts
        assert_eq!(Rand::new(0).word(), 2_357_136_044);
        assert_eq!(Rand::new(0).byte(), 0x8c);
    }

    #[test]
    fn the_headers_of_the_plugin_are_the_sequence_from_a_seed_of_zero_under_its_password() {
        // each header of both archives is the ten bytes of the generator, in the order the
        // entries were written, encrypted twice as Info-ZIP does it: the check bytes are the
        // DOS time of the entries, 024E
        let start = Keys::from_password(b"doublecmd-headers");
        let drawn = headers(0, 0, 12);
        for (random, header) in drawn.iter().zip(FIRST_HEADERS.iter().chain(&SECOND_HEADERS)) {
            assert_eq!(infozip::header(start, random, [0x4e, 0x02]), *header);
        }
        // the second archive starts where the first ended
        assert_eq!(headers(0, 6, 6), drawn[6..]);
    }

    #[test]
    fn the_first_bytes_of_the_headers_say_how_many_were_drawn_before() {
        let first = |headers: &[[u8; 12]; 6]| -> Vec<u8> { headers.iter().map(|header| header[0]).collect() };
        assert_eq!(drawn_before(0, &first(&FIRST_HEADERS), 1 << 16), Some(0));
        assert_eq!(drawn_before(0, &first(&SECOND_HEADERS), 1 << 16), Some(6));
        // not within fewer headers than were drawn, not with another seed, and not for no entry
        assert_eq!(drawn_before(0, &first(&SECOND_HEADERS), 6), None);
        assert_eq!(drawn_before(1, &first(&FIRST_HEADERS), 1 << 16), None);
        assert_eq!(drawn_before(0, &[], 1 << 16), None);
        // a sequence that lies far in: the headers of entries 50,000 to 50,003
        let far: Vec<u8> = headers(0, 50_000, 4).iter().map(|header| header[0]).collect();
        assert_eq!(drawn_before(0, &far, 1 << 16), Some(50_000));
    }
}
