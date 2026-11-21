//! The `rand()` of macOS, which the `zip` of macOS fills its encryption headers from.
//!
//! The `zip` command of macOS is Info-ZIP's, built against the C library of the system. That
//! library has the `rand()` of 4.4BSD as FreeBSD carried it until its release 10: the
//! "minimal standard" generator of Park and Miller, whose state is the value it last gave,
//!
//! ```text
//! next = 16807 * state mod (2^31 - 1)
//! ```
//!
//! worked out without a word of 64 bits, by the method of Schrage, and with one rule beside
//! it: a state of zero, which the multiplication would never leave, is taken for 123459876.
//! `srand(seed)` puts the seed in the place of the state as it is. A seed and the same seed
//! with 2^31 - 1 added to it give the same first value, and with it every value after: of the
//! 2^32 seeds, three or two each give one stream.
//!
//! Info-ZIP seeds it once for a run with the time exclusive-or the number of its process, and
//! draws ten values for each encrypted entry, of each of which it takes bits 7 to 14
//! ([`super::glibc`] has the same for the generator of glibc, and [`super::infozip`] what
//! becomes of the bytes). The first byte of every header is such a byte as it was drawn.

use super::Generator;

/// The modulus of the generator, a prime: 2^31 - 1.
pub const MODULUS: u64 = 0x7fff_ffff;

/// Its multiplier: 7^5.
const MULTIPLIER: u64 = 16_807;

/// The state that stands for a state of zero.
const IN_PLACE_OF_ZERO: u64 = 123_459_876;

/// The generator after `srand(seed)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rand {
    state: u64,
}

impl Generator for Rand {
    fn seeded(seed: u32) -> Self {
        Self { state: u64::from(seed) }
    }

    /// The next value of `rand()`: below 2^31 - 1.
    fn rand(&mut self) -> u32 {
        if self.state == 0 {
            self.state = IN_PLACE_OF_ZERO;
        }
        // what the C code works out in two halves, so that it fits a word of 32 bits, is this
        // product for every state a seed of 32 bits can give
        self.state = self.state * MULTIPLIER % MODULUS;
        u32::try_from(self.state).unwrap_or_default()
    }

    fn stream_of(seed: u32) -> u32 {
        // zero is taken for another state, and 2^31 - 1 and its double step to the same zero
        let state = if seed == 0 { IN_PLACE_OF_ZERO } else { u64::from(seed) % MODULUS };
        u32::try_from(state).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use archivewolf_zip_crypto::Keys;

    use super::*;
    use crate::attack::zip_crypto::seed::Control;
    use crate::attack::zip_crypto::seed::fits;
    use crate::attack::zip_crypto::seed::header_bytes;
    use crate::attack::zip_crypto::seed::infozip;
    use crate::attack::zip_crypto::seed::seeds;
    use crate::attack::zip_crypto::seed::stay;

    const SEEDS: u64 = 1 << 32;
    const PIECE: u64 = 1 << 16;

    fn stream_of(seed: u32) -> u32 {
        Rand::stream_of(seed)
    }

    #[test]
    fn the_generator_gives_the_values_of_the_minimal_standard() {
        // the first values after a seed of one, as Park and Miller give them; the ten
        // thousandth is the check value of their paper
        let mut rand = Rand::seeded(1);
        assert_eq!([rand.rand(), rand.rand(), rand.rand(), rand.rand(), rand.rand()], [16_807, 282_475_249, 1_622_650_073, 984_943_658, 1_144_108_930]);
        let mut rand = Rand::seeded(1);
        let mut last = 0;
        for _ in 0..10_000 {
            last = rand.rand();
        }
        assert_eq!(last, 1_043_618_065);
    }

    #[test]
    fn the_product_is_what_the_c_code_works_out_in_two_halves() {
        // `do_rand` of the C library, on a word of 64 bits as macOS has it
        let c_code = |state: u64| -> u64 {
            let state = i64::try_from(if state == 0 { IN_PLACE_OF_ZERO } else { state }).unwrap();
            let (hi, lo) = (state / 127_773, state % 127_773);
            let x = 16_807 * lo - 2836 * hi;
            u64::try_from(if x < 0 { x + 0x7fff_ffff } else { x }).unwrap()
        };
        // every kind of seed: small, around the modulus and its double, and the largest
        let seeds = [0_u32, 1, 2, 127_772, 127_773, 0x7fff_fffe, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_fffd, 0xffff_fffe, 0xffff_ffff, 1_526_274_454];
        for seed in seeds.into_iter().chain((0..2000).map(|step| 0x0123_4567_u32.wrapping_mul(step * 2 + 1))) {
            let mut rand = Rand::seeded(seed);
            let mut state = u64::from(seed);
            for _ in 0..12 {
                state = c_code(state);
                assert_eq!(u64::from(rand.rand()), state, "{seed}");
            }
        }
    }

    #[test]
    fn seeds_of_one_stream_are_told_by_the_smallest_of_them() {
        assert_eq!([stream_of(1), stream_of(0x8000_0000), stream_of(0xffff_ffff)], [1, 1, 1]);
        assert_eq!(header_bytes::<Rand>(1, 3), header_bytes::<Rand>(0x8000_0000, 3));
        assert_eq!(header_bytes::<Rand>(1, 3), header_bytes::<Rand>(0xffff_ffff, 3));
        assert_ne!(header_bytes::<Rand>(1, 3), header_bytes::<Rand>(2, 3));
        // zero stands for the state it is taken for, and the modulus steps to zero
        assert_eq!(stream_of(0), 123_459_876);
        assert_eq!(header_bytes::<Rand>(0, 2), header_bytes::<Rand>(123_459_876, 2));
        assert_eq!(stream_of(0x7fff_ffff), 0);
    }

    /// A seed as `zip` makes it: a time of May 2018, exclusive-or a process number of 4711.
    const SEED: u32 = 0x5af8_5096;

    /// The headers of entries that a `zip` seeded with `seed` writes under a password, as
    /// [`infozip::header`] makes them from the bytes of this generator.
    fn written(seed: u32, password: &[u8], entries: usize) -> Vec<stay::Entry> {
        let start = Keys::from_password(password);
        header_bytes::<Rand>(seed, entries).into_iter().zip(0_u8..).map(|(random, number)| stay::Entry { random, header: infozip::header(start, &random, [number, 0x5a]) }).collect()
    }

    #[test]
    fn a_seed_is_found_by_the_first_byte_of_each_header() {
        let seed = SEED;
        let first: Vec<u8> = written(seed, b"a password", 5).iter().map(|entry| entry.header[0]).collect();
        assert!(fits::<Rand>(seed, &first) && !fits::<Rand>(seed + 1, &first));
        // a slice of the seeds that holds it, as the search goes through it
        let piece = u64::from(seed) / PIECE;
        let near: Vec<u32> = (piece * PIECE..(piece + 1) * PIECE).filter_map(|seed| u32::try_from(seed).ok()).filter(|seed| fits::<Rand>(*seed, &first)).collect();
        assert_eq!(near, [seed]);
        assert!(seeds::<Rand>(&[], Control { stop: &AtomicBool::new(false), done: &AtomicU64::new(0), threads: 1 }).is_empty());
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_seed_of_a_run_is_the_only_stream_among_all_and_its_headers_give_the_keys() {
        let seed = SEED;
        let password = b"a password of some length";
        let entries = written(seed, password, 5);
        let first: Vec<u8> = entries.iter().map(|entry| entry.header[0]).collect();
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let control = Control { stop: &stop, done: &done, threads: std::thread::available_parallelism().map_or(1, std::num::NonZero::get) };

        // five entries are 40 bits of test for a stream of 31: the seed and what gives its stream
        let found = seeds::<Rand>(&first, control);
        assert_eq!(done.load(Ordering::Relaxed), SEEDS);
        assert_eq!(found, [seed, seed + 0x7fff_ffff]);
        assert!(found.iter().all(|other| stream_of(*other) == stream_of(seed)));

        // and the attack on the headers gives the keys of the password
        let recovery = stay::recover(&entries, control).unwrap();
        assert_eq!(recovery.keys, [Keys::from_password(password)]);
    }
}
