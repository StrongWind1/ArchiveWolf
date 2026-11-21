//! The `rand()` of musl, the C library of Alpine Linux and of most programs that are linked
//! into one file.
//!
//! It is a generator of 64 bits of state of which the top 31 are given (`src/prng/rand.c`):
//!
//! ```text
//! srand(s):  state = s - 1
//! rand():    state = 6364136223846793005 * state + 1;  return state >> 33
//! ```
//!
//! The seed less one is worked out as a word of 32 bits, so a seed of zero is the state
//! 2^32 - 1. Every seed has a state of its own, and no two give the same values.

use super::Generator;

/// The multiplier of the generator.
const MULTIPLIER: u64 = 6_364_136_223_846_793_005;

/// The generator after `srand(seed)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rand {
    state: u64,
}

impl Generator for Rand {
    fn seeded(seed: u32) -> Self {
        Self { state: u64::from(seed.wrapping_sub(1)) }
    }

    /// The next value of `rand()`: below 2^31.
    fn rand(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(MULTIPLIER).wrapping_add(1);
        u32::try_from(self.state >> 33).unwrap_or_default()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use archivewolf_zip_crypto::Keys;

    use super::*;
    use crate::attack::zip_crypto::seed::fits;
    use crate::attack::zip_crypto::seed::header_bytes;
    use crate::attack::zip_crypto::seed::infozip;
    use crate::attack::zip_crypto::seed::infozip::HEADER_LEN;

    /// The fixture `gen_infozip_musl.zip`: six entries written by `zip -e -P` of Info-ZIP 3.0
    /// that was built against musl, under this password,
    const PASSWORD: &[u8] = b"musl-headers";
    /// the encryption header of each, in archive order,
    pub(crate) const HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0x92, 0x1a, 0x54, 0xfe, 0x1f, 0xdf, 0x94, 0x43, 0x9f, 0xb3, 0x14, 0x66],
        [0xec, 0x3c, 0xac, 0x79, 0x45, 0x14, 0xee, 0x35, 0x0c, 0x6d, 0x20, 0x8b],
        [0x57, 0xae, 0x4d, 0x09, 0x1e, 0xf8, 0x87, 0x73, 0x3c, 0xfa, 0xfd, 0x40],
        [0x49, 0xe8, 0xbf, 0xae, 0xfb, 0x68, 0xed, 0xbd, 0x5c, 0xf3, 0xb2, 0xaf],
        [0xa9, 0xdd, 0x61, 0x7b, 0x3f, 0x11, 0xc0, 0xed, 0xf9, 0x44, 0x77, 0x77],
        [0x95, 0xf5, 0x1e, 0x0e, 0xa0, 0xe8, 0x76, 0xdf, 0xaa, 0x13, 0x5d, 0xa4],
    ];
    /// and the seed of the run that wrote them.
    const SEED: u32 = 1_797_846_278;

    #[test]
    fn the_generator_gives_the_values_of_musl() {
        // what a program that was linked with musl 1.2.5 printed for these seeds
        let printed: [(u32, [u32; 6]); 6] = [
            (0, [2_049_033_599, 2_025_915_578, 1_407_788_582, 829_275_321, 1_509_453_734, 681_666_918]),
            (1, [0, 740_882_966, 1_616_430_695, 1_708_849_955, 1_669_437_588, 406_334_850]),
            (2, [740_882_966, 1_616_430_695, 1_708_849_955, 1_669_437_588, 406_334_850, 276_737_754]),
            (0x5af8_5096, [1_047_003_882, 1_687_369_892, 1_137_303_437, 536_954_940, 1_195_388_949, 1_644_374_844]),
            (0x7fff_ffff, [2_060_675_997, 1_143_819_502, 299_738_925, 1_328_181_187, 262_874_297, 738_396_528]),
            (0xffff_ffff, [1_308_150_633, 1_150_367_849, 1_315_369_323, 868_687_688, 625_072_825, 811_264_014]),
        ];
        for (seed, values) in printed {
            let mut rand = Rand::seeded(seed);
            assert_eq!(values.map(|_| rand.rand()), values, "{seed}");
            assert_eq!(Rand::stream_of(seed), seed);
        }
    }

    #[test]
    fn the_seed_of_the_recorded_archive_gives_its_headers_under_its_password() {
        let first: Vec<u8> = HEADERS.iter().map(|header| header[0]).collect();
        assert!(fits::<Rand>(SEED, &first));
        // no other seed of the 2^16 around it does
        let near: Vec<u32> = ((SEED & !0xffff)..=(SEED | 0xffff)).filter(|seed| fits::<Rand>(*seed, &first)).collect();
        assert_eq!(near, [SEED]);
        // the bytes of the generator, encrypted twice under the password, are the ten bytes
        // that stand in the archive, in every entry
        let keys = Keys::from_password(PASSWORD);
        for (random, header) in header_bytes::<Rand>(SEED, HEADERS.len()).iter().zip(&HEADERS) {
            assert!(infozip::fits(keys, random, header), "{header:02x?}");
        }
        assert!(!infozip::fits(keys, &header_bytes::<Rand>(SEED + 1, 1)[0], &HEADERS[0]));
    }
}
