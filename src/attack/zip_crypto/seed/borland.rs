//! The `rand()` of the C runtime of Borland, which WinRAR up to 3.20 fills the encryption
//! headers of its ZIP archives from.
//!
//! WinRAR writes ZIP archives with the code of Info-ZIP, and its header is the one of `zip`:
//! ten bytes of `rand()`, encrypted twice, and two check bytes. What differs between its
//! versions is the compiler they were built with, and with it the generator.
//!
//! - **Up to 3.20 it is the generator of Borland**: 32 bits of state of which bits 16 to 30
//!   are given.
//!
//!   ```text
//!   srand(s):  state = s;  rand()
//!   rand():    state = 22695477 * state + 1;  return (state >> 16) & 0x7fff
//!   ```
//!
//! - **`srand` draws one value and throws it away**, so the first header starts one step
//!   behind the seed. The seed is the time exclusive-or the number of the process, as `zip`
//!   seeds everywhere.
//! - **The top bit of the state never reaches a value**, as with the runtime of Microsoft
//!   ([`super::msvcrt`]): a seed and the same seed with its top bit turned give the same
//!   values, and there are 2^31 streams.
//! - **WinRAR 3.20 puts each byte through the table of the CRC-32** before it encrypts it:
//!   for the byte `r` that `zip` would take, the entry of `r`, shifted down by the low two
//!   bits of `r`, exclusive-or `r`. Only 175 of the 256 byte values come out of that.
//!   [`Mixed`] is the generator read that way.
//!
//! Measured on archives of 2.90, 3.00 and 3.20. From 3.51 to 4.01 WinRAR takes the ten bytes
//! from a hash of two clocks and encrypts them once, which no path here reaches, and from
//! 4.20 on it is built with the compiler of Microsoft and draws from the generator of
//! [`super::msvcrt`] again.

use std::sync::LazyLock;

use archivewolf_zip_crypto::Keys;

use super::Generator;
use super::header_byte;

/// The multiplier and the increment of the generator.
const MULTIPLIER: u32 = 22_695_477;
const INCREMENT: u32 = 1;

/// The generator as WinRAR leaves it after it was seeded: one value on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rand {
    state: u32,
}

impl Rand {
    /// One step of the state.
    const fn stepped(state: u32) -> u32 {
        state.wrapping_mul(MULTIPLIER).wrapping_add(INCREMENT)
    }
}

impl Generator for Rand {
    fn seeded(seed: u32) -> Self {
        Self { state: Self::stepped(seed) }
    }

    /// The next value of `rand()`: below 2^15.
    fn rand(&mut self) -> u32 {
        self.state = Self::stepped(self.state);
        (self.state >> 16) & 0x7fff
    }

    fn stream_of(seed: u32) -> u32 {
        seed & 0x7fff_ffff
    }
}

/// The table of the CRC-32.
static CRC: LazyLock<[u32; 256]> = LazyLock::new(|| {
    std::array::from_fn(|byte| {
        let mut keys = Keys::new(0, 0, 0);
        // the first key after a byte, from a first key of zero, is the entry of the byte
        keys.update(u8::try_from(byte).unwrap_or_default());
        keys.x
    })
});

/// What WinRAR 3.20 makes of the byte `zip` takes of a value: the entry of the byte in the
/// table of the CRC-32, shifted down by the low two bits of the byte, exclusive-or the byte.
fn mixed(byte: u8) -> u8 {
    let entry = CRC.get(usize::from(byte)).copied().unwrap_or_default();
    (entry >> (byte & 3)).to_le_bytes()[0] ^ byte
}

/// The generator as WinRAR 3.20 reads it: its values are made so that the byte `zip` takes
/// of each, bits 7 to 14, is the byte WinRAR 3.20 puts into a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mixed {
    rand: Rand,
}

impl Generator for Mixed {
    fn seeded(seed: u32) -> Self {
        Self { rand: Rand::seeded(seed) }
    }

    fn rand(&mut self) -> u32 {
        u32::from(mixed(header_byte(self.rand.rand()))) << 7
    }

    fn stream_of(seed: u32) -> u32 {
        Rand::stream_of(seed)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::attack::zip_crypto::seed::fits;
    use crate::attack::zip_crypto::seed::header_bytes;
    use crate::attack::zip_crypto::seed::infozip;
    use crate::attack::zip_crypto::seed::infozip::HEADER_LEN;

    use crate::attack::zip_crypto::seed::msvcrt;

    /// The fixture `gen_winrar_290.zip`: six entries written by WinRAR 2.90 on Windows
    /// Server 2022, under this password,
    const PASSWORD: &[u8] = b"winrar-headers";
    /// the encryption header of each, in archive order,
    pub(crate) const HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0x62, 0xfd, 0xc4, 0x07, 0x7e, 0xa5, 0x62, 0xad, 0x45, 0x4e, 0xcc, 0x50],
        [0xc5, 0x4a, 0x8d, 0xad, 0x4f, 0xd4, 0x1c, 0x06, 0x06, 0x5c, 0x08, 0xd3],
        [0x41, 0x9b, 0xab, 0xfc, 0xcc, 0xdc, 0x71, 0xb9, 0xf9, 0xbf, 0xbe, 0xc6],
        [0x76, 0x58, 0x4a, 0xea, 0x56, 0x86, 0xde, 0xce, 0xcc, 0xea, 0xe9, 0xdd],
        [0x70, 0x2b, 0xa0, 0x5d, 0xb3, 0xc6, 0x35, 0xaf, 0x2b, 0x05, 0xa8, 0x84],
        [0x5c, 0x44, 0x5d, 0x97, 0xbb, 0x62, 0x9a, 0xe7, 0x6c, 0xa2, 0xca, 0x63],
    ];
    /// and the seed of the run that wrote them: the time, exclusive-or the number of the
    /// process. The program that started WinRAR wrote down the second before, 1,795,284,069,
    /// and the process number 6212.
    const SEED: u32 = 1_795_277_858;

    #[test]
    fn the_generator_gives_the_values_of_the_runtime() {
        // the values every program of Turbo C and Borland C++ gives when it never seeds: its
        // state starts at one
        let mut rand = Rand { state: 1 };
        assert_eq!([(); 6].map(|()| rand.rand()), [346, 130, 10_982, 1090, 11_656, 7117]);
        // a seed is one step in front of the state its first value is made of
        let mut seeded = Rand::seeded(0);
        assert_eq!(seeded.state, 1);
        assert_eq!(seeded.rand(), 346);
        assert_eq!([Rand::stream_of(5), Rand::stream_of(0x8000_0005), Rand::stream_of(0xffff_ffff)], [5, 5, 0x7fff_ffff]);
        let (mut low, mut high) = (Rand::seeded(0x1234_5678), Rand::seeded(0x9234_5678));
        assert_eq!([(); 8].map(|()| low.rand()), [(); 8].map(|()| high.rand()));
    }

    #[test]
    fn the_seed_of_the_recorded_archive_gives_its_headers_under_its_password() {
        let first: Vec<u8> = HEADERS.iter().map(|header| header[0]).collect();
        assert!(fits::<Rand>(SEED, &first));
        // of the 2^16 seeds around it, no other does
        let near: Vec<u32> = ((SEED & !0xffff)..=(SEED | 0xffff)).filter(|seed| fits::<Rand>(*seed, &first)).collect();
        assert_eq!(near, [SEED]);
        // the seed is the time the archive was written at, with the number of its process over it
        let (time, process): (u32, u32) = (1_795_284_070, 6212);
        assert_eq!(SEED, time ^ process);
        // the bytes of the generator, encrypted twice under the password, are the ten bytes
        // that stand in the archive, in every entry
        let keys = Keys::from_password(PASSWORD);
        for (random, header) in header_bytes::<Rand>(SEED, HEADERS.len()).iter().zip(&HEADERS) {
            assert!(infozip::fits(keys, random, header), "{header:02x?}");
        }
        // and not those of the generator of Microsoft, which later versions draw from
        let other = header_bytes::<msvcrt::Rand>(SEED, 1);
        assert!(!infozip::fits(keys, &other[0], &HEADERS[0]));
    }

    /// The fixture `gen_winrar_320.zip`: the same six files under the same password, written
    /// by WinRAR 3.20 as the process 6100 at the second 1,795,284,070.
    pub(crate) const MIXED_HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0x55, 0x26, 0x75, 0xab, 0xe2, 0x56, 0x10, 0x5e, 0xbd, 0x29, 0xda, 0xd0],
        [0x8f, 0xc3, 0xeb, 0x46, 0xd3, 0x65, 0xcd, 0xd7, 0x07, 0xb1, 0x5c, 0x0a],
        [0x48, 0xb8, 0xfc, 0xed, 0xc2, 0x7c, 0x41, 0xee, 0xcc, 0x93, 0x48, 0xe3],
        [0x43, 0xdc, 0xd7, 0xe7, 0x5d, 0x6d, 0xf7, 0xbe, 0xdd, 0x57, 0x16, 0x07],
        [0x0e, 0x4f, 0xb2, 0xca, 0x54, 0x02, 0xfd, 0x33, 0x65, 0xe4, 0x1a, 0xeb],
        [0xf8, 0x79, 0x3f, 0xa1, 0x4a, 0xb4, 0xbc, 0x0a, 0xe3, 0x38, 0xba, 0x7d],
    ];

    #[test]
    fn winrar_3_20_puts_each_byte_through_the_table_of_the_crc() {
        // the first bytes of the map, and how many byte values it reaches
        assert_eq!([0, 1, 2, 3, 4, 5, 6, 7].map(mixed), [0, 74, 73, 52, 29, 66, 75, 179]);
        let mut reached: Vec<u8> = (0..=255).map(mixed).collect();
        reached.sort_unstable();
        reached.dedup();
        assert_eq!(reached.len(), 175);
        // the archive: its seed is the time exclusive-or the process number, and no other of
        // the 2^16 seeds around it gives its first bytes
        let (time, process): (u32, u32) = (1_795_284_070, 6100);
        let seed = time ^ process;
        let first: Vec<u8> = MIXED_HEADERS.iter().map(|header| header[0]).collect();
        let near: Vec<u32> = ((seed & !0xffff)..=(seed | 0xffff)).filter(|seed| fits::<Mixed>(*seed, &first)).collect();
        assert_eq!(near, [seed]);
        assert!(!fits::<Rand>(seed, &first));
        let keys = Keys::from_password(PASSWORD);
        for (random, header) in header_bytes::<Mixed>(seed, MIXED_HEADERS.len()).iter().zip(&MIXED_HEADERS) {
            assert!(infozip::fits(keys, random, header), "{header:02x?}");
        }
        assert_eq!(Mixed::stream_of(0x8000_0005), 5);
    }
}
