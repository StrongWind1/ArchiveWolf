//! The `rand()` of the C runtime of Windows, which `zip.exe` and the programs built on
//! minizip fill their encryption headers from there.
//!
//! It is a generator of 32 bits of state of which bits 16 to 30 are given:
//!
//! ```text
//! srand(s):  state = s
//! rand():    state = 214013 * state + 2531011;  return (state >> 16) & 0x7fff
//! ```
//!
//! The top bit of the state never reaches a value: it stays the top bit under the
//! multiplication, and the values end one bit below it. So a seed and the same seed with
//! its top bit turned give the same values, and there are 2^31 streams.
//!
//! `zip.exe` seeds as `zip` does everywhere, with the time exclusive-or the number of its
//! process (`win32/osdep.h`). The library of `zip`, which other programs for Windows call,
//! has no process number of its own to take and seeds with the time exclusive-or a
//! constant, 3141592654, and so does minizip on every system.
//!
//! Three kinds of programs were measured to draw from it on Windows Server 2022:
//!
//! - **`zip.exe` 3.0 as Info-ZIP gave it out**, in 32 and in 64 bits, which carries the
//!   runtime of Visual C++ 6.0 inside itself, and the builds of GnuWin32 and of MinGW, which
//!   call `msvcrt.dll`.
//! - **WinRAR from 4.20 to 7.23**, for an archive under what it calls ZIP legacy encryption:
//!   its ZIP code is that of Info-ZIP, and it seeds as `zip.exe` does. Up to 5.21 every
//!   encrypted ZIP archive it writes is such an archive.
//! - The `zip.exe` of Cygwin and of MSYS2 does not: its `rand()` is that of
//!   [`super::glibc`].

use super::Generator;

/// The multiplier and the increment of the generator.
const MULTIPLIER: u32 = 214_013;
const INCREMENT: u32 = 2_531_011;

/// The generator after `srand(seed)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rand {
    state: u32,
}

impl Generator for Rand {
    fn seeded(seed: u32) -> Self {
        Self { state: seed }
    }

    /// The next value of `rand()`: below 2^15.
    fn rand(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(MULTIPLIER).wrapping_add(INCREMENT);
        (self.state >> 16) & 0x7fff
    }

    fn stream_of(seed: u32) -> u32 {
        seed & 0x7fff_ffff
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

    /// The fixture `gen_infozip_win.zip`: six entries written by `zip.exe -e -P` of Info-ZIP
    /// 3.0 on Windows Server 2022, under this password,
    const PASSWORD: &[u8] = b"win-headers";
    /// the encryption header of each, in archive order,
    pub(crate) const HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0xa1, 0x2e, 0x9b, 0xdc, 0x12, 0xd7, 0x1e, 0xa8, 0x9c, 0x88, 0x79, 0xa3],
        [0x62, 0xb1, 0x25, 0xc9, 0xbd, 0xe1, 0x02, 0xd6, 0x9c, 0x43, 0x67, 0x0a],
        [0x3e, 0xab, 0x31, 0x53, 0x14, 0x4b, 0xc0, 0x72, 0xec, 0x5a, 0x08, 0xd9],
        [0x16, 0x20, 0x80, 0x8f, 0x03, 0xea, 0xdb, 0xa5, 0x89, 0xb6, 0xf2, 0x3f],
        [0x81, 0xf2, 0x83, 0x39, 0x43, 0x5a, 0x23, 0x39, 0x11, 0x9e, 0xe4, 0xc4],
        [0xa0, 0x37, 0x19, 0x8b, 0xfc, 0x6c, 0xac, 0xe7, 0x30, 0xdc, 0x54, 0x3d],
    ];
    /// and the seed of the run that wrote them: the time, exclusive-or a process number.
    const SEED: u32 = 1_795_223_696;

    /// The fixture `gen_infozip_official.zip`: the same six files, written by the `zip.exe`
    /// 3.0 for Windows that Info-ZIP gave out, under the password `zip-official32-headers`,
    pub(crate) const OFFICIAL_HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0xa3, 0xce, 0xe4, 0x62, 0xe1, 0x44, 0xb3, 0x84, 0xd8, 0x83, 0x1c, 0x6f],
        [0x59, 0x1a, 0x53, 0x88, 0xc2, 0x90, 0x85, 0x08, 0xd2, 0xc3, 0x61, 0x5c],
        [0x05, 0x86, 0x37, 0xe5, 0xa3, 0xdb, 0xcc, 0x55, 0x7a, 0x26, 0x1d, 0x42],
        [0x86, 0xe4, 0x9b, 0x60, 0x87, 0x33, 0xb5, 0xbf, 0x26, 0x60, 0x75, 0x46],
        [0x2c, 0xa1, 0x48, 0x6f, 0xe2, 0x1c, 0x41, 0xe4, 0xac, 0x52, 0xbc, 0x0e],
        [0x7a, 0x13, 0x6d, 0x26, 0x66, 0x99, 0x82, 0x20, 0x2e, 0xce, 0x49, 0x32],
    ];
    /// and the fixture `gen_winrar_723.zip`: the same six files, written by WinRAR 7.23
    /// with `-mezl`, under the password `winrar-headers`.
    pub(crate) const WINRAR_HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0x4c, 0x4c, 0xed, 0xd7, 0xe7, 0xb6, 0xf2, 0x43, 0x48, 0xf3, 0x78, 0xc9],
        [0xab, 0xe7, 0x05, 0x77, 0x5d, 0x46, 0x9c, 0xe7, 0x46, 0xe4, 0x12, 0xcf],
        [0xa4, 0x36, 0x83, 0x2e, 0x6b, 0x77, 0x6e, 0x56, 0x4b, 0xdb, 0x1d, 0x96],
        [0xb2, 0x9a, 0xb9, 0x13, 0x40, 0x11, 0x51, 0x44, 0xe3, 0xd0, 0x68, 0xcf],
        [0x13, 0xd3, 0x8c, 0x11, 0x96, 0xfa, 0xb2, 0x93, 0xf1, 0x89, 0x9b, 0x59],
        [0x90, 0xab, 0x65, 0x4f, 0x9b, 0xaf, 0x4e, 0x8f, 0x77, 0x31, 0xba, 0xc5],
    ];

    #[test]
    fn the_generator_gives_the_values_of_the_runtime() {
        // what a program for Windows printed for these seeds, with the runtime of Wine 10.0;
        // the values after a seed of one are those every C runtime of Microsoft is known by,
        // and the archive below was written with the runtime of Windows itself
        let printed: [(u32, [u32; 6]); 6] = [
            (0, [38, 7719, 21_238, 2437, 8855, 11_797]),
            (1, [41, 18_467, 6334, 26_500, 19_169, 15_724]),
            (2, [45, 29_216, 24_198, 17_795, 29_484, 19_650]),
            (0x5af8_5096, [22_119, 2887, 19_407, 11_951, 4821, 4482]),
            (0x7fff_ffff, [35, 29_739, 3374, 11_141, 31_308, 7870]),
            (0xffff_ffff, [35, 29_739, 3374, 11_141, 31_308, 7870]),
        ];
        for (seed, values) in printed {
            let mut rand = Rand::seeded(seed);
            assert_eq!(values.map(|_| rand.rand()), values, "{seed}");
        }
        assert_eq!([Rand::stream_of(5), Rand::stream_of(0x8000_0005), Rand::stream_of(0xffff_ffff)], [5, 5, 0x7fff_ffff]);
    }

    #[test]
    fn the_seed_of_the_recorded_archive_gives_its_headers_under_its_password() {
        let first: Vec<u8> = HEADERS.iter().map(|header| header[0]).collect();
        assert!(fits::<Rand>(SEED, &first));
        // of the 2^16 seeds around it, no other does
        let near: Vec<u32> = ((SEED & !0xffff)..=(SEED | 0xffff)).filter(|seed| fits::<Rand>(*seed, &first)).collect();
        assert_eq!(near, [SEED]);
        // the seed is the time the archive was written, in November 2026, with a small process number over it
        assert!((1_795_000_000..1_795_400_000).contains(&SEED), "{SEED}");
        // the bytes of the generator, encrypted twice under the password, are the ten bytes
        // that stand in the archive, in every entry
        let keys = Keys::from_password(PASSWORD);
        for (random, header) in header_bytes::<Rand>(SEED, HEADERS.len()).iter().zip(&HEADERS) {
            assert!(infozip::fits(keys, random, header), "{header:02x?}");
        }
    }

    #[test]
    fn the_program_info_zip_gave_out_and_winrar_seed_with_the_time_and_their_process_number() {
        // the time and the process number are what the program that started each wrote down
        for (password, headers, time, process) in [(&b"zip-official32-headers"[..], &OFFICIAL_HEADERS, 1_795_282_864_u32, 3148_u32), (b"winrar-headers", &WINRAR_HEADERS, 1_795_283_874, 5400)] {
            let seed = time ^ process;
            let first: Vec<u8> = headers.iter().map(|header| header[0]).collect();
            assert!(fits::<Rand>(seed, &first));
            let keys = Keys::from_password(password);
            for (random, header) in header_bytes::<Rand>(seed, headers.len()).iter().zip(headers) {
                assert!(infozip::fits(keys, random, header), "{header:02x?}");
            }
        }
    }
}
