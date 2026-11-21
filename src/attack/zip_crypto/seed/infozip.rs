//! The encryption header as Info-ZIP makes it, which is a filter for keys once the bytes that
//! went into it are known.
//!
//! `crypthead` of `crypt.c` in Zip 3.0 draws ten bytes from `rand()` and encrypts them under
//! the password. It then sets the keys up again, encrypts those ten bytes a second time, and
//! goes on from there with the two check bytes, which are so encrypted once. With the seed of
//! the generator the ten bytes are known, and a key that is put to the test has to turn them
//! into the ten bytes that stand in the archive. The first byte says nothing, since the two
//! passes cancel there. The other nine are 72 bits, in every entry, and they do not assume
//! that any other entry has the same password.

use archivewolf_zip_crypto::Keys;

use super::glibc::HEADER_BYTES;

/// The twelve bytes of an encryption header.
pub const HEADER_LEN: usize = 12;

/// The header Info-ZIP writes for an entry: `random` are the ten bytes it drew, `check` the
/// two bytes it puts behind them, and `start` the keys after the password.
///
/// The check bytes are bits 16 to 31 of the CRC-32, low byte first, or the two bytes of the
/// DOS time, low byte first, for an entry with a data descriptor, which is what `zip -e`
/// writes (`zipup.c`: the time takes the place of the CRC-32 there). A caller that knows them
/// holds a key to all twelve bytes with this, and to the ten that need no check byte with
/// [`fits`].
#[must_use]
pub fn header(start: Keys, random: &[u8; HEADER_BYTES], check: [u8; 2]) -> [u8; HEADER_LEN] {
    let mut pass = start;
    let once = random.map(|byte| pass.encrypt(byte));
    let mut pass = start;
    let mut header = [0_u8; HEADER_LEN];
    for (byte, plain) in header.iter_mut().zip(once.iter().chain(&check)) {
        *byte = pass.encrypt(*plain);
    }
    header
}

/// Whether the keys `start` turn the ten bytes `random` into the first ten bytes of `header`,
/// as the writer did: the filter of 72 bits.
#[must_use]
pub fn fits(start: Keys, random: &[u8; HEADER_BYTES], header: &[u8; HEADER_LEN]) -> bool {
    let (mut first, mut second) = (start, start);
    random.iter().zip(header).all(|(&byte, &written)| second.encrypt(first.encrypt(byte)) == written)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::attack::zip_crypto::seed::glibc;

    /// The fixture `gen_minizip_glibc.zip`: six entries written by the `minizip` of zlib
    /// 1.2.11 on Linux, under the password `minizip-headers`. Their encryption headers, in
    /// archive order,
    pub(crate) const MINIZIP_HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0xa9, 0x91, 0xea, 0x17, 0x2b, 0xa2, 0x12, 0xab, 0x07, 0x4b, 0xc3, 0x1e],
        [0xc7, 0x36, 0xe3, 0xf9, 0xa1, 0x51, 0x40, 0xd0, 0x82, 0x52, 0xf3, 0x71],
        [0x4f, 0x41, 0x73, 0xeb, 0x77, 0x21, 0xb7, 0xf3, 0x37, 0x3e, 0xa7, 0x37],
        [0xa4, 0x2c, 0x8c, 0xf6, 0x4d, 0x6d, 0x6c, 0x5f, 0x68, 0xff, 0x6a, 0x27],
        [0xda, 0x10, 0x6e, 0xb3, 0x4a, 0xfe, 0xa1, 0x15, 0x7a, 0xcd, 0xd8, 0x11],
        [0xae, 0x90, 0x4f, 0xa3, 0xcd, 0xd5, 0xb1, 0x6b, 0x6e, 0xfa, 0xc1, 0xdb],
    ];
    /// and the seed of the run that wrote them: the time, exclusive-or 3141592654.
    pub(crate) const MINIZIP_SEED: u32 = 3_493_857_940;

    #[test]
    fn minizip_makes_its_headers_as_zip_does_from_a_seed_without_a_process_number() {
        let keys = Keys::from_password(b"minizip-headers");
        let first: Vec<u8> = MINIZIP_HEADERS.iter().map(|header| header[0]).collect();
        assert!(glibc::fits(MINIZIP_SEED, &first));
        for (random, written) in glibc::header_bytes(MINIZIP_SEED, MINIZIP_HEADERS.len()).iter().zip(&MINIZIP_HEADERS) {
            assert!(fits(keys, random, written), "{written:02x?}");
        }
        // the seed is the time the archive was written, in November 2026, with the digits of pi over it
        let time = MINIZIP_SEED ^ 0xbb40_e64e;
        assert!((1_795_000_000..1_795_400_000).contains(&time), "{time}");
    }

    /// The fixture `gen_infozip_six.zip`: six entries written by `zip -e -P` of Info-ZIP 3.0
    /// on Linux, under this password,
    pub(crate) const SIX_PASSWORD: &[u8] = b"six-headers";
    /// the keys after that password,
    pub(crate) const SIX_KEYS: Keys = Keys::new(0xb4fd_7fc8, 0x9cc4_f2bc, 0x92c9_5100);
    /// the encryption header of each, in archive order,
    pub(crate) const SIX_HEADERS: [[u8; HEADER_LEN]; 6] = [
        [0xe0, 0xdc, 0x2f, 0xe7, 0x47, 0xfb, 0x97, 0x02, 0x01, 0x72, 0x03, 0xf7],
        [0xd5, 0xc2, 0x0b, 0x6d, 0xf9, 0x73, 0x39, 0x27, 0x61, 0x69, 0x1b, 0x49],
        [0xa9, 0x2f, 0x36, 0x56, 0xf3, 0x20, 0x5a, 0x01, 0x7e, 0xba, 0x41, 0xaf],
        [0x17, 0xa5, 0xc8, 0xec, 0x58, 0x8e, 0x32, 0x50, 0x28, 0x1f, 0xf0, 0xb2],
        [0xec, 0xaa, 0x5c, 0x16, 0xfa, 0xeb, 0x7b, 0x34, 0xc3, 0x24, 0x91, 0x79],
        [0x94, 0x50, 0x4d, 0xe8, 0xfa, 0xac, 0xfe, 0x46, 0x3d, 0x6a, 0x43, 0xe6],
    ];
    /// and the seed that gives the first byte of all six, the only one in the window of the
    /// time the archive was written at: that time, 1,795,212,702, exclusive-or the process
    /// number 774,689.
    pub(crate) const SIX_SEED: u32 = 1_795_889_087;

    /// The same for the fixture `gen_infozip_four.zip`, of four entries, which the same
    /// program wrote in the same second as the process 774,692.
    pub(crate) const FOUR_PASSWORD: &[u8] = b"four-headers";
    pub(crate) const FOUR_KEYS: Keys = Keys::new(0x9309_413d, 0x76da_fb18, 0x09f0_cd24);
    pub(crate) const FOUR_HEADERS: [[u8; HEADER_LEN]; 4] = [
        [0x32, 0x7f, 0xd6, 0x7a, 0x3e, 0x63, 0x7f, 0x8c, 0xdb, 0xaa, 0xdc, 0x00],
        [0xf2, 0xd7, 0x2b, 0x50, 0x1d, 0xcb, 0x99, 0xf1, 0x5a, 0x83, 0x06, 0xba],
        [0xf6, 0x55, 0xa3, 0x1c, 0xf3, 0x5a, 0x60, 0x3e, 0x73, 0x5d, 0x85, 0x60],
        [0xcc, 0x1c, 0x78, 0xb7, 0x11, 0xfa, 0x98, 0x63, 0xcd, 0x27, 0x61, 0x87],
    ];
    pub(crate) const FOUR_SEED: u32 = 1_795_889_082;

    /// The DOS time of every entry of both archives, 17:11:42. `zip -e` writes a data
    /// descriptor, so the two bytes of the time are the check bytes.
    const TIME: u16 = 0x8975;

    #[test]
    fn the_keys_of_the_password_make_the_headers_of_the_archive() {
        for (password, keys, seed, headers) in [(SIX_PASSWORD, SIX_KEYS, SIX_SEED, &SIX_HEADERS[..]), (FOUR_PASSWORD, FOUR_KEYS, FOUR_SEED, &FOUR_HEADERS[..])] {
            assert_eq!(Keys::from_password(password), keys);
            let random = glibc::header_bytes(seed, headers.len());
            for (random, written) in random.iter().zip(headers) {
                assert!(fits(keys, random, written));
                assert_eq!(header(keys, random, TIME.to_le_bytes()), *written);
            }
        }
    }

    #[test]
    fn other_keys_and_other_bytes_fail_the_filter() {
        let keys = Keys::from_password(SIX_PASSWORD);
        let random = glibc::header_bytes(SIX_SEED, SIX_HEADERS.len());
        for wrong in [Keys::from_password(b"six-header"), Keys::INITIAL, Keys::new(keys.x ^ 1, keys.y, keys.z), Keys::new(keys.x, keys.y ^ 0x8000_0000, keys.z), Keys::new(keys.x, keys.y, keys.z ^ 4)] {
            assert!(!fits(wrong, &random[0], &SIX_HEADERS[0]), "{wrong}");
        }
        // the bytes of another entry, and of another seed
        assert!(!fits(keys, &random[1], &SIX_HEADERS[0]));
        assert!(!fits(keys, &glibc::header_bytes(SIX_SEED + 1, 1)[0], &SIX_HEADERS[0]));
        // a header that differs in its last random byte only
        let mut written = SIX_HEADERS[0];
        written[9] ^= 1;
        assert!(!fits(keys, &random[0], &written));
        // the check bytes are not part of the filter
        written = SIX_HEADERS[0];
        written[10] ^= 0xff;
        written[11] ^= 0xff;
        assert!(fits(keys, &random[0], &written));
    }

    #[test]
    fn the_first_header_byte_is_the_first_random_byte_under_any_keys() {
        let random = [0xa5, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        for keys in [Keys::INITIAL, Keys::from_password(b"a"), Keys::new(1, 2, 3)] {
            assert_eq!(header(keys, &random, [0, 0])[0], 0xa5);
        }
    }
}
