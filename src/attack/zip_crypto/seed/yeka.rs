//! The encryption header of `github.com/yeka/zip`, which is always the same.
//!
//! The library uses no generator. It encrypts a constant of twelve bytes that stands in its
//! source under the password, puts the two bytes of the DOS time over the last two bytes of
//! the result, sets the keys up again and encrypts that (`zipcrypto.go`, `zipCryptoWriter`).
//! So the first byte of every header is the first byte of the constant, since the two passes
//! cancel there, and the first ten bytes depend on the password alone: they are the same in
//! every entry of every archive under one password.

use archivewolf_zip_crypto::Keys;

use super::infozip::HEADER_LEN;

/// The twelve bytes the library encrypts in place of random ones.
pub const CONSTANT: [u8; HEADER_LEN] = [0xf8, 0x53, 0xcf, 0x05, 0x2d, 0xdd, 0xad, 0xc8, 0x66, 0x3f, 0x8c, 0xac];

/// How many bytes at the start of a header depend on the password alone. The two behind them
/// are made of the time.
pub const SHARED: usize = 10;

/// How many encrypted entries [`recognise`] asks for.
///
/// With one entry the only mark is the first byte, which a writer of random headers gives
/// once in 256 archives. With two, the ten equal bytes are 80 bits more against such a
/// writer, and further entries add nothing that matters. One other writer is not told apart
/// by any number of entries: a library that makes its header from a generator seeded with a
/// clock writes equal headers for entries of one tick (design, section 8.5), and their first
/// byte is `F8` once in 256 archives. The filter decides then, when keys are put to it.
pub const MIN_ENTRIES: usize = 2;

/// Whether the encryption headers of an archive are those of `yeka/zip`: at least
/// [`MIN_ENTRIES`] of them, the first byte of the constant in front, and the first ten bytes
/// the same in all.
///
/// `headers` holds the header of every encrypted entry. Entries under two passwords have two
/// sets of ten bytes, and are not recognised together.
#[must_use]
pub fn recognise(headers: &[[u8; HEADER_LEN]]) -> bool {
    let [marker, ..] = CONSTANT;
    let Some((first, rest)) = headers.split_first() else { return false };
    headers.len() >= MIN_ENTRIES && first.first() == Some(&marker) && rest.iter().all(|header| header.first_chunk::<SHARED>() == first.first_chunk::<SHARED>())
}

/// The header the library writes for an entry whose DOS time is `time`, from the keys after
/// the password.
#[must_use]
pub fn header(start: Keys, time: u16) -> [u8; HEADER_LEN] {
    let mut pass = start;
    let mut once = CONSTANT.map(|byte| pass.encrypt(byte));
    for (byte, of_time) in once.iter_mut().skip(SHARED).zip(time.to_le_bytes()) {
        *byte = of_time;
    }
    let mut pass = start;
    once.map(|byte| pass.encrypt(byte))
}

/// Whether the keys `start` turn the constant into the first ten bytes of `header`: a filter
/// of 72 bits, the first byte being the same under every key. It needs no seed and no time.
#[must_use]
pub fn fits(start: Keys, header: &[u8; HEADER_LEN]) -> bool {
    let (mut first, mut second) = (start, start);
    CONSTANT.iter().zip(header).take(SHARED).all(|(&byte, &written)| second.encrypt(first.encrypt(byte)) == written)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::attack::zip_crypto::seed::dotnet::tests::SHARP_NET5;
    use crate::attack::zip_crypto::seed::infozip::tests::SIX_HEADERS;

    /// The password of the archives A and B of the design (`gen_yeka_a.zip`, `gen_yeka_b.zip`),
    const PASSWORD: &[u8] = b"Tr0ub4dor&3xyz";
    /// and that of archive C (`gen_yeka_c.zip`).
    const OTHER_PASSWORD: &[u8] = b"other-password";
    /// The DOS time of the five entries of each archive: 12:00:00, 12:01:02 and so on.
    const TIMES: [u16; 5] = [0x6000, 0x6021, 0x6042, 0x6063, 0x6084];
    /// The encryption headers of the five entries of archive A. Those of archive B are the
    /// same, byte for byte: the same password and the same times.
    pub(crate) const HEADERS: [[u8; HEADER_LEN]; 5] = [
        [0xf8, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8, 0x0c, 0xe0],
        [0xf8, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8, 0x2d, 0x60],
        [0xf8, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8, 0x4e, 0x12],
        [0xf8, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8, 0x6f, 0xcb],
        [0xf8, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8, 0x88, 0xb0],
    ];
    /// Those of archive C.
    pub(crate) const OTHER_HEADERS: [[u8; HEADER_LEN]; 5] = [
        [0xf8, 0xf5, 0x21, 0x07, 0x65, 0x05, 0x68, 0x9d, 0x75, 0xa5, 0x0a, 0x93],
        [0xf8, 0xf5, 0x21, 0x07, 0x65, 0x05, 0x68, 0x9d, 0x75, 0xa5, 0x2b, 0x6d],
        [0xf8, 0xf5, 0x21, 0x07, 0x65, 0x05, 0x68, 0x9d, 0x75, 0xa5, 0x48, 0x24],
        [0xf8, 0xf5, 0x21, 0x07, 0x65, 0x05, 0x68, 0x9d, 0x75, 0xa5, 0x69, 0xd0],
        [0xf8, 0xf5, 0x21, 0x07, 0x65, 0x05, 0x68, 0x9d, 0x75, 0xa5, 0x8e, 0x73],
    ];

    #[test]
    fn the_recorded_archives_are_recognised() {
        assert!(recognise(&HEADERS));
        assert!(recognise(&OTHER_HEADERS));
        assert!(recognise(&HEADERS[..MIN_ENTRIES]));
    }

    #[test]
    fn other_headers_are_not_recognised() {
        // Info-ZIP and SharpZipLib
        assert!(!recognise(&SIX_HEADERS));
        assert!(!recognise(&SHARP_NET5));
        // too few entries to tell
        assert!(!recognise(&[]));
        assert!(!recognise(&HEADERS[..1]));
        // two passwords in one archive
        assert!(!recognise(&[HEADERS[0], OTHER_HEADERS[0]]));
        // equal headers that do not start with the first byte of the constant
        let mut shifted = HEADERS;
        for header in &mut shifted {
            header[0] = 0xf9;
        }
        assert!(!recognise(&shifted));
        // one entry that differs in the last of the ten bytes
        let mut differs = HEADERS;
        differs[4][SHARED - 1] ^= 1;
        assert!(!recognise(&differs));
    }

    #[test]
    fn the_keys_of_the_password_make_the_headers_of_the_archive() {
        // the keys of the first password are those the design records for it (section 8.5)
        let recorded = [Keys::new(0x9f15_e5d8, 0x9569_12eb, 0xfbf5_8431), Keys::new(0xefd7_9102, 0xbc1d_ce1f, 0xf474_1427)];
        for ((password, headers), keys) in [(PASSWORD, &HEADERS), (OTHER_PASSWORD, &OTHER_HEADERS)].into_iter().zip(recorded) {
            assert_eq!(Keys::from_password(password), keys);
            for (written, time) in headers.iter().zip(TIMES) {
                assert!(fits(keys, written));
                assert_eq!(header(keys, time), *written);
            }
        }
    }

    #[test]
    fn other_keys_fail_the_filter() {
        let keys = Keys::from_password(PASSWORD);
        for wrong in [Keys::from_password(OTHER_PASSWORD), Keys::INITIAL, Keys::new(keys.x ^ 1, keys.y, keys.z), Keys::new(keys.x, keys.y ^ 0x8000_0000, keys.z), Keys::new(keys.x, keys.y, keys.z ^ 4)] {
            assert!(!fits(wrong, &HEADERS[0]), "{wrong}");
        }
        assert!(!fits(keys, &OTHER_HEADERS[0]));
        // the two bytes of the time are not part of the filter
        let mut written = HEADERS[0];
        written[10] ^= 0xff;
        written[11] ^= 0xff;
        assert!(fits(keys, &written));
        written[SHARED - 1] ^= 1;
        assert!(!fits(keys, &written));
    }
}
