//! Entries made up for the tests of the claims.

use crate::analysis::Split;
use crate::formats::zip::encryption::ZipEncryption;
use crate::formats::zip::extra_fields::ExtraMarks;
use crate::formats::zip::parser::ZipEntry;

/// An entry of `zip-crypto` with this name, method, flags, size and packed size.
pub(crate) fn entry(name: &str, method: u16, flags: u16, size: u64, packed: u64) -> ZipEntry {
    ZipEntry {
        filename: name.as_bytes().to_vec(),
        flags,
        compression_method: method,
        last_mod_time: 0,
        last_mod_date: 0,
        crc32: 0,
        compressed_size: packed,
        uncompressed_size: size,
        local_header_offset: 0,
        encryption: ZipEncryption::ZipCrypto,
        directory: false,
        two_byte_check: false,
        made_by: 0,
        needed: 20,
        extra: ExtraMarks::default(),
        here: true,
        split: Split::No,
    }
}
