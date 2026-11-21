//! What goes into a hash line: the fields of an entry, and the range of the archive that holds
//! its encrypted data.
//!
//! Nothing here decides whether an entry gets a line. That is done before, where the entry is
//! held against what its mode loads ([`super::scoring`]): what is read here is known to lie
//! inside the archive and to be no more than a line carries.

use std::io;

use super::encryption::Rar50Record;
use super::headers::RarEntry;
use super::lines::Rar30HashInput;
use super::lines::Rar50HashInput;
use super::lines::RarLegacyHashInput;
use super::lines::emit_rar_15;
use super::lines::emit_rar_20;
use super::lines::emit_rar_30;
use super::lines::emit_rar_50;
use super::rar4::EndBlock;
use super::scoring::DataLine;
use crate::formats::source::Source;

/// What the first bytes of the end of archive block of RAR 3 decrypt to, as the number a
/// `$rar$30$` line of type 0 carries in the place of a CRC-32.
const RAR_30_END_BLOCK: u32 = 0xc43d_7b00;

/// How many bytes of the first encrypted header a `$rar$50$` line carries when the archive has
/// no check value: enough for the main header, which is that header.
const RAR_50_HEADER_DATA: u64 = 256;

/// The `$rar$50$` line of type 0: the check value of an encryption record, and what the key
/// it is derived from takes.
pub(crate) fn check_value_line(crypt: &Rar50Record, value: [u8; 8]) -> String {
    emit_rar_50(&Rar50HashInput { hash_type: 0, salt: crypt.salt, lg2count: crypt.lg2count, iv: [0; 16], psw_check: Some(value), check_type: 0, crc32: None, blake2sp: None, pack_size: None, unpack_size: None, method: None, data: None })
}

/// The line that carries the encrypted data of `entry`, which unpacks to `unpacked` bytes.
/// An error when the data cannot be read.
pub(crate) fn data_line(source: &Source, entry: &RarEntry, line: DataLine, unpacked: u64) -> io::Result<String> {
    let data = source.read_at(entry.data_offset, entry.packed)?;
    Ok(match line {
        DataLine::Rar15 => emit_rar_15(&RarLegacyHashInput { crc32: entry.crc32, unpack_size: unpacked, data_size: entry.packed, method: entry.method, data }),
        DataLine::Rar20 => emit_rar_20(&RarLegacyHashInput { crc32: entry.crc32, unpack_size: unpacked, data_size: entry.packed, method: entry.method, data }),
        DataLine::Rar30 { salt } => emit_rar_30(&Rar30HashInput { hash_type: 1, salt, crc32: entry.crc32, pack_size: entry.packed, unpack_size: unpacked, method: entry.method, data }),
        DataLine::Rar50(crypt) => {
            // the line says which checksum it carries, and whether that one is keyed
            let check_type = match (entry.blake2sp.is_some(), crypt.hashmac) {
                (false, false) => 0,
                (false, true) => 1,
                (true, false) => 2,
                (true, true) => 3,
            };
            let crc32 = if entry.blake2sp.is_some() { None } else { Some(entry.crc32) };
            emit_rar_50(&Rar50HashInput { hash_type: 1, salt: crypt.salt, lg2count: crypt.lg2count, iv: crypt.iv, psw_check: None, check_type, crc32, blake2sp: entry.blake2sp, pack_size: Some(entry.packed), unpack_size: Some(unpacked), method: Some(entry.method), data: Some(data) })
        },
    })
}

/// The `$rar$30$` line of type 0: the salt of an archive with encrypted headers and its
/// encrypted end of archive block.
pub(crate) fn rar_30_header_line(end: &EndBlock) -> String {
    let size = u64::try_from(end.data.len()).unwrap_or(u64::MAX);
    emit_rar_30(&Rar30HashInput { hash_type: 0, salt: end.salt, crc32: RAR_30_END_BLOCK, pack_size: size, unpack_size: size, method: 0, data: end.data.clone() })
}

/// The `$rar$50$` line of type 1 for an archive with encrypted headers and no check value:
/// the vector of its first encrypted header and the start of that header, in whole cipher
/// blocks. `block_at` is where the vector stands. `None` when less than one block follows it.
pub(crate) fn rar_50_header_line(source: &Source, crypt: &Rar50Record, block_at: u64) -> Option<String> {
    let mut iv = [0_u8; 16];
    source.read_exact_at(block_at, &mut iv).ok()?;
    let data = source.read_up_to(block_at.checked_add(16)?, RAR_50_HEADER_DATA).ok()?;
    let whole = data.len() / 16 * 16;
    let data = data.get(..whole).filter(|data| !data.is_empty())?.to_vec();
    let size = u64::try_from(data.len()).ok()?;
    Some(emit_rar_50(&Rar50HashInput { hash_type: 1, salt: crypt.salt, lg2count: crypt.lg2count, iv, psw_check: None, check_type: 4, crc32: None, blake2sp: None, pack_size: Some(size), unpack_size: Some(size), method: Some(0), data: Some(data) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::EntryKind;

    fn crypt(check_value: Option<[u8; 8]>, hashmac: bool) -> Rar50Record {
        Rar50Record { lg2count: 15, salt: [0x11; 16], iv: [0x22; 16], check_value, unused: None, hashmac }
    }

    /// An archive of 100 bytes of 0xEE, then 48 bytes of data, and the entry that owns them.
    fn entry_and_source(method: u8) -> (RarEntry, Source) {
        let mut bytes = vec![0xEE; 100];
        bytes.extend((0..48).map(|at| 0x40 + at));
        let mut entry = RarEntry::new(EntryKind::File, 100);
        entry.packed = 48;
        entry.crc32 = 0xDEAD_BEEF;
        entry.method = method;
        (entry, Source::from_bytes(bytes))
    }

    const DATA: &str = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f";

    #[test]
    fn a_check_value_makes_a_line_without_data() {
        // the vector of the entry is not in the line: the check value does not depend on it
        let line = check_value_line(&crypt(Some([0xCC; 8]), true), [0xCC; 8]);
        assert_eq!(line, format!("$rar$50$*0*{}*15*{}*cccccccccccccccc*0*****$/rar$", "11".repeat(16), "00".repeat(16)));
    }

    #[test]
    fn the_lines_of_the_early_ciphers_carry_the_entry_whole() {
        let (entry, source) = entry_and_source(0x33);
        assert_eq!(data_line(&source, &entry, DataLine::Rar15, 500).unwrap(), format!("$rar$15$*deadbeef*1f4*30*33*{DATA}$/rar$"));
        assert_eq!(data_line(&source, &entry, DataLine::Rar20, 500).unwrap(), format!("$rar$20$*deadbeef*1f4*30*33*{DATA}$/rar$"));
        assert_eq!(data_line(&source, &entry, DataLine::Rar30 { salt: [0xA5; 8] }, 500).unwrap(), format!("$rar$30$*1*a5a5a5a5a5a5a5a5*deadbeef*30*1f4*33*{DATA}$/rar$"));
    }

    #[test]
    fn a_rar_5_line_says_which_checksum_it_carries() {
        let (mut entry, source) = entry_and_source(3);
        let start = format!("$rar$50$*1*{}*15*{}*", "11".repeat(16), "22".repeat(16));
        let line = |entry: &RarEntry, hashmac: bool| data_line(&source, entry, DataLine::Rar50(crypt(None, hashmac)), 500).unwrap();

        assert_eq!(line(&entry, false), format!("{start}*0*deadbeef*30*1f4*3*{DATA}$/rar$"));
        assert_eq!(line(&entry, true), format!("{start}*1*deadbeef*30*1f4*3*{DATA}$/rar$"));
        entry.blake2sp = Some([0xB2; 32]);
        assert_eq!(line(&entry, false), format!("{start}*2*{}*30*1f4*3*{DATA}$/rar$", "b2".repeat(32)));
        assert_eq!(line(&entry, true), format!("{start}*3*{}*30*1f4*3*{DATA}$/rar$", "b2".repeat(32)));
    }

    #[test]
    fn data_that_is_not_in_the_archive_is_an_error_and_no_line() {
        let (mut entry, source) = entry_and_source(0x30);
        entry.packed = 49;
        assert!(data_line(&source, &entry, DataLine::Rar15, 49).is_err());
        entry.packed = u64::MAX;
        assert!(data_line(&source, &entry, DataLine::Rar15, 49).is_err(), "a size that is a lie is refused before anything is read");
        entry.data_offset = u64::MAX;
        assert!(data_line(&source, &entry, DataLine::Rar15, 49).is_err());
    }

    #[test]
    fn the_end_block_of_rar_3_makes_a_line_of_its_length() {
        let short = EndBlock { salt: [1, 2, 3, 4, 5, 6, 7, 8], data: vec![0xEE; 16], trailing: 0 };
        assert_eq!(rar_30_header_line(&short), format!("$rar$30$*0*0102030405060708*c43d7b00*10*10*0*{}$/rar$", "ee".repeat(16)));
        let long = EndBlock { data: vec![0xEE; 32], ..short };
        assert_eq!(rar_30_header_line(&long), format!("$rar$30$*0*0102030405060708*c43d7b00*20*20*0*{}$/rar$", "ee".repeat(32)));
    }

    #[test]
    fn encrypted_headers_of_rar_5_without_a_check_value_give_their_first_blocks() {
        // 30 bytes in front, a vector, then 40 bytes of encrypted header: two whole blocks
        let mut bytes = vec![0xEE; 30];
        bytes.extend_from_slice(&[0x77; 16]);
        bytes.extend((0..40).map(|at| 0x40 + at));
        let line = rar_50_header_line(&Source::from_bytes(bytes.clone()), &crypt(None, false), 30).unwrap();
        assert_eq!(line, format!("$rar$50$*1*{}*15*{}**4**20*20*0*{}$/rar$", "11".repeat(16), "77".repeat(16), &DATA[..64]));

        // no more than 256 bytes of a long archive
        bytes.extend_from_slice(&[0x55; 1000]);
        let line = rar_50_header_line(&Source::from_bytes(bytes.clone()), &crypt(None, false), 30).unwrap();
        assert!(line.contains("**4**100*100*0*"), "{line}");

        // less than a block behind the vector, or no vector
        assert_eq!(rar_50_header_line(&Source::from_bytes(bytes[..61].to_vec()), &crypt(None, false), 30), None);
        assert_eq!(rar_50_header_line(&Source::from_bytes(bytes[..40].to_vec()), &crypt(None, false), 30), None);
        assert_eq!(rar_50_header_line(&Source::from_bytes(bytes), &crypt(None, false), u64::MAX), None);
    }
}
