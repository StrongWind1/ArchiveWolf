//! The parser for RAR 5 and RAR 7 archives (`Rar!\x1a\x07\x01\x00`).
//!
//! The archive is a chain of blocks. Each is a CRC-32, its own size in a number of at most
//! three bytes, and that many bytes of header: a type, flags, and what the type calls for. A
//! block can be followed by data, whose size its header gives. The numbers of the format are
//! of variable length and up to 64 bits wide, so every sum of them is checked here.
//!
//! Encryption is said in two places. An encryption header in front of everything else means
//! that every block behind it is encrypted, the listing included. Without one, each file and
//! service header says in an extra record how its data is encrypted.
//!
//! Parts of this file follow the UnRAR source. Its license, paragraph 2, has to accompany such code:
//!
//! ```text
//! UnRAR source code may be used in any software to handle
//! RAR archives without limitations free of charge, but cannot be
//! used to develop RAR (WinRAR) compatible archiver and to
//! re-create RAR compression algorithm, which is proprietary.
//! Distribution of modified UnRAR source code in separate form
//! or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "UnRAR source code"
//! words, is included in license, or in documentation if license
//! is not available, and in source code comments of resulting package.
//! ```
//!
//! The full text is in `LICENSE-UNRAR.txt`.

use anyhow::Context as _;

use super::encryption::Rar50Record;
use super::encryption::Rar50Refused;
use super::encryption::RarEncryption;
use super::headers::Fields;
use super::headers::HeaderEncryption;
use super::headers::RAR5_SIGNATURE;
use super::headers::RarArchive;
use super::headers::RarEntry;
use super::headers::RarGeneration;
use super::headers::stored_comment;
use crate::analysis::EntryKind;
use crate::analysis::Scheme;
use crate::analysis::Volume;
use crate::formats::source::Cursor;
use crate::formats::source::Source;

/// Block type: the main archive header.
const HEAD_MAIN: u64 = 1;
/// Block type: a file.
const HEAD_FILE: u64 = 2;
/// Block type: a service record.
const HEAD_SERVICE: u64 = 3;
/// Block type: the archive encryption header.
const HEAD_CRYPT: u64 = 4;
/// Block type: the end of the archive.
const HEAD_ENDARC: u64 = 5;

/// Block flag: an extra area ends the header.
const HFL_EXTRA: u64 = 0x0001;
/// Block flag: data follows the header.
const HFL_DATA: u64 = 0x0002;
/// Block flag: the data continues from the volume before.
const HFL_SPLITBEFORE: u64 = 0x0008;
/// Block flag: the data continues in the volume after.
const HFL_SPLITAFTER: u64 = 0x0010;

/// Main header flag: the archive is a volume of a set.
const MHFL_VOLUME: u64 = 0x0001;
/// Main header flag: the number of the volume follows. Set on every volume but the first.
const MHFL_VOLNUMBER: u64 = 0x0002;

/// File flag: the entry is a directory.
const FHFL_DIRECTORY: u64 = 0x0001;
/// File flag: a modification time follows.
const FHFL_UTIME: u64 = 0x0002;
/// File flag: the CRC-32 of the unpacked data follows.
const FHFL_CRC32: u64 = 0x0004;
/// File flag: the unpacked size is not known.
const FHFL_UNPUNKNOWN: u64 = 0x0008;

/// Compression information: the entry continues the entries before it.
const FCI_SOLID: u64 = 0x0040;

/// Extra record of a file or service header: how its data is encrypted.
const FHEXTRA_CRYPT: u64 = 0x01;
/// Extra record of a file or service header: a checksum that is not a CRC-32.
const FHEXTRA_HASH: u64 = 0x02;
/// Kind of checksum in a hash record: BLAKE2sp.
const FHEXTRA_HASH_BLAKE2: u64 = 0x00;

/// The smallest block there is: a CRC-32, one byte of size, a type and flags.
const SHORTEST_BLOCK: u64 = 7;

/// One block: its header without the CRC-32 and the size in front of it.
struct Block {
    /// The header, from its type on.
    header: Vec<u8>,
    /// Size of the whole block header, with the CRC-32 and the size field.
    size: u64,
    /// Where the header ends and its data starts.
    end: u64,
    /// Whether the CRC-32 in front of the header is the one of the header.
    intact: bool,
}

/// How reading the next block went.
enum Step {
    /// A block.
    Block(Block),
    /// Nothing that is a block: the end of the file, or bytes that are no header.
    End,
    /// A block that reaches past the end of the file.
    Truncated,
}

/// Read the block the cursor stands in front of.
///
/// The size field takes three bytes at most, so a header is two megabytes at most, and it is
/// read only when it lies inside the file: a size that is a lie costs nothing.
fn read_block(cursor: &mut Cursor<'_>, len: u64) -> Step {
    let pos = cursor.position();
    let Ok([c0, c1, c2, c3, s0, s1, s2]) = cursor.array::<7>() else { return Step::End };
    let size_bytes = [s0, s1, s2];
    let mut size_field = Fields::new(&size_bytes);
    let Some(header_size) = size_field.vint() else { return Step::End };
    let Ok(size_len) = u64::try_from(size_field.position()) else { return Step::End };

    let size = 4_u64.saturating_add(size_len).saturating_add(header_size);
    if header_size == 0 || size < SHORTEST_BLOCK {
        return Step::End;
    }
    let (Some(start), Some(end)) = (pos.checked_add(4 + size_len), pos.checked_add(size)) else { return Step::End };
    if end > len || cursor.seek(start).is_err() {
        return Step::Truncated;
    }
    let Ok(header) = cursor.read_vec(header_size) else { return Step::Truncated };

    let mut crc = crc32fast::Hasher::new();
    crc.update(size_bytes.get(..size_field.position()).unwrap_or_default());
    crc.update(&header);
    Step::Block(Block { header, size, end, intact: crc.finalize() == u32::from_le_bytes([c0, c1, c2, c3]) })
}

/// Read the records of the extra area, which is the last `extra_size` bytes of `header`.
///
/// `read_to` is how far the fields in front of it reach. An extra area that would start
/// before that is none, as in UnRAR.
fn read_extra(header: &[u8], read_to: usize, extra_size: u64, service: bool, entry: &mut RarEntry) {
    let Some(start) = usize::try_from(extra_size).ok().and_then(|size| header.len().checked_sub(size)) else { return };
    let mut records = Fields::new(header);
    if start < read_to || !records.seek(start) {
        return;
    }

    // every pass takes at least a byte off what is left, or ends the loop
    while records.left() >= 2 {
        let Some(record) = records.vint().and_then(|size| usize::try_from(size).ok()).filter(|&size| size > 0).and_then(|size| records.bytes(size)) else { break };
        let mut fields = Fields::new(record);
        match fields.vint() {
            Some(FHEXTRA_CRYPT) => {
                entry.encryption = match Rar50Record::read(&mut fields, true, service) {
                    Ok(crypt) => RarEncryption::Rar50(crypt),
                    Err(Rar50Refused::Version(version)) => RarEncryption::Unknown { version },
                    Err(Rar50Refused::Cut) => RarEncryption::Unreadable(Scheme::Rar50),
                };
            },
            Some(FHEXTRA_HASH) if fields.vint() == Some(FHEXTRA_HASH_BLAKE2) => entry.blake2sp = fields.array().or(entry.blake2sp),
            _ => {},
        }
    }
}

/// Read a file or service header from the fields behind its block flags. `None` when the
/// header ends before its fixed fields do.
fn read_entry(fields: &mut Fields<'_>, block: &Block, flags: u64, extra_size: u64, packed: u64, service: bool) -> Option<RarEntry> {
    let file_flags = fields.vint()?;
    let unpacked = fields.vint()?;
    let _attributes = fields.vint()?;
    if file_flags & FHFL_UTIME != 0 {
        let _modified = fields.u32_le()?;
    }
    let crc32 = if file_flags & FHFL_CRC32 == 0 { None } else { Some(fields.u32_le()?) };
    let compression = fields.vint()?;
    let _host = fields.vint()?;
    // the name ends where the header does, whatever its length says
    let name_size = fields.vint()?;
    let name = fields.bytes_up_to(usize::try_from(name_size).unwrap_or(usize::MAX));

    let kind = match (service, file_flags & FHFL_DIRECTORY != 0) {
        (true, _) => EntryKind::Service,
        (false, true) => EntryKind::Directory,
        (false, false) => EntryKind::File,
    };
    let mut entry = RarEntry::new(kind, block.end);
    entry.name = name.to_vec();
    entry.packed = packed;
    entry.unpacked = (file_flags & FHFL_UNPUNKNOWN == 0).then_some(unpacked);
    entry.crc32 = crc32.unwrap_or(0);
    entry.has_crc32 = crc32.is_some();
    // three bits of method and six of algorithm version: both fit a byte
    entry.method = u8::try_from((compression >> 7) & 0x07).unwrap_or(u8::MAX);
    entry.algorithm = u8::try_from(compression & 0x3F).unwrap_or(u8::MAX);
    entry.stored = entry.method == 0;
    entry.solid = !service && compression & FCI_SOLID != 0;
    entry.split_before = flags & HFL_SPLITBEFORE != 0;
    entry.split_after = flags & HFL_SPLITAFTER != 0;

    read_extra(&block.header, fields.position(), extra_size, service, &mut entry);
    Some(entry)
}

/// Whether the main header says that the archive is a volume, and which.
fn read_volume(fields: &mut Fields<'_>) -> Option<Volume> {
    let flags = fields.vint()?;
    let number = if flags & MHFL_VOLNUMBER == 0 { 0 } else { fields.vint()? };
    Some(match (flags & MHFL_VOLUME != 0, number) {
        (false, _) => Volume::Single,
        (true, 0) => Volume::First,
        (true, _) => Volume::Later,
    })
}

/// Parse the RAR 5 archive that starts `start` bytes into `source`.
///
/// An error when the signature is not followed by a block. With `strict`, which is for a
/// signature found inside a program, that block also has to be a main header or an encryption
/// header with the right CRC-32. From there on the parser takes what it can read. It stops at
/// the first bytes that are no block and says where in [`RarArchive::broken_at`], unless they
/// are the end of the file; it says so in [`RarArchive::truncated`] when a block or the data
/// of an entry reaches past the end of the file. The first header that fails its CRC-32 is in
/// [`RarArchive::bad_checksum_at`], and the walk goes on, as UnRAR reports such a header and
/// still reads it.
pub(crate) fn parse(source: &Source, start: u64, strict: bool) -> anyhow::Result<RarArchive> {
    let len = source.len();
    let mut archive = RarArchive::new(RarGeneration::Rar5);
    let mut cursor = source.cursor(start);
    cursor.skip(u64::try_from(RAR5_SIGNATURE.len())?).context("RAR 5: the file ends inside the signature")?;

    // every pass moves the cursor on by seven bytes or more, or ends the loop
    let mut first = true;
    loop {
        let at = cursor.position();
        let block = match read_block(&mut cursor, len) {
            Step::Block(block) => block,
            Step::End if first => anyhow::bail!("RAR 5: the signature is not followed by a header"),
            Step::Truncated if first => anyhow::bail!("RAR 5: the file ends inside its first header"),
            Step::End => {
                // the end of the file is the end of an archive without an end block
                archive.broken_at = (at < len).then_some(at);
                break;
            },
            Step::Truncated => {
                archive.truncated = true;
                break;
            },
        };
        if !block.intact {
            let _ = archive.bad_checksum_at.get_or_insert(at);
        }
        let mut fields = Fields::new(&block.header);
        let (Some(head_type), Some(flags)) = (fields.vint(), fields.vint()) else {
            anyhow::ensure!(!first, "RAR 5: the first header has no type");
            archive.broken_at = Some(at);
            break;
        };
        if std::mem::take(&mut first) && strict {
            anyhow::ensure!(block.intact && matches!(head_type, HEAD_MAIN | HEAD_CRYPT), "RAR 5: the signature is not followed by a main header");
        }

        let extra_size = if flags & HFL_EXTRA == 0 { Some(0) } else { fields.vint() };
        let data_size = if flags & HFL_DATA == 0 { Some(0) } else { fields.vint() };
        // an extra area as long as its header is none
        let (Some(extra_size), Some(data_size)) = (extra_size.filter(|&size| size < block.size), data_size) else {
            archive.broken_at = Some(at);
            break;
        };
        let next = block.end.checked_add(data_size).filter(|&next| next <= len);

        match head_type {
            HEAD_CRYPT => {
                archive.headers = match Rar50Record::read(&mut fields, false, false) {
                    Ok(crypt) => HeaderEncryption::Rar50 { crypt: Box::new(crypt), block_at: next.unwrap_or(block.end) },
                    Err(Rar50Refused::Version(version)) => HeaderEncryption::Unknown { version },
                    Err(Rar50Refused::Cut) => HeaderEncryption::Rar50Unreadable,
                };
                // the main header, which says whether this is a volume, is encrypted
                archive.volume = None;
                break;
            },
            HEAD_MAIN => archive.volume = read_volume(&mut fields).or(archive.volume),
            HEAD_FILE | HEAD_SERVICE => {
                let Some(mut entry) = read_entry(&mut fields, &block, flags, extra_size, data_size, head_type == HEAD_SERVICE) else {
                    // a block that says it is a file header and is none
                    archive.broken_at = Some(at);
                    break;
                };
                entry.header_offset = at;
                if archive.comment.is_none() {
                    archive.comment = stored_comment(source, &entry);
                }
                archive.entries.push(entry);
            },
            HEAD_ENDARC => break,
            _ => {},
        }

        if next.is_none_or(|next| cursor.seek(next).is_err()) {
            archive.truncated = true;
            break;
        }
    }
    Ok(archive)
}

#[cfg(test)]
mod tests {
    use super::super::testing::rar5::Entry;
    use super::super::testing::rar5::MAX;
    use super::super::testing::rar5::SERVICE;
    use super::super::testing::rar5::archive;
    use super::super::testing::rar5::blake2_record;
    use super::super::testing::rar5::block;
    use super::super::testing::rar5::crypt_record;
    use super::super::testing::rar5::end;
    use super::super::testing::rar5::main;
    use super::super::testing::rar5::vint;
    use super::*;

    fn parsed(bytes: Vec<u8>) -> RarArchive {
        parse(&Source::from_bytes(bytes), 0, false).unwrap()
    }

    fn fixture(rel: &str) -> RarArchive {
        parse(&Source::open(std::path::Path::new(&format!("tests/fixtures/{rel}")), 0).unwrap(), 0, false).unwrap()
    }

    #[test]
    fn the_entries_of_a_fixture_are_read_with_their_encryption() {
        let listed = fixture("rar-50/v500_p_m0.rar");
        assert_eq!((listed.generation, &listed.headers, listed.volume, listed.truncated), (RarGeneration::Rar5, &HeaderEncryption::None, Some(Volume::Single), false));
        let encrypted: Vec<&RarEntry> = listed.entries.iter().filter(|entry| entry.encryption != RarEncryption::None).collect();
        assert!(!encrypted.is_empty());
        for entry in encrypted {
            let RarEncryption::Rar50(crypt) = entry.encryption else { panic!("{:?}", entry.encryption) };
            assert!(crypt.lg2count == 15 && crypt.salt != [0; 16] && crypt.iv != [0; 16] && crypt.check_value.is_some());
            assert!(entry.data_is_inside(std::fs::metadata("tests/fixtures/rar-50/v500_p_m0.rar").unwrap().len()));
        }

        let plain = fixture("unencrypted/rars_rar5_stored.rar");
        assert!(!plain.entries.is_empty() && plain.entries.iter().all(|entry| entry.encryption == RarEncryption::None));
    }

    #[test]
    fn an_encryption_header_hides_everything_behind_it() {
        let hidden = fixture("rar-50/v500_hp_m3.rar");
        let HeaderEncryption::Rar50 { crypt, block_at } = hidden.headers else { panic!("{:?}", hidden.headers) };
        assert!(crypt.lg2count == 15 && crypt.check_value.is_some() && crypt.iv == [0; 16] && !crypt.hashmac);
        assert!(block_at > 8);
        assert!(hidden.entries.is_empty());
        assert_eq!(hidden.volume, None, "the header that says so is encrypted");
    }

    #[test]
    fn an_entry_is_what_its_header_says() {
        let bytes = archive(&[
            main(&[0]),
            Entry { name: b"dir", file_flags: 0x01, ..Entry::default() }.block(),
            // method 3 of the RAR 7 algorithm, solid
            Entry { name: b"a.txt", unpacked: 900, compression: 0x01C1, records: vec![crypt_record(3, 15)], data: &[0x5A; 32], ..Entry::default() }.block(),
            Entry { head_type: SERVICE, name: b"CMT", unpacked: 5, data: b"hello", ..Entry::default() }.block(),
            end(),
        ]);
        let listed = parsed(bytes);
        let [directory, file, service] = listed.entries.as_slice() else { panic!("three entries: {:?}", listed.entries) };

        assert_eq!((directory.kind, directory.name_lossy().as_str(), directory.packed), (EntryKind::Directory, "dir", 0));
        assert_eq!((file.kind, file.packed, file.unpacked, file.crc32, file.has_crc32), (EntryKind::File, 32, Some(900), 0xCAFE_F00D, true));
        assert_eq!((file.method, file.algorithm, file.stored, file.solid), (3, 1, false, true));
        assert_eq!(file.encryption, RarEncryption::Rar50(Rar50Record { lg2count: 15, salt: [0x11; 16], iv: [0x22; 16], check_value: Some([0xAA; 8]), unused: None, hashmac: true }));
        assert_eq!((service.kind, service.stored, service.encryption), (EntryKind::Service, true, RarEncryption::None));
        assert!(!listed.truncated);
    }

    #[test]
    fn a_checksum_can_be_a_blake2sp_digest_or_missing() {
        let entry = |crc32: Option<u32>, records: Vec<Vec<u8>>| parsed(archive(&[main(&[0]), Entry { unpacked: 4, crc32, records, data: &[0; 16], ..Entry::default() }.block()])).entries[0].clone();

        let digest = entry(Some(7), vec![blake2_record(), crypt_record(0, 15)]);
        assert_eq!((digest.blake2sp, digest.has_crc32, digest.crc32), (Some([0xB2; 32]), true, 7));
        assert!(matches!(digest.encryption, RarEncryption::Rar50(crypt) if crypt.check_value.is_none() && !crypt.hashmac));

        let none = entry(None, vec![crypt_record(0, 15)]);
        assert_eq!((none.has_crc32, none.crc32, none.blake2sp, none.packed), (false, 0, None, 16));
        assert!(matches!(none.encryption, RarEncryption::Rar50(_)), "the fields behind the missing CRC-32 are read in their place");
    }

    #[test]
    fn an_unpacked_size_can_be_unknown() {
        let bytes = archive(&[main(&[0]), Entry { file_flags: 0x08, compression: 0x0180, data: &[1, 2, 3], ..Entry::default() }.block()]);
        assert_eq!(parsed(bytes).entries[0].unpacked, None);
    }

    #[test]
    fn a_record_the_format_refuses_keeps_its_entry_encrypted() {
        let record = |version: u8, lg2count: u8, len: usize| {
            let mut record = crypt_record(1, lg2count);
            record[1] = version;
            record.truncate(len);
            parsed(archive(&[main(&[0]), Entry { unpacked: 4, records: vec![record], data: &[0; 16], ..Entry::default() }.block()])).entries[0].encryption
        };
        assert!(matches!(record(0, 15, 48), RarEncryption::Rar50(_)));
        assert_eq!(record(1, 15, 48), RarEncryption::Unknown { version: 1 });
        assert_eq!(record(0, 15, 20), RarEncryption::Unreadable(Scheme::Rar50), "a record that ends inside its salt");
        // a count its own software refuses is read as it stands
        assert!(matches!(record(0, 25, 48), RarEncryption::Rar50(crypt) if crypt.lg2count == 25 && !crypt.rounds_accepted()));
    }

    #[test]
    fn a_main_header_says_which_volume_this_is() {
        let volume = |flags: &[u8]| parsed(archive(&[main(flags), end()])).volume;
        assert_eq!(volume(&[0]), Some(Volume::Single));
        assert_eq!(volume(&[1]), Some(Volume::First));
        assert_eq!(volume(&[3, 0]), Some(Volume::First));
        assert_eq!(volume(&[3, 2]), Some(Volume::Later));
        assert_eq!(volume(&[2, 7]), Some(Volume::Single), "a number without the flag for a volume");

        assert_eq!(fixture("unencrypted/vols.part1.rar").volume, Some(Volume::First));
        assert_eq!(fixture("unparseable/vols.part2.rar").volume, Some(Volume::Later));
        let later = fixture("unparseable/big.part2.rar");
        assert!(later.entries[0].split_before && later.entries[0].split_after);
    }

    #[test]
    fn a_comment_is_the_data_of_its_service_record() {
        let text = b"A short comment.";
        let comment = |crc32: u32| Entry { head_type: SERVICE, name: b"CMT", unpacked: 16, crc32: Some(crc32), data: text, ..Entry::default() }.block();
        let with = |record: Vec<u8>| parsed(archive(&[main(&[0]), record, Entry { name: b"a.txt", unpacked: 1, data: b"a", ..Entry::default() }.block(), end()]));

        let read = with(comment(crc32fast::hash(text)));
        assert_eq!(read.comment.as_deref(), Some(&text[..]));
        assert_eq!(read.entries.len(), 2, "the record is an entry all the same");
        assert_eq!(with(comment(0xCAFE_F00D)).comment, None, "a checksum that is not the one of the text");

        // packed, encrypted, or under another name: not a comment that can be read
        let odd = |change: fn(&mut Entry<'_>)| {
            let mut entry = Entry { head_type: SERVICE, name: b"CMT", unpacked: 16, crc32: Some(crc32fast::hash(text)), data: text, ..Entry::default() };
            change(&mut entry);
            with(entry.block()).comment
        };
        assert_eq!(odd(|entry| entry.compression = 0x0180), None);
        assert_eq!(odd(|entry| entry.records = vec![crypt_record(0, 15)]), None);
        assert_eq!(odd(|entry| entry.name = b"QO"), None);
        assert_eq!(odd(|entry| entry.unpacked = 17), None);
        assert_eq!(odd(|entry| entry.head_type = 2), None, "a file that is named like the record");
    }

    /// The sizes of the format are numbers of up to 64 bits. Each of these used to be added
    /// to an offset without a check, which ended the process.
    #[test]
    fn a_size_of_any_width_is_an_error_or_a_result_and_never_a_panic() {
        // the size of the first header
        let mut bytes = archive(&[]);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&MAX);
        bytes.extend_from_slice(&[0; 32]);
        assert!(parse(&Source::from_bytes(bytes), 0, false).is_err(), "a size field of ten bytes is none");

        // the size of the data of a block
        let body = [&[1, 0x02][..], &MAX].concat();
        let mut bytes = archive(&[block(&body)]);
        bytes.extend_from_slice(&[0; 32]);
        let cut = parsed(bytes);
        assert_eq!((cut.entries.len(), cut.truncated), (0, true));

        // the length of a name
        let body = [&[2, 0x00][..], &[0, 0, 0, 0, 0], &MAX, b"name"].concat();
        let named = parsed(archive(&[main(&[0]), block(&body), end()]));
        assert_eq!((named.entries.len(), named.entries[0].name.as_slice(), named.truncated), (1, &b"name"[..], false));

        // the size of the extra area: larger than the header, and larger than what is left of it
        for extra in [vint(0x7FFF_FFFF), MAX.to_vec(), vint(12)] {
            let body = [&[2, 0x01][..], &extra, &[0, 0, 0, 0, 0, 0], &[0; 8]].concat();
            let odd = parsed(archive(&[main(&[0]), block(&body), end()]));
            assert!(odd.entries.len() <= 1 && !odd.truncated, "{extra:?}");
            assert!(odd.entries.iter().all(|entry| entry.encryption == RarEncryption::None));
        }

        // the size of a record in the extra area
        let extra = [&MAX[..], &[0x01]].concat();
        let body = [&[2, 0x01][..], &vint(u64::try_from(extra.len()).unwrap()), &[0, 0, 0, 0, 0, 0], &extra].concat();
        let record = parsed(archive(&[main(&[0]), block(&body), end()]));
        assert_eq!((record.entries.len(), record.entries[0].encryption), (1, RarEncryption::None));

        // the size of the data of an entry
        let huge = parsed(archive(&[main(&[0]), Entry { packed: Some(u64::MAX), ..Entry::default() }.block()]));
        assert_eq!((huge.entries.len(), huge.entries[0].packed, huge.truncated), (1, u64::MAX, true));
        assert!(!huge.entries[0].data_is_inside(u64::MAX));
    }

    #[test]
    fn what_is_no_block_ends_the_walk() {
        let whole = archive(&[main(&[0]), Entry { name: b"a.txt", unpacked: 1, data: b"a", ..Entry::default() }.block(), end()]);
        assert_eq!(parsed(whole.clone()).entries.len(), 1);

        // a header that is cut off by the end of the file, at every place
        let entry_at = 8 + main(&[0]).len();
        let data_at = whole.len() - end().len() - 1;
        for len in entry_at + 1..=data_at {
            let cut = parsed(whole[..len].to_vec());
            // fewer than seven bytes are no block; more are one that the file cuts off
            assert_eq!(cut.truncated, len >= entry_at + 7, "{len} bytes: {cut:?}");
            // the entry is there with its header, and its one byte of data is missing
            assert_eq!(cut.entries.len(), usize::from(len == data_at), "{len} bytes");
        }

        // zeros behind the last block are no block
        let mut padded = archive(&[main(&[0]), Entry { name: b"a.txt", unpacked: 1, data: b"a", ..Entry::default() }.block()]);
        padded.extend_from_slice(&[0; 64]);
        let walked = parsed(padded);
        assert_eq!((walked.entries.len(), walked.truncated), (1, false));
    }

    #[test]
    fn a_signature_with_nothing_behind_it_is_an_error() {
        assert!(parse(&Source::from_bytes(RAR5_SIGNATURE.to_vec()), 0, false).is_err());
        assert!(parse(&Source::from_bytes(RAR5_SIGNATURE[..5].to_vec()), 0, false).is_err());
        let mut zeros = RAR5_SIGNATURE.to_vec();
        zeros.extend_from_slice(&[0; 64]);
        assert!(parse(&Source::from_bytes(zeros), 0, false).is_err());
        // a first header that says it is longer than the file
        let mut cut = RAR5_SIGNATURE.to_vec();
        cut.extend_from_slice(&[0, 0, 0, 0, 0x7F, 1, 0]);
        assert!(parse(&Source::from_bytes(cut), 0, false).is_err());
    }

    #[test]
    fn a_signature_inside_a_program_needs_a_main_header_with_its_checksum() {
        let good = archive(&[main(&[0]), end()]);
        assert!(parse(&Source::from_bytes(good.clone()), 0, true).is_ok());

        let mut wrong_crc = good;
        wrong_crc[8] ^= 1;
        assert!(parse(&Source::from_bytes(wrong_crc.clone()), 0, true).is_err());
        assert!(parse(&Source::from_bytes(wrong_crc), 0, false).is_ok(), "at the start of a file the header is taken at its word");

        let file_first = archive(&[Entry { name: b"a.txt", unpacked: 1, data: b"a", ..Entry::default() }.block()]);
        assert!(parse(&Source::from_bytes(file_first.clone()), 0, true).is_err());
        assert_eq!(parsed(file_first).entries.len(), 1);

        assert!(parse(&Source::open(std::path::Path::new("tests/fixtures/rar-50/v730_hp_m3.rar"), 0).unwrap(), 0, true).is_ok(), "an encryption header counts");
    }
}
