//! The parser for RAR 1.3 and 1.4 archives (`RE~^`).
//!
//! The format is a main header of seven bytes, which can carry the archive comment, and then
//! file headers of 21 bytes and a name, each followed by its data. There is no end block: the
//! archive ends where the file does.
//!
//! The archive comment can be packed and is then stored under a fixed key. That is not
//! encryption, and it is the one thing this parser unpacks.
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

use super::encryption::RarEncryption;
use super::headers::RarArchive;
use super::headers::RarEntry;
use super::headers::RarGeneration;
use super::unpack15::Unpack15;
use crate::analysis::EntryKind;
use crate::analysis::Volume;
use crate::formats::source::Cursor;
use crate::formats::source::Source;

/// Size of the main header without a comment: the signature, its own size and its flags.
const MAIN_HEAD: u64 = 7;
/// Size of a file header without its name.
const FILE_HEAD: u64 = 21;

/// Main header flag: the archive is a volume of a set.
const MHD_VOLUME: u8 = 0x01;
/// Main header flag: an archive comment follows the fixed part of the header.
const MHD_COMMENT: u8 = 0x02;
/// Main header flag: every file but the first is packed as a continuation of the one before.
const MHD_SOLID: u8 = 0x08;
/// Main header flag: the archive comment is packed, and stored under a fixed key.
const MHD_PACK_COMMENT: u8 = 0x10;

/// File header flag: the entry continues from the volume before.
const LHD_SPLIT_BEFORE: u8 = 0x01;
/// File header flag: the entry continues in the volume after.
const LHD_SPLIT_AFTER: u8 = 0x02;
/// File header flag: the entry is encrypted.
const LHD_PASSWORD: u8 = 0x04;

/// File attribute of DOS: a directory.
const ATTR_DIRECTORY: u8 = 0x10;

/// The archive comment, which the cursor stands in front of: two bytes of length and the text.
///
/// A packed comment is two more bytes with the length it unpacks to, and then the packed text
/// under the key `{0, 7, 77}` of the RAR 1.3 cipher. The key is the same in every archive and
/// has nothing to do with a password. Unpacking is bounded by the format: both lengths are 16
/// bits wide.
fn comment(cursor: &mut Cursor<'_>, head_size: u64, packed: bool) -> Option<Vec<u8>> {
    let length = u64::from(cursor.u16_le().ok()?);
    // the comment lies inside the main header, behind its fixed bytes and its own length
    if length == 0 || MAIN_HEAD.saturating_add(2).saturating_add(length) > head_size {
        return None;
    }
    if !packed {
        return cursor.read_vec(length).ok();
    }

    let unpacked = usize::from(cursor.u16_le().ok()?);
    let mut body = cursor.read_vec(length.checked_sub(2)?).ok()?;
    let mut key = [0_u8, 7, 77];
    for byte in &mut body {
        key[1] = key[1].wrapping_add(key[2]);
        key[0] = key[0].wrapping_add(key[1]);
        *byte = byte.wrapping_sub(key[0]);
    }
    let mut decoder = Unpack15::new();
    let _ = decoder.decode(&body, unpacked, false).ok()?;
    Some(decoder.member().to_vec())
}

/// Parse the RAR 1.3 or 1.4 archive that starts `start` bytes into `source`.
///
/// An error when the main header is not all there or is shorter than a main header is. From
/// there on the parser takes what it can read. It stops at the first bytes that are no file
/// header and says where in [`RarArchive::broken_at`], unless they are the end of the file;
/// it says so in [`RarArchive::truncated`] when a header or the data of an entry reaches past
/// the end of the file. The headers of this generation have no checksum.
pub(crate) fn parse(source: &Source, start: u64) -> anyhow::Result<RarArchive> {
    let mut cursor = source.cursor(start);
    let [_, _, _, _, size_low, size_high, flags] = cursor.array::<7>().context("RAR 1.4: the file ends inside the main header")?;
    let head_size = u64::from(u16::from_le_bytes([size_low, size_high]));
    anyhow::ensure!(head_size >= MAIN_HEAD, "RAR 1.4: a main header of {head_size} bytes is no main header");

    let mut archive = RarArchive::new(RarGeneration::Rar1);
    if flags & MHD_COMMENT != 0 {
        archive.comment = comment(&mut cursor, head_size, flags & MHD_PACK_COMMENT != 0);
    }
    let solid = flags & MHD_SOLID != 0;
    archive.solid = solid;

    // every pass moves `pos` on by 21 bytes or more, or ends the loop
    let mut pos = start.saturating_add(head_size);
    loop {
        if cursor.seek(pos).is_err() {
            archive.truncated = true;
            break;
        }
        let Ok(fixed) = cursor.array::<21>() else {
            // the end of the file is the end of the archive: this generation has no end block
            archive.broken_at = (pos < source.len()).then_some(pos);
            break;
        };
        let packed = u64::from(u32::from_le_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]));
        let unpacked = u64::from(u32::from_le_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]));
        let checksum = u16::from_le_bytes([fixed[8], fixed[9]]);
        let entry_head = u64::from(u16::from_le_bytes([fixed[10], fixed[11]]));
        let [attributes, entry_flags, _, name_size, method] = [fixed[16], fixed[17], fixed[18], fixed[19], fixed[20]];
        if entry_head < FILE_HEAD {
            archive.broken_at = Some(pos);
            break;
        }
        // the name ends where the header does, whatever its length says
        let Ok(name) = cursor.read_vec(u64::from(name_size).min(entry_head - FILE_HEAD)) else {
            archive.truncated = true;
            break;
        };

        let kind = if attributes & ATTR_DIRECTORY != 0 { EntryKind::Directory } else { EntryKind::File };
        let mut entry = RarEntry::new(kind, pos.saturating_add(entry_head));
        entry.header_offset = pos;
        entry.name = name;
        entry.packed = packed;
        entry.unpacked = Some(unpacked);
        entry.crc32 = u32::from(checksum);
        entry.method = method;
        entry.stored = method == 0;
        entry.split_before = entry_flags & LHD_SPLIT_BEFORE != 0;
        entry.split_after = entry_flags & LHD_SPLIT_AFTER != 0;
        // the format flags the archive and no file: every file but the first continues the one before
        entry.solid = solid && !archive.entries.is_empty();
        if entry_flags & LHD_PASSWORD != 0 {
            entry.encryption = RarEncryption::Rar13;
        }

        let inside = entry.data_is_inside(source.len());
        pos = entry.data_offset.saturating_add(packed);
        archive.entries.push(entry);
        if !inside {
            archive.truncated = true;
            break;
        }
    }

    // there is no flag for the first volume: it is the one whose first file starts in it
    let continues = archive.entries.first().is_some_and(|entry| entry.split_before);
    archive.volume = Some(match (flags & MHD_VOLUME != 0, continues) {
        (false, _) => Volume::Single,
        (true, false) => Volume::First,
        (true, true) => Volume::Later,
    });
    Ok(archive)
}

#[cfg(test)]
mod tests {
    use super::super::testing::rar1::file;
    use super::super::testing::rar1::main;
    use super::*;

    fn parsed(bytes: Vec<u8>) -> RarArchive {
        parse(&Source::from_bytes(bytes), 0).unwrap()
    }

    fn fixture(rel: &str) -> RarArchive {
        parsed(std::fs::read(format!("tests/fixtures/{rel}")).unwrap())
    }

    #[test]
    fn the_entries_of_a_fixture_are_read_with_their_flags() {
        let archive = fixture("rar-13/rar14-solid-password.rar");
        assert_eq!((archive.generation, archive.volume, archive.truncated), (RarGeneration::Rar1, Some(Volume::Single), false));
        assert_eq!(archive.entries.len(), 3);
        assert!(archive.entries.iter().all(|entry| entry.encryption == RarEncryption::Rar13 && entry.kind == EntryKind::File));
        // the archive is solid: every file but the first continues the one before
        assert_eq!(archive.entries.iter().map(|entry| entry.solid).collect::<Vec<_>>(), [false, true, true]);

        let plain = fixture("unencrypted/rar14-solid.rar");
        assert!(plain.entries.iter().all(|entry| entry.encryption == RarEncryption::None));
    }

    #[test]
    fn an_entry_is_what_its_header_says() {
        let mut bytes = main(0);
        bytes.extend_from_slice(&file(b"DIR", 0, ATTR_DIRECTORY, 0, 0, 0, b""));
        bytes.extend_from_slice(&file(b"A.TXT", LHD_PASSWORD, 0, 3, 5, 900, b"abcde"));
        bytes.extend_from_slice(&file(b"B.TXT", 0, 0x20, 0, 2, 2, b"xy"));
        let archive = parsed(bytes);

        let [directory, packed, stored] = archive.entries.as_slice() else { panic!("three entries: {:?}", archive.entries) };
        assert_eq!((directory.kind, directory.name.as_slice(), directory.packed), (EntryKind::Directory, &b"DIR"[..], 0));
        assert_eq!((packed.kind, packed.name_lossy().as_str(), packed.encryption), (EntryKind::File, "A.TXT", RarEncryption::Rar13));
        assert_eq!((packed.packed, packed.unpacked, packed.crc32, packed.method, packed.stored), (5, Some(900), 0x1234, 3, false));
        assert_eq!((stored.encryption, stored.stored, stored.data_offset), (RarEncryption::None, true, u64::try_from(7 + 24 + 26 + 5 + 26).unwrap()));
        assert!(!archive.truncated);
    }

    #[test]
    fn a_volume_is_the_first_when_its_first_file_starts_in_it() {
        let volume = |first_flags: u8| {
            let mut bytes = main(MHD_VOLUME);
            bytes.extend_from_slice(&file(b"A.BIN", first_flags, 0, 0, 2, 2, b"ab"));
            parsed(bytes)
        };
        assert_eq!(volume(LHD_SPLIT_AFTER).volume, Some(Volume::First));
        let later = volume(LHD_SPLIT_BEFORE | LHD_SPLIT_AFTER);
        assert_eq!(later.volume, Some(Volume::Later));
        assert!(later.entries[0].split_before && later.entries[0].split_after && later.entries[0].is_split());

        assert_eq!(fixture("unencrypted/r14volst.rar").volume, Some(Volume::First));
        assert_eq!(fixture("unknown-pw/edge_rars_ESPLIT.RAR").volume, Some(Volume::First));
    }

    #[test]
    fn data_or_a_header_past_the_end_of_the_file_is_said() {
        // the data of the entry is not all there
        let mut bytes = main(0);
        bytes.extend_from_slice(&file(b"A.BIN", LHD_PASSWORD, 0, 0, 1000, 1000, b"only this"));
        let archive = parsed(bytes);
        assert_eq!((archive.entries.len(), archive.truncated), (1, true));
        assert!(!archive.entries[0].data_is_inside(7 + 26 + 9));

        // a size of four gigabytes costs nothing
        let mut bytes = main(0);
        bytes.extend_from_slice(&file(b"A.BIN", 0, 0, 0, u32::MAX, u32::MAX, b""));
        assert!(parsed(bytes).truncated);

        // the name is cut off by the end of the file
        let mut bytes = main(0);
        let header = file(b"LONGNAME.TXT", 0, 0, 0, 0, 0, b"");
        bytes.extend_from_slice(&header[..25]);
        let archive = parsed(bytes);
        assert_eq!((archive.entries.len(), archive.truncated), (0, true));

        // a main header that says it is longer than the file
        let mut bytes = main(0);
        bytes[4] = 200;
        assert!(parsed(bytes).truncated);

        // bytes that are too few for a header are no header and no more
        let mut bytes = main(0);
        bytes.extend_from_slice(&[0xEE; 20]);
        let archive = parsed(bytes);
        assert_eq!((archive.entries.len(), archive.truncated), (0, false));
    }

    #[test]
    fn a_main_header_that_is_none_is_an_error() {
        assert!(parse(&Source::from_bytes(b"RE~^".to_vec()), 0).is_err());
        assert!(parse(&Source::from_bytes(b"RE~^\x06\x00\x00".to_vec()), 0).is_err());
        assert!(parse(&Source::from_bytes(b"RE~^\x00\x00\x00 and more".to_vec()), 0).is_err());
        assert_eq!(parsed(b"RE~^\x07\x00\x00".to_vec()).entries.len(), 0);
    }

    #[test]
    fn a_file_header_shorter_than_a_file_header_ends_the_walk() {
        let mut bytes = main(0);
        bytes.extend_from_slice(&file(b"A.TXT", 0, 0, 0, 1, 1, b"a"));
        let mut broken = file(b"B.TXT", 0, 0, 0, 1, 1, b"b");
        broken[10] = 20;
        bytes.extend_from_slice(&broken);
        let archive = parsed(bytes);
        assert_eq!((archive.entries.len(), archive.truncated), (1, false));
    }

    #[test]
    fn a_name_ends_where_its_header_does() {
        let mut bytes = main(0);
        let mut header = file(b"AB", 0, 0, 0, 0, 0, b"");
        header[19] = 200;
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&[b'x'; 300]);
        assert_eq!(parsed(bytes).entries[0].name, b"AB");
    }

    #[test]
    fn a_plain_comment_is_read() {
        let archive = fixture("unencrypted/rar14_with_comment.rar");
        assert_eq!(archive.comment.as_deref(), Some(&b"ArchiveWolf RAR 1.4 test comment"[..]));
        assert!(!archive.entries.is_empty(), "the entries behind the comment are read");
    }

    #[test]
    fn a_packed_comment_is_unpacked() {
        let archive = fixture("unencrypted/rar14_packed_comment.rar");
        assert_eq!(String::from_utf8(archive.comment.unwrap()).unwrap().trim_end(), "This is the archive comment.");
    }

    #[test]
    fn a_comment_that_does_not_lie_inside_the_main_header_is_none() {
        let with_comment = |head: u8, flags: u8, rest: &[u8]| {
            let mut bytes = b"RE~^".to_vec();
            bytes.extend_from_slice(&[head, 0, flags]);
            bytes.extend_from_slice(rest);
            parsed(bytes).comment
        };
        assert_eq!(with_comment(12, MHD_COMMENT, &[3, 0, b'a', b'b', b'c']), Some(b"abc".to_vec()));
        assert_eq!(with_comment(12, 0, &[3, 0, b'a', b'b', b'c']), None, "no flag, no comment");
        assert_eq!(with_comment(11, MHD_COMMENT, &[3, 0, b'a', b'b', b'c']), None, "longer than the header");
        assert_eq!(with_comment(9, MHD_COMMENT, &[0, 0]), None, "an empty one");
        assert_eq!(with_comment(200, MHD_COMMENT, &[100, 0, b'a']), None, "cut off by the end of the file");
        // a packed comment needs the length it unpacks to, and a stream that unpacks to it
        assert_eq!(with_comment(10, MHD_COMMENT | MHD_PACK_COMMENT, &[1, 0, 9]), None);
        assert_eq!(with_comment(20, MHD_COMMENT | MHD_PACK_COMMENT, &[11, 0, 0xFF, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9]), None);
    }
}
