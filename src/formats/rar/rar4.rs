//! The parser for RAR 1.5 to 4.x archives (`Rar!\x1a\x07\x00`).
//!
//! The archive is a chain of blocks. Each starts with seven bytes: a checksum, a type, flags
//! and its own size in 16 bits. A file header and a service header are followed by their data,
//! whose size they give in 32 or 64 bits; some other blocks are followed by data as well.
//!
//! Encryption is said in two places. A flag on the main header means that every block behind
//! it is encrypted, the listing included: each such block has eight bytes of salt in front of
//! it, and without the password not even its size can be read. Without that flag, each file
//! header says whether its data is encrypted, and the version needed to unpack it says how.
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
use super::headers::Fields;
use super::headers::HeaderEncryption;
use super::headers::RAR4_SIGNATURE;
use super::headers::RarArchive;
use super::headers::RarEntry;
use super::headers::RarGeneration;
use super::headers::stored_comment;
use crate::analysis::EntryKind;
use crate::analysis::Scheme;
use crate::analysis::Volume;
use crate::formats::source::Cursor;
use crate::formats::source::Source;

/// The marker block: the first of the block types the format has, which end with the end block.
const HEAD3_MARK: u8 = 0x72;
/// Block type: the main archive header.
const HEAD3_MAIN: u8 = 0x73;
/// Block type: a file.
const HEAD3_FILE: u8 = 0x74;
/// Block type: a comment of RAR 2.9 and earlier, which lies inside another header.
const HEAD3_CMT: u8 = 0x75;
/// Block type: a service record of RAR 2.9 and earlier.
const HEAD3_OLDSERVICE: u8 = 0x77;
/// Block type: a recovery record of RAR 2.9 and earlier.
const HEAD3_PROTECT: u8 = 0x78;
/// Block type: a service record.
const HEAD3_SERVICE: u8 = 0x7A;
/// Block type: the end of the archive.
const HEAD3_ENDARC: u8 = 0x7B;

/// Block flag: the header is followed by data, whose size is its first field.
const LONG_BLOCK: u16 = 0x8000;

/// Main header flag: the archive is a volume of a set.
const MHD_VOLUME: u16 = 0x0001;
/// Main header flag: a comment block lies inside the main header (RAR 2.9 and earlier).
const MHD_COMMENT: u16 = 0x0002;
/// Main header flag: every file but the first is packed as a continuation (RAR 1.5 flags the
/// archive and no file).
const MHD_SOLID: u16 = 0x0008;
/// Main header flag: every block behind the main header is encrypted.
const MHD_PASSWORD: u16 = 0x0080;
/// Main header flag: this is the first volume. Set by RAR 3.0 and later.
const MHD_FIRSTVOLUME: u16 = 0x0100;

/// File header flag: the entry continues from the volume before.
const LHD_SPLIT_BEFORE: u16 = 0x0001;
/// File header flag: the entry continues in the volume after.
const LHD_SPLIT_AFTER: u16 = 0x0002;
/// File header flag: the data is encrypted.
const LHD_PASSWORD: u16 = 0x0004;
/// File header flag: the entry is packed as a continuation of the one before.
const LHD_SOLID: u16 = 0x0010;
/// File header flag: a comment stands inside the header (RAR 2.x), and the checksum of the
/// header covers only what stands in front of it.
const LHD_COMMENT: u16 = 0x0008;
/// File header flags: the size of the dictionary, where all three bits set mean a directory.
const LHD_DIRECTORY: u16 = 0x00E0;
/// File header flag: the sizes have a high half of 32 bits each.
const LHD_LARGE: u16 = 0x0100;
/// File header flag: the name is followed by its packed Unicode form.
const LHD_UNICODE: u16 = 0x0200;
/// File header flag: a salt of eight bytes follows the name.
const LHD_SALT: u16 = 0x0400;

/// File attribute of DOS: a directory. RAR 1.5 marked directories by it.
const ATTR_DIRECTORY: u32 = 0x10;
/// Flag in the attribute field of a comment record: its text is UTF-16.
const SUBHEAD_CMT_UNICODE: u32 = 0x01;

/// Size of the seven bytes every block starts with.
const BLOCK_HEAD: u64 = 7;
/// Size of a main header without a comment.
const MAIN_HEAD: u64 = 13;
/// Size of a file header without its name.
const FILE_HEAD: u64 = 32;
/// Size of the header of a comment block that lies inside a main header.
const COMMENT_HEAD: usize = 13;

/// The first version of the format that flags its first volume and salts its keys.
const VERSION_RAR3: u8 = 29;

/// How far from the end of the file the end block of an archive with encrypted headers is
/// looked for. Anything that follows the archive in its file has to fit in here with it.
pub(crate) const END_BLOCK_SEARCH: u64 = 64 * 1024;

/// Decode the packed Unicode form of a name.
///
/// When `LHD_UNICODE` is set, the name field holds the DOS name, a NUL, and then the name
/// in wide characters, packed. This decodes it to UTF-8, and falls back to the DOS name when
/// there is no packed part or the packed part gives no character, as UnRAR does: the name in
/// front of the NUL is then the whole name, in UTF-8 where a Unix RAR wrote it.
///
/// The encoding is a byte that is the high half of most characters, then groups of four
/// two-bit codes, each followed by what its codes take: one byte for a character below 256,
/// one byte under the common high half, two bytes for any character, or a run that is copied
/// from the DOS name. A run starts in the DOS name at the position the decoded name has
/// reached, which is where `EncodeFileName::Decode` of UnRAR reads it, and ends where the
/// DOS name ends.
fn decode_unicode_name(raw: &[u8]) -> Vec<u8> {
    let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let dos_name = raw.get(..nul_pos).unwrap_or(raw);
    let Some((&high_byte, mut rest)) = raw.get(nul_pos.saturating_add(1)..).unwrap_or_default().split_first() else {
        return dos_name.to_vec();
    };
    let high = u16::from(high_byte) << 8;
    let mut flag_bits = 0u32;
    let mut flags = 0u8;
    let mut wide_name: Vec<u16> = Vec::with_capacity(dos_name.len());

    // every pass takes at least one byte off `rest`, or ends the loop
    while let Some((&next, after)) = rest.split_first() {
        if flag_bits == 0 {
            flags = next;
            flag_bits = 8;
            rest = after;
            continue;
        }
        match flags >> 6 {
            0 => {
                wide_name.push(u16::from(next));
                rest = after;
            },
            1 => {
                wide_name.push(u16::from(next) | high);
                rest = after;
            },
            2 => {
                let Some((&[lo, hi], after)) = rest.split_first_chunk::<2>() else { break };
                wide_name.push(u16::from_le_bytes([lo, hi]));
                rest = after;
            },
            _ => {
                rest = after;
                let correction = if next & 0x80 == 0 {
                    None
                } else {
                    let Some((&correction, after)) = rest.split_first() else { break };
                    rest = after;
                    Some(correction)
                };
                let count = usize::from(next & 0x7F) + 2;
                let run = dos_name.get(wide_name.len()..).unwrap_or_default().iter().take(count);
                wide_name.extend(run.map(|&byte| correction.map_or(u16::from(byte), |correction| u16::from(byte.wrapping_add(correction)) | high)));
            },
        }
        flags <<= 2;
        flag_bits -= 2;
    }

    if wide_name.is_empty() {
        return dos_name.to_vec();
    }
    String::from_utf16_lossy(&wide_name).into_bytes()
}

/// One block: the seven bytes it starts with.
#[derive(Debug, Clone, Copy)]
struct Block {
    /// Where the block starts.
    pos: u64,
    /// Its type.
    head_type: u8,
    /// Its flags.
    flags: u16,
    /// Size of its header.
    size: u64,
    /// Where its header ends, and its data starts when it has any.
    end: u64,
}

/// How reading the next block went.
enum Step {
    /// A block whose header lies inside the file.
    Block(Block),
    /// Nothing that is a block: the end of the file, or bytes that are no header.
    End,
    /// A block whose header reaches past the end of the file.
    Truncated,
}

/// Read the seven bytes of the block the cursor stands in front of.
fn read_block(cursor: &mut Cursor<'_>, len: u64) -> Step {
    let pos = cursor.position();
    let Ok([_, _, head_type, flags_low, flags_high, size_low, size_high]) = cursor.array::<7>() else { return Step::End };
    let size = u64::from(u16::from_le_bytes([size_low, size_high]));
    if size < BLOCK_HEAD {
        return Step::End;
    }
    match pos.checked_add(size) {
        Some(end) if end <= len => Step::Block(Block { pos, head_type, flags: u16::from_le_bytes([flags_low, flags_high]), size, end }),
        _ => Step::Truncated,
    }
}

/// Whether a header holds against its checksum: its first two bytes are the low half of the
/// CRC-32 over the rest of it.
fn checksum_holds(header: &[u8]) -> bool {
    match header.split_first_chunk::<2>() {
        Some((stored, covered)) => crc32fast::hash(covered) & 0xFFFF == u32::from(u16::from_le_bytes(*stored)),
        None => false,
    }
}

/// A file or service header, and the version that is needed to unpack its data.
///
/// `header` is the whole header from its first byte, at least [`FILE_HEAD`] bytes of it. A
/// field that the header is too short for is read as UnRAR reads it, as zero, with one
/// exception: a salt that is flagged and not there makes the entry unreadable and not salted
/// with zeros.
fn read_entry(header: &[u8], block: &Block, file_block: bool) -> Option<(RarEntry, u8)> {
    let fixed: &[u8; 32] = header.first_chunk()?;
    let flags = block.flags;
    let packed_low = u32::from_le_bytes([fixed[7], fixed[8], fixed[9], fixed[10]]);
    let unpacked_low = u32::from_le_bytes([fixed[11], fixed[12], fixed[13], fixed[14]]);
    let crc32 = u32::from_le_bytes([fixed[16], fixed[17], fixed[18], fixed[19]]);
    let (unp_ver, method) = (fixed[24], fixed[25]);
    let name_size = usize::from(u16::from_le_bytes([fixed[26], fixed[27]]));
    let attributes = u32::from_le_bytes([fixed[28], fixed[29], fixed[30], fixed[31]]);

    let mut fields = Fields::new(header);
    let _ = fields.seek(fixed.len());
    let large = flags & LHD_LARGE != 0;
    let (packed_high, unpacked_high) = if large { (fields.u32_le().unwrap_or(0), fields.u32_le().unwrap_or(0)) } else { (0, 0) };
    // all bits set mean that the size is not known: the entry was packed from a stream
    let unknown = unpacked_low == u32::MAX && (!large || unpacked_high == u32::MAX);

    let raw_name = fields.bytes_up_to(name_size);
    let salted = flags & LHD_SALT != 0;
    if !file_block {
        // a service header keeps data of its own between its name and its salt
        let own = header.len().saturating_sub(name_size).saturating_sub(fixed.len()).saturating_sub(if salted { 8 } else { 0 });
        let _ = fields.bytes_up_to(own);
    }
    let salt = if salted { Some(fields.array::<8>()) } else { None };

    let directory = flags & LHD_DIRECTORY == LHD_DIRECTORY || (unp_ver < 20 && attributes & ATTR_DIRECTORY != 0);
    let kind = match (file_block, directory) {
        (false, _) => EntryKind::Service,
        (true, true) => EntryKind::Directory,
        (true, false) => EntryKind::File,
    };
    let mut entry = RarEntry::new(kind, block.end);
    entry.name = if file_block && flags & LHD_UNICODE != 0 { decode_unicode_name(raw_name) } else { raw_name.to_vec() };
    entry.packed = u64::from(packed_low) | (u64::from(packed_high) << 32);
    entry.unpacked = (!unknown).then_some(u64::from(unpacked_low) | (u64::from(unpacked_high) << 32));
    entry.crc32 = crc32;
    entry.method = method;
    entry.stored = method == 0x30;
    entry.split_before = flags & LHD_SPLIT_BEFORE != 0;
    entry.split_after = flags & LHD_SPLIT_AFTER != 0;
    entry.solid = file_block && flags & LHD_SOLID != 0;
    if flags & LHD_PASSWORD != 0 {
        entry.encryption = match (RarEncryption::of_unpack_version(unp_ver, salt.flatten()), salt) {
            (RarEncryption::Rar30 { .. }, Some(None)) => RarEncryption::Unreadable(Scheme::Rar30),
            (method, _) => method,
        };
    }
    Some((entry, unp_ver))
}

/// The comment of RAR 2.9 and earlier, which lies inside the main header as a block of its
/// own, when it is stored and not packed and its checksum is the one of its text.
fn embedded_comment(header: &[u8]) -> Option<Vec<u8>> {
    let block = header.get(usize::try_from(MAIN_HEAD).ok()?..)?;
    let head: &[u8; COMMENT_HEAD] = block.first_chunk()?;
    let size = usize::from(u16::from_le_bytes([head[5], head[6]]));
    let (method, checksum) = (head[10], u16::from_le_bytes([head[11], head[12]]));
    if head[2] != HEAD3_CMT || method != 0x30 {
        return None;
    }
    let text = block.get(COMMENT_HEAD..size)?;
    // the low half of the CRC-32 of the text
    (!text.is_empty() && crc32fast::hash(text) & 0xFFFF == u32::from(checksum)).then(|| text.to_vec())
}

/// The comment of RAR 3 and 4: the data of the service record `CMT`, when it is stored. Its
/// text is UTF-16 when the record says so.
fn service_comment(source: &Source, entry: &RarEntry, header: &[u8]) -> Option<Vec<u8>> {
    let text = stored_comment(source, entry)?;
    let attributes = header.get(28..32).and_then(|field| field.first_chunk::<4>()).map(|field| u32::from_le_bytes(*field))?;
    if attributes & SUBHEAD_CMT_UNICODE == 0 {
        return Some(text);
    }
    let wide: Vec<u16> = text.chunks_exact(2).filter_map(|pair| pair.first_chunk::<2>()).map(|pair| u16::from_le_bytes(*pair)).collect();
    Some(String::from_utf16_lossy(&wide).into_bytes())
}

/// Whether a volume is the first of its set or a later one.
///
/// RAR 3.0 and later flag the first volume. Earlier versions do not, and there the first
/// volume is the one whose first file starts in it. `first_file` is whether the first file
/// header continues from the volume before, and the version that is needed to unpack it;
/// `None` when the volume shows no file header.
fn which_volume(main_flags: u16, first_file: Option<(bool, u8)>) -> Volume {
    if main_flags & MHD_VOLUME == 0 {
        Volume::Single
    } else if main_flags & MHD_FIRSTVOLUME != 0 {
        Volume::First
    } else {
        match first_file {
            Some((false, unp_ver)) if unp_ver < VERSION_RAR3 => Volume::First,
            _ => Volume::Later,
        }
    }
}

/// Hold a block of a type the format does not have against its checksum, and leave the cursor
/// where it stood.
///
/// Such a block is passed over. A file header whose type byte is damaged is one, and its
/// entry would be gone from the listing without a word: its checksum says so. The blocks the
/// format does have besides the main, file and service headers are not checked, since several
/// of the old ones never had a checksum that holds (`Archive::ReadHeader15` of UnRAR).
fn unknown_block_checked(cursor: &mut Cursor<'_>, block: &Block, archive: &mut RarArchive) {
    if (HEAD3_MARK..=HEAD3_ENDARC).contains(&block.head_type) {
        return;
    }
    let back = cursor.position();
    let header = cursor.seek(block.pos).ok().and_then(|()| cursor.read_vec(block.size).ok());
    if !header.is_some_and(|header| checksum_holds(&header)) {
        let _ = archive.bad_checksum_at.get_or_insert(block.pos);
    }
    // a place the cursor stood at a moment ago
    drop(cursor.seek(back));
}

/// Parse the RAR 1.5 to 4.x archive that starts `start` bytes into `source`.
///
/// An error when the marker is not followed by a block. With `strict`, which is for a marker
/// found inside a program, that block also has to be a main header. From there on the parser
/// takes what it can read. It stops at the first bytes that are no block and says where in
/// [`RarArchive::broken_at`], unless they are the end of the file; it says so in
/// [`RarArchive::truncated`] when a block or the data of an entry reaches past the end of the
/// file.
///
/// The main header and every file and service header are held against their checksum, as
/// `Archive::ReadHeader15` of UnRAR does it: the low half of the CRC-32 over the header from
/// its type on, which for a main header is its thirteen fixed bytes. A file header with a
/// comment inside it (RAR 2.x) has a checksum over part of it only and is not checked. The
/// first header that fails is in [`RarArchive::bad_checksum_at`], and the walk goes on.
pub(crate) fn parse(source: &Source, start: u64, strict: bool) -> anyhow::Result<RarArchive> {
    let len = source.len();
    let mut archive = RarArchive::new(RarGeneration::Rar4);
    let mut cursor = source.cursor(start);
    cursor.skip(u64::try_from(RAR4_SIGNATURE.len())?).context("RAR: the file ends inside the marker")?;

    let mut main_flags = 0_u16;
    let mut first_file = None;
    let mut files = 0_usize;

    // every pass moves the cursor on by seven bytes or more, or ends the loop
    let mut first = true;
    loop {
        let at = cursor.position();
        let block = match read_block(&mut cursor, len) {
            Step::Block(block) => block,
            Step::End if first => anyhow::bail!("RAR: the marker is not followed by a header"),
            Step::Truncated if first => anyhow::bail!("RAR: the file ends inside its first header"),
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
        if std::mem::take(&mut first) && strict {
            anyhow::ensure!(block.head_type == HEAD3_MAIN && block.size >= MAIN_HEAD, "RAR: the marker is not followed by a main header");
        }

        let mut next = Some(block.end);
        match block.head_type {
            HEAD3_MAIN => {
                main_flags = block.flags;
                let fixed = cursor.seek(block.pos).ok().and_then(|()| cursor.read_vec(block.size.min(MAIN_HEAD)).ok());
                if !fixed.is_some_and(|fixed| checksum_holds(&fixed)) {
                    let _ = archive.bad_checksum_at.get_or_insert(block.pos);
                }
                if block.flags & MHD_PASSWORD != 0 {
                    archive.headers = HeaderEncryption::Rar30 { salt_at: block.end, volume: block.flags & MHD_VOLUME != 0 };
                    break;
                }
                if block.flags & MHD_COMMENT != 0 && cursor.seek(block.pos).is_ok() {
                    archive.comment = cursor.read_vec(block.size).ok().and_then(|header| embedded_comment(&header));
                }
            },
            HEAD3_FILE | HEAD3_SERVICE => {
                let file_block = block.head_type == HEAD3_FILE;
                let header = if block.size < FILE_HEAD { None } else { cursor.seek(block.pos).ok().and_then(|()| cursor.read_vec(block.size).ok()) };
                let Some((mut entry, unp_ver)) = header.and_then(|header| {
                    let (entry, unp_ver) = read_entry(&header, &block, file_block)?;
                    if block.flags & LHD_COMMENT == 0 && !checksum_holds(&header) {
                        let _ = archive.bad_checksum_at.get_or_insert(block.pos);
                    }
                    if !file_block && archive.comment.is_none() {
                        archive.comment = service_comment(source, &entry, &header);
                    }
                    Some((entry, unp_ver))
                }) else {
                    // a block that says it is a file header and is none
                    archive.broken_at = Some(block.pos);
                    break;
                };
                entry.header_offset = block.pos;
                if file_block {
                    // RAR 1.5 flags the archive and no file: every file but the first continues
                    entry.solid |= main_flags & MHD_SOLID != 0 && unp_ver <= 15 && files > 0;
                    files += 1;
                    let _ = first_file.get_or_insert((entry.split_before, unp_ver));
                }
                next = block.end.checked_add(entry.packed);
                archive.entries.push(entry);
            },
            HEAD3_ENDARC => break,
            // the two old blocks that always have data, and any other block that says so
            head_type if head_type == HEAD3_PROTECT || head_type == HEAD3_OLDSERVICE || block.flags & LONG_BLOCK != 0 => {
                unknown_block_checked(&mut cursor, &block, &mut archive);
                let data_size = if block.size >= BLOCK_HEAD + 4 { cursor.u32_le().unwrap_or(0) } else { 0 };
                next = block.end.checked_add(u64::from(data_size));
            },
            _ => unknown_block_checked(&mut cursor, &block, &mut archive),
        }

        if next.is_none_or(|next| cursor.seek(next).is_err()) {
            archive.truncated = true;
            break;
        }
    }

    archive.volume = Some(which_volume(main_flags, first_file));
    Ok(archive)
}

/// The salt of the first encrypted block of an archive with encrypted headers.
pub(crate) fn header_salt(source: &Source, salt_at: u64) -> Option<[u8; 8]> {
    let mut salt = [0_u8; 8];
    source.read_exact_at(salt_at, &mut salt).ok()?;
    Some(salt)
}

/// The end of archive block of an archive with encrypted headers, as it stands in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndBlock {
    /// The salt in front of it.
    pub salt: [u8; 8],
    /// The encrypted block: 16 bytes, or 32 for the longer end block of a volume.
    pub data: Vec<u8>,
    /// How many bytes follow the block in the file.
    pub trailing: u64,
}

/// Find the end of archive block of an archive with encrypted headers.
///
/// It is the one block whose content is known without the password, and so the one a
/// password can be tested against. Where it lies cannot be read: the sizes of the blocks
/// in front of it are encrypted. What can be read is the salt, which stands behind the main
/// header in front of the first encrypted block, and RAR writes every block of an archive
/// with that one salt. The end block is the last place in the file where the salt stands.
///
/// It is not taken from the end of the file, where bytes that were appended to the archive
/// would be read in its place. It is looked for in the last [`END_BLOCK_SEARCH`] bytes.
///
/// The block is 16 bytes. A volume written by RAR 3.10 or later ends in a longer one, which
/// encrypts to 32. `volume` is whether the main header says that the archive is a volume.
///
/// `None` when the salt does not stand there again: the file is cut short, or more follows
/// the archive than the search reaches back over. The first block is taken for the end block
/// only when the file ends with it. With more behind it, it is the header of a file whose
/// data follows, in an archive that was cut off before its next block.
pub(crate) fn end_block(source: &Source, salt_at: u64, volume: bool) -> Option<EndBlock> {
    let salt = header_salt(source, salt_at)?;
    let from = source.len().saturating_sub(END_BLOCK_SEARCH).max(salt_at);
    let tail = source.read_at(from, source.len().checked_sub(from)?).ok()?;

    // the last place where the salt stands with a block behind it
    let at = tail.get(..tail.len().checked_sub(16)?)?.windows(salt.len()).rposition(|window| window == salt)?;
    let behind = tail.get(at.checked_add(salt.len())?..)?;
    let size = if volume && behind.len() >= 32 { 32 } else { 16 };
    let trailing = u64::try_from(behind.len().checked_sub(size)?).ok()?;
    let first_block = u64::try_from(at).ok().and_then(|at| from.checked_add(at)) == Some(salt_at);
    if first_block && trailing > 0 {
        return None;
    }
    Some(EndBlock { salt, data: behind.get(..size)?.to_vec(), trailing })
}

#[cfg(test)]
mod tests {
    use super::super::testing::rar4::Head;
    use super::super::testing::rar4::archive;
    use super::super::testing::rar4::block;
    use super::super::testing::rar4::end;
    use super::super::testing::rar4::file;
    use super::super::testing::rar4::main;
    use super::*;

    fn parsed(bytes: Vec<u8>) -> RarArchive {
        parse(&Source::from_bytes(bytes), 0, false).unwrap()
    }

    fn fixture(rel: &str) -> RarArchive {
        parse(&Source::open(std::path::Path::new(&format!("tests/fixtures/{rel}")), 0).unwrap(), 0, false).unwrap()
    }

    #[test]
    fn the_entries_of_a_fixture_are_read_with_their_encryption() {
        let plain = fixture("unencrypted/rars_rar3_stored.rar");
        assert_eq!((plain.generation, &plain.headers, plain.volume, plain.truncated), (RarGeneration::Rar4, &HeaderEncryption::None, Some(Volume::Single), false));
        assert!(!plain.entries.is_empty() && plain.entries.iter().all(|entry| entry.encryption == RarEncryption::None));

        let encrypted = fixture("rar-30/v420_p_m3.rar");
        assert!(encrypted.entries.iter().any(|entry| matches!(entry.encryption, RarEncryption::Rar30 { salt: Some(_) })));
        assert!(fixture("rar-15/rar15-password-stored.rar").entries.iter().all(|entry| entry.encryption == RarEncryption::Rar15));
        assert!(fixture("rar-20/rar20-password-stored.rar").entries.iter().all(|entry| entry.encryption == RarEncryption::Rar20));
    }

    #[test]
    fn an_entry_is_what_its_header_says() {
        let salt = [0xA5; 8];
        let bytes = archive(&[
            main(0),
            file(HEAD3_FILE, LHD_DIRECTORY, &Head { name: b"dir", ..Head::default() }, b""),
            file(HEAD3_FILE, LHD_PASSWORD | LHD_SALT | LHD_SOLID, &Head { name: b"a.txt", method: 0x33, packed: 32, unpacked: 900, tail: &salt, ..Head::default() }, &[0x5A; 32]),
            file(HEAD3_FILE, LHD_PASSWORD, &Head { name: b"old.txt", unp_ver: 20, packed: 16, unpacked: 10, ..Head::default() }, &[0x5A; 16]),
            end(),
        ]);
        let listed = parsed(bytes);
        let [directory, salted, old] = listed.entries.as_slice() else { panic!("three entries: {:?}", listed.entries) };

        assert_eq!((directory.kind, directory.name_lossy().as_str(), directory.encryption), (EntryKind::Directory, "dir", RarEncryption::None));
        assert_eq!((salted.kind, salted.packed, salted.unpacked, salted.crc32), (EntryKind::File, 32, Some(900), 0xCAFE_F00D));
        assert_eq!((salted.method, salted.stored, salted.solid, salted.encryption), (0x33, false, true, RarEncryption::Rar30 { salt: Some(salt) }));
        assert_eq!((old.encryption, old.stored, old.solid), (RarEncryption::Rar20, true, false));
        assert!(!listed.truncated && old.data_is_inside(u64::MAX));
    }

    #[test]
    fn an_entry_under_rar_3_without_a_salt_has_none_and_one_that_is_cut_off_is_unreadable() {
        let entry = |flags: u16, tail: &[u8]| parsed(archive(&[main(0), file(HEAD3_FILE, flags, &Head { packed: 16, unpacked: 9, tail, ..Head::default() }, &[0; 16])])).entries[0].encryption;
        assert_eq!(entry(LHD_PASSWORD, &[]), RarEncryption::Rar30 { salt: None });
        assert_eq!(entry(LHD_PASSWORD | LHD_SALT, &[1, 2, 3, 4, 5, 6, 7, 8]), RarEncryption::Rar30 { salt: Some([1, 2, 3, 4, 5, 6, 7, 8]) });
        // the flag for a salt, and a header that ends before the salt does
        assert_eq!(entry(LHD_PASSWORD | LHD_SALT, &[1, 2, 3]), RarEncryption::Unreadable(Scheme::Rar30));
        assert_eq!(entry(LHD_SALT, &[1, 2, 3]), RarEncryption::None, "a salt says nothing without the flag for a password");
    }

    #[test]
    fn sizes_have_a_high_half_and_can_be_unknown() {
        let sizes = |flags: u16, unpacked: u32, tail: &[u8]| {
            let entry = parsed(archive(&[main(0), file(HEAD3_FILE, flags, &Head { packed: 5, unpacked, high: tail, ..Head::default() }, &[])])).entries[0].clone();
            (entry.packed, entry.unpacked)
        };
        assert_eq!(sizes(0, 7, &[]), (5, Some(7)));
        assert_eq!(sizes(0, u32::MAX, &[]), (5, None), "all bits set: packed from a stream");
        assert_eq!(sizes(LHD_LARGE, 7, &[1, 0, 0, 0, 2, 0, 0, 0]), ((1 << 32) | 5, Some((2 << 32) | 7)));
        assert_eq!(sizes(LHD_LARGE, u32::MAX, &[0, 0, 0, 0, 0, 0, 0, 0]), (5, Some(u64::from(u32::MAX))));
        assert_eq!(sizes(LHD_LARGE, u32::MAX, &[0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF]), (5, None));
        assert_eq!(sizes(LHD_LARGE, 7, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), ((u64::from(u32::MAX) << 32) | 5, Some((u64::from(u32::MAX) << 32) | 7)));
    }

    /// The packed size of a large file is a number of 64 bits. It used to be added to an
    /// offset without a check, which ended the process.
    #[test]
    fn a_packed_size_of_any_width_is_a_result_and_never_a_panic() {
        let bytes = archive(&[main(0), file(HEAD3_FILE, LHD_LARGE, &Head { packed: u32::MAX, unpacked: 10, high: &[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0], ..Head::default() }, &[0; 64])]);
        let large = parsed(bytes);
        assert_eq!((large.entries.len(), large.entries[0].packed, large.truncated), (1, u64::MAX, true));
        assert!(!large.entries[0].data_is_inside(u64::MAX));

        // the same with the size of the data of another block
        let mut bytes = archive(&[main(0), block(0x7C, LONG_BLOCK, &u32::MAX.to_le_bytes())]);
        bytes.extend_from_slice(&[0; 64]);
        let other = parsed(bytes);
        assert_eq!((other.entries.len(), other.truncated), (0, true));
    }

    #[test]
    fn a_service_record_is_an_entry_with_its_salt_behind_its_own_data() {
        let listed = fixture("rar-15/rars_service_block_stored.rar");
        let [service, entry] = listed.entries.as_slice() else { panic!("two entries: {:?}", listed.entries) };
        assert_eq!((service.kind, service.name_lossy().as_str(), service.encryption), (EntryKind::Service, "RARS", RarEncryption::None));
        assert_eq!((entry.kind, entry.encryption), (EntryKind::File, RarEncryption::Rar15));

        // six bytes of its own, then the salt
        let tail = [9, 9, 9, 9, 9, 9, 1, 2, 3, 4, 5, 6, 7, 8];
        let bytes = archive(&[main(0), file_block_of(HEAD3_SERVICE, LHD_PASSWORD | LHD_SALT, &tail)]);
        let parsed = parsed(bytes);
        assert_eq!(parsed.entries[0].encryption, RarEncryption::Rar30 { salt: Some([1, 2, 3, 4, 5, 6, 7, 8]) });
        assert!(!parsed.entries[0].solid);
    }

    fn file_block_of(head_type: u8, flags: u16, tail: &[u8]) -> Vec<u8> {
        file(head_type, flags, &Head { name: b"STM", packed: 16, unpacked: 9, tail, ..Head::default() }, &[0; 16])
    }

    #[test]
    fn blocks_that_are_no_entries_are_passed_over_with_their_data() {
        // an old recovery record has data whether it is flagged or not
        let behind = fixture("unparseable/protect-header-seek.rar");
        assert_eq!(behind.entries.iter().map(RarEntry::name_lossy).collect::<Vec<_>>(), ["after-protect.txt"]);
        // an old service record in front of each file
        assert_eq!(fixture("unparseable/mac-subblock.rar").entries.len(), 2);

        let mut unknown = block(0x7C, LONG_BLOCK, &4_u32.to_le_bytes());
        unknown.extend_from_slice(b"data");
        let bytes = archive(&[main(0), unknown, block(0x7D, 0, &[1, 2, 3]), file(HEAD3_FILE, 0, &Head::default(), b""), end(), file(HEAD3_FILE, 0, &Head::default(), b"")]);
        let walked = parsed(bytes);
        assert_eq!((walked.entries.len(), walked.truncated), (1, false), "the end block ends the walk");
    }

    #[test]
    fn rar_1_5_flags_a_solid_archive_and_no_file() {
        let old = Head { unp_ver: 15, method: 0x33, packed: 4, unpacked: 9, ..Head::default() };
        let new = Head { unp_ver: 29, method: 0x33, packed: 4, unpacked: 9, ..Head::default() };
        let solid = |flags: u16| {
            let bytes = archive(&[main(flags), file(HEAD3_FILE, 0, &old, &[0; 4]), file(HEAD3_FILE, 0, &old, &[0; 4]), file(HEAD3_FILE, 0, &new, &[0; 4]), file(HEAD3_FILE, LHD_SOLID, &new, &[0; 4])]);
            parsed(bytes).entries.iter().map(|entry| entry.solid).collect::<Vec<_>>()
        };
        assert_eq!(solid(MHD_SOLID), [false, true, false, true]);
        assert_eq!(solid(0), [false, false, false, true]);
    }

    #[test]
    fn a_volume_is_the_first_by_its_flag_or_by_its_first_file() {
        assert_eq!(which_volume(0, None), Volume::Single);
        assert_eq!(which_volume(MHD_FIRSTVOLUME, None), Volume::Single, "no volume at all");
        assert_eq!(which_volume(MHD_VOLUME | MHD_FIRSTVOLUME, Some((true, 29))), Volume::First);
        assert_eq!(which_volume(MHD_VOLUME, Some((true, 29))), Volume::Later);
        assert_eq!(which_volume(MHD_VOLUME, Some((false, 29))), Volume::Later, "RAR 3 flags its first volume, and this one is not flagged");
        assert_eq!(which_volume(MHD_VOLUME, Some((false, 20))), Volume::First, "RAR 2 has no flag: its first file starts here");
        assert_eq!(which_volume(MHD_VOLUME, Some((true, 20))), Volume::Later);
        assert_eq!(which_volume(MHD_VOLUME, None), Volume::Later);

        assert_eq!(fixture("unencrypted/test-documents.part1.rar").volume, Some(Volume::First));
        assert_eq!(fixture("unparseable/test-documents.part2.rar").volume, Some(Volume::Later));
        assert_eq!(fixture("unknown-pw/edge_rars_split-encrypted.rar").volume, Some(Volume::First));
        let later = fixture("unparseable/test-documents.part3.rar");
        assert!(later.entries[0].split_before && !later.entries[0].split_after && !later.entries[1].is_split());
    }

    #[test]
    fn encrypted_headers_end_the_walk_at_the_main_header() {
        let hidden = fixture("rar-30/v420_hp_m3.rar");
        assert_eq!(hidden.headers, HeaderEncryption::Rar30 { salt_at: 20, volume: false });
        assert!(hidden.entries.is_empty());
        assert_eq!(hidden.volume, Some(Volume::Single));

        let volume = parsed(archive(&[main(MHD_PASSWORD | MHD_VOLUME), vec![0xEE; 64]]));
        assert_eq!(volume.headers, HeaderEncryption::Rar30 { salt_at: 20, volume: true });
        assert_eq!(volume.volume, Some(Volume::Later), "a volume that is not flagged as the first");
    }

    /// An archive with encrypted headers: a main header, a first encrypted block of `first`
    /// bytes behind the salt, `between` bytes that stand for the rest, and an end block of
    /// `end` bytes behind the salt again.
    fn encrypted(volume: bool, salt: [u8; 8], first: usize, between: usize, end: usize) -> Vec<u8> {
        let mut bytes = archive(&[main(MHD_PASSWORD | if volume { MHD_VOLUME } else { 0 })]);
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&vec![0x11; first]);
        bytes.extend_from_slice(&vec![0x22; between]);
        bytes.extend_from_slice(&salt);
        bytes.extend((0..end).map(|at| 0x80 | u8::try_from(at).unwrap()));
        bytes
    }

    const SALT: [u8; 8] = [0xD1, 0x5A, 0x17, 0x00, 0xFE, 0x42, 0x99, 0x03];

    fn end_of(bytes: Vec<u8>, volume: bool) -> Option<EndBlock> {
        end_block(&Source::from_bytes(bytes), 20, volume)
    }

    #[test]
    fn the_end_block_is_the_last_block_under_the_salt_of_the_first() {
        let block = end_of(encrypted(false, SALT, 48, 1000, 16), false).unwrap();
        assert_eq!((block.salt, block.trailing), (SALT, 0));
        assert_eq!(block.data, (0x80..0x90).collect::<Vec<u8>>());

        // an archive that holds nothing but its end block: the first block is the last
        let mut empty = archive(&[main(MHD_PASSWORD)]);
        empty.extend_from_slice(&SALT);
        empty.extend_from_slice(&[0x77; 16]);
        assert_eq!(end_of(empty, false), Some(EndBlock { salt: SALT, data: vec![0x77; 16], trailing: 0 }));

        // the fixtures: the block is the last 16 bytes of the file, under the salt at byte 20
        for rel in ["rar-30/v420_hp_m3.rar", "rar-30/v300_hp_m3.rar", "rar-30/v500_ma4_hp_m3.rar"] {
            let bytes = std::fs::read(format!("tests/fixtures/{rel}")).unwrap();
            let block = end_of(bytes.clone(), false).unwrap();
            assert_eq!((&block.salt[..], &block.data[..], block.trailing), (&bytes[20..28], &bytes[bytes.len() - 16..], 0), "{rel}");
        }
    }

    /// Bytes that follow the archive in its file are not the archive. The block used to be
    /// taken from the end of the file, and with it whatever had been appended.
    #[test]
    fn bytes_behind_the_archive_are_not_taken_for_its_end_block() {
        let clean = end_of(encrypted(false, SALT, 48, 1000, 16), false).unwrap();
        for appended in [1, 8, 15, 16, 17, 24, 512, 60_000] {
            let mut bytes = encrypted(false, SALT, 48, 1000, 16);
            bytes.extend_from_slice(&vec![0; appended]);
            let block = end_of(bytes, false).unwrap();
            assert_eq!((&block.salt, &block.data, block.trailing), (&clean.salt, &clean.data, u64::try_from(appended).unwrap()), "{appended} bytes appended");
        }

        // more than the search reaches back: the block is not found, and nothing else is taken for it
        let mut bytes = encrypted(false, SALT, 48, 1000, 16);
        bytes.extend_from_slice(&vec![0; usize::try_from(END_BLOCK_SEARCH).unwrap()]);
        assert_eq!(end_of(bytes, false), None);
    }

    #[test]
    fn a_volume_ends_in_a_block_of_32_bytes_or_in_one_of_16() {
        // RAR 3.10 and later: the end block of a volume holds a checksum and a number
        let long = end_of(encrypted(true, SALT, 48, 1000, 32), true).unwrap();
        assert_eq!((long.data.len(), long.trailing), (32, 0));
        assert_eq!(long.data, (0x80..0xA0).collect::<Vec<u8>>());

        // before that it was the seven bytes of any end block
        let short = end_of(encrypted(true, SALT, 48, 1000, 16), true).unwrap();
        assert_eq!((short.data.len(), short.trailing), (16, 0));

        // an archive that is no volume has the short block, whatever follows it
        let single = end_of(encrypted(false, SALT, 48, 1000, 32), false).unwrap();
        assert_eq!((single.data.len(), single.trailing), (16, 16));
    }

    #[test]
    fn an_archive_without_its_end_block_has_none() {
        // cut off inside the data of its one file, far from the first block
        let mut cut = archive(&[main(MHD_PASSWORD)]);
        cut.extend_from_slice(&SALT);
        cut.extend_from_slice(&vec![0x33; 100_000]);
        assert_eq!(end_of(cut, false), None);

        // cut off close behind its first block: the header of a file is not taken for the end
        // block, which it would be when the first block were the last one whatever follows it
        for left in [17, 48, 1000] {
            let mut cut = archive(&[main(MHD_PASSWORD)]);
            cut.extend_from_slice(&SALT);
            cut.extend_from_slice(&vec![0x33; left]);
            assert_eq!(end_of(cut.clone(), false), None, "{left} bytes behind the first salt");
            assert_eq!(end_of(cut, true), None, "{left} bytes behind the first salt of a volume");
        }

        // too short for a block behind the salt, or for the salt
        let mut short = archive(&[main(MHD_PASSWORD)]);
        short.extend_from_slice(&SALT);
        short.extend_from_slice(&[0x33; 15]);
        assert_eq!(end_of(short.clone(), false), None);
        short.truncate(24);
        assert_eq!(end_of(short, false), None);
        assert_eq!(header_salt(&Source::from_bytes(vec![0; 27]), 20), None);
        assert_eq!(end_block(&Source::from_bytes(vec![0; 64]), u64::MAX, true), None);
    }

    #[test]
    fn a_comment_inside_the_main_header_is_read_when_it_is_stored() {
        let text = b"An old comment.";
        let comment = |method: u8, checksum: u16| {
            let mut body = [0_u8; 6].to_vec();
            let mut inner = vec![0, 0, HEAD3_CMT, 0, 0];
            inner.extend_from_slice(&u16::try_from(COMMENT_HEAD + text.len()).unwrap().to_le_bytes());
            inner.extend_from_slice(&u16::try_from(text.len()).unwrap().to_le_bytes());
            inner.extend_from_slice(&[20, method]);
            inner.extend_from_slice(&checksum.to_le_bytes());
            inner.extend_from_slice(text);
            body.extend_from_slice(&inner);
            parsed(archive(&[block(HEAD3_MAIN, MHD_COMMENT, &body), end()])).comment
        };
        let checksum = u16::try_from(crc32fast::hash(text) & 0xFFFF).unwrap();
        assert_eq!(comment(0x30, checksum), Some(text.to_vec()));
        assert_eq!(comment(0x30, checksum ^ 1), None, "a checksum that is not the one of the text");
        assert_eq!(comment(0x33, checksum), None, "a packed comment is not unpacked");

        // the packed comment of a fixture, and the files behind it
        let packed = fixture("unknown-pw/edge_rars_comment_psw.rar");
        assert_eq!((packed.comment, packed.entries.len()), (None, 2));
    }

    #[test]
    fn a_comment_in_a_service_record_is_read_when_it_is_stored() {
        let text = b"A new comment.";
        let record = |flags: u16, method: u8, attributes: u32, data: &[u8]| {
            let size = u32::try_from(data.len()).unwrap();
            let head = Head { name: b"CMT", method, packed: size, unpacked: size, attributes, crc32: crc32fast::hash(data), ..Head::default() };
            parsed(archive(&[main(0), file(HEAD3_SERVICE, flags, &head, data), end()]))
        };
        let stored = record(0, 0x30, 0, text);
        assert_eq!(stored.comment.as_deref(), Some(&text[..]));
        assert_eq!((stored.entries.len(), stored.entries[0].kind), (1, EntryKind::Service));

        let wide: Vec<u8> = "caf\u{e9}".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(record(0, 0x30, SUBHEAD_CMT_UNICODE, &wide).comment, Some("caf\u{e9}".as_bytes().to_vec()));
        assert_eq!(record(0, 0x33, 0, text).comment, None, "a packed comment is not unpacked");
        assert_eq!(record(LHD_PASSWORD, 0x30, 0, text).comment, None, "an encrypted one is not read");
        // RAR 4 packs its comments: the record is listed, and its text is not shown
        let packed = fixture("unparseable/gh-86-missing-data.rar");
        assert_eq!((packed.comment, packed.entries[0].name_lossy().as_str(), packed.entries[0].kind), (None, "CMT", EntryKind::Service));
    }

    #[test]
    fn a_marker_with_nothing_behind_it_is_an_error() {
        assert!(parse(&Source::from_bytes(RAR4_SIGNATURE.to_vec()), 0, false).is_err());
        assert!(parse(&Source::from_bytes(RAR4_SIGNATURE[..4].to_vec()), 0, false).is_err());
        // a block that says it is shorter than a block is, and one that is longer than the file
        assert!(parse(&Source::from_bytes(archive(&[vec![0, 0, 0x73, 0, 0, 6, 0, 0, 0]])), 0, false).is_err());
        assert!(parse(&Source::from_bytes(archive(&[vec![0, 0, 0x73, 0, 0, 200, 0, 0, 0]])), 0, false).is_err());
        assert!(parse(&Source::open(std::path::Path::new("tests/fixtures/unparseable/corrupt-header.rar"), 0).unwrap(), 0, false).is_err());
    }

    #[test]
    fn a_marker_inside_a_program_needs_a_main_header() {
        let good = archive(&[main(0), end()]);
        assert!(parse(&Source::from_bytes(good), 0, true).is_ok());

        let file_first = archive(&[file(HEAD3_FILE, 0, &Head::default(), b"")]);
        assert!(parse(&Source::from_bytes(file_first.clone()), 0, true).is_err());
        assert_eq!(parsed(file_first).entries.len(), 1, "at the start of a file the block is taken at its word");
        assert!(parse(&Source::from_bytes(archive(&[block(HEAD3_MAIN, 0, &[0; 5])])), 0, true).is_err(), "a main header of twelve bytes");
    }

    #[test]
    fn what_is_no_block_ends_the_walk() {
        let whole = archive(&[main(0), file(HEAD3_FILE, 0, &Head { packed: 3, unpacked: 3, ..Head::default() }, b"abc"), end()]);
        assert_eq!(parsed(whole.clone()).entries.len(), 1);

        let entry_at = 7 + 13;
        let data_at = whole.len() - end().len() - 3;
        for len in entry_at + 1..data_at + 3 {
            let cut = parsed(whole[..len].to_vec());
            // fewer than seven bytes are no block; more are one that the file cuts off
            assert_eq!(cut.truncated, len >= entry_at + 7, "{len} bytes: {cut:?}");
            assert_eq!(cut.entries.len(), usize::from(len >= data_at), "{len} bytes");
        }

        // zeros behind the last block of an archive without an end block are no block
        let mut padded = archive(&[main(0), file(HEAD3_FILE, 0, &Head::default(), b"")]);
        padded.extend_from_slice(&[0; 64]);
        let walked = parsed(padded);
        assert_eq!((walked.entries.len(), walked.truncated), (1, false));

        // a file header that is shorter than a file header
        let short = archive(&[main(0), block(HEAD3_FILE, 0, &[0; 20])]);
        assert_eq!(parsed(short).entries.len(), 0);
    }

    /// Name fields as RAR 4.20 wrote them: the DOS name, a NUL, the packed wide name.
    #[test]
    fn a_unicode_name_copies_its_runs_from_where_the_name_has_got_to() {
        let decode = |field: &str| String::from_utf8(decode_unicode_name(&hex::decode(field).unwrap())).unwrap();

        // "2??.txt": one byte, one byte under the high half 0x4e, two bytes, then ".txt" as a run
        assert_eq!(decode("323f3f2e747874004e1b322d876502"), "2\u{4e2d}\u{6587}.txt");
        // "????.txt": four characters under the high half 0x04, then ".txt" as a run
        assert_eq!(decode("3f3f3f3f2e7478740004554430393bc002"), "\u{444}\u{430}\u{439}\u{43b}.txt");
        // every character in two bytes, with a path
        assert_eq!(decode("646f63735c3f3f3f3f2e7478740000aa64006f0063007300aa5c00440430043904aa3b042e0074007800807400"), "docs\\\u{444}\u{430}\u{439}\u{43b}.txt");
        assert_eq!(decode("723f73756d3f2e7478740000aa7200e90073007500aa6d00e9002e007400a078007400"), "r\u{e9}sum\u{e9}.txt");
    }

    #[test]
    fn a_run_of_a_unicode_name_can_be_shifted_and_ends_with_the_dos_name() {
        // "abcd", high half 0x04, a run of four with the correction 0x10: 0x0471 to 0x0474
        assert_eq!(decode_unicode_name(b"abcd\x00\x04\xc0\x82\x10"), "\u{471}\u{472}\u{473}\u{474}".as_bytes());
        // a run that asks for more than the DOS name holds stops at its end, as UnRAR does
        assert_eq!(decode_unicode_name(b"ab\x00\x00\xc0\x7f"), b"ab");
        // one plain character, then a run: it starts at the second byte of the DOS name
        assert_eq!(decode_unicode_name(b"xyz\x00\x00\x30Q\x00"), b"Qyz");
    }

    #[test]
    fn a_unicode_name_that_is_cut_short_keeps_what_was_decoded() {
        // no packed part at all: the DOS name is the name
        assert_eq!(decode_unicode_name(b"plain.txt"), b"plain.txt");
        assert_eq!(decode_unicode_name(b"plain.txt\x00"), b"plain.txt");
        // a two-byte character with one byte left
        assert_eq!(decode_unicode_name(b"ab\x00\x00\x20A\x42"), b"A");
    }

    /// A packed part that gives no character is none: the name in front of it stands, as in
    /// UnRAR. It used to be listed as an empty name.
    #[test]
    fn a_unicode_name_whose_packed_part_gives_nothing_is_the_name_in_front_of_it() {
        // a run with a correction that is missing, and a packed part of the one high byte
        assert_eq!(decode_unicode_name(b"ab\x00\x00\xc0\x80"), b"ab");
        assert_eq!(decode_unicode_name(b"ab\x00\x04"), b"ab");

        // a name a Unix RAR wrote in UTF-8, with a packed part that was cut off
        let listed = fixture("unencrypted/encname-truncated.rar");
        assert_eq!(listed.entries.iter().map(RarEntry::name_lossy).collect::<Vec<_>>(), ["caf\u{e9}-r\u{e9}sum\u{e9}-\u{65e5}\u{672c}\u{8a9e}.txt"]);
    }

    #[test]
    fn the_names_of_a_rar4_archive_with_a_unicode_name_are_the_ones_unrar_lists() {
        let listed = fixture("rar-30/rars_rar4_mixed_visible_names_password.rar");
        let names: Vec<String> = listed.entries.iter().map(RarEntry::name_lossy).collect();
        assert_eq!(names, ["1File.txt", "2\u{4e2d}\u{6587}.txt", "3Sec.txt"]);
    }
}
