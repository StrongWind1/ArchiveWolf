//! From a file to the entries of the ZIP archive in it, read by range.
//!
//! The archive is found from its end: the end of central directory record, the ZIP64 records
//! in front of it when there are any, then the central directory, which is walked with a
//! buffered reader. Local file headers and the data of entries are not touched here.
//!
//! Every offset an archive states is relative to the start of the archive, which is the start
//! of the file unless a program stands in front. The difference is found once, as the distance
//! between where a record is and where the archive says it is, and it can point either way: a
//! file can also hold only the end of an archive, when it is the last piece of one that was
//! cut into pieces. Offsets are moved by that distance in 128-bit arithmetic, which no pair of
//! 64-bit values can overflow, and a result that is no offset into the file is an entry that
//! is not in the file.
//!
//! A file that starts with the split marker and has no end record is the first volume of a
//! split archive. Its central directory is in the last volume, so its entries are read from
//! their local headers as far as those reach.

use anyhow::Context as _;
use anyhow::bail;

use super::encryption::FLAG_DATA_DESCRIPTOR;
use super::encryption::ZipEncryption;
use super::encryption::detect_encryption;
use super::extra_fields::ExtraMarks;
use super::extra_fields::Zip64Wanted;
use super::extra_fields::parse_extra_fields;
use super::headers::CD_HEADER_LEN;
use super::headers::CD_SIG;
use super::headers::CentralDirectoryHeader;
use super::headers::DirectoryProtection;
use super::headers::EOCD_LEN;
use super::headers::EOCD_SIG;
use super::headers::Eocd;
use super::headers::LOCAL_HEADER_LEN;
use super::headers::LOCAL_SIG;
use super::headers::LocalFileHeader;
use super::headers::SPLIT_SIG;
use super::headers::ZIP64_EOCD_LEN;
use super::headers::ZIP64_EOCD_SIG;
use super::headers::ZIP64_LOCATOR_LEN;
use super::headers::Zip64Eocd;
use super::headers::Zip64Locator;
use super::headers::find_eocd;
use crate::analysis::Split;
use crate::analysis::Volume;
use crate::formats::limits::capacity_for;
use crate::formats::source::Cursor;
use crate::formats::source::Source;

/// How much of the end of a file is searched for an end record whose comment ends the file:
/// the record and the longest comment it can carry.
const STRICT_TAIL: u64 = EOCD_LEN as u64 + 65_535;

/// How much of the end of a file is searched for an end record that has bytes behind it. A
/// megabyte is what minizip-ng searches.
const LOOSE_TAIL: u64 = EOCD_LEN as u64 + (1 << 20);

/// How many end records with bytes behind them are tried. A file that is an archive has one,
/// and the bytes behind it hold the signature of another by chance once in thousands of files:
/// more than a few are a file built to make the search long.
const LOOSE_CANDIDATES: usize = 64;

/// How far in front of its locator a ZIP64 end record is searched for when it is neither where
/// the locator says nor directly in front of it: a version 2 record with the longest hash.
const ZIP64_RECORD_SEARCH: u64 = 1 << 17;

/// A parsed ZIP archive.
#[derive(Debug)]
pub(crate) struct ZipArchive {
    /// The entries of the central directory, in its order. Empty when the directory is
    /// encrypted.
    pub entries: Vec<ZipEntry>,
    /// Archive comment (may be empty).
    pub comment: Vec<u8>,
    /// Whether the archive has ZIP64 records: an end record, or a value in an extra field.
    pub is_zip64: bool,
    /// Where the archive starts in its file: above 0 when a program stands in front.
    pub start: u64,
    /// Whether the file is one volume of a set, or holds less than its headers name.
    pub volume: Volume,
    /// How the central directory is encrypted, when it is.
    pub directory: Option<DirectoryProtection>,
}

/// One entry of a ZIP archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZipEntry {
    /// Filename (raw bytes, may be CP437 or UTF-8).
    pub filename: Vec<u8>,
    /// General purpose bit flags.
    pub flags: u16,
    /// Compression method from the header (99 for WinZip AES: the real one is in `encryption`).
    pub compression_method: u16,
    /// Last modification time (MS-DOS format).
    pub last_mod_time: u16,
    /// Last modification date (MS-DOS format).
    pub last_mod_date: u16,
    /// CRC-32.
    pub crc32: u32,
    /// Compressed size, with the encryption header of the entry.
    pub compressed_size: u64,
    /// Uncompressed size.
    pub uncompressed_size: u64,
    /// Offset of the local file header in the file when the entry is `here`, and as the
    /// central directory states it otherwise.
    pub local_header_offset: u64,
    /// How the entry is marked as encrypted.
    pub encryption: ZipEncryption,
    /// Whether the entry is a directory.
    pub directory: bool,
    /// Whether the entry was written by PKZIP before 2.0, whose encryption header ends in two
    /// check bytes: "version made by" below 2.0.
    pub two_byte_check: bool,
    /// "Version made by" of the central directory: the system in the high byte, the version of
    /// the writer in the low one. 0 for an entry that is read from its local header.
    pub made_by: u16,
    /// "Version needed to extract".
    pub needed: u16,
    /// Which extra fields the entry has, of those a writer is known by.
    pub extra: ExtraMarks,
    /// Whether the local header of the entry is in this file.
    pub here: bool,
    /// Whether the entry is in another volume, or runs into one.
    pub split: Split,
}

/// Convert the filename of an entry to a string, with a replacement character for every byte
/// sequence that is not UTF-8.
#[must_use]
pub(crate) fn filename_lossy(entry: &ZipEntry) -> String {
    String::from_utf8_lossy(&entry.filename).into_owned()
}

/// Parse the ZIP archive in `source`.
pub(crate) fn parse(source: &Source) -> anyhow::Result<ZipArchive> {
    match locate(source)? {
        Some(located) => read_archive(source, &located),
        None => read_first_volume(source),
    }
}

/// `declared`, an offset as the archive states it, moved by `shift` into the file. `None` when
/// the result is no offset at all.
fn place(declared: u64, shift: i128) -> Option<u64> {
    u64::try_from(i128::from(declared) + shift).ok()
}

/// The little-endian number in the four bytes at `offset`, or `None` when the file does not
/// hold them.
fn signature_at(source: &Source, offset: u64) -> Option<u32> {
    let mut bytes = [0_u8; 4];
    source.read_exact_at(offset, &mut bytes).ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// The end of an archive: its end record, and where its central directory is.
#[derive(Debug)]
struct Located {
    eocd_pos: u64,
    eocd: Eocd,
    has_zip64: bool,
    /// How many entries the central directory has.
    count: u64,
    /// Where the central directory starts in the file. `None` when it is encrypted.
    directory_at: Option<u64>,
    /// How the central directory is encrypted, when it is.
    protection: Option<DirectoryProtection>,
    /// The distance from an offset the archive states to its place in the file.
    shift: i128,
    /// The number of the disk this file is.
    this_disk: u32,
}

/// The end record whose comment ends the file, resolved. `None` when the file ends in no such
/// record; an error when it does and the record does not resolve.
fn locate_at_end(source: &Source) -> anyhow::Result<Option<Located>> {
    let len = source.len();
    let tail_start = len.saturating_sub(STRICT_TAIL);
    let tail = source.read_at(tail_start, len - tail_start)?;

    if let Ok(at) = find_eocd(&tail)
        && let Some(eocd) = tail.get(at..).and_then(Eocd::parse)
        && let Some(eocd_pos) = u64::try_from(at).ok().and_then(|at| tail_start.checked_add(at))
    {
        return resolve(source, eocd_pos, eocd).map(Some);
    }
    Ok(None)
}

/// Whether the file ends in a ZIP archive, by the search [`parse`] itself makes: an end record
/// whose comment ends the file, with its central directory where the record says. With
/// `behind`, bytes may follow the record as well, which costs a search of the last megabyte.
///
/// The scanner asks this of a file that starts with no signature. The last volume of a split
/// archive, an archive behind bytes that are no program, and a self-extracting archive with a
/// signature appended all end in an archive and start with something else.
pub(crate) fn ends_in_archive(source: &Source, behind: bool) -> bool {
    let found = if behind { locate(source) } else { locate_at_end(source) };
    found.ok().flatten().is_some()
}

/// Find the end record of the archive and resolve it.
///
/// A record whose comment ends the file is taken first, as every reader does. When there is
/// none, bytes follow the archive: the records in the last megabyte are tried from the end of
/// the file backward, [`LOOSE_CANDIDATES`] of them at most, and the first whose central
/// directory is where it says is the one. `None` when the file has no end record.
fn locate(source: &Source) -> anyhow::Result<Option<Located>> {
    if let Some(located) = locate_at_end(source)? {
        return Ok(Some(located));
    }

    let len = source.len();
    let tail_start = len.saturating_sub(LOOSE_TAIL);
    let tail = source.read_at(tail_start, len - tail_start)?;
    let signature = EOCD_SIG.to_le_bytes();
    let mut end = tail.len();
    for _ in 0..LOOSE_CANDIDATES {
        let Some(at) = tail.get(..end).and_then(|searched| searched.windows(signature.len()).rposition(|window| window == signature)) else { break };
        // the next search ends in front of this signature
        end = at.saturating_add(signature.len() - 1);
        let Some(record) = tail.get(at..) else { break };
        let fits = |eocd: &Eocd| record.len() >= EOCD_LEN + usize::from(eocd.comment_len);
        if let Some(eocd) = Eocd::parse(record).filter(fits)
            && let Some(eocd_pos) = u64::try_from(at).ok().and_then(|at| tail_start.checked_add(at))
            && let Ok(located) = resolve(source, eocd_pos, eocd)
        {
            return Ok(Some(located));
        }
        if at == 0 {
            break;
        }
    }
    Ok(None)
}

/// The ZIP64 end record that the locator in front of the end record at `eocd_pos` names, with
/// its place in the file. `None` when there is no locator.
///
/// The record is looked for directly in front of the locator, where a writer puts it, then
/// where the locator says, then further in front of the locator: a version 2 record is longer
/// than a version 1 record, and a program in front of the archive moves both.
fn find_zip64(source: &Source, eocd_pos: u64) -> anyhow::Result<Option<(u64, Zip64Eocd, Zip64Locator)>> {
    let Some(locator_pos) = eocd_pos.checked_sub(ZIP64_LOCATOR_LEN as u64) else { return Ok(None) };
    let Some(locator) = source.read_at(locator_pos, ZIP64_LOCATOR_LEN as u64).ok().as_deref().and_then(Zip64Locator::parse) else { return Ok(None) };

    let record_at = |pos: u64| source.read_up_to(pos, (ZIP64_EOCD_LEN + super::headers::ZIP64_EOCD_V2_LEN) as u64).ok().as_deref().and_then(Zip64Eocd::parse);
    // a record ends where the locator starts when its size says so
    let ends_at_locator = |pos: u64, record: &Zip64Eocd| pos.checked_add(12).and_then(|start| start.checked_add(record.record_size)) == Some(locator_pos);

    if let Some(pos) = locator_pos.checked_sub(ZIP64_EOCD_LEN as u64)
        && let Some(record) = record_at(pos).filter(|record| ends_at_locator(pos, record))
    {
        return Ok(Some((pos, record, locator)));
    }
    if let Some(record) = record_at(locator.eocd64_offset) {
        return Ok(Some((locator.eocd64_offset, record, locator)));
    }

    let search_start = locator_pos.saturating_sub(ZIP64_RECORD_SEARCH);
    let searched = source.read_at(search_start, locator_pos - search_start)?;
    let signature = ZIP64_EOCD_SIG.to_le_bytes();
    let mut end = searched.len();
    while let Some(at) = searched.get(..end).and_then(|bytes| bytes.windows(signature.len()).rposition(|window| window == signature)) {
        end = at.saturating_add(signature.len() - 1);
        if let Some(pos) = u64::try_from(at).ok().and_then(|at| search_start.checked_add(at))
            && let Some(record) = searched.get(at..).and_then(Zip64Eocd::parse).filter(|record| ends_at_locator(pos, record))
        {
            return Ok(Some((pos, record, locator)));
        }
        if at == 0 {
            break;
        }
    }
    bail!("ZIP64 end of central directory record not found: its locator names offset {} on disk {}", locator.eocd64_offset, locator.eocd64_disk);
}

/// Work out where the central directory of the end record at `eocd_pos` is.
fn resolve(source: &Source, eocd_pos: u64, eocd: Eocd) -> anyhow::Result<Located> {
    let len = source.len();
    let zip64 = find_zip64(source, eocd_pos)?;

    // with ZIP64 records, their values count: the end record holds marks in their place
    let (count, size, declared, this_disk, start_disk, directory_end) = match &zip64 {
        Some((pos, record, _)) => (record.entries_total, record.size, record.offset, record.disk_number, record.start_disk, *pos),
        None => (u64::from(eocd.entries_total), u64::from(eocd.size), u64::from(eocd.offset), u32::from(eocd.disk_number), u32::from(eocd.start_disk), eocd_pos),
    };
    let zip64_shift = zip64.as_ref().map(|(pos, _, locator)| i128::from(*pos) - i128::from(locator.eocd64_offset));
    let located = |directory_at: Option<u64>, protection: Option<DirectoryProtection>, shift: i128| Located { eocd_pos, eocd, has_zip64: zip64.is_some(), count, directory_at, protection, shift, this_disk };

    if let Some(protection) = zip64.as_ref().and_then(|(_, record, _)| record.directory).filter(|directory| directory.alg_id != 0 || directory.method != 0) {
        if protection.alg_id == 0 {
            bail!("the central directory is compressed with method {}, which is not unpacked", protection.method);
        }
        // an encrypted directory starts with a decryption header and has no signature to find
        return Ok(located(None, Some(protection), zip64_shift.unwrap_or(0)));
    }

    // where the directory ends, it starts `size` bytes in front
    let computed = directory_end.checked_sub(size);
    if count == 0 {
        let at = computed.unwrap_or(directory_end);
        return Ok(located(Some(at), None, i128::from(at) - i128::from(declared)));
    }

    let stated = Some(declared).filter(|&at| at.checked_add(size).is_some_and(|end| end <= len));
    let moved = zip64_shift.and_then(|shift| place(declared, shift));
    for at in [stated, moved, computed].into_iter().flatten() {
        if signature_at(source, at) == Some(CD_SIG) {
            return Ok(located(Some(at), None, i128::from(at) - i128::from(declared)));
        }
    }
    if start_disk != this_disk {
        bail!("the central directory is not in this file: it starts on disk {start_disk}, and this is disk {this_disk}");
    }
    bail!("central directory not found: neither at offset {declared}, where the end record puts it, nor in front of the end record");
}

/// Whether an entry is a directory: its name ends in a slash, or its attributes say so in the
/// form of the system it was written on (the MS-DOS directory bit, the Unix file type).
fn is_directory(name: &[u8], version_made_by: u16, external_attrs: u32) -> bool {
    if name.ends_with(b"/") {
        return true;
    }
    match version_made_by >> 8 {
        // FAT, HPFS, NTFS, VFAT
        0 | 6 | 10 | 14 => external_attrs & 0x10 != 0,
        // Unix: the high half is the mode
        3 => (external_attrs >> 16) & 0o170_000 == 0o040_000,
        _ => false,
    }
}

/// Whether a local file header with the name `name` is at `at`.
fn local_header_names(source: &Source, at: u64, name: &[u8]) -> bool {
    let Some(header) = source.read_at(at, LOCAL_HEADER_LEN as u64).ok().as_deref().and_then(LocalFileHeader::parse) else { return false };
    usize::from(header.name_len) == name.len() && at.checked_add(LOCAL_HEADER_LEN as u64).and_then(|name_at| source.read_at(name_at, u64::from(header.name_len)).ok()).is_some_and(|found| found == name)
}

/// One entry of the central directory, read at the cursor. The flag says whether a value of
/// it came from a ZIP64 extra field.
fn read_entry(source: &Source, cursor: &mut Cursor<'_>, located: &Located) -> anyhow::Result<(ZipEntry, bool)> {
    let header = CentralDirectoryHeader::parse(&cursor.array::<CD_HEADER_LEN>().context("cut short")?).context("no central directory signature")?;
    let filename = cursor.read_vec(u64::from(header.name_len)).context("its name is cut short")?;
    let extra = cursor.read_vec(u64::from(header.extra_len)).context("its extra fields are cut short")?;
    cursor.skip(u64::from(header.comment_len)).context("its comment is cut short")?;

    let wanted = Zip64Wanted { uncompressed: header.uncompressed_size == u32::MAX, compressed: header.compressed_size == u32::MAX, offset: header.local_header_offset == u32::MAX, disk: header.disk_start == u16::MAX };
    let extras = parse_extra_fields(&extra, wanted);
    let zip64 = extras.zip64;
    let uses_zip64 = zip64.uncompressed.is_some() || zip64.compressed.is_some() || zip64.offset.is_some() || zip64.disk.is_some();

    let declared = zip64.offset.unwrap_or(u64::from(header.local_header_offset));
    let disk = zip64.disk.unwrap_or(u32::from(header.disk_start));
    let position = place(declared, located.shift).filter(|&at| at < source.len());
    let (here, split) = match position {
        Some(_) if disk == located.this_disk => (true, Split::No),
        // an archive whose volumes were joined into one file still names their disks
        Some(at) if local_header_names(source, at, &filename) => (true, Split::No),
        // on this disk, and past the end of the file: not in another volume, but not here
        None if disk == located.this_disk && located.shift >= 0 => (false, Split::No),
        _ => (false, if disk > located.this_disk { Split::After } else { Split::Before }),
    };

    let entry = ZipEntry {
        directory: is_directory(&filename, header.version_made_by, header.external_attrs),
        filename,
        flags: header.flags,
        compression_method: header.compression_method,
        last_mod_time: header.last_mod_time,
        last_mod_date: header.last_mod_date,
        crc32: header.crc32,
        compressed_size: zip64.compressed.unwrap_or(u64::from(header.compressed_size)),
        uncompressed_size: zip64.uncompressed.unwrap_or(u64::from(header.uncompressed_size)),
        local_header_offset: position.filter(|_| here).unwrap_or(declared),
        encryption: detect_encryption(header.flags, header.compression_method, header.version_needed, &extras),
        two_byte_check: header.version_made_by & 0xFF < 20,
        made_by: header.version_made_by,
        needed: header.version_needed,
        extra: extras.marks,
        here,
        split,
    };
    Ok((entry, uses_zip64))
}

/// Whether the file starts with a record of a ZIP archive.
fn starts_with_a_record(source: &Source) -> bool {
    // `PK00` stands where the split marker would, in an archive that was written for
    // splitting and fitted into one file
    signature_at(source, 0).is_some_and(|signature| [LOCAL_SIG, SPLIT_SIG, EOCD_SIG, CD_SIG, 0x3030_4b50].contains(&signature))
}

/// Read the central directory of an archive whose end was found.
fn read_archive(source: &Source, located: &Located) -> anyhow::Result<ZipArchive> {
    let len = source.len();
    let comment = EOCD_LEN.try_into().ok().and_then(|record: u64| located.eocd_pos.checked_add(record)).and_then(|at| source.read_at(at, u64::from(located.eocd.comment_len)).ok()).unwrap_or_default();

    let mut entries = Vec::new();
    let mut is_zip64 = located.has_zip64;
    if let Some(directory_at) = located.directory_at {
        let mut cursor = source.cursor(directory_at);
        entries.reserve(capacity_for(located.count, usize::try_from(cursor.remaining()).unwrap_or(usize::MAX), CD_HEADER_LEN));
        // every entry takes 46 bytes or more, so the walk ends with the file whatever the count
        for index in 0..located.count {
            let (entry, uses_zip64) = read_entry(source, &mut cursor, located).with_context(|| format!("central directory entry {index} at offset {}", cursor.position()))?;
            is_zip64 |= uses_zip64;
            entries.push(entry);
        }
    }

    // a file that holds less than its directory names: the front of the archive is missing, an
    // entry lies past its end, or an entry is said to be on a disk this file is not
    let reaches_past_the_end = |entry: &ZipEntry| entry.local_header_offset.checked_add(LOCAL_HEADER_LEN as u64).and_then(|data| data.checked_add(entry.compressed_size)).is_none_or(|end| end > len);
    let volume = if located.this_disk > 0 {
        Volume::Later
    } else if located.shift < 0 || entries.iter().any(|entry| !entry.here || reaches_past_the_end(entry)) {
        Volume::Incomplete
    } else {
        Volume::Single
    };

    let start = match u64::try_from(located.shift) {
        Ok(shift) if shift > 0 => shift,
        // the front of the archive is not in the file: what is there starts with the file
        Err(_) => 0,
        // the offsets are those of the file, so the archive starts where its first record is
        Ok(_) if starts_with_a_record(source) => 0,
        Ok(_) => entries.iter().filter(|entry| entry.here).map(|entry| entry.local_header_offset).min().or(located.directory_at).unwrap_or(located.eocd_pos),
    };

    Ok(ZipArchive { entries, comment, is_zip64, start, volume, directory: located.protection })
}

/// The position of the local header that follows the data of an entry which ends at `end`.
/// An entry with flag bit 3 has a data descriptor behind its data, of 12 to 24 bytes: with
/// or without a signature, with sizes of four or of eight bytes.
fn next_local_header(cursor: &mut Cursor<'_>, end: u64, flags: u16) -> Option<u64> {
    let descriptor: &[u64] = if flags & FLAG_DATA_DESCRIPTOR == 0 { &[0] } else { &[0, 12, 16, 20, 24] };
    descriptor.iter().filter_map(|&skip| end.checked_add(skip)).find(|&at| cursor.seek(at).is_ok() && cursor.u32_le().is_ok_and(|signature| signature == LOCAL_SIG))
}

/// Read the first volume of a split archive: a file that starts with the split marker and has
/// no end record. Its central directory is in the last volume, so the entries are read from
/// their local headers, up to the one that runs into the next volume.
fn read_first_volume(source: &Source) -> anyhow::Result<ZipArchive> {
    let len = source.len();
    if signature_at(source, 0) != Some(SPLIT_SIG) || signature_at(source, 4) != Some(LOCAL_SIG) {
        bail!("no end of central directory record: not a ZIP archive, or one that is cut short, or the first piece of one that was cut into pieces");
    }

    let mut entries = Vec::new();
    let mut is_zip64 = false;
    let mut cursor = source.cursor(4);
    let mut next = Some(4_u64);
    while let Some(position) = next.take() {
        if cursor.seek(position).is_err() {
            break;
        }
        let Some(header) = cursor.array::<LOCAL_HEADER_LEN>().ok().as_ref().and_then(|record| LocalFileHeader::parse(record)) else { break };
        let (Ok(filename), Ok(extra)) = (cursor.read_vec(u64::from(header.name_len)), cursor.read_vec(u64::from(header.extra_len))) else { break };

        let wanted = Zip64Wanted { uncompressed: header.uncompressed_size == u32::MAX, compressed: header.compressed_size == u32::MAX, ..Zip64Wanted::default() };
        let extras = parse_extra_fields(&extra, wanted);
        is_zip64 |= extras.zip64.uncompressed.is_some() || extras.zip64.compressed.is_some();
        let compressed_size = extras.zip64.compressed.unwrap_or(u64::from(header.compressed_size));

        // a writer that could not go back wrote zeros here and the sizes behind the data
        let sizes_unknown = header.flags & FLAG_DATA_DESCRIPTOR != 0 && header.compressed_size == 0 && header.crc32 == 0;
        let end = cursor.position().checked_add(compressed_size).filter(|&end| end <= len && !sizes_unknown);

        entries.push(ZipEntry {
            directory: filename.ends_with(b"/"),
            filename,
            flags: header.flags,
            compression_method: header.compression_method,
            last_mod_time: header.last_mod_time,
            last_mod_date: header.last_mod_date,
            crc32: header.crc32,
            compressed_size,
            uncompressed_size: extras.zip64.uncompressed.unwrap_or(u64::from(header.uncompressed_size)),
            local_header_offset: position,
            encryption: detect_encryption(header.flags, header.compression_method, header.version_needed, &extras),
            // a local header does not say what wrote it: one check byte is what every writer fills
            two_byte_check: false,
            made_by: 0,
            needed: header.version_needed,
            extra: extras.marks,
            here: true,
            split: if end.is_some() { Split::No } else { Split::After },
        });
        next = end.and_then(|end| next_local_header(&mut cursor, end, header.flags));
    }

    Ok(ZipArchive { entries, comment: Vec::new(), is_zip64, start: 0, volume: Volume::First, directory: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::zip::craft::Member;
    use crate::formats::zip::craft::Zip;
    use crate::formats::zip::craft::member;

    fn parsed(bytes: Vec<u8>) -> ZipArchive {
        parse(&Source::from_bytes(bytes)).unwrap()
    }

    fn names(archive: &ZipArchive) -> Vec<String> {
        archive.entries.iter().map(filename_lossy).collect()
    }

    #[test]
    fn a_small_archive_is_read_from_its_end() {
        let archive = parsed(Zip::of(&[member("a.txt", 0, b"hi"), member("b.txt", 1, &[0x5A; 20])]).comment(b"made by hand").build());
        assert_eq!(names(&archive), ["a.txt", "b.txt"]);
        assert_eq!((archive.is_zip64, archive.start, archive.volume, archive.directory), (false, 0, Volume::Single, None));
        assert_eq!(archive.comment, b"made by hand");

        let (first, second) = (&archive.entries[0], &archive.entries[1]);
        assert_eq!((first.compression_method, first.crc32, first.compressed_size, first.uncompressed_size, first.local_header_offset), (0, crc32fast::hash(b"hi"), 2, 2, 0));
        assert_eq!((first.encryption, second.encryption), (ZipEncryption::None, ZipEncryption::ZipCrypto));
        assert_eq!(second.local_header_offset, 30 + 5 + 2);
        assert!(archive.entries.iter().all(|entry| entry.here && entry.split == Split::No && !entry.directory && !entry.two_byte_check));
    }

    #[test]
    fn an_archive_without_entries_is_an_archive() {
        let archive = parsed(Zip::of(&[]).build());
        assert!(archive.entries.is_empty());
        assert_eq!((archive.start, archive.volume), (0, Volume::Single));

        let mut behind = vec![0xEE; 64];
        behind.extend_from_slice(&Zip::of(&[]).build());
        assert_eq!(parsed(behind).start, 64);
    }

    #[test]
    fn what_is_no_archive_is_an_error() {
        for bytes in [Vec::new(), vec![0; 21], b"PK\x03\x04 a local header and no end record".to_vec(), vec![0x50; 100_000]] {
            assert!(parse(&Source::from_bytes(bytes)).is_err());
        }
    }

    /// A program in front of an archive moves every offset by its length. The distance is
    /// found from where the central directory is.
    #[test]
    fn a_program_in_front_moves_every_offset() {
        let zip = Zip::of(&[member("a.txt", 0, b"first"), member("b.txt", 0, b"second")]).build();
        let mut behind = vec![0xCC; 100];
        behind.extend_from_slice(&zip);
        let archive = parsed(behind);
        assert_eq!((archive.start, archive.volume), (100, Volume::Single));
        assert_eq!(archive.entries.iter().map(|entry| entry.local_header_offset).collect::<Vec<_>>(), [100, 100 + 30 + 5 + 5]);
        assert!(archive.entries.iter().all(|entry| entry.here));
    }

    /// Bytes behind the end record: a file with a signature appended, a download with a
    /// trailing newline. `unzip` and `7zz` open such a file.
    #[test]
    fn bytes_behind_the_end_record_do_not_hide_it() {
        let zip = Zip::of(&[member("a.txt", 1, &[0x5A; 30])]).build();
        for trailing in [1, 2, 21, 22, 23, 4096, 70_000, 1 << 20] {
            let mut bytes = zip.clone();
            bytes.resize(zip.len() + trailing, 0xA5);
            let archive = parse(&Source::from_bytes(bytes)).unwrap_or_else(|error| panic!("{trailing} bytes behind: {error:#}"));
            assert_eq!(names(&archive), ["a.txt"], "{trailing} bytes behind");
        }
        // further behind than is searched
        let mut bytes = zip.clone();
        bytes.resize(zip.len() + (1 << 20) + 1, 0);
        assert!(parse(&Source::from_bytes(bytes)).is_err());

        // of two records, the one nearest the end whose directory is there
        let mut twice = zip.clone();
        twice.extend_from_slice(b"PK\x05\x06 and something that is no end record at all");
        assert_eq!(names(&parsed(twice)), ["a.txt"]);
    }

    /// A megabyte of end records that are none, each with a ZIP64 locator in front of it that
    /// sends the parser searching: only a few are tried.
    #[test]
    fn a_file_of_false_end_records_is_refused_without_a_long_search() {
        let mut bytes = Zip::of(&[member("a.txt", 1, &[0x5A; 30])]).build();
        let mut false_end = b"PK\x06\x07".to_vec();
        false_end.extend_from_slice(&[0xFF; 16]);
        false_end.extend_from_slice(b"PK\x05\x06\0\0\0\0\x01\0\x01\0\x2e\0\0\0\x10\0\0\0\0\0");
        // one byte behind the last of them, so that none ends the file
        bytes.extend(false_end.iter().copied().cycle().take(900_000));
        bytes.push(0);
        let started = std::time::Instant::now();
        assert!(parse(&Source::from_bytes(bytes)).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "{:?}", started.elapsed());
    }

    #[test]
    fn zip64_records_give_the_values_the_end_record_marks() {
        let archive = parsed(Zip::of(&[member("a.txt", 0, b"abc"), member("b.txt", 0, b"defg")]).zip64().build());
        assert!(archive.is_zip64);
        assert_eq!(names(&archive), ["a.txt", "b.txt"]);
        assert_eq!(archive.entries[1].local_header_offset, 30 + 5 + 3);
    }

    /// The ZIP64 locator holds an offset too, and a program in front moves it with the rest:
    /// the record is found in front of its locator.
    #[test]
    fn a_program_in_front_of_a_zip64_archive() {
        let zip = Zip::of(&[member("a.txt", 1, &[0x5A; 40]), member("b.txt", 0, b"plain")]).zip64().build();
        for stub in [1_usize, 400, 70_000] {
            let mut behind = vec![0x90; stub];
            behind.extend_from_slice(&zip);
            let archive = parse(&Source::from_bytes(behind)).unwrap_or_else(|error| panic!("a program of {stub} bytes: {error:#}"));
            assert_eq!((names(&archive), archive.start, archive.is_zip64), (vec!["a.txt".to_owned(), "b.txt".to_owned()], stub as u64, true));
            assert_eq!(archive.entries[0].local_header_offset, stub as u64);
        }
    }

    /// A ZIP64 extra field holds a value only for a header field that carries the mark. An
    /// entry past 4 GiB with small sizes has the offset and nothing else, and its eight bytes
    /// used to be read as the uncompressed size.
    #[test]
    fn a_zip64_extra_field_with_the_offset_alone() {
        let mut bytes = Zip::of(&[member("pad.bin", 0, &[7; 50]), member("secret.txt", 1, &[0x5A; 12 + 20])]).build();
        // the second central header: mark its offset and append the ZIP64 field that holds it
        let offset = 30 + 7 + 50_u64;
        let central = bytes.windows(4).rposition(|window| window == b"PK\x01\x02").unwrap();
        let extra: Vec<u8> = [&[1, 0, 8, 0][..], &offset.to_le_bytes()].concat();
        bytes[central + 42..central + 46].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[central + 30..central + 32].copy_from_slice(&12_u16.to_le_bytes());
        let name_end = central + 46 + 10;
        drop(bytes.splice(name_end..name_end, extra));
        let eocd = bytes.len() - 22;
        let size = u32::from_le_bytes(bytes[eocd + 12..eocd + 16].try_into().unwrap()) + 12;
        bytes[eocd + 12..eocd + 16].copy_from_slice(&size.to_le_bytes());

        let archive = parsed(bytes);
        let entry = &archive.entries[1];
        assert_eq!((entry.local_header_offset, entry.compressed_size, entry.uncompressed_size), (offset, 32, 20));
        assert!(entry.here && archive.is_zip64, "a value from a ZIP64 field makes the archive ZIP64");
    }

    /// Offsets and sizes of 2^64-1 in ZIP64 fields: each of these was once added to something
    /// without a check.
    #[test]
    fn values_at_the_end_of_the_number_range_are_values_and_not_a_panic() {
        // the central directory at 2^64-1, of 2^64-1 bytes, with 2^64-1 entries
        for (entries, size, offset) in [(u64::MAX, 46, u64::MAX), (1, u64::MAX, u64::MAX), (u64::MAX, u64::MAX, 0), (1, u64::MAX, 30)] {
            let bytes = Zip::of(&[member("a", 0, b"x")]).zip64_values(entries, size, offset).build();
            drop(parse(&Source::from_bytes(bytes)));
        }
        // the locator names 2^64-1, and the record is found in front of it all the same
        let bytes = Zip::of(&[member("a", 0, b"x")]).zip64().locator_offset(u64::MAX).build();
        assert_eq!(names(&parsed(bytes)), ["a"]);
        // an entry whose local header is at 2^64-1, and one whose sizes are
        let far = Member { zip64: Some((u64::MAX, u64::MAX, u64::MAX)), ..member("far", 1, &[0x5A; 20]) };
        let archive = parsed(Zip::of(&[far]).build());
        let entry = &archive.entries[0];
        assert_eq!((entry.compressed_size, entry.uncompressed_size, entry.local_header_offset), (u64::MAX, u64::MAX, u64::MAX));
        assert!(!entry.here && archive.volume == Volume::Incomplete, "past the end of the file");

        let mut behind = vec![0; 9];
        behind.extend_from_slice(&Zip::of(&[Member { zip64: Some((u64::MAX, u64::MAX, u64::MAX)), ..member("far", 1, &[0x5A; 20]) }]).build());
        assert!(!parsed(behind).entries[0].here, "and moved by a program in front, still no offset");
    }

    #[test]
    fn a_count_is_never_trusted_with_an_allocation() {
        // 65535 entries announced, one there: the walk ends where the directory does
        let mut bytes = Zip::of(&[member("a", 0, b"x")]).build();
        let eocd = bytes.len() - 22;
        bytes[eocd + 8..eocd + 12].copy_from_slice(&[0xFF; 4]);
        let error = parse(&Source::from_bytes(bytes)).unwrap_err();
        assert!(format!("{error:#}").contains("central directory entry 1"), "{error:#}");

        let bytes = Zip::of(&[member("a", 0, b"x")]).zip64_values(u64::MAX, 47, 32).build();
        assert!(parse(&Source::from_bytes(bytes)).is_err());
    }

    #[test]
    fn a_directory_is_told_by_its_name_or_by_its_attributes() {
        assert!(is_directory(b"dir/", 0x0314, 0));
        assert!(!is_directory(b"file", 0x0314, 0));
        // MS-DOS and NTFS: the directory attribute
        assert!(is_directory(b"dir", 0x0014, 0x10));
        assert!(is_directory(b"dir", 0x0A3F, 0x30));
        assert!(!is_directory(b"file", 0x0014, 0x20));
        // Unix: the file type in the high half
        assert!(is_directory(b"dir", 0x031E, 0o040_755 << 16));
        assert!(!is_directory(b"file", 0x031E, 0o100_644 << 16));
        assert!(!is_directory(b"link", 0x031E, 0o120_777 << 16));
        // on Unix the low half is not the MS-DOS attributes, and on other systems nothing is known
        assert!(!is_directory(b"file", 0x031E, 0x10));
        assert!(!is_directory(b"dir", 0x0714, 0x10));

        let archive = parsed(Zip::of(&[Member { made_by: 0x0014, external: 0x10, ..member("folder", 0, b"") }, member("folder/", 0, b""), member("file", 0, b"")]).build());
        assert_eq!(archive.entries.iter().map(|entry| entry.directory).collect::<Vec<_>>(), [true, true, false]);
    }

    #[test]
    fn the_writer_before_pkzip_2_is_told_by_version_made_by() {
        let archive = parsed(Zip::of(&[Member { made_by: 10, ..member("old", 1, &[0x5A; 20]) }, Member { made_by: 0x0313, ..member("older", 1, &[0x5A; 20]) }, Member { made_by: 20, version: 10, ..member("new", 1, &[0x5A; 20]) }]).build());
        assert_eq!(archive.entries.iter().map(|entry| entry.two_byte_check).collect::<Vec<_>>(), [true, true, false], "version needed 1.0 from a writer at 2.0 is one check byte");
    }

    /// The last volume of a spanned archive says which disk it is, and each entry says which
    /// disk it starts on. An entry of another disk is not in this file.
    #[test]
    fn the_last_volume_of_a_spanned_archive() {
        let bytes = Zip::of(&[Member { disk: 0, ..member("first.bin", 1, &[0x5A; 40]) }, Member { disk: 2, ..member("last.txt", 1, &[0x5A; 30]) }]).disk(2).build();
        let archive = parsed(bytes);
        assert_eq!(archive.volume, Volume::Later);
        // the offset of an entry of another disk leads to no header of that name here
        let first = &archive.entries[0];
        assert!(first.here, "a local header of its name is at its offset: the volumes were joined, or the file is all there is");

        let mut bytes = Zip::of(&[Member { disk: 0, ..member("first.bin", 1, &[0x5A; 40]) }, Member { disk: 2, ..member("last.txt", 1, &[0x5A; 30]) }]).disk(2).build();
        bytes[30] ^= 0xFF;
        let archive = parsed(bytes);
        assert_eq!(archive.entries.iter().map(|entry| (entry.here, entry.split)).collect::<Vec<_>>(), [(false, Split::Before), (true, Split::No)]);
    }

    /// The end of an archive that was cut into pieces: its directory names offsets in front
    /// of the start of the file.
    #[test]
    fn the_last_piece_of_an_archive_cut_into_pieces() {
        let zip = Zip::of(&[member("a.bin", 1, &[0x5A; 300]), member("b.bin", 1, &[0xA5; 300]), member("c.txt", 1, &[0x3C; 40])]).build();
        let second_header = 30 + 5 + 300;
        let piece = zip[second_header + 10..].to_vec();
        let archive = parsed(piece);
        assert_eq!(archive.volume, Volume::Incomplete);
        assert_eq!(archive.entries.iter().map(|entry| (entry.here, entry.split)).collect::<Vec<_>>(), [(false, Split::Before), (false, Split::Before), (true, Split::No)]);
        assert_eq!(archive.start, 0);
    }

    #[test]
    fn an_entry_past_the_end_of_the_file_makes_the_archive_incomplete() {
        let cut = Member { declared: Some(0x00FF_FFFF), ..member("cut.bin", 1, &[0x5A; 52]) };
        let archive = parsed(Zip::of(&[cut]).build());
        assert_eq!((archive.volume, archive.entries[0].here), (Volume::Incomplete, true), "its header is here, its data is not");
    }

    /// The first volume of a split archive starts with the split marker and has no end
    /// record: its entries are read from their local headers.
    #[test]
    fn the_first_volume_of_a_split_archive() {
        let zip = Zip::of(&[member("whole.txt", 1, &[0x5A; 40]), Member { flags: 9, ..member("with-descriptor.txt", 1, &[0x5A; 25]) }, member("cut.bin", 1, &[0xA5; 500])]).descriptors().build();
        let directory = zip.windows(4).position(|window| window == b"PK\x01\x02").unwrap();
        let mut volume = b"PK\x07\x08".to_vec();
        volume.extend_from_slice(&zip[..directory - 200]);

        let archive = parsed(volume);
        assert_eq!(archive.volume, Volume::First);
        assert_eq!(names(&archive), ["whole.txt", "with-descriptor.txt", "cut.bin"]);
        assert_eq!(archive.entries.iter().map(|entry| entry.split).collect::<Vec<_>>(), [Split::No, Split::No, Split::After]);
        assert_eq!(archive.entries[0].local_header_offset, 4);
        assert!(archive.entries.iter().all(|entry| entry.here && entry.encryption == ZipEncryption::ZipCrypto && !entry.two_byte_check));

        // the marker alone, or a file that has no marker, is no first volume
        assert!(parse(&Source::from_bytes(b"PK\x07\x08".to_vec())).is_err());
        assert!(parse(&Source::from_bytes(zip[..directory].to_vec())).is_err());
    }

    #[test]
    fn names_that_are_not_utf_8_are_shown_with_a_replacement() {
        let archive = parsed(Zip::of(&[member("hello.txt", 0, b"")]).build());
        assert_eq!(filename_lossy(&archive.entries[0]), "hello.txt");
        let mut entry = archive.entries[0].clone();
        entry.filename = vec![0xC0, 0xC1, 0xFE, 0xFF];
        assert!(filename_lossy(&entry).contains('\u{FFFD}'));
    }
}
