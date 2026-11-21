//! The archive without its password.
//!
//! `-o FILE` writes the archive with the entries the keys open decrypted: the same entries,
//! still packed, in the same order, with the encryption flag cleared and the twelve bytes of
//! each encryption header taken out. Nothing is unpacked. Entries the keys do not open are
//! copied as they are. The file is created new: one that exists is never overwritten, and a
//! symbolic link is never followed.
//!
//! The archive is read by range and written as it is read. What stands between its records is
//! copied as it is, so a program in front of the archive and a comment behind it stay.

use std::io::Read as _;
use std::io::Write;
use std::path::Path;

use anyhow::Context as _;
use anyhow::bail;
use anyhow::ensure;
use archivewolf_zip_crypto::Keys;

use crate::formats::source::Source;
use crate::formats::zip::headers::CD_HEADER_LEN;
use crate::formats::zip::headers::CD_SIG;
use crate::formats::zip::headers::CentralDirectoryHeader;
use crate::formats::zip::headers::EOCD_LEN;
use crate::formats::zip::headers::Eocd;
use crate::formats::zip::headers::LOCAL_HEADER_LEN;
use crate::formats::zip::headers::LocalFileHeader;
use crate::formats::zip::headers::ZIP64_EOCD_LEN;
use crate::formats::zip::headers::ZIP64_LOCATOR_LEN;
use crate::formats::zip::headers::Zip64Eocd;
use crate::formats::zip::headers::Zip64Locator;
use crate::formats::zip::headers::find_eocd;

/// The encryption flag of an entry.
const ENCRYPTED: u16 = 0x0001;
/// The flag of an entry with a data descriptor behind its data.
const DESCRIPTOR: u16 = 0x0008;
/// The twelve bytes of an encryption header.
const HEADER: u64 = 12;
/// The signature a data descriptor may start with.
const DESCRIPTOR_SIG: [u8; 4] = *b"PK\x07\x08";
/// The extra field of ZIP64 values.
const ZIP64_ID: u16 = 0x0001;
/// What a field of 32 bits holds when its value is in a ZIP64 field.
const IN_ZIP64: u32 = u32::MAX;
/// How much is copied at a time.
const PIECE: usize = 64 * 1024;

/// What was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Written {
    /// How many entries were decrypted.
    pub decrypted: usize,
    /// How many encrypted entries were copied as they are.
    pub left: usize,
}

/// One record of the central directory, as it stands in the archive.
struct Record {
    fixed: [u8; CD_HEADER_LEN],
    header: CentralDirectoryHeader,
    /// The name, the extra fields and the comment, in one piece.
    rest: Vec<u8>,
    /// Where the extra fields start in `rest`.
    extra_at: usize,
    /// The packed size of the entry, with its encryption header.
    packed: u64,
    unpacked: u64,
    /// Where its local header is in the file.
    local_at: u64,
    /// Where its local header is in the file that is written.
    new_local_at: u64,
    /// The keys that open it, when it is decrypted.
    keys: Option<Keys>,
}

/// A number of two, four or eight bytes at a place of a record, low byte first.
fn get<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// Put bytes over a place of a record.
fn put(bytes: &mut [u8], at: usize, value: &[u8]) -> anyhow::Result<()> {
    let slot = at.checked_add(value.len()).and_then(|end| bytes.get_mut(at..end)).context("a record of the archive is shorter than its fields")?;
    slot.copy_from_slice(value);
    Ok(())
}

/// Where the body of the ZIP64 field starts in the extra fields of a header, and how long it
/// is.
fn zip64_field(extra: &[u8]) -> Option<(usize, usize)> {
    let mut at = 0_usize;
    while let (Some(id), Some(size)) = (get::<2>(extra, at).map(u16::from_le_bytes), get::<2>(extra, at + 2).map(u16::from_le_bytes)) {
        let body = at + 4;
        if id == ZIP64_ID {
            return (body + usize::from(size) <= extra.len()).then_some((body, usize::from(size)));
        }
        at = body + usize::from(size);
    }
    None
}

/// An offset of the file as the archive states it: the archive may start behind a program,
/// and then states every offset that much lower.
fn declared(actual: u64, shift: i128) -> anyhow::Result<u64> {
    u64::try_from(i128::from(actual) - shift).ok().context("an offset of the archive does not fit")
}

/// Copy the bytes `from` to `until - 1` of the archive as they are.
fn copy(source: &Source, from: u64, until: u64, out: &mut impl Write) -> anyhow::Result<()> {
    ensure!(from <= until, "the records of the archive overlap: it is not written anew");
    let mut reader = source.reader(from, until - from).context("the archive ends before its records do")?;
    let mut buffer = vec![0_u8; PIECE];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(());
        }
        out.write_all(buffer.get(..count).unwrap_or_default())?;
    }
}

/// Where the archive ends: its end record, its ZIP64 records when it has them, and where its
/// central directory is.
struct End {
    eocd_at: u64,
    eocd: Eocd,
    /// The ZIP64 end record, with where it is.
    zip64: Option<(u64, Zip64Eocd)>,
    count: u64,
    directory_at: u64,
    directory_size: u64,
    /// The distance from an offset the archive states to its place in the file.
    shift: i128,
}

/// Find the end of the archive. Only an archive of one file whose records are where their
/// writer put them is written anew: anything else is an error, and nothing is written.
fn end_of(source: &Source) -> anyhow::Result<End> {
    let len = source.len();
    let tail_at = len.saturating_sub((EOCD_LEN + 65_535) as u64);
    let tail = source.read_at(tail_at, len - tail_at)?;
    let at = find_eocd(&tail)?;
    let eocd = tail.get(at..).and_then(Eocd::parse).context("no end of central directory record")?;
    let eocd_at = tail_at + at as u64;
    ensure!(eocd.disk_number == 0 && eocd.start_disk == 0, "the archive is one volume of a set: it is not written anew");

    let has_locator = eocd_at.checked_sub(ZIP64_LOCATOR_LEN as u64).and_then(|at| source.read_at(at, ZIP64_LOCATOR_LEN as u64).ok()).as_deref().and_then(Zip64Locator::parse).is_some();
    let zip64 = if has_locator {
        let record_at = eocd_at.checked_sub((ZIP64_LOCATOR_LEN + ZIP64_EOCD_LEN) as u64).context("the ZIP64 end record is not in front of its locator")?;
        let record = source.read_at(record_at, ZIP64_EOCD_LEN as u64).ok().as_deref().and_then(Zip64Eocd::parse).filter(|record| record.record_size == (ZIP64_EOCD_LEN - 12) as u64);
        Some((record_at, record.context("the ZIP64 end record is not in front of its locator: the archive is not written anew")?))
    } else {
        None
    };
    let (count, directory_size, stated, directory_end) = match &zip64 {
        Some((at, record)) => (record.entries_total, record.size, record.offset, *at),
        None => (u64::from(eocd.entries_total), u64::from(eocd.size), u64::from(eocd.offset), eocd_at),
    };
    ensure!(zip64.as_ref().is_none_or(|(_, record)| record.directory.is_none()), "the central directory of the archive is encrypted: it is not written anew");
    let directory_at = directory_end.checked_sub(directory_size).context("the central directory is larger than the file")?;
    ensure!(count == 0 || source.read_at(directory_at, 4).ok().as_deref() == Some(&CD_SIG.to_le_bytes()[..]), "the central directory is not in front of the end record: the archive is not written anew");
    Ok(End { eocd_at, eocd, zip64, count, directory_at, directory_size, shift: i128::from(directory_at) - i128::from(stated) })
}

/// Read the central directory: every record as it stands, with where its entry lies.
fn records(source: &Source, end: &End) -> anyhow::Result<Vec<Record>> {
    let mut cursor = source.cursor(end.directory_at);
    let mut records = Vec::new();
    for index in 0..end.count {
        let fixed = cursor.array::<CD_HEADER_LEN>().with_context(|| format!("central directory entry {index} is cut short"))?;
        let header = CentralDirectoryHeader::parse(&fixed).with_context(|| format!("central directory entry {index} has no signature"))?;
        let rest = cursor.read_vec(u64::from(header.name_len) + u64::from(header.extra_len) + u64::from(header.comment_len)).with_context(|| format!("central directory entry {index} is cut short"))?;
        let extra_at = usize::from(header.name_len);
        let extra = rest.get(extra_at..extra_at + usize::from(header.extra_len)).unwrap_or_default();

        // the values a ZIP64 field holds, in their order: unpacked size, packed size, offset
        let mut at = zip64_field(extra).map(|(body, _)| body);
        let mut value = |marked: bool, plain: u32| -> anyhow::Result<u64> {
            if !marked {
                return Ok(u64::from(plain));
            }
            let place = at.context("a size of the archive is said to be in a ZIP64 field that is not there")?;
            at = Some(place + 8);
            get::<8>(extra, place).map(u64::from_le_bytes).context("a ZIP64 field of the archive is cut short")
        };
        let unpacked = value(header.uncompressed_size == IN_ZIP64, header.uncompressed_size)?;
        let packed = value(header.compressed_size == IN_ZIP64, header.compressed_size)?;
        let stated = value(header.local_header_offset == IN_ZIP64, header.local_header_offset)?;
        let local_at = u64::try_from(i128::from(stated) + end.shift).ok().filter(|at| *at < source.len()).with_context(|| format!("entry {index} of the archive is not in this file"))?;
        ensure!(header.disk_start == 0, "entry {index} of the archive is on another volume: the archive is not written anew");
        records.push(Record { fixed, header, rest, extra_at, packed, unpacked, local_at, new_local_at: 0, keys: None });
    }
    Ok(records)
}

/// Write one entry: its local header, its data, and its data descriptor when that can be
/// told. Returns where the entry ends in the archive that is read.
fn entry(source: &Source, record: &Record, out: &mut impl Write) -> anyhow::Result<u64> {
    let fixed = source.read_at(record.local_at, LOCAL_HEADER_LEN as u64).context("a local header lies past the end of the file")?;
    let local = LocalFileHeader::parse(&fixed).context("an entry of the archive has no local header where the directory puts it")?;
    let mut head = source.read_at(record.local_at, local.len()).context("a local header lies past the end of the file")?;
    let data_at = record.local_at + local.len();
    let data_end = data_at.checked_add(record.packed).filter(|end| *end <= source.len()).context("the data of an entry runs past the end of the file")?;

    let Some(keys) = record.keys.filter(|_| record.packed >= HEADER && local.flags & ENCRYPTED != 0) else {
        out.write_all(&head)?;
        copy(source, data_at, data_end, out)?;
        return Ok(data_end);
    };

    // the flag is cleared, and the packed size is that of the data without its header
    put(&mut head, 6, &(local.flags & !ENCRYPTED).to_le_bytes())?;
    if local.compressed_size == IN_ZIP64 {
        // a local header holds both sizes in its ZIP64 field, the unpacked one first
        let extra_at = LOCAL_HEADER_LEN + usize::from(local.name_len);
        let (body, _) = head.get(extra_at..).and_then(zip64_field).context("the packed size of an entry is said to be in a ZIP64 field that is not there")?;
        put(&mut head, extra_at + body + 8, &(record.packed - HEADER).to_le_bytes())?;
    } else if local.compressed_size != 0 || local.flags & DESCRIPTOR == 0 {
        put(&mut head, 18, &local.compressed_size.saturating_sub(12).to_le_bytes())?;
    }
    out.write_all(&head)?;

    let mut keys = keys;
    for &byte in &source.read_at(data_at, HEADER)? {
        let _ = keys.decrypt(byte);
    }
    let mut reader = source.reader(data_at + HEADER, record.packed - HEADER)?;
    let mut buffer = vec![0_u8; PIECE];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let piece = buffer.get_mut(..count).unwrap_or_default();
        for byte in piece.iter_mut() {
            *byte = keys.decrypt(*byte);
        }
        out.write_all(piece)?;
    }

    // a data descriptor repeats the packed size: with or without a signature, in four bytes or eight
    if local.flags & DESCRIPTOR != 0 {
        let behind = source.read_up_to(data_end, 24)?;
        let signed = behind.starts_with(&DESCRIPTOR_SIG);
        let body = behind.get(if signed { 4 } else { 0 }..).unwrap_or_default();
        let narrow = get::<4>(body, 4).map(u32::from_le_bytes).zip(get::<4>(body, 8).map(u32::from_le_bytes)).filter(|(packed, unpacked)| u64::from(*packed) == record.packed && u64::from(*unpacked) == record.unpacked);
        let wide = get::<8>(body, 4).map(u64::from_le_bytes).zip(get::<8>(body, 12).map(u64::from_le_bytes)).filter(|(packed, unpacked)| *packed == record.packed && *unpacked == record.unpacked);
        let sizes: Option<Vec<u8>> = match (narrow, wide) {
            (Some((packed, unpacked)), _) => Some([(packed - 12).to_le_bytes(), unpacked.to_le_bytes()].concat()),
            (None, Some((packed, unpacked))) => Some([(packed - HEADER).to_le_bytes(), unpacked.to_le_bytes()].concat()),
            (None, None) => None,
        };
        if let (Some(sizes), Some(front)) = (sizes, behind.get(..if signed { 8 } else { 4 })) {
            out.write_all(front)?;
            out.write_all(&sizes)?;
            return Ok(data_end + (front.len() + sizes.len()) as u64);
        }
    }
    Ok(data_end)
}

/// A writer that counts what it wrote: where the next byte goes.
struct Counting<W> {
    inner: W,
    at: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let count = self.inner.write(buf)?;
        self.at += count as u64;
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Write the archive in `source` to a new file at `output`, with every entry that `keys_of`
/// gives keys for decrypted. `keys_of` is asked with the place of an entry in the central
/// directory.
///
/// The file is created by this call or not at all, and is removed again when the archive
/// turns out to be one that cannot be written anew: half an archive is never left behind.
pub(crate) fn write(source: &Source, keys_of: &dyn Fn(usize) -> Option<Keys>, output: &Path) -> anyhow::Result<Written> {
    let end = end_of(source)?;
    let mut records = records(source, &end)?;
    for (index, record) in records.iter_mut().enumerate() {
        record.keys = keys_of(index).filter(|_| record.header.flags & ENCRYPTED != 0 && record.packed >= HEADER);
    }

    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(output).with_context(|| format!("cannot create {}", output.display()))?;
    let written = contents(source, &end, &mut records, &mut Counting { inner: std::io::BufWriter::new(file), at: 0 });
    if written.is_err() {
        // the file is this call's own: nothing else was at its place
        drop(std::fs::remove_file(output));
    }
    written
}

/// Write the whole archive: the entries in the order they lie in the file, then the central
/// directory and the end records with every offset and size as they are now.
fn contents(source: &Source, end: &End, records: &mut [Record], out: &mut Counting<impl Write>) -> anyhow::Result<Written> {
    let mut order: Vec<usize> = (0..records.len()).collect();
    order.sort_by_key(|&index| records.get(index).map_or(0, |record| record.local_at));
    let mut at = 0_u64;
    for index in order {
        let Some(record) = records.get_mut(index) else { continue };
        copy(source, at, record.local_at, out)?;
        record.new_local_at = out.at;
        at = entry(source, record, out)?;
    }
    copy(source, at, end.directory_at, out)?;

    let directory_at = out.at;
    for record in records.iter() {
        let mut fixed = record.fixed;
        let mut rest = record.rest.clone();
        let stated = declared(record.new_local_at, end.shift)?;
        // the ZIP64 field holds its values in their order: unpacked size, packed size, offset
        let extra = rest.get(record.extra_at..).unwrap_or_default();
        let mut field = zip64_field(extra).map(|(body, _)| record.extra_at + body);
        let mut place = |marked: bool| {
            let at = field.filter(|_| marked);
            if marked {
                field = field.map(|at| at + 8);
            }
            at
        };
        let _unpacked = place(record.header.uncompressed_size == IN_ZIP64);
        let packed_at = place(record.header.compressed_size == IN_ZIP64);
        let offset_at = place(record.header.local_header_offset == IN_ZIP64);

        if record.keys.is_some() {
            put(&mut fixed, 8, &(record.header.flags & !ENCRYPTED).to_le_bytes())?;
            match packed_at {
                Some(at) => put(&mut rest, at, &(record.packed - HEADER).to_le_bytes())?,
                None => put(&mut fixed, 20, &record.header.compressed_size.saturating_sub(12).to_le_bytes())?,
            }
        }
        match offset_at {
            Some(at) => put(&mut rest, at, &stated.to_le_bytes())?,
            None => put(&mut fixed, 42, &u32::try_from(stated).ok().context("an offset of the archive does not fit")?.to_le_bytes())?,
        }
        out.write_all(&fixed)?;
        out.write_all(&rest)?;
    }
    ensure!(out.at - directory_at == end.directory_size, "the central directory of the archive is not as long as its end record says: the archive is not written anew");

    // the end records, with where the central directory is now
    let directory_stated = declared(directory_at, end.shift)?;
    let directory_end = end.directory_at + end.directory_size;
    if let Some((record_at, _)) = &end.zip64 {
        copy(source, directory_end, *record_at, out)?;
        let record_stated = declared(out.at, end.shift)?;
        let mut record = source.read_at(*record_at, ZIP64_EOCD_LEN as u64)?;
        put(&mut record, 48, &directory_stated.to_le_bytes())?;
        out.write_all(&record)?;
        let mut locator = source.read_at(*record_at + ZIP64_EOCD_LEN as u64, ZIP64_LOCATOR_LEN as u64)?;
        put(&mut locator, 8, &record_stated.to_le_bytes())?;
        out.write_all(&locator)?;
    } else {
        copy(source, directory_end, end.eocd_at, out)?;
    }
    let mut eocd = source.read_at(end.eocd_at, source.len() - end.eocd_at)?;
    if end.eocd.offset != IN_ZIP64 {
        put(&mut eocd, 16, &u32::try_from(directory_stated).ok().context("an offset of the archive does not fit")?.to_le_bytes())?;
    }
    out.write_all(&eocd)?;
    out.flush()?;

    let decrypted = records.iter().filter(|record| record.keys.is_some()).count();
    let left = records.iter().filter(|record| record.keys.is_none() && record.header.flags & ENCRYPTED != 0).count();
    if decrypted == 0 {
        bail!("the keys open no entry of the archive: nothing is written");
    }
    Ok(Written { decrypted, left })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::zip::data_extract::Data;
    use crate::formats::zip::data_extract::locate;
    use crate::formats::zip::encryption::ZipEncryption;
    use crate::formats::zip::parser::ZipArchive;
    use crate::formats::zip::parser::filename_lossy;
    use crate::formats::zip::parser::parse;

    /// Write a fixture without its password, with the keys of `password` for every entry of
    /// `zip-crypto` that `pick` takes, and read the result back.
    fn rewritten(fixture: &str, password: &str, pick: impl Fn(&str) -> bool) -> (Written, Source, ZipArchive, Source, ZipArchive) {
        let source = Source::open(Path::new(&format!("tests/fixtures/{fixture}")), 0).unwrap();
        let before = parse(&source).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("open.zip");
        let keys = Keys::from_password(password.as_bytes());
        let written = write(&source, &|index| before.entries.get(index).filter(|entry| entry.encryption == ZipEncryption::ZipCrypto && pick(&filename_lossy(entry))).map(|_| keys), &output).unwrap_or_else(|fault| panic!("{fixture}: {fault:#}"));
        let after_source = Source::from_bytes(std::fs::read(&output).unwrap());
        let after = parse(&after_source).unwrap();
        (written, source, before, after_source, after)
    }

    /// Whether the data of an entry that is not encrypted unpacks to its CRC-32. An entry of a
    /// method this test does not unpack is held to its packed size alone.
    fn unpacks(source: &Source, entry: &crate::formats::zip::parser::ZipEntry) -> bool {
        let Data::Here(start) = locate(source, entry) else { return false };
        let reader = source.reader(start, entry.compressed_size).unwrap();
        let mut content = Vec::new();
        let read = match entry.compression_method {
            0 => std::io::Read::read_to_end(&mut std::io::Read::take(reader, u64::MAX), &mut content),
            8 => std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(reader), &mut content),
            _ => return true,
        };
        read.is_ok() && content.len() as u64 == entry.uncompressed_size && crc32fast::hash(&content) == entry.crc32
    }

    #[test]
    fn every_entry_the_keys_open_is_decrypted_and_still_packed() {
        for (fixture, password) in [
            ("zip-crypto/bkcrack-src_secrets.zip", "W4sF0rgotten"),
            ("zip-crypto/gen_infozip_store_multi.zip", "iz-store_multi"),
            ("zip-crypto/gen_infozip_deflate.zip", "iz-deflate"),
            // data descriptors behind the data, from a pipe and from a writer that always writes them
            ("zip-crypto/gen_infozip_stream.zip", "iz-stream"),
            ("zip-crypto/gen_own_zc_datadesc.zip", "own-dd"),
            ("zip-crypto/gen_own_zc_datadesc_stored.zip", "own-dd"),
            // ZIP64 records and fields
            ("zip-crypto/gen_infozip_zip64.zip", "iz-zip64"),
            // methods that are not unpacked here: the entry is decrypted all the same
            ("zip-crypto/gen_7z_zipcrypto_bzip2.zip", "7z-zipcrypto_bzip2"),
            ("zip-crypto/gen_own_zc_eight_stored.zip", "own-eight"),
        ] {
            let (written, _, before, after_source, after) = rewritten(fixture, password, |_| true);
            let encrypted = before.entries.iter().filter(|entry| entry.encryption == ZipEncryption::ZipCrypto).count();
            assert_eq!((written.decrypted, written.left), (encrypted, 0), "{fixture}");
            assert_eq!(after.entries.len(), before.entries.len(), "{fixture}");
            for (old, new) in before.entries.iter().zip(&after.entries) {
                assert_eq!((&new.filename, new.crc32, new.uncompressed_size, new.compression_method), (&old.filename, old.crc32, old.uncompressed_size, old.compression_method), "{fixture}");
                assert_eq!(new.encryption, ZipEncryption::None, "{fixture}");
                let shorter = if old.encryption == ZipEncryption::ZipCrypto { 12 } else { 0 };
                assert_eq!(new.compressed_size + shorter, old.compressed_size, "{fixture}");
                assert!(unpacks(&after_source, new), "{fixture}: {} does not unpack to its CRC-32", filename_lossy(new));
            }
            assert_eq!((after.comment == before.comment, after.is_zip64), (true, before.is_zip64), "{fixture}");
        }
    }

    #[test]
    fn an_entry_the_keys_do_not_open_is_copied_as_it_is() {
        // `first.txt` is opened and `second.txt`, under another password, is left
        let (written, source, before, after_source, after) = rewritten("zip-crypto/gen_own_zc_two_passwords.zip", "own-first", |name| name == "first.txt");
        assert_eq!(written, Written { decrypted: 1, left: 1 });
        assert_eq!(after.entries.iter().map(|entry| entry.encryption).collect::<Vec<_>>(), [ZipEncryption::None, ZipEncryption::ZipCrypto]);
        assert!(unpacks(&after_source, &after.entries[0]));
        let data = |source: &Source, entry: &crate::formats::zip::parser::ZipEntry| {
            let Data::Here(start) = locate(source, entry) else { panic!("no data") };
            source.read_at(start, entry.compressed_size).unwrap()
        };
        assert_eq!(data(&after_source, &after.entries[1]), data(&source, &before.entries[1]));
        // the second entry lies twelve bytes further up, and the directory says so
        assert_eq!(after.entries[1].local_header_offset + 12, before.entries[1].local_header_offset);
    }

    #[test]
    fn an_archive_behind_a_program_keeps_the_program_and_its_offsets() {
        let (written, source, before, after_source, after) = rewritten("zip-crypto/zipcrypto_sfx.zip", "bktest", |_| true);
        assert!(written.decrypted > 0 && written.left == 0);
        assert_eq!(after.start, before.start);
        assert!(before.start > 0, "the fixture has a program in front");
        assert_eq!(after_source.read_at(0, before.start).unwrap(), source.read_at(0, before.start).unwrap());
        assert!(after.entries.iter().all(|entry| entry.encryption == ZipEncryption::None && unpacks(&after_source, entry)));
    }

    #[test]
    fn a_file_that_exists_is_never_overwritten_and_keys_that_open_nothing_leave_no_file() {
        let source = Source::open(Path::new("tests/fixtures/zip-crypto/bkcrack-src_secrets.zip"), 0).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing.zip");
        std::fs::write(&existing, b"keep me").unwrap();
        let keys = Keys::from_password(b"W4sF0rgotten");
        assert!(format!("{:#}", write(&source, &|_| Some(keys), &existing).unwrap_err()).contains("cannot create"));
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep me");

        let output = dir.path().join("nothing.zip");
        let fault = write(&source, &|_| None, &output).unwrap_err();
        assert!(fault.to_string().contains("the keys open no entry"), "{fault:#}");
        assert!(!output.exists());

        #[cfg(unix)]
        {
            let link = dir.path().join("link.zip");
            std::os::unix::fs::symlink(dir.path().join("target.zip"), &link).unwrap();
            assert!(write(&source, &|_| Some(keys), &link).is_err());
            assert!(!dir.path().join("target.zip").exists());
        }
    }
}
