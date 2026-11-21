//! The records of a ZIP archive, each read from the few bytes it takes.
//!
//! Nothing here reads a file. A record is parsed from bytes the parser fetched for it, and a
//! record that is cut short is `None`: every field is taken with a check, so no length or
//! offset from a file is ever added to another one here.

use anyhow::bail;
use anyhow::ensure;

/// Local file header signature: `PK\x03\x04`.
pub(crate) const LOCAL_SIG: u32 = 0x0403_4b50;
/// Central directory header signature: `PK\x01\x02`.
pub(crate) const CD_SIG: u32 = 0x0201_4b50;
/// End of central directory signature: `PK\x05\x06`.
pub(crate) const EOCD_SIG: u32 = 0x0605_4b50;
/// ZIP64 end of central directory signature: `PK\x06\x06`.
pub(crate) const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
/// ZIP64 end of central directory locator signature: `PK\x06\x07`.
pub(crate) const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
/// `PK\x07\x08`: in front of a data descriptor, and at the start of the first volume of a
/// split or spanned archive.
pub(crate) const SPLIT_SIG: u32 = 0x0807_4b50;

/// Size of an end of central directory record without its comment.
pub(crate) const EOCD_LEN: usize = 22;
/// Size of a ZIP64 end of central directory locator.
pub(crate) const ZIP64_LOCATOR_LEN: usize = 20;
/// Size of a ZIP64 end of central directory record up to the offset of the directory, which is
/// all of a version 1 record without an extensible data sector.
pub(crate) const ZIP64_EOCD_LEN: usize = 56;
/// What a version 2 record adds in front of its hash data.
pub(crate) const ZIP64_EOCD_V2_LEN: usize = 28;
/// Size of a central directory header without its name, extra fields and comment.
pub(crate) const CD_HEADER_LEN: usize = 46;
/// Size of a local file header without its name and extra fields.
pub(crate) const LOCAL_HEADER_LEN: usize = 30;

/// Little-endian fields taken one after the other from the front of some bytes. A field the
/// bytes do not hold is `None`, and nothing is taken then.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fields<'a>(pub &'a [u8]);

impl<'a> Fields<'a> {
    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    /// The next two bytes as a number.
    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    /// The next four bytes as a number.
    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// The next eight bytes as a number.
    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }

    /// The next `len` bytes.
    pub(crate) fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(len)?;
        self.0 = rest;
        Some(head)
    }

    /// How many bytes are left.
    pub(crate) const fn left(&self) -> usize {
        self.0.len()
    }
}

/// End of central directory record, without its comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Eocd {
    /// Number of this disk.
    pub disk_number: u16,
    /// Disk where the central directory starts.
    pub start_disk: u16,
    /// Total number of central directory entries.
    pub entries_total: u16,
    /// Size of the central directory in bytes.
    pub size: u32,
    /// Offset of the central directory from the start of its disk.
    pub offset: u32,
    /// Length of the archive comment that follows the record.
    pub comment_len: u16,
}

impl Eocd {
    /// The record at the start of `record`, or `None` when the bytes are not one.
    pub(crate) fn parse(record: &[u8]) -> Option<Self> {
        let mut fields = Fields(record);
        if fields.u32()? != EOCD_SIG {
            return None;
        }
        let disk_number = fields.u16()?;
        let start_disk = fields.u16()?;
        let _entries_this_disk = fields.u16()?;
        let entries_total = fields.u16()?;
        let size = fields.u32()?;
        let offset = fields.u32()?;
        let comment_len = fields.u16()?;
        Some(Self { disk_number, start_disk, entries_total, size, offset, comment_len })
    }
}

/// ZIP64 end of central directory locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Zip64Locator {
    /// Disk that holds the ZIP64 end of central directory record.
    pub eocd64_disk: u32,
    /// Offset of that record from the start of its disk.
    pub eocd64_offset: u64,
    /// Total number of disks.
    pub total_disks: u32,
}

impl Zip64Locator {
    /// The locator at the start of `record`, or `None` when the bytes are not one.
    pub(crate) fn parse(record: &[u8]) -> Option<Self> {
        let mut fields = Fields(record);
        if fields.u32()? != ZIP64_LOCATOR_SIG {
            return None;
        }
        let eocd64_disk = fields.u32()?;
        let eocd64_offset = fields.u64()?;
        let total_disks = fields.u32()?;
        Some(Self { eocd64_disk, eocd64_offset, total_disks })
    }
}

/// What a version 2 ZIP64 end of central directory record says about the central directory
/// itself: how it is compressed and how it is encrypted (APPNOTE 7.3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectoryProtection {
    /// Method the central directory is compressed with, 0 for none.
    pub method: u16,
    /// Algorithm it is encrypted with, 0 for none.
    pub alg_id: u16,
    /// Key length in bits.
    pub bit_len: u16,
    /// Processing flags, as in extra field 0x0017.
    pub flags: u16,
}

/// ZIP64 end of central directory record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Zip64Eocd {
    /// Size of the record behind its first 12 bytes.
    pub record_size: u64,
    /// Number of this disk.
    pub disk_number: u32,
    /// Disk where the central directory starts.
    pub start_disk: u32,
    /// Total number of central directory entries.
    pub entries_total: u64,
    /// Size of the central directory in bytes.
    pub size: u64,
    /// Offset of the central directory from the start of its disk.
    pub offset: u64,
    /// The fields of version 2, when the record is of that version and holds them.
    pub directory: Option<DirectoryProtection>,
}

impl Zip64Eocd {
    /// The record at the start of `record`, or `None` when the bytes are not one. The fields of
    /// version 2 are read when the record says it needs version 6.2 to extract, which is what
    /// tells them from the extensible data sector of version 1.
    pub(crate) fn parse(record: &[u8]) -> Option<Self> {
        let mut fields = Fields(record);
        if fields.u32()? != ZIP64_EOCD_SIG {
            return None;
        }
        let record_size = fields.u64()?;
        let _version_made_by = fields.u16()?;
        let version_needed = fields.u16()?;
        let disk_number = fields.u32()?;
        let start_disk = fields.u32()?;
        let _entries_this_disk = fields.u64()?;
        let entries_total = fields.u64()?;
        let size = fields.u64()?;
        let offset = fields.u64()?;
        let directory = if version_needed & 0xFF >= 62 { Self::version_2(fields) } else { None };
        Some(Self { record_size, disk_number, start_disk, entries_total, size, offset, directory })
    }

    fn version_2(mut fields: Fields<'_>) -> Option<DirectoryProtection> {
        let method = fields.u16()?;
        let _compressed_size = fields.u64()?;
        let _original_size = fields.u64()?;
        let alg_id = fields.u16()?;
        let bit_len = fields.u16()?;
        let flags = fields.u16()?;
        Some(DirectoryProtection { method, alg_id, bit_len, flags })
    }
}

/// Central directory file header, without its name, extra fields and comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CentralDirectoryHeader {
    /// Version and host system of the software that wrote the entry.
    pub version_made_by: u16,
    /// Version needed to extract.
    pub version_needed: u16,
    /// General purpose bit flags.
    pub flags: u16,
    /// Compression method.
    pub compression_method: u16,
    /// Last modification time (MS-DOS format).
    pub last_mod_time: u16,
    /// Last modification date (MS-DOS format).
    pub last_mod_date: u16,
    /// CRC-32 of the uncompressed data.
    pub crc32: u32,
    /// Compressed size (0xFFFFFFFF when the ZIP64 extra field holds it).
    pub compressed_size: u32,
    /// Uncompressed size (0xFFFFFFFF when the ZIP64 extra field holds it).
    pub uncompressed_size: u32,
    /// Length of the name.
    pub name_len: u16,
    /// Length of the extra fields.
    pub extra_len: u16,
    /// Length of the comment.
    pub comment_len: u16,
    /// Disk the entry starts on (0xFFFF when the ZIP64 extra field holds it).
    pub disk_start: u16,
    /// External file attributes.
    pub external_attrs: u32,
    /// Offset of the local file header (0xFFFFFFFF when the ZIP64 extra field holds it).
    pub local_header_offset: u32,
}

impl CentralDirectoryHeader {
    /// The header at the start of `record`, or `None` when the bytes are not one.
    pub(crate) fn parse(record: &[u8]) -> Option<Self> {
        let mut fields = Fields(record);
        if fields.u32()? != CD_SIG {
            return None;
        }
        let version_made_by = fields.u16()?;
        let version_needed = fields.u16()?;
        let flags = fields.u16()?;
        let compression_method = fields.u16()?;
        let last_mod_time = fields.u16()?;
        let last_mod_date = fields.u16()?;
        let crc32 = fields.u32()?;
        let compressed_size = fields.u32()?;
        let uncompressed_size = fields.u32()?;
        let name_len = fields.u16()?;
        let extra_len = fields.u16()?;
        let comment_len = fields.u16()?;
        let disk_start = fields.u16()?;
        let _internal_attrs = fields.u16()?;
        let external_attrs = fields.u32()?;
        let local_header_offset = fields.u32()?;
        Some(Self { version_made_by, version_needed, flags, compression_method, last_mod_time, last_mod_date, crc32, compressed_size, uncompressed_size, name_len, extra_len, comment_len, disk_start, external_attrs, local_header_offset })
    }
}

/// Local file header, without its name and extra fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalFileHeader {
    /// Version needed to extract.
    pub version_needed: u16,
    /// General purpose bit flags.
    pub flags: u16,
    /// Compression method.
    pub compression_method: u16,
    /// Last modification time (MS-DOS format).
    pub last_mod_time: u16,
    /// Last modification date (MS-DOS format).
    pub last_mod_date: u16,
    /// CRC-32 of the uncompressed data.
    pub crc32: u32,
    /// Compressed size.
    pub compressed_size: u32,
    /// Uncompressed size.
    pub uncompressed_size: u32,
    /// Length of the name.
    pub name_len: u16,
    /// Length of the extra fields.
    pub extra_len: u16,
}

impl LocalFileHeader {
    /// The header at the start of `record`, or `None` when the bytes are not one.
    pub(crate) fn parse(record: &[u8]) -> Option<Self> {
        let mut fields = Fields(record);
        if fields.u32()? != LOCAL_SIG {
            return None;
        }
        let version_needed = fields.u16()?;
        let flags = fields.u16()?;
        let compression_method = fields.u16()?;
        let last_mod_time = fields.u16()?;
        let last_mod_date = fields.u16()?;
        let crc32 = fields.u32()?;
        let compressed_size = fields.u32()?;
        let uncompressed_size = fields.u32()?;
        let name_len = fields.u16()?;
        let extra_len = fields.u16()?;
        Some(Self { version_needed, flags, compression_method, last_mod_time, last_mod_date, crc32, compressed_size, uncompressed_size, name_len, extra_len })
    }

    /// How many bytes the header takes with its name and its extra fields.
    pub(crate) fn len(&self) -> u64 {
        LOCAL_HEADER_LEN as u64 + u64::from(self.name_len) + u64::from(self.extra_len)
    }
}

/// Maximum backward search distance for an end of central directory record whose comment ends
/// the file: the record and the longest comment it can carry.
const EOCD_MAX_SEARCH: usize = EOCD_LEN + 65_535;

/// Scan backward from the end of `data` for the end of central directory record whose comment
/// ends exactly where `data` ends, and return its offset.
///
/// This is what the scanner asks of the end of a program to tell whether it ends in a ZIP
/// archive. The parser asks the same first, and looks further when it finds none (bytes behind
/// the record).
pub(crate) fn find_eocd(data: &[u8]) -> anyhow::Result<usize> {
    ensure!(data.len() >= EOCD_LEN, "file too small for a ZIP archive (< 22 bytes)");

    let search_start = data.len().saturating_sub(EOCD_MAX_SEARCH);
    let signature = EOCD_SIG.to_le_bytes();

    let mut pos = data.len() - EOCD_LEN;
    loop {
        if let Some(record) = data.get(pos..).filter(|record| record.starts_with(&signature))
            && let Some(eocd) = Eocd::parse(record)
            && record.len() == EOCD_LEN + usize::from(eocd.comment_len)
        {
            return Ok(pos);
        }
        if pos <= search_start {
            break;
        }
        pos -= 1;
    }

    bail!("EOCD signature not found — not a ZIP archive");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eocd_bytes(disk: u16, entries: u16, size: u32, offset: u32, comment: &[u8]) -> Vec<u8> {
        let mut buf = EOCD_SIG.to_le_bytes().to_vec();
        for field in [disk, disk, entries, entries] {
            buf.extend_from_slice(&field.to_le_bytes());
        }
        buf.extend_from_slice(&size.to_le_bytes());
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(comment);
        buf
    }

    #[test]
    fn fields_are_taken_in_order_and_never_past_the_end() {
        let mut fields = Fields(&[1, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 9, 8]);
        assert_eq!((fields.u16(), fields.u32(), fields.u64()), (Some(1), Some(2), Some(3)));
        assert_eq!(fields.left(), 2);
        assert_eq!(fields.u32(), None, "four bytes are not there");
        assert_eq!(fields.left(), 2, "and nothing was taken");
        assert_eq!(fields.bytes(3), None);
        assert_eq!(fields.bytes(2), Some(&[9, 8][..]));
        assert_eq!((fields.u16(), fields.bytes(0)), (None, Some(&[][..])));
    }

    #[test]
    fn an_end_record_is_found_where_its_comment_ends_the_data() {
        assert_eq!(find_eocd(&eocd_bytes(0, 0, 0, 0, b"")).unwrap(), 0);

        let mut data = vec![0xAA; 100];
        data.extend_from_slice(&eocd_bytes(0, 1, 46, 0, b""));
        assert_eq!(find_eocd(&data).unwrap(), 100);

        let mut data = vec![0xBB; 50];
        data.extend_from_slice(&eocd_bytes(0, 0, 0, 0, b"helloworld"));
        assert_eq!(find_eocd(&data).unwrap(), 50);
        assert_eq!(Eocd::parse(&data[50..]).unwrap().comment_len, 10);

        assert!(find_eocd(&[0; 10]).is_err());
        // a record with bytes behind its comment is not one that ends the data
        data.push(0);
        assert!(find_eocd(&data).is_err());
    }

    #[test]
    fn an_end_record_gives_its_fields() {
        let eocd = Eocd::parse(&eocd_bytes(3, 5, 230, 1024, b"test")).unwrap();
        assert_eq!(eocd, Eocd { disk_number: 3, start_disk: 3, entries_total: 5, size: 230, offset: 1024, comment_len: 4 });
        assert_eq!(Eocd::parse(&eocd_bytes(0, 0, 0, 0, b"")[..21]), None, "cut short");
        assert_eq!(Eocd::parse(&[0x50, 0x4B, 0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), None, "another signature");
    }

    fn zip64_record(version: u16, tail: &[u8]) -> Vec<u8> {
        let mut record = ZIP64_EOCD_SIG.to_le_bytes().to_vec();
        record.extend_from_slice(&(44 + tail.len() as u64).to_le_bytes());
        record.extend_from_slice(&version.to_le_bytes());
        record.extend_from_slice(&version.to_le_bytes());
        record.extend_from_slice(&7_u32.to_le_bytes());
        record.extend_from_slice(&6_u32.to_le_bytes());
        for field in [3_u64, 3, 300, 1000] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        record.extend_from_slice(tail);
        record
    }

    #[test]
    fn a_zip64_end_record_gives_its_fields() {
        let record = Zip64Eocd::parse(&zip64_record(45, &[])).unwrap();
        assert_eq!(record, Zip64Eocd { record_size: 44, disk_number: 7, start_disk: 6, entries_total: 3, size: 300, offset: 1000, directory: None });
        assert_eq!(Zip64Eocd::parse(&zip64_record(45, &[])[..55]), None);

        let mut locator = ZIP64_LOCATOR_SIG.to_le_bytes().to_vec();
        locator.extend_from_slice(&1_u32.to_le_bytes());
        locator.extend_from_slice(&0x1_0000_0000_u64.to_le_bytes());
        locator.extend_from_slice(&2_u32.to_le_bytes());
        assert_eq!(Zip64Locator::parse(&locator), Some(Zip64Locator { eocd64_disk: 1, eocd64_offset: 0x1_0000_0000, total_disks: 2 }));
        assert_eq!(Zip64Locator::parse(&locator[..19]), None);
    }

    /// The fields of version 2 say how the central directory is compressed and encrypted. A
    /// version 1 record with an extensible data sector of the same length does not have them.
    #[test]
    fn a_version_2_record_says_how_the_directory_is_protected() {
        let mut tail = Vec::new();
        tail.extend_from_slice(&8_u16.to_le_bytes());
        tail.extend_from_slice(&500_u64.to_le_bytes());
        tail.extend_from_slice(&900_u64.to_le_bytes());
        for field in [0x6610_u16, 256, 1, 0x8004, 0] {
            tail.extend_from_slice(&field.to_le_bytes());
        }
        assert_eq!(tail.len(), ZIP64_EOCD_V2_LEN);
        assert_eq!(Zip64Eocd::parse(&zip64_record(62, &tail)).unwrap().directory, Some(DirectoryProtection { method: 8, alg_id: 0x6610, bit_len: 256, flags: 1 }));
        assert_eq!(Zip64Eocd::parse(&zip64_record(45, &tail)).unwrap().directory, None, "an extensible data sector");
        assert_eq!(Zip64Eocd::parse(&zip64_record(62, &tail[..20])).unwrap().directory, None, "cut short");
    }

    #[test]
    fn a_central_header_gives_its_fields() {
        let mut record = CD_SIG.to_le_bytes().to_vec();
        for field in [0x031E_u16, 20, 0x0009, 8, 0x5A5A, 0x1111] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        for field in [0xDEAD_BEEF_u32, 100, 200] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        for field in [9_u16, 12, 3, 2, 0] {
            record.extend_from_slice(&field.to_le_bytes());
        }
        record.extend_from_slice(&0x81A4_0000_u32.to_le_bytes());
        record.extend_from_slice(&0x0100_u32.to_le_bytes());
        assert_eq!(record.len(), CD_HEADER_LEN);

        let header = CentralDirectoryHeader::parse(&record).unwrap();
        assert_eq!((header.version_made_by, header.version_needed, header.flags, header.compression_method, header.last_mod_time), (0x031E, 20, 9, 8, 0x5A5A));
        assert_eq!((header.crc32, header.compressed_size, header.uncompressed_size), (0xDEAD_BEEF, 100, 200));
        assert_eq!((header.name_len, header.extra_len, header.comment_len, header.disk_start), (9, 12, 3, 2));
        assert_eq!((header.external_attrs, header.local_header_offset), (0x81A4_0000, 0x0100));

        assert_eq!(CentralDirectoryHeader::parse(&record[..45]), None);
        record[0] = 0xFF;
        assert_eq!(CentralDirectoryHeader::parse(&record), None);
    }
}
