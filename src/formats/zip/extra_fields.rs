//! The extra fields of a ZIP header that say how an entry is encrypted, and its ZIP64 values.
//!
//! Extra fields are records of a 2-byte identifier, a 2-byte size and that many bytes. The
//! walk over them keeps the three kinds the analysis needs and nothing of the others, so what
//! is held for an entry does not grow with what a writer put into its extra fields.

use super::headers::Fields;

/// WinZip AES encryption extra field.
const ZIP_WINZIP_ID: u16 = 0x9901;
/// PKWARE strong encryption extra field.
const ZIP_PKWARE_ID: u16 = 0x0017;
/// ZIP64 extended information extra field.
const ZIP64_ID: u16 = 0x0001;

/// WinZip AES extra field (0x9901).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZipWinzipExtra {
    /// AE version: 1 = AE-1, 2 = AE-2.
    pub ae_version: u16,
    /// Encryption strength: 1 = AES-128, 2 = AES-192, 3 = AES-256.
    pub strength: u8,
    /// The compression method the entry really uses (its header says 99).
    pub actual_compression: u16,
}

/// PKWARE strong encryption extra field (0x0017), which only a central header carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZipPkwareExtra {
    /// Algorithm identifier.
    pub alg_id: u16,
    /// Key length in bits.
    pub bit_len: u16,
    /// Processing flags: 1 = password, 2 = certificate, 3 = either.
    pub flags: u16,
}

/// Which fields of a header hold the mark that sends a reader to the ZIP64 extra field:
/// 0xFFFFFFFF in a size or an offset, 0xFFFF in a disk number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Zip64Wanted {
    /// The uncompressed size.
    pub uncompressed: bool,
    /// The compressed size.
    pub compressed: bool,
    /// The offset of the local header.
    pub offset: bool,
    /// The number of the disk the entry starts on.
    pub disk: bool,
}

/// The values a ZIP64 extra field holds for the fields that were marked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Zip64Values {
    /// Uncompressed size.
    pub uncompressed: Option<u64>,
    /// Compressed size.
    pub compressed: Option<u64>,
    /// Offset of the local header.
    pub offset: Option<u64>,
    /// Number of the disk the entry starts on.
    pub disk: Option<u32>,
}

/// What the extra fields of one header say.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Extras {
    /// The first WinZip AES field.
    pub zip_winzip: Option<ZipWinzipExtra>,
    /// The first PKWARE strong encryption field.
    pub pkware: Option<ZipPkwareExtra>,
    /// The values of the first ZIP64 field.
    pub zip64: Zip64Values,
    /// Which fields there are, of those a writer is known by.
    pub marks: ExtraMarks,
}

/// Which extra fields a header has, of those that tell the programs that write ZIP archives
/// apart, and how long its extra fields are in all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ExtraMarks {
    /// A ZIP64 field (`0001`).
    pub zip64: bool,
    /// NTFS times (`000a`).
    pub ntfs: bool,
    /// Time stamps of Info-ZIP (`5455`).
    pub times: bool,
    /// User IDs of Info-ZIP on Unix (`7875`).
    pub unix_ids: bool,
    /// The length of all extra fields of the header together.
    pub len: u16,
}

/// The extra field of NTFS times.
const NTFS_ID: u16 = 0x000a;
/// The extra field of the time stamps of Info-ZIP.
const TIMES_ID: u16 = 0x5455;
/// The extra field of the user IDs of Info-ZIP on Unix.
const UNIX_IDS_ID: u16 = 0x7875;

/// Walk the extra fields of one header.
///
/// A ZIP64 field holds a value only for a header field that carries the mark, in the order
/// uncompressed size, compressed size, offset, disk (APPNOTE 4.5.3): `wanted` says which
/// those are. A field that is cut short ends the walk, and what was read before it stands.
pub(crate) fn parse_extra_fields(raw: &[u8], wanted: Zip64Wanted) -> Extras {
    let mut extras = Extras::default();
    extras.marks.len = u16::try_from(raw.len()).unwrap_or(u16::MAX);
    let mut seen_zip64 = false;
    let mut fields = Fields(raw);

    while fields.left() >= 4 {
        let (Some(id), Some(size)) = (fields.u16(), fields.u16()) else { break };
        let Some(body) = fields.bytes(usize::from(size)) else { break };
        match id {
            ZIP64_ID => extras.marks.zip64 = true,
            NTFS_ID => extras.marks.ntfs = true,
            TIMES_ID => extras.marks.times = true,
            UNIX_IDS_ID => extras.marks.unix_ids = true,
            _ => {},
        }
        match id {
            ZIP_WINZIP_ID if extras.zip_winzip.is_none() => extras.zip_winzip = parse_zip_winzip(body),
            ZIP_PKWARE_ID if extras.pkware.is_none() => extras.pkware = parse_zip_pkware(body),
            ZIP64_ID if !seen_zip64 => {
                seen_zip64 = true;
                extras.zip64 = parse_zip64(body, wanted);
            },
            _ => {},
        }
    }
    extras
}

/// A WinZip AES field: version, vendor, strength and the real compression method, 7 bytes.
fn parse_zip_winzip(body: &[u8]) -> Option<ZipWinzipExtra> {
    let mut fields = Fields(body);
    let ae_version = fields.u16()?;
    let _vendor = fields.u16()?;
    let strength = *fields.bytes(1)?.first()?;
    let actual_compression = fields.u16()?;
    Some(ZipWinzipExtra { ae_version, strength, actual_compression })
}

/// A PKWARE strong encryption field: format, algorithm, key length and flags, 8 bytes.
fn parse_zip_pkware(body: &[u8]) -> Option<ZipPkwareExtra> {
    let mut fields = Fields(body);
    let _format = fields.u16()?;
    let alg_id = fields.u16()?;
    let bit_len = fields.u16()?;
    let flags = fields.u16()?;
    Some(ZipPkwareExtra { alg_id, bit_len, flags })
}

/// A ZIP64 field: one value for each header field that carries the mark, in a fixed order. A
/// value the field is too short for stays absent, and so do the ones behind it.
fn parse_zip64(body: &[u8], wanted: Zip64Wanted) -> Zip64Values {
    /// Take the marked values in their order. `None` at the first the field is too short for.
    fn take(mut fields: Fields<'_>, wanted: Zip64Wanted, values: &mut Zip64Values) -> Option<()> {
        if wanted.uncompressed {
            values.uncompressed = Some(fields.u64()?);
        }
        if wanted.compressed {
            values.compressed = Some(fields.u64()?);
        }
        if wanted.offset {
            values.offset = Some(fields.u64()?);
        }
        if wanted.disk {
            values.disk = Some(fields.u32()?);
        }
        Some(())
    }

    let mut values = Zip64Values::default();
    // a field that ends early is no error: the values in front of the end are kept
    let _complete = take(Fields(body), wanted, &mut values);
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(id: u16, body: &[u8]) -> Vec<u8> {
        let mut buf = id.to_le_bytes().to_vec();
        buf.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(body);
        buf
    }

    fn le64(values: &[u64]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_le_bytes()).collect()
    }

    const NOTHING: Zip64Wanted = Zip64Wanted { uncompressed: false, compressed: false, offset: false, disk: false };
    const ALL: Zip64Wanted = Zip64Wanted { uncompressed: true, compressed: true, offset: true, disk: true };

    #[test]
    fn a_zip_winzip_field_gives_version_strength_and_method() {
        let raw = field(ZIP_WINZIP_ID, &[2, 0, 0x41, 0x45, 3, 8, 0]);
        let extras = parse_extra_fields(&raw, NOTHING);
        assert_eq!(extras.zip_winzip, Some(ZipWinzipExtra { ae_version: 2, strength: 3, actual_compression: 8 }));
        assert_eq!((extras.pkware, extras.zip64), (None, Zip64Values::default()));

        // a field that is too short for its seven bytes says nothing
        assert_eq!(parse_extra_fields(&field(ZIP_WINZIP_ID, &[2, 0, 0x41, 0x45, 3, 8]), NOTHING).zip_winzip, None);
    }

    #[test]
    fn a_zip_pkware_field_gives_algorithm_key_length_and_flags() {
        let raw = field(ZIP_PKWARE_ID, &[2, 0, 0x10, 0x66, 0, 1, 1, 0]);
        assert_eq!(parse_extra_fields(&raw, NOTHING).pkware, Some(ZipPkwareExtra { alg_id: 0x6610, bit_len: 256, flags: 1 }));
        // the certificate data some writers put behind the eight bytes is not read
        let raw = field(ZIP_PKWARE_ID, &[2, 0, 0x0E, 0x66, 128, 0, 3, 0, 1, 0, 0, 0, 4, 0x80, 20, 0]);
        assert_eq!(parse_extra_fields(&raw, NOTHING).pkware, Some(ZipPkwareExtra { alg_id: 0x660E, bit_len: 128, flags: 3 }));
        assert_eq!(parse_extra_fields(&field(ZIP_PKWARE_ID, &[2, 0, 0x10, 0x66, 0, 1, 1]), NOTHING).pkware, None);
    }

    #[test]
    fn a_zip64_field_with_every_value() {
        let mut body = le64(&[0x1_0000_0000, 0x2_0000_0000, 0x3_0000_0000]);
        body.extend_from_slice(&5_u32.to_le_bytes());
        let values = parse_extra_fields(&field(ZIP64_ID, &body), ALL).zip64;
        assert_eq!(values, Zip64Values { uncompressed: Some(0x1_0000_0000), compressed: Some(0x2_0000_0000), offset: Some(0x3_0000_0000), disk: Some(5) });
    }

    /// The field holds a value only for a header field that is marked, so the same eight bytes
    /// are the uncompressed size in one entry and the offset in another: every entry past
    /// 4 GiB whose own sizes are small has an offset and nothing else.
    #[test]
    fn a_zip64_field_is_read_by_which_header_fields_are_marked() {
        let one = field(ZIP64_ID, &le64(&[0x1_2345_6789]));
        assert_eq!(parse_extra_fields(&one, Zip64Wanted { offset: true, ..NOTHING }).zip64, Zip64Values { offset: Some(0x1_2345_6789), ..Zip64Values::default() });
        assert_eq!(parse_extra_fields(&one, Zip64Wanted { uncompressed: true, ..NOTHING }).zip64, Zip64Values { uncompressed: Some(0x1_2345_6789), ..Zip64Values::default() });
        assert_eq!(parse_extra_fields(&one, Zip64Wanted { compressed: true, ..NOTHING }).zip64, Zip64Values { compressed: Some(0x1_2345_6789), ..Zip64Values::default() });
        assert_eq!(parse_extra_fields(&one, NOTHING).zip64, Zip64Values::default(), "nothing is marked: nothing is read");

        let two = field(ZIP64_ID, &le64(&[7, 9]));
        assert_eq!(parse_extra_fields(&two, Zip64Wanted { compressed: true, offset: true, ..NOTHING }).zip64, Zip64Values { compressed: Some(7), offset: Some(9), ..Zip64Values::default() });
        assert_eq!(parse_extra_fields(&two, Zip64Wanted { uncompressed: true, offset: true, ..NOTHING }).zip64, Zip64Values { uncompressed: Some(7), offset: Some(9), ..Zip64Values::default() });

        let disk = field(ZIP64_ID, &3_u32.to_le_bytes());
        assert_eq!(parse_extra_fields(&disk, Zip64Wanted { disk: true, ..NOTHING }).zip64, Zip64Values { disk: Some(3), ..Zip64Values::default() });
    }

    /// A field too short for a marked value leaves that value and the ones behind it absent:
    /// the header keeps its mark, and nothing is read from the wrong place.
    #[test]
    fn a_zip64_field_that_is_too_short_gives_what_it_holds() {
        let one = field(ZIP64_ID, &le64(&[11]));
        assert_eq!(parse_extra_fields(&one, ALL).zip64, Zip64Values { uncompressed: Some(11), ..Zip64Values::default() });
        let short = field(ZIP64_ID, &[1, 2, 3, 4]);
        assert_eq!(parse_extra_fields(&short, Zip64Wanted { uncompressed: true, disk: true, ..NOTHING }).zip64, Zip64Values::default());
        assert_eq!(parse_extra_fields(&field(ZIP64_ID, &[]), ALL).zip64, Zip64Values::default());
    }

    #[test]
    fn the_first_field_of_a_kind_counts_and_other_kinds_are_passed_over() {
        let mut raw = field(0xBEEF, &[0xAA, 0xBB, 0xCC]);
        raw.extend_from_slice(&field(ZIP_WINZIP_ID, &[1, 0, 0x41, 0x45, 1, 0, 0]));
        raw.extend_from_slice(&field(0x5455, &[3, 0, 0, 0, 0]));
        raw.extend_from_slice(&field(ZIP_WINZIP_ID, &[2, 0, 0x41, 0x45, 3, 8, 0]));
        raw.extend_from_slice(&field(ZIP64_ID, &le64(&[1])));
        raw.extend_from_slice(&field(ZIP64_ID, &le64(&[2])));
        let extras = parse_extra_fields(&raw, Zip64Wanted { compressed: true, ..NOTHING });
        assert_eq!(extras.zip_winzip, Some(ZipWinzipExtra { ae_version: 1, strength: 1, actual_compression: 0 }));
        assert_eq!(extras.zip64.compressed, Some(1));
    }

    #[test]
    fn the_fields_a_writer_is_known_by_are_marked() {
        // the time stamps and the user IDs of Info-ZIP, then NTFS times as 7-Zip writes them
        let mut raw = field(0x5455, &[3, 0, 0, 0, 0]);
        raw.extend(field(0x7875, &[1, 4, 0, 0, 0, 0, 4, 0, 0, 0, 0]));
        let info_zip = parse_extra_fields(&raw, NOTHING).marks;
        assert_eq!(info_zip, ExtraMarks { times: true, unix_ids: true, len: 24, ..ExtraMarks::default() });
        let seven_zip = parse_extra_fields(&field(0x000a, &[0; 32]), NOTHING).marks;
        assert_eq!(seven_zip, ExtraMarks { ntfs: true, len: 36, ..ExtraMarks::default() });
        // a ZIP64 field is marked whether or not a value is wanted from it
        assert!(parse_extra_fields(&field(ZIP64_ID, &[0; 16]), NOTHING).marks.zip64);
        assert_eq!(parse_extra_fields(&[], NOTHING).marks, ExtraMarks::default());
    }

    #[test]
    fn a_field_that_is_cut_short_ends_the_walk() {
        let mut raw = field(ZIP_PKWARE_ID, &[2, 0, 0x10, 0x66, 0, 1, 1, 0]);
        // declares ten bytes and has three
        raw.extend_from_slice(&[0x01, 0x99, 10, 0, 0, 0, 0]);
        let extras = parse_extra_fields(&raw, NOTHING);
        assert!(extras.pkware.is_some() && extras.zip_winzip.is_none());

        assert_eq!(parse_extra_fields(&[], ALL), Extras::default());
        // what it says of a header that has no whole field is that its extra fields have a length
        assert_eq!(parse_extra_fields(&[0x01, 0x99, 7], ALL), Extras { marks: ExtraMarks { len: 3, ..ExtraMarks::default() }, ..Extras::default() });
    }
}
