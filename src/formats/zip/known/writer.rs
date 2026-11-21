//! The program that wrote an archive, worked out from the marks it leaves in the central
//! directory.
//!
//! The marks name a family, not a version, and they are a reading of the defaults of each
//! writer: a claim that rests on them is no surer than `derived`.

use std::fmt;

use serde::Serialize;
use serde::Serializer;

use crate::formats::zip::encryption::FLAG_DATA_DESCRIPTOR;
use crate::formats::zip::encryption::ZipEncryption;
use crate::formats::zip::parser::ZipEntry;

/// A family of programs that write `zip-crypto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Writer {
    /// Info-ZIP `zip`, the `zip` command of Linux and macOS.
    InfoZip,
    /// 7-Zip and what calls its library.
    SevenZip,
    /// SharpZipLib, the library of .NET.
    SharpZipLib,
    /// DotNetZip (`Ionic.Zip`), the other library of .NET.
    DotNetZip,
    /// `github.com/yeka/zip`, the library of Go.
    Yeka,
    /// WinRAR from 4.20 on, writing what it calls ZIP legacy encryption with the code of
    /// Info-ZIP.
    WinRar,
    /// A writer the marks do not name.
    Unknown,
}

impl Writer {
    /// Every family, in the order of the design.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 7] = [Self::InfoZip, Self::SevenZip, Self::SharpZipLib, Self::DotNetZip, Self::Yeka, Self::WinRar, Self::Unknown];

    /// The name of the family in the JSON object and in a plan.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InfoZip => "info-zip",
            Self::SevenZip => "7-zip",
            Self::SharpZipLib => "sharp-zip-lib",
            Self::DotNetZip => "dot-net-zip",
            Self::Yeka => "yeka",
            Self::WinRar => "winrar",
            Self::Unknown => "unknown",
        }
    }

    /// The family in the words of a report.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::InfoZip => "Info-ZIP",
            Self::SevenZip => "7-Zip",
            Self::SharpZipLib => "SharpZipLib",
            Self::DotNetZip => "DotNetZip",
            Self::Yeka => "yeka/zip",
            Self::WinRar => "WinRAR",
            Self::Unknown => "a writer the directory does not name",
        }
    }

    /// How many check bytes the family ends its encryption header with: one, two, or not
    /// known.
    #[must_use]
    pub(crate) const fn check_bytes(self) -> Option<u8> {
        match self {
            Self::InfoZip | Self::Yeka | Self::WinRar => Some(2),
            Self::SevenZip | Self::SharpZipLib | Self::DotNetZip => Some(1),
            Self::Unknown => None,
        }
    }

    /// The fewest encrypted entries of one run from which a header path of the attack finds
    /// the keys of the family with no known byte of any file. `None` for a family that has
    /// no such path.
    #[must_use]
    pub(crate) const fn header_path_entries(self) -> Option<usize> {
        match self {
            Self::InfoZip | Self::WinRar => Some(4),
            Self::SharpZipLib | Self::DotNetZip => Some(5),
            Self::SevenZip | Self::Yeka | Self::Unknown => None,
        }
    }

    /// The family whose marks one entry of the central directory carries.
    #[must_use]
    fn of_entry(entry: &ZipEntry) -> Self {
        let [version, system] = entry.made_by.to_le_bytes();
        let descriptor = entry.flags & FLAG_DATA_DESCRIPTOR != 0;
        match (version, system) {
            // Info-ZIP zip 3.0 names its own version on every system it runs on, and writes an
            // encrypted entry with a data descriptor whatever it writes to
            (30, _) if descriptor => Self::InfoZip,
            // 7-Zip names 6.3 whatever its version is
            (63, _) => Self::SevenZip,
            (51, 0) if entry.needed == 45 && entry.extra.zip64 => Self::SharpZipLib,
            (45, 0) if entry.needed == 20 && entry.extra.ntfs && !descriptor => Self::DotNetZip,
            (20, 0) if entry.needed == 20 && descriptor && entry.extra.len == 0 => Self::Yeka,
            // WinRAR names 3.1 from its version 4.20 on, and writes an encrypted entry with a
            // data descriptor as the code of Info-ZIP it carries does. Before 4.20 it leaves
            // the marks of the line above, which the headers take back
            (31, 0) if entry.needed == 20 && descriptor => Self::WinRar,
            _ => Self::Unknown,
        }
    }

    /// The family, when the encryption headers of the entries are held against it too. The
    /// marks that `yeka/zip` leaves in the directory are also those of the `ZipArchive`
    /// library of Artpol on Windows, and the headers tell the two apart for certain: every
    /// header of `yeka/zip` starts with the first byte of its constant.
    #[must_use]
    pub(crate) fn held_against(self, headers: &[[u8; 12]]) -> Self {
        if self == Self::Yeka && headers.iter().any(|header| header.first() != Some(&CONSTANT_FIRST)) { Self::Unknown } else { self }
    }

    /// The family that wrote the encrypted entries of an archive: the one every such entry
    /// carries the marks of. Entries of two families, as in an archive that was added to by
    /// another program, name none.
    #[must_use]
    pub(crate) fn of(entries: &[ZipEntry]) -> Self {
        let mut families = entries.iter().filter(|entry| entry.encryption == ZipEncryption::ZipCrypto && !entry.directory).map(Self::of_entry);
        let Some(first) = families.next() else { return Self::Unknown };
        if families.all(|family| family == first) { first } else { Self::Unknown }
    }
}

/// What the encryption headers of the entries of an archive say of their writer, when they
/// are held against each other (sections 8.5 and 8.6 of the design).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderMark {
    /// Every header starts with the same ten bytes, the first of them `F8`: `yeka/zip`, which
    /// encrypts a constant twice. Certain from two entries on.
    Constant,
    /// Some headers are equal in their first eleven bytes: a generator that was seeded with a
    /// clock, as SharpZipLib and DotNetZip have it on the .NET Framework. The entries that
    /// share their header with another, by their place in the list that was given.
    Repeated(Vec<usize>),
}

/// The first byte of the constant that `yeka/zip` encrypts twice: both passes start from the
/// same keys, so the first byte of every header is the constant's, as it is.
const CONSTANT_FIRST: u8 = 0xf8;

/// What the encryption headers of an archive say when they are compared: `headers` holds the
/// twelve bytes in front of the data of each encrypted entry.
#[must_use]
pub(crate) fn header_mark(headers: &[[u8; 12]]) -> Option<HeaderMark> {
    let (first, rest) = headers.split_first()?;
    if !rest.is_empty() && first.first() == Some(&CONSTANT_FIRST) && rest.iter().all(|header| header.first_chunk::<10>() == first.first_chunk::<10>()) {
        return Some(HeaderMark::Constant);
    }
    let mut seen: std::collections::HashMap<[u8; 11], usize> = std::collections::HashMap::new();
    for header in headers {
        if let Some(start) = header.first_chunk::<11>() {
            *seen.entry(*start).or_insert(0) += 1;
        }
    }
    let repeated: Vec<usize> = headers.iter().enumerate().filter(|(_, header)| header.first_chunk::<11>().and_then(|start| seen.get(start)).is_some_and(|count| *count > 1)).map(|(index, _)| index).collect();
    (!repeated.is_empty()).then_some(HeaderMark::Repeated(repeated))
}

impl Serialize for Writer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl fmt::Display for Writer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::source::Source;
    use crate::formats::zip::parser::parse;

    fn writer_of(fixture: &str) -> Writer {
        let source = Source::open(std::path::Path::new(fixture), 0).unwrap();
        Writer::of(&parse(&source).unwrap().entries)
    }

    #[test]
    fn the_marks_of_the_directory_name_the_family() {
        for (fixture, writer) in [
            ("tests/fixtures/zip-crypto/gen_infozip_deflate.zip", Writer::InfoZip),
            ("tests/fixtures/zip-crypto/gen_infozip_store_multi.zip", Writer::InfoZip),
            ("tests/fixtures/zip-crypto/gen_infozip_stream.zip", Writer::InfoZip),
            ("tests/fixtures/zip-crypto/gen_7z_zipcrypto_deflate.zip", Writer::SevenZip),
            ("tests/fixtures/zip-crypto/gen_7z_zipcrypto_copy.zip", Writer::SevenZip),
            ("tests/fixtures/zip-crypto/jpg.zip", Writer::InfoZip),
            ("tests/fixtures/zip-crypto/bkcrack-src_secrets.zip", Writer::SevenZip),
            // a generator that names the version of Info-ZIP and writes no data descriptor is not Info-ZIP
            ("tests/fixtures/zip-crypto/gen_own_zc_two_passwords.zip", Writer::Unknown),
            // the ZipArchive library on Windows leaves the marks of yeka/zip: its headers take them back
            ("tests/fixtures/zip-crypto/gen_ziparchive_win.zip", Writer::Yeka),
            ("tests/fixtures/zip-crypto/gen_ziparchive_glibc.zip", Writer::Unknown),
            ("tests/fixtures/zip-crypto/gen_ziputils_win.zip", Writer::Unknown),
            ("tests/fixtures/zip-crypto/gen_ziputils_session.zip", Writer::Unknown),
            // WinRAR 7.23 names itself. 2.90 names version 2.0 and no family: its packed entries
            // carry the marks of yeka/zip and its stored ones do not
            ("tests/fixtures/zip-crypto/gen_winrar_723.zip", Writer::WinRar),
            ("tests/fixtures/zip-crypto/gen_winrar_290.zip", Writer::Unknown),
            // the zip.exe that Info-ZIP gave out and that of Cygwin are zip
            ("tests/fixtures/zip-crypto/gen_infozip_official.zip", Writer::InfoZip),
            ("tests/fixtures/zip-crypto/gen_infozip_cygwin.zip", Writer::InfoZip),
            // nothing in it is of zip-crypto
            ("tests/fixtures/zip-winzip/aes256.zip", Writer::Unknown),
        ] {
            assert_eq!(writer_of(fixture), writer, "{fixture}");
        }
    }

    #[test]
    fn equal_headers_are_a_mark_of_their_writer() {
        let header = |start: [u8; 10], end: [u8; 2]| [&start[..], &end[..]].concat().try_into().unwrap();
        let constant = [0xf8, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8];
        // the constant of yeka/zip under one password, with the time of each entry behind it
        assert_eq!(header_mark(&[header(constant, [0x0c, 0xe0]), header(constant, [0x2d, 0x60])]), Some(HeaderMark::Constant));
        // one entry says nothing, and ten equal bytes that do not start with the constant's are no mark
        assert_eq!(header_mark(&[header(constant, [0x0c, 0xe0])]), None);
        let other = [0x11, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8];
        assert_eq!(header_mark(&[header(other, [1, 2]), header(other, [3, 4])]), None);
        // eleven equal bytes: entries whose generator was seeded within one tick of the clock
        let third = [0x55; 10];
        assert_eq!(header_mark(&[header(other, [1, 2]), header(third, [9, 9]), header(other, [1, 4])]), Some(HeaderMark::Repeated(vec![0, 2])));
        assert_eq!(header_mark(&[]), None);
    }

    #[test]
    fn the_marks_of_yeka_are_not_yeka_when_a_header_starts_with_another_byte() {
        let header = |first: u8| -> [u8; 12] { [first, 0x51, 0x60, 0x71, 0x8e, 0xbf, 0x18, 0x18, 0xa9, 0xd8, 0x0c, 0xe0] };
        assert_eq!(Writer::Yeka.held_against(&[header(0xf8), header(0xf8)]), Writer::Yeka);
        assert_eq!(Writer::Yeka.held_against(&[]), Writer::Yeka);
        // the ZipArchive library on Windows: the marks of yeka/zip in the directory, and headers of a generator
        assert_eq!(Writer::Yeka.held_against(&[header(0xf8), header(0x23)]), Writer::Unknown);
        assert_eq!(Writer::Yeka.held_against(&[header(0x23)]), Writer::Unknown);
        // the headers say nothing against another family
        assert_eq!(Writer::InfoZip.held_against(&[header(0x23)]), Writer::InfoZip);
    }

    #[test]
    fn a_family_is_named_one_way_everywhere() {
        let names: Vec<&str> = Writer::ALL.iter().map(|writer| writer.as_str()).collect();
        assert_eq!(names, ["info-zip", "7-zip", "sharp-zip-lib", "dot-net-zip", "yeka", "winrar", "unknown"]);
        for writer in Writer::ALL {
            assert_eq!(serde_json::to_value(writer).unwrap(), serde_json::json!(writer.as_str()));
            assert!(!writer.label().is_empty());
        }
        assert_eq!((Writer::InfoZip.check_bytes(), Writer::SevenZip.check_bytes(), Writer::Unknown.check_bytes()), (Some(2), Some(1), None));
        assert_eq!(Writer::ALL.map(Writer::header_path_entries), [Some(4), None, Some(5), Some(5), None, Some(4), None]);
    }
}
