//! A RAR archive as its headers describe it: what the three parsers fill, the signatures that
//! tell them apart, and the reader for the fields of a header.
//!
//! There are three generations of the format, each with a parser of its own: RAR 1.3 and 1.4
//! ([`super::rar1`]), RAR 1.5 to 4.x ([`super::rar4`]) and RAR 5 and 7 ([`super::rar5`]).
//! All three read the archive by range from a [`Source`]: the headers one at a time, and never
//! the data between them. What a parser holds in memory is one header and the entries it has
//! read so far.
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
use super::encryption::RarEncryption;
use crate::analysis::EntryKind;
use crate::analysis::Volume;
use crate::formats::SFX_SCAN_LIMIT;
use crate::formats::source::Source;

/// RAR 1.3 and 1.4: `RE~^`.
pub(crate) const RAR1_SIGNATURE: &[u8] = b"RE~^";
/// RAR 1.5 to 4.x: `Rar!\x1a\x07\x00`.
pub(crate) const RAR4_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x00";
/// RAR 5 and 7: `Rar!\x1a\x07\x01\x00`.
pub(crate) const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// The mark a RAR 1.4 self-extracting program carries at byte 28. A `RE~^` further in counts
/// as an archive only behind such a program: four bytes alone turn up anywhere.
const RAR1_SFX_MARK: &[u8] = b"RSFX";

/// How the headers of an archive are encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderEncryption {
    /// They are not.
    None,
    /// RAR 3 and 4: every block behind the main header is encrypted, each with eight bytes of
    /// salt in front of it.
    Rar30 {
        /// Where the salt of the first encrypted block is.
        salt_at: u64,
        /// Whether the main header says that the archive is a volume of a set.
        volume: bool,
    },
    /// RAR 5: an encryption header in front of everything else.
    Rar50 {
        /// What the encryption header says. Its vector is not in it: each block has its own.
        crypt: Box<Rar50Record>,
        /// Where the first encrypted block is: sixteen bytes of vector, then the header.
        block_at: u64,
    },
    /// RAR 5: an encryption header that ends before its fields do.
    Rar50Unreadable,
    /// RAR 5: an encryption header of a version this tool does not know.
    Unknown {
        /// The version the header names.
        version: u64,
    },
}

/// The generation of a RAR archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RarGeneration {
    /// RAR 1.3 and 1.4.
    Rar1,
    /// RAR 1.5 to 4.x.
    Rar4,
    /// RAR 5 and 7.
    Rar5,
}

/// A RAR archive as its headers describe it.
#[derive(Debug, Clone)]
pub(crate) struct RarArchive {
    /// The generation.
    pub generation: RarGeneration,
    /// The file and service headers, in the order of the archive. Empty when the headers are
    /// encrypted.
    pub entries: Vec<RarEntry>,
    /// How the headers are encrypted.
    pub headers: HeaderEncryption,
    /// The archive comment, when it is stored where it can be read.
    pub comment: Option<Vec<u8>>,
    /// Whether the archive is a volume of a set, and which. `None` when the header that says
    /// so is encrypted.
    pub volume: Option<Volume>,
    /// A header, or the data of an entry, reaches past the end of the file.
    pub truncated: bool,
    /// Where the headers stop before the file does, at bytes that are no header. `None` when
    /// the walk over the headers came to an end block, to the end of the file, or to headers
    /// that are encrypted.
    pub broken_at: Option<u64>,
    /// Where the first header starts that fails its checksum.
    pub bad_checksum_at: Option<u64>,
    /// The main header flags the archive as solid. Read for `rar1`, where no entry says so by
    /// itself.
    pub solid: bool,
}

impl RarArchive {
    /// An archive of which nothing has been read yet.
    pub(crate) const fn new(generation: RarGeneration) -> Self {
        Self { generation, entries: Vec::new(), headers: HeaderEncryption::None, comment: None, volume: Some(Volume::Single), truncated: false, broken_at: None, bad_checksum_at: None, solid: false }
    }
}

/// One file or service header of a RAR archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RarEntry {
    /// The name, as bytes: UTF-8 for RAR 3 and later, the code page of the writer before.
    pub name: Vec<u8>,
    /// A file, a directory or a service record.
    pub kind: EntryKind,
    /// Size of the data in this file.
    pub packed: u64,
    /// Size of what it unpacks to. `None` when the header says that the size is not known:
    /// the entry was packed from a stream.
    pub unpacked: Option<u64>,
    /// CRC-32 of the unpacked data. For RAR 1.4 its 16-bit checksum, for RAR 5 what the header
    /// stores when it stores one.
    pub crc32: u32,
    /// RAR 5: whether a CRC-32 is stored at all.
    pub has_crc32: bool,
    /// RAR 5: the BLAKE2sp digest of the unpacked data, when the archive stores that.
    pub blake2sp: Option<[u8; 32]>,
    /// How the entry is encrypted.
    pub encryption: RarEncryption,
    /// The compression method as the format stores it: 0 to 5 for RAR 1.4 and RAR 5, 0x30 to
    /// 0x35 for RAR 1.5 to 4.x.
    pub method: u8,
    /// Whether the data is stored and not packed.
    pub stored: bool,
    /// RAR 5: the version of the compression algorithm, 0 for RAR 5 and 1 for RAR 7.
    pub algorithm: u8,
    /// Where the header of the entry starts in the archive.
    pub header_offset: u64,
    /// Where the data starts, as an offset into the source.
    pub data_offset: u64,
    /// The entry continues from the volume before.
    pub split_before: bool,
    /// The entry continues in the volume after.
    pub split_after: bool,
    /// The entry is packed as a continuation of the entries before it.
    pub solid: bool,
}

impl RarEntry {
    /// An entry of which only its kind and its place are known.
    pub(crate) const fn new(kind: EntryKind, data_offset: u64) -> Self {
        Self { name: Vec::new(), kind, packed: 0, unpacked: Some(0), crc32: 0, has_crc32: true, blake2sp: None, encryption: RarEncryption::None, method: 0, stored: true, algorithm: 0, header_offset: 0, data_offset, split_before: false, split_after: false, solid: false }
    }

    /// The name as text.
    pub(crate) fn name_lossy(&self) -> String {
        String::from_utf8_lossy(&self.name).into_owned()
    }

    /// Whether the entry continues from or into another volume.
    pub(crate) const fn is_split(&self) -> bool {
        self.split_before || self.split_after
    }

    /// Whether the data of the entry lies inside an archive of `len` bytes.
    pub(crate) fn data_is_inside(&self, len: u64) -> bool {
        self.data_offset.checked_add(self.packed).is_some_and(|end| end <= len)
    }
}

/// The longest archive comment that is read: what UnRAR reads at most (`MAXCMTSIZE`).
const MAX_COMMENT: u64 = 0x4_0000;

/// The archive comment a service record holds, when it can be read as it stands: the record is
/// named `CMT`, is not encrypted, not packed and not split, and its data is what its checksum
/// says. RAR 5 stores its comments that way. RAR 3 and 4 pack theirs, and nothing here unpacks.
pub(crate) fn stored_comment(source: &Source, entry: &RarEntry) -> Option<Vec<u8>> {
    let readable = entry.kind == EntryKind::Service && entry.name == b"CMT" && entry.encryption == RarEncryption::None && entry.stored && !entry.is_split();
    if !readable || entry.packed == 0 || entry.packed > MAX_COMMENT || entry.unpacked != Some(entry.packed) {
        return None;
    }
    let text = source.read_at(entry.data_offset, entry.packed).ok()?;
    (!entry.has_crc32 || crc32fast::hash(&text) == entry.crc32).then_some(text)
}

/// A header that is held in memory, read field by field.
///
/// A field that does not lie inside the header is `None`, and the position stays where it is.
/// Nothing here can read out of bounds or overflow, whatever a header says about itself.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Fields<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Fields<'a> {
    /// The fields of `data`, from its start.
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// The position, counted from the start of the header.
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// How many bytes are left.
    pub(crate) const fn left(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Move to `position`. `false`, and no move, when it lies behind the header.
    pub(crate) const fn seek(&mut self, position: usize) -> bool {
        if position > self.data.len() {
            return false;
        }
        self.pos = position;
        true
    }

    /// The next `len` bytes.
    pub(crate) fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    /// The next `len` bytes, or as many as are left.
    pub(crate) fn bytes_up_to(&mut self, len: usize) -> &'a [u8] {
        self.bytes(len.min(self.left())).unwrap_or_default()
    }

    /// The next `N` bytes.
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let mut probe = *self;
        let out = probe.bytes(N)?.try_into().ok()?;
        *self = probe;
        Some(out)
    }

    /// The next byte.
    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// The next four bytes as a little-endian number.
    pub(crate) fn u32_le(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// The next variable-length number of RAR 5: seven bits in a byte, the low ones first, and
    /// the high bit set on every byte but the last.
    ///
    /// A number takes ten bytes at most. Bits above the 64th are dropped, as `RawRead::GetV`
    /// of UnRAR drops them. `None` for a number that does not end inside the header or inside
    /// ten bytes.
    pub(crate) fn vint(&mut self) -> Option<u64> {
        let mut probe = *self;
        let mut value = 0_u64;
        for shift in (0..64).step_by(7) {
            let byte = probe.u8()?;
            value |= u64::from(byte & 0x7F) << shift;
            if byte & 0x80 == 0 {
                *self = probe;
                return Some(value);
            }
        }
        None
    }
}

/// The generation the signature at the start of `bytes` names.
pub(crate) fn generation_of(bytes: &[u8]) -> Option<RarGeneration> {
    // the longer signature first: the one of RAR 5 starts like the one of RAR 1.5
    if bytes.starts_with(RAR5_SIGNATURE) {
        Some(RarGeneration::Rar5)
    } else if bytes.starts_with(RAR4_SIGNATURE) {
        Some(RarGeneration::Rar4)
    } else if bytes.starts_with(RAR1_SIGNATURE) {
        Some(RarGeneration::Rar1)
    } else {
        None
    }
}

/// Parse the archive that starts `start` bytes into `source`, by the signature that is there.
///
/// `strict` is for a signature that was found inside a program: what follows it then has to
/// be the first header of an archive, and not only bytes that can be read as a header.
fn parse_at(source: &Source, start: u64, strict: bool) -> anyhow::Result<RarArchive> {
    let signature = source.read_up_to(start, 8).context("cannot read the signature")?;
    match generation_of(&signature) {
        Some(RarGeneration::Rar1) => super::rar1::parse(source, start),
        Some(RarGeneration::Rar4) => super::rar4::parse(source, start, strict),
        Some(RarGeneration::Rar5) => super::rar5::parse(source, start, strict),
        None => anyhow::bail!("not a RAR archive"),
    }
}

/// The longest first header of a RAR 5 archive that counts when the archive is looked for
/// inside a program. A main header is a few dozen bytes, and the scanner draws the same line.
const RAR5_FIRST_HEADER_MAX: u64 = 4096;

/// Whether the bytes behind a signature that was found inside a program start like the first
/// header of an archive: for RAR 1.5 to 4.x a main header, for RAR 5 a main header or an
/// encryption header with the right CRC-32.
///
/// This is what the parsers ask of such a signature, asked of bytes that are in memory: a
/// program can hold the bytes of a signature a million times, and each is looked at in a few
/// instructions.
fn first_header_follows(generation: RarGeneration, behind: &[u8]) -> bool {
    match generation {
        RarGeneration::Rar1 => matches!(behind, [low, high, ..] if u16::from_le_bytes([*low, *high]) >= 7),
        RarGeneration::Rar4 => matches!(behind, [_, _, 0x73, _, _, low, high, ..] if u16::from_le_bytes([*low, *high]) >= 13),
        RarGeneration::Rar5 => {
            let Some(([c0, c1, c2, c3], sized)) = behind.split_first_chunk::<4>() else { return false };
            let mut size_field = Fields::new(sized.get(..3).unwrap_or(sized));
            let Some(size) = size_field.vint().filter(|&size| size <= RAR5_FIRST_HEADER_MAX) else { return false };
            let covered = usize::try_from(size).ok().and_then(|size| sized.get(..size_field.position().checked_add(size)?));
            let header_type = sized.get(size_field.position());
            matches!(header_type, Some(1 | 4)) && covered.is_some_and(|covered| crc32fast::hash(covered) == u32::from_le_bytes([*c0, *c1, *c2, *c3]))
        },
    }
}

/// Parse the RAR archive in `source`, and say where in the source it starts.
///
/// A source that starts with a signature is that archive, and what follows the signature is
/// taken at its word: whoever opened the source there has found the archive. A source that
/// starts with a program is searched as far as an archive can start behind one, and every
/// signature in it is tried until what follows one parses. A signature in the text or the code
/// of the program is passed over that way.
pub(crate) fn parse(source: &Source) -> anyhow::Result<(u64, RarArchive)> {
    let head = source.read_up_to(0, 32).context("cannot read the start of the file")?;
    if generation_of(&head).is_some() {
        return Ok((0, parse_at(source, 0, false)?));
    }
    anyhow::ensure!(head.starts_with(b"MZ") || head.starts_with(b"\x7fELF"), "not a RAR archive");

    // How far into the file the search goes: the same distance the scanner searches. What is
    // read reaches further by a first header, so that the last signature has its header too.
    let limit = u64::try_from(SFX_SCAN_LIMIT).unwrap_or(u64::MAX).saturating_sub(source.offset());
    let window = source.read_up_to(0, limit.saturating_add(RAR5_FIRST_HEADER_MAX).saturating_add(16)).context("cannot read the program")?;
    let marked = head.get(28..32).is_some_and(|mark| mark == RAR1_SFX_MARK);

    let mut first_error = None;
    for (offset, _) in window.iter().enumerate().skip(1).filter(|&(_, &byte)| byte == b'R') {
        let Some((generation, behind)) = window.get(offset..).and_then(|from| Some((generation_of(from)?, from))) else { continue };
        let signature = match generation {
            RarGeneration::Rar1 => RAR1_SIGNATURE,
            RarGeneration::Rar4 => RAR4_SIGNATURE,
            RarGeneration::Rar5 => RAR5_SIGNATURE,
        };
        if (generation == RarGeneration::Rar1 && !marked) || !behind.get(signature.len()..).is_some_and(|behind| first_header_follows(generation, behind)) {
            continue;
        }
        let Ok(start) = u64::try_from(offset) else { break };
        if start >= limit {
            break;
        }
        match parse_at(source, start, true) {
            Ok(archive) => return Ok((start, archive)),
            Err(error) => {
                tracing::debug!("{}: the signature at offset {start} is not followed by an archive: {error:#}", source.path().display());
                let _ = first_error.get_or_insert(error);
            },
        }
    }
    Err(first_error.unwrap_or_else(|| anyhow::anyhow!("not a RAR archive")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_names_its_generation() {
        assert_eq!(generation_of(b"Rar!\x1a\x07\x00rest"), Some(RarGeneration::Rar4));
        assert_eq!(generation_of(b"Rar!\x1a\x07\x01\x00rest"), Some(RarGeneration::Rar5));
        assert_eq!(generation_of(b"RE~^data"), Some(RarGeneration::Rar1));
        assert_eq!(generation_of(b"Rar!\x1a\x07\x02\x00"), None, "a generation that does not exist yet");
        assert_eq!(generation_of(b"notrar"), None);
        assert_eq!(generation_of(b"Rar!"), None);
        assert_eq!(generation_of(b""), None);
    }

    #[test]
    fn fields_are_read_in_order_and_never_past_the_end() {
        let mut fields = Fields::new(&[0xAB, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, b'n', b'a', b'm', b'e']);
        assert_eq!(fields.u8(), Some(0xAB));
        assert_eq!(fields.array::<2>(), Some([0x34, 0x12]));
        assert_eq!(fields.u32_le(), Some(0xDEAD_BEEF));
        assert_eq!((fields.position(), fields.left()), (7, 4));
        assert_eq!(fields.bytes(2), Some(&b"na"[..]));

        // a field that is cut off is not read by halves, and the position stays
        assert_eq!(fields.u32_le(), None);
        assert_eq!(fields.bytes(3), None);
        assert_eq!(fields.bytes(usize::MAX), None, "a length that overflows the position");
        assert_eq!(fields.position(), 9);
        assert_eq!(fields.bytes_up_to(100), b"me");
        assert_eq!((fields.u8(), fields.left()), (None, 0));
        assert!(fields.bytes(0).is_some_and(<[u8]>::is_empty));

        assert!(fields.seek(11) && !fields.seek(12));
        assert!(fields.seek(1));
        assert_eq!(fields.array::<2>(), Some([0x34, 0x12]));
    }

    #[test]
    fn a_variable_length_number_is_seven_bits_a_byte() {
        let vint = |bytes: &[u8]| Fields::new(bytes).vint();
        assert_eq!(vint(&[42]), Some(42));
        assert_eq!(vint(&[0x7F]), Some(127));
        assert_eq!(vint(&[0x80, 0x01]), Some(128));
        assert_eq!(vint(&[0xFF, 0xFF, 0x01]), Some(0x7FFF));
        assert_eq!(vint(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]), Some(u64::MAX));
        // the bits of the tenth byte that do not fit are dropped
        assert_eq!(vint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7E]), Some(0));

        // a number that does not end: in the header, or in ten bytes
        assert_eq!(vint(&[]), None);
        assert_eq!(vint(&[0x80]), None);
        assert_eq!(vint(&[0x80; 10]), None);
        assert_eq!(vint(&[0xFF; 32]), None);

        // one that fails leaves the position where it was
        let mut fields = Fields::new(&[7, 0x80, 0x80]);
        assert_eq!(fields.vint(), Some(7));
        assert_eq!((fields.vint(), fields.position()), (None, 1));
    }

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/{rel}")).unwrap()
    }

    /// A program of `len` bytes: the mark of its kind, then zeros.
    fn program(mark: &[u8], len: usize) -> Vec<u8> {
        let mut data = mark.to_vec();
        data.resize(len, 0);
        data
    }

    #[test]
    fn a_source_that_starts_with_a_signature_is_that_archive() {
        for (rel, generation) in [("unencrypted/rars_rar3_stored.rar", RarGeneration::Rar4), ("unencrypted/rars_rar5_stored.rar", RarGeneration::Rar5), ("unencrypted/rar14-solid.rar", RarGeneration::Rar1)] {
            let (start, archive) = parse(&Source::from_bytes(fixture(rel))).unwrap();
            assert_eq!((start, archive.generation), (0, generation), "{rel}");
            assert!(!archive.entries.is_empty(), "{rel}");
        }
        assert!(parse(&Source::from_bytes(b"not a rar file".to_vec())).is_err());
        assert!(parse(&Source::from_bytes(Vec::new())).is_err());
        assert!(parse(&Source::from_bytes(b"Rar!".to_vec())).is_err());
    }

    /// The signatures a program can hold before its archive starts: in its text, with nothing
    /// behind them, or with a header that is none. Each is tried and passed over.
    #[test]
    fn every_signature_in_a_program_is_tried_until_one_is_followed_by_an_archive() {
        let archive = fixture("rar-50/v730_p_m3.rar");
        let expected = parse(&Source::from_bytes(archive.clone())).unwrap().1.entries;

        let mut data = program(b"MZ", 64);
        // the word in the text of the program, a bare RAR 5 signature, and one of RAR 1.5 with
        // a block that is no main header behind it
        data.extend_from_slice(b"This program unpacks Rar! archives. ");
        data.extend_from_slice(RAR5_SIGNATURE);
        data.extend_from_slice(b" marks one. ");
        data.extend_from_slice(RAR4_SIGNATURE);
        data.extend_from_slice(&[0, 0, 0x74, 0, 0, 3, 0, 0, 0]);
        data.extend_from_slice(RAR1_SIGNATURE);
        data.resize(512, 0);
        data.extend_from_slice(&archive);

        let (start, parsed) = parse(&Source::from_bytes(data)).unwrap();
        assert_eq!((start, parsed.generation), (512, RarGeneration::Rar5));
        assert_eq!(parsed.entries.len(), expected.len());
        // the offsets of the data are those of the source, not of the archive
        assert_eq!(parsed.entries[0].data_offset, expected[0].data_offset + 512);
        assert_eq!(parsed.entries[0].name, expected[0].name);
    }

    #[test]
    fn a_program_without_an_archive_is_an_error() {
        let mut data = program(b"\x7fELF", 300);
        data.extend_from_slice(RAR5_SIGNATURE);
        data.extend_from_slice(b"and nothing that is a header");
        let error = parse(&Source::from_bytes(data)).unwrap_err();
        assert!(!error.to_string().is_empty());
        assert_eq!(parse(&Source::from_bytes(program(b"MZ", 4096))).unwrap_err().to_string(), "not a RAR archive");

        // an archive in a file that is no program is not looked for
        let mut data = vec![0_u8; 100];
        data.extend_from_slice(&fixture("rar-50/v730_p_m3.rar"));
        assert_eq!(parse(&Source::from_bytes(data)).unwrap_err().to_string(), "not a RAR archive");
    }

    #[test]
    fn a_rar_1_4_archive_counts_only_behind_a_program_that_is_marked() {
        let archive = fixture("rar-13/rar14-password-stored.rar");
        let mut data = program(b"MZ", 64);
        data.extend_from_slice(&archive);
        assert!(parse(&Source::from_bytes(data.clone())).is_err(), "no RSFX mark");

        data[28..32].copy_from_slice(b"RSFX");
        let (start, parsed) = parse(&Source::from_bytes(data)).unwrap();
        assert_eq!((start, parsed.generation, parsed.entries.len()), (64, RarGeneration::Rar1, 1));
    }

    #[test]
    fn the_search_ends_where_an_archive_can_no_longer_start() {
        let archive = fixture("rar-50/v730_p_m3.rar");
        let mut data = program(b"MZ", SFX_SCAN_LIMIT - 1);
        data.extend_from_slice(&archive);
        assert_eq!(parse(&Source::from_bytes(data)).unwrap().0, u64::try_from(SFX_SCAN_LIMIT - 1).unwrap());

        let mut data = program(b"MZ", SFX_SCAN_LIMIT);
        data.extend_from_slice(&archive);
        assert!(parse(&Source::from_bytes(data)).is_err());
    }

    /// A program can hold the bytes of a signature in every place an archive could start. Each
    /// is looked at where it lies in memory, and none of them is read as an archive.
    #[test]
    fn a_program_of_signatures_alone_is_searched_in_good_time() {
        let mut data = program(b"MZ", 64);
        while data.len() < SFX_SCAN_LIMIT + 64 {
            for signature in [RAR5_SIGNATURE, RAR4_SIGNATURE, RAR1_SIGNATURE] {
                data.extend_from_slice(signature);
                data.extend_from_slice(&[0x01, 0x80, 0x80, 0x00, 0x05]);
            }
        }
        let started = std::time::Instant::now();
        assert_eq!(parse(&Source::from_bytes(data)).unwrap_err().to_string(), "not a RAR archive");
        assert!(started.elapsed() < std::time::Duration::from_secs(20), "{:?}", started.elapsed());
    }

    #[test]
    fn what_follows_a_signature_inside_a_program_is_looked_at_before_it_is_parsed() {
        // a main header of RAR 1.5 to 4.x: its type, and a size of thirteen bytes or more
        assert!(first_header_follows(RarGeneration::Rar4, &[0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!first_header_follows(RarGeneration::Rar4, &[0, 0, 0x73, 0, 0, 12, 0]));
        assert!(!first_header_follows(RarGeneration::Rar4, &[0, 0, 0x74, 0, 0, 40, 0]));
        assert!(!first_header_follows(RarGeneration::Rar4, &[0, 0, 0x73]));

        // a main header or an encryption header of RAR 5, with the CRC-32 of its bytes
        let header = |body: &[u8]| {
            let sized = [&[u8::try_from(body.len()).unwrap()][..], body].concat();
            [&crc32fast::hash(&sized).to_le_bytes()[..], &sized].concat()
        };
        assert!(first_header_follows(RarGeneration::Rar5, &header(&[1, 0, 0])));
        assert!(first_header_follows(RarGeneration::Rar5, &header(&[4, 0, 0, 0, 15])));
        assert!(!first_header_follows(RarGeneration::Rar5, &header(&[2, 0, 0])), "a file header starts no archive");
        let mut damaged = header(&[1, 0, 0]);
        damaged[0] ^= 1;
        assert!(!first_header_follows(RarGeneration::Rar5, &damaged));
        assert!(!first_header_follows(RarGeneration::Rar5, &header(&[1, 0, 0])[..6]), "cut off");
        assert!(!first_header_follows(RarGeneration::Rar5, &[0, 0, 0, 0, 0x80, 0x80, 0x80, 0x01]), "a size field that does not end");
        assert!(!first_header_follows(RarGeneration::Rar5, &[]));

        // a main header of RAR 1.4 is seven bytes or more
        assert!(first_header_follows(RarGeneration::Rar1, &[7, 0, 0]));
        assert!(!first_header_follows(RarGeneration::Rar1, &[6, 0, 0]));
    }
}
