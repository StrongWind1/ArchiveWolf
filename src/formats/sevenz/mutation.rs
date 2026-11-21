//! Archives no writer made: real fixtures with a few bytes changed, held to one property.
//!
//! Whatever is done to an archive, reading it ends, and soon: in an error, or in an analysis
//! whose lines and missing lines name entries it has. Nothing panics on the way.
//!
//! A change is made to the header of an archive, which is where the reader does its work, and
//! the checksums over the header and over the signature header are made right again
//! afterwards, so that the reader does not stop at the first of them. A header that the file
//! stores packed is changed in both forms: as it is stored, and unpacked, where every byte is a
//! field of the format.
//!
//! The run is seeded: it makes the same changes every time.

use std::time::Duration;
use std::time::Instant;

use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::Config;
use proptest::test_runner::RngAlgorithm;
use proptest::test_runner::TestRng;
use proptest::test_runner::TestRunner;

use super::analyse::analyse;
use super::craft;
use super::reader;
use crate::analysis::Analysed;
use crate::analysis::Headers;
use crate::formats::source::Source;
use crate::line::Lines;
use crate::line::Tag;

/// The fixtures that are changed: every shape of a folder and of a header the fixtures have.
const FIXTURES: [&str; 17] = [
    "7z-aes/7z_stored.7z",
    "7z-aes/7z_lzma2.7z",
    "7z-aes/7z_nonsolid_enc.7z",
    "7z-aes/7z_empty_pw.7z",
    "7z-aes/solid.7z",
    "7z-aes/bcj_lzma2.7z",
    "7z-aes/bcj2_enc.7z",
    "7z-aes/salted.7z",
    "7z-aes/rawkey.7z",
    "7z-aes/headers.7z",
    "7z-aes/gen_py7zr_lzma2_hdr.7z",
    "7z-aes/encrypted.7z",
    "7z-aes/arca_mixed.7z",
    "7z-aes/gen_7z_mixed_plain_first.7z",
    "7z-aes/ttzip-core_test_read_format_7zip_encryption_partially.7z",
    "unencrypted/plain.7z",
    "unencrypted/two_empty_file.7z",
];

/// Numbers that sit at the edges of what a field holds, of what the format's numbers take in
/// one byte more, and of the limits of the reader.
const EDGES: [u64; 24] = [0, 1, 2, 4, 15, 16, 17, 63, 64, 65, 0x7F, 0x80, 0xFF, 0x3FFF, 0x4000, 0xFFFF, (1 << 18) + 1, (1 << 26) + 1, 0x7FFF_FFFF, 0xFFFF_FFFF, 1 << 32, 1 << 62, 1 << 63, u64::MAX];

/// How many changed archives the seeded run reads.
const CASES: u32 = 10_000;

/// No archive here has more than a few kilobytes of header: reading one takes microseconds.
const TIME: Duration = Duration::from_secs(5);

/// An archive taken apart: its packed streams and its header.
#[derive(Debug, Clone)]
struct Base {
    packed: Vec<u8>,
    header: Vec<u8>,
}

/// The fixtures taken apart. One whose header is stored packed and can be unpacked is there
/// twice: with the header as stored, and with the header unpacked.
fn bases() -> Vec<Base> {
    let mut bases = Vec::new();
    for rel in FIXTURES {
        let bytes = std::fs::read(format!("tests/fixtures/{rel}")).unwrap();
        let field = |at: usize| usize::try_from(u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())).unwrap();
        let (offset, size) = (32 + field(12), field(20));
        let (packed, header) = (bytes[32..offset].to_vec(), bytes[offset..offset + size].to_vec());

        let read = reader::read(&Source::from_bytes(bytes.clone())).unwrap();
        if read.headers == reader::Headers::Readable && read.header_bytes() != header.as_slice() && !read.header_bytes().is_empty() {
            bases.push(Base { packed: packed.clone(), header: read.header_bytes().to_vec() });
        }
        bases.push(Base { packed, header });
    }
    bases
}

/// One change to an archive. A place is a fraction of what it falls into.
#[derive(Debug, Clone)]
enum Change {
    /// Flip one bit of the header.
    Flip(Index, u8),
    /// Set one byte of the header: to an identifier of a field, or to the flags of a coder.
    Byte(Index, u8),
    /// Write a number over the header, in the form the format stores numbers in.
    Number(Index, u64),
    /// Copy a run of bytes of the header to another place in it.
    Splice(Index, Index, usize),
    /// Take bytes out of the header.
    Remove(Index, usize),
    /// Cut the header short.
    Shorten(Index),
    /// Set where the signature header says the header lies (`false`), or how long it is.
    Field(bool, u64),
    /// Cut the file short, and put nothing right afterwards.
    Truncate(Index),
}

fn change() -> impl Strategy<Value = Change> {
    let at = any::<Index>;
    let edge = || proptest::sample::select(&EDGES[..]);
    prop_oneof![
        3 => (at(), 0..8_u8).prop_map(|(at, bit)| Change::Flip(at, bit)),
        3 => (at(), 0..0x40_u8).prop_map(|(at, value)| Change::Byte(at, value)),
        3 => (at(), edge()).prop_map(|(at, value)| Change::Number(at, value)),
        1 => (at(), at(), 1..64_usize).prop_map(|(from, to, len)| Change::Splice(from, to, len)),
        1 => (at(), 1..16_usize).prop_map(|(at, len)| Change::Remove(at, len)),
        1 => at().prop_map(Change::Shorten),
        1 => (any::<bool>(), edge()).prop_map(|(size, value)| Change::Field(size, value)),
        1 => at().prop_map(Change::Truncate),
    ]
}

/// Make the changes to an archive and put it together again. The checksums are right
/// afterwards, but for an archive that is cut short at the end.
fn changed(base: &Base, changes: &[Change]) -> Vec<u8> {
    let mut header = base.header.clone();
    let mut fields = Vec::new();
    let mut keep = None;

    for change in changes {
        if header.is_empty() {
            break;
        }
        let len = header.len();
        match change {
            Change::Flip(at, bit) => header[at.index(len)] ^= 1 << bit,
            Change::Byte(at, value) => header[at.index(len)] = *value,
            Change::Number(at, value) => {
                let at = at.index(header.len());
                for (place, byte) in craft::number(*value).into_iter().enumerate() {
                    if let Some(slot) = header.get_mut(at + place) {
                        *slot = byte;
                    }
                }
            },
            Change::Splice(from, to, len) => {
                let (from, to) = (from.index(header.len()), to.index(header.len()));
                let run: Vec<u8> = header[from..(from + len).min(header.len())].to_vec();
                for (place, byte) in run.into_iter().enumerate() {
                    if let Some(slot) = header.get_mut(to + place) {
                        *slot = byte;
                    }
                }
            },
            Change::Remove(at, len) => {
                let at = at.index(header.len());
                drop(header.drain(at..(at + len).min(header.len())));
            },
            Change::Shorten(keep) => header.truncate(keep.index(header.len())),
            Change::Field(size, value) => fields.push((*size, *value)),
            Change::Truncate(at) => keep = Some(*at),
        }
    }

    let mut archive = craft::archive(&header, &base.packed);
    for (size, value) in fields {
        let at = if size { 20 } else { 12 };
        archive[at..at + 8].copy_from_slice(&value.to_le_bytes());
        let crc = crc32fast::hash(&archive[12..32]);
        archive[8..12].copy_from_slice(&crc.to_le_bytes());
    }
    if let Some(keep) = keep {
        archive.truncate(keep.index(archive.len()));
    }
    archive
}

/// Hold what was read of an archive to what an analysis has to be, whatever the archive.
fn holds(analysed: &Analysed, wanted: Lines) -> Result<(), String> {
    let Analysed { analysis, lines } = analysed;
    let entries = analysis.entry_list.len();
    let check = |holds: bool, what: &str| if holds { Ok(()) } else { Err(what.to_owned()) };

    check(lines.len() == analysis.lines.len(), "a line `info` does not name")?;
    check(wanted == Lines::All || lines.len() <= 1, "more than the best line")?;
    for line in lines {
        check(line.tag == Tag::SevenZ && line.mode == 46900, "a line of another kind")?;
        check(line.text.starts_with("$7z$*") && line.text.ends_with("$/7z$") && !line.text.contains(':'), "a line that is none")?;
        check(line.entry.is_some() != (analysis.headers == Headers::Encrypted), "a line from the wrong place")?;
        check(line.entry.is_none_or(|entry| entry < entries), "a line from an entry that is not there")?;
        // six fields, and five for each of one stream or four
        let fields = line.text.split('*').count() - 1;
        check(fields == 11 || fields == 26, "a line with a wrong number of fields")?;
    }
    for missing in &analysis.no_line {
        check(missing.entry.is_none_or(|entry| entry < entries), "a missing line of an entry that is not there")?;
    }
    check(serde_json::to_string(analysis).is_ok(), "an analysis that cannot be written")
}

/// Read an archive both ways `hash` asks for, in good time, and hold the outcome to [`holds`].
fn read_both(archive: &[u8]) -> Result<(), String> {
    for wanted in [Lines::Best, Lines::All] {
        let started = Instant::now();
        let outcome = analyse(&Source::from_bytes(archive.to_vec()), wanted);
        let took = started.elapsed();
        if took > TIME {
            return Err(format!("reading took {took:?}"));
        }
        if let Ok(analysed) = &outcome {
            holds(analysed, wanted)?;
        }
    }
    Ok(())
}

#[test]
fn the_fixtures_as_they_are_hold() {
    let bases = bases();
    assert!(bases.len() > FIXTURES.len(), "some headers are there unpacked as well");
    for base in &bases {
        let archive = craft::archive(&base.header, &base.packed);
        assert!(analyse(&Source::from_bytes(archive.clone()), Lines::All).is_ok());
        assert_eq!(read_both(&archive), Ok(()));
    }
}

/// Up to four changes at once to one archive, ten thousand times over.
#[test]
fn a_changed_archive_is_read_to_an_error_or_an_analysis() {
    let bases = bases();
    let config = Config { cases: CASES, failure_persistence: None, ..Config::default() };
    let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha));
    let strategy = (0..bases.len(), proptest::collection::vec(change(), 1..5));

    let outcome = runner.run(&strategy, |(base, changes)| read_both(&changed(&bases[base], &changes)).map_err(TestCaseError::fail));
    assert!(outcome.is_ok(), "{outcome:?}");
}

/// Every byte of every header set to each of eight values, one change at a time.
#[test]
fn every_byte_of_a_header_can_be_anything() {
    for base in bases().iter().filter(|base| base.header.len() <= 1024) {
        for at in 0..base.header.len() {
            for value in [0x00, 0x01, 0x0B, 0x17, 0x40, 0x7F, 0x80, 0xFF] {
                let mut header = base.header.clone();
                header[at] = value;
                let outcome = read_both(&craft::archive(&header, &base.packed));
                assert_eq!(outcome, Ok(()), "byte {at} of {:02x?} set to {value:#04x}", base.header);
            }
        }
    }
}
