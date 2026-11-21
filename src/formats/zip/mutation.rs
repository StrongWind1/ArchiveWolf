//! Mutated copies of real archives, through the analysis and the building of every line.
//!
//! The tool reads files that may be built to break it, so no input may make it panic or run
//! long. Each case takes an archive, changes it, and
//! analyses the result twice: for the best lines and for all of them. The changes are the ones
//! a broken or a hostile file has: a bit that flipped, a size or a count or an offset in a
//! header with a value at the edge of its range, a file that is cut short, a piece of the file
//! copied over another. A ZIP header has no checksum of its own, so a changed header is read
//! as it stands and nothing needs to be recomputed for the parser to go on.
//!
//! The run is seeded: the same cases every time, a few seconds in all.

use std::time::Duration;
use std::time::Instant;

use proptest::collection::vec;
use proptest::prelude::Strategy;
use proptest::prelude::any;
use proptest::prop_oneof;
use proptest::test_runner::Config;
use proptest::test_runner::RngAlgorithm;
use proptest::test_runner::TestCaseError;
use proptest::test_runner::TestRng;
use proptest::test_runner::TestRunner;

use super::analyse::analyse;
use super::craft::DecryptionHeader;
use super::craft::Member;
use super::craft::Zip;
use super::craft::aes_extra;
use super::craft::deflated;
use super::craft::member;
use super::craft::noise;
use super::craft::pkware_extra;
use crate::formats::source::Source;
use crate::line::Lines;

/// The fixtures that are mutated: one or more of every scheme and of every shape the parser
/// has a path for, each small enough to be analysed thousands of times.
const FIXTURES: [&str; 20] = [
    "zip-crypto/stored.zip",
    "zip-crypto/noradi.zip",
    "zip-crypto/mixed.zip",
    "zip-crypto/gen_infozip_zip64.zip",
    "zip-crypto/gen_own_zc_pkzip1_twobyte.zip",
    "zip-crypto/gen_own_zc_bzip2.zip",
    "zip-crypto/gen_7z_zipcrypto_lzma.zip",
    "zip-crypto/zipcrypto_datadesc.zip",
    "zip-crypto/gen_own_zc_eight_stored.zip",
    "zip-winzip/gen_7z_aes256_tiny.zip",
    "zip-winzip/gen_own_aes256_empty.zip",
    "zip-winzip/rawzip_aes128.zip",
    "zip-pkware/gen_ses_aes128_iv_stored.zip",
    "zip-pkware/gen_ses_aes256_noiv_deflate.zip",
    "unknown-pw/edge_zip-forensic_securezip-strong-signed.zip",
    "pseudo/pseudo.zip",
    "pseudo/pseudo_encrypted_zc.zip",
    "pseudo/gen_infozip_empty.zip",
    "unparseable/multidisk_stub.zip",
    "regress/zip/zip64_offset_only.zip",
];

/// The longest one analysis of a mutated archive may take. The archives are a few kilobytes
/// and an analysis of one takes well under a millisecond: this is the bound that tells a
/// loop over a count from a header from the work a file of that size is worth.
const TIME_LIMIT: Duration = Duration::from_secs(5);

/// The fields of the records that hold a size, a count, an offset or a mark: where the field
/// is in its record, and how many bytes it has.
const FIELDS: [(&[u8; 4], &[(usize, usize)]); 5] = [
    // local file header: version, flags, method, the two sizes, the two lengths
    (b"PK\x03\x04", &[(4, 2), (6, 2), (8, 2), (18, 4), (22, 4), (26, 2), (28, 2)]),
    // central header: both versions, flags, method, sizes, the three lengths, disk, offset
    (b"PK\x01\x02", &[(4, 2), (6, 2), (8, 2), (10, 2), (20, 4), (24, 4), (28, 2), (30, 2), (32, 2), (34, 2), (42, 4)]),
    // end record: the two disks, the two counts, size and offset of the directory, comment
    (b"PK\x05\x06", &[(4, 2), (6, 2), (8, 2), (10, 2), (12, 4), (16, 4), (20, 2)]),
    // ZIP64 end record: its size, the version it needs, disks, counts, size and offset
    (b"PK\x06\x06", &[(4, 8), (14, 2), (16, 4), (20, 4), (24, 8), (32, 8), (40, 8), (48, 8)]),
    // ZIP64 locator: disk, offset, number of disks
    (b"PK\x06\x07", &[(4, 4), (8, 8), (16, 4)]),
];

/// Values at the edges of what a field can hold and of what the format gives a meaning.
const VALUES: [u64; 24] = [0, 1, 2, 8, 11, 12, 13, 20, 99, 0x41, 0x2041, 0x7F, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x0001_0000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFE, 0xFFFF_FFFF, 0x0001_0000_0000, 0x7FFF_FFFF_FFFF_FFFF, u64::MAX];

/// One change to an archive.
#[derive(Debug, Clone)]
enum Mutation {
    /// Flip one bit.
    Flip { at: usize, bit: u8 },
    /// Put a value from [`VALUES`], or the size of the file with something added, into a
    /// field of a record.
    Field { record: usize, field: usize, value: usize, near_len: Option<i8> },
    /// Keep the start of the file and drop the rest.
    Truncate { keep: usize },
    /// Copy some bytes of the file over others.
    Splice { from: usize, to: usize, len: usize },
    /// Put bytes in front of the file, as a program has, or behind it.
    Pad { front: bool, len: usize },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        3 => (any::<usize>(), 0..8_u8).prop_map(|(at, bit)| Mutation::Flip { at, bit }),
        5 => (any::<usize>(), any::<usize>(), any::<usize>(), proptest::option::weighted(0.2, -2..=2_i8)).prop_map(|(record, field, value, near_len)| Mutation::Field { record, field, value, near_len }),
        1 => any::<usize>().prop_map(|keep| Mutation::Truncate { keep }),
        2 => (any::<usize>(), any::<usize>(), 1..600_usize).prop_map(|(from, to, len)| Mutation::Splice { from, to, len }),
        1 => (any::<bool>(), 1..300_usize).prop_map(|(front, len)| Mutation::Pad { front, len }),
    ]
}

/// The offsets of the records of `data`, each with the fields of its kind.
fn records(data: &[u8]) -> Vec<(usize, &'static [(usize, usize)])> {
    data.windows(4).enumerate().filter_map(|(at, window)| FIELDS.iter().find(|(signature, _)| window == *signature).map(|(_, fields)| (at, *fields))).collect()
}

/// Apply one change. A change that has nothing to act on leaves the archive as it is.
fn apply(data: &mut Vec<u8>, change: &Mutation) {
    if data.is_empty() {
        return;
    }
    match *change {
        Mutation::Flip { at, bit } => {
            let at = at % data.len();
            data[at] ^= 1 << bit;
        },
        Mutation::Field { record, field, value, near_len } => {
            let found = records(data);
            if found.is_empty() {
                return;
            }
            let (at, fields) = found[record % found.len()];
            let (offset, width) = fields[field % fields.len()];
            let value = near_len.map_or(VALUES[value % VALUES.len()], |delta| (data.len() as u64).wrapping_add_signed(i64::from(delta)));
            if let Some(target) = data.get_mut(at + offset..at + offset + width) {
                target.copy_from_slice(&value.to_le_bytes()[..width]);
            }
        },
        Mutation::Truncate { keep } => data.truncate(keep % (data.len() + 1)),
        Mutation::Splice { from, to, len } => {
            let (from, to) = (from % data.len(), to % data.len());
            let len = len.min(data.len() - from).min(data.len() - to);
            data.copy_within(from..from + len, to);
        },
        Mutation::Pad { front, len } => {
            let padding = noise(len);
            if front {
                drop(data.splice(0..0, padding));
            } else {
                data.extend_from_slice(&padding);
            }
        },
    }
}

/// The archives that are mutated: the fixtures, and archives of the shapes no fixture has.
fn seeds() -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = FIXTURES.iter().map(|rel| std::fs::read(format!("tests/fixtures/{rel}")).unwrap_or_else(|error| panic!("{rel}: {error}"))).collect();

    let zip_crypto = noise(12 + 80);
    let text = b"plain data with the flag of encryption set on it, ".repeat(30);
    let stream = deflated(&text);
    let aes = noise(16 + 2 + 60 + 10);
    let aes_field = aes_extra(2, 3, 8);
    let recipient = [vec![0x91; 20], noise(64)].concat();
    let pkware_field = pkware_extra(0x660F, 192, 3);
    let pkware = [DecryptionHeader { flags: 3, recipients: vec![recipient], ..DecryptionHeader::password(0x660F, 192) }.bytes(), noise(48)].concat();
    let blowfish_field = pkware_extra(0x6720, 128, 1);
    let blowfish = [DecryptionHeader { iv: vec![7; 8], erd: noise(32), ..DecryptionHeader::password(0x6720, 128) }.bytes(), noise(40)].concat();
    let members = [
        member("locked.bin", 1, &zip_crypto),
        Member { method: 8, crc: Some(crc32fast::hash(&text)), size: u32::try_from(text.len()).ok(), ..member("open.txt", 1, &stream) },
        Member { method: 99, extra: &aes_field, ..member("aes.bin", 1, &aes) },
        Member { version: 51, central_extra: &pkware_field, size: Some(300), ..member("strong.bin", 0x41, &pkware) },
        Member { version: 51, central_extra: &blowfish_field, size: Some(300), ..member("blowfish.bin", 0x41, &blowfish) },
        member("dir/", 0, b""),
        Member { flags: 9, ..member("described.bin", 9, &zip_crypto) },
    ];

    // every scheme in one archive, plain and with ZIP64 records
    seeds.push(Zip::of(&members).comment(b"a comment").descriptors().build());
    seeds.push(Zip::of(&members).zip64().descriptors().build());
    // the last volume of a spanned archive, and an encrypted central directory
    seeds.push(Zip::of(&[Member { disk: 1, ..member("locked.bin", 1, &zip_crypto) }, Member { disk: 3, ..member("last.bin", 1, &zip_crypto) }]).disk(3).build());
    seeds.push(Zip::of(&members).directory_protection(8, 0x6610, 256, 1).build());
    // the first volume of a split archive: the split marker, local headers, and no directory
    let whole = Zip::of(&members).descriptors().build();
    let directory = whole.windows(4).position(|window| window == b"PK\x01\x02").unwrap_or(whole.len());
    seeds.push([b"PK\x07\x08".as_slice(), &whole[..directory.saturating_sub(30)]].concat());
    seeds
}

#[test]
fn mutated_archives_are_analysed_without_a_panic_and_without_delay() {
    let seeds = seeds();
    // every seed is an archive the analysis accepts as it is
    for (index, seed) in seeds.iter().enumerate() {
        assert!(analyse(&Source::from_bytes(seed.clone()), Lines::All).is_ok(), "seed {index} does not parse");
    }

    let cases = (0..seeds.len(), vec(mutation(), 1..5));
    let mut runner = TestRunner::new_with_rng(Config { cases: 10_000, failure_persistence: None, ..Config::default() }, TestRng::deterministic_rng(RngAlgorithm::ChaCha));
    let outcome = runner.run(&cases, |(seed, changes)| {
        let mut data = seeds[seed].clone();
        for change in &changes {
            apply(&mut data, change);
        }
        for wanted in [Lines::Best, Lines::All] {
            let started = Instant::now();
            // an error is an answer: the archive does not parse
            if let Ok(analysed) = analyse(&Source::from_bytes(data.clone()), wanted) {
                // what `info` names is what `hash` writes, and every line is one a mode can be named for
                if analysed.analysis.lines.len() != analysed.lines.len() || analysed.lines.iter().any(|line| !line.text.ends_with("$/zip$")) {
                    return Err(TestCaseError::fail(format!("{} lines named, {} written", analysed.analysis.lines.len(), analysed.lines.len())));
                }
            }
            if started.elapsed() > TIME_LIMIT {
                return Err(TestCaseError::fail(format!("an analysis took {:?}", started.elapsed())));
            }
        }
        Ok(())
    });
    if let Err(failure) = outcome {
        panic!("{failure}");
    }
}

/// Every prefix of an archive, and every archive with its first bytes gone: the two ways a
/// file is cut. One fixture of each scheme, at every length.
#[test]
fn an_archive_cut_at_any_byte_is_analysed_without_a_panic() {
    for rel in ["zip-crypto/stored.zip", "zip-winzip/gen_7z_aes256_tiny.zip", "zip-pkware/gen_ses_aes128_iv_stored.zip", "zip-crypto/gen_infozip_zip64.zip"] {
        let data = std::fs::read(format!("tests/fixtures/{rel}")).unwrap();
        for cut in 0..=data.len() {
            for piece in [&data[..cut], &data[cut..]] {
                drop(analyse(&Source::from_bytes(piece.to_vec()), Lines::All));
            }
        }
    }
}
