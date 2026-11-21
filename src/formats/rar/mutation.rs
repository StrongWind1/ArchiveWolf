//! Archives that were damaged on purpose: what started as a fixture is changed at random and
//! analysed, and whatever it has become, the analysis ends without a panic and in good time,
//! and every line it writes is one its hashcat mode loads.
//!
//! The runs are seeded, so they are the same on every machine and every day. A failure prints
//! the changes that led to it.

use std::time::Duration;
use std::time::Instant;

use proptest::prelude::Just;
use proptest::prelude::Strategy;
use proptest::prelude::any;
use proptest::prelude::prop_assert;
use proptest::prelude::prop_assert_eq;
use proptest::prelude::prop_oneof;
use proptest::sample::Index;
use proptest::test_runner::Config;
use proptest::test_runner::RngSeed;
use proptest::test_runner::TestCaseError;
use proptest::test_runner::TestRunner;

use super::analyse::analyse;
use crate::analysis::Analysed;
use crate::formats::source::Source;
use crate::line::Lines;
use crate::line::Tag;

/// Fixtures of every generation and of every way the format encrypts, each small enough to be
/// analysed a few thousand times in a second.
const SEEDS: [&str; 30] = [
    "rar-13/rar14-password-compressed.rar",
    "rar-13/rar14-password-stored.rar",
    "rar-13/rar14-solid-password.rar",
    "unencrypted/rar14_packed_comment.rar",
    "unencrypted/rar14_with_comment.rar",
    "rar-15/rar15-password-compressed.rar",
    "rar-15/rar15-password-stored.rar",
    "rar-15/rars_service_block_stored.rar",
    "rar-20/rar20-password-compressed.rar",
    "rar-20/rar20-password-stored.rar",
    "rar-30/bad-crc-enc-headers.rar",
    "rar-30/rar3-nonascii-password.rar",
    "rar-30/rars_rar4_mixed_visible_names_password.rar",
    "rar-30/ttzip-core_test_read_format_rar4_encrypted.rar",
    "regress/rar/rar3_no_salt.rar",
    "regress/rar/rar4_hp_vol.part2.rar",
    "regress/rar/rar3_hp_vol.part2.rar",
    "unknown-pw/edge_rars_comment_psw.rar",
    "unknown-pw/edge_rars_split-encrypted.rar",
    "unencrypted/rar4-ext_time.rar",
    "rar-50/nocheck_hp_m0.rar",
    "rar-50/nocheck_st_b2mac.rar",
    "rar-50/nocheck_st_crc.rar",
    "rar-50/synth_type1_blake2sp.rar",
    "rar-50/ttzip-core_test_read_format_rar5_encrypted.rar",
    "regress/rar/rar5_comment.rar",
    "regress/rar/rar5_hp_vol.part3.rar",
    "regress/rar/rar5_p_vol.part2.rar",
    "regress/rar/rounds_2e25.rar",
    "regress/rar/service_zero_check_value.rar",
];

/// Where most of the changes land: the headers of a small archive lie in its first bytes.
const HEADERS: usize = 600;

/// The longest one analysis may take. They take microseconds: this is for a loop that does not
/// end, on a machine that is busy with other tests.
const TIME_LIMIT: Duration = Duration::from_secs(20);

/// The most data a line carries.
const DATA_MAX: usize = 4 << 20;

fn seed(index: usize) -> Vec<u8> {
    std::fs::read(format!("tests/fixtures/{}", SEEDS[index % SEEDS.len()])).unwrap()
}

/// One change to the bytes of an archive.
#[derive(Debug, Clone)]
enum Change {
    /// One bit turned over.
    FlipBit { at: Index, bit: u8 },
    /// A number of 8, 16, 32 or 64 bits written in the place of what was there.
    Number { at: Index, value: u64, width: usize },
    /// A variable-length number of RAR 5 written in the place of what was there.
    Vint { at: Index, value: u64 },
    /// Everything from here on cut off.
    Truncate { at: Index },
    /// A run of bytes copied from one place to another.
    Copy { from: Index, to: Index, len: usize },
    /// Bytes put in between two others.
    Insert { at: Index, bytes: Vec<u8> },
    /// A run of bytes taken out.
    Remove { at: Index, len: usize },
    /// The rest of another fixture in the place of the rest of this one.
    Graft { at: Index, other: usize, from: Index },
}

/// Numbers a size or a count is likely to go wrong with: the ends of every width, and the
/// values around a sign bit.
fn interesting() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0),
        Just(1),
        Just(6),
        Just(7),
        Just(0x7F),
        Just(0x80),
        Just(0xFF),
        Just(0x7FFF),
        Just(0x8000),
        Just(0xFFFF),
        Just(0x1_0000),
        Just(0x7FFF_FFFF),
        Just(0x8000_0000),
        Just(0xFFFF_FFFF),
        Just(0x1_0000_0000),
        Just(0x7FFF_FFFF_FFFF_FFFF),
        Just(0x8000_0000_0000_0000),
        Just(u64::MAX),
        any::<u64>(),
        0_u64..5000,
    ]
}

fn change() -> impl Strategy<Value = Change> {
    let width = prop_oneof![Just(1_usize), Just(2), Just(4), Just(8)];
    prop_oneof![
        4 => (any::<Index>(), 0_u8..8).prop_map(|(at, bit)| Change::FlipBit { at, bit }),
        6 => (any::<Index>(), interesting(), width).prop_map(|(at, value, width)| Change::Number { at, value, width }),
        3 => (any::<Index>(), interesting()).prop_map(|(at, value)| Change::Vint { at, value }),
        1 => any::<Index>().prop_map(|at| Change::Truncate { at }),
        2 => (any::<Index>(), any::<Index>(), 1_usize..64).prop_map(|(from, to, len)| Change::Copy { from, to, len }),
        1 => (any::<Index>(), proptest::collection::vec(any::<u8>(), 1..40)).prop_map(|(at, bytes)| Change::Insert { at, bytes }),
        1 => (any::<Index>(), 1_usize..40).prop_map(|(at, len)| Change::Remove { at, len }),
        1 => (any::<Index>(), 0..SEEDS.len(), any::<Index>()).prop_map(|(at, other, from)| Change::Graft { at, other, from }),
    ]
}

/// A place in `bytes`, most often among its first [`HEADERS`] bytes.
fn place(at: Index, bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    // one index in five lands anywhere in the file
    let reach = if at.index(5) == 0 { bytes.len() } else { bytes.len().min(HEADERS) };
    at.index(reach)
}

/// A number of variable length.
fn vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = u8::try_from(value & 0x7F).unwrap();
        value >>= 7;
        if value == 0 {
            out.push(low);
            return out;
        }
        out.push(low | 0x80);
    }
}

/// Write `new` over the bytes at `at`, as far as the archive reaches.
fn overwrite(bytes: &mut [u8], at: usize, new: &[u8]) {
    for (old, new) in bytes.iter_mut().skip(at).zip(new) {
        *old = *new;
    }
}

fn apply(bytes: &mut Vec<u8>, change: &Change) {
    match change {
        Change::FlipBit { at, bit } => {
            let at = place(*at, bytes);
            if let Some(byte) = bytes.get_mut(at) {
                *byte ^= 1 << bit;
            }
        },
        Change::Number { at, value, width } => {
            let at = place(*at, bytes);
            overwrite(bytes, at, &value.to_le_bytes()[..*width]);
        },
        Change::Vint { at, value } => {
            let at = place(*at, bytes);
            overwrite(bytes, at, &vint(*value));
        },
        Change::Truncate { at } => bytes.truncate(place(*at, bytes)),
        Change::Copy { from, to, len } => {
            let from = place(*from, bytes);
            let run = bytes[from..bytes.len().min(from + len)].to_vec();
            let to = place(*to, bytes);
            overwrite(bytes, to, &run);
        },
        Change::Insert { at, bytes: new } => {
            let at = place(*at, bytes);
            drop(bytes.splice(at..at, new.iter().copied()));
        },
        Change::Remove { at, len } => {
            let at = place(*at, bytes);
            drop(bytes.drain(at..bytes.len().min(at + len)));
        },
        Change::Graft { at, other, from } => {
            let other = seed(*other);
            bytes.truncate(place(*at, bytes));
            bytes.extend_from_slice(&other[place(*from, &other)..]);
        },
    }
}

/// The number a field of a line holds, in hex.
fn hex_number(field: &str, digits: usize) -> Result<u64, String> {
    if field.is_empty() || field.len() > digits || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field:?} is no hex number of up to {digits} digits"));
    }
    u64::from_str_radix(field, 16).map_err(|error| error.to_string())
}

/// The bytes a field of a line holds, in hex.
fn hex_bytes(field: &str) -> Result<usize, String> {
    if !field.len().is_multiple_of(2) || !field.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("a field of {} characters is no lower-case hex", field.len()));
    }
    Ok(field.len() / 2)
}

fn ensure(holds: bool, what: &str) -> Result<(), String> {
    if holds { Ok(()) } else { Err(what.to_owned()) }
}

/// Whether the hashcat mode of a line loads it: the checks of `rarl_hash_decode` (modes 46500
/// and 46600), `parse_new_rar30` (46700) and `parse_new_rar50` (46800) of the hashcat fork, and
/// for RAR 5 the round count UnRAR accepts.
fn loads(tag: Tag, line: &str) -> Result<(), String> {
    let body = line.strip_prefix(tag.as_str()).and_then(|rest| rest.strip_suffix("$/rar$")).and_then(|rest| rest.strip_prefix('*')).ok_or("no line of its tag")?;
    let fields: Vec<&str> = body.split('*').collect();
    match (tag, fields.as_slice()) {
        (Tag::Rar15 | Tag::Rar20, [crc, unpacked, size, method, data]) => {
            ensure(crc.len() == 8 && hex_bytes(crc).is_ok(), "the CRC-32 has eight digits")?;
            let (unpacked, size, method) = (hex_number(unpacked, 8)?, hex_number(size, 8)?, hex_number(method, 8)?);
            ensure((0x30..=0x35).contains(&method), "a method from 0x30 to 0x35")?;
            ensure(size != 0 && usize::try_from(size).is_ok_and(|size| size <= DATA_MAX && hex_bytes(data) == Ok(size)), "as much data as the size says, and no more than a line carries")?;
            ensure(tag == Tag::Rar15 || size % 16 == 0, "whole blocks")?;
            ensure(unpacked != 0, "an unpacked size")?;
            let stored = if tag == Tag::Rar20 { unpacked.next_multiple_of(16) } else { unpacked };
            ensure(method != 0x30 || size == stored, "a stored entry is as long as its data")
        },
        (Tag::Rar30, [hash_type, salt, _, _, _, _, data]) if *hash_type == "0" => {
            ensure(salt.len() == 16 && hex_bytes(salt).is_ok(), "a salt of eight bytes")?;
            ensure(matches!(hex_bytes(data), Ok(16 | 32)), "one or two blocks of an end block")
        },
        (Tag::Rar30, [hash_type, salt, crc, packed, unpacked, method, data]) if *hash_type == "1" => {
            ensure(salt.len() == 16 && hex_bytes(salt).is_ok(), "a salt of eight bytes")?;
            let (_, packed, unpacked, method) = (hex_number(crc, 16)?, hex_number(packed, 10)?, hex_number(unpacked, 10)?, hex_number(method, 4)?);
            ensure((0x30..=0x35).contains(&method), "a method from 0x30 to 0x35")?;
            ensure(unpacked != 0 && unpacked <= 0xFFFF_FFFF, "an unpacked size of 32 bits")?;
            let size = hex_bytes(data)?;
            ensure(size >= 16 && size % 16 == 0 && size <= DATA_MAX && u64::try_from(size) == Ok(packed), "whole blocks, as many as the size says and no more than a line carries")?;
            ensure(method != 0x30 || unpacked <= packed, "a stored entry is no longer than its data")
        },
        (Tag::Rar50, [hash_type, salt, lg2count, iv, check_value, check_type, checksum, packed, unpacked, method, data]) => {
            ensure(salt.len() == 32 && hex_bytes(salt).is_ok() && iv.len() == 32 && hex_bytes(iv).is_ok(), "a salt and a vector of sixteen bytes")?;
            ensure(lg2count.parse::<u8>().is_ok_and(|power| (1..=24).contains(&power)) && lg2count.len() <= 2, "a count from 2^1 to 2^24")?;
            ensure(matches!(*check_type, "0" | "1" | "2" | "3" | "4"), "a kind of check")?;
            if *hash_type == "0" {
                ensure(check_value.len() == 16 && hex_bytes(check_value).is_ok(), "a check value of eight bytes")?;
                return ensure([checksum, packed, unpacked, method, data].iter().all(|field| field.is_empty()), "nothing behind a check value");
            }
            ensure(*hash_type == "1" && check_value.is_empty(), "type 1 without a check value")?;
            let digits = match *check_type {
                "4" => 0,
                "2" | "3" => 64,
                _ => 8,
            };
            ensure(checksum.len() == digits && hex_bytes(checksum).is_ok(), "the checksum of its kind")?;
            let (packed, unpacked, method) = (hex_number(packed, 16)?, hex_number(unpacked, 16)?, hex_number(method, 16)?);
            ensure(method <= 5, "a method from 0 to 5")?;
            let size = hex_bytes(data)?;
            ensure(size >= 16 && size % 16 == 0 && size <= DATA_MAX && u64::try_from(size) == Ok(packed), "whole blocks, as many as the size says and no more than a line carries")?;
            ensure(*check_type == "4" || (unpacked != 0 && (method != 0 || unpacked <= packed)), "an unpacked size that fits the data")
        },
        _ => Err(format!("{} fields", fields.len())),
    }
}

/// Analyse `bytes` both ways, and hold what comes back against what has to hold for any input.
fn check(bytes: &[u8]) -> Result<(), TestCaseError> {
    for wanted in [Lines::Best, Lines::All] {
        let started = Instant::now();
        let outcome = analyse(&Source::from_bytes(bytes.to_vec()), wanted);
        prop_assert!(started.elapsed() < TIME_LIMIT, "the analysis took {:?}", started.elapsed());
        // an archive that does not parse is an answer
        let Ok(Analysed { analysis, lines }) = outcome else { continue };

        // `info` names the lines `hash` writes, and each comes from an entry that is listed
        prop_assert_eq!(analysis.lines.len(), lines.len());
        for line in &lines {
            prop_assert!(line.entry.is_none_or(|index| index < analysis.entry_list.len()), "a line from entry {:?} of {}", line.entry, analysis.entry_list.len());
            if let Err(why) = loads(line.tag, &line.text) {
                return Err(TestCaseError::fail(format!("mode {} does not load its line ({why}): {:.200}", line.mode, line.text)));
            }
        }
        // what is encrypted has a line or a reason, and what is not has neither
        prop_assert_eq!(analysis.is_encrypted(), !lines.is_empty() || !analysis.no_line.is_empty(), "lines {}, reasons {:?}", lines.len(), analysis.no_line);
        for missing in &analysis.no_line {
            prop_assert!(missing.entry.is_none_or(|index| index < analysis.entry_list.len()));
        }
        prop_assert!(serde_json::to_string(&analysis).is_ok());
    }
    Ok(())
}

/// A run of `cases` cases under a seed of its own.
///
/// A longer run, or one under another seed, is asked for the way any proptest is: with
/// `PROPTEST_CASES` and `PROPTEST_RNG_SEED` in the environment.
fn runner(cases: u32, seed: u64) -> TestRunner {
    let asked = |name: &str| std::env::var(name).ok().and_then(|value| value.parse::<u64>().ok());
    let cases = asked("PROPTEST_CASES").and_then(|cases| u32::try_from(cases).ok()).unwrap_or(cases);
    let seed = asked("PROPTEST_RNG_SEED").unwrap_or(seed);
    TestRunner::new(Config { cases, rng_seed: RngSeed::Fixed(seed), failure_persistence: None, ..Config::default() })
}

#[test]
fn every_fixture_gives_lines_its_mode_loads() {
    for (index, name) in SEEDS.iter().enumerate() {
        check(&seed(index)).unwrap_or_else(|error| panic!("{name}: {error}"));
    }
}

#[test]
fn the_check_of_a_line_refuses_what_a_mode_refuses() {
    let data = "5a".repeat(32);
    for line in [
        format!("$rar$15$*cafef00d*20*20*30*{data}$/rar$"),
        format!("$rar$20$*cafef00d*14*20*30*{data}$/rar$"),
        format!("$rar$30$*1*a5a5a5a5a5a5a5a5*cafef00d*20*14*30*{data}$/rar$"),
        format!("$rar$30$*0*a5a5a5a5a5a5a5a5*c43d7b00*20*20*0*{data}$/rar$"),
        format!("$rar$50$*0*{0}*15*{0}*aaaaaaaaaaaaaaaa*0*****$/rar$", "11".repeat(16)),
        format!("$rar$50$*1*{0}*15*{0}**0*cafef00d*20*14*0*{data}$/rar$", "11".repeat(16)),
        format!("$rar$50$*1*{0}*15*{0}**4**20*20*0*{data}$/rar$", "11".repeat(16)),
    ] {
        let kind = Tag::of(&line).unwrap().0;
        assert_eq!(loads(kind, &line), Ok(()), "{line}");
    }
    for line in [
        format!("$rar$15$*cafef00d*21*20*30*{data}$/rar$"),
        format!("$rar$15$*cafef00d*100000000*20*33*{data}$/rar$"),
        format!("$rar$20$*cafef00d*14*1f*33*{}$/rar$", "5a".repeat(31)),
        format!("$rar$30$*1*a5a5a5a5a5a5a5a5*cafef00d*20*0*30*{data}$/rar$"),
        format!("$rar$30$*1*a5a5a5a5a5a5a5a5*cafef00d*20*14*36*{data}$/rar$"),
        format!("$rar$30$*0*a5a5a5a5a5a5a5a5*c43d7b00*18*18*0*{}$/rar$", "5a".repeat(24)),
        format!("$rar$50$*0*{0}*25*{0}*aaaaaaaaaaaaaaaa*0*****$/rar$", "11".repeat(16)),
        format!("$rar$50$*0*{0}*0*{0}*aaaaaaaaaaaaaaaa*0*****$/rar$", "11".repeat(16)),
        format!("$rar$50$*1*{0}*15*{0}**0*00000000*1f*14*0*{1}$/rar$", "11".repeat(16), "5a".repeat(31)),
        format!("$rar$50$*1*{0}*15*{0}**0*cafef00d*20*14*6*{data}$/rar$", "11".repeat(16)),
    ] {
        let kind = Tag::of(&line).unwrap().0;
        assert!(loads(kind, &line).is_err(), "{line}");
    }
}

/// Every file that is the start of a fixture: an archive cut short at any byte.
#[test]
fn an_archive_cut_short_anywhere_is_analysed() {
    for (index, name) in SEEDS.iter().enumerate() {
        let whole = seed(index);
        for len in 0..whole.len().min(HEADERS) {
            check(&whole[..len]).unwrap_or_else(|error| panic!("{name} cut to {len} bytes: {error}"));
        }
    }
}

/// Every byte among the headers of a fixture set to the values a size goes wrong with.
#[test]
fn an_archive_with_any_one_byte_changed_is_analysed() {
    for (index, name) in SEEDS.iter().enumerate() {
        let whole = seed(index);
        for at in 0..whole.len().min(HEADERS / 2) {
            for value in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
                let mut changed = whole.clone();
                changed[at] = value;
                check(&changed).unwrap_or_else(|error| panic!("{name} with byte {at} set to {value:#04x}: {error}"));
            }
        }
    }
}

#[test]
fn a_fixture_changed_at_random_is_analysed_and_its_lines_load() {
    let strategy = (0..SEEDS.len(), proptest::collection::vec(change(), 1..7));
    let outcome = runner(3000, 0x5241_5221).run(&strategy, |(index, changes)| {
        let mut bytes = seed(index);
        for change in &changes {
            apply(&mut bytes, change);
        }
        check(&bytes)
    });
    if let Err(error) = outcome {
        panic!("{error}");
    }
}

/// The same behind a program, where the archive has to be found first: a signature is tried
/// only when a header with the right checksum follows it, so the checksum of the first header
/// is put right after the changes.
#[test]
fn a_changed_archive_behind_a_program_is_found_or_refused() {
    let strategy = (0..SEEDS.len(), proptest::collection::vec(change(), 0..4), 4_usize..300);
    let outcome = runner(1500, 0x4D5A_9000).run(&strategy, |(index, changes, stub)| {
        let mut archive = seed(index);
        for change in &changes {
            apply(&mut archive, change);
        }
        // the first header of a RAR 5 archive: four bytes of CRC-32 over its size and the rest
        if archive.starts_with(b"Rar!\x1a\x07\x01\x00") && archive.len() > 14 && archive[12] < 0x80 {
            let end = (13 + usize::from(archive[12])).min(archive.len());
            let crc = crc32fast::hash(&archive[12..end]);
            archive[8..12].copy_from_slice(&crc.to_le_bytes());
        }
        let mut bytes = b"MZ".to_vec();
        bytes.resize(stub, 0);
        if stub >= 32 {
            bytes[28..32].copy_from_slice(b"RSFX");
        }
        bytes.extend_from_slice(&archive);
        check(&bytes)
    });
    if let Err(error) = outcome {
        panic!("{error}");
    }
}
