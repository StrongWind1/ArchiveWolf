//! The packers against streams that the real programs wrote.
//!
//! `tests/packers/zlib.json` and `tests/packers/infozip.json` hold, for each input and each
//! setting, the length and the SHA-256 of the stream of the real program, and a few streams
//! whole. `tests/packers/README.md` says how they were recorded. The inputs are not in the
//! tree: they are files that never change, or the bytes of the generators below, which
//! `tests/packers/inputs.py` has a second time for the recording.
//!
//! The default run compares a part of the cases, since this crate is not optimised in the
//! development profile. The two tests that are ignored compare every case:
//! `cargo nextest run --cargo-profile release-dev -p archivewolf -E 'test(/pack::tests/)' --run-ignored only`.

use std::collections::HashMap;
use std::io::Read as _;

use flate2::read::DeflateDecoder;
use rayon::iter::IntoParallelRefIterator as _;
use rayon::iter::ParallelExtend as _;
use rayon::iter::ParallelIterator as _;
use serde::Deserialize;
use sha2::Digest as _;
use sha2::Sha256;

use super::Deflater;
use super::Method;
use super::Packer;
use super::Strategy;

// ---------------------------------------------------------------------------
// The inputs
// ---------------------------------------------------------------------------

/// The 64 words of the text inputs, with a space between them.
const WORDS: &str = "the of and to in is that for it as was with be by on not he this are or his from at which but have an had they you were their one all we can her has there been if more when will would who so no archive password entry stream window block packer level header length distance literal Huffman Deflate known plaintext";

/// The 32-bit xorshift generator of Marsaglia, with the shifts 13, 17 and 5.
struct Xorshift(u32);

impl Xorshift {
    /// The next 32 bits.
    fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }

    /// A number below the limit.
    fn below(&mut self, limit: usize) -> usize {
        self.next() as usize % limit
    }

    /// The low byte of the next 32 bits.
    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }
}

/// Bytes of the generator: each output gives four, the lowest first.
fn random_bytes(rng: &mut Xorshift, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 4);
    while out.len() < length {
        out.extend(rng.next().to_le_bytes());
    }
    out.truncate(length);
    out
}

/// Words of the list: one in sixteen ends a sentence, one in sixteen has a comma after it.
fn text(rng: &mut Xorshift, length: usize) -> Vec<u8> {
    let words: Vec<&str> = WORDS.split(' ').collect();
    let mut out = Vec::with_capacity(length + 16);
    while out.len() < length {
        out.extend(words[rng.below(words.len())].as_bytes());
        out.extend(
            match rng.below(16) {
                0 => ".\n",
                1 => ", ",
                _ => " ",
            }
            .as_bytes(),
        );
    }
    out.truncate(length);
    out
}

/// Random bytes of the length of the period, over and over.
fn repeat(rng: &mut Xorshift, length: usize, period: usize) -> Vec<u8> {
    random_bytes(rng, period).into_iter().cycle().take(length).collect()
}

/// Runs of one of four letters.
fn runs(rng: &mut Xorshift, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 700);
    while out.len() < length {
        let letter = b'a' + u8::try_from(rng.below(4)).unwrap();
        let count = 1 + rng.below(700);
        out.resize(out.len() + count, letter);
    }
    out.truncate(length);
    out
}

/// Records of 16 bytes, as a table in a binary file has them.
fn binary(rng: &mut Xorshift, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 16);
    let mut counter = 0_u32;
    while out.len() < length {
        out.extend(counter.to_le_bytes());
        out.extend(&rng.next().to_le_bytes()[..2]);
        if let Some(high) = out.last_mut() {
            *high &= 0x03;
        }
        out.extend([0, 0]);
        out.extend((rng.next() & 0x0f0f_0f0f).to_le_bytes());
        out.extend([0x01, 0x00, 0x00, 0x80]);
        counter += 1;
    }
    out.truncate(length);
    out
}

/// Appends at least the given length: one to five random bytes, then 10 to 199 bytes that
/// the output already has.
fn copies(rng: &mut Xorshift, out: &mut Vec<u8>, length: usize) {
    let target = out.len() + length;
    while out.len() < target {
        for _ in 0..=rng.below(5) {
            out.push(rng.byte());
        }
        let back = rng.below(out.len());
        let end = (back + 10 + rng.below(190)).min(out.len());
        out.extend_from_within(back..end);
    }
}

/// Stretches of the other kinds.
fn mix(rng: &mut Xorshift, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length + 60_000);
    while out.len() < length {
        let kind = rng.below(5);
        let stretch = 1 + rng.below(60_000);
        match kind {
            0 => out.extend(random_bytes(rng, stretch)),
            1 => out.extend(text(rng, stretch)),
            2 => {
                let byte = rng.byte();
                out.resize(out.len() + stretch, byte);
            },
            3 => {
                let period = 1 + rng.below(300);
                out.extend(repeat(rng, stretch, period));
            },
            _ => copies(rng, &mut out, stretch),
        }
    }
    out.truncate(length);
    out
}

/// 21 byte values whose counts are the Fibonacci numbers, shuffled, six times. A Huffman
/// tree of such counts is deeper than the 15 bits a code may have.
fn fib(rng: &mut Xorshift) -> Vec<u8> {
    let mut block = Vec::new();
    let (mut count, mut following) = (1_usize, 1_usize);
    for value in 0..21_u8 {
        block.resize(block.len() + count, value * 7 + 3);
        (count, following) = (following, count + following);
    }
    for i in (1..block.len()).rev() {
        let j = rng.below(i + 1);
        block.swap(i, j);
    }
    block.repeat(6)
}

/// The input of a name. `tests/packers/inputs.py` lists the kinds.
fn make(name: &str) -> Vec<u8> {
    let (kind, rest) = name.split_once(':').unwrap_or((name, ""));
    if kind == "file" {
        return std::fs::read(rest).unwrap();
    }
    let numbers: Vec<usize> = rest.split(':').filter(|part| !part.is_empty()).map(|part| part.parse().unwrap()).collect();
    let seed = if kind == "fib" { numbers.first() } else { numbers.get(1) };
    let rng = &mut Xorshift(seed.map_or(1, |seed| u32::try_from(*seed).unwrap()));
    let length = numbers.first().copied().unwrap_or(0);
    match kind {
        "empty" => Vec::new(),
        "zeros" => vec![0; length],
        "fib" => fib(rng),
        "random" => random_bytes(rng, length),
        "text" => text(rng, length),
        "repeat" => repeat(rng, length, numbers[2]),
        "runs" => runs(rng, length),
        "binary" => binary(rng, length),
        "copies" => {
            let mut out = Vec::new();
            copies(rng, &mut out, length);
            out.truncate(length);
            out
        },
        "mix" => mix(rng, length),
        _ => panic!("unknown input: {name}"),
    }
}

// ---------------------------------------------------------------------------
// The records
// ---------------------------------------------------------------------------

/// `tests/packers/zlib.json`.
#[derive(Deserialize)]
struct ZlibRecord {
    /// The inputs, each with its streams.
    inputs: Vec<ZlibInput>,
    /// The streams that are kept whole.
    whole: Vec<ZlibWhole>,
}

/// One input of the record of zlib.
#[derive(Deserialize)]
struct ZlibInput {
    /// The name of the input.
    input: String,
    /// Its length.
    length: usize,
    /// Its SHA-256.
    sha256: String,
    /// Each stream zlib makes of it: the length, the SHA-256, and the settings that give it.
    streams: Vec<(usize, String, Vec<u16>)>,
}

/// One stream of zlib that is kept whole.
#[derive(Deserialize)]
struct ZlibWhole {
    /// The name of the input.
    input: String,
    /// The setting.
    setting: u16,
    /// The stream, in hex.
    stream: String,
}

/// `tests/packers/infozip.json`.
#[derive(Deserialize)]
struct ZipRecord {
    /// The inputs, each with its streams.
    inputs: Vec<ZipInput>,
    /// The streams that are kept whole.
    whole: Vec<ZipWhole>,
}

/// One input of the record of zip.
#[derive(Deserialize)]
struct ZipInput {
    /// The name of the input.
    input: String,
    /// Its length.
    length: usize,
    /// Its SHA-256.
    sha256: String,
    /// For each level: the level, 1 where zip stores the input in an archive that is a file,
    /// and the length and the SHA-256 of the stream it writes to a pipe. zip writes no
    /// stream for the empty input.
    cases: Vec<(u8, u8, Option<usize>, Option<String>)>,
}

/// One stream of zip that is kept whole.
#[derive(Deserialize)]
struct ZipWhole {
    /// The name of the input.
    input: String,
    /// The level.
    level: u8,
    /// zip stores the input in an archive that is a file.
    stored: bool,
    /// The stream, in hex.
    stream: String,
}

/// The record of zlib.
fn zlib_record() -> ZlibRecord {
    serde_json::from_str(&std::fs::read_to_string("tests/packers/zlib.json").unwrap()).unwrap()
}

/// The record of zip.
fn zip_record() -> ZipRecord {
    serde_json::from_str(&std::fs::read_to_string("tests/packers/infozip.json").unwrap()).unwrap()
}

/// The packer of a setting of the record of zlib: three digits, the level, the memory level
/// and the strategy.
fn zlib_packer(setting: u16) -> Packer {
    let digit = |place: u16| u8::try_from(setting / place % 10).unwrap();
    let strategy = match digit(1) {
        0 => Strategy::Default,
        1 => Strategy::Filtered,
        2 => Strategy::HuffmanOnly,
        3 => Strategy::Rle,
        4 => Strategy::Fixed,
        other => panic!("no strategy {other}"),
    };
    Packer::Zlib { level: digit(100), mem_level: digit(10), strategy }
}

/// The SHA-256 of some bytes, in hex.
fn sha256(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The input of a name, held to the length and the SHA-256 that the record has of it: the
/// generators here and those of the recording must not drift apart.
fn checked_input(name: &str, length: usize, digest: &str) -> Vec<u8> {
    let data = make(name);
    assert_eq!(data.len(), length, "{name}: the input is not as long as the recorded one");
    assert_eq!(sha256(&data), digest, "{name}: the input is not the recorded one");
    data
}

/// What is wrong with a stream, if anything: it is not the recorded one, or it does not
/// unpack to its input.
fn fault(packer: Packer, data: &[u8], stream: &[u8], length: usize, digest: &str) -> Option<String> {
    if stream.len() != length || sha256(stream) != digest {
        return Some(format!("{}: {} bytes, and the program wrote {length}", packer.name(), stream.len()));
    }
    let mut unpacked = Vec::with_capacity(data.len());
    let read = DeflateDecoder::new(stream).read_to_end(&mut unpacked);
    (read.is_err() || unpacked != data).then(|| format!("{}: the stream does not unpack to its input", packer.name()))
}

/// Compares the packer with the record of zlib, for the settings of each input that
/// `wanted` says yes to, given the length of the input and the setting. Returns the number
/// of cases compared.
fn compare_zlib(wanted: impl Fn(usize, u16) -> bool + Sync) -> usize {
    let record = zlib_record();
    let mut compared = 0;
    let mut faults = Vec::new();
    for input in &record.inputs {
        let cases: Vec<(u16, usize, &str)> = input.streams.iter().flat_map(|(length, digest, settings)| settings.iter().map(move |setting| (*setting, *length, digest.as_str()))).filter(|case| wanted(input.length, case.0)).collect();
        if cases.is_empty() {
            continue;
        }
        let data = checked_input(&input.input, input.length, &input.sha256);
        compared += cases.len();
        faults.par_extend(cases.par_iter().filter_map(|&(setting, length, digest)| {
            let packer = zlib_packer(setting);
            let (stream, method) = packer.pack_entry(&data);
            assert_eq!(method, Method::Deflate, "zlib has no rule that stores a file");
            fault(packer, &data, &stream, length, digest).map(|what| format!("{}: {what}", input.input))
        }));
    }
    assert!(faults.is_empty(), "{} of {compared} streams are not those of zlib:\n{}", faults.len(), faults.join("\n"));
    compared
}

/// Compares the packer with the record of zip, for the levels of each input that `wanted`
/// says yes to, given the length of the input and the level. Returns the number of cases
/// compared.
fn compare_zip(wanted: impl Fn(usize, u8) -> bool + Sync) -> usize {
    let record = zip_record();
    let mut compared = 0;
    let mut faults = Vec::new();
    for input in &record.inputs {
        let cases: Vec<&(u8, u8, Option<usize>, Option<String>)> = input.cases.iter().filter(|case| wanted(input.length, case.0)).collect();
        if cases.is_empty() {
            continue;
        }
        let data = checked_input(&input.input, input.length, &input.sha256);
        compared += cases.len();
        faults.par_extend(cases.par_iter().filter_map(|(level, stored, length, digest)| {
            let packer = Packer::InfoZip { level: *level };
            let (stream, method) = packer.pack_entry(&data);
            let stores = if *stored == 1 { Method::Store } else { Method::Deflate };
            if method != stores {
                return Some(format!("{}: {}: {method:?}, and zip chose {stores:?}", input.input, packer.name()));
            }
            // zip writes no stream at all for the empty input
            let (Some(length), Some(digest)) = (length, digest) else { return None };
            fault(packer, &data, &stream, *length, digest).map(|what| format!("{}: {what}", input.input))
        }));
    }
    assert!(faults.is_empty(), "{} of {compared} streams are not those of zip:\n{}", faults.len(), faults.join("\n"));
    compared
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

/// The settings of zlib that the default run compares for an input of a length: every
/// setting for the small inputs, every level at three memory levels for the next, and for
/// the rest some twenty that between them use every level and every strategy.
fn in_default_run(length: usize, setting: u16) -> bool {
    match length {
        0..=1_000 => true,
        1_001..=12_000 => matches!(setting / 10 % 10, 1 | 8 | 9),
        12_001..=200_000 => matches!(setting, 180 | 280 | 380 | 480 | 580 | 680 | 780 | 880 | 980 | 190 | 690 | 990 | 310 | 481 | 681 | 981 | 682 | 692 | 683 | 184 | 684),
        200_001..=500_000 => matches!(setting, 180 | 680 | 980),
        _ => false,
    }
}

/// zlib at its default strategy, for the part of the record that the default run takes.
#[test]
fn zlib_streams_of_the_default_strategy() {
    assert_eq!(compare_zlib(|length, setting| setting % 10 == 0 && in_default_run(length, setting)), 884);
}

/// zlib at the strategy that takes no short matches, for the same part.
#[test]
fn zlib_streams_of_the_filtered_strategy() {
    assert_eq!(compare_zlib(|length, setting| setting % 10 == 1 && in_default_run(length, setting)), 825);
}

/// zlib at the two strategies without a search for matches, for the same part.
#[test]
fn zlib_streams_of_the_huffman_and_rle_strategies() {
    assert_eq!(compare_zlib(|length, setting| matches!(setting % 10, 2 | 3) && in_default_run(length, setting)), 1635);
}

/// zlib at the strategy with the fixed codes, for the same part.
#[test]
fn zlib_streams_of_the_fixed_strategy() {
    assert_eq!(compare_zlib(|length, setting| setting % 10 == 4 && in_default_run(length, setting)), 820);
}

/// Every stream of the record of zlib: 27 inputs, each at 405 settings.
#[test]
#[ignore = "12 s on 16 threads when optimised, and minutes when not: run with --release"]
fn zlib_streams_all() {
    assert_eq!(compare_zlib(|_, _| true), 27 * 405);
}

/// zip at every level for the inputs up to 200,000 bytes, and at two levels for those up to
/// 700,000: one without and one with lazy matching, both with the guess that ends a block.
#[test]
fn info_zip_streams() {
    let compared = compare_zip(|length, level| match length {
        0..=200_000 => true,
        200_001..=700_000 => matches!(level, 3 | 6),
        _ => false,
    });
    assert_eq!(compared, 179);
}

/// Every stream of the record of zip: 27 inputs, each at nine levels.
#[test]
#[ignore = "a second when optimised, and a minute when not: run with --release"]
fn info_zip_streams_all() {
    assert_eq!(compare_zip(|_, _| true), 27 * 9);
}

/// The streams that the records keep whole, byte for byte.
#[test]
fn whole_streams() {
    let zlib = zlib_record();
    assert!(zlib.whole.len() >= 8);
    for case in &zlib.whole {
        let packer = zlib_packer(case.setting);
        assert_eq!(hex::encode(packer.pack(&make(&case.input))), case.stream, "{}: {}", case.input, packer.name());
    }
    let zip = zip_record();
    assert!(zip.whole.len() >= 8);
    for case in &zip.whole {
        let packer = Packer::InfoZip { level: case.level };
        let (stream, method) = packer.pack_entry(&make(&case.input));
        assert_eq!(hex::encode(stream), case.stream, "{}: {}", case.input, packer.name());
        assert_eq!(method == Method::Store, case.stored, "{}: {}", case.input, packer.name());
    }
}

/// The stream does not depend on how the input is cut: pieces of odd sizes give what one
/// piece gives. Among the sizes are those at which `deflate` of zlib slides its window early.
#[test]
fn update_in_pieces_gives_the_stream_of_one_piece() {
    let packers = [
        Packer::Zlib { level: 6, mem_level: 8, strategy: Strategy::Default },
        Packer::Zlib { level: 1, mem_level: 9, strategy: Strategy::Default },
        Packer::Zlib { level: 4, mem_level: 1, strategy: Strategy::Filtered },
        Packer::Zlib { level: 6, mem_level: 9, strategy: Strategy::HuffmanOnly },
        Packer::Zlib { level: 6, mem_level: 8, strategy: Strategy::Rle },
        Packer::Zlib { level: 9, mem_level: 8, strategy: Strategy::Fixed },
        Packer::InfoZip { level: 1 },
        Packer::InfoZip { level: 9 },
    ];
    let data = make("mix:150000:14");
    let cuts: [&[usize]; 5] = [&[1], &[7, 262, 3], &[4099], &[65_274, 261, 1, 65_300], &[32_768, 32_506, 263, 65_535]];
    for packer in packers {
        let whole = packer.pack(&data);
        for sizes in cuts {
            let mut stream = Vec::new();
            let mut deflater = Deflater::new(packer);
            let mut rest = data.as_slice();
            for size in sizes.iter().cycle() {
                if rest.is_empty() {
                    break;
                }
                let (piece, after) = rest.split_at((*size).min(rest.len()));
                deflater.update(piece, &mut stream);
                rest = after;
            }
            let _: Method = deflater.finish(&mut stream);
            assert!(stream == whole, "{}: pieces of {sizes:?} give another stream", packer.name());
        }
    }
}

/// The case in which zlib itself gives another stream when the input is cut: 100,000 random
/// bytes without a search for matches, at memory level 9, cut at 65,300. zlib slides its
/// window at the cut, and can then no longer store the block that starts before it. The
/// packer gives the stream of one call, which is the recorded one.
#[test]
fn a_cut_where_zlib_slides_early_changes_nothing() {
    let record = zlib_record();
    let input = record.inputs.iter().find(|input| input.input == "random:100000:12").unwrap();
    let (length, digest, _) = input.streams.iter().find(|(_, _, settings)| settings.contains(&692)).unwrap();
    let data = make(&input.input);
    let mut stream = Vec::new();
    let mut deflater = Deflater::new(zlib_packer(692));
    deflater.update(&data[..65_300], &mut stream);
    deflater.update(&data[65_300..], &mut stream);
    assert_eq!(deflater.finish(&mut stream), Method::Deflate);
    assert_eq!((stream.len(), sha256(&stream)), (*length, digest.clone()));
}

/// The names of the packers, and the settings that are out of range.
#[test]
fn names_and_settings_out_of_range() {
    assert_eq!(Packer::Zlib { level: 6, mem_level: 8, strategy: Strategy::Default }.name(), "zlib level 6, memory level 8");
    assert_eq!(Packer::Zlib { level: 9, mem_level: 9, strategy: Strategy::Filtered }.name(), "zlib level 9, memory level 9, strategy filtered");
    assert_eq!(Packer::Zlib { level: 1, mem_level: 1, strategy: Strategy::HuffmanOnly }.name(), "zlib level 1, memory level 1, strategy Huffman only");
    assert_eq!(Packer::Zlib { level: 2, mem_level: 3, strategy: Strategy::Rle }.name(), "zlib level 2, memory level 3, strategy RLE");
    assert_eq!(Packer::Zlib { level: 3, mem_level: 4, strategy: Strategy::Fixed }.name(), "zlib level 3, memory level 4, strategy fixed");
    assert_eq!(Packer::InfoZip { level: 9 }.name(), "Info-ZIP level 9");

    // a level or a memory level outside 1 to 9 is the nearest inside
    let data = make("text:5000:8");
    let streams: HashMap<&str, Vec<u8>> = HashMap::from([
        ("zlib 1", Packer::Zlib { level: 1, mem_level: 1, strategy: Strategy::Default }.pack(&data)),
        ("zlib 9", Packer::Zlib { level: 9, mem_level: 9, strategy: Strategy::Default }.pack(&data)),
        ("zip 1", Packer::InfoZip { level: 1 }.pack(&data)),
        ("zip 9", Packer::InfoZip { level: 9 }.pack(&data)),
    ]);
    assert_eq!(Packer::Zlib { level: 0, mem_level: 0, strategy: Strategy::Default }.pack(&data), streams["zlib 1"]);
    assert_eq!(Packer::Zlib { level: 200, mem_level: 10, strategy: Strategy::Default }.pack(&data), streams["zlib 9"]);
    assert_eq!(Packer::Zlib { level: 0, mem_level: 0, strategy: Strategy::Default }.name(), "zlib level 1, memory level 1");
    assert_eq!(Packer::InfoZip { level: 0 }.pack(&data), streams["zip 1"]);
    assert_eq!(Packer::InfoZip { level: 10 }.pack(&data), streams["zip 9"]);
    assert_eq!(Packer::InfoZip { level: 10 }.name(), "Info-ZIP level 9");
    assert_ne!(streams["zlib 1"], streams["zlib 9"]);
    assert_ne!(streams["zip 1"], streams["zip 9"]);
}

/// What zip puts into the archive: the input itself where one block of it is not smaller
/// than the input, the stream otherwise. zlib has no such rule.
#[test]
fn info_zip_stores_what_does_not_pack() {
    let random = make("random:1000:6");
    let (stream, method) = Packer::InfoZip { level: 6 }.pack_entry(&random);
    assert_eq!(method, Method::Store);
    assert_eq!(stream.len(), random.len() + 5, "the stream is one stored block all the same");
    assert_eq!(Packer::Zlib { level: 6, mem_level: 9, strategy: Strategy::Default }.pack_entry(&random).1, Method::Deflate);

    // nothing at all packs to the two bytes of an empty block, which are more than nothing
    assert_eq!(Packer::InfoZip { level: 6 }.pack_entry(&[]), (vec![0x03, 0x00], Method::Store));
    assert_eq!(Packer::Zlib { level: 6, mem_level: 8, strategy: Strategy::Default }.pack_entry(&[]), (vec![0x03, 0x00], Method::Deflate));

    // text packs, and random bytes that take more than one block are never stored
    assert_eq!(Packer::InfoZip { level: 6 }.pack_entry(&make("text:5000:8")).1, Method::Deflate);
    let long = make("random:100000:12");
    let (stream, method) = Packer::InfoZip { level: 1 }.pack_entry(&long);
    assert_eq!(method, Method::Deflate);
    assert!(stream.len() > long.len());
}
