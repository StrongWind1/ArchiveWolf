//! The `$7z$*` hash line, hashcat mode 46900.
//!
//! ```text
//! $7z$*power*salt*crc32*crc_len*join*N*stream_1*...*stream_N$/7z$
//!
//! stream  =  iv*packed*unpacked*chain*data
//! ```
//!
//! A 7z archive stores nothing that says whether a password is right, so a line carries what a
//! candidate has to decrypt and unpack: every packed stream of one folder with its own
//! initialisation vector, the coders that run on it, and the CRC-32 of what comes out.
//!
//! A chain is a list of coders separated by commas. A coder is `id/properties/size`, the id and
//! the properties in hex as the archive stores them and the size of its output in hex.
//!
//! This is the same reading of an archive as `tools/7z2hashcat.py` in the hashcat tree, and the two
//! write the same lines.
//!
//! What a line carries is decided from the header alone ([`plan`]): which folder, how much of
//! each stream, and what a password is then tested on. The data is read only for the folders
//! whose lines are written, a stream at a time and never more than a line carries. A line is
//! planned only when mode 46900 loads it and can confirm a password with it: the limits of
//! the mode (`src/modules/module_46900.c` and `sevenzip_decode.c` in the hashcat tree) are
//! held here as the constants named `MODE_...`.

use std::fmt::Write as _;
use std::io::ErrorKind;

use super::reader::Archive;
use super::reader::Chain;
use super::reader::Folder;
use super::reader::Headers;
use super::reader::ID_AES;
use super::reader::ID_COPY;
use super::reader::ID_LZMA;
use super::reader::ID_LZMA2;
use crate::analysis::NoLine;
use crate::analysis::Untestable;
use crate::formats::source::Source;
use crate::line::NoCrc;

const ID_DELTA: &[u8] = &[0x03];
const ID_ARM64: &[u8] = &[0x0A];
const ID_RISCV: &[u8] = &[0x0B];
const ID_SWAP2: &[u8] = &[0x02, 0x03, 0x02];
const ID_SWAP4: &[u8] = &[0x02, 0x03, 0x04];
const ID_PPMD: &[u8] = &[0x03, 0x04, 0x01];
const ID_BCJ: &[u8] = &[0x03, 0x03, 0x01, 0x03];
const ID_BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1B];
const ID_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
const ID_IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
const ID_ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
const ID_ARMT: &[u8] = &[0x03, 0x03, 0x07, 0x01];
const ID_SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];
const ID_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
const ID_DEFLATE64: &[u8] = &[0x04, 0x01, 0x09];
const ID_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
const ID_ZSTD: &[u8] = &[0x04, 0xF7, 0x11, 0x01];

const COMPRESSORS: [&[u8]; 7] = [ID_LZMA, ID_LZMA2, ID_PPMD, ID_DEFLATE, ID_DEFLATE64, ID_BZIP2, ID_ZSTD];
const FILTERS: [&[u8]; 11] = [ID_DELTA, ID_ARM64, ID_RISCV, ID_SWAP2, ID_SWAP4, ID_BCJ, ID_PPC, ID_IA64, ID_ARM, ID_ARMT, ID_SPARC];

/// The filters that take no properties, or four bytes: where the code starts.
const BRANCH_FILTERS: [&[u8]; 8] = [ID_ARM64, ID_RISCV, ID_BCJ, ID_PPC, ID_IA64, ID_ARM, ID_ARMT, ID_SPARC];

/// The start of these streams says something about the key: random bytes are not one of them for
/// more than a few bytes. A `PPMd` stream takes anything, stored data is anything, and the library
/// hashcat unpacks Zstandard with does not say how far it came.
const START_TELLS: [&[u8]; 5] = [ID_LZMA, ID_LZMA2, ID_DEFLATE, ID_DEFLATE64, ID_BZIP2];

/// Of these, the ones whose start is a test only when a full megabyte of it is there.
const START_NEEDS_ALL: [&[u8]; 3] = [ID_LZMA2, ID_DEFLATE, ID_DEFLATE64];

const AES_BLOCK: u64 = 16;

/// The value of `NumCyclesPower` that stands for no key derivation: the key is the password.
pub(crate) const POWER_NO_DERIVATION: u8 = 0x3F;

/// The most rounds 7-Zip derives a key with, as a power of two.
const MAX_POWER: u8 = 24;

/// The most data of one stream a line carries.
const MAX_INLINE_DATA: u64 = 4 * 1024 * 1024;

/// How much of a stream a line carries when it can only test the start.
const START_DATA: u64 = 1024 * 1024;

/// hashcat unpacks a candidate to at most this many bytes (`SZ_OUT_MAX`).
const MAX_UNPACK: u64 = 64 * 1024 * 1024;

/// A branch converter looks this far past the bytes it has been asked for.
const FILTER_LOOKAHEAD: u64 = 16;

/// The most data the mode reads from one line, over all its streams (`SZ_DATA_MAX`).
const MODE_MAX_DATA: u64 = 0x7F_F000;

/// The most coders the mode takes in one chain (`SZ_CHAIN_MAX`).
const MODE_MAX_CHAIN: usize = 8;

/// The most bytes of properties the mode stores for one coder (`SZ_PROPS_MAX`).
const MODE_MAX_PROPS: usize = 16;

/// The largest `PPMd` model the mode gives a candidate (`SZ_PPMD_MEM_MAX`).
const MODE_MAX_PPMD_MEMORY: u32 = 256 * 1024 * 1024;

/// The smallest `PPMd` model, and the orders, that the coder itself takes.
const PPMD_MIN_MEMORY: u32 = 1 << 11;
const PPMD_ORDERS: std::ops::RangeInclusive<u8> = 2..=64;

/// A CRC-32 over fewer bytes than this proves no more than the bytes themselves.
const FULL_CRC_BYTES: u64 = 4;

/// The most text of lines that is held for one archive. `hash --all` asks for a line of every
/// folder, and an archive can have a great many folders of megabytes each.
pub(crate) const MAX_LINES_TEXT: u64 = 1 << 27;

/// What a line rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proof {
    /// The CRC-32 of what the folder unpacks to.
    Crc,
    /// What is unpacked is the header of an archive.
    Header,
    /// The stream unpacks to its size and ends there.
    End,
    /// The start of the stream unpacks without an error.
    Start,
}

/// The properties of the 7zAES coder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Key<'a> {
    /// `NumCyclesPower` of the key derivation.
    pub power: u8,
    /// Salt of the key derivation, usually empty.
    pub salt: &'a [u8],
    /// Initialisation vector, as many bytes as the archive stores.
    pub iv: &'a [u8],
}

/// Split the properties of the 7zAES coder into power, salt and initialisation vector. `None`
/// when they are missing or cut short.
pub(crate) fn aes_properties(props: &[u8]) -> Option<Key<'_>> {
    let &first = props.first()?;
    let power = first & 0x3F;
    if first & 0xC0 == 0 {
        return Some(Key { power, salt: &[], iv: &[] });
    }
    let &second = props.get(1)?;
    let salt_end = 2 + usize::from((first >> 7) & 1) + usize::from(second >> 4);
    let iv_end = salt_end + usize::from((first >> 6) & 1) + usize::from(second & 0x0F);
    Some(Key { power, salt: props.get(2..salt_end)?, iv: props.get(salt_end..iv_end)? })
}

/// A coder as a line names it.
#[derive(Debug, Clone, Copy)]
struct ChainCoder<'a> {
    /// The id the archive stores.
    id: &'a [u8],
    /// The properties the archive stores.
    props: &'a [u8],
    /// Size of what the coder puts out.
    size: u64,
}

/// One packed stream of a folder, ready for the line.
#[derive(Debug, Clone)]
struct Stream<'a> {
    /// The properties of its 7zAES coder.
    key: Key<'a>,
    /// Where the stream starts in the archive.
    offset: u64,
    /// Size of the encrypted stream.
    packed: u64,
    /// Size of what it decrypts to.
    unpacked: u64,
    /// The coders that run on this stream after decryption, in that order.
    chain: Vec<ChainCoder<'a>>,
    /// How many bytes of it the line carries.
    take: u64,
}

/// Everything a line carries, and what a password is tested on.
#[derive(Debug, Clone)]
pub(crate) struct Plan<'a> {
    /// The packed streams, one, or four for BCJ2.
    streams: Vec<Stream<'a>>,
    /// The coders that run after the streams have been joined.
    join: Vec<ChainCoder<'a>>,
    /// CRC-32 of the first `crc_len` bytes the folder unpacks to.
    crc: Option<u32>,
    /// How many bytes the CRC-32 covers.
    pub crc_len: u64,
    /// The number of the folder in the archive.
    pub folder: usize,
    /// What the line rests on.
    pub proof: Proof,
    /// Why that is not the CRC-32 of the folder, when it is not.
    pub why: Option<NoCrc>,
}

impl Plan<'_> {
    /// How many bits a wrong password has to match when the line rests on a CRC-32 over fewer
    /// than four bytes. `None` for every other line.
    pub(crate) fn weak_bits(&self) -> Option<u32> {
        (self.proof == Proof::Crc && self.crc_len < FULL_CRC_BYTES).then(|| u32::try_from(self.crc_len.saturating_mul(8)).unwrap_or(u32::MAX))
    }

    /// Where the folder stands among the folders of its archive, the best first: the line
    /// that proves most, then the one that costs a cracker least. A CRC-32 over four bytes or
    /// more, a stream that has to end where it should, the start of a stream, and last a
    /// CRC-32 over less than four bytes; then one stream before four, the smallest first file,
    /// and the smallest packed size.
    fn rank(&self) -> (u8, usize, u64, u64) {
        let class = match self.proof {
            Proof::Crc if self.weak_bits().is_none() => 0,
            Proof::Header | Proof::End => 1,
            Proof::Start => 2,
            Proof::Crc => 3,
        };
        (class, self.streams.len(), self.crc_len, self.streams.iter().fold(0, |sum, stream| sum.saturating_add(stream.packed)))
    }

    /// How many bytes the text of the line takes, near enough: two for every byte of data.
    fn text_size(&self) -> u64 {
        self.streams.iter().fold(0, |sum, stream| sum.saturating_add(stream.take.saturating_mul(2)))
    }
}

/// One line that was built.
#[derive(Debug, Clone)]
pub(crate) struct BuiltLine {
    /// The number of the folder it is built from.
    pub folder: usize,
    /// The line.
    pub text: String,
    /// What it rests on.
    pub proof: Proof,
    /// Why that is not the CRC-32 of the folder, when it is not.
    pub why: Option<NoCrc>,
    /// How many bits a wrong password has to match, when the CRC-32 covers fewer than four
    /// bytes.
    pub weak_bits: Option<u32>,
    /// How many bytes the CRC-32 covers.
    pub crc_len: u64,
}

/// The lines of an archive, and the folders that were asked for one and gave none.
#[derive(Debug, Clone, Default)]
pub(crate) struct Built {
    /// The lines, in the order `hash` writes them.
    pub lines: Vec<BuiltLine>,
    /// The folders without a line, by number, and the case each is.
    pub refused: Vec<(usize, NoLine)>,
}

fn is_packer(id: &[u8]) -> bool {
    COMPRESSORS.contains(&id)
}

fn is_filter(id: &[u8]) -> bool {
    FILTERS.contains(&id)
}

/// The name of a coder as people write it, or its identifier in hex.
pub(crate) fn coder_name(id: &[u8]) -> String {
    const NAMES: [(&[u8], &str); 20] = [
        (ID_COPY, "stored"),
        (ID_LZMA, "LZMA"),
        (ID_LZMA2, "LZMA2"),
        (ID_PPMD, "PPMd"),
        (ID_DEFLATE, "Deflate"),
        (ID_DEFLATE64, "Deflate64"),
        (ID_BZIP2, "BZip2"),
        (ID_ZSTD, "Zstandard"),
        (ID_DELTA, "Delta"),
        (ID_BCJ, "BCJ"),
        (ID_BCJ2, "BCJ2"),
        (ID_PPC, "PPC"),
        (ID_IA64, "IA64"),
        (ID_ARM, "ARM"),
        (ID_ARMT, "ARMT"),
        (ID_SPARC, "SPARC"),
        (ID_ARM64, "ARM64"),
        (ID_RISCV, "RISCV"),
        (ID_SWAP2, "Swap2"),
        (ID_SWAP4, "Swap4"),
    ];
    NAMES.iter().find(|(known, _)| *known == id).map_or_else(|| hex::encode(id), |(_, name)| (*name).to_owned())
}

fn chain_coder<'a>(folder: &Folder<'a>, chain: &Chain<'a>, index: usize) -> Result<ChainCoder<'a>, NoLine> {
    let coder = chain.coders.get(index).ok_or(NoLine::Unreadable)?;
    let size = folder.sizes().get(index).copied().ok_or(NoLine::Unreadable)?;
    Ok(ChainCoder { id: coder.id, props: coder.props, size })
}

/// Walk from one input, or from a coder, down to the packed stream that feeds it.
fn branch<'a>(folder: &Folder<'a>, chain: &Chain<'a>, start_coder: Option<usize>, start_input: usize) -> Result<Stream<'a>, NoLine> {
    let mut path: Vec<usize> = Vec::new();
    let mut source = start_input;

    if let Some(index) = start_coder {
        path.push(index);
        source = chain.first_input(index).ok_or(NoLine::Unreadable)?;
    }

    // no coder feeds two inputs, so the way down passes each coder once at the most
    let mut pack_number = None;
    for _ in 0..=chain.coders.len() {
        if let Some(number) = chain.pack_of(source) {
            pack_number = Some(number);
            break;
        }
        let index = chain.feeder(source).ok_or(NoLine::Unreadable)?;
        if chain.coders.get(index).ok_or(NoLine::Unreadable)?.inputs != 1 {
            return Err(NoLine::JoinedTwice);
        }
        path.push(index);
        source = chain.first_input(index).ok_or(NoLine::Unreadable)?;
    }
    let pack_number = pack_number.ok_or(NoLine::Unreadable)?;

    let is_aes = |index: &usize| chain.coders.get(*index).is_some_and(|coder| coder.id == ID_AES);

    let Some((&aes, before)) = path.split_last().filter(|(last, _)| is_aes(last)) else {
        return Err(NoLine::StreamNotEncryptedLast);
    };
    if before.iter().any(is_aes) {
        return Err(NoLine::EncryptedTwice);
    }

    let key = aes_properties(chain.coders.get(aes).ok_or(NoLine::Unreadable)?.props).ok_or(NoLine::CoderProperties)?;
    // a packed stream at a position no file reaches is not in this one
    let (offset, packed) = folder.pack(pack_number).ok_or(NoLine::DataOutsideFile)?;
    let unpacked = folder.sizes().get(aes).copied().ok_or(NoLine::Unreadable)?;

    let mut decode = Vec::with_capacity(before.len());
    for &index in before.iter().rev() {
        let coder = chain_coder(folder, chain, index)?;
        if coder.id != ID_COPY {
            decode.push(coder);
        }
    }

    Ok(Stream { key, offset, packed, unpacked, chain: decode, take: 0 })
}

/// Follow the connections of a folder from its output back to its packed streams.
///
/// Returns the packed streams, each with the coders that run on it alone, and the coders that run
/// after the streams have been joined.
fn resolve<'a>(folder: &Folder<'a>, chain: &Chain<'a>) -> Result<(Vec<Stream<'a>>, Vec<ChainCoder<'a>>), NoLine> {
    // the path from the output down to the coder that takes more than one stream, if there is one
    let mut tail: Vec<usize> = Vec::new();
    let mut index = chain.main;
    for _ in 0..chain.coders.len() {
        let coder = chain.coders.get(index).ok_or(NoLine::Unreadable)?;
        let first_input = chain.first_input(index).ok_or(NoLine::Unreadable)?;
        let Some(feeder) = chain.feeder(first_input) else {
            break;
        };
        if coder.inputs != 1 {
            break;
        }
        tail.push(index);
        index = feeder;
    }

    let joiner = chain.coders.get(index).ok_or(NoLine::Unreadable)?;

    if joiner.inputs == 1 {
        return Ok((vec![branch(folder, chain, Some(chain.main), 0)?], Vec::new()));
    }

    let is_aes = |i: &usize| chain.coders.get(*i).is_some_and(|coder| coder.id == ID_AES);
    if is_aes(&index) || tail.iter().any(is_aes) {
        return Err(NoLine::EncryptedAfterJoin);
    }

    let first_input = chain.first_input(index).ok_or(NoLine::Unreadable)?;
    let mut found = Vec::with_capacity(joiner.inputs);
    for n in 0..joiner.inputs {
        found.push(branch(folder, chain, None, first_input.saturating_add(n))?);
    }

    let mut join = vec![chain_coder(folder, chain, index)?];
    for &i in tail.iter().rev() {
        let coder = chain_coder(folder, chain, i)?;
        if coder.id != ID_COPY {
            join.push(coder);
        }
    }

    Ok((found, join))
}

/// How many packed bytes the first `wanted` unpacked bytes can take up at the very most.
fn worst_case(id: &[u8], wanted: u64) -> u64 {
    let more = if id == ID_LZMA || id == ID_LZMA2 {
        // the bound the LZMA encoder itself gives for data that does not compress
        wanted / 3 + 128 + 64
    } else if id == ID_DEFLATE || id == ID_DEFLATE64 {
        // a rare literal costs up to 15 bits, and a block starts with its code tables
        wanted.saturating_add(1024)
    } else if id == ID_BZIP2 {
        // nothing comes out before a whole block of up to 900,000 bytes has gone in
        wanted / 50 + 920_000
    } else if id == ID_ZSTD {
        // nothing comes out before a whole block of up to 128 KiB has gone in
        wanted / 1000 + 131_072 + 64
    } else {
        // stored data. PPMd has no bound worth the name and never gets here
        0
    };
    wanted.saturating_add(more)
}

/// Whether the properties of a coder are ones the coder takes, as hashcat reads them: a coder
/// that is handed anything else unpacks nothing, whatever the key.
fn properties_fit(coder: &ChainCoder<'_>) -> Result<(), NoLine> {
    let (id, props) = (coder.id, coder.props);
    let fit = if id == ID_LZMA {
        // lc, lp and pb in one byte, then the dictionary
        props.len() >= 5 && props.first().is_some_and(|&model| model < 225)
    } else if id == ID_LZMA2 {
        matches!(props, [dictionary] if *dictionary <= 40)
    } else if id == ID_PPMD {
        let memory = props.get(1..5).and_then(|bytes| <[u8; 4]>::try_from(bytes).ok()).map(u32::from_le_bytes);
        match (props.first(), memory) {
            (Some(order), Some(memory)) if PPMD_ORDERS.contains(order) && memory >= PPMD_MIN_MEMORY => {
                if memory > MODE_MAX_PPMD_MEMORY {
                    return Err(NoLine::PpmdMemory { memory, limit: MODE_MAX_PPMD_MEMORY });
                }
                true
            },
            _ => false,
        }
    } else if id == ID_DELTA {
        props.len() == 1
    } else if BRANCH_FILTERS.contains(&id) {
        props.is_empty() || props.len() == 4
    } else {
        true
    };
    if !fit {
        return Err(NoLine::PropertiesInvalid { coder: coder_name(id) });
    }
    if props.len() > MODE_MAX_PROPS {
        return Err(NoLine::PropertiesTooLong { coder: coder_name(id), len: props.len(), limit: MODE_MAX_PROPS });
    }
    Ok(())
}

/// Hold one chain of coders against what the mode takes: its length, its coders and their
/// properties, and how much a coder that feeds another has to unpack.
fn chain_fits(chain: &[ChainCoder<'_>]) -> Result<(), NoLine> {
    for coder in chain {
        if !is_packer(coder.id) && !is_filter(coder.id) && coder.id != ID_BCJ2 {
            return Err(NoLine::Coder { id: hex::encode(coder.id) });
        }
    }
    if chain.len() > MODE_MAX_CHAIN {
        return Err(NoLine::TooManyCoders { count: chain.len(), limit: MODE_MAX_CHAIN });
    }
    for (place, coder) in chain.iter().enumerate() {
        properties_fit(coder)?;
        // a packer that feeds another one is unpacked in full
        let feeds = is_packer(coder.id) && chain.iter().skip(place.saturating_add(1)).any(|later| is_packer(later.id));
        if feeds && coder.size == 0 {
            return Err(NoLine::SizesDisagree);
        }
        if feeds && coder.size > MAX_UNPACK {
            return Err(NoLine::UnpacksTooMuch { size: coder.size, limit: MAX_UNPACK });
        }
    }
    Ok(())
}

/// What the streams of a folder and their coders have to be for the mode to load the line.
fn shape_fits(found: &[Stream<'_>], join: &[ChainCoder<'_>]) -> Result<(), NoLine> {
    let joined = found.len() > 1;
    for stream in found {
        // BCJ2 leaves a stream empty when the code has no calls or no jumps to take out
        if joined && stream.packed == 0 && stream.unpacked == 0 && stream.chain.is_empty() {
            continue;
        }
        if stream.packed == 0 || !stream.packed.is_multiple_of(AES_BLOCK) {
            return Err(NoLine::NotWholeBlocks);
        }
        if stream.unpacked > stream.packed || stream.packed - stream.unpacked >= AES_BLOCK {
            return Err(NoLine::SizesDisagree);
        }
    }

    chain_fits(join)?;
    for stream in found {
        chain_fits(&stream.chain)?;
    }

    if joined && (found.len() != 4 || join.first().is_none_or(|coder| coder.id != ID_BCJ2)) {
        return Err(NoLine::JoinNotBcj2);
    }
    if !joined && found.iter().any(|stream| stream.chain.iter().any(|coder| coder.id == ID_BCJ2)) {
        return Err(NoLine::Bcj2OnOneStream);
    }
    // what runs after BCJ2 has put the streams together works in place: a filter
    if let Some(coder) = join.iter().skip(1).find(|coder| !is_filter(coder.id)) {
        return Err(NoLine::Coder { id: hex::encode(coder.id) });
    }
    Ok(())
}

/// What the line of a folder rests on, how many bytes of each stream it carries, and why that
/// is less than a CRC-32 when it is.
struct Taken {
    proof: Proof,
    why: Option<NoCrc>,
    takes: Vec<u64>,
}

/// Decide what the line of a folder with four streams carries: all of every stream, tested by
/// the CRC-32.
fn take_joined(found: &[Stream<'_>], unreachable: Option<NoCrc>) -> Result<Taken, NoLine> {
    if let Some(why) = unreachable {
        return Err(NoLine::Bcj2WithoutCrc(why));
    }
    let mut together = 0_u64;
    for stream in found {
        if stream.packed > MAX_INLINE_DATA {
            return Err(NoLine::Bcj2StreamTooLarge { packed: stream.packed, limit: MAX_INLINE_DATA });
        }
        // each stream is unpacked in full before the four are put together
        if let Some(last) = stream.chain.last().filter(|last| last.size > MAX_UNPACK) {
            return Err(NoLine::UnpacksTooMuch { size: last.size, limit: MAX_UNPACK });
        }
        together = together.saturating_add(stream.packed);
    }
    if together > MODE_MAX_DATA {
        return Err(NoLine::Bcj2TooLarge { packed: together, limit: MODE_MAX_DATA });
    }
    Ok(Taken { proof: Proof::Crc, why: None, takes: found.iter().map(|stream| stream.packed).collect() })
}

/// Decide what the line of a folder with one stream carries.
fn take_single(stream: &Stream<'_>, crc: Option<u32>, crc_len: u64, total: u64, header: bool, unreachable: Option<NoCrc>) -> Result<Taken, NoLine> {
    let taken = |take: u64, proof: Proof, why: Option<NoCrc>| Ok(Taken { proof, why, takes: vec![take] });

    // the coder that reads what was decrypted, as the mode sees it
    let compressor = stream.chain.first().map(|coder| coder.id).filter(|id| is_packer(id)).unwrap_or(ID_COPY);
    let packers = stream.chain.iter().filter(|coder| is_packer(coder.id)).count();
    let filtered = stream.chain.iter().any(|coder| is_filter(coder.id));
    let mut why = unreachable;

    if why.is_none() {
        let mut need = stream.packed;

        // The stream is cut when the CRC-32 covers the first file of several. Not a PPMd
        // stream, which has no bound, and not a chain the bound does not hold for: one that
        // does not start with its packer, or has a second one that needs all of the first.
        let cut = crc_len < total && compressor != ID_PPMD && packers <= 1 && stream.chain.first().is_none_or(|coder| is_packer(coder.id) || packers == 0);
        if cut {
            let wanted = crc_len.saturating_add(if filtered { FILTER_LOOKAHEAD } else { 0 });
            need = stream.packed.min(worst_case(compressor, wanted).div_ceil(AES_BLOCK).saturating_mul(AES_BLOCK));
        }

        if need <= MAX_INLINE_DATA {
            return taken(need, Proof::Crc, None);
        }

        why = Some(NoCrc::TooMuchToCarry { need, limit: MAX_INLINE_DATA });
    }
    // from here on the CRC-32 is out of reach, and `reason` says why
    let reason = why.unwrap_or(NoCrc::NotStored);

    // a header says by its structure whether it is one, however it is packed
    if header && crc.is_none() && stream.packed <= MAX_INLINE_DATA && total <= MAX_UNPACK {
        return taken(stream.packed, Proof::Header, why);
    }

    if compressor == ID_COPY {
        return Err(NoLine::NothingToTest { crc: reason, stream: Untestable::Stored });
    }

    // all of a stream that is short enough: it has to unpack to its size and end there
    if crc.is_none() && stream.packed <= MAX_INLINE_DATA && total <= MAX_UNPACK {
        return taken(stream.packed, Proof::End, why);
    }

    if !START_TELLS.contains(&compressor) {
        return Err(NoLine::NothingToTest { crc: reason, stream: Untestable::SilentStart { coder: coder_name(compressor) } });
    }

    // LZMA2 and Deflate can store data as it is, in chunks of up to 64 KiB that nothing checks. A
    // megabyte holds enough chunk headers for a wrong key to fail on one of them. Less does not.
    if START_NEEDS_ALL.contains(&compressor) && stream.packed < START_DATA {
        return Err(NoLine::NothingToTest { crc: reason, stream: Untestable::ShortStart { coder: coder_name(compressor), packed: stream.packed } });
    }

    taken(stream.packed.min(START_DATA), Proof::Start, why)
}

/// Decide what the line of a folder carries, from the header alone. `header` says that the
/// folder holds the header of the archive, and `file_len` how long the archive is.
///
/// The error is the case in which the folder has no line.
pub(crate) fn plan<'a>(folder: &Folder<'a>, header: bool, file_len: u64) -> Result<Plan<'a>, NoLine> {
    let chain = folder.chain().map_err(|_| NoLine::Unreadable)?;
    if chain.coders.iter().any(|coder| coder.is_cipher() && coder.id != ID_AES) {
        return Err(NoLine::UnknownScheme);
    }

    let total = folder.size();
    if total == 0 {
        return Err(NoLine::Empty);
    }

    let (mut found, join) = resolve(folder, &chain)?;

    let Some(first) = found.first() else {
        return Err(NoLine::NoPackedStream);
    };
    let key = first.key;
    if found.iter().any(|stream| stream.key.power != key.power || stream.key.salt != key.salt) {
        return Err(NoLine::SeveralKeys);
    }
    if key.power == POWER_NO_DERIVATION {
        return Err(NoLine::KeyIsPassword);
    }
    if key.power > MAX_POWER {
        return Err(NoLine::TooManyRounds { power: key.power });
    }

    shape_fits(&found, &join)?;

    // the CRC-32 of the first file when the folder holds one with data, of the folder otherwise
    let (crc, crc_len) = match folder.first_file() {
        Some((size, Some(value))) if size > 0 => (Some(value), size),
        _ => (folder.crc(), total),
    };
    let unreachable = match crc {
        None => Some(NoCrc::NotStored),
        Some(_) if crc_len.checked_add(FILTER_LOOKAHEAD).is_none_or(|unpacked| unpacked > MAX_UNPACK) => Some(NoCrc::TooMuchToUnpack { size: crc_len, limit: MAX_UNPACK }),
        Some(_) => None,
    };

    let taken = match found.as_slice() {
        [only] => take_single(only, crc, crc_len, total, header, unreachable)?,
        _ => take_joined(&found, unreachable)?,
    };

    // every stream lies in the file, to its end
    for (stream, &take) in found.iter_mut().zip(&taken.takes) {
        if stream.offset.checked_add(stream.packed).is_none_or(|end| end > file_len) {
            return Err(NoLine::DataOutsideFile);
        }
        stream.take = take;
    }

    Ok(Plan { streams: found, join, crc, crc_len, folder: folder.number, proof: taken.proof, why: taken.why })
}

fn show_chain(chain: &[ChainCoder<'_>]) -> String {
    chain.iter().map(|coder| format!("{}/{}/{:x}", hex::encode(coder.id), hex::encode(coder.props), coder.size)).collect::<Vec<_>>().join(",")
}

/// Build the line of a plan: read what it carries of each stream and write it out.
///
/// The inner error is the case of a stream that is not in the file after all. Any other failure
/// to read is an error of the run.
fn line_of(source: &Source, plan: &Plan<'_>) -> anyhow::Result<Result<BuiltLine, NoLine>> {
    let Some(first) = plan.streams.first() else {
        return Ok(Err(NoLine::NoPackedStream));
    };

    let mut taken = String::new();
    for stream in &plan.streams {
        let bytes = match source.read_at(stream.offset, stream.take) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(Err(NoLine::DataOutsideFile)),
            Err(error) => return Err(error.into()),
        };
        let _ = write!(taken, "*{}*{:x}*{:x}*{}*{}", hex::encode(stream.key.iv), stream.packed, stream.unpacked, show_chain(&stream.chain), hex::encode(bytes));
    }

    // a line that does not rest on the CRC-32 does not carry it: hashcat tests what the line holds
    let crc = match (plan.proof, plan.crc) {
        (Proof::Crc, Some(value)) => format!("{value:08x}"),
        (Proof::Header, _) => "header".to_owned(),
        _ => String::new(),
    };

    let text = format!("$7z$*{}*{}*{crc}*{:x}*{}*{}{taken}$/7z$", first.key.power, hex::encode(first.key.salt), plan.crc_len, show_chain(&plan.join), plan.streams.len());
    Ok(Ok(BuiltLine { folder: plan.folder, text, proof: plan.proof, why: plan.why, weak_bits: plan.weak_bits(), crc_len: plan.crc_len }))
}

/// The hash lines of an archive: one from the folder that ranks best, or one for every folder
/// (`all`). A folder that has no line is handed back with the case it is: the ones that are
/// refused from the header first, then the ones whose data could not be read or held.
///
/// Every encrypted folder is planned, which costs its few bytes of the header. What is kept
/// of a plan is where its folder stands; the data of a folder is read when its line is built.
pub(crate) fn hash_lines(source: &Source, archive: &Archive, all: bool) -> anyhow::Result<Built> {
    lines_within(source, archive, all, MAX_LINES_TEXT)
}

/// [`hash_lines`] with the most text of lines that is held.
fn lines_within(source: &Source, archive: &Archive, all: bool, budget: u64) -> anyhow::Result<Built> {
    let header = archive.headers == Headers::Encrypted;
    let mut built = Built::default();

    let mut ranked = Vec::new();
    for folder in archive.folders().filter(Folder::is_encrypted) {
        match plan(&folder, header, source.len()) {
            Ok(plan) => ranked.push((plan.rank(), folder.number)),
            Err(why) => built.refused.push((folder.number, why)),
        }
    }
    // folders that stand alike keep the order of the archive
    ranked.sort_unstable();

    let mut held = 0_u64;
    for (_, number) in ranked {
        let Some(folder) = archive.folder(number) else { continue };
        let plan = match plan(&folder, header, source.len()) {
            Ok(plan) => plan,
            Err(why) => {
                built.refused.push((number, why));
                continue;
            },
        };
        let size = plan.text_size();
        if !built.lines.is_empty() && held.saturating_add(size) > budget {
            built.refused.push((number, NoLine::LinesOverBudget { limit: budget }));
            continue;
        }
        match line_of(source, &plan)? {
            Ok(line) => {
                held = held.saturating_add(size);
                built.lines.push(line);
                if !all {
                    break;
                }
            },
            Err(why) => built.refused.push((number, why)),
        }
    }

    Ok(built)
}

/// Where a 7z archive starts in a file: at its signature, which a self-extracting archive has
/// behind a program. The scanner finds that place for a run; its tests hold this search to the
/// same answer.
#[cfg(test)]
pub(crate) fn archive_start(data: &[u8]) -> Option<usize> {
    use super::reader::SIGNATURE;

    let limit = data.len().min(crate::formats::SFX_SCAN_LIMIT);
    let mut from = 0_usize;
    while let Some(at) = data.get(from..limit).and_then(|window| window.windows(SIGNATURE.len()).position(|bytes| bytes == SIGNATURE)) {
        let start = from + at;
        if let Some(head) = data.get(start..start + 32)
            && let (Some(covered), Some(stored)) = (head.get(12..32), head.get(8..12))
            && <[u8; 4]>::try_from(stored).is_ok_and(|bytes| crc32fast::hash(covered) == u32::from_le_bytes(bytes))
        {
            return Some(start);
        }
        from = start + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::formats::sevenz::craft;
    use crate::formats::sevenz::reader;

    const MIB: u64 = 1024 * 1024;
    const BCJ: &[u8] = ID_BCJ;

    fn built(source: &Source, all: bool) -> Built {
        let archive = reader::read(source).unwrap();
        hash_lines(source, &archive, all).unwrap()
    }

    fn lines(name: &str, all: bool) -> (Vec<String>, Vec<(usize, NoLine)>) {
        let built = built(&Source::open(Path::new(&format!("tests/fixtures/7z-aes/{name}")), 0).unwrap(), all);
        (built.lines.into_iter().map(|line| line.text).collect(), built.refused)
    }

    fn key() -> Vec<u8> {
        craft::aes_props(19, &[], &[7; 16])
    }

    /// A folder of one file with a CRC-32: these coders in front of the cipher, the sizes of
    /// their outputs, and a packed stream of `packed` bytes that decrypts to as many.
    fn folder(coders: &[(&[u8], &[u8])], sizes: &[u64], packed: u64) -> craft::Folder {
        let key = key();
        let all: Vec<(&[u8], &[u8])> = coders.iter().copied().chain([(craft::AES, key.as_slice())]).collect();
        craft::Folder::new(craft::chain(&all), &[sizes, &[packed]].concat(), packed, Some(0x1234_5678))
    }

    /// The case in which the one folder of an archive has no line.
    fn refused(folder: &craft::Folder) -> NoLine {
        let built = built(&Source::from_bytes(craft::archive_of(std::slice::from_ref(folder))), true);
        assert!(built.lines.is_empty(), "{}", built.lines[0].text);
        assert_eq!(built.refused.len(), 1, "{folder:?}");
        built.refused[0].1.clone()
    }

    /// The fields of the line of the one folder of an archive.
    fn fields(folder: craft::Folder) -> Vec<String> {
        let built = built(&Source::from_bytes(craft::archive_of(&[folder])), true);
        assert_eq!(built.refused, []);
        built.lines[0].text.trim_start_matches("$7z$*").trim_end_matches("$/7z$").split('*').map(str::to_owned).collect()
    }

    #[test]
    fn stored_line_has_no_chain() {
        let (lines, refused) = lines("7z_stored.7z", false);
        assert_eq!(lines, ["$7z$*19**cefd04dc*1c**1*08fc89645bd2a05ed8088f2ca4395060*20*1c**e7e23b23a8cce6a5aaa56347c8871ccd247cde2bf4a84b878e720cbd776e61a4$/7z$"]);
        assert!(refused.is_empty());
    }

    #[test]
    fn a_coder_is_id_properties_size() {
        let (lines, _) = lines("7z_lzma2.7z", false);
        assert!(lines[0].contains("*21/00/1c*"), "{}", lines[0]);
        assert!(!lines[0].contains(':'), "a colon would make hashcat take the line for another list format");
    }

    #[test]
    fn bcj2_carries_four_streams_each_with_its_vector() {
        let (lines, _) = lines("bcj2_enc.7z", false);
        let fields: Vec<&str> = lines[0].trim_start_matches("$7z$*").trim_end_matches("$/7z$").split('*').collect();
        assert_eq!(fields.len(), 6 + 4 * 5);
        assert_eq!(fields[4], "0303011b//1c");
        assert_eq!(fields[5], "4");
        let ivs: std::collections::HashSet<&str> = (0..4).map(|i| fields[6 + 5 * i]).collect();
        assert_eq!(ivs.len(), 4);
    }

    #[test]
    fn every_folder_gets_a_line_when_asked() {
        assert_eq!(lines("7z_nonsolid_enc.7z", false).0.len(), 1);
        assert_eq!(lines("7z_nonsolid_enc.7z", true).0.len(), 3);
    }

    #[test]
    fn a_folder_without_a_line_is_handed_back_with_its_case() {
        assert_eq!(lines("7z_empty_pw.7z", false), (Vec::new(), vec![(0, NoLine::Empty)]));
        assert_eq!(lines("rawkey.7z", true), (Vec::new(), vec![(0, NoLine::KeyIsPassword)]));
        let plain = Source::open(Path::new("tests/fixtures/unencrypted/plain.7z"), 0).unwrap();
        let built = built(&plain, true);
        assert!(built.lines.is_empty() && built.refused.is_empty(), "a folder that is not encrypted is asked for nothing");
    }

    #[test]
    fn the_properties_of_the_cipher_give_power_salt_and_vector() {
        assert_eq!(aes_properties(&[19]), Some(Key { power: 19, salt: &[], iv: &[] }));
        assert_eq!(aes_properties(&craft::aes_props(19, &[], &[0xAA; 16])), Some(Key { power: 19, salt: &[], iv: &[0xAA; 16] }));
        assert_eq!(aes_properties(&craft::aes_props(24, &[0xBB; 4], &[0xCC; 8])), Some(Key { power: 24, salt: &[0xBB; 4], iv: &[0xCC; 8] }));
        assert_eq!(aes_properties(&craft::aes_props(0x3F, &[1; 16], &[2; 16])), Some(Key { power: 0x3F, salt: &[1; 16], iv: &[2; 16] }));
        // none at all, the second byte missing, and fewer bytes than the two sizes say
        assert_eq!(aes_properties(&[]), None);
        assert_eq!(aes_properties(&[0xD3]), None);
        assert_eq!(aes_properties(&[0xD3, 0x3F, 1, 2, 3, 4, 5]), None);
    }

    #[test]
    fn worst_case_is_never_below_the_data() {
        for id in [ID_LZMA, ID_LZMA2, ID_DEFLATE, ID_BZIP2, ID_ZSTD, ID_COPY] {
            assert!(worst_case(id, 1000) >= 1000);
            assert_eq!(worst_case(id, u64::MAX), u64::MAX, "a size no file has is no overflow");
        }
        assert_eq!((worst_case(ID_LZMA2, 300), worst_case(ID_DEFLATE64, 300), worst_case(ID_BZIP2, 300), worst_case(ID_ZSTD, 3000), worst_case(ID_COPY, 300)), (592, 1624, 920_306, 134_139, 300));
    }

    /// The weakest folder was ranked best: no line that proves little may come before one that
    /// proves more.
    #[test]
    fn a_line_that_proves_little_never_ranks_before_one_that_proves_more() {
        let key = key();
        let aes = |packed: u64, size: u64, crc: Option<u32>| craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[size], packed, crc);
        let folders = [
            // one stored byte with a CRC-32: 8 bits
            aes(16, 1, Some(0xD202_EF8D)),
            // a file whose CRC-32 cannot be tested, and a megabyte of LZMA to test the start of
            craft::Folder::new(craft::chain(&[(craft::LZMA, craft::LZMA_PROPS), (craft::AES, &key)]), &[65 * MIB, MIB], MIB, Some(1)),
            // no CRC-32, and a stream that has to end where it should
            craft::Folder::new(craft::chain(&[(craft::LZMA, craft::LZMA_PROPS), (craft::AES, &key)]), &[100, 30], 32, None),
            // three stored bytes: 24 bits
            aes(16, 3, Some(2)),
            // 40 stored bytes and 28 of them, each with a CRC-32
            aes(48, 40, Some(3)),
            aes(32, 28, Some(4)),
        ];
        let source = Source::from_bytes(craft::archive_of(&folders));

        let all = built(&source, true);
        let order: Vec<(usize, Proof, Option<u32>)> = all.lines.iter().map(|line| (line.folder, line.proof, line.weak_bits)).collect();
        assert_eq!(order, [(5, Proof::Crc, None), (4, Proof::Crc, None), (2, Proof::End, None), (1, Proof::Start, None), (0, Proof::Crc, Some(8)), (3, Proof::Crc, Some(24))]);
        assert_eq!(all.lines[3].why, Some(NoCrc::TooMuchToUnpack { size: 65 * MIB, limit: MAX_UNPACK }));
        assert!(all.refused.is_empty());

        // the best of them, and the weak one only when it is all there is
        let best = built(&source, false);
        assert_eq!((best.lines.len(), best.lines[0].folder, best.lines[0].weak_bits), (1, 5, None));
        let only = built(&Source::from_bytes(craft::archive_of(&folders[..1])), false);
        assert_eq!((only.lines.len(), only.lines[0].weak_bits, only.lines[0].crc_len), (1, Some(8), 1));
        assert!(only.lines[0].text.starts_with("$7z$*19**d202ef8d*1**1*"), "{}", only.lines[0].text);
    }

    #[test]
    fn a_folder_that_gives_no_line_leaves_the_next_one_to_give_it() {
        let key = key();
        let aes = |packed: u64, size: u64, crc: Option<u32>| craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[size], packed, crc);
        // an empty folder, one without anything to test, the one that gives the line, and one
        // whose data lies past the end of the file
        let folders = [aes(0, 0, Some(0)), aes(16, 16, None), aes(64, 60, Some(5)), aes(4096, 4090, Some(6))];
        let packed = vec![0; 16 + 64 + 16];
        let source = Source::from_bytes(craft::archive(&craft::header(&folders), &packed));
        let best = built(&source, false);
        assert_eq!(best.lines.iter().map(|line| line.folder).collect::<Vec<_>>(), [2]);
        assert_eq!(best.refused, [(0, NoLine::Empty), (1, NoLine::NothingToTest { crc: NoCrc::NotStored, stream: Untestable::Stored }), (3, NoLine::DataOutsideFile)]);
    }

    #[test]
    fn a_folder_the_line_cannot_say_has_its_case() {
        let key = key();
        let four = || [key.as_slice(); 4];
        let bcj2 = |coders: Vec<u8>| craft::Folder { coders, sizes: vec![40, 30, 5, 5, 30, 5, 5, 16], packs: vec![32, 16, 16, 16], crc: Some(1), files: Vec::new() };

        assert_eq!(refused(&folder(&[], &[], 17)), NoLine::NotWholeBlocks);
        assert_eq!(refused(&craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[33], 32, Some(1))), NoLine::SizesDisagree);
        assert_eq!(refused(&craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[16], 32, Some(1))), NoLine::SizesDisagree);
        assert_eq!(refused(&craft::Folder::new(craft::chain(&[(craft::AES, &[0xD3])]), &[16], 16, Some(1))), NoLine::CoderProperties);
        assert_eq!(refused(&folder(&[(&[0x04, 0xF7, 0x11, 0x02], &[])], &[100], 32)), NoLine::Coder { id: "04f71102".to_owned() });
        // encrypted before it is packed, encrypted twice, and under a cipher that is not 7zAES
        assert_eq!(refused(&craft::Folder::new(craft::chain(&[(craft::AES, &key), (craft::LZMA2, &[0x18])]), &[100, 100], 32, Some(1))), NoLine::StreamNotEncryptedLast);
        assert_eq!(refused(&folder(&[(craft::LZMA2, &[0x18]), (craft::AES, &key)], &[100, 32], 32)), NoLine::EncryptedTwice);
        assert_eq!(refused(&folder(&[(&[0x06, 0xF1, 0x01, 0x01], &[])], &[32], 32)), NoLine::UnknownScheme);

        // four streams that a coder other than BCJ2 joins, BCJ2 over one stream, a cipher behind
        // the join, and two joins
        let mut other = craft::bcj2(four());
        other[2..6].copy_from_slice(ID_ARM);
        assert_eq!(refused(&bcj2(other)), NoLine::JoinNotBcj2);
        assert_eq!(refused(&folder(&[(craft::BCJ2, &[])], &[32], 32)), NoLine::Bcj2OnOneStream);
        let behind = [craft::number(2), craft::coder(craft::AES, &key, None), craft::coder(craft::BCJ2, &[], Some((4, 1))), vec![0, 1, 1, 2, 3, 4]].concat();
        assert_eq!(refused(&craft::Folder { coders: behind, sizes: vec![32, 32], packs: vec![16; 4], crc: Some(1), files: Vec::new() }), NoLine::EncryptedAfterJoin);
        let twice = [craft::number(3), craft::coder(craft::BCJ2, &[], Some((4, 1))).repeat(2), craft::coder(craft::AES, &key, None), vec![0, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8]].concat();
        assert_eq!(refused(&craft::Folder { coders: twice, sizes: vec![32; 3], packs: vec![16; 7], crc: Some(1), files: Vec::new() }), NoLine::JoinedTwice);

        // streams of one folder under two salts
        let salted = craft::aes_props(19, &[1, 2, 3], &[7; 16]);
        assert_eq!(refused(&bcj2(craft::bcj2([&key, &salted, &key, &key]))), NoLine::SeveralKeys);
        // BCJ2 without a CRC-32, and with one that is out of reach
        assert_eq!(refused(&craft::Folder { crc: None, ..bcj2(craft::bcj2(four())) }), NoLine::Bcj2WithoutCrc(NoCrc::NotStored));
        let large = craft::Folder { sizes: vec![65 * MIB, 30, 5, 5, 30, 5, 5, 16], ..bcj2(craft::bcj2(four())) };
        assert_eq!(refused(&large), NoLine::Bcj2WithoutCrc(NoCrc::TooMuchToUnpack { size: 65 * MIB, limit: MAX_UNPACK }));
    }

    #[test]
    fn a_folder_with_nothing_to_test_has_no_line() {
        let key = key();
        // stored data without a CRC-32: every key decrypts it to something
        assert_eq!(refused(&craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[16], 16, None)), NoLine::NothingToTest { crc: NoCrc::NotStored, stream: Untestable::Stored });
        // and so does a filter over stored data
        assert_eq!(refused(&craft::Folder { crc: None, ..folder(&[(BCJ, &[])], &[16], 16) }), NoLine::NothingToTest { crc: NoCrc::NotStored, stream: Untestable::Stored });
        // PPMd that is too large to unpack to its end: its start takes anything
        let ppmd: &[u8] = &[6, 0, 0, 0, 1];
        assert_eq!(refused(&craft::Folder { crc: None, ..folder(&[(craft::PPMD, ppmd)], &[65 * MIB], 32) }), NoLine::NothingToTest { crc: NoCrc::NotStored, stream: Untestable::SilentStart { coder: "PPMd".to_owned() } });
        // a size of 2^64-1 overflowed here: the CRC-32 is out of reach, and 16 bytes of LZMA2 are no test
        let unreachable = NoCrc::TooMuchToUnpack { size: u64::MAX, limit: MAX_UNPACK };
        assert_eq!(refused(&folder(&[(craft::LZMA2, &[0x18])], &[u64::MAX], 16)), NoLine::NothingToTest { crc: unreachable, stream: Untestable::ShortStart { coder: "LZMA2".to_owned(), packed: 16 } });
        // stored data that is longer than a line carries
        let need = NoCrc::TooMuchToCarry { need: 5 * MIB, limit: MAX_INLINE_DATA };
        assert_eq!(refused(&craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[5 * MIB], 5 * MIB, Some(1))), NoLine::NothingToTest { crc: need, stream: Untestable::Stored });
    }

    /// Lines were written that mode 46900 refuses, or loads and can confirm no password with.
    #[test]
    fn a_line_the_mode_would_refuse_is_not_written() {
        let key = key();
        let four = || [key.as_slice(); 4];
        let ppmd = |order: u8, memory: u32| [&[order][..], &memory.to_le_bytes()].concat();

        // the model of PPMd: 256 MiB is what the mode gives one
        assert_eq!(fields(folder(&[(craft::PPMD, &ppmd(6, 1 << 28))], &[100], 32)).len(), 11);
        assert_eq!(refused(&folder(&[(craft::PPMD, &ppmd(6, (1 << 28) + 1))], &[100], 32)), NoLine::PpmdMemory { memory: (1 << 28) + 1, limit: 1 << 28 });
        assert_eq!(refused(&folder(&[(craft::PPMD, &ppmd(6, 0xC000_0000))], &[100], 32)), NoLine::PpmdMemory { memory: 0xC000_0000, limit: 1 << 28 });

        // properties a coder does not take
        let bad = |coder: &str| NoLine::PropertiesInvalid { coder: coder.to_owned() };
        assert_eq!(refused(&folder(&[(craft::PPMD, &ppmd(1, 1 << 20))], &[100], 32)), bad("PPMd"));
        assert_eq!(refused(&folder(&[(craft::PPMD, &ppmd(6, 1 << 10))], &[100], 32)), bad("PPMd"));
        assert_eq!(refused(&folder(&[(craft::PPMD, &[6, 0, 0, 1])], &[100], 32)), bad("PPMd"));
        assert_eq!(refused(&folder(&[(craft::LZMA, &[0x5D, 0, 0, 1])], &[100], 32)), bad("LZMA"));
        assert_eq!(refused(&folder(&[(craft::LZMA, &[225, 0, 0, 1, 0])], &[100], 32)), bad("LZMA"));
        assert_eq!(refused(&folder(&[(craft::LZMA2, &[41])], &[100], 32)), bad("LZMA2"));
        assert_eq!(refused(&folder(&[(craft::LZMA2, &[0x18, 0])], &[100], 32)), bad("LZMA2"));
        assert_eq!(refused(&folder(&[(ID_DELTA, &[0, 0]), (craft::LZMA2, &[0x18])], &[100, 100], 32)), bad("Delta"));
        assert_eq!(refused(&folder(&[(BCJ, &[0, 0, 0]), (craft::LZMA2, &[0x18])], &[100, 100], 32)), bad("BCJ"));
        // and properties that are longer than the mode stores: LZMA takes the start of them
        assert_eq!(fields(folder(&[(craft::LZMA, &[&[0x5D, 0, 0, 1, 0][..], &[0; 11]].concat())], &[100], 32)).len(), 11);
        assert_eq!(refused(&folder(&[(craft::LZMA, &[&[0x5D, 0, 0, 1, 0][..], &[0; 12]].concat())], &[100], 32)), NoLine::PropertiesTooLong { coder: "LZMA".to_owned(), len: 17, limit: 16 });

        // eight coders in a row, and not nine
        let swaps = |count: usize| folder(&vec![(ID_SWAP2, &[][..]); count], &vec![32; count], 32);
        assert_eq!(fields(swaps(8))[9].split(',').count(), 8);
        assert_eq!(refused(&swaps(9)), NoLine::TooManyCoders { count: 9, limit: 8 });

        // a packer that feeds another is unpacked in full: to 64 MiB and no more, and not to nothing
        let two = |inner: u64| folder(&[(craft::LZMA2, &[0x18]), (craft::LZMA, craft::LZMA_PROPS)], &[100, inner], 32);
        assert_eq!(fields(two(64 * MIB))[9], "030101/5d00000100/4000000,21/18/64");
        assert_eq!(refused(&two(64 * MIB + 1)), NoLine::UnpacksTooMuch { size: 64 * MIB + 1, limit: MAX_UNPACK });
        assert_eq!(refused(&two(0)), NoLine::SizesDisagree);

        // BCJ2: a stream of more than 4 MiB, four streams of more than the mode reads together,
        // one that unpacks to more than 64 MiB, and a packer behind the join
        let bcj2 = |sizes: [u64; 8], packs: [u64; 4]| craft::Folder { coders: craft::bcj2(four()), sizes: sizes.to_vec(), packs: packs.to_vec(), crc: Some(1), files: Vec::new() };
        let (big, half) = (4 * MIB + 16, 3 * MIB);
        assert_eq!(refused(&bcj2([40, 30, 5, 5, big, 16, 16, 16], [big, 16, 16, 16])), NoLine::Bcj2StreamTooLarge { packed: big, limit: MAX_INLINE_DATA });
        assert_eq!(refused(&bcj2([40, 30, 5, 5, half, half, half, 16], [half, half, half, 16])), NoLine::Bcj2TooLarge { packed: 3 * half + 16, limit: MODE_MAX_DATA });
        assert_eq!(refused(&bcj2([40, 65 * MIB, 5, 5, 30, 5, 5, 16], [32, 16, 16, 16])), NoLine::UnpacksTooMuch { size: 65 * MIB, limit: MAX_UNPACK });
        let behind = [
            craft::number(9),
            craft::coder(craft::LZMA2, &[0x18], None),
            craft::coder(craft::BCJ2, &[], Some((4, 1))),
            craft::coder(craft::LZMA, craft::LZMA_PROPS, None).repeat(3),
            craft::coder(craft::AES, &key, None).repeat(4),
            vec![0, 1, 1, 2, 2, 3, 3, 4, 4, 8, 5, 5, 6, 6, 7, 7],
            vec![8, 9, 10, 11],
        ]
        .concat();
        assert_eq!(refused(&craft::Folder { coders: behind, sizes: vec![40, 40, 30, 5, 5, 30, 5, 5, 16], packs: vec![32, 16, 16, 16], crc: Some(1), files: Vec::new() }), NoLine::Coder { id: "21".to_owned() });

        // an empty stream of BCJ2 is one without a coder: with one, the mode refuses the line
        let empty_jump = craft::Folder { coders: craft::bcj2(four()), sizes: vec![40, 30, 5, 0, 30, 5, 0, 16], packs: vec![32, 16, 0, 16], crc: Some(1), files: Vec::new() };
        assert_eq!(refused(&empty_jump), NoLine::NotWholeBlocks);
    }

    #[test]
    fn a_stream_is_cut_to_what_the_first_file_can_take_and_only_where_that_bound_holds() {
        let data = |fields: Vec<String>| fields[10].len() / 2;
        let solid = |coders: &[(&[u8], &[u8])], sizes: &[u64]| craft::Folder { files: vec![(100, Some(7)), (2 * MIB - 100, None)], crc: None, ..folder(coders, sizes, MIB) };

        // LZMA2: 100 bytes take 100 + 33 + 192 at the most, in whole cipher blocks
        assert_eq!(data(fields(solid(&[(craft::LZMA2, &[0x18])], &[2 * MIB]))), 336);
        // a filter behind the packer looks 16 bytes ahead
        assert_eq!(data(fields(solid(&[(BCJ, &[]), (craft::LZMA2, &[0x18])], &[2 * MIB, 2 * MIB]))), 352);
        // PPMd has no bound, a second packer needs all of the first, and a filter in front of
        // the packer changes what the packer reads: all of the stream
        let whole = usize::try_from(MIB).unwrap();
        assert_eq!(data(fields(solid(&[(craft::PPMD, &[6, 0, 0, 0, 1])], &[2 * MIB]))), whole);
        assert_eq!(data(fields(solid(&[(craft::LZMA2, &[0x18]), (craft::LZMA, craft::LZMA_PROPS)], &[2 * MIB, MIB]))), whole);
        assert_eq!(data(fields(solid(&[(craft::LZMA2, &[0x18]), (BCJ, &[])], &[2 * MIB, MIB]))), whole);
        // the CRC-32 and its length are those of the first file
        let fields = fields(solid(&[(craft::LZMA2, &[0x18])], &[2 * MIB]));
        assert_eq!((fields[2].as_str(), fields[3].as_str(), fields[9].as_str()), ("00000007", "64", "21/18/200000"));
    }

    #[test]
    fn the_lines_of_one_archive_are_held_to_a_budget() {
        let key = key();
        let folders: Vec<craft::Folder> = (0..5_u32).map(|number| craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[1024], 1024, Some(number))).collect();
        let source = Source::from_bytes(craft::archive_of(&folders));
        let archive = reader::read(&source).unwrap();

        // three lines of 2048 characters of data fit 7000, and the best line is written whatever it takes
        let built = lines_within(&source, &archive, true, 7000).unwrap();
        assert_eq!(built.lines.iter().map(|line| line.folder).collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(built.refused, [(3, NoLine::LinesOverBudget { limit: 7000 }), (4, NoLine::LinesOverBudget { limit: 7000 })]);
        let built = lines_within(&source, &archive, false, 1).unwrap();
        assert_eq!((built.lines.len(), built.refused.len()), (1, 0));
    }

    #[test]
    fn the_names_of_the_coders_are_those_people_write() {
        assert_eq!([coder_name(ID_COPY), coder_name(ID_LZMA2), coder_name(ID_BCJ2), coder_name(ID_ZSTD), coder_name(&[0x04, 0xF7, 0x11, 0x02])], ["stored", "LZMA2", "BCJ2", "Zstandard", "04f71102"]);
    }
}
