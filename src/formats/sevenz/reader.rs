//! Reading a 7z archive: the signature header, the header it points to, and what that header
//! says of every folder.
//!
//! This is the one reader of the format. The analysis and the hash lines are both made from
//! the [`Archive`] it returns. It follows `CPP/7zip/Archive/7z/7zIn.cpp` of 7-Zip: the same
//! order of the blocks, the same limits on a folder (64 coders, 64 inputs, an identifier of
//! at most 8 bytes, one output for every coder), and the same tolerance for attributes it does
//! not know, which are skipped by their size.
//!
//! Nothing is read but the 32 bytes of the signature header, the header, and the packed stream
//! of a header that is stored packed. What is kept of a folder is a few numbers and the place
//! of its coders in the header: the coders themselves are read again from the header when they
//! are asked for ([`Folder::chain`]), so a header that describes a million folders costs a
//! million small records and nothing else.
//!
//! Every count the header holds is held against the bytes that are left before anything is
//! allocated or looped over, and every sum is checked.

use std::io::ErrorKind;
use std::ops::Range;

use anyhow::Context as _;
use anyhow::bail;
use anyhow::ensure;

use crate::analysis::NoLine;
use crate::formats::decode;
use crate::formats::decode::Decoded;
use crate::formats::limits::MAX_DECODE_BUFFER;
use crate::formats::limits::capacity_for;
use crate::formats::source::Source;

/// What a 7z archive starts with.
pub(crate) const SIGNATURE: [u8; 6] = [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C];

/// Size of the signature header. The positions the header names count from its end.
const START: u64 = 32;

const K_END: u64 = 0x00;
const K_HEADER: u64 = 0x01;
const K_ARCHIVE_PROPERTIES: u64 = 0x02;
const K_ADDITIONAL_STREAMS_INFO: u64 = 0x03;
const K_MAIN_STREAMS_INFO: u64 = 0x04;
const K_FILES_INFO: u64 = 0x05;
const K_PACK_INFO: u64 = 0x06;
const K_UNPACK_INFO: u64 = 0x07;
const K_SUBSTREAMS_INFO: u64 = 0x08;
const K_SIZE: u64 = 0x09;
const K_CRC: u64 = 0x0A;
const K_FOLDER: u64 = 0x0B;
const K_CODERS_UNPACK_SIZE: u64 = 0x0C;
const K_NUM_UNPACK_STREAM: u64 = 0x0D;
const K_EMPTY_STREAM: u64 = 0x0E;
const K_NAMES: u64 = 0x11;
const K_ENCODED_HEADER: u64 = 0x17;

pub(crate) const ID_COPY: &[u8] = &[0x00];
pub(crate) const ID_LZMA2: &[u8] = &[0x21];
pub(crate) const ID_LZMA: &[u8] = &[0x03, 0x01, 0x01];
pub(crate) const ID_AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

/// The first byte of every identifier in the part of 7-Zip's method table that holds the
/// ciphers (`DOC/Methods.txt`, "06.. - Crypto").
const CIPHER_RANGE: u8 = 0x06;

/// 7-Zip reads no folder with more coders than this, nor with more inputs over all its coders.
const MAX_CODERS: usize = 64;

/// 7-Zip reads no coder identifier longer than this.
const MAX_ID: usize = 8;

/// The most folders an archive may describe. Each costs a record here and an entry in the
/// analysis, a few hundred bytes together, however few bytes of the header it takes.
pub(crate) const MAX_FOLDERS: usize = 1 << 18;

/// The most packed streams an archive may list: four for every folder, which is what a folder
/// that uses BCJ2 reads.
const MAX_PACKS: usize = 4 * MAX_FOLDERS;

/// The most coders the folders of an archive may have together: sixteen for every folder, twice
/// what the longest chain 7-Zip writes takes.
const MAX_ALL_CODERS: usize = 16 * MAX_FOLDERS;

/// The most file names that are kept. A name of no characters takes two bytes of a header and
/// far more in memory, so an archive of more files than this is listed without their names.
pub(crate) const MAX_NAMES: u64 = 1 << 20;

/// The largest header that is held, as the file stores it or as it unpacks.
const MAX_HEADER: u64 = MAX_DECODE_BUFFER;

/// How many times a header may be stored packed inside a packed header. 7-Zip packs it once.
const MAX_NESTING: usize = 4;

const CUT_SHORT: &str = "7z: its header is cut short";

/// A cursor over the bytes of a header.
#[derive(Debug)]
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// How many bytes are left.
    const fn left(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, count: usize) -> anyhow::Result<&'a [u8]> {
        let end = self.pos.checked_add(count).context(CUT_SHORT)?;
        let out = self.data.get(self.pos..end).context(CUT_SHORT)?;
        self.pos = end;
        Ok(out)
    }

    fn byte(&mut self) -> anyhow::Result<u8> {
        self.take(1)?.first().copied().context(CUT_SHORT)
    }

    fn u32(&mut self) -> anyhow::Result<u32> {
        let bytes = <[u8; 4]>::try_from(self.take(4)?).context(CUT_SHORT)?;
        Ok(u32::from_le_bytes(bytes))
    }

    /// A number in the variable length form of the format: the high bits of the first byte
    /// say how many bytes follow.
    fn number(&mut self) -> anyhow::Result<u64> {
        let first = self.byte()?;
        let mut mask = 0x80_u8;
        let mut value = 0_u64;
        for i in 0..8_u32 {
            if first & mask == 0 {
                return Ok(value | (u64::from(first & mask.wrapping_sub(1)) << (8 * i)));
            }
            value |= u64::from(self.byte()?) << (8 * i);
            mask >>= 1;
        }
        Ok(value)
    }

    /// How many things follow, each of which takes at least `each` bytes: a count that the
    /// bytes left could not hold is an error before anything is done with it.
    fn count(&mut self, each: usize) -> anyhow::Result<usize> {
        let value = self.number()?;
        usize::try_from(value).ok().filter(|&count| count <= self.left() / each.max(1)).context("7z: its header holds an impossible count")
    }

    /// An attribute this reader has no use for: its size, then that many bytes.
    fn skip_attribute(&mut self) -> anyhow::Result<()> {
        let size = usize::try_from(self.number()?).context(CUT_SHORT)?;
        self.take(size).map(drop)
    }

    /// Skip attributes up to the one named `id`. The end of the block comes first when it is
    /// not there, and that is an error.
    fn wait(&mut self, id: u64) -> anyhow::Result<()> {
        loop {
            let found = self.number()?;
            if found == id {
                return Ok(());
            }
            ensure!(found != K_END, "7z: its header lacks a field it has to hold");
            self.skip_attribute()?;
        }
    }
}

/// A list of CRC-32 values of which some may be missing, read one at a time: a byte that says
/// whether all are there, a bit for each when not, then the values that are.
#[derive(Debug)]
struct Digests<'a> {
    all: bool,
    bits: &'a [u8],
    next: usize,
}

impl<'a> Digests<'a> {
    /// The start of a list of `count` values. The bits are taken here, so a count the header
    /// cannot hold fails before any value is read.
    fn open(reader: &mut Reader<'a>, count: u64) -> anyhow::Result<Self> {
        let all = reader.byte()? != 0;
        let bits = if all { &[][..] } else { reader.take(usize::try_from(count.div_ceil(8)).context(CUT_SHORT)?)? };
        Ok(Self { all, bits, next: 0 })
    }

    /// The next value, `None` where the archive stores none.
    fn next(&mut self, reader: &mut Reader<'a>) -> anyhow::Result<Option<u32>> {
        let defined = self.all || self.bits.get(self.next / 8).is_some_and(|byte| byte & (0x80 >> (self.next % 8)) != 0);
        self.next = self.next.saturating_add(1);
        if defined { reader.u32().map(Some) } else { Ok(None) }
    }
}

/// One coder of a folder, as the header stores it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Coder<'a> {
    /// Its identifier.
    pub id: &'a [u8],
    /// How many streams it takes.
    pub inputs: usize,
    /// Its properties.
    pub props: &'a [u8],
}

impl Coder<'_> {
    /// Whether the coder is a cipher: its identifier lies in the cipher range of 7-Zip's method
    /// table.
    pub(crate) fn is_cipher(&self) -> bool {
        self.id.first() == Some(&CIPHER_RANGE)
    }
}

/// The coders of one folder and how they are connected.
#[derive(Debug, Clone)]
pub(crate) struct Chain<'a> {
    /// The coders, in the order the header stores them.
    pub coders: Vec<Coder<'a>>,
    /// The number of the first input of every coder, the inputs being counted across the folder.
    bases: Vec<usize>,
    /// For every input, the coder whose output feeds it. `None` for an input that a packed
    /// stream feeds.
    feeders: Vec<Option<usize>>,
    /// The inputs that packed streams feed, in the order of those streams.
    pub packed: Vec<usize>,
    /// The coder whose output is the output of the folder.
    pub main: usize,
}

impl Chain<'_> {
    /// The number of the first input of a coder.
    pub(crate) fn first_input(&self, coder: usize) -> Option<usize> {
        self.bases.get(coder).copied()
    }

    /// The coder whose output feeds an input.
    pub(crate) fn feeder(&self, input: usize) -> Option<usize> {
        self.feeders.get(input).copied().flatten()
    }

    /// Which of the packed streams of the folder feeds an input.
    pub(crate) fn pack_of(&self, input: usize) -> Option<usize> {
        self.packed.iter().position(|&fed| fed == input)
    }
}

/// Read the coders of one folder, as `ReadUnpackInfo` of 7-Zip does.
fn read_chain<'a>(reader: &mut Reader<'a>) -> anyhow::Result<Chain<'a>> {
    let count = usize::try_from(reader.number()?).ok().filter(|count| (1..=MAX_CODERS).contains(count)).context("7z: a folder has no coder, or more coders than 7-Zip reads")?;

    let mut coders = Vec::with_capacity(count);
    let mut bases = Vec::with_capacity(count);
    let mut inputs = 0_usize;
    for _ in 0..count {
        let flags = reader.byte()?;
        ensure!(flags & 0xC0 == 0, "7z: coder with unknown flags");
        let id_size = usize::from(flags & 0x0F);
        ensure!(id_size <= MAX_ID, "7z: coder with an identifier of {id_size} bytes");
        let id = reader.take(id_size)?;
        let mut taken = 1_usize;
        if flags & 0x10 != 0 {
            taken = usize::try_from(reader.number()?).ok().filter(|taken| (1..=MAX_CODERS).contains(taken)).context("7z: coder with no input, or with more inputs than 7-Zip reads")?;
            ensure!(reader.number()? == 1, "7z: coder with more than one output");
        }
        let props = if flags & 0x20 != 0 {
            let size = reader.count(1)?;
            reader.take(size)?
        } else {
            &[]
        };
        bases.push(inputs);
        inputs = inputs.saturating_add(taken);
        ensure!(inputs <= MAX_CODERS, "7z: a folder has more inputs than 7-Zip reads");
        coders.push(Coder { id, inputs: taken, props });
    }

    // every coder but one feeds an input, and no input and no coder is named twice
    let mut feeders = vec![None; inputs];
    let mut feeds = vec![false; count];
    for _ in 1..count {
        let input = usize::try_from(reader.number()?).context("7z: folder with damaged connections")?;
        let coder = usize::try_from(reader.number()?).context("7z: folder with damaged connections")?;
        let (Some(slot @ None), Some(used @ false)) = (feeders.get_mut(input), feeds.get_mut(coder)) else {
            bail!("7z: folder with damaged connections");
        };
        *slot = Some(coder);
        *used = true;
    }
    let main = feeds.iter().position(|used| !used).context("7z: folder with damaged connections")?;

    // The inputs that are left are fed by packed streams: one is found, several are listed.
    // There is always one, since every coder has an input and one coder feeds none.
    let free = feeders.iter().filter(|feeder| feeder.is_none()).count();
    let mut packed = Vec::with_capacity(free);
    if free == 1 {
        packed.extend(feeders.iter().position(Option::is_none));
    } else {
        let mut listed = vec![false; inputs];
        for _ in 0..free {
            let input = usize::try_from(reader.number()?).context("7z: folder with damaged connections")?;
            let (Some(None), Some(seen @ false)) = (feeders.get(input), listed.get_mut(input)) else {
                bail!("7z: folder with damaged connections");
            };
            *seen = true;
            packed.push(input);
        }
    }

    Ok(Chain { coders, bases, feeders, packed, main })
}

/// What is kept of one folder.
#[derive(Debug, Clone, Copy)]
struct Stored {
    /// Where its coders start in the header.
    at: usize,
    /// How many coders it has.
    coders: usize,
    /// Which of them gives the output of the folder.
    main: usize,
    /// How many packed streams it reads.
    packs: usize,
    /// The place of the size of its first coder among the sizes of all coders.
    sizes_at: usize,
    /// The place of its first packed stream among all packed streams.
    first_pack: usize,
    /// Whether one of its coders is a cipher.
    cipher: bool,
    /// The CRC-32 of what it unpacks to.
    crc: Option<u32>,
    /// How many files it holds.
    files: u64,
    /// Size of the first of them.
    first_size: u64,
    /// CRC-32 of the first of them.
    first_crc: Option<u32>,
    /// Whether the archive stores a CRC-32 for the folder or for any of its files.
    any_crc: bool,
}

/// What a `StreamsInfo` block describes.
#[derive(Debug, Default)]
struct Streams {
    /// Where the packed streams start, counted from the end of the signature header.
    pack_pos: u64,
    /// Where each packed stream starts, counted from `pack_pos`, and where the last one ends.
    pack_starts: Vec<u64>,
    /// Size of the output of every coder of every folder.
    coder_sizes: Vec<u64>,
    folders: Vec<Stored>,
    /// The folders are described outside the header, and nothing more of the block was read.
    external: bool,
}

impl Streams {
    /// Size of what a folder unpacks to: the output of its main coder.
    fn size_of(&self, folder: &Stored) -> anyhow::Result<u64> {
        folder.sizes_at.checked_add(folder.main).and_then(|at| self.coder_sizes.get(at)).copied().context("7z: folder without sizes")
    }
}

fn read_pack_info(reader: &mut Reader<'_>, streams: &mut Streams) -> anyhow::Result<()> {
    streams.pack_pos = reader.number()?;
    let count = reader.count(1)?;
    ensure!(count <= MAX_PACKS, "7z: its header lists {count} packed streams, more than the {MAX_PACKS} that are read");

    // 7-Zip wants the sizes even of no streams. An archive without streams that leaves them
    // out is read all the same.
    loop {
        match reader.number()? {
            K_SIZE => break,
            K_END if count == 0 => {
                streams.pack_starts = vec![0];
                return Ok(());
            },
            K_END => bail!("7z: pack information without sizes"),
            _ => reader.skip_attribute()?,
        }
    }

    let mut starts = Vec::with_capacity(count.saturating_add(1));
    let mut end = 0_u64;
    starts.push(end);
    for _ in 0..count {
        end = end.checked_add(reader.number()?).context("7z: packed streams of an impossible size")?;
        starts.push(end);
    }
    streams.pack_starts = starts;

    loop {
        match reader.number()? {
            K_END => return Ok(()),
            K_CRC => {
                let mut digests = Digests::open(reader, u64::try_from(count)?)?;
                for _ in 0..count {
                    let _ = digests.next(reader)?;
                }
            },
            _ => reader.skip_attribute()?,
        }
    }
}

/// Read the folders of an `UnpackInfo` block. With `external`, folders that are described
/// outside the header end the reading: [`Streams::external`] is set.
fn read_unpack_info(reader: &mut Reader<'_>, streams: &mut Streams, external: bool) -> anyhow::Result<()> {
    reader.wait(K_FOLDER)?;
    let claimed = reader.number()?;
    if reader.byte()? != 0 {
        ensure!(external, "7z: folders stored outside a header that has no such place");
        streams.external = true;
        return Ok(());
    }
    // a folder takes two bytes at the least: its count of coders and the flags of one
    let count = usize::try_from(claimed).ok().filter(|&count| count <= reader.left() / 2).context("7z: its header holds an impossible count")?;
    ensure!(count <= MAX_FOLDERS, "7z: its header describes {count} folders, more than the {MAX_FOLDERS} that are read");

    let packs_stored = streams.pack_starts.len().saturating_sub(1);
    let mut folders = Vec::with_capacity(count);
    let mut sizes_at = 0_usize;
    let mut first_pack = 0_usize;
    for _ in 0..count {
        let at = reader.pos;
        let chain = read_chain(reader)?;
        let (coders, packs) = (chain.coders.len(), chain.packed.len());
        folders.push(Stored { at, coders, main: chain.main, packs, sizes_at, first_pack, cipher: chain.coders.iter().any(Coder::is_cipher), crc: None, files: 1, first_size: 0, first_crc: None, any_crc: false });
        sizes_at = sizes_at.checked_add(coders).filter(|&all| all <= MAX_ALL_CODERS).context("7z: its folders have more coders together than are read")?;
        first_pack = first_pack.checked_add(packs).filter(|&used| used <= packs_stored).context("7z: more packed streams used than stored")?;
    }

    reader.wait(K_CODERS_UNPACK_SIZE)?;
    let mut sizes = Vec::with_capacity(capacity_for(sizes_at, reader.left(), 1));
    for _ in 0..sizes_at {
        sizes.push(reader.number()?);
    }

    let mut seen = false;
    loop {
        match reader.number()? {
            K_END => break,
            K_CRC => {
                ensure!(!seen, "7z: its header names the checksums of its folders twice");
                seen = true;
                let mut digests = Digests::open(reader, u64::try_from(count)?)?;
                for folder in &mut folders {
                    folder.crc = digests.next(reader)?;
                }
            },
            _ => reader.skip_attribute()?,
        }
    }

    streams.folders = folders;
    streams.coder_sizes = sizes;
    Ok(())
}

/// Give every folder the size and the checksum of its first file as they stand without a
/// `SubStreamsInfo` block, or before its checksums are read: a folder holds one file, which is
/// all the folder unpacks to.
fn one_file_each(streams: &mut Streams) -> anyhow::Result<()> {
    for index in 0..streams.folders.len() {
        let Some(folder) = streams.folders.get(index).copied() else { continue };
        let size = streams.size_of(&folder)?;
        if let Some(folder) = streams.folders.get_mut(index) {
            folder.files = 1;
            folder.first_size = size;
        }
    }
    Ok(())
}

/// Read the sizes of the files inside each folder. Only the first is kept.
fn read_file_sizes(reader: &mut Reader<'_>, streams: &mut Streams) -> anyhow::Result<()> {
    for index in 0..streams.folders.len() {
        let Some(folder) = streams.folders.get(index).copied() else { continue };
        let total = streams.size_of(&folder)?;
        if folder.files == 0 {
            continue;
        }
        // every file but the last has its size here, and the loop ends with the header
        let mut first = None;
        let mut sum = 0_u64;
        for _ in 1..folder.files {
            let size = reader.number()?;
            sum = sum.checked_add(size).context("7z: files larger than their folder")?;
            let _ = first.get_or_insert(size);
        }
        let last = total.checked_sub(sum).context("7z: files larger than their folder")?;
        if let Some(folder) = streams.folders.get_mut(index) {
            folder.first_size = first.unwrap_or(last);
        }
    }
    Ok(())
}

/// Read the checksums of the files inside each folder. A folder that holds one file and has a
/// checksum of its own does not repeat it here.
fn read_file_crcs(reader: &mut Reader<'_>, streams: &mut Streams) -> anyhow::Result<()> {
    let listed = |folder: &Stored| !(folder.files == 1 && folder.crc.is_some());
    let count = streams.folders.iter().filter(|folder| listed(folder)).try_fold(0_u64, |sum, folder| sum.checked_add(folder.files)).context("7z: its header holds an impossible count")?;
    let mut digests = Digests::open(reader, count)?;
    for folder in streams.folders.iter_mut().filter(|folder| listed(folder)) {
        // a count the header cannot hold ends here, with the bytes of the header
        for number in 0..folder.files {
            let crc = digests.next(reader)?;
            if number == 0 {
                folder.first_crc = crc;
            }
            folder.any_crc |= crc.is_some();
        }
    }
    Ok(())
}

fn read_substreams(reader: &mut Reader<'_>, streams: &mut Streams) -> anyhow::Result<()> {
    let mut counted = false;
    let mut part = loop {
        match reader.number()? {
            K_NUM_UNPACK_STREAM => {
                ensure!(!counted, "7z: its header counts the files of its folders twice");
                counted = true;
                for folder in &mut streams.folders {
                    folder.files = reader.number()?;
                }
            },
            part @ (K_CRC | K_SIZE | K_END) => break part,
            _ => reader.skip_attribute()?,
        }
    };

    if part == K_SIZE {
        read_file_sizes(reader, streams)?;
        part = reader.number()?;
    } else {
        ensure!(streams.folders.iter().all(|folder| folder.files <= 1), "7z: folder with several files and no sizes");
    }

    let mut seen = false;
    loop {
        match part {
            K_END => return Ok(()),
            K_CRC => {
                ensure!(!seen, "7z: its header names the checksums of its files twice");
                seen = true;
                read_file_crcs(reader, streams)?;
            },
            _ => reader.skip_attribute()?,
        }
        part = reader.number()?;
    }
}

/// Read a `StreamsInfo` block: the packed streams, the folders, and the files inside each
/// folder. With `external`, folders described outside the header end the reading.
fn read_streams(reader: &mut Reader<'_>, external: bool) -> anyhow::Result<Streams> {
    let mut streams = Streams { pack_starts: vec![0], ..Streams::default() };
    let mut part = reader.number()?;

    if part == K_PACK_INFO {
        read_pack_info(reader, &mut streams)?;
        part = reader.number()?;
    }
    if part == K_UNPACK_INFO {
        read_unpack_info(reader, &mut streams, external)?;
        if streams.external {
            return Ok(streams);
        }
        part = reader.number()?;
    }

    one_file_each(&mut streams)?;
    if part == K_SUBSTREAMS_INFO {
        read_substreams(reader, &mut streams)?;
        part = reader.number()?;
    }
    for folder in &mut streams.folders {
        if folder.files == 1 && folder.crc.is_some() {
            folder.first_crc = folder.crc;
        }
        folder.any_crc |= folder.crc.is_some();
    }

    ensure!(part == K_END, "7z: unknown field in the stream information");
    Ok(streams)
}

/// Where the list of files of a header says what the folders need of it.
#[derive(Debug, Clone)]
struct Files {
    /// How many files the archive lists, with and without data.
    count: u64,
    /// Where the names lie in the header: UTF-16, each ended by a zero.
    names: Range<usize>,
    /// Where the bits lie that mark the files without data, when there are any.
    empty: Option<Range<usize>>,
}

/// Read the list of files of a header, as far as the folders need it: where the names are and
/// which files have no data. `None` when the names are stored outside the header.
fn read_files(reader: &mut Reader<'_>) -> anyhow::Result<Option<Files>> {
    let count = reader.number()?;
    let mut names = None;
    let mut empty = None;

    loop {
        let kind = reader.number()?;
        if kind == K_END {
            break;
        }
        let size = reader.count(1)?;
        let start = reader.pos;
        let body = reader.take(size)?;
        if kind == K_EMPTY_STREAM {
            ensure!(count.div_ceil(8) <= u64::try_from(size)?, "7z: its list of files is cut short");
            empty = Some(start..reader.pos);
        } else if kind == K_NAMES && body.first() == Some(&0) {
            names = Some(start.saturating_add(1)..reader.pos);
        }
    }

    Ok(names.map(|names| Files { count, names, empty }))
}

/// Whether the header of an archive can be read without the password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Headers {
    /// It was read: the folders are those of the archive.
    Readable,
    /// It is encrypted: the folders are those of the packed header, and the files of the
    /// archive cannot be told.
    Encrypted,
    /// It could not be read, and this is the case it is. Nothing is known of the folders.
    Unread(NoLine),
}

/// A 7z archive as its header describes it.
#[derive(Debug)]
pub(crate) struct Archive {
    /// Whether the header could be read.
    pub headers: Headers,
    /// The header the folders were read from, which their coders are read from again.
    header: Vec<u8>,
    streams: Streams,
    files: Option<Files>,
}

/// One folder of an archive: one chain of coders over one or more files.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Folder<'a> {
    archive: &'a Archive,
    stored: &'a Stored,
    /// Its number in the archive, from 0.
    pub number: usize,
}

impl<'a> Folder<'a> {
    /// The coders of the folder and how they are connected.
    pub(crate) fn chain(&self) -> anyhow::Result<Chain<'a>> {
        let mut reader = Reader::new(self.archive.header.get(self.stored.at..).context(CUT_SHORT)?);
        read_chain(&mut reader)
    }

    /// Size of the output of every coder, in the order of the coders.
    pub(crate) fn sizes(&self) -> &'a [u64] {
        self.stored.sizes_at.checked_add(self.stored.coders).and_then(|end| self.archive.streams.coder_sizes.get(self.stored.sizes_at..end)).unwrap_or_default()
    }

    /// Size of what the folder unpacks to: the output of the one coder that feeds no other.
    pub(crate) fn size(&self) -> u64 {
        self.sizes().get(self.stored.main).copied().unwrap_or(0)
    }

    /// Whether one of its coders is a cipher.
    pub(crate) const fn is_encrypted(&self) -> bool {
        self.stored.cipher
    }

    /// The CRC-32 of what the folder unpacks to, when the archive stores one.
    pub(crate) const fn crc(&self) -> Option<u32> {
        self.stored.crc
    }

    /// How many files the folder holds.
    pub(crate) const fn files(&self) -> u64 {
        self.stored.files
    }

    /// Size and CRC-32 of the first file of the folder. `None` for a folder that holds no file.
    pub(crate) fn first_file(&self) -> Option<(u64, Option<u32>)> {
        (self.stored.files > 0).then_some((self.stored.first_size, self.stored.first_crc))
    }

    /// Whether the archive stores a CRC-32 for the folder or for one of its files.
    pub(crate) const fn has_crc(&self) -> bool {
        self.stored.any_crc
    }

    /// Where a packed stream of the folder lies in the archive, and its size. `None` for a
    /// stream the folder does not have, or one at a position no file reaches.
    pub(crate) fn pack(&self, number: usize) -> Option<(u64, u64)> {
        let streams = &self.archive.streams;
        let index = self.stored.first_pack.checked_add(number).filter(|_| number < self.stored.packs)?;
        let (start, end) = (*streams.pack_starts.get(index)?, *streams.pack_starts.get(index.checked_add(1)?)?);
        Some((START.checked_add(streams.pack_pos)?.checked_add(start)?, end.checked_sub(start)?))
    }

    /// Size of the packed streams of the folder together.
    pub(crate) fn packed(&self) -> Option<u64> {
        let starts = &self.archive.streams.pack_starts;
        let end = self.stored.first_pack.checked_add(self.stored.packs)?;
        starts.get(end)?.checked_sub(*starts.get(self.stored.first_pack)?)
    }
}

/// The names of the files that have data, read one at a time from the header.
#[derive(Debug)]
pub(crate) struct Names<'a> {
    /// The names: UTF-16, each ended by a zero.
    units: std::slice::ChunksExact<'a, u8>,
    /// A bit for every file, set for one without data.
    empty: &'a [u8],
    /// The number of the file the next name belongs to.
    file: u64,
    /// How many files there are.
    count: u64,
}

impl Iterator for Names<'_> {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        while self.file < self.count {
            let index = usize::try_from(self.file).ok()?;
            self.file = self.file.saturating_add(1);
            let has_data = self.empty.get(index / 8).is_none_or(|byte| byte & (0x80 >> (index % 8)) == 0);
            let mut name = Vec::new();
            for pair in self.units.by_ref() {
                match u16::from_le_bytes([pair.first().copied()?, pair.get(1).copied()?]) {
                    0 => break,
                    unit if has_data => name.push(unit),
                    _ => {},
                }
            }
            if has_data {
                return Some(String::from_utf16_lossy(&name));
            }
        }
        None
    }
}

impl Archive {
    /// An archive of which nothing was read but how its header stands.
    fn bare(headers: Headers) -> Self {
        Self { headers, header: Vec::new(), streams: Streams { pack_starts: vec![0], ..Streams::default() }, files: None }
    }

    /// The header the folders were read from: as the file stores it, or unpacked.
    #[cfg(test)]
    pub(crate) fn header_bytes(&self) -> &[u8] {
        &self.header
    }

    /// How many folders the header describes.
    pub(crate) const fn len(&self) -> usize {
        self.streams.folders.len()
    }

    /// The folders, in the order of the archive.
    pub(crate) fn folders(&self) -> impl Iterator<Item = Folder<'_>> {
        self.streams.folders.iter().enumerate().map(|(number, stored)| Folder { archive: self, stored, number })
    }

    /// One folder by its number.
    pub(crate) fn folder(&self, number: usize) -> Option<Folder<'_>> {
        self.streams.folders.get(number).map(|stored| Folder { archive: self, stored, number })
    }

    /// The names of the files that have data, in the order of the archive: the files of the
    /// first folder, then those of the second, and so on.
    ///
    /// `None` when the header does not give them: it has no list of files, the names are
    /// stored outside it, the list does not fit the folders, or it names more files than are
    /// kept ([`MAX_NAMES`]).
    pub(crate) fn names(&self) -> Option<Names<'_>> {
        let files = self.files.as_ref()?;
        let names = self.header.get(files.names.clone())?;
        let empty = files.empty.clone().map_or(Some(&[][..]), |range| self.header.get(range))?;

        // every file has a name that ends, and the files with data are those of the folders
        let ended = names.chunks_exact(2).filter(|pair| **pair == [0, 0]).count();
        let listed = usize::try_from(files.count).ok().filter(|&count| count <= ended)?;
        let marked = (0..listed).filter(|index| empty.get(index / 8).is_some_and(|byte| byte & (0x80 >> (index % 8)) != 0)).count();
        let with_data = u64::try_from(listed.checked_sub(marked)?).ok()?;
        let in_folders = self.streams.folders.iter().try_fold(0_u64, |sum, folder| sum.checked_add(folder.files))?;
        (with_data == in_folders && with_data <= MAX_NAMES).then(|| Names { units: names.chunks_exact(2), empty, file: 0, count: files.count })
    }
}

/// Unpack an LZMA or LZMA2 stream of a known size. No more than `size` bytes are unpacked for
/// it, whatever the stream goes on to hold.
fn unlzma(id: &[u8], props: &[u8], raw: &[u8], size: u64) -> anyhow::Result<Vec<u8>> {
    let decoded = if id == ID_LZMA {
        decode::lzma::<Vec<u8>>(raw, props, size)
    } else {
        // LZMA2 marks its own end: one byte more shows a stream that goes on past `size`
        decode::lzma2::<Vec<u8>>(raw, props, size.saturating_add(1))
    };
    match decoded {
        Decoded::Data(out) if u64::try_from(out.len()).is_ok_and(|len| len == size) => Ok(out),
        Decoded::Data(_) | Decoded::Corrupt => bail!("7z: its packed header does not unpack to the {size} bytes it declares"),
        Decoded::OverLimit => bail!("7z: its packed header declares {size} bytes, more than the {MAX_HEADER} that are unpacked in memory"),
    }
}

/// Where a header that is stored packed lies, and how it unpacks.
#[derive(Debug)]
struct PackedHeader {
    /// The identifier of its one coder.
    id: Vec<u8>,
    /// The start of the properties of that coder: all a decoder here reads of them.
    props: Vec<u8>,
    /// Where the packed stream lies in the archive.
    offset: u64,
    /// Size of the packed stream.
    stored: u64,
    /// Size of what it unpacks to.
    size: u64,
    /// The CRC-32 of what it unpacks to.
    crc: Option<u32>,
}

/// Find the header that `packed` describes: an archive whose one folder holds a header that is
/// stored packed and not encrypted.
///
/// The inner `Err` is the case of a header packed in a way this tool does not unpack. It
/// unpacks what 7-Zip and py7zr write: one coder, LZMA or LZMA2, or none at all.
fn packed_header(packed: &Archive) -> anyhow::Result<Result<PackedHeader, NoLine>> {
    let mut folders = packed.folders();
    let (Some(folder), None) = (folders.next(), folders.next()) else {
        bail!("7z: packed header with more than one folder");
    };
    let chain = folder.chain()?;
    let ([coder], [_]) = (chain.coders.as_slice(), chain.packed.as_slice()) else {
        return Ok(Err(NoLine::PackedHeaderCoder { id: chain.coders.iter().map(|coder| hex::encode(coder.id)).collect::<Vec<_>>().join("+") }));
    };
    if ![ID_COPY, ID_LZMA, ID_LZMA2].contains(&coder.id) {
        return Ok(Err(NoLine::PackedHeaderCoder { id: hex::encode(coder.id) }));
    }

    let size = folder.size();
    ensure!(size <= MAX_HEADER, "7z: its packed header declares {size} bytes, more than the {MAX_HEADER} that are unpacked in memory");
    let (offset, stored) = folder.pack(0).context("7z: its packed header does not lie inside the file")?;
    ensure!(stored <= MAX_HEADER, "7z: its packed header has {stored} bytes, more than the {MAX_HEADER} that are read");
    Ok(Ok(PackedHeader { id: coder.id.to_vec(), props: coder.props.iter().copied().take(5).collect(), offset, stored, size, crc: folder.crc() }))
}

/// Read a header that is stored packed and unpack it.
fn unpack_header(source: &Source, packed: &PackedHeader) -> anyhow::Result<Vec<u8>> {
    let size = packed.size;
    let raw = match source.read_at(packed.offset, packed.stored) {
        Ok(raw) => raw,
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => bail!("7z: its packed header does not lie inside the file"),
        Err(error) => return Err(error.into()),
    };

    let plain = if packed.id == ID_COPY {
        let mut plain = raw;
        ensure!(u64::try_from(plain.len()).is_ok_and(|len| len >= size), "7z: its packed header does not unpack to the {size} bytes it declares");
        plain.truncate(usize::try_from(size)?);
        plain
    } else {
        unlzma(&packed.id, &packed.props, &raw, size)?
    };
    ensure!(packed.crc.is_none_or(|crc| crc32fast::hash(&plain) == crc), "7z: its packed header does not unpack to what its checksum says");
    Ok(plain)
}

/// Read a header that is not packed: what follows its first byte, which says that it is one.
fn read_header(source: &Source, header: Vec<u8>) -> anyhow::Result<Archive> {
    let (streams, files) = {
        let mut reader = Reader::new(&header);
        ensure!(reader.number()? == K_HEADER, "7z: its header starts with an unknown field");
        let mut part = reader.number()?;

        if part == K_ARCHIVE_PROPERTIES {
            while reader.number()? != K_END {
                reader.skip_attribute()?;
            }
            part = reader.number()?;
        }
        if part == K_ADDITIONAL_STREAMS_INFO {
            drop(read_streams(&mut reader, false)?);
            part = reader.number()?;
        }
        let mut streams = Streams { pack_starts: vec![0], ..Streams::default() };
        if part == K_MAIN_STREAMS_INFO {
            streams = read_streams(&mut reader, true)?;
            if streams.external {
                return Ok(Archive::bare(Headers::Unread(NoLine::ExternalFolders)));
            }
            part = reader.number()?;
        }
        // a list of files that is damaged still leaves the folders, which is all a line needs
        let files = if part == K_FILES_INFO {
            read_files(&mut reader).unwrap_or_else(|error| {
                tracing::warn!("{}: the list of files cannot be read: {error}", source.path().display());
                None
            })
        } else {
            None
        };
        (streams, files)
    };
    Ok(Archive { headers: Headers::Readable, header, streams, files })
}

/// Read a 7z archive that starts where `source` starts.
///
/// An error for a file that is no 7z archive or whose header is damaged. A header that lies
/// past the end of the file, one that names its folders outside itself and one that is packed
/// in a way this tool does not unpack are no errors: the archive is handed back with
/// [`Headers::Unread`] and the case.
pub(crate) fn read(source: &Source) -> anyhow::Result<Archive> {
    let mut start = [0_u8; 32];
    match source.read_exact_at(0, &mut start) {
        Ok(()) => {},
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => bail!("not a 7z archive: the file ends inside its signature header"),
        Err(error) => return Err(error.into()),
    }
    let (Some(signature), Some(&major), Some(stored), Some(covered)) = (start.first_chunk::<6>(), start.get(6), start.get(8..12), start.get(12..32)) else {
        bail!("not a 7z archive");
    };
    ensure!(*signature == SIGNATURE, "not a 7z archive: no signature");
    ensure!(major == 0, "7z: an archive of a major version this tool does not know ({major})");
    ensure!(<[u8; 4]>::try_from(stored).is_ok_and(|stored| u32::from_le_bytes(stored) == crc32fast::hash(covered)), "7z: its signature header is damaged");

    let field = |at: usize| covered.get(at..at.saturating_add(8)).and_then(|bytes| <[u8; 8]>::try_from(bytes).ok()).map(u64::from_le_bytes);
    let (Some(offset), Some(size)) = (field(0), field(8)) else {
        bail!("not a 7z archive");
    };
    let crc = covered.get(16..20).and_then(|bytes| <[u8; 4]>::try_from(bytes).ok()).map(u32::from_le_bytes).context("not a 7z archive")?;

    // an archive without files has no header at all
    if size == 0 {
        return Ok(Archive::bare(Headers::Readable));
    }

    // the header is the last thing in an archive: the first volume of a split archive, and a
    // file that is cut short, do not hold it
    let Some(at) = START.checked_add(offset).filter(|at| at.checked_add(size).is_some_and(|end| end <= source.len())) else {
        return Ok(Archive::bare(Headers::Unread(NoLine::HeaderOutsideFile)));
    };
    ensure!(size <= MAX_HEADER, "7z: its header has {size} bytes, more than the {MAX_HEADER} that are read");
    let mut header = source.read_at(at, size)?;
    ensure!(crc32fast::hash(&header) == crc, "7z: its header is damaged");

    // The header as the file stores it, then what each packed header unpacks to. A packed
    // header only says where the next one lies in the file and how it unpacks, so it is dropped
    // before the next one is read: what is held at once is one packed stream and what it
    // unpacks to.
    for _ in 0..=MAX_NESTING {
        let streams = {
            let mut reader = Reader::new(&header);
            match reader.number()? {
                K_HEADER => None,
                K_ENCODED_HEADER => Some(read_streams(&mut reader, false)?),
                _ => bail!("7z: its header starts with an unknown field"),
            }
        };
        let Some(streams) = streams else {
            return read_header(source, header);
        };
        let packed = Archive { headers: Headers::Encrypted, header, streams, files: None };
        if packed.len() == 0 {
            // 7-Zip reads a packed header of no folder as an archive without files
            return Ok(Archive::bare(Headers::Readable));
        }
        if packed.folders().any(|folder| folder.is_encrypted()) {
            return Ok(packed);
        }
        let inner = match packed_header(&packed)? {
            Ok(inner) => inner,
            Err(why) => return Ok(Archive::bare(Headers::Unread(why))),
        };
        drop(packed);
        header = unpack_header(source, &inner)?;
    }

    bail!("7z: its header is packed too many times")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::formats::sevenz::craft;

    fn fixture(rel: &str) -> Source {
        Source::open(Path::new(&format!("tests/fixtures/{rel}")), 0).unwrap()
    }

    fn crafted(header: &[u8], packed: &[u8]) -> anyhow::Result<Archive> {
        read(&Source::from_bytes(craft::archive(header, packed)))
    }

    #[test]
    fn a_number_is_read_in_every_length_it_has() {
        for value in [0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1F_FFFF, 0x20_0000, 0xFFF_FFFF, 0x1000_0000, (1 << 35) - 1, 1 << 35, (1 << 42) - 1, 1 << 42, (1 << 49) - 1, 1 << 49, (1 << 56) - 1, 1 << 56, u64::MAX] {
            let bytes = craft::number(value);
            let mut reader = Reader::new(&bytes);
            assert_eq!((reader.number().unwrap(), reader.left()), (value, 0), "{bytes:02x?}");
        }
        // the first byte says how many follow, and they have to be there
        assert_eq!(Reader::new(&[0x2A]).number().unwrap(), 42);
        assert_eq!(Reader::new(&[0x80, 0xFF]).number().unwrap(), 255);
        assert_eq!(Reader::new(&[0xC1, 0x02, 0x03]).number().unwrap(), 0x01_0302);
        for cut in [&[][..], &[0x80], &[0xFF, 1, 2, 3, 4, 5, 6, 7]] {
            assert!(Reader::new(cut).number().is_err(), "{cut:02x?}");
        }
    }

    #[test]
    fn a_count_is_held_against_the_bytes_that_are_left() {
        // three things of two bytes each fit six bytes, and not five
        let mut bytes = craft::number(3);
        bytes.extend_from_slice(&[0; 6]);
        assert_eq!(Reader::new(&bytes).count(2).unwrap(), 3);
        assert!(Reader::new(&bytes[..6]).count(2).is_err());
        // a count of 2^62 costs an error and nothing else
        let mut bytes = craft::number(1 << 62);
        bytes.extend_from_slice(&[0; 16]);
        assert!(Reader::new(&bytes).count(1).is_err());
        assert!(Reader::new(&craft::number(u64::MAX)).count(1).is_err());
    }

    #[test]
    fn attributes_this_reader_does_not_know_are_skipped_by_their_size() {
        // an unknown attribute of three bytes, then the one that is waited for
        let mut reader = Reader::new(&[0x30, 0x03, 1, 2, 3, 0x0B, 0x55]);
        reader.wait(K_FOLDER).unwrap();
        assert_eq!(reader.byte().unwrap(), 0x55);
        // the end of the block comes first: the attribute is not there
        assert!(Reader::new(&[0x30, 0x00, 0x00, 0x0B]).wait(K_FOLDER).is_err());
        // a size that reaches past the header
        assert!(Reader::new(&[0x30, 0x05, 1, 2]).wait(K_FOLDER).is_err());
        let mut huge = vec![0x30];
        huge.extend(craft::number(u64::MAX));
        assert!(Reader::new(&huge).wait(K_FOLDER).is_err());
    }

    #[test]
    fn the_signature_header_is_checked_before_anything_else() {
        let good = craft::archive(&[], &[]);
        assert_eq!(read(&Source::from_bytes(good.clone())).unwrap().len(), 0);

        assert!(read(&Source::from_bytes(good[..31].to_vec())).is_err(), "too short for a signature header");
        let mut other = good.clone();
        other[0] = b'8';
        assert!(read(&Source::from_bytes(other)).is_err(), "no signature");
        let mut flipped = good.clone();
        flipped[20] ^= 1;
        assert!(read(&Source::from_bytes(flipped)).unwrap_err().to_string().contains("signature header is damaged"));
        let mut major = good;
        major[6] = 1;
        assert!(read(&Source::from_bytes(major)).unwrap_err().to_string().contains("major version"));

        // the header itself has a checksum too
        let mut archive = craft::archive(&craft::header(&[]), &[]);
        let last = archive.len() - 1;
        archive[last] ^= 0x40;
        assert!(read(&Source::from_bytes(archive)).unwrap_err().to_string().contains("its header is damaged"));
    }

    #[test]
    fn a_header_that_lies_past_the_end_of_the_file_is_not_read_and_is_no_error() {
        let whole = std::fs::read("tests/fixtures/7z-aes/7z_nonsolid_enc.7z").unwrap();
        // every cut that leaves the signature header: a first volume, or a file cut short
        for keep in [32, 33, whole.len() / 2, whole.len() - 1] {
            let archive = read(&Source::from_bytes(whole[..keep].to_vec())).unwrap();
            assert_eq!((archive.headers.clone(), archive.len()), (Headers::Unread(NoLine::HeaderOutsideFile), 0), "{keep} bytes");
        }
        // a position and a size that do not fit a number together
        let mut start = whole[..32].to_vec();
        start[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
        let crc = crc32fast::hash(&start[12..32]);
        start[8..12].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(read(&Source::from_bytes(start)).unwrap().headers, Headers::Unread(NoLine::HeaderOutsideFile));
    }

    #[test]
    fn the_folders_of_an_archive_are_read_with_their_sizes_and_their_files() {
        let archive = read(&fixture("7z-aes/7z_nonsolid_enc.7z")).unwrap();
        assert_eq!((archive.headers.clone(), archive.len()), (Headers::Readable, 3));
        for folder in archive.folders() {
            let chain = folder.chain().unwrap();
            // 7-Zip stores the checksum of a folder of one file with the file
            assert!(folder.is_encrypted() && folder.has_crc() && folder.crc().is_none());
            assert_eq!((folder.files(), chain.packed.len()), (1, 1));
            assert!(chain.coders.iter().any(|coder| coder.id == ID_AES && coder.is_cipher()));
            assert!(matches!(folder.first_file(), Some((size, Some(_))) if size == folder.size()), "one file is all its folder unpacks to");
            let (offset, packed) = folder.pack(0).unwrap();
            assert!(offset >= START && packed > 0 && packed % 16 == 0 && folder.packed() == Some(packed));
            assert_eq!(folder.pack(1), None);
        }
        let names: Vec<String> = archive.names().unwrap().collect();
        assert_eq!(names.len(), 3);

        // a solid folder holds several files, and the first has its own size and checksum
        let solid = read(&fixture("7z-aes/solid.7z")).unwrap();
        let folder = solid.folder(0).unwrap();
        assert!(solid.len() == 1 && folder.files() > 1);
        let (first, crc) = folder.first_file().unwrap();
        assert!(first < folder.size() && crc.is_some());
        assert_eq!(u64::try_from(solid.names().unwrap().count()).unwrap(), folder.files());
    }

    #[test]
    fn the_size_of_a_folder_is_that_of_the_coder_that_feeds_no_other() {
        // a filter in front of a packer: three coders, and the filter gives the output
        let archive = read(&fixture("7z-aes/bcj_lzma2.7z")).unwrap();
        let folder = archive.folder(0).unwrap();
        let chain = folder.chain().unwrap();
        assert_eq!(chain.coders.len(), 3);
        assert_eq!(folder.size(), folder.sizes()[chain.main]);
        // two files of 28 and 46 bytes, whatever the packer and the cipher put out on the way
        assert_eq!((folder.size(), folder.files(), folder.first_file().map(|(size, _)| size)), (74, 2, Some(28)));
        assert_eq!(chain.feeder(chain.first_input(chain.main).unwrap()).map(|feeder| chain.coders[feeder].id), Some(ID_LZMA2));
    }

    #[test]
    fn an_encrypted_header_gives_the_folder_of_the_header_and_no_names() {
        for rel in ["7z-aes/7z_hdr_lzma2.7z", "7z-aes/gen_py7zr_lzma2_hdr.7z"] {
            let archive = read(&fixture(rel)).unwrap();
            assert_eq!((archive.headers.clone(), archive.len()), (Headers::Encrypted, 1), "{rel}");
            assert!(archive.folder(0).unwrap().is_encrypted() && archive.names().is_none(), "{rel}");
        }
        // a header that is packed and not encrypted is unpacked, and its folders are the archive's
        let packed = read(&fixture("7z-aes/encrypted.7z")).unwrap();
        assert_eq!(packed.headers, Headers::Readable);
        assert!(packed.len() > 0 && packed.names().is_some());
    }

    #[test]
    fn a_folder_is_read_as_7_zip_reads_it() {
        let read_one = |coders: Vec<u8>| read_chain(&mut Reader::new(&coders)).map(|chain| (chain.coders.len(), chain.main, chain.packed.clone(), (0..11).map(|input| chain.feeder(input)).collect::<Vec<_>>(), chain.first_input(1)));

        let (coders, main, packed, feeders, _) = read_one(craft::chain(&[(craft::LZMA2, &[0x18]), (craft::AES, &[19])])).unwrap();
        assert_eq!((coders, main, packed.as_slice(), &feeders[..2]), (2, 0, &[1][..], &[Some(1), None][..]));

        let key = craft::aes_props(19, &[], &[7; 16]);
        let (coders, main, packed, feeders, second) = read_one(craft::bcj2([&key, &key, &key, &key])).unwrap();
        assert_eq!((coders, main, packed.as_slice(), second), (8, 0, &[7, 8, 9, 10][..], Some(4)));
        assert_eq!(feeders, [Some(1), Some(2), Some(3), Some(7), Some(4), Some(5), Some(6), None, None, None, None]);

        // no coder, 65 coders, an identifier of nine bytes, unknown flags, no input, two outputs
        assert!(read_one(craft::number(0)).is_err());
        assert!(read_one([craft::number(65), craft::coder(&[0], &[], None).repeat(65)].concat()).is_err());
        assert!(read_one([craft::number(1), craft::coder(&[1; 9], &[], None)].concat()).is_err());
        assert!(read_one(vec![1, 0x41, 0]).is_err());
        assert!(read_one([craft::number(1), craft::coder(&[0], &[], Some((0, 1)))].concat()).is_err());
        assert!(read_one([craft::number(1), craft::coder(&[0], &[], Some((1, 2)))].concat()).is_err());
        // 65 inputs over two coders
        assert!(read_one([craft::number(2), craft::coder(&[0], &[], Some((64, 1))), craft::coder(&[0], &[], None), vec![0, 1]].concat()).is_err());
        // an input named twice, a coder named twice, an input and a coder that are not there
        let three = [craft::number(3), craft::coder(&[0], &[], None).repeat(3)].concat();
        for bonds in [[0, 1, 0, 2], [0, 1, 1, 1], [3, 1, 0, 2], [0, 3, 1, 2]] {
            assert!(read_one([three.clone(), bonds.to_vec()].concat()).is_err(), "{bonds:?}");
        }
        // packed streams that name an input twice, one that a coder feeds, and one that is not there
        let join = [craft::number(2), craft::coder(&[0], &[], Some((3, 1))), craft::coder(&[0], &[], None), vec![0, 1]].concat();
        assert_eq!(read_one([join.clone(), vec![1, 2, 3]].concat()).unwrap().2, [1, 2, 3]);
        for packs in [[1, 1, 3], [0, 2, 3], [1, 2, 4]] {
            assert!(read_one([join.clone(), packs.to_vec()].concat()).is_err(), "{packs:?}");
        }
    }

    #[test]
    fn the_first_file_of_a_folder_has_its_own_size_and_checksum() {
        let key = craft::aes_props(19, &[], &[0; 16]);
        let coders = || craft::chain(&[(craft::LZMA2, &[0x18]), (craft::AES, &key)]);
        let folders = [
            // three files, the first and the last with a checksum
            craft::Folder { files: vec![(10, Some(0xAAAA_AAAA)), (20, None), (70, Some(0xCCCC_CCCC))], ..craft::Folder::new(coders(), &[100, 30], 32, None) },
            // one file and a checksum of the folder: it is not repeated among the files
            craft::Folder::new(coders(), &[50, 30], 32, Some(0x1111_1111)),
            // one file without any checksum
            craft::Folder::new(coders(), &[60, 30], 32, None),
            // two files of which the first has none
            craft::Folder { files: vec![(5, None), (2, Some(0xDDDD_DDDD))], ..craft::Folder::new(coders(), &[7, 16], 16, Some(0x2222_2222)) },
        ];
        let archive = read(&Source::from_bytes(craft::archive_of(&folders))).unwrap();
        let seen: Vec<_> = archive.folders().map(|folder| (folder.files(), folder.first_file(), folder.crc(), folder.has_crc(), folder.size())).collect();
        assert_eq!(seen, [(3, Some((10, Some(0xAAAA_AAAA))), None, true, 100), (1, Some((50, Some(0x1111_1111))), Some(0x1111_1111), true, 50), (1, Some((60, None)), None, false, 60), (2, Some((5, None)), Some(0x2222_2222), true, 7),]);
        // the packed streams lie one behind the other, from the end of the signature header
        let places: Vec<_> = archive.folders().map(|folder| folder.pack(0).unwrap()).collect();
        assert_eq!(places, [(32, 32), (64, 32), (96, 32), (128, 16)]);
        assert_eq!(archive.names().unwrap().collect::<Vec<_>>(), ["f0", "f1", "f2", "f3", "f4", "f5", "f6"]);

        // files that are larger than their folder, and several files without their sizes
        let larger = craft::Folder { files: vec![(101, None), (1, None)], ..craft::Folder::new(coders(), &[100, 30], 32, None) };
        assert!(read(&Source::from_bytes(craft::archive_of(&[larger]))).is_err());
        let mut header = vec![0x01, 0x04];
        header.extend(craft::streams(&[craft::Folder::new(coders(), &[100, 30], 32, None)], 0));
        let end = header.len() - 1;
        drop(header.splice(end..end, [0x08, 0x0D, 0x02, 0x00]));
        header.push(0x00);
        assert!(crafted(&header, &[0; 32]).unwrap_err().to_string().contains("several files and no sizes"));
    }

    #[test]
    fn names_are_given_to_the_files_that_have_data_and_to_no_other() {
        let key = craft::aes_props(19, &[], &[0; 16]);
        let folder = craft::Folder { files: vec![(10, None), (6, None)], ..craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[16], 16, None) };
        // the files of a list, the bits that mark the ones without data, and how many it says it has
        let build = |names: &[&str], empty: &[u8], count: u8| {
            let mut header = vec![0x01, 0x04];
            header.extend(craft::streams(std::slice::from_ref(&folder), 0));
            let mut files = craft::files(names);
            files[1] = count;
            let end = files.len() - 1;
            drop(files.splice(end..end, [&[0x0E, u8::try_from(empty.len()).unwrap()][..], empty].concat()));
            header.extend(files);
            header.push(0x00);
            crafted(&header, &[0; 16]).unwrap()
        };
        // five files: a directory, a file, an empty file, a file, a directory
        let archive = build(&["dir", "one", "none", "two", "last"], &[0b1010_1000], 5);
        assert_eq!(archive.names().unwrap().collect::<Vec<_>>(), ["one", "two"]);

        // a list that does not fit the folders gives no names at all: too few files with data,
        // and fewer names than files
        assert!(build(&["dir", "one", "none", "two", "last"], &[0b1110_1000], 5).names().is_none());
        assert!(build(&["dir", "one", "none", "two"], &[0b1010_1000], 5).names().is_none());
        // and one whose bits end before its files do still leaves the folders
        let mut header = vec![0x01, 0x04];
        header.extend(craft::streams(std::slice::from_ref(&folder), 0));
        header.extend_from_slice(&[0x05, 0x09, 0x0E, 0x01, 0x00, 0x00, 0x00]);
        let archive = crafted(&header, &[0; 16]).unwrap();
        assert!(archive.len() == 1 && archive.names().is_none());
    }

    #[test]
    fn folders_outside_the_header_and_a_header_packed_another_way_are_no_errors() {
        // the folders are in a stream the header only points to
        let external = [0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x10, 0x00, 0x07, 0x0B, 0x03, 0x01, 0x00];
        assert_eq!(crafted(&external, &[0; 16]).unwrap().headers, Headers::Unread(NoLine::ExternalFolders));
        // a packed header has no such stream to point to
        let mut inner = vec![0x17];
        inner.extend_from_slice(&external[2..]);
        assert!(crafted(&inner, &[0; 16]).is_err());

        // a header packed with PPMd, and one packed through two coders
        let ppmd = craft::packed_header(craft::chain(&[(craft::PPMD, &[6, 0, 0, 0, 1])]), &[100], 0, 16, None);
        assert_eq!(crafted(&ppmd, &[0; 16]).unwrap().headers, Headers::Unread(NoLine::PackedHeaderCoder { id: "030401".to_owned() }));
        let two = craft::packed_header(craft::chain(&[(&[0x03, 0x03, 0x01, 0x03], &[]), (craft::LZMA2, &[0x18])]), &[100, 100], 0, 16, None);
        assert_eq!(crafted(&two, &[0; 16]).unwrap().headers, Headers::Unread(NoLine::PackedHeaderCoder { id: "03030103+21".to_owned() }));
    }

    #[test]
    fn a_header_stored_packed_without_a_coder_is_read_and_nesting_ends() {
        let key = craft::aes_props(19, &[], &[0; 16]);
        let plain = craft::header(&[craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[16], 16, Some(1))]);
        let size = |bytes: &[u8]| u64::try_from(bytes.len()).unwrap();
        // the data of the folder, then the header as a stream of its own, then the header that says so
        let wrap = |inner: &[u8], pack_pos: u64, crc: Option<u32>| craft::packed_header(craft::chain(&[(&[0x00], &[])]), &[size(inner)], pack_pos, size(inner), crc);
        let packed = [vec![0; 16], plain.clone()].concat();
        let archive = crafted(&wrap(&plain, 16, Some(crc32fast::hash(&plain))), &packed).unwrap();
        assert_eq!((archive.headers.clone(), archive.len(), archive.folder(0).unwrap().size()), (Headers::Readable, 1, 16));
        assert_eq!(archive.names().unwrap().collect::<Vec<_>>(), ["f0"]);

        // a checksum that does not fit what was unpacked
        assert!(crafted(&wrap(&plain, 16, Some(1)), &packed).is_err());

        // a header packed four times inside itself is read; one packed five times is not
        let nest = |depth: usize| {
            let mut streams = packed.clone();
            let mut outer = plain.clone();
            let mut at = 16_u64;
            for _ in 0..depth {
                outer = wrap(&outer, at, None);
                at = size(&streams);
                streams.extend_from_slice(&outer);
            }
            crafted(&outer, &streams).map(|archive| archive.len())
        };
        assert_eq!(nest(MAX_NESTING).unwrap(), 1);
        assert!(nest(MAX_NESTING + 1).unwrap_err().to_string().contains("packed too many times"));
    }

    #[test]
    fn a_count_of_folders_past_the_limit_is_an_error() {
        let mut header = vec![0x01, 0x04, 0x07, 0x0B];
        header.extend(craft::number(u64::try_from(MAX_FOLDERS).unwrap() + 1));
        header.push(0x00);
        header.extend(std::iter::repeat_n([0x01, 0x00], MAX_FOLDERS + 1).flatten());
        assert!(crafted(&header, &[]).unwrap_err().to_string().contains("more than the"));
        // and a count that the header could not hold is one before that
        let mut header = vec![0x01, 0x04, 0x07, 0x0B];
        header.extend(craft::number(1 << 40));
        header.extend_from_slice(&[0x00, 0x01, 0x00]);
        assert!(crafted(&header, &[]).unwrap_err().to_string().contains("impossible count"));

        // more packed streams than four for every folder there may be
        let packs = MAX_PACKS + 1;
        let mut header = vec![0x01, 0x04, 0x06, 0x00];
        header.extend(craft::number(u64::try_from(packs).unwrap()));
        header.push(0x09);
        header.extend(std::iter::repeat_n(0x10, packs));
        assert!(crafted(&header, &[]).unwrap_err().to_string().contains("packed streams, more than"));

        // more coders together than sixteen for every folder there may be: 64 in each of 65,537
        let folders = MAX_ALL_CODERS / MAX_CODERS + 1;
        let wide = [craft::number(64), vec![0x00; 64], (1..64).flat_map(|feeder| [feeder - 1, feeder]).collect()].concat();
        let mut header = vec![0x01, 0x04, 0x06, 0x00];
        header.extend(craft::number(u64::try_from(folders).unwrap()));
        header.push(0x09);
        header.extend(std::iter::repeat_n(0x10, folders));
        header.extend_from_slice(&[0x00, 0x07, 0x0B]);
        header.extend(craft::number(u64::try_from(folders).unwrap()));
        header.push(0x00);
        header.extend(std::iter::repeat_n(wide, folders).flatten());
        assert!(crafted(&header, &[]).unwrap_err().to_string().contains("more coders together"));
    }
}
