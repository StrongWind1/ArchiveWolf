//! Packers: the Deflate stream of a file, byte for byte as the program that wrote an archive
//! makes it.
//!
//! An entry that is packed and then encrypted gives known plaintext only to someone who can
//! pack the same file the same way. Deflate leaves
//! the packer free in what it writes, so "the same way" means the same code with the same
//! settings. Two programs are here, each at every setting it has:
//!
//! - **zlib**, which most libraries and tools call: levels 1 to 9, memory levels 1 to 9 and
//!   the five strategies. The stream is that of `deflateInit2(level, Z_DEFLATED, -15,
//!   mem_level, strategy)`, the whole input, and `Z_FINISH`.
//! - **Info-ZIP `zip` 3.0**, which has a Deflate of its own, the ancestor of zlib's:
//!   `zip -1` to `zip -9`. It hashes as zlib does at memory level 8 and fills its blocks as
//!   zlib does at memory level 9, and it has two rules that zlib has not: from level 3 on it
//!   ends a block early where it guesses that this pays, and it stores a file that did not
//!   pack. So no setting of zlib gives its streams, except for inputs on which none of that
//!   shows.
//!
//! Both are ports of the C code, and both are held to streams that the real programs wrote:
//! `tests/packers/` has the recordings and says how they were made.

mod deflate;
#[cfg(test)]
mod tests;
mod trees;

use self::deflate::Engine;
use self::deflate::Finder;
use self::deflate::Settings;
use self::trees::Rules;

/// The entry of a table at an index, and the default of its type where the table has none.
fn at<T: Copy + Default>(table: &[T], index: usize) -> T {
    table.get(index).copied().unwrap_or_default()
}

/// Writes one entry of a table. An index that the table does not have writes nothing.
fn put<T>(table: &mut [T], index: usize, value: T) {
    if let Some(entry) = table.get_mut(index) {
        *entry = value;
    }
}

/// The low 16 bits of a number: what a cast to `ush` leaves of it in the C code.
fn low16(value: usize) -> u16 {
    u16::try_from(value & 0xffff).unwrap_or(u16::MAX)
}

/// The low 8 bits of a number: what a cast to `uch` leaves of it in the C code.
fn low8(value: usize) -> u8 {
    u8::try_from(value & 0xff).unwrap_or(u8::MAX)
}

/// The strategies of zlib (`Z_DEFAULT_STRATEGY` to `Z_FIXED`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Strategy {
    /// `Z_DEFAULT_STRATEGY`.
    Default,
    /// `Z_FILTERED`: matches of five bytes and under are not taken. From level 4 on.
    Filtered,
    /// `Z_HUFFMAN_ONLY`: no matches. The level changes nothing.
    HuffmanOnly,
    /// `Z_RLE`: runs of one byte and no other matches. The level changes nothing.
    Rle,
    /// `Z_FIXED`: every block that is not stored has the fixed codes.
    Fixed,
}

/// One program's way of packing at one setting.
///
/// A level or a memory level outside 1 to 9 is taken as the nearest inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Packer {
    /// zlib: `deflateInit2(level, Z_DEFLATED, -15, mem_level, strategy)`, the whole input,
    /// and `Z_FINISH`.
    Zlib {
        /// The level, 1 to 9. Level 0 is not offered: what it writes depends on the sizes of
        /// the buffers of the caller.
        level: u8,
        /// The memory level, 1 to 9. zlib's own default is 8.
        mem_level: u8,
        /// The strategy.
        strategy: Strategy,
    },
    /// Info-ZIP `zip` 3.0 with its own Deflate: `zip -1` to `zip -9`.
    InfoZip {
        /// The level, 1 to 9. The default of `zip` is 6.
        level: u8,
    },
}

/// What the program puts into the archive for a file it has packed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Method {
    /// The stream, as method 8.
    Deflate,
    /// The file itself, as method 0. Info-ZIP does that with a file that packs into one block
    /// and is not smaller for it, when it can seek back in the archive to say so in the
    /// header of the entry. The stream is then what it writes when it cannot: to a pipe.
    Store,
}

impl Packer {
    /// The name of the packer in words, as in "zlib level 6, memory level 8".
    #[must_use]
    pub(crate) fn name(self) -> String {
        match self {
            Self::Zlib { level, mem_level, strategy } => {
                let strategy = match strategy {
                    Strategy::Default => "",
                    Strategy::Filtered => ", strategy filtered",
                    Strategy::HuffmanOnly => ", strategy Huffman only",
                    Strategy::Rle => ", strategy RLE",
                    Strategy::Fixed => ", strategy fixed",
                };
                format!("zlib level {}, memory level {}{strategy}", level.clamp(1, 9), mem_level.clamp(1, 9))
            },
            Self::InfoZip { level } => format!("Info-ZIP level {}", level.clamp(1, 9)),
        }
    }

    /// The raw Deflate stream of the whole input.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pack(self, data: &[u8]) -> Vec<u8> {
        self.pack_entry(data).0
    }

    /// The raw Deflate stream of the whole input, and what the program puts into the archive:
    /// that stream, or the input itself.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn pack_entry(self, data: &[u8]) -> (Vec<u8>, Method) {
        let mut stream = Vec::new();
        let mut deflater = Deflater::new(self);
        deflater.update(data, &mut stream);
        let method = deflater.finish(&mut stream);
        (stream, method)
    }

    /// The parts of the packer.
    fn settings(self) -> Settings {
        match self {
            Self::Zlib { level, mem_level, strategy } => {
                let mem_level = mem_level.clamp(1, 9);
                let finder = match strategy {
                    Strategy::HuffmanOnly => Finder::Huffman,
                    Strategy::Rle => Finder::Rle,
                    Strategy::Default | Strategy::Filtered | Strategy::Fixed => Finder::Level,
                };
                // deflateInit2: hash_bits = memLevel + 7, lit_bufsize = 1 << (memLevel + 6)
                let rules = Rules { block_symbols: (1 << (mem_level + 6)) - 1, fixed: strategy == Strategy::Fixed, stores_file: false };
                Settings { level: level.clamp(1, 9), hash_bits: u32::from(mem_level) + 7, finder, filtered: strategy == Strategy::Filtered, guesses_end: false, rules }
            },
            Self::InfoZip { level } => {
                let level = level.clamp(1, 9);
                // deflate.c and trees.c of zip: HASH_BITS is 15 and LIT_BUFSIZE 0x8000
                let rules = Rules { block_symbols: 0x8000 - 1, fixed: false, stores_file: true };
                Settings { level, hash_bits: 15, finder: Finder::Level, filtered: false, guesses_end: level > 2, rules }
            },
        }
    }
}

/// A packer at work on one input that comes in pieces, in memory that does not grow with it.
///
/// [`Deflater::update`] is `deflate` of zlib with `Z_NO_FLUSH`, and [`Deflater::finish`] is
/// `deflate` with `Z_FINISH`, with one difference: the stream is that of the whole input
/// given in one piece, however the input is cut. zlib itself writes another stream for some
/// cuts that are not at a multiple of 512 bytes, which `deflate.rs` says more about.
#[derive(Debug)]
pub(crate) struct Deflater {
    /// The state of the stream.
    engine: Engine,
}

impl Deflater {
    /// A packer before its first byte.
    #[must_use]
    pub(crate) fn new(packer: Packer) -> Self {
        Self { engine: Engine::new(&packer.settings()) }
    }

    /// Takes the next piece of the input, and appends to `out` the part of the stream that
    /// is final with it. Up to a block of the stream is held back.
    pub(crate) fn update(&mut self, input: &[u8], out: &mut Vec<u8>) {
        self.engine.deflate(input, false, out);
    }

    /// Ends the input: appends the rest of the stream to `out`, and says what the program
    /// puts into the archive.
    pub(crate) fn finish(mut self, out: &mut Vec<u8>) -> Method {
        self.engine.deflate(&[], true, out);
        if self.engine.stores_file() { Method::Store } else { Method::Deflate }
    }
}
