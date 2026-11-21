//! Decompression of untrusted streams within fixed bounds.
//!
//! One function per codec, all with the same shape: the packed bytes, what the archive says about
//! the coder, and `want`, the number of bytes the caller expects the stream to unpack to. A
//! decode never produces more than `want` bytes, never produces more than its sink may take
//! ([`Sink::MAX`]) and never gives a decoder more than [`MAX_DECODER_MEMORY`] for a dictionary.
//! Those bounds hold for the memory in use at any moment and not only for what is returned:
//! output leaves the decoder in small pieces, and a dictionary is sized from what the stream can
//! produce here and not from what its header claims.
//!
//! The codecs are the ones the tool decodes at all. LZMA and LZMA2 are what a packed 7z header
//! is stored with: they take the packed bytes as a slice, and a header is small. Stored data and
//! Deflate are what the proof of pseudo-encryption unpacks: [`stored`] and [`deflate`] take a
//! reader, so the data of an entry comes straight from a range of its
//! [`Source`](super::source::Source) and is never held whole.
//!
//! The sink decides what is kept. `Vec<u8>` keeps the bytes, up to [`MAX_DECODE_BUFFER`].
//! [`Summary`] keeps their length and CRC-32, up to [`MAX_DECODE_OUTPUT`]. One archive is held
//! to [`MAX_ARCHIVE_WORK`](super::limits::MAX_ARCHIVE_WORK) across its entries by a
//! [`Budget`](super::limits::Budget), which the caller asks before each decode.
//!
//! A caller has three outcomes to tell apart ([`Decoded`]). `Corrupt` says the stream is not
//! what the archive describes: for a marked entry, that it is encrypted. `OverLimit` does not:
//! it says that nothing was unpacked and nothing is known.

use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;

use super::limits::MAX_DECODE_BUFFER;
use super::limits::MAX_DECODE_OUTPUT;
use super::limits::MAX_DECODER_MEMORY;
use super::limits::capacity_for;

/// How a bounded decode ended.
#[derive(Debug)]
pub enum Decoded<S> {
    /// The stream unpacked into the sink. It holds at most the bytes that were asked for, and
    /// fewer when the stream ended first, so the caller compares the length with what it expects.
    Data(S),
    /// The stream is not valid for its codec, or could not be read: what encrypted data and a
    /// damaged archive produce.
    Corrupt,
    /// Unpacking would take more output or more decoder memory than the limits allow. The stream
    /// was not judged: it may be valid.
    OverLimit,
}

/// Where the output of a decode goes.
pub trait Sink: Write {
    /// The most bytes one decode may give this sink.
    const MAX: u64;

    /// An empty sink for `packed` bytes of input that are asked for `want` bytes of output.
    /// `packed` is `usize::MAX` when the input is a reader, whose length is not known.
    fn start(want: u64, packed: usize) -> Self;
}

impl Sink for Vec<u8> {
    const MAX: u64 = MAX_DECODE_BUFFER;

    fn start(want: u64, packed: usize) -> Self {
        Self::with_capacity(capacity_for(want, packed, 1))
    }
}

/// The length and CRC-32 of an output that is not kept.
#[derive(Debug, Clone, Default)]
pub struct Summary {
    len: u64,
    hasher: crc32fast::Hasher,
}

impl Summary {
    /// How many bytes came out.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether nothing came out.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The CRC-32 of the bytes that came out.
    #[must_use]
    pub fn crc32(self) -> u32 {
        self.hasher.finalize()
    }
}

impl Write for Summary {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.len = self.len.saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink for Summary {
    const MAX: u64 = MAX_DECODE_OUTPUT;

    fn start(_want: u64, _packed: usize) -> Self {
        Self::default()
    }
}

/// Move up to `left` bytes from a decoder into a sink and return how many came. `Err` is how the
/// decode ended when the decoder failed.
fn copy<S: Sink>(reader: impl Read, left: u64, sink: &mut S) -> Result<u64, Decoded<S>> {
    match std::io::copy(&mut reader.take(left), sink) {
        Ok(count) => Ok(count),
        // a decoder that would need more memory than it was allowed
        Err(error) if error.kind() == ErrorKind::OutOfMemory => Err(Decoded::OverLimit),
        Err(_) => Err(Decoded::Corrupt),
    }
}

/// Unpack up to `want` bytes from a decoder into a new sink.
fn drain<S: Sink>(reader: impl Read, want: u64, packed: usize) -> Decoded<S> {
    let mut sink = S::start(want, packed);
    match copy(reader, want, &mut sink) {
        Ok(_) => Decoded::Data(sink),
        Err(end) => end,
    }
}

/// The window to give an LZ decoder for a stream that names a dictionary of `dictionary` bytes
/// and is asked for `want` bytes. A stream cannot reach further back than it has put out, so the
/// smaller of the two is all it can use. `None` when that is more than a decoder may have.
fn window(dictionary: u64, want: u64) -> Option<u32> {
    let needed = u32::try_from(dictionary.min(want)).ok()?;
    (needed <= MAX_DECODER_MEMORY).then_some(needed.max(lzma_rust2::DICT_SIZE_MIN))
}

/// The dictionary size an LZMA2 property byte stands for.
fn lzma2_dictionary(prop: u8) -> Option<u64> {
    match prop {
        0..=39 => Some((2 | u64::from(prop & 1)) << (prop / 2 + 11)),
        40 => Some(u64::from(u32::MAX)),
        _ => None,
    }
}

/// Stored data, as ZIP method 0 keeps it: the first `want` bytes of `packed` as they are.
///
/// `packed` is a reader, so the data can come from a range of a
/// [`Source`](super::source::Source) and is never in memory as a whole.
pub fn stored<S: Sink>(packed: impl Read, want: u64) -> Decoded<S> {
    if want > S::MAX {
        return Decoded::OverLimit;
    }
    drain(packed, want, usize::MAX)
}

/// Raw Deflate, as ZIP method 8 stores it.
///
/// `packed` is a reader, so the stream can come from a range of a
/// [`Source`](super::source::Source) and is never in memory as a whole. A stream that ends
/// before `want` bytes gives what it holds, and one that goes on is not read past them, so a
/// caller that asks for one byte more than the entry declares sees both.
pub fn deflate<S: Sink>(packed: impl Read, want: u64) -> Decoded<S> {
    if want > S::MAX {
        return Decoded::OverLimit;
    }
    drain(flate2::read::DeflateDecoder::new(packed), want, usize::MAX)
}

/// A raw LZMA stream of exactly `want` bytes. `props` is the five bytes a 7z coder stores for
/// it: the `lc`/`lp`/`pb` byte and the dictionary size.
///
/// The stream does not mark its end, so `want` is part of how it is framed and not only a bound:
/// a stream that holds fewer bytes is corrupt, and one that holds more is corrupt when `want`
/// falls inside a match.
pub(crate) fn lzma<S: Sink>(packed: &[u8], props: &[u8], want: u64) -> Decoded<S> {
    if want > S::MAX {
        return Decoded::OverLimit;
    }
    let Some(&[model, d0, d1, d2, d3]) = props.first_chunk::<5>() else {
        return Decoded::Corrupt;
    };
    let Some(window) = window(u64::from(u32::from_le_bytes([d0, d1, d2, d3])), want) else {
        return Decoded::OverLimit;
    };
    match lzma_rust2::LzmaReader::new_with_props(packed, want, model, window, None) {
        Ok(reader) => drain(reader, want, packed.len()),
        Err(_) => Decoded::Corrupt,
    }
}

/// A raw LZMA2 stream. `props` is the one byte a 7z coder stores for it: the dictionary size.
pub(crate) fn lzma2<S: Sink>(packed: &[u8], props: &[u8], want: u64) -> Decoded<S> {
    if want > S::MAX {
        return Decoded::OverLimit;
    }
    let Some(dictionary) = props.first().copied().and_then(lzma2_dictionary) else {
        return Decoded::Corrupt;
    };
    let Some(window) = window(dictionary, want) else {
        return Decoded::OverLimit;
    };
    drain(lzma_rust2::Lzma2Reader::new(packed, window, None), want, packed.len())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::formats::limits::Budget;
    use crate::formats::limits::MAX_ARCHIVE_WORK;
    use crate::formats::source::Source;

    // Streams of `text()` and of zero bytes that this crate has no encoder for. They come from
    // Python's `lzma` module: raw LZMA1 and LZMA2 with a 64 KiB dictionary.
    /// `text()` as raw LZMA.
    const LZMA_TEXT: &str = "003a1a08ce76c7e5e9d60734c3d10ebfce55e1aabde0e48f9801dd8de507549e65255f273a6a7eb4d349033841487d3bf329e6f3ffffb5d00000";
    /// One mebibyte of zero bytes as raw LZMA.
    const LZMA_ZEROS: &str = concat!(
        "00006ffdffffa3b7ff473e481572396151b89228e6a38607f9eee41e82d32fc53a3c014bb17ec98a8a4d2fa30dd97fa6e38c231153e05918c5758ae277f8b6947f0c6ac0de74",
        "4964e2e95c53b204d8f7440cab5f0d6d46e9e5c37688b79657acb64de1691d6ffb4b88106c42cb883f5c008fd04eaf262894711f3d8f24e1709ea7235fec28cb85d195988a7e",
        "2a91f22775f719c006984d98fdd8afd5900fc42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55b0508f9c7daadfc",
        "fb522af7e51cdccfffff82160000",
    );
    /// `text()` as raw LZMA2.
    const LZMA2_TEXT: &str = "e0016700335d003a1a08ce76c7e5e9d60734c3d10ebfce55e1aabde0e48f9801dd8de507549e65255f273a6a7eb4d349033841487d3bf290c00000";
    /// One LZMA2 chunk of zero bytes, without the byte that ends a stream.
    const LZMA2_CHUNK: &str = concat!(
        "ffff11016c5d00006ffdffffa3b7ff473e481572396151b89228e6a38607f9eee41e82d32fc53a3c014bb17ec98a8a4d2fa30dd97fa6e38c231153e05918c5758ae277f8b694",
        "7f0c6ac0de744964e2e95c53b204d8f7440cab5f0d6d46e9e5c37688b79657acb64de1691d6ffb4b88106c42cb883f5c008fd04eaf262894711f3d8f24e1709ea7235fec28cb",
        "85d195988a7e2a91f22775f719c006984d98fdd8afd5900fc42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55b05",
        "08f9c7daadfcfb522b74cd1e5b2042f9dd533df82964093b80cb2a6cdfb53bf0c4bd2e5faa0f3e4b664290130eff1093f8717859f80bcdff9528460fa9fc7cdefb9a302e56c0",
        "8f85f38381c065c42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55b0508f9c7daadfcfb522b74cd1e5b2042f9dd",
        "533df82964093b80cb2a6cdfb53bf0c4bc4827e658",
    );
    /// The properties of the LZMA streams above: lc=3 lp=0 pb=2 and a 64 KiB dictionary.
    const LZMA_PROPS: [u8; 5] = [0x5D, 0x00, 0x00, 0x01, 0x00];
    /// The LZMA2 property byte for a 64 KiB dictionary.
    const LZMA2_PROPS: [u8; 1] = [0x08];
    /// How many zero bytes `LZMA2_CHUNK` unpacks to. The chunk resets the dictionary, so any
    /// number of copies in a row is a valid stream.
    const LZMA2_CHUNK_SIZE: u64 = 2_096_914;

    fn text() -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog, ".repeat(8)
    }

    fn unhex(digits: &str) -> Vec<u8> {
        hex::decode(digits).unwrap()
    }

    fn size(data: &[u8]) -> u64 {
        u64::try_from(data.len()).unwrap()
    }

    /// An LZMA2 stream of `chunks * LZMA2_CHUNK_SIZE` zero bytes, 371 packed bytes for each chunk.
    fn lzma2_zeros(chunks: usize) -> Vec<u8> {
        let mut stream = unhex(LZMA2_CHUNK).repeat(chunks);
        stream.push(0);
        stream
    }

    fn deflated(data: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn kept(decoded: Decoded<Vec<u8>>) -> Vec<u8> {
        match decoded {
            Decoded::Data(bytes) => bytes,
            other => panic!("expected data, got {other:?}"),
        }
    }

    fn summed(decoded: Decoded<Summary>) -> (u64, u32) {
        match decoded {
            Decoded::Data(summary) => (summary.len(), summary.crc32()),
            other => panic!("expected data, got {other:?}"),
        }
    }

    /// Both sinks got `expected`: one holds it, the other its length and CRC-32.
    fn agree(codec: &str, expected: &[u8], bytes: Decoded<Vec<u8>>, summary: Decoded<Summary>) {
        assert_eq!(kept(bytes), expected, "{codec}");
        assert_eq!(summed(summary), (size(expected), crc32fast::hash(expected)), "{codec}");
    }

    #[test]
    fn every_codec_gives_back_what_was_packed() {
        let text = text();
        let len = size(&text);

        agree("stored", &text, stored(text.as_slice(), len), stored(text.as_slice(), len));
        let packed = deflated(&text);
        agree("deflate", &text, deflate(packed.as_slice(), len), deflate(packed.as_slice(), len));
        let packed = unhex(LZMA_TEXT);
        agree("lzma", &text, lzma(&packed, &LZMA_PROPS, len), lzma(&packed, &LZMA_PROPS, len));
        let packed = unhex(LZMA2_TEXT);
        agree("lzma2", &text, lzma2(&packed, &LZMA2_PROPS, len), lzma2(&packed, &LZMA2_PROPS, len));
    }

    #[test]
    fn a_summary_of_nothing_is_empty() {
        let nothing: Decoded<Summary> = stored([].as_slice(), 0);
        let Decoded::Data(summary) = nothing else { panic!("expected data") };
        assert!(summary.is_empty());
        assert_eq!((summary.len(), summary.crc32()), (0, 0));
    }

    /// A stream that marks its own end gives what it holds when it is asked for more, so a caller
    /// that asks for one byte past the declared size sees whether the stream ends there.
    #[test]
    fn a_stream_that_ends_early_gives_what_it_holds() {
        let text = text();
        let more = size(&text) + 1;
        assert_eq!(kept(stored(text.as_slice(), more)), text);
        assert_eq!(kept(deflate(deflated(&text).as_slice(), more)), text);
        assert_eq!(kept(lzma2(&unhex(LZMA2_TEXT), &LZMA2_PROPS, more)), text);
    }

    /// The streams here unpack to between a few thousand bytes and four gigabytes. Asked for a
    /// thousand bytes they give a thousand, and the rest is never unpacked: the four-gigabyte one
    /// would take minutes and gigabytes otherwise.
    #[test]
    fn a_decode_gives_no_more_than_it_is_asked_for() {
        const WANT: u64 = 1000;
        let expected = vec![0_u8; 1000];

        agree("stored", &expected, stored([0_u8; 4000].as_slice(), WANT), stored([0_u8; 4000].as_slice(), WANT));
        let packed = deflated(&vec![0_u8; 8 << 20]);
        agree("deflate", &expected, deflate(packed.as_slice(), WANT), deflate(packed.as_slice(), WANT));
        let packed = lzma2_zeros(2048);
        agree("lzma2", &expected, lzma2(&packed, &LZMA2_PROPS, WANT), lzma2(&packed, &LZMA2_PROPS, WANT));
    }

    /// The size of an LZMA stream is part of how it is framed. One megabyte of zeros asked for a
    /// thousand bytes ends inside a match: that is not the stream the caller described.
    #[test]
    fn an_lzma_stream_has_to_be_the_size_it_is_asked_for() {
        let packed = unhex(LZMA_ZEROS);
        assert_eq!(kept(lzma(&packed, &LZMA_PROPS, 1 << 20)), vec![0_u8; 1 << 20]);
        assert!(matches!(lzma::<Vec<u8>>(&packed, &LZMA_PROPS, 1000), Decoded::Corrupt));
        assert!(matches!(lzma::<Vec<u8>>(&packed, &LZMA_PROPS, (1 << 20) + 1), Decoded::Corrupt));
    }

    /// Asking for more than a sink may take is refused before the stream is looked at: these
    /// inputs are noise, and a decode that started on them would call them corrupt.
    #[test]
    fn more_than_a_sink_may_take_is_refused_untouched() {
        let noise = [0xA5_u8; 64];

        let over = MAX_DECODE_BUFFER + 1;
        assert!(matches!(stored::<Vec<u8>>(noise.as_slice(), over), Decoded::OverLimit));
        assert!(matches!(deflate::<Vec<u8>>(noise.as_slice(), over), Decoded::OverLimit));
        assert!(matches!(lzma::<Vec<u8>>(&noise, &LZMA_PROPS, over), Decoded::OverLimit));
        assert!(matches!(lzma2::<Vec<u8>>(&noise, &LZMA2_PROPS, over), Decoded::OverLimit));
        assert!(matches!(lzma2::<Vec<u8>>(&noise, &LZMA2_PROPS, u64::MAX), Decoded::OverLimit));
    }

    /// The same for a sink that keeps nothing: its limit is on the time a decode takes.
    #[test]
    fn more_than_may_be_unpacked_at_all_is_refused_untouched() {
        let noise = [0xA5_u8; 64];

        let over = MAX_DECODE_OUTPUT + 1;
        assert!(matches!(stored::<Summary>(noise.as_slice(), over), Decoded::OverLimit));
        assert!(matches!(deflate::<Summary>(noise.as_slice(), over), Decoded::OverLimit));
        assert!(matches!(lzma::<Summary>(&noise, &LZMA_PROPS, over), Decoded::OverLimit));
        assert!(matches!(lzma2::<Summary>(&noise, &LZMA2_PROPS, over), Decoded::OverLimit));
        assert!(matches!(deflate::<Summary>(noise.as_slice(), u64::MAX), Decoded::OverLimit));
    }

    /// The most a sink may take is allowed, and costs nothing until the stream produces it.
    #[test]
    fn the_limit_itself_is_allowed() {
        let text = text();
        assert_eq!(kept(deflate(deflated(&text).as_slice(), MAX_DECODE_BUFFER)), text);
        assert_eq!(kept(lzma2(&unhex(LZMA2_TEXT), &LZMA2_PROPS, MAX_DECODE_BUFFER)), text);
        assert_eq!(summed(deflate(deflated(&text).as_slice(), MAX_DECODE_OUTPUT)), (size(&text), crc32fast::hash(&text)));
        assert_eq!(summed(stored(text.as_slice(), MAX_DECODE_OUTPUT)), (size(&text), crc32fast::hash(&text)));
    }

    /// What the proof of pseudo-encryption does with these parts: the data of an entry comes
    /// from a range of the archive, its length and CRC-32 are all that is kept, and the archive
    /// as a whole has a budget.
    #[test]
    fn an_entry_is_checked_from_a_range_of_its_archive() {
        let text = text();
        let packed = deflated(&text);
        let mut archive = vec![0xEE; 100];
        archive.extend_from_slice(&packed);
        archive.extend_from_slice(&text);
        let source = Source::from_bytes(archive);
        let (packed_len, len) = (size(&packed), size(&text));
        let expected = (len, crc32fast::hash(&text));

        let mut budget = Budget::new();
        assert!(budget.take(len));
        assert_eq!(summed(deflate(source.reader(100, packed_len).unwrap(), len + 1)), expected, "a Deflate entry");
        assert!(budget.take(len));
        assert_eq!(summed(stored(source.reader(100 + packed_len, len).unwrap(), len)), expected, "a stored entry");

        // the same range read as the wrong thing: not what the archive describes
        assert!(matches!(deflate::<Summary>(source.reader(0, 100).unwrap(), len), Decoded::Corrupt));
        // an entry that says it unpacks to more than one entry may: nothing is read for it
        assert!(matches!(deflate::<Summary>(source.reader(100, packed_len).unwrap(), MAX_DECODE_OUTPUT + 1), Decoded::OverLimit));
        // and one the archive has no budget left for is not started
        assert!(!budget.take(MAX_ARCHIVE_WORK));
    }

    #[test]
    fn noise_is_corrupt() {
        let noise = [0xA5_u8; 64];
        assert!(matches!(deflate::<Vec<u8>>([0xFF_u8; 64].as_slice(), 100), Decoded::Corrupt));
        assert!(matches!(deflate::<Summary>(noise.as_slice(), 100), Decoded::Corrupt));
        assert!(matches!(lzma::<Vec<u8>>(&[0xFF; 64], &LZMA_PROPS, 100), Decoded::Corrupt));
        assert!(matches!(lzma2::<Vec<u8>>(&noise, &LZMA2_PROPS, 100), Decoded::Corrupt));
        // nothing to unpack is not a stream either
        assert!(matches!(lzma::<Vec<u8>>(&[], &LZMA_PROPS, 100), Decoded::Corrupt));
    }

    #[test]
    fn properties_that_are_not_properties_are_corrupt() {
        let text = text();
        let len = size(&text);
        assert!(matches!(lzma::<Vec<u8>>(&unhex(LZMA_TEXT), &LZMA_PROPS[..4], len), Decoded::Corrupt));
        assert!(matches!(lzma::<Vec<u8>>(&unhex(LZMA_TEXT), &[0xFF, 0, 0, 1, 0], len), Decoded::Corrupt));
        assert!(matches!(lzma2::<Vec<u8>>(&unhex(LZMA2_TEXT), &[], len), Decoded::Corrupt));
        assert!(matches!(lzma2::<Vec<u8>>(&unhex(LZMA2_TEXT), &[41], len), Decoded::Corrupt));
    }

    #[test]
    fn an_lzma2_property_byte_names_a_dictionary() {
        assert_eq!(lzma2_dictionary(0), Some(4096));
        assert_eq!(lzma2_dictionary(1), Some(6144));
        assert_eq!(lzma2_dictionary(8), Some(1 << 16));
        assert_eq!(lzma2_dictionary(0x18), Some(1 << 24));
        assert_eq!(lzma2_dictionary(39), Some(3 << 30));
        assert_eq!(lzma2_dictionary(40), Some(0xFFFF_FFFF));
        assert_eq!(lzma2_dictionary(41), None);
        assert_eq!(lzma2_dictionary(0xFF), None);
    }

    /// A header may name a dictionary of 4 GiB for a stream of a few hundred bytes. The window is
    /// sized by what the stream can put out.
    #[test]
    fn a_window_is_no_larger_than_the_output() {
        let limit = u64::from(MAX_DECODER_MEMORY);
        assert_eq!(window(u64::from(u32::MAX), 360), Some(4096));
        assert_eq!(window(u64::from(u32::MAX), 1 << 20), Some(1 << 20));
        assert_eq!(window(1 << 16, 1 << 30), Some(1 << 16));
        assert_eq!(window(limit, 1 << 30), Some(MAX_DECODER_MEMORY));
        assert_eq!(window(limit + 1, limit), Some(MAX_DECODER_MEMORY));
        assert_eq!(window(limit + 1, limit + 1), None);
        assert_eq!(window(u64::from(u32::MAX), u64::MAX), None);

        let text = text();
        let len = size(&text);
        assert_eq!(kept(lzma(&unhex(LZMA_TEXT), &[0x5D, 0xFF, 0xFF, 0xFF, 0xFF], len)), text);
        assert_eq!(kept(lzma2(&unhex(LZMA2_TEXT), &[40], len)), text);
        assert_eq!(kept(lzma2(&lzma2_zeros(4), &[40], 4 * LZMA2_CHUNK_SIZE)), vec![0_u8; 4 * 2_096_914]);
    }

    /// A small deterministic generator: the same damage on every run.
    struct Dice(u64);

    impl Dice {
        fn roll(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.roll() % u64::try_from(bound).unwrap()).unwrap()
        }

        /// A copy of `stream` with a few bytes changed, cut short, or with bytes put in.
        fn damage(&mut self, stream: &[u8]) -> Vec<u8> {
            let mut damaged = stream.to_vec();
            for _ in 0..=self.below(4) {
                let at = self.below(damaged.len());
                match self.below(4) {
                    0 => damaged.truncate(at.max(1)),
                    1 => damaged.insert(at, self.roll().to_le_bytes()[0]),
                    2 => damaged[at] ^= 1 << self.below(8),
                    _ => damaged[at] = self.roll().to_le_bytes()[0],
                }
            }
            damaged
        }
    }

    /// A length within what was asked for, whatever the decode made of the stream.
    fn within(codec: &str, decoded: Decoded<Summary>, want: u64) {
        if let Decoded::Data(summary) = decoded {
            assert!(summary.len() <= want, "{codec} gave {} bytes when asked for {want}", summary.len());
        }
    }

    /// Damaged streams are what a hostile archive gives a decoder. Whatever they hold, a decode
    /// returns, with one of its three answers and within what it was asked for.
    #[test]
    fn a_damaged_stream_never_takes_a_decode_down() {
        let text = text();
        let want = size(&text) + 16;
        let streams = [deflated(&text), unhex(LZMA_TEXT), unhex(LZMA2_TEXT)];
        let [in_deflate, in_lzma, in_chunks] = &streams;

        let mut dice = Dice(0x9E37_79B9_7F4A_7C15);
        for _ in 0..400 {
            within("deflate", deflate(dice.damage(in_deflate).as_slice(), want), want);
            within("lzma", lzma(&dice.damage(in_lzma), &LZMA_PROPS, want), want);
            within("lzma", lzma(in_lzma, &dice.damage(&LZMA_PROPS), want), want);
            within("lzma2", lzma2(&dice.damage(in_chunks), &LZMA2_PROPS, want), want);
            within("lzma2", lzma2(in_chunks, &dice.damage(&LZMA2_PROPS), want), want);

            let noise: Vec<u8> = (0..dice.below(300)).map(|_| dice.roll().to_le_bytes()[0]).collect();
            within("deflate", deflate(noise.as_slice(), want), want);
            within("stored", stored(noise.as_slice(), want), want);
            within("lzma", lzma(&noise, &LZMA_PROPS, want), want);
            within("lzma2", lzma2(&noise, &LZMA2_PROPS, want), want);
        }
    }
}
