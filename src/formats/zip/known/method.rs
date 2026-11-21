//! What the packing method of an entry says of its stream, whatever was packed, and where the
//! content of an entry lies in its stream.

use super::claim::Cells;
use super::claim::Certainty;
use super::claim::Claim;
use super::claim::Form;
use super::claim::Origin;
use super::set::ByteSet;
use super::writer::Writer;
use crate::formats::zip::parser::ZipEntry;

/// The compression methods the claims know (APPNOTE 4.4.5).
const STORED: u16 = 0;
const DEFLATE: u16 = 8;
const DEFLATE64: u16 = 9;
const BZIP2: u16 = 12;
const LZMA: u16 = 14;
const XZ: u16 = 95;

/// The twelve bytes of the encryption header, which the packed size of an entry counts.
const HEADER: u64 = 12;

/// The five bytes in front of the data of a stored block of Deflate.
const BLOCK_HEAD: u64 = 5;

/// The most a stored block of Deflate holds.
const BLOCK_MAX: u64 = 65_535;

/// The least the first of several stored blocks holds, for every writer that was measured:
/// zlib ends its blocks at about 16,390 bytes, Info-ZIP at about 32,800.
const FIRST_BLOCK_MIN: i64 = 16_000;

/// How far from its end the content of an entry of several stored blocks is taken to lie in
/// the last block.
const LAST_BLOCK_MIN: u64 = 256;

/// The largest file whose Deflate stream is taken to be one block with the fixed code when
/// its start is known (section 6.2: over half of the files up to 256 bytes are packed so).
const FIXED_MAX: u64 = 256;

/// How the content of an entry lies in its stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layout {
    /// The stream is the content: method 0.
    Stored,
    /// Deflate that did not pack: the content in stored blocks, each with five bytes in front.
    /// The two sizes show it: the stream is longer than the content by five bytes a block.
    StoredBlocks {
        /// How many blocks there are.
        blocks: u64,
    },
    /// Packed: the stream is not the content. A small Deflate entry may still start as its
    /// content says (the fixed code).
    Packed,
}

impl Layout {
    /// The layout of an entry, from its method and its two sizes.
    #[must_use]
    pub(crate) fn of(entry: &ZipEntry) -> Self {
        let Some(stream) = entry.compressed_size.checked_sub(HEADER) else { return Self::Packed };
        match entry.compression_method {
            STORED if stream == entry.uncompressed_size => Self::Stored,
            DEFLATE | DEFLATE64 => {
                let extra = stream.checked_sub(entry.uncompressed_size).filter(|extra| *extra > 0 && extra % BLOCK_HEAD == 0);
                match extra.map(|extra| extra / BLOCK_HEAD) {
                    // as many blocks as the content needs at least, and none that is nearly empty
                    Some(blocks) if entry.uncompressed_size > 0 && blocks >= entry.uncompressed_size.div_ceil(BLOCK_MAX) && blocks <= entry.uncompressed_size / 1024 + 1 => Self::StoredBlocks { blocks },
                    _ => Self::Packed,
                }
            },
            _ => Self::Packed,
        }
    }

    /// The words of a plan for the layout.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::StoredBlocks { .. } => "Deflate, did not pack",
            Self::Packed => "packed",
        }
    }

    /// A form of the content of an entry as a form of its stream. `content` counts from the
    /// first byte of the file. `None` when the content does not show in the stream.
    ///
    /// - A stored entry is its content.
    /// - One stored block puts the content five bytes later.
    /// - Several put its start five bytes later, as far as the first block is sure to reach,
    ///   and its end at the end of the stream.
    /// - A small Deflate entry whose first bytes are known starts with what those bytes are in
    ///   the fixed code.
    #[must_use]
    pub(crate) fn place(self, content: &Form, entry: &ZipEntry) -> Option<Form> {
        let size = i64::try_from(entry.uncompressed_size).ok()?;
        match self {
            Self::Stored => Some(content.clipped(0, size)),
            Self::StoredBlocks { blocks: 1 } => Some(content.clipped(0, size).shifted(5)),
            Self::StoredBlocks { blocks } => {
                let head = content.clipped(0, size.min(FIRST_BLOCK_MIN)).shifted(5);
                let tail_from = size.saturating_sub_unsigned(LAST_BLOCK_MIN).max(FIRST_BLOCK_MIN);
                let tail = content.clipped(tail_from, size).shifted(i64::try_from(blocks.checked_mul(BLOCK_HEAD)?).ok()?);
                head.merged(&tail)
            },
            Self::Packed if matches!(entry.compression_method, DEFLATE | DEFLATE64) && entry.uncompressed_size <= FIXED_MAX => {
                let start = known_start(content);
                let (stream, (bits, count)) = fixed_code(&start);
                let mut form = Form::bytes(0, &stream);
                // the stream is packed in bits from the low end of each byte: of the byte behind
                // the last whole one, the low bits are known (section 3.6 of the design)
                if count > 0 {
                    let _ = form.add(i64::try_from(stream.len()).ok()?, Cells::Sets(vec![ByteSet::low_bits(bits, count)]));
                }
                (stream.len() >= 2).then_some(form)
            },
            Self::Packed => None,
        }
    }
}

/// The bytes a form of content knows exactly from position 0 on.
fn known_start(content: &Form) -> Vec<u8> {
    (0..).map_while(|at| content.get(at).and_then(ByteSet::only)).collect()
}

/// The start of a Deflate stream of one block with the fixed code whose content starts with
/// `start`: the whole bytes that the three bits of the block header and the codes of the
/// literals fill. A packer writes a repeat as a pair of length and distance, so the bytes
/// count only up to the first place where three of them have stood before. With the whole
/// bytes come the bits that are left over: the low bits of the byte behind them, and how many.
fn fixed_code(start: &[u8]) -> (Vec<u8>, (u8, u32)) {
    let literals = (0..start.len()).find(|&at| at >= 1 && start.get(at..at + 3).is_some_and(|next| (0..at).any(|before| start.get(before..before + 3) == Some(next)))).unwrap_or(start.len());
    // the last block, and the fixed code: bits 1, then 01 from the low end
    let (mut bits, mut count, mut stream) = (0b011_u32, 3_u32, Vec::new());
    for &byte in start.get(..literals).unwrap_or_default() {
        // literals 0 to 143 have the eight-bit codes from 00110000 on, the others nine bits from 110010000
        let (code, length) = if byte < 144 { (0x30 + u32::from(byte), 8) } else { (0x190 + u32::from(byte) - 144, 9) };
        // a code goes into the stream from its top bit down
        for bit in (0..length).rev() {
            bits |= ((code >> bit) & 1) << count;
            count += 1;
            if count == 8 {
                stream.push(bits.to_le_bytes()[0]);
                (bits, count) = (0, 0);
            }
        }
    }
    (stream, (bits.to_le_bytes()[0], count))
}

/// What the method of `entry` says of its stream: claims in positions of the stream.
#[must_use]
pub(crate) fn claims(entry: &ZipEntry, writer: Writer) -> Vec<Claim> {
    let size = entry.uncompressed_size;
    match (entry.compression_method, Layout::of(entry)) {
        (_, Layout::StoredBlocks { blocks: 1 }) => {
            // the last block, stored: its size and the complement of its size
            let len = u16::try_from(size).unwrap_or(u16::MAX).to_le_bytes();
            let head = [0x01, len[0], len[1], !len[0], !len[1]];
            vec![Claim::new(Origin::Method, Certainty::Derived, "header of the one stored block of Deflate", Form::bytes(0, &head))]
        },
        (_, Layout::StoredBlocks { .. }) => vec![Claim::new(Origin::Method, Certainty::Derived, "header of the first stored block of Deflate", Form::bytes(0, &[0x00]))],
        (BZIP2, _) => bzip2(size, writer),
        (XZ, _) => xz(),
        (LZMA, _) => lzma(size),
        _ => Vec::new(),
    }
}

/// A bzip2 stream starts with `BZh`, the digit of its block size and the mark of a block. The
/// digit is 9 from 7-Zip and 6 from Info-ZIP.
fn bzip2(size: u64, writer: Writer) -> Vec<Claim> {
    let form = |digit: u8| {
        let mut form = Form::bytes(0, &[b'B', b'Z', b'h', digit, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59]);
        // the pointer into the block is smaller than the block
        if size < 128 * 1024 {
            let _ = form.add(14, Cells::Bytes(vec![0]));
        }
        if size < 512 {
            let _ = form.add(15, Cells::Bytes(vec![0]));
        }
        form
    };
    let usual: &[u8] = match writer {
        Writer::SevenZip => b"9",
        Writer::InfoZip => b"6",
        _ => b"96",
    };
    let others: Vec<u8> = (b'1'..=b'9').filter(|digit| !usual.contains(digit)).collect();
    vec![
        Claim { origin: Origin::Method, certainty: Certainty::Likely, what: "start of a bzip2 stream".to_owned(), forms: usual.iter().map(|&digit| form(digit)).collect() },
        Claim { origin: Origin::Method, certainty: Certainty::Guess, what: "start of a bzip2 stream of another block size".to_owned(), forms: others.iter().map(|&digit| form(digit)).collect() },
    ]
}

/// An XZ stream starts with its magic, the kind of its check and the head of its first block:
/// sixteen bytes, in one form for each kind of check that is in use.
fn xz() -> Vec<Claim> {
    let with_crc32 = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x02, 0x00, 0x21, 0x01];
    let with_crc64 = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x02, 0x00, 0x21, 0x01];
    let form = |head: &[u8; 16]| {
        let mut form = Form::bytes(0, head);
        // behind the byte of the dictionary size the block header is filled up with zeros
        let _ = form.add(17, Cells::Bytes(vec![0, 0, 0]));
        form
    };
    vec![Claim { origin: Origin::Method, certainty: Certainty::Likely, what: "start of an XZ stream".to_owned(), forms: vec![form(&with_crc32), form(&with_crc64)] }]
}

/// An LZMA entry starts with the version of its writer, the size of its properties, the
/// properties and a first byte of data that is always zero: ten bytes, in one form for each
/// version of 7-Zip and each dictionary size that is in use.
fn lzma(size: u64) -> Vec<Claim> {
    /// The versions of 7-Zip whose library is in use, the newest first.
    const VERSIONS: [[u8; 2]; 9] = [[25, 1], [24, 9], [23, 1], [22, 1], [21, 7], [19, 0], [18, 5], [16, 4], [9, 20]];
    // the encoder cuts its dictionary down to the first size of the form 2 or 3 times a power
    // of two that holds the file (LzmaEnc.c, LzmaEncProps_Normalize); its defaults by level otherwise
    let fitted = (11..=30).flat_map(|power| [2_u64 << power, 3_u64 << power]).find(|&dictionary| size <= dictionary);
    let defaults = [1_u64 << 24, 1 << 25, 1 << 26, 1 << 23, 1 << 20, 1 << 16];
    let dictionaries: Vec<u32> = fitted.into_iter().chain(defaults).filter_map(|dictionary| u32::try_from(dictionary).ok()).fold(Vec::new(), |mut seen, dictionary| {
        if !seen.contains(&dictionary) {
            seen.push(dictionary);
        }
        seen
    });
    let forms = dictionaries
        .iter()
        .take(2)
        .flat_map(|dictionary| {
            VERSIONS.iter().map(move |version| {
                let d = dictionary.to_le_bytes();
                Form::bytes(0, &[version[0], version[1], 0x05, 0x00, 0x5d, d[0], d[1], d[2], d[3], 0x00])
            })
        })
        .collect();
    vec![Claim { origin: Origin::Method, certainty: Certainty::Guess, what: "start of an LZMA stream as 7-Zip writes it".to_owned(), forms }]
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::formats::zip::known::testing::entry;

    #[test]
    fn the_two_sizes_show_data_that_did_not_pack() {
        assert_eq!(Layout::of(&entry("a", 0, 1, 1000, 1012)), Layout::Stored);
        assert_eq!(Layout::of(&entry("a", 8, 1, 1000, 1017)), Layout::StoredBlocks { blocks: 1 });
        // 300,000 bytes in ten blocks of Info-ZIP, and 200,000 in thirteen of zlib
        assert_eq!(Layout::of(&entry("a", 8, 1, 300_000, 300_062)), Layout::StoredBlocks { blocks: 10 });
        assert_eq!(Layout::of(&entry("a", 8, 1, 200_000, 200_077)), Layout::StoredBlocks { blocks: 13 });
        // packed, longer by something that is no count of blocks, and too few blocks for the content
        assert_eq!(Layout::of(&entry("a", 8, 1, 1000, 512)), Layout::Packed);
        assert_eq!(Layout::of(&entry("a", 8, 1, 1000, 1016)), Layout::Packed);
        assert_eq!(Layout::of(&entry("a", 8, 1, 200_000, 200_017)), Layout::Packed);
        assert_eq!(Layout::of(&entry("a", 8, 1, 0, 17)), Layout::Packed);
        assert_eq!(Layout::of(&entry("a", 12, 1, 1000, 1017)), Layout::Packed);
        // a stored entry whose sizes do not fit, and one shorter than its header
        assert_eq!(Layout::of(&entry("a", 0, 1, 1000, 1000)), Layout::Packed);
        assert_eq!(Layout::of(&entry("a", 0, 1, 0, 4)), Layout::Packed);
    }

    #[test]
    fn the_header_of_one_stored_block_is_known_whole() {
        let claims = claims(&entry("photo.jpg", 8, 1, 1000, 1017), Writer::Unknown);
        assert_eq!(claims.len(), 1);
        assert_eq!((claims[0].certainty, &claims[0].forms), (Certainty::Derived, &vec![Form::bytes(0, &[0x01, 0xe8, 0x03, 0x17, 0xfc])]));
        // of several, the first byte
        let claims = super::claims(&entry("film.mp4", 8, 1, 300_000, 300_062), Writer::Unknown);
        assert_eq!(claims[0].forms, [Form::bytes(0, &[0x00])]);
        assert!(super::claims(&entry("a.txt", 8, 1, 1000, 400), Writer::Unknown).is_empty());
        assert!(super::claims(&entry("a.txt", 0, 1, 1000, 1012), Writer::Unknown).is_empty());
    }

    #[test]
    fn content_is_placed_where_the_layout_puts_it() {
        let content = Form::bytes(0, b"\x89PNG").merged(&Form::bytes(996, b"\xaeB`\x82")).unwrap();
        let stored = entry("a.png", 0, 1, 1000, 1012);
        assert_eq!(Layout::Stored.place(&content, &stored), Some(content.clone()));
        let one = entry("a.png", 8, 1, 1000, 1017);
        assert_eq!(Layout::of(&one).place(&content, &one), Some(content.shifted(5)));

        // several blocks: the start five later, the end at the end of the stream
        let big = Form::bytes(0, b"\x89PNG").merged(&Form::bytes(299_996, b"\xaeB`\x82")).unwrap();
        let several = entry("a.png", 8, 1, 300_000, 300_062);
        let placed = Layout::of(&several).place(&big, &several).unwrap();
        assert_eq!(placed.stretches(), [(5, 4), (300_046, 4)]);
        // what lies in the middle of such an entry is not placed
        let middle = Form::bytes(150_000, b"somewhere");
        assert!(Layout::of(&several).place(&middle, &several).unwrap().is_empty());
        // and nothing of a packed entry that is not small
        let packed = entry("a.txt", 8, 1, 5000, 2000);
        assert_eq!(Layout::of(&packed).place(&content, &packed), None);
    }

    #[test]
    fn the_start_of_a_small_file_gives_the_start_of_its_stream_in_the_fixed_code() {
        // what zlib writes for a text of 30 bytes without a repeat
        let text = b"The quick brown fox jumps over";
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
        encoder.write_all(text).unwrap();
        let real = encoder.finish().unwrap();
        let (ours, (bits, count)) = fixed_code(text);
        assert_eq!(ours.len(), 30);
        assert_eq!(ours[..], real[..30]);
        // three bits are left over, the low bits of the next byte of the stream
        assert_eq!((count, bits), (3, real[30] & 7));
        // a part of the start gives a part of the stream
        assert_eq!(fixed_code(&text[..8]).0[..], real[..8]);
        // bytes from 144 on take nine bits, and a repeat ends what is known
        assert_eq!(fixed_code(&[0xff; 8]).0.len(), 1);
        assert_eq!(fixed_code(b"abcabcabc").0.len(), 3);
        assert_eq!(fixed_code(b""), (Vec::new(), (0b011, 3)));

        let small = entry("note.txt", 8, 1, 30, 44);
        let placed = Layout::of(&small).place(&Form::bytes(0, &text[..12]), &small).unwrap();
        assert_eq!(placed.stretches(), [(0, 12)]);
        assert_eq!(placed.clipped(0, 12), Form::bytes(0, &real[..12]));
        // of the thirteenth byte the three low bits are known, which leaves 32 of its values
        assert!(placed.get(12).is_some_and(|set| set.len() == 32 && set.contains(real[12])));
        // nothing is known of the stream when the file does not start with known bytes
        assert_eq!(Layout::of(&small).place(&Form::bytes(5, b"later"), &small), None);
    }

    #[test]
    fn a_bzip2_an_xz_and_an_lzma_stream_start_with_known_bytes() {
        let claims = claims(&entry("a", 12, 1, 300, 150), Writer::SevenZip);
        assert_eq!((claims[0].forms.len(), claims[1].forms.len()), (1, 8));
        assert_eq!(claims[0].forms[0].stretches(), [(0, 10), (14, 2)]);
        assert_eq!(claims[0].forms[0].get(3), Some(ByteSet::of(b'9')));
        assert_eq!(super::claims(&entry("a", 12, 1, 300_000, 150), Writer::InfoZip)[0].forms[0].stretches(), [(0, 10)]);
        assert_eq!(super::claims(&entry("a", 12, 1, 300, 150), Writer::Unknown)[0].forms.len(), 2);

        let xz = super::claims(&entry("a", 95, 1, 300, 150), Writer::SevenZip);
        assert_eq!(xz[0].forms[0].stretches(), [(0, 16), (17, 3)]);
        assert_eq!(xz[0].forms.len(), 2);

        let lzma = super::claims(&entry("a", 14, 1, 5000, 150), Writer::SevenZip);
        assert_eq!(lzma[0].certainty, Certainty::Guess);
        // the newest version first, with the dictionary that holds 5,000 bytes: 3 << 11
        assert_eq!(lzma[0].forms[0], Form::bytes(0, &[25, 1, 5, 0, 0x5d, 0x00, 0x18, 0x00, 0x00, 0x00]));
        assert_eq!(lzma[0].forms.len(), 18);
    }
}
