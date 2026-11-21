//! What is known of the encryption header of an entry: its check bytes.
//!
//! The last byte of the header is the top byte of the CRC-32, or of the file time for an entry
//! with a data descriptor. Many writers put the byte below it in front. The answer is a short
//! list of ways the end of the header may be, the surest first: a search takes the first, and
//! the others are what it falls back to.

use super::claim::Certainty;
use super::claim::Form;
use super::writer::Writer;
use crate::formats::zip::encryption::FLAG_DATA_DESCRIPTOR;
use crate::formats::zip::parser::ZipEntry;

/// One way the end of an encryption header may be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CheckBytes {
    /// The known bytes, at positions -2 and -1 or at -1 alone.
    pub form: Form,
    /// How sure it is.
    pub certainty: Certainty,
    /// How many check bytes it holds.
    pub count: u8,
    /// Where the bytes are taken from: `CRC-32` or `file time`.
    pub from: &'static str,
}

impl CheckBytes {
    /// What it is, in the words of a plan.
    #[must_use]
    pub(crate) fn what(&self) -> String {
        if self.count == 1 { format!("the check byte, from the {}", self.from) } else { format!("two check bytes, from the {}", self.from) }
    }
}

/// The ways the encryption header of `entry` may end, the surest first.
///
/// - Without a data descriptor the last byte is the top byte of the CRC-32: certain.
/// - With one it is the top byte of the file time for every writer that was read: derived for
///   a writer the directory names, likely for one it does not, with the CRC-32 as a guess
///   behind it.
/// - The byte in front of it is known for a writer of two check bytes, and a guess for a
///   writer the directory does not name: it makes a run one byte longer, and when a search
///   with it fails the same search without it is the next.
#[must_use]
pub(crate) fn check_bytes(entry: &ZipEntry, writer: Writer) -> Vec<CheckBytes> {
    let crc = entry.crc32.to_be_bytes();
    let time = entry.last_mod_time.to_be_bytes();
    let from_crc = (["CRC-32"; 1], [crc[1], crc[0]]);
    let from_time = (["file time"; 1], [time[1], time[0]]);
    let descriptor = entry.flags & FLAG_DATA_DESCRIPTOR != 0;

    // the sources of the last byte, each with how sure it is
    let sources: Vec<(&'static str, [u8; 2], Certainty)> = match (descriptor, writer) {
        (false, _) => vec![(from_crc.0[0], from_crc.1, Certainty::Certain)],
        (true, Writer::Unknown) => vec![(from_time.0[0], from_time.1, Certainty::Likely), (from_crc.0[0], from_crc.1, Certainty::Guess)],
        (true, _) => vec![(from_time.0[0], from_time.1, Certainty::Derived)],
    };

    let mut ways = Vec::new();
    for (from, [second, last], certainty) in sources {
        let one = CheckBytes { form: Form::bytes(-1, &[last]), certainty, count: 1, from };
        let two = |certainty: Certainty| CheckBytes { form: Form::bytes(-2, &[second, last]), certainty, count: 2, from };
        match writer.check_bytes() {
            Some(1) => ways.push(one),
            Some(_) => {
                ways.push(two(certainty.min(Certainty::Derived)));
                ways.push(one);
            },
            None if entry.two_byte_check => {
                // "version made by" below 2.0: PKZIP 1, which wrote two
                ways.push(two(certainty.min(Certainty::Derived)));
                ways.push(one);
            },
            None => {
                ways.push(one);
                ways.push(two(Certainty::Guess));
            },
        }
    }
    ways
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::zip::known::set::ByteSet;
    use crate::formats::zip::known::testing::entry;

    #[test]
    fn the_last_byte_is_the_top_of_the_crc_32_and_certain() {
        let stored = entry("a.bin", 0, 0x0001, 100, 112);
        let stored = ZipEntry { crc32: 0xa1b2_c3d4, last_mod_time: 0x7e55, ..stored };
        let ways = check_bytes(&stored, Writer::SevenZip);
        assert_eq!(ways.len(), 1);
        assert_eq!((ways[0].certainty, ways[0].count, ways[0].form.get(-1), ways[0].form.get(-2)), (Certainty::Certain, 1, Some(ByteSet::of(0xa1)), None));
        assert_eq!(ways[0].what(), "the check byte, from the CRC-32");

        // a writer of two check bytes: both, then the last alone
        let ways = check_bytes(&stored, Writer::InfoZip);
        assert_eq!(ways.iter().map(|way| (way.count, way.certainty)).collect::<Vec<_>>(), [(2, Certainty::Derived), (1, Certainty::Certain)]);
        assert_eq!((ways[0].form.get(-2), ways[0].form.get(-1)), (Some(ByteSet::of(0xb2)), Some(ByteSet::of(0xa1))));
        assert_eq!(ways[0].what(), "two check bytes, from the CRC-32");

        // a writer that is not known: the second byte is a guess, behind the certain one
        let ways = check_bytes(&stored, Writer::Unknown);
        assert_eq!(ways.iter().map(|way| (way.count, way.certainty)).collect::<Vec<_>>(), [(1, Certainty::Certain), (2, Certainty::Guess)]);
    }

    #[test]
    fn with_a_data_descriptor_the_bytes_come_from_the_file_time() {
        let streamed = ZipEntry { crc32: 0xa1b2_c3d4, last_mod_time: 0x7e55, ..entry("a.bin", 8, 0x0009, 100, 80) };
        let ways = check_bytes(&streamed, Writer::InfoZip);
        assert_eq!(ways.iter().map(|way| (way.count, way.certainty, way.from)).collect::<Vec<_>>(), [(2, Certainty::Derived, "file time"), (1, Certainty::Derived, "file time")]);
        assert_eq!((ways[0].form.get(-2), ways[0].form.get(-1)), (Some(ByteSet::of(0x55)), Some(ByteSet::of(0x7e))));

        // a writer that is not known may have used the CRC-32 all the same
        let ways = check_bytes(&streamed, Writer::Unknown);
        assert_eq!(ways.iter().map(|way| (way.count, way.certainty, way.from)).collect::<Vec<_>>(), [(1, Certainty::Likely, "file time"), (2, Certainty::Guess, "file time"), (1, Certainty::Guess, "CRC-32"), (2, Certainty::Guess, "CRC-32")]);
        assert_eq!(ways[2].form.get(-1), Some(ByteSet::of(0xa1)));
    }

    #[test]
    fn pkzip_1_is_known_by_its_version_to_write_two() {
        let old = ZipEntry { two_byte_check: true, crc32: 0x0102_0304, ..entry("a.bin", 0, 0x0001, 100, 112) };
        let ways = check_bytes(&old, Writer::Unknown);
        assert_eq!(ways.iter().map(|way| (way.count, way.certainty)).collect::<Vec<_>>(), [(2, Certainty::Derived), (1, Certainty::Certain)]);
    }
}
