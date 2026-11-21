//! The proof of pseudo-encryption: whether an entry that is marked as ZipCrypto is encrypted.
//!
//! A tool can set the flag on an entry it never encrypted. Such an entry unpacks, as it stands,
//! to the CRC-32 the archive stores for it, and encrypted data does not: that is the proof.
//! It is run on entries marked as ZipCrypto and on
//! no others. WinZip AES and strong encryption put a salt or a decryption header in front of
//! the data, which no plain data is mistaken for, and an entry that is not marked is not
//! looked at.
//!
//! The data comes from a range of the file and goes through a decoder that keeps its length
//! and its CRC-32 and nothing else, under the limits of [`crate::formats::limits`]: a
//! gigabyte for one entry, four for one archive. An entry the limits leave out, or one of a
//! method other than stored and Deflate, is not put to the proof. It stays encrypted, and the
//! analysis says that the proof was not run.

use super::data_extract::ZIP_CRYPTO_HEADER;
use super::parser::ZipEntry;
use super::scoring::METHOD_DEFLATE;
use super::scoring::METHOD_STORED;
use crate::formats::decode::Decoded;
use crate::formats::decode::Summary;
use crate::formats::decode::deflate;
use crate::formats::decode::stored;
use crate::formats::limits::Budget;
use crate::formats::source::Source;

/// How much of a Deflate stream is unpacked before the whole of it is: encrypted data stops
/// being a Deflate stream within a few bytes, and that is found out for this much of the budget.
const DEFLATE_PROBE: u64 = 64 * 1024;

/// How the proof came out for one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Proof {
    /// The data as it stands unpacks to the stored CRC-32: the entry is not encrypted.
    Open,
    /// It does not: the entry is encrypted.
    Sealed,
    /// The proof was not run: the entry is too large for it, of a method it does not unpack,
    /// or the archive has used up what is unpacked for one archive.
    NotRun,
    /// The entry is stored, and its two sizes fit neither encrypted data, which is 12 bytes
    /// longer than what it holds, nor the same data with the flag set on it.
    SizesDisagree,
}

/// What one way of unpacking the data showed.
enum Unpacked {
    /// The stored CRC-32 and the stored size.
    Matches,
    /// Something else, or no valid stream at all.
    Differs,
    /// Nothing: a limit stood in the way.
    OverLimit,
}

/// Hold a decode against what the entry is said to hold.
fn judge(decoded: Decoded<Summary>, entry: &ZipEntry) -> Unpacked {
    match decoded {
        Decoded::Data(summary) => {
            if summary.len() == entry.uncompressed_size && summary.crc32() == entry.crc32 {
                Unpacked::Matches
            } else {
                Unpacked::Differs
            }
        },
        Decoded::Corrupt => Unpacked::Differs,
        Decoded::OverLimit => Unpacked::OverLimit,
    }
}

/// Take the `len` bytes at `at` as stored data of the entry.
fn unpack_stored(source: &Source, at: u64, len: u64, entry: &ZipEntry, budget: &mut Budget) -> Unpacked {
    if !budget.take(len) {
        return Unpacked::OverLimit;
    }
    source.reader(at, len).map_or(Unpacked::Differs, |reader| judge(stored(reader, len), entry))
}

/// Take the `len` bytes at `at` as a Deflate stream of the entry.
///
/// One byte more than the entry is said to hold is asked for, so a stream that goes on past
/// that size differs. The start of the stream is unpacked first: data that is no Deflate
/// stream fails there, and only a stream that holds is unpacked in full.
fn unpack_deflate(source: &Source, at: u64, len: u64, entry: &ZipEntry, budget: &mut Budget) -> Unpacked {
    let Some(want) = entry.uncompressed_size.checked_add(1) else { return Unpacked::OverLimit };
    if want > DEFLATE_PROBE {
        if !budget.take(DEFLATE_PROBE) {
            return Unpacked::OverLimit;
        }
        let Ok(reader) = source.reader(at, len) else { return Unpacked::Differs };
        match deflate::<Summary>(reader, DEFLATE_PROBE) {
            Decoded::Data(summary) if summary.len() == DEFLATE_PROBE => {},
            // no Deflate stream, or one that ends before the entry is said to
            Decoded::Data(_) | Decoded::Corrupt => return Unpacked::Differs,
            Decoded::OverLimit => return Unpacked::OverLimit,
        }
    }
    if !budget.take(want) {
        return Unpacked::OverLimit;
    }
    source.reader(at, len).map_or(Unpacked::Differs, |reader| judge(deflate(reader, want), entry))
}

/// Put an entry that is marked as ZipCrypto to the proof. Its data is the `compressed_size`
/// bytes at `start`, which lie inside the file.
///
/// An entry that holds nothing proves nothing: the CRC-32 of no data is the same whether a
/// 12-byte encryption header stands in front of it or not. It is encrypted, as its flag says.
pub(crate) fn prove(source: &Source, entry: &ZipEntry, start: u64, budget: &mut Budget) -> Proof {
    let (packed, size) = (entry.compressed_size, entry.uncompressed_size);
    // a writer that set the flag on plain data left it as it was, or left room for the header
    let behind_header = packed.checked_sub(ZIP_CRYPTO_HEADER).zip(start.checked_add(ZIP_CRYPTO_HEADER));

    match entry.compression_method {
        METHOD_STORED => {
            let (at, room_for_header) = match behind_header {
                Some((stream, at)) if stream == size => (at, true),
                _ if packed == size => (start, false),
                _ => return Proof::SizesDisagree,
            };
            if size == 0 {
                return Proof::Sealed;
            }
            match unpack_stored(source, at, size, entry, budget) {
                Unpacked::Matches => Proof::Open,
                Unpacked::Differs if room_for_header => Proof::Sealed,
                // no room for an encryption header, and not the data the checksum is of
                Unpacked::Differs => Proof::SizesDisagree,
                Unpacked::OverLimit => Proof::NotRun,
            }
        },
        METHOD_DEFLATE => {
            if size == 0 {
                return Proof::Sealed;
            }
            for (at, len) in [Some((start, packed)), behind_header.map(|(stream, at)| (at, stream))].into_iter().flatten() {
                match unpack_deflate(source, at, len, entry, budget) {
                    Unpacked::Matches => return Proof::Open,
                    Unpacked::Differs => {},
                    Unpacked::OverLimit => return Proof::NotRun,
                }
            }
            Proof::Sealed
        },
        _ => Proof::NotRun,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::limits::MAX_ARCHIVE_WORK;
    use crate::formats::limits::MAX_DECODE_OUTPUT;
    use crate::formats::zip::craft::Member;
    use crate::formats::zip::craft::Zip;
    use crate::formats::zip::craft::deflated;
    use crate::formats::zip::craft::member;
    use crate::formats::zip::craft::noise;
    use crate::formats::zip::data_extract::Data;
    use crate::formats::zip::data_extract::locate;
    use crate::formats::zip::parser::parse;

    const TEXT: &[u8] = b"not really encrypted, whatever the flag says";

    /// The proof for the one entry of an archive built from `entry`.
    fn proved(entry: Member<'_>) -> Proof {
        proved_with(entry, &mut Budget::new())
    }

    fn proved_with(entry: Member<'_>, budget: &mut Budget) -> Proof {
        let source = Source::from_bytes(Zip::of(&[entry]).build());
        let entries = parse(&source).unwrap().entries;
        let Data::Here(start) = locate(&source, &entries[0]) else { panic!("the data is not here") };
        prove(&source, &entries[0], start, budget)
    }

    fn crc(data: &[u8]) -> u32 {
        crc32fast::hash(data)
    }

    fn size(data: &[u8]) -> u32 {
        u32::try_from(data.len()).unwrap()
    }

    #[test]
    fn stored_data_with_the_flag_set_on_it_is_open() {
        // as it stands
        assert_eq!(proved(Member { crc: Some(crc(TEXT)), size: Some(size(TEXT)), ..member("a.txt", 1, TEXT) }), Proof::Open);
        // behind 12 bytes a writer left room for
        let padded = [&[0_u8; 12][..], TEXT].concat();
        assert_eq!(proved(Member { crc: Some(crc(TEXT)), ..member("a.txt", 1, &padded) }), Proof::Open);
    }

    #[test]
    fn stored_data_that_does_not_have_its_checksum_is_encrypted() {
        let data = [&[0x11_u8; 12][..], TEXT].concat();
        assert_eq!(proved(member("locked.bin", 1, &data)), Proof::Sealed);
        // one byte of it changed is enough
        let mut damaged = [&[0_u8; 12][..], TEXT].concat();
        damaged[20] ^= 1;
        assert_eq!(proved(Member { crc: Some(crc(TEXT)), ..member("a.txt", 1, &damaged) }), Proof::Sealed);
    }

    #[test]
    fn deflated_data_with_the_flag_set_on_it_is_open() {
        let text = TEXT.repeat(40);
        let stream = deflated(&text);
        assert_eq!(proved(Member { method: 8, crc: Some(crc(&text)), size: Some(size(&text)), ..member("a.txt", 1, &stream) }), Proof::Open);
        let padded = [&[0_u8; 12][..], &stream].concat();
        assert_eq!(proved(Member { method: 8, crc: Some(crc(&text)), size: Some(size(&text)), ..member("a.txt", 1, &padded) }), Proof::Open);

        // longer than the probe: unpacked in full after its start held
        let long: Vec<u8> = (0..300_000_u32).flat_map(|n| (n.wrapping_mul(2_654_435_761) >> 24).to_le_bytes()).collect();
        let stream = deflated(&long);
        assert_eq!(proved(Member { method: 8, crc: Some(crc(&long)), size: Some(size(&long)), ..member("long.bin", 1, &stream) }), Proof::Open);
        // the same stream with a checksum that is not its own, and with a size that is not
        assert_eq!(proved(Member { method: 8, crc: Some(7), size: Some(size(&long)), ..member("long.bin", 1, &stream) }), Proof::Sealed);
        assert_eq!(proved(Member { method: 8, crc: Some(crc(&long)), size: Some(1_100_000), ..member("long.bin", 1, &stream) }), Proof::Sealed);
        assert_eq!(proved(Member { method: 8, crc: Some(crc(&long[..70_000])), size: Some(70_000), ..member("long.bin", 1, &stream) }), Proof::Sealed, "the stream goes on past the size");
    }

    #[test]
    fn data_that_is_no_deflate_stream_is_encrypted() {
        let noise = noise(4000);
        assert_eq!(proved(Member { method: 8, size: Some(9000), ..member("locked.bin", 1, &noise) }), Proof::Sealed);
        assert_eq!(proved(Member { method: 8, size: Some(9000), ..member("short.bin", 1, &noise[..5]) }), Proof::Sealed, "shorter than the header");
    }

    /// The CRC-32 of nothing is 0 with or without an encryption header in front, so an entry
    /// that holds nothing is not shown to be open by it.
    #[test]
    fn an_empty_entry_proves_nothing() {
        assert_eq!(proved(Member { crc: Some(0), size: Some(0), ..member("empty.txt", 1, &[0x5A; 12]) }), Proof::Sealed, "a header and no data");
        assert_eq!(proved(Member { crc: Some(0), size: Some(0), ..member("empty.txt", 1, b"") }), Proof::Sealed, "no header either");
        let empty_stream = deflated(b"");
        assert_eq!(proved(Member { method: 8, crc: Some(0), size: Some(0), ..member("empty.txt", 1, &empty_stream) }), Proof::Sealed);
        let behind_header = [&[0x5A_u8; 12][..], &empty_stream].concat();
        assert_eq!(proved(Member { method: 8, crc: Some(0), size: Some(0), ..member("empty.txt", 1, &behind_header) }), Proof::Sealed);
    }

    #[test]
    fn a_stored_entry_whose_sizes_fit_no_reading_is_neither() {
        // 40 bytes that hold 10, 40 that hold 50, 5 that hold none
        for (data, holds) in [(&[0x5A_u8; 40][..], 10), (&[0x5A; 40], 50), (&[0x5A; 5], 0)] {
            assert_eq!(proved(Member { size: Some(holds), ..member("odd.bin", 1, data) }), Proof::SizesDisagree, "{} bytes for {holds}", data.len());
        }
        // as long as what it holds, and not what its checksum is of
        assert_eq!(proved(Member { size: Some(40), ..member("odd.bin", 1, &[0x5A; 40]) }), Proof::SizesDisagree);
    }

    #[test]
    fn a_method_the_proof_does_not_unpack_is_not_put_to_it() {
        for method in [1, 6, 9, 12, 14, 93, 95, 98, 1000] {
            assert_eq!(proved(Member { method, ..member("a.bin", 1, &[0x5A; 60]) }), Proof::NotRun, "method {method}");
        }
    }

    /// An entry that is said to unpack to more than the limit for one entry is not unpacked at
    /// all, and neither is one the budget of the archive has nothing left for.
    #[test]
    fn the_limits_leave_an_entry_unproven_and_not_judged() {
        let stream = deflated(&TEXT.repeat(4000));
        let over = u32::try_from(MAX_DECODE_OUTPUT).unwrap() + 1;
        assert_eq!(proved(Member { method: 8, size: Some(over), ..member("huge.bin", 1, &stream) }), Proof::NotRun);
        assert_eq!(proved(Member { method: 8, size: Some(u32::MAX - 1), ..member("huge.bin", 1, &stream) }), Proof::NotRun);

        let mut spent = Budget::new();
        assert!(spent.take(MAX_ARCHIVE_WORK - 10));
        assert_eq!(proved_with(Member { crc: Some(crc(TEXT)), size: Some(size(TEXT)), ..member("a.txt", 1, TEXT) }, &mut spent), Proof::NotRun);
        let small = deflated(TEXT);
        assert_eq!(proved_with(Member { method: 8, crc: Some(crc(TEXT)), size: Some(size(TEXT)), ..member("a.txt", 1, &small) }, &mut spent), Proof::NotRun);
        // what fits into what is left is still proven
        assert_eq!(proved_with(Member { crc: Some(crc(b"tiny")), size: Some(4), ..member("a.txt", 1, b"tiny") }, &mut spent), Proof::Open);
    }

    /// Encrypted data costs the budget a probe and not the size its header claims, so an
    /// archive of many large encrypted entries does not run out of proof.
    #[test]
    fn data_that_fails_at_once_costs_a_probe() {
        let noise = noise(4000);
        let mut budget = Budget::new();
        for _ in 0..40 {
            assert_eq!(proved_with(Member { method: 8, size: Some(900_000_000), ..member("locked.bin", 1, &noise) }, &mut budget), Proof::Sealed);
        }
        assert!(budget.take(MAX_ARCHIVE_WORK - 80 * DEFLATE_PROBE), "forty entries took two probes each");
    }
}
