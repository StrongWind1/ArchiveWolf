//! Which entry gives the line of its scheme, and how much of it the line carries.
//!
//! An archive needs one hash line for each scheme in it, and the entry it is taken from decides
//! how sure a cracked password is and how fast it is tested. Entries are ranked ([`Rank`]): one
//! that carries data before one that cannot, then by what its line can prove, then by how much
//! a cracker has to work through. When the entry that ranks first gives no line, the next one
//! is asked.

use super::data_extract::DataPlan;
use super::data_extract::ZIP_CRYPTO_HEADER;
use super::data_extract::ZIP_DEFLATE_DATA;
use super::data_extract::ZIP_LINE_DATA;
use super::data_extract::ZIP_MAGIC_DATA;
use super::data_extract::zip_winzip_overhead;
use super::encryption::FLAG_DATA_DESCRIPTOR;
use super::parser::ZipEntry;

const PKWARE_AES_128: u16 = 0x660E;
const PKWARE_AES_256: u16 = 0x6610;
const PKWARE_RC4: u16 = 0x6801;

/// Stored.
pub(crate) const METHOD_STORED: u16 = 0;
/// Deflate.
pub(crate) const METHOD_DEFLATE: u16 = 8;
/// bzip2.
pub(crate) const METHOD_BZIP2: u16 = 12;
/// xz.
pub(crate) const METHOD_XZ: u16 = 95;

/// Whether an entry can carry data. One that cannot never ranks before one that can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Carries {
    /// A file with content.
    Data,
    /// A directory, or a file without content.
    Nothing,
}

/// The place of an entry among the entries of its scheme. The lower rank is asked first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Rank {
    /// Whether the entry can carry data.
    pub carries: Carries,
    /// What its line can prove: lower proves more.
    pub proof: u8,
    /// How much a cracker works through for a candidate: less is better.
    pub size: u64,
    /// What decides between entries that agree in the rest.
    pub tie: u16,
}

impl Rank {
    /// The rank behind every other: for an entry that is asked only so that it can say why
    /// it gives no line.
    pub(crate) const LAST: Self = Self { carries: Carries::Nothing, proof: u8::MAX, size: u64::MAX, tie: u16::MAX };
}

/// How a wrong password is told from the right one with the data a line carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Proof {
    /// The stream decodes, or starts with a long fixed signature: a wrong password does not pass.
    Stream,
    /// A CRC-32 or an 80-bit authentication code over the data.
    Checksum,
    /// Only the one or two check bytes of the header: about one wrong password in 256 passes.
    HeaderOnly,
}

/// What a hash line takes from an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Zip1Plan {
    /// How much of the stream.
    pub data: DataPlan,
    /// What the data proves.
    pub proof: Proof,
}

/// A CRC-32 settles nothing beyond the data it covers until that data is this long.
pub(crate) const CRC32_FULL_BYTES: u64 = 4;

/// How many bits a wrong password has to match on a line with a stored entry of `stored` bytes
/// and `checks` header checks.
///
/// The CRC-32 of fewer than four bytes names those bytes and nothing more, so it is worth eight
/// bits for each of them, and 32 from four bytes on. Every header adds its check byte.
#[must_use]
pub(crate) fn stored_proof_bits(stored: u64, checks: usize) -> u64 {
    8 * stored.min(CRC32_FULL_BYTES) + 8 * checks as u64
}

/// Whether an entry is one that cannot carry data: a directory, or a file without content.
fn carries(entry: &ZipEntry, stream: u64) -> Carries {
    if entry.directory || entry.uncompressed_size == 0 || stream == 0 { Carries::Nothing } else { Carries::Data }
}

/// Decide what a `$zip$1$` line carries for this entry.
///
/// The cases are the ones mode 46100 has a test for (`zip1_set_verify` in `zip_traditional.c`):
/// a stored entry in full, a deflate stream in full or its start, the start of a bzip2 stream
/// of 10 bytes or more and of an xz stream of 8 or more. Anything else goes without data.
#[must_use]
pub(crate) fn plan_zip_crypto(entry: &ZipEntry) -> Zip1Plan {
    let header_only = Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly };
    let Some(stream) = entry.compressed_size.checked_sub(ZIP_CRYPTO_HEADER).filter(|&stream| stream > 0) else { return header_only };

    match entry.compression_method {
        METHOD_STORED if stream <= ZIP_LINE_DATA => Zip1Plan { data: DataPlan::Full, proof: Proof::Checksum },
        METHOD_DEFLATE if stream <= ZIP_DEFLATE_DATA => Zip1Plan { data: DataPlan::Full, proof: Proof::Stream },
        METHOD_DEFLATE => Zip1Plan { data: DataPlan::Prefix(ZIP_DEFLATE_DATA), proof: Proof::Stream },
        METHOD_BZIP2 if stream >= 10 => Zip1Plan { data: DataPlan::Prefix(ZIP_MAGIC_DATA), proof: Proof::Stream },
        METHOD_XZ if stream >= 8 => Zip1Plan { data: DataPlan::Prefix(ZIP_MAGIC_DATA), proof: Proof::Stream },
        _ => header_only,
    }
}

/// Rank a ZipCrypto entry.
///
/// A stream that proves the password by decoding comes first, then a checksum, then a stored
/// entry too short for its CRC-32 to count in full, then entries with nothing but their header.
/// Within a group the smaller stream wins, and a header whose check byte comes from the CRC-32
/// beats one that may hold the file time.
#[must_use]
pub(crate) fn score_zip_crypto(entry: &ZipEntry) -> Rank {
    let plan = plan_zip_crypto(entry);
    // a deflate stream of a few bytes proves little, so it ranks with the checksums
    let tiny = plan.proof == Proof::Stream && entry.compression_method == METHOD_DEFLATE && entry.compressed_size < ZIP_CRYPTO_HEADER + 24;
    let short = plan.proof == Proof::Checksum && entry.compressed_size < ZIP_CRYPTO_HEADER + CRC32_FULL_BYTES;
    let proof = match plan.proof {
        Proof::Stream if !tiny => 0,
        Proof::Checksum if short => 2,
        Proof::Stream | Proof::Checksum => 1,
        Proof::HeaderOnly => 3,
    };
    let stream = entry.compressed_size.saturating_sub(ZIP_CRYPTO_HEADER);
    Rank { carries: carries(entry, stream), proof, size: entry.compressed_size, tie: u16::from(entry.flags & FLAG_DATA_DESCRIPTOR != 0) }
}

/// Decide what a `$zip$2$` line carries for a WinZip AES entry with `ciphertext` bytes of data
/// compressed with `method`.
///
/// The authentication code covers the whole ciphertext, so a line that has all of it needs
/// nothing else. An entry too long for a line is tested by decrypting the start of its stream,
/// for the methods mode 46200 has such a test for (`zip2_set_verify` in `module_46200.c`).
#[must_use]
pub(crate) fn plan_zip_winzip(method: u16, ciphertext: u64) -> Zip1Plan {
    if ciphertext <= ZIP_LINE_DATA {
        return Zip1Plan { data: DataPlan::Full, proof: Proof::Checksum };
    }
    match method {
        METHOD_DEFLATE => Zip1Plan { data: DataPlan::Prefix(ZIP_DEFLATE_DATA), proof: Proof::Stream },
        METHOD_BZIP2 | METHOD_XZ => Zip1Plan { data: DataPlan::Prefix(ZIP_MAGIC_DATA), proof: Proof::Stream },
        _ => Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly },
    }
}

/// Rank a WinZip AES entry: what can be proved first, then the amount of data, then the key size.
#[must_use]
pub(crate) fn score_zip_winzip(entry: &ZipEntry, strength: u8, method: u16) -> Rank {
    let ciphertext = entry.compressed_size.saturating_sub(zip_winzip_overhead(strength));
    let plan = plan_zip_winzip(method, ciphertext);
    Rank { carries: carries(entry, ciphertext), proof: u8::from(plan.proof == Proof::HeaderOnly), size: plan.data.take(ciphertext), tie: u16::from(strength) }
}

/// Rank an entry under PKWARE strong encryption with the algorithm `alg_id` and the processing
/// flags `flags`: AES first, which is what a line exists for, then the smaller entry, then one
/// that only a password opens.
#[must_use]
pub(crate) fn score_zip_pkware(entry: &ZipEntry, alg_id: u16, flags: u16) -> Rank {
    let proof = match alg_id {
        PKWARE_AES_128..=PKWARE_AES_256 => 0,
        PKWARE_RC4 => 2,
        0xFFFF => 3,
        _ => 1,
    };
    Rank { carries: carries(entry, entry.compressed_size), proof, size: entry.compressed_size, tie: u16::from(flags != 1) }
}

#[cfg(test)]
mod tests {
    use super::super::encryption::ZipEncryption;
    use super::*;
    use crate::analysis::Split;

    fn make_entry(compressed_size: u64, method: u16, flags: u16) -> ZipEntry {
        ZipEntry {
            filename: b"test.txt".to_vec(),
            flags,
            compression_method: method,
            last_mod_time: 0,
            last_mod_date: 0,
            crc32: 0,
            compressed_size,
            uncompressed_size: compressed_size,
            local_header_offset: 0,
            encryption: ZipEncryption::ZipCrypto,
            directory: false,
            two_byte_check: false,
            made_by: 0,
            needed: 20,
            extra: crate::formats::zip::extra_fields::ExtraMarks::default(),
            here: true,
            split: Split::No,
        }
    }

    #[test]
    fn zip_crypto_deflate_preferred_over_stored() {
        let stored = make_entry(100, 0, 0x0001);
        let deflate = make_entry(100, 8, 0x0001);
        assert!(score_zip_crypto(&deflate) < score_zip_crypto(&stored));
    }

    #[test]
    fn zip_crypto_tiny_deflate_ranks_with_stored() {
        let tiny = make_entry(12 + 5, 8, 0x0001);
        let stored = make_entry(12 + 4, 0, 0x0001);
        let real = make_entry(12 + 4000, 8, 0x0001);
        assert!(score_zip_crypto(&real) < score_zip_crypto(&stored));
        assert!(score_zip_crypto(&stored) < score_zip_crypto(&tiny));
    }

    #[test]
    fn zip_crypto_short_stored_ranks_below_a_full_checksum() {
        let short = make_entry(12 + 3, 0, 0x0001);
        let full = make_entry(12 + 4000, 0, 0x0001);
        let tiny = make_entry(12 + 5, 8, 0x0001);
        let header_only = make_entry(5000, 14, 0x0001);
        assert!(score_zip_crypto(&full) < score_zip_crypto(&short));
        assert!(score_zip_crypto(&tiny) < score_zip_crypto(&short));
        assert!(score_zip_crypto(&short) < score_zip_crypto(&header_only));
    }

    #[test]
    fn stored_proof_counts_the_bytes_a_crc_can_name() {
        assert_eq!(stored_proof_bits(1, 1), 16);
        assert_eq!(stored_proof_bits(3, 1), 32);
        assert_eq!(stored_proof_bits(4, 1), 40);
        assert_eq!(stored_proof_bits(4000, 1), 40);
        assert_eq!(stored_proof_bits(1, 8), 72);
    }

    #[test]
    fn zip_crypto_smaller_preferred() {
        let small = make_entry(50, 0, 0x0001);
        let large = make_entry(200, 0, 0x0001);
        assert!(score_zip_crypto(&small) < score_zip_crypto(&large));
    }

    #[test]
    fn zip_crypto_crc_checkbyte_preferred() {
        let crc_check = make_entry(100, 0, 0x0001);
        let modtime_check = make_entry(100, 0, 0x0001 | FLAG_DATA_DESCRIPTOR);
        assert!(score_zip_crypto(&crc_check) < score_zip_crypto(&modtime_check));
    }

    /// An entry that cannot carry data never ranks before one that can, whatever each line
    /// would prove and however small the empty one is.
    #[test]
    fn an_entry_without_data_ranks_behind_every_entry_with_data() {
        let header_only = make_entry(9_000_000, 14, 0x0009);
        let empty = make_entry(12, 0, 0x0001);
        let nothing = make_entry(0, 0, 0x0001);
        let directory = ZipEntry { directory: true, ..make_entry(12 + 500, 8, 0x0001) };
        let empty_deflate = ZipEntry { uncompressed_size: 0, ..make_entry(12 + 2, 8, 0x0001) };
        for without in [&empty, &nothing, &directory, &empty_deflate] {
            assert_eq!(score_zip_crypto(without).carries, Carries::Nothing);
            assert!(score_zip_crypto(&header_only) < score_zip_crypto(without), "{without:?}");
        }

        // WinZip AES: an empty entry has a full authentication code, and still ranks behind
        let data = make_entry(28 + 3_000_000, 99, 0x0001);
        let empty = make_entry(28, 99, 0x0001);
        let directory = ZipEntry { directory: true, ..make_entry(0, 99, 0x0001) };
        assert!(score_zip_winzip(&data, 3, 8) < score_zip_winzip(&empty, 3, 0));
        assert!(score_zip_winzip(&data, 3, 8) < score_zip_winzip(&directory, 1, 0));

        // strong encryption: an entry without content has a decryption header all the same
        let content = make_entry(4000, 8, 0x0041);
        let no_content = ZipEntry { uncompressed_size: 0, ..make_entry(200, 0, 0x0041) };
        assert!(score_zip_pkware(&content, 0x6720, 3) < score_zip_pkware(&no_content, PKWARE_AES_256, 1));
    }

    #[test]
    fn zip_crypto_plans() {
        assert_eq!(plan_zip_crypto(&make_entry(12, 0, 1)), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
        assert_eq!(plan_zip_crypto(&make_entry(11, 0, 1)), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
        assert_eq!(plan_zip_crypto(&make_entry(12 + ZIP_LINE_DATA, 0, 1)), Zip1Plan { data: DataPlan::Full, proof: Proof::Checksum });
        assert_eq!(plan_zip_crypto(&make_entry(13 + ZIP_LINE_DATA, 0, 1)), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
        assert_eq!(plan_zip_crypto(&make_entry(12 + ZIP_DEFLATE_DATA, 8, 1)), Zip1Plan { data: DataPlan::Full, proof: Proof::Stream });
        assert_eq!(plan_zip_crypto(&make_entry(13 + ZIP_DEFLATE_DATA, 8, 1)), Zip1Plan { data: DataPlan::Prefix(ZIP_DEFLATE_DATA), proof: Proof::Stream });
        assert_eq!(plan_zip_crypto(&make_entry(u64::MAX, 8, 1)), Zip1Plan { data: DataPlan::Prefix(ZIP_DEFLATE_DATA), proof: Proof::Stream });
        assert_eq!(plan_zip_crypto(&make_entry(5000, 12, 1)), Zip1Plan { data: DataPlan::Prefix(ZIP_MAGIC_DATA), proof: Proof::Stream });
        assert_eq!(plan_zip_crypto(&make_entry(5000, 95, 1)), Zip1Plan { data: DataPlan::Prefix(ZIP_MAGIC_DATA), proof: Proof::Stream });
        // a stream shorter than the signature the mode compares goes without data
        assert_eq!(plan_zip_crypto(&make_entry(12 + 9, 12, 1)), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
        assert_eq!(plan_zip_crypto(&make_entry(12 + 7, 95, 1)), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
        assert_eq!(plan_zip_crypto(&make_entry(5000, 14, 1)), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
        assert_eq!(plan_zip_crypto(&make_entry(5000, 97, 1)), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
    }

    #[test]
    fn zip_winzip_scoring() {
        let small = make_entry(100, 99, 0x0001);
        let large = make_entry(500, 99, 0x0001);
        assert!(score_zip_winzip(&small, 1, 8) < score_zip_winzip(&large, 3, 8));
        // the same amount of ciphertext: the shorter key is derived faster
        assert!(score_zip_winzip(&make_entry(120, 99, 0x0001), 1, 8) < score_zip_winzip(&make_entry(128, 99, 0x0001), 3, 8));
        // an entry whose line holds nothing but the verifier ranks behind one with data
        let verifier_only = make_entry(28 + ZIP_LINE_DATA + 1, 99, 0x0001);
        assert!(score_zip_winzip(&make_entry(28 + ZIP_LINE_DATA, 99, 0x0001), 3, 0) < score_zip_winzip(&verifier_only, 3, 0));
    }

    #[test]
    fn zip_winzip_plans() {
        assert_eq!(plan_zip_winzip(0, ZIP_LINE_DATA), Zip1Plan { data: DataPlan::Full, proof: Proof::Checksum });
        assert_eq!(plan_zip_winzip(8, ZIP_LINE_DATA + 1), Zip1Plan { data: DataPlan::Prefix(ZIP_DEFLATE_DATA), proof: Proof::Stream });
        assert_eq!(plan_zip_winzip(12, ZIP_LINE_DATA + 1), Zip1Plan { data: DataPlan::Prefix(ZIP_MAGIC_DATA), proof: Proof::Stream });
        assert_eq!(plan_zip_winzip(0, ZIP_LINE_DATA + 1), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
        assert_eq!(plan_zip_winzip(14, u64::MAX), Zip1Plan { data: DataPlan::Nothing, proof: Proof::HeaderOnly });
    }

    #[test]
    fn zip_pkware_aes_preferred_over_the_other_ciphers() {
        let entry = make_entry(100, 8, 0x0041);
        let aes = score_zip_pkware(&entry, PKWARE_AES_256, 1);
        assert_eq!(aes, score_zip_pkware(&entry, PKWARE_AES_128, 1));
        assert!(aes < score_zip_pkware(&entry, 0x6720, 1));
        assert!(score_zip_pkware(&entry, 0x6720, 1) < score_zip_pkware(&entry, PKWARE_RC4, 1));
        assert!(score_zip_pkware(&entry, PKWARE_RC4, 1) < score_zip_pkware(&entry, 0xFFFF, 1));
    }

    #[test]
    fn zip_pkware_password_only_preferred() {
        let entry = make_entry(100, 8, 0x0041);
        assert!(score_zip_pkware(&entry, PKWARE_AES_256, 1) < score_zip_pkware(&entry, PKWARE_AES_256, 3));
        assert!(score_zip_pkware(&make_entry(50, 8, 0x0041), PKWARE_AES_256, 3) < score_zip_pkware(&entry, PKWARE_AES_256, 1), "the smaller entry first");
    }
}
