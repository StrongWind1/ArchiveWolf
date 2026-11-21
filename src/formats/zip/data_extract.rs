//! The data of an entry, read by range: what a hash line carries and what the analysis shows.
//!
//! Nothing here reads more of an entry than a line holds. Where an entry lies is worked out
//! once ([`locate`]), with checked arithmetic, and every read after that is a range inside it.

use anyhow::Context as _;
use anyhow::ensure;

use super::encryption::FLAG_DATA_DESCRIPTOR;
use super::headers::Fields;
use super::headers::LOCAL_HEADER_LEN;
use super::headers::LocalFileHeader;
use super::lines::Zip1Check;
use super::lines::ZipPkwareHashInput;
use super::lines::ZipWinzipHashInput;
use super::parser::ZipEntry;
use crate::formats::source::Source;

/// The most data of an entry a line carries: what mode 46100 loads (`ZIP1_DATA_MAX` in
/// `zip_traditional.c`). Mode 46200 loads twice as much, and a line never needs it.
pub(crate) const ZIP_LINE_DATA: u64 = 4 * 1024 * 1024;

/// The most of a deflate stream a line carries. A shorter stream goes in whole and is checked
/// against its CRC-32; a longer one is cut here, and a megabyte that still inflates under a wrong
/// key does not happen: every stored block alone has a 16-bit check on its length.
pub(crate) const ZIP_DEFLATE_DATA: u64 = 1024 * 1024;

/// How much of a stream that is recognised by its signature a line carries.
pub(crate) const ZIP_MAGIC_DATA: u64 = 32;

/// Size of the ZipCrypto encryption header in front of an entry's data.
pub(crate) const ZIP_CRYPTO_HEADER: u64 = 12;

/// The same as the length of an array.
const ZIP_CRYPTO_HEADER_LEN: usize = 12;

/// Authentication code size for WinZip AES (HMAC-SHA1 truncated to 80 bits).
const AUTH_CODE_LEN: usize = 10;

/// Password verification value size.
const PV_LEN: usize = 2;

/// The largest compression method number the modes read: the field has three digits
/// (`zip_traditional.c` and `module_46200.c`).
pub(crate) const LINE_METHOD_MAX: u16 = 999;

/// The longest initialisation vector modes 46300 to 46320 load (`zip_strong.c`).
pub(crate) const ZIP3_IV_MAX: u64 = 16;
/// The most encrypted random data modes 46300 to 46320 load (`ZIP3_ERD_MAX`).
pub(crate) const ZIP3_ERD_MAX: u64 = 4096;
/// The most validation data modes 46300 to 46320 load (`ZIP3_VDATA_MAX`).
pub(crate) const ZIP3_VDATA_MAX: u64 = 1024;

/// The longest decryption header that is read, counted behind its size field. It is the bound
/// 7-Zip puts on the same field (`ZipStrong.cpp`), and room for several hundred recipients.
pub(crate) const PKWARE_HEADER_MAX: u32 = 1 << 18;

/// How much of an entry's encrypted stream goes into a hash line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataPlan {
    /// All of it.
    Full,
    /// Its first bytes.
    Prefix(u64),
    /// None of it.
    Nothing,
}

impl DataPlan {
    /// The number of bytes this plan takes from a stream of `len` bytes.
    #[must_use]
    pub(crate) fn take(self, len: u64) -> u64 {
        match self {
            Self::Full => len,
            Self::Prefix(n) => n.min(len),
            Self::Nothing => 0,
        }
    }
}

/// Where the data of an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Data {
    /// In this file, all of it: the `compressed_size` bytes of the entry start here.
    Here(u64),
    /// Its local header is in this file and its data runs past the end of the file.
    Cut,
    /// No local header of it is in this file.
    Missing,
}

/// Find the data of an entry: behind its local header, whose name and extra fields can differ
/// in length from those of the central directory.
pub(crate) fn locate(source: &Source, entry: &ZipEntry) -> Data {
    if !entry.here {
        return Data::Missing;
    }
    let Some(header) = source.read_at(entry.local_header_offset, LOCAL_HEADER_LEN as u64).ok().as_deref().and_then(LocalFileHeader::parse) else { return Data::Missing };
    match entry.local_header_offset.checked_add(header.len()) {
        Some(start) if start.checked_add(entry.compressed_size).is_some_and(|end| end <= source.len()) => Data::Here(start),
        _ => Data::Cut,
    }
}

/// The header check of a ZipCrypto entry whose data starts at `start`: its 12 encrypted bytes
/// and what the end decrypts to. `None` for an entry too short to have the header.
///
/// A writer that knew the CRC-32 put its top byte last. One that wrote the data descriptor (bit 3)
/// did not know it yet and used the top byte of the file time, which is why the CRC-32 is named as
/// an alternative there. Only PKZIP before 2.0 wrote two meaningful bytes.
pub(crate) fn zip1_check(source: &Source, entry: &ZipEntry, start: u64) -> Option<Zip1Check> {
    if entry.compressed_size < ZIP_CRYPTO_HEADER {
        return None;
    }
    let mut header = [0_u8; ZIP_CRYPTO_HEADER_LEN];
    source.read_exact_at(start, &mut header).ok()?;

    let from_crc = u16::try_from(entry.crc32 >> 16).unwrap_or(0);
    let from_time = entry.last_mod_time;
    let two_bytes = entry.two_byte_check;
    Some(if entry.flags & FLAG_DATA_DESCRIPTOR == 0 { Zip1Check { header, two_bytes, value: from_crc, alternative: None } } else { Zip1Check { header, two_bytes, value: from_time, alternative: Some(from_crc) } })
}

/// The start of the encrypted stream of a ZipCrypto entry behind its 12-byte header: as much
/// as `plan` takes.
pub(crate) fn zip1_data(source: &Source, entry: &ZipEntry, start: u64, plan: DataPlan) -> anyhow::Result<Vec<u8>> {
    let stream = entry.compressed_size.checked_sub(ZIP_CRYPTO_HEADER).context("entry is shorter than the encryption header")?;
    let at = start.checked_add(ZIP_CRYPTO_HEADER).context("entry data offset overflows")?;
    Ok(source.read_at(at, plan.take(stream))?)
}

/// The salt of a WinZip AES entry whose data starts at `start`: its first 8, 12 or 16 bytes.
pub(crate) fn zip_winzip_salt(source: &Source, entry: &ZipEntry, start: u64, strength: u8) -> Option<Vec<u8>> {
    let salt_len = 4 * u64::from(strength) + 4;
    ((1..=3).contains(&strength) && entry.compressed_size >= salt_len).then(|| source.read_at(start, salt_len).ok()).flatten()
}

/// How many bytes of a WinZip AES entry are not ciphertext: salt, verifier and authentication
/// code.
pub(crate) fn zip_winzip_overhead(strength: u8) -> u64 {
    4 * u64::from(strength) + 4 + (PV_LEN + AUTH_CODE_LEN) as u64
}

/// Read what a `$zip$2$` line carries from a WinZip AES entry whose data starts at `start`:
/// the salt, the verifier, the authentication code and as much ciphertext as `plan` takes.
pub(crate) fn extract_zip_winzip_data(source: &Source, entry: &ZipEntry, start: u64, strength: u8, method: u16, plan: DataPlan) -> anyhow::Result<ZipWinzipHashInput> {
    ensure!((1..=3).contains(&strength), "invalid AES strength: {strength}");

    let salt_len = 4 * u64::from(strength) + 4;
    let overhead = zip_winzip_overhead(strength);
    let packed = entry.compressed_size.checked_sub(overhead).with_context(|| format!("compressed size ({}) too small for WinZip AES overhead ({overhead})", entry.compressed_size))?;

    let head = source.read_at(start, salt_len + PV_LEN as u64).context("salt read out of bounds")?;
    let (salt, verifier) = head.split_at_checked(head.len().saturating_sub(PV_LEN)).context("salt read out of bounds")?;
    let password_verify: [u8; PV_LEN] = verifier.try_into().context("PV")?;

    let ciphertext_at = start.checked_add(salt_len + PV_LEN as u64).context("entry data offset overflows")?;
    let mut auth_code = [0_u8; AUTH_CODE_LEN];
    source.read_exact_at(ciphertext_at.checked_add(packed).context("entry data offset overflows")?, &mut auth_code).context("auth code read out of bounds")?;
    let data = source.read_at(ciphertext_at, plan.take(packed)).context("ciphertext read out of bounds")?;

    Ok(ZipWinzipHashInput { strength, salt: salt.to_vec(), password_verify, auth_code, method, packed, data })
}

/// The start of a PKWARE strong encryption decryption header: everything in front of the
/// encrypted random data. It names the algorithm, the key length and the flags, which the
/// analysis shows, and the sizes of what follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PkwarePrefix {
    /// Size of the initialisation vector the header stores, 0 when it stores none.
    pub iv_len: u16,
    /// The vector, when it is no longer than a line carries.
    pub iv: Vec<u8>,
    /// Size of the header behind this field.
    pub size: u32,
    /// Format of the header. Only 3 is defined.
    pub format: u16,
    /// Algorithm identifier.
    pub alg_id: u16,
    /// Key length in bits.
    pub bit_len: u16,
    /// Processing flags: 1 password, 2 certificates, 3 either; 0x4000 marks random data that is
    /// wrapped with 3DES.
    pub flags: u16,
    /// Size of the encrypted random data.
    pub erd_len: u16,
}

/// Read the start of the decryption header of the entry whose data starts at `start`. `None`
/// when the entry is too short to hold it.
pub(crate) fn read_pkware_prefix(source: &Source, entry: &ZipEntry, start: u64) -> Option<PkwarePrefix> {
    /// The fields between the vector and the random data.
    const FIXED: u64 = 14;

    let head = source.read_up_to(start, entry.compressed_size.min(2 + ZIP3_IV_MAX + FIXED)).ok()?;
    let mut fields = Fields(&head);
    let iv_len = fields.u16()?;
    let (iv, rest) = if u64::from(iv_len) <= ZIP3_IV_MAX {
        (fields.bytes(usize::from(iv_len))?.to_vec(), fields.0.to_vec())
    } else {
        // a vector no line carries: the fields behind it are read where it ends
        let behind = start.checked_add(2)?.checked_add(u64::from(iv_len))?;
        let fits = u64::from(iv_len).checked_add(2 + FIXED).is_some_and(|needed| needed <= entry.compressed_size);
        (Vec::new(), fits.then(|| source.read_at(behind, FIXED).ok()).flatten()?)
    };

    let mut fields = Fields(&rest);
    let size = fields.u32()?;
    let format = fields.u16()?;
    let alg_id = fields.u16()?;
    let bit_len = fields.u16()?;
    let flags = fields.u16()?;
    let erd_len = fields.u16()?;
    Some(PkwarePrefix { iv_len, iv, size, format, alg_id, bit_len, flags, erd_len })
}

/// The initialisation vector a decryption header stands for: the one it stores, or the CRC-32
/// and the 64-bit size of the entry when it stores none (APPNOTE 7.2.4.1, 7-Zip `ZipStrong.cpp`).
pub(crate) fn pkware_iv(prefix: &PkwarePrefix, entry: &ZipEntry) -> Vec<u8> {
    if prefix.iv_len != 0 {
        return prefix.iv.clone();
    }
    let mut derived = Vec::with_capacity(12);
    derived.extend_from_slice(&entry.crc32.to_le_bytes());
    derived.extend_from_slice(&entry.uncompressed_size.to_le_bytes());
    derived
}

/// What stands behind the start of a decryption header: the encrypted random data and the
/// validation data, with the list of certificate recipients between them passed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SesBody {
    /// Encrypted random data.
    pub erd: Vec<u8>,
    /// How many certificate recipients the header lists.
    pub recipients: u32,
    /// Encrypted validation data with its CRC-32.
    pub vdata: Vec<u8>,
}

/// Read the decryption header of the entry whose data starts at `start`, behind its `prefix`.
///
/// The header is read whole, up to [`PKWARE_HEADER_MAX`], and walked in memory. Between the
/// random data and the validation data stands the number of certificate recipients, and when
/// that is not zero their list: a hash algorithm, a hash size, and for each recipient a size
/// and that many bytes (APPNOTE 7.2.4.7, 7.2.4.8 and 7.4.4). The list is counted and skipped.
pub(crate) fn read_pkware_body(source: &Source, entry: &ZipEntry, start: u64, prefix: &PkwarePrefix) -> anyhow::Result<SesBody> {
    ensure!(prefix.size <= PKWARE_HEADER_MAX, "the decryption header says it has {} bytes, and {PKWARE_HEADER_MAX} are read", prefix.size);
    // IVSize, the vector and the size field stand in front of what the size counts
    let behind_size = start.checked_add(2 + u64::from(prefix.iv_len) + 4).context("the offset of the decryption header overflows")?;
    let end = behind_size.checked_add(u64::from(prefix.size)).context("the offset of the decryption header overflows")?;
    ensure!(start.checked_add(entry.compressed_size).is_some_and(|data_end| end <= data_end), "the decryption header is longer than the entry");
    let body = source.read_at(behind_size, u64::from(prefix.size)).context("the decryption header lies outside the file")?;

    // format, algorithm, key length, flags and the size of the random data were read already
    let mut fields = Fields(&body);
    let _fixed = fields.bytes(10).context("the decryption header is cut short")?;
    let erd = fields.bytes(usize::from(prefix.erd_len)).context("the random data of the decryption header is cut short")?.to_vec();

    let recipients = fields.u32().context("the decryption header ends before its count of recipients")?;
    if recipients != 0 {
        let _hash_algorithm = fields.u16().context("the recipient list of the decryption header is cut short")?;
        let _hash_size = fields.u16().context("the recipient list of the decryption header is cut short")?;
        // every recipient takes its two bytes of size or more
        ensure!(usize::try_from(recipients).is_ok_and(|count| count <= fields.left() / 2), "the decryption header has no room for {recipients} recipients");
        for _ in 0..recipients {
            let size = fields.u16().context("the recipient list of the decryption header is cut short")?;
            let _element = fields.bytes(usize::from(size)).context("the recipient list of the decryption header is cut short")?;
        }
    }

    let v_size = fields.u16().context("the decryption header ends before its validation data")?;
    let vdata = fields.bytes(usize::from(v_size)).context("the validation data of the decryption header is cut short")?.to_vec();
    Ok(SesBody { erd, recipients, vdata })
}

/// What a `$zip$3$` line carries, from the two halves of a decryption header: the whole
/// encrypted random data and the whole validation data. hashcat decrypts the first with the
/// password, derives the file key from it and checks the CRC-32 the second ends with.
pub(crate) fn pkware_line_input(entry: &ZipEntry, prefix: &PkwarePrefix, body: SesBody) -> ZipPkwareHashInput {
    ZipPkwareHashInput { alg_id: prefix.alg_id, bit_len: prefix.bit_len, flags: prefix.flags, iv: pkware_iv(prefix, entry), erd: body.erd, vdata: body.vdata }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::zip::craft::DecryptionHeader;
    use crate::formats::zip::craft::Member;
    use crate::formats::zip::craft::Zip;
    use crate::formats::zip::craft::aes_extra;
    use crate::formats::zip::craft::member;
    use crate::formats::zip::craft::pkware_extra;
    use crate::formats::zip::parser::parse;

    /// An archive of `members` as a source, with its entries.
    fn opened(members: &[Member<'_>]) -> (Source, Vec<ZipEntry>) {
        let source = Source::from_bytes(Zip::of(members).build());
        let entries = parse(&source).unwrap().entries;
        (source, entries)
    }

    fn start_of(source: &Source, entry: &ZipEntry) -> u64 {
        match locate(source, entry) {
            Data::Here(start) => start,
            other => panic!("the data is not here: {other:?}"),
        }
    }

    /// The data of a WinZip AES entry: a salt that counts up, a verifier, ciphertext and a code.
    fn aes_data(strength: u8, ciphertext: usize) -> Vec<u8> {
        let mut data: Vec<u8> = (0..4 * strength + 4).collect();
        data.extend_from_slice(&[0xAB, 0xCD]);
        data.extend(std::iter::repeat_n(0xEE, ciphertext));
        data.extend_from_slice(&[0xDD; 10]);
        data
    }

    #[test]
    fn a_plan_takes_what_it_says_and_no_more_than_there_is() {
        assert_eq!(DataPlan::Full.take(10), 10);
        assert_eq!(DataPlan::Prefix(4).take(10), 4);
        assert_eq!(DataPlan::Prefix(40).take(10), 10);
        assert_eq!(DataPlan::Nothing.take(10), 0);
        assert_eq!(DataPlan::Full.take(u64::MAX), u64::MAX);
    }

    #[test]
    fn the_data_of_an_entry_is_behind_its_local_header() {
        let (source, entries) = opened(&[member("a.txt", 0, b"first"), Member { extra: &[0xCA, 0xFE, 2, 0, 1, 2], ..member("b.txt", 1, &[0x5A; 20]) }]);
        assert_eq!(locate(&source, &entries[0]), Data::Here(30 + 5));
        assert_eq!(locate(&source, &entries[1]), Data::Here(40 + 30 + 5 + 6));

        // an entry of another volume, one that points at no header, one that ends past the file
        let mut elsewhere = entries[1].clone();
        elsewhere.here = false;
        assert_eq!(locate(&source, &elsewhere), Data::Missing);
        let mut astray = entries[1].clone();
        astray.local_header_offset = 3;
        assert_eq!(locate(&source, &astray), Data::Missing);
        for offset in [source.len(), u64::MAX, u64::MAX - 29] {
            astray.local_header_offset = offset;
            assert_eq!(locate(&source, &astray), Data::Missing, "offset {offset}");
        }
        for size in [1 << 20, u64::MAX, u64::MAX - 80] {
            let mut cut = entries[1].clone();
            cut.compressed_size = size;
            assert_eq!(locate(&source, &cut), Data::Cut, "size {size}");
        }
    }

    #[test]
    fn a_zip_crypto_check_is_the_header_and_what_it_ends_in() {
        let header: Vec<u8> = (100..112).collect();
        let data = [header.as_slice(), b"encrypted"].concat();
        let (source, entries) = opened(&[Member { crc: Some(0xAB12_3456), time: 0x7788, ..member("a", 1, &data) }, Member { crc: Some(0xAB12_3456), time: 0x7788, made_by: 11, ..member("b", 9, &data) }, member("short", 1, &[0x5A; 11])]);

        let check = zip1_check(&source, &entries[0], start_of(&source, &entries[0])).unwrap();
        assert_eq!(check, Zip1Check { header: header.clone().try_into().unwrap(), two_bytes: false, value: 0xAB12, alternative: None });
        // a data descriptor: the file time, and the CRC-32 as the value some writers use all the same
        let check = zip1_check(&source, &entries[1], start_of(&source, &entries[1])).unwrap();
        assert_eq!(check, Zip1Check { header: header.try_into().unwrap(), two_bytes: true, value: 0x7788, alternative: Some(0xAB12) });
        assert_eq!(zip1_check(&source, &entries[2], start_of(&source, &entries[2])), None, "eleven bytes hold no header");

        let start = start_of(&source, &entries[0]);
        assert_eq!(zip1_data(&source, &entries[0], start, DataPlan::Full).unwrap(), b"encrypted");
        assert_eq!(zip1_data(&source, &entries[0], start, DataPlan::Prefix(3)).unwrap(), b"enc");
        assert!(zip1_data(&source, &entries[0], start, DataPlan::Nothing).unwrap().is_empty());
        assert!(zip1_data(&source, &entries[2], start_of(&source, &entries[2]), DataPlan::Full).is_err());
    }

    #[test]
    fn a_zip_winzip_entry_gives_salt_verifier_code_and_ciphertext() {
        for strength in 1..=3_u8 {
            let extra = aes_extra(2, strength, 8);
            let data = aes_data(strength, 20);
            let (source, entries) = opened(&[Member { method: 99, extra: &extra, ..member("enc.bin", 1, &data) }]);
            let start = start_of(&source, &entries[0]);

            let input = extract_zip_winzip_data(&source, &entries[0], start, strength, 8, DataPlan::Full).unwrap();
            let salt: Vec<u8> = (0..4 * strength + 4).collect();
            assert_eq!((input.strength, input.salt.as_slice(), input.password_verify, input.auth_code), (strength, salt.as_slice(), [0xAB, 0xCD], [0xDD; 10]));
            assert_eq!((input.method, input.packed, input.data.as_slice()), (8, 20, &[0xEE; 20][..]));
            assert_eq!(zip_winzip_salt(&source, &entries[0], start, strength), Some(salt));

            let cut = extract_zip_winzip_data(&source, &entries[0], start, strength, 8, DataPlan::Prefix(5)).unwrap();
            assert_eq!((cut.packed, cut.data.len()), (20, 5), "the size is that of all the ciphertext");
            assert!(extract_zip_winzip_data(&source, &entries[0], start, strength, 8, DataPlan::Nothing).unwrap().data.is_empty());
        }
    }

    #[test]
    fn a_zip_winzip_entry_that_cannot_be_one_gives_nothing() {
        let extra = aes_extra(2, 3, 8);
        let (source, entries) = opened(&[Member { method: 99, extra: &extra, ..member("enc.bin", 1, &aes_data(3, 20)) }, Member { method: 99, extra: &extra, ..member("short.bin", 1, &[0; 27]) }]);
        let start = start_of(&source, &entries[0]);
        for strength in [0, 4, 255] {
            assert!(extract_zip_winzip_data(&source, &entries[0], start, strength, 8, DataPlan::Full).is_err(), "strength {strength}");
            assert_eq!(zip_winzip_salt(&source, &entries[0], start, strength), None);
        }
        // 27 bytes hold a salt of 16 and not the 28 of salt, verifier and code
        let start = start_of(&source, &entries[1]);
        assert!(extract_zip_winzip_data(&source, &entries[1], start, 3, 8, DataPlan::Full).is_err());
        assert!(zip_winzip_salt(&source, &entries[1], start, 3).is_some());
        assert_eq!(zip_winzip_overhead(3), 28);
    }

    /// An entry under strong encryption with `header` in front of 40 bytes of data.
    fn pkware_entry(header: &DecryptionHeader) -> (Source, ZipEntry, u64) {
        let extra = pkware_extra(header.alg_id, header.bits, header.flags);
        let data = [header.bytes().as_slice(), &[0x77; 40]].concat();
        let (source, entries) = opened(&[Member { version: 51, central_extra: &extra, crc: Some(0xDEAD_BEEF), size: Some(100), ..member("ses.bin", 0x41, &data) }]);
        let start = start_of(&source, &entries[0]);
        (source, entries[0].clone(), start)
    }

    #[test]
    fn a_decryption_header_gives_its_fields() {
        let header = DecryptionHeader::password(0x660E, 128);
        let (source, entry, start) = pkware_entry(&header);
        let prefix = read_pkware_prefix(&source, &entry, start).unwrap();
        assert_eq!((prefix.iv_len, prefix.iv.as_slice(), prefix.format, prefix.alg_id, prefix.bit_len, prefix.flags, prefix.erd_len), (16, &[0xA1; 16][..], 3, 0x660E, 128, 1, 144));
        assert_eq!(pkware_iv(&prefix, &entry), [0xA1; 16]);

        let body = read_pkware_body(&source, &entry, start, &prefix).unwrap();
        assert_eq!((body.erd.as_slice(), body.recipients, body.vdata.as_slice()), (header.erd.as_slice(), 0, &[0xCC; 16][..]));
        let input = pkware_line_input(&entry, &prefix, body);
        assert_eq!((input.alg_id, input.bit_len, input.flags, input.iv.as_slice(), input.erd.len(), input.vdata.len()), (0x660E, 128, 1, &[0xA1; 16][..], 144, 16));
    }

    /// What the derivation of zip2john (`zip2john.c`, lines 516 to 529) gives for a CRC-32 and an
    /// unpacked size when the header stores no vector. Recorded from that code built as a program
    /// of its own, which takes the CRC-32 in hex and the size in decimal: no test runs it.
    const ZIP2JOHN_VECTORS: [(u32, u64, &str); 6] = [
        (0xDEAD_BEEF, 100, "efbeadde6400000000000000"),
        (0x0000_0000, 0, "000000000000000000000000"),
        (0xFFFF_FFFF, 4_294_967_295, "ffffffffffffffff00000000"),
        (0x1234_5678, 4_294_967_296, "785634120000000001000000"),
        (0xCBF4_3926, 18_446_744_073_709_551_615, "2639f4cbffffffffffffffff"),
        (0x0000_0001, 1_099_511_627_776, "010000000000000000010000"),
    ];

    #[test]
    fn a_header_without_a_vector_stands_for_the_crc_and_the_size() {
        let (source, entry, start) = pkware_entry(&DecryptionHeader { iv: Vec::new(), ..DecryptionHeader::password(0x660E, 128) });
        let prefix = read_pkware_prefix(&source, &entry, start).unwrap();
        assert_eq!((prefix.iv_len, prefix.erd_len), (0, 144));
        assert_eq!(hex::encode(pkware_iv(&prefix, &entry)), "efbeadde6400000000000000");

        for (crc32, unpacked, expected) in ZIP2JOHN_VECTORS {
            let entry = ZipEntry { crc32, uncompressed_size: unpacked, ..entry.clone() };
            assert_eq!(hex::encode(pkware_iv(&prefix, &entry)), expected, "CRC-32 {crc32:08x}, size {unpacked}");
        }
    }

    /// A header for a password or a certificate lists its recipients between the random data and
    /// the validation data. The list is passed over, however many it names.
    #[test]
    fn a_list_of_recipients_is_passed_over() {
        let recipient = [vec![0x91; 20], vec![0x02; 268]].concat();
        let header = DecryptionHeader { flags: 3, recipients: vec![recipient.clone(), recipient], vdata: vec![0xC7; 32], ..DecryptionHeader::password(0x6610, 256) };
        let (source, entry, start) = pkware_entry(&header);
        let prefix = read_pkware_prefix(&source, &entry, start).unwrap();
        let body = read_pkware_body(&source, &entry, start, &prefix).unwrap();
        assert_eq!((body.recipients, body.erd.len(), body.vdata.as_slice()), (2, 144, &[0xC7; 32][..]));
    }

    #[test]
    fn a_vector_longer_than_a_line_carries_is_stepped_over() {
        let header = DecryptionHeader { iv: vec![0x1B; 40], ..DecryptionHeader::password(0x6610, 256) };
        let (source, entry, start) = pkware_entry(&header);
        let prefix = read_pkware_prefix(&source, &entry, start).unwrap();
        assert_eq!((prefix.iv_len, prefix.iv.len(), prefix.alg_id, prefix.erd_len), (40, 0, 0x6610, 144));
        assert_eq!(read_pkware_body(&source, &entry, start, &prefix).unwrap().vdata, [0xCC; 16]);
    }

    #[test]
    fn a_decryption_header_that_is_cut_or_lies_is_refused() {
        let header = DecryptionHeader::password(0x660E, 128);
        let (source, entry, start) = pkware_entry(&header);
        let prefix = read_pkware_prefix(&source, &entry, start).unwrap();

        // an entry too short for the fields in front of the random data
        for size in [0, 1, 17, 31] {
            assert_eq!(read_pkware_prefix(&source, &ZipEntry { compressed_size: size, ..entry.clone() }, start), None, "{size} bytes");
        }
        // sizes that lead out of the header, out of the entry, or past what is read
        assert!(read_pkware_body(&source, &entry, start, &PkwarePrefix { erd_len: 60_000, ..prefix.clone() }).is_err());
        assert!(read_pkware_body(&source, &entry, start, &PkwarePrefix { size: 20, ..prefix.clone() }).is_err());
        assert!(read_pkware_body(&source, &entry, start, &PkwarePrefix { size: PKWARE_HEADER_MAX + 1, ..prefix.clone() }).is_err());
        assert!(read_pkware_body(&source, &ZipEntry { compressed_size: 60, ..entry.clone() }, start, &prefix).is_err());
        assert!(read_pkware_body(&source, &entry, u64::MAX - 8, &prefix).is_err());

        // a count of recipients the header has no room for is not looped over
        let lying = DecryptionHeader { recipients: vec![vec![0; 30]], ..DecryptionHeader::password(0x660E, 128) };
        let mut data = lying.bytes();
        let count_at = 2 + 16 + 4 + 10 + 144;
        data[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let extra = pkware_extra(0x660E, 128, 3);
        let (source, entries) = opened(&[Member { version: 51, central_extra: &extra, ..member("ses.bin", 0x41, &data) }]);
        let start = start_of(&source, &entries[0]);
        let prefix = read_pkware_prefix(&source, &entries[0], start).unwrap();
        let error = read_pkware_body(&source, &entries[0], start, &prefix).unwrap_err();
        assert!(error.to_string().contains("no room for 4294967295 recipients"), "{error:#}");
    }
}
