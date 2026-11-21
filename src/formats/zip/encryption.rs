//! How a ZIP entry is marked as encrypted: by its flags, its compression method and its extra
//! fields.
//!
//! An entry is marked by flag bit 0 (encrypted), by flag bit 6 (strong encryption) or by
//! compression method 99 (WinZip AES). Any of the three is enough: an entry that carries one of
//! them is never reported as unencrypted, whatever the others say. When the mark names a scheme
//! and the extra field that holds the parameters of that scheme is missing, the entry is a
//! [`ZipEncryption::Contradiction`]: named, and not one a line can be built for.
//!
//! Flag bit 13 says that the values of the local header are masked, which a writer does when
//! it encrypts the central directory. It is not a scheme of an entry: whether the central
//! directory is encrypted is said by the ZIP64 end of central directory record.

use super::extra_fields::Extras;
use super::extra_fields::ZipPkwareExtra;
use crate::analysis::Scheme;

/// Bit 0: entry is encrypted.
pub(crate) const FLAG_ENCRYPTED: u16 = 0x0001;
/// Bit 3: data descriptor follows compressed data (CRC/sizes after data).
pub(crate) const FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
/// Bit 6: strong encryption (PKWARE). When set, bit 0 must also be set.
pub(crate) const FLAG_STRONG_ENCRYPTION: u16 = 0x0040;

/// The compression method that marks an entry as WinZip AES. The real method is in extra
/// field 0x9901.
pub(crate) const METHOD_ZIP_WINZIP: u16 = 99;

/// How a ZIP entry is marked as encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZipEncryption {
    /// Not marked.
    None,
    /// Traditional PKWARE encryption.
    ZipCrypto,
    /// WinZip AES (PBKDF2-HMAC-SHA1, AES in counter mode, HMAC-SHA1).
    ZipWinzip {
        /// AE version (1 = AE-1, 2 = AE-2).
        ae_version: u16,
        /// Key strength: 1 = AES-128, 2 = AES-192, 3 = AES-256.
        strength: u8,
        /// The compression method the entry really uses.
        actual_compression: u16,
    },
    /// PKWARE strong encryption, with what extra field 0x0017 of the central header says when
    /// the entry has one. The decryption header in front of its data says the same again.
    ZipPkware(Option<ZipPkwareExtra>),
    /// Marked as the scheme named, without the extra field that scheme needs: compression
    /// method 99 without extra field 0x9901, or flag bit 6 without bit 0 and without extra
    /// field 0x0017.
    Contradiction(Scheme),
}

/// Map AES strength byte (1/2/3) to key size in bits, 0 for any other value.
#[must_use]
pub(crate) const fn aes_strength_bits(strength: u8) -> u16 {
    match strength {
        1 => 128,
        2 => 192,
        3 => 256,
        _ => 0,
    }
}

/// How an entry is marked, from its flags, its compression method, the version it needs and
/// its extra fields.
///
/// zip2john takes an entry that has flag bit 0, extra field 0x0017 and needs version 5.1, 5.2
/// or 6.1 and later for strong encryption even when bit 6 is clear (`zip2john.c`, line 474),
/// and so does this.
#[must_use]
pub(crate) fn detect_encryption(flags: u16, compression_method: u16, version_needed: u16, extras: &Extras) -> ZipEncryption {
    let encrypted = flags & FLAG_ENCRYPTED != 0;

    if compression_method == METHOD_ZIP_WINZIP {
        return match extras.zip_winzip {
            Some(aes) => ZipEncryption::ZipWinzip { ae_version: aes.ae_version, strength: aes.strength, actual_compression: aes.actual_compression },
            None => ZipEncryption::Contradiction(Scheme::ZipWinzip),
        };
    }

    if flags & FLAG_STRONG_ENCRYPTION != 0 {
        return if encrypted || extras.pkware.is_some() { ZipEncryption::ZipPkware(extras.pkware) } else { ZipEncryption::Contradiction(Scheme::ZipPkware) };
    }

    if !encrypted {
        return ZipEncryption::None;
    }

    let version = version_needed & 0xFF;
    if extras.pkware.is_some() && (version == 51 || version == 52 || version >= 61) {
        return ZipEncryption::ZipPkware(extras.pkware);
    }
    ZipEncryption::ZipCrypto
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::zip::extra_fields::ZipWinzipExtra;

    const AES: ZipWinzipExtra = ZipWinzipExtra { ae_version: 2, strength: 3, actual_compression: 8 };
    const PKWARE: ZipPkwareExtra = ZipPkwareExtra { alg_id: 0x6610, bit_len: 256, flags: 1 };

    fn with_aes() -> Extras {
        Extras { zip_winzip: Some(AES), ..Extras::default() }
    }

    fn with_pkware() -> Extras {
        Extras { pkware: Some(PKWARE), ..Extras::default() }
    }

    #[test]
    fn an_entry_without_a_mark_is_not_encrypted() {
        assert_eq!(detect_encryption(0x0000, 8, 20, &Extras::default()), ZipEncryption::None);
        assert_eq!(detect_encryption(FLAG_DATA_DESCRIPTOR | 0x0800, 0, 20, &Extras::default()), ZipEncryption::None);
        // extra fields alone mark nothing: the flags and the method do
        assert_eq!(detect_encryption(0, 8, 20, &with_aes()), ZipEncryption::None);
        assert_eq!(detect_encryption(0, 8, 51, &with_pkware()), ZipEncryption::None);
    }

    #[test]
    fn flag_bit_0_alone_is_zip_crypto() {
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 8, 20, &Extras::default()), ZipEncryption::ZipCrypto);
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 0, 10, &Extras::default()), ZipEncryption::ZipCrypto);
        // a WinZip AES field on an entry whose method is not 99 does not make it AES
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 8, 20, &with_aes()), ZipEncryption::ZipCrypto);
        // a strong encryption field on an entry that needs version 2.0 does not make it strong
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 8, 20, &with_pkware()), ZipEncryption::ZipCrypto);
    }

    #[test]
    fn method_99_with_its_extra_field_is_zip_winzip() {
        let expected = ZipEncryption::ZipWinzip { ae_version: 2, strength: 3, actual_compression: 8 };
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 99, 20, &with_aes()), expected);
        assert_eq!(detect_encryption(FLAG_ENCRYPTED | FLAG_DATA_DESCRIPTOR, 99, 51, &with_aes()), expected);
        // the method and the field say AES: a clear flag does not make the entry plain
        assert_eq!(detect_encryption(0, 99, 20, &with_aes()), expected);
    }

    #[test]
    fn bit_6_is_zip_pkware() {
        assert_eq!(detect_encryption(FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION, 8, 51, &with_pkware()), ZipEncryption::ZipPkware(Some(PKWARE)));
        // only a central header has the field: the decryption header says the same again
        assert_eq!(detect_encryption(FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION, 8, 51, &Extras::default()), ZipEncryption::ZipPkware(None));
        assert_eq!(detect_encryption(FLAG_STRONG_ENCRYPTION, 8, 51, &with_pkware()), ZipEncryption::ZipPkware(Some(PKWARE)));
    }

    #[test]
    fn zip_pkware_is_told_by_the_version_when_bit_6_is_clear() {
        for version in [51, 52, 61, 62, 63] {
            assert_eq!(detect_encryption(FLAG_ENCRYPTED, 8, version, &with_pkware()), ZipEncryption::ZipPkware(Some(PKWARE)), "version {version}");
        }
        for version in [20, 45, 50, 53, 60] {
            assert_eq!(detect_encryption(FLAG_ENCRYPTED, 8, version, &with_pkware()), ZipEncryption::ZipCrypto, "version {version}");
        }
        // the host system in the high byte is not part of the version
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 8, 0x0333, &with_pkware()), ZipEncryption::ZipPkware(Some(PKWARE)));
    }

    /// A mark without the field that holds its parameters is never read as no mark, and never
    /// as another scheme.
    #[test]
    fn a_mark_that_contradicts_the_extra_fields_is_named() {
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 99, 20, &Extras::default()), ZipEncryption::Contradiction(Scheme::ZipWinzip));
        assert_eq!(detect_encryption(0, 99, 20, &Extras::default()), ZipEncryption::Contradiction(Scheme::ZipWinzip));
        assert_eq!(detect_encryption(FLAG_ENCRYPTED, 99, 51, &with_pkware()), ZipEncryption::Contradiction(Scheme::ZipWinzip));
        assert_eq!(detect_encryption(FLAG_STRONG_ENCRYPTION, 8, 20, &Extras::default()), ZipEncryption::Contradiction(Scheme::ZipPkware));
    }

    /// Flag bit 13 says the local header is masked. It does not say how the entry is encrypted.
    #[test]
    fn bit_13_is_not_a_scheme() {
        assert_eq!(detect_encryption(0x2000, 0, 20, &Extras::default()), ZipEncryption::None);
        assert_eq!(detect_encryption(0x2000 | FLAG_ENCRYPTED, 8, 20, &Extras::default()), ZipEncryption::ZipCrypto);
        assert_eq!(detect_encryption(0x2041, 8, 62, &with_pkware()), ZipEncryption::ZipPkware(Some(PKWARE)));
    }

    #[test]
    fn the_strength_byte_names_the_key_size() {
        assert_eq!([1, 2, 3, 0, 4, 255].map(aes_strength_bits), [128, 192, 256, 0, 0, 0]);
    }
}
