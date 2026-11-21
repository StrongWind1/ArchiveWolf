//! How one entry of a RAR archive is encrypted, as its header says.
//!
//! All six encryption methods of the format are represented, from the additive stream of
//! RAR 1.3 through PBKDF2-HMAC-SHA256 in RAR 5, and the two cases its own software refuses:
//! an encryption record of a version it does not know, and one that ends before its fields do.
//!
//! Parts of this file follow the UnRAR source. Its license, paragraph 2, has to accompany such code:
//!
//! ```text
//! UnRAR source code may be used in any software to handle
//! RAR archives without limitations free of charge, but cannot be
//! used to develop RAR (WinRAR) compatible archiver and to
//! re-create RAR compression algorithm, which is proprietary.
//! Distribution of modified UnRAR source code in separate form
//! or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "UnRAR source code"
//! words, is included in license, or in documentation if license
//! is not available, and in source code comments of resulting package.
//! ```
//!
//! The full text is in `LICENSE-UNRAR.txt`.

use sha2::Digest as _;

use super::headers::Fields;
use crate::analysis::Scheme;

/// The highest exponent of the round count UnRAR accepts (`CRYPT5_KDF_LG2_COUNT_MAX`): above
/// 2^24 rounds it refuses the archive.
pub(crate) const RAR_50_LG2_COUNT_MAX: u8 = 24;

/// Flag of a RAR 5 encryption record: a check value follows the salt and the vector.
const CRYPT5_PSWCHECK: u64 = 0x0001;
/// Flag of the encryption record of an entry: its checksums are keyed.
const CRYPT5_HASHMAC: u64 = 0x0002;

/// Why the check value a record stores does not count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unused {
    /// It is the zero value RAR 5.21 and earlier left in service records: it would match every
    /// password.
    Zero,
    /// It fails its own checksum, or the record ends inside it.
    Damaged,
}

/// What a RAR 5 encryption record says: the one of an entry, or the encryption header of an
/// archive whose headers are encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rar50Record {
    /// The exponent of the round count: 2 to this power rounds of PBKDF2-HMAC-SHA256.
    pub lg2count: u8,
    /// The salt of the key derivation.
    pub salt: [u8; 16],
    /// The vector the data is encrypted with. Zero for an encryption header, which has none:
    /// every encrypted header brings its own.
    pub iv: [u8; 16],
    /// The check value a password is tested against, when the record has one that can be
    /// used: the flag is set, the value agrees with its own checksum, and it is not the zero
    /// value RAR 5.21 and earlier left in service records. UnRAR decides the same way.
    pub check_value: Option<[u8; 8]>,
    /// Why the check value the record stores is not in `check_value`, when it stores one.
    pub unused: Option<Unused>,
    /// The checksums of the entry are keyed.
    pub hashmac: bool,
}

/// Why a RAR 5 encryption record gives no [`Rar50Record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rar50Refused {
    /// It names a version of the encryption other than 0.
    Version(u64),
    /// It ends before its fields do.
    Cut,
}

impl Rar50Record {
    /// Read an encryption record from its version field on.
    ///
    /// `entry` says that the record belongs to an entry: it has a vector then. `service` says
    /// that the entry is a service record.
    pub(crate) fn read(fields: &mut Fields<'_>, entry: bool, service: bool) -> Result<Self, Rar50Refused> {
        let version = fields.vint().ok_or(Rar50Refused::Cut)?;
        if version != 0 {
            return Err(Rar50Refused::Version(version));
        }
        let flags = fields.vint().ok_or(Rar50Refused::Cut)?;
        let lg2count = fields.u8().ok_or(Rar50Refused::Cut)?;
        let salt = fields.array().ok_or(Rar50Refused::Cut)?;
        let iv = if entry { fields.array().ok_or(Rar50Refused::Cut)? } else { [0; 16] };

        // The value is used when the start of its SHA-256 says that it is undamaged. One that is
        // cut off has no such word for it, and the entry is then tested by its data.
        let stored = (flags & CRYPT5_PSWCHECK != 0).then(|| fields.array::<8>().zip(fields.array::<4>()));
        let (check_value, unused) = match stored {
            None => (None, None),
            Some(None) => (None, Some(Unused::Damaged)),
            // UnRAR looks at the zero of a service record whatever its checksum says
            Some(Some((value, _))) if service && value == [0; 8] => (None, Some(Unused::Zero)),
            Some(Some((value, checksum))) if !sha2::Sha256::digest(value).starts_with(&checksum) => (None, Some(Unused::Damaged)),
            Some(Some((value, _))) => (Some(value), None),
        };
        Ok(Self { lg2count, salt, iv, check_value, unused, hashmac: entry && flags & CRYPT5_HASHMAC != 0 })
    }

    /// Whether UnRAR accepts the round count.
    pub(crate) const fn rounds_accepted(&self) -> bool {
        self.lg2count <= RAR_50_LG2_COUNT_MAX
    }
}

/// How one entry is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RarEncryption {
    /// Not at all.
    None,
    /// RAR 1.3: three key bytes added to the data.
    Rar13,
    /// RAR 1.5: a stream from a 64-bit state.
    Rar15,
    /// RAR 2.0: a block cipher with a substitution table made from the password.
    Rar20,
    /// RAR 3 and 4: AES-128 under a key from 262,144 rounds of SHA-1.
    Rar30 {
        /// The salt of the key derivation. `None` when the header stores none.
        salt: Option<[u8; 8]>,
    },
    /// RAR 5 and 7: AES-256 under a key from PBKDF2-HMAC-SHA256.
    Rar50(Rar50Record),
    /// A RAR 5 encryption record of a version this tool does not know.
    Unknown {
        /// The version the record names.
        version: u64,
    },
    /// The entry is encrypted under the scheme named, and the fields that say how end before
    /// its header does.
    Unreadable(Scheme),
}

impl RarEncryption {
    /// The cipher of an encrypted entry of a RAR 1.5 to 4.x archive, by the version that is
    /// needed to unpack it. From `Archive::ReadHeader15` of UnRAR.
    #[must_use]
    pub(crate) const fn of_unpack_version(unp_ver: u8, salt: Option<[u8; 8]>) -> Self {
        match unp_ver {
            13 => Self::Rar13,
            15 => Self::Rar15,
            20 | 26 => Self::Rar20,
            _ => Self::Rar30 { salt },
        }
    }

    /// The scheme of the method. `None` for an entry that is not encrypted.
    #[must_use]
    pub(crate) const fn scheme(&self) -> Option<Scheme> {
        match self {
            Self::None => None,
            Self::Rar13 => Some(Scheme::Rar13),
            Self::Rar15 => Some(Scheme::Rar15),
            Self::Rar20 => Some(Scheme::Rar20),
            Self::Rar30 { .. } => Some(Scheme::Rar30),
            Self::Rar50(_) => Some(Scheme::Rar50),
            Self::Unknown { .. } => Some(Scheme::RarUnknown),
            Self::Unreadable(scheme) => Some(*scheme),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unpack_version_names_the_cipher() {
        let salt = Some([7; 8]);
        assert_eq!(RarEncryption::of_unpack_version(13, salt), RarEncryption::Rar13);
        assert_eq!(RarEncryption::of_unpack_version(15, salt), RarEncryption::Rar15);
        assert_eq!(RarEncryption::of_unpack_version(20, salt), RarEncryption::Rar20);
        assert_eq!(RarEncryption::of_unpack_version(26, salt), RarEncryption::Rar20);
        assert_eq!(RarEncryption::of_unpack_version(29, salt), RarEncryption::Rar30 { salt });
        assert_eq!(RarEncryption::of_unpack_version(36, None), RarEncryption::Rar30 { salt: None });
    }

    #[test]
    fn every_method_has_its_scheme() {
        assert_eq!(RarEncryption::None.scheme(), None);
        assert_eq!(RarEncryption::Rar13.scheme(), Some(Scheme::Rar13));
        assert_eq!(RarEncryption::Rar20.scheme(), Some(Scheme::Rar20));
        assert_eq!(RarEncryption::Rar30 { salt: None }.scheme(), Some(Scheme::Rar30));
        assert_eq!(RarEncryption::Unknown { version: 3 }.scheme(), Some(Scheme::RarUnknown));
        assert_eq!(RarEncryption::Unreadable(Scheme::Rar50).scheme(), Some(Scheme::Rar50));
    }

    /// An encryption record from its version on: the flags, the count, then what `rest` holds.
    fn record(version: u8, flags: u8, lg2count: u8, rest: &[u8]) -> Vec<u8> {
        let mut out = vec![version, flags, lg2count];
        out.extend_from_slice(rest);
        out
    }

    /// A check value with the checksum that belongs to it.
    fn checked(value: [u8; 8]) -> Vec<u8> {
        let mut out = value.to_vec();
        out.extend_from_slice(&sha2::Sha256::digest(value)[..4]);
        out
    }

    fn read(bytes: &[u8], entry: bool, service: bool) -> Result<Rar50Record, Rar50Refused> {
        Rar50Record::read(&mut Fields::new(bytes), entry, service)
    }

    #[test]
    fn the_record_of_an_entry_has_a_salt_a_vector_and_a_check_value() {
        let mut rest = vec![0x11; 16];
        rest.extend_from_slice(&[0x22; 16]);
        rest.extend_from_slice(&checked([0xAA; 8]));

        let read_back = read(&record(0, 3, 15, &rest), true, false).unwrap();
        assert_eq!(read_back, Rar50Record { lg2count: 15, salt: [0x11; 16], iv: [0x22; 16], check_value: Some([0xAA; 8]), unused: None, hashmac: true });
        assert!(read_back.rounds_accepted());

        // without the flag there is no check value, and none is read
        let plain = read(&record(0, 0, 15, &rest[..32]), true, false).unwrap();
        assert_eq!((plain.check_value, plain.hashmac), (None, false));
    }

    #[test]
    fn the_encryption_header_has_no_vector() {
        let mut rest = vec![0x33; 16];
        rest.extend_from_slice(&checked([0xBB; 8]));
        let header = read(&record(0, 1, 16, &rest), false, false).unwrap();
        assert_eq!(header, Rar50Record { lg2count: 16, salt: [0x33; 16], iv: [0; 16], check_value: Some([0xBB; 8]), unused: None, hashmac: false });
    }

    #[test]
    fn a_check_value_that_cannot_be_used_is_none() {
        let salt_and_iv = [0x44; 32];
        let with = |check: &[u8], service: bool| {
            let mut rest = salt_and_iv.to_vec();
            rest.extend_from_slice(check);
            read(&record(0, 1, 15, &rest), true, service).unwrap().check_value
        };

        // a checksum that is not the one of the value: the value is damaged
        let mut damaged = checked([0xCC; 8]);
        damaged[9] ^= 1;
        assert_eq!(with(&damaged, false), None);

        // RAR 5.21 and earlier set the flag on a service record and left the value at zero
        assert_eq!(with(&checked([0; 8]), true), None);
        assert_eq!(with(&checked([0; 8]), false), Some([0; 8]), "a file can have a value of zero");
        assert_eq!(with(&checked([0xCC; 8]), true), Some([0xCC; 8]), "a service record of a later version");
    }

    #[test]
    fn a_record_its_own_software_refuses_is_told_apart() {
        assert_eq!(read(&record(1, 0, 15, &[0; 32]), true, false), Err(Rar50Refused::Version(1)));
        assert_eq!(read(&[0x80, 0x01, 0, 15], true, false), Err(Rar50Refused::Version(128)));

        // a count above 2^24 is read, and said to be refused
        let slow = read(&record(0, 0, 25, &[0; 32]), true, false).unwrap();
        assert_eq!((slow.lg2count, slow.rounds_accepted()), (25, false));
        assert!(read(&record(0, 0, 24, &[0; 32]), true, false).unwrap().rounds_accepted());
        assert!(!read(&record(0, 0, 255, &[0; 32]), true, false).unwrap().rounds_accepted());
    }

    #[test]
    fn a_record_that_is_cut_short_is_not_read_by_halves() {
        let mut whole = record(0, 1, 15, &[0x55; 32]);
        whole.extend_from_slice(&checked([0xDD; 8]));
        assert_eq!(read(&whole, true, false).unwrap().check_value, Some([0xDD; 8]));

        // without all of its salt and its vector there is nothing to say of the encryption
        for len in 0..35 {
            assert_eq!(read(&whole[..len], true, false), Err(Rar50Refused::Cut), "{len} of {} bytes", whole.len());
        }
        // a check value that is cut off is one that cannot be used: the rest stands
        for len in 35..whole.len() {
            let cut = read(&whole[..len], true, false).unwrap();
            assert_eq!((cut.salt, cut.iv, cut.check_value), ([0x55; 16], [0x55; 16], None), "{len} of {} bytes", whole.len());
        }
    }
}
