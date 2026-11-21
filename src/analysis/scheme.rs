//! The schemes and their parameters: how an entry, or the headers of an archive, are encrypted.
//!
//! A scheme is a complete way of encrypting: cipher, key size, key derivation, and what a key
//! can be checked against. The names here are those the tool prints and those of the JSON
//! object.

use std::fmt;

use serde::Serialize;
use serde::Serializer;

use crate::line::Tag;

/// An encryption scheme, by its ID.
///
/// An ID is the format, a hyphen, and the name of the scheme within the format. It is the one
/// name of the scheme: in the JSON object, in the report, in a fixture directory, in a commit
/// scope and in the documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Scheme {
    /// ZIP traditional encryption (ZipCrypto).
    #[serde(rename = "zip-crypto")]
    ZipCrypto,
    /// WinZip AES, AE-1 and AE-2.
    #[serde(rename = "zip-winzip")]
    ZipWinzip,
    /// PKWARE strong encryption, over the data of an entry or over the central directory.
    #[serde(rename = "zip-pkware")]
    ZipPkware,
    /// RAR 1.3 and 1.4.
    #[serde(rename = "rar-13")]
    Rar13,
    /// RAR 1.5.
    #[serde(rename = "rar-15")]
    Rar15,
    /// RAR 2.0.
    #[serde(rename = "rar-20")]
    Rar20,
    /// RAR 3.x to 4.x.
    #[serde(rename = "rar-30")]
    Rar30,
    /// RAR 5 and 7.
    #[serde(rename = "rar-50")]
    Rar50,
    /// 7-Zip AES-256.
    #[serde(rename = "7z-aes")]
    SevenZAes,
    /// A RAR encryption version the tool does not know: encrypted, and not with a scheme it
    /// can name.
    #[serde(rename = "rar-unknown")]
    RarUnknown,
    /// A 7-Zip cipher other than 7zAES, or a 7-Zip archive whose headers say nothing of how it
    /// is encrypted.
    #[serde(rename = "7z-unknown")]
    SevenZUnknown,
}

impl Scheme {
    /// Every scheme. ZIP has no unknown one: its two flag bits and method 99 name all three.
    pub const ALL: [Self; 11] = [Self::ZipCrypto, Self::ZipWinzip, Self::ZipPkware, Self::Rar13, Self::Rar15, Self::Rar20, Self::Rar30, Self::Rar50, Self::SevenZAes, Self::RarUnknown, Self::SevenZUnknown];

    /// The ID of the scheme.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZipCrypto => "zip-crypto",
            Self::ZipWinzip => "zip-winzip",
            Self::ZipPkware => "zip-pkware",
            Self::Rar13 => "rar-13",
            Self::Rar15 => "rar-15",
            Self::Rar20 => "rar-20",
            Self::Rar30 => "rar-30",
            Self::Rar50 => "rar-50",
            Self::SevenZAes => "7z-aes",
            Self::RarUnknown => "rar-unknown",
            Self::SevenZUnknown => "7z-unknown",
        }
    }

    /// What the scheme is, as people write it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ZipCrypto => "ZIP traditional encryption (ZipCrypto)",
            Self::ZipWinzip => "WinZip AES",
            Self::ZipPkware => "PKWARE strong encryption",
            Self::Rar13 => "RAR 1.3 and 1.4",
            Self::Rar15 => "RAR 1.5",
            Self::Rar20 => "RAR 2.0",
            Self::Rar30 => "RAR 3.x to 4.x",
            Self::Rar50 => "RAR 5 and 7",
            Self::SevenZAes => "7-Zip AES-256",
            Self::RarUnknown => "a RAR encryption version without a name",
            Self::SevenZUnknown => "a 7-Zip cipher without a name",
        }
    }

    /// The tag of the lines written for the scheme, when a hashcat mode tests it.
    #[must_use]
    pub const fn tag(self) -> Option<Tag> {
        Some(match self {
            Self::ZipCrypto => Tag::Zip1,
            Self::ZipWinzip => Tag::Zip2,
            Self::ZipPkware => Tag::Zip3,
            Self::Rar15 => Tag::Rar15,
            Self::Rar20 => Tag::Rar20,
            Self::Rar30 => Tag::Rar30,
            Self::Rar50 => Tag::Rar50,
            Self::SevenZAes => Tag::SevenZ,
            Self::Rar13 | Self::RarUnknown | Self::SevenZUnknown => return None,
        })
    }

    /// Whether the scheme can encrypt the headers of an archive as well as the data of its
    /// entries. The variants of such a scheme say which: see [`Scope`].
    #[must_use]
    pub const fn has_scope(self) -> bool {
        matches!(self, Self::ZipPkware | Self::Rar30 | Self::Rar50 | Self::SevenZAes)
    }

    /// The qualifiers of the variants of the scheme, in their order: the places of a variant ID
    /// behind the scheme and its scope, each with the words one of which stands there.
    ///
    /// This is the grammar of a variant ID, and what [`Protection::variant`] writes is held
    /// against it.
    #[must_use]
    pub const fn qualifiers(self) -> &'static [Qualifier] {
        const fn always(words: &'static [&'static str]) -> Qualifier {
            Qualifier { words, optional: false }
        }
        const fn sometimes(words: &'static [&'static str]) -> Qualifier {
            Qualifier { words, optional: true }
        }
        const ZIP_CRYPTO: [Qualifier; 1] = [always(&["check8", "check16"])];
        const ZIP_WINZIP: [Qualifier; 2] = [always(&["128", "192", "256", "other"]), always(&["ae1", "ae2", "other"])];
        const ZIP_PKWARE: [Qualifier; 2] = [always(&["aes128", "aes192", "aes256", "des", "3des168", "3des112", "rc2old", "rc2", "rc4", "blowfish", "twofish", "other"]), always(&["password", "certificate", "either"])];
        const RAR_30: [Qualifier; 1] = [sometimes(&["nosalt"])];
        const RAR_50: [Qualifier; 2] = [always(&["check", "nocheck"]), sometimes(&["keyed"])];
        const SEVEN_Z_AES: [Qualifier; 1] = [sometimes(&["rawkey"])];
        match self {
            Self::ZipCrypto => &ZIP_CRYPTO,
            Self::ZipWinzip => &ZIP_WINZIP,
            Self::ZipPkware => &ZIP_PKWARE,
            Self::Rar30 => &RAR_30,
            Self::Rar50 => &RAR_50,
            Self::SevenZAes => &SEVEN_Z_AES,
            Self::Rar13 | Self::Rar15 | Self::Rar20 | Self::RarUnknown | Self::SevenZUnknown => &[],
        }
    }

    /// The scheme a variant ID names, or `None` for text that is no variant ID.
    ///
    /// An ID is the ID of a scheme, then `data` or `headers` when the scheme has a scope, then
    /// qualifiers of the scheme in their order. It may end early: every ID names the variants
    /// that start with it, and the ID of a scheme alone is one.
    #[must_use]
    pub fn of_variant(id: &str) -> Option<Self> {
        let mut words = id.split(':');
        let name = words.next()?;
        let scheme = Self::ALL.into_iter().find(|scheme| scheme.as_str() == name)?;
        let mut rest: Vec<&str> = words.collect();
        if scheme.has_scope() && !rest.is_empty() {
            let scope = rest.remove(0);
            if scope != Scope::Data.as_str() && scope != Scope::Headers.as_str() {
                return None;
            }
        }
        let mut places = scheme.qualifiers().iter();
        for word in rest {
            // the next place that holds the word, and only places that may be left out before it
            loop {
                let place = places.next()?;
                if place.words.contains(&word) {
                    break;
                }
                if !place.optional {
                    return None;
                }
            }
        }
        Some(scheme)
    }

    /// Whether this is an identifier the tool has no name for.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::RarUnknown | Self::SevenZUnknown)
    }

    /// Whether the scheme falls without the password: `zip-crypto` to known plaintext, `rar-13`
    /// to a search of its keys.
    #[must_use]
    pub const fn falls_without_password(self) -> bool {
        matches!(self, Self::ZipCrypto | Self::Rar13)
    }

    /// The scheme a line with `tag` is for.
    #[must_use]
    pub const fn of_line(tag: Tag) -> Self {
        match tag {
            Tag::Zip1 | Tag::Zip4 => Self::ZipCrypto,
            Tag::Zip2 => Self::ZipWinzip,
            Tag::Zip3 => Self::ZipPkware,
            Tag::Rar15 => Self::Rar15,
            Tag::Rar20 => Self::Rar20,
            Tag::Rar30 => Self::Rar30,
            Tag::Rar50 => Self::Rar50,
            Tag::SevenZ => Self::SevenZAes,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One place of a variant ID behind the scheme and its scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qualifier {
    /// The words one of which stands at this place.
    pub words: &'static [&'static str],
    /// Whether the place is left out when its word does not apply. A place that is not
    /// optional is left out only where the ID ends: where nothing more was read.
    pub optional: bool,
}

/// What a variant covers: the data of an entry, or the headers of the archive.
///
/// The same two words for every format. They stand for what an archiver calls `-p` and `-hp`,
/// `-mhe=off` and `-mhe=on`, or encryption of the central directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// The data of an entry or a folder. The listing can be read without the password.
    Data,
    /// The headers: the names, the sizes and everything else the listing holds.
    Headers,
}

impl Scope {
    /// Both scopes.
    pub const ALL: [Self; 2] = [Self::Data, Self::Headers];

    /// The name of the scope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Data => "data",
            Self::Headers => "headers",
        }
    }
}

/// Who can open what PKWARE strong encryption holds (APPNOTE 7.2.4, the flags).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// A password.
    Password,
    /// The private key of a certificate. No password opens it.
    Certificate,
    /// A password, or the private key of a certificate.
    Either,
}

impl Access {
    /// The access the flags of a decryption header say, or `None` when they say none.
    #[must_use]
    pub const fn of_flags(flags: u16) -> Option<Self> {
        match flags & 0x0003 {
            0x0001 => Some(Self::Password),
            0x0002 => Some(Self::Certificate),
            0x0003 => Some(Self::Either),
            _ => None,
        }
    }

    /// The name of the access.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Certificate => "certificate",
            Self::Either => "either",
        }
    }
}

/// A cipher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Cipher {
    /// The stream cipher of ZIP traditional encryption. A cipher that only one scheme has is
    /// named as the scheme is.
    #[serde(rename = "zip-crypto")]
    ZipCrypto,
    /// AES. The key size says which.
    #[serde(rename = "aes")]
    Aes,
    /// DES.
    #[serde(rename = "des")]
    Des,
    /// Triple DES with three keys: 168 bits.
    #[serde(rename = "3des")]
    TripleDes,
    /// Triple DES with two keys: 112 bits.
    #[serde(rename = "3des-2key")]
    TripleDes2Key,
    /// RC2 as PKWARE used it before version 5.2 of the format.
    #[serde(rename = "rc2-old")]
    Rc2Old,
    /// RC2.
    #[serde(rename = "rc2")]
    Rc2,
    /// RC4.
    #[serde(rename = "rc4")]
    Rc4,
    /// Blowfish.
    #[serde(rename = "blowfish")]
    Blowfish,
    /// Twofish.
    #[serde(rename = "twofish")]
    Twofish,
    /// The cipher of RAR 1.3: three key bytes added to the data.
    #[serde(rename = "rar-13")]
    Rar13,
    /// The cipher of RAR 1.5: a stream from a 64-bit state.
    #[serde(rename = "rar-15")]
    Rar15,
    /// The block cipher of RAR 2.0.
    #[serde(rename = "rar-20")]
    Rar20,
}

impl Cipher {
    /// The name of the cipher as people write it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ZipCrypto => "ZipCrypto",
            Self::Aes => "AES",
            Self::Des => "DES",
            Self::TripleDes => "3DES",
            Self::TripleDes2Key => "3DES with two keys",
            Self::Rc2Old => "RC2 (before 5.2)",
            Self::Rc2 => "RC2",
            Self::Rc4 => "RC4",
            Self::Blowfish => "Blowfish",
            Self::Twofish => "Twofish",
            Self::Rar13 => "RAR 1.3 cipher",
            Self::Rar15 => "RAR 1.5 cipher",
            Self::Rar20 => "RAR 2.0 cipher",
        }
    }
}

/// The function a key is derived with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum KdfName {
    /// PBKDF2 with HMAC-SHA1.
    #[serde(rename = "pbkdf2-hmac-sha1")]
    Pbkdf2HmacSha1,
    /// PBKDF2 with HMAC-SHA256.
    #[serde(rename = "pbkdf2-hmac-sha256")]
    Pbkdf2HmacSha256,
    /// SHA-1 over the password, once or many times.
    #[serde(rename = "sha1")]
    Sha1,
    /// SHA-256 over the password, many times.
    #[serde(rename = "sha256")]
    Sha256,
}

impl KdfName {
    /// The name of the function as people write it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pbkdf2HmacSha1 => "PBKDF2-HMAC-SHA1",
            Self::Pbkdf2HmacSha256 => "PBKDF2-HMAC-SHA256",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
        }
    }
}

/// A key derivation and its cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Kdf {
    /// The function.
    pub name: KdfName,
    /// How many rounds of it, when the scheme counts rounds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rounds: Option<u64>,
}

/// One thing a password can be tested against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum CheckKind {
    /// The last byte or the last two bytes of a ZipCrypto encryption header.
    #[serde(rename = "check-byte")]
    CheckByte,
    /// The password verifier of WinZip AES.
    #[serde(rename = "verifier")]
    Verifier,
    /// The check value of RAR 5.
    #[serde(rename = "check-value")]
    CheckValue,
    /// A CRC-32 of the data.
    #[serde(rename = "crc32")]
    Crc32,
    /// A BLAKE2sp digest of the data.
    #[serde(rename = "blake2sp")]
    Blake2sp,
    /// An authentication code over the encrypted data.
    #[serde(rename = "hmac")]
    Hmac,
    /// The structure of what decrypts.
    #[serde(rename = "structure")]
    Structure,
    /// A checksum of the data that is no CRC-32: the 16 bits RAR 1.3 and 1.4 store.
    #[serde(rename = "checksum")]
    Checksum,
}

impl CheckKind {
    /// The name of the check as people write it.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::CheckByte => "check byte",
            Self::Verifier => "verifier",
            Self::CheckValue => "check value",
            Self::Crc32 => "CRC-32",
            Self::Blake2sp => "BLAKE2sp",
            Self::Hmac => "authentication code",
            Self::Structure => "structure",
            Self::Checksum => "checksum",
        }
    }
}

/// One thing a password can be tested against, and how many bits of it there are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Check {
    /// What it is.
    pub kind: CheckKind,
    /// How many bits it has. Absent for the structure of the data, which has no number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<u32>,
    /// Whether the checksum is keyed: RAR 5 can store its checksums as an authentication code
    /// under a key derived from the password.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub keyed: bool,
}

impl Check {
    /// A check of `bits` bits.
    #[must_use]
    pub const fn new(kind: CheckKind, bits: u32) -> Self {
        Self { kind, bits: Some(bits), keyed: false }
    }

    /// The structure of what decrypts.
    #[must_use]
    pub const fn structure() -> Self {
        Self { kind: CheckKind::Structure, bits: None, keyed: false }
    }

    /// The same check, keyed.
    #[must_use]
    pub const fn keyed(mut self) -> Self {
        self.keyed = true;
        self
    }
}

/// The parameters of a scheme as one entry uses it: everything but the salt. Entries that agree
/// in their scheme and in these are one row of `schemes`.
///
/// A field is absent when the scheme has no such parameter, or when the parser does not read
/// it yet.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Parameters {
    /// WinZip AES: 1 for AE-1, 2 for AE-2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ae: Option<u16>,
    /// The cipher.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher: Option<Cipher>,
    /// The identifier the archive stores for its cipher or its scheme, when the tool has no
    /// name for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<u64>,
    /// Size of the key in bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_bits: Option<u32>,
    /// PKWARE strong encryption: who can open it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    /// The key derivation and its cost.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf: Option<Kdf>,
    /// What a password can be tested against.
    pub check: Vec<Check>,
    /// RAR 5: the archive stores a check value that does not count, because it fails its own
    /// checksum or is the zero of an old service record. A password is not tested against it,
    /// so it is not in `check`; the variant still says what the archive stores.
    #[serde(skip)]
    pub check_value_unused: bool,
}

/// The salt of a key derivation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum Salt {
    /// The scheme derives its key without a salt, or this entry has none.
    #[default]
    None,
    /// The salt.
    Known(Vec<u8>),
    /// The scheme has a salt and the parser does not keep it. Such an entry is in no key group:
    /// the tool cannot say which entries share its key.
    Unknown,
}

impl Salt {
    /// The salt in hex, or `None` when there is none to show: the scheme has none, or it is not
    /// known.
    #[must_use]
    pub fn hex(&self) -> Option<String> {
        match self {
            Self::Known(bytes) => Some(hex::encode(bytes)),
            Self::None | Self::Unknown => None,
        }
    }

    /// The salt an archive stores: none when it stores no bytes for it.
    #[must_use]
    pub fn stored(bytes: &[u8]) -> Self {
        if bytes.is_empty() { Self::None } else { Self::Known(bytes.to_vec()) }
    }
}

/// How one entry, or the headers of an archive, are encrypted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Protection {
    /// The scheme.
    pub scheme: Scheme,
    /// Its parameters.
    pub parameters: Parameters,
    /// The salt of the key derivation.
    pub salt: Salt,
}

/// A protection as the JSON object shows it: with the variant it is of.
#[derive(Serialize)]
struct Shown<'a> {
    scheme: Scheme,
    variant: String,
    #[serde(flatten)]
    parameters: &'a Parameters,
    /// In hex. Absent when there is none, or when it is not known.
    #[serde(skip_serializing_if = "Option::is_none")]
    salt: Option<String>,
}

impl Protection {
    /// A scheme of which nothing else is known.
    #[must_use]
    pub fn bare(scheme: Scheme) -> Self {
        Self { scheme, parameters: Parameters::default(), salt: Salt::None }
    }

    /// The ID of the variant this is: the ID of the scheme, then the scope for a scheme that
    /// has one, then the qualifiers of the scheme in their fixed order, with colons between.
    ///
    /// A qualifier that cannot be read ends the ID: `zip-pkware:data` is strong encryption of
    /// which the cipher is not known. So an ID names every variant that starts with it.
    #[must_use]
    pub fn variant(&self, scope: Scope) -> String {
        let parameters = &self.parameters;
        let mut id = vec![self.scheme.as_str()];
        if self.scheme.has_scope() {
            id.push(scope.as_str());
        }
        match self.scheme {
            Scheme::ZipCrypto => match parameters.check.iter().find(|check| check.kind == CheckKind::CheckByte).and_then(|check| check.bits) {
                Some(8) => id.push("check8"),
                Some(16) => id.push("check16"),
                _ => {},
            },
            Scheme::ZipWinzip => {
                let strength = match (parameters.key_bits, parameters.identifier) {
                    (Some(128), _) => Some("128"),
                    (Some(192), _) => Some("192"),
                    (Some(256), _) => Some("256"),
                    (_, Some(_)) => Some("other"),
                    _ => None,
                };
                if let Some(strength) = strength {
                    id.push(strength);
                    match parameters.ae {
                        Some(1) => id.push("ae1"),
                        Some(2) => id.push("ae2"),
                        Some(_) => id.push("other"),
                        None => {},
                    }
                }
            },
            Scheme::ZipPkware => {
                let cipher = match (parameters.cipher, parameters.key_bits, parameters.identifier) {
                    (Some(Cipher::Aes), Some(128), _) => Some("aes128"),
                    (Some(Cipher::Aes), Some(192), _) => Some("aes192"),
                    (Some(Cipher::Aes), Some(256), _) => Some("aes256"),
                    (Some(Cipher::Des), ..) => Some("des"),
                    (Some(Cipher::TripleDes), ..) => Some("3des168"),
                    (Some(Cipher::TripleDes2Key), ..) => Some("3des112"),
                    (Some(Cipher::Rc2Old), ..) => Some("rc2old"),
                    (Some(Cipher::Rc2), ..) => Some("rc2"),
                    (Some(Cipher::Rc4), ..) => Some("rc4"),
                    (Some(Cipher::Blowfish), ..) => Some("blowfish"),
                    (Some(Cipher::Twofish), ..) => Some("twofish"),
                    (Some(_), ..) | (None, _, Some(_)) => Some("other"),
                    (None, _, None) => None,
                };
                if let Some(cipher) = cipher {
                    id.push(cipher);
                    if let Some(access) = parameters.access {
                        id.push(access.as_str());
                    }
                }
            },
            // nothing was read of a derivation that is not there
            Scheme::Rar30 if parameters.kdf.is_some() && self.salt == Salt::None => id.push("nosalt"),
            Scheme::Rar50 if parameters.kdf.is_some() => {
                let stored = parameters.check_value_unused || parameters.check.iter().any(|check| check.kind == CheckKind::CheckValue);
                id.push(if stored { "check" } else { "nocheck" });
                if parameters.check.iter().any(|check| check.keyed) {
                    id.push("keyed");
                }
            },
            // the properties of the coder were read, and they hold no number of rounds
            Scheme::SevenZAes if parameters.kdf.is_none() && self.salt != Salt::Unknown && parameters.cipher.is_some() => id.push("rawkey"),
            Scheme::Rar13 | Scheme::Rar15 | Scheme::Rar20 | Scheme::Rar30 | Scheme::Rar50 | Scheme::SevenZAes | Scheme::RarUnknown | Scheme::SevenZUnknown => {},
        }
        id.join(":")
    }

    /// What the key derivation takes besides the password, or `None` when the salt is not
    /// known. Entries that agree in this share a derived key.
    #[must_use]
    pub(crate) fn key_inputs(&self) -> Option<(Scheme, Option<Cipher>, Option<u64>, Option<u32>, Option<Kdf>, &[u8])> {
        let salt: &[u8] = match &self.salt {
            Salt::None => &[],
            Salt::Known(bytes) => bytes,
            Salt::Unknown => return None,
        };
        Some((self.scheme, self.parameters.cipher, self.parameters.identifier, self.parameters.key_bits, self.parameters.kdf, salt))
    }
}

/// A protection is written into a JSON object as the fields of an entry: the scheme, the
/// variant, the parameters and the salt. What an entry holds is data, so the variant is one of
/// that scope. The protection of the headers is not written this way: its row of `schemes`
/// carries its variant.
impl Serialize for Protection {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Shown { scheme: self.scheme, variant: self.variant(Scope::Data), parameters: &self.parameters, salt: self.salt.hex() }.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A protection with these parameters and this salt.
    fn with(scheme: Scheme, parameters: Parameters, salt: Salt) -> Protection {
        Protection { scheme, parameters, salt }
    }

    /// The parameters of AES with a key of `key_bits` bits.
    fn aes(key_bits: u32) -> Parameters {
        Parameters { cipher: Some(Cipher::Aes), key_bits: Some(key_bits), ..Parameters::default() }
    }

    #[test]
    fn the_schemes_are_named_as_the_naming_standard_names_them() {
        let names: Vec<&str> = Scheme::ALL.iter().map(|scheme| scheme.as_str()).collect();
        assert_eq!(names, ["zip-crypto", "zip-winzip", "zip-pkware", "rar-13", "rar-15", "rar-20", "rar-30", "rar-50", "7z-aes", "rar-unknown", "7z-unknown"]);
        for scheme in Scheme::ALL {
            assert_eq!(serde_json::to_value(scheme).unwrap(), scheme.as_str(), "the JSON name is the ID");
            assert_eq!(scheme.to_string(), scheme.as_str());
            // an ID is a format, a hyphen and a name, in lower case
            let (format, name) = scheme.as_str().split_once('-').unwrap();
            assert!(["zip", "rar", "7z"].contains(&format), "{scheme}");
            assert!(!name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()), "{scheme}");
            assert_eq!(scheme.is_unknown(), name == "unknown");
            // a scheme without a name has no line, and so has rar-13
            assert_eq!(scheme.tag().is_none(), scheme.is_unknown() || scheme == Scheme::Rar13, "{scheme}");
            assert!(scheme.tag().is_none_or(|tag| Scheme::of_line(tag) == scheme), "{scheme}");
        }
    }

    #[test]
    fn a_zip_variant_is_the_scheme_and_its_qualifiers_in_their_order() {
        // zip-crypto: the width of its check
        for (bits, id) in [(8, "zip-crypto:check8"), (16, "zip-crypto:check16")] {
            let parameters = Parameters { check: vec![Check::new(CheckKind::CheckByte, bits), Check::new(CheckKind::Crc32, 32)], ..Parameters::default() };
            assert_eq!(with(Scheme::ZipCrypto, parameters, Salt::None).variant(Scope::Data), id);
        }
        assert_eq!(Protection::bare(Scheme::ZipCrypto).variant(Scope::Data), "zip-crypto", "an ID ends where nothing more was read");

        // zip-winzip: the key size, then the version
        assert_eq!(with(Scheme::ZipWinzip, Parameters { ae: Some(2), ..aes(256) }, Salt::Unknown).variant(Scope::Data), "zip-winzip:256:ae2");
        assert_eq!(with(Scheme::ZipWinzip, Parameters { ae: Some(1), ..aes(128) }, Salt::Unknown).variant(Scope::Data), "zip-winzip:128:ae1");
        assert_eq!(with(Scheme::ZipWinzip, Parameters { ae: Some(2), cipher: Some(Cipher::Aes), identifier: Some(7), ..Parameters::default() }, Salt::Unknown).variant(Scope::Data), "zip-winzip:other:ae2");
        assert_eq!(with(Scheme::ZipWinzip, Parameters { ae: Some(3), ..aes(192) }, Salt::Unknown).variant(Scope::Data), "zip-winzip:192:other");

        // zip-pkware: the scope, the cipher, who can open it
        let pkware = |cipher: Option<Cipher>, key_bits: u32, access: Option<Access>| Parameters { cipher, key_bits: Some(key_bits), access, ..Parameters::default() };
        assert_eq!(with(Scheme::ZipPkware, pkware(Some(Cipher::Aes), 256, Some(Access::Password)), Salt::Unknown).variant(Scope::Data), "zip-pkware:data:aes256:password");
        assert_eq!(with(Scheme::ZipPkware, pkware(Some(Cipher::Aes), 128, Some(Access::Certificate)), Salt::None).variant(Scope::Headers), "zip-pkware:headers:aes128:certificate");
        assert_eq!(with(Scheme::ZipPkware, pkware(Some(Cipher::TripleDes), 168, Some(Access::Either)), Salt::None).variant(Scope::Data), "zip-pkware:data:3des168:either");
        assert_eq!(with(Scheme::ZipPkware, pkware(Some(Cipher::TripleDes2Key), 112, None), Salt::None).variant(Scope::Data), "zip-pkware:data:3des112");
        assert_eq!(with(Scheme::ZipPkware, pkware(Some(Cipher::Rc2Old), 40, Some(Access::Password)), Salt::None).variant(Scope::Data), "zip-pkware:data:rc2old:password");
        assert_eq!(with(Scheme::ZipPkware, Parameters { identifier: Some(0xFFFF), ..pkware(None, 0, Some(Access::Password)) }, Salt::None).variant(Scope::Data), "zip-pkware:data:other:password");
        assert_eq!(with(Scheme::ZipPkware, pkware(Some(Cipher::Aes), 512, Some(Access::Password)), Salt::None).variant(Scope::Data), "zip-pkware:data:other:password");
        assert_eq!(Protection::bare(Scheme::ZipPkware).variant(Scope::Data), "zip-pkware:data");
    }

    #[test]
    fn a_rar_variant_is_the_scheme_the_scope_and_its_qualifiers() {
        let sha1 = Some(Kdf { name: KdfName::Sha1, rounds: None });

        // the early RAR schemes have one variant each
        for scheme in [Scheme::Rar13, Scheme::Rar15, Scheme::Rar20] {
            assert_eq!(Protection::bare(scheme).variant(Scope::Data), scheme.as_str());
        }

        // rar-30: the scope, and whether there is a salt
        let rar_30 = Parameters { kdf: sha1, ..aes(128) };
        assert_eq!(with(Scheme::Rar30, rar_30.clone(), Salt::Known(vec![1; 8])).variant(Scope::Data), "rar-30:data");
        assert_eq!(with(Scheme::Rar30, rar_30.clone(), Salt::None).variant(Scope::Data), "rar-30:data:nosalt");
        assert_eq!(with(Scheme::Rar30, rar_30, Salt::Known(vec![1; 8])).variant(Scope::Headers), "rar-30:headers");
        assert_eq!(Protection::bare(Scheme::Rar30).variant(Scope::Headers), "rar-30:headers");

        // rar-50: the scope, the check value, and whether the checksums are keyed
        let rar_50 = |check: Vec<Check>| Parameters { kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 15) }), check, ..aes(256) };
        assert_eq!(with(Scheme::Rar50, rar_50(vec![Check::new(CheckKind::CheckValue, 64), Check::new(CheckKind::Crc32, 32)]), Salt::Known(vec![2; 16])).variant(Scope::Data), "rar-50:data:check");
        assert_eq!(with(Scheme::Rar50, rar_50(vec![Check::new(CheckKind::CheckValue, 64), Check::new(CheckKind::Blake2sp, 256).keyed()]), Salt::Known(vec![2; 16])).variant(Scope::Data), "rar-50:data:check:keyed");
        assert_eq!(with(Scheme::Rar50, rar_50(vec![Check::new(CheckKind::Crc32, 32).keyed()]), Salt::Known(vec![2; 16])).variant(Scope::Data), "rar-50:data:nocheck:keyed");
        assert_eq!(with(Scheme::Rar50, rar_50(vec![Check::structure()]), Salt::Known(vec![2; 16])).variant(Scope::Headers), "rar-50:headers:nocheck");
        assert_eq!(with(Scheme::Rar50, Parameters::default(), Salt::Unknown).variant(Scope::Headers), "rar-50:headers");
    }

    #[test]
    fn a_7z_variant_is_the_scheme_the_scope_and_whether_the_password_is_the_key() {
        let derived = Parameters { kdf: Some(Kdf { name: KdfName::Sha256, rounds: Some(1 << 19) }), ..aes(256) };
        assert_eq!(with(Scheme::SevenZAes, derived.clone(), Salt::None).variant(Scope::Data), "7z-aes:data");
        assert_eq!(with(Scheme::SevenZAes, derived, Salt::Known(vec![3; 4])).variant(Scope::Headers), "7z-aes:headers");
        assert_eq!(with(Scheme::SevenZAes, aes(256), Salt::None).variant(Scope::Data), "7z-aes:data:rawkey");
        assert_eq!(with(Scheme::SevenZAes, aes(256), Salt::Unknown).variant(Scope::Data), "7z-aes:data", "the properties of the coder were not read");
        assert_eq!(Protection::bare(Scheme::SevenZAes).variant(Scope::Headers), "7z-aes:headers");

        // a scheme without a name has no variant but itself
        assert_eq!(Protection::bare(Scheme::RarUnknown).variant(Scope::Headers), "rar-unknown");
        assert_eq!(Protection::bare(Scheme::SevenZUnknown).variant(Scope::Data), "7z-unknown");

        // every variant starts with the ID of its scheme, and says its scope when the scheme has one
        for scheme in Scheme::ALL {
            for scope in [Scope::Data, Scope::Headers] {
                let id = Protection::bare(scheme).variant(scope);
                let expected = if scheme.has_scope() { format!("{scheme}:{}", scope.as_str()) } else { scheme.to_string() };
                assert_eq!(id, expected);
            }
        }
    }

    #[test]
    fn a_variant_id_is_read_by_the_grammar_that_writes_it() {
        for id in [
            "zip-crypto",
            "zip-crypto:check8",
            "zip-crypto:check16",
            "zip-winzip:256:ae2",
            "zip-winzip:other:ae1",
            "zip-winzip:128",
            "zip-pkware:data",
            "zip-pkware:headers:3des112:either",
            "zip-pkware:data:other:certificate",
            "rar-13",
            "rar-30:data",
            "rar-30:data:nosalt",
            "rar-30:headers",
            "rar-50",
            "rar-50:data:check",
            "rar-50:data:nocheck:keyed",
            "rar-50:headers:check",
            "7z-aes:data",
            "7z-aes:headers:rawkey",
            "rar-unknown",
            "7z-unknown",
        ] {
            let scheme = Scheme::of_variant(id).unwrap_or_else(|| panic!("{id} is a variant ID"));
            assert!(id == scheme.as_str() || id.starts_with(&format!("{scheme}:")), "{id}");
        }
        for id in [
            "",
            "zip",
            "zipcrypto",
            "rar50",
            "zip-crypto:data",
            "zip-crypto:check8:check16",
            "zip-winzip:ae2",
            "zip-winzip:256:ae2:keyed",
            "zip-pkware:aes256",
            "zip-pkware:data:password",
            "rar-13:data",
            "rar-30:nosalt",
            "rar-30:data:keyed",
            "rar-50:data:keyed",
            "rar-50:data:check:keyed:keyed",
            "rar-50:both",
            "7z-aes:rawkey",
            "7z-aes:data:",
            "rar-unknown:data",
            "RAR-50",
            "rar-50:Data",
        ] {
            assert_eq!(Scheme::of_variant(id), None, "{id} is no variant ID");
        }
        // every word of the grammar is lower case, and no scheme uses a word twice
        for scheme in Scheme::ALL {
            let words: Vec<&str> = scheme.qualifiers().iter().flat_map(|place| place.words.iter().copied()).filter(|word| *word != "other").collect();
            assert!(words.iter().all(|word| !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())), "{scheme}");
            let mut once = words.clone();
            once.sort_unstable();
            once.dedup();
            assert_eq!(once.len(), words.len(), "{scheme}");
            assert!(scheme.has_scope() || !scheme.qualifiers().iter().any(|place| place.words.contains(&"data")), "{scheme}");
        }
    }

    #[test]
    fn the_flags_of_zip_pkware_say_who_can_open_it() {
        assert_eq!([0, 1, 2, 3, 0x8001].map(Access::of_flags), [None, Some(Access::Password), Some(Access::Certificate), Some(Access::Either), Some(Access::Password)]);
        assert_eq!(serde_json::to_value([Access::Password, Access::Certificate, Access::Either]).unwrap(), serde_json::json!(["password", "certificate", "either"]));
        assert_eq!(serde_json::to_value([Scope::Data, Scope::Headers]).unwrap(), serde_json::json!(["data", "headers"]));
    }

    #[test]
    fn two_schemes_fall_without_the_password() {
        let weak: Vec<Scheme> = Scheme::ALL.into_iter().filter(|scheme| scheme.falls_without_password()).collect();
        assert_eq!(weak, [Scheme::ZipCrypto, Scheme::Rar13]);
    }

    #[test]
    fn every_kind_of_line_belongs_to_a_scheme() {
        let schemes: Vec<Scheme> = Tag::ALL.into_iter().map(Scheme::of_line).collect();
        assert_eq!(schemes, [Scheme::ZipCrypto, Scheme::ZipWinzip, Scheme::ZipPkware, Scheme::ZipCrypto, Scheme::Rar15, Scheme::Rar20, Scheme::Rar30, Scheme::Rar50, Scheme::SevenZAes]);
    }

    #[test]
    fn a_protection_is_its_scheme_its_parameters_and_its_salt() {
        let protection = Protection {
            scheme: Scheme::Rar50,
            parameters: Parameters { cipher: Some(Cipher::Aes), key_bits: Some(256), kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 15) }), check: vec![Check::new(CheckKind::CheckValue, 64), Check::new(CheckKind::Crc32, 32).keyed()], ..Parameters::default() },
            salt: Salt::Known(vec![0xAB, 0xCD]),
        };
        assert_eq!(
            serde_json::to_value(&protection).unwrap(),
            serde_json::json!({
                "scheme": "rar-50", "variant": "rar-50:data:check:keyed", "cipher": "aes", "key_bits": 256,
                "kdf": { "name": "pbkdf2-hmac-sha256", "rounds": 32768 },
                "check": [{ "kind": "check-value", "bits": 64 }, { "kind": "crc32", "bits": 32, "keyed": true }],
                "salt": "abcd",
            })
        );

        // what is not known is absent, and a check without a number has none
        let bare = Protection { scheme: Scheme::Rar30, parameters: Parameters { check: vec![Check::structure()], ..Parameters::default() }, salt: Salt::Unknown };
        assert_eq!(serde_json::to_value(&bare).unwrap(), serde_json::json!({ "scheme": "rar-30", "variant": "rar-30:data", "check": [{ "kind": "structure" }] }));
        assert_eq!(serde_json::to_value(Protection::bare(Scheme::RarUnknown)).unwrap(), serde_json::json!({ "scheme": "rar-unknown", "variant": "rar-unknown", "check": [] }));
    }

    #[test]
    fn a_salt_that_is_not_known_gives_no_key_inputs() {
        let mut protection = Protection::bare(Scheme::ZipWinzip);
        assert!(protection.key_inputs().is_some(), "no salt is a salt that is known");
        protection.salt = Salt::Unknown;
        assert!(protection.key_inputs().is_none());
        assert_eq!(Salt::stored(&[]), Salt::None);
        assert_eq!(Salt::stored(&[1]), Salt::Known(vec![1]));
    }
}
