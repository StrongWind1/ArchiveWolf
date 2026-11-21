//! Why an entry or a scheme gets no line.
//!
//! There are nine reasons, and each case has one of them. [`NoLine`] is the list of cases:
//! what was found, with the numbers its sentence needs.
//! Nothing outside this file writes such a sentence, so a case reads the same wherever it is
//! reported.

use std::fmt;

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap as _;

use super::scheme::Cipher;
use super::scheme::Scheme;
use crate::line::NoCrc;

/// A reason why no line is written, by its code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Reason {
    /// No hashcat mode exists for the scheme.
    #[serde(rename = "no-mode")]
    NoMode,
    /// No password opens the entry: it is encrypted to certificates.
    #[serde(rename = "no-password")]
    NoPassword,
    /// The identifier is not known.
    #[serde(rename = "unknown-scheme")]
    UnknownScheme,
    /// The scheme's own software refuses these parameters.
    #[serde(rename = "unsupported-parameters")]
    UnsupportedParameters,
    /// The line format has no way to say what the archive holds.
    #[serde(rename = "not-expressible")]
    NotExpressible,
    /// The line would exceed what its mode loads.
    #[serde(rename = "over-limit")]
    OverLimit,
    /// The data of the entry is not all in this file.
    #[serde(rename = "split")]
    Split,
    /// Nothing in the archive can be tested.
    #[serde(rename = "no-data")]
    NoData,
    /// The headers of the entry cannot be read.
    #[serde(rename = "damaged")]
    Damaged,
}

impl Reason {
    /// Every reason.
    pub const ALL: [Self; 9] = [Self::NoMode, Self::NoPassword, Self::UnknownScheme, Self::UnsupportedParameters, Self::NotExpressible, Self::OverLimit, Self::Split, Self::NoData, Self::Damaged];

    /// The code of the reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoMode => "no-mode",
            Self::NoPassword => "no-password",
            Self::UnknownScheme => "unknown-scheme",
            Self::UnsupportedParameters => "unsupported-parameters",
            Self::NotExpressible => "not-expressible",
            Self::OverLimit => "over-limit",
            Self::Split => "split",
            Self::NoData => "no-data",
            Self::Damaged => "damaged",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a 7-Zip stream is when its CRC-32 cannot be tested and nothing else about it can.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Untestable {
    /// Stored data, which says nothing about the key by itself.
    Stored,
    /// Data of a coder whose start says nothing about the key.
    SilentStart {
        /// The coder, by name or by its identifier in hex.
        coder: String,
    },
    /// Too few bytes of a coder whose start says something only at length.
    ShortStart {
        /// The coder, by name or by its identifier in hex.
        coder: String,
        /// How many bytes there are.
        packed: u64,
    },
}

/// A case in which no line is written: what was found. [`NoLine::reason`] is its reason and
/// [`fmt::Display`] its sentence, without the name of the entry.
///
/// A format that meets a new case adds a variant here, in the part of its format, with its
/// reason and its sentence below. It does not write the sentence where it finds the case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NoLine {
    // --- any format ---
    /// No hashcat mode exists for the scheme.
    NoMode(Scheme),
    /// No hashcat mode exists for `rar-13`, and the archive is one `attack rar-13` reads: the
    /// command searches the key.
    KeySearch,
    /// The scheme is not one the tool knows.
    UnknownScheme,
    /// The headers of the entry, or its data, cannot be read. What the parser said is in the log.
    Unreadable,
    /// The entry is empty: every password would match.
    Empty,

    // --- ZIP ---
    /// PKWARE strong encryption with a cipher no mode tests. `cipher` is absent when the tool
    /// has no name for the identifier.
    PkwareCipher {
        /// The cipher.
        cipher: Option<Cipher>,
        /// The algorithm identifier the archive stores.
        identifier: u16,
    },
    /// The central directory is encrypted.
    CentralDirectoryEncrypted,
    /// The entry is encrypted to certificates.
    Certificate,
    /// The compression method is a number with more digits than the mode of the line reads.
    MethodNumber {
        /// The compression method.
        method: u16,
    },
    /// A field of a strong encryption header is larger than the mode of the line loads.
    LineField {
        /// What the field holds: `random data`, `validation data`, `initialisation vector`.
        field: &'static str,
        /// Its size in bytes.
        size: u64,
        /// What the mode loads at most.
        limit: u64,
    },
    /// The random data of a strong encryption header is wrapped with 3DES.
    RandomDataWrapped,
    /// The decryption header names a format other than 3, the one the specification defines.
    HeaderFormat {
        /// The format it names.
        format: u16,
    },

    // --- RAR ---
    /// The entry continues from or into another volume.
    Split,
    /// The entry is a compressed member of a solid archive, which cannot be unpacked without the
    /// entries before it.
    SolidMember,
    /// The encrypted data is longer than a line carries, and a cut stream cannot be checked.
    TooLarge {
        /// Size of the encrypted data.
        packed: u64,
        /// What a line carries at most.
        limit: u64,
    },
    /// A RAR 5 service record whose check value is zero: every password would match.
    ZeroCheckValue,
    /// A RAR 5 check value whose own checksum is wrong.
    CheckValueDamaged,
    /// A RAR 3 entry whose key is derived without a salt: a line always carries one.
    NoSalt,
    /// The size the entry unpacks to is not stored: it was packed from a stream.
    SizeUnknown,
    /// A RAR 5 entry that stores no checksum of its data and has no check value.
    NoChecksum,
    /// The key derivation of RAR 5 asks for more rounds than RAR accepts.
    RoundsRefused {
        /// The exponent: 2 to this power rounds.
        power: u8,
    },
    /// The key derivation of RAR 5 asks for fewer rounds than its hashcat mode loads.
    RoundsBelowMode {
        /// The exponent: 2 to this power rounds.
        power: u8,
    },
    /// The entry is packed in a way hashcat does not unpack.
    Packing {
        /// The method or the version of the algorithm, in words.
        name: String,
    },
    /// The entry unpacks to more than its hashcat mode takes.
    UnpacksTooLarge {
        /// Size of the unpacked data.
        size: u64,
        /// What the mode takes at most.
        limit: u64,
    },

    // --- 7-Zip ---
    /// The properties of the AES coder are missing or cut short.
    CoderProperties,
    /// The folder joins its streams more than once.
    JoinedTwice,
    /// A stream of the folder is not encrypted, or is encrypted before it is packed.
    StreamNotEncryptedLast,
    /// The folder is encrypted twice.
    EncryptedTwice,
    /// The folder is encrypted after its streams are joined.
    EncryptedAfterJoin,
    /// The folder has no packed stream.
    NoPackedStream,
    /// The streams of the folder do not share one key.
    SeveralKeys,
    /// The key is the password itself, with no key derivation.
    KeyIsPassword,
    /// The key derivation asks for more rounds than 7-Zip accepts.
    TooManyRounds {
        /// The exponent: 2 to this power rounds.
        power: u8,
    },
    /// An encrypted stream is not a whole number of cipher blocks.
    NotWholeBlocks,
    /// The sizes of an encrypted stream do not fit each other.
    SizesDisagree,
    /// The folder uses a coder hashcat cannot unpack.
    Coder {
        /// The identifier of the coder, in hex.
        id: String,
    },
    /// The folder joins its streams with a coder other than BCJ2.
    JoinNotBcj2,
    /// The folder uses BCJ2 on a single stream.
    Bcj2OnOneStream,
    /// The folder uses BCJ2, and its CRC-32 cannot be tested.
    Bcj2WithoutCrc(NoCrc),
    /// The folder uses BCJ2, and one of its streams is longer than a line carries.
    Bcj2StreamTooLarge {
        /// Size of the stream.
        packed: u64,
        /// What a line carries at most.
        limit: u64,
    },
    /// The CRC-32 of the folder cannot be tested, and nothing else about its stream can.
    NothingToTest {
        /// Why the CRC-32 cannot be tested.
        crc: NoCrc,
        /// What the stream is.
        stream: Untestable,
    },
    /// The data of the folder does not lie inside the file.
    DataOutsideFile,
    /// The header of the archive lies past the end of the file.
    HeaderOutsideFile,
    /// The folders are described in a stream outside the header.
    ExternalFolders,
    /// The header is packed with a coder the tool does not unpack.
    PackedHeaderCoder {
        /// The identifier of the coder, in hex.
        id: String,
    },
    /// The properties of a coder are not ones the coder takes.
    PropertiesInvalid {
        /// The coder, by name or by its identifier in hex.
        coder: String,
    },
    /// The properties of a coder are longer than hashcat stores.
    PropertiesTooLong {
        /// The coder, by name or by its identifier in hex.
        coder: String,
        /// Size of its properties.
        len: usize,
        /// What hashcat stores at most.
        limit: usize,
    },
    /// A stream runs through more coders than hashcat takes.
    TooManyCoders {
        /// How many coders.
        count: usize,
        /// What hashcat takes at most.
        limit: usize,
    },
    /// The `PPMd` model is larger than hashcat gives one.
    PpmdMemory {
        /// Size of the model.
        memory: u32,
        /// What hashcat gives one at most.
        limit: u32,
    },
    /// A coder unpacks to more than hashcat unpacks for a candidate.
    UnpacksTooMuch {
        /// Size of what the coder unpacks to.
        size: u64,
        /// What hashcat unpacks at most.
        limit: u64,
    },
    /// The folder uses BCJ2, and its streams together are longer than a line carries.
    Bcj2TooLarge {
        /// Size of the streams together.
        packed: u64,
        /// What a line carries at most.
        limit: u64,
    },
    /// The lines of the folders that rank before this one fill what is held for one archive.
    LinesOverBudget {
        /// How many bytes of lines are held at most.
        limit: u64,
    },
}

impl NoLine {
    /// The reason of the case.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        match self {
            Self::NoMode(_) | Self::KeySearch | Self::PkwareCipher { .. } | Self::CentralDirectoryEncrypted | Self::RandomDataWrapped | Self::KeyIsPassword => Reason::NoMode,
            Self::Certificate => Reason::NoPassword,
            Self::UnknownScheme => Reason::UnknownScheme,
            Self::TooManyRounds { .. } | Self::RoundsRefused { .. } => Reason::UnsupportedParameters,
            Self::SolidMember | Self::NoSalt | Self::SizeUnknown | Self::JoinedTwice | Self::StreamNotEncryptedLast | Self::EncryptedTwice | Self::EncryptedAfterJoin | Self::SeveralKeys | Self::JoinNotBcj2 | Self::Bcj2OnOneStream => Reason::NotExpressible,
            Self::MethodNumber { .. }
            | Self::LineField { .. }
            | Self::TooLarge { .. }
            | Self::RoundsBelowMode { .. }
            | Self::Packing { .. }
            | Self::UnpacksTooLarge { .. }
            | Self::Coder { .. }
            | Self::Bcj2StreamTooLarge { .. }
            | Self::PropertiesTooLong { .. }
            | Self::TooManyCoders { .. }
            | Self::PpmdMemory { .. }
            | Self::UnpacksTooMuch { .. }
            | Self::Bcj2TooLarge { .. }
            | Self::LinesOverBudget { .. } => Reason::OverLimit,
            Self::Split | Self::HeaderOutsideFile => Reason::Split,
            Self::Empty | Self::ZeroCheckValue | Self::NoChecksum | Self::NoPackedStream => Reason::NoData,
            Self::Unreadable | Self::HeaderFormat { .. } | Self::CheckValueDamaged | Self::CoderProperties | Self::NotWholeBlocks | Self::SizesDisagree | Self::DataOutsideFile | Self::ExternalFolders | Self::PackedHeaderCoder { .. } | Self::PropertiesInvalid { .. } => Reason::Damaged,
            // a CRC-32 that is not there leaves nothing to test; one that is out of reach is a limit
            Self::Bcj2WithoutCrc(crc) | Self::NothingToTest { crc, .. } => match crc {
                NoCrc::NotStored => Reason::NoData,
                NoCrc::TooMuchToUnpack { .. } | NoCrc::TooMuchToCarry { .. } => Reason::OverLimit,
            },
        }
    }
}

impl fmt::Display for NoLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMode(scheme) => write!(f, "no hashcat mode exists for {scheme}"),
            Self::KeySearch => write!(f, "no hashcat mode exists for rar-13: `attack rar-13` searches its key"),
            Self::UnknownScheme => write!(f, "it is encrypted with a scheme the tool does not know"),
            Self::Unreadable => write!(f, "its headers or its data cannot be read"),
            Self::Empty => write!(f, "it is empty, so every password would match"),
            Self::PkwareCipher { cipher: Some(cipher), .. } => write!(f, "it is under strong encryption with {}, which no hashcat mode tests", cipher.label()),
            Self::PkwareCipher { cipher: None, identifier } => write!(f, "it is under strong encryption with algorithm 0x{identifier:04x}, which no hashcat mode tests"),
            Self::CentralDirectoryEncrypted => write!(f, "the central directory is encrypted, which no hashcat mode tests"),
            Self::Certificate => write!(f, "it is encrypted to certificates: no password opens it"),
            Self::MethodNumber { method } => write!(f, "its compression method {method} has more digits than its hashcat mode reads"),
            Self::LineField { field, size, limit } => write!(f, "its {field} has {size} bytes, more than the {limit} its hashcat mode loads"),
            Self::RandomDataWrapped => write!(f, "its random data is wrapped with 3DES, which no hashcat mode unwraps"),
            Self::HeaderFormat { format } => write!(f, "its decryption header names format {format}, and 3 is the one the specification defines"),
            Self::Split => write!(f, "it continues in another volume: a line needs the volume that holds the whole entry"),
            Self::SolidMember => write!(f, "it is a compressed solid member, which cannot be unpacked without the entries before it"),
            Self::TooLarge { packed, limit } => write!(f, "its {packed} bytes of encrypted data exceed the {limit} a line carries, and a cut stream cannot be checked"),
            Self::ZeroCheckValue => write!(f, "it is a service record whose check value is zero, so every password would match"),
            Self::CheckValueDamaged => write!(f, "the checksum of its check value is wrong"),
            Self::NoSalt => write!(f, "its key is derived without a salt, and a line has no way to say that"),
            Self::SizeUnknown => write!(f, "the size it unpacks to is not stored, and a line has no way to say that"),
            Self::NoChecksum => write!(f, "it stores no checksum of its data and no check value, so no password could be confirmed"),
            Self::RoundsRefused { power } => write!(f, "its key derivation asks for 2^{power} rounds, which RAR itself refuses"),
            Self::RoundsBelowMode { power } => write!(f, "its key derivation asks for 2^{power} rounds, fewer than its hashcat mode loads"),
            Self::Packing { name } => write!(f, "it is packed with {name}, which hashcat does not unpack"),
            Self::UnpacksTooLarge { size, limit } => write!(f, "it unpacks to {size} bytes, more than the {limit} its hashcat mode takes"),
            Self::CoderProperties => write!(f, "the properties of its AES coder are missing or cut short"),
            Self::JoinedTwice => write!(f, "it joins streams more than once"),
            Self::StreamNotEncryptedLast => write!(f, "one of its streams is not encrypted, or is encrypted before it is packed"),
            Self::EncryptedTwice => write!(f, "it is encrypted twice"),
            Self::EncryptedAfterJoin => write!(f, "it is encrypted after its streams are joined"),
            Self::NoPackedStream => write!(f, "it has no packed stream"),
            Self::SeveralKeys => write!(f, "its streams do not share one key"),
            Self::KeyIsPassword => write!(f, "its key is the password itself, with no key derivation, which 7-Zip reads and never writes and hashcat does not test"),
            Self::TooManyRounds { power } => write!(f, "its key derivation asks for 2^{power} rounds, which 7-Zip itself refuses"),
            Self::NotWholeBlocks => write!(f, "an encrypted stream is not a whole number of cipher blocks"),
            Self::SizesDisagree => write!(f, "the sizes of an encrypted stream do not fit each other"),
            Self::Coder { id } => write!(f, "it uses the coder {id}, which hashcat cannot unpack"),
            Self::JoinNotBcj2 => write!(f, "it joins streams with a coder other than BCJ2"),
            Self::Bcj2OnOneStream => write!(f, "it uses BCJ2 on a single stream"),
            Self::Bcj2WithoutCrc(crc) => write!(f, "it uses BCJ2 and {crc}"),
            Self::Bcj2StreamTooLarge { packed, limit } => write!(f, "it uses BCJ2 and one of its streams has {packed} bytes, more than the {limit} a line carries"),
            Self::NothingToTest { crc, stream: Untestable::Stored } => write!(f, "{crc}, and stored data says nothing about the key by itself"),
            Self::NothingToTest { crc, stream: Untestable::SilentStart { coder } } => write!(f, "{crc}, and the start of {coder} data says nothing about the key"),
            Self::NothingToTest { crc, stream: Untestable::ShortStart { coder, packed } } => write!(f, "{crc}, and its {packed} bytes of {coder} data are too few to say anything about the key by their start"),
            Self::DataOutsideFile => write!(f, "its data does not lie inside the file"),
            Self::HeaderOutsideFile => write!(f, "the header of the archive lies past the end of this file: a volume of a split archive, or a file that is cut short"),
            Self::ExternalFolders => write!(f, "the folders of the archive are described in a stream outside its header, which the tool does not unpack"),
            Self::PackedHeaderCoder { id } => write!(f, "the header of the archive is packed with the coder {id}, which the tool does not unpack"),
            Self::PropertiesInvalid { coder } => write!(f, "the properties of its {coder} coder are not ones the coder takes"),
            Self::PropertiesTooLong { coder, len, limit } => write!(f, "the properties of its {coder} coder take {len} bytes, more than the {limit} hashcat stores"),
            Self::TooManyCoders { count, limit } => write!(f, "one of its streams runs through {count} coders, more than the {limit} hashcat takes"),
            Self::PpmdMemory { memory, limit } => write!(f, "its PPMd model takes {memory} bytes, more than the {limit} hashcat gives one"),
            Self::UnpacksTooMuch { size, limit } => write!(f, "one of its coders unpacks to {size} bytes, more than the {limit} hashcat unpacks for a candidate"),
            Self::Bcj2TooLarge { packed, limit } => write!(f, "it uses BCJ2 and its streams have {packed} bytes together, more than the {limit} a line carries"),
            Self::LinesOverBudget { limit } => write!(f, "the lines of the folders that rank before it fill the {limit} bytes that are held for one archive"),
        }
    }
}

/// A scheme or an entry that gets no line, and why. In the JSON object it is `entry` when it
/// is about one entry and `scheme` when it is not, then `reason` and `text`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Missing {
    /// The scheme that gets no line.
    pub scheme: Scheme,
    /// The entry that gets none, by its place in the list of entries. `None` when the scheme
    /// as a whole gets no line, or the headers it encrypts give none.
    pub entry: Option<usize>,
    /// Why.
    pub why: NoLine,
}

impl Missing {
    /// A scheme that gets no line.
    #[must_use]
    pub const fn for_scheme(scheme: Scheme, why: NoLine) -> Self {
        Self { scheme, entry: None, why }
    }

    /// An entry under `scheme` that gets no line.
    #[must_use]
    pub const fn for_entry(scheme: Scheme, index: usize, why: NoLine) -> Self {
        Self { scheme, entry: Some(index), why }
    }

    /// The reason.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.why.reason()
    }
}

impl Serialize for Missing {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        match self.entry {
            Some(index) => map.serialize_entry("entry", &index)?,
            None => map.serialize_entry("scheme", &self.scheme)?,
        }
        map.serialize_entry("reason", &self.reason())?;
        map.serialize_entry("text", &self.why.to_string())?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One case of every variant.
    fn cases() -> Vec<NoLine> {
        let crc = NoCrc::TooMuchToCarry { need: 5_000_000, limit: 4_194_304 };
        vec![
            NoLine::NoMode(Scheme::Rar13),
            NoLine::KeySearch,
            NoLine::UnknownScheme,
            NoLine::Unreadable,
            NoLine::Empty,
            NoLine::PkwareCipher { cipher: Some(Cipher::Blowfish), identifier: 0x6720 },
            NoLine::PkwareCipher { cipher: None, identifier: 0xFFFF },
            NoLine::CentralDirectoryEncrypted,
            NoLine::Certificate,
            NoLine::MethodNumber { method: 1000 },
            NoLine::HeaderFormat { format: 4 },
            NoLine::LineField { field: "random data", size: 8192, limit: 4096 },
            NoLine::RandomDataWrapped,
            NoLine::Split,
            NoLine::SolidMember,
            NoLine::TooLarge { packed: 5_000_000, limit: 4_194_304 },
            NoLine::ZeroCheckValue,
            NoLine::CheckValueDamaged,
            NoLine::NoSalt,
            NoLine::SizeUnknown,
            NoLine::NoChecksum,
            NoLine::RoundsRefused { power: 25 },
            NoLine::RoundsBelowMode { power: 0 },
            NoLine::Packing { name: "method 0x36".to_owned() },
            NoLine::UnpacksTooLarge { size: 1 << 32, limit: 0xFFFF_FFFF },
            NoLine::CoderProperties,
            NoLine::JoinedTwice,
            NoLine::StreamNotEncryptedLast,
            NoLine::EncryptedTwice,
            NoLine::EncryptedAfterJoin,
            NoLine::NoPackedStream,
            NoLine::SeveralKeys,
            NoLine::KeyIsPassword,
            NoLine::TooManyRounds { power: 30 },
            NoLine::NotWholeBlocks,
            NoLine::SizesDisagree,
            NoLine::Coder { id: "04f71104".to_owned() },
            NoLine::JoinNotBcj2,
            NoLine::Bcj2OnOneStream,
            NoLine::Bcj2WithoutCrc(NoCrc::NotStored),
            NoLine::Bcj2WithoutCrc(crc),
            NoLine::Bcj2StreamTooLarge { packed: 5_000_000, limit: 4_194_304 },
            NoLine::NothingToTest { crc: NoCrc::NotStored, stream: Untestable::Stored },
            NoLine::NothingToTest { crc, stream: Untestable::SilentStart { coder: "PPMd".to_owned() } },
            NoLine::NothingToTest { crc, stream: Untestable::ShortStart { coder: "LZMA2".to_owned(), packed: 4096 } },
            NoLine::DataOutsideFile,
            NoLine::HeaderOutsideFile,
            NoLine::ExternalFolders,
            NoLine::PackedHeaderCoder { id: "030401".to_owned() },
            NoLine::PropertiesInvalid { coder: "LZMA".to_owned() },
            NoLine::PropertiesTooLong { coder: "LZMA".to_owned(), len: 17, limit: 16 },
            NoLine::TooManyCoders { count: 9, limit: 8 },
            NoLine::PpmdMemory { memory: 0xC000_0000, limit: 1 << 28 },
            NoLine::UnpacksTooMuch { size: 1 << 30, limit: 1 << 26 },
            NoLine::Bcj2TooLarge { packed: 9_000_000, limit: 0x7F_F000 },
            NoLine::LinesOverBudget { limit: 1 << 28 },
        ]
    }

    #[test]
    fn the_reasons_are_the_nine_of_the_specification() {
        let codes: Vec<&str> = Reason::ALL.iter().map(|reason| reason.as_str()).collect();
        assert_eq!(codes, ["no-mode", "no-password", "unknown-scheme", "unsupported-parameters", "not-expressible", "over-limit", "split", "no-data", "damaged"]);
        for reason in Reason::ALL {
            assert_eq!(serde_json::to_value(reason).unwrap(), reason.as_str());
            assert_eq!(reason.to_string(), reason.as_str());
        }
    }

    #[test]
    fn every_reason_has_a_case_and_every_case_one_sentence() {
        let cases = cases();
        for reason in Reason::ALL {
            assert!(cases.iter().any(|case| case.reason() == reason), "no case gives {reason}");
        }
        for case in &cases {
            let text = case.to_string();
            assert!(!text.is_empty() && !text.contains('\n') && !text.ends_with('.'), "{case:?}: {text:?}");
            assert!(text.chars().next().is_some_and(char::is_lowercase), "a sentence that follows a name: {text:?}");
        }
        // two cases never share a sentence
        let mut texts: Vec<String> = cases.iter().map(ToString::to_string).collect();
        texts.sort();
        texts.dedup();
        assert_eq!(texts.len(), cases.len());
    }

    #[test]
    fn a_case_has_the_reason_the_specification_gives_it() {
        assert_eq!(NoLine::NoMode(Scheme::Rar13).reason(), Reason::NoMode);
        assert_eq!(NoLine::PkwareCipher { cipher: Some(Cipher::Rc4), identifier: 0x6801 }.reason(), Reason::NoMode);
        assert_eq!(NoLine::CentralDirectoryEncrypted.reason(), Reason::NoMode);
        assert_eq!(NoLine::RandomDataWrapped.reason(), Reason::NoMode);
        assert_eq!(NoLine::MethodNumber { method: 1000 }.reason(), Reason::OverLimit);
        assert_eq!(NoLine::LineField { field: "validation data", size: 2048, limit: 1024 }.reason(), Reason::OverLimit);
        assert_eq!(NoLine::KeyIsPassword.reason(), Reason::NoMode);
        assert_eq!(NoLine::Certificate.reason(), Reason::NoPassword);
        assert_eq!(NoLine::UnknownScheme.reason(), Reason::UnknownScheme);
        assert_eq!(NoLine::TooManyRounds { power: 25 }.reason(), Reason::UnsupportedParameters);
        assert_eq!(NoLine::StreamNotEncryptedLast.reason(), Reason::NotExpressible);
        assert_eq!(NoLine::SolidMember.reason(), Reason::NotExpressible);
        assert_eq!(NoLine::TooLarge { packed: 1, limit: 0 }.reason(), Reason::OverLimit);
        assert_eq!(NoLine::Split.reason(), Reason::Split);
        assert_eq!(NoLine::Empty.reason(), Reason::NoData);
        assert_eq!(NoLine::Unreadable.reason(), Reason::Damaged);

        // a folder whose CRC-32 is not there has nothing to test; one whose CRC-32 is out of
        // reach runs into a limit
        let stream = Untestable::Stored;
        assert_eq!(NoLine::NothingToTest { crc: NoCrc::NotStored, stream: stream.clone() }.reason(), Reason::NoData);
        assert_eq!(NoLine::NothingToTest { crc: NoCrc::TooMuchToUnpack { size: 1 << 30, limit: 1 << 26 }, stream }.reason(), Reason::OverLimit);
        assert_eq!(NoLine::Bcj2WithoutCrc(NoCrc::NotStored).reason(), Reason::NoData);
    }

    #[test]
    fn a_missing_line_names_a_scheme_or_an_entry() {
        let scheme = Missing::for_scheme(Scheme::Rar13, NoLine::NoMode(Scheme::Rar13));
        assert_eq!(serde_json::to_value(&scheme).unwrap(), serde_json::json!({ "scheme": "rar-13", "reason": "no-mode", "text": "no hashcat mode exists for rar-13" }));
        assert_eq!(serde_json::to_value(Missing::for_scheme(Scheme::Rar13, NoLine::KeySearch)).unwrap()["text"], "no hashcat mode exists for rar-13: `attack rar-13` searches its key");

        let entry = Missing::for_entry(Scheme::ZipPkware, 4, NoLine::Certificate);
        assert_eq!(serde_json::to_value(&entry).unwrap(), serde_json::json!({ "entry": 4, "reason": "no-password", "text": "it is encrypted to certificates: no password opens it" }));
        assert_eq!(entry.reason(), Reason::NoPassword);
    }
}
