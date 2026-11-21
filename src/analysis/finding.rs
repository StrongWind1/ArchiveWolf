//! Findings: what a user should know about an archive beyond scheme and coverage.
//!
//! Each finding has a fixed code, the entries it concerns and a sentence (specification,
//! section 6.4). [`Found`] is the list of them, with the numbers a sentence needs, and nothing
//! outside this file writes such a sentence.
//!

use std::fmt;

use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap as _;

use super::reason::NoLine;
use super::scheme::Scheme;

/// What was found. [`Found::code`] is its code and [`fmt::Display`] its sentence, without the
/// names of the entries.
///
/// A format that finds something new adds a variant here, with its code and its sentence.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Found {
    /// Entries are marked encrypted and are not.
    PseudoEncryption,
    /// More than one scheme in one archive.
    MixedSchemes(Vec<Scheme>),
    /// Some entries are encrypted and some are not.
    Partial {
        /// How many entries are encrypted.
        encrypted: usize,
        /// How many entries hold data and are not.
        plain: usize,
    },
    /// A scheme that falls without the password.
    WeakScheme(Scheme),
    /// `rar-13`, which falls without the password, in a container `attack rar-13` does not
    /// read: the command takes archives of RAR 1.3 and 1.4 and no other.
    WeakSchemeOutOfReach,
    /// Entries are encrypted to certificates: no password opens them.
    Certificate,
    /// An encryption identifier the tool does not know.
    UnknownScheme {
        /// The identifier as the archive stores it, when it is one number.
        identifier: Option<u64>,
    },
    /// A known scheme with parameters outside what its own software accepts.
    UnsupportedParameters(NoLine),
    /// An encrypted entry continues in another volume.
    SplitEntry,
    /// The file ends before the archive does.
    Incomplete,
    /// The headers stop before the file does, at bytes that are no header: what lies behind
    /// them is not listed.
    HeadersBroken {
        /// Where in the file the headers stop.
        at: u64,
        /// How many bytes follow there.
        left: u64,
    },
    /// A header fails its checksum: what it says of its entry may be wrong.
    HeaderChecksum {
        /// Where in the file the header starts.
        at: u64,
    },
    /// RAR 5: a stored check value fails its own checksum and does not count.
    CheckValueDamaged,
    /// The best line the archive allows is weak: it tests check bytes, a verifier or a checksum
    /// over fewer than four bytes, and no data beyond them.
    WeakCheck {
        /// How many bits it tests.
        bits: u32,
    },
    /// ZIP: entries are marked as encrypted with ZipCrypto, and the proof of pseudo-encryption
    /// was not run on them: they are too large for it, or of a method it does not unpack.
    ProofNotRun,
    /// `zip-crypto`: the archive itself gives away eight bytes or more in a row of what was
    /// encrypted, which is what the known-plaintext attack starts from.
    KnownPlaintext {
        /// The longest run among the entries, in bytes.
        longest: u64,
    },
    /// `zip-crypto`: the encryption headers were filled in a way that gives something away.
    WeakHeader(WeakHeader),
}

/// How the encryption headers of a `zip-crypto` archive are weak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeakHeader {
    /// Every header starts with the same ten bytes, the first of them `F8`: `yeka/zip`, which
    /// encrypts a constant. The bytes depend on the password alone.
    Constant,
    /// Some headers are equal in their first eleven bytes: a generator that was seeded with a
    /// clock.
    Repeated,
    /// The headers of the Info-ZIP family, in an archive with entries enough for the keys to
    /// follow from them.
    InfoZip,
    /// The headers of SharpZipLib or DotNetZip, in an archive with entries enough for their
    /// generator to be found when it can be.
    EncryptedOnce,
}

impl Found {
    /// The codes of every finding there is, in the order of the specification.
    pub const CODES: [&'static str; 14] = ["pseudo-encryption", "mixed-schemes", "partial", "weak-scheme", "certificate", "unknown-scheme", "unsupported-parameters", "split-entry", "incomplete", "damaged", "weak-check", "proof-not-run", "known-plaintext", "weak-header"];

    /// The code of the finding.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PseudoEncryption => "pseudo-encryption",
            Self::MixedSchemes(_) => "mixed-schemes",
            Self::Partial { .. } => "partial",
            Self::WeakScheme(_) | Self::WeakSchemeOutOfReach => "weak-scheme",
            Self::Certificate => "certificate",
            Self::UnknownScheme { .. } => "unknown-scheme",
            Self::UnsupportedParameters(_) => "unsupported-parameters",
            Self::SplitEntry => "split-entry",
            Self::Incomplete => "incomplete",
            Self::HeadersBroken { .. } | Self::HeaderChecksum { .. } | Self::CheckValueDamaged => "damaged",
            Self::WeakCheck { .. } => "weak-check",
            Self::ProofNotRun => "proof-not-run",
            Self::KnownPlaintext { .. } => "known-plaintext",
            Self::WeakHeader(_) => "weak-header",
        }
    }
}

impl fmt::Display for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PseudoEncryption => write!(f, "marked encrypted and not encrypted: the data as it stands unpacks to the stored CRC-32"),
            Self::MixedSchemes(schemes) => {
                let names: Vec<&str> = schemes.iter().map(|scheme| scheme.as_str()).collect();
                write!(f, "more than one scheme in one archive: {}", names.join(", "))
            },
            Self::Partial { encrypted, plain } => {
                let locked = if *encrypted == 1 { "1 entry is encrypted".to_owned() } else { format!("{encrypted} entries are encrypted") };
                let open = if *plain == 1 { "1 that holds data is not".to_owned() } else { format!("{plain} that hold data are not") };
                write!(f, "{locked}, and {open}")
            },
            Self::WeakScheme(Scheme::ZipCrypto) => write!(f, "zip-crypto falls without the password to 12 bytes of known plaintext"),
            Self::WeakScheme(Scheme::Rar13) => write!(f, "rar-13 falls without the password: `attack rar-13` searches its 2^23 keys"),
            Self::WeakScheme(scheme) => write!(f, "{scheme} falls without the password"),
            Self::WeakSchemeOutOfReach => write!(f, "rar-13 falls without the password to a search of its 2^23 keys; `attack rar-13` reads archives of RAR 1.3 and 1.4 only, and this is a later container"),
            Self::Certificate => write!(f, "encrypted to certificates: no password opens it"),
            Self::UnknownScheme { identifier: Some(identifier) } => write!(f, "encrypted with a scheme the tool does not know, identifier 0x{identifier:x}"),
            Self::UnknownScheme { identifier: None } => write!(f, "encrypted with a scheme the tool does not know"),
            Self::UnsupportedParameters(case) => write!(f, "parameters its own software refuses: {case}"),
            Self::SplitEntry => write!(f, "encrypted, and continues in another volume"),
            Self::Incomplete => write!(f, "the file ends before the archive does"),
            Self::HeadersBroken { at, left } => write!(f, "the headers stop at offset {at}, where {left} bytes follow that are no header: what lies behind them is not listed"),
            Self::HeaderChecksum { at } => write!(f, "the header at offset {at} fails its checksum: what it says of its entry may be wrong"),
            Self::CheckValueDamaged => write!(f, "the stored check value fails its own checksum and does not count: the line tests what the password decrypts in its place"),
            Self::WeakCheck { bits } => write!(f, "the best line is weak, it tests {bits} bits and no data beyond them: a password found with it has to be confirmed by opening the archive"),
            Self::ProofNotRun => write!(f, "marked encrypted, and the proof of pseudo-encryption was not run: it unpacks stored and Deflate data within its limits only"),
            Self::KnownPlaintext { longest } => write!(f, "the archive itself gives away what was encrypted, up to {longest} bytes in a row: `attack zip-crypto --plan` says what a search for the keys costs"),
            Self::WeakHeader(WeakHeader::Constant) => write!(f, "the encryption headers start with the same ten bytes, as `yeka/zip` writes them: they depend on the password alone, and `attack zip-crypto` holds every key against them"),
            Self::WeakHeader(WeakHeader::Repeated) => write!(f, "encryption headers that are equal in their first eleven bytes: their generator was seeded with a clock"),
            Self::WeakHeader(WeakHeader::InfoZip) => write!(f, "the encryption headers are those of the Info-ZIP family, which may give the keys with no known file: `attack zip-crypto` finds out"),
            Self::WeakHeader(WeakHeader::EncryptedOnce) => write!(f, "the encryption headers are those of a .NET library whose generator can be predicted on some runtimes, which gives the keys with no known file: `attack zip-crypto` finds out"),
        }
    }
}

/// One finding: what was found, and the entries it concerns by their place in the list of
/// entries. In the JSON object it is `code`, `entries` and `text`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Finding {
    /// What was found.
    pub found: Found,
    /// The entries it concerns. Empty for a finding about the archive as a whole.
    pub entries: Vec<usize>,
}

impl Finding {
    /// A finding about some entries.
    #[must_use]
    pub const fn new(found: Found, entries: Vec<usize>) -> Self {
        Self { found, entries }
    }

    /// The code of the finding.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.found.code()
    }
}

impl Serialize for Finding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("code", self.code())?;
        map.serialize_entry("entries", &self.entries)?;
        map.serialize_entry("text", &self.found.to_string())?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One finding of every kind.
    fn all() -> Vec<Found> {
        vec![
            Found::PseudoEncryption,
            Found::MixedSchemes(vec![Scheme::ZipCrypto, Scheme::ZipWinzip]),
            Found::Partial { encrypted: 4, plain: 2 },
            Found::WeakScheme(Scheme::ZipCrypto),
            Found::Certificate,
            Found::UnknownScheme { identifier: Some(0x6699) },
            Found::UnsupportedParameters(NoLine::TooManyRounds { power: 30 }),
            Found::SplitEntry,
            Found::Incomplete,
            Found::HeadersBroken { at: 20, left: 900 },
            Found::WeakCheck { bits: 8 },
            Found::ProofNotRun,
            Found::KnownPlaintext { longest: 19 },
            Found::WeakHeader(WeakHeader::InfoZip),
        ]
    }

    #[test]
    fn the_codes_are_those_of_the_specification() {
        let codes: Vec<&str> = all().iter().map(Found::code).collect();
        assert_eq!(codes, Found::CODES);
        assert_eq!(codes, ["pseudo-encryption", "mixed-schemes", "partial", "weak-scheme", "certificate", "unknown-scheme", "unsupported-parameters", "split-entry", "incomplete", "damaged", "weak-check", "proof-not-run", "known-plaintext", "weak-header"]);
        assert_eq!(Found::HeaderChecksum { at: 20 }.code(), "damaged");
    }

    #[test]
    fn every_finding_has_one_sentence() {
        for found in all().into_iter().chain([
            Found::WeakScheme(Scheme::Rar13),
            Found::WeakSchemeOutOfReach,
            Found::WeakScheme(Scheme::Rar15),
            Found::UnknownScheme { identifier: None },
            Found::HeaderChecksum { at: 20 },
            Found::CheckValueDamaged,
            Found::WeakHeader(WeakHeader::Constant),
            Found::WeakHeader(WeakHeader::Repeated),
            Found::WeakHeader(WeakHeader::EncryptedOnce),
        ]) {
            let text = found.to_string();
            assert!(!text.is_empty() && !text.contains('\n') && !text.ends_with('.'), "{found:?}: {text:?}");
        }
        assert_eq!(Found::MixedSchemes(vec![Scheme::ZipCrypto, Scheme::ZipWinzip]).to_string(), "more than one scheme in one archive: zip-crypto, zip-winzip");
        assert_eq!(Found::UnsupportedParameters(NoLine::TooManyRounds { power: 30 }).to_string(), "parameters its own software refuses: its key derivation asks for 2^30 rounds, which 7-Zip itself refuses");
        assert!(Found::WeakScheme(Scheme::Rar13).to_string().contains("`attack rar-13` searches"), "`info` says when an attack applies");
        assert_eq!(Found::WeakSchemeOutOfReach.code(), "weak-scheme");
        assert!(Found::WeakSchemeOutOfReach.to_string().contains("RAR 1.3 and 1.4 only"), "and when the command does not read the archive");
    }

    #[test]
    fn a_finding_is_its_code_its_entries_and_its_sentence() {
        let finding = Finding::new(Found::PseudoEncryption, vec![1, 4]);
        assert_eq!(finding.code(), "pseudo-encryption");
        assert_eq!(serde_json::to_value(&finding).unwrap(), serde_json::json!({ "code": "pseudo-encryption", "entries": [1, 4], "text": "marked encrypted and not encrypted: the data as it stands unpacks to the stored CRC-32" }));

        let whole = Finding::new(Found::Incomplete, Vec::new());
        assert_eq!(serde_json::to_value(&whole).unwrap()["entries"], serde_json::json!([]));
    }
}
