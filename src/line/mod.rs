//! Hash lines: the tags there are, the hashcat mode that loads each, and what a line proves.
//!
//! A [`Line`] is what a format builds for one entry, or for the encrypted headers of an
//! archive. `hash` writes its text, and `info` names it by tag and mode. Both are fed from the
//! same list, so `info` cannot name a line that `hash` would not write.
//!
//! Nothing here builds the text of a line: that is the work of each format.

use std::fmt;

use serde::Serialize;
use serde::Serializer;

/// Which lines a format is asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lines {
    /// One line for each scheme in the archive, from the entry that ranks best. What `hash`
    /// writes by default and what `info` names.
    Best,
    /// A line for every encrypted entry or folder: `hash --all`.
    All,
}

/// The tag of a hash line: what it starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tag {
    /// `$zip$1$`: ZipCrypto.
    Zip1,
    /// `$zip$2$`: WinZip AES.
    Zip2,
    /// `$zip$3$`: PKWARE strong encryption with AES.
    Zip3,
    /// `$zip$4$`: the three keys of ZipCrypto.
    Zip4,
    /// `$rar$15$`: RAR 1.5.
    Rar15,
    /// `$rar$20$`: RAR 2.0.
    Rar20,
    /// `$rar$30$`: RAR 3 and 4.
    Rar30,
    /// `$rar$50$`: RAR 5 and 7.
    Rar50,
    /// `$7z$*`: 7-Zip.
    SevenZ,
}

impl Tag {
    /// Every tag.
    pub const ALL: [Self; 9] = [Self::Zip1, Self::Zip2, Self::Zip3, Self::Zip4, Self::Rar15, Self::Rar20, Self::Rar30, Self::Rar50, Self::SevenZ];

    /// Whether `hash` writes lines with this tag. `$zip$4$` holds the keys the known-plaintext
    /// attack recovers, and no command writes it yet.
    #[must_use]
    pub const fn written_by_hash(self) -> bool {
        !matches!(self, Self::Zip4)
    }

    /// The tag as text: what a line of it starts with.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zip1 => "$zip$1$",
            Self::Zip2 => "$zip$2$",
            Self::Zip3 => "$zip$3$",
            Self::Zip4 => "$zip$4$",
            Self::Rar15 => "$rar$15$",
            Self::Rar20 => "$rar$20$",
            Self::Rar30 => "$rar$30$",
            Self::Rar50 => "$rar$50$",
            Self::SevenZ => "$7z$*",
        }
    }

    /// The hashcat modes that load lines with this tag. Most tags have one. `$zip$3$` has one
    /// for each AES key size and `$zip$4$` one for each of its two forms: [`Tag::of`] says which
    /// of them loads a given line.
    #[must_use]
    pub const fn modes(self) -> &'static [u32] {
        match self {
            Self::Zip1 => &[46100],
            Self::Zip2 => &[46200],
            Self::Zip3 => &[46300, 46310, 46320],
            Self::Zip4 => &[46400, 46410],
            Self::Rar15 => &[46500],
            Self::Rar20 => &[46600],
            Self::Rar30 => &[46700],
            Self::Rar50 => &[46800],
            Self::SevenZ => &[46900],
        }
    }

    /// The tag of a line and the hashcat mode that loads it, from the text of the line.
    /// `None` for text that starts like no line.
    #[must_use]
    pub fn of(text: &str) -> Option<(Self, u32)> {
        let tag = Self::ALL.into_iter().find(|tag| text.starts_with(tag.as_str()))?;
        let mode = match tag {
            Self::Zip1 => 46100,
            Self::Zip2 => 46200,
            // one mode for each AES key size, which is the second field
            Self::Zip3 => match text.split('*').nth(2) {
                Some("192") => 46310,
                Some("256") => 46320,
                _ => 46300,
            },
            // the first field says which of the two forms the line has
            Self::Zip4 if text.starts_with("$zip$4$*1*") => 46410,
            Self::Zip4 => 46400,
            Self::Rar15 => 46500,
            Self::Rar20 => 46600,
            Self::Rar30 => 46700,
            Self::Rar50 => 46800,
            Self::SevenZ => 46900,
        };
        Some((tag, mode))
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Tag {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// What a line lets a cracker confirm a password by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proves {
    /// A checksum of the unpacked data, an authentication code over the data, or a 64-bit
    /// check value.
    Exact,
    /// The stream unpacking to its size without error, or the decrypted bytes parsing as a
    /// header.
    Structural,
    /// Check bytes, a verifier or a checksum over less than four bytes: `bits` bits in all. A
    /// password found with such a line has to be confirmed by opening the archive.
    Weak {
        /// How many bits a wrong password has to match.
        bits: u32,
    },
}

impl Proves {
    /// The name of the class: `exact`, `structural` or `weak`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Structural => "structural",
            Self::Weak { .. } => "weak",
        }
    }
}

impl fmt::Display for Proves {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Proves {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Why the CRC-32 of a 7-Zip folder is not what its line tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoCrc {
    /// The archive stores no CRC-32 for the folder.
    NotStored,
    /// The first file of the folder unpacks to `size` bytes, more than the `limit` hashcat
    /// unpacks for a candidate.
    TooMuchToUnpack {
        /// Size of the first file.
        size: u64,
        /// What hashcat unpacks at most.
        limit: u64,
    },
    /// Testing the CRC-32 takes `need` bytes of the stream, more than the `limit` a line carries.
    TooMuchToCarry {
        /// Bytes of the stream the test needs.
        need: u64,
        /// What a line carries at most.
        limit: u64,
    },
}

impl fmt::Display for NoCrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStored => write!(f, "the archive stores no CRC-32 for it"),
            Self::TooMuchToUnpack { size, limit } => write!(f, "its first file unpacks to {size} bytes, more than the {limit} hashcat unpacks for a candidate"),
            Self::TooMuchToCarry { need, limit } => write!(f, "testing its CRC-32 takes {need} bytes of it, more than the {limit} a line carries"),
        }
    }
}

/// A remark on what a line tests when that is less than a checksum over the whole entry: the
/// reason, with the numbers it rests on. Each has one sentence, which [`fmt::Display`] gives
/// without the name of the entry.
///
/// A format that finds a new reason adds a variant here, in the part of its format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Note {
    // --- ZIP ---
    /// `$zip$1$`: the entry is empty, so the line tests the check bytes of its headers and
    /// nothing else.
    EmptyEntry {
        /// How many headers the line carries.
        checks: usize,
    },
    /// `$zip$1$`: the entry is stored and longer than a line carries, and a CRC-32 needs all of
    /// it, so the line tests the check bytes of its headers and nothing else.
    StoredTooLarge {
        /// Size of the stored data.
        stored: u64,
        /// What a line carries at most.
        limit: u64,
        /// How many headers the line carries.
        checks: usize,
    },
    /// `$zip$1$`: hashcat has no decoder for the compression method of the entry, so the line
    /// tests the check bytes of its headers and nothing else.
    NoDecoder {
        /// The compression method.
        method: u16,
        /// How many headers the line carries.
        checks: usize,
    },
    /// `$zip$1$`: the entry is stored and shorter than four bytes, so its CRC-32 proves no more
    /// than the bytes themselves.
    ShortStored {
        /// Size of the stored data.
        stored: u64,
        /// How many headers the line carries.
        checks: usize,
    },
    /// `$zip$1$`: the entry is stored and the line carries no other header, so a password is
    /// confirmed by the CRC-32 and one check byte: 40 bits.
    StoredAlone,
    /// `$zip$2$`: the data is longer than a line carries and its method cannot be tested from
    /// its start, so the line tests the 16-bit verifier alone.
    VerifierOnly {
        /// Size of the encrypted data.
        packed: u64,
        /// What a line carries at most.
        limit: u64,
        /// The compression method.
        method: u16,
    },
    // --- RAR ---
    /// A line on the data of an entry that unpacks to fewer than four bytes: its checksum
    /// proves no more than those bytes.
    ShortEntry {
        /// Size of the unpacked data.
        size: u64,
    },
    /// `$rar$30$` from encrypted headers: the archive is a volume with the short end block of
    /// RAR 3.00, which holds what the line tests only in the last volume of a set.
    VolumeEndBlock,
    /// `$rar$30$` from encrypted headers: bytes follow what is taken for the end block.
    BehindEndBlock {
        /// How many.
        count: u64,
    },
    // --- 7-Zip ---
    /// `$7z$*`: the line tests that the stream unpacks to its size and ends there.
    StreamEnd(NoCrc),
    /// `$7z$*`: the line tests that the start of the stream unpacks without an error.
    StreamStart(NoCrc),
    /// `$7z$*`: the CRC-32 of the line covers fewer than four bytes, so it proves no more than
    /// the bytes themselves.
    ShortCrc {
        /// How many bytes the CRC-32 covers.
        size: u64,
    },
}

/// `1 header` or `N headers`.
fn headers(count: usize) -> String {
    format!("{count} header{}", if count == 1 { "" } else { "s" })
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyEntry { checks } => write!(f, "it is empty, so the line tests only the check bytes of {}", headers(*checks)),
            Self::StoredTooLarge { stored, limit, checks } => write!(f, "its {stored} stored bytes exceed the {limit} a line carries, and a CRC-32 needs all of them, so the line tests only the check bytes of {}", headers(*checks)),
            Self::NoDecoder { method, checks } => write!(f, "hashcat has no decoder for compression method {method}, so the line tests only the check bytes of {}", headers(*checks)),
            Self::ShortStored { stored, checks } => {
                write!(f, "it holds {stored} stored byte{}, and a CRC-32 over fewer than 4 bytes proves no more than the bytes themselves, so the line tests them and the check bytes of {}", if *stored == 1 { "" } else { "s" }, headers(*checks))
            },
            Self::StoredAlone => write!(f, "it is stored and the line carries no other header to test against, so a password is confirmed by 40 bits: very long runs can hit a false match"),
            Self::VerifierOnly { packed, limit, method } => write!(f, "its {packed} bytes exceed the {limit} a line carries and compression method {method} cannot be tested from its start, so the line tests only the 16-bit verifier"),
            Self::ShortEntry { size } => write!(f, "it unpacks to {size} byte{}, and a checksum over fewer than 4 bytes proves no more than the bytes themselves", if *size == 1 { "" } else { "s" }),
            Self::VolumeEndBlock => write!(f, "the archive is a volume with the short end block of RAR 3.00, so the line confirms a password only when this is the last volume of its set"),
            Self::BehindEndBlock { count } => write!(f, "{count} byte{} follow what is taken for the end of the archive, so the line confirms a password only when the archive is whole and they were appended to it", if *count == 1 { "" } else { "s" }),
            Self::StreamEnd(why) => write!(f, "{why}, so the line tests that the stream unpacks to its size and ends there"),
            Self::StreamStart(why) => write!(f, "{why}, so the line tests that the start of the stream unpacks without an error"),
            Self::ShortCrc { size } => write!(f, "its CRC-32 covers {size} byte{}, and a CRC-32 over fewer than 4 bytes proves no more than the bytes themselves", if *size == 1 { "" } else { "s" }),
        }
    }
}

/// One hash line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The tag of the line.
    pub tag: Tag,
    /// The hashcat mode that loads it.
    pub mode: u32,
    /// The entry the line was built from, as its place in the list of entries of the archive.
    /// `None` for a line built from the encrypted headers.
    pub entry: Option<usize>,
    /// What the line lets a cracker confirm a password by.
    pub proves: Proves,
    /// Why that is less than a checksum over the whole entry, when it is and a reason is known.
    pub note: Option<Note>,
    /// The line as `hash` writes it.
    pub text: String,
}

impl Line {
    /// A line with its tag and its mode, which the text says.
    ///
    /// An error for text that starts like no line: a format that built it has a defect.
    pub fn new(text: String, entry: Option<usize>, proves: Proves) -> anyhow::Result<Self> {
        let Some((tag, mode)) = Tag::of(&text) else {
            anyhow::bail!("a hash line of no known type was built: {}", text.chars().take(16).collect::<String>());
        };
        Ok(Self { tag, mode, entry, proves, note: None, text })
    }

    /// The same line with a remark on what it tests.
    #[must_use]
    pub const fn with_note(mut self, note: Note) -> Self {
        self.note = Some(note);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_type_has_its_mode() {
        for (text, tag, mode) in [
            ("$zip$1$*1*00/aa*8*cefd04dc*1c*1c*00$/zip$", Tag::Zip1, 46100),
            ("$zip$2$*1*1*0*00*0000*0*00*00$/zip$", Tag::Zip2, 46200),
            ("$zip$3$*660e*128*1*00$/zip$", Tag::Zip3, 46300),
            ("$zip$3$*660f*192*1*00$/zip$", Tag::Zip3, 46310),
            ("$zip$3$*6610*256*1*00$/zip$", Tag::Zip3, 46320),
            ("$zip$4$*0*00000000*00000000*00000000$/zip$", Tag::Zip4, 46400),
            ("$zip$4$*1*00000000*00000000*00000000$/zip$", Tag::Zip4, 46410),
            ("$rar$15$*00000000*1*1*30*00$/rar$", Tag::Rar15, 46500),
            ("$rar$20$*00000000*10*10*30*00$/rar$", Tag::Rar20, 46600),
            ("$rar$30$*0*0000000000000000*c43d7b00*10*10*0*00$/rar$", Tag::Rar30, 46700),
            ("$rar$50$*0*00*15*00*00*0*****$/rar$", Tag::Rar50, 46800),
            ("$7z$*19**cefd04dc*1c**1*00*20*1c**00$/7z$", Tag::SevenZ, 46900),
        ] {
            let line = Line::new(text.to_owned(), Some(3), Proves::Exact).unwrap();
            assert_eq!((line.tag, line.mode, line.text.as_str(), line.entry, line.note), (tag, mode, text, Some(3), None));
            assert!(text.starts_with(tag.as_str()), "{text}");
            assert!(tag.modes().contains(&mode), "{tag} does not list mode {mode}");
        }
        assert!(Line::new("$pkzip$1*1*2*0*$/pkzip$".to_owned(), None, Proves::Exact).is_err());
        assert!(Line::new(String::new(), None, Proves::Exact).is_err());
        assert!(Line::new("$7z$0$19$0$$16$".to_owned(), None, Proves::Exact).is_err(), "the line of another tool is not one of ours");
    }

    #[test]
    fn the_tags_are_named_as_the_specification_names_them() {
        let names: Vec<&str> = Tag::ALL.iter().map(|tag| tag.as_str()).collect();
        assert_eq!(names, ["$zip$1$", "$zip$2$", "$zip$3$", "$zip$4$", "$rar$15$", "$rar$20$", "$rar$30$", "$rar$50$", "$7z$*"]);
        assert_eq!(serde_json::to_value(Tag::SevenZ).unwrap(), "$7z$*");
        assert_eq!(Tag::Rar50.to_string(), "$rar$50$");

        // the modes are 46100 to 46900, and no two tags share one
        let mut modes: Vec<u32> = Tag::ALL.iter().flat_map(|tag| tag.modes().iter().copied()).collect();
        assert_eq!(modes, [46100, 46200, 46300, 46310, 46320, 46400, 46410, 46500, 46600, 46700, 46800, 46900]);
        modes.dedup();
        assert_eq!(modes.len(), 12);
    }

    #[test]
    fn what_a_line_proves_has_three_names() {
        assert_eq!(serde_json::to_value(Proves::Exact).unwrap(), "exact");
        assert_eq!(serde_json::to_value(Proves::Structural).unwrap(), "structural");
        assert_eq!(serde_json::to_value(Proves::Weak { bits: 8 }).unwrap(), "weak");
        assert_eq!(Proves::Weak { bits: 16 }.to_string(), "weak");
    }

    #[test]
    fn a_note_is_one_sentence_without_a_name() {
        let line = Line::new("$zip$1$*1*00/aa*8*cefd04dc*1c*1c*00$/zip$".to_owned(), Some(0), Proves::Weak { bits: 8 }).unwrap().with_note(Note::NoDecoder { method: 9, checks: 1 });
        assert_eq!(line.note.unwrap().to_string(), "hashcat has no decoder for compression method 9, so the line tests only the check bytes of 1 header");

        assert_eq!(Note::EmptyEntry { checks: 8 }.to_string(), "it is empty, so the line tests only the check bytes of 8 headers");
        assert_eq!(Note::StoredTooLarge { stored: 5_000_000, limit: 4_194_304, checks: 2 }.to_string(), "its 5000000 stored bytes exceed the 4194304 a line carries, and a CRC-32 needs all of them, so the line tests only the check bytes of 2 headers");
        assert_eq!(Note::ShortStored { stored: 1, checks: 1 }.to_string(), "it holds 1 stored byte, and a CRC-32 over fewer than 4 bytes proves no more than the bytes themselves, so the line tests them and the check bytes of 1 header");
        assert!(Note::StoredAlone.to_string().contains("40 bits"));
        assert_eq!(Note::VerifierOnly { packed: 9_000_000, limit: 4_194_304, method: 0 }.to_string(), "its 9000000 bytes exceed the 4194304 a line carries and compression method 0 cannot be tested from its start, so the line tests only the 16-bit verifier");
        assert_eq!(Note::StreamEnd(NoCrc::NotStored).to_string(), "the archive stores no CRC-32 for it, so the line tests that the stream unpacks to its size and ends there");
        assert_eq!(Note::StreamStart(NoCrc::TooMuchToUnpack { size: 1 << 30, limit: 1 << 26 }).to_string(), "its first file unpacks to 1073741824 bytes, more than the 67108864 hashcat unpacks for a candidate, so the line tests that the start of the stream unpacks without an error");
        assert_eq!(Note::ShortCrc { size: 1 }.to_string(), "its CRC-32 covers 1 byte, and a CRC-32 over fewer than 4 bytes proves no more than the bytes themselves");
        assert_eq!(Note::StreamStart(NoCrc::TooMuchToCarry { need: 5_000_000, limit: 4_194_304 }).to_string(), "testing its CRC-32 takes 5000000 bytes of it, more than the 4194304 a line carries, so the line tests that the start of the stream unpacks without an error");
    }
}
