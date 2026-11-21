//! 7-Zip: from an archive to its analysis and its hash lines.
//!
//! [`analyse`] is the one way in. What is the same for every format is done by
//! [`Parts::assemble`].
//!
//! An entry of a 7-Zip archive is a folder: one chain of coders over one or more files, which
//! is the unit 7-Zip encrypts. A folder has no name; the files whose data it holds are its
//! `files`. Its place in the list of entries is its number in the archive, which is also what
//! 7-Zip lists as the block of a file.
//!
//! A file without data, an empty file or a directory, is in no folder and is no entry. It has
//! no stream, so nothing of it can be encrypted, and it says nothing about how much of the
//! archive is: an archive whose every folder is encrypted is encrypted in full, whatever empty
//! files it lists beside them.
//!
//! When the header cannot be read at all (it lies past the end of the file, it names its
//! folders in a stream outside itself, or it is packed with a coder this tool does not unpack)
//! nothing is known of what the archive holds. One entry in the state `undetermined` then
//! stands for all of it, with the reason, so that such an archive is never taken for one in
//! which nothing is encrypted.
//!
//! One reader serves the analysis and the lines: `reader::read`.

use super::line;
use super::line::Key;
use super::line::POWER_NO_DERIVATION;
use super::line::Proof;
use super::reader;
use super::reader::Archive;
use super::reader::Chain;
use super::reader::Folder;
use super::reader::Headers;
use super::reader::ID_AES;
use super::reader::ID_COPY;
use crate::analysis::Analysed;
use crate::analysis::Check;
use crate::analysis::CheckKind;
use crate::analysis::Cipher;
use crate::analysis::Entry;
use crate::analysis::EntryKind;
use crate::analysis::Format;
use crate::analysis::Generation;
use crate::analysis::HeaderState;
use crate::analysis::Kdf;
use crate::analysis::KdfName;
use crate::analysis::Method;
use crate::analysis::Missing;
use crate::analysis::NoLine;
use crate::analysis::Parameters;
use crate::analysis::Parts;
use crate::analysis::Protection;
use crate::analysis::Salt;
use crate::analysis::Scheme;
use crate::analysis::State;
use crate::analysis::Volume;
use crate::formats::source::Source;
use crate::line::Line;
use crate::line::Lines;
use crate::line::Note;
use crate::line::Proves;

/// Analyse one 7z archive and build its lines: the best one, or one for every folder.
///
/// The archive starts where `source` starts: at its signature.
pub(crate) fn analyse(source: &Source, wanted: Lines) -> anyhow::Result<Analysed> {
    let archive = reader::read(source)?;

    let mut parts = Parts::new(Format::SevenZ, Generation::SevenZ);
    parts.offset = source.offset();
    parts.volume = Some(Volume::Single);

    match &archive.headers {
        Headers::Unread(why) => {
            if *why == NoLine::HeaderOutsideFile {
                parts.volume = Some(Volume::Incomplete);
            }
            // nothing is known of what the archive holds: one entry stands for all of it
            parts.entries.push(Entry::new(EntryKind::Folder, State::Undetermined));
            parts.no_line.push(Missing::for_entry(Scheme::SevenZUnknown, 0, why.clone()));
        },
        Headers::Encrypted => {
            // the folders are those of the packed header: the first encrypted one says how
            let protection = archive.folders().find(Folder::is_encrypted).map_or_else(|| Protection::bare(Scheme::SevenZAes), |folder| protection(&folder, folder.chain().ok().as_ref(), true));
            parts.headers = HeaderState::Encrypted(protection);
            add_lines(source, &archive, wanted, &mut parts)?;
        },
        Headers::Readable => {
            parts.entries = archive.folders().map(|folder| describe(&folder)).collect();
            if let Some(mut names) = archive.names() {
                for (entry, folder) in parts.entries.iter_mut().zip(archive.folders()) {
                    entry.files = names.by_ref().take(usize::try_from(folder.files()).unwrap_or(usize::MAX)).collect();
                }
            }
            add_lines(source, &archive, wanted, &mut parts)?;
        },
    }

    Ok(parts.assemble(source.path()))
}

/// How a folder under 7zAES is encrypted. `key` is absent when the properties of the coder
/// cannot be read: the salt is then not known.
fn aes_protection(key: Option<Key<'_>>, check: Vec<Check>) -> Protection {
    let parameters = Parameters { cipher: Some(Cipher::Aes), key_bits: Some(256), check, ..Parameters::default() };
    let Some(key) = key else {
        return Protection { scheme: Scheme::SevenZAes, parameters, salt: Salt::Unknown };
    };
    // 0x3F is no number of rounds: the password is the key, and nothing is derived
    let kdf = (key.power != POWER_NO_DERIVATION).then(|| Kdf { name: KdfName::Sha256, rounds: 1_u64.checked_shl(u32::from(key.power)) });
    Protection { scheme: Scheme::SevenZAes, parameters: Parameters { kdf, ..parameters }, salt: Salt::stored(key.salt) }
}

/// How a folder is encrypted. `chain` is its coders, and `header` says that it holds the
/// header of the archive.
///
/// A cipher other than 7zAES is a scheme this tool does not know: it is named by its identifier
/// as the archive stores it: its bytes as one number.
fn protection(folder: &Folder<'_>, chain: Option<&Chain<'_>>, header: bool) -> Protection {
    let coders = chain.map_or(&[][..], |chain| chain.coders.as_slice());
    if let Some(unknown) = coders.iter().find(|coder| coder.is_cipher() && coder.id != ID_AES) {
        // the reader takes an identifier of eight bytes at most, so its bytes are one number
        let identifier = (unknown.id.len() <= 8).then(|| unknown.id.iter().fold(0_u64, |value, &byte| (value << 8) | u64::from(byte)));
        return Protection { scheme: Scheme::SevenZUnknown, parameters: Parameters { identifier, ..Parameters::default() }, salt: Salt::Unknown };
    }

    // a password is tested on the CRC-32 the archive stores, or else on what unpacks: a header
    // is one by its structure, and so is the stream of a packer
    let unpacks = header || coders.iter().any(|coder| coder.id != ID_AES && coder.id != ID_COPY);
    let check = if folder.has_crc() {
        vec![Check::new(CheckKind::Crc32, 32)]
    } else if unpacks {
        vec![Check::structure()]
    } else {
        Vec::new()
    };
    aes_protection(coders.iter().find(|coder| coder.id == ID_AES).and_then(|coder| line::aes_properties(coder.props)), check)
}

/// How a folder is packed: its coders but the cipher, in the order the archive stores them,
/// and the identifier of the coder when there is one.
fn method(chain: &Chain<'_>) -> Method {
    let packers: Vec<_> = chain.coders.iter().filter(|coder| !coder.is_cipher()).collect();
    let names: Vec<String> = packers.iter().filter(|coder| coder.id != ID_COPY).map(|coder| line::coder_name(coder.id)).collect();
    let number = match packers.as_slice() {
        [only] => Some(only.id.iter().fold(0_u64, |value, &byte| (value << 8) | u64::from(byte))),
        _ => None,
    };
    Method { name: Some(if names.is_empty() { "stored".to_owned() } else { names.join("+") }), number }
}

/// Describe one folder for the analysis.
fn describe(folder: &Folder<'_>) -> Entry {
    let chain = folder.chain().ok();
    let mut described = Entry::new(EntryKind::Folder, if folder.is_encrypted() { State::Encrypted } else { State::Plain });
    if folder.is_encrypted() {
        described.protection = Some(protection(folder, chain.as_ref(), false));
    }
    described.method = chain.as_ref().map(method);
    described.packed = folder.packed();
    described.size = Some(folder.size());
    described
}

/// Build the lines of an archive and put them, and the folders that gave none, into the parts.
fn add_lines(source: &Source, archive: &Archive, wanted: Lines, parts: &mut Parts) -> anyhow::Result<()> {
    let header = archive.headers == Headers::Encrypted;
    let built = line::hash_lines(source, archive, wanted == Lines::All)?;

    for line in built.lines {
        let (proves, note) = match (line.proof, line.weak_bits) {
            (Proof::Crc, Some(bits)) => (Proves::Weak { bits }, Some(Note::ShortCrc { size: line.crc_len })),
            (Proof::Crc, None) => (Proves::Exact, None),
            (Proof::Header, _) => (Proves::Structural, None),
            (Proof::End, _) => (Proves::Structural, line.why.map(Note::StreamEnd)),
            (Proof::Start, _) => (Proves::Structural, line.why.map(Note::StreamStart)),
        };
        // the line of an encrypted header comes from no entry
        let line = Line::new(line.text, (!header).then_some(line.folder), proves)?;
        parts.lines.push(match note {
            Some(note) => line.with_note(note),
            None => line,
        });
    }
    for (folder, why) in built.refused {
        let scheme = if why == NoLine::UnknownScheme { Scheme::SevenZUnknown } else { Scheme::SevenZAes };
        parts.no_line.push(if header { Missing::for_scheme(scheme, why) } else { Missing::for_entry(scheme, folder, why) });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::analysis::Coverage;
    use crate::analysis::Entries;
    use crate::analysis::Headers;
    use crate::analysis::Reason;
    use crate::formats::sevenz::craft;
    use crate::line::Tag;

    fn analysed(rel: &str, wanted: Lines) -> Analysed {
        let source = Source::open(Path::new(&format!("tests/fixtures/{rel}")), 0).unwrap();
        analyse(&source, wanted).unwrap()
    }

    #[test]
    fn an_entry_is_a_folder_with_its_files() {
        let Analysed { analysis, lines } = analysed("7z-aes/7z_nonsolid_enc.7z", Lines::All);
        assert_eq!((analysis.format, analysis.generation, analysis.headers, analysis.coverage), (Format::SevenZ, Generation::SevenZ, Headers::Readable, Coverage::All));
        assert_eq!((analysis.volume, analysis.offset), (Some(Volume::Single), 0));
        assert_eq!(analysis.entry_list.len(), 3);
        for entry in &analysis.entry_list {
            assert_eq!((entry.kind, entry.state, entry.name.as_ref()), (EntryKind::Folder, State::Encrypted, None));
            assert_eq!(entry.files.len(), 1);
            let protection = entry.protection.as_ref().unwrap();
            assert_eq!((protection.scheme, protection.parameters.cipher, protection.parameters.key_bits), (Scheme::SevenZAes, Some(Cipher::Aes), Some(256)));
            assert_eq!(protection.parameters.kdf, Some(Kdf { name: KdfName::Sha256, rounds: Some(1 << 19) }));
            assert_eq!(protection.parameters.check, [Check::new(CheckKind::Crc32, 32)]);
        }
        // a line for every folder, each from its own
        let mut from: Vec<usize> = lines.iter().filter_map(|line| line.entry).collect();
        from.sort_unstable();
        assert_eq!(from, [0, 1, 2]);
        assert!(lines.iter().all(|line| (line.tag, line.mode, line.proves) == (Tag::SevenZ, 46900, Proves::Exact)));
    }

    #[test]
    fn an_encrypted_header_hides_the_folders() {
        let Analysed { analysis, lines } = analysed("7z-aes/7z_hdr_lzma2.7z", Lines::Best);
        assert_eq!((analysis.headers, analysis.entries, analysis.coverage), (Headers::Encrypted, Entries::Hidden, Coverage::Unknown));
        assert!(analysis.entry_list.is_empty());
        assert_eq!(analysis.schemes.len(), 1);
        assert_eq!((analysis.schemes[0].scheme, analysis.schemes[0].parameters.key_bits), (Scheme::SevenZAes, Some(256)));
        assert_eq!(analysis.schemes[0].parameters.kdf, Some(Kdf { name: KdfName::Sha256, rounds: Some(1 << 19) }));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].entry, None, "the line of an encrypted header comes from no entry");
    }

    #[test]
    fn a_key_that_is_the_password_has_no_derivation_and_no_line() {
        let Analysed { analysis, lines } = analysed("7z-aes/rawkey.7z", Lines::Best);
        assert!(lines.is_empty());
        assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::SevenZAes, 0, NoLine::KeyIsPassword)]);
        assert_eq!(analysis.no_line[0].reason(), Reason::NoMode);
        let protection = analysis.entry_list[0].protection.as_ref().unwrap();
        assert_eq!(protection.parameters.kdf, None, "0x3F is no number of rounds");
    }

    /// `rawkey.7z` with another `NumCyclesPower`. Its header is stored as it is, so the one byte
    /// can be set and the two checksums over it made right again.
    fn with_power(power: u8) -> Vec<u8> {
        let mut archive = std::fs::read("tests/fixtures/7z-aes/rawkey.7z").unwrap();
        // the AES coder, the size of its properties, and their first byte: 0x3F with a vector
        let at = archive.windows(6).position(|window| window == [0x06, 0xF1, 0x07, 0x01, 0x12, 0x7F]).unwrap() + 5;
        archive[at] = 0x40 | power;
        let header = crc32fast::hash(&archive[0x40..]);
        archive[28..32].copy_from_slice(&header.to_le_bytes());
        let start = crc32fast::hash(&archive[12..32]);
        archive[8..12].copy_from_slice(&start.to_le_bytes());
        archive
    }

    #[test]
    fn more_rounds_than_7_zip_accepts_are_unsupported_parameters() {
        for power in [25, 30, 62] {
            let Analysed { analysis, lines } = analyse(&Source::from_bytes(with_power(power)), Lines::Best).unwrap();
            assert!(lines.is_empty());
            assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::SevenZAes, 0, NoLine::TooManyRounds { power })]);
            assert_eq!(analysis.no_line[0].reason(), Reason::UnsupportedParameters);
            assert_eq!(analysis.entry_list[0].protection.as_ref().unwrap().parameters.kdf, Some(Kdf { name: KdfName::Sha256, rounds: Some(1 << power) }));
            assert_eq!(analysis.findings.last().unwrap(), &crate::analysis::Finding::new(crate::analysis::Found::UnsupportedParameters(NoLine::TooManyRounds { power }), vec![0]));
        }

        // the same archive with a number of rounds 7-Zip takes has a line
        for power in [0, 19, 24] {
            let Analysed { analysis, lines } = analyse(&Source::from_bytes(with_power(power)), Lines::Best).unwrap();
            assert_eq!((lines.len(), analysis.no_line.len()), (1, 0));
            assert!(lines[0].text.starts_with(&format!("$7z$*{power}*")), "{}", lines[0].text);
        }
    }

    #[test]
    fn a_folder_the_line_cannot_describe_and_an_empty_one_say_so() {
        for fixture in ["7z-aes/tier5_padded.7z", "7z-aes/unknown_coder.7z"] {
            let Analysed { analysis, lines } = analysed(fixture, Lines::All);
            assert!(lines.is_empty(), "{fixture}");
            assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::SevenZAes, 0, NoLine::StreamNotEncryptedLast)], "{fixture}");
            assert_eq!(analysis.no_line[0].reason(), Reason::NotExpressible, "{fixture}");
        }
        let Analysed { analysis, lines } = analysed("7z-aes/7z_empty_pw.7z", Lines::All);
        assert!(lines.is_empty());
        assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::SevenZAes, 0, NoLine::Empty)]);
        assert_eq!(analysis.no_line[0].reason(), Reason::NoData);
    }

    #[test]
    fn folders_of_one_archive_can_differ_in_their_state() {
        let analysis = analysed("7z-aes/ttzip-core_test_read_format_7zip_encryption_partially.7z", Lines::Best).analysis;
        let states: Vec<(State, &[String])> = analysis.entry_list.iter().map(|entry| (entry.state, entry.files.as_slice())).collect();
        assert_eq!(states.len(), 2);
        assert!(states.contains(&(State::Plain, &["bar_unencrypted.txt".to_owned()][..])), "{states:?}");
        assert!(states.contains(&(State::Encrypted, &["bar_encrypted.txt".to_owned()][..])), "{states:?}");
        assert_eq!(analysis.coverage, Coverage::Some);
        assert!(analysis.findings.iter().any(|finding| finding.code() == "partial"));
    }

    #[test]
    fn a_plain_archive_has_folders_and_no_scheme() {
        let Analysed { analysis, lines } = analysed("unencrypted/plain.7z", Lines::All);
        assert!(lines.is_empty() && analysis.no_line.is_empty() && analysis.schemes.is_empty());
        assert_eq!(analysis.coverage, Coverage::None);
        assert!(!analysis.entry_list.is_empty());
        assert!(analysis.entry_list.iter().all(|entry| entry.state == State::Plain && entry.protection.is_none() && entry.kind == EntryKind::Folder));
    }

    /// Each of these once ended in a panic, an abort or minutes of work. Now each is read to an
    /// error or to an analysis, and what it holds of memory and time is what its bytes can back.
    #[test]
    fn the_inputs_that_once_broke_the_reader_end_in_a_result_or_an_error() {
        let hostile = craft::hostile();
        let outcome = |name: &str| {
            let (_, bytes) = hostile.iter().find(|(known, _)| *known == name).unwrap();
            let started = std::time::Instant::now();
            let outcome = analyse(&Source::from_bytes(bytes.clone()), Lines::All);
            assert!(started.elapsed() < std::time::Duration::from_secs(5), "{name} took {:?}", started.elapsed());
            outcome.map(|analysed| (analysed.analysis.entry_list.len(), analysed.lines.len(), analysed.analysis.no_line.iter().map(Missing::reason).collect::<Vec<_>>()))
        };

        // no archive: an error, and the run goes on
        for name in ["skip-overflow", "no-output", "three-outputs", "inputs-overflow", "crcs-2e40", "crcs-2e63", "pack-position", "pack-size", "unpack-2e62", "unpack-max", "wide-coder"] {
            assert!(outcome(name).is_err(), "{name}");
        }
        // a list of files nothing backs leaves an archive without folders
        for name in ["files-2e62", "files-2e36", "files-2e27", "names-of-2e40"] {
            assert_eq!(outcome(name).unwrap(), (0, 0, Vec::new()), "{name}");
        }
        // an archive whose one folder has no line, and the reason
        assert_eq!(outcome("crc-length-overflow").unwrap(), (1, 0, vec![Reason::OverLimit]));
        assert_eq!(outcome("ppmd-memory").unwrap(), (1, 0, vec![Reason::OverLimit]));
        assert_eq!(outcome("stored-no-crc").unwrap(), (1, 0, vec![Reason::NoData]));
        // and archives with their lines: four streams in one, and one line for 4096 folders
        // that all hold the same
        assert_eq!(outcome("bcj2").unwrap(), (1, 1, Vec::new()));
        let (folders, lines, refused) = outcome("many-folders").unwrap();
        assert_eq!((folders, refused), (4096, Vec::new()));
        assert_eq!(lines, 1, "the folders all hold the same, and the same line is written once");
        assert_eq!(hostile.len(), 20);
    }

    #[test]
    fn rounds_follow_the_power_and_a_power_that_is_none_gives_none() {
        let key = |power: u8, salt: &'static [u8]| Some(Key { power, salt, iv: &[] });
        assert_eq!(aes_protection(key(19, &[]), Vec::new()).parameters.kdf, Some(Kdf { name: KdfName::Sha256, rounds: Some(524_288) }));
        assert_eq!(aes_protection(key(62, &[1, 2]), Vec::new()).parameters.kdf, Some(Kdf { name: KdfName::Sha256, rounds: Some(1 << 62) }));
        assert_eq!(aes_protection(key(62, &[1, 2]), Vec::new()).salt, Salt::Known(vec![1, 2]));
        assert_eq!(aes_protection(key(POWER_NO_DERIVATION, &[]), Vec::new()).parameters.kdf, None);
        assert_eq!(aes_protection(None, Vec::new()).salt, Salt::Unknown, "properties that cannot be read leave the salt open");
        assert_eq!(aes_protection(key(19, &[]), Vec::new()).salt, Salt::None);
    }

    // -----------------------------------------------------------------------
    // Crafted archives: what no free tool writes
    // -----------------------------------------------------------------------

    fn key(power: u8, salt: &[u8]) -> Vec<u8> {
        craft::aes_props(power, salt, &[9; 16])
    }

    /// A folder of one file of 100 bytes with a CRC-32: these coders, the last of which reads
    /// the packed stream of 32 bytes.
    fn folder(coders: &[(&[u8], &[u8])]) -> craft::Folder {
        let mut sizes = vec![100; coders.len()];
        if let Some(last) = sizes.last_mut() {
            *last = 32;
        }
        craft::Folder::new(craft::chain(coders), &sizes, 32, Some(0xC0FF_EE00))
    }

    fn crafted(folders: &[craft::Folder], wanted: Lines) -> Analysed {
        analyse(&Source::from_bytes(craft::archive_of(folders)), wanted).unwrap()
    }

    fn codes(analysis: &crate::analysis::Analysis) -> Vec<&'static str> {
        analysis.findings.iter().map(crate::analysis::Finding::code).collect()
    }

    /// Section 7.3: any other coder in the cipher range of 7-Zip's method table is encrypted
    /// under a scheme the tool does not know, and is named by its identifier.
    #[test]
    fn a_cipher_other_than_7z_aes_is_an_unknown_scheme_with_its_identifier() {
        let aes = key(19, &[]);
        let folders = [
            folder(&[(craft::LZMA2, &[0x18]), (craft::AES, &aes)]),
            // ZipCrypto and the RAR 3 cipher as the method table lists them, behind a packer and alone
            folder(&[(craft::LZMA2, &[0x18]), (&[0x06, 0xF1, 0x01, 0x01], &[])]),
            folder(&[(&[0x06, 0xF1, 0x03, 0x03], &[1, 2, 3])]),
            // bare AES-256 in CBC mode, and an identifier of five bytes: its raw value is shown all the same
            folder(&[(&[0x06, 0xF0, 0x01, 0x81], &[])]),
            folder(&[(&[0x06, 0xF1, 0x07, 0x01, 0x02], &[])]),
            // 7zAES together with another cipher is no scheme the tool knows either
            folder(&[(&[0x06, 0xF1, 0x01, 0x01], &[]), (craft::AES, &aes)]),
            folder(&[(craft::LZMA, craft::LZMA_PROPS)]),
        ];
        let Analysed { analysis, lines } = crafted(&folders, Lines::All);

        let seen: Vec<_> = analysis.entry_list.iter().map(|entry| (entry.state, entry.protection.as_ref().map(|protection| (protection.scheme, protection.parameters.identifier)))).collect();
        assert_eq!(
            seen,
            [
                (State::Encrypted, Some((Scheme::SevenZAes, None))),
                (State::Encrypted, Some((Scheme::SevenZUnknown, Some(0x06F1_0101)))),
                (State::Encrypted, Some((Scheme::SevenZUnknown, Some(0x06F1_0303)))),
                (State::Encrypted, Some((Scheme::SevenZUnknown, Some(0x06F0_0181)))),
                (State::Encrypted, Some((Scheme::SevenZUnknown, Some(0x0006_F107_0102)))),
                (State::Encrypted, Some((Scheme::SevenZUnknown, Some(0x06F1_0101)))),
                (State::Plain, None),
            ]
        );
        assert!(analysis.entry_list[1..6].iter().all(|entry| entry.key_group.is_none() && entry.protection.as_ref().unwrap().salt == Salt::Unknown));

        // the one folder under 7zAES has the line, and each of the others its reason
        assert_eq!(lines.iter().map(|line| line.entry).collect::<Vec<_>>(), [Some(0)]);
        assert_eq!(analysis.no_line, (1..6).map(|index| Missing::for_entry(Scheme::SevenZUnknown, index, NoLine::UnknownScheme)).collect::<Vec<_>>());
        assert!(analysis.no_line.iter().all(|missing| missing.reason() == Reason::UnknownScheme));

        // more than one scheme, some folders open, and a finding for each identifier
        assert_eq!(codes(&analysis), ["mixed-schemes", "partial", "unknown-scheme", "unknown-scheme", "unknown-scheme", "unknown-scheme"]);
        let unknown: Vec<_> = analysis.findings.iter().filter(|finding| finding.code() == "unknown-scheme").map(|finding| finding.entries.clone()).collect();
        assert_eq!(unknown, [vec![1, 5], vec![2], vec![3], vec![4]]);
        // every scheme the tool cannot name is reported with the value the archive stores for it
        let said: Vec<String> = analysis.findings.iter().filter(|finding| finding.code() == "unknown-scheme").map(|finding| finding.found.to_string()).collect();
        assert!(said.iter().all(|text| text.contains("identifier 0x")), "{said:?}");
        assert!(said[3].ends_with("identifier 0x6f1070102"), "{said:?}");
        assert_eq!((analysis.mixed, analysis.coverage), (true, Coverage::Some));
        assert!(serde_json::to_string(&analysis).unwrap().contains(r#""scheme":"7z-unknown","variant":"7z-unknown","identifier":116457729"#));
    }

    #[test]
    fn a_header_under_an_unknown_cipher_is_encrypted_and_has_no_line() {
        let header = craft::packed_header(craft::chain(&[(craft::LZMA, craft::LZMA_PROPS), (&[0x06, 0xF1, 0x03, 0x03], &[])]), &[200, 32], 0, 32, Some(1));
        let Analysed { analysis, lines } = analyse(&Source::from_bytes(craft::archive(&header, &[0; 32])), Lines::Best).unwrap();
        assert_eq!((analysis.headers, analysis.entries, analysis.coverage), (Headers::Encrypted, Entries::Hidden, Coverage::Unknown));
        assert_eq!((analysis.schemes[0].scheme, analysis.schemes[0].parameters.identifier), (Scheme::SevenZUnknown, Some(0x06F1_0303)));
        assert!(lines.is_empty());
        assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::SevenZUnknown, NoLine::UnknownScheme)]);
    }

    /// Section 6.1: a first volume of a split archive, and a file that is cut short, are
    /// incomplete and no failure.
    #[test]
    fn a_file_that_ends_before_its_header_is_incomplete_and_undetermined() {
        let whole = std::fs::read("tests/fixtures/7z-aes/7z_nonsolid_enc.7z").unwrap();
        for keep in [32, 100, whole.len() - 1] {
            let Analysed { analysis, lines } = analyse(&Source::from_bytes(whole[..keep].to_vec()), Lines::All).unwrap();
            assert_eq!(analysis.volume, Some(Volume::Incomplete), "{keep} bytes");
            assert_eq!(codes(&analysis), ["incomplete"]);
            assert_eq!(analysis.coverage, Coverage::Unknown, "nothing of the archive was read: it is not all encrypted, and not none of it");
            // nothing is known of what it holds, and that is not "nothing is encrypted"
            assert_eq!(analysis.entry_list.iter().map(|entry| (entry.kind, entry.state)).collect::<Vec<_>>(), [(EntryKind::Folder, State::Undetermined)]);
            assert!(analysis.is_encrypted() && analysis.schemes.is_empty() && lines.is_empty());
            assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::SevenZUnknown, 0, NoLine::HeaderOutsideFile)]);
            assert_eq!(analysis.no_line[0].reason(), Reason::Split);
        }
        assert_eq!(analyse(&Source::from_bytes(whole), Lines::All).unwrap().analysis.volume, Some(Volume::Single));
    }

    /// Section 7.3 as the brief extends it: a reference to something outside the header is a
    /// reason and no failure.
    #[test]
    fn a_header_the_tool_cannot_read_is_undetermined_with_its_reason() {
        let external = craft::archive(&[0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x10, 0x00, 0x07, 0x0B, 0x01, 0x01, 0x00], &[0; 16]);
        let packed = craft::archive(&craft::packed_header(craft::chain(&[(craft::PPMD, &[6, 0, 0, 0, 1])]), &[100], 0, 16, None), &[0; 16]);
        for (archive, why) in [(external, NoLine::ExternalFolders), (packed, NoLine::PackedHeaderCoder { id: "030401".to_owned() })] {
            let Analysed { analysis, lines } = analyse(&Source::from_bytes(archive), Lines::All).unwrap();
            assert_eq!((analysis.volume, analysis.headers), (Some(Volume::Single), Headers::Readable));
            assert_eq!(analysis.entry_list.iter().map(|entry| entry.state).collect::<Vec<_>>(), [State::Undetermined]);
            assert!(analysis.is_encrypted() && lines.is_empty() && analysis.findings.is_empty());
            assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::SevenZUnknown, 0, why)]);
            assert_eq!(analysis.no_line[0].reason(), Reason::Damaged);
        }
    }

    /// Section 6.2: folders whose key derivation takes the same rounds and the same salt share
    /// a key, and no others do.
    #[test]
    fn key_groups_follow_rounds_and_salt() {
        let packed = |props: &[u8]| folder(&[(craft::LZMA2, &[0x18]), (craft::AES, props)]);
        let folders = [packed(&key(19, &[])), packed(&key(19, &[1, 2, 3, 4])), packed(&key(19, &[])), packed(&key(18, &[])), packed(&key(19, &[1, 2, 3, 4])), packed(&key(19, &[1, 2, 3, 5])), folder(&[(craft::LZMA2, &[0x18])])];
        let analysis = crafted(&folders, Lines::Best).analysis;

        assert_eq!(analysis.entry_list.iter().map(|entry| entry.key_group).collect::<Vec<_>>(), [Some(1), Some(2), Some(1), Some(3), Some(2), Some(4), None]);
        assert_eq!(analysis.entry_list[1].protection.as_ref().unwrap().salt, Salt::Known(vec![1, 2, 3, 4]));
        // one row for each number of rounds: five folders in three groups, and one in one
        let rows: Vec<_> = analysis.schemes.iter().map(|row| (row.parameters.kdf.and_then(|kdf| kdf.rounds), row.entries, row.key_groups)).collect();
        assert_eq!(rows, [(Some(1 << 19), Some(5), Some(3)), (Some(1 << 18), Some(1), Some(1))]);
        assert_eq!((analysis.mixed, analysis.coverage), (false, Coverage::Some));
    }

    /// Section 6.2: what a password can be tested against is the CRC-32 the archive stores, or
    /// the structure of what unpacks, or nothing.
    #[test]
    fn a_folder_names_what_a_password_is_tested_against() {
        let aes = key(19, &[]);
        let packed = folder(&[(craft::LZMA2, &[0x18]), (craft::AES, &aes)]);
        let stored = craft::Folder::new(craft::chain(&[(craft::AES, &aes)]), &[32], 32, Some(1));
        let folders = [packed.clone(), craft::Folder { crc: None, ..packed }, stored.clone(), craft::Folder { crc: None, ..stored }];
        let Analysed { analysis, lines } = crafted(&folders, Lines::All);

        let checks: Vec<_> = analysis.entry_list.iter().map(|entry| entry.protection.as_ref().unwrap().parameters.check.clone()).collect();
        assert_eq!(checks, [vec![Check::new(CheckKind::Crc32, 32)], vec![Check::structure()], vec![Check::new(CheckKind::Crc32, 32)], Vec::new()]);
        // and the lines test just that: two checksums, the smaller file first, one stream that
        // has to end, and nothing
        let proves: Vec<_> = lines.iter().map(|line| (line.entry, line.proves, line.note)).collect();
        assert_eq!(proves, [(Some(2), Proves::Exact, None), (Some(0), Proves::Exact, None), (Some(1), Proves::Structural, Some(Note::StreamEnd(crate::line::NoCrc::NotStored)))]);
        assert_eq!(analysis.no_line.iter().map(|missing| (missing.entry, missing.reason())).collect::<Vec<_>>(), [(Some(3), Reason::NoData)]);
    }

    /// Section 6.2: the method of a folder is its coders but the cipher, by name, and the
    /// identifier of the coder when there is one.
    #[test]
    fn a_folder_names_its_coders_and_the_number_of_the_one() {
        let aes = key(19, &[]);
        let bcj: &[u8] = &[0x03, 0x03, 0x01, 0x03];
        let folders = [
            folder(&[(craft::LZMA2, &[0x18]), (craft::AES, &aes)]),
            folder(&[(bcj, &[]), (craft::LZMA, craft::LZMA_PROPS), (craft::AES, &aes)]),
            folder(&[(craft::AES, &aes)]),
            folder(&[(&[0x00], &[])]),
            folder(&[(craft::PPMD, &[6, 0, 0, 0, 1])]),
            folder(&[(&[0x04, 0xF7, 0x11, 0x02], &[]), (craft::AES, &aes)]),
        ];
        let analysis = crafted(&folders, Lines::Best).analysis;
        let methods: Vec<_> = analysis.entry_list.iter().map(|entry| entry.method.as_ref().map(|method| (method.name.as_deref(), method.number))).collect();
        assert_eq!(methods, [Some((Some("LZMA2"), Some(0x21))), Some((Some("BCJ+LZMA"), None)), Some((Some("stored"), None)), Some((Some("stored"), Some(0))), Some((Some("PPMd"), Some(0x03_0401))), Some((Some("04f71102"), Some(0x04F7_1102)))]);
        // every folder has its sizes: what it unpacks to, and its packed streams together
        assert!(analysis.entry_list.iter().all(|entry| entry.packed == Some(32) && entry.split.is_none() && entry.name.is_none()));
        assert_eq!(analysis.entry_list.iter().map(|entry| entry.size).collect::<Vec<_>>(), [Some(100), Some(100), Some(32), Some(32), Some(32), Some(100)]);
        assert_eq!(analysis.entry_list.iter().map(|entry| entry.files.clone()).collect::<Vec<_>>(), (0..6).map(|number| vec![format!("f{number}")]).collect::<Vec<_>>());
    }

    /// Section 6.4, `weak-check`: when the best line an archive allows tests fewer than 32
    /// bits, the line is weak and says so.
    #[test]
    fn the_best_line_of_an_archive_is_weak_only_when_no_other_is_to_be_had() {
        let aes = key(19, &[]);
        let stored = |size: u64, crc: u32| craft::Folder::new(craft::chain(&[(craft::AES, &aes)]), &[size], 16, Some(crc));

        let Analysed { analysis, lines } = crafted(&[stored(2, 7)], Lines::Best);
        assert_eq!((lines.len(), lines[0].proves, lines[0].note), (1, Proves::Weak { bits: 16 }, Some(Note::ShortCrc { size: 2 })));
        assert_eq!(analysis.findings, [crate::analysis::Finding::new(crate::analysis::Found::WeakCheck { bits: 16 }, vec![0])]);

        // beside a folder whose line proves more, the weak one is neither the best nor a finding
        let Analysed { analysis, lines } = crafted(&[stored(1, 7), stored(12, 8)], Lines::Best);
        assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, Some(1), Proves::Exact));
        assert!(analysis.findings.is_empty() && analysis.no_line.is_empty());
        assert_eq!(analysis.entry_list.iter().map(|entry| entry.line.is_some()).collect::<Vec<_>>(), [false, true]);

        // every folder asked: the weak line comes last and is marked
        let lines = crafted(&[stored(1, 7), stored(12, 8)], Lines::All).lines;
        assert_eq!(lines.iter().map(|line| (line.entry, line.proves)).collect::<Vec<_>>(), [(Some(1), Proves::Exact), (Some(0), Proves::Weak { bits: 8 })]);
    }

    /// A file without data is in no folder and is no entry: it does not make an archive
    /// "partly encrypted".
    #[test]
    fn files_without_data_are_no_entries() {
        // an empty directory, an empty file and two files in one encrypted folder
        let analysis = analysed("7z-aes/arca_encrypted.7z", Lines::Best).analysis;
        assert_eq!(analysis.entry_list.len(), 1);
        assert_eq!(analysis.entry_list[0].files, ["first.txt", "second.txt"]);
        assert_eq!((analysis.entry_list[0].size, analysis.coverage), (Some(248), Coverage::All));
        assert!(analysis.findings.is_empty());

        // an archive of nothing but empty files has no folder at all
        let empty = analysed("unencrypted/two_empty_file.7z", Lines::Best).analysis;
        assert!(empty.entry_list.is_empty() && !empty.is_encrypted());
        assert_eq!(empty.coverage, Coverage::None);
    }

    /// Section 7.3: encryption is per folder, and so are size, packed size and salt.
    #[test]
    fn every_folder_has_its_own_state_sizes_and_salt() {
        let analysis = analysed("7z-aes/gen_7z_mixed_plain_first.7z", Lines::Best).analysis;
        let plain: Vec<_> = analysis.entry_list.iter().filter(|entry| entry.state == State::Plain).flat_map(|entry| entry.files.clone()).collect();
        assert_eq!(plain, ["tiny.txt"], "7-Zip lists this file as not encrypted");
        assert!(analysis.entry_list.iter().any(|entry| entry.state == State::Encrypted));

        let sizes: Vec<_> = analysed("7z-aes/7z_nonsolid_enc.7z", Lines::Best).analysis.entry_list.iter().map(|entry| (entry.size, entry.packed)).collect();
        assert_eq!(sizes, [(Some(28), Some(32)), (Some(46), Some(64)), (Some(67), Some(80))]);

        let salted = analysed("7z-aes/salted.7z", Lines::Best).analysis;
        assert!(matches!(&salted.entry_list[0].protection.as_ref().unwrap().salt, Salt::Known(salt) if !salt.is_empty()));

        // a header that is encrypted and has no checksum is tested by its structure
        let Analysed { analysis, lines } = analysed("7z-aes/gen_py7zr_lzma2_hdr.7z", Lines::Best);
        assert_eq!(analysis.schemes[0].parameters.check, [Check::structure()]);
        assert_eq!((lines.len(), lines[0].proves, lines[0].entry), (1, Proves::Structural, None));
        assert!(lines[0].text.starts_with("$7z$*19**header*"), "{}", &lines[0].text[..40]);
    }

    /// Section 8.4: each reason a 7-Zip archive can have for a missing line, from one case of it.
    #[test]
    fn every_reason_a_7z_archive_can_have_is_given() {
        let aes = key(19, &[]);
        let reason = |folder: craft::Folder| {
            let analysis = crafted(&[folder], Lines::All).analysis;
            assert_eq!(analysis.no_line.len(), 1);
            let reason = analysis.no_line[0].reason();
            assert_eq!(analysis.entry_list[0].line, Some(crate::analysis::EntryLine(Err(reason))));
            reason
        };
        let packed = |props: &[u8]| folder(&[(craft::LZMA2, &[0x18]), (craft::AES, props)]);

        assert_eq!(reason(packed(&key(0x3F, &[]))), Reason::NoMode);
        assert_eq!(reason(folder(&[(&[0x06, 0xF1, 0x01, 0x01], &[])])), Reason::UnknownScheme);
        assert_eq!(reason(packed(&key(25, &[]))), Reason::UnsupportedParameters);
        assert_eq!(reason(folder(&[(craft::AES, &aes), (craft::LZMA2, &[0x18])])), Reason::NotExpressible);
        assert_eq!(reason(folder(&[(craft::PPMD, &[6, 0, 0, 0, 0x40]), (craft::AES, &aes)])), Reason::OverLimit);
        assert_eq!(reason(craft::Folder::new(craft::chain(&[(craft::AES, &aes)]), &[0], 0, None)), Reason::NoData);
        assert_eq!(reason(craft::Folder::new(craft::chain(&[(craft::AES, &[0xD3])]), &[32], 32, Some(1))), Reason::Damaged);
        // `split` is the reason of a file that does not hold its header: the test above.
        // `no-password` is for certificates, which 7-Zip does not have.
    }
}
