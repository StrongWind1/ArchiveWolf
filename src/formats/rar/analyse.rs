//! RAR: from an archive to its analysis and its hash lines.
//!
//! [`analyse`] is the one way in. It parses the archive by range, describes each entry for
//! the analysis (or the encryption of the headers, when they hide the entries), holds every
//! encrypted entry against what its hashcat mode loads, ranks the ones that pass and builds
//! the lines that are asked for. What is the same for every format is done by
//! [`Parts::assemble`].

use std::collections::BTreeSet;

use super::data_extract::check_value_line;
use super::data_extract::data_line;
use super::data_extract::rar_30_header_line;
use super::data_extract::rar_50_header_line;
use super::encryption::Rar50Record;
use super::encryption::RarEncryption;
use super::encryption::Unused;
use super::headers::HeaderEncryption;
use super::headers::RarArchive;
use super::headers::RarEntry;
use super::headers::RarGeneration;
use super::headers::parse;
use super::rar4::end_block;
use super::rar4::header_salt;
use super::scoring::Candidate;
use super::scoring::Plan;
use super::scoring::assess;
use super::scoring::rounds_fit;
use crate::analysis::Analysed;
use crate::analysis::Check;
use crate::analysis::CheckKind;
use crate::analysis::Cipher;
use crate::analysis::Entry;
use crate::analysis::Finding;
use crate::analysis::Format;
use crate::analysis::Found;
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
use crate::analysis::Split;
use crate::analysis::State;
use crate::analysis::Volume;
use crate::formats::source::Source;
use crate::line::Line;
use crate::line::Lines;
use crate::line::Note;
use crate::line::Proves;

/// The rounds of SHA-1 a RAR 3 key is derived with.
const RAR_30_ROUNDS: u64 = 0x4_0000;

/// Analyse one RAR archive and build its lines: the best one of each scheme, or one for every
/// entry.
pub(crate) fn analyse(source: &Source, wanted: Lines) -> anyhow::Result<Analysed> {
    let (start, archive) = parse(source)?;

    let generation = match archive.generation {
        RarGeneration::Rar1 => Generation::Rar1,
        RarGeneration::Rar4 => Generation::Rar4,
        RarGeneration::Rar5 => Generation::Rar5,
    };
    let mut parts = Parts::new(Format::Rar, generation);
    parts.offset = source.offset().saturating_add(start);
    // a file that ends before its archive does is that first, whatever volume it is
    parts.volume = if archive.truncated { Some(Volume::Incomplete) } else { archive.volume };
    parts.comment = archive.comment.as_deref().map(|comment| String::from_utf8_lossy(comment).trim_end().to_owned()).filter(|comment| !comment.is_empty());

    match &archive.headers {
        HeaderEncryption::None => {
            parts.entries = archive.entries.iter().map(|entry| describe(archive.generation, entry)).collect();
            // a check value that fails its own checksum is damage, and is said: the entry is
            // tested by its data in its place
            let spoiled: Vec<usize> = archive.entries.iter().enumerate().filter(|(_, entry)| matches!(entry.encryption, RarEncryption::Rar50(crypt) if crypt.unused == Some(Unused::Damaged))).map(|(index, _)| index).collect();
            if !spoiled.is_empty() {
                parts.findings.push(Finding::new(Found::CheckValueDamaged, spoiled));
            }
            entry_lines(source, &archive, wanted, &mut parts)?;
        },
        HeaderEncryption::Rar30 { salt_at, volume } => rar_30_headers(source, *salt_at, *volume, &mut parts)?,
        HeaderEncryption::Rar50 { crypt, block_at } => rar_50_headers(source, crypt, *block_at, &mut parts)?,
        HeaderEncryption::Rar50Unreadable => {
            parts.headers = HeaderState::Encrypted(unreadable(Scheme::Rar50));
            parts.no_line.push(Missing::for_scheme(Scheme::Rar50, NoLine::Unreadable));
        },
        HeaderEncryption::Unknown { version } => {
            let protection = unknown(*version);
            parts.findings.push(Finding::new(Found::UnknownScheme { identifier: protection.parameters.identifier }, Vec::new()));
            parts.headers = HeaderState::Encrypted(protection);
            parts.no_line.push(Missing::for_scheme(Scheme::RarUnknown, NoLine::UnknownScheme));
        },
    }

    // what the walk over the headers met: bytes that are no header, and a header that fails
    // its checksum. The offsets are those of the file.
    if let Some(at) = archive.broken_at {
        parts.findings.push(Finding::new(Found::HeadersBroken { at: source.offset().saturating_add(at), left: source.len().saturating_sub(at) }, Vec::new()));
    }
    if let Some(at) = archive.bad_checksum_at {
        parts.findings.push(Finding::new(Found::HeaderChecksum { at: source.offset().saturating_add(at) }, Vec::new()));
    }

    Ok(parts.assemble(source.path()))
}

/// The parameters of `rar-30`, with what a password can be tested against.
fn rar_30_parameters(check: Vec<Check>) -> Parameters {
    Parameters { cipher: Some(Cipher::Aes), key_bits: Some(128), kdf: Some(Kdf { name: KdfName::Sha1, rounds: Some(RAR_30_ROUNDS) }), check, ..Parameters::default() }
}

/// The parameters of `rar-50` with `lg2count` as the exponent of its round count. A count that
/// does not fit 64 bits has no number.
fn rar_50_parameters(crypt: &Rar50Record, check: Vec<Check>) -> Parameters {
    let rounds = 1_u64.checked_shl(u32::from(crypt.lg2count));
    Parameters { cipher: Some(Cipher::Aes), key_bits: Some(256), kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds }), check, check_value_unused: crypt.unused.is_some(), ..Parameters::default() }
}

/// What is encrypted under an encryption record of a version the tool does not know: the
/// version is all that can be said of it.
fn unknown(version: u64) -> Protection {
    Protection { scheme: Scheme::RarUnknown, parameters: Parameters { identifier: Some(version), ..Parameters::default() }, salt: Salt::None }
}

/// What is encrypted under `scheme` by fields that are cut off: the scheme is all that can be
/// said of it, and its salt is not known.
fn unreadable(scheme: Scheme) -> Protection {
    Protection { scheme, parameters: Parameters::default(), salt: Salt::Unknown }
}

/// How an entry is encrypted, from what its header says.
fn protection(entry: &RarEntry) -> Option<Protection> {
    let crc32 = Check::new(CheckKind::Crc32, 32);
    let early = |scheme: Scheme, cipher: Cipher, key_bits: u32, check: Check| Protection { scheme, parameters: Parameters { cipher: Some(cipher), key_bits: Some(key_bits), check: vec![check], ..Parameters::default() }, salt: Salt::None };

    Some(match entry.encryption {
        RarEncryption::None => return None,
        // the checksum of RAR 1.3 is a sum of 16 bits, and the keys a password can give are 2^23
        RarEncryption::Rar13 => early(Scheme::Rar13, Cipher::Rar13, 24, Check::new(CheckKind::Checksum, 16)),
        RarEncryption::Rar15 => early(Scheme::Rar15, Cipher::Rar15, 64, crc32),
        RarEncryption::Rar20 => early(Scheme::Rar20, Cipher::Rar20, 128, crc32),
        RarEncryption::Rar30 { salt } => Protection { scheme: Scheme::Rar30, parameters: rar_30_parameters(vec![crc32]), salt: salt.map_or(Salt::None, |salt| Salt::Known(salt.to_vec())) },
        RarEncryption::Rar50(crypt) => {
            let mut check = Vec::new();
            if crypt.check_value.is_some() {
                check.push(Check::new(CheckKind::CheckValue, 64));
            }
            // the checksum of the data: a digest in the place of the CRC-32 when there is one
            let of_data = if entry.blake2sp.is_some() { Some(Check::new(CheckKind::Blake2sp, 256)) } else { entry.has_crc32.then_some(crc32) };
            check.extend(of_data.map(|check| if crypt.hashmac { check.keyed() } else { check }));
            Protection { scheme: Scheme::Rar50, parameters: rar_50_parameters(&crypt, check), salt: Salt::Known(crypt.salt.to_vec()) }
        },
        RarEncryption::Unknown { version } => unknown(version),
        RarEncryption::Unreadable(scheme) => unreadable(scheme),
    })
}

/// The name of a compression method: RAR 1.5 to 4 count from 0x30, the others from 0.
const fn method_name(generation: RarGeneration, method: u8) -> Option<&'static str> {
    let level = match generation {
        RarGeneration::Rar1 | RarGeneration::Rar5 => method,
        RarGeneration::Rar4 => method.wrapping_sub(0x30),
    };
    Some(match level {
        0 => "store",
        1 => "fastest",
        2 => "fast",
        3 => "normal",
        4 => "good",
        5 => "best",
        _ => return None,
    })
}

/// Describe one entry for the analysis.
fn describe(generation: RarGeneration, entry: &RarEntry) -> Entry {
    // RAR has no pseudo-encryption: an entry that is marked is encrypted
    let state = if entry.encryption == RarEncryption::None { State::Plain } else { State::Encrypted };
    let mut described = Entry::new(entry.kind, state);
    described.name = Some(entry.name_lossy());
    described.protection = protection(entry);
    described.method = Some(Method { name: method_name(generation, entry.method).map(str::to_owned), number: Some(u64::from(entry.method)) });
    described.packed = Some(entry.packed);
    described.size = entry.unpacked;
    described.split = Some(Split::from_flags(entry.split_before, entry.split_after));
    described
}

/// The headers of a RAR 3 or 4 archive are encrypted: say how, and build the line from the
/// end of archive block, or put down that it was not found.
fn rar_30_headers(source: &Source, salt_at: u64, volume: bool, parts: &mut Parts) -> anyhow::Result<()> {
    let salt = header_salt(source, salt_at).map_or(Salt::Unknown, |salt| Salt::Known(salt.to_vec()));
    // the line tests that the end block decrypts to what an end block holds
    parts.headers = HeaderState::Encrypted(Protection { scheme: Scheme::Rar30, parameters: rar_30_parameters(vec![Check::structure()]), salt });

    let Some(end) = end_block(source, salt_at, volume) else {
        tracing::warn!("{}: the headers are encrypted, and no end of archive block under their salt was found in the last bytes of the file: it is cut short, or more than a few kilobytes follow the archive", source.path().display());
        parts.no_line.push(Missing::for_scheme(Scheme::Rar30, NoLine::Unreadable));
        return Ok(());
    };
    let line = Line::new(rar_30_header_line(&end), None, Proves::Structural)?;
    // the short end block of a volume holds what the line tests only when no volume follows
    let note = if volume && end.data.len() < 32 { Some(Note::VolumeEndBlock) } else { (end.trailing > 0).then_some(Note::BehindEndBlock { count: end.trailing }) };
    parts.lines.push(match note {
        Some(note) => line.with_note(note),
        None => line,
    });
    Ok(())
}

/// The headers of a RAR 5 archive are encrypted: say how, and build the line from the check
/// value of the encryption header, or from the first encrypted header when it has none.
fn rar_50_headers(source: &Source, crypt: &Rar50Record, block_at: u64, parts: &mut Parts) -> anyhow::Result<()> {
    let check = if crypt.check_value.is_some() { Check::new(CheckKind::CheckValue, 64) } else { Check::structure() };
    parts.headers = HeaderState::Encrypted(Protection { scheme: Scheme::Rar50, parameters: rar_50_parameters(crypt, vec![check]), salt: Salt::Known(crypt.salt.to_vec()) });
    if crypt.unused == Some(Unused::Damaged) {
        parts.findings.push(Finding::new(Found::CheckValueDamaged, Vec::new()));
    }

    if let Err(case) = rounds_fit(crypt) {
        parts.no_line.push(Missing::for_scheme(Scheme::Rar50, case));
    } else if let Some(value) = crypt.check_value {
        parts.lines.push(Line::new(check_value_line(crypt, value), None, Proves::Exact)?);
    } else if let Some(text) = rar_50_header_line(source, crypt, block_at) {
        // without a check value, the line tests that the first encrypted header decrypts to a header
        parts.lines.push(Line::new(text, None, Proves::Structural)?);
    } else {
        tracing::warn!("{}: the headers are encrypted without a check value, and the file ends before the first of them does", source.path().display());
        parts.no_line.push(Missing::for_scheme(Scheme::Rar50, NoLine::Unreadable));
    }
    Ok(())
}

/// Build the lines of the entries that are encrypted on their own: for each scheme the line of
/// its best entry, or a line for every entry. An entry whose headers allow no line is put down
/// with its reason, always; so is one that was tried and whose data could not be read.
fn entry_lines(source: &Source, archive: &RarArchive, wanted: Lines, parts: &mut Parts) -> anyhow::Result<()> {
    let all = wanted == Lines::All;
    // every encrypted entry, held against what the mode of its scheme loads
    let assessed: Vec<(usize, Scheme, Result<Candidate, NoLine>)> = archive.entries.iter().enumerate().filter_map(|(index, entry)| Some((index, entry.encryption.scheme()?, assess(entry, source.len())?))).collect();

    // the ones that can give a line, the best first, and in the order of the archive among equals
    let mut ranked: Vec<(usize, Scheme, Candidate)> = assessed.iter().filter_map(|(index, scheme, outcome)| outcome.as_ref().ok().map(|candidate| (*index, *scheme, *candidate))).collect();
    ranked.sort_by_key(|&(_, _, candidate)| candidate.rank);

    // When the best entry of a scheme gives no line, the next one is tried.
    let mut served = BTreeSet::new();
    let mut failed = BTreeSet::new();
    for (index, scheme, candidate) in ranked {
        let Some(entry) = archive.entries.get(index).filter(|_| all || !served.contains(&scheme)) else { continue };
        let text = match candidate.plan {
            Plan::CheckValue { crypt, value } => Ok(check_value_line(&crypt, value)),
            Plan::Data { line, unpacked } => data_line(source, entry, line, unpacked),
        };
        match text {
            Ok(text) => {
                let line = Line::new(text, Some(index), candidate.proves)?;
                parts.lines.push(match candidate.note {
                    Some(note) => line.with_note(note),
                    None => line,
                });
                let _ = served.insert(scheme);
            },
            Err(error) => {
                tracing::warn!("{}: {}: its data cannot be read: {error}", source.path().display(), entry.name_lossy());
                let _ = failed.insert(index);
            },
        }
    }

    for (index, scheme, outcome) in assessed {
        // a scheme without a mode says so once for the archive, below
        if matches!(scheme, Scheme::Rar13 | Scheme::RarUnknown) {
            continue;
        }
        let why = match outcome {
            Err(why) => why,
            Ok(_) if failed.contains(&index) => NoLine::Unreadable,
            Ok(_) => continue,
        };
        // An entry that cannot give a line has its reason always, so that what is said of it
        // does not hang on the entries around it.
        parts.no_line.push(Missing::for_entry(scheme, index, why));
    }

    for scheme in [Scheme::Rar13, Scheme::RarUnknown] {
        if archive.entries.iter().any(|entry| entry.encryption.scheme() == Some(scheme)) {
            let why = match scheme {
                Scheme::RarUnknown => NoLine::UnknownScheme,
                // the key search reads the container of RAR 1.3 and 1.4 and no other
                _ if archive.generation == RarGeneration::Rar1 => NoLine::KeySearch,
                _ => NoLine::NoMode(scheme),
            };
            parts.no_line.push(Missing::for_scheme(scheme, why));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::super::testing::rar1;
    use super::super::testing::rar4;
    use super::super::testing::rar5;
    use super::*;
    use crate::analysis::Analysis;
    use crate::analysis::Coverage;
    use crate::analysis::Entries;
    use crate::analysis::EntryKind;
    use crate::analysis::Headers;
    use crate::analysis::Reason;
    use crate::line::Tag;

    fn fixture(rel: &str, wanted: Lines) -> Analysed {
        let source = Source::open(Path::new(&format!("tests/fixtures/{rel}")), 0).unwrap();
        analyse(&source, wanted).unwrap()
    }

    fn bytes_of(rel: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/{rel}")).unwrap()
    }

    fn analysed(archive: Vec<u8>, wanted: Lines) -> Analysed {
        analyse(&Source::from_bytes(archive), wanted).unwrap()
    }

    fn codes(analysis: &Analysis) -> Vec<&'static str> {
        analysis.findings.iter().map(Finding::code).collect()
    }

    fn texts(lines: &[Line]) -> Vec<&str> {
        lines.iter().map(|line| line.text.as_str()).collect()
    }

    /// The one entry of an archive, the cases in which it got no line, and its lines.
    fn only_entry(archive: Vec<u8>) -> (Vec<NoLine>, Vec<Line>) {
        let Analysed { analysis, lines } = analysed(archive, Lines::Best);
        assert_eq!(analysis.entry_list.len(), 1);
        assert_eq!(analysis.entry_list[0].state, State::Encrypted, "an entry that is marked is encrypted, with a line or without");
        assert!(analysis.no_line.iter().all(|missing| missing.entry == Some(0)));
        (analysis.no_line.into_iter().map(|missing| missing.why).collect(), lines)
    }

    /// A RAR 3 archive of one encrypted entry: these flags besides the one for a password,
    /// this header, and the data that follows it.
    fn rar4_entry(flags: u16, head: &rar4::Head<'_>, data: &[u8]) -> Vec<u8> {
        rar4::archive(&[rar4::main(0), rar4::file(rar4::FILE, flags | rar4::PASSWORD, head, data), rar4::end()])
    }

    /// The header of a RAR 3 entry with a salt of 0xA5.
    fn salted(method: u8, packed: u32, unpacked: u32) -> rar4::Head<'static> {
        rar4::Head { method, packed, unpacked, tail: &[0xA5; 8], ..rar4::Head::default() }
    }

    /// A RAR 5 archive of these blocks behind a main header.
    fn rar5_of(blocks: Vec<Vec<u8>>) -> Vec<u8> {
        let mut all = vec![rar5::main(&[0])];
        all.extend(blocks);
        all.push(rar5::end());
        rar5::archive(&all)
    }

    /// An encrypted RAR 5 file: these flags and this count in its encryption record.
    fn rar5_file<'a>(name: &'a [u8], crypt_flags: u8, lg2count: u8, unpacked: u64, data: &'a [u8]) -> rar5::Entry<'a> {
        rar5::Entry { name, unpacked, records: vec![rar5::crypt_record(crypt_flags, lg2count)], data, ..rar5::Entry::default() }
    }

    // --- the headers ---

    #[test]
    fn encrypted_headers_hide_the_entries_and_name_their_scheme() {
        let Analysed { analysis, lines } = fixture("rar-50/v730_hp_m5.rar", Lines::Best);
        assert_eq!((analysis.format, analysis.generation), (Format::Rar, Generation::Rar5));
        assert_eq!((analysis.headers, analysis.entries, analysis.coverage), (Headers::Encrypted, Entries::Hidden, Coverage::Unknown));
        assert!(analysis.entry_list.is_empty());
        assert_eq!(analysis.volume, None, "the header that says whether this is a volume is encrypted");

        let scheme = &analysis.schemes[0];
        assert_eq!((scheme.scheme, scheme.parameters.cipher, scheme.parameters.key_bits), (Scheme::Rar50, Some(Cipher::Aes), Some(256)));
        assert_eq!(scheme.parameters.kdf, Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 15) }));
        assert_eq!(scheme.parameters.check, [Check::new(CheckKind::CheckValue, 64)]);

        // one line, from the headers and from no entry, on the check value
        assert_eq!(lines.len(), 1);
        assert_eq!((lines[0].tag, lines[0].mode, lines[0].entry, lines[0].proves, lines[0].note), (Tag::Rar50, 46800, None, Proves::Exact, None));
    }

    #[test]
    fn encrypted_headers_of_rar_5_without_a_check_value_are_tested_by_their_structure() {
        let Analysed { analysis, lines } = fixture("rar-50/nocheck_hp_m0.rar", Lines::Best);
        assert_eq!(analysis.schemes[0].parameters.check, [Check::structure()]);
        assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, None, Proves::Structural));
        assert!(lines[0].text.starts_with("$rar$50$*1*") && lines[0].text.contains("**4**100*100*0*"), "{}", lines[0].text);

        // an archive that ends behind its encryption header has nothing to test
        let cut = analysed(rar5::archive(&[rar5::crypt_header(0, 0, 15), vec![0x77; 20]]), Lines::Best);
        assert!(cut.lines.is_empty());
        assert_eq!(cut.analysis.no_line, [Missing::for_scheme(Scheme::Rar50, NoLine::Unreadable)]);
        assert_eq!(cut.analysis.headers, Headers::Encrypted);
    }

    #[test]
    fn a_rar_3_header_line_rests_on_structure_and_names_its_salt() {
        let bytes = bytes_of("rar-30/v420_hp_m3.rar");
        let Analysed { analysis, lines } = analysed(bytes.clone(), Lines::Best);
        assert_eq!((analysis.generation, analysis.headers, analysis.volume), (Generation::Rar4, Headers::Encrypted, Some(Volume::Single)));
        let scheme = &analysis.schemes[0];
        assert_eq!((scheme.scheme, scheme.parameters.key_bits, &scheme.parameters.check), (Scheme::Rar30, Some(128), &vec![Check::structure()]));
        assert_eq!(scheme.parameters.kdf, Some(Kdf { name: KdfName::Sha1, rounds: Some(262_144) }));
        assert_eq!((lines.len(), lines[0].tag, lines[0].entry, lines[0].proves, lines[0].note), (1, Tag::Rar30, None, Proves::Structural, None));

        // the salt stands behind the main header, and the block is the last one under it
        let expected = format!("$rar$30$*0*{}*c43d7b00*10*10*0*{}$/rar$", hex::encode(&bytes[20..28]), hex::encode(&bytes[bytes.len() - 16..]));
        assert_eq!(lines[0].text, expected);
    }

    /// What follows the archive in its file is not the archive: the line is the one of the
    /// archive alone. The salt and the block used to be the last 24 bytes of the file.
    #[test]
    fn the_line_of_encrypted_rar_3_headers_does_not_change_with_what_is_appended() {
        let bytes = bytes_of("rar-30/v420_hp_m3.rar");
        let alone = analysed(bytes.clone(), Lines::Best).lines;

        for appended in [&[0_u8; 8][..], &[0x1A], &[0xFF; 24], &[0; 2048]] {
            let mut longer = bytes.clone();
            longer.extend_from_slice(appended);
            let Analysed { analysis, lines } = analysed(longer, Lines::Best);
            assert_eq!(texts(&lines), texts(&alone), "{} bytes appended", appended.len());
            assert_eq!(lines[0].note, Some(Note::BehindEndBlock { count: u64::try_from(appended.len()).unwrap() }));
            assert!(analysis.no_line.is_empty());
        }
    }

    #[test]
    fn a_volume_with_encrypted_headers_gives_the_line_of_its_end_block() {
        let salt = [0x51, 0xA7, 0x00, 0x33, 0xC0, 0xDE, 0x42, 0x99];
        let volume = |main_flags: u16, end: &[u8]| {
            let mut bytes = rar4::archive(&[rar4::main(main_flags | rar4::HEADERS_ENCRYPTED)]);
            bytes.extend_from_slice(&salt);
            bytes.extend_from_slice(&[0x11; 4000]);
            bytes.extend_from_slice(&salt);
            bytes.extend_from_slice(end);
            analysed(bytes, Lines::Best)
        };

        // RAR 3.10 and later end a volume in a block of 20 bytes, which encrypts to 32: the
        // line carries both blocks, and the salt in front of them
        let long = volume(rar4::VOLUME, &[0xE0; 32]);
        assert_eq!(texts(&long.lines), [format!("$rar$30$*0*51a70033c0de4299*c43d7b00*20*20*0*{}$/rar$", "e0".repeat(32))]);
        assert_eq!((long.lines[0].note, long.analysis.volume), (None, Some(Volume::Later)));
        assert_eq!(long.analysis.schemes[0].parameters.check, [Check::structure()]);

        // before that a volume ended in the short block, which holds what the line tests in
        // the last volume only: the line says so
        let short = volume(rar4::VOLUME, &[0xE0; 16]);
        assert_eq!(texts(&short.lines), [format!("$rar$30$*0*51a70033c0de4299*c43d7b00*10*10*0*{}$/rar$", "e0".repeat(16))]);
        assert_eq!(short.lines[0].note, Some(Note::VolumeEndBlock));

        // the same bytes in an archive that is no volume: 16 of them are the block
        let single = volume(0, &[0xE0; 32]);
        assert!(single.lines[0].text.contains("*10*10*0*"));
        assert_eq!((single.lines[0].note, single.analysis.volume), (Some(Note::BehindEndBlock { count: 16 }), Some(Volume::Single)));
    }

    #[test]
    fn encrypted_rar_3_headers_without_an_end_block_have_a_reason_and_keep_their_salt() {
        let mut bytes = rar4::archive(&[rar4::main(rar4::HEADERS_ENCRYPTED)]);
        bytes.extend_from_slice(&[0xD1; 8]);
        bytes.extend((0..200_000_u32).map(|at| u8::try_from(at % 251).unwrap()));
        let Analysed { analysis, lines } = analysed(bytes, Lines::Best);

        assert!(lines.is_empty());
        assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::Rar30, NoLine::Unreadable)]);
        assert_eq!(analysis.no_line[0].reason(), Reason::Damaged);
        assert_eq!((analysis.headers, analysis.entries), (Headers::Encrypted, Entries::Hidden));
        assert_eq!(serde_json::to_value(&analysis).unwrap()["schemes"][0]["scheme"], "rar-30");
    }

    // --- parameters its own software refuses ---

    #[test]
    fn a_round_count_rar_refuses_is_encrypted_and_has_no_line() {
        // an entry: encrypted, named, with its parameters and the finding
        let bytes = rar5_of(vec![rar5_file(b"slow.txt", rar5::CHECK_VALUE, 25, 9, &[0x5A; 16]).block(), rar5::Entry { name: b"plain.txt", unpacked: 1, data: b"a", ..rar5::Entry::default() }.block()]);
        for wanted in [Lines::Best, Lines::All] {
            let Analysed { analysis, lines } = analysed(bytes.clone(), wanted);
            assert!(lines.is_empty());
            let entry = &analysis.entry_list[0];
            assert_eq!((entry.state, entry.protection.as_ref().unwrap().scheme), (State::Encrypted, Scheme::Rar50));
            assert_eq!(entry.protection.as_ref().unwrap().parameters.kdf, Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 25) }));
            assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::Rar50, 0, NoLine::RoundsRefused { power: 25 })]);
            assert_eq!(analysis.no_line[0].reason(), Reason::UnsupportedParameters);
            assert_eq!(codes(&analysis), ["partial", "unsupported-parameters"]);
            assert_eq!(analysis.findings[1].entries, [0]);
        }

        // beside an entry that gives the line, it is still said
        let mixed = rar5_of(vec![rar5_file(b"slow.txt", rar5::CHECK_VALUE, 25, 9, &[0x5A; 16]).block(), rar5_file(b"fine.txt", rar5::CHECK_VALUE, 15, 9, &[0x5A; 16]).block()]);
        let Analysed { analysis, lines } = analysed(mixed, Lines::Best);
        assert_eq!((lines.len(), lines[0].entry), (1, Some(1)));
        assert_eq!(codes(&analysis), ["unsupported-parameters"]);

        // the headers: encrypted, with their parameters, and no line
        let Analysed { analysis, lines } = analysed(rar5::archive(&[rar5::crypt_header(0, rar5::CHECK_VALUE, 25), vec![0x77; 64]]), Lines::Best);
        assert!(lines.is_empty());
        assert_eq!((analysis.headers, analysis.entries), (Headers::Encrypted, Entries::Hidden));
        assert_eq!(analysis.schemes[0].parameters.kdf, Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 25) }));
        assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::Rar50, NoLine::RoundsRefused { power: 25 })]);
        assert_eq!(codes(&analysis), ["unsupported-parameters"]);
    }

    #[test]
    fn a_round_count_below_what_the_mode_loads_has_no_line() {
        let (missing, lines) = only_entry(rar5_of(vec![rar5_file(b"a", rar5::CHECK_VALUE, 0, 9, &[0x5A; 16]).block()]));
        assert_eq!((missing.as_slice(), lines.len()), (&[NoLine::RoundsBelowMode { power: 0 }][..], 0));
        assert_eq!(missing[0].reason(), Reason::OverLimit);
    }

    #[test]
    fn an_encryption_version_the_tool_does_not_know_is_encrypted_under_an_unknown_scheme() {
        let mut record = rar5::crypt_record(rar5::CHECK_VALUE, 15);
        record[1] = 3;
        let bytes = rar5_of(vec![rar5::Entry { name: b"new.txt", unpacked: 9, records: vec![record], data: &[0x5A; 16], ..rar5::Entry::default() }.block()]);
        let Analysed { analysis, lines } = analysed(bytes, Lines::All);
        assert!(lines.is_empty());
        let entry = &analysis.entry_list[0];
        let protection = entry.protection.as_ref().unwrap();
        assert_eq!((entry.state, protection.scheme, protection.parameters.identifier), (State::Encrypted, Scheme::RarUnknown, Some(3)));
        assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::RarUnknown, NoLine::UnknownScheme)]);
        assert_eq!(analysis.no_line[0].reason(), Reason::UnknownScheme);
        assert_eq!(analysis.findings, [Finding::new(Found::UnknownScheme { identifier: Some(3) }, vec![0])]);
        assert_eq!(analysis.coverage, Coverage::All);

        // the headers
        let Analysed { analysis, lines } = analysed(rar5::archive(&[rar5::crypt_header(2, 0, 15), vec![0x77; 64]]), Lines::Best);
        assert!(lines.is_empty());
        assert_eq!((analysis.headers, analysis.entries, analysis.generation), (Headers::Encrypted, Entries::Hidden, Generation::Rar5));
        assert_eq!((analysis.schemes[0].scheme, analysis.schemes[0].parameters.identifier), (Scheme::RarUnknown, Some(2)));
        assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::RarUnknown, NoLine::UnknownScheme)]);
        assert_eq!(analysis.findings, [Finding::new(Found::UnknownScheme { identifier: Some(2) }, Vec::new())]);
    }

    #[test]
    fn an_encryption_record_that_is_cut_short_is_encrypted_and_damaged() {
        let mut record = rar5::crypt_record(0, 15);
        record.truncate(12);
        let (missing, lines) = only_entry(rar5_of(vec![rar5::Entry { unpacked: 9, records: vec![record], data: &[0x5A; 16], ..rar5::Entry::default() }.block()]));
        assert_eq!((missing.as_slice(), lines.len()), (&[NoLine::Unreadable][..], 0));

        // the encryption header
        let mut header = vec![4, 0];
        header.extend_from_slice(&rar5::crypt_fields(0, 0, 15, false)[..10]);
        let Analysed { analysis, lines } = analysed(rar5::archive(&[rar5::block(&header), vec![0x77; 64]]), Lines::Best);
        assert!(lines.is_empty());
        assert_eq!((analysis.headers, analysis.schemes[0].scheme), (Headers::Encrypted, Scheme::Rar50));
        assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::Rar50, NoLine::Unreadable)]);

        // the salt of a RAR 3 entry
        let (missing, lines) = only_entry(rar4_entry(rar4::SALT, &rar4::Head { packed: 16, unpacked: 9, tail: &[1, 2, 3], ..rar4::Head::default() }, &[0x5A; 16]));
        assert_eq!((missing.as_slice(), lines.len()), (&[NoLine::Unreadable][..], 0));
    }

    // --- which entry gets the line ---

    #[test]
    fn an_entry_built_in_memory_gives_a_line() {
        let Analysed { analysis, lines } = analysed(rar4_entry(rar4::SALT, &salted(0x30, 32, 20), &[0x5A; 32]), Lines::Best);
        assert_eq!((lines.len(), lines[0].tag, lines[0].entry, lines[0].proves, lines[0].note), (1, Tag::Rar30, Some(0), Proves::Exact, None));
        assert_eq!(lines[0].text, format!("$rar$30$*1*a5a5a5a5a5a5a5a5*cafef00d*20*14*30*{}$/rar$", "5a".repeat(32)));
        let protection = analysis.entry_list[0].protection.as_ref().unwrap();
        assert_eq!((protection.scheme, &protection.salt, &protection.parameters.check), (Scheme::Rar30, &Salt::Known(vec![0xA5; 8]), &vec![Check::new(CheckKind::Crc32, 32)]));
        assert!(analysis.no_line.is_empty() && analysis.findings.is_empty());
        assert_eq!(analysis.volume, Some(Volume::Single));
    }

    /// A zeroed check value on a service record, and one whose checksum is wrong, are no check
    /// values. Such an entry used to rank first and leave the archive without a line.
    #[test]
    fn a_check_value_that_cannot_be_used_does_not_stand_in_the_way_of_the_next_entry() {
        let zeroed = || {
            // the value is zero and its checksum is the one of zero: only the kind of record says no
            let mut record = rar5::crypt_record(rar5::CHECK_VALUE, 15);
            record[36..44].fill(0);
            record[44..48].copy_from_slice(&rar5::checksum_of([0; 8]));
            rar5::Entry { head_type: rar5::SERVICE, name: b"STM", unpacked: 9, records: vec![record], data: &[0x5A; 16], ..rar5::Entry::default() }
        };
        let damaged = || {
            let mut record = rar5::crypt_record(rar5::CHECK_VALUE, 15);
            record[47] ^= 1;
            rar5::Entry { name: b"damaged.txt", unpacked: 9, records: vec![record], data: &[0x4C; 16], ..rar5::Entry::default() }
        };
        let good = rar5_file(b"good.txt", rar5::CHECK_VALUE, 15, 9, &[0x6B; 16]);

        let Analysed { analysis, lines } = analysed(rar5_of(vec![zeroed().block(), damaged().block(), good.block()]), Lines::Best);
        assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, Some(2), Proves::Exact));
        assert!(lines[0].text.starts_with("$rar$50$*0*") && lines[0].text.ends_with("*aaaaaaaaaaaaaaaa*0*****$/rar$"), "{}", lines[0].text);
        assert!(analysis.no_line.is_empty());
        // what a password can be tested against is said for each entry as it is
        let checks: Vec<usize> = analysis.entry_list.iter().map(|entry| entry.protection.as_ref().unwrap().parameters.check.len()).collect();
        assert_eq!(checks, [1, 1, 2]);
        // and the variant says what the archive stores: all three store a check value
        let variants: Vec<String> = analysis.entry_list.iter().map(|entry| entry.variant().unwrap()).collect();
        assert_eq!(variants, ["rar-50:data:check", "rar-50:data:check", "rar-50:data:check"]);
        // the one that fails its own checksum is damage and is said; the zero of an old service record is not
        assert_eq!(analysis.findings, [Finding::new(Found::CheckValueDamaged, vec![1])]);

        // every entry is asked: the two are tested by their data, as UnRAR tests them
        let all = analysed(rar5_of(vec![zeroed().block(), damaged().block(), good.block()]), Lines::All).lines;
        assert_eq!(all.iter().map(|line| line.entry).collect::<Vec<_>>(), [Some(2), Some(0), Some(1)]);
        assert!(all[1].text.starts_with("$rar$50$*1*") && all[1].text.contains("**0*cafef00d*10*9*0*5a5a"), "{}", all[1].text);

        // alone, such an entry gives its own line, or the reason its data has
        let alone = analysed(rar5_of(vec![zeroed().block()]), Lines::Best);
        assert_eq!((alone.lines.len(), alone.lines[0].entry), (1, Some(0)));
        let empty = rar5::Entry { data: &[], unpacked: 0, ..zeroed() };
        let (missing, lines) = only_entry(rar5_of(vec![empty.block()]));
        assert_eq!((missing.as_slice(), lines.len()), (&[NoLine::ZeroCheckValue][..], 0), "nothing to test in the place of the check value");
        assert_eq!(missing[0].reason(), Reason::NoData);
        let spoiled = rar5::Entry { data: &[], unpacked: 0, ..damaged() };
        let (missing, lines) = only_entry(rar5_of(vec![spoiled.block()]));
        assert_eq!((missing.as_slice(), lines.len()), (&[NoLine::CheckValueDamaged][..], 0));
        assert_eq!(missing[0].reason(), Reason::Damaged);
    }

    #[test]
    fn encrypted_headers_whose_check_value_is_damaged_keep_their_name_and_say_so() {
        let mut header = rar5::crypt_header(0, 1, 15);
        // the last byte of the checksum of the check value, and the CRC-32 of the header set right again
        let last = header.len() - 1;
        header[last] ^= 1;
        let sized = header[4..].to_vec();
        header[..4].copy_from_slice(&crc32fast::hash(&sized).to_le_bytes());
        let mut blocks = vec![header];
        blocks.push(vec![0x77; 64]);
        let Analysed { analysis, lines } = analysed(rar5::archive(&blocks), Lines::Best);
        assert_eq!(analysis.schemes[0].variant, "rar-50:headers:check", "the archive stores a check value");
        assert_eq!(analysis.schemes[0].parameters.check, [Check::structure()], "and a password is not tested against it");
        assert_eq!(analysis.findings, [Finding::new(Found::CheckValueDamaged, Vec::new())]);
        assert_eq!((lines.len(), lines[0].proves), (1, Proves::Structural));
    }

    #[test]
    fn the_fixture_with_a_zeroed_check_value_gets_the_line_of_its_next_entry() {
        let Analysed { analysis, lines } = fixture("regress/rar/service_zero_check_value.rar", Lines::Best);
        assert_eq!(lines.len(), 1);
        let from = &analysis.entry_list[lines[0].entry.unwrap()];
        assert_eq!((from.kind, lines[0].proves), (EntryKind::File, Proves::Exact));
        assert!(lines[0].text.starts_with("$rar$50$*0*"));
        assert!(analysis.no_line.is_empty());
        assert!(analysis.entry_list.iter().any(|entry| entry.kind == EntryKind::Service && entry.state == State::Encrypted));
    }

    #[test]
    fn every_scheme_of_an_archive_gets_the_line_of_its_best_entry() {
        let old = rar4::Head { unp_ver: 20, packed: 32, unpacked: 20, ..rar4::Head::default() };
        let older = rar4::Head { unp_ver: 15, packed: 20, unpacked: 20, ..rar4::Head::default() };
        let bytes = rar4::archive(&[rar4::main(0), rar4::encrypted(b"packed.txt", 0x33, 900, &[0x11; 64]), rar4::file(rar4::FILE, rar4::PASSWORD, &old, &[0x22; 32]), rar4::encrypted(b"stored.txt", 0x30, 40, &[0x33; 48]), rar4::file(rar4::FILE, rar4::PASSWORD, &older, &[0x44; 20]), rar4::end()]);
        let Analysed { analysis, lines } = analysed(bytes.clone(), Lines::Best);
        // one line for each scheme: of the two under RAR 3 the stored one
        assert_eq!(lines.iter().map(|line| (line.tag, line.entry)).collect::<Vec<_>>(), [(Tag::Rar15, Some(3)), (Tag::Rar20, Some(1)), (Tag::Rar30, Some(2))]);
        assert!(analysis.no_line.is_empty());
        assert!(analysis.mixed);
        assert_eq!(codes(&analysis), ["mixed-schemes"]);
        // the two entries under RAR 3 share their salt, and so their key
        assert_eq!(analysis.entry_list.iter().map(|entry| entry.key_group).collect::<Vec<_>>(), [Some(1), Some(2), Some(1), Some(3)]);

        let all = analysed(bytes, Lines::All).lines;
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn a_line_on_fewer_than_four_bytes_is_weak_and_the_last_to_be_picked() {
        let tiny = rar4::encrypted(b"tiny.txt", 0x30, 2, &[0x11; 16]);
        let large = rar4::encrypted(b"large.txt", 0x33, 90_000, &[0x22; 4096]);

        let Analysed { analysis, lines } = analysed(rar4::archive(&[rar4::main(0), tiny.clone(), large, rar4::end()]), Lines::Best);
        assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, Some(1), Proves::Exact));
        assert!(analysis.findings.is_empty());

        // when it is all there is, the line is written and said to be weak
        let Analysed { analysis, lines } = analysed(rar4::archive(&[rar4::main(0), tiny, rar4::end()]), Lines::Best);
        assert_eq!((lines.len(), lines[0].proves, lines[0].note), (1, Proves::Weak { bits: 16 }, Some(Note::ShortEntry { size: 2 })));
        assert_eq!(analysis.findings, [Finding::new(Found::WeakCheck { bits: 16 }, vec![0])]);
    }

    // --- headers that are damaged ---

    /// The codes and the sentences of the findings.
    fn findings(analysis: &Analysis) -> Vec<(&'static str, String)> {
        analysis.findings.iter().map(|finding| (finding.code(), finding.found.to_string())).collect()
    }

    #[test]
    fn headers_that_stop_before_the_file_does_are_damaged_and_nothing_is_said_of_the_rest() {
        // two encrypted entries behind a plain one whose header size is destroyed
        let plain = rar4::file(rar4::FILE, 0, &rar4::Head { name: b"plain.txt", packed: 4, unpacked: 4, ..rar4::Head::default() }, b"text");
        let sealed = rar4::file(rar4::FILE, rar4::PASSWORD | rar4::SALT, &salted(0x30, 32, 20), &[0x5A; 32]);
        let whole = rar4::archive(&[rar4::main(0), plain, sealed.clone(), sealed, rar4::end()]);
        let Analysed { analysis, lines } = analysed(whole.clone(), Lines::Best);
        assert_eq!((analysis.coverage, lines.len(), analysis.findings.len()), (Coverage::Some, 1, 1));

        let mut broken = whole.clone();
        let first_file = 7 + 13;
        broken[first_file + 5..first_file + 7].copy_from_slice(&3_u16.to_le_bytes());
        let Analysed { analysis, lines } = analysed(broken.clone(), Lines::Best);
        assert!(lines.is_empty() && analysis.entry_list.is_empty());
        assert_eq!(findings(&analysis), [("damaged", format!("the headers stop at offset 20, where {} bytes follow that are no header: what lies behind them is not listed", broken.len() - 20))]);
        assert_eq!(analysis.coverage, Coverage::Unknown, "two encrypted entries lie behind the damage: the archive is not reported as unencrypted");
        assert_eq!(analysis.volume, Some(Volume::Single));

        // a file header that is too short to be one, in the place of the second entry
        let mut short = rar4::archive(&[rar4::main(0), rar4::file(rar4::FILE, 0, &rar4::Head { packed: 4, unpacked: 4, ..rar4::Head::default() }, b"text")]);
        let at = short.len() as u64;
        short.extend_from_slice(&rar4::block(rar4::FILE, 0, &[0; 10]));
        let Analysed { analysis, .. } = analysed(short, Lines::Best);
        assert_eq!((analysis.entry_list.len(), analysis.coverage), (1, Coverage::Unknown));
        assert!(findings(&analysis)[0].1.starts_with(&format!("the headers stop at offset {at}, where 17 bytes follow")), "{:?}", analysis.findings);

        // an archive without an end block ends where the file does: that is no damage
        let open = rar4::archive(&[rar4::main(0), rar4::file(rar4::FILE, 0, &rar4::Head { packed: 4, unpacked: 4, ..rar4::Head::default() }, b"text")]);
        let Analysed { analysis, .. } = analysed(open, Lines::Best);
        assert_eq!((analysis.findings.len(), analysis.coverage), (0, Coverage::None));
        // and bytes behind an end block are none of the archive
        let mut padded = whole;
        padded.extend_from_slice(&[0; 300]);
        assert_eq!(analysed(padded, Lines::Best).analysis.findings.len(), 1, "the finding of the entry that is not encrypted, and no other");
    }

    #[test]
    fn a_header_that_fails_its_checksum_is_read_and_said_to_be_damaged() {
        let sealed = rar4::file(rar4::FILE, rar4::PASSWORD | rar4::SALT, &salted(0x30, 32, 20), &[0x5A; 32]);
        let whole = rar4::archive(&[rar4::main(0), sealed, rar4::end()]);
        assert!(analysed(whole.clone(), Lines::Best).analysis.findings.is_empty());
        let first_file = 7 + 13;

        // one bit of the flags of the file header: the entry is read as it stands
        let mut flipped = whole.clone();
        flipped[first_file + 4] ^= 0x10;
        let Analysed { analysis, lines } = analysed(flipped, Lines::Best);
        assert_eq!((analysis.entry_list.len(), lines.len(), analysis.coverage), (1, 1, Coverage::All));
        assert_eq!(findings(&analysis), [("damaged", "the header at offset 20 fails its checksum: what it says of its entry may be wrong".to_owned())]);

        // its type: the block is passed over as one the format does not have, and its
        // checksum says that an entry may be gone with it
        let mut retyped = whole.clone();
        retyped[first_file + 2] = 0x7C;
        let Analysed { analysis, lines } = analysed(retyped, Lines::Best);
        assert!(analysis.entry_list.is_empty() && lines.is_empty());
        assert_eq!(findings(&analysis).iter().map(|(code, _)| *code).collect::<Vec<_>>(), ["damaged"]);

        // the main header
        let mut main = whole;
        main[7 + 3] ^= 0x04;
        assert_eq!(findings(&analysed(main, Lines::Best).analysis)[0].1, "the header at offset 7 fails its checksum: what it says of its entry may be wrong");

        // an archive that RAR wrote, with one byte of a header changed, and one that is whole
        assert_eq!(codes(&fixture("unencrypted/bad-header-crc.rar", Lines::Best).analysis), ["damaged"]);
        for whole in ["rar-30/ttzip-core_test_read_format_rar4_encrypted.rar", "rar-15/rar15-password-compressed.rar", "rar-20/rar20-password-stored.rar", "unknown-pw/edge_rars_comment_psw.rar", "unencrypted/lhd-comment-dual-crc.rar"] {
            assert!(!codes(&fixture(whole, Lines::Best).analysis).contains(&"damaged"), "{whole}");
        }
    }

    #[test]
    fn the_headers_of_rar_5_are_held_to_the_same() {
        let whole = rar5_of(vec![rar5_file(b"a.txt", 1, 15, 20, &[0x5A; 32]).block()]);
        assert!(analysed(whole.clone(), Lines::Best).analysis.findings.is_empty());
        let first_file = 8 + rar5::main(&[0]).len();

        let mut flipped = whole.clone();
        flipped[first_file] ^= 0xFF;
        let Analysed { analysis, lines } = analysed(flipped, Lines::Best);
        assert_eq!((analysis.entry_list.len(), lines.len()), (1, 1), "the header is read as it stands");
        assert_eq!(findings(&analysis), [("damaged", format!("the header at offset {first_file} fails its checksum: what it says of its entry may be wrong"))]);

        let mut broken = whole;
        broken[first_file + 4] = 0;
        let Analysed { analysis, lines } = analysed(broken.clone(), Lines::Best);
        assert!(analysis.entry_list.is_empty() && lines.is_empty());
        assert_eq!(findings(&analysis), [("damaged", format!("the headers stop at offset {first_file}, where {} bytes follow that are no header: what lies behind them is not listed", broken.len() - first_file))]);
        assert_eq!(analysis.coverage, Coverage::Unknown);

        for whole in ["rar-50/v500_p_m0.rar", "rar-50/v730_p_m3.rar", "unencrypted/rars_rar5_stored.rar"] {
            assert!(!codes(&fixture(whole, Lines::Best).analysis).contains(&"damaged"), "{whole}");
        }
    }

    #[test]
    fn the_headers_of_rar_1_end_with_the_file_or_are_damaged() {
        let mut archive = rar1::main(0);
        archive.extend_from_slice(&rar1::file(b"A.TXT", rar1::PASSWORD, 0, 0, 4, 4, b"text"));
        assert!(!codes(&analysed(archive.clone(), Lines::Best).analysis).contains(&"damaged"));

        // a few bytes behind the last entry that are no file header
        let at = archive.len();
        archive.extend_from_slice(&[0; 9]);
        let analysis = analysed(archive, Lines::Best).analysis;
        assert_eq!(analysis.entry_list.len(), 1);
        assert!(findings(&analysis).contains(&("damaged", format!("the headers stop at offset {at}, where 9 bytes follow that are no header: what lies behind them is not listed"))), "{:?}", analysis.findings);
        assert_eq!(analysis.coverage, Coverage::Unknown, "one encrypted entry is listed, and what is not listed may be plain");
    }

    // --- the cases without a line ---

    #[test]
    fn an_entry_that_cannot_give_a_line_says_so_beside_one_that_does() {
        // two entries of `rar-30`: one with its salt, one without. The first gives the line of
        // the scheme, and the second has its reason all the same, in whichever order they stand.
        let salted = rar4::file(rar4::FILE, rar4::PASSWORD | rar4::SALT, &salted(0x30, 32, 20), &[0x5A; 32]);
        let bare = rar4::file(rar4::FILE, rar4::PASSWORD, &rar4::Head { name: b"bare.txt", packed: 32, unpacked: 20, ..rar4::Head::default() }, &[0x5A; 32]);
        for (blocks, good, refused) in [(vec![salted.clone(), bare.clone()], 0, 1), (vec![bare, salted], 1, 0)] {
            let mut all = vec![rar4::main(0)];
            all.extend(blocks);
            all.push(rar4::end());
            for wanted in [Lines::Best, Lines::All] {
                let Analysed { analysis, lines } = analysed(rar4::archive(&all), wanted);
                assert_eq!((lines.len(), lines[0].entry), (1, Some(good)));
                assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::Rar30, refused, NoLine::NoSalt)]);
                assert_eq!(analysis.entry_list[refused].line, Some(crate::analysis::EntryLine(Err(Reason::NotExpressible))));
            }
        }
    }

    #[test]
    fn an_entry_without_a_salt_has_no_line() {
        // the same entry with its salt gives a line: without one the line would carry zeros
        let (missing, lines) = only_entry(rar4_entry(0, &rar4::Head { packed: 32, unpacked: 20, ..rar4::Head::default() }, &[0x5A; 32]));
        assert_eq!((missing.as_slice(), lines.len()), (&[NoLine::NoSalt][..], 0));
        assert_eq!(missing[0].reason(), Reason::NotExpressible);

        let Analysed { analysis, .. } = fixture("regress/rar/rar3_no_salt.rar", Lines::All);
        assert_eq!(analysis.no_line.iter().map(|missing| missing.why.clone()).collect::<Vec<_>>(), [NoLine::NoSalt]);
        let protection = analysis.entry_list[0].protection.as_ref().unwrap();
        assert_eq!((protection.scheme, &protection.salt, analysis.entry_list[0].key_group), (Scheme::Rar30, &Salt::None, Some(1)));
    }

    #[test]
    fn every_case_of_an_entry_without_a_line_has_its_reason() {
        let case = |flags: u16, head: &rar4::Head<'_>, data: &[u8]| {
            let (missing, lines) = only_entry(rar4_entry(flags | rar4::SALT, head, data));
            assert!(lines.is_empty() && missing.len() == 1, "{missing:?}");
            (missing[0].clone(), missing[0].reason())
        };
        let high = [0, 0, 0, 0, 1, 0, 0, 0];

        assert_eq!(case(0, &salted(0x30, 16, 0), &[0x5A; 16]), (NoLine::Empty, Reason::NoData));
        assert_eq!(case(0, &salted(0x30, 0, 0), &[]), (NoLine::Empty, Reason::NoData));
        assert_eq!(case(rar4::SOLID, &salted(0x33, 32, 100), &[0x5A; 32]), (NoLine::SolidMember, Reason::NotExpressible));
        assert_eq!(case(0, &salted(0x33, 32, u32::MAX), &[0x5A; 32]), (NoLine::SizeUnknown, Reason::NotExpressible));
        assert_eq!(case(rar4::LARGE, &rar4::Head { high: &high, ..salted(0x33, 32, 7) }, &[0x5A; 32]), (NoLine::UnpacksTooLarge { size: (1 << 32) | 7, limit: 0xFFFF_FFFF }, Reason::OverLimit));
        assert_eq!(case(0, &salted(0x36, 32, 100), &[0x5A; 32]), (NoLine::Packing { name: "method 0x36".to_owned() }, Reason::OverLimit));
        assert_eq!(case(0, &salted(0x33, 30, 100), &[0x5A; 30]), (NoLine::NotWholeBlocks, Reason::Damaged));
        assert_eq!(case(0, &salted(0x30, 32, 33), &[0x5A; 32]), (NoLine::SizesDisagree, Reason::Damaged));
        // five megabytes are said to follow: none of them has to be there to say no
        let packed = 5 << 20;
        assert_eq!(case(0, &salted(0x30, packed, packed), &[]), (NoLine::TooLarge { packed: u64::from(packed), limit: 4 << 20 }, Reason::OverLimit));
    }

    #[test]
    fn an_entry_whose_data_is_not_all_there_is_damaged_and_the_archive_incomplete() {
        let bytes = rar4::archive(&[rar4::main(0), rar4::file(rar4::FILE, rar4::PASSWORD | rar4::SALT, &salted(0x30, 64, 60), &[0x5A; 10])]);
        let Analysed { analysis, lines } = analysed(bytes, Lines::Best);
        assert!(lines.is_empty());
        assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::Rar30, 0, NoLine::DataOutsideFile)]);
        assert_eq!(analysis.no_line[0].reason(), Reason::Damaged);
        assert_eq!((analysis.volume, analysis.entry_list[0].state), (Some(Volume::Incomplete), State::Encrypted));
        assert_eq!(codes(&analysis), ["incomplete"]);
    }

    #[test]
    fn rar_5_entries_without_a_line_have_their_reason() {
        let case = |entry: rar5::Entry<'_>| {
            let (missing, lines) = only_entry(rar5_of(vec![entry.block()]));
            assert!(lines.is_empty() && missing.len() == 1, "{missing:?}");
            (missing[0].clone(), missing[0].reason())
        };
        let plain = |unpacked: u64, data: &'static [u8]| rar5_file(b"a", 0, 15, unpacked, data);

        assert_eq!(case(plain(0, &[])), (NoLine::Empty, Reason::NoData));
        assert_eq!(case(rar5::Entry { crc32: None, ..plain(9, &[0x5A; 16]) }), (NoLine::NoChecksum, Reason::NoData));
        assert_eq!(case(rar5::Entry { file_flags: rar5::SIZE_UNKNOWN, compression: 0x0180, ..plain(0, &[0x5A; 16]) }), (NoLine::SizeUnknown, Reason::NotExpressible));
        assert_eq!(case(rar5::Entry { compression: 0x01C0, ..plain(900, &[0x5A; 16]) }), (NoLine::SolidMember, Reason::NotExpressible));
        assert_eq!(case(rar5::Entry { compression: 0x0300, ..plain(900, &[0x5A; 16]) }), (NoLine::Packing { name: "method 6".to_owned() }, Reason::OverLimit));
        assert_eq!(case(rar5::Entry { compression: 0x0182, ..plain(900, &[0x5A; 16]) }), (NoLine::Packing { name: "version 2 of the compression algorithm".to_owned() }, Reason::OverLimit));
        assert_eq!(case(plain(9, &[0x5A; 15])), (NoLine::NotWholeBlocks, Reason::Damaged));
        assert_eq!(case(plain(17, &[0x5A; 16])), (NoLine::SizesDisagree, Reason::Damaged));
        assert_eq!(case(rar5::Entry { flags: rar5::SPLIT_AFTER, ..plain(900, &[0x5A; 16]) }), (NoLine::Split, Reason::Split));
    }

    // --- volumes ---

    #[test]
    fn an_entry_that_continues_in_another_volume_has_no_line() {
        let Analysed { analysis, lines } = fixture("unknown-pw/edge_rars_split-encrypted.rar", Lines::Best);
        assert!(lines.is_empty());
        assert!(analysis.no_line.iter().all(|missing| missing.reason() == Reason::Split && missing.entry.is_some()), "{:?}", analysis.no_line);
        assert!(!analysis.no_line.is_empty());
        assert_eq!(analysis.volume, Some(Volume::First));
        let split = analysis.findings.iter().find(|finding| finding.code() == "split-entry").unwrap();
        assert!(!split.entries.is_empty());
        assert!(split.entries.iter().all(|&index| analysis.entry_list[index].split != Some(Split::No)));
    }

    #[test]
    fn a_later_volume_is_an_archive_and_gets_a_line_when_it_holds_a_check_value() {
        // the middle of a file: its header in this volume carries the encryption record
        let part = rar5::Entry { flags: rar5::SPLIT_BEFORE | rar5::SPLIT_AFTER, ..rar5_file(b"big.bin", rar5::CHECK_VALUE, 15, 900_000, &[0x5A; 64]) };
        let bytes = rar5::archive(&[rar5::main(&[3, 2]), part.block(), rar5::end()]);
        let Analysed { analysis, lines } = analysed(bytes, Lines::Best);
        assert_eq!((analysis.volume, analysis.entry_list[0].split), (Some(Volume::Later), Some(Split::Both)));
        assert_eq!((lines.len(), lines[0].entry, lines[0].proves), (1, Some(0), Proves::Exact));
        assert!(lines[0].text.starts_with("$rar$50$*0*"));
        assert_eq!(codes(&analysis), ["split-entry"]);

        // without a check value its data would be needed, and that is not all here
        let part = rar5::Entry { flags: rar5::SPLIT_BEFORE, ..rar5_file(b"big.bin", 0, 15, 900_000, &[0x5A; 64]) };
        let bytes = rar5::archive(&[rar5::main(&[3, 2]), part.block(), rar5::end()]);
        let Analysed { analysis, lines } = analysed(bytes, Lines::Best);
        assert!(lines.is_empty());
        assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::Rar50, 0, NoLine::Split)]);
        assert_eq!(analysis.entry_list[0].split, Some(Split::Before));

        // the later volumes of the fixtures: analysed, and nothing in them is encrypted
        for rel in ["unparseable/big.part2.rar", "unparseable/solid.part4.rar", "unparseable/test-documents.part3.rar"] {
            let later = fixture(rel, Lines::Best).analysis;
            assert_eq!((later.volume, later.coverage), (Some(Volume::Later), Coverage::None), "{rel}");
        }
        assert_eq!(fixture("unencrypted/big.part1.rar", Lines::Best).analysis.volume, Some(Volume::First));
    }

    // --- what an entry is ---

    #[test]
    fn rar_1_3_has_no_line_and_says_that_an_attack_applies() {
        let Analysed { analysis, lines } = fixture("rar-13/rar14-password-stored.rar", Lines::All);
        assert!(lines.is_empty());
        assert_eq!((analysis.generation, analysis.volume), (Generation::Rar1, Some(Volume::Single)));
        assert_eq!(analysis.no_line, [Missing::for_scheme(Scheme::Rar13, NoLine::KeySearch)], "an archive the key search reads");
        assert_eq!(analysis.no_line[0].reason(), Reason::NoMode);
        let weak = analysis.findings.iter().find(|finding| finding.code() == "weak-scheme").unwrap();
        assert!(weak.found.to_string().contains("attack rar-13"));

        // what a key is tested against is the 16-bit checksum of the entry
        let entry = &analysis.entry_list[0];
        assert_eq!(entry.protection.as_ref().unwrap().parameters.check, [Check::new(CheckKind::Checksum, 16)]);
        assert_eq!((entry.kind, entry.method.as_ref().unwrap().name.as_deref()), (EntryKind::File, Some("store")));
    }

    #[test]
    fn a_rar_1_4_archive_lists_its_directories_and_names_its_methods() {
        let mut bytes = rar1::main(0);
        bytes.extend_from_slice(&rar1::file(b"DOCS", 0, 0x10, 0, 0, 0, b""));
        bytes.extend_from_slice(&rar1::file(b"DOCS\\A.TXT", rar1::PASSWORD, 0x20, 3, 5, 900, b"abcde"));
        let Analysed { analysis, .. } = analysed(bytes, Lines::Best);
        let rows: Vec<(EntryKind, State, Option<&str>)> = analysis.entry_list.iter().map(|entry| (entry.kind, entry.state, entry.method.as_ref().and_then(|method| method.name.as_deref()))).collect();
        assert_eq!(rows, [(EntryKind::Directory, State::Plain, Some("store")), (EntryKind::File, State::Encrypted, Some("normal"))]);
        // a directory holds no data: the one file is encrypted, and that is all of them
        assert_eq!(analysis.coverage, Coverage::All);
    }

    #[test]
    fn the_comment_of_a_rar_1_4_archive_is_shown() {
        let plain = fixture("unencrypted/rar14_with_comment.rar", Lines::Best).analysis;
        assert_eq!(plain.comment.as_deref(), Some("ArchiveWolf RAR 1.4 test comment"));
        let packed = fixture("unencrypted/rar14_packed_comment.rar", Lines::Best).analysis;
        assert_eq!(packed.comment.as_deref(), Some("This is the archive comment."));
        assert!(!packed.is_encrypted(), "a comment under the fixed key is no encryption");
    }

    #[test]
    fn the_comment_of_a_rar_5_archive_is_shown_and_its_record_listed() {
        let Analysed { analysis, .. } = fixture("regress/rar/rar5_comment.rar", Lines::Best);
        assert_eq!(analysis.comment.as_deref(), Some("A short comment."));
        assert_eq!((analysis.entry_list[0].kind, analysis.entry_list[0].name.as_deref()), (EntryKind::Service, Some("CMT")));
    }

    #[test]
    fn the_service_records_of_rar_3_are_entries_and_do_not_count_for_coverage() {
        let Analysed { analysis, lines } = fixture("rar-15/rars_service_block_stored.rar", Lines::Best);
        let kinds: Vec<(EntryKind, State)> = analysis.entry_list.iter().map(|entry| (entry.kind, entry.state)).collect();
        assert_eq!(kinds, [(EntryKind::Service, State::Plain), (EntryKind::File, State::Encrypted)]);
        assert_eq!((analysis.coverage, lines[0].entry), (Coverage::All, Some(1)));
        assert!(analysis.findings.is_empty());
    }

    #[test]
    fn entries_under_one_salt_and_one_count_are_one_key_group() {
        let with_salt = |name: &'static [u8], salt: u8, lg2count: u8| {
            let mut record = rar5::crypt_record(rar5::CHECK_VALUE | rar5::KEYED, lg2count);
            record[4..20].fill(salt);
            rar5::Entry { name, unpacked: 9, records: vec![record, rar5::blake2_record()], data: &[0x5A; 16], ..rar5::Entry::default() }.block()
        };
        let bytes = rar5_of(vec![with_salt(b"a", 1, 15), with_salt(b"b", 1, 15), with_salt(b"c", 2, 15), with_salt(b"d", 1, 16), rar5::Entry { name: b"dir", file_flags: rar5::DIRECTORY, ..rar5::Entry::default() }.block()]);
        let Analysed { analysis, lines } = analysed(bytes, Lines::Best);

        assert_eq!(analysis.entry_list.iter().map(|entry| entry.key_group).collect::<Vec<_>>(), [Some(1), Some(1), Some(2), Some(3), None]);
        assert_eq!(analysis.schemes.iter().map(|row| (row.entries, row.key_groups)).collect::<Vec<_>>(), [(Some(3), Some(2)), (Some(1), Some(1))]);
        // a check value of 64 bits, and a digest of the data under a key
        assert_eq!(analysis.schemes[0].parameters.check, [Check::new(CheckKind::CheckValue, 64), Check::new(CheckKind::Blake2sp, 256).keyed()]);
        assert_eq!((analysis.entry_list[4].kind, analysis.entry_list[4].state, analysis.coverage), (EntryKind::Directory, State::Plain, Coverage::All));
        // the first of the cheapest: entries under one salt give the same line, written once
        assert_eq!((lines.len(), lines[0].entry), (1, Some(0)));
    }

    #[test]
    fn the_checks_of_an_entry_are_the_ones_its_header_stores() {
        let checks = |crypt_flags: u8, crc32: Option<u32>, digest: bool| {
            let mut records = vec![rar5::crypt_record(crypt_flags, 15)];
            if digest {
                records.push(rar5::blake2_record());
            }
            let bytes = rar5_of(vec![rar5::Entry { unpacked: 9, crc32, records, data: &[0x5A; 16], ..rar5::Entry::default() }.block()]);
            analysed(bytes, Lines::Best).analysis.entry_list[0].protection.clone().unwrap().parameters.check
        };
        let crc32 = Check::new(CheckKind::Crc32, 32);
        let digest = Check::new(CheckKind::Blake2sp, 256);
        assert_eq!(checks(0, Some(1), false), [crc32]);
        assert_eq!(checks(rar5::KEYED, Some(1), false), [crc32.keyed()]);
        assert_eq!(checks(0, Some(1), true), [digest]);
        assert_eq!(checks(rar5::CHECK_VALUE | rar5::KEYED, None, true), [Check::new(CheckKind::CheckValue, 64), digest.keyed()]);
        assert_eq!(checks(0, None, false), []);
    }

    #[test]
    fn an_archive_behind_a_program_is_found_and_its_offset_given() {
        let Analysed { analysis, lines } = fixture("rar-30/v420_p_m3_sfx.sfx", Lines::Best);
        assert_eq!((analysis.offset, analysis.generation), (244_864, Generation::Rar4));
        assert_eq!(lines.len(), 1);

        // a source that was opened at the archive says where that is
        let source = Source::open(Path::new("tests/fixtures/rar-30/v420_p_m3_sfx.sfx"), 244_864).unwrap();
        let behind = analyse(&source, Lines::Best).unwrap();
        assert_eq!(behind.analysis.offset, 244_864);
        assert_eq!(texts(&behind.lines), texts(&lines));
    }

    /// A file with a hole of a terabyte where the data of an entry is said to be. The hole
    /// costs no disk, and reading it would take longer than a test has.
    #[cfg(target_os = "linux")]
    fn with_a_hole(dir: &Path, name: &str, front: &[u8], back: &[u8]) -> Source {
        use std::io::Seek as _;
        use std::io::Write as _;

        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(front).unwrap();
        let _ = file.seek(std::io::SeekFrom::Current(1 << 40)).unwrap();
        file.write_all(back).unwrap();
        drop(file);
        Source::open(&path, 0).unwrap()
    }

    /// The archive is read by range: its headers, and the data of the entry that gives the
    /// line. An entry of a terabyte in front of that one is stepped over.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_data_of_an_entry_is_stepped_over_and_never_read() {
        const HUGE: u64 = 1 << 40;
        let dir = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();

        // RAR 5: a terabyte of encrypted data without a check value, then a small entry
        let huge = rar5::Entry { name: b"huge.bin", unpacked: HUGE, packed: Some(HUGE), records: vec![rar5::crypt_record(0, 15)], ..rar5::Entry::default() };
        let front = rar5::archive(&[rar5::main(&[0]), huge.block()]);
        let back = [rar5_file(b"small.txt", 0, 15, 9, &[0x5A; 16]).block(), rar5::end()].concat();
        let Analysed { analysis, lines } = analyse(&with_a_hole(dir.path(), "huge5.rar", &front, &back), Lines::All).unwrap();
        assert_eq!((analysis.entry_list.len(), analysis.volume, analysis.entry_list[0].packed), (2, Some(Volume::Single), Some(HUGE)));
        assert_eq!((lines.len(), lines[0].entry), (1, Some(1)));
        assert_eq!(analysis.no_line, [Missing::for_entry(Scheme::Rar50, 0, NoLine::TooLarge { packed: HUGE, limit: 4 << 20 })]);

        // RAR 3: the same, with the size in its two halves
        let head = rar4::Head { name: b"huge.bin", unpacked: 4096, high: &[0, 1, 0, 0, 0, 0, 0, 0], tail: &[0xA5; 8], ..rar4::Head::default() };
        let front = rar4::archive(&[rar4::main(0), rar4::file(rar4::FILE, rar4::PASSWORD | rar4::SALT | rar4::LARGE, &head, &[])]);
        let back = [rar4::encrypted(b"small.txt", 0x30, 9, &[0x5A; 16]), rar4::end()].concat();
        let Analysed { analysis, lines } = analyse(&with_a_hole(dir.path(), "huge3.rar", &front, &back), Lines::Best).unwrap();
        assert_eq!((analysis.entry_list.len(), analysis.volume, analysis.entry_list[0].packed), (2, Some(Volume::Single), Some(HUGE)));
        assert_eq!((lines.len(), lines[0].entry), (1, Some(1)));

        // RAR 3 with encrypted headers: the end block is looked for where the file ends
        let front = [rar4::archive(&[rar4::main(rar4::HEADERS_ENCRYPTED)]), vec![0xD1; 8], vec![0x11; 48]].concat();
        let back = [vec![0xD1; 8], vec![0xE0; 16]].concat();
        let lines = analyse(&with_a_hole(dir.path(), "huge-hp.rar", &front, &back), Lines::Best).unwrap().lines;
        assert_eq!(texts(&lines), [format!("$rar$30$*0*d1d1d1d1d1d1d1d1*c43d7b00*10*10*0*{}$/rar$", "e0".repeat(16))]);

        assert!(started.elapsed() < std::time::Duration::from_secs(20), "{:?}", started.elapsed());
    }

    /// The rows of the coverage table that have a line, each on an archive that RAR wrote: the
    /// scheme that is named, the line, what it proves, and whether it comes from the headers.
    #[test]
    fn every_row_of_the_coverage_table_with_a_line_gives_that_line() {
        for (rel, scheme, start, proves, from_headers) in [
            ("rar-15/rar15-password-stored.rar", Scheme::Rar15, "$rar$15$*", Proves::Exact, false),
            ("rar-15/rar15-password-compressed.rar", Scheme::Rar15, "$rar$15$*", Proves::Exact, false),
            ("rar-20/rar20-password-stored.rar", Scheme::Rar20, "$rar$20$*", Proves::Exact, false),
            ("rar-20/rar20-password-compressed.rar", Scheme::Rar20, "$rar$20$*", Proves::Exact, false),
            ("rar-30/v420_p_m0.rar", Scheme::Rar30, "$rar$30$*1*", Proves::Exact, false),
            ("rar-30/v420_p_m3.rar", Scheme::Rar30, "$rar$30$*1*", Proves::Exact, false),
            ("rar-30/v300_hp_m3.rar", Scheme::Rar30, "$rar$30$*0*", Proves::Structural, true),
            ("rar-50/v500_p_m0.rar", Scheme::Rar50, "$rar$50$*0*", Proves::Exact, false),
            ("rar-50/v730_p_m3.rar", Scheme::Rar50, "$rar$50$*0*", Proves::Exact, false),
            ("rar-50/nocheck_st_crc.rar", Scheme::Rar50, "$rar$50$*1*", Proves::Exact, false),
            ("rar-50/nocheck_m3_b2mac.rar", Scheme::Rar50, "$rar$50$*1*", Proves::Exact, false),
            ("rar-50/v700_hp_m3.rar", Scheme::Rar50, "$rar$50$*0*", Proves::Exact, true),
            ("rar-50/nocheck_hp_m3.rar", Scheme::Rar50, "$rar$50$*1*", Proves::Structural, true),
        ] {
            let Analysed { analysis, lines } = fixture(rel, Lines::Best);
            assert_eq!((analysis.schemes.len(), analysis.schemes[0].scheme), (1, scheme), "{rel}");
            assert_eq!((lines.len(), lines[0].proves, lines[0].entry.is_none()), (1, proves, from_headers), "{rel}");
            assert!(lines[0].text.starts_with(start) && lines[0].text.ends_with("$/rar$"), "{rel}: {:.60}", lines[0].text);
            assert_eq!(analysis.headers, if from_headers { Headers::Encrypted } else { Headers::Readable }, "{rel}");
            assert!(analysis.no_line.is_empty() && analysis.is_encrypted(), "{rel}");
        }
    }

    #[test]
    fn a_keyed_checksum_is_shown_as_keyed() {
        let checks = |rel: &str| fixture(rel, Lines::Best).analysis.schemes[0].parameters.check.clone();
        let (crc32, digest, check_value) = (Check::new(CheckKind::Crc32, 32), Check::new(CheckKind::Blake2sp, 256), Check::new(CheckKind::CheckValue, 64));
        assert_eq!(checks("rar-50/nocheck_st_crc.rar"), [crc32]);
        assert_eq!(checks("rar-50/nocheck_st_crcmac.rar"), [crc32.keyed()]);
        assert_eq!(checks("rar-50/nocheck_st_b2.rar"), [digest]);
        assert_eq!(checks("rar-50/nocheck_st_b2mac.rar"), [digest.keyed()]);
        assert_eq!(checks("rar-50/v730_p_m3.rar"), [check_value, crc32.keyed()]);
        assert_eq!(checks("rar-50/v730_p_m3_blake2sp.rar"), [check_value, digest.keyed()]);
    }

    #[test]
    fn methods_are_named_by_the_generation_of_the_archive() {
        assert_eq!(method_name(RarGeneration::Rar4, 0x30), Some("store"));
        assert_eq!(method_name(RarGeneration::Rar4, 0x33), Some("normal"));
        assert_eq!(method_name(RarGeneration::Rar4, 0x36), None);
        assert_eq!(method_name(RarGeneration::Rar5, 0), Some("store"));
        assert_eq!(method_name(RarGeneration::Rar5, 5), Some("best"));
        assert_eq!(method_name(RarGeneration::Rar5, 0x30), None);
        assert_eq!(method_name(RarGeneration::Rar1, 0), Some("store"));
        assert_eq!(method_name(RarGeneration::Rar1, 5), Some("best"));
    }
}
