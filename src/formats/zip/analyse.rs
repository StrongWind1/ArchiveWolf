//! ZIP: from an archive to its analysis and its hash lines.
//!
//! [`analyse`] is the one way in. It parses the archive, looks at every entry that is marked
//! as encrypted (where its data is, and for ZipCrypto whether it is encrypted at all),
//! describes each entry for the analysis, ranks the encrypted entries of each scheme and
//! builds the lines that are asked for. What is the same for every format is done by
//! [`Parts::assemble`].
//!
//! Everything is read by range. An entry that is not marked costs no read at all, a marked one
//! the few bytes of its local header and of the start of its data, and the proof of
//! pseudo-encryption what [`super::triage`] says.
//!
//! A line is built only when its hashcat mode loads it and can confirm a password with it. The
//! limits are those of the module sources (`zip_traditional.c`, `module_46200.c` and
//! `zip_strong.c` on branch `feat/zip-modes` of the hashcat fork), and each of them is named
//! where it is checked.

use std::path::Path;

use super::data_extract::Data;
use super::data_extract::DataPlan;
use super::data_extract::LINE_METHOD_MAX;
use super::data_extract::PkwarePrefix;
use super::data_extract::ZIP_CRYPTO_HEADER;
use super::data_extract::ZIP_LINE_DATA;
use super::data_extract::ZIP3_ERD_MAX;
use super::data_extract::ZIP3_IV_MAX;
use super::data_extract::ZIP3_VDATA_MAX;
use super::data_extract::extract_zip_winzip_data;
use super::data_extract::locate;
use super::data_extract::pkware_iv;
use super::data_extract::pkware_line_input;
use super::data_extract::read_pkware_body;
use super::data_extract::read_pkware_prefix;
use super::data_extract::zip_winzip_overhead;
use super::data_extract::zip_winzip_salt;
use super::data_extract::zip1_check;
use super::data_extract::zip1_data;
use super::encryption::ZipEncryption;
use super::encryption::aes_strength_bits;
use super::extra_fields::ZipPkwareExtra;
use super::headers::DirectoryProtection;
use super::known;
use super::known::claim::Claim;
use super::known::writer::HeaderMark;
use super::known::writer::Writer;
use super::known::writer::header_mark;
use super::lines::ZIP1_MAX_CHECKS;
use super::lines::Zip1Check;
use super::lines::Zip1Input;
use super::lines::emit_zip1;
use super::lines::emit_zip2;
use super::lines::emit_zip3;
use super::parser::ZipEntry;
use super::parser::filename_lossy;
use super::parser::parse;
use super::scoring::CRC32_FULL_BYTES;
use super::scoring::METHOD_STORED;
use super::scoring::Proof;
use super::scoring::Rank;
use super::scoring::Zip1Plan;
use super::scoring::plan_zip_crypto;
use super::scoring::plan_zip_winzip;
use super::scoring::score_zip_crypto;
use super::scoring::score_zip_pkware;
use super::scoring::score_zip_winzip;
use super::scoring::stored_proof_bits;
use super::triage;
use super::triage::prove;
use crate::analysis::Access;
use crate::analysis::Analysed;
use crate::analysis::Check;
use crate::analysis::CheckKind;
use crate::analysis::Cipher;
use crate::analysis::Entry;
use crate::analysis::EntryKind;
use crate::analysis::Finding;
use crate::analysis::Format;
use crate::analysis::Found;
use crate::analysis::Generation;
use crate::analysis::HeaderState;
use crate::analysis::Kdf;
use crate::analysis::KdfName;
use crate::analysis::KnownBytes;
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
use crate::analysis::WeakHeader;
use crate::formats::limits::Budget;
use crate::formats::source::Source;
use crate::line::Line;
use crate::line::Lines;
use crate::line::Note;
use crate::line::Proves;

/// What was found out about one entry beyond what its headers say.
#[derive(Debug, Clone)]
struct Seen {
    state: State,
    /// Where its data is. Looked up for an entry that is marked, and for no other.
    data: Data,
    /// Why the entry gives no line whatever it is asked, when its headers settle that.
    refused: Option<NoLine>,
    /// Whether the entry is one the proof of pseudo-encryption is for, and it was not run.
    proof_not_run: bool,
    /// The start of its decryption header, for an entry under strong encryption.
    pkware: Option<PkwarePrefix>,
}

/// A line that was built: its text, what it proves, and the remark on it.
type Built = (String, Proves, Option<Note>);

/// Analyse one ZIP archive and build its lines: the best of each scheme, or every one.
pub(crate) fn analyse(source: &Source, wanted: Lines) -> anyhow::Result<Analysed> {
    let path = source.path();
    let archive = parse(source)?;

    let mut parts = Parts::new(Format::Zip, if archive.is_zip64 { Generation::Zip64 } else { Generation::Zip });
    parts.offset = source.offset().saturating_add(archive.start);
    parts.volume = Some(archive.volume);
    parts.comment = (!archive.comment.is_empty()).then(|| String::from_utf8_lossy(&archive.comment).into_owned());
    if archive.volume == Volume::Later {
        tracing::warn!("{}: the last volume of a multi-disk (spanned) archive: an entry that starts in another volume gets no line from this one", path.display());
    }

    if let Some(directory) = archive.directory {
        // the entries are in the encrypted directory: nothing is known of them
        let (protection, why) = directory_protection(directory);
        parts.headers = HeaderState::Encrypted(protection);
        parts.no_line.push(Missing::for_scheme(Scheme::ZipPkware, why));
        return Ok(parts.assemble(path));
    }

    let mut budget = Budget::new();
    let seen: Vec<Seen> = archive.entries.iter().map(|entry| look(source, entry, &mut budget)).collect();
    parts.entries = archive.entries.iter().zip(&seen).map(|(entry, seen)| describe(source, entry, seen)).collect();

    let unproven: Vec<usize> = seen.iter().enumerate().filter(|(_, seen)| seen.proof_not_run).map(|(index, _)| index).collect();
    if !unproven.is_empty() {
        parts.findings.push(Finding::new(Found::ProofNotRun, unproven));
    }

    known_without_a_key(source, &archive.entries, &seen, &mut parts);

    let archive = Looked { source, path, entries: &archive.entries, seen: &seen };
    archive.zip_crypto_lines(wanted, &mut parts)?;
    archive.zip_winzip_lines(wanted, &mut parts)?;
    archive.pkware_lines(wanted, &mut parts)?;
    Ok(parts.assemble(path))
}

/// What the archive gives away of its `zip-crypto` entries without a key: the family of their
/// writer, the bytes of their encrypted streams that are known, and what their encryption
/// headers say. Nothing is searched: all of it is
/// read from the headers, from the twelve bytes in front of the data of each such entry, and
/// from the start of a copy that is not encrypted.
fn known_without_a_key(source: &Source, entries: &[ZipEntry], seen: &[Seen], parts: &mut Parts) {
    let of_zip_crypto = |index: usize| entries.get(index).zip(seen.get(index)).filter(|(entry, seen)| entry.encryption == ZipEncryption::ZipCrypto && !entry.directory && seen.state == State::Encrypted);
    let places: Vec<usize> = (0..entries.len()).filter(|&index| of_zip_crypto(index).is_some()).collect();
    if places.is_empty() {
        return;
    }
    let mut writer = Writer::of(entries);

    // the twelve bytes in front of the data of each entry, held against each other
    let headers: Vec<(usize, [u8; 12])> = places
        .iter()
        .filter_map(|&index| {
            let (entry, seen) = of_zip_crypto(index)?;
            let Data::Here(start) = seen.data else { return None };
            let mut header = [0_u8; 12];
            (entry.compressed_size >= ZIP_CRYPTO_HEADER && source.read_exact_at(start, &mut header).is_ok()).then_some((index, header))
        })
        .collect();
    let as_written: Vec<[u8; 12]> = headers.iter().map(|(_, header)| *header).collect();
    writer = writer.held_against(&as_written);
    let weak = match header_mark(&as_written) {
        Some(HeaderMark::Constant) => {
            writer = Writer::Yeka;
            Some((WeakHeader::Constant, headers.iter().map(|(index, _)| *index).collect()))
        },
        Some(HeaderMark::Repeated(repeated)) => Some((WeakHeader::Repeated, repeated.iter().filter_map(|&place| headers.get(place)).map(|(index, _)| *index).collect())),
        None => match writer {
            Writer::InfoZip if writer.header_path_entries().is_some_and(|needed| places.len() >= needed) => Some((WeakHeader::InfoZip, places.clone())),
            Writer::SharpZipLib | Writer::DotNetZip if writer.header_path_entries().is_some_and(|needed| places.len() >= needed) => Some((WeakHeader::EncryptedOnce, places.clone())),
            _ => None,
        },
    };
    parts.writer = Some(writer.as_str());

    // the known bytes of each entry: from its method and its name, and from a copy in the archive
    let copies = known::directory::copies(source, entries);
    let mut longest = 0;
    let mut with_known = Vec::new();
    for &index in &places {
        let Some((entry, _)) = of_zip_crypto(index) else { continue };
        let more: Vec<&Claim> = copies.iter().filter(|(of, _)| *of == index).map(|(_, claim)| claim).collect();
        let Some(run) = known::known_run(&known::facts(entry, writer, None), &more) else { continue };
        if let Some(described) = parts.entries.get_mut(index) {
            described.known = Some(KnownBytes { source: run.origin.as_str(), run: run.len, certainty: run.certainty.as_str() });
        }
        longest = longest.max(run.len);
        with_known.push(index);
    }
    if !with_known.is_empty() {
        parts.findings.push(Finding::new(Found::KnownPlaintext { longest }, with_known));
    }
    if let Some((how, concerned)) = weak {
        parts.findings.push(Finding::new(Found::WeakHeader(how), concerned));
    }
}

/// The name of a compression method, for the ones that have a common one.
const fn method_name(method: u16) -> Option<&'static str> {
    Some(match method {
        0 => "stored",
        1 => "shrink",
        6 => "implode",
        8 => "deflate",
        9 => "deflate64",
        12 => "bzip2",
        14 => "lzma",
        93 => "zstd",
        95 => "xz",
        98 => "ppmd",
        _ => return None,
    })
}

/// The cipher a PKWARE algorithm identifier stands for (APPNOTE 7.2.3.2). `None` for 0xFFFF,
/// which the format defines as "unknown algorithm", and for a number the format does not have.
const fn pkware_cipher(alg_id: u16) -> Option<Cipher> {
    Some(match alg_id {
        0x6601 => Cipher::Des,
        0x6602 => Cipher::Rc2Old,
        0x6603 => Cipher::TripleDes,
        0x6609 => Cipher::TripleDes2Key,
        0x6702 => Cipher::Rc2,
        0x660E..=0x6610 => Cipher::Aes,
        0x6720 => Cipher::Blowfish,
        0x6721 => Cipher::Twofish,
        0x6801 => Cipher::Rc4,
        _ => return None,
    })
}

/// Whether a PKWARE algorithm identifier is one of the three a `$zip$3$` line exists for.
const fn is_aes(alg_id: u16) -> bool {
    matches!(alg_id, 0x660E..=0x6610)
}

/// The parameters of strong encryption with the algorithm `alg_id`, a key of `bit_len` bits and
/// the processing flags `flags`.
///
/// A password is tested against the padding the random data decrypts to and against the
/// CRC-32 the validation data ends with. The key comes from one SHA-1 over the password, and
/// the scheme has no count of rounds: neither extra field 0x0017 nor the decryption header
/// has a field for one (APPNOTE 7.2.3 and 7.2.4). When the flags say that only certificates
/// open the entry, there is no derivation and no check.
fn pkware_parameters(alg_id: u16, bit_len: u16, flags: u16) -> Parameters {
    let cipher = pkware_cipher(alg_id);
    let by_password = flags & 0x0001 != 0;
    Parameters {
        cipher,
        identifier: cipher.is_none().then_some(u64::from(alg_id)),
        key_bits: Some(u32::from(bit_len)),
        access: Access::of_flags(flags),
        kdf: by_password.then_some(Kdf { name: KdfName::Sha1, rounds: None }),
        check: if by_password { vec![Check::structure(), Check::new(CheckKind::Crc32, 32)] } else { Vec::new() },
        ..Parameters::default()
    }
}

/// How an encrypted central directory is protected, and why it gives no line: no mode tests
/// it, or no password opens it.
fn directory_protection(directory: DirectoryProtection) -> (Protection, NoLine) {
    let why = if directory.flags & 0x0001 == 0 { NoLine::Certificate } else { NoLine::CentralDirectoryEncrypted };
    // the vector and the random data are in the archive decryption header, which is not read
    (Protection { scheme: Scheme::ZipPkware, parameters: pkware_parameters(directory.alg_id, directory.bit_len, directory.flags), salt: Salt::None }, why)
}

/// Look at one entry: where its data is, and whether it is what its mark says.
fn look(source: &Source, entry: &ZipEntry, budget: &mut Budget) -> Seen {
    let unmarked = Seen { state: State::Plain, data: Data::Missing, refused: None, proof_not_run: false, pkware: None };
    if entry.encryption == ZipEncryption::None {
        // not marked: plain, and whether it unpacks is the business of an archive tool
        return unmarked;
    }
    let data = locate(source, entry);
    let marked = Seen { state: State::Encrypted, data, ..unmarked };

    match (entry.encryption, data) {
        (ZipEncryption::Contradiction(_), _) => Seen { state: State::Undetermined, refused: Some(NoLine::Unreadable), ..marked },
        (ZipEncryption::ZipCrypto, Data::Here(start)) => match prove(source, entry, start, budget) {
            triage::Proof::Open => Seen { state: State::PseudoEncrypted, ..marked },
            triage::Proof::Sealed => marked,
            triage::Proof::NotRun => Seen { proof_not_run: true, ..marked },
            triage::Proof::SizesDisagree => Seen { state: State::Undetermined, refused: Some(NoLine::SizesDisagree), ..marked },
        },
        // marked as ZipCrypto, and the data the proof needs is not in the file
        (ZipEncryption::ZipCrypto, _) => Seen { state: State::Undetermined, ..marked },
        (ZipEncryption::ZipPkware(_), Data::Here(start)) => Seen { pkware: read_pkware_prefix(source, entry, start), ..marked },
        // a salt or a decryption header stands in front of the data: no plain data is taken for it
        _ => marked,
    }
}

/// How an entry that is marked is encrypted, from its headers and the start of its data.
fn protection(source: &Source, entry: &ZipEntry, seen: &Seen) -> Option<Protection> {
    Some(match entry.encryption {
        ZipEncryption::None => return None,
        ZipEncryption::ZipCrypto => {
            // the width of the check is the one the line is built with
            let check_bits = if entry.two_byte_check { 16 } else { 8 };
            Protection { scheme: Scheme::ZipCrypto, parameters: Parameters { cipher: Some(Cipher::ZipCrypto), key_bits: Some(96), check: vec![Check::new(CheckKind::CheckByte, check_bits), Check::new(CheckKind::Crc32, 32)], ..Parameters::default() }, salt: Salt::None }
        },
        ZipEncryption::ZipWinzip { ae_version, strength, .. } => {
            let mut check = vec![Check::new(CheckKind::Verifier, 16), Check::new(CheckKind::Hmac, 80)];
            // AE-2 stores no CRC-32: the authentication code stands in for it
            if ae_version == 1 {
                check.push(Check::new(CheckKind::Crc32, 32));
            }
            let key_bits = Some(u32::from(aes_strength_bits(strength))).filter(|&bits| bits != 0);
            // a strength the format does not have is shown as it is stored
            let identifier = key_bits.is_none().then_some(u64::from(strength));
            // the salt is the start of the data of the entry
            let salt = match seen.data {
                Data::Here(start) => zip_winzip_salt(source, entry, start, strength).map_or(Salt::Unknown, Salt::Known),
                Data::Cut | Data::Missing => Salt::Unknown,
            };
            Protection { scheme: Scheme::ZipWinzip, parameters: Parameters { ae: Some(ae_version), cipher: Some(Cipher::Aes), identifier, key_bits, kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha1, rounds: Some(1000) }), check, ..Parameters::default() }, salt }
        },
        ZipEncryption::ZipPkware(extra) => match (&seen.pkware, extra) {
            // the decryption header is what a reader decrypts with; the vector in it is the
            // one value of an entry that goes into the key of its data beside the password
            (Some(prefix), _) => {
                let salt = if u64::from(prefix.iv_len) <= ZIP3_IV_MAX { Salt::Known(pkware_iv(prefix, entry)) } else { Salt::Unknown };
                Protection { scheme: Scheme::ZipPkware, parameters: pkware_parameters(prefix.alg_id, prefix.bit_len, prefix.flags), salt }
            },
            (None, Some(extra)) => Protection { scheme: Scheme::ZipPkware, parameters: pkware_parameters(extra.alg_id, extra.bit_len, extra.flags), salt: Salt::Unknown },
            (None, None) => Protection { salt: Salt::Unknown, ..Protection::bare(Scheme::ZipPkware) },
        },
        ZipEncryption::Contradiction(scheme) => Protection { salt: Salt::Unknown, ..Protection::bare(scheme) },
    })
}

/// Describe one entry for the analysis.
fn describe(source: &Source, entry: &ZipEntry, seen: &Seen) -> Entry {
    let number = if let ZipEncryption::ZipWinzip { actual_compression, .. } = entry.encryption { actual_compression } else { entry.compression_method };

    let mut described = Entry::new(if entry.directory { EntryKind::Directory } else { EntryKind::File }, seen.state);
    described.name = Some(filename_lossy(entry));
    described.method = Some(Method { name: method_name(number).map(str::to_owned), number: Some(u64::from(number)) });
    described.packed = Some(entry.compressed_size);
    described.size = Some(entry.uncompressed_size);
    described.split = Some(entry.split);
    if seen.state.is_locked() {
        described.protection = protection(source, entry, seen);
    }
    described
}

/// What a ZipCrypto line proves, and the remark on it when that is less than a full check.
fn zip1_strength(entry: &ZipEntry, plan: Zip1Plan, checks: &[Zip1Check]) -> (Proves, Option<Note>) {
    let count = checks.len();
    let check_bits: u32 = checks.iter().map(|check| if check.two_bytes { 16 } else { 8 }).sum();
    let stored = entry.compressed_size.saturating_sub(ZIP_CRYPTO_HEADER);

    match plan.proof {
        Proof::HeaderOnly => {
            let note = if stored == 0 {
                Note::EmptyEntry { checks: count }
            } else if entry.compression_method == 0 {
                Note::StoredTooLarge { stored, limit: ZIP_LINE_DATA, checks: count }
            } else {
                Note::NoDecoder { method: entry.compression_method, checks: count }
            };
            (Proves::Weak { bits: check_bits }, Some(note))
        },
        // a CRC-32 over fewer than four bytes names those bytes and nothing more
        Proof::Checksum if stored < CRC32_FULL_BYTES => {
            let data_bits = u32::try_from(stored_proof_bits(stored, 0)).unwrap_or(u32::MAX);
            (Proves::Weak { bits: data_bits.saturating_add(check_bits) }, Some(Note::ShortStored { stored, checks: count }))
        },
        Proof::Checksum if count == 1 => (Proves::Exact, Some(Note::StoredAlone)),
        Proof::Checksum => (Proves::Exact, None),
        // a stream that is there in full is held against its CRC-32; one that is cut has to decode
        Proof::Stream if plan.data == DataPlan::Full => (Proves::Exact, None),
        Proof::Stream => (Proves::Structural, None),
    }
}

/// An archive whose entries were looked at.
struct Looked<'a> {
    source: &'a Source,
    path: &'a Path,
    entries: &'a [ZipEntry],
    seen: &'a [Seen],
}

impl Looked<'_> {
    /// The entries that are marked with the scheme `rank` knows, in the order they are asked
    /// for a line: by rank, and behind every other one those of which it is already known
    /// that they give none (their headers settle it, or their data is not in the file).
    /// Entries that agree in all of that keep the order of the archive.
    fn ranked(&self, rank: impl Fn(usize, &ZipEntry) -> Option<Rank>) -> Vec<usize> {
        let mut ranked: Vec<(bool, Rank, usize)> = self.entries.iter().zip(self.seen).enumerate().filter(|(_, (_, seen))| seen.state.is_locked()).filter_map(|(index, (entry, seen))| Some((seen.refused.is_some() || !matches!(seen.data, Data::Here(_)), rank(index, entry)?, index))).collect();
        ranked.sort();
        ranked.into_iter().map(|(_, _, index)| index).collect()
    }

    /// Where the data of the entry at `index` starts, or why the entry gives no line: its
    /// headers settle that, or its data is not all in this file.
    fn data_of(&self, index: usize) -> Result<(&ZipEntry, u64), NoLine> {
        let (Some(entry), Some(seen)) = (self.entries.get(index), self.seen.get(index)) else { return Err(NoLine::Unreadable) };
        if let Some(why) = &seen.refused {
            return Err(why.clone());
        }
        match seen.data {
            Data::Here(start) => Ok((entry, start)),
            Data::Cut | Data::Missing if entry.split != Split::No => Err(NoLine::Split),
            Data::Cut | Data::Missing => Err(NoLine::Unreadable),
        }
    }

    /// Say in the log why an entry could not be read, and give the reason the analysis shows.
    fn unreadable(&self, entry: &ZipEntry, error: &anyhow::Error) -> NoLine {
        tracing::warn!("{}: {}: {error:#}", self.path.display(), filename_lossy(entry));
        NoLine::Unreadable
    }

    /// Ask the entries at `ranked` for a line, in that order.
    ///
    /// Every entry is first held against what its headers say (`settled`): one that cannot give
    /// a line whatever its data holds is put down with its reason, always, so that what is said
    /// of an entry does not hang on the entries around it. Of the others the data is read
    /// (`build`): of all of them, or until one gives a line. One whose data gives no line is
    /// put down with its reason too.
    fn ask(scheme: Scheme, ranked: &[usize], wanted: Lines, parts: &mut Parts, settled: impl Fn(usize) -> Result<(), NoLine>, build: impl Fn(usize) -> Result<Built, NoLine>) -> anyhow::Result<()> {
        let mut served = false;
        for &index in ranked {
            if let Err(why) = settled(index) {
                parts.no_line.push(Missing::for_entry(scheme, index, why));
                continue;
            }
            if served && wanted == Lines::Best {
                continue;
            }
            match build(index) {
                Ok((text, proves, note)) => {
                    let line = Line::new(text, Some(index), proves)?;
                    parts.lines.push(match note {
                        Some(note) => line.with_note(note),
                        None => line,
                    });
                    served = true;
                },
                Err(why) => parts.no_line.push(Missing::for_entry(scheme, index, why)),
            }
        }
        Ok(())
    }

    /// The `$zip$1$` lines.
    fn zip_crypto_lines(&self, wanted: Lines, parts: &mut Parts) -> anyhow::Result<()> {
        let ranked = self.ranked(|_, entry| (entry.encryption == ZipEncryption::ZipCrypto).then(|| score_zip_crypto(entry)));
        Self::ask(Scheme::ZipCrypto, &ranked, wanted, parts, |index| self.zip1_entry(index).map(|_| ()), |index| self.zip1_line(index, &ranked, wanted))
    }

    /// The entry at `index` and where its data starts, when its headers allow a `$zip$1$` line.
    /// Nothing of its data is read for this.
    fn zip1_entry(&self, index: usize) -> Result<(&ZipEntry, u64), NoLine> {
        let (entry, start) = self.data_of(index)?;
        if entry.compressed_size == 0 {
            return Err(NoLine::Empty);
        }
        if entry.compressed_size < ZIP_CRYPTO_HEADER {
            return Err(self.unreadable(entry, &anyhow::anyhow!("its {} bytes are fewer than the 12 of an encryption header", entry.compressed_size)));
        }
        // the mode reads a method of one to three digits
        if entry.compression_method > LINE_METHOD_MAX {
            return Err(NoLine::MethodNumber { method: entry.compression_method });
        }
        // The mode refuses a stored entry whose data is not as long as what it unpacks to. The
        // proof of pseudo-encryption sorts such an entry out when it runs; one it did not run
        // on can still be as long as what it holds, with no room for an encryption header.
        if entry.compression_method == METHOD_STORED && entry.compressed_size.checked_sub(ZIP_CRYPTO_HEADER) != Some(entry.uncompressed_size) {
            return Err(NoLine::SizesDisagree);
        }
        Ok((entry, start))
    }

    /// The `$zip$1$` line of the entry at `index`, with the header checks of the entries at
    /// `others` behind its own when the line rests on a checksum or on check bytes alone.
    fn zip1_line(&self, index: usize, others: &[usize], wanted: Lines) -> Result<Built, NoLine> {
        let (entry, start) = self.zip1_entry(index)?;
        let Some(first) = zip1_check(self.source, entry, start) else { return Err(self.unreadable(entry, &anyhow::anyhow!("its encryption header cannot be read"))) };

        let plan = plan_zip_crypto(entry);
        let data = zip1_data(self.source, entry, start, plan.data).map_err(|error| self.unreadable(entry, &error))?;

        // A stream that decodes proves the password by itself. Anything weaker also tests the
        // headers of the other entries, which assumes they share the password; `hash --all`
        // gives every entry a line of its own for the archives where they do not. The mode
        // reads eight checks.
        let mut checks = vec![first];
        if wanted == Lines::Best && plan.proof != Proof::Stream {
            let encrypted = others.iter().filter(|&&other| other != index).filter_map(|&other| Some((self.entries.get(other)?, self.seen.get(other)?)));
            checks.extend(
                encrypted
                    .filter_map(|(other, seen)| match (seen.state, seen.data) {
                        (State::Encrypted, Data::Here(start)) => zip1_check(self.source, other, start),
                        _ => None,
                    })
                    .take(ZIP1_MAX_CHECKS - 1),
            );
        }

        let (proves, note) = zip1_strength(entry, plan, &checks);
        let input = Zip1Input { checks, method: entry.compression_method, crc32: entry.crc32, unpacked: entry.uncompressed_size, packed: entry.compressed_size.saturating_sub(ZIP_CRYPTO_HEADER), data };
        Ok((emit_zip1(&input), proves, note))
    }

    /// The `$zip$2$` lines.
    fn zip_winzip_lines(&self, wanted: Lines, parts: &mut Parts) -> anyhow::Result<()> {
        let ranked = self.ranked(|_, entry| match entry.encryption {
            ZipEncryption::ZipWinzip { strength, actual_compression, .. } => Some(score_zip_winzip(entry, strength, actual_compression)),
            // marked as WinZip AES by its method, and asked so that it can say why it gives no line
            ZipEncryption::Contradiction(Scheme::ZipWinzip) => Some(Rank::LAST),
            _ => None,
        });
        Self::ask(Scheme::ZipWinzip, &ranked, wanted, parts, |index| self.zip2_entry(index).map(|_| ()), |index| self.zip2_line(index))
    }

    /// What a `$zip$2$` line needs of the entry at `index`, when its headers allow one: the
    /// entry, where its data starts, its strength, its method and the size of its encrypted
    /// data. Nothing of its data is read for this.
    fn zip2_entry(&self, index: usize) -> Result<(&ZipEntry, u64, u8, u16, u64), NoLine> {
        let (entry, start) = self.data_of(index)?;
        let ZipEncryption::ZipWinzip { ae_version, strength, actual_compression: method } = entry.encryption else { return Err(NoLine::Unreadable) };
        // AE-1 and AE-2 are all the format has, and three strengths: anything else is not known
        if !matches!(ae_version, 1 | 2) || !matches!(strength, 1..=3) {
            return Err(NoLine::UnknownScheme);
        }
        if entry.compressed_size == 0 {
            return Err(NoLine::Empty);
        }
        let overhead = zip_winzip_overhead(strength);
        let Some(packed) = entry.compressed_size.checked_sub(overhead) else { return Err(self.unreadable(entry, &anyhow::anyhow!("its {} bytes are fewer than the {overhead} of salt, verifier and authentication code", entry.compressed_size))) };
        // the mode reads a method of one to three digits
        if method > LINE_METHOD_MAX {
            return Err(NoLine::MethodNumber { method });
        }
        Ok((entry, start, strength, method, packed))
    }

    /// The `$zip$2$` line of the entry at `index`.
    fn zip2_line(&self, index: usize) -> Result<Built, NoLine> {
        let (entry, start, strength, method, packed) = self.zip2_entry(index)?;
        let plan = plan_zip_winzip(method, packed);
        let input = extract_zip_winzip_data(self.source, entry, start, strength, method, plan.data).map_err(|error| self.unreadable(entry, &error))?;
        let (proves, note) = match plan.proof {
            Proof::HeaderOnly => (Proves::Weak { bits: 16 }, Some(Note::VerifierOnly { packed, limit: ZIP_LINE_DATA, method })),
            // the authentication code covers the whole ciphertext
            Proof::Checksum => (Proves::Exact, None),
            Proof::Stream => (Proves::Structural, None),
        };
        Ok((emit_zip2(&input), proves, note))
    }

    /// The algorithm and the flags of the entry at `index` under strong encryption: from its
    /// decryption header, and from its central header when that cannot be read.
    fn pkware_facts(&self, index: usize, extra: Option<ZipPkwareExtra>) -> Option<(u16, u16)> {
        self.seen.get(index).and_then(|seen| seen.pkware.as_ref()).map(|prefix| (prefix.alg_id, prefix.flags)).or_else(|| extra.map(|extra| (extra.alg_id, extra.flags)))
    }

    /// The `$zip$3$` lines.
    fn pkware_lines(&self, wanted: Lines, parts: &mut Parts) -> anyhow::Result<()> {
        let ranked = self.ranked(|index, entry| match entry.encryption {
            ZipEncryption::ZipPkware(extra) => {
                // an entry of which neither is known ranks with the algorithm the format calls unknown
                let (alg_id, flags) = self.pkware_facts(index, extra).unwrap_or((0xFFFF, 0));
                Some(score_zip_pkware(entry, alg_id, flags))
            },
            ZipEncryption::Contradiction(Scheme::ZipPkware) => Some(Rank::LAST),
            _ => None,
        });
        Self::ask(Scheme::ZipPkware, &ranked, wanted, parts, |index| self.zip3_entry(index).map(|_| ()), |index| self.zip3_line(index).map(|text| (text, Proves::Exact, None)))
    }

    /// What a `$zip$3$` line needs of the entry at `index`, when its headers allow one: the
    /// entry, where its data starts, and the start of its decryption header, which was read
    /// when the entry was looked at. Nothing more is read for this.
    fn zip3_entry(&self, index: usize) -> Result<(&ZipEntry, u64, &PkwarePrefix), NoLine> {
        let (entry, start) = self.data_of(index)?;
        let ZipEncryption::ZipPkware(extra) = entry.encryption else { return Err(NoLine::Unreadable) };
        let prefix = self.seen.get(index).and_then(|seen| seen.pkware.as_ref());

        let Some((alg_id, flags)) = self.pkware_facts(index, extra) else { return Err(self.unreadable(entry, &anyhow::anyhow!("it has neither extra field 0x0017 nor a decryption header that can be read"))) };
        if flags & 0x0001 == 0 {
            return Err(NoLine::Certificate);
        }
        if !is_aes(alg_id) {
            // 7-Zip, John the Ripper and hashcat all stop at AES: how PKWARE derives the key of
            // its other ciphers is not published, and no archive with a known password exists
            // to check a guess against
            return Err(NoLine::PkwareCipher { cipher: pkware_cipher(alg_id), identifier: alg_id });
        }
        let Some(prefix) = prefix else { return Err(self.unreadable(entry, &anyhow::anyhow!("its decryption header is cut short"))) };
        // format 3 is the one layout APPNOTE defines: any other is no decryption header
        if prefix.format != 3 {
            return Err(NoLine::HeaderFormat { format: prefix.format });
        }
        // the modes refuse random data that is wrapped with 3DES
        if prefix.flags & 0x4000 != 0 {
            return Err(NoLine::RandomDataWrapped);
        }
        // each mode loads its own algorithm with its own key length and no other pair
        if u32::from(prefix.bit_len) != 128 + 64 * u32::from(alg_id - 0x660E) {
            return Err(self.unreadable(entry, &anyhow::anyhow!("a key of {} bits does not go with algorithm 0x{alg_id:04x}", prefix.bit_len)));
        }
        let over = |field: &'static str, size: u64, limit: u64| (size > limit).then_some(NoLine::LineField { field, size, limit });
        if let Some(why) = over("initialisation vector", u64::from(prefix.iv_len), ZIP3_IV_MAX).or_else(|| over("random data", u64::from(prefix.erd_len), ZIP3_ERD_MAX)) {
            return Err(why);
        }
        // the random data ends in a block of padding: it is one cipher block or more, and whole
        if prefix.erd_len < 16 || prefix.erd_len % 16 != 0 {
            return Err(self.unreadable(entry, &anyhow::anyhow!("its {} bytes of random data are not a whole number of cipher blocks", prefix.erd_len)));
        }
        Ok((entry, start, prefix))
    }

    /// The `$zip$3$` line of the entry at `index`. hashcat tests the padding the random data
    /// decrypts to, and the line carries the validation data with its CRC-32 for a second test.
    fn zip3_line(&self, index: usize) -> Result<String, NoLine> {
        let (entry, start, prefix) = self.zip3_entry(index)?;
        let body = read_pkware_body(self.source, entry, start, prefix).map_err(|error| self.unreadable(entry, &error))?;
        if body.vdata.len() as u64 > ZIP3_VDATA_MAX {
            return Err(NoLine::LineField { field: "validation data", size: body.vdata.len() as u64, limit: ZIP3_VDATA_MAX });
        }
        if body.vdata.len() < 4 {
            return Err(self.unreadable(entry, &anyhow::anyhow!("its validation data is too short to hold its CRC-32")));
        }
        Ok(emit_zip3(&pkware_line_input(entry, prefix, body)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::Coverage;
    use crate::analysis::Reason;
    use crate::formats::zip::craft::Zip;
    use crate::formats::zip::craft::member;

    fn analysed(rel: &str, wanted: Lines) -> Analysed {
        let source = Source::open(Path::new(&format!("tests/fixtures/{rel}")), 0).unwrap();
        analyse(&source, wanted).unwrap()
    }

    #[test]
    fn a_zip_crypto_archive_is_described_entry_by_entry() {
        let Analysed { analysis, lines } = analysed("zip-crypto/test05.zip", Lines::Best);
        assert_eq!((analysis.format, analysis.generation, analysis.offset, analysis.volume), (Format::Zip, Generation::Zip, 0, Some(Volume::Single)));
        assert_eq!(analysis.coverage, Coverage::All);

        let entry = &analysis.entry_list[0];
        assert_eq!((entry.kind, entry.state, entry.split), (EntryKind::File, State::Encrypted, Some(Split::No)));
        let protection = entry.protection.as_ref().unwrap();
        assert_eq!((protection.scheme, protection.parameters.cipher, protection.parameters.key_bits), (Scheme::ZipCrypto, Some(Cipher::ZipCrypto), Some(96)));
        assert_eq!(protection.parameters.check, [Check::new(CheckKind::CheckByte, 8), Check::new(CheckKind::Crc32, 32)]);
        assert!(entry.packed.is_some() && entry.size.is_some() && entry.method.is_some());

        // every entry under ZipCrypto shares the one key a password gives
        assert!(analysis.entry_list.iter().all(|entry| entry.key_group == Some(1)));
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].entry.map(|index| analysis.entry_list[index].state), Some(State::Encrypted));
    }

    #[test]
    fn a_zip_winzip_entry_names_its_version_its_key_size_and_its_salt() {
        let Analysed { analysis, lines } = analysed("zip-winzip/winzip_aes256_hello.zip", Lines::Best);
        let entry = analysis.entry_list.iter().find(|entry| entry.state == State::Encrypted).unwrap();
        let protection = entry.protection.as_ref().unwrap();
        assert_eq!(protection.scheme, Scheme::ZipWinzip);
        assert_eq!((protection.parameters.cipher, protection.parameters.key_bits), (Some(Cipher::Aes), Some(256)));
        assert!(matches!(protection.parameters.ae, Some(1 | 2)));
        assert_eq!(protection.parameters.kdf, Some(Kdf { name: KdfName::Pbkdf2HmacSha1, rounds: Some(1000) }));
        assert!(matches!(&protection.salt, Salt::Known(salt) if salt.len() == 16), "the salt of AES-256 is 16 bytes");
        assert_eq!(entry.key_group, Some(1));
        // the salt the analysis shows is the one the line carries
        let Salt::Known(salt) = &protection.salt else { panic!("no salt") };
        assert!(lines[0].text.contains(&hex::encode(salt)));
    }

    #[test]
    fn a_certificate_entry_has_no_line_and_says_why() {
        let Analysed { analysis, lines } = analysed("unknown-pw/edge_zip-forensic_securezip-strong-signed.zip", Lines::Best);
        assert!(lines.is_empty());
        assert_eq!(analysis.no_line.len(), 1);
        assert_eq!((analysis.no_line[0].scheme, analysis.no_line[0].reason(), &analysis.no_line[0].why), (Scheme::ZipPkware, Reason::NoPassword, &NoLine::Certificate));
        assert!(analysis.findings.iter().any(|finding| finding.code() == "certificate"));
    }

    #[test]
    fn a_marked_entry_that_is_open_has_no_scheme_and_no_line() {
        let Analysed { analysis, lines } = analysed("pseudo/pseudo_encrypted_zc.zip", Lines::All);
        assert!(lines.is_empty() && analysis.no_line.is_empty());
        assert!(analysis.entry_list.iter().any(|entry| entry.state == State::PseudoEncrypted));
        assert!(analysis.entry_list.iter().all(|entry| entry.protection.is_none() && entry.key_group.is_none()));
        assert_eq!(analysis.coverage, Coverage::None);
        assert!(analysis.schemes.is_empty() && !analysis.is_encrypted());
        assert!(analysis.findings.iter().any(|finding| finding.code() == "pseudo-encryption"));
    }

    #[test]
    fn what_a_zip_crypto_line_proves_follows_from_its_plan() {
        let entry = |compressed_size: u64, method: u16| ZipEntry {
            filename: b"a".to_vec(),
            flags: 1,
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
        };
        let check = |two_bytes: bool| Zip1Check { header: [0; 12], two_bytes, value: 0, alternative: None };
        let strength = |entry: &ZipEntry, checks: &[Zip1Check]| zip1_strength(entry, plan_zip_crypto(entry), checks);
        let one = [check(false)];

        // a stream that is there in full, and one that is cut
        assert_eq!(strength(&entry(12 + 500, 8), &one), (Proves::Exact, None));
        assert_eq!(strength(&entry(12 + (2 << 20), 8), &one), (Proves::Structural, None));
        assert_eq!(strength(&entry(5000, 12), &one), (Proves::Structural, None));

        // stored: a CRC-32, which with one header is 40 bits
        assert_eq!(strength(&entry(12 + 500, 0), &one), (Proves::Exact, Some(Note::StoredAlone)));
        assert_eq!(strength(&entry(12 + 500, 0), &[check(false), check(false)]), (Proves::Exact, None));
        assert_eq!(strength(&entry(12 + 3, 0), &one), (Proves::Weak { bits: 32 }, Some(Note::ShortStored { stored: 3, checks: 1 })));
        assert_eq!(strength(&entry(12 + 1, 0), &one), (Proves::Weak { bits: 16 }, Some(Note::ShortStored { stored: 1, checks: 1 })));

        // nothing but the check bytes of the headers: 8 bits each, 16 where PKZIP 1.x wrote two
        assert_eq!(strength(&entry(12, 0), &one), (Proves::Weak { bits: 8 }, Some(Note::EmptyEntry { checks: 1 })));
        assert_eq!(strength(&entry(5000, 14), &one), (Proves::Weak { bits: 8 }, Some(Note::NoDecoder { method: 14, checks: 1 })));
        assert_eq!(strength(&entry(5000, 14), &[check(false), check(true), check(false)]), (Proves::Weak { bits: 32 }, Some(Note::NoDecoder { method: 14, checks: 3 })));
        let large = 12 + ZIP_LINE_DATA + 1;
        assert_eq!(strength(&entry(large, 0), &one), (Proves::Weak { bits: 8 }, Some(Note::StoredTooLarge { stored: large - 12, limit: ZIP_LINE_DATA, checks: 1 })));
    }

    fn analysed_bytes(archive: Vec<u8>, wanted: Lines) -> Analysed {
        analyse(&Source::from_bytes(archive), wanted).unwrap()
    }

    #[test]
    fn an_archive_built_in_memory_is_analysed_like_a_file() {
        let Analysed { analysis, lines } = analysed_bytes(Zip::of(&[member("dir/", 0, b""), member("dir/open.txt", 0, b"in the clear"), member("dir/locked.bin", 1, &[0x5A; 12 + 40])]).build(), Lines::Best);
        assert_eq!(analysis.path, "<memory>");
        let kinds: Vec<(EntryKind, State)> = analysis.entry_list.iter().map(|entry| (entry.kind, entry.state)).collect();
        assert_eq!(kinds, [(EntryKind::Directory, State::Plain), (EntryKind::File, State::Plain), (EntryKind::File, State::Encrypted)]);
        assert_eq!(analysis.coverage, Coverage::Some, "one file of two is encrypted, and the directory does not count");
        let codes: Vec<&str> = analysis.findings.iter().map(Finding::code).collect();
        assert_eq!(codes, ["partial", "weak-scheme"]);
        assert_eq!(analysis.findings[0].entries, [1], "the finding names the file that is open and not the directory");
        assert_eq!((lines.len(), lines[0].entry, lines[0].proves, lines[0].note), (1, Some(2), Proves::Exact, Some(Note::StoredAlone)));
    }

    #[test]
    fn an_archive_behind_a_program_starts_where_the_program_ends() {
        let mut behind = vec![0xEE; 300];
        behind.extend_from_slice(&Zip::of(&[member("a.txt", 1, &[0x5A; 12 + 40])]).build());
        let Analysed { analysis, lines } = analysed_bytes(behind, Lines::Best);
        assert_eq!(analysis.offset, 300);
        assert_eq!(lines.len(), 1);
    }

    /// A stored entry as long as what it holds has no room for an encryption header. The proof
    /// of pseudo-encryption says what it is, and when the budget of the archive left the proof
    /// out, the entry is still not given a line its mode would refuse.
    #[test]
    fn a_stored_entry_the_proof_left_out_gets_no_line_its_mode_refuses() {
        let source = Source::from_bytes(Zip::of(&[crate::formats::zip::craft::Member { size: Some(40), ..member("a.bin", 1, &[0x5A; 40]) }, member("b.bin", 1, &[0x5A; 12 + 40])]).build());
        let entries = parse(&source).unwrap().entries;
        let seen: Vec<Seen> = entries.iter().map(|entry| Seen { state: State::Encrypted, data: locate(&source, entry), refused: None, proof_not_run: true, pkware: None }).collect();
        let looked = Looked { source: &source, path: Path::new("<memory>"), entries: &entries, seen: &seen };
        assert_eq!(looked.zip1_line(0, &[0, 1], Lines::All), Err(NoLine::SizesDisagree));
        assert!(looked.zip1_line(1, &[0, 1], Lines::All).is_ok());
    }

    #[test]
    fn two_schemes_in_one_archive_are_a_finding() {
        let analysis = analysed("zip-winzip/gen_own_mixed_zc_aes.zip", Lines::Best).analysis;
        assert!(analysis.mixed);
        let mixed = analysis.findings.iter().find(|finding| finding.code() == "mixed-schemes").unwrap();
        assert_eq!(mixed.found, Found::MixedSchemes(vec![Scheme::ZipCrypto, Scheme::ZipWinzip]));
        assert_eq!(analysis.lines.len(), 2, "a line for each scheme");

        let partial = analysed("zip-crypto/mixed.zip", Lines::Best).analysis;
        assert!(partial.findings.iter().any(|finding| finding.code() == "partial") && partial.coverage == Coverage::Some);
    }

    #[test]
    fn a_line_that_tests_check_bytes_alone_is_a_finding() {
        let Analysed { analysis, lines } = analysed("zip-crypto/gen_7z_zipcrypto_deflate64.zip", Lines::Best);
        assert_eq!((lines.len(), lines[0].proves, lines[0].note), (1, Proves::Weak { bits: 8 }, Some(Note::NoDecoder { method: 9, checks: 1 })));
        let weak = analysis.findings.iter().find(|finding| finding.code() == "weak-check").unwrap();
        assert_eq!((&weak.found, weak.entries.as_slice()), (&Found::WeakCheck { bits: 8 }, &[lines[0].entry.unwrap()][..]));
    }

    #[test]
    fn the_ciphers_of_zip_pkware_have_their_names() {
        assert_eq!(
            [0x6601, 0x6602, 0x6603, 0x6609, 0x660E, 0x660F, 0x6610, 0x6702, 0x6720, 0x6721, 0x6801].map(pkware_cipher),
            [Some(Cipher::Des), Some(Cipher::Rc2Old), Some(Cipher::TripleDes), Some(Cipher::TripleDes2Key), Some(Cipher::Aes), Some(Cipher::Aes), Some(Cipher::Aes), Some(Cipher::Rc2), Some(Cipher::Blowfish), Some(Cipher::Twofish), Some(Cipher::Rc4),]
        );
        assert_eq!([0xFFFF, 0x6600, 0x660D, 0x6611, 0].map(pkware_cipher), [None; 5]);
        assert!(is_aes(0x660E) && is_aes(0x6610) && !is_aes(0x6611) && !is_aes(0x6609));
        assert_eq!(method_name(8), Some("deflate"));
        assert_eq!(method_name(97), None);
    }
}
