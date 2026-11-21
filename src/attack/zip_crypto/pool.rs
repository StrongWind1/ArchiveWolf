//! The archives of a run and the entries the attack can work on.
//!
//! `zip-crypto` has no salt: the keys at the start of every entry under one password are the
//! same, in every archive. So the entries of all the archives that are given are one pool.
//! An archive is read by range, with the parser
//! of `info`: the attack sees the entries that `info` lists.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;

use crate::analysis::Format;
use crate::formats::limits::Budget;
use crate::formats::source::Source;
use crate::formats::zip::data_extract::Data;
use crate::formats::zip::data_extract::locate;
use crate::formats::zip::encryption::ZipEncryption;
use crate::formats::zip::known;
use crate::formats::zip::known::Facts;
use crate::formats::zip::known::set::ByteSet;
use crate::formats::zip::known::types::Row;
use crate::formats::zip::known::types::fits;
use crate::formats::zip::known::writer::Writer;
use crate::formats::zip::parser::ZipEntry;
use crate::formats::zip::parser::filename_lossy;
use crate::formats::zip::parser::parse;
use crate::formats::zip::triage;
use crate::scanner::scan_paths;

use super::seed::yeka;

/// The length of the encryption header in front of the data of an entry.
pub(crate) const HEADER: u64 = 12;

/// One archive of a run.
#[derive(Debug)]
pub(crate) struct Archive {
    /// The path it was given by.
    pub path: PathBuf,
    /// The file, read by range.
    pub source: Source,
    /// Its entries, as `info` lists them.
    pub entries: Vec<ZipEntry>,
    /// The family of the program that wrote its encrypted entries.
    pub writer: Writer,
}

/// One entry of `zip-crypto` that the attack can work on: its data is in the file.
#[derive(Debug)]
pub(crate) struct Target {
    /// The archive it is in, by its place in the pool.
    pub archive: usize,
    /// Its place among the entries of that archive.
    pub index: usize,
    /// Its name, for people.
    pub name: String,
    /// What the directory says of it.
    pub entry: ZipEntry,
    /// Where its encryption header starts in the file.
    pub start: u64,
    /// The twelve bytes of its encryption header, as they stand in the archive.
    pub header: [u8; 12],
    /// What the archive itself says of its stream.
    pub facts: Facts,
}

impl Target {
    /// How many bytes its stream has behind the encryption header.
    #[must_use]
    pub(crate) const fn stream_len(&self) -> u64 {
        self.entry.compressed_size.saturating_sub(HEADER)
    }

    /// Every value the last byte of its encryption header may decrypt to, whatever its writer
    /// took it from: what a key of another entry is held against.
    #[must_use]
    pub(crate) fn last_check(&self) -> ByteSet {
        self.facts.checks.iter().filter_map(|way| way.form.get(-1)).fold(ByteSet::NONE, ByteSet::union)
    }
}

/// An encrypted entry the attack cannot work on, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LeftOut {
    /// The archive and the name of the entry.
    pub name: String,
    /// Why, in the words of a note.
    pub why: &'static str,
}

/// The archives of a run and their entries of `zip-crypto`.
#[derive(Debug, Default)]
pub(crate) struct Pool {
    /// The archives, in the order they were given.
    pub archives: Vec<Archive>,
    /// The entries the attack can work on, archive by archive, in the order of the directory.
    pub targets: Vec<Target>,
    /// The entries of `zip-crypto` it cannot.
    pub left_out: Vec<LeftOut>,
}

impl Pool {
    /// Read the archives. `kind_of` says which type the user gave for an entry of a name, when
    /// they gave one.
    ///
    /// An error is a path that is no ZIP archive or cannot be read: the user named it, and an
    /// attack on fewer archives than they meant is not what they asked for.
    pub(crate) fn read(paths: &[PathBuf], kind_of: &dyn Fn(&str) -> Option<&'static Row>) -> anyhow::Result<Self> {
        let mut pool = Self::default();
        for path in paths {
            let archive = open(path)?;
            let number = pool.archives.len();
            // what `info` unpacks of one archive to tell encrypted data from data that is only marked
            let mut budget = Budget::new();
            for (index, entry) in archive.entries.iter().enumerate().filter(|(_, entry)| entry.encryption == ZipEncryption::ZipCrypto && !entry.directory) {
                let name = filename_lossy(entry);
                let shown = if paths.len() > 1 { format!("{}: {name}", path.display()) } else { name.clone() };
                let mut left_out = |why| pool.left_out.push(LeftOut { name: shown.clone(), why });
                let start = match locate(&archive.source, entry) {
                    Data::Here(start) => start,
                    Data::Cut => {
                        left_out("its data runs past the end of the file");
                        continue;
                    },
                    Data::Missing => {
                        left_out("its data is not in this file");
                        continue;
                    },
                };
                // an entry is a target when `info` calls it encrypted, and not because its flag says so
                match triage::prove(&archive.source, entry, start, &mut budget) {
                    triage::Proof::Sealed | triage::Proof::NotRun => {},
                    triage::Proof::Open => {
                        left_out("it is not encrypted: its data unpacks as it stands to its CRC-32, and the flag was set on it all the same");
                        continue;
                    },
                    triage::Proof::SizesDisagree => {
                        left_out("it is stored, and its packed size is not its size and the twelve bytes of an encryption header: whatever encrypted it, it is not traditional encryption");
                        continue;
                    },
                }
                let mut header = [0_u8; 12];
                if entry.compressed_size < HEADER || archive.source.read_exact_at(start, &mut header).is_err() {
                    left_out("it is shorter than an encryption header");
                    continue;
                }
                let facts = known::facts(entry, archive.writer, kind_of(&name));
                pool.targets.push(Target { archive: number, index, name: shown, entry: entry.clone(), start, header, facts });
            }
            // a writer that puts the same ten bytes in front of every entry is known by them
            // for certain, whatever the directory says (section 8.6 of the design)
            let mut archive = archive;
            let headers: Vec<[u8; 12]> = pool.targets.iter().filter(|target| target.archive == number).map(|target| target.header).collect();
            // and the marks that yeka/zip leaves in the directory are not its own alone: its
            // headers have to speak for it too
            let writer = if yeka::recognise(&headers) { Writer::Yeka } else { archive.writer.held_against(&headers) };
            if archive.writer != writer {
                archive.writer = writer;
                for target in pool.targets.iter_mut().filter(|target| target.archive == number) {
                    target.facts = known::facts(&target.entry, writer, kind_of(&filename_lossy(&target.entry)));
                }
            }
            pool.archives.push(archive);
        }
        Ok(pool)
    }

    /// The bytes of the stream of a target at the positions `from` to `until - 1`, as they
    /// stand in the archive. Position -12 is the first byte of the encryption header. What
    /// lies outside the entry is not read: the answer is then shorter.
    pub(crate) fn cipher(&self, target: &Target, from: i64, until: i64) -> std::io::Result<Vec<u8>> {
        let end = i64::try_from(target.stream_len()).unwrap_or(i64::MAX);
        let (from, until) = (from.clamp(-12, end), until.clamp(-12, end));
        let Some(archive) = self.archives.get(target.archive) else { return Ok(Vec::new()) };
        let offset = target.start.saturating_add((from + 12).unsigned_abs());
        archive.source.read_at(offset, until.saturating_sub(from).unsigned_abs())
    }

    /// The source of the archive a target is in.
    #[must_use]
    pub(crate) fn source(&self, target: &Target) -> Option<&Source> {
        self.archives.get(target.archive).map(|archive| &archive.source)
    }

    /// The targets a pattern of the command line names: the name itself, a name with `*` for
    /// any text, or the last part of a name. An empty pattern names the one target there is.
    #[must_use]
    pub(crate) fn named(&self, pattern: &str) -> Vec<usize> {
        if pattern.is_empty() {
            return if self.targets.len() == 1 { vec![0] } else { Vec::new() };
        }
        self.targets.iter().enumerate().filter(|(_, target)| name_fits(pattern, &target.entry)).map(|(index, _)| index).collect()
    }
}

/// Whether a pattern of the command line names an entry.
#[must_use]
pub(crate) fn name_fits(pattern: &str, entry: &ZipEntry) -> bool {
    let name = filename_lossy(entry);
    let last = name.rsplit('/').next().unwrap_or(&name);
    fits(pattern, &name) || fits(pattern, last)
}

/// Open one archive: find it in its file, and read its directory.
fn open(path: &Path) -> anyhow::Result<Archive> {
    let is_file = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?.is_file();
    anyhow::ensure!(is_file, "{} is not a file", path.display());
    let scan = scan_paths(&[path.to_path_buf()]);
    if let Some(error) = scan.errors.first() {
        anyhow::bail!("cannot read {}: {}", path.display(), error.message);
    }
    anyhow::ensure!(scan.archives.first().is_some_and(|found| found.kind == Format::Zip), "{} is not a ZIP archive: `archivewolf info` says what it is", path.display());

    let source = Source::open(path, 0).with_context(|| format!("cannot read {}", path.display()))?;
    let zip = parse(&source).with_context(|| format!("cannot read {}", path.display()))?;
    let writer = Writer::of(&zip.entries);
    Ok(Archive { path: path.to_path_buf(), source, entries: zip.entries, writer })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(fixtures: &[&str]) -> Pool {
        let paths: Vec<PathBuf> = fixtures.iter().map(|name| PathBuf::from(format!("tests/fixtures/{name}"))).collect();
        Pool::read(&paths, &|_| None).unwrap()
    }

    fn one(fixture: &str) -> Pool {
        pool(&[fixture])
    }

    #[test]
    fn the_entries_of_zip_crypto_of_every_archive_are_one_pool() {
        let pool = pool(&["zip-crypto/bkcrack-src_secrets.zip", "zip-crypto/multi_stored.zip"]);
        assert_eq!(pool.archives.len(), 2);
        assert_eq!(pool.archives.iter().map(|archive| archive.writer).collect::<Vec<_>>(), [Writer::SevenZip, Writer::InfoZip]);
        let names: Vec<&str> = pool.targets.iter().map(|target| target.name.as_str()).collect();
        assert_eq!(names.len(), 5);
        assert!(names[0].ends_with("bkcrack-src_secrets.zip: advice.jpg") && names[1].ends_with(": spiral.svg"), "{names:?}");
        assert!(pool.left_out.is_empty());

        // the header and the stream are read where the local header puts them
        let spiral = &pool.targets[1];
        let recorded = std::fs::read("crates/zip-crypto/tests/data/spiral.cipher.bin").unwrap();
        assert_eq!(spiral.header[..], recorded[..12]);
        assert_eq!(spiral.stream_len() + 12, recorded.len() as u64);
        assert_eq!(pool.cipher(spiral, -12, 30).unwrap()[..], recorded[..42]);
        assert_eq!(pool.cipher(spiral, 1260, 5000).unwrap()[..], recorded[1272..]);
        assert_eq!(pool.cipher(spiral, -50, -11).unwrap()[..], recorded[..1]);
        assert_eq!(spiral.last_check().len(), 1);
    }

    #[test]
    fn the_constant_header_of_yeka_names_its_writer_for_certain() {
        let yeka = one("zip-crypto/gen_yeka_a.zip");
        assert_eq!(yeka.archives[0].writer, Writer::Yeka);
        // two check bytes, from the file time: every entry has a data descriptor
        assert!(yeka.targets.iter().all(|target| target.facts.checks[0].count == 2 && target.facts.checks[0].from == "file time"));
    }

    #[test]
    fn an_entry_is_named_by_its_name_a_pattern_or_its_last_part() {
        let secrets = pool(&["zip-crypto/bkcrack-src_secrets.zip"]);
        let pool = &secrets;
        assert_eq!(pool.named("spiral.svg"), [1]);
        assert_eq!(pool.named("*.svg"), [1]);
        assert_eq!(pool.named("*"), [0, 1]);
        assert_eq!(pool.named("advice.*"), [0]);
        assert!(pool.named("no-such-entry").is_empty());
        // no name is the one entry there is, and nothing when there are several
        assert!(pool.named("").is_empty());
        assert_eq!(one("zip-crypto/jpg.zip").named(""), [0]);
    }

    #[test]
    fn what_is_no_zip_archive_is_an_error_and_what_is_not_of_zip_crypto_is_no_target() {
        for (path, why) in [("tests/fixtures/rar-50/v730_p_m3.rar", "is not a ZIP archive"), ("Cargo.toml", "is not a ZIP archive"), ("tests/fixtures", "is not a file"), ("tests/fixtures/absent.zip", "cannot read")] {
            let error = Pool::read(&[PathBuf::from(path)], &|_| None).unwrap_err();
            assert!(format!("{error:#}").contains(why), "{path}: {error:#}");
        }
        let other = pool(&["zip-winzip/aes256.zip", "unencrypted/zip31c_unencrypted.zip"]);
        assert!(other.targets.is_empty() && other.left_out.is_empty() && other.archives.len() == 2);
    }

    #[test]
    fn an_entry_that_is_only_marked_as_zip_crypto_is_left_out_as_info_leaves_it() {
        // a cipher of its own behind the flag of traditional encryption: a stored entry that is
        // 72 bytes longer than its content, where an encryption header is twelve. It is an
        // archive of 7-Zip whose one entry is said, in both of its headers, to hold 60 bytes less
        let mut bytes = std::fs::read("tests/fixtures/zip-crypto/gen_7z_zipcrypto_copy.zip").unwrap();
        let word = |bytes: &[u8], at: usize| usize::try_from(u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])).unwrap();
        let directory = word(&bytes, bytes.len() - 6);
        assert_eq!((&bytes[..4], &bytes[directory..directory + 4]), (&b"PK\x03\x04"[..], &b"PK\x01\x02"[..]));
        for size_at in [22, directory + 24] {
            let less = u32::try_from(word(&bytes, size_at) - 60).unwrap();
            bytes[size_at..size_at + 4].copy_from_slice(&less.to_le_bytes());
        }
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("own.zip");
        std::fs::write(&path, bytes).unwrap();
        let own = Pool::read(&[path], &|_| None).unwrap();
        assert!(own.targets.is_empty());
        assert_eq!(own.left_out.len(), 1);
        assert!(own.left_out[0].name == "text40k.txt" && own.left_out[0].why.contains("it is not traditional encryption"), "{:?}", own.left_out);

        // the flag set on data that was never encrypted
        let marked = one("pseudo/pseudo.zip");
        assert!(marked.targets.is_empty());
        assert!(marked.left_out.iter().all(|left| left.why.starts_with("it is not encrypted")) && !marked.left_out.is_empty(), "{:?}", marked.left_out);
    }
}
