//! The search of the 2^23 keys a RAR 1.3 password can give, and the decrypted copy of the
//! archive that the key found is written into.
//!
//! No hashcat mode exists for this scheme, so the result of the attack is the key and a copy
//! of the archive with the same entries and the password flag cleared, which any tool that
//! reads RAR 1.3 unpacks. That copy is the one file the tool ever writes: to a path that is
//! named for it, in a file that is created for it.

mod content;
mod crack;
mod decrypt;
mod sweep;

use std::path::Path;

use anyhow::Context as _;

use self::decrypt::Recovery;
use self::decrypt::Run;
use self::decrypt::Selection;
use self::sweep::Notes;
use crate::analysis::Format;
pub use crate::attack::budget::Budget;
use crate::formats::limits::MAX_ATTACK_ARCHIVE;
use crate::formats::rar::headers::RarGeneration;
use crate::formats::source::Source;
use crate::scanner::scan_paths;

/// How a search for the key of a RAR 1.3 archive ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Search {
    /// One key is left.
    Key {
        /// The key.
        key: [u8; 3],
        /// What tells it from every other key, in words.
        how: String,
    },
    /// Several keys satisfy every entry checksum and nothing tells them apart.
    Ambiguous(Vec<[u8; 3]>),
    /// No key satisfies the entry checksums.
    NoKey,
    /// No entry of the archive is encrypted: there is no key to search for.
    NothingEncrypted,
    /// The search did not reach its end, and so found nothing: its estimate was over the
    /// budget and it was not started, or the budget ended it. What happened, how far it got
    /// and how to raise the budget, in words.
    Stopped(String),
}

/// What a search is given besides the archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The time the search may take.
    pub budget: Budget,
    /// No notes on standard error: neither the estimate nor the progress.
    pub quiet: bool,
}

/// Make sure that nothing is in the place the decrypted copy is to be written to.
///
/// An error when anything is there, a symbolic link included, whatever it points at, and when
/// the directory the file is to be created in is not there. The command asks this before the
/// search, which can take minutes. [`write_decrypted`] holds the same line by itself when it
/// creates the file.
pub fn check_output(output: &Path) -> anyhow::Result<()> {
    match output.symlink_metadata() {
        Ok(meta) if meta.file_type().is_symlink() => anyhow::bail!("{} is a symbolic link: it is not followed, and nothing is written", output.display()),
        Ok(_) => anyhow::bail!("{} exists: it is not overwritten, and nothing is written", output.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
        Err(error) => anyhow::bail!("cannot create {}: {error}", output.display()),
    }
    let directory = output.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    anyhow::ensure!(directory.is_dir(), "cannot create {}: {} is not a directory", output.display(), directory.display());
    Ok(())
}

/// Read the RAR 1.3 archive in the file at `path`: its bytes from the signature on, without
/// the program in front of a self-extracting archive.
///
/// The key search tests every key on the packed data of an entry, so this command holds its
/// archive in memory, which no other command does. The archive is found and its generation
/// read by range first, and one over [`MAX_ATTACK_ARCHIVE`] is refused before a byte of its
/// data is read.
pub fn read_archive(path: &Path) -> anyhow::Result<Source> {
    let is_file = std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?.is_file();
    anyhow::ensure!(is_file, "{} is not a file", path.display());

    let scan = scan_paths(&[path.to_path_buf()]);
    if let Some(error) = scan.errors.first() {
        anyhow::bail!("cannot read {}: {}", path.display(), error.message);
    }
    let Some(found) = scan.archives.first().filter(|found| found.kind == Format::Rar) else {
        anyhow::bail!("{} is not a RAR archive", path.display());
    };

    let file = Source::open(path, u64::try_from(found.sfx_offset)?).with_context(|| format!("cannot read {}", path.display()))?;
    let (start, parsed) = crate::formats::rar::headers::parse(&file).with_context(|| format!("cannot read {}", path.display()))?;
    anyhow::ensure!(parsed.generation == RarGeneration::Rar1, "{} is not an archive of RAR 1.3 or 1.4, and the attack reads no other: `archivewolf info` says what it is and which lines exist for it", path.display());

    let len = file.len().saturating_sub(start);
    anyhow::ensure!(len <= MAX_ATTACK_ARCHIVE, "{} holds an archive of {len} bytes, and the key search holds its archive in memory: {MAX_ATTACK_ARCHIVE} bytes at most", path.display());
    let bytes = file.read_at(start, len).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(Source::from_bytes(bytes))
}

/// Search the keys a RAR 1.3 password can give for the one that decrypts `archive`, which is
/// what [`read_archive`] returns.
///
/// A key is tested by decrypting an entry, unpacking it and comparing its checksum. The
/// checksum has 16 bits, so several keys can pass it: they are narrowed over all entries, and
/// by what the entries decrypt to. An error is an archive that cannot be searched at all.
///
/// Every key has to be tested before one can be told from those that pass by chance, so the
/// first pass over the keys is made on the entry that is cheapest to test. What it takes is
/// measured in the first moments and noted on standard error with the entry, before the pass
/// starts; its progress is noted while it runs. A search whose estimate is over the budget is
/// not started, and one that the budget ends has found nothing: both are [`Search::Stopped`].
pub fn search(archive: &Source, options: Options) -> anyhow::Result<Search> {
    let run = Run { budget: options.budget, notes: Notes { quiet: options.quiet } };
    let recovery = crate::run::isolate::run(|| decrypt::recover_key(archive, run)).map_err(|panicked| anyhow::anyhow!("internal error: {}", panicked.summary))??;
    let Some((recovery, left_out)) = recovery else { return Ok(Search::NothingEncrypted) };
    // a key is only as sure as the entries it was tested on
    let tested = if left_out == 0 { "every entry checksum".to_owned() } else { format!("the checksum of every entry that was tested ({left_out} could not be)") };
    Ok(match recovery {
        Recovery::NoKey => Search::NoKey,
        Recovery::Unique(key) => Search::Key { key, how: format!("the only key that satisfies {tested}") },
        Recovery::Selected { key, equivalent, by } => {
            let why = match by {
                Selection::StreamLength => "whose compressed data ends exactly at the packed size",
                Selection::Content => "that decrypts to recognisable content",
            };
            let checksum = if left_out == 0 { "the 16-bit entry checksum".to_owned() } else { tested };
            Search::Key { key, how: format!("{equivalent} keys satisfy {checksum}; this is the only one {why}") }
        },
        Recovery::Ambiguous(keys) => Search::Ambiguous(keys),
        Recovery::Stopped(why) => Search::Stopped(why),
    })
}

/// Write a copy of `archive` with every encrypted entry decrypted by `key` and its password
/// flag cleared, to a new file at `output`. Returns the number of entries decrypted.
///
/// The file is created by this call or not at all: a file that is there is not overwritten,
/// and a symbolic link is not followed.
pub fn write_decrypted(archive: &Source, key: [u8; 3], output: &Path) -> anyhow::Result<usize> {
    decrypt::write_plaintext_archive(archive, key, output).with_context(|| format!("cannot create {}", output.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORED: &str = "tests/fixtures/rar-13/rar14-password-stored.rar";
    /// The key the password "password" gives.
    const KEY: [u8; 3] = [0x73, 0x1f, 0x3d];
    /// A search with no limit that notes nothing.
    const QUIET: Options = Options { budget: Budget::Unlimited, quiet: true };

    #[test]
    fn the_key_of_a_stored_archive_is_found_and_the_copy_has_nothing_encrypted() {
        let archive = read_archive(Path::new(STORED)).unwrap();
        assert_eq!(crack::key_from_password(b"password"), KEY);
        let Search::Key { key, how } = search(&archive, QUIET).unwrap() else { panic!("no key") };
        assert_eq!(key, KEY);
        assert!(!how.is_empty());

        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("copy.rar");
        check_output(&output).unwrap();
        assert!(write_decrypted(&archive, key, &output).unwrap() > 0);
        let copy = read_archive(&output).unwrap();
        assert_eq!(copy.len(), archive.len());
        assert_eq!(search(&copy, QUIET).unwrap(), Search::NothingEncrypted);
    }

    #[test]
    fn an_output_that_exists_is_refused_and_left_as_it_is() {
        let archive = read_archive(Path::new(STORED)).unwrap();
        let dir = tempfile::tempdir().unwrap();

        let existing = dir.path().join("existing.rar");
        std::fs::write(&existing, b"keep me").unwrap();
        let error = check_output(&existing).unwrap_err();
        assert!(error.to_string().contains("exists"), "{error}");
        // and the write itself never replaces a file, asked first or not
        assert!(write_decrypted(&archive, KEY, &existing).is_err());
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep me");

        // a directory is in the way like a file is
        assert!(check_output(dir.path()).is_err());
        // a file cannot be created in a directory that is not there, and none is made for it
        let nowhere = dir.path().join("absent").join("copy.rar");
        let error = check_output(&nowhere).unwrap_err();
        assert!(error.to_string().contains("is not a directory"), "{error}");
        assert!(write_decrypted(&archive, KEY, &nowhere).is_err());
        assert!(!dir.path().join("absent").exists());

        // a name alone is a file in the current directory
        check_output(Path::new("archivewolf-test-output-that-is-not-there.rar")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_refused_and_its_target_is_left_as_it_is() {
        let archive = read_archive(Path::new(STORED)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"keep me").unwrap();

        let link = dir.path().join("link.rar");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = check_output(&link).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(write_decrypted(&archive, KEY, &link).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep me");

        // a link to nowhere is a link all the same: the file it names is not created
        let missing = dir.path().join("missing.txt");
        let dangling = dir.path().join("dangling.rar");
        std::os::unix::fs::symlink(&missing, &dangling).unwrap();
        assert!(check_output(&dangling).unwrap_err().to_string().contains("symbolic link"));
        assert!(write_decrypted(&archive, KEY, &dangling).is_err());
        assert!(!missing.exists());
    }

    /// The key search holds its archive in memory, so an archive over the limit is refused,
    /// and before its data is read: the file here is a header and a hole of more than 1 GiB.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_archive_over_the_limit_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let huge = dir.path().join("huge.rar");
        std::fs::write(&huge, b"RE~^\x07\x00\x00").unwrap();
        std::fs::OpenOptions::new().write(true).open(&huge).unwrap().set_len(MAX_ATTACK_ARCHIVE + 1).unwrap();
        let error = format!("{:#}", read_archive(&huge).unwrap_err());
        assert!(error.contains("holds its archive in memory") && error.contains("1073741824 bytes at most"), "{error}");

        // at the limit it is read: that is tested on what fits a test, an archive of a few bytes
        let small = dir.path().join("small.rar");
        std::fs::write(&small, b"RE~^\x07\x00\x00").unwrap();
        assert_eq!(read_archive(&small).unwrap().held().map(<[u8]>::len), Some(7));
    }

    #[test]
    fn only_a_rar_13_archive_is_read() {
        for (path, why) in [
            ("tests/fixtures/rar-50/v730_p_m3.rar", "is not an archive of RAR 1.3 or 1.4"),
            ("tests/fixtures/rar-15/rar15-password-stored.rar", "is not an archive of RAR 1.3 or 1.4"),
            ("tests/fixtures/zip-crypto/zipcrypto.zip", "not a RAR archive"),
            ("Cargo.toml", "not a RAR archive"),
            ("tests/fixtures", "is not a file"),
            ("tests/fixtures/absent.rar", "cannot read"),
        ] {
            let error = read_archive(Path::new(path)).unwrap_err();
            assert!(format!("{error:#}").contains(why), "{path}: {error:#}");
        }
    }

    #[test]
    fn an_archive_with_nothing_encrypted_has_no_key_to_search_for() {
        let archive = read_archive(Path::new("tests/fixtures/unencrypted/rar14-solid.rar")).unwrap();
        assert_eq!(search(&archive, QUIET).unwrap(), Search::NothingEncrypted);
    }
}
