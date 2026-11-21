//! Parallel directory walker and magic-byte detection.
//!
//! Walks directories with `walkdir` and identifies archive formats by their
//! magic bytes, using `rayon` for parallelism.
//!
//! Detection reads the first bytes of a file. A program (PE or ELF) is read further, as far
//! as an archive can start behind a self-extracting stub. A file that starts with neither a
//! signature nor a program has its end looked at, because a ZIP archive is found from its
//! end: the last volume of a split archive and an archive behind other bytes start with
//! nothing that says so. The bytes of an archive are not kept: whoever processes it reads the
//! file then, one at a time.

pub mod magic;

use std::fs::File;
use std::io::Read as _;
use std::io::Seek as _;
use std::io::SeekFrom;
use std::path::Path;
use std::path::PathBuf;

use rayon::prelude::IntoParallelIterator as _;
use rayon::prelude::ParallelIterator as _;
use walkdir::WalkDir;

use crate::analysis::Format;
use crate::formats::source::Source;

/// An archive found by a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Path to the archive file.
    pub path: PathBuf,
    /// Detected archive format.
    pub kind: Format,
    /// Byte offset of the archive signature in the file: 0 for a plain archive, the length
    /// of the program in front for a self-extracting one.
    pub sfx_offset: usize,
}

/// A path that could not be read during a scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanError {
    /// The path given, or the file or directory below it.
    pub path: PathBuf,
    /// What went wrong.
    pub message: String,
}

/// What a scan found, each list sorted by path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scan {
    /// The archives.
    pub archives: Vec<ScanResult>,
    /// The paths that could not be read.
    pub errors: Vec<ScanError>,
    /// The files that were named among the given paths and are no archive. A file that a walk
    /// over a directory comes by is passed over and is not listed here.
    pub not_archives: Vec<PathBuf>,
}

/// One file to look at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Candidate {
    /// The path it was reached by.
    path: PathBuf,
    /// Whether it was named among the given paths, and not come by in a walk.
    named: bool,
}

/// Minimum file size worth scanning (shortest signature is 4 bytes).
const MIN_FILE_SIZE: u64 = 4;

/// Scan one or more paths for archive files.
///
/// Directories are walked recursively. Each regular file is checked for
/// magic bytes at offset 0, and a program is searched for the signature of an archive
/// behind it. Files are examined in parallel and reported in the order of their paths, a
/// file once however many of the given paths lead to it and however they spell it: two paths
/// are one file when they resolve to the same place.
///
/// A file is an archive by what it holds, whatever it is called: a later volume of a set
/// starts with the signature of its format and is found like any other archive.
#[must_use]
pub fn scan_paths(paths: &[PathBuf]) -> Scan {
    let mut files = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        collect_files(path, &mut files, &mut errors);
    }
    let files = once_each(files);

    let detected: Vec<(Candidate, std::io::Result<Option<(Format, usize)>>)> = files
        .into_par_iter()
        .map(|file| {
            let found = detect_file(&file.path);
            (file, found)
        })
        .collect();

    let mut archives = Vec::new();
    let mut not_archives = Vec::new();
    for (file, outcome) in detected {
        match outcome {
            Ok(Some((kind, sfx_offset))) => archives.push(ScanResult { path: file.path, kind, sfx_offset }),
            Ok(None) if file.named => not_archives.push(file.path),
            Ok(None) => tracing::debug!("{}: not an archive, passed over", file.path.display()),
            Err(error) => errors.push(ScanError { path: file.path, message: error.to_string() }),
        }
    }
    errors.sort_by(|a, b| a.path.cmp(&b.path));
    Scan { archives, errors, not_archives }
}

/// The files in the order of their paths, each file once.
///
/// Two paths are one file when they resolve to the same place: `a.zip` and `./dir/../a.zip`,
/// or a file and a link to it. The file keeps the path that sorts first, and it counts as
/// named when any of its paths was.
fn once_each(mut files: Vec<Candidate>) -> Vec<Candidate> {
    files.sort();
    let mut places: std::collections::HashMap<PathBuf, usize> = std::collections::HashMap::new();
    let mut kept: Vec<Candidate> = Vec::new();
    for file in files {
        // a path that cannot be resolved stands for itself, and is reported when it is read
        let place = std::fs::canonicalize(&file.path).unwrap_or_else(|_| file.path.clone());
        if let Some(first) = places.get(&place).and_then(|&at| kept.get_mut(at)) {
            first.named |= file.named;
        } else {
            let _ = places.insert(place, kept.len());
            kept.push(file);
        }
    }
    kept
}

/// List the regular files a given path stands for: itself, or everything below a directory.
fn collect_files(root: &Path, files: &mut Vec<Candidate>, errors: &mut Vec<ScanError>) {
    match std::fs::metadata(root) {
        Ok(meta) if meta.is_file() => {
            files.push(Candidate { path: root.to_path_buf(), named: true });
            return;
        },
        Ok(_) => {},
        Err(error) => {
            errors.push(ScanError { path: root.to_path_buf(), message: error.to_string() });
            return;
        },
    }

    for entry in WalkDir::new(root).follow_links(true) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                let path = error.path().map_or_else(|| root.to_path_buf(), Path::to_path_buf);
                if error.loop_ancestor().is_some() || is_dangling_link(&path) {
                    // nothing is lost: a loop leads back to a directory that is walked, and
                    // a link to nowhere has no file behind it
                    tracing::debug!("{}: skipped: {error}", path.display());
                } else {
                    let message = error.io_error().map_or_else(|| error.to_string(), ToString::to_string);
                    errors.push(ScanError { path, message });
                }
                continue;
            },
        };
        if !entry.file_type().is_file() {
            continue;
        }
        match entry.metadata() {
            Ok(meta) if meta.len() < MIN_FILE_SIZE => {},
            Ok(_) => files.push(Candidate { path: entry.into_path(), named: false }),
            Err(error) => {
                let message = error.io_error().map_or_else(|| error.to_string(), ToString::to_string);
                errors.push(ScanError { path: entry.into_path(), message });
            },
        }
    }
}

/// Whether `path` is a symbolic link whose target does not exist.
fn is_dangling_link(path: &Path) -> bool {
    path.symlink_metadata().is_ok_and(|meta| meta.file_type().is_symlink()) && !path.exists()
}

/// Read up to `limit` bytes from where `file` stands.
fn read_up_to(file: &mut File, limit: usize, into: &mut Vec<u8>) -> std::io::Result<()> {
    let limit = u64::try_from(limit).unwrap_or(u64::MAX);
    file.by_ref().take(limit).read_to_end(into).map(|_| ())
}

/// Decide what one file is from as little of it as that takes.
///
/// The first bytes settle it for an archive that starts with its signature. A program is read
/// as far as an archive can start behind it, and its last bytes say whether it ends in a ZIP
/// archive. Any other file is a ZIP archive when it ends in one. Returns the kind and the
/// offset of the signature, which is 0 for an archive that was found by its end.
fn detect_file(path: &Path) -> std::io::Result<Option<(Format, usize)>> {
    let mut file = File::open(path)?;

    let mut window = Vec::with_capacity(magic::SIGNATURE_MAX);
    read_up_to(&mut file, magic::SIGNATURE_MAX, &mut window)?;
    if let Some(kind) = magic::detect(&window) {
        return Ok(Some((kind, 0)));
    }
    if !magic::is_executable(&window) {
        return Ok(ends_in_zip(path, false).then_some((Format::Zip, 0)));
    }

    let len = file.metadata()?.len();
    read_up_to(&mut file, magic::SFX_WINDOW.saturating_sub(window.len()), &mut window)?;

    let tail_len = u64::try_from(magic::ZIP_TAIL).unwrap_or(u64::MAX);
    let in_window = u64::try_from(window.len()).unwrap_or(u64::MAX);
    let mut far_end = Vec::new();
    let tail = if len > in_window {
        // the file goes on past the window: fetch its end
        let _ = file.seek(SeekFrom::Start(len.saturating_sub(tail_len)))?;
        read_up_to(&mut file, magic::ZIP_TAIL, &mut far_end)?;
        far_end.as_slice()
    } else {
        window.get(window.len().saturating_sub(magic::ZIP_TAIL)..).unwrap_or(&window)
    };

    let found = magic::scan_sfx(&magic::Program { window: &window, tail, len });
    // a program whose archive has something behind its end record, a signature for one
    Ok(found.or_else(|| ends_in_zip(path, true).then_some((Format::Zip, 0))))
}

/// Whether the file ends in a ZIP archive, as the ZIP parser finds one. With `behind`, bytes
/// may follow the end record.
fn ends_in_zip(path: &Path, behind: bool) -> bool {
    Source::open(path, 0).is_ok_and(|source| crate::formats::zip::parser::ends_in_archive(&source, behind))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/{rel}")).unwrap()
    }

    fn names(scan: &Scan) -> Vec<String> {
        scan.archives.iter().map(|found| found.path.file_name().unwrap().to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn archives_come_back_sorted_by_path_and_once_each() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        // written in an order that is neither the sorted one nor its reverse
        for name in ["m.zip", "z.zip", "a.zip", "sub/k.zip", "b.zip"] {
            std::fs::write(dir.path().join(name), fixture("zip-crypto/zipcrypto.zip")).unwrap();
        }
        std::fs::write(dir.path().join("notes.txt"), b"not an archive at all").unwrap();

        let scan = scan_paths(&[dir.path().to_path_buf()]);
        assert_eq!(names(&scan), ["a.zip", "b.zip", "m.zip", "k.zip", "z.zip"]);
        assert!(scan.archives.is_sorted_by(|a, b| a.path < b.path));
        assert!(scan.errors.is_empty());

        // the same files through three overlapping arguments, given back to front
        let again = scan_paths(&[dir.path().join("z.zip"), sub, dir.path().to_path_buf()]);
        assert_eq!(again, scan);
    }

    #[test]
    fn a_file_reached_by_two_spellings_of_its_path_is_one_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        let archive = dir.path().join("a.zip");
        std::fs::write(&archive, fixture("zip-crypto/zipcrypto.zip")).unwrap();

        let spelled = dir.path().join("sub").join("..").join("a.zip");
        let scan = scan_paths(&[spelled.clone(), archive.clone(), dir.path().to_path_buf()]);
        assert_eq!(scan.archives.len(), 1, "{:?}", scan.archives);
        // the path that sorts first is the one the file is reported by
        assert_eq!(scan.archives[0].path, std::cmp::min(spelled, archive));
    }

    #[cfg(unix)]
    #[test]
    fn a_file_and_a_link_to_it_are_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("real.zip");
        std::fs::write(&archive, fixture("zip-crypto/zipcrypto.zip")).unwrap();
        std::os::unix::fs::symlink(&archive, dir.path().join("link.zip")).unwrap();

        let scan = scan_paths(&[dir.path().to_path_buf()]);
        assert_eq!(names(&scan), ["link.zip"], "one file, under the path that sorts first");
    }

    #[test]
    fn a_named_file_that_is_no_archive_is_listed_and_one_in_a_walk_is_passed_over() {
        let dir = tempfile::tempdir().unwrap();
        let named = dir.path().join("named.txt");
        std::fs::write(&named, b"not an archive at all").unwrap();
        let walked = dir.path().join("walked");
        std::fs::create_dir_all(&walked).unwrap();
        std::fs::write(walked.join("notes.txt"), b"not an archive either").unwrap();
        std::fs::write(walked.join("a.zip"), fixture("zip-crypto/zipcrypto.zip")).unwrap();
        // shorter than any signature, and named all the same
        let tiny = dir.path().join("tiny");
        std::fs::write(&tiny, b"PK").unwrap();

        let scan = scan_paths(&[named.clone(), walked, tiny.clone()]);
        assert_eq!(names(&scan), ["a.zip"]);
        assert_eq!(scan.not_archives, [named, tiny]);
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn a_walk_goes_as_deep_as_the_directories_do() {
        let dir = tempfile::tempdir().unwrap();
        let mut deep = dir.path().to_path_buf();
        for _ in 0..80 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("deep.zip"), fixture("zip-crypto/zipcrypto.zip")).unwrap();

        let scan = scan_paths(&[dir.path().to_path_buf()]);
        assert_eq!(names(&scan), ["deep.zip"]);
        assert!(scan.errors.is_empty());
    }

    #[test]
    fn a_path_that_does_not_exist_is_an_error_and_the_rest_is_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.zip");
        std::fs::write(&archive, fixture("zip-crypto/zipcrypto.zip")).unwrap();
        let missing = dir.path().join("missing.zip");

        let scan = scan_paths(&[missing.clone(), archive.clone()]);
        assert_eq!(scan.archives, [ScanResult { path: archive, kind: Format::Zip, sfx_offset: 0 }]);
        assert_eq!(scan.errors.len(), 1);
        assert_eq!(scan.errors[0].path, missing);
        assert!(!scan.errors[0].message.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_nowhere_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(dir.path().join("gone"), dir.path().join("dangling")).unwrap();
        std::fs::write(dir.path().join("a.zip"), fixture("zip-crypto/zipcrypto.zip")).unwrap();

        let scan = scan_paths(&[dir.path().to_path_buf()]);
        assert_eq!(names(&scan), ["a.zip"]);
        assert!(scan.errors.is_empty(), "{:?}", scan.errors);
    }

    /// A terabyte: more than detection could read into memory, or read at all in the time a
    /// test has. The files are holes, so they cost no disk.
    #[cfg(target_os = "linux")]
    const HUGE: u64 = 1 << 40;

    #[cfg(target_os = "linux")]
    fn huge_file(path: &Path, start: &[u8]) {
        std::fs::write(path, start).unwrap();
        std::fs::OpenOptions::new().write(true).open(path).unwrap().set_len(HUGE).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detection_reads_the_start_of_a_file_and_not_the_file() {
        let dir = tempfile::tempdir().unwrap();

        let plain = dir.path().join("huge.bin");
        huge_file(&plain, b"nothing an archive starts with");
        assert_eq!(detect_file(&plain).unwrap(), None);

        // an archive signature in front: found from the first bytes
        let archive = dir.path().join("huge.7z");
        huge_file(&archive, &fixture("7z-aes/flag.7z"));
        assert_eq!(detect_file(&archive).unwrap(), Some((Format::SevenZ, 0)));

        // a program: its start is searched and its end is looked at, no more
        let program = dir.path().join("huge.elf");
        huge_file(&program, b"\x7fELF");
        assert_eq!(detect_file(&program).unwrap(), None);

        let scan = scan_paths(&[dir.path().to_path_buf()]);
        assert_eq!(scan.archives, [ScanResult { path: archive, kind: Format::SevenZ, sfx_offset: 0 }]);
        assert!(scan.errors.is_empty(), "{:?}", scan.errors);
    }

    #[test]
    fn a_self_extracting_zip_longer_than_the_window_is_found_by_its_end() {
        // program, then a ZIP archive whose end record lies far past what is read from the start
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big-sfx.exe");
        let archive = fixture("zip-crypto/zipcrypto.zip");
        let mut data = b"MZ".to_vec();
        data.resize(4096, 0);
        data.extend_from_slice(&archive);
        std::fs::write(&path, &data).unwrap();
        assert_eq!(detect_file(&path).unwrap(), Some((Format::Zip, 4096)));

        // the same local header with the end of the archive pushed out of reach of the window
        let (body, end) = archive.split_at(archive.len() - 22);
        let mut data = b"MZ".to_vec();
        data.resize(4096, 0);
        data.extend_from_slice(body);
        data.resize(magic::SFX_WINDOW + (1 << 20), 0);
        data.extend_from_slice(end);
        std::fs::write(&path, &data).unwrap();
        assert_eq!(detect_file(&path).unwrap(), Some((Format::Zip, 4096)));

        // without an end record the local header is only bytes in a program
        data.truncate(data.len() - 22);
        std::fs::write(&path, &data).unwrap();
        assert_eq!(detect_file(&path).unwrap(), None);
    }

    /// A ZIP archive is found from its end, so one that starts with neither a signature nor a
    /// program is still an archive: the last volume of a split set starts in the middle of an
    /// entry, and a script or a picture can stand in front of an archive.
    #[test]
    fn a_zip_archive_that_starts_with_something_else_is_found_by_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let archive = fixture("zip-crypto/zipcrypto.zip");

        let behind_a_script = dir.path().join("installer.sh");
        let mut data = b"#!/bin/sh\necho unpacking\nexit 0\n".to_vec();
        data.extend_from_slice(&archive);
        std::fs::write(&behind_a_script, &data).unwrap();
        assert_eq!(detect_file(&behind_a_script).unwrap(), Some((Format::Zip, 0)));

        // an end record that names a central directory that is not there is only bytes
        let only_a_record = dir.path().join("record.bin");
        let mut data = vec![0x55_u8; 4096];
        data.extend_from_slice(&archive[archive.len() - 22..]);
        std::fs::write(&only_a_record, &data).unwrap();
        assert_eq!(detect_file(&only_a_record).unwrap(), None);

        // a self-extracting archive with a signature appended: the end record is not at the end
        let signed = dir.path().join("signed.exe");
        let mut data = b"MZ".to_vec();
        data.resize(4096, 0);
        data.extend_from_slice(&archive);
        data.extend_from_slice(&[0xA5; 1800]);
        std::fs::write(&signed, &data).unwrap();
        assert_eq!(detect_file(&signed).unwrap(), Some((Format::Zip, 0)));

        // a program that ends in bytes and no archive stays what it is
        let program = dir.path().join("plain.exe");
        let mut data = b"MZ".to_vec();
        data.resize(8192, 0x90);
        std::fs::write(&program, &data).unwrap();
        assert_eq!(detect_file(&program).unwrap(), None);
    }

    /// A later volume of a set is an archive. It used to be passed over for its name, in a walk
    /// and when it was named itself.
    #[test]
    fn a_later_volume_is_found_like_any_archive_whatever_its_name() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["set.part1.rar", "set.part2.rar", "set.part10.rar", "set.r00", "set.r17", "plain.bin"] {
            std::fs::write(dir.path().join(name), fixture("unparseable/vols.part2.rar")).unwrap();
        }
        let scan = scan_paths(&[dir.path().to_path_buf()]);
        assert_eq!(names(&scan), ["plain.bin", "set.part1.rar", "set.part10.rar", "set.part2.rar", "set.r00", "set.r17"]);
        assert!(scan.archives.iter().all(|found| found.kind == Format::Rar && found.sfx_offset == 0));

        // named on its own
        let later = PathBuf::from("tests/fixtures/unparseable/big.part3.rar");
        assert_eq!(scan_paths(std::slice::from_ref(&later)).archives, [ScanResult { path: later, kind: Format::Rar, sfx_offset: 0 }]);
    }
}
