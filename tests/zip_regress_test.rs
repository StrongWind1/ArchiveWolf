//! ZIP archives that once got a wrong answer, through the command as a user runs it.
//!
//! Each test names what went wrong. The archives are real ones: two fixtures under
//! `tests/fixtures/regress/zip` that were made for these cases (passwords `pw` and
//! `7z-aes256_deflate`), and fixtures of the other tests with bytes put in front of them or
//! behind them here.
//!
//! The last test compares with another program, `zipinfo`. It is ignored in the default run
//! and fails when the program is missing: `cargo test --test zip_regress_test -- --ignored`.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

// A test crate is linked against every dependency of the package, and the lint
// `unused_crate_dependencies` wants each of them named. These tests run the binary and other
// programs, and need none of these.
use anyhow as _;
use archivewolf as _;
use archivewolf_zip_crypto as _;
use assert_cmd as _;
use clap as _;
use crc32fast as _;
use flate2 as _;
use hex as _;
use lzma_rust2 as _;
use predicates as _;
use proptest as _;
use rayon as _;
use serde as _;
use serde_json::Value;
use sha2 as _;
use tracing as _;
use tracing_subscriber as _;
use walkdir as _;

/// What a run of the command gave.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `archivewolf` with `arguments`.
fn archivewolf(arguments: &[&str]) -> Result<Run, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(arguments).env_remove("RUST_LOG").output().map_err(|error| format!("archivewolf could not be started: {error}"))?;
    Ok(Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned() })
}

/// The lines `hash` writes for an archive, which it has to process without a failure.
fn lines_of(archive: &Path) -> Result<Vec<String>, String> {
    let path = archive.to_str().ok_or("a path that is not UTF-8")?;
    let run = archivewolf(&["hash", path])?;
    if run.code != Some(0) {
        return Err(format!("hash {path}: status {:?}: {}", run.code, run.stderr));
    }
    Ok(run.stdout.lines().map(str::to_owned).collect())
}

/// The analysis of an archive as `info --json` prints it.
fn report_of(archive: &Path) -> Result<Value, String> {
    let path = archive.to_str().ok_or("a path that is not UTF-8")?;
    let run = archivewolf(&["info", "--json", path])?;
    if run.code != Some(0) {
        return Err(format!("info {path}: status {:?}: {}", run.code, run.stderr));
    }
    serde_json::from_str(run.stdout.trim()).map_err(|error| format!("info {path}: {error}: {}", run.stdout))
}

fn fixture(rel: &str) -> PathBuf {
    Path::new("tests/fixtures").join(rel)
}

/// A ZIP64 extra field holds a value for each header field that is 0xFFFFFFFF and for no
/// other. The entry of this archive has the offset alone there, as every entry past 4 GiB with
/// small sizes has, and its eight bytes were read as the uncompressed size: the entry was
/// looked for at the wrong place and the archive got no line.
#[test]
fn a_zip64_extra_field_that_holds_the_offset_alone() {
    let archive = fixture("regress/zip/zip64_offset_only.zip");
    assert_eq!(lines_of(&archive).unwrap(), ["$zip$1$*1*e2e717cf722432066bf6e167/bd*8*bdefc3cd*6e0*3d*8fa067aa59978b30e2a454ba487ff7292585bf7d39cc9bca54ae6c90c2cf462b06118fd17e1173aaade767cc8b3c5c46db6623dea89bc4208cc592fb28$/zip$"]);

    let report = report_of(&archive).unwrap();
    assert_eq!((&report["generation"], &report["volume"]), (&"zip64".into(), &"single".into()));
    let entry = &report["entry_list"][1];
    assert_eq!((&entry["name"], &entry["state"], &entry["packed"], &entry["size"]), (&"secret.txt".into(), &"encrypted".into(), &73.into(), &1760.into()));
    assert_eq!(report["lines"], serde_json::json!([{ "mode": 46100, "tag": "$zip$1$", "entry": 1, "proves": "exact" }]));
}

/// An empty directory that is marked as WinZip AES cannot carry data. It ranked first, gave
/// no line, and the archive was left without one, although the file beside it gives one.
#[test]
fn a_directory_that_is_marked_as_encrypted_does_not_take_the_line() {
    let archive = fixture("regress/zip/aes_directory_entry.zip");
    let lines = lines_of(&archive).unwrap();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("$zip$2$*3*9a8661046f275e3652a68db2f093d314*7472*87e3b9dd158afcb10291*8*31b9*5e4df7a6"), "{}", lines[0]);

    let report = report_of(&archive).unwrap();
    let kinds: Vec<(&Value, &Value, &Value)> = report["entry_list"].as_array().unwrap().iter().map(|entry| (&entry["name"], &entry["kind"], &entry["state"])).collect();
    assert_eq!(kinds, [(&"docs/".into(), &"directory".into(), &"encrypted".into()), (&"text40k.txt".into(), &"file".into(), &"encrypted".into())]);
    assert_eq!(report["lines"][0]["entry"], 1);
    assert_eq!(report["no_line"], serde_json::json!([{ "entry": 0, "reason": "no-data", "text": "it is empty, so every password would match" }]), "the directory has nothing to test and says so");
    // a run that asked for one line and got it is told nothing of the directory
    let best = archivewolf(&["hash", archive.to_str().unwrap()]).unwrap();
    assert!(!best.stderr.contains("no line"), "{}", best.stderr);

    // asked with --all, the directory says that it has nothing to test
    let all = archivewolf(&["hash", "--all", archive.to_str().unwrap()]).unwrap();
    assert_eq!((all.code, all.stdout.lines().count()), (Some(0), 1), "{}", all.stderr);
    assert!(all.stderr.contains("no line: docs/: it is empty, so every password would match [no-data]"), "{}", all.stderr);
}

/// Bytes behind the end record, as a download with a trailing newline or a file with a
/// signature appended has: "EOCD signature not found". `unzip` and `7zz` open such a file.
#[test]
fn bytes_behind_the_end_record() {
    let original = fixture("zip-crypto/7z.zip");
    let expected = lines_of(&original).unwrap();
    assert_eq!(expected.len(), 1);

    let dir = tempfile::tempdir().unwrap();
    for trailing in [1_usize, 22, 3000] {
        let mut bytes = std::fs::read(&original).unwrap();
        bytes.resize(bytes.len() + trailing, b'\n');
        let path = dir.path().join(format!("trailing-{trailing}.zip"));
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(lines_of(&path).unwrap(), expected, "{trailing} bytes behind the end record");
    }
}

/// A program in front of a ZIP64 archive moves the offset in the ZIP64 locator with every
/// other one: "ZIP64 EOCD: bad signature".
#[test]
fn a_program_in_front_of_a_zip64_archive() {
    let original = fixture("zip-crypto/gen_infozip_zip64.zip");
    let expected = lines_of(&original).unwrap();
    assert_eq!(expected.len(), 1);

    let mut bytes = b"MZ".to_vec();
    bytes.resize(128, 0x90);
    bytes.extend_from_slice(&std::fs::read(&original).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sfx-zip64.zip");
    std::fs::write(&path, bytes).unwrap();

    assert_eq!(lines_of(&path).unwrap(), expected);
    let report = report_of(&path).unwrap();
    assert_eq!((&report["generation"], &report["offset"], &report["volume"]), (&"zip64".into(), &128.into(), &"single".into()));
}

/// A file that is no archive at all, in the forms that once ended the process: none of them
/// is a failure of the run as a whole.
#[test]
fn what_cannot_be_parsed_is_reported_and_is_no_crash() {
    let dir = tempfile::tempdir().unwrap();
    // a local header, and an end record that names a directory of 2^32-1 bytes at 2^32-1
    let mut bytes = b"PK\x03\x04".to_vec();
    bytes.resize(64, 0);
    bytes.extend_from_slice(b"PK\x05\x06\0\0\0\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\0\0");
    let path = dir.path().join("lies.zip");
    std::fs::write(&path, bytes).unwrap();
    for command in ["info", "hash"] {
        let run = archivewolf(&[command, path.to_str().unwrap()]).unwrap();
        assert_eq!(run.code, Some(2), "{command}: {}", run.stderr);
        assert!(run.stdout.is_empty() && run.stderr.contains("central directory not found") && !run.stderr.contains("internal error"), "{command}: {}", run.stderr);
    }
}

/// One row of `zipinfo -l`: name, sizes, whether the entry is marked as encrypted.
#[derive(Debug, PartialEq, Eq)]
struct Listed {
    name: String,
    size: u64,
    packed: u64,
    marked: bool,
}

/// What `zipinfo -l` lists for an archive, or `None` when it does not list it as an archive
/// without a complaint.
fn zipinfo(archive: &Path) -> Result<Option<Vec<Listed>>, String> {
    let output = Command::new("zipinfo").arg("-l").arg(archive).output().map_err(|error| format!("zipinfo could not be started: {error}: the comparison needs Info-ZIP's zipinfo"))?;
    if output.status.code() != Some(0) {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut listed = Vec::new();
    // the rows stand between the two lines of the head and the line of totals
    for row in text.lines().skip(2).filter(|row| !row.contains(" bytes uncompressed, ")) {
        let fields: Vec<&str> = row.split_whitespace().collect();
        let [_, _, _, size, flags, packed, _, _, _, name @ ..] = fields.as_slice() else { return Ok(None) };
        let (Ok(size), Ok(packed)) = (size.parse(), packed.parse()) else { return Ok(None) };
        // a capital letter says that the entry is marked as encrypted
        listed.push(Listed { name: name.join(" "), size, packed, marked: flags.starts_with(|letter: char| letter.is_ascii_uppercase()) });
    }
    Ok(Some(listed))
}

/// What `info --json` lists for an archive, in the form of [`zipinfo`].
fn listed_by_archivewolf(archive: &Path) -> Result<Vec<Listed>, String> {
    let report = report_of(archive)?;
    let entries = report.get("entry_list").and_then(Value::as_array).ok_or("no entry list")?;
    entries
        .iter()
        .map(|entry| {
            let text = |field: &str| entry.get(field).and_then(Value::as_str);
            let number = |field: &str| entry.get(field).and_then(Value::as_u64);
            let (Some(name), Some(size), Some(packed), Some(state)) = (text("name"), number("size"), number("packed"), text("state")) else { return Err(format!("an entry without a name, a size or a state: {entry}")) };
            Ok(Listed { name: name.to_owned(), size, packed, marked: state != "plain" })
        })
        .collect()
}

/// The entries `info` lists are the entries `zipinfo` lists: the same number in the same
/// order, with the same sizes and the same mark of encryption, and the same names where a
/// name is plain ASCII without a blank run (the two programs show other names in their own
/// ways).
#[test]
#[ignore = "runs zipinfo"]
fn the_listing_is_that_of_zipinfo() {
    let mut compared = 0_usize;
    let mut differences = Vec::new();
    for directory in ["zip-crypto", "zip-winzip", "zip-pkware", "pseudo", "unencrypted", "unknown-pw", "regress/zip"] {
        let mut archives: Vec<PathBuf> = std::fs::read_dir(fixture(directory)).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.extension().is_some_and(|extension| extension == "zip")).collect();
        archives.sort();
        for archive in archives {
            let Some(theirs) = zipinfo(&archive).unwrap() else { continue };
            let Ok(ours) = listed_by_archivewolf(&archive) else { continue };
            compared += 1;
            let same_name = |a: &Listed, b: &Listed| a.name == b.name || !a.name.is_ascii() || a.name.contains("  ") || a.name.chars().any(char::is_control);
            let same = ours.len() == theirs.len() && ours.iter().zip(&theirs).all(|(a, b)| (a.size, a.packed, a.marked) == (b.size, b.packed, b.marked) && same_name(a, b));
            if !same {
                differences.push(format!("{}:\n  archivewolf {ours:?}\n  zipinfo     {theirs:?}", archive.display()));
            }
        }
    }
    assert!(compared >= 150, "only {compared} archives were listed by both");
    assert!(differences.is_empty(), "{} of {compared} listings differ:\n{}", differences.len(), differences.join("\n"));
}
