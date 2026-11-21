//! The RAR 1.3 key search, end to end.
//!
//! `attack rar-13` is run on every RAR 1.3 fixture with other programs hidden from `PATH`: the
//! tool starts none. Where `unrar` is installed, the test itself uses it to check that the
//! decrypted copy unpacks to what the original does with its password.
//!
//! The search has to test 2^23 keys, so what it costs is what one test costs: the tests here
//! hold it to the entry it chooses, to what it says before it starts and while it runs, and to
//! its budget. Archives that no fixture has are built here, under the key of the fixtures.
#![expect(unused_crate_dependencies, reason = "integration test")]
#![expect(clippy::unwrap_used, reason = "test helpers: panic on bad fixture data is intentional")]

use std::collections::BTreeMap;
use std::path::Path;

use assert_cmd::Command;

/// What one run of the binary gave back.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn unrar_available() -> bool {
    std::process::Command::new("unrar").output().is_ok()
}

/// Run `attack rar-13 <archive> -o <output>` with an empty `PATH`.
fn attack(archive: &Path, output: &Path) -> Run {
    attack_with(&[], archive, output, &[])
}

/// Run `<before> attack rar-13 <archive> -o <output> <after>` with an empty `PATH`.
fn attack_with(before: &[&str], archive: &Path, output: &Path, after: &[&str]) -> Run {
    let empty = tempfile::tempdir().unwrap();
    let out = Command::cargo_bin("archivewolf").unwrap().args(before).args(["attack", "rar-13"]).arg(archive).arg("-o").arg(output).args(after).env("PATH", empty.path()).env("NO_COLOR", "1").env_remove("RUST_LOG").output().unwrap();
    Run { code: out.status.code(), stdout: String::from_utf8_lossy(&out.stdout).into_owned(), stderr: String::from_utf8_lossy(&out.stderr).into_owned() }
}

/// The notes on standard error, without the name of the program in front of each.
fn notes(run: &Run) -> Vec<&str> {
    assert!(run.stderr.lines().all(|line| line.starts_with("archivewolf: ")), "a line that is no note: {}", run.stderr);
    run.stderr.lines().map(|line| line.strip_prefix("archivewolf: ").unwrap()).collect()
}

/// The notes of progress that are written while a pass runs, one a pause.
fn timed_notes(run: &Run) -> Vec<&str> {
    notes(run).into_iter().filter(|note| note.contains(" keys tested (") && note.ends_with(" left")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(bytes))
}

/// The three-byte key of the password "password".
const KEY: [u8; 3] = [0x73, 0x1f, 0x3d];

/// Encrypt `plain` as RAR 1.3 does with `key`.
fn encrypt(key: [u8; 3], plain: &[u8]) -> Vec<u8> {
    let [mut k0, mut k1, k2] = key;
    let mut cipher = plain.to_vec();
    for byte in &mut cipher {
        k1 = k1.wrapping_add(k2);
        k0 = k0.wrapping_add(k1);
        *byte = byte.wrapping_add(k0);
    }
    cipher
}

/// The checksum RAR 1.4 keeps of an entry.
fn checksum14(plain: &[u8]) -> u16 {
    plain.iter().fold(0u16, |sum, &byte| sum.wrapping_add(u16::from(byte)).rotate_left(1))
}

/// Text of `len` bytes.
fn text(len: usize) -> Vec<u8> {
    b"The quick brown fox jumps over the lazy dog.\r\n".iter().copied().cycle().take(len).collect()
}

/// The header of a RAR 1.4 archive, solid or not.
fn archive_head(solid: bool) -> Vec<u8> {
    vec![b'R', b'E', b'~', b'^', 7, 0, if solid { 0x88 } else { 0x80 }]
}

/// One entry of a RAR 1.4 archive, header and data: `packed` as it is, said to unpack to
/// `unp_size` bytes with the checksum `checksum`. The flag 0x04 says that it is encrypted.
fn entry(name: &str, flags: u8, method: u8, packed: &[u8], unp_size: u32, checksum: u16) -> Vec<u8> {
    let mut bytes = u32::try_from(packed.len()).unwrap().to_le_bytes().to_vec();
    bytes.extend_from_slice(&unp_size.to_le_bytes());
    bytes.extend_from_slice(&checksum.to_le_bytes());
    bytes.extend_from_slice(&u16::try_from(21 + name.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, flags, 2, u8::try_from(name.len()).unwrap(), method]);
    bytes.extend_from_slice(name.as_bytes());
    bytes.extend_from_slice(packed);
    bytes
}

/// A stored entry of `plain`, encrypted with the key of "password".
fn stored_entry(name: &str, plain: &[u8]) -> Vec<u8> {
    entry(name, 0x04, 0, &encrypt(KEY, plain), u32::try_from(plain.len()).unwrap(), checksum14(plain))
}

/// The same entry as the decrypted copy of the archive has it.
fn plain_entry(name: &str, plain: &[u8]) -> Vec<u8> {
    entry(name, 0, 0, plain, u32::try_from(plain.len()).unwrap(), checksum14(plain))
}

/// Write `bytes` to a file `name` in `dir`.
fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new("tests/fixtures/rar-13").join(name)
}

/// Key derived from the password "password".
const RAR_13_KEY: &str = "RAR 1.3 key = 73 1f 3d";

/// A fixture with one stored entry: the search takes about a second.
const STORED: &str = "rar14-password-stored.rar";
/// Where the entry header of `STORED` starts, and its size: the 16-bit checksum of the entry
/// is at byte 8 of it.
const STORED_ENTRY: std::ops::Range<usize> = 7..125;
const CHECKSUM_AT: usize = 8;

/// Extract `archive` with unrar into a fresh directory and return name → bytes.
fn unrar_extract(archive: &Path, password: Option<&str>) -> BTreeMap<String, Vec<u8>> {
    let dir = tempfile::tempdir().unwrap();
    let pw = password.map_or_else(|| "-p-".to_owned(), |p| format!("-p{p}"));
    let status = std::process::Command::new("unrar").args(["x", "-y", "-idq", &pw]).arg(archive).arg(format!("{}/", dir.path().display())).status().unwrap();
    assert!(status.success(), "unrar failed on {}", archive.display());
    std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap()).map(|e| (e.file_name().to_string_lossy().into_owned(), std::fs::read(e.path()).unwrap())).collect()
}

/// What a fixture gave before the search was given an estimate and a budget: the key and how it
/// was told from the others, and the decrypted copy.
struct Before {
    name: &'static str,
    /// The first line on standard output.
    key_line: &'static str,
    /// SHA-256 of the decrypted copy.
    copy: &'static str,
    /// The entry the keys are tested on, as the note before the search names it.
    tested_on: &'static str,
}

const STORED_BEFORE: Before = Before {
    name: STORED,
    key_line: "KEY RECOVERED: RAR 1.3 key = 73 1f 3d (145 keys satisfy the 16-bit entry checksum; this is the only one that decrypts to recognisable content)",
    copy: "df3727a8d51fa21719c8cbb2609b0ac7e4b1fa432bde4d3af0e8a158ce0de61c",
    tested_on: "SECRET.TXT (stored, 87 bytes), the only entry a key can be tested on",
};
const STOREPWD_BEFORE: Before = Before {
    name: "edge_rars_STOREPWD.RAR",
    key_line: "KEY RECOVERED: RAR 1.3 key = 73 1f 3d (148 keys satisfy the 16-bit entry checksum; this is the only one that decrypts to recognisable content)",
    copy: "0b806bf9da0a75bf9893d1f5f6ee37110124bdf522aff40dac07e50711adfc4a",
    tested_on: "SECRET.TXT (stored, 27 bytes), the only entry a key can be tested on",
};
const COMPRESSED_BEFORE: Before = Before {
    name: "rar14-password-compressed.rar",
    key_line: "KEY RECOVERED: RAR 1.3 key = 73 1f 3d (44 keys satisfy the 16-bit entry checksum; this is the only one whose compressed data ends exactly at the packed size)",
    copy: "fa66590900b3215057500aa7eca33e72311626446e40b80907306d8c9f375247",
    tested_on: "SECRET.TXT (compressed, 83 bytes that unpack to 87), the only entry a key can be tested on",
};
const README_BEFORE: Before = Before {
    name: "README_password=password.rar",
    key_line: "KEY RECOVERED: RAR 1.3 key = 73 1f 3d (26 keys satisfy the 16-bit entry checksum; this is the only one whose compressed data ends exactly at the packed size)",
    copy: "e5692692645c18be15326273997fbee0fb95cccaf13a93f7557bb8469d44c23a",
    tested_on: "README (compressed, 1078 bytes that unpack to 2016), the only entry a key can be tested on",
};
const SOLID_BEFORE: Before = Before {
    name: "rar14-solid-password.rar",
    key_line: "KEY RECOVERED: RAR 1.3 key = 73 1f 3d (the only key that satisfies every entry checksum)",
    copy: "9034d38d8512118f2712dd5d82c45a2ac702098f320088a296535586896e801d",
    tested_on: "BIG.TXT (compressed, 11879 bytes that unpack to 79404), the first compressed entry of a solid archive: the later ones unpack only after it",
};

/// Recover the key with no password, write the decrypted archive, and check that the key and
/// the copy are what they were, and that the copy extracts to exactly what the original does
/// with its password. Returns the run, for what else a test looks at.
fn recover_and_compare(before: &Before, budget: &[&str]) -> Run {
    let name = before.name;
    let out_dir = tempfile::tempdir().unwrap();
    let stem = Path::new(name).file_stem().unwrap().to_string_lossy();
    let decrypted = out_dir.path().join(format!("{stem}.decrypted.rar"));

    let run = attack_with(&[], &fixture(name), &decrypted, budget);
    assert_eq!(run.code, Some(0), "{name}: {}{}", run.stdout, run.stderr);
    assert!(run.stdout.contains("KEY RECOVERED") && run.stdout.contains(RAR_13_KEY), "{name}: {}", run.stdout);
    assert_eq!(run.stdout.lines().next(), Some(before.key_line), "{name}");
    assert!(decrypted.exists(), "{name}: no decrypted archive written: {}", run.stdout);
    assert_eq!(sha256(&std::fs::read(&decrypted).unwrap()), before.copy, "{name}: the copy is another than it was");
    assert!(run.stdout.contains("DECRYPTED: ") && run.stdout.contains(&decrypted.display().to_string()), "{name}: {}", run.stdout);
    assert_eq!(std::fs::read_dir(out_dir.path()).unwrap().count(), 1, "{name}: the copy is the one file written");

    // what the search is made on and what it takes, before it starts, and where it got to
    let notes = notes(&run);
    assert_eq!(notes.first().copied(), Some(format!("testing 8388608 keys on {}", before.tested_on).as_str()), "{name}: {}", run.stderr);
    assert!(notes.get(1).is_some_and(|note| note.starts_with("this takes ") && note.contains(" on ") && note.contains(" thread")), "{name}: {}", run.stderr);
    assert!(notes.iter().skip(2).any(|note| note.starts_with("8388608 of 8388608 keys tested: ")), "{name}: {}", run.stderr);

    // the same entries, and none of them encrypted any more
    let report = |path: &Path| -> serde_json::Value { serde_json::from_slice(&Command::cargo_bin("archivewolf").unwrap().args(["info", "--json"]).arg(path).output().unwrap().stdout).unwrap() };
    let (before, after) = (report(&fixture(name)), report(&decrypted));
    let names = |report: &serde_json::Value| -> Vec<String> { report.pointer("/entry_list").and_then(serde_json::Value::as_array).unwrap().iter().map(|entry| entry.pointer("/name").and_then(serde_json::Value::as_str).unwrap().to_owned()).collect() };
    let count = |report: &serde_json::Value, state: &str| report.pointer(&format!("/entries/{state}")).and_then(serde_json::Value::as_u64).unwrap();
    assert_eq!(names(&after), names(&before), "{name}");
    assert!(count(&before, "encrypted") > 0 && count(&before, "encrypted") == count(&after, "plain") - count(&before, "plain"), "{name}: {before}");
    assert_eq!((count(&after, "encrypted"), count(&after, "plain"), after.pointer("/coverage").and_then(serde_json::Value::as_str)), (0, count(&after, "total"), Some("none")), "{name}: {after}");
    assert_eq!((after.pointer("/schemes"), after.pointer("/no_line")), (Some(&serde_json::json!([])), Some(&serde_json::json!([]))), "{name}: {after}");
    assert_eq!(std::fs::metadata(&decrypted).unwrap().len(), std::fs::metadata(fixture(name)).unwrap().len(), "{name}");

    if unrar_available() {
        let original = unrar_extract(&fixture(name), Some("password"));
        let recovered = unrar_extract(&decrypted, None);
        assert!(!original.is_empty());
        assert_eq!(original, recovered, "{name}: decrypted archive extracts differently from the original");
    }
    run
}

#[test]
fn rar_13_stored_key_recovered_and_archive_matches() {
    let run = recover_and_compare(&STORED_BEFORE, &[]);
    assert_eq!(notes(&run).last().copied(), Some("8388608 of 8388608 keys tested: 145 pass the checksum of SECRET.TXT"), "{}", run.stderr);
    let run = recover_and_compare(&STOREPWD_BEFORE, &[]);
    assert_eq!(notes(&run).last().copied(), Some("8388608 of 8388608 keys tested: 148 pass the checksum of SECRET.TXT"), "{}", run.stderr);
}

#[test]
fn rar_13_compressed_key_recovered_and_archive_matches() {
    let run = recover_and_compare(&COMPRESSED_BEFORE, &[]);
    assert_eq!(notes(&run).last().copied(), Some("8388608 of 8388608 keys tested: 44 pass the checksum of SECRET.TXT"), "{}", run.stderr);
}

// The searches below take minutes without optimisation. They are given no budget: what they
// prove is the key, on a machine that may be busy with other tests.

#[test]
#[ignore = "expensive: unpacks a 1 KB entry for every key, run via make test-rar-13"]
fn rar_13_compressed_codepage_text_key_recovered_and_archive_matches() {
    let run = recover_and_compare(&README_BEFORE, &["--budget", "none"]);
    // a search of seconds notes its progress more than once before it ends
    assert!(notes(&run).get(1).is_some_and(|note| note.ends_with("; there is no budget")), "{}", run.stderr);
    assert!(timed_notes(&run).len() >= 2, "{}", run.stderr);
}

#[test]
#[ignore = "expensive: unpacks a 12 KB entry for every key, run via make test-rar-13"]
fn rar_13_solid_key_recovered_and_archive_matches() {
    let run = recover_and_compare(&SOLID_BEFORE, &["--budget", "none"]);
    assert!(timed_notes(&run).len() >= 2, "{}", run.stderr);
    // the keys that pass the first member are tested on the two that unpack after it
    assert!(notes(&run).last().is_some_and(|note| note.ends_with(" tested on all 3 entries: 1 passes every checksum")), "{}", run.stderr);
}

#[test]
#[ignore = "expensive: copies a 64 KiB window and unpacks an entry for every key, run via make test-rar-13"]
fn rar_13_solid_behind_an_unencrypted_member_key_recovered() {
    // the solid fixture with its first member as it was before it was encrypted: the two
    // archives have the same layout, so the one is spliced into the other
    let clear = std::fs::read("tests/fixtures/unencrypted/rar14-solid.rar").unwrap();
    let encrypted = std::fs::read(fixture("rar14-solid-password.rar")).unwrap();
    let second_member = 11914;
    assert_eq!(clear.len(), encrypted.len());
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), "mixed.rar", &[&clear[..second_member], &encrypted[second_member..]].concat());
    let output = dir.path().join("copy.rar");

    let run = attack_with(&[], &archive, &output, &["--budget", "none"]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert_eq!(notes(&run).first().copied(), Some("testing 8388608 keys on SECOND.TXT (compressed, 37 bytes that unpack to 1720), the first compressed entry of a solid archive: the later ones unpack only after it"), "{}", run.stderr);
    assert_eq!(run.stdout.lines().next(), Some("KEY RECOVERED: RAR 1.3 key = 73 1f 3d (the only key that satisfies every entry checksum)"));
    // decrypted, the archive is the one that never was encrypted
    assert_eq!(std::fs::read(&output).unwrap(), clear);
}

#[test]
#[ignore = "expensive: sums a megabyte for every key, run via make test-rar-13"]
fn rar_13_stored_megabyte_key_recovered() {
    let plain = text(1 << 20);
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), "megabyte.rar", &[archive_head(false), stored_entry("BIG.TXT", &plain)].concat());
    let output = dir.path().join("copy.rar");

    let run = attack_with(&[], &archive, &output, &["--budget", "none"]);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    assert_eq!(notes(&run).first().copied(), Some("testing 8388608 keys on BIG.TXT (stored, 1048576 bytes), the only entry a key can be tested on"), "{}", run.stderr);
    assert!(run.stdout.starts_with("KEY RECOVERED: RAR 1.3 key = 73 1f 3d ("), "{}", run.stdout);
    assert_eq!(std::fs::read(&output).unwrap(), [archive_head(false), plain_entry("BIG.TXT", &plain)].concat());
}

// ---------------------------------------------------------------------------
// What the search says before it starts and while it runs
// ---------------------------------------------------------------------------

#[test]
fn the_entry_and_the_estimate_are_noted_before_the_search_and_q_notes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let archive = fixture(STOREPWD_BEFORE.name);

    // the entry, its size and the number of keys; then the time, the threads and the budget;
    // then where the search got to. The result is on standard output, and only the result.
    let run = attack(&archive, &dir.path().join("default.rar"));
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let said = notes(&run);
    assert_eq!(said[0], "testing 8388608 keys on SECRET.TXT (stored, 27 bytes), the only entry a key can be tested on");
    let (takes, budget) = said[1].split_once("; ").unwrap_or_else(|| panic!("{}", run.stderr));
    let (time, threads) = takes.strip_prefix("this takes ").and_then(|rest| rest.split_once(" on ")).unwrap_or_else(|| panic!("{}", run.stderr));
    assert!(time == "under a second" || time.strip_prefix("about ").is_some_and(|span| span.ends_with(" second") || span.ends_with(" seconds")), "{}", run.stderr);
    assert!(threads == "1 thread" || threads.strip_suffix(" threads").is_some_and(|count| count.parse::<usize>().is_ok_and(|count| count > 1)), "{}", run.stderr);
    assert_eq!(budget, "the budget is 10 minutes");
    assert_eq!(*said.last().unwrap(), "8388608 of 8388608 keys tested: 148 pass the checksum of SECRET.TXT");
    // whatever is noted between the estimate and the end of the pass is the progress of it
    assert_eq!(said.len(), 3 + timed_notes(&run).len(), "{}", run.stderr);
    assert_eq!(run.stdout.lines().count(), 3, "{}", run.stdout);
    assert_eq!(run.stdout.lines().next(), Some(STOREPWD_BEFORE.key_line));

    // the budget that was given is the one that is named
    let raised = attack_with(&[], &archive, &dir.path().join("raised.rar"), &["--budget", "2h"]);
    assert_eq!(raised.code, Some(0), "{}{}", raised.stdout, raised.stderr);
    assert!(notes(&raised)[1].ends_with("; the budget is 2 hours"), "{}", raised.stderr);
    let lifted = attack_with(&[], &archive, &dir.path().join("lifted.rar"), &["--budget", "none"]);
    assert_eq!(lifted.code, Some(0), "{}{}", lifted.stdout, lifted.stderr);
    assert!(notes(&lifted)[1].ends_with("; there is no budget"), "{}", lifted.stderr);

    // -q: the same result, and not a word beside it
    let quiet = attack_with(&["-q"], &archive, &dir.path().join("quiet.rar"), &[]);
    assert_eq!(quiet.code, Some(0), "{}{}", quiet.stdout, quiet.stderr);
    assert!(quiet.stderr.is_empty(), "{}", quiet.stderr);
    assert_eq!(quiet.stdout.lines().next(), Some(STOREPWD_BEFORE.key_line));
    for copy in ["default.rar", "raised.rar", "lifted.rar", "quiet.rar"] {
        assert_eq!(sha256(&std::fs::read(dir.path().join(copy)).unwrap()), STOREPWD_BEFORE.copy, "{copy}");
    }
}

#[test]
fn every_key_is_tested_on_the_small_entry_of_an_archive_with_a_large_one_in_front() {
    // 300 KB first and 30 bytes behind them: a pass over the keys on the first entry of the
    // archive would sum 300 KB for each key
    let (large, small) = (text(300_000), text(30));
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), "two.rar", &[archive_head(false), stored_entry("LARGE.TXT", &large), stored_entry("SMALL.TXT", &small)].concat());
    let output = dir.path().join("copy.rar");

    let run = attack(&archive, &output);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let said = notes(&run);
    assert_eq!(said[0], "testing 8388608 keys on SMALL.TXT (stored, 30 bytes), the cheapest of the 2 entries a key can be tested on by itself");
    assert!(said.iter().any(|note| note.starts_with("8388608 of 8388608 keys tested: ") && note.ends_with(" the checksum of SMALL.TXT")), "{}", run.stderr);
    // the keys that passed it were tested on the large one, and one is left
    let last = said.last().unwrap();
    assert!(last.ends_with(" tested on all 2 entries: 1 passes every checksum"), "{}", run.stderr);
    assert_eq!(run.stdout.lines().next(), Some("KEY RECOVERED: RAR 1.3 key = 73 1f 3d (the only key that satisfies every entry checksum)"));
    assert_eq!(std::fs::read(&output).unwrap(), [archive_head(false), plain_entry("LARGE.TXT", &large), plain_entry("SMALL.TXT", &small)].concat());
}

// ---------------------------------------------------------------------------
// The budget
// ---------------------------------------------------------------------------

/// What every search that its budget stopped ends its one line with.
const MORE_TIME: &str = ", or lift it with --budget none); no archive written";

/// The budget a stopped search says to raise it to, which is one the command line takes.
fn named_budget(line: &str) -> &str {
    assert!(line.contains("(raise it with --budget "), "{line}");
    let named = line.split("(raise it with --budget ").nth(1).and_then(|rest| rest.split(',').next()).unwrap();
    let (count, unit) = named.split_at(named.len() - 1);
    assert!(count.parse::<u64>().is_ok_and(|count| count > 0) && ["s", "m", "h"].contains(&unit), "{line}");
    named
}

#[test]
fn a_search_that_cannot_finish_in_its_budget_is_not_started_exits_3_and_writes_nothing() {
    // a megabyte, stored: a second is not enough for 2^23 keys on it on any machine
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), "megabyte.rar", &[archive_head(false), stored_entry("BIG.BIN", &text(1 << 20))].concat());
    let output = dir.path().join("copy.rar");

    let started = std::time::Instant::now();
    let run = attack_with(&[], &archive, &output, &["--budget", "1s"]);
    assert!(started.elapsed() < std::time::Duration::from_secs(20), "the search was run: {:?}", started.elapsed());
    assert_eq!(run.code, Some(3), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "only the archive is there");

    // the entry, and then the one line that says what the search takes, what it may take,
    // that it was not started and why, and how to give it the time
    let said = notes(&run);
    assert_eq!(said.len(), 2, "{}", run.stderr);
    assert_eq!(said[0], "testing 8388608 keys on BIG.BIN (stored, 1048576 bytes), the only entry a key can be tested on");
    let line = said[1].strip_prefix(&format!("{}: ", archive.display())).unwrap_or_else(|| panic!("{}", run.stderr));
    assert!(line.starts_with("not searched: testing 8388608 keys on BIG.BIN takes about "), "{line}");
    assert!(line.contains(" and the budget is 1 second, and a search that stops before the last key finds none (raise it with --budget "), "{line}");
    assert!(line.ends_with(MORE_TIME), "{line}");
    assert_ne!(named_budget(line), "1s");

    // -q takes the note of the entry away and leaves the line that is the outcome
    let quiet = attack_with(&["-q"], &archive, &output, &["--budget", "1s"]);
    assert_eq!(quiet.code, Some(3), "{}{}", quiet.stdout, quiet.stderr);
    assert!(quiet.stdout.is_empty() && !output.exists());
    assert_eq!(quiet.stderr.lines().count(), 1, "{}", quiet.stderr);
    assert!(quiet.stderr.contains(": not searched: ") && quiet.stderr.trim_end().ends_with(MORE_TIME), "{}", quiet.stderr);
}

#[test]
fn a_budget_that_runs_out_ends_the_search_exits_3_and_writes_nothing() {
    // One stored byte is tested for every key in no time, and one key in 256 passes it. The
    // 32,768 that do are then tested on four megabytes, which takes far more than a second:
    // the estimate is of the first pass and lets the search start, and the budget ends it.
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), "narrow.rar", &[archive_head(false), stored_entry("BIG.BIN", &text(4 << 20)), stored_entry("A", b"a")].concat());
    let output = dir.path().join("copy.rar");

    let started = std::time::Instant::now();
    let run = attack_with(&[], &archive, &output, &["--budget", "1s"]);
    let took = started.elapsed();
    assert_eq!(run.code, Some(3), "{}{}", run.stdout, run.stderr);
    assert!(took >= std::time::Duration::from_secs(1) && took < std::time::Duration::from_mins(1), "{took:?}");
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "only the archive is there");

    let said = notes(&run);
    assert_eq!(said[0], "testing 8388608 keys on A (stored, 1 byte), the cheapest of the 2 entries a key can be tested on by itself");
    assert!(said[1].starts_with("this takes ") && said[1].ends_with("; the budget is 1 second"), "{}", run.stderr);
    // how far it got, and how to give it more time
    let line = said.last().and_then(|line| line.strip_prefix(&format!("{}: ", archive.display()))).unwrap_or_else(|| panic!("{}", run.stderr));
    assert!(line.starts_with("the budget of 1 second ended the search"), "{line}");
    if said.contains(&"8388608 of 8388608 keys tested: 32768 pass the checksum of A") {
        assert!(line.starts_with("the budget of 1 second ended the search: every key was tested on A, and the 32768 that passed were still being tested on the other entries (raise it with --budget "), "{line}");
    } else {
        // a machine too busy to test one byte for every key in a second
        assert!(line.contains(" of 8388608 keys tested ("), "{line}");
    }
    assert!(line.ends_with(MORE_TIME), "{line}");
    assert!(!named_budget(line).is_empty());
}

#[test]
fn a_budget_is_none_or_a_number_with_a_unit_and_anything_else_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("copy.rar");
    for budget in ["", "10", "m", "ten", "10d", "1.5h", "0s", "NONE", "10 m", "10m30s", "99999999999999999999h"] {
        let run = attack_with(&[], &fixture(STORED), &output, &["--budget", budget]);
        // the argument parser's own status, before anything is read or searched
        assert_eq!(run.code, Some(2), "{budget:?}: {}{}", run.stdout, run.stderr);
        assert!(run.stdout.is_empty(), "{budget:?}: {}", run.stdout);
        assert!(run.stderr.contains("--budget <TIME>"), "{budget:?}: {}", run.stderr);
        assert!(!output.exists(), "{budget:?}");
    }
    let run = attack_with(&[], &fixture(STORED), &output, &["--budget", "0s"]);
    assert!(run.stderr.contains("a budget of no time ends the search before it starts"), "{}", run.stderr);
    let run = attack_with(&[], &fixture(STORED), &output, &["--budget", "10"]);
    assert!(run.stderr.contains("a budget is a number with a unit, as in 90s, 10m or 2h, or `none` for no limit"), "{}", run.stderr);

    // the forms that are taken are in the help of the command, with the default
    let help = Command::cargo_bin("archivewolf").unwrap().args(["attack", "rar-13", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(help.contains("--budget <TIME>") && help.contains("90s, 10m or 2h") && help.contains("[default: 10m]"), "{help}");
}

// ---------------------------------------------------------------------------
// What a header claims
// ---------------------------------------------------------------------------

#[test]
fn an_entry_that_unpacks_to_more_than_is_unpacked_for_a_key_is_left_out_and_said_to_be() {
    // 100 KB can be 200 MiB unpacked, which is over what one key is given: the key is found
    // on the entries that can be tested, and what it rests on is said with it
    let over = entry("OVER.BIN", 0x04, 3, &vec![0x11; 100_000], 200 << 20, 0x1234);
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), "over.rar", &[archive_head(false), over.clone(), stored_entry("A.TXT", &text(30)), stored_entry("B.TXT", &text(40))].concat());
    let output = dir.path().join("copy.rar");

    let run = attack(&archive, &output);
    assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
    let said = notes(&run);
    assert_eq!(said[0], "OVER.BIN is not tested: it unpacks to 209715200 bytes, and no more than 134217728 are unpacked for a key");
    assert_eq!(said[1], "testing 8388608 keys on A.TXT (stored, 30 bytes), the cheapest of the 2 entries a key can be tested on by itself");
    assert_eq!(run.stdout.lines().next(), Some("KEY RECOVERED: RAR 1.3 key = 73 1f 3d (the only key that satisfies the checksum of every entry that was tested (1 could not be))"));
    assert!(output.exists());

    // with nothing else to test a key on, the archive cannot be searched: that is a
    // failure of the archive, and no search that found nothing
    let alone = write(dir.path(), "alone.rar", &[archive_head(false), over].concat());
    let nothing = dir.path().join("nothing.rar");
    let run = attack(&alone, &nothing);
    assert_eq!(run.code, Some(2), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty() && !nothing.exists(), "{}", run.stdout);
    assert!(notes(&run).last().is_some_and(|note| note.ends_with("no encrypted entry is left to test keys against: none can be unpacked within the limit")), "{}", run.stderr);
}

#[test]
fn four_kilobytes_that_claim_four_gigabytes_are_answered_without_a_search() {
    // compressed, 4 KiB packed, 4 GiB unpacked by its header: no stream of 4 KiB gives that
    // under any key, so there is nothing to unpack 2^23 times, and nothing to reserve
    let garbage: Vec<u8> = (0..4096u32).map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes()[3]).collect();
    let dir = tempfile::tempdir().unwrap();
    let archive = write(dir.path(), "claim.rar", &[archive_head(false), entry("A.BIN", 0x04, 3, &garbage, u32::MAX, 0x1234)].concat());
    let output = dir.path().join("copy.rar");

    let started = std::time::Instant::now();
    let run = attack(&archive, &output);
    assert!(started.elapsed() < std::time::Duration::from_secs(20), "a search was run: {:?}", started.elapsed());
    assert_eq!(run.code, Some(3), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty() && !output.exists(), "{}", run.stdout);
    let said = notes(&run);
    assert_eq!(said[0], "A.BIN is not what its header says: 4096 packed bytes do not unpack to 4294967295 under any key, so no key is searched for");
    assert!(said[1].ends_with("no key satisfies the entry checksums: the archive is damaged, or its entries are not of rar-13; no archive written"), "{}", run.stderr);
    assert_eq!(said.len(), 2, "{}", run.stderr);
}

// ---------------------------------------------------------------------------
// The file the attack writes
// ---------------------------------------------------------------------------

#[test]
fn an_output_that_exists_is_refused_before_the_search_and_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("copy.rar");
    std::fs::write(&output, b"what was here before").unwrap();

    let run = attack(&fixture(STORED), &output);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty(), "the search did not start: {}", run.stdout);
    assert!(run.stderr.contains("exists") && run.stderr.contains("not overwritten"), "{}", run.stderr);
    assert_eq!(std::fs::read(&output).unwrap(), b"what was here before");

    // a directory in that place is in the way as well
    let run = attack(&fixture(STORED), dir.path());
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn a_symbolic_link_is_refused_before_the_search_and_its_target_is_left_as_it_is() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, b"what the link points at").unwrap();
    let link = dir.path().join("copy.rar");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let run = attack(&fixture(STORED), &link);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty(), "the search did not start: {}", run.stdout);
    assert!(run.stderr.contains("symbolic link"), "{}", run.stderr);
    assert_eq!(std::fs::read(&target).unwrap(), b"what the link points at");
    assert!(link.symlink_metadata().unwrap().file_type().is_symlink(), "the link is still a link");

    // a link to a file that is not there: the file is not created through it
    let missing = dir.path().join("missing.rar");
    let dangling = dir.path().join("dangling.rar");
    std::os::unix::fs::symlink(&missing, &dangling).unwrap();
    let run = attack(&fixture(STORED), &dangling);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty() && run.stderr.contains("symbolic link"), "{}{}", run.stdout, run.stderr);
    assert!(!missing.exists(), "the target of the link was created");
    assert!(dangling.symlink_metadata().unwrap().file_type().is_symlink());
}

#[test]
fn the_copy_is_written_once_and_never_over_itself() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("copy.rar");

    let first = attack(&fixture(STORED), &output);
    assert_eq!(first.code, Some(0), "{}{}", first.stdout, first.stderr);
    let written = std::fs::read(&output).unwrap();
    assert!(written.starts_with(b"RE~^"));

    let second = attack(&fixture(STORED), &output);
    assert_eq!(second.code, Some(1), "{}{}", second.stdout, second.stderr);
    assert!(second.stdout.is_empty(), "{}", second.stdout);
    assert_eq!(std::fs::read(&output).unwrap(), written);
}

#[test]
fn a_directory_that_is_not_there_is_not_made_for_the_copy() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("absent").join("copy.rar");
    let run = attack(&fixture(STORED), &output);
    assert_eq!(run.code, Some(1), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty(), "the search did not start: {}", run.stdout);
    assert!(run.stderr.contains("is not a directory"), "{}", run.stderr);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

// ---------------------------------------------------------------------------
// Searches that end without a key
// ---------------------------------------------------------------------------

#[test]
fn several_keys_that_nothing_tells_apart_are_reported_and_nothing_is_written() {
    // another checksum on the one entry: the keys that decrypt it to that checksum are all
    // wrong, and what they decrypt it to is noise under each of them
    let dir = tempfile::tempdir().unwrap();
    let mut data = std::fs::read(fixture(STORED)).unwrap();
    data[STORED_ENTRY.start + CHECKSUM_AT] ^= 0x01;
    let archive = dir.path().join("other-checksum.rar");
    std::fs::write(&archive, &data).unwrap();
    let output = dir.path().join("copy.rar");

    let run = attack(&archive, &output);
    assert_eq!(run.code, Some(3), "{}{}", run.stdout, run.stderr);
    assert!(!output.exists(), "a copy was written for a key that is not known");
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{}", run.stdout);
    let count: usize = lines[0].strip_prefix("KEY AMBIGUOUS: ").and_then(|rest| rest.split(' ').next()).and_then(|number| number.parse().ok()).unwrap_or_else(|| panic!("{}", run.stdout));
    assert!(count > 1 && lines[0].ends_with("no archive written"), "{}", run.stdout);
    // every key that is left is named, three bytes each
    let keys: Vec<&str> = lines[1].strip_prefix("Candidate keys: ").unwrap_or_else(|| panic!("{}", run.stdout)).split(", ").collect();
    assert_eq!(keys.len(), count, "{}", run.stdout);
    assert!(keys.iter().all(|key| key.len() == 8 && key.split(' ').all(|byte| byte.len() == 2 && u8::from_str_radix(byte, 16).is_ok())), "{}", run.stdout);
    assert!(!run.stdout.contains("73 1f 3d") && !run.stdout.contains("KEY RECOVERED"), "{}", run.stdout);
}

#[test]
fn no_key_exits_3_and_nothing_is_written() {
    // the entry twice, the second time with another checksum: no key decrypts the same bytes
    // to both
    let dir = tempfile::tempdir().unwrap();
    let mut data = std::fs::read(fixture(STORED)).unwrap();
    let mut second = data[STORED_ENTRY].to_vec();
    second[CHECKSUM_AT] ^= 0x01;
    data.extend_from_slice(&second);
    let archive = dir.path().join("no-key.rar");
    std::fs::write(&archive, &data).unwrap();
    let output = dir.path().join("copy.rar");

    let run = attack(&archive, &output);
    assert_eq!(run.code, Some(3), "{}{}", run.stdout, run.stderr);
    assert!(run.stdout.is_empty(), "{}", run.stdout);
    assert!(run.stderr.contains("no key satisfies the entry checksums"), "{}", run.stderr);
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "only the archive is there");
}

#[test]
fn what_is_not_an_encrypted_rar_13_archive_is_nothing_to_do() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("copy.rar");
    for (archive, why) in [
        ("tests/fixtures/rar-50/v730_p_m3.rar", "is not an archive of RAR 1.3 or 1.4"),
        ("tests/fixtures/rar-15/rar15-password-stored.rar", "is not an archive of RAR 1.3 or 1.4"),
        ("tests/fixtures/zip-crypto/zipcrypto.zip", "not a RAR archive"),
        ("Cargo.toml", "not a RAR archive"),
        ("tests/fixtures/rar-13", "is not a file"),
        ("tests/fixtures/rar-13/absent.rar", "cannot read"),
        ("tests/fixtures/unencrypted/rar14-solid.rar", "no entry is encrypted"),
    ] {
        let run = attack(Path::new(archive), &output);
        assert_eq!(run.code, Some(1), "{archive}: {}{}", run.stdout, run.stderr);
        assert!(run.stdout.is_empty(), "{archive}: {}", run.stdout);
        assert!(run.stderr.starts_with("archivewolf: ") && run.stderr.contains(why), "{archive}: {}", run.stderr);
        assert!(!output.exists(), "{archive}");
    }
}
