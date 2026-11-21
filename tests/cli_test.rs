#![expect(unused_crate_dependencies, reason = "integration test")]
#![expect(missing_docs, reason = "test module")]
#![expect(unused_results, reason = "assert_cmd assertions are self-verifying")]
use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::prelude::predicate;

/// What one run of the binary gave back.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run the binary. A run that could not be started has no exit status, and says why on what
/// stands for its standard error.
fn aw(args: &[&str]) -> Run {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(args).env("NO_COLOR", "1").env_remove("RUST_LOG").output();
    output.map_or_else(|error| Run { code: None, stdout: String::new(), stderr: error.to_string() }, |output| Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned() })
}

/// Whether a line of output is a hash line: one of the three signatures in front, its end mark
/// behind, and nothing around them.
fn is_hash_line(line: &str) -> bool {
    [("$zip$", "$/zip$"), ("$rar$", "$/rar$"), ("$7z$", "$/7z$")].iter().any(|(start, end)| line.starts_with(start) && line.ends_with(end))
}

/// Whether text holds a hash line, anywhere in it.
fn holds_a_hash_line(text: &str) -> bool {
    ["$/zip$", "$/rar$", "$/7z$"].iter().any(|end| text.contains(end))
}

#[test]
fn version_flag() {
    Command::cargo_bin("archivewolf").unwrap().arg("--version").assert().success().stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_flag() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("info"))
        .stdout(predicate::str::contains("hash"))
        .stdout(predicate::str::contains("attack"))
        .stdout(predicate::str::contains("unlock").not())
        .stdout(predicate::str::contains("advanced").not())
        .stdout(predicate::str::contains("strip").not());
}

#[test]
fn info_no_paths_errors() {
    Command::cargo_bin("archivewolf").unwrap().arg("info").assert().failure();
    Command::cargo_bin("archivewolf").unwrap().arg("hash").assert().failure();
}

#[test]
fn info_non_archive_is_nothing_to_do() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "Cargo.toml"]).assert().code(1).stdout(predicate::str::is_empty()).stderr(predicate::str::contains("no archives found"));
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "Cargo.toml"]).assert().code(1).stdout(predicate::str::is_empty()).stderr(predicate::str::contains("no archives found"));
}

#[test]
fn info_zip_crypto_detected() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-crypto/test02.zip"]).assert().success().stdout(predicate::str::contains("zip-crypto:check8  ZipCrypto")).stdout(predicate::str::contains("$zip$1$, hashcat mode 46100"));
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/test02.zip"]).assert().success().stdout(predicate::str::starts_with("$zip$1$*"));
}

#[test]
fn info_pseudo_encryption() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "tests/fixtures/pseudo/pseudo_encrypted_zc.zip"])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 pseudo-encrypted"))
        .stdout(predicate::str::contains("marked encrypted and not encrypted"))
        .stdout(predicate::str::contains("$zip$").not());
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/pseudo/pseudo_encrypted_zc.zip"]).assert().success().stdout(predicate::str::is_empty());
}

#[test]
fn info_zip_winzip() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "tests/fixtures/zip-winzip/winzip_aes256_hello.zip"])
        .assert()
        .success()
        .stdout(predicate::str::contains("zip-winzip:256:ae2  AE-"))
        .stdout(predicate::str::contains("AES-256"))
        .stdout(predicate::str::contains("$zip$2$, hashcat mode 46200"));
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-winzip/winzip_aes256_hello.zip"]).assert().success().stdout(predicate::str::starts_with("$zip$2$*"));
}

#[test]
fn info_emits_hash_for_encrypted() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-crypto/test03.zip"]).assert().success().stdout(predicate::str::contains("$zip$1$, hashcat mode 46100")).stdout(predicate::str::contains("PASSWORD:").not()).stdout(predicate::str::contains("RECOVERED").not());
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/test03.zip"]).assert().success().stdout(predicate::str::starts_with("$zip$1$*"));
}

#[test]
fn info_multi_entry() {
    // the block counts the entries, and --entries lists them
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-crypto/test05.zip"]).assert().success().stdout(predicate::str::contains("ZIP, 2 entries")).stdout(predicate::str::contains("2 of 2 entries encrypted; coverage all"));
    let listed = aw(&["info", "--entries", "tests/fixtures/zip-crypto/test05.zip"]);
    assert_eq!(listed.code, Some(0), "{}", listed.stderr);
    let rows: Vec<&str> = listed.stdout.lines().filter(|line| line.ends_with("test05_plain.txt") || line.ends_with("flag.txt")).filter(|line| line.contains("  file  encrypted  zip-crypto:check8  ")).collect();
    assert_eq!(rows.len(), 2, "a row for each entry: {}", listed.stdout);
    assert!(listed.stdout.starts_with(&aw(&["info", "tests/fixtures/zip-crypto/test05.zip"]).stdout), "the rows come below the block and change nothing in it");
}

#[test]
fn info_json_output() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--json", "tests/fixtures/zip-crypto/test02.zip"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().count(), 1, "one archive is one line");
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    // the fields of the specification, section 6.1, and the entries, always
    let fields: Vec<&str> = parsed.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(fields, ["coverage", "entries", "entry_list", "findings", "format", "generation", "headers", "lines", "mixed", "no_line", "offset", "path", "schemes", "volume", "writer"]);
    assert_eq!(parsed["entries"]["total"].as_u64(), parsed["entry_list"].as_array().map(|list| list.len() as u64));
    assert_eq!(parsed["lines"].as_array().unwrap().len(), 1);
    // --entries changes nothing in the object
    let with_entries = Command::cargo_bin("archivewolf").unwrap().args(["info", "--json", "--entries", "tests/fixtures/zip-crypto/test02.zip"]).output().unwrap();
    assert_eq!(with_entries.stdout, output.stdout);
}

#[test]
fn info_directory_scan() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/"]).output().unwrap();
    // three files under unparseable/ are a RAR marker with no header behind it: they do not parse
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let zip_count = stdout.lines().filter(|line| !line.starts_with(' ') && line.contains(".zip   ZIP")).count();
    assert!(zip_count >= 5, "expected at least 5 ZIP archives in directory, found {zip_count}");
    // one block for each archive, an empty line between two of them and none at the end
    let blocks = stdout.split("\n\n").count();
    let archives = stdout.lines().filter(|line| !line.is_empty() && !line.starts_with(' ')).count();
    assert_eq!(blocks, archives);
    assert!(archives > 500 && stdout.ends_with('\n') && !stdout.ends_with("\n\n"), "{archives} archives");
}

#[test]
fn info_unencrypted_zip() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/unencrypted/zip31c_unencrypted.zip"]).assert().success().stdout(predicate::str::contains("coverage none")).stdout(predicate::str::contains("line      none: nothing is encrypted"));
}

#[test]
fn info_rar3_unencrypted() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/unencrypted/rar4_unencrypted.rar"]).assert().success().stdout(predicate::str::contains("   RAR 1.5 to 4, ")).stdout(predicate::str::contains("line      none: nothing is encrypted"));
}

#[test]
fn info_7z_encrypted() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/7z-aes/flag.7z"]).assert().success().stdout(predicate::str::contains("   7z, ")).stdout(predicate::str::contains("7z-aes:data  AES-256, SHA-256 2^"));
}

#[test]
fn info_7z_hash_emitted() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/7z-aes/flag.7z"]).assert().success().stdout(predicate::str::contains("$7z$*, hashcat mode 46900"));
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/7z-aes/flag.7z"]).assert().success().stdout(predicate::str::starts_with("$7z$*"));
}

#[test]
fn info_rar5_encrypted_hash_emitted() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/rar-50/v730_hp_m5.rar"]).assert().success().stdout(predicate::str::contains("headers   encrypted: names and sizes hidden")).stdout(predicate::str::contains("$rar$50$, hashcat mode 46800, exact, from the headers"));
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/v730_hp_m5.rar"]).assert().success().stdout(predicate::str::starts_with("$rar$50$*"));
}

// ---------------------------------------------------------------------------
// hash: standard output is the lines and nothing else
// ---------------------------------------------------------------------------

#[test]
fn hash_prints_hash_lines_and_nothing_else() {
    for all in [false, true] {
        let mut args = vec!["hash", "tests/fixtures"];
        if all {
            args.push("--all");
        }
        let run = aw(&args);
        // three files under unparseable/ are a RAR marker with no header behind it: they do not parse
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        let lines: Vec<&str> = run.stdout.lines().collect();
        assert!(lines.len() > 300, "{} lines", lines.len());
        for line in &lines {
            assert!(is_hash_line(line), "not a hash line: {line}");
            assert!(!line.starts_with('#'), "a comment line: {line}");
        }
        // every line type there is a fixture for
        for kind in ["$zip$1$*", "$zip$2$*", "$zip$3$*", "$rar$15$*", "$rar$20$*", "$rar$30$*", "$rar$50$*", "$7z$*"] {
            assert!(lines.iter().any(|line| line.starts_with(kind)), "no {kind} line");
        }
        assert!(run.stdout.ends_with('\n') && !run.stdout.contains("\n\n"), "one line each, no empty line");
    }
}

#[test]
fn hash_all_gives_every_entry_a_line() {
    let best = aw(&["hash", "tests/fixtures/zip-crypto/gen_own_zc_eight_stored.zip"]);
    let all = aw(&["hash", "--all", "tests/fixtures/zip-crypto/gen_own_zc_eight_stored.zip"]);
    assert_eq!((best.stdout.lines().count(), all.stdout.lines().count()), (1, 10));
    assert!(all.stdout.lines().all(is_hash_line));
}

#[test]
fn hash_mode_writes_only_the_lines_of_that_mode() {
    let dirs = ["tests/fixtures/zip-crypto", "tests/fixtures/zip-winzip", "tests/fixtures/zip-pkware", "tests/fixtures/rar-15", "tests/fixtures/rar-20", "tests/fixtures/rar-30", "tests/fixtures/rar-50", "tests/fixtures/7z-aes"];
    let everything = aw(&[&["hash"][..], &dirs].concat());
    assert_eq!(everything.code, Some(0), "{}", everything.stderr);
    let all_lines: Vec<&str> = everything.stdout.lines().collect();

    let mut filtered_total = 0;
    for (mode, kind) in [("46100", "$zip$1$*"), ("46200", "$zip$2$*"), ("46300", "$zip$3$*"), ("46310", "$zip$3$*"), ("46320", "$zip$3$*"), ("46500", "$rar$15$*"), ("46600", "$rar$20$*"), ("46700", "$rar$30$*"), ("46800", "$rar$50$*"), ("46900", "$7z$*")] {
        let run = aw(&[&["hash", "--mode", mode][..], &dirs].concat());
        assert_eq!(run.code, Some(0), "{mode}: {}", run.stderr);
        let lines: Vec<&str> = run.stdout.lines().collect();
        assert!(!lines.is_empty(), "no line of mode {mode}");
        assert!(lines.iter().all(|line| line.starts_with(kind) && is_hash_line(line)), "{mode}: {}", run.stdout);
        // the lines of a mode are the lines of the whole run that the mode reads, in their order
        let bits = match mode {
            "46300" => Some("*128*"),
            "46310" => Some("*192*"),
            "46320" => Some("*256*"),
            _ => None,
        };
        let expected: Vec<&str> = all_lines.iter().copied().filter(|line| line.starts_with(kind) && bits.is_none_or(|bits| line.split_at(12).1.starts_with(bits))).collect();
        assert_eq!(lines, expected, "mode {mode}");
        assert!(run.stderr.contains(&format!("{} hash line", lines.len())) && run.stderr.contains(&format!("{} of mode {mode}", lines.len())), "{mode}: {}", run.stderr);
        filtered_total += lines.len();
    }
    assert_eq!(filtered_total, all_lines.len(), "every line belongs to exactly one mode");

    // a mode nothing of a run has a line for: no line, and that is not a failure
    let none = aw(&["hash", "--mode", "46900", "tests/fixtures/zip-winzip"]);
    assert_eq!((none.code, none.stdout.as_str()), (Some(0), ""), "{}", none.stderr);
    assert!(none.stderr.contains("archivewolf: no hash lines"), "{}", none.stderr);

    // a number that is no mode `hash` writes lines for would pick nothing out of any run: it is
    // refused before anything is read, with the modes there are
    for other in ["13600", "4610", "46400"] {
        let refused = aw(&[&["hash", "--mode", other][..], &dirs].concat());
        assert_eq!((refused.code, refused.stdout.as_str()), (Some(2), ""), "{other}: {}", refused.stderr);
        assert!(refused.stderr.contains("--mode") && !refused.stderr.contains("no hash lines"), "{other}: {}", refused.stderr);
    }
    assert!(aw(&["hash", "--mode", "13600", "tests/fixtures/zip-winzip"]).stderr.contains("46100, 46200, 46300, 46310, 46320, 46500, 46600, 46700, 46800, 46900 and for no other"));
}

#[test]
fn hash_json_writes_one_object_for_each_line() {
    let paths = ["tests/fixtures/zip-crypto/zipcrypto.zip", "tests/fixtures/zip-winzip/winzip_aes256.zip", "tests/fixtures/zip-pkware/gen_ses_aes192_iv_deflate.zip", "tests/fixtures/rar-50/v730_p_m3.rar", "tests/fixtures/7z-aes/7z_nonsolid_enc.7z"];
    for all in [false, true] {
        let flags: &[&str] = if all { &["hash", "--all"] } else { &["hash"] };
        let plain = aw(&[flags, &paths].concat());
        let json = aw(&[flags, &["--json"], &paths].concat());
        assert_eq!((plain.code, json.code), (Some(0), Some(0)), "{}{}", plain.stderr, json.stderr);

        let objects: Vec<serde_json::Value> = json.stdout.lines().map(|line| serde_json::from_str(line).unwrap_or_else(|error| panic!("not JSON: {error}: {line}"))).collect();
        let lines: Vec<&str> = plain.stdout.lines().collect();
        assert_eq!(objects.len(), lines.len());
        assert_eq!(objects.len(), if all { 7 } else { 5 }, "three folders in the 7z archive: {}", json.stdout);

        for (object, line) in objects.iter().zip(&lines) {
            let (path, mode, tag) = (object["path"].as_str().unwrap(), object["mode"].as_u64().unwrap(), object["tag"].as_str().unwrap());
            assert_eq!(object["line"].as_str(), Some(*line), "the line is the one `hash` prints");
            assert!(line.starts_with(tag), "{tag}: {line}");
            assert!(paths.contains(&path), "{path}");
            let expected = match tag {
                "$zip$1$" => (46100, "zipcrypto.zip", "zip-crypto"),
                "$zip$2$" => (46200, "winzip_aes256.zip", "zip-winzip"),
                "$zip$3$" => (46310, "gen_ses_aes192_iv_deflate.zip", "zip-pkware"),
                "$rar$50$" => (46800, "v730_p_m3.rar", "rar-50"),
                "$7z$*" => (46900, "7z_nonsolid_enc.7z", "7z-aes"),
                other => panic!("unexpected line type {other}"),
            };
            assert_eq!(mode, expected.0, "{tag}");
            assert!(path.ends_with(expected.1), "{tag} from {path}");
            // the scheme, the entry the line comes from and what it proves
            assert_eq!(object["scheme"].as_str(), Some(expected.2), "{tag}");
            assert!(object["entry"].is_u64(), "{tag}: every line here comes from an entry: {object}");
            assert!(matches!(object["proves"].as_str(), Some("exact" | "structural" | "weak")), "{tag}: {object}");
            let fields: Vec<&str> = object.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(fields, ["entry", "line", "mode", "path", "proves", "scheme", "tag"]);
        }
        // in the order of the paths, as the lines are
        let order: Vec<&str> = objects.iter().map(|object| object["path"].as_str().unwrap()).collect();
        assert!(order.is_sorted(), "{order:?}");
    }

    // --mode filters the objects like the lines
    let only = aw(&[&["hash", "--json", "--mode", "46800"][..], &paths].concat());
    let objects: Vec<serde_json::Value> = only.stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(objects.len(), 1);
    assert_eq!((objects[0]["mode"].as_u64(), objects[0]["tag"].as_str()), (Some(46800), Some("$rar$50$")));
}

/// The entry of a line is the place of its entry in the list `info --json` prints.
#[test]
fn hash_json_names_the_entry_a_line_comes_from() {
    let paths = ["tests/fixtures/zip-crypto/zipcrypto.zip", "tests/fixtures/zip-winzip/winzip_aes256.zip", "tests/fixtures/zip-pkware/gen_ses_aes192_iv_deflate.zip", "tests/fixtures/rar-50/v730_p_m3.rar", "tests/fixtures/7z-aes/7z_nonsolid_enc.7z"];
    let info = aw(&[&["info", "--json"][..], &paths].concat());
    let reports: Vec<serde_json::Value> = info.stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(reports.len(), paths.len(), "{}", info.stderr);

    let json = aw(&[&["hash", "--all", "--json"][..], &paths].concat());
    let objects: Vec<serde_json::Value> = json.stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(objects.len(), 7, "{}", json.stderr);
    for object in &objects {
        let report = reports.iter().find(|report| report["path"] == object["path"]).unwrap();
        let entry = &report["entry_list"][usize::try_from(object["entry"].as_u64().unwrap()).unwrap()];
        assert_eq!((&entry["state"], &entry["scheme"]), (&serde_json::Value::from("encrypted"), &object["scheme"]), "{object}");
    }
    let folders: Vec<u64> = objects.iter().filter(|object| object["tag"] == "$7z$*").map(|object| object["entry"].as_u64().unwrap()).collect();
    assert_eq!(folders.len(), 3);
    assert!((0..3).all(|folder| folders.contains(&folder)), "a line from each folder: {folders:?}");

    // a line built from encrypted headers comes from no entry
    let header = aw(&["hash", "--json", "tests/fixtures/rar-50/v730_hp_m5.rar", "tests/fixtures/7z-aes/7z_hdr_lzma2.7z"]);
    let objects: Vec<serde_json::Value> = header.stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
    assert_eq!(objects.len(), 2, "{}", header.stderr);
    for object in &objects {
        assert!(object.get("entry").is_none(), "{object}");
        assert!(object["scheme"].is_string() && object["proves"].is_string(), "{object}");
    }
}

#[test]
fn hash_notes_go_to_standard_error_and_quiet_drops_them() {
    // a stored entry alone in its archive: the line comes with a remark on what it proves
    let archive = "tests/fixtures/zip-crypto/gen_own_zc_stored.zip";
    let run = aw(&["hash", archive]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert_eq!(run.stdout.lines().count(), 1);
    assert!(run.stderr.contains(&format!("{archive}: note: ")) && run.stderr.contains("40 bits"), "{}", run.stderr);
    assert!(run.stderr.contains("archivewolf: 1 hash line: 1 of mode 46100"), "{}", run.stderr);
    assert!(!holds_a_hash_line(&run.stderr), "{}", run.stderr);
    assert!(!run.stderr.contains("unlock") && !run.stderr.contains("--password"), "a remark names no command that is gone: {}", run.stderr);

    let quiet = aw(&["-q", "hash", archive]);
    assert_eq!((quiet.code, quiet.stdout.as_str(), quiet.stderr.as_str()), (Some(0), run.stdout.as_str(), ""));
    assert_eq!(aw(&["hash", "--quiet", archive]).stderr, "");

    // an archive that gets no line says why, with the reason, and the count says there is none
    let rawkey = "tests/fixtures/7z-aes/rawkey.7z";
    let none = aw(&["hash", rawkey]);
    assert_eq!((none.code, none.stdout.as_str()), (Some(0), ""), "{}", none.stderr);
    assert!(none.stderr.contains(&format!("{rawkey}: no line: folder 0 (test.txt): ")) && none.stderr.contains("[no-mode]") && none.stderr.contains("archivewolf: no hash lines"), "{}", none.stderr);

    // a weak line is named, with what it tests
    let deflate64 = "tests/fixtures/zip-crypto/gen_7z_zipcrypto_deflate64.zip";
    let weak = aw(&["hash", deflate64]);
    assert!(weak.stderr.contains(&format!("{deflate64}: weak line: text40k.txt: hashcat has no decoder for compression method 9")) && weak.stderr.contains(": 8 bits. Confirm a password found with it by opening the archive."), "{}", weak.stderr);

    // several modes in one run: the count names each
    let mixed = aw(&["hash", "tests/fixtures/zip-crypto/zipcrypto.zip", "tests/fixtures/rar-50/v730_p_m3.rar", "tests/fixtures/7z-aes/7z_stored.7z", "tests/fixtures/zip-winzip/winzip_aes256.zip"]);
    assert!(mixed.stderr.contains("archivewolf: 4 hash lines: 1 of mode 46100, 1 of mode 46200, 1 of mode 46800, 1 of mode 46900"), "{}", mixed.stderr);
}

/// In a run over many archives a note is of use only when it says which archive it is about.
#[test]
fn every_note_of_hash_names_its_archive() {
    for flags in [&["hash"][..], &["hash", "--all"]] {
        let run = aw(&[flags, &["tests/fixtures"]].concat());
        // three files under unparseable/ are a RAR marker with no header behind it: they do not parse
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        let notes: Vec<&str> = run.stderr.lines().filter(|line| line.contains(": no line: ") || line.contains(": weak line: ") || line.contains(": note: ")).collect();
        assert!(notes.len() > 40, "{} notes", notes.len());
        for note in &notes {
            assert!(note.starts_with("tests/fixtures/"), "a note without its archive: {note}");
            let path = note.split(": ").next().unwrap();
            assert!(std::path::Path::new(path).is_file(), "not the path of an archive: {note}");
        }
        // and nothing else is on standard error but the note on care, the count, the archives that
        // do not parse with the hint that follows each, and the log
        for line in run.stderr.lines().filter(|line| !notes.contains(line)) {
            assert!(line.starts_with("Note: hash lines hold") || line.starts_with("archivewolf: ") || line.starts_with("  Hint: ") || line.contains(" WARN "), "{line}");
        }
        // one of each kind: no mode, a split entry, a certificate, a weak line
        for words in ["[no-mode]", "[split]", "[no-password]", "[no-data]", "[not-expressible]", ": weak line: "] {
            assert!(notes.iter().any(|note| note.contains(words)), "no note with {words}");
        }
    }
}

// ---------------------------------------------------------------------------
// A reader that closes standard output
// ---------------------------------------------------------------------------

/// `archivewolf hash dir | head -1`: the reader takes a line and closes the pipe while the run
/// has megabytes left to write. That is the end of the run: no panic, no message, no failure.
#[test]
fn a_reader_that_closes_standard_output_ends_the_run_quietly() {
    use std::io::BufRead as _;
    use std::io::Read as _;
    use std::process::Stdio;

    for args in [&["hash", "tests/fixtures"][..], &["hash", "--all", "--json", "tests/fixtures"], &["info", "tests/fixtures"], &["info", "--json", "tests/fixtures"]] {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(args).env("NO_COLOR", "1").env_remove("RUST_LOG").stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut first = String::new();
        stdout.read_line(&mut first).unwrap();
        assert!(first.ends_with('\n') && first.len() > 1, "{args:?}: {first:?}");
        // the reader has what it wants
        drop(stdout);

        let mut stderr = String::new();
        child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(0), "{args:?}: {stderr}");
        assert!(!stderr.contains("panicked") && !stderr.contains("Broken pipe") && !stderr.contains("os error") && !stderr.contains("standard output"), "{args:?}: {stderr}");
        assert!(!stderr.contains(" hash lines: "), "{args:?}: a run that was cut off counts nothing: {stderr}");
    }

    // a run that is read to its end still counts its lines
    let whole = aw(&["hash", "tests/fixtures/zip-crypto"]);
    assert!(whole.stderr.contains(" hash lines: "), "{}", whole.stderr);
}

// ---------------------------------------------------------------------------
// info: names the lines and prints none
// ---------------------------------------------------------------------------

#[test]
fn info_names_the_lines_and_prints_none() {
    let dirs = ["tests/fixtures/zip-crypto", "tests/fixtures/zip-winzip", "tests/fixtures/zip-pkware", "tests/fixtures/rar-15", "tests/fixtures/rar-20", "tests/fixtures/rar-30", "tests/fixtures/rar-50", "tests/fixtures/7z-aes"];
    let plain = aw(&[&["info"][..], &dirs].concat());
    assert_eq!(plain.code, Some(0), "{}", plain.stderr);
    assert!(!holds_a_hash_line(&plain.stdout), "info printed a hash line");
    assert!(!holds_a_hash_line(&plain.stderr), "info printed a hash line");
    assert!(!plain.stdout.contains("# hashcat"), "{}", plain.stdout);

    let json = aw(&[&["info", "--json"][..], &dirs].concat());
    assert_eq!(json.code, Some(0), "{}", json.stderr);
    assert!(!holds_a_hash_line(&json.stdout), "info --json printed a hash line");

    // one row for each line `hash` writes, in its order: its type, its mode, its entry, its
    // scheme and what it proves
    let lines = aw(&[&["hash", "--json"][..], &dirs].concat());
    let written: Vec<serde_json::Value> = lines.stdout.lines().map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()).collect();
    assert!(written.len() > 250, "{}", written.len());

    let mut named = Vec::new();
    for line in json.stdout.lines() {
        let report: serde_json::Value = serde_json::from_str(line).unwrap();
        for hash in report["lines"].as_array().unwrap() {
            let fields: Vec<&str> = hash.as_object().unwrap().keys().map(String::as_str).collect();
            assert!(fields == ["entry", "mode", "proves", "tag"] || fields == ["mode", "proves", "tag"], "a line is named by its type, its mode, its entry and what it proves, and nothing else: {hash}");
            named.push((report["path"].clone(), hash["mode"].clone(), hash["tag"].clone(), hash.get("entry").cloned(), hash["proves"].clone()));
        }
    }
    let expected: Vec<_> = written.iter().map(|object| (object["path"].clone(), object["mode"].clone(), object["tag"].clone(), object.get("entry").cloned(), object["proves"].clone())).collect();
    assert_eq!(named, expected);

    let rows: Vec<String> = plain.stdout.lines().filter(|line| line.contains(", hashcat mode ")).map(|line| line.trim_start().trim_start_matches("line").trim_start().to_owned()).collect();
    assert_eq!(rows.len(), written.len());
    for (row, object) in rows.iter().zip(&written) {
        let start = format!("{}, hashcat mode {}, {}, from ", object["tag"].as_str().unwrap(), object["mode"], object["proves"].as_str().unwrap());
        assert!(row.starts_with(&start), "{row} for {object}");
        assert_eq!(row.ends_with(", from the headers"), object.get("entry").is_none(), "{row}");
    }
}

// ---------------------------------------------------------------------------
// What the earlier design had and this one does not
// ---------------------------------------------------------------------------

#[test]
fn the_commands_and_flags_of_the_earlier_design_are_rejected() {
    let zip = "tests/fixtures/zip-crypto/zipcrypto.zip";
    let rar = "tests/fixtures/rar-13/rar14-password-stored.rar";
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("out");
    let out = out.to_str().unwrap();

    let gone: &[&[&str]] = &[
        &["unlock", zip],
        &["unlock", "--password", "testpass", zip],
        &["advanced", "strip", zip, "-o", out],
        &["advanced", "extract", zip, "-o", out],
        &["advanced", "decrypt", rar, "--password", "password", "-o", out],
        &["advanced", "collide", zip],
        &["attack", "zip-crypto", zip, "--password", "testpass"],
        &["attack", "zip-crypto", zip, "--wordlist", "Cargo.toml"],
        &["--format", "hashcat", "info", zip],
        &["info", "--format", "json", zip],
        &["hash", "--format", "hashcat", zip],
        &["--all-hashes", "info", zip],
        &["info", "--all-hashes", zip],
        &["hash", "--all-hashes", zip],
        &["info", "--password", "testpass", zip],
        &["hash", "--password", "testpass", zip],
        &["hash", "-p", "testpass", zip],
        &["info", "--password-file", "Cargo.toml", zip],
        &["info", "--output-dir", out, zip],
        &["hash", "--output-dir", out, zip],
        &["hash", "-o", out, zip],
        &["attack", "rar-13", rar, "-o", out, "--password", "password"],
        &["attack", "rar-13", rar, "-o", out, "--password-file", "Cargo.toml"],
        &["attack", "rar-13", rar, "-o", out, "--key0", "73", "--key1", "1f", "--key2", "3d"],
        &["attack", "rar-13", rar, "--output-dir", out],
        // a flag is taken only by the command it means something to
        &["info", "--all", zip],
        &["info", "--mode", "46100", zip],
        &["--json", "info", zip],
        &["--all", "hash", zip],
        &["attack", "rar-13", rar, "-o", out, "--json"],
        // and an attack names the file it writes
        &["attack", "rar-13", rar],
    ];
    for args in gone {
        let run = aw(args);
        assert_eq!(run.code, Some(2), "{args:?} is taken: {}{}", run.stdout, run.stderr);
        assert!(run.stdout.is_empty(), "{args:?}: {}", run.stdout);
        assert!(run.stderr.starts_with("error: "), "{args:?}: {}", run.stderr);
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "a command line that is refused writes nothing");
}

#[test]
fn help_names_no_command_or_flag_that_is_gone() {
    for args in [&["--help"][..], &["info", "--help"], &["hash", "--help"], &["attack", "--help"], &["attack", "rar-13", "--help"], &["attack", "zip-crypto", "--help"]] {
        let run = aw(args);
        assert_eq!(run.code, Some(0), "{args:?}");
        for gone in ["unlock", "advanced", "--format", "--all-hashes", "--password", "--key0", "--output-dir", "collide", "extract", "strip"] {
            assert!(!run.stdout.contains(gone), "{args:?} names {gone}:\n{}", run.stdout);
        }
    }
    let attack = aw(&["attack", "--help"]);
    assert!(attack.stdout.contains("rar-13") && attack.stdout.contains("zip-crypto"), "{}", attack.stdout);
    // the attack on zip-crypto takes what the user knows, and no password
    let zip_crypto = aw(&["attack", "zip-crypto", "--help"]);
    for option in ["--known", "--bytes", "--starts", "--class", "--type", "--keys", "--entry", "--only", "--no-guess", "--deep", "--plan", "--budget", "--attempt-budget", "--threads", "--slice", "--json", "Giving what you know:", "Choosing what is tried:", "Limits:", "Exit status:"] {
        assert!(zip_crypto.stdout.contains(option), "no {option} in:\n{}", zip_crypto.stdout);
    }
}

#[test]
fn a_path_that_starts_with_a_dash_is_read_behind_a_double_dash() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy("tests/fixtures/zip-crypto/zipcrypto.zip", dir.path().join("-x.zip")).unwrap();
    let bin = env!("CARGO_BIN_EXE_archivewolf");

    let info = std::process::Command::new(bin).current_dir(dir.path()).args(["info", "--json", "--", "-x.zip"]).output().unwrap();
    assert_eq!(info.status.code(), Some(0), "{}", String::from_utf8_lossy(&info.stderr));
    let report: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(report["path"], "-x.zip");

    let hash = std::process::Command::new(bin).current_dir(dir.path()).args(["hash", "--", "-x.zip"]).output().unwrap();
    assert_eq!(hash.status.code(), Some(0), "{}", String::from_utf8_lossy(&hash.stderr));
    assert!(String::from_utf8_lossy(&hash.stdout).starts_with("$zip$1$*"));

    // without the double dash it is a flag nobody knows
    let flag = std::process::Command::new(bin).current_dir(dir.path()).args(["hash", "-x.zip"]).output().unwrap();
    assert_eq!(flag.status.code(), Some(2));
}

/// `-v` says where each line comes from, `-vv` says what a walk passes over, and every note is
/// one plain line: no time, no level and no colour, so that a run reads the same every time.
#[test]
fn the_notes_grow_with_the_verbosity_and_are_plain_lines() {
    let mixed = "tests/fixtures/zip-winzip/gen_own_mixed_zc_aes.zip";
    let plain = aw(&["hash", mixed]);
    let more = aw(&["-v", "hash", mixed]);
    assert_eq!((plain.code, more.code, plain.stdout == more.stdout), (Some(0), Some(0), true));
    assert!(!plain.stderr.contains("from zc.txt"), "{}", plain.stderr);
    assert!(more.stderr.contains(&format!("archivewolf: {mixed}: $zip$1$, hashcat mode 46100, exact, from zc.txt\n")), "{}", more.stderr);
    assert!(more.stderr.contains(&format!("archivewolf: {mixed}: $zip$2$, hashcat mode 46200, exact, from aes.txt\n")), "{}", more.stderr);

    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(mixed, dir.path().join("a.zip")).unwrap();
    std::fs::write(dir.path().join("notes.txt"), b"not an archive at all").unwrap();
    let walk = dir.path().to_str().unwrap();
    assert!(!aw(&["-v", "hash", walk]).stderr.contains("notes.txt"));
    let most = aw(&["-vv", "hash", walk]);
    assert!(most.stderr.contains("notes.txt: not an archive, passed over\n"), "{}", most.stderr);

    // a note of the tool starts with its name, and none carries an escape or a clock
    let warned = aw(&["info", "tests/fixtures/unparseable/multidisk_stub.zip"]);
    assert!(warned.stderr.starts_with("archivewolf: tests/fixtures/unparseable/multidisk_stub.zip: the last volume"), "{}", warned.stderr);
    for run in [&plain, &more, &most, &warned] {
        assert!(!run.stderr.contains('\x1b') && !run.stderr.contains(" WARN ") && !run.stderr.contains(" INFO "), "{}", run.stderr);
    }
    assert_eq!(warned.stderr, aw(&["info", "tests/fixtures/unparseable/multidisk_stub.zip"]).stderr, "the same notes on every run");
}

/// A file that is named and is no archive is said on standard error. It is no failure: the run
/// ends as it would without it.
#[test]
fn a_named_file_that_is_no_archive_is_said_and_fails_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let text = dir.path().join("notes.txt");
    std::fs::write(&text, b"not an archive at all").unwrap();
    let text = text.to_str().unwrap();
    let archive = "tests/fixtures/zip-crypto/zipcrypto.zip";

    let both = aw(&["info", archive, text]);
    assert_eq!(both.code, Some(0), "{}", both.stderr);
    assert_eq!(both.stderr, format!("archivewolf: {text}: not an archive\n"));
    assert_eq!(both.stdout, aw(&["info", archive]).stdout);
    assert_eq!(aw(&["-q", "info", archive, text]).stderr, "");

    let alone = aw(&["hash", text]);
    assert_eq!((alone.code, alone.stdout.as_str()), (Some(1), ""));
    assert!(alone.stderr.starts_with(&format!("archivewolf: {text}: not an archive\n")) && alone.stderr.contains("no archives found"), "{}", alone.stderr);
}

/// A file that two arguments lead to is reported once, however its path is spelled.
#[test]
fn a_file_given_twice_under_two_spellings_is_reported_once() {
    let archive = "tests/fixtures/rar-50/v500_p_m0.rar";
    let run = aw(&["hash", archive, "./tests/fixtures/rar-50/../rar-50/v500_p_m0.rar", "tests/fixtures/rar-50"]);
    let once = aw(&["hash", "tests/fixtures/rar-50"]);
    assert_eq!(run.code, Some(0), "{}", run.stderr);
    // the same lines, each once: the file is listed where the path that sorts first puts it
    let sorted = |text: &str| {
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        lines.sort();
        lines
    };
    assert_eq!(sorted(&run.stdout).len(), sorted(&once.stdout).len());
    assert!(sorted(&run.stdout) == sorted(&once.stdout), "the lines of a run over the directory, and no line twice");
}
