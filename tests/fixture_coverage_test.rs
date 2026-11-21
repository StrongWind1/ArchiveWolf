#![expect(unused_crate_dependencies, reason = "integration test")]
#![expect(missing_docs, reason = "test module")]
#![expect(clippy::expect_used, reason = "test helpers: panic on bad fixture data is intentional")]
#![expect(clippy::unwrap_used, reason = "test helpers: panic on bad fixture data is intentional")]

use std::collections::HashMap;
use std::path::Path;

use assert_cmd::Command;

fn load_passwords() -> HashMap<String, String> {
    let data = std::fs::read_to_string("tests/fixtures/passwords.json").expect("passwords.json must exist");
    serde_json::from_str(&data).expect("passwords.json must be valid JSON")
}

fn archive_files(dir: &str) -> Vec<std::path::PathBuf> {
    let base = Path::new("tests/fixtures").join(dir);
    if !base.is_dir() {
        return Vec::new();
    }
    let mut files: Vec<_> = std::fs::read_dir(&base)
        .unwrap()
        .flatten()
        .filter(|e| {
            let ext = e.path().extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
            matches!(ext.as_str(), "zip" | "rar" | "7z" | "exe")
        })
        .map(|e| e.path())
        .collect();
    files.sort();
    files
}

fn rel_path(p: &Path) -> String {
    p.strip_prefix("tests/fixtures/").unwrap_or(p).to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// 7z-aes: files parse and at least one emits a $7z$ hash
// ---------------------------------------------------------------------------

#[test]
fn sevenz_aes_all_parse_and_emit_hash() {
    let files = archive_files("7z-aes");
    assert!(!files.is_empty(), "7z-aes/ should contain archives");

    let mut hash_count = 0u32;
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains("$7z$") {
            hash_count += 1;
        }
    }
    assert!(hash_count > 0, "7z-aes/ should emit at least one $7z$ hash");
}

// ---------------------------------------------------------------------------
// zip-winzip: every file emits a $zip$2$ hash
// ---------------------------------------------------------------------------

#[test]
fn zip_winzip_all_parse_and_emit_hash() {
    let files = archive_files("zip-winzip");
    assert!(!files.is_empty(), "zip-winzip/ should contain archives");

    let mut failures = Vec::new();
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.contains("$zip$2$") {
            failures.push(format!("{}: no $zip$2$ hash emitted", rel_path(f)));
        }
    }
    assert!(failures.is_empty(), "zip-winzip hash emission failures:\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// zip-pkware: every file emits a $zip$3$ hash
// ---------------------------------------------------------------------------

#[test]
fn zip_pkware_all_parse_and_emit_hash() {
    let files = archive_files("zip-pkware");
    assert!(!files.is_empty(), "zip-pkware directory must have fixtures");
    let mut failures = Vec::new();

    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if !stdout.contains("$zip$3$") {
            failures.push(format!("{}: no $zip$3$ hash emitted", rel_path(f)));
        }
    }
    assert!(failures.is_empty(), "zip-pkware failures:\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// zip-crypto: every file parses and emits a hash, unless nothing in it is encrypted
// ---------------------------------------------------------------------------

#[test]
fn zip_crypto_all_parse_and_emit_hash() {
    let files = archive_files("zip-crypto");
    assert!(!files.is_empty(), "zip-crypto/ should contain archives");

    let mut failures = Vec::new();
    for f in &files {
        let info_out = Command::cargo_bin("archivewolf").unwrap().args(["info", f.to_str().unwrap()]).output().unwrap();
        let info = String::from_utf8_lossy(&info_out.stdout);
        let hash_out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&hash_out.stdout);
        if !stdout.contains("$zip$1$") && !info.contains("line      none: nothing is encrypted") {
            failures.push(format!("{}: no ZipCrypto hash emitted", rel_path(f)));
        }
    }
    assert!(failures.is_empty(), "zip-crypto hash emission failures:\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// rar5: files parse and at least one emits a $rar$50$ hash
// ---------------------------------------------------------------------------

#[test]
fn rar5_all_parse_and_emit_hash() {
    let files = archive_files("rar-50");
    assert!(!files.is_empty(), "rar-50/ should contain archives");

    let mut hash_count = 0u32;
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains("$rar$50$") {
            hash_count += 1;
        }
    }
    assert!(hash_count > 0, "rar-50/ should emit at least one $rar$50$ hash");
}

// ---------------------------------------------------------------------------
// rar3: files parse and at least one emits a RAR3/legacy hash
// ---------------------------------------------------------------------------

#[test]
fn rar3_all_parse_and_emit_hash() {
    let files = archive_files("rar-30");
    assert!(!files.is_empty(), "rar-30/ should contain archives");

    let mut hash_count = 0u32;
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.contains("$rar$30$") || stdout.contains("$rar$15$") || stdout.contains("$rar$20$") {
            hash_count += 1;
        }
    }
    assert!(hash_count > 0, "rar-30/ should emit at least one RAR3/legacy hash");
}

// ---------------------------------------------------------------------------
// rar-13: every file parses (no hashcat mode, so no line expected)
// ---------------------------------------------------------------------------

#[test]
fn rar_13_all_parse() {
    let files = archive_files("rar-13");
    assert!(!files.is_empty(), "rar-13/ should contain archives");

    let mut failures = Vec::new();
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["info", f.to_str().unwrap()]).output().unwrap();
        if !out.status.success() {
            failures.push(format!("{}: info failed", rel_path(f)));
        }
    }
    assert!(failures.is_empty(), "rar-13 parse failures:\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// rar-15: every file emits a $rar$15$ hash
// ---------------------------------------------------------------------------

#[test]
fn rar_15_all_parse_and_emit_hash() {
    let files = archive_files("rar-15");
    assert!(!files.is_empty(), "rar-15/ should contain archives");

    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("$rar$15$"), "{}: no $rar$15$ hash", rel_path(f));
    }
}

// ---------------------------------------------------------------------------
// rar-20: every file emits a $rar$20$ hash
// ---------------------------------------------------------------------------

#[test]
fn rar_20_all_parse_and_emit_hash() {
    let files = archive_files("rar-20");
    assert!(!files.is_empty(), "rar-20/ should contain archives");

    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("$rar$20$"), "{}: no $rar$20$ hash", rel_path(f));
    }
}

// ---------------------------------------------------------------------------
// pseudo: every file parses and detected as pseudo-encrypted
// ---------------------------------------------------------------------------

#[test]
fn pseudo_all_detected() {
    let files = archive_files("pseudo");
    assert!(!files.is_empty(), "pseudo/ should contain archives");

    // An entry that holds nothing proves nothing: the CRC-32 of no data is 0 with or without an
    // encryption header in front. These three hold only such entries, each with its flag and its
    // 12-byte header: they are encrypted, and their line tests the check byte of that header.
    let empty = ["edge_libzip_empty-pkware.zip", "gen_infozip_empty.zip", "gen_own_zc_empty_only.zip"];

    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["info", f.to_str().unwrap()]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        if empty.iter().any(|name| f.ends_with(name)) {
            assert!(stdout.contains(" encrypted; coverage all") && !stdout.contains("pseudo-encrypted") && stdout.contains("line      $zip$1$, hashcat mode 46100, weak, from "), "{}: an empty entry with an encryption header is encrypted: {stdout}", rel_path(f));
            continue;
        }
        assert!(stdout.contains(" pseudo-encrypted; coverage none") && stdout.contains(": marked encrypted and not encrypted: ") && stdout.contains("line      none: nothing is encrypted"), "{}: not detected as pseudo-encrypted: {stdout}", rel_path(f));
        // and nothing in it is given a line or a scheme
        let json = Command::cargo_bin("archivewolf").unwrap().args(["info", "--json", f.to_str().unwrap()]).output().unwrap();
        let report: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!(report["entries"]["pseudo"], report["entries"]["total"], "{}", rel_path(f));
        assert_eq!((&report["schemes"], &report["lines"], &report["no_line"]), (&serde_json::json!([]), &serde_json::json!([]), &serde_json::json!([])), "{}", rel_path(f));
        assert!(report["entry_list"].as_array().unwrap().iter().all(|entry| entry["state"] == "pseudo-encrypted" && entry.get("scheme").is_none()), "{}", rel_path(f));
        let listed: Vec<u64> = report["findings"][0]["entries"].as_array().unwrap().iter().filter_map(serde_json::Value::as_u64).collect();
        assert_eq!((report["findings"][0]["code"].as_str(), listed.len() as u64), (Some("pseudo-encryption"), report["entries"]["total"].as_u64().unwrap()), "{}", rel_path(f));
    }
}

// ---------------------------------------------------------------------------
// unencrypted: every file parses with no false-positive hashes
// ---------------------------------------------------------------------------

#[test]
fn unencrypted_all_parse_no_encryption() {
    let files = archive_files("unencrypted");
    assert!(!files.is_empty(), "unencrypted/ should contain archives");

    let mut failures = Vec::new();
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["info", f.to_str().unwrap()]).output().unwrap();
        if !out.status.success() {
            failures.push(format!("{}: info failed", rel_path(f)));
            continue;
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let hashcat_out = Command::cargo_bin("archivewolf").unwrap().args(["hash", f.to_str().unwrap()]).output().unwrap();
        let hash_stdout = String::from_utf8_lossy(&hashcat_out.stdout);
        if (hash_stdout.contains("$zip$") || hash_stdout.contains("$rar$") || hash_stdout.contains("$7z$")) && !stdout.contains("; coverage none") && !stdout.contains("; coverage some") {
            failures.push(format!("{}: classified as unencrypted but emits hash", rel_path(f)));
        }
    }
    assert!(failures.is_empty(), "unencrypted failures:\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// unparseable: every file doesn't panic
// ---------------------------------------------------------------------------

#[test]
fn unparseable_no_panics() {
    let files = archive_files("unparseable");
    assert!(!files.is_empty(), "unparseable/ should contain archives");

    let mut panics = Vec::new();
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["info", f.to_str().unwrap()]).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("panic") || stderr.contains("RUST_BACKTRACE") {
            panics.push(format!("{}: panicked", rel_path(f)));
        }
    }
    assert!(panics.is_empty(), "unparseable panics:\n{}", panics.join("\n"));
}

// ---------------------------------------------------------------------------
// unknown-pw: every file parses without panic
// ---------------------------------------------------------------------------

#[test]
fn unknown_pw_all_parse_no_panic() {
    let files = archive_files("unknown-pw");
    if files.is_empty() {
        return;
    }

    let mut panics = Vec::new();
    for f in &files {
        let out = Command::cargo_bin("archivewolf").unwrap().args(["info", f.to_str().unwrap()]).output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("panic") || stderr.contains("RUST_BACKTRACE") {
            panics.push(format!("{}: panicked", rel_path(f)));
        }
    }
    assert!(panics.is_empty(), "unknown-pw panics:\n{}", panics.join("\n"));
}

// ---------------------------------------------------------------------------
// passwords.json coverage: every entry resolves to an existing file
// ---------------------------------------------------------------------------

#[test]
fn passwords_json_all_files_exist() {
    let passwords = load_passwords();
    let mut missing = Vec::new();
    for rel in passwords.keys() {
        let path = Path::new("tests/fixtures").join(rel);
        if !path.exists() {
            missing.push(rel.clone());
        }
    }
    assert!(missing.is_empty(), "passwords.json references missing files:\n{}", missing.join("\n"));
}

// ---------------------------------------------------------------------------
// Global: no archive in any encryption-type directory panics
// ---------------------------------------------------------------------------

#[test]
fn global_no_panics() {
    let dirs = ["7z-aes", "zip-crypto", "zip-winzip", "zip-pkware", "pseudo", "rar-13", "rar-15", "rar-20", "rar-30", "rar-50"];
    let mut panics = Vec::new();

    for dir in dirs {
        for f in archive_files(dir) {
            let out = Command::cargo_bin("archivewolf").unwrap().args(["info", f.to_str().unwrap()]).output().unwrap();
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("panic") || stderr.contains("RUST_BACKTRACE") {
                panics.push(format!("{}: panicked", rel_path(&f)));
            }
        }
    }
    assert!(panics.is_empty(), "panics detected:\n{}", panics.join("\n"));
}
