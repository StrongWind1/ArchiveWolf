#![expect(unused_crate_dependencies, reason = "integration test")]
#![expect(unused_results, reason = "assert_cmd assertions are self-verifying")]
//! Verification tests against real archives created with local tools.
//!
//! Each test validates that ArchiveWolf produces correct output for
//! archives created with `zip`, `rar`, and `7zz`: what `info` says of
//! them, and the lines `hash` writes for them.

use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt as _;
use predicates::prelude::predicate;

const FIXTURES: &str = "tests/fixtures";

// ---------------------------------------------------------------------------
// ZIP: ZipCrypto detection
// ---------------------------------------------------------------------------

#[test]
fn zip_crypto_detected() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-crypto/zipcrypto.zip"]).assert().success().stdout(predicate::str::contains("scheme    zip-crypto:check8  ZipCrypto, check byte 8 bits, CRC-32 (1 entry, 1 key group)"));
}

// ---------------------------------------------------------------------------
// ZIP: WinZip AES-256 detection + hash emission
// ---------------------------------------------------------------------------

#[test]
fn zip_winzip256_detected() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "tests/fixtures/zip-winzip/winzip_aes256.zip"])
        .assert()
        .success()
        .stdout(predicate::str::contains("scheme    zip-winzip:256:ae2  AE-"))
        .stdout(predicate::str::contains(", AES-256, PBKDF2-HMAC-SHA1 1000, verifier 16 bits, authentication code 80 bits"));
}

#[test]
fn zip_winzip256_hash_emitted() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-winzip/winzip_aes256.zip"]).assert().success().stdout(predicate::str::contains("$zip$2$"));
}

// ---------------------------------------------------------------------------
// ZIP: Pseudo-encryption detection
// ---------------------------------------------------------------------------

#[test]
fn zip_pseudo_encryption_detected() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "tests/fixtures/pseudo/pseudo.zip"])
        .assert()
        .success()
        .stdout(predicate::str::contains("entries   none of 1 entry encrypted, 1 pseudo-encrypted; coverage none"))
        .stdout(predicate::str::contains("findings  plain.txt: marked encrypted and not encrypted"))
        .stdout(predicate::str::contains("line      none: nothing is encrypted"));
}

// ---------------------------------------------------------------------------
// ZIP: tiny stored entries (1, 2, 4 bytes)
// ---------------------------------------------------------------------------

#[test]
fn zip_tiny_stored_entries_are_listed() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--entries", "tests/fixtures/unparseable/crc_tiny.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for (name, size) in [("one.txt", 2), ("two.txt", 3), ("four.txt", 5)] {
        let row = stdout.lines().find(|line| line.ends_with(&format!("  {name}"))).unwrap_or_else(|| panic!("no row for {name}: {stdout}"));
        let cells: Vec<&str> = row.split_whitespace().collect();
        assert_eq!((cells[1], cells[2], cells[3], cells[5], cells[7]), ("file", "encrypted", "zip-crypto:check8", "stored", size.to_string().as_str()), "{row}");
    }
}

// ---------------------------------------------------------------------------
// ZIP: Mixed archive (encrypted + unencrypted entries)
// ---------------------------------------------------------------------------

#[test]
fn zip_mixed_archive() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--entries", "tests/fixtures/zip-crypto/mixed.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("entries   1 of 2 entries encrypted; coverage some"), "one entry of two is encrypted: {stdout}");
    assert!(stdout.contains("plain.txt: 1 entry is encrypted, and 1 that holds data is not"), "the finding names the entry that is open: {stdout}");
    let state_of = |name: &str| stdout.lines().find(|line| line.ends_with(&format!("  {name}"))).and_then(|row| row.split_whitespace().nth(2).map(str::to_owned));
    assert_eq!(state_of("plain.txt").as_deref(), Some("plain"), "{stdout}");
    assert_eq!(state_of("tiny.txt").as_deref(), Some("encrypted"), "{stdout}");
}

// ---------------------------------------------------------------------------
// ZIP: Stored ZipCrypto with PNG
// ---------------------------------------------------------------------------

#[test]
fn zip_stored_has_png_for_bk() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--entries", "tests/fixtures/zip-crypto/zipcrypto_stored.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().any(|line| line.contains("  file  encrypted  zip-crypto:check8  ") && line.contains("  stored  ") && line.ends_with("  tiny.png")), "should list the PNG entry as stored under ZipCrypto: {stdout}");
    assert!(stdout.contains("zip-crypto:check8  ZipCrypto"), "should detect ZipCrypto");
}

// ---------------------------------------------------------------------------
// RAR5: Detection + hash emission
// ---------------------------------------------------------------------------

#[test]
fn rar5_header_encrypted_detected() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "tests/fixtures/rar-50/v730_hp_m3.rar"])
        .assert()
        .success()
        .stdout(predicate::str::contains("   RAR 5\n  headers   encrypted: names and sizes hidden\n  scheme    rar-50:headers:check  AES-256, PBKDF2-HMAC-SHA256 2^15, check value 64 bits\n"));
}

#[test]
fn rar5_header_encrypted_hash_emitted() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/v730_hp_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$50$"));
}

#[test]
fn rar5_file_encrypted_detected() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "tests/fixtures/rar-50/v730_p_m3.rar"])
        .assert()
        .success()
        .stdout(predicate::str::contains("headers   readable"))
        .stdout(predicate::str::contains("encrypted; coverage all"))
        .stdout(predicate::str::contains("scheme    rar-50:data:check:keyed  AES-256, PBKDF2-HMAC-SHA256 2^15, check value 64 bits"));
}

#[test]
fn rar5_unencrypted() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/unencrypted/plain.rar"]).assert().success().stdout(predicate::str::contains("   RAR 5, ")).stdout(predicate::str::contains("; coverage none")).stdout(predicate::str::contains("line      none: nothing is encrypted"));
}

// ---------------------------------------------------------------------------
// 7z: Detection + hash emission (stored and compressed)
// ---------------------------------------------------------------------------

#[test]
fn sevenz_stored_encrypted_detected() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "--entries", "tests/fixtures/7z-aes/7z_stored.7z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("scheme    7z-aes:data  AES-256, SHA-256 2^19, CRC-32 (1 folder, 1 key group)"))
        .stdout(predicate::str::contains("  folder  encrypted  7z-aes:data      1  stored  "));
}

#[test]
fn sevenz_stored_hash_emitted() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/7z-aes/7z_stored.7z"]).assert().success().stdout(predicate::str::contains("$7z$"));
}

#[test]
fn sevenz_lzma2_encrypted_detected() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "--entries", "tests/fixtures/7z-aes/7z_lzma2.7z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("scheme    7z-aes:data  AES-256, SHA-256 2^19, CRC-32 (1 folder, 1 key group)"))
        .stdout(predicate::str::contains("  folder  encrypted  7z-aes:data      1  LZMA2  "));
}

#[test]
fn sevenz_lzma2_hash_emitted() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/7z-aes/7z_lzma2.7z"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("$7z$"), "should emit $7z$ hash");
}

#[test]
fn sevenz_encrypted_headers_detected() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "--entries", "tests/fixtures/7z-aes/headers.7z"])
        .assert()
        .success()
        .stdout(predicate::str::contains("   7z\n  headers   encrypted: names and sizes hidden\n  scheme    7z-aes:headers  AES-256, SHA-256 2^19"))
        .stdout(predicate::str::contains(", from the headers\n"))
        .stdout(predicate::str::contains("  list  ").not());
}

#[test]
fn sevenz_unencrypted() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/unencrypted/plain.7z"]).assert().success().stdout(predicate::str::contains("; coverage none")).stdout(predicate::str::contains("line      none: nothing is encrypted"));
}

// ---------------------------------------------------------------------------
// Directory scan: finds all fixture formats
// ---------------------------------------------------------------------------

#[test]
fn scan_fixtures_directory_finds_all_formats() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", FIXTURES]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for (name, label) in [("ZIP", ".zip   ZIP, "), ("ZIP64", "   ZIP64, "), ("RAR 1.4", ".rar   RAR 1.4, "), ("RAR 1.5 to 4", ".rar   RAR 1.5 to 4, "), ("RAR 5", ".rar   RAR 5, "), ("7z", ".7z   7z, ")] {
        assert!(stdout.lines().any(|line| !line.starts_with(' ') && line.contains(label)), "should find {name} archives");
    }
}

// ---------------------------------------------------------------------------
// JSON output is valid
// ---------------------------------------------------------------------------

#[test]
fn json_output_is_valid_for_all_formats() {
    for (fixture, format, generation) in [("zip-crypto/zipcrypto.zip", "zip", "zip"), ("rar-50/v730_p_m3.rar", "rar", "rar5"), ("7z-aes/7z_stored.7z", "7z", "7z"), ("rar-30/v420_p_m3.rar", "rar", "rar4"), ("rar-13/rar14-password-stored.rar", "rar", "rar1")] {
        let path = format!("{FIXTURES}/{fixture}");
        let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--json", &path]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{fixture} failed: {}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let reports: Vec<serde_json::Value> = stdout.lines().map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON for {fixture}: {e}\nline: {line}"))).collect();
        assert_eq!(reports.len(), 1, "{fixture}: one archive is one line of JSON: {stdout}");
        let report = &reports[0];
        assert_eq!(report["path"], path.as_str(), "{fixture}");
        assert_eq!((report["format"].as_str(), report["generation"].as_str()), (Some(format), Some(generation)), "{fixture}");
        let entries = report["entry_list"].as_array().unwrap_or_else(|| panic!("{fixture}: no entries in {report}"));
        assert!(!entries.is_empty() && report["entries"]["total"] == entries.len(), "{fixture}: the counts are those of the list: {report}");
        assert!(entries.iter().all(|entry| entry["kind"].is_string() && entry["state"].is_string()), "{fixture}: {report}");
        assert!(entries.iter().any(|entry| entry["state"] == "encrypted" && entry["scheme"].is_string() && entry["key_group"].is_u64()), "{fixture}: {report}");
        // an encrypted archive has a line, or says why it has none
        let hashes = report["lines"].as_array().unwrap();
        assert!(hashes.iter().all(|hash| hash["mode"].is_u64() && hash["tag"].is_string() && hash["proves"].is_string() && hash["entry"].is_u64()), "{fixture}: {report}");
        if generation == "rar1" {
            assert_eq!(report["no_line"], serde_json::json!([{ "scheme": "rar-13", "reason": "no-mode", "text": "no hashcat mode exists for rar-13: `attack rar-13` searches its key" }]), "{fixture}");
        } else {
            assert_eq!((hashes.len(), report["no_line"].as_array().map(Vec::len)), (1, Some(0)), "{fixture}: {report}");
        }
    }
}

// ---------------------------------------------------------------------------
// ZIP: Deflate ZipCrypto
// ---------------------------------------------------------------------------

#[test]
fn zip_deflate_zip_crypto_detected() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-crypto/zipcrypto_deflate.zip"]).assert().success().stdout(predicate::str::contains("ZipCrypto"));
}

// ---------------------------------------------------------------------------
// ZIP: WinZip AES-128
// ---------------------------------------------------------------------------

#[test]
fn zip_winzip128_detected() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-winzip/winzip_aes128.zip"]).assert().success().stdout(predicate::str::contains("zip-winzip:128:ae2  AE-")).stdout(predicate::str::contains(", AES-128, PBKDF2-HMAC-SHA1 1000, "));
}

// ---------------------------------------------------------------------------
// ZIP: Multi-entry stored ZipCrypto
// ---------------------------------------------------------------------------

#[test]
fn zip_multi_entry_stored() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--entries", "tests/fixtures/zip-crypto/multi_stored.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["multi1.txt", "multi2.txt", "multi3.txt"] {
        assert!(stdout.lines().any(|line| line.contains("  file  encrypted  zip-crypto:check8  ") && line.ends_with(&format!("  {name}"))), "should list {name}: {stdout}");
    }
    assert!(stdout.contains("$zip$1$, hashcat mode 46100, exact, from multi"), "should name the hash line: {stdout}");
    let lines = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/multi_stored.zip"]).output().unwrap();
    assert!(String::from_utf8_lossy(&lines.stdout).starts_with("$zip$1$*3*"), "should emit one line that tests all three entries");
}

// ---------------------------------------------------------------------------
// ZIP: Nested ZIP detection
// ---------------------------------------------------------------------------

#[test]
fn zip_nested_detected() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-crypto/nested.zip"]).assert().success().stdout(predicate::str::contains("ZipCrypto"));
}

// ---------------------------------------------------------------------------
// ZIP: Comment
// ---------------------------------------------------------------------------

#[test]
fn zip_comment_shown() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/zip-crypto/commented.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\n  comment   This is a test comment\n"), "should show archive comment: {stdout}");
}

// ---------------------------------------------------------------------------
// RAR5: Multi-file
// ---------------------------------------------------------------------------

#[test]
fn rar5_multi_file_detected() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/rar-50/v730_p_m0.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("RAR 5, 2 entries") && stdout.contains("entries   1 of 2 entries encrypted; coverage all"), "should detect encryption: {stdout}");
}

// ---------------------------------------------------------------------------
// 7z: Multi-file encrypted
// ---------------------------------------------------------------------------

#[test]
fn sevenz_multi_file() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/7z-aes/multi.7z"]).output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("entries   1 of 1 folder encrypted; coverage all") && stdout.contains("scheme    7z-aes:data  AES-256"), "should detect encryption: {stdout}");
}

// ---------------------------------------------------------------------------
// RAR 1.4: RARFMT14 parsing + CRYPT_RAR13 detection
// ---------------------------------------------------------------------------

#[test]
fn rar14_encrypted_parsed() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/rar-13/rar14-password-stored.rar"]).output().unwrap();
    assert!(output.status.success(), "archivewolf should succeed on RAR14");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("   RAR 1.4, 1 entry") && stdout.contains("entries   1 of 1 entry encrypted; coverage all") && stdout.contains("scheme    rar-13  RAR 1.3 cipher"), "should detect encryption: {stdout}");
}

#[test]
fn rar14_unencrypted_parsed() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/unencrypted/rar14-solid.rar"]).assert().success().stdout(predicate::str::contains("RAR"));
}

#[test]
fn rar14_encrypted_compressed_parsed() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/rar-13/rar14-password-compressed.rar"]).assert().success().stdout(predicate::str::contains("scheme    rar-13  RAR 1.3 cipher")).stdout(predicate::str::contains("no line   rar-13: no-mode: "));
}

// ---------------------------------------------------------------------------
// RAR 1.5 and RAR 2.0: Legacy encrypted archives
// ---------------------------------------------------------------------------

#[test]
fn rar_15_encrypted_emits_rar_15_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-15/rar15-password-stored.rar"]).assert().success().stdout(predicate::str::contains("$rar$15$"));
}

#[test]
fn rar_20_encrypted_emits_rar_20_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-20/rar20-password-compressed.rar"]).assert().success().stdout(predicate::str::contains("$rar$20$"));
}

// ---------------------------------------------------------------------------
// RAR3/4: Encrypted archives
// ---------------------------------------------------------------------------

#[test]
fn rar3_header_encrypted_emits_rar_30() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_hp_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$*0*"));
}

#[test]
fn rar3_file_encrypted_emits_rar_30() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_p_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$*1*"));
}

#[test]
fn rar4_header_encrypted_emits_rar_30() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_hp_m0.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$*0*"));
}

#[test]
fn rar3_file_encrypted_detected() {
    Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/rar-30/v420_p_m3.rar"]).assert().success().stdout(predicate::str::contains("scheme    rar-30:data  AES-128, SHA-1 2^18, CRC-32 (1 entry, 1 key group)"));
}

// ---------------------------------------------------------------------------
// `hash` outputs raw hashes only
// ---------------------------------------------------------------------------

#[test]
fn hash_output_raw_only() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/zipcrypto.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("Entry"), "hash output should not contain triage table");
    assert!(!stdout.contains("Verdict"), "hash output should not contain verdicts");
    assert_eq!(stdout.lines().count(), 1, "one line for the archive: {stdout}");
    for line in stdout.lines() {
        assert!(line.starts_with("$zip$1$*") && line.ends_with("$/zip$"), "each line should be a hash and nothing else: {line}");
    }
}

// ---------------------------------------------------------------------------
// Full directory scan of all fixtures
// ---------------------------------------------------------------------------

#[test]
fn scan_all_fixtures() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", FIXTURES]).output().unwrap();
    // three files under unparseable/ are a RAR marker with no header behind it: they do not parse
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let heads: Vec<&str> = stdout.lines().filter(|line| !line.is_empty() && !line.starts_with(' ')).collect();
    let zip_count = heads.iter().filter(|line| line.contains("   ZIP")).count();
    let rar_count = heads.iter().filter(|line| line.contains("   RAR ")).count();
    let sevenz_count = heads.iter().filter(|line| line.contains("   7z")).count();
    assert_eq!(zip_count + rar_count + sevenz_count, heads.len(), "every block starts with what its archive is");
    assert!(zip_count >= 8, "expected >=8 ZIP archives, found {zip_count}");
    assert!(rar_count >= 3, "expected >=3 RAR archives, found {rar_count}");
    assert!(sevenz_count >= 3, "expected >=3 7z archives, found {sevenz_count}");
}

// ---------------------------------------------------------------------------
// ZIP spec audit: fixture-level verification of bug fixes
// ---------------------------------------------------------------------------

// B0: Encrypted SFX ZIP emits hash (local_header_offset includes sfx_offset)
#[test]
fn zip_sfx_encrypted_emits_hash() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/zipcrypto_sfx.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("$zip$1$"), "B0: encrypted SFX must produce $zip$1$ hash");
}

// B0: SFX hash matches non-SFX hash AND matches zip2john + zip2hashcat data.
// Three-way verified: zip2john, zip2hashcat, and archivewolf all produce
// identical encrypted data for plain.txt (CRC=cefd04dc):
// e2cdf70d245020b6f1c0a9ac6b2bdbf377541080da2cf6f2800fd56089e0b667e2ca441282e2c459
#[test]
fn zip_sfx_hash_matches_non_sfx_and_reference() {
    let sfx_out = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/zipcrypto_sfx.zip"]).output().unwrap();
    let non_sfx_out = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/zipcrypto_stored.zip"]).output().unwrap();
    let sfx_stdout = String::from_utf8_lossy(&sfx_out.stdout);
    let non_sfx_stdout = String::from_utf8_lossy(&non_sfx_out.stdout);
    let sfx_hashes: Vec<&str> = sfx_stdout.lines().filter(|l| l.starts_with("$zip$")).collect();
    let non_sfx_hashes: Vec<&str> = non_sfx_stdout.lines().filter(|l| l.starts_with("$zip$")).collect();
    assert_eq!(sfx_hashes, non_sfx_hashes, "SFX and non-SFX must produce identical hashes");

    // Expected type=1 hash from zip2hashcat cross-verification:
    // cb=02, crc=cefd04dc, mt=0, cs=28, data=e2cdf70d...e2c459
    let line = non_sfx_hashes.iter().find(|h| h.contains("*cefd04dc*")).expect("must have a line for plain.txt");
    assert!(line.contains("*e2cdf70d245020b6f1c0a9ac/02/ce*") && line.contains("*0*cefd04dc*1c*1c*"), "fields must match zip2hashcat reference: header e2cdf70d..., cb=02, crc=cefd04dc: {line}");
    assert!(line.ends_with("e2ca441282e2c459$/zip$"), "data must end with e2ca441282e2c459 (matches zip2hashcat)");
}

// Triage: encrypted entry with corrupt local header still emits type=0 hash.
// We corrupt a MIDDLE entry's local header (not the first one, which the scanner
// needs to recognize the archive). The CD still says encrypted, so the type=0
// hash (check-byte from CD data) must still be emitted even though the local
// header for that entry can't be parsed.
#[test]
fn zip_encrypted_corrupt_local_header_still_hashes() {
    let zip_data = std::fs::read("tests/fixtures/zip-crypto/zipcrypto_stored.zip").unwrap();
    let mut corrupt = zip_data.clone();
    // Corrupt the SECOND local file header at offset 123 (found by signature scan).
    // Entry 1 at offset 0 stays valid so the scanner finds the archive.
    if corrupt.len() > 127 && corrupt[123..127] == *b"PK\x03\x04" {
        corrupt[123] = 0xFF;
        corrupt[124] = 0xFF;
        corrupt[125] = 0xFF;
        corrupt[126] = 0xFF;
    }
    let tmp = std::env::temp_dir().join("aw_corrupt_lfh2.zip");
    std::fs::write(&tmp, &corrupt).unwrap();
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", tmp.to_str().unwrap()]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // type=0 (check-byte) hash only needs CD data; the corrupt entry should
    // still contribute its check byte from the CD (it's triaged as Encrypted
    // since bit 0 is set in the CD flags and the LFH read failure returns
    // Encrypted for encrypted_flag=true).
    assert!(stdout.contains("$zip$1$*"), "corrupt LFH must not prevent type=0 hash emission");
    drop(std::fs::remove_file(&tmp));
}

// G6: Data descriptor ZipCrypto (bit 3 set) uses mod_time check byte.
// Fixture: zipcrypto_datadesc.zip has mod_time=0xA5B6, CRC=0x5B2CC364.
// mod_time >> 8 = 0xA5. CRC >> 24 = 0x5B. These differ.
// If the hash contains check byte "a5", we correctly used mod_time.
// If it contains "5b", we incorrectly used CRC.
#[test]
fn zip_data_descriptor_check_byte_is_modtime() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/zipcrypto_datadesc.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hash_line = stdout.lines().find(|l| l.starts_with("$zip$1$*1*")).expect("must emit a one-entry line");
    // $zip$1$*1*HEADER/CHECK[/ALTERNATIVE]*METHOD*CRC*...
    let inner = &hash_line["$zip$1$*".len()..hash_line.len() - "$/zip$".len()];
    let fields: Vec<&str> = inner.split('*').collect();
    let check: Vec<&str> = fields[1].split('/').collect();
    assert_eq!(check[1], "a5", "G6: check byte must be 0xa5 (mod_time >> 8) first");
    assert_eq!(check[2], "5b", "the CRC byte (0x5b) is named as the alternative");
    assert_eq!(fields[3], "5b2cc364", "CRC32 must be from CD");
}

// G6: Cross-verify data descriptor fixture against zip2hashcat reference output.
// zip2hashcat output: $pkzip$1*1*2*0*22*16*5b2cc364*0*28*0*22*a5b6*283587d8...3ddb*$/pkzip$
// Fields: CS=a5b6 (mod_time), CRC=5b2cc364, data=283587d8...3ddb
// Our line: header=283587d8fa820fda5da3113a, check a5, crc=5b2cc364, data=3a4b02b1...3ddb
#[test]
fn zip_data_descriptor_crosscheck_zip2hashcat() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/zipcrypto_datadesc.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().find(|l| l.starts_with("$zip$1$*")).expect("ZipCrypto line");
    // zip2hashcat data field (verbatim from running ref/zip2hashcat/zip2hashcat): the first
    // 12 bytes are the encryption header, the rest is the stream
    let reference_header = "283587d8fa820fda5da3113a";
    let reference_stream = "3a4b02b1909988ddfe2aac0cea11cb99af2400283ddb";
    assert!(line.contains(&format!("*{reference_header}/a5/5b*0*5b2cc364*")), "header, check byte (mod_time>>8) and crc must match reference: {line}");
    assert!(line.ends_with(&format!("*{reference_stream}$/zip$")), "stream must match zip2hashcat byte-for-byte");
}

// Verify zipcrypto_stored.zip (bit 3 clear) uses CRC check byte, not mod_time.
// The archive was written with the data descriptor bit set, so the file time comes first and
// the CRC byte is the alternative. Cross-verified: zip2hashcat CS=cefd for CRC=cefd04dc.
#[test]
fn zip_no_data_descriptor_check_byte_is_crc() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/zip-crypto/zipcrypto_stored.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let hash_line = stdout.lines().find(|l| l.starts_with("$zip$1$*3*")).expect("a stored entry brings the headers of the other two");
    let inner = &hash_line["$zip$1$*".len()..hash_line.len() - "$/zip$".len()];
    let fields: Vec<&str> = inner.split('*').collect();
    let crc = fields[5];
    let check: Vec<&str> = fields[1].split('/').collect();
    assert_eq!(check.last().copied(), Some(&crc[..2]), "the CRC check byte must be CRC >> 24 (high byte)");
    assert_eq!(check[1].len(), 2, "one byte: nothing but PKZIP 1.x wrote two");
}

// WinZip AES ct cap: verify ciphertext is capped at 64KB
#[test]
#[expect(clippy::cast_possible_truncation, reason = "test: synthetic ZIP field values are known-small")]
fn zip_winzip_ciphertext_cap() {
    // Build a large WinZip AES ZIP (>64KB payload)
    use std::io::Write as _;
    let filename = b"large.bin";
    let strength: u8 = 1;
    let salt_len = 4 * usize::from(strength) + 4; // 8
    let fake_salt = vec![0xAA; salt_len];
    let fake_pv = [0xBB; 2];
    let fake_ct = vec![0xCC; 70_000]; // 70KB > 64KB cap
    let fake_auth = [0xDD; 10];
    let compressed_size = (salt_len + 2 + fake_ct.len() + 10) as u32;

    let extra_9901: Vec<u8> = {
        let mut e = Vec::new();
        e.extend_from_slice(&0x9901_u16.to_le_bytes());
        e.extend_from_slice(&7_u16.to_le_bytes());
        e.extend_from_slice(&1_u16.to_le_bytes());
        e.extend_from_slice(&0x4541_u16.to_le_bytes());
        e.push(strength);
        e.extend_from_slice(&0_u16.to_le_bytes());
        e
    };

    let mut buf = Vec::new();
    // Local file header
    buf.extend_from_slice(b"PK\x03\x04");
    buf.extend_from_slice(&20_u16.to_le_bytes());
    buf.extend_from_slice(&1_u16.to_le_bytes()); // encrypted
    buf.extend_from_slice(&99_u16.to_le_bytes()); // AES
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u32.to_le_bytes());
    buf.extend_from_slice(&compressed_size.to_le_bytes());
    buf.extend_from_slice(&70000_u32.to_le_bytes());
    buf.extend_from_slice(&(filename.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(extra_9901.len() as u16).to_le_bytes());
    buf.extend_from_slice(filename);
    buf.extend_from_slice(&extra_9901);
    buf.extend_from_slice(&fake_salt);
    buf.extend_from_slice(&fake_pv);
    buf.extend_from_slice(&fake_ct);
    buf.extend_from_slice(&fake_auth);

    let cd_offset = buf.len() as u32;
    // Central directory
    buf.extend_from_slice(b"PK\x01\x02");
    buf.extend_from_slice(&20_u16.to_le_bytes());
    buf.extend_from_slice(&20_u16.to_le_bytes());
    buf.extend_from_slice(&1_u16.to_le_bytes());
    buf.extend_from_slice(&99_u16.to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u32.to_le_bytes());
    buf.extend_from_slice(&compressed_size.to_le_bytes());
    buf.extend_from_slice(&70000_u32.to_le_bytes());
    buf.extend_from_slice(&(filename.len() as u16).to_le_bytes());
    buf.extend_from_slice(&(extra_9901.len() as u16).to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u32.to_le_bytes());
    buf.extend_from_slice(&0_u32.to_le_bytes());
    buf.extend_from_slice(filename);
    buf.extend_from_slice(&extra_9901);
    let cd_size = buf.len() as u32 - cd_offset;
    // EOCD
    buf.extend_from_slice(b"PK\x05\x06");
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());
    buf.extend_from_slice(&1_u16.to_le_bytes());
    buf.extend_from_slice(&1_u16.to_le_bytes());
    buf.extend_from_slice(&cd_size.to_le_bytes());
    buf.extend_from_slice(&cd_offset.to_le_bytes());
    buf.extend_from_slice(&0_u16.to_le_bytes());

    let tmp = std::env::temp_dir().join("aw_large_aes.zip");
    let mut f = std::fs::File::create(&tmp).unwrap();
    f.write_all(&buf).unwrap();
    drop(f);

    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", tmp.to_str().unwrap()]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("$zip$2$"), "large AES entry must produce hash");
    // Find the hash and check ct field length
    let hash_line = stdout.lines().find(|l| l.starts_with("$zip$2$")).unwrap();
    let inner = &hash_line["$zip$2$*".len()..hash_line.len() - "$/zip$".len()];
    let fields: Vec<&str> = inner.split('*').collect();
    let ct_hex = fields[5]; // ct field
    let ct_bytes = ct_hex.len() / 2;
    assert!(ct_bytes <= 65536, "ct must be capped at 64KB (65536 bytes), got {ct_bytes}");
    assert!(ct_bytes > 0, "ct must not be empty");
    drop(std::fs::remove_file(&tmp));
}

// G5: Multi-disk archive warning fires and hash is still emitted
#[test]
fn zip_multidisk_warning_and_hash() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/unparseable/multidisk_stub.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("$zip$1$"), "G5: multi-disk archive must still emit hash");
    assert!(stderr.contains("multi-disk") || stderr.contains("spanned"), "G5: multi-disk warning must appear in stderr");
}

// The content of a tiny entry follows from its CRC-32, and nothing is reconstructed from it: the
// entry goes into the hash line like any other. crc_tiny.zip: one.txt (2B), two.txt (3B),
// four.txt (5B). All three are stored, so one line tests the headers of all of them.
#[test]
fn zip_tiny_entries_all_reach_the_hash_line() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/unparseable/crc_tiny.zip"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("CRC32") && !stderr.contains("RECOVERED"), "no content is recovered from a checksum: {stderr}");
    let line = stdout.lines().find(|l| l.starts_with("$zip$1$*")).expect("ZipCrypto line");
    assert!(line.starts_with("$zip$1$*3*"), "the line tests all three entries: {line}");
}
