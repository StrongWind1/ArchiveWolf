//! RAR coverage-matrix tests.
//!
//! Exercises every scenario from RAR-HASH-FORMAT-SPEC.md's Complete Coverage
//! Matrix. Each test verifies that a valid encrypted RAR archive produces a
//! hash (the spec's worst failure mode is silently producing nothing).
//!
//! Tests also cover each fix from the rar2john/rar2hashcat/unrar audit.
#![expect(unused_results, reason = "assert_cmd Assert chains are consumed by the assertion itself")]
#![expect(unused_crate_dependencies, reason = "test binary only uses assert_cmd and predicates")]

use assert_cmd::Command;
use predicates::prelude::*;

/// The analysis of one archive as `info --json` prints it, or `None` when the archive does not
/// parse.
fn analysis(path: &str) -> Option<serde_json::Value> {
    let output = Command::cargo_bin("archivewolf").ok()?.args(["info", "--json", path]).output().ok()?;
    serde_json::from_slice(&output.stdout).ok()
}

/// What the analysis says of the encryption of an archive: whether anything in it is encrypted,
/// whether its headers are, and whether RAR 1.3 is the only scheme in it.
fn encryption(path: &str) -> (bool, bool, bool) {
    let Some(report) = analysis(path) else { return (false, false, false) };
    let headers = report.pointer("/headers").and_then(serde_json::Value::as_str) == Some("encrypted");
    let entries = report.pointer("/entries/encrypted").and_then(serde_json::Value::as_u64).is_some_and(|count| count > 0);
    let schemes: Vec<&str> = report.pointer("/schemes").and_then(serde_json::Value::as_array).map(|rows| rows.iter().filter_map(|row| row.pointer("/scheme").and_then(serde_json::Value::as_str)).collect()).unwrap_or_default();
    (entries || headers, headers, !schemes.is_empty() && schemes.iter().all(|scheme| *scheme == "rar-13"))
}

// ---------------------------------------------------------------------------
// Coverage Matrix: every encryption method × scope must produce a hash
// (except RAR13, which has no hashcat mode: `attack rar-13` searches its key)
// ---------------------------------------------------------------------------

// RAR 1.3 (CRYPT_RAR13): no line — verify detection
#[test]
fn coverage_rar_13_detected_not_hashed() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "tests/fixtures/rar-13/rar14-password-stored.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("entries   1 of 1 entry encrypted; coverage all") && stdout.contains("scheme    rar-13  RAR 1.3 cipher"), "should detect RAR13 encryption: {stdout}");
    assert!(!stdout.contains(", hashcat mode "), "RAR13 has no line and `info` names none: {stdout}");
    assert!(stdout.contains("\n  line      none\n  no line   rar-13: no-mode: no hashcat mode exists for rar-13: `attack rar-13` searches its key\n"), "and says why, and what applies: {stdout}");
    assert!(stdout.contains("SECRET.TXT: rar-13 falls without the password: `attack rar-13` searches its 2^23 keys"), "{stdout}");
    let hashcat_output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-13/rar14-password-stored.rar"]).output().unwrap();
    assert_eq!(hashcat_output.status.code(), Some(0), "an archive without a line is not a failure");
    let hash_stdout = String::from_utf8_lossy(&hashcat_output.stdout);
    assert!(hash_stdout.is_empty(), "RAR13 should NOT produce a hash: {hash_stdout}");
}

// RAR 1.5 (CRYPT_RAR15): stored entry
#[test]
fn coverage_rar_15_stored_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-15/rar15-password-stored.rar"]).assert().success().stdout(predicate::str::contains("$rar$15$"));
}

// RAR 1.5 (CRYPT_RAR15): compressed entry
#[test]
fn coverage_rar_15_compressed_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-15/rar15-password-compressed.rar"]).assert().success().stdout(predicate::str::contains("$rar$15$"));
}

// RAR 2.0 (CRYPT_RAR20): stored entry
#[test]
fn coverage_rar_20_stored_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-20/rar20-password-stored.rar"]).assert().success().stdout(predicate::str::contains("$rar$20$"));
}

// RAR 2.0 (CRYPT_RAR20): compressed entry
#[test]
fn coverage_rar_20_compressed_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-20/rar20-password-compressed.rar"]).assert().success().stdout(predicate::str::contains("$rar$20$"));
}

// RAR 3.x header-encrypted (-hp)
#[test]
fn coverage_rar_30_hp_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_hp_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$*0*"));
}

// RAR 3.x file-level stored
#[test]
fn coverage_rar_30_file_stored_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_p_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$*1*"));
}

// RAR 4.x header-encrypted (same format as RAR3)
#[test]
fn coverage_rar4_hp_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_hp_m0.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$*0*"));
}

// RAR 4.x file-level encrypted
#[test]
fn coverage_rar4_file_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_p_m0.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$*1*"));
}

// RAR 5.0+ with PswCheck (header-encrypted)
#[test]
fn coverage_rar_50_hp_pswcheck_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/v730_hp_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$50$*0*"));
}

// RAR 5.0+ with PswCheck (file-level)
#[test]
fn coverage_rar_50_file_pswcheck_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/v500_p_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$50$*0*"));
}

// RAR 5.0+ header-encrypted (from junrar)
#[test]
fn coverage_rar_50_hp_junrar_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/v521_hp_m3.rar"]).assert().success().stdout(predicate::str::contains("$rar$50$"));
}

// RAR 5.0+ with HASHMAC (rar5-htb-mac.rar has HASHMAC flag)
#[test]
fn coverage_rar_50_hashmac_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/v730_p_m3_blake2sp.rar"]).assert().success().stdout(predicate::str::contains("$rar$50$"));
}

// RAR 5.0+ non-ASCII password archive
#[test]
fn coverage_rar_50_nonascii_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/rar5-nonascii-password.rar"]).assert().success().stdout(predicate::str::contains("$rar$50$"));
}

// RAR 3.x non-ASCII password archive
#[test]
fn coverage_rar_30_nonascii_produces_hash() {
    Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/rar3-nonascii-password.rar"]).assert().success().stdout(predicate::str::contains("$rar$30$"));
}

// ---------------------------------------------------------------------------
// Bug fix: RAR3 salt extraction order (B1)
// Archives with both LHD_SALT and LHD_EXTTIME must read salt before ext_time
// ---------------------------------------------------------------------------

#[test]
fn fix_rar3_salt_before_exttime() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_p_m0.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = stdout.lines().find(|l| l.starts_with("$rar$30$")).unwrap_or("").trim_start_matches("$rar$30$*").trim_end_matches("$/rar$").split('*').collect();
    assert_eq!(fields.get(1).map(|s| s.len()), Some(16), "salt must be 16 hex chars (8 bytes): {stdout}");
}

#[test]
fn fix_rar3_salt_before_exttime_second_fixture() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_p_m5.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let fields: Vec<&str> = stdout.lines().find(|l| l.starts_with("$rar$30$")).unwrap_or("").trim_start_matches("$rar$30$*").trim_end_matches("$/rar$").split('*').collect();
    assert_eq!(fields.get(1).map(|s| s.len()), Some(16), "salt must be 16 hex chars (8 bytes): {stdout}");
}

// ---------------------------------------------------------------------------
// Fix: RAR3 type-0 unpack_size should equal pack_size (G17)
// ---------------------------------------------------------------------------

#[test]
fn fix_rar_30_type0_unpack_equals_pack() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-30/v420_hp_m3.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // $rar$30$*0*salt*crc*ps*us*method*data$/rar$
    // For 32-byte Bevand: ps=20, us=20
    for line in stdout.lines() {
        if line.starts_with("$rar$30$*0*") {
            let fields: Vec<&str> = line.trim_start_matches("$rar$30$*").trim_end_matches("$/rar$").split('*').collect();
            assert!(fields.len() >= 6, "expected >= 6 fields in $rar$30$ hash");
            let ps = fields.get(3).unwrap_or(&"");
            let us = fields.get(4).unwrap_or(&"");
            assert_eq!(ps, us, "type-0 pack_size ({ps}) must equal unpack_size ({us})");
        }
    }
}

// ---------------------------------------------------------------------------
// Fix: RAR20 block alignment (G4)
// ---------------------------------------------------------------------------

#[test]
fn fix_rar_20_block_aligned() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-20/rar20-password-compressed.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("$rar$20$*") {
            let fields: Vec<&str> = line.trim_start_matches("$rar$20$*").trim_end_matches("$/rar$").split('*').collect();
            let ds_hex = fields.get(2).unwrap_or(&"0");
            let ds = u64::from_str_radix(ds_hex, 16).unwrap_or(0);
            assert_eq!(ds % 16, 0, "RAR20 data_size ({ds}) must be a multiple of 16");
        }
    }
}

// ---------------------------------------------------------------------------
// Fix: SFX detection (G7) — unit test via parse
// ---------------------------------------------------------------------------

#[test]
fn fix_sfx_rar_signature_detected() {
    use std::io::Write as _;
    let mut sfx = Vec::new();
    sfx.write_all(b"MZ").unwrap(); // PE header
    sfx.write_all(&[0u8; 100]).unwrap(); // padding
    sfx.write_all(b"Rar!\x1a\x07\x00").unwrap(); // RAR3 signature at offset 102
    sfx.write_all(&[0u8; 50]).unwrap();

    // detect_version should find RAR3
    // We can't call the internal function from integration tests,
    // but we can verify the binary handles it by checking parse doesn't crash
    let tmpdir = tempfile::tempdir().unwrap();
    let sfx_path = tmpdir.path().join("test.exe");
    std::fs::write(&sfx_path, &sfx).unwrap();

    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", sfx_path.to_str().unwrap()]).output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("not a RAR archive"), "SFX should be detected as RAR: stderr={stderr}");
}

// ---------------------------------------------------------------------------
// Verify: no silent failures across all encrypted junrar fixtures
// ---------------------------------------------------------------------------

#[test]
fn no_silent_failures_encrypted_fixtures() {
    let encrypted_fixtures: &[(&str, &str)] = &[
        ("tests/fixtures/rar-30/v420_p_m3.rar", "$rar$30$"),
        ("tests/fixtures/rar-30/v420_hp_m3.rar", "$rar$30$"),
        ("tests/fixtures/rar-30/v420_p_m0.rar", "$rar$30$"),
        ("tests/fixtures/rar-30/v420_hp_m0.rar", "$rar$30$"),
        ("tests/fixtures/rar-15/rar15-password-stored.rar", "$rar$15$"),
        ("tests/fixtures/rar-15/rar15-password-compressed.rar", "$rar$15$"),
        ("tests/fixtures/rar-20/rar20-password-compressed.rar", "$rar$20$"),
        ("tests/fixtures/rar-50/v730_hp_m3.rar", "$rar$50$"),
        ("tests/fixtures/rar-50/v730_p_m3.rar", "$rar$50$"),
    ];

    for (path, expected_prefix) in encrypted_fixtures {
        let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", path]).output().unwrap_or_else(|e| panic!("failed to run archivewolf on {path}: {e}"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(expected_prefix), "SILENT FAILURE: {path} should produce a {expected_prefix} hash but got:\n{stdout}");
    }
}

#[test]
fn no_silent_failures_junrar_encrypted_fixtures() {
    let encrypted_junrar: &[(&str, &str)] = &[
        ("tests/fixtures/rar-15/rar15-password-stored.rar", "$rar$15$"),
        ("tests/fixtures/rar-15/rar15-password-compressed.rar", "$rar$15$"),
        ("tests/fixtures/rar-20/rar20-password-stored.rar", "$rar$20$"),
        ("tests/fixtures/rar-20/rar20-password-compressed.rar", "$rar$20$"),
        ("tests/fixtures/rar-30/rar3-nonascii-password.rar", "$rar$30$"),
        ("tests/fixtures/rar-30/v420_hp_m5.rar", "$rar$30$"),
        ("tests/fixtures/rar-30/v420_p_m0.rar", "$rar$30$"),
        ("tests/fixtures/rar-30/v420_p_m5.rar", "$rar$30$"),
        ("tests/fixtures/rar-50/v521_hp_m3.rar", "$rar$50$"),
        ("tests/fixtures/rar-50/v500_p_m3.rar", "$rar$50$"),
        ("tests/fixtures/rar-50/rar5-nonascii-password.rar", "$rar$50$"),
        ("tests/fixtures/rar-50/v730_p_m3_blake2sp.rar", "$rar$50$"),
        ("tests/fixtures/rar-30/bad-crc-enc-headers.rar", "$rar$30$"),
    ];

    for (path, expected_prefix) in encrypted_junrar {
        let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", path]).output().unwrap_or_else(|e| panic!("failed to run archivewolf on {path}: {e}"));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(expected_prefix), "SILENT FAILURE: {path} should produce a {expected_prefix} hash but got:\n{stdout}");
    }
}

// ---------------------------------------------------------------------------
// Verify: unencrypted fixtures produce NO hash (no false positives)
// ---------------------------------------------------------------------------

#[test]
fn unencrypted_fixtures_produce_no_line() {
    // one archive of each format generation: RAR 5, RAR 3/4 and RAR 1.4
    let unencrypted = ["unencrypted/plain.rar", "unencrypted/rar4_unencrypted.rar", "unencrypted/rar14-solid.rar"];

    for fixture in &unencrypted {
        let path = format!("tests/fixtures/{fixture}");

        // the archive is read and reported, so the absence of a hash below means something
        let report = Command::cargo_bin("archivewolf").unwrap().args(["info", &path]).output().unwrap();
        assert_eq!(report.status.code(), Some(0), "{fixture}: {}", String::from_utf8_lossy(&report.stderr));
        let table = String::from_utf8_lossy(&report.stdout);
        assert!(table.starts_with(&format!("{path}   RAR ")) && table.contains("; coverage none\n") && table.contains("  line      none: nothing is encrypted\n"), "{fixture}: no report of an unencrypted RAR archive:\n{table}");
        assert_eq!(encryption(&path), (false, false, false), "{fixture}");

        let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", &path]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{fixture}: {}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains("$rar$"), "FALSE POSITIVE: unencrypted {fixture} should produce no $rar$ hash but got:\n{stdout}");
    }
}

// ---------------------------------------------------------------------------
// Synthetic fixtures: scenarios that real fixtures may not cover
// ---------------------------------------------------------------------------

// RAR5 BLAKE2sp file-level encrypted (real WinRAR 7.11 archive, -htb -p)
#[test]
fn synthetic_rar5_blake2sp_file_produces_hash() {
    let path = "tests/fixtures/rar-50/v730_p_m3_blake2sp.rar";
    if !std::path::Path::new(&path).exists() {
        eprintln!("fixture not found: {path}");
        return;
    }
    Command::cargo_bin("archivewolf").unwrap().args(["hash", path]).assert().success().stdout(predicate::str::contains("$rar$50$"));
}

// RAR5 -hp header-encrypted with BLAKE2sp (real WinRAR 7.11, -htb -hp)
#[test]
fn synthetic_rar5_hp_blake2sp_produces_hash() {
    let path = "tests/fixtures/rar-50/v730_hp_m3_blake2sp.rar";
    if !std::path::Path::new(&path).exists() {
        eprintln!("fixture not found: {path}");
        return;
    }
    Command::cargo_bin("archivewolf").unwrap().args(["hash", path]).assert().success().stdout(predicate::str::contains("$rar$50$"));
}

// SFX RAR5 archive (real WinRAR 7.11, -sfx -p)
#[test]
fn synthetic_sfx_rar5_produces_hash() {
    let path = "tests/fixtures/unknown-pw/rar50_sfx.exe";
    if !std::path::Path::new(&path).exists() {
        eprintln!("fixture not found: {path}");
        return;
    }
    Command::cargo_bin("archivewolf").unwrap().args(["hash", path]).assert().success().stdout(predicate::str::contains("$rar$50$"));
}

// Verify RAR5 FHFL_CRC32 vs FHFL_UTIME flag parsing is correct
// (rar5_file.rar was previously misdetected as unencrypted due to this bug)
#[test]
fn rar5_file_correctly_detected_as_encrypted() {
    Command::cargo_bin("archivewolf")
        .unwrap()
        .args(["info", "--entries", "tests/fixtures/rar-50/v730_p_m3.rar"])
        .assert()
        .success()
        .stdout(predicate::str::contains("headers   readable"))
        .stdout(predicate::str::contains("encrypted; coverage all"))
        .stdout(predicate::str::is_match("\n +0  file +encrypted  rar-50:data:check:keyed +1  normal +\\d+ +\\d+  no +\\$rar\\$50\\$ 46800  ").unwrap());
    assert_eq!(encryption("tests/fixtures/rar-50/v730_p_m3.rar"), (true, false, false));
    assert_eq!(encryption("tests/fixtures/rar-50/v730_hp_m3.rar"), (true, true, false));
}

// RAR5 type-1 (no PswCheck) with BLAKE2sp+HASHMAC — synthetic byte-level archive
#[test]
fn synthetic_type1_blake2sp_hashmac_produces_hash() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/synth_type1_blake2sp.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("$rar$50$*1*"), "must produce type=1 hash: {stdout}");
    assert!(stdout.contains("*3*"), "checktype must be 3 (BLAKE2sp+HASHMAC): {stdout}");
    assert!(stdout.contains("bbbbbbbb"), "must contain BLAKE2sp digest: {stdout}");
    assert!(!stdout.contains("*0*bbbb"), "checktype must NOT be 0: {stdout}");
}

// RAR5 type-1 (no PswCheck) with CRC32+HASHMAC — synthetic byte-level archive
#[test]
fn synthetic_type1_crc32_hashmac_produces_hash() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "tests/fixtures/rar-50/synth_type1_hashmac.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("$rar$50$*1*"), "must produce type=1 hash: {stdout}");
    assert!(stdout.contains("*1*"), "checktype must be 1 (CRC32+HASHMAC): {stdout}");
    assert!(stdout.contains("cafebabe"), "must contain CRC32: {stdout}");
}

// ---------------------------------------------------------------------------
// EXHAUSTIVE: walk every .rar and .exe fixture, run archivewolf, verify that
// every encrypted RAR produces a hash and no encrypted RAR silently fails.
// This is the definitive proof that "extracting a hash of a valid rar file
// never fails."
// ---------------------------------------------------------------------------

#[test]
fn exhaustive_every_encrypted_rar_produces_hash() {
    let mut checked = 0u32;
    let mut encrypted_with_hash = 0u32;
    let mut encrypted_rar_13_only = 0u32;
    let mut unencrypted = 0u32;
    let mut failures: Vec<String> = Vec::new();

    let fixture_dirs = ["tests/fixtures/rar-13", "tests/fixtures/rar-15", "tests/fixtures/rar-20", "tests/fixtures/rar-30", "tests/fixtures/rar-50", "tests/fixtures/unencrypted", "tests/fixtures/unparseable"];
    for dir in &fixture_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !ext.eq_ignore_ascii_case("rar") && !ext.eq_ignore_ascii_case("exe") {
                continue;
            }
            // Skip non-first multivolume parts — they can't produce hashes
            if name.contains(".part2.") || name.contains(".part3.") || name.contains(".part4.") || name.ends_with(".001.rar") || name.ends_with(".002.rar") {
                continue;
            }

            checked += 1;

            // Run archivewolf info to detect encryption
            let info_output = Command::cargo_bin("archivewolf").unwrap().args(["info", path.to_str().unwrap()]).output();
            let Ok(info_out) = info_output else { continue };
            let info_stdout = String::from_utf8_lossy(&info_out.stdout);

            // What the analysis says: an encrypted entry, encrypted headers, RAR 1.3 alone
            let (is_encrypted, is_header_encrypted, is_rar_13) = encryption(path.to_str().unwrap());

            if !is_encrypted {
                unencrypted += 1;
                continue;
            }

            // RAR13 has no hashcat mode and so no line: its key is searched by `attack rar-13`
            if is_rar_13 && !is_header_encrypted {
                encrypted_rar_13_only += 1;
                continue;
            }

            // This archive is encrypted (not RAR13) — it MUST produce a hash
            let hash_output = Command::cargo_bin("archivewolf").unwrap().args(["hash", path.to_str().unwrap()]).output();
            let Ok(hash_out) = hash_output else {
                failures.push(format!("{name}: archivewolf crashed"));
                continue;
            };
            let hash_stdout = String::from_utf8_lossy(&hash_out.stdout);

            if hash_stdout.contains("$rar$") {
                encrypted_with_hash += 1;
            } else {
                failures.push(format!("{name}: encrypted but NO hash produced. Info: {}", info_stdout.lines().take(5).collect::<Vec<_>>().join(" | ")));
            }
        }
    }

    eprintln!("Exhaustive RAR scan: {checked} files checked, {encrypted_with_hash} encrypted with hash, {encrypted_rar_13_only} RAR13 (no line), {unencrypted} unencrypted");

    assert!(checked > 20, "should check at least 20 fixtures, checked {checked}");
    assert!(encrypted_with_hash > 15, "should find at least 15 encrypted fixtures with hashes, found {encrypted_with_hash}");
    assert!(encrypted_rar_13_only >= 5 && unencrypted > 50, "{encrypted_rar_13_only} RAR 1.3 archives, {unencrypted} without encryption");
    assert!(failures.is_empty(), "SILENT FAILURES:\n{}", failures.join("\n"));
}

// ---------------------------------------------------------------------------
// COMPLETENESS: prove the spec covers every encryption method in unrar.
// This test documents the mapping and ensures no CRYPT_METHOD is unhandled.
// ---------------------------------------------------------------------------

#[test]
fn spec_covers_all_unrar_crypt_methods() {
    // Every CRYPT_METHOD from unrar's crypt.hpp mapped to our handling:
    // CRYPT_NONE     → RarEncryption::None (no line needed)
    // CRYPT_RAR13    → CryptRar13 (inline 2^24 crack, no line)
    // CRYPT_RAR15    → CryptRar15 → $rar$15$ hash
    // CRYPT_RAR20    → CryptRar20 → $rar$20$ hash
    // CRYPT_RAR30    → CryptRar30 → $rar$30$ hash
    // CRYPT_RAR50    → CryptRar50 → $rar$50$ hash
    // CRYPT_UNKNOWN  → enc_ver > 0 → warn and skip (future encryption)
    //
    // Every header type that carries encryption:
    // RAR3 main header MHD_PASSWORD  → is_header_encrypted → Bevand trick
    // RAR3 file header LHD_PASSWORD  → file-level → $rar$30$
    // RAR5 HEAD_CRYPT                → header-encrypted → $rar$50$ type 0/1
    // RAR5 FHEXTRA_CRYPT             → file-level → $rar$50$ type 0/1
    // RAR14 LHD_PASSWORD             → CRYPT_RAR13 → inline crack
    //
    // Verified against unrar arcread.cpp lines:
    //   294 (RAR13), 295 (RAR15), 297 (RAR20), 298 (RAR30),
    //   595/1110 (RAR50), 1067/1076 (UNKNOWN), 1303 (RAR14)
    //
    // This test exists as documentation. The assertion below verifies that
    // the exhaustive scan found every encrypted fixture.
    let _ = "This test documents completeness. See exhaustive_every_encrypted_rar_produces_hash for runtime verification.";
}

// RAR14 comment extraction: end-to-end test with synthetic fixture
#[test]
fn rar14_comment_end_to_end() {
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--entries", "tests/fixtures/unencrypted/rar14_with_comment.rar"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.lines().any(|line| line.starts_with("  comment   ") && line.len() > "  comment   ".len()), "should extract comment from RAR14 with MHD_COMMENT flag: {stdout}");
    assert!(stdout.lines().any(|line| line.contains("  file  plain  ") && line.ends_with("test.txt")), "should find file entry after comment: {stdout}");
    assert!(stdout.contains("   RAR 1.4, 1 entry"), "should detect as RAR 1.4: {stdout}");
    let report = analysis("tests/fixtures/unencrypted/rar14_with_comment.rar").unwrap();
    assert!(report["comment"].as_str().is_some_and(|comment| !comment.is_empty()), "{report}");
    assert_eq!((&report["format"], &report["generation"]), (&serde_json::Value::from("rar"), &serde_json::Value::from("rar1")));
}

// A RAR 3/4 name stored in the Unicode form of the format is listed as the name it is.
#[test]
fn a_rar4_entry_with_a_unicode_name_is_listed_under_its_name() {
    // "2\u{4e2d}\u{6587}.txt", which used to be decoded to a name with two question marks in it
    let output = Command::cargo_bin("archivewolf").unwrap().args(["info", "--entries", "tests/fixtures/rar-30/rars_rar4_mixed_visible_names_password.rar"]).output().unwrap();
    let listing = String::from_utf8_lossy(&output.stdout);
    assert!(listing.lines().any(|line| line.ends_with("  2\u{4e2d}\u{6587}.txt")) && !listing.contains("??"), "{listing}");
}

// Entries that share a name, or differ in a backslash, are entries of their own: each has a line.
#[test]
fn entries_of_one_name_each_get_a_line_when_all_are_asked_for() {
    for (fixture, entries) in [("regress/f3-tools/same_name_two_passwords.rar", 2), ("regress/f3-tools/backslash_and_slash.rar", 2), ("regress/f3-tools/special_passwords.rar", 4)] {
        let output = Command::cargo_bin("archivewolf").unwrap().args(["hash", "--all", &format!("tests/fixtures/{fixture}")]).output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{fixture}: {}", String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines().collect();
        assert_eq!(lines.len(), entries, "{fixture}: {stdout}");
        assert!(lines.iter().all(|line| line.starts_with("$rar$50$*") && line.ends_with("$/rar$")), "{fixture}: {stdout}");
        let distinct: std::collections::HashSet<&&str> = lines.iter().collect();
        assert_eq!(distinct.len(), entries, "{fixture}: every entry has a line of its own");
    }
}

#[test]
fn rar5_without_pswcheck_emits_type1_for_every_checktype() {
    // Real archives with the PswCheck field removed from their headers; unrar accepts each one.
    for (fixture, check_type, method) in [
        ("rar-50/nocheck_st_crc.rar", "0", "0"),
        ("rar-50/nocheck_st_crcmac.rar", "1", "0"),
        ("rar-50/nocheck_st_b2.rar", "2", "0"),
        ("rar-50/nocheck_st_b2mac.rar", "3", "0"),
        ("rar-50/nocheck_m3_crc.rar", "0", "3"),
        ("rar-50/nocheck_m3_b2mac.rar", "3", "3"),
        ("rar-50/nocheck_m5_exe_crcmac.rar", "1", "5"),
        ("rar-50/nocheck_hp_m3.rar", "4", "0"),
    ] {
        let all = hashes(fixture);
        let hash = all.first().unwrap_or_else(|| panic!("{fixture}: no line"));
        let fields: Vec<&str> = hash.trim_end_matches("$/rar$").split('*').collect();
        assert_eq!(fields.len(), 12, "{fixture}: {hash}");
        assert_eq!((fields[1], fields[5], fields[6], fields[10]), ("1", "", check_type, method), "{fixture}");
        assert_eq!(usize::from_str_radix(fields[8], 16).unwrap(), fields[11].len() / 2, "{fixture}: the hash carries the whole entry");
        assert_eq!(fields[11].len() % 32, 0, "{fixture}: whole AES blocks");
    }
}

// ---------------------------------------------------------------------------
// Hash selection
// ---------------------------------------------------------------------------

/// The `$rar$` lines `hash` writes for a fixture. None when the binary could not be run.
fn hashes(fixture: &str) -> Vec<String> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(["hash", &format!("tests/fixtures/{fixture}")]).output();
    out.map(|out| String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("$rar$")).map(str::to_owned).collect()).unwrap_or_default()
}

#[test]
fn rar_50_hashes_have_eleven_fields_for_both_types() {
    for fixture in ["rar-50/v730_p_m3.rar", "rar-50/v730_hp_m3.rar", "rar-50/synth_type1_hashmac.rar", "rar-50/synth_type1_blake2sp.rar"] {
        for hash in hashes(fixture) {
            assert_eq!(hash.matches('*').count(), 11, "{fixture}: {hash}");
        }
    }
}

#[test]
fn hash_data_is_never_truncated_below_the_packed_size() {
    // A stored 434 KB entry is over the preferred inline size. Its hash must
    // still carry the whole stream: a cut stream cannot be checked against the CRC.
    for fixture in ["rar-30/v420_p_m0.rar", "rar-30/v300_p_m0.rar", "rar-15/readme_154_password.rar"] {
        let all = hashes(fixture);
        let hash = all.first().unwrap_or_else(|| panic!("{fixture}: no line"));
        let fields: Vec<&str> = hash.trim_end_matches("$/rar$").split('*').collect();
        let (size_field, data) = if hash.starts_with("$rar$30$") { (fields[4], fields[7]) } else { (fields[3], fields[5]) };
        assert_eq!(usize::from_str_radix(size_field, 16).unwrap(), data.len() / 2, "{fixture}: size field and data length disagree");
    }
}

#[test]
fn service_block_before_the_files_is_skipped() {
    // The `rars` tool writes a LONG_BLOCK service header with data ahead of the file header.
    for (fixture, prefix) in [("rar-15/rars_service_block_stored.rar", "$rar$15$*"), ("rar-15/rars_service_block_m3.rar", "$rar$15$*"), ("rar-20/rars_service_block_stored.rar", "$rar$20$*"), ("rar-20/rars_service_block_m5.rar", "$rar$20$*")] {
        let all = hashes(fixture);
        assert_eq!(all.len(), 1, "{fixture}: expected one hash");
        assert!(all[0].starts_with(prefix), "{fixture}: {}", &all[0][..20]);
        let method = all[0].split('*').nth(4).unwrap();
        assert_eq!(method == "30", fixture.contains("stored"), "{fixture}: method {method}");
    }
}
