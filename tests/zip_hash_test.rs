//! ZIP hash lines, end to end.
//!
//! A ZIP entry carries a short check in front of its data: one byte for traditional encryption,
//! two for WinZip AES. A wrong password passes the first once in 256 tries, so a line is built to
//! test the data wherever hashcat can, and says so where it cannot. These tests hold that line,
//! for every way an entry can be encrypted and packed.
#![expect(unused_crate_dependencies, reason = "integration test")]
#![expect(clippy::unwrap_used, reason = "test helpers: panic on bad fixture data is intentional")]

use assert_cmd::Command;

/// Hash lines and stderr of `hash`, or of `hash --all`.
fn hashes(fixture: &str, all: bool) -> (Vec<String>, String) {
    let mut cmd = Command::cargo_bin("archivewolf").unwrap();
    let _ = cmd.arg("hash");
    if all {
        let _ = cmd.arg("--all");
    }
    let out = cmd.arg(format!("tests/fixtures/{fixture}")).output().unwrap();
    let lines = String::from_utf8_lossy(&out.stdout).lines().filter(|l| l.starts_with("$zip$")).map(str::to_owned).collect();
    (lines, String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn entries_with_different_passwords_each_get_a_line_when_all_are_asked_for() {
    for rel in ["zip-crypto/gen_own_zc_two_passwords.zip", "zip-crypto/gen_own_zc_two_passwords_deflate.zip", "zip-winzip/gen_own_aes256_two_passwords.zip"] {
        let (lines, _) = hashes(rel, false);
        assert_eq!(lines.len(), 1, "{rel}: one line for the best entry");

        let (lines, _) = hashes(rel, true);
        assert_eq!(lines.len(), 2, "{rel}: --all gives every entry a line of its own");
        assert_ne!(lines[0], lines[1], "{rel}");
    }
}

#[test]
fn a_stream_that_decodes_stands_alone_and_a_checksum_brings_the_other_headers() {
    // deflate: the line tests one entry
    let (lines, _) = hashes("zip-crypto/gen_own_zc_two_passwords_deflate.zip", false);
    assert!(lines.first().is_some_and(|l| l.starts_with("$zip$1$*1*")), "{lines:?}");

    // stored: the headers of the other entries come along, at most eight in all
    let (lines, _) = hashes("zip-crypto/gen_own_zc_eight_stored.zip", false);
    assert!(lines.first().is_some_and(|l| l.starts_with("$zip$1$*8*")), "{lines:?}");

    // and --all never mixes entries
    let (lines, _) = hashes("zip-crypto/gen_own_zc_eight_stored.zip", true);
    assert_eq!(lines.len(), 10);
    assert!(lines.iter().all(|l| l.starts_with("$zip$1$*1*")));
}

#[test]
fn only_pkzip_before_2_0_gets_a_two_byte_check() {
    let (lines, _) = hashes("zip-crypto/gen_own_zc_pkzip1_twobyte.zip", false);
    let line = lines.first().expect("line");
    let token = line.split('*').nth(2).expect("first check");
    assert_eq!(token.split('/').nth(1).map(str::len), Some(4), "made by PKZIP 1.0: two check bytes: {line}");

    // Info-ZIP and 7-Zip fill the second-last byte with anything
    for rel in ["zip-crypto/gen_infozip_deflate.zip", "zip-crypto/gen_7z_zipcrypto_deflate.zip"] {
        let (lines, _) = hashes(rel, false);
        let token = lines.first().and_then(|l| l.split('*').nth(2).map(str::to_owned)).expect("first check");
        assert_eq!(token.split('/').nth(1).map(str::len), Some(2), "{rel}: one check byte: {token}");
    }
}

#[test]
fn what_a_line_cannot_prove_is_said() {
    let (lines, notes) = hashes("zip-crypto/gen_7z_zipcrypto_deflate64.zip", false);
    assert_eq!(lines.len(), 1);
    assert!(lines.first().is_some_and(|l| l.ends_with("*$/zip$")), "no decoder for Deflate64: the line carries no data");
    assert!(notes.contains("gen_7z_zipcrypto_deflate64.zip: weak line: text40k.txt: hashcat has no decoder for compression method 9, so the line tests only the check bytes of 1 header: 8 bits."), "{notes}");

    let (lines, notes) = hashes("zip-crypto/gen_own_zc_stored.zip", false);
    assert_eq!(lines.len(), 1);
    assert!(notes.contains(": note: ") && notes.contains("40 bits") && !notes.contains("weak line"), "a single stored entry: {notes}");

    // a CRC-32 over one byte says no more than the byte: 8 bits of data and 8 of the header
    let (lines, notes) = hashes("zip-crypto/gen_own_zc_stored_1byte.zip", false);
    assert_eq!(lines.len(), 1);
    assert!(notes.contains(": weak line: ") && notes.contains("it holds 1 stored byte, and a CRC-32 over fewer than 4 bytes proves no more than the bytes themselves") && notes.contains(": 16 bits."), "a one-byte stored entry: {notes}");
    assert!(!notes.contains("40 bits"), "{notes}");

    let (_, notes) = hashes("zip-crypto/gen_own_zc_deflate.zip", false);
    assert!(!notes.contains("weak line") && !notes.contains(": note: "), "a deflate stream needs no remark: {notes}");

    // a remark tells the user to confirm a result, and names no command that tests a password
    for rel in ["zip-crypto/gen_7z_zipcrypto_deflate64.zip", "zip-crypto/gen_own_zc_stored.zip", "zip-crypto/gen_own_zc_stored_1byte.zip"] {
        let (_, notes) = hashes(rel, false);
        assert!(notes.contains("Confirm a password found with it by opening the archive.") && !notes.contains("archivewolf unlock"), "{rel}: {notes}");
        assert!(notes.lines().filter(|line| line.contains("Confirm")).all(|line| line.starts_with(&format!("tests/fixtures/{rel}: "))), "a remark names its archive: {notes}");
    }
}

#[test]
fn bzip2_and_xz_lines_carry_the_signature_only() {
    for rel in ["zip-crypto/gen_own_zc_bzip2.zip", "zip-crypto/gen_own_zc_xz.zip"] {
        let (lines, _) = hashes(rel, false);
        let data = lines.first().and_then(|l| l.strip_suffix("$/zip$")).and_then(|l| l.rsplit('*').next()).expect("data").to_owned();
        assert_eq!(data.len(), 64, "{rel}: 32 bytes of stream");
    }
}

#[test]
fn zip_pkware_lines_name_the_key_size_mode() {
    for (bits, mode) in [(128_u32, 46300_u64), (192, 46310), (256, 46320)] {
        let rel = format!("tests/fixtures/zip-pkware/gen_ses_aes{bits}_iv_deflate.zip");
        let line_start = format!("$zip$3$*{:04x}*{bits}*1*", 0x660E + (bits - 128) / 64);

        // the mode a line is read by is in the JSON of the line and in what `info` says of it
        let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", "--json", &rel]).output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let object: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
        assert_eq!(object["mode"].as_u64(), Some(mode), "{rel}: {stdout}");
        assert_eq!(object["tag"].as_str(), Some("$zip$3$"), "{rel}: {stdout}");
        assert!(object["line"].as_str().is_some_and(|line| line.starts_with(&line_start)), "{rel}: {stdout}");
        let info = Command::cargo_bin("archivewolf").unwrap().args(["info", &rel]).output().unwrap();
        assert!(String::from_utf8_lossy(&info.stdout).contains(&format!("$zip$3$, hashcat mode {mode}, exact, from ")), "{rel}");
        assert!(String::from_utf8_lossy(&info.stdout).contains(&format!("scheme    zip-pkware:data:aes{bits}:password  AES-{bits}, SHA-1, structure, CRC-32 (1 entry, 1 key group)")), "{rel}");
        assert_eq!((object["scheme"].as_str(), object["proves"].as_str(), object["entry"].as_u64()), (Some("zip-pkware"), Some("exact"), Some(0)), "{rel}: {stdout}");

        // and that mode, of the three, is the one that selects it
        for (other, expected) in [(46300, mode == 46300), (46310, mode == 46310), (46320, mode == 46320)] {
            let out = Command::cargo_bin("archivewolf").unwrap().args(["hash", "--mode", &other.to_string(), &rel]).output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(stdout.contains(&line_start), expected, "{rel} with --mode {other}: {stdout}");
            assert_eq!(stdout.is_empty(), !expected, "{rel} with --mode {other}: {stdout}");
        }
    }
}

#[test]
fn a_stored_vector_and_a_derived_one_both_reach_the_line() {
    for rel in ["zip-pkware/gen_ses_aes256_iv_stored.zip", "zip-pkware/gen_ses_aes256_noiv_stored.zip"] {
        let (lines, _) = hashes(rel, false);
        let iv = lines.first().and_then(|l| l.split('*').nth(4).map(str::to_owned)).expect("iv");
        assert_eq!(iv.len(), if rel.contains("noiv") { 24 } else { 32 }, "{rel}: {iv}");
    }
}

#[test]
fn an_empty_encrypted_entry_has_a_line_that_tests_its_header() {
    // the flag is set and a 12-byte header is there, but no data follows it: the entry is
    // encrypted, and the check byte of its header is all a password can be tested against
    for (rel, entries) in [("pseudo/gen_infozip_empty.zip", 1), ("pseudo/gen_own_zc_empty_only.zip", 2)] {
        let (lines, stderr) = hashes(rel, true);
        assert_eq!(lines.len(), entries, "{rel}: {lines:?}");
        assert!(lines.iter().all(|line| line.starts_with("$zip$1$*1*") && line.ends_with("*0*00000000*0*0*$/zip$")), "{rel}: {lines:?}");
        assert!(stderr.contains("weak line: ") && stderr.contains("it is empty, so the line tests only the check bytes of 1 header"), "{rel}: {stderr}");
    }
}
