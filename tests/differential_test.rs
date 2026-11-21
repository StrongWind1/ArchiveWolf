#![expect(unused_crate_dependencies, reason = "integration test")]
//! Differential tests and spec compliance verification.
//!
//! Checks the 7z hash lines field by field against real 7z fixtures.

// ---------------------------------------------------------------------------
// 7z hash lines: $7z$*power*salt*crc32*crc_len*join*N*stream...$/7z$
// ---------------------------------------------------------------------------

#[expect(clippy::unwrap_used, reason = "test helper: the binary is built by cargo and always starts")]
fn sevenz_run(args: &[&str]) -> String {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(args).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr)
}

fn sevenz_lines(fixture: &str, all: bool) -> Vec<String> {
    let path = format!("tests/fixtures/7z-aes/{fixture}");
    let mut args = vec!["hash", path.as_str()];
    if all {
        args.push("--all");
    }
    sevenz_run(&args).lines().filter(|l| l.starts_with("$7z$")).map(str::to_owned).collect()
}

/// The fields of a line between its two signatures.
fn sevenz_fields(line: &str) -> Vec<&str> {
    line.strip_prefix("$7z$*").and_then(|rest| rest.strip_suffix("$/7z$")).unwrap_or("").split('*').collect()
}

#[test]
fn sevenz_stored_line_matches_golden() {
    assert_eq!(sevenz_lines("7z_stored.7z", false), ["$7z$*19**cefd04dc*1c**1*08fc89645bd2a05ed8088f2ca4395060*20*1c**e7e23b23a8cce6a5aaa56347c8871ccd247cde2bf4a84b878e720cbd776e61a4$/7z$"]);
}

#[test]
fn sevenz_lzma2_line_matches_golden() {
    assert_eq!(sevenz_lines("7z_lzma2.7z", false), ["$7z$*19**cefd04dc*1c**1*977dec2a487185d3f40101101bb5180d*20*20*21/00/1c*3d9be6b0dd5966e74c8315960b2f51bbf04de89967933b4149bfd429aedcfdd3$/7z$"]);
}

#[test]
fn sevenz_line_has_no_colon() {
    // hashcat counts the colons of a line to tell the lists of other tools apart
    for fixture in ["7z_lzma2.7z", "stacked.7z", "bcj2_enc.7z", "headers.7z", "salted.7z"] {
        for line in sevenz_lines(fixture, true) {
            assert!(!line.contains(':'), "{fixture}: {line}");
        }
    }
}

#[test]
fn sevenz_line_never_carries_an_empty_crc() {
    for fixture in ["7z_stored.7z", "7z_lzma2.7z", "solid.7z", "multi.7z", "headers.7z"] {
        let lines = sevenz_lines(fixture, false);
        let fields = sevenz_fields(lines.first().unwrap());
        assert_eq!(fields[2].len(), 8, "{fixture}: {fields:?}");
        assert_ne!(fields[2], "00000000", "{fixture}");
    }
}

#[test]
fn sevenz_solid_folder_is_tested_on_its_first_file() {
    // three files of 28, 46 and 70 bytes in one folder: the CRC-32 is that of the first
    let lines = sevenz_lines("solid.7z", false);
    let fields = sevenz_fields(lines.first().unwrap());
    assert_eq!(fields[3], "1c");
    assert!(fields[9].ends_with("/8d"), "the coder still says how much the folder unpacks to: {}", fields[9]);
}

#[test]
fn sevenz_every_folder_gets_a_line_with_all() {
    assert_eq!(sevenz_lines("7z_nonsolid_enc.7z", false).len(), 1);
    assert_eq!(sevenz_lines("7z_nonsolid_enc.7z", true).len(), 3);

    // five folders, each under a password of its own
    let all = sevenz_run(&["hash", "-q", "--all", "tests/fixtures/regress/f3-tools/special_passwords.7z"]);
    let lines: std::collections::HashSet<&str> = all.lines().collect();
    assert_eq!(lines.len(), 5, "{all}");
    assert!(lines.iter().all(|line| line.starts_with("$7z$*") && line.ends_with("$/7z$")), "{all}");
}

#[test]
fn sevenz_best_folder_is_the_one_with_the_smallest_first_file() {
    let best = sevenz_lines("7z_nonsolid_enc.7z", false);
    let all = sevenz_lines("7z_nonsolid_enc.7z", true);
    assert_eq!(best.first(), all.first());
    let sizes: Vec<u64> = all.iter().map(|line| u64::from_str_radix(sevenz_fields(line)[3], 16).unwrap()).collect();
    assert!(sizes.is_sorted(), "{sizes:?}");
}

#[test]
fn sevenz_coders_are_named_in_the_order_they_unpack() {
    // packed with BCJ and then LZMA2, so unpacked with LZMA2 and then BCJ
    let lines = sevenz_lines("bcj_lzma2.7z", false);
    assert_eq!(sevenz_fields(lines.first().unwrap())[9], "21/00/4a,03030103//4a");
}

#[test]
fn sevenz_bcj2_line_carries_four_streams() {
    let lines = sevenz_lines("bcj2_enc.7z", false);
    let fields = sevenz_fields(lines.first().unwrap());
    assert_eq!(fields.len(), 6 + 4 * 5);
    assert_eq!(fields[4], "0303011b//1c", "BCJ2 runs after the streams are joined");
    assert_eq!(fields[5], "4");
    // every stream has a vector of its own
    let ivs: std::collections::HashSet<&str> = (0..4).map(|i| fields[6 + 5 * i]).collect();
    assert_eq!(ivs.len(), 4);
}

#[test]
fn sevenz_encrypted_header_has_one_line() {
    let lines = sevenz_lines("headers.7z", false);
    assert_eq!(lines.len(), 1, "an archive with an encrypted header has one line");
    assert_eq!(sevenz_lines("headers.7z", true), lines, "and no other when every folder is asked for");
}

#[test]
fn sevenz_salt_goes_into_the_line() {
    let lines = sevenz_lines("salted.7z", false);
    let fields = sevenz_fields(lines.first().unwrap());
    assert_eq!(fields[0], "15");
    assert_eq!(fields[1], "deadbeef");
}

#[test]
fn sevenz_what_has_no_line_says_why() {
    // not encrypted at all: a 7zAES coder in front of nothing
    assert!(sevenz_lines("7z_empty_pw.7z", false).is_empty());

    // the key is the password itself, which hashcat does not test
    assert!(sevenz_lines("rawkey.7z", false).is_empty());
    let rawkey = sevenz_run(&["info", "tests/fixtures/7z-aes/rawkey.7z"]);
    assert!(rawkey.contains("  no line   folder 0 (test.txt): no-mode: its key is the password itself, with no key derivation"), "{rawkey}");
    assert!(sevenz_run(&["info", "tests/fixtures/7z-aes/7z_empty_pw.7z"]).contains("  no line   folder 0: no-data: it is empty"));

    // encrypted before it is packed, by a coder nothing knows
    for fixture in ["unknown_coder.7z", "tier5_padded.7z"] {
        assert!(sevenz_lines(fixture, false).is_empty(), "{fixture}");
        assert!(sevenz_run(&["info", &format!("tests/fixtures/7z-aes/{fixture}")]).contains("  no line   folder 0 (test.txt): not-expressible: one of its streams is not encrypted, or is encrypted before it is packed"), "{fixture}");
    }
}
