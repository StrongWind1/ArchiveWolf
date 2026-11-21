//! The lines do not drift: the third of the three proofs that a line is right.
//!
//! `tests/golden/` holds the expected hash line, byte for byte, for one fixture of every line type
//! and case. `manifest.json` there says for each one why that fixture was picked and what backs
//! its line. These tests hold `archivewolf hash` to the lines, and the manifest to the list of
//! cases below.
//!
//! A line here changes only when its format does (section 8.7). It is then recorded again,
//! compared with the extractors again (`make test-extractors`) and cracked again
//! (`make test-hashcat`).

mod support;

use std::collections::BTreeSet;

use support::Recorded;

/// The modes a fixture gives a line for. Modes 46400 and 46410 read `$zip$4$`, which only the
/// tabled `attack zip-crypto` writes, so no fixture gives one.
const MODES_WITH_A_LINE: [u32; 10] = [46100, 46200, 46300, 46310, 46320, 46500, 46600, 46700, 46800, 46900];

/// One case of a line that has to be recorded.
struct Case {
    /// Its name in the manifest, and the name of the file that holds its line.
    id: &'static str,
    /// The hashcat mode that reads it.
    mode: u32,
    /// The line type, as `hash --json` names it.
    tag: &'static str,
    /// Whether the fields of a line are those of this case. The fields are the line split at
    /// `*`, with the end mark taken off: field 0 is the line type.
    shape: fn(&[&str]) -> bool,
}

/// Whether field `index` is there and is `text`.
fn is(fields: &[&str], index: usize, text: &str) -> bool {
    fields.get(index).is_some_and(|field| *field == text)
}

/// The length of field `index`, 0 when the line has no such field.
fn long(fields: &[&str], index: usize) -> usize {
    fields.get(index).map_or(0, |field| field.len())
}

/// Whether field `index` is there and starts with `text`.
fn starts(fields: &[&str], index: usize, text: &str) -> bool {
    fields.get(index).is_some_and(|field| field.starts_with(text))
}

/// The checks of a `$zip$1$` line, and the five fields behind them: method, CRC-32, unpacked
/// size, packed size, data. Nothing when the line does not hold as many checks as it says.
fn zip1<'line, 'field>(fields: &'line [&'field str]) -> Option<(&'line [&'field str], &'line [&'field str])> {
    let count: usize = fields.get(1)?.parse().ok()?;
    let end = count.checked_add(2)?;
    let (checks, rest) = (fields.get(2..end)?, fields.get(end..)?);
    (rest.len() == 5).then_some((checks, rest))
}

/// Every line type and case the fixtures give. Each has a line under `tests/golden/`.
///
/// Not here, because no fixture gives it: `$zip$4$`; a `$zip$1$` or `$zip$2$` line with the start
/// of a deflate stream over a megabyte; a `$rar$30$` line with the 32 bytes of a volume end; a
/// `$7z$` line without a CRC-32. A stored `$rar$30$` entry is left out for its size: 868,794
/// characters in each of the three fixtures that give one.
const CASES: &[Case] = &[
    Case { id: "zip-crypto-deflate", mode: 46100, tag: "$zip$1$", shape: |f| zip1(f).is_some_and(|(checks, rest)| checks.len() == 1 && is(rest, 0, "8") && long(rest, 4) > 0) },
    Case { id: "zip-crypto-stored-shared-checks", mode: 46100, tag: "$zip$1$", shape: |f| zip1(f).is_some_and(|(checks, rest)| (2..8).contains(&checks.len()) && checks.iter().all(|check| check.split('/').count() == 3) && is(rest, 0, "0") && long(rest, 4) > 0) },
    Case { id: "zip-crypto-check16", mode: 46100, tag: "$zip$1$", shape: |f| zip1(f).is_some_and(|(checks, _)| !checks.is_empty() && checks.iter().all(|check| check.split('/').nth(1).is_some_and(|value| value.len() == 4))) },
    Case { id: "zip-crypto-eight-checks", mode: 46100, tag: "$zip$1$", shape: |f| zip1(f).is_some_and(|(checks, _)| checks.len() == 8) },
    Case { id: "zip-crypto-signature", mode: 46100, tag: "$zip$1$", shape: |f| zip1(f).is_some_and(|(_, rest)| is(rest, 0, "12") && long(rest, 4) == 64) },
    Case { id: "zip-crypto-header-only", mode: 46100, tag: "$zip$1$", shape: |f| zip1(f).is_some_and(|(_, rest)| is(rest, 4, "")) },
    Case { id: "zip-winzip-128", mode: 46200, tag: "$zip$2$", shape: |f| f.len() == 8 && is(f, 1, "1") && long(f, 2) == 16 && long(f, 7) > 0 },
    Case { id: "zip-winzip-192", mode: 46200, tag: "$zip$2$", shape: |f| f.len() == 8 && is(f, 1, "2") && long(f, 2) == 24 && long(f, 7) > 0 },
    Case { id: "zip-winzip-256", mode: 46200, tag: "$zip$2$", shape: |f| f.len() == 8 && is(f, 1, "3") && long(f, 2) == 32 && long(f, 7) > 0 },
    // AE-1 does not show in a line: the shape is that of any entry with data
    Case { id: "zip-winzip-ae1", mode: 46200, tag: "$zip$2$", shape: |f| f.len() == 8 && long(f, 4) == 20 && long(f, 7) > 0 },
    Case { id: "zip-winzip-empty", mode: 46200, tag: "$zip$2$", shape: |f| f.len() == 8 && long(f, 4) == 20 && is(f, 6, "0") && is(f, 7, "") },
    Case { id: "zip-pkware-aes128-iv", mode: 46300, tag: "$zip$3$", shape: |f| f.len() == 7 && is(f, 1, "660e") && is(f, 2, "128") && long(f, 4) == 32 },
    Case { id: "zip-pkware-aes128-no-iv", mode: 46300, tag: "$zip$3$", shape: |f| f.len() == 7 && is(f, 1, "660e") && is(f, 2, "128") && long(f, 4) == 24 },
    Case { id: "zip-pkware-aes192-iv", mode: 46310, tag: "$zip$3$", shape: |f| f.len() == 7 && is(f, 1, "660f") && is(f, 2, "192") && long(f, 4) == 32 },
    Case { id: "zip-pkware-aes192-no-iv", mode: 46310, tag: "$zip$3$", shape: |f| f.len() == 7 && is(f, 1, "660f") && is(f, 2, "192") && long(f, 4) == 24 },
    Case { id: "zip-pkware-aes256-iv", mode: 46320, tag: "$zip$3$", shape: |f| f.len() == 7 && is(f, 1, "6610") && is(f, 2, "256") && long(f, 4) == 32 },
    Case { id: "zip-pkware-aes256-no-iv", mode: 46320, tag: "$zip$3$", shape: |f| f.len() == 7 && is(f, 1, "6610") && is(f, 2, "256") && long(f, 4) == 24 },
    // SecureZIP writes more validation data than the 16 bytes of the generator
    Case { id: "zip-pkware-securezip", mode: 46320, tag: "$zip$3$", shape: |f| f.len() == 7 && is(f, 1, "6610") && is(f, 2, "256") && long(f, 6) > 32 },
    Case { id: "rar-15-stored", mode: 46500, tag: "$rar$15$", shape: |f| f.len() == 6 && is(f, 4, "30") && long(f, 5) > 0 },
    Case { id: "rar-15-packed", mode: 46500, tag: "$rar$15$", shape: |f| f.len() == 6 && long(f, 4) == 2 && !is(f, 4, "30") && long(f, 5) > 0 },
    Case { id: "rar-20-stored", mode: 46600, tag: "$rar$20$", shape: |f| f.len() == 6 && is(f, 4, "30") && long(f, 5) > 0 },
    Case { id: "rar-20-packed", mode: 46600, tag: "$rar$20$", shape: |f| f.len() == 6 && long(f, 4) == 2 && !is(f, 4, "30") && long(f, 5) > 0 },
    Case { id: "rar-30-headers", mode: 46700, tag: "$rar$30$", shape: |f| f.len() == 8 && is(f, 1, "0") && is(f, 3, "c43d7b00") && is(f, 6, "0") && long(f, 7) == 32 },
    Case { id: "rar-30-data", mode: 46700, tag: "$rar$30$", shape: |f| f.len() == 8 && is(f, 1, "1") && long(f, 6) == 2 && long(f, 7) > 0 },
    // an entry and an encryption header give the same shape: which of the two it is shows in the archive only
    Case { id: "rar-50-data-check", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "0") && long(f, 5) == 16 && is(f, 11, "") },
    Case { id: "rar-50-headers-check", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "0") && long(f, 5) == 16 && is(f, 11, "") },
    Case { id: "rar-50-data-crc32", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "1") && is(f, 5, "") && is(f, 6, "0") && long(f, 7) == 8 && is(f, 10, "0") && long(f, 11) > 0 },
    Case { id: "rar-50-data-crc32-keyed", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "1") && is(f, 5, "") && is(f, 6, "1") && long(f, 7) == 8 && is(f, 10, "0") && long(f, 11) > 0 },
    Case { id: "rar-50-data-blake2sp", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "1") && is(f, 5, "") && is(f, 6, "2") && long(f, 7) == 64 && long(f, 11) > 0 },
    Case { id: "rar-50-data-blake2sp-keyed", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "1") && is(f, 5, "") && is(f, 6, "3") && long(f, 7) == 64 && long(f, 11) > 0 },
    Case { id: "rar-50-data-packed", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "1") && long(f, 10) > 0 && !is(f, 10, "0") && long(f, 11) > 0 },
    Case { id: "rar-50-headers-nocheck", mode: 46800, tag: "$rar$50$", shape: |f| f.len() == 12 && is(f, 1, "1") && is(f, 5, "") && is(f, 6, "4") && is(f, 7, "") && long(f, 11) > 0 },
    Case { id: "7z-aes-stored", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && is(f, 2, "") && long(f, 3) == 8 && is(f, 5, "") && is(f, 6, "1") && is(f, 10, "") },
    Case { id: "7z-aes-lzma2", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && is(f, 6, "1") && starts(f, 10, "21/") && !f.get(10).is_some_and(|chain| chain.contains(',')) },
    Case { id: "7z-aes-lzma-short-iv", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && long(f, 7) == 16 && starts(f, 10, "030101/") },
    Case { id: "7z-aes-filter", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && is(f, 6, "1") && f.get(10).is_some_and(|chain| chain.contains(',')) },
    Case { id: "7z-aes-bcj2", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 27 && is(f, 6, "4") && starts(f, 5, "0303011b/") },
    // a stored header and a stored folder give the same shape: which of the two it is shows in the archive only
    Case { id: "7z-aes-headers", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && long(f, 3) == 8 && is(f, 6, "1") && is(f, 10, "") },
    Case { id: "7z-aes-headers-packed", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && long(f, 3) == 8 && is(f, 6, "1") && starts(f, 10, "030101/") },
    Case { id: "7z-aes-headers-nocrc", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && is(f, 3, "header") },
    Case { id: "7z-aes-salt", mode: 46900, tag: "$7z$*", shape: |f| f.len() == 12 && long(f, 2) > 0 },
];

/// The fields of a line of type `kind`: split at `*`, the end mark taken off. Nothing when the
/// line does not start with its type or does not end with its mark.
fn fields_of<'line>(line: &'line str, kind: &str) -> Option<Vec<&'line str>> {
    let mark = [("$zip$", "$/zip$"), ("$rar$", "$/rar$"), ("$7z$", "$/7z$")].iter().find(|(start, _)| kind.starts_with(start))?.1;
    let fields: Vec<&str> = line.strip_suffix(mark)?.split('*').collect();
    // the type of a 7-Zip line is written with the `*` that follows it, which the split takes off
    (fields.first() == Some(&kind.trim_end_matches('*'))).then_some(fields)
}

/// The manifest, or the end of the test.
fn recorded() -> Vec<Recorded> {
    let recorded = support::recorded_lines();
    assert!(recorded.is_ok(), "{}", recorded.err().unwrap_or_default());
    recorded.unwrap_or_default()
}

#[test]
fn hash_writes_every_recorded_line_byte_for_byte() {
    let recorded = recorded();
    let mut drifted = Vec::new();
    for entry in &recorded {
        let expected = entry.line().unwrap_or_else(|fault| panic!("{fault}"));
        let mode = entry.mode().to_string();
        let written = support::archivewolf_hash(&["--mode", &mode], &entry.fixture()).unwrap_or_else(|fault| panic!("{fault}"));
        if written != format!("{expected}\n").into_bytes() {
            drifted.push(format!("  {} ({}, mode {mode}):\n{}", entry.text("case"), entry.fixture().display(), support::difference(("recorded", &expected), ("archivewolf", &String::from_utf8_lossy(&written)))));
        }
    }
    assert!(drifted.is_empty(), "{} of {} recorded lines are not what `archivewolf hash` writes:\n{}", drifted.len(), recorded.len(), drifted.join("\n"));
}

#[test]
fn hash_json_gives_every_recorded_line_its_path_mode_and_type() {
    for entry in &recorded() {
        let (case, fixture) = (entry.text("case"), entry.fixture());
        let expected = entry.line().unwrap_or_else(|fault| panic!("{fault}"));
        let written = support::archivewolf_hash(&["--json", "--mode", &entry.mode().to_string()], &fixture).unwrap_or_else(|fault| panic!("{fault}"));
        let text = String::from_utf8(written).unwrap_or_else(|fault| panic!("{case}: {fault}"));
        let objects: Vec<serde_json::Value> = text.lines().map(|line| serde_json::from_str(line).unwrap_or_else(|fault| panic!("{case}: {fault}: {}", support::trimmed(line)))).collect();
        assert_eq!(objects.len(), 1, "{case}: one object for the one line of mode {}", entry.mode());
        let object = &objects[0];
        assert_eq!(object["path"].as_str(), fixture.to_str(), "{case}");
        assert_eq!(object["mode"].as_u64(), Some(u64::from(entry.mode())), "{case}");
        assert_eq!(object["tag"].as_str(), Some(entry.text("tag")), "{case}");
        assert!(object["line"].as_str() == Some(expected.as_str()), "{case}: the line of the object is not the recorded one");
    }
}

#[test]
fn every_line_type_and_variant_is_recorded_with_the_shape_of_its_variant() {
    let recorded = recorded();
    let mut faults = Vec::new();
    for case in CASES {
        let Some(entry) = recorded.iter().find(|entry| entry.text("case") == case.id) else {
            faults.push(format!("{}: no line is recorded", case.id));
            continue;
        };
        if (entry.mode(), entry.text("tag")) != (case.mode, case.tag) {
            faults.push(format!("{}: recorded as {} of mode {}, not as {} of mode {}", case.id, entry.text("tag"), entry.mode(), case.tag, case.mode));
        }
        let line = entry.line().unwrap_or_else(|fault| panic!("{fault}"));
        match fields_of(&line, case.tag) {
            None => faults.push(format!("{}: the line does not start with {} and end with its mark: {}", case.id, case.tag, support::trimmed(&line))),
            Some(fields) if !(case.shape)(&fields) => faults.push(format!("{}: the line of {} is not of this case: {}", case.id, entry.text("fixture"), support::trimmed(&line))),
            Some(_) => {},
        }
    }

    // a recorded line that is on no list has no shape to hold it to
    let listed: BTreeSet<&str> = CASES.iter().map(|case| case.id).collect();
    assert_eq!(listed.len(), CASES.len(), "a case is listed twice");
    for entry in &recorded {
        if !listed.contains(entry.text("case")) {
            faults.push(format!("{}: recorded, and not in the list of cases of this test", entry.text("case")));
        }
    }
    assert!(faults.is_empty(), "{} faults:\n  {}", faults.len(), faults.join("\n  "));

    let modes: BTreeSet<u32> = recorded.iter().map(Recorded::mode).collect();
    assert_eq!(modes, BTreeSet::from(MODES_WITH_A_LINE), "the modes that have a recorded line");
}

#[test]
fn every_file_under_golden_belongs_to_an_entry_of_the_manifest() {
    let mut expected: BTreeSet<String> = recorded().iter().map(|entry| format!("{}.line", entry.text("case"))).collect();
    assert!(expected.insert("manifest.json".to_owned()));
    let found: BTreeSet<String> = std::fs::read_dir(support::GOLDEN).unwrap().map(|file| file.unwrap().file_name().to_string_lossy().into_owned()).collect();
    let (stray, missing): (Vec<&String>, Vec<&String>) = (found.difference(&expected).collect(), expected.difference(&found).collect());
    assert!(stray.is_empty() && missing.is_empty(), "under {}: no entry of the manifest for {stray:?}, no file for {missing:?}", support::GOLDEN);
}

#[test]
fn a_report_of_a_difference_names_the_field_and_stays_short() {
    let long = "ab".repeat(4000);
    let report = support::difference(("recorded", &format!("$zip$1$*1*{long}*8$/zip$\n")), ("archivewolf", &format!("$zip$1$*1*{long}ff*8$/zip$\nmore\n")));
    assert!(report.contains("lines: recorded 1, archivewolf 2"), "{report}");
    assert!(report.contains("line 1, field 3, from character 7985:"), "{report}");
    assert!(report.contains("line 2, the whole line:") && report.contains("nothing") && report.contains("more"), "{report}");
    assert!(report.len() < 600, "{} characters: {report}", report.len());

    assert_eq!(support::trimmed("short"), "short");
    let cut = support::trimmed(&long);
    assert!(cut.len() < 130 && cut.ends_with("(8000 characters)"), "{cut}");
}
