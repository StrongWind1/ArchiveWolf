//! Every variant 7-Zip defines, row by row of its registry, through the binary: what
//! `info --json` reports and what `hash` writes for each way a 7-Zip archive can be encrypted,
//! and for the archives whose header cannot be read.
//!
//! A row that 7-Zip or py7zr writes is shown on a fixture. A row no free tool writes is shown on
//! an archive built here (`src/formats/sevenz/craft.rs`). The names in the JSON objects are the
//! interface of the tool: they are compared as they are written.

#[path = "../src/formats/sevenz/craft.rs"]
mod craft;

// A test crate is linked against every dependency of the package, and the lint
// `unused_crate_dependencies` wants each of them named.
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
use sha2 as _;
use tracing as _;
use tracing_subscriber as _;
use walkdir as _;

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::process::Command;

    use super::craft;

    const FIXTURES: &str = "tests/fixtures";

    /// What a run of the binary wrote, and how it ended.
    struct Run {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    fn run(args: &[&str], archive: &Path) -> Run {
        let output = Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(args).arg(archive).env("PATH", "").output().unwrap();
        Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned() }
    }

    /// The analysis of an archive file, which has to be read without a failure.
    fn info(archive: &Path) -> Value {
        let run = run(&["info", "--json"], archive);
        assert_eq!(run.code, Some(0), "{}: {}", archive.display(), run.stderr);
        serde_json::from_str(&run.stdout).unwrap()
    }

    fn fixture(rel: &str) -> Value {
        info(&Path::new(FIXTURES).join(rel))
    }

    /// Write an archive to a file of its own and hand it to `with`.
    fn with_archive<T>(bytes: &[u8], with: impl FnOnce(&Path) -> T) -> T {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crafted.7z");
        std::fs::write(&path, bytes).unwrap();
        with(&path)
    }

    /// The analysis of an archive of these folders, and what `hash --all` makes of it.
    fn crafted(folders: &[craft::Folder]) -> (Value, Run) {
        with_archive(&craft::archive_of(folders), |path| (info(path), run(&["hash", "--all"], path)))
    }

    /// A folder of one file of 100 bytes with a CRC-32: these coders, the last of which reads the
    /// packed stream of 32 bytes.
    fn folder(coders: &[(&[u8], &[u8])]) -> craft::Folder {
        let mut sizes = vec![100; coders.len()];
        if let Some(last) = sizes.last_mut() {
            *last = 32;
        }
        craft::Folder::new(craft::chain(coders), &sizes, 32, Some(0xC0FF_EE00))
    }

    fn key(power: u8) -> Vec<u8> {
        craft::aes_props(power, &[], &[9; 16])
    }

    fn codes(analysis: &Value) -> Vec<&str> {
        analysis["findings"].as_array().unwrap().iter().map(|finding| finding["code"].as_str().unwrap()).collect()
    }

    /// Row 1: AES-256 with a key derived by SHA-256, in a folder. The whole object, name for name.
    #[test]
    fn row_1_a_folder_under_7z_aes_is_reported_in_full_and_gets_a_line() {
        let rounds = 1 << 19;
        let scheme = json!({ "scheme": "7z-aes", "variant": "7z-aes:data", "cipher": "aes", "key_bits": 256, "kdf": { "name": "sha256", "rounds": rounds }, "check": [{ "kind": "crc32", "bits": 32 }] });
        let mut row = scheme.clone();
        row["entries"] = json!(1);
        row["key_groups"] = json!(1);
        let mut entry = scheme;
        for (name, value) in [("kind", json!("folder")), ("files", json!(["plain.txt"])), ("state", json!("encrypted")), ("key_group", json!(1)), ("method", json!({ "name": "stored", "number": 0 })), ("packed", json!(32)), ("size", json!(28)), ("line", json!({ "mode": 46900, "tag": "$7z$*" }))] {
            entry[name] = value;
        }
        let expected = json!({
            "path": "tests/fixtures/7z-aes/7z_stored.7z",
            "format": "7z",
            "generation": "7z",
            "offset": 0,
            "volume": "single",
            "headers": "readable",
            "entries": { "total": 1, "encrypted": 1, "plain": 0, "pseudo": 0, "undetermined": 0 },
            "coverage": "all",
            "schemes": [row],
            "mixed": false,
            "findings": [],
            "lines": [{ "mode": 46900, "tag": "$7z$*", "entry": 0, "proves": "exact" }],
            "no_line": [],
            "entry_list": [entry],
        });
        assert_eq!(fixture("7z-aes/7z_stored.7z"), expected);

        // the rounds are 2 to the power the archive stores: 7-Zip writes 19 and reads 0 to 24
        assert_eq!(fixture("7z-aes/salted.7z")["entry_list"][0]["kdf"], json!({ "name": "sha256", "rounds": 1 << 15 }));
        assert!(fixture("7z-aes/salted.7z")["entry_list"][0]["salt"].as_str().is_some_and(|salt| !salt.is_empty() && salt.len() % 2 == 0));
        for power in [0_u8, 24] {
            let (analysis, hash) = crafted(&[folder(&[(craft::LZMA2, &[0x18]), (craft::AES, &key(power))])]);
            assert_eq!(analysis["entry_list"][0]["kdf"]["rounds"], json!(1_u64 << power));
            assert!(hash.stdout.starts_with(&format!("$7z$*{power}**c0ffee00*64**1*")), "{}", hash.stdout);
        }

        // a self-extracting archive is the same archive at an offset
        let sfx = fixture("7z-aes/gen_7z_sfx.7z");
        assert_eq!((sfx["offset"].as_u64(), sfx["entry_list"][0]["scheme"].as_str()), (Some(43_432), Some("7z-aes")));
    }

    /// Row 2: an encrypted header hides the entries, and the line comes from the header.
    #[test]
    fn row_2_an_encrypted_header_hides_the_entries_and_gives_the_line() {
        let analysis = fixture("7z-aes/headers.7z");
        assert_eq!((analysis["headers"].as_str(), &analysis["entries"], analysis["coverage"].as_str()), (Some("encrypted"), &json!("hidden"), Some("unknown")));
        assert_eq!(analysis["entry_list"], json!([]));
        assert_eq!(analysis["schemes"], json!([{ "scheme": "7z-aes", "variant": "7z-aes:headers", "cipher": "aes", "key_bits": 256, "kdf": { "name": "sha256", "rounds": 1 << 19 }, "check": [{ "kind": "crc32", "bits": 32 }] }]));
        assert_eq!(analysis["lines"], json!([{ "mode": 46900, "tag": "$7z$*", "proves": "exact" }]), "a line from the headers names no entry");

        // py7zr stores no checksum for the header: the line tests that what decrypts is one
        let analysis = fixture("7z-aes/gen_py7zr_lzma2_hdr.7z");
        assert_eq!(analysis["schemes"][0]["check"], json!([{ "kind": "structure" }]));
        assert_eq!(analysis["lines"][0]["proves"], json!("structural"));
        let hash = run(&["hash", "--json"], &Path::new(FIXTURES).join("7z-aes/gen_py7zr_lzma2_hdr.7z"));
        let line: Value = serde_json::from_str(&hash.stdout).unwrap();
        assert!(line.get("entry").is_none() && line["line"].as_str().is_some_and(|line| line.starts_with("$7z$*19**header*")), "{}", hash.stdout);
    }

    /// Row 3: a round count byte of 0x3F means that the key is the password. It is no number of
    /// rounds, and no mode tests it.
    #[test]
    fn row_3_a_key_that_is_the_password_has_no_derivation_and_no_line() {
        let analysis = fixture("7z-aes/rawkey.7z");
        assert!(analysis["entry_list"][0].get("kdf").is_none() && analysis["schemes"][0].get("kdf").is_none(), "{analysis}");
        assert_eq!((analysis["entry_list"][0]["state"].as_str(), analysis["entry_list"][0]["line"]["reason"].as_str()), (Some("encrypted"), Some("no-mode")));
        assert_eq!(analysis["lines"], json!([]));
        assert_eq!(analysis["no_line"][0]["reason"], json!("no-mode"));
        assert!(codes(&analysis).is_empty());
    }

    /// Row 4: 25 to 62 are round counts 7-Zip itself refuses.
    #[test]
    fn row_4_more_rounds_than_7_zip_takes_are_unsupported_parameters() {
        for power in [25_u8, 40, 62] {
            let (analysis, hash) = crafted(&[folder(&[(craft::LZMA2, &[0x18]), (craft::AES, &key(power))])]);
            assert_eq!(analysis["entry_list"][0]["kdf"], json!({ "name": "sha256", "rounds": 1_u64 << power }));
            assert_eq!((analysis["no_line"][0]["reason"].as_str(), codes(&analysis)), (Some("unsupported-parameters"), vec!["unsupported-parameters"]));
            assert!(hash.stdout.is_empty() && hash.stderr.contains(&format!("2^{power} rounds, which 7-Zip itself refuses [unsupported-parameters]")), "{}", hash.stderr);
        }
    }

    /// Row 5: a stream that is not encrypted, or is encrypted before it is packed, is a layout the
    /// line cannot say.
    #[test]
    fn row_5_a_stream_that_is_not_encrypted_last_has_no_line() {
        for rel in ["7z-aes/tier5_padded.7z", "7z-aes/unknown_coder.7z"] {
            let analysis = fixture(rel);
            assert_eq!((analysis["entry_list"][0]["state"].as_str(), analysis["entry_list"][0]["scheme"].as_str()), (Some("encrypted"), Some("7z-aes")), "{rel}");
            assert_eq!(analysis["no_line"], json!([{ "entry": 0, "reason": "not-expressible", "text": "one of its streams is not encrypted, or is encrypted before it is packed" }]), "{rel}");
        }
        // the same layout built here: the cipher in front of the packer
        let (analysis, hash) = crafted(&[folder(&[(craft::AES, &key(19)), (craft::LZMA2, &[0x18])])]);
        assert_eq!(analysis["no_line"][0]["reason"], json!("not-expressible"));
        assert!(hash.stdout.is_empty());
    }

    /// Row 6: any other coder in the cipher range of 7-Zip's method table is encrypted under a
    /// scheme the tool does not know, with its identifier as the archive stores it.
    #[test]
    fn row_6_another_cipher_is_an_unknown_scheme_with_its_identifier() {
        let zip_crypto: &[u8] = &[0x06, 0xF1, 0x01, 0x01];
        let (analysis, hash) = crafted(&[folder(&[(craft::LZMA2, &[0x18]), (zip_crypto, &[])]), folder(&[(craft::LZMA2, &[0x18]), (craft::AES, &key(19))])]);

        let unknown = &analysis["entry_list"][0];
        assert_eq!((unknown["state"].as_str(), unknown["scheme"].as_str(), unknown["identifier"].as_u64()), (Some("encrypted"), Some("7z-unknown"), Some(0x06F1_0101)));
        assert!(unknown.get("key_group").is_none() && unknown.get("salt").is_none());
        assert_eq!(unknown["line"], json!({ "reason": "unknown-scheme" }));
        assert_eq!(analysis["no_line"], json!([{ "entry": 0, "reason": "unknown-scheme", "text": "it is encrypted with a scheme the tool does not know" }]));
        assert_eq!(codes(&analysis), ["mixed-schemes", "unknown-scheme"]);
        assert_eq!(analysis["findings"][1], json!({ "code": "unknown-scheme", "entries": [0], "text": "encrypted with a scheme the tool does not know, identifier 0x6f10101" }));
        assert_eq!((analysis["mixed"].as_bool(), analysis["coverage"].as_str()), (Some(true), Some("all")));
        // the folder under 7zAES beside it has its line
        assert_eq!((hash.stdout.lines().count(), analysis["lines"][0]["entry"].as_u64()), (1, Some(1)));
    }

    /// Row 7: encryption is per folder. A file in a folder that is not encrypted is plain beside
    /// encrypted ones.
    #[test]
    fn row_7_folders_of_one_archive_are_encrypted_or_not_each_on_its_own() {
        let analysis = fixture("7z-aes/ttzip-core_test_read_format_7zip_encryption_partially.7z");
        let seen: Vec<_> = analysis["entry_list"].as_array().unwrap().iter().map(|entry| (entry["files"][0].as_str().unwrap(), entry["state"].as_str().unwrap(), entry["size"].as_u64().unwrap())).collect();
        assert_eq!(seen, [("bar_unencrypted.txt", "plain", 4), ("bar_encrypted.txt", "encrypted", 4)]);
        assert_eq!((analysis["coverage"].as_str(), codes(&analysis)), (Some("some"), vec!["partial"]));
        assert_eq!(analysis["entries"], json!({ "total": 2, "encrypted": 1, "plain": 1, "pseudo": 0, "undetermined": 0 }));
        assert_eq!(analysis["lines"], json!([{ "mode": 46900, "tag": "$7z$*", "entry": 1, "proves": "exact" }]));

        // 7-Zip lists tiny.txt of this archive as not encrypted, and the other files as encrypted
        let analysis = fixture("7z-aes/gen_7z_mixed_plain_first.7z");
        let plain: Vec<&str> = analysis["entry_list"].as_array().unwrap().iter().filter(|entry| entry["state"] == "plain").flat_map(|entry| entry["files"].as_array().unwrap()).map(|name| name.as_str().unwrap()).collect();
        assert_eq!(plain, ["tiny.txt"]);
    }

    /// A first volume of a split archive, and a file that is cut short, are incomplete. Neither is
    /// a failure, and neither is taken for an archive in which nothing is encrypted.
    #[test]
    fn a_file_without_its_header_is_incomplete_and_no_failure() {
        let whole = std::fs::read(Path::new(FIXTURES).join("7z-aes/7z_nonsolid_enc.7z")).unwrap();
        for keep in [32, whole.len() / 2, whole.len() - 1] {
            with_archive(&whole[..keep], |path| {
                let analysis = info(path);
                assert_eq!((analysis["volume"].as_str(), codes(&analysis)), (Some("incomplete"), vec!["incomplete"]), "{keep} bytes");
                assert_eq!(analysis["entry_list"], json!([{ "kind": "folder", "state": "undetermined", "line": { "reason": "split" } }]));
                assert_eq!(analysis["entries"], json!({ "total": 1, "encrypted": 0, "plain": 0, "pseudo": 0, "undetermined": 1 }));
                assert_eq!(analysis["no_line"][0]["reason"], json!("split"));

                let text = run(&["info"], path);
                assert!(text.stdout.contains("   7z, incomplete, 1 folder\n") && text.stdout.contains("1 not determined") && !text.stdout.contains("nothing is encrypted"), "{}", text.stdout);
                let hash = run(&["hash"], path);
                assert!(hash.code == Some(0) && hash.stdout.is_empty() && hash.stderr.contains("a volume of a split archive, or a file that is cut short [split]"), "{}", hash.stderr);
            });
        }
    }

    /// A header that names its folders in a stream outside itself, and one that is packed with a
    /// coder the tool does not unpack, are a reason and no failure.
    #[test]
    fn a_header_the_tool_cannot_read_is_a_reason_and_no_failure() {
        let external = craft::archive(&[0x01, 0x04, 0x06, 0x00, 0x01, 0x09, 0x10, 0x00, 0x07, 0x0B, 0x01, 0x01, 0x00], &[0; 16]);
        let packed = craft::archive(&craft::packed_header(craft::chain(&[(craft::PPMD, &[6, 0, 0, 0, 1])]), &[100], 0, 16, None), &[0; 16]);
        for (archive, said) in [(external, "described in a stream outside its header"), (packed, "packed with the coder 030401")] {
            with_archive(&archive, |path| {
                let analysis = info(path);
                assert_eq!(analysis["entry_list"], json!([{ "kind": "folder", "state": "undetermined", "line": { "reason": "damaged" } }]));
                assert_eq!((analysis["volume"].as_str(), analysis["no_line"][0]["reason"].as_str()), (Some("single"), Some("damaged")));
                assert!(analysis["no_line"][0]["text"].as_str().unwrap().contains(said), "{analysis}");
            });
        }
    }

    /// The archive of the review: a file of one byte and a larger one, each in a folder of its own,
    /// written by 7-Zip with the password `weakpw`. The line came from the one byte, which eight
    /// bits of a wrong password match. It comes from the larger file now, and the line of the one
    /// byte says what it is.
    #[test]
    fn the_folder_that_proves_most_gives_the_line_and_a_weak_line_says_so() {
        let path = Path::new(FIXTURES).join("regress/7z/weak_first.7z");
        let best = run(&["hash"], &path);
        assert_eq!(best.stdout.lines().count(), 1);
        assert!(best.stdout.starts_with("$7z$*19**619fd8f1*56**1*11cd6981152913aaabb720eb6055e145*60*56**263274d2"), "{}", best.stdout);
        assert!(!best.stderr.contains("weak"), "{}", best.stderr);

        let analysis = info(&path);
        assert_eq!(analysis["lines"], json!([{ "mode": 46900, "tag": "$7z$*", "entry": 1, "proves": "exact" }]));
        assert_eq!(analysis["entry_list"][1]["files"], json!(["big.txt"]));
        assert!(codes(&analysis).is_empty() && analysis["entry_list"][0].get("hash").is_none());

        // every folder asked: the line that proves most first, and the weak one marked
        let all = run(&["hash", "--all", "--json"], &path);
        let lines: Vec<Value> = all.stdout.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(lines.iter().map(|line| (line["entry"].as_u64().unwrap(), line["proves"].as_str().unwrap())).collect::<Vec<_>>(), [(1, "exact"), (0, "weak")]);
        assert_eq!(lines[1]["line"], json!("$7z$*19**8cdc1683*1**1*a7b2f94adaa5422654338991f6bd7d38*10*1**cf21be47650c3f7156bb90e8a4cd5c21$/7z$"));
        assert!(all.stderr.contains("weak line: folder 0 (a.txt): its CRC-32 covers 1 byte, and a CRC-32 over fewer than 4 bytes proves no more than the bytes themselves: 8 bits."), "{}", all.stderr);

        // an archive with nothing better: the weak line is the best there is, and that is a finding
        let stored = craft::Folder::new(craft::chain(&[(craft::AES, &key(19))]), &[3], 16, Some(0xAABB_CCDD));
        let (analysis, hash) = crafted(&[stored]);
        assert_eq!(analysis["lines"], json!([{ "mode": 46900, "tag": "$7z$*", "entry": 0, "proves": "weak" }]));
        assert_eq!(analysis["findings"], json!([{ "code": "weak-check", "entries": [0], "text": "the best line is weak, it tests 24 bits and no data beyond them: a password found with it has to be confirmed by opening the archive" }]));
        assert!(hash.stdout.starts_with("$7z$*19**aabbccdd*3**1*") && hash.stderr.contains("weak line: folder 0 (f0)") && hash.stderr.contains("24 bits"), "{}", hash.stderr);
    }

    /// Whatever an archive is, its analysis is one object with the names of the interface: also for
    /// the inputs that were built to break the reader.
    #[test]
    fn every_archive_that_is_read_gives_the_object_of_the_interface() {
        const NAMES: [&str; 14] = ["path", "format", "generation", "offset", "volume", "headers", "entries", "coverage", "schemes", "mixed", "findings", "lines", "no_line", "entry_list"];
        let mut read = 0;
        for (name, bytes) in craft::hostile() {
            with_archive(&bytes, |path| {
                let run = run(&["info", "--json"], path);
                if run.code == Some(0) {
                    read += 1;
                    let analysis: serde_json::Map<String, Value> = serde_json::from_str(&run.stdout).unwrap();
                    assert_eq!(analysis.keys().map(String::as_str).collect::<BTreeSet<_>>(), BTreeSet::from(NAMES), "{name}");
                    assert_eq!((analysis["format"].as_str(), analysis["generation"].as_str(), analysis["volume"].as_str()), (Some("7z"), Some("7z"), Some("single")), "{name}");
                } else {
                    assert_eq!((run.code, run.stdout.as_str()), (Some(2), ""), "{name}: {}", run.stderr);
                }
            });
        }
        assert_eq!(read, 9, "nine of the inputs are archives, with or without folders");
    }

    /// A line that mode 46900 would refuse is not written: the reason is, with what was found.
    #[test]
    fn a_line_the_mode_would_refuse_gives_its_reason() {
        let aes = key(19);
        let long = [&[0x5D, 0, 0, 1, 0][..], &[0; 12]].concat();
        let cases: [(craft::Folder, &str); 4] = [
            (folder(&[(craft::PPMD, &[6, 0, 0, 0, 0x20]), (craft::AES, &aes)]), "its PPMd model takes 536870912 bytes, more than the 268435456 hashcat gives one [over-limit]"),
            (folder(&[(craft::LZMA, &long), (craft::AES, &aes)]), "the properties of its LZMA coder take 17 bytes, more than the 16 hashcat stores [over-limit]"),
            (folder(&[(&[0x04, 0xF7, 0x11, 0x02], &[]), (craft::AES, &aes)]), "it uses the coder 04f71102, which hashcat cannot unpack [over-limit]"),
            (
                craft::Folder::new(craft::chain(&[(craft::LZMA2, &[0x18]), (craft::AES, &aes)]), &[65 << 20, 32], 32, Some(1)),
                "its first file unpacks to 68157440 bytes, more than the 67108864 hashcat unpacks for a candidate, and its 32 bytes of LZMA2 data are too few to say anything about the key by their start [over-limit]",
            ),
        ];
        for (folder, said) in cases {
            let (analysis, hash) = crafted(&[folder]);
            assert_eq!((analysis["entry_list"][0]["state"].as_str(), analysis["entry_list"][0]["line"]["reason"].as_str()), (Some("encrypted"), Some("over-limit")), "{said}");
            assert!(hash.code == Some(0) && hash.stdout.is_empty() && hash.stderr.contains(said), "{said}: {}", hash.stderr);
        }
    }
}
