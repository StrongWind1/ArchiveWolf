//! RAR through the command line: archives that were built to break the parser end in a result
//! or in a parse error, a later volume is analysed like any archive, and what `hash` says of a
//! line reaches standard error.
//!
//! The archives are built here from a few bytes, or from a fixture with a few bytes changed.
//! Each stands for a class of input that once ended the process: with status 101 for a panic
//! on a sum that overflows, or 134 for an allocation of what a header claims.

// A test crate is linked against every dependency of the package, and the lint
// `unused_crate_dependencies` wants each of them named. These tests run the binary.
use anyhow as _;
use archivewolf as _;
use archivewolf_zip_crypto as _;
use assert_cmd as _;
use clap as _;
use crc32fast as _;
use flate2 as _;
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
    use std::path::Path;
    use std::path::PathBuf;

    use serde_json::Value;

    const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
    const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
    /// The largest variable-length number: ten bytes for 2^64 - 1.
    const VMAX: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];

    /// What one run of the binary gave back.
    struct Run {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    impl Run {
        /// The objects `--json` wrote, one for each line.
        fn objects(&self) -> Vec<Value> {
            self.stdout.lines().map(|line| serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}: {line}"))).collect()
        }

        /// The reasons of the one archive `info --json` was run on.
        fn reasons(&self) -> Vec<String> {
            self.objects()[0]["no_line"].as_array().unwrap().iter().map(|missing| missing["reason"].as_str().unwrap().to_owned()).collect()
        }
    }

    /// Run the binary. A run that could not be started has no exit status.
    fn aw(args: &[&str]) -> Run {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(args).env("NO_COLOR", "1").env_remove("RUST_LOG").output();
        output.map_or_else(|error| Run { code: None, stdout: String::new(), stderr: error.to_string() }, |output| Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned() })
    }

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(Path::new("tests/fixtures").join(rel)).unwrap()
    }

    /// A RAR 5 block around `body`, with a CRC-32 of zero: the parser takes a header at its word.
    fn block5(body: &[u8]) -> Vec<u8> {
        let mut out = vec![0, 0, 0, 0, u8::try_from(body.len()).unwrap()];
        out.extend_from_slice(body);
        out
    }

    /// The archives that used to end the process, by name.
    fn crafted() -> Vec<(&'static str, Vec<u8>)> {
        let zeros = [0_u8; 32];
        let mut archives = Vec::new();
        let mut add = |name: &'static str, parts: &[&[u8]]| archives.push((name, parts.concat()));

        // RAR 5: a header size, a data size, a name length, an extra size and a record size of 2^64 - 1
        add("header-size.rar", &[RAR5, &[0; 4], VMAX, &zeros]);
        add("data-size.rar", &[RAR5, &block5(&[&[1, 2][..], VMAX].concat()), &zeros]);
        add("name-length.rar", &[RAR5, &block5(&[&[2, 0, 0, 0, 0, 0, 0][..], VMAX].concat()), &zeros]);
        add("extra-size.rar", &[RAR5, &block5(&[2, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), &zeros]);
        add("record-size.rar", &[RAR5, &block5(&[&[2, 1, 11, 0, 0, 0, 0, 0, 0][..], VMAX, &[1]].concat()), &zeros]);

        // RAR 3: a packed size of 2^64 - 1 in a file header with the flag for large sizes
        let main = [0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0];
        let mut large = vec![0, 0, 0x74, 0x00, 0x81, 45, 0];
        large.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 29, 0x30, 5, 0, 0, 0, 0, 0]);
        large.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
        large.extend_from_slice(b"a.txt");
        add("rar3-large.rar", &[RAR4, &main, &large, &[0; 64]]);

        // RAR 1.5: a packed entry that is said to unpack to four gigabytes, to 2^44 bytes, to 2^64
        let packed = fixture("rar-15/rar15-password-compressed.rar");
        let mut claims = packed.clone();
        claims[31..35].copy_from_slice(&[0xFF; 4]);
        add("unpacks-to-4g.rar", &[&claims]);
        for (name, high) in [("unpacks-to-2e44.rar", 0x1000_u32), ("unpacks-to-2e64.rar", u32::MAX)] {
            let mut claims = packed.clone();
            let flags = u16::from_le_bytes([claims[23], claims[24]]) | 0x0100;
            let size = u16::from_le_bytes([claims[25], claims[26]]) + 8;
            claims[23..25].copy_from_slice(&flags.to_le_bytes());
            claims[25..27].copy_from_slice(&size.to_le_bytes());
            drop(claims.splice(52..52, [&[0; 4][..], &high.to_le_bytes()].concat()));
            add(name, &[&claims]);
        }

        // RAR 1.4: a stored entry and a packed one that are said to be four gigabytes long
        let head = |packed: u32, unpacked: u32, method: u8| [&packed.to_le_bytes()[..], &unpacked.to_le_bytes(), &[0x34, 0x12, 26, 0, 0, 0, 0, 0, 0, 0x04, 2, 5, method], b"A.BIN"].concat();
        add("rar14-stored-4g.rar", &[b"RE~^\x07\x00\x00", &head(u32::MAX, u32::MAX, 0), &[0x5A; 100]]);
        add("rar14-packed-4g.rar", &[b"RE~^\x07\x00\x00", &head(100, u32::MAX, 3), &[0x5A; 100]]);
        archives
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Every command over every crafted archive: a result or a parse error, and never the end of
    /// the process.
    #[test]
    fn archives_built_to_break_the_parser_end_in_a_result_or_a_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in crafted() {
            let path = write(dir.path(), name, &bytes);
            let path = path.to_str().unwrap();
            for args in [&["info"][..], &["info", "--json"], &["info", "--entries"], &["hash"], &["hash", "--all"], &["hash", "--json"]] {
                let run = aw(&[args, &[path]].concat());
                assert!(matches!(run.code, Some(0 | 2)), "{name} {args:?}: status {:?}\n{}", run.code, run.stderr);
                assert!(!run.stderr.contains("panicked") && !run.stderr.contains("internal error"), "{name} {args:?}: {}", run.stderr);
            }
        }
        // the whole directory in one run: the one that does not parse does not end it
        let run = aw(&["info", "--json", dir.path().to_str().unwrap()]);
        assert_eq!((run.code, run.objects().len()), (Some(2), crafted().len() - 1), "{}", run.stderr);
    }

    #[test]
    fn each_crafted_archive_is_said_to_be_what_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let info = |name: &str| {
            let bytes = crafted().into_iter().find(|(crafted, _)| *crafted == name).unwrap().1;
            let path = write(dir.path(), name, &bytes);
            aw(&["info", "--json", path.to_str().unwrap()])
        };

        // a size field that is no size field leaves no header to read
        let run = info("header-size.rar");
        assert_eq!(run.code, Some(2));
        assert!(run.stderr.contains("the signature is not followed by a header"), "{}", run.stderr);

        // data of 2^64 bytes does not lie inside the file: the archive is incomplete
        for name in ["data-size.rar", "rar3-large.rar", "rar14-stored-4g.rar"] {
            let run = info(name);
            assert_eq!((run.code, &run.objects()[0]["volume"]), (Some(0), &Value::from("incomplete")), "{name}");
        }
        assert_eq!(info("rar3-large.rar").objects()[0]["entry_list"][0]["packed"], Value::from(u64::MAX));
        for name in ["name-length.rar", "extra-size.rar", "record-size.rar"] {
            let run = info(name);
            assert_eq!((run.code, &run.objects()[0]["entries"]["encrypted"]), (Some(0), &Value::from(0)), "{name}");
        }

        // RAR 1.5 under a size its mode does not take: encrypted, and no line
        let run = info("unpacks-to-4g.rar");
        assert_eq!((run.reasons(), &run.objects()[0]["entry_list"][0]["state"]), (vec!["not-expressible".to_owned()], &Value::from("encrypted")), "all bits set: the size is not known");
        assert!(run.objects()[0]["entry_list"][0].get("size").is_none());
        for (name, size) in [("unpacks-to-2e44.rar", 0x1000_u64 << 32), ("unpacks-to-2e64.rar", u64::from(u32::MAX) << 32)] {
            let run = info(name);
            assert_eq!(run.reasons(), ["over-limit"], "{name}");
            assert_eq!(run.objects()[0]["entry_list"][0]["size"].as_u64().unwrap() >> 32 << 32, size, "{name}");
            assert!(run.objects()[0]["lines"].as_array().unwrap().is_empty());
        }

        // RAR 1.3 has no line whatever its sizes are, and nothing is unpacked to say so
        for name in ["rar14-stored-4g.rar", "rar14-packed-4g.rar"] {
            let run = info(name);
            assert_eq!((run.reasons(), &run.objects()[0]["entry_list"][0]["scheme"]), (vec!["no-mode".to_owned()], &Value::from("rar-13")), "{name}");
        }
    }

    #[test]
    fn a_round_count_rar_refuses_is_shown_as_encrypted() {
        let run = aw(&["info", "--json", "tests/fixtures/regress/rar/rounds_2e25.rar"]);
        let report = &run.objects()[0];
        assert_eq!((run.code, &report["entries"]["encrypted"], &report["coverage"]), (Some(0), &Value::from(2), &Value::from("some")));
        assert_eq!(run.reasons(), ["unsupported-parameters", "unsupported-parameters"]);
        assert_eq!(report["schemes"][0]["kdf"]["rounds"], Value::from(1_u64 << 25));
        assert!(report["findings"].as_array().unwrap().iter().any(|finding| finding["code"] == "unsupported-parameters" && finding["entries"] == serde_json::json!([1, 3])), "{report}");
        assert!(aw(&["hash", "--all", "tests/fixtures/regress/rar/rounds_2e25.rar"]).stdout.is_empty());
    }

    #[test]
    fn a_zeroed_check_value_leaves_the_line_to_the_next_entry() {
        let run = aw(&["hash", "--json", "tests/fixtures/regress/rar/service_zero_check_value.rar"]);
        let lines = run.objects();
        assert_eq!((run.code, lines.len()), (Some(0), 1), "{}", run.stderr);
        assert!(lines[0]["line"].as_str().unwrap().starts_with("$rar$50$*0*") && lines[0]["proves"] == "exact", "{}", lines[0]);
        assert!(!run.stderr.contains("no line"), "{}", run.stderr);

        // every entry is asked: the record is tested by its data, like the file whose copy it is
        let all = aw(&["hash", "--all", "tests/fixtures/regress/rar/service_zero_check_value.rar"]);
        assert_eq!(all.stdout.lines().filter(|line| line.starts_with("$rar$50$*0*")).count(), 2, "the two files with a check value");
        assert_eq!(all.stdout.lines().filter(|line| line.starts_with("$rar$50$*1*")).count(), 1);
    }

    #[test]
    fn an_entry_without_a_salt_has_a_reason_and_no_line_of_zeros() {
        let run = aw(&["hash", "--all", "tests/fixtures/regress/rar/rar3_no_salt.rar"]);
        assert_eq!((run.code, run.stdout.as_str()), (Some(0), ""));
        assert!(run.stderr.contains("rar3_no_salt.rar: no line: fox.txt: its key is derived without a salt, and a line has no way to say that [not-expressible]"), "{}", run.stderr);
        assert_eq!(aw(&["info", "--json", "tests/fixtures/regress/rar/rar3_no_salt.rar"]).objects()[0]["entry_list"][0]["state"], "encrypted");
    }

    /// The line of encrypted RAR 3 headers is the one of the archive, whatever follows it in its
    /// file. For a few bytes behind the archive, the salt and the block used to be read from them.
    #[test]
    fn bytes_behind_an_archive_with_encrypted_headers_do_not_change_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let alone = aw(&["hash", "tests/fixtures/rar-30/v420_hp_m3.rar"]);
        assert!(alone.stdout.starts_with("$rar$30$*0*") && alone.stdout.lines().count() == 1);

        let mut longer = fixture("rar-30/v420_hp_m3.rar");
        longer.extend_from_slice(&[0; 8]);
        let path = write(dir.path(), "trailing.rar", &longer);
        let run = aw(&["hash", path.to_str().unwrap()]);
        assert_eq!((run.code, &run.stdout), (Some(0), &alone.stdout));
        assert!(run.stderr.contains("note: the headers: 8 bytes follow what is taken for the end of the archive"), "{}", run.stderr);
    }

    #[test]
    fn an_archive_behind_a_program_that_names_the_format_is_found() {
        let dir = tempfile::tempdir().unwrap();
        // "Rar!" in the text of the program, a bare signature of each generation, then the archive
        let mut program = b"MZ\x90\x00 This program unpacks Rar! archives. ".to_vec();
        program.extend_from_slice(RAR5);
        program.extend_from_slice(b" and ");
        program.extend_from_slice(RAR4);
        program.resize(300, 0);
        program.extend_from_slice(&fixture("rar-50/v730_p_m3.rar"));
        let path = write(dir.path(), "decoy.exe", &program);

        let run = aw(&["info", "--json", path.to_str().unwrap()]);
        let report = &run.objects()[0];
        assert_eq!((run.code, &report["offset"], &report["generation"]), (Some(0), &Value::from(300), &Value::from("rar5")), "{}", run.stderr);
        let bare = aw(&["hash", "tests/fixtures/rar-50/v730_p_m3.rar"]);
        assert_eq!(aw(&["hash", path.to_str().unwrap()]).stdout, bare.stdout);
    }

    // ---------------------------------------------------------------------------
    // Volumes
    // ---------------------------------------------------------------------------

    /// A later volume is an archive. Naming one used to end with status 1, as if it were no
    /// archive at all, and a walk passed it over.
    #[test]
    fn a_later_volume_is_analysed_named_or_met_in_a_walk() {
        for (path, generation) in [("tests/fixtures/unparseable/big.part2.rar", "rar5"), ("tests/fixtures/unparseable/test-documents.part3.rar", "rar4")] {
            let run = aw(&["info", "--json", path]);
            let report = &run.objects()[0];
            assert_eq!((run.code, &report["volume"], &report["generation"]), (Some(0), &Value::from("later"), &Value::from(generation)), "{path}: {}", run.stderr);
        }
        let run = aw(&["info", "tests/fixtures/unparseable/big.part2.rar"]);
        assert!(run.stdout.starts_with("tests/fixtures/unparseable/big.part2.rar   RAR 5, later volume of a set, 2 entries\n"), "{}", run.stdout);

        let walk = aw(&["info", "--json", "tests/fixtures/regress/rar"]);
        let volumes: Vec<(String, Value)> = walk.objects().into_iter().filter(|report| report["path"].as_str().unwrap().contains("_vol.part")).map(|report| (report["path"].as_str().unwrap().rsplit('/').next().unwrap().to_owned(), report["volume"].clone())).collect();
        let of = |name: &str| volumes.iter().find(|(volume, _)| volume == name).unwrap_or_else(|| panic!("{name} was passed over: {volumes:?}")).1.clone();
        assert_eq!(volumes.len(), 9);
        assert_eq!((of("rar5_p_vol.part1.rar"), of("rar5_p_vol.part2.rar")), (Value::from("first"), Value::from("later")));
        assert_eq!((of("rar4_hp_vol.part1.rar"), of("rar4_hp_vol.part2.rar")), (Value::from("first"), Value::from("later")));
        // the header that says which volume it is is encrypted in RAR 5
        assert_eq!(of("rar5_hp_vol.part2.rar"), Value::Null);
    }

    /// The archives were written with the password `secret`: RAR 7.11 for RAR 5, RAR 4.20 and
    /// RAR 3.00 for the two kinds of end block.
    #[test]
    fn every_volume_of_a_set_gives_the_line_it_holds() {
        let lines = |name: &str| {
            let run = aw(&["hash", &format!("tests/fixtures/regress/rar/{name}")]);
            assert_eq!(run.code, Some(0), "{name}: {}", run.stderr);
            (run.stdout.lines().map(str::to_owned).collect::<Vec<_>>(), run.stderr)
        };

        // RAR 5: the encryption header is in every volume, and so is its check value
        let (first, _) = lines("rar5_hp_vol.part1.rar");
        assert!(first.len() == 1 && first[0].starts_with("$rar$50$*0*"), "{first:?}");
        assert_eq!((lines("rar5_hp_vol.part2.rar").0, lines("rar5_hp_vol.part3.rar").0), (first.clone(), first));

        // RAR 5, entries encrypted: each part of the file brings the check value in its header
        let (first, _) = lines("rar5_p_vol.part1.rar");
        assert!(first.len() == 1 && first[0].starts_with("$rar$50$*0*"), "{first:?}");
        assert_eq!(lines("rar5_p_vol.part2.rar").0, first);

        // RAR 4.20: a volume ends in a block of 32 bytes behind its salt, and the line carries both
        for name in ["rar4_hp_vol.part1.rar", "rar4_hp_vol.part2.rar"] {
            let bytes = fixture(&format!("regress/rar/{name}"));
            let (line, notes) = lines(name);
            assert_eq!(line, [format!("$rar$30$*0*{}*c43d7b00*20*20*0*{}$/rar$", hex::encode(&bytes[20..28]), hex::encode(&bytes[bytes.len() - 32..]))], "{name}");
            assert_eq!(bytes[bytes.len() - 40..bytes.len() - 32], bytes[20..28], "the salt of the first block stands in front of the last");
            assert!(!notes.contains(": note: "), "{notes}");
        }

        // RAR 3.00: a volume ends in the short block, which is the one the line tests only in the
        // last volume. The line is written, and says so.
        for name in ["rar3_hp_vol.part1.rar", "rar3_hp_vol.part2.rar"] {
            let bytes = fixture(&format!("regress/rar/{name}"));
            let (line, notes) = lines(name);
            assert_eq!(line, [format!("$rar$30$*0*{}*c43d7b00*10*10*0*{}$/rar$", hex::encode(&bytes[20..28]), hex::encode(&bytes[bytes.len() - 16..]))], "{name}");
            assert!(notes.contains(&format!("{name}: note: the headers: the archive is a volume with the short end block of RAR 3.00, so the line confirms a password only when this is the last volume of its set.")), "{notes}");
        }
    }

    // ---------------------------------------------------------------------------
    // Against UnRAR
    // ---------------------------------------------------------------------------

    /// The names `unrar lb` lists for an archive, or why it listed none.
    fn unrar_names(path: &Path) -> Result<Vec<String>, String> {
        let output = std::process::Command::new("unrar").args(["lb", "-p-", "-c-"]).arg(path).output().map_err(|error| format!("unrar could not be run: {error}"))?;
        if !output.status.success() {
            return Err(format!("unrar ended with {}", output.status));
        }
        Ok(String::from_utf8_lossy(&output.stdout).lines().map(str::to_owned).collect())
    }

    /// The files and directories `info --entries` lists are the ones UnRAR lists, for every
    /// fixture UnRAR opens. It needs `unrar` on the path, and fails when that is missing.
    #[test]
    #[ignore = "runs unrar"]
    fn the_entries_of_every_fixture_are_the_ones_unrar_lists() {
        let _version = std::process::Command::new("unrar").output().expect("this test needs `unrar` on the path");

        let mut compared = 0;
        for dir in ["rar-13", "rar-15", "rar-20", "rar-30", "rar-50", "unencrypted", "regress/rar", "regress/f3-tools"] {
            let mut paths: Vec<PathBuf> = std::fs::read_dir(Path::new("tests/fixtures").join(dir)).unwrap().map(|entry| entry.unwrap().path()).filter(|path| path.extension().is_some_and(|extension| extension.eq_ignore_ascii_case("rar"))).collect();
            paths.sort();
            for path in paths {
                let run = aw(&["info", "--json", path.to_str().unwrap()]);
                let Some(report) = run.objects().into_iter().next() else { continue };
                // encrypted headers hide the entries from both, and UnRAR lists nothing it cannot open
                let Ok(listed) = unrar_names(&path) else { continue };
                if report["headers"] == "encrypted" {
                    continue;
                }
                // Before RAR 5 a path is stored with backslashes, which UnRAR lists as the
                // separator of this system. In RAR 5 a backslash is a character of the name.
                let separator = if report["generation"] == "rar5" { "\\" } else { "/" };
                let ours: Vec<String> = report["entry_list"].as_array().unwrap().iter().filter(|entry| entry["kind"] != "service").map(|entry| entry["name"].as_str().unwrap().replace('\\', separator)).collect();
                if ours.iter().any(|name| name.chars().any(|ch| ch == char::REPLACEMENT_CHARACTER || ch.is_control())) {
                    continue;
                }
                assert_eq!(ours, listed, "{}", path.display());
                compared += 1;
            }
        }
        assert!(compared > 100, "{compared} archives were compared");
    }
}
