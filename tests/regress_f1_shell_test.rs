//! The command-line contract, end to end: the exit status, one archive failing without
//! ending the run, the order of reports, self-extracting archives, what reaches the
//! terminal from inside an archive, and the command the tool prints.
//!
//! Every test drives the binary, so each one states behaviour a script or a user sees.
#![expect(unused_crate_dependencies, reason = "integration test")]

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::Path;
    use std::path::PathBuf;

    use assert_cmd::Command;

    /// What one run of the binary gave back.
    struct Run {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    }

    /// Run `archivewolf` with colour off, so standard error is the text and nothing else.
    fn aw<I, S>(args: I) -> Run
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        finish(Command::cargo_bin("archivewolf").unwrap().args(args))
    }

    /// Run the command and keep what it gave back.
    fn finish(command: &mut Command) -> Run {
        let output = command.env("NO_COLOR", "1").env_remove("RUST_BACKTRACE").env_remove("RUST_LOG").output().unwrap();
        Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned() }
    }

    fn fixture(rel: &str) -> String {
        format!("tests/fixtures/{rel}")
    }

    fn fixture_bytes(rel: &str) -> Vec<u8> {
        std::fs::read(fixture(rel)).unwrap()
    }

    /// The path as the command line takes it. Every path here is valid UTF-8.
    fn arg(path: &Path) -> &str {
        path.to_str().unwrap()
    }

    /// One JSON report per line of standard output.
    fn reports(run: &Run) -> Vec<serde_json::Value> {
        run.stdout.lines().map(|line| serde_json::from_str(line).unwrap_or_else(|error| panic!("not JSON: {error}: {line}"))).collect()
    }

    /// A ZIP archive cut off in the middle of its first entry: it has the signature and no end.
    fn truncated_zip() -> Vec<u8> {
        let mut data = fixture_bytes("zip-crypto/zipcrypto.zip");
        data.truncate(60);
        data
    }

    /// Control characters other than the newline that ends a line.
    fn control_characters(text: &str) -> Vec<char> {
        text.chars().filter(|ch| ch.is_control() && *ch != '\n').collect()
    }

    // -----------------------------------------------------------------------
    // Exit status
    // -----------------------------------------------------------------------

    #[test]
    fn a_path_that_does_not_exist_exits_1() {
        for command in ["info", "hash"] {
            let run = aw([command, "/nonexistent/archivewolf/missing.zip"]);
            assert_eq!(run.code, Some(1), "{command}: {}", run.stderr);
            assert!(run.stdout.is_empty(), "{command}: {}", run.stdout);
            assert!(run.stderr.contains("archivewolf: /nonexistent/archivewolf/missing.zip: "), "{command}: the path is named: {}", run.stderr);
        }
    }

    #[test]
    fn a_file_that_is_not_an_archive_exits_1() {
        for command in ["info", "hash"] {
            let run = aw([command, "Cargo.toml"]);
            assert_eq!(run.code, Some(1), "{command}: {}", run.stderr);
            assert!(run.stdout.is_empty(), "{command}: {}", run.stdout);
            assert!(run.stderr.contains("no archives found"), "{command}: {}", run.stderr);
        }
    }

    #[test]
    fn an_archive_that_does_not_parse_exits_2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cut.zip");
        std::fs::write(&path, truncated_zip()).unwrap();

        for command in [&["info"][..], &["info", "--json"], &["hash"], &["hash", "--json"], &["hash", "--all", "--mode", "46100"]] {
            let run = aw(command.iter().copied().chain([arg(&path)]));
            assert_eq!(run.code, Some(2), "{command:?}: {}", run.stderr);
            assert!(run.stdout.is_empty(), "{command:?}: {}", run.stdout);
            assert!(run.stderr.contains(&format!("archivewolf: {}: ", path.display())), "{command:?}: {}", run.stderr);
        }
    }

    #[test]
    fn a_missing_path_beside_an_archive_exits_2_and_the_archive_is_reported() {
        let run = aw(["info", &fixture("zip-crypto/zipcrypto.zip"), "/nonexistent/archivewolf/missing.zip"]);
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        assert!(run.stdout.contains("zipcrypto.zip") && run.stdout.contains("$zip$1$, hashcat mode 46100"), "{}", run.stdout);
        assert!(run.stderr.contains("archivewolf: /nonexistent/archivewolf/missing.zip: "), "{}", run.stderr);

        // and its line is written all the same
        let run = aw(["hash", &fixture("zip-crypto/zipcrypto.zip"), "/nonexistent/archivewolf/missing.zip"]);
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        assert!(run.stdout.starts_with("$zip$1$*") && run.stdout.lines().count() == 1, "{}", run.stdout);
        assert!(run.stderr.contains("archivewolf: /nonexistent/archivewolf/missing.zip: "), "{}", run.stderr);
    }

    #[test]
    fn an_archive_with_nothing_encrypted_has_no_line_and_is_no_failure() {
        for rel in ["unencrypted/zip31c_unencrypted.zip", "unencrypted/plain.rar", "unencrypted/plain.7z", "pseudo/pseudo.zip"] {
            let run = aw(["hash", "--all", &fixture(rel)]);
            assert_eq!(run.code, Some(0), "{rel}: {}", run.stderr);
            assert!(run.stdout.is_empty(), "{rel}: nothing to write a line for: {}", run.stdout);
            assert!(run.stderr.contains("archivewolf: no hash lines"), "{rel}: {}", run.stderr);

            let json = aw(["info", "--json", &fixture(rel)]);
            assert_eq!(json.code, Some(0), "{rel}: {}", json.stderr);
            assert_eq!(reports(&json)[0]["lines"], serde_json::json!([]), "{rel}: {}", json.stdout);
        }

        // a plain archive beside an encrypted one: the run is a success, with the one line
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("locked.zip"), fixture_bytes("zip-crypto/zipcrypto.zip")).unwrap();
        std::fs::write(dir.path().join("open.zip"), fixture_bytes("unencrypted/zip31c_unencrypted.zip")).unwrap();
        let run = aw(["hash", arg(dir.path())]);
        assert_eq!((run.code, run.stdout.lines().count()), (Some(0), 1), "{}", run.stderr);
    }

    #[test]
    fn the_json_report_of_an_archive_has_no_field_for_a_recovery() {
        let run = aw(["info", "--json", &fixture("zip-crypto/zipcrypto.zip")]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        let all = reports(&run);
        let fields: Vec<&str> = all[0].as_object().unwrap().keys().map(String::as_str).collect();
        // the fields of the analysis and no other: no password, no outcome, no free text
        assert_eq!(fields, ["coverage", "entries", "entry_list", "findings", "format", "generation", "headers", "lines", "mixed", "no_line", "offset", "path", "schemes", "volume", "writer"], "{}", run.stdout);
        assert_eq!(all[0]["lines"], serde_json::json!([{ "mode": 46100, "tag": "$zip$1$", "entry": 0, "proves": "exact" }]));
        assert_eq!(all[0]["entries"], serde_json::json!({ "total": 1, "encrypted": 1, "plain": 0, "pseudo": 0, "undetermined": 0 }));
        assert_eq!((&all[0]["format"], &all[0]["generation"], &all[0]["headers"], &all[0]["coverage"], &all[0]["mixed"]), (&"zip".into(), &"zip".into(), &"readable".into(), &"all".into(), &false.into()));
        assert_eq!(all[0]["no_line"], serde_json::json!([]));
    }

    #[test]
    fn help_documents_the_exit_status() {
        for args in [&["--help"][..], &["info", "--help"], &["hash", "--help"], &["attack", "rar-13", "--help"]] {
            let run = aw(args);
            assert_eq!(run.code, Some(0), "{args:?}");
            for row in ["Exit status:", "  0  Every input", "  1  Nothing was processed", "  2  At least one input", "  3  An attack ended"] {
                assert!(run.stdout.contains(row), "{args:?}: no {row:?} in\n{}", run.stdout);
            }
        }
        // a command line that cannot be parsed keeps the status of the argument parser
        assert_eq!(aw(["info"]).code, Some(2));
        assert_eq!(aw(["no-such-command"]).code, Some(2));
    }

    // -----------------------------------------------------------------------
    // One archive failing does not end the run
    // -----------------------------------------------------------------------

    /// A 7z archive of 44 bytes whose header claims a size that overflows when added up.
    const HOSTILE_7Z: [u8; 44] = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0x00, 0x04, 0x3d, 0x8f, 0xb3, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x3c, 0x68, 0xfa, 0x01, 0x02, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    #[test]
    fn one_archive_that_cannot_be_processed_does_not_end_the_run() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a_bad.7z"), HOSTILE_7Z).unwrap();
        std::fs::write(dir.path().join("b_good.7z"), fixture_bytes("7z-aes/flag.7z")).unwrap();
        std::fs::write(dir.path().join("c_good.zip"), fixture_bytes("zip-crypto/zipcrypto.zip")).unwrap();

        let run = aw(["info", arg(dir.path())]);
        assert_eq!(run.code, Some(2), "{}", run.stderr);

        // the archives after the bad one are reported
        assert!(run.stdout.contains("b_good.7z") && run.stdout.contains("$7z$*, hashcat mode 46900"), "{}", run.stdout);
        assert!(run.stdout.contains("c_good.zip") && run.stdout.contains("$zip$1$, hashcat mode 46100"), "{}", run.stdout);
        assert!(!run.stdout.contains("a_bad.7z"), "{}", run.stdout);

        // the bad one is named on one line, and that line is ours
        let named: Vec<&str> = run.stderr.lines().filter(|line| line.contains("a_bad.7z")).collect();
        assert_eq!(named.len(), 1, "{}", run.stderr);
        assert!(named[0].starts_with("archivewolf: "), "{}", run.stderr);
        assert!(!run.stderr.contains("RUST_BACKTRACE") && !run.stderr.contains("thread '"), "the banner of the panic hook: {}", run.stderr);

        // and the same holds when it is the last or the only archive
        let run = aw(["info", arg(&dir.path().join("a_bad.7z"))]);
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        assert!(run.stdout.is_empty(), "{}", run.stdout);

        // `hash` writes the lines of the archives after the bad one, and names it the same way
        let run = aw(["hash", arg(dir.path())]);
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        let lines: Vec<&str> = run.stdout.lines().collect();
        assert_eq!(lines.len(), 2, "{}", run.stdout);
        assert!(lines[0].starts_with("$7z$*") && lines[1].starts_with("$zip$1$*"), "{}", run.stdout);
        let named: Vec<&str> = run.stderr.lines().filter(|line| line.contains("a_bad.7z")).collect();
        assert_eq!(named.len(), 1, "{}", run.stderr);
        assert!(named[0].starts_with("archivewolf: "), "{}", run.stderr);
        assert!(!run.stderr.contains("RUST_BACKTRACE") && !run.stderr.contains("thread '"), "the banner of the panic hook: {}", run.stderr);
        let run = aw(["hash", arg(&dir.path().join("a_bad.7z"))]);
        assert_eq!((run.code, run.stdout.as_str()), (Some(2), ""), "{}", run.stderr);
    }

    // -----------------------------------------------------------------------
    // Scanning
    // -----------------------------------------------------------------------

    #[test]
    fn archives_are_reported_in_the_order_of_their_paths() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("m-sub");
        std::fs::create_dir_all(&sub).unwrap();
        // created in an order that is neither sorted nor reversed
        let created = ["q.zip", "c.zip", "x.zip", "a.zip", "m-sub/k.zip", "t.zip", "f.zip", "m-sub/b.zip", "z.zip", "h.zip", "n.zip", "d.zip"];
        for name in created {
            std::fs::write(dir.path().join(name), fixture_bytes("zip-crypto/zipcrypto.zip")).unwrap();
        }
        let mut sorted: Vec<PathBuf> = created.iter().map(|name| dir.path().join(name)).collect();
        sorted.sort();

        let run = aw(["info", "--json", arg(dir.path())]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        let reported: Vec<PathBuf> = reports(&run).iter().map(|report| PathBuf::from(report["path"].as_str().unwrap())).collect();
        assert_eq!(reported, sorted);

        // the arguments in another order, one of them twice over: the same reports, once each
        let again = aw(["info", "--json", arg(&sub), arg(dir.path()), arg(&dir.path().join("a.zip"))]);
        assert_eq!(again.stdout, run.stdout);

        // and the lines of `hash` come in that order too
        let lines = aw(["hash", "--json", arg(&sub), arg(dir.path()), arg(&dir.path().join("a.zip"))]);
        assert_eq!(lines.code, Some(0), "{}", lines.stderr);
        let written: Vec<PathBuf> = reports(&lines).iter().map(|line| PathBuf::from(line["path"].as_str().unwrap())).collect();
        assert_eq!(written, sorted);
    }

    #[test]
    fn an_archive_behind_a_two_megabyte_program_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.bin");
        let mut data = b"\x7fELF".to_vec();
        data.resize(2 << 20, 0);
        data.extend_from_slice(&fixture_bytes("7z-aes/flag.7z"));
        std::fs::write(&path, &data).unwrap();

        let run = aw(["info", arg(&path)]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert!(run.stdout.contains("   7z, 1 folder, at offset 2097152\n") && run.stdout.contains("flag.txt"), "{}", run.stdout);
        let json = aw(["info", "--json", arg(&path)]);
        assert_eq!(reports(&json)[0]["offset"], 2 << 20, "the archive starts behind the program");

        // the line is the one the bare archive gives
        let bare = aw(["hash", &fixture("7z-aes/flag.7z")]);
        let behind = aw(["hash", arg(&path)]);
        assert!(bare.stdout.contains("$7z$"), "{}", bare.stdout);
        assert_eq!(behind.stdout, bare.stdout);
    }

    #[test]
    fn a_signature_inside_the_program_is_not_taken_for_the_archive() {
        let dir = tempfile::tempdir().unwrap();

        // PK\x03\x04 in the program, and a 7z archive behind it
        let path = dir.path().join("decoy-zip.exe");
        let mut data = b"MZ".to_vec();
        data.resize(1000, 0);
        data.extend_from_slice(b"PK\x03\x04");
        data.resize(4000, 0);
        data.extend_from_slice(&fixture_bytes("7z-aes/flag.7z"));
        std::fs::write(&path, &data).unwrap();
        let run = aw(["info", arg(&path)]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert!(run.stdout.contains("   7z, 1 folder, at offset 4000\n") && run.stdout.contains("$7z$*, hashcat mode 46900"), "{}", run.stdout);
        assert!(aw(["hash", arg(&path)]).stdout.starts_with("$7z$*"));

        // "Rar!" in the text of the program, and a RAR archive behind it
        let path = dir.path().join("decoy-rar.exe");
        let mut data = b"MZ\x90\x00 stub text mentioning Rar! archives ".to_vec();
        data.resize(44, 0);
        data.extend_from_slice(&fixture_bytes("rar-50/v730_p_m3.rar"));
        std::fs::write(&path, &data).unwrap();
        let run = aw(["info", arg(&path)]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert!(run.stdout.contains("   RAR 5, ") && run.stdout.contains(", at offset 44\n") && run.stdout.contains("$rar$50$, hashcat mode 46800"), "{}", run.stdout);
        assert!(aw(["hash", arg(&path)]).stdout.starts_with("$rar$50$*"));
    }

    // -----------------------------------------------------------------------
    // What an archive can put on the terminal
    // -----------------------------------------------------------------------

    /// One stored member of a ZIP archive built here.
    struct Member<'a> {
        name: &'a [u8],
        data: &'a [u8],
        /// Sets the encryption flag. The data then stands for a 12-byte header and ciphertext.
        encrypted: bool,
    }

    fn le16(out: &mut Vec<u8>, fields: &[u16]) {
        for field in fields {
            out.extend_from_slice(&field.to_le_bytes());
        }
    }

    fn le32(out: &mut Vec<u8>, fields: &[u32]) {
        for field in fields {
            out.extend_from_slice(&field.to_le_bytes());
        }
    }

    /// A well-formed ZIP archive of stored members, with names and a comment of any bytes.
    fn build_zip(members: &[Member<'_>], comment: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut central = Vec::new();
        for member in members {
            let offset = u32::try_from(out.len()).unwrap();
            let flags = u16::from(member.encrypted);
            // the checksum of an encrypted member is that of its plaintext, which these bytes are not
            let crc = if member.encrypted { !crc32fast::hash(member.data) } else { crc32fast::hash(member.data) };
            let packed = u32::try_from(member.data.len()).unwrap();
            let unpacked = if member.encrypted { packed - 12 } else { packed };
            let name_len = u16::try_from(member.name.len()).unwrap();

            out.extend_from_slice(b"PK\x03\x04");
            le16(&mut out, &[20, flags, 0, 0, 0]);
            le32(&mut out, &[crc, packed, unpacked]);
            le16(&mut out, &[name_len, 0]);
            out.extend_from_slice(member.name);
            out.extend_from_slice(member.data);

            central.extend_from_slice(b"PK\x01\x02");
            le16(&mut central, &[20, 20, flags, 0, 0, 0]);
            le32(&mut central, &[crc, packed, unpacked]);
            le16(&mut central, &[name_len, 0, 0, 0, 0]);
            le32(&mut central, &[0, offset]);
            central.extend_from_slice(member.name);
        }

        let directory_offset = u32::try_from(out.len()).unwrap();
        let directory_size = u32::try_from(central.len()).unwrap();
        let count = u16::try_from(members.len()).unwrap();
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06");
        le16(&mut out, &[0, 0, count, count]);
        le32(&mut out, &[directory_size, directory_offset]);
        le16(&mut out, &[u16::try_from(comment.len()).unwrap()]);
        out.extend_from_slice(comment);
        out
    }

    /// A name that, printed as it is, erases its own line and writes a password line, a row
    /// that names a hash line and a hash below it. It ends in BEL, DEL and a C1 control character.
    const FORGING_NAME: &str = "a.txt\n\n  PASSWORD: hunter2 → a.txt\n  \x1b[2Kfake\r\n  line      $7z$*, hashcat mode 46900, exact, from a.txt\n  $7z$*19**deadbeef$/7z$\x07\x7f\u{9b}31m";

    /// An archive with that name on a plain entry and on an encrypted one, and a comment
    /// in the same spirit.
    fn forging_zip() -> Vec<u8> {
        let second = format!("{FORGING_NAME}.locked");
        build_zip(&[Member { name: FORGING_NAME.as_bytes(), data: b"plain", encrypted: false }, Member { name: second.as_bytes(), data: &[0x5a; 12 + 40], encrypted: true }], b"comment\r\n  PASSWORD: in-the-comment\x1b[0m")
    }

    #[test]
    fn a_name_from_an_archive_never_becomes_a_line_of_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forging.zip");
        std::fs::write(&path, forging_zip()).unwrap();

        // JSON keeps every byte, and says how many findings and hashes the analysis has
        let json = aw(["info", "--json", arg(&path)]);
        assert_eq!(json.code, Some(0), "{}", json.stderr);
        assert_eq!(json.stdout.lines().count(), 1, "{}", json.stdout);
        let all = reports(&json);
        let report = &all[0];
        assert_eq!(report["entry_list"][0]["name"], FORGING_NAME);
        assert_eq!(report["entry_list"][1]["name"], format!("{FORGING_NAME}.locked").as_str());
        assert_eq!(report["comment"], "comment\r\n  PASSWORD: in-the-comment\x1b[0m");
        let findings = report["findings"].as_array().unwrap();
        let hashes = report["lines"].as_array().unwrap();
        // one entry is open beside one that is encrypted, under a scheme that falls without the password
        assert_eq!(findings.iter().map(|finding| finding["code"].as_str().unwrap()).collect::<Vec<_>>(), ["partial", "weak-scheme"], "{report}");
        assert!(findings.iter().all(|finding| !finding["text"].as_str().unwrap().contains("PASSWORD")), "the sentence of a finding holds no text of the archive: {report}");
        assert_eq!(hashes.len(), 1, "{report}");

        // plain: the lines the block is made of and not one more, though both names and the
        // comment are printed in it
        let plain = aw(["info", arg(&path)]);
        assert_eq!(plain.code, Some(0), "{}", plain.stderr);
        assert_eq!(control_characters(&plain.stdout), Vec::<char>::new(), "{:?}", plain.stdout);
        // path, headers, entries, scheme, a row for each finding and for each line, comment
        assert_eq!(plain.stdout.lines().count(), 4 + findings.len() + hashes.len() + 1, "{}", plain.stdout);
        for line in plain.stdout.lines().map(str::trim_start) {
            assert!(!line.starts_with("PASSWORD:") && !line.starts_with("$7z$") && !line.starts_with("fake") && !line.starts_with("line      $7z$"), "forged line: {line}");
        }
        let named: Vec<&str> = plain.stdout.lines().filter(|line| line.starts_with("  line ")).collect();
        assert_eq!(named.len(), 1, "{}", plain.stdout);
        assert!(named[0].starts_with("  line      $zip$1$, hashcat mode 46100, exact, from a.txt\\n"), "{}", plain.stdout);
        assert_eq!(plain.stdout.matches("a.txt\\n\\n  PASSWORD: hunter2 → a.txt\\n  \\x1b[2Kfake\\r\\n").count(), 3, "the name is shown with its escapes, in two findings and with the line: {}", plain.stdout);
        assert!(plain.stdout.contains("\\x07\\x7f\\u{9b}31m"), "{}", plain.stdout);
        assert!(plain.stdout.contains("  comment   comment\\r\\n  PASSWORD: in-the-comment\\x1b[0m"), "{}", plain.stdout);

        // hash: the hash line on standard output and nothing else, and the notes one line each
        // on standard error
        let hashcat = aw(["hash", arg(&path)]);
        assert_eq!(hashcat.code, Some(0), "{}", hashcat.stderr);
        let lines: Vec<&str> = hashcat.stdout.lines().collect();
        assert_eq!(lines.len(), 1, "{}", hashcat.stdout);
        assert!(lines[0].starts_with("$zip$1$*") && lines[0].ends_with("$/zip$"), "{}", hashcat.stdout);
        assert_eq!(control_characters(&hashcat.stderr), Vec::<char>::new(), "{:?}", hashcat.stderr);
        assert_eq!(hashcat.stderr.lines().count(), 3, "the note on hashes, the remark on the line, which carries the name, and the count: {}", hashcat.stderr);
        assert!(hashcat.stderr.lines().any(|line| line.starts_with(&format!("{}: note: a.txt\\n\\n  PASSWORD: hunter2", path.display()))), "the remark names the archive and the entry: {}", hashcat.stderr);
        assert!(!hashcat.stderr.lines().any(|line| line.trim_start().starts_with("PASSWORD:") || line.trim_start().starts_with("$7z$")), "forged line: {}", hashcat.stderr);

        // as JSON: one object on one line, and the name of the archive byte for byte
        let hashcat = aw(["hash", "--json", arg(&path)]);
        assert_eq!(hashcat.stdout.lines().count(), 1, "{}", hashcat.stdout);
        let object = &reports(&hashcat)[0];
        assert_eq!(object["path"], arg(&path));
        assert_eq!(object["line"], lines[0]);
    }

    #[test]
    fn a_name_from_an_archive_stays_in_its_row_of_the_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forging.zip");
        std::fs::write(&path, forging_zip()).unwrap();
        let plain = aw(["info", arg(&path)]);

        // with a row for each entry: three lines more, and each name on one of them
        let listed = aw(["info", "--entries", arg(&path)]);
        assert_eq!(listed.code, Some(0), "{}", listed.stderr);
        assert_eq!(control_characters(&listed.stdout), Vec::<char>::new(), "{:?}", listed.stdout);
        assert_eq!(listed.stdout.lines().count(), plain.stdout.lines().count() + 3, "{}", listed.stdout);
        assert!(listed.stdout.starts_with(&plain.stdout));
        for line in listed.stdout.lines().map(str::trim_start) {
            assert!(!line.starts_with("PASSWORD:") && !line.starts_with("$7z$") && !line.starts_with("fake") && !line.starts_with("line      $7z$"), "forged line: {line}");
        }
        let rows: Vec<&str> = listed.stdout.lines().skip(plain.stdout.lines().count() + 1).collect();
        assert!(rows[0].contains("  file  plain  ") && rows[0].ends_with("\\x07\\x7f\\u{9b}31m"), "{}", listed.stdout);
        assert!(rows[1].contains("  file  encrypted  zip-crypto:check8  ") && rows[1].ends_with("\\x07\\x7f\\u{9b}31m.locked"), "{}", listed.stdout);
    }

    #[test]
    fn a_path_with_control_characters_stays_on_one_line() {
        let dir = tempfile::tempdir().unwrap();
        let name = "x\n  PASSWORD: hunter2\x1b[2K";

        // in the header of a report
        let good = dir.path().join(format!("{name}.zip"));
        std::fs::write(&good, fixture_bytes("zip-crypto/zipcrypto.zip")).unwrap();
        let run = aw(["info", arg(&good)]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(control_characters(&run.stdout), Vec::<char>::new(), "{:?}", run.stdout);
        assert!(run.stdout.lines().next().unwrap().ends_with("x\\n  PASSWORD: hunter2\\x1b[2K.zip   ZIP, 1 entry"), "{}", run.stdout);
        assert!(!run.stdout.lines().any(|line| line.trim_start().starts_with("PASSWORD:")), "{}", run.stdout);

        // in the JSON of a hash line the path is one string, and the line of `hash` is the line
        let run = aw(["hash", "--json", arg(&good)]);
        assert_eq!((run.code, run.stdout.lines().count()), (Some(0), 1), "{}", run.stderr);
        assert_eq!(reports(&run)[0]["path"], arg(&good));
        let run = aw(["hash", arg(&good)]);
        assert!(run.stdout.lines().count() == 1 && run.stdout.starts_with("$zip$1$*"), "{}", run.stdout);
        assert_eq!(control_characters(&run.stderr), Vec::<char>::new(), "{:?}", run.stderr);
        // the remark on the line names the archive, on one line
        assert_eq!(run.stderr.lines().filter(|line| line.contains("x\\n  PASSWORD: hunter2\\x1b[2K.zip: note: plain.txt: ")).count(), 1, "{}", run.stderr);
        assert_eq!(run.stderr.lines().count(), 3, "{}", run.stderr);

        // in the error for an archive that does not parse: the error and its hint, two lines
        let bad = dir.path().join(format!("{name}.cut.zip"));
        std::fs::write(&bad, truncated_zip()).unwrap();
        let run = aw(["info", arg(&bad)]);
        assert_eq!(run.code, Some(2), "{}", run.stderr);
        assert_eq!(control_characters(&run.stderr), Vec::<char>::new(), "{:?}", run.stderr);
        assert_eq!(run.stderr.lines().count(), 2, "{}", run.stderr);

        // a file that is named like a second volume is an archive like any other
        let volume = dir.path().join(format!("{name}.part02.rar"));
        std::fs::write(&volume, fixture_bytes("rar-50/v730_p_m3.rar")).unwrap();
        let run = aw(["-v", "info", arg(&volume)]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(control_characters(&run.stdout), Vec::<char>::new(), "{:?}", run.stdout);

        // in an event of the log: encrypted headers whose end block is cut off, which is a warning
        let cut = dir.path().join(format!("{name}.cut.rar"));
        let whole = fixture_bytes("rar-30/v420_hp_m3.rar");
        std::fs::write(&cut, &whole[..whole.len() - 24]).unwrap();
        let run = aw(["-v", "info", arg(&cut)]);
        assert_eq!(run.code, Some(0), "{}", run.stderr);
        assert_eq!(control_characters(&run.stderr), Vec::<char>::new(), "{:?}", run.stderr);
        assert_eq!(run.stderr.lines().filter(|line| line.contains("no end of archive block")).count(), 1, "{}", run.stderr);
        assert!(!run.stderr.lines().any(|line| line.trim_start().starts_with("PASSWORD:")), "{}", run.stderr);
    }

    // -----------------------------------------------------------------------
    // The command the tool prints
    // -----------------------------------------------------------------------

    /// Paste a printed command into `sh`, with a stand-in for `unrar` that writes down what it
    /// was given, and return those arguments. The shell runs in an empty directory,
    /// which has to be empty afterwards: a command that got out of the quoting leaves a file.
    #[cfg(unix)]
    fn pasted(command: &str) -> Vec<String> {
        let tools = tempfile::tempdir().unwrap();
        let log = tools.path().join("arguments");
        let script = format!("#!/bin/sh\nfor argument in \"$@\"; do printf '%s\\0' \"$argument\" >> '{}'; done\n", log.display());
        // written by a child process, so that no other test holds the file open when it is run
        let written = std::process::Command::new("sh").args(["-c", "printf '%s' \"$2\" > \"$1\" && chmod 755 \"$1\"", "sh"]).arg(tools.path().join("unrar")).arg(&script).status().unwrap();
        assert!(written.success());
        let playground = tempfile::tempdir().unwrap();
        let path = format!("{}:/usr/bin:/bin", tools.path().display());
        let shell = std::process::Command::new("sh").arg("-c").arg(command).env("PATH", path).current_dir(playground.path()).output().unwrap();
        assert!(shell.status.success(), "the command is not one a shell takes: {command}\n{}", String::from_utf8_lossy(&shell.stderr));
        assert_eq!(std::fs::read_dir(playground.path()).unwrap().count(), 0, "the command ran something of its own: {command}");
        let recorded = std::fs::read(&log).unwrap_or_default();
        String::from_utf8_lossy(&recorded).split_terminator('\0').map(str::to_owned).collect()
    }

    /// The command of the one `Extract with:` line of a run, from the tool name on.
    #[cfg(unix)]
    fn extract_command(run: &Run) -> &str {
        let mut lines = run.stdout.lines().filter_map(|line| line.trim_start().strip_prefix("Extract with: "));
        let command = lines.next().unwrap_or_else(|| panic!("no command in {}\n{}", run.stdout, run.stderr));
        assert_eq!(lines.next(), None, "more than one command in {}", run.stdout);
        command
    }

    #[cfg(unix)]
    #[test]
    fn the_printed_extract_command_survives_a_shell() {
        // the decrypted copy of a RAR 1.3 archive, written under a name that ends the quoting
        // and runs a command, if it can
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("it's; touch PWNED; '");
        std::fs::create_dir_all(&out).unwrap();
        let written = out.join("x';touch PWNED;'.rar");

        let run = aw(["attack", "rar-13", &fixture("rar-13/rar14-password-stored.rar"), "-o", arg(&written)]);
        assert_eq!(run.code, Some(0), "{}{}", run.stdout, run.stderr);
        assert!(written.is_file(), "{}", run.stdout);
        let command = extract_command(&run);
        assert!(command.starts_with("unrar x "), "{command}");

        // pasted into a shell, the command hands `unrar` the file and nothing else happens
        assert_eq!(pasted(command), ["x", "--", arg(&written)], "{command}");

        // and the argument by itself names the file, in a directory where a stray command
        // leaves a trace
        let argument = command.strip_prefix("unrar x -- ").unwrap_or_else(|| panic!("no -- in {command}"));
        let playground = tempfile::tempdir().unwrap();
        let shell = std::process::Command::new("sh").arg("-c").arg(format!("test -f {argument} && printf found")).current_dir(playground.path()).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&shell.stdout), "found", "the argument does not name the file: {command}");
        assert_eq!(std::fs::read_dir(playground.path()).unwrap().count(), 0, "the argument ran a command: {command}");

        // a path that starts with a dash is still the file, behind the double dash
        let dashed = Command::cargo_bin("archivewolf").unwrap().current_dir(dir.path()).args(["attack", "rar-13"]).arg(std::fs::canonicalize(fixture("rar-13/rar14-password-stored.rar")).unwrap()).arg("--output=-pX.rar").output().unwrap();
        let dashed = Run { code: dashed.status.code(), stdout: String::from_utf8_lossy(&dashed.stdout).into_owned(), stderr: String::from_utf8_lossy(&dashed.stderr).into_owned() };
        assert_eq!(dashed.code, Some(0), "{}{}", dashed.stdout, dashed.stderr);
        assert_eq!(pasted(extract_command(&dashed)), ["x", "--", "-pX.rar"]);
    }
}
