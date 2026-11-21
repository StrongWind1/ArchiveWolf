//! `attack zip-crypto` from end to end, as a user runs it: the command finds the keys of an
//! archive from what it is given, proves them, and says what they open; and it finds nothing,
//! and says why, when what it is given is wrong.
//!
//! The searches here are short: a file or some hundred bytes of one are known, which leaves a
//! few thousand candidates. The long searches, where a signature or eight bytes are all there
//! is, are in `make test-zip-crypto`.

#![expect(unused_crate_dependencies, reason = "integration test")]

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Output;

    use archivewolf_zip_crypto::Keys;
    use assert_cmd::Command;
    use serde_json::Value;

    /// The archive of the tutorial of bkcrack: `advice.jpg` packed and `spiral.svg` stored,
    /// written by 7-Zip under one password.
    const SECRETS: &str = "tests/fixtures/zip-crypto/bkcrack-src_secrets.zip";
    /// Its keys, and the three lines the command prints for them.
    const KEYS: [&str; 3] = ["keys c4490e28 b414a23d 91404b31", "$zip$4$*0*c4490e28*b414a23d*91404b31$/zip$", "$zip$4$*1*c4490e28*b414a23d*91404b31$/zip$"];

    /// Where the command keeps the speed of the machine while the tests run.
    ///
    /// The command measures its speed once and keeps it in the cache directory of the user.
    /// A measurement that is taken while every other test searches is far too low, and what an
    /// attempt is estimated to take decides whether it is started under a budget: so the tests
    /// put a speed there themselves, the same for every run, of 10,000 candidates a second.
    fn cache() -> PathBuf {
        cache_of("zip-crypto-test-cache", archivewolf_zip_crypto::Kernel::best(), std::thread::available_parallelism().map_or(1, std::num::NonZero::get), 10_000.0)
    }

    /// A cache directory under `target/` that holds a speed of a kernel for a count of
    /// threads. The command searches with the kernel its cache names.
    fn cache_of(name: &str, kernel: archivewolf_zip_crypto::Kernel, threads: usize, rate: f64) -> PathBuf {
        let cache = Path::new(env!("CARGO_MANIFEST_DIR")).join("target").join(name);
        let processor = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|text| text.lines().find(|line| line.starts_with("model name")).and_then(|line| line.split_once(':')).map(|(_, name)| name.trim().to_owned())).unwrap_or_else(|| std::env::consts::ARCH.to_owned());
        let kept = serde_json::json!({ "processor": processor, "kernel": kernel.name(), "threads": threads, "rate": rate });
        // written beside its place and moved there, so that no other test reads half of it
        let file = cache.join("archivewolf/zip-crypto-speed.json");
        if std::fs::read_to_string(&file).ok().as_deref() != Some(kept.to_string().as_str()) {
            std::fs::create_dir_all(cache.join("archivewolf")).unwrap();
            let beside = cache.join(format!("archivewolf/speed-{}.tmp", std::process::id()));
            std::fs::write(&beside, kept.to_string()).unwrap();
            std::fs::rename(&beside, &file).unwrap();
        }
        cache
    }

    /// `archivewolf attack zip-crypto` with these arguments.
    fn attack(args: &[&str]) -> Output {
        Command::cargo_bin("archivewolf").unwrap().args(["attack", "zip-crypto"]).args(args).env("XDG_CACHE_HOME", cache()).env_remove("RUST_LOG").output().unwrap()
    }

    /// The command on four threads of a machine that is said to search a hundred candidates a
    /// second. A state is written every ten seconds of search at the measured speed, which is
    /// every thousand candidates here: a search of some thousand is kept in several stretches.
    fn attack_kept(args: &[&str]) -> Output {
        let cache = cache_of("zip-crypto-test-cache-slow", archivewolf_zip_crypto::Kernel::best(), 4, 100.0);
        Command::cargo_bin("archivewolf").unwrap().args(["attack", "zip-crypto", "--threads", "4", "--budget", "none"]).args(args).env("XDG_CACHE_HOME", cache).env_remove("RUST_LOG").output().unwrap()
    }

    /// A ZIP archive of one stored entry under `zip-crypto`, as a writer of one check byte makes it.
    fn archive_of(name: &str, content: &[u8], password: &str) -> Vec<u8> {
        let crc = crc32fast::hash(content);
        let mut keys = Keys::from_password(password.as_bytes());
        let header: Vec<u8> = (0..11_u8).map(|byte| byte.wrapping_mul(37).wrapping_add(11)).chain([crc.to_be_bytes()[0]]).collect();
        let data: Vec<u8> = header.iter().chain(content).map(|&byte| keys.encrypt(byte)).collect();
        let (packed, size, name_len) = (u32::try_from(data.len()).unwrap(), u32::try_from(content.len()).unwrap(), u16::try_from(name.len()).unwrap());
        // version, flags, method, time, date, CRC-32, sizes, lengths of the name and of the extra fields
        let fields: Vec<u8> = [&20_u16.to_le_bytes()[..], &1_u16.to_le_bytes(), &0_u16.to_le_bytes(), &0x6000_u16.to_le_bytes(), &0x5b74_u16.to_le_bytes(), &crc.to_le_bytes(), &packed.to_le_bytes(), &size.to_le_bytes(), &name_len.to_le_bytes(), &0_u16.to_le_bytes()].concat();
        let local = [b"PK\x03\x04", &fields[..], name.as_bytes(), &data].concat();
        // made by 2.0 on FAT, then the same fields, comment, disk, attributes and the offset of the local header
        let central = [b"PK\x01\x02", &20_u16.to_le_bytes()[..], &fields, &[0; 10], &0_u32.to_le_bytes(), name.as_bytes()].concat();
        let end = [b"PK\x05\x06", &[0; 4][..], &1_u16.to_le_bytes(), &1_u16.to_le_bytes(), &u32::try_from(central.len()).unwrap().to_le_bytes(), &u32::try_from(local.len()).unwrap().to_le_bytes(), &0_u16.to_le_bytes()].concat();
        [local, central, end].concat()
    }

    /// The lines of a plan that do not depend on the machine: without its speed and its times.
    fn plan_of(said: &str) -> Vec<String> {
        said.lines().filter(|line| !line.starts_with("measuring ")).map(|line| line.split([';', ',']).next().unwrap_or(line).to_owned()).collect()
    }

    fn lines(bytes: &[u8]) -> Vec<String> {
        String::from_utf8_lossy(bytes).lines().map(str::to_owned).collect()
    }

    /// The content of a stored entry of an archive, decrypted with the keys of its password.
    fn stored(archive: &str, name: &str, password: &str) -> Vec<u8> {
        let bytes = std::fs::read(archive).unwrap();
        let mut at = 0;
        loop {
            assert_eq!(&bytes[at..at + 4], b"PK\x03\x04", "{archive}: no entry named {name}");
            let field = |offset: usize| usize::from(u16::from_le_bytes([bytes[at + offset], bytes[at + offset + 1]]));
            let packed = usize::try_from(u32::from_le_bytes(bytes[at + 18..at + 22].try_into().unwrap())).unwrap();
            let data = at + 30 + field(26) + field(28);
            if &bytes[at + 30..at + 30 + field(26)] == name.as_bytes() {
                let mut keys = Keys::from_password(password.as_bytes());
                let plain: Vec<u8> = bytes[data..data + packed].iter().map(|&byte| keys.decrypt(byte)).collect();
                return plain[12..].to_vec();
            }
            at = data + packed;
        }
    }

    /// The bytes of `gen_infozip_did_not_pack.zip`: an xorshift generator, as its row in
    /// `FIXTURES.md` says.
    fn noise(count: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..count)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[3]
            })
            .collect()
    }

    fn write(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn a_file_that_is_in_the_archive_gives_its_keys_and_they_are_proved() {
        let dir = tempfile::tempdir().unwrap();
        let known = write(&dir, "drawing.svg", &stored(SECRETS, "spiral.svg", "W4sF0rgotten"));
        let output = attack(&[SECRETS, "--known", known.to_str().unwrap()]);
        assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
        // standard output is the result and nothing else
        assert_eq!(lines(&output.stdout), KEYS);

        let said = String::from_utf8_lossy(&output.stderr);
        for part in [
            "bkcrack-src_secrets.zip: 2 entries under zip-crypto, written by 7-Zip",
            "the plan, budget 15 minutes",
            "(CRC-32 and size)   1,266 bytes in a row",
            "certain",
            "[1/",
            "keys found at candidate ",
            "proof: decrypts spiral.svg to its CRC-32",
            "keys found on spiral.svg (stored, matched file ",
            "proved: decrypts spiral.svg to its CRC-32",
            "the keys open 2 of 2 encrypted entries",
        ] {
            assert!(said.contains(part), "no {part:?} in:\n{said}");
        }
        // nothing of the file reaches the terminal but its path
        assert!(!said.contains("<?xml"), "{said}");
    }

    #[test]
    fn bytes_at_a_position_give_the_keys_and_the_same_bytes_at_another_do_not() {
        let plain = stored(SECRETS, "spiral.svg", "W4sF0rgotten");
        let given = format!("spiral.svg@200={}", hex::encode(&plain[200..700]));
        let output = attack(&[SECRETS, "--bytes", &given, "--only", "run", "--entry", "spiral.svg", "--budget", "15s"]);
        assert_eq!((output.status.code(), lines(&output.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{}", String::from_utf8_lossy(&output.stderr));

        // one position further on the bytes are not there: no keys, and the reason is said
        let wrong = format!("spiral.svg@201={}", hex::encode(&plain[200..700]));
        let output = attack(&[SECRETS, "--bytes", &wrong, "--budget", "15s"]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{said}");
        assert!(output.stdout.is_empty());
        assert!(said.contains("no keys. All ") && said.contains("The claim was a guess, and the guess was wrong."), "{said}");
        // the attempts on the signature of the file take longer than the budget: they are named and not started
        assert!(said.contains("not started. It takes about ") && said.contains("--budget "), "{said}");
        assert!(said.contains("what would help most: one file that is in the archive, in any version (--known)"), "{said}");
    }

    #[test]
    fn a_version_of_a_file_is_tried_in_windows_and_one_wrong_byte_in_each_finds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut plain = stored(SECRETS, "spiral.svg", "W4sF0rgotten");
        // the byte lies in the window at the start of the file and in the one at its end
        plain[600] ^= 1;
        std::fs::create_dir_all(dir.path().join("old")).unwrap();
        drop(write(&dir, "old/spiral.svg", &plain));
        let output = attack(&[SECRETS, "--known", dir.path().to_str().unwrap(), "--budget", "15s"]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{said}");
        assert!(output.stdout.is_empty());
        assert_eq!(said.matches("spiral.svg: no keys. All ").count(), 2, "{said}");
        assert!(said.contains("window of the similar file "), "{said}");

        // the same file with its end as it is in the archive: the window at the end gives the keys
        let mut plain = stored(SECRETS, "spiral.svg", "W4sF0rgotten");
        plain[100] ^= 1;
        drop(write(&dir, "old/spiral.svg", &plain));
        let output = attack(&[SECRETS, "--known", dir.path().to_str().unwrap(), "--budget", "15s"]);
        assert_eq!((output.status.code(), lines(&output.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{}", String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    fn data_that_did_not_pack_is_as_good_as_stored() {
        // Info-ZIP wrote the 40,000 bytes as Deflate in two stored blocks: the file lies five bytes into the stream
        let archive = "tests/fixtures/zip-crypto/gen_infozip_did_not_pack.zip";
        let dir = tempfile::tempdir().unwrap();
        let known = write(&dir, "what-it-was.bin", &noise(40_000, 2026));
        let output = attack(&[archive, "--known", known.to_str().unwrap()]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{said}");
        let keys = Keys::from_password(b"own-noise");
        assert_eq!(lines(&output.stdout)[0], format!("keys {keys}"));
        assert!(said.contains("written by Info-ZIP") && said.contains("Deflate, did not pack"), "{said}");
        assert!(said.contains("keys found on noise.bin (Deflate, did not pack, matched file "), "{said}");
        assert!(said.contains("proved: decrypts noise.bin to its CRC-32"), "{said}");
    }

    #[test]
    fn the_file_of_a_packed_entry_is_packed_as_its_writer_did_and_gives_the_keys() {
        // Info-ZIP packed this entry at its highest level, as the flags of the entry say
        let archive = "tests/fixtures/zip-crypto/gen_infozip_deflate.zip";
        let bytes = std::fs::read(archive).unwrap();
        let name_len = usize::from(u16::from_le_bytes([bytes[26], bytes[27]])) + usize::from(u16::from_le_bytes([bytes[28], bytes[29]]));
        let packed = usize::try_from(u32::from_le_bytes(bytes[18..22].try_into().unwrap())).unwrap();
        let mut keys = Keys::from_password(b"iz-deflate");
        let stream: Vec<u8> = bytes[30 + name_len..30 + name_len + packed].iter().map(|&byte| keys.decrypt(byte)).collect();
        let mut content = Vec::new();
        let _ = std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(&stream[12..]), &mut content).unwrap();
        assert!(content.len() > stream.len());

        let dir = tempfile::tempdir().unwrap();
        let known = write(&dir, "the-file.txt", &content);
        let output = attack(&[archive, "--known", known.to_str().unwrap()]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{said}");
        assert_eq!(lines(&output.stdout)[0], format!("keys {}", Keys::from_password(b"iz-deflate")));
        assert!(said.contains("packed with 31 packers, and ") && said.contains(&format!(" of them give the {} bytes of", stream.len() - 12)), "{said}");
        assert!(said.contains("packed as Info-ZIP level 9 does") && said.contains("keys found on "), "{said}");
        assert!(said.contains("proved: decrypts "), "{said}");
    }

    #[test]
    fn entries_under_another_password_are_reported_closed_and_reject_no_key() {
        // `first.txt` and `second.txt` are under two passwords
        let archive = "tests/fixtures/zip-crypto/gen_own_zc_two_passwords.zip";
        let dir = tempfile::tempdir().unwrap();
        let known = write(&dir, "first.txt", &stored(archive, "first.txt", "own-first"));
        let output = attack(&[archive, "--known", known.to_str().unwrap()]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{said}");
        assert_eq!(lines(&output.stdout)[0], format!("keys {}", Keys::from_password(b"own-first")));
        assert!(said.contains("the keys open 1 of 2 encrypted entries"), "{said}");
        assert!(said.contains("not opened: second.txt (another password)"), "{said}");
    }

    #[test]
    fn keys_from_an_earlier_run_are_tested_on_every_entry_and_nothing_is_searched() {
        let output = attack(&[SECRETS, "--keys", "c4490e28", "b414a23d", "91404b31"]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!((output.status.code(), lines(&output.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{said}");
        assert!(said.contains("given, not searched for") && said.contains("the keys open 2 of 2 encrypted entries") && !said.contains("the plan"), "{said}");

        // keys of another password open nothing: that is no result
        let output = attack(&[SECRETS, "--keys", "c4490e28", "b414a23d", "91404b30"]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{said}");
        assert!(said.contains("the keys open 0 of 2 encrypted entries") && said.contains("not opened: advice.jpg, spiral.svg"), "{said}");
    }

    #[test]
    fn a_password_of_six_bytes_or_fewer_is_worked_out_from_the_keys() {
        // `stored.zip` is under the password `pass`
        let archive = "tests/fixtures/zip-crypto/stored.zip";
        let keys = Keys::from_password(b"pass");
        let output = attack(&[archive, "--keys", &format!("{:08x}", keys.x), &format!("{:08x}", keys.y), &format!("{:08x}", keys.z)]);
        assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
        let printed = lines(&output.stdout);
        assert_eq!((printed.len(), printed[3].as_str()), (4, "password pass"));
    }

    #[test]
    fn the_plan_is_printed_and_nothing_is_searched() {
        let output = attack(&[SECRETS, "--plan"]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{said}");
        assert!(output.stdout.is_empty());
        for part in [
            "what is known",
            "1 check byte",
            "stored, type known from the name",
            "the plan, budget 15 minutes",
            "spiral.svg: signature of an XML file   20 bytes in a row",
            "likely",
            "not in the plan",
            "advice.jpg   a JPEG image, packed: its content does not show in its stream",
            "what would help most: ",
        ] {
            assert!(said.contains(part), "no {part:?} in:\n{said}");
        }
        assert!(!said.contains("[1/"), "{said}");
        // the same input gives the same plan
        assert_eq!(plan_of(&String::from_utf8_lossy(&attack(&[SECRETS, "--plan"]).stderr)), plan_of(&said));
        // -v names every claim, with its source and how sure it is
        let more = String::from_utf8_lossy(&attack(&[SECRETS, "--plan", "-v"]).stderr).into_owned();
        assert!(more.contains("claims") && more.contains("header     certain   the check byte, from the CRC-32") && more.contains("name       likely    signature of an XML file: 30 bytes known in a row, in 4 forms"), "{more}");
        // -q says nothing
        let quiet = Command::cargo_bin("archivewolf").unwrap().args(["-q", "attack", "zip-crypto", SECRETS, "--plan"]).env("XDG_CACHE_HOME", cache()).output().unwrap();
        assert!(quiet.stderr.is_empty() && quiet.stdout.is_empty() && quiet.status.code() == Some(0));
    }

    #[test]
    fn the_result_is_one_json_object_and_the_way_to_it_a_stream_of_events() {
        let dir = tempfile::tempdir().unwrap();
        let known = write(&dir, "spiral.svg", &stored(SECRETS, "spiral.svg", "W4sF0rgotten"));
        let output = attack(&[SECRETS, "--known", known.to_str().unwrap(), "--json", "-v"]);
        assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
        let printed = lines(&output.stdout);
        assert_eq!(printed.len(), 1);
        let result: Value = serde_json::from_str(&printed[0]).unwrap();
        assert_eq!(result["status"], "proved");
        assert_eq!(result["keys"], serde_json::json!(["c4490e28", "b414a23d", "91404b31"]));
        assert_eq!((result["entry"].as_str(), result["path"].as_str(), result["opens"].as_u64(), result["encrypted"].as_u64()), (Some("spiral.svg"), Some("run"), Some(2), Some(2)));
        assert_eq!(result["lines"], serde_json::json!([KEYS[1], KEYS[2]]));
        assert_eq!(result["entries"], serde_json::json!([{ "entry": "advice.jpg", "opened": "proved" }, { "entry": "spiral.svg", "opened": "proved" }]));
        assert!(result["password"].is_null() && result["bits"].as_f64().is_some_and(|bits| bits > 112.0));

        // every line of standard error is an event
        let events: Vec<Value> = lines(&output.stderr).iter().map(|line| serde_json::from_str(line).unwrap_or_else(|fault| panic!("{line}: {fault}"))).collect();
        let names: Vec<&str> = events.iter().filter_map(|event| event["event"].as_str()).filter(|name| *name != "progress").collect();
        assert_eq!(names, ["plan", "attempt-start", "attempt-end", "result"]);
        let plan = &events[0];
        assert_eq!((plan["attempts"][0]["entry"].as_str(), plan["attempts"][0]["path"].as_str(), plan["attempts"][0]["source"].as_str(), plan["attempts"][0]["certainty"].as_str(), plan["attempts"][0]["run"].as_u64()), (Some("spiral.svg"), Some("run"), Some("user"), Some("certain"), Some(1266)));
        assert_eq!((events[2]["outcome"].as_str(), events[3]["status"].as_str()), (Some("keys"), Some("proved")));
    }

    #[test]
    fn the_archive_is_written_without_its_password_to_a_file_that_is_not_there_yet() {
        let dir = tempfile::tempdir().unwrap();
        let known = write(&dir, "spiral.svg", &stored(SECRETS, "spiral.svg", "W4sF0rgotten"));
        let open = dir.path().join("open.zip");
        let output = attack(&[SECRETS, "--known", known.to_str().unwrap(), "-o", open.to_str().unwrap()]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!((output.status.code(), lines(&output.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{said}");
        assert!(said.contains("open.zip: 2 entries decrypted and still packed"), "{said}");

        // what was written is the same archive with nothing encrypted in it
        let info = Command::cargo_bin("archivewolf").unwrap().args(["info", "--json", open.to_str().unwrap()]).output().unwrap();
        let report: Value = serde_json::from_slice(&info.stdout).unwrap();
        assert_eq!((report["entries"]["total"].as_u64(), report["entries"]["encrypted"].as_u64(), report["coverage"].as_str()), (Some(2), Some(0), Some("none")));
        assert_eq!(std::fs::metadata(&open).unwrap().len() + 24, std::fs::metadata(SECRETS).unwrap().len());
        // and its stored entry is the file
        assert!(std::fs::read(&open).unwrap().windows(19).any(|window| window == b"<?xml version=\"1.0\""));

        // a file that is there is not overwritten, and that is found out before anything is searched
        let again = attack(&[SECRETS, "--known", known.to_str().unwrap(), "-o", open.to_str().unwrap()]);
        let said = String::from_utf8_lossy(&again.stderr);
        assert_eq!(again.status.code(), Some(1), "{said}");
        assert!(said.contains("exists: it is not overwritten") && !said.contains("the plan") && again.stdout.is_empty(), "{said}");
        // one archive is written, not two
        let two = attack(&[SECRETS, SECRETS, "-o", dir.path().join("two.zip").to_str().unwrap()]);
        assert_eq!(two.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&two.stderr).contains("-o writes one archive without its password: 2 are given"));
        // keys that open nothing write nothing
        let closed = dir.path().join("closed.zip");
        let none = attack(&[SECRETS, "--keys", "1", "2", "3", "-o", closed.to_str().unwrap()]);
        assert_eq!(none.status.code(), Some(3));
        assert!(!closed.exists() && String::from_utf8_lossy(&none.stderr).contains("closed.zip is not written: the keys are not proved"));
    }

    #[test]
    fn a_run_goes_on_from_its_state_and_runs_nothing_twice() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let plain = stored(SECRETS, "spiral.svg", "W4sF0rgotten");
        // 500 bytes of the file: 16,634 candidates, and the keys at the 4,855th. The entry is
        // named as text, so that the plan is this one attempt
        let given = format!("spiral.svg@200={}", hex::encode(&plain[200..700]));
        let anew = [SECRETS, "--bytes", &given, "--type", "spiral.svg=text", "--only", "run", "--state", state.to_str().unwrap()];
        let on = [&anew[..], &["--resume"]].concat();
        let kept = || -> Value { serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap() };
        let keep = |value: &Value| std::fs::write(&state, value.to_string()).unwrap();

        // a run that finds the keys leaves them in its state, with how far its search had come
        let first = attack_kept(&anew);
        let said = String::from_utf8_lossy(&first.stderr);
        assert_eq!((first.status.code(), lines(&first.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{said}");
        assert!(said.contains("[1/1] ") && said.contains("keys found at candidate 4,855 of 16,634"), "{said}");
        let found = kept();
        assert_eq!(found["proved"], serde_json::json!([0xc449_0e28_u32, 0xb414_a23d_u32, 0x9140_4b31_u32]));
        assert_eq!((found["running"]["search"].as_u64(), found["running"]["next"].as_u64()), (Some(0), Some(4000)), "{found}");
        assert_eq!(found["ended"], serde_json::json!([]));
        let attempt = found["running"]["attempt"].as_str().unwrap().to_owned();

        // a run that goes on from it has the result at once
        let again = attack_kept(&on);
        let said = String::from_utf8_lossy(&again.stderr);
        assert_eq!((again.status.code(), lines(&again.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{said}");
        assert!(said.contains("found by a run before, as the state says: not searched for") && !said.contains("reduction"), "{said}");

        // a state that stands behind the keys: the rest is searched and holds nothing, which
        // shows that the candidates in front of that place are not searched again
        let mut behind = found.clone();
        behind["proved"] = Value::Null;
        behind["running"]["next"] = 6000.into();
        keep(&behind);
        let rest = attack_kept(&on);
        let said = String::from_utf8_lossy(&rest.stderr);
        assert_eq!(rest.status.code(), Some(3), "{said}");
        assert!(rest.stdout.is_empty());
        assert!(said.contains("going on from candidate 6,001 of 16,634") && said.contains("spiral.svg: no keys. All 10,634 candidates tried"), "{said}");
        let ended = kept();
        assert_eq!((&ended["ended"], &ended["running"], &ended["proved"]), (&serde_json::json!([attempt]), &Value::Null, &Value::Null));

        // the attempt has ended: a run that goes on does not run it again
        let nothing = attack_kept(&on);
        let said = String::from_utf8_lossy(&nothing.stderr);
        assert_eq!(nothing.status.code(), Some(3), "{said}");
        assert!(said.contains("a run before brought it to its end without keys: not run again") && said.contains("no keys: 1 of 1 attempts ran to their end without them") && !said.contains("reduction"), "{said}");

        // a state that stands in front of the keys: they are found from there
        let mut before = found;
        before["proved"] = Value::Null;
        before["running"]["next"] = 4000.into();
        keep(&before);
        let rest = attack_kept(&on);
        let said = String::from_utf8_lossy(&rest.stderr);
        assert_eq!((rest.status.code(), lines(&rest.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{said}");
        assert!(said.contains("going on from candidate 4,001 of 16,634") && said.contains("keys found at candidate 4,855 of 16,634"), "{said}");
    }

    #[test]
    fn a_state_that_is_in_the_way_or_of_something_else_ends_the_command_at_its_start() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state.json");
        let state = state.to_str().unwrap();
        let refused = |args: &[&str], why: &str| {
            let output = attack_kept(args);
            let said = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{said}");
            assert!(output.stdout.is_empty());
            assert!(said.contains(why) && !said.contains("the plan"), "no {why:?} in:\n{said}");
        };

        // nothing to go on from
        refused(&[SECRETS, "--state", state, "--resume"], "cannot be read");
        // a run that prints its plan keeps no state
        let plan = attack_kept(&[SECRETS, "--state", state, "--plan"]);
        assert_eq!(plan.status.code(), Some(0));
        assert!(!Path::new(state).exists());

        // a file that is there is not taken by a run that starts anew
        std::fs::write(state, "what the user keeps here\n").unwrap();
        refused(&[SECRETS, "--state", state], "the file exists. --resume goes on from it");
        refused(&[SECRETS, "--state", state, "--resume"], "is not a state of this command");
        assert_eq!(std::fs::read_to_string(state).unwrap(), "what the user keeps here\n");

        // the state of one archive is not that of another, nor that of another part of its searches
        let other = dir.path().join("other.json");
        let other = other.to_str().unwrap();
        // no run of bytes is known of that archive: its plan is empty, and its state is kept all the same
        let six = attack_kept(&["tests/fixtures/zip-crypto/gen_infozip_six.zip", "--only", "run", "--state", other]);
        assert_eq!(six.status.code(), Some(3), "{}", String::from_utf8_lossy(&six.stderr));
        assert!(Path::new(other).is_file());
        refused(&[SECRETS, "--state", other, "--resume"], "the state of other archives, or of another part of the search");
        refused(&["tests/fixtures/zip-crypto/gen_infozip_six.zip", "--slice", "1/2", "--state", other, "--resume"], "the state of other archives, or of another part of the search");

        // --resume says where from
        let bare = attack_kept(&[SECRETS, "--resume"]);
        assert_eq!(bare.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&bare.stderr).contains("--state <FILE>"));
    }

    #[test]
    fn every_kernel_the_processor_runs_finds_the_same_keys() {
        use archivewolf_zip_crypto::Kernel;
        let plain = stored(SECRETS, "spiral.svg", "W4sF0rgotten");
        let given = format!("spiral.svg@200={}", hex::encode(&plain[200..700]));
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        for kernel in [Kernel::Scalar, Kernel::Avx2, Kernel::Avx512].into_iter().filter(|kernel| kernel.is_supported()) {
            // the command searches with the kernel that its cache says was the fastest
            let cache = cache_of(&format!("zip-crypto-test-cache-{}", kernel.name()), kernel, threads, 10_000.0);
            let output = Command::cargo_bin("archivewolf").unwrap().args(["attack", "zip-crypto", SECRETS, "--bytes", &given, "--type", "spiral.svg=text", "--only", "run"]).env("XDG_CACHE_HOME", cache).output().unwrap();
            let said = String::from_utf8_lossy(&output.stderr);
            assert_eq!((output.status.code(), lines(&output.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{}: {said}", kernel.name());
            assert!(said.contains(&format!("with the {} kernel", kernel.name())) && said.contains("keys found at candidate 4,855 of 16,634"), "{}: {said}", kernel.name());
        }

        // a cache that names a kernel this build does not have is measured anew
        let dir = tempfile::tempdir().unwrap();
        let processor = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|text| text.lines().find(|line| line.starts_with("model name")).and_then(|line| line.split_once(':')).map(|(_, name)| name.trim().to_owned())).unwrap_or_else(|| std::env::consts::ARCH.to_owned());
        std::fs::create_dir_all(dir.path().join("archivewolf")).unwrap();
        std::fs::write(dir.path().join("archivewolf/zip-crypto-speed.json"), serde_json::json!({ "processor": processor, "kernel": "of another build", "threads": 2, "rate": 5.0 }).to_string()).unwrap();
        let output = Command::cargo_bin("archivewolf").unwrap().args(["attack", "zip-crypto", SECRETS, "--plan", "--threads", "2"]).env("XDG_CACHE_HOME", dir.path()).output().unwrap();
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("measuring the speed of this machine: two seconds, once"), "{said}");
        let kept: Value = serde_json::from_slice(&std::fs::read(dir.path().join("archivewolf/zip-crypto-speed.json")).unwrap()).unwrap();
        assert!(Kernel::named(kept["kernel"].as_str().unwrap()).is_some_and(Kernel::is_supported) && kept["rate"].as_f64().unwrap() > 5.0, "{kept}");
    }

    #[test]
    fn a_list_of_known_files_names_the_entries_that_exist_elsewhere() {
        let dir = tempfile::tempdir().unwrap();
        let plain = stored(SECRETS, "spiral.svg", "W4sF0rgotten");
        let rows = format!(
            "\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\",\"FileSize\"\n\"000000000000000000000000000000000000AAAA\",\"0000000000000000000000000000BBBB\",\"{:08X}\",\"drawing.svg\",{}\n\"000000000000000000000000000000000000CCCC\",\"0000000000000000000000000000DDDD\",\"00000000\",\"other.bin\",7\n",
            crc32fast::hash(&plain),
            plain.len()
        );
        let list = write(&dir, "files.csv", rows.as_bytes());

        let output = attack(&[SECRETS, "--catalogue", list.to_str().unwrap(), "--plan"]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{said}");
        assert!(said.contains("files.csv: 2 rows read; 1 entry is in it"), "{said}");
        assert!(said.contains("  spiral.svg   known as \"drawing.svg\"   SHA-1 000000000000000000000000000000000000AAAA   MD5 0000000000000000000000000000BBBB"), "{said}");
        assert!(said.contains("find one of these files, pass it with --known, and the rest is seconds"), "{said}");
        // the list names files and gives no bytes: the plan is that of the archive alone
        let alone = attack(&[SECRETS, "--plan"]);
        assert!(said.ends_with(&*String::from_utf8_lossy(&alone.stderr)), "{said}");

        // the same as an event
        let output = attack(&[SECRETS, "--catalogue", list.to_str().unwrap(), "--plan", "--json", "-v"]);
        let events: Vec<Value> = String::from_utf8_lossy(&output.stderr).lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
        let listed = events.iter().find(|event| event["event"] == "catalogue").unwrap();
        assert_eq!((listed["rows"].as_u64(), &listed["known"][0]["entry"], &listed["known"][0]["name"]), (Some(2), &Value::from("spiral.svg"), &Value::from("drawing.svg")));

        // a file that is no such list ends the command at its start
        let refused = attack(&[SECRETS, "--catalogue", SECRETS, "--plan"]);
        assert_eq!(refused.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&refused.stderr).contains("the first line has to name the columns"));
    }

    #[test]
    fn an_archive_with_nothing_of_zip_crypto_is_nothing_to_start_on() {
        for (archive, why) in [("tests/fixtures/zip-winzip/aes256.zip", "no entry of zip-crypto to work on"), ("tests/fixtures/rar-50/v730_p_m3.rar", "is not a ZIP archive"), ("tests/fixtures/absent.zip", "cannot read")] {
            let output = attack(&[archive]);
            let said = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{archive}: {said}");
            assert!(said.starts_with("archivewolf: ") && said.contains(why) && output.stdout.is_empty(), "{archive}: {said}");
        }
    }

    #[test]
    fn several_archives_under_one_password_are_one_pool() {
        // the keys that a file of one archive gives are tested on the entries of both
        let dir = tempfile::tempdir().unwrap();
        let known = write(&dir, "spiral.svg", &stored(SECRETS, "spiral.svg", "W4sF0rgotten"));
        let same = write(&dir, "same-password.zip", &archive_of("notes.txt", b"under the password of the other archive", "W4sF0rgotten"));
        let other = write(&dir, "other-password.zip", &archive_of("diary.txt", b"under a password of its own, which the keys do not open", "another"));
        let output = attack(&[same.to_str().unwrap(), SECRETS, other.to_str().unwrap(), "--known", known.to_str().unwrap()]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!((output.status.code(), lines(&output.stdout)), (Some(0), KEYS.map(str::to_owned).to_vec()), "{said}");
        assert!(said.contains("the keys open 3 of 4 encrypted entries"), "{said}");
        assert!(said.contains("not opened: ") && said.contains("other-password.zip: diary.txt (another password)"), "{said}");
    }
}
