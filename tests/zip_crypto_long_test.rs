//! The long searches of `attack zip-crypto`, from end to end: the cases where a signature,
//! eight bytes or nothing at all is known, which take from seconds to minutes on every thread
//! of the machine. They are not part of the default run: `make test-zip-crypto` runs them,
//! with an optimised build.

#![expect(unused_crate_dependencies, reason = "integration test")]

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Output;

    use archivewolf_zip_crypto::Keys;
    use assert_cmd::Command;

    const FIXTURES: &str = "tests/fixtures/zip-crypto";

    /// `archivewolf attack zip-crypto` with these arguments, with no limit of time. The speed
    /// of the machine is measured by the first of these runs and kept below `target/`.
    fn attack(args: &[&str]) -> Output {
        let cache = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/zip-crypto-long-cache");
        Command::cargo_bin("archivewolf").unwrap().args(["attack", "zip-crypto", "--budget", "none"]).args(args).env("XDG_CACHE_HOME", cache).env_remove("RUST_LOG").output().unwrap()
    }

    /// Hold a run to the keys of a password, proved.
    fn finds(output: &Output, password: &str) {
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(0), "{said}");
        let printed = String::from_utf8_lossy(&output.stdout);
        assert_eq!(printed.lines().next(), Some(format!("keys {}", Keys::from_password(password.as_bytes())).as_str()), "{said}");
        assert!(said.contains("proved: decrypts "), "{said}");
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_six_entries_of_info_zip_give_the_keys_with_nothing_known() {
        let output = attack(&[&format!("{FIXTURES}/gen_infozip_six.zip")]);
        finds(&output, "six-headers");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("written by Info-ZIP") && said.contains("seed 1,795,889,087 of the generator of glibc: it gives the first byte of the header of all 6 entries"), "{said}");
        assert!(said.contains("the keys open 6 of 6 encrypted entries"), "{said}");
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_zip_on_musl_and_on_windows_and_of_minizip_give_the_keys() {
        // the real zip built against two other C libraries, and minizip, which makes its
        // headers as zip does and leaves no mark of itself
        for (fixture, password, library) in [("gen_infozip_musl.zip", "musl-headers", "musl"), ("gen_infozip_win.zip", "win-headers", "Windows"), ("gen_minizip_glibc.zip", "minizip-headers", "glibc")] {
            let output = attack(&[&format!("{FIXTURES}/{fixture}")]);
            finds(&output, password);
            let said = String::from_utf8_lossy(&output.stderr);
            assert!(said.contains(&format!(" of the generator of {library}: it gives the first byte of the header of all 6 entries")), "{fixture}: {said}");
            assert!(said.contains("the keys open 6 of 6 encrypted entries"), "{fixture}: {said}");
        }
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_sharpziplib_and_of_dotnetzip_on_the_net_framework_give_the_clock_and_the_keys() {
        // on the .NET Framework a clock seeds the generator of every entry: the clock is found
        // from the headers of the groups of entries that were written between two of its steps
        for (fixture, password) in [("gen_sharpziplib_netfx.zip", "sharp-on-the-framework"), ("gen_dotnetzip_netfx.zip", "dotnetzip-on-the-framework")] {
            let output = attack(&[&format!("{FIXTURES}/{fixture}")]);
            finds(&output, password);
            let said = String::from_utf8_lossy(&output.stderr);
            assert!(said.contains("the clock of the machine: it had been running for 18 days 8 hours when the first entry was written"), "{fixture}: {said}");
            assert!(said.contains("reduction: 12 bytes in a row"), "{fixture}: {said}");
        }
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_double_commander_are_one_sequence_and_give_the_keys() {
        // Abbrevia in the zip plugin of Double Commander draws from the generator of Free
        // Pascal, which nothing seeds there: the first archive of a run of the plugin starts
        // the sequence, and the second goes on where the first ended
        for (fixture, before) in [("gen_doublecmd_first.zip", "no encrypted entry"), ("gen_doublecmd_second.zip", "6 encrypted entries")] {
            let output = attack(&[&format!("{FIXTURES}/{fixture}")]);
            finds(&output, "doublecmd-headers");
            let said = String::from_utf8_lossy(&output.stderr);
            assert!(said.contains(&format!("the generator of Free Pascal as it starts, with no seed: Abbrevia draws its headers from it in the zip plugin of Double Commander, which had written {before} before these since it was loaded")), "{fixture}: {said}");
            assert!(said.contains("the keys open 6 of 6 encrypted entries"), "{fixture}: {said}");
        }
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_the_ziparchive_library_give_the_clock_and_the_keys() {
        // the library seeds the generator of its C library with the time for every entry: the
        // second each entry was written in is found among those the archive names, and the
        // headers together leave the search a handful of candidates
        for (fixture, password, runtime, second) in [("gen_ziparchive_glibc.zip", "ziparchive-on-glibc", "glibc", "1,795,236,980"), ("gen_ziparchive_win.zip", "ziparchive-on-windows", "Windows", "1,795,232,739")] {
            let output = attack(&[&format!("{FIXTURES}/{fixture}")]);
            finds(&output, password);
            let said = String::from_utf8_lossy(&output.stderr);
            assert!(said.contains(&format!("the archive was written by the ZipArchive library on {runtime}, which seeds its generator from a clock for every entry: its first entry was written at second {second} of Unix time")), "{fixture}: {said}");
            assert!(said.contains("The clock gives the header of each of the 14 groups of entries") && said.contains("the keys open 14 of 14 encrypted entries"), "{fixture}: {said}");
        }
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn zip_utils_in_a_session_with_another_desktop_window_is_not_found() {
        // zip utils seeds with the count of the clock exclusive-or the handle of the desktop
        // window. This archive was written by a program that ran as a service does, where the
        // handle is not the one of the desktop a user works at: the search says so and ends
        let output = attack(&[&format!("{FIXTURES}/gen_ziputils_win.zip")]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{said}");
        assert!(said.contains("no clock of the ZipArchive library or of zip utils gives the headers"), "{said}");
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_four_entries_of_info_zip_are_enough() {
        finds(&attack(&[&format!("{FIXTURES}/gen_infozip_four.zip")]), "four-headers");
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_sharpziplib_and_of_dotnetzip_on_net_5_give_a_run_of_twelve() {
        for archive in ["gen_sharpziplib_net5.zip", "gen_dotnetzip_net5.zip"] {
            let output = attack(&[&format!("{FIXTURES}/{archive}")]);
            finds(&output, "Tr0ub4dor&3xyz");
            let said = String::from_utf8_lossy(&output.stderr);
            assert!(said.contains("it gives eleven bytes of every header") && said.contains("reduction: 12 bytes in a row"), "{archive}: {said}");
        }
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_headers_of_sharpziplib_on_net_9_give_no_seed_and_that_is_said() {
        let output = attack(&[&format!("{FIXTURES}/gen_sharpziplib_net9.zip")]);
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{said}");
        assert!(output.stdout.is_empty());
        assert!(said.contains("no seed gives the first byte of every header: the archive was written on a runtime whose generator cannot be predicted"), "{said}");
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_name_of_a_stored_entry_is_enough() {
        // `spiral.svg` of the tutorial of bkcrack starts as an XML file does: a run of twenty
        let output = attack(&[&format!("{FIXTURES}/bkcrack-src_secrets.zip")]);
        finds(&output, "W4sF0rgotten");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("keys found on spiral.svg (stored, signature of an XML file, 20 bytes in a row)"), "{said}");
        assert!(said.contains("the keys open 2 of 2 encrypted entries"), "{said}");
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn a_run_of_eight_with_a_class_behind_it_is_enough() {
        // the case of section 5.3 of the design: seven bytes of the file, its check byte, and
        // the statement that the file is text. The file is named as text, so that its name
        // does not give the start of an XML file away
        let output = attack(&[&format!("{FIXTURES}/bkcrack-src_secrets.zip"), "--starts", "spiral.svg=<?xml v", "--class", "spiral.svg=text", "--type", "spiral.svg=text", "--entry", "spiral.svg", "--only", "run"]);
        finds(&output, "W4sF0rgotten");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("bytes given on the command line   8 bytes in a row, 4,194,304 candidates"), "{said}");
        assert!(said.contains("keys found on spiral.svg (stored, bytes given on the command line, 8 bytes in a row)"), "{said}");
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn a_wrong_start_finds_nothing_and_proves_nothing() {
        // a cache of its own, which says that the machine searches a hundred candidates a
        // second: a measurement that was taken while the machine did something else
        let cache = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/zip-crypto-long-cache-wrong");
        let processor = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|text| text.lines().find(|line| line.starts_with("model name")).and_then(|line| line.split_once(':')).map(|(_, name)| name.trim().to_owned())).unwrap_or_else(|| std::env::consts::ARCH.to_owned());
        let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let kept = cache.join("archivewolf/zip-crypto-speed.json");
        std::fs::create_dir_all(cache.join("archivewolf")).unwrap();
        std::fs::write(&kept, serde_json::json!({ "processor": processor, "kernel": archivewolf_zip_crypto::Kernel::best().name(), "threads": threads, "rate": 100.0 }).to_string()).unwrap();

        // twelve bytes that the file does not start with: every candidate is tried, and none is the key
        let output = Command::cargo_bin("archivewolf")
            .unwrap()
            .args(["attack", "zip-crypto", "--budget", "none", &format!("{FIXTURES}/bkcrack-src_secrets.zip"), "--starts", "spiral.svg=<?xml w1234567", "--type", "spiral.svg=text", "--entry", "spiral.svg", "--only", "run"])
            .env("XDG_CACHE_HOME", &cache)
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(3), "{said}");
        assert!(output.stdout.is_empty());
        assert!(said.contains("spiral.svg: no keys. All ") && said.contains("The claim was a guess, and the guess was wrong."), "{said}");

        // the search took more than half a minute at a speed that is not the kept one: what
        // it did is kept in its place, and the next plan is made with it
        assert!(said.contains("the speed that was kept, 100 candidates a second, is not what this run did: "), "{said}");
        let corrected: serde_json::Value = serde_json::from_slice(&std::fs::read(&kept).unwrap()).unwrap();
        assert!(corrected["rate"].as_f64().unwrap() > 1000.0 && corrected["threads"].as_u64() == Some(threads as u64), "{corrected}");
    }
}
