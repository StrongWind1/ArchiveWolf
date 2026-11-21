//! 7-Zip archives built to break the tool, run through the binary itself.
//!
//! The unit tests of the format read these inputs in the test process. Here the binary reads
//! them, because two of the old failures cannot be seen from inside: an allocation that fails
//! aborts the process, which no test survives to report, and one that succeeds by the grace of
//! the operating system is no failure at all until memory is short. So on Linux the binary runs
//! with its address space capped at 1 GiB, as in `regress_f2_bounds_test.rs`: a run that asks
//! for more than its input can back ends there, and a run that reads an archive of gigabytes
//! whole cannot even start.
//!
//! The binary runs with an empty `PATH`: it starts no other program.

#[path = "../src/formats/sevenz/craft.rs"]
mod craft;

// A test crate is linked against every dependency of the package, and the lint
// `unused_crate_dependencies` wants each of them named.
use anyhow as _;
use archivewolf as _;
use archivewolf_zip_crypto as _;
use assert_cmd as _;
use clap as _;
use flate2 as _;
use hex as _;
use lzma_rust2 as _;
use predicates as _;
use proptest as _;
use rayon as _;
use serde as _;
use serde_json as _;
use sha2 as _;
use tracing as _;
use tracing_subscriber as _;
use walkdir as _;

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;
    use std::time::Instant;

    use super::craft;

    /// What a run of the binary came to.
    struct Run {
        code: Option<i32>,
        stdout: String,
        stderr: String,
        took: Duration,
    }

    impl Run {
        /// The process returned from `main` in good time with one of the two statuses an archive
        /// can give it: it did not panic, did not abort on a failed allocation and was not killed.
        fn ended_normally(&self) -> bool {
            matches!(self.code, Some(0 | 2)) && !self.stderr.contains("panicked") && !self.stderr.contains("internal error") && !self.stderr.contains("memory allocation of") && self.took < Duration::from_secs(20)
        }

        fn report(&self) -> String {
            let cut = |text: &str| text.chars().take(600).collect::<String>();
            format!("exit {:?} after {:?}\nstdout: {}\nstderr: {}", self.code, self.took, cut(&self.stdout), cut(&self.stderr))
        }
    }

    #[cfg(target_os = "linux")]
    fn command(args: &[&str], archive: &Path) -> Command {
        // one thread and one allocator arena, so that the address space in use is what the work needs
        let mut command = Command::new("/bin/sh");
        let _ = command.args(["-c", "ulimit -v 1048576 && exec \"$0\" \"$@\"", env!("CARGO_BIN_EXE_archivewolf")]).args(args).arg(archive).env("PATH", "").env("RAYON_NUM_THREADS", "1").env("MALLOC_ARENA_MAX", "1");
        command
    }

    #[cfg(not(target_os = "linux"))]
    fn command(args: &[&str], archive: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_archivewolf"));
        let _ = command.args(args).arg(archive).env("PATH", "");
        command
    }

    /// Run the binary with `args` on an archive file.
    fn run(args: &[&str], archive: &Path) -> Run {
        let started = Instant::now();
        let output = command(args, archive).output().unwrap();
        Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned(), took: started.elapsed() }
    }

    /// Every input that once ended in a panic (status 101), an abort on a failed allocation (134)
    /// or minutes of work now ends in an analysis (0) or in the error of an archive that does not
    /// parse (2), for `info` and for `hash` alike.
    #[test]
    fn the_inputs_that_once_broke_the_tool_end_with_status_0_or_2() {
        let dir = tempfile::tempdir().unwrap();
        let mut statuses = Vec::new();
        for (name, bytes) in craft::hostile() {
            let path = dir.path().join(format!("{name}.7z"));
            std::fs::write(&path, bytes).unwrap();
            for args in [&["info"][..], &["info", "--json"], &["hash"], &["hash", "--all"]] {
                let run = run(args, &path);
                assert!(run.ended_normally(), "{name} with {args:?}: {}", run.report());
                // an archive that is read says something: its block, its line, or why it has none
                if run.code == Some(0) && args[0] == "info" {
                    assert!(run.stdout.contains(&format!("{name}.7z")), "{name} with {args:?}: {}", run.report());
                }
                statuses.push((name, args[0], run.code));
            }
        }

        // each kind of outcome is among them: no archive, an archive without a line, one with a line
        let status = |name: &str, command: &str| statuses.iter().find(|(known, with, _)| *known == name && *with == command).and_then(|(_, _, code)| *code);
        assert_eq!((status("skip-overflow", "info"), status("wide-coder", "hash"), status("crcs-2e40", "info")), (Some(2), Some(2), Some(2)));
        assert_eq!((status("files-2e36", "info"), status("ppmd-memory", "hash"), status("many-folders", "hash")), (Some(0), Some(0), Some(0)));
    }

    /// A folder that names a model of gigabytes, a size of 2^64-1 or no checksum at all gets its
    /// reason on standard error and no line, and the 4096 folders that all hold the same get one.
    #[test]
    fn a_hostile_folder_gets_a_reason_and_a_sound_one_its_line() {
        let dir = tempfile::tempdir().unwrap();
        let hostile = craft::hostile();
        let hash = |name: &str| {
            let (_, bytes) = hostile.iter().find(|(known, _)| *known == name).unwrap();
            let path = dir.path().join(format!("{name}.7z"));
            std::fs::write(&path, bytes).unwrap();
            run(&["hash", "--all"], &path)
        };

        for (name, reason) in [("ppmd-memory", "[over-limit]"), ("crc-length-overflow", "[over-limit]"), ("stored-no-crc", "[no-data]")] {
            let run = hash(name);
            assert!(run.stdout.is_empty() && run.stderr.contains("no line: folder 0") && run.stderr.contains(reason), "{name}: {}", run.report());
        }
        let run = hash("many-folders");
        assert!(run.stdout.lines().count() == 1 && run.stdout.starts_with("$7z$*24*"), "{}", run.report());
        let run = hash("bcj2");
        assert_eq!(run.stdout.lines().next().map(|line| line.split('*').count()), Some(27), "four streams: {}", run.report());
    }

    /// An archive of more than 5 GiB, most of it a hole in the file. With 1 GiB of address space
    /// the binary cannot read it whole: it reads the header at its end and, for the lines, the
    /// megabyte and the 64 bytes that go into them.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_archive_of_gigabytes_is_read_by_range() {
        use std::io::Seek as _;
        use std::io::SeekFrom;
        use std::io::Write as _;

        const GIB: u64 = 1 << 30;
        let key = craft::aes_props(19, &[], &[3; 16]);
        let folders = [
            // 3 GiB of LZMA whose first file is too large to unpack: the line tests the start
            craft::Folder::new(craft::chain(&[(craft::LZMA, craft::LZMA_PROPS), (craft::AES, &key)]), &[8 * GIB, 3 * GIB], 3 * GIB, Some(1)),
            // 2 GiB of stored data: more than a line carries, and nothing else to test
            craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[2 * GIB], 2 * GIB, Some(2)),
            // 64 stored bytes behind all that: a line with its checksum
            craft::Folder::new(craft::chain(&[(craft::AES, &key)]), &[60], 64, Some(3)),
        ];
        let header = craft::header(&folders);
        let data = 5 * GIB + 64;

        // the signature header says where the header lies: behind the data, which is never written
        let mut start = craft::archive(&header, &[]);
        start.truncate(32);
        start[12..20].copy_from_slice(&data.to_le_bytes());
        let crc = crc32fast::hash(&start[12..32]);
        start[8..12].copy_from_slice(&crc.to_le_bytes());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gigabytes.7z");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&start).unwrap();
        let _ = file.seek(SeekFrom::Start(32 + data)).unwrap();
        file.write_all(&header).unwrap();
        drop(file);
        assert!(std::fs::metadata(&path).unwrap().len() > 5 * GIB);

        let info = run(&["info", "--json"], &path);
        assert!(info.ended_normally() && info.code == Some(0), "{}", info.report());
        let analysis: serde_json::Value = serde_json::from_str(&info.stdout).unwrap();
        let sizes: Vec<(u64, u64)> = analysis["entry_list"].as_array().unwrap().iter().map(|entry| (entry["packed"].as_u64().unwrap(), entry["size"].as_u64().unwrap())).collect();
        assert_eq!(sizes, [(3 * GIB, 8 * GIB), (2 * GIB, 2 * GIB), (64, 60)]);
        assert_eq!((analysis["volume"].as_str(), analysis["lines"][0]["entry"].as_u64(), analysis["lines"][0]["proves"].as_str()), (Some("single"), Some(2), Some("exact")));

        let hash = run(&["hash", "--all"], &path);
        assert!(hash.ended_normally() && hash.code == Some(0), "{}", hash.report());
        let lines: Vec<&str> = hash.stdout.lines().collect();
        assert_eq!(lines.len(), 2, "{}", hash.report());
        // the 64 bytes that lie past the fifth gigabyte, then the first megabyte of the 3 GiB
        assert!(lines[0].starts_with("$7z$*19**00000003*3c**1*") && lines[0].ends_with(&format!("*{}$/7z$", "0".repeat(128))), "{}", &lines[0][..60]);
        assert!(lines[1].starts_with("$7z$*19***200000000**1*") && lines[1].len() > 2 << 20 && lines[1].len() < (2 << 20) + 200, "{} characters", lines[1].len());
        assert!(hash.stderr.contains("no line: folder 1") && hash.stderr.contains("[over-limit]"), "{}", hash.report());
        assert!(info.took < Duration::from_secs(5) && hash.took < Duration::from_secs(5), "info {:?}, hash {:?}", info.took, hash.took);
    }
}
