//! What `info` says of the folders of a 7-Zip archive, held against what 7-Zip itself lists.
//!
//! `7zz l -slt` names for every file its size, whether it is encrypted, and its block, which is
//! the number of its folder. For every 7-Zip fixture whose header can be read without the
//! password, the files of each folder, the sum of their sizes, the packed size of the folder
//! and its encryption have to be what 7-Zip lists, and every file 7-Zip lists outside a block
//! has to be one without data: such a file is no entry.
//!
//! The test runs `7zz`, which the tool itself never does. It is ignored by default, and it
//! fails when `7zz` is not there: `cargo test --test 7z_listing_test -- --ignored`.

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
use tempfile as _;
use tracing as _;
use tracing_subscriber as _;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Command;

    use serde_json::Value;

    const FIXTURES: &str = "tests/fixtures";

    /// One file as 7-Zip lists it.
    #[derive(Debug)]
    struct Listed {
        path: String,
        size: u64,
        packed: Option<u64>,
        encrypted: bool,
        directory: bool,
        /// The number of its folder. `None` for a file without data.
        block: Option<usize>,
    }

    /// What 7-Zip lists of an archive: where it starts in the file, how many folders it has,
    /// and its files. `None` when 7-Zip cannot list it with this password.
    fn listed(archive: &Path, password: &str) -> Option<(u64, usize, Vec<Listed>)> {
        let output = Command::new("7zz").args(["l", "-slt", &format!("-p{password}"), "--"]).arg(archive).output().expect("this test needs 7zz, the command line of 7-Zip, on the PATH");
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let (head, files) = text.split_once("\n----------\n")?;
        let field = |block: &str, name: &str| block.lines().find_map(|line| line.strip_prefix(&format!("{name} = "))).map(str::to_owned);

        let offset = field(head, "Offset").map_or(0, |offset| offset.parse().unwrap());
        let blocks = field(head, "Blocks").map_or(0, |blocks| blocks.parse().unwrap());
        let files = files
            .split("\n\n")
            .filter(|block| block.starts_with("Path = "))
            .map(|block| Listed {
                path: field(block, "Path").unwrap(),
                size: field(block, "Size").unwrap().parse().unwrap(),
                packed: field(block, "Packed Size").and_then(|packed| packed.parse().ok()),
                encrypted: field(block, "Encrypted").unwrap() == "+",
                directory: field(block, "Attributes").is_some_and(|attributes| attributes.starts_with('D')) || field(block, "Folder").is_some_and(|folder| folder == "+"),
                block: field(block, "Block").and_then(|number| number.parse().ok()),
            })
            .collect();
        Some((offset, blocks, files))
    }

    /// Every 7-Zip fixture, in the order of their paths.
    fn fixtures() -> Vec<PathBuf> {
        let mut found: Vec<PathBuf> = walkdir::WalkDir::new(FIXTURES).into_iter().map(|entry| entry.unwrap().into_path()).filter(|path| path.extension().is_some_and(|extension| extension == "7z")).collect();
        found.sort();
        found
    }

    #[test]
    #[ignore = "runs 7zz: cargo test --test 7z_listing_test -- --ignored"]
    fn the_folders_are_what_7_zip_lists_as_blocks() {
        let passwords: BTreeMap<String, String> = serde_json::from_str(&std::fs::read_to_string(Path::new(FIXTURES).join("passwords.json")).unwrap()).unwrap();
        let (mut compared, mut hidden, mut files_seen, mut without_data) = (0, 0, 0, 0);

        for archive in fixtures() {
            let name = archive.strip_prefix(FIXTURES).unwrap().to_string_lossy().into_owned();
            let ours = Command::new(env!("CARGO_BIN_EXE_archivewolf")).args(["info", "--json"]).arg(&archive).env("PATH", "").output().unwrap();
            assert!(ours.status.success(), "{name}: {}", String::from_utf8_lossy(&ours.stderr));
            let analysis: Value = serde_json::from_slice(&ours.stdout).unwrap();
            let password = passwords.get(&name).map_or("x", String::as_str);

            if analysis["headers"] == "encrypted" {
                // 7-Zip cannot list it without the password either, and with it every file is encrypted
                assert!(listed(&archive, "not the password").is_none(), "{name}: 7-Zip lists an archive whose header is encrypted");
                if let Some((_, _, files)) = passwords.get(&name).and_then(|password| listed(&archive, password)) {
                    assert!(files.iter().all(|file| file.encrypted || file.block.is_none()), "{name}");
                }
                hidden += 1;
                continue;
            }

            let (offset, blocks, files) = listed(&archive, password).unwrap_or_else(|| panic!("{name}: 7-Zip does not list it"));
            let folders = analysis["entry_list"].as_array().unwrap();
            assert_eq!(analysis["offset"].as_u64(), Some(offset), "{name}: where the archive starts");
            assert_eq!(folders.len(), blocks, "{name}: the number of folders");

            for (number, folder) in folders.iter().enumerate() {
                let inside: Vec<&Listed> = files.iter().filter(|file| file.block == Some(number)).collect();
                // The files of the folder are the files of the block, in their order. An empty
                // file that 7-Zip lists between them holds nothing of the folder and may be left out.
                let names: Vec<String> = folder["files"].as_array().map(|names| names.iter().map(|name| name.as_str().unwrap().replace('\\', "/")).collect()).unwrap_or_default();
                let mut ours = names.iter().peekable();
                for file in &inside {
                    if ours.peek().is_some_and(|ours| **ours == file.path.replace('\\', "/")) {
                        let _ = ours.next();
                    } else {
                        assert_eq!(file.size, 0, "{name}, folder {number}: {} is not among {names:?}", file.path);
                    }
                }
                assert_eq!(ours.next(), None, "{name}, folder {number}: {names:?} against {inside:?}");
                assert_eq!(folder["size"].as_u64(), Some(inside.iter().map(|file| file.size).sum()), "{name}, folder {number}: what it unpacks to");
                if let Some(first) = inside.first() {
                    assert_eq!(folder["packed"].as_u64(), first.packed, "{name}, folder {number}: its packed size");
                    assert_eq!(folder["state"] == "encrypted", first.encrypted, "{name}, folder {number}: whether it is encrypted");
                    assert!(inside.iter().all(|file| file.encrypted == first.encrypted), "{name}, folder {number}");
                }
                files_seen += inside.len();
            }

            // what 7-Zip lists outside every block has no data and is not encrypted
            for file in files.iter().filter(|file| file.block.is_none()) {
                assert!((file.directory || file.size == 0) && !file.encrypted, "{name}: {file:?} is in no folder");
                without_data += 1;
            }
            compared += 1;
        }

        // the fixtures have archives of every kind, and all of them were looked at
        assert!(compared >= 100 && hidden >= 10 && files_seen >= 150 && without_data >= 10, "{compared} compared, {hidden} with an encrypted header, {files_seen} files, {without_data} without data");
    }
}
