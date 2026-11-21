//! Regression tests for bounded parsing and bounded decompression.
//!
//! Every archive here is built in the test: a few dozen bytes that claim a size of 2^62, or a few
//! hundred kilobytes that unpack to gigabytes. Each used to end in a panic, an abort or gigabytes
//! of memory. The binary runs with an empty PATH, since it starts no other program, and on Linux
//! with its address space capped at 1 GiB, which no run here comes near and every one of the old
//! failures went through.
#![expect(unused_crate_dependencies, reason = "integration test")]

use std::path::Path;
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

/// One LZMA2 chunk that unpacks to `LZMA2_CHUNK_SIZE` zero bytes, without the byte that ends a
/// stream. It resets the dictionary, so any number of copies in a row is a valid stream. Made
/// with Python's `lzma` module from two mebibytes of zeros and a 64 KiB dictionary.
const LZMA2_CHUNK: &str = concat!(
    "ffff11016c5d00006ffdffffa3b7ff473e481572396151b89228e6a38607f9eee41e82d32fc53a3c014bb17ec98a8a4d2fa30dd97fa6e38c231153e05918c5758ae277f8b6947f",
    "0c6ac0de744964e2e95c53b204d8f7440cab5f0d6d46e9e5c37688b79657acb64de1691d6ffb4b88106c42cb883f5c008fd04eaf262894711f3d8f24e1709ea7235fec28cb85",
    "d195988a7e2a91f22775f719c006984d98fdd8afd5900fc42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55b0508",
    "f9c7daadfcfb522b74cd1e5b2042f9dd533df82964093b80cb2a6cdfb53bf0c4bd2e5faa0f3e4b664290130eff1093f8717859f80bcdff9528460fa9fc7cdefb9a302e56c08f",
    "85f38381c065c42553f8f591363105a5b0ee6fc1704d470cd19111aaad601dbaceb127185c5986e9665258bee976ac59e4e55b0508f9c7daadfcfb522b74cd1e5b2042f9dd53",
    "3df82964093b80cb2a6cdfb53bf0c4bc4827e658",
);
const LZMA2_CHUNK_SIZE: u64 = 2_096_914;
/// The LZMA2 property byte for a 64 KiB dictionary, in 7z and in `.xz` alike.
const LZMA2_DICTIONARY: u8 = 0x08;

/// CRC-32 of 100 zero bytes.
const CRC_100_ZEROS: u32 = 0x9988_C6CA;
/// CRC-32 of the 901,673,020 zero bytes that 430 chunks unpack to.
const CRC_430_CHUNKS: u32 = 0x1ED0_3B30;

/// The password the encrypted ZIP entries here are built with.
const PASSWORD: &str = "infected";

/// The two ways an archive is looked at: analysed, and turned into hash lines.
const INFO: &[&str] = &["info"];
const HASH: &[&str] = &["hash", "--all"];

// ---------------------------------------------------------------------------
// Running the binary
// ---------------------------------------------------------------------------

/// What a run of the binary came to.
struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    took: Duration,
}

impl Run {
    /// The process returned from `main` in good time: it did not panic, did not abort on a
    /// failed allocation and was not killed.
    fn ended_normally(&self) -> bool {
        self.code.is_some_and(|code| code != 101 && code != 134) && !self.stderr.contains("panicked") && !self.stderr.contains("memory allocation of") && self.took < Duration::from_mins(1)
    }

    fn report(&self) -> String {
        format!("exit {:?} after {:?}\nstdout: {}\nstderr: {}", self.code, self.took, self.stdout, self.stderr)
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
fn try_file(archive: &Path, args: &[&str]) -> std::io::Result<Run> {
    let started = Instant::now();
    let output = command(args, archive).output()?;
    Ok(Run { code: output.status.code(), stdout: String::from_utf8_lossy(&output.stdout).into_owned(), stderr: String::from_utf8_lossy(&output.stderr).into_owned(), took: started.elapsed() })
}

/// Run the binary with `args` on an archive made of `bytes`.
fn try_archive(bytes: &[u8], name: &str, args: &[&str]) -> std::io::Result<Run> {
    let dir = tempfile::tempdir()?;
    let archive = dir.path().join(name);
    std::fs::write(&archive, bytes)?;
    try_file(&archive, args)
}

// ---------------------------------------------------------------------------
// Building streams
// ---------------------------------------------------------------------------

/// The low `count` bytes of a value, little-endian.
fn le(value: u64, count: usize) -> impl Iterator<Item = u8> {
    value.to_le_bytes().into_iter().take(count)
}

fn len_of<T>(bytes: &[T]) -> u64 {
    bytes.len() as u64
}

/// An LZMA2 stream of `chunks * LZMA2_CHUNK_SIZE` zero bytes: 371 packed bytes for every chunk.
fn lzma2_zeros(chunks: usize) -> Result<Vec<u8>, hex::FromHexError> {
    let mut stream = hex::decode(LZMA2_CHUNK)?.repeat(chunks);
    stream.push(0);
    Ok(stream)
}

/// An `.xz` file of one block around an LZMA2 stream, with no check.
fn xz_around(lzma2: &[u8], unpacked: u64) -> Vec<u8> {
    fn with_crc(mut bytes: Vec<u8>) -> Vec<u8> {
        let crc = crc32fast::hash(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes
    }
    fn number(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.extend(le((value & 0x7F) | 0x80, 1));
            value >>= 7;
        }
        out.extend(le(value, 1));
    }

    let mut file = vec![0xFD, b'7', b'z', b'X', b'Z', 0x00];
    file.extend(with_crc(vec![0x00, 0x00]));
    let header = with_crc(vec![0x02, 0x00, 0x21, 0x01, LZMA2_DICTIONARY, 0, 0, 0]);
    file.extend_from_slice(&header);
    file.extend_from_slice(lzma2);
    file.resize(file.len().next_multiple_of(4), 0);

    let mut index = vec![0x00];
    number(1, &mut index);
    number(len_of(&header) + len_of(lzma2), &mut index);
    number(unpacked, &mut index);
    index.resize(index.len().next_multiple_of(4), 0);
    let index = with_crc(index);
    file.extend_from_slice(&index);

    let mut footer: Vec<u8> = le(len_of(&index) / 4 - 1, 4).collect();
    footer.extend_from_slice(&[0x00, 0x00]);
    file.extend_from_slice(&crc32fast::hash(&footer).to_le_bytes());
    file.extend_from_slice(&footer);
    file.extend_from_slice(b"YZ");
    file
}

// ---------------------------------------------------------------------------
// Building ZIP archives
// ---------------------------------------------------------------------------

/// Traditional PKWARE encryption of `plain` under `password`.
fn zip_crypto(password: &[u8], plain: &[u8]) -> Vec<u8> {
    fn crc_step(crc: u32, byte: u32) -> u32 {
        let mut entry = (crc ^ byte) & 0xFF;
        for _ in 0..8 {
            entry = if entry & 1 == 1 { (entry >> 1) ^ 0xEDB8_8320 } else { entry >> 1 };
        }
        (crc >> 8) ^ entry
    }
    fn update(keys: &mut [u32; 3], byte: u8) {
        keys[0] = crc_step(keys[0], u32::from(byte));
        keys[1] = keys[1].wrapping_add(keys[0] & 0xFF).wrapping_mul(134_775_813).wrapping_add(1);
        keys[2] = crc_step(keys[2], keys[1] >> 24);
    }

    let mut keys = [0x1234_5678, 0x2345_6789, 0x3456_7890];
    for &byte in password {
        update(&mut keys, byte);
    }
    plain
        .iter()
        .map(|&byte| {
            let temp = (keys[2] | 2) & 0xFFFF;
            let stream = le(u64::from(temp.wrapping_mul(temp ^ 1) >> 8), 1).next().unwrap_or(0);
            update(&mut keys, byte);
            byte ^ stream
        })
        .collect()
}

/// A ZIP archive with one `ZipCrypto` entry that holds `stream` and declares `declared` bytes.
fn zip_with_encrypted_entry(method: u16, stream: &[u8], declared: u32, crc: u32) -> Vec<u8> {
    zip_with_entries_of_one_stream(method, stream, &[declared], crc)
}

/// A ZIP archive whose entries all are the same `ZipCrypto` stream: one local record, and one
/// central directory record for each size in `declared`, all of which point at it. The file
/// grows by 56 bytes for an entry, whatever the entry claims to unpack to.
fn zip_with_entries_of_one_stream(method: u16, stream: &[u8], declared: &[u32], crc: u32) -> Vec<u8> {
    let name = |number: usize| if declared.len() == 1 { "zeros.bin".to_owned() } else { format!("zeros.{number:04}") };
    let mut plain: Vec<u8> = (1..=10).collect();
    plain.extend(le(u64::from(crc >> 16), 2));
    plain.extend_from_slice(stream);
    let body = zip_crypto(PASSWORD.as_bytes(), &plain);

    // version, flags (encrypted), method, time, date, CRC-32, packed size, declared size, name length
    let fields = |size: u32| -> Vec<u8> {
        let head = le(20, 2).chain(le(1, 2)).chain(le(u64::from(method), 2)).chain(le(0x6000, 2)).chain(le(0x5A21, 2));
        head.chain(le(u64::from(crc), 4)).chain(le(len_of(&body), 4)).chain(le(u64::from(size), 4)).chain(le(len_of(name(0).as_bytes()), 2)).collect()
    };

    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&fields(declared.first().copied().unwrap_or(0)));
    zip.extend_from_slice(&[0; 2]);
    zip.extend_from_slice(name(0).as_bytes());
    zip.extend_from_slice(&body);
    let central_at = len_of(&zip);

    for (number, &size) in declared.iter().enumerate() {
        zip.extend_from_slice(b"PK\x01\x02\x14\x00");
        zip.extend_from_slice(&fields(size));
        zip.extend_from_slice(&[0; 16]);
        zip.extend_from_slice(name(number).as_bytes());
    }
    let central_size = len_of(&zip) - central_at;

    zip.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00");
    zip.extend(le(len_of(declared), 2).chain(le(len_of(declared), 2)).chain(le(central_size, 4)).chain(le(central_at, 4)).chain(le(0, 2)));
    zip
}

/// A ZIP archive with one stored, unencrypted entry. `central_extra` goes into its central
/// directory record, which then names `offset` as the place of the local header and `size` as
/// both sizes; `locator` goes between the central directory and its end record.
fn zip_with_stored_entry(size: u32, offset: u32, central_extra: &[u8], locator: &[u8]) -> Vec<u8> {
    let name = b"a.txt";
    let content = b"hello world, this is plain data!";
    let head: Vec<u8> = le(20, 2).chain(le(0, 2)).chain(le(0, 2)).chain(le(0x6000, 2)).chain(le(0x5A21, 2)).chain(le(u64::from(crc32fast::hash(content)), 4)).collect();

    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&head);
    zip.extend(le(len_of(content), 4).chain(le(len_of(content), 4)).chain(le(len_of(name), 2)).chain(le(0, 2)));
    zip.extend_from_slice(name);
    zip.extend_from_slice(content);
    let central_at = len_of(&zip);

    zip.extend_from_slice(b"PK\x01\x02\x14\x00");
    zip.extend_from_slice(&head);
    zip.extend(le(u64::from(size), 4).chain(le(u64::from(size), 4)).chain(le(len_of(name), 2)).chain(le(len_of(central_extra), 2)));
    // no comment, disk 0, no attributes, then where the local header is
    zip.extend_from_slice(&[0; 10]);
    zip.extend(le(u64::from(offset), 4));
    zip.extend_from_slice(name);
    zip.extend_from_slice(central_extra);
    let central_size = len_of(&zip) - central_at;

    zip.extend_from_slice(locator);
    zip.extend_from_slice(b"PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00");
    zip.extend(le(central_size, 4).chain(le(central_at, 4)).chain(le(0, 2)));
    zip
}

// ---------------------------------------------------------------------------
// Building 7z archives
// ---------------------------------------------------------------------------

const SEVENZ_LZMA2: &[u8] = &[0x21];
const SEVENZ_PPMD: &[u8] = &[0x03, 0x04, 0x01];
const SEVENZ_AES: &[u8] = &[0x06, 0xF1, 0x07, 0x01];

/// A 7z NUMBER.
fn number(value: u64) -> Vec<u8> {
    if value < 0x80 {
        return le(value, 1).collect();
    }
    for extra in 1..8_usize {
        if value < 1 << (7 * extra + 7) {
            let marker = (0xFF_u64 << (8 - extra)) & 0xFF;
            return le(marker | (value >> (8 * extra)), 1).chain(le(value, extra)).collect();
        }
    }
    le(0xFF, 1).chain(le(value, 8)).collect()
}

/// One coder of a folder: its id and its properties.
fn coder(id: &[u8], props: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = le(len_of(id) | 0x20, 1).collect();
    out.extend_from_slice(id);
    out.extend(number(len_of(props)));
    out.extend_from_slice(props);
    out
}

/// A signature header, the packed streams and the header that describes them.
fn sevenz(packed: &[u8], header: &[u8]) -> Vec<u8> {
    let start: Vec<u8> = le(len_of(packed), 8).chain(le(len_of(header), 8)).chain(le(u64::from(crc32fast::hash(header)), 4)).collect();
    let mut archive = b"7z\xBC\xAF\x27\x1C\x00\x04".to_vec();
    archive.extend_from_slice(&crc32fast::hash(&start).to_le_bytes());
    archive.extend_from_slice(&start);
    archive.extend_from_slice(packed);
    archive.extend_from_slice(header);
    archive
}

/// A 7z archive whose header is stored packed with LZMA2 and says it unpacks to `declared` bytes.
fn sevenz_with_packed_header(packed: &[u8], declared: u64) -> Vec<u8> {
    let mut header = vec![0x17, 0x06, 0x00, 0x01, 0x09];
    header.extend(number(len_of(packed)));
    header.extend_from_slice(&[0x00, 0x07, 0x0B, 0x01, 0x00, 0x01]);
    header.extend(coder(SEVENZ_LZMA2, &[0x18]));
    header.push(0x0C);
    header.extend(number(declared));
    header.extend_from_slice(&[0x00, 0x00]);
    sevenz(packed, &header)
}

/// A 7z archive of one folder, a compressor behind 7zAES, with one file in it. The folder says
/// `stream` unpacks to `declared` bytes with the CRC-32 `crc`.
///
/// The stream is stored as it is, filled up to the cipher block: nothing here decrypts it, so
/// what the folder would decrypt to is of no account, and what the headers claim is all there is.
fn sevenz_with_encrypted_folder(coder_id: &[u8], props: &[u8], stream: &[u8], declared: u64, crc: u32) -> Vec<u8> {
    const POWER: u8 = 6;
    const SALT: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    const IV: [u8; 16] = [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];

    let mut packed = stream.to_vec();
    packed.resize(stream.len().next_multiple_of(16), 0);

    // 2^POWER rounds, a salt of 8 bytes and an initialisation vector of 16
    let mut aes_props = vec![POWER | 0xC0, 0x7F];
    aes_props.extend_from_slice(&SALT);
    aes_props.extend_from_slice(&IV);

    // pack info: one packed stream
    let mut header = vec![0x01, 0x04, 0x06, 0x00, 0x01, 0x09];
    header.extend(number(len_of(&packed)));
    // unpack info: one folder of two coders, the first reading what the second writes
    header.extend_from_slice(&[0x00, 0x07, 0x0B, 0x01, 0x00, 0x02]);
    header.extend(coder(coder_id, props));
    header.extend(coder(SEVENZ_AES, &aes_props));
    header.extend_from_slice(&[0x00, 0x01, 0x0C]);
    header.extend(number(declared));
    header.extend(number(len_of(stream)));
    header.extend_from_slice(&[0x0A, 0x01]);
    header.extend_from_slice(&crc.to_le_bytes());
    header.extend_from_slice(&[0x00, 0x00]);
    // files info: one file with a name
    let name: Vec<u8> = "zeros.bin\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
    header.extend_from_slice(&[0x05, 0x01, 0x11]);
    header.extend(number(len_of(&name) + 1));
    header.push(0x00);
    header.extend_from_slice(&name);
    header.extend_from_slice(&[0x00, 0x00]);
    sevenz(&packed, &header)
}

// ---------------------------------------------------------------------------
// Offsets and sizes that do not fit
// ---------------------------------------------------------------------------

/// A ZIP64 locator that puts the ZIP64 end record at offset 2^64-1, and a ZIP64 extra field that
/// puts a local header there. `offset + 4` overflowed in the readers and the process panicked.
#[test]
fn zip64_offsets_at_the_end_of_the_address_space_are_read_as_errors() {
    let locator: Vec<u8> = b"PK\x06\x07".iter().copied().chain(le(0, 4)).chain(le(u64::MAX, 8)).chain(le(1, 4)).collect();
    let extra: Vec<u8> = le(1, 2).chain(le(24, 2)).chain(le(32, 8)).chain(le(32, 8)).chain(le(u64::MAX, 8)).collect();

    for (name, archive) in [("locator.zip", zip_with_stored_entry(32, 0, &[], &locator)), ("local-header.zip", zip_with_stored_entry(u32::MAX, u32::MAX, &extra, &[]))] {
        for args in [INFO, HASH] {
            let run = try_archive(&archive, name, args).unwrap();
            assert!(run.ended_normally(), "{name} with {args:?}: {}", run.report());
        }
    }
}

/// 76 bytes that say their header unpacks to 2^62 bytes, or to 2^64-1. A buffer of that size was
/// asked for before a byte was unpacked.
#[test]
fn a_7z_header_that_claims_an_impossible_size_costs_nothing() {
    for declared in [1 << 62, u64::MAX, u64::MAX - 1, 1 << 40] {
        let archive = sevenz_with_packed_header(&[0; 16], declared);
        for args in [INFO, HASH] {
            let run = try_archive(&archive, "claim.7z", args).unwrap();
            assert!(run.ended_normally(), "{declared} bytes with {args:?}: {}", run.report());
        }
    }
}

// ---------------------------------------------------------------------------
// Streams that unpack to more than they say, or to more than may be unpacked
// ---------------------------------------------------------------------------

/// A packed header of 760 KiB that says it unpacks to 100 bytes and unpacks to 4 GiB.
#[test]
fn a_packed_7z_header_is_unpacked_no_further_than_it_declares() {
    let archive = sevenz_with_packed_header(&lzma2_zeros(2048).unwrap(), 100);
    for args in [INFO, HASH] {
        let run = try_archive(&archive, "header-bomb.7z", args).unwrap();
        assert!(run.ended_normally(), "{args:?}: {}", run.report());
    }
}

/// Archives whose encrypted data unpacks to gigabytes, or says it does. Nothing encrypted is
/// unpacked to list an archive or to write its lines, so each of them costs what its headers
/// cost: a 7z folder that says it unpacks to 100 bytes and unpacks to 4 GiB, one that honestly
/// unpacks to 860 MiB, a `PPMd` coder that names a model of gigabytes, a ZIP entry of 570 KiB
/// of `.xz` that unpacks to 3 GiB, the same stream in an entry that says it holds 1000 bytes,
/// and a thousand entries that all are one stream and claim a gigabyte each.
#[test]
fn archives_that_unpack_to_gigabytes_are_listed_and_hashed_without_unpacking_them() {
    let folder_bomb = sevenz_with_encrypted_folder(SEVENZ_LZMA2, &[LZMA2_DICTIONARY], &lzma2_zeros(2048).unwrap(), 100, CRC_100_ZEROS);
    let large_folder = sevenz_with_encrypted_folder(SEVENZ_LZMA2, &[LZMA2_DICTIONARY], &lzma2_zeros(430).unwrap(), 430 * LZMA2_CHUNK_SIZE, CRC_430_CHUNKS);
    let ppmd_props: Vec<u8> = le(6, 1).chain(le(0xC000_0000, 4)).collect();
    let ppmd_memory = sevenz_with_encrypted_folder(SEVENZ_PPMD, &ppmd_props, &[0; 16], 100, CRC_100_ZEROS);

    let unpacked = 1537 * LZMA2_CHUNK_SIZE;
    let xz = xz_around(&lzma2_zeros(1537).unwrap(), unpacked);
    let xz_bomb = zip_with_encrypted_entry(95, &xz, u32::try_from(unpacked).unwrap(), 0x1234_5678);
    let xz_lying = zip_with_encrypted_entry(95, &xz, 1000, 0x060B_1780);

    let mut stream = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut stream, &[0; 100]).unwrap();
    let stream = stream.finish().unwrap();
    let mut declared = vec![(1_u32 << 30) - 1; 1000];
    declared.push(100);
    let shared = zip_with_entries_of_one_stream(8, &stream, &declared, CRC_100_ZEROS);
    assert!(shared.len() < 64 << 10, "{} bytes", shared.len());

    for (name, archive) in [("folder-bomb.7z", folder_bomb), ("large-folder.7z", large_folder), ("ppmd-memory.7z", ppmd_memory), ("xz-bomb.zip", xz_bomb), ("xz-lying.zip", xz_lying), ("shared.zip", shared)] {
        for args in [INFO, HASH] {
            let run = try_archive(&archive, name, args).unwrap();
            assert!(run.ended_normally(), "{name} with {args:?}: {}", run.report());
            assert_eq!(run.code, Some(0), "{name} with {args:?}: {}", run.report());
            // an encrypted archive is listed, and gets a line or the reason why it has none
            let said = !run.stdout.is_empty() || (args == HASH && run.stderr.to_lowercase().contains("no line: "));
            assert!(said, "{name} with {args:?}: the archive is encrypted and says nothing: {}", run.report());
        }
    }
}

/// The build compiles no C: nothing in the lockfile is a compiler driver or a binding to a
/// native library. Two crates carry `-sys` in their names and are Rust all the way down.
#[test]
fn the_lockfile_names_no_native_build_dependency() {
    const DRIVERS: [&str; 6] = ["cc", "cmake", "pkg-config", "bindgen", "vcpkg", "nasm-rs"];
    const RUST_ONLY: [&str; 2] = ["linux-raw-sys", "windows-sys"];

    let names: Vec<&str> = include_str!("../Cargo.lock").lines().filter_map(|line| line.strip_prefix("name = \"")).filter_map(|rest| rest.strip_suffix('"')).collect();
    assert!(names.contains(&"flate2") && names.contains(&"lzma-rust2"), "the lockfile was not read: {names:?}");
    let native: Vec<&&str> = names.iter().filter(|name| DRIVERS.contains(name) || (name.ends_with("-sys") && !RUST_ONLY.contains(name))).collect();
    assert!(native.is_empty(), "native build dependencies in Cargo.lock: {native:?}");
}
