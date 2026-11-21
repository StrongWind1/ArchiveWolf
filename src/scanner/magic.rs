//! Magic byte definitions and SFX offset scanning.
//!
//! Identifies archive formats by their binary signatures at fixed offsets,
//! never by file extension.
//!
//! A signature at the start of a file is taken at its word: if what follows is damaged, the
//! parser says so. A signature found inside a program is only a candidate. The bytes of a
//! signature turn up in code and in text, so a candidate counts when what follows it has
//! the structure of that archive, and the scan goes on when it does not.

use std::cell::OnceCell;

use crate::analysis::Format;
use crate::formats::SFX_SCAN_LIMIT;

/// ZIP local file header: `PK\x03\x04`.
const ZIP_LOCAL: &[u8] = b"PK\x03\x04";
/// ZIP empty archive (EOCD only): `PK\x05\x06`.
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
/// ZIP spanned archive marker: `PK\x07\x08`.
const ZIP_SPANNED: &[u8] = b"PK\x07\x08";

/// Generation `rar1`, RAR 1.3 and 1.4: `RE~^`.
const RAR1: &[u8] = b"RE~^";
/// Generation `rar4`, RAR 1.5 to 4.x: `Rar!\x1a\x07\x00`.
const RAR4: &[u8] = b"Rar!\x1a\x07\x00";
/// Generation `rar5`, RAR 5 and 7: `Rar!\x1a\x07\x01\x00`.
const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";

/// 7-Zip: `7z\xbc\xaf\x27\x1c`.
const SEVENZ: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Which structure a signature announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signature {
    Rar5,
    Rar4,
    SevenZ,
    ZipLocal,
    ZipEocd,
    ZipSpanned,
    Rar1,
}

/// All recognized signatures, ordered longest-first so that RAR5 matches
/// before RAR3 when both prefixes overlap.
const SIGNATURES: &[(&[u8], Format, Signature)] = &[
    (RAR5, Format::Rar, Signature::Rar5),
    (RAR4, Format::Rar, Signature::Rar4),
    (SEVENZ, Format::SevenZ, Signature::SevenZ),
    (ZIP_LOCAL, Format::Zip, Signature::ZipLocal),
    (ZIP_EOCD, Format::Zip, Signature::ZipEocd),
    (ZIP_SPANNED, Format::Zip, Signature::ZipSpanned),
    (RAR1, Format::Rar, Signature::Rar1),
];

/// The longest signature, and so the most a file has to give up to be told from an archive.
pub(crate) const SIGNATURE_MAX: usize = RAR5.len();

/// Check magic bytes at offset 0 and return the archive kind.
#[must_use]
pub fn detect(data: &[u8]) -> Option<Format> {
    SIGNATURES.iter().find(|(sig, _, _)| data.starts_with(sig)).map(|&(_, kind, _)| kind)
}

/// Whether a file starts like a program (PE `MZ` or ELF), the only files searched for an
/// archive behind a self-extracting stub.
#[must_use]
pub(crate) fn is_executable(head: &[u8]) -> bool {
    head.starts_with(b"MZ") || head.starts_with(b"\x7fELF")
}

/// The first header of a RAR 5 archive is checked when it is no longer than this. A main
/// archive header is a few dozen bytes.
const RAR5_FIRST_HEADER_MAX: usize = 4096;

/// Bytes read past [`SFX_SCAN_LIMIT`], so that a signature found just below the limit still
/// has the header behind it in the window.
const SFX_LOOKAHEAD: usize = 2 * RAR5_FIRST_HEADER_MAX;

/// How much of the start of a program the scanner reads to search it.
pub(crate) const SFX_WINDOW: usize = SFX_SCAN_LIMIT + SFX_LOOKAHEAD;

/// How much of the end of a file says whether it ends in a ZIP archive: the end record and
/// the longest comment it can carry.
pub(crate) const ZIP_TAIL: usize = 22 + 65_535;

/// First bytes of each signature, used as a fast prefilter in SFX scanning.
const SIG_FIRST_BYTES: &[u8] = &[b'R', 0x37, b'P'];

/// A program searched for an archive: its start, its end and its length.
///
/// `window` holds the first [`SFX_WINDOW`] bytes or the whole file when it is shorter, and
/// `tail` the last [`ZIP_TAIL`] bytes or the whole file when it is shorter.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Program<'a> {
    /// The start of the file.
    pub window: &'a [u8],
    /// The end of the file.
    pub tail: &'a [u8],
    /// The length of the file.
    pub len: u64,
}

/// Scan for an embedded archive signature at a non-zero offset (SFX detection).
///
/// Only runs on files that look like executables (PE `MZ` or ELF `\x7fELF` header).
/// A signature has to lie within the first [`SFX_SCAN_LIMIT`] bytes and be followed by the
/// structure of its archive. Returns the archive kind and the offset of the first that is.
#[must_use]
pub(crate) fn scan_sfx(program: &Program<'_>) -> Option<(Format, usize)> {
    if !is_executable(program.window) {
        return None;
    }

    let searched = program.window.get(..SFX_SCAN_LIMIT).unwrap_or(program.window);
    // whether the file ends in a ZIP archive is the same for every candidate: found out once
    let ends_in_zip = OnceCell::new();

    for (offset, first) in searched.iter().enumerate().skip(1) {
        if !SIG_FIRST_BYTES.contains(first) {
            continue;
        }
        let (Some(inside), Some(follows)) = (searched.get(offset..), program.window.get(offset..)) else { break };
        for &(sig, kind, signature) in SIGNATURES {
            if inside.starts_with(sig) && is_archive_start(signature, follows, offset, program, &ends_in_zip) {
                return Some((kind, offset));
            }
        }
    }
    None
}

/// Whether the bytes behind a signature have the structure of the archive it announces.
///
/// `follows` starts at the signature, which is `offset` bytes into the file.
fn is_archive_start(signature: Signature, follows: &[u8], offset: usize, program: &Program<'_>, ends_in_zip: &OnceCell<bool>) -> bool {
    let zip_end = || *ends_in_zip.get_or_init(|| crate::formats::zip::headers::find_eocd(program.tail).is_ok());
    match signature {
        Signature::SevenZ => sevenz_start_header(follows),
        Signature::Rar5 => rar5_first_header(follows),
        Signature::Rar4 => rar4_main_header(follows, offset, program.len),
        Signature::Rar1 => rar1_main_header(follows, program.window),
        Signature::ZipLocal => zip_local_header(follows, offset, program.len) && zip_end(),
        Signature::ZipSpanned => follows.get(ZIP_SPANNED.len()..).is_some_and(|next| next.starts_with(ZIP_LOCAL) && zip_local_header(next, offset.saturating_add(ZIP_SPANNED.len()), program.len)) && zip_end(),
        Signature::ZipEocd => zip_end(),
    }
}

/// Little-endian `u16` at `at`.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes.get(at..)?.first_chunk::<2>().copied().map(u16::from_le_bytes)
}

/// Little-endian `u32` at `at`.
fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes.get(at..)?.first_chunk::<4>().copied().map(u32::from_le_bytes)
}

/// Whether a structure of `size` bytes that starts `offset` bytes into the file ends inside it.
fn fits(offset: usize, size: usize, len: u64) -> bool {
    offset.checked_add(size).and_then(|end| u64::try_from(end).ok()).is_some_and(|end| end <= len)
}

/// 7z: the start header is 32 bytes, and bytes 8..12 are the CRC-32 of bytes 12..32.
fn sevenz_start_header(follows: &[u8]) -> bool {
    match (u32_at(follows, 8), follows.get(12..32)) {
        (Some(stored), Some(covered)) => crc32fast::hash(covered) == stored,
        _ => false,
    }
}

/// RAR 5: the signature is followed by an archive header or an encryption header, whose
/// CRC-32 covers everything from its size field on.
fn rar5_first_header(follows: &[u8]) -> bool {
    let Some(block) = follows.get(RAR5.len()..) else { return false };
    let (Some(stored), Some(sized)) = (u32_at(block, 0), block.get(4..)) else { return false };

    // the size is a variable-length integer of at most three bytes, seven bits in each
    let mut size = 0_usize;
    let mut size_len = 0_usize;
    for (shift, byte) in [0_u32, 7, 14].into_iter().zip(sized) {
        size |= usize::from(byte & 0x7F) << shift;
        size_len += 1;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let ended = size_len.checked_sub(1).and_then(|last| sized.get(last)).is_some_and(|byte| byte & 0x80 == 0);
    if !ended || size == 0 || size > RAR5_FIRST_HEADER_MAX {
        return false;
    }

    // 1 is the main archive header, 4 the archive encryption header
    let kind = sized.get(size_len);
    let covered = sized.get(..size_len + size);
    matches!(kind, Some(1 | 4)) && covered.is_some_and(|covered| crc32fast::hash(covered) == stored)
}

/// RAR 1.5 to 4: the seven-byte marker is followed by the main header, type `0x73`, at
/// least 13 bytes long.
fn rar4_main_header(follows: &[u8], offset: usize, len: u64) -> bool {
    let Some(header) = follows.get(RAR4.len()..) else { return false };
    let (Some(&kind), Some(size)) = (header.get(2), u16_at(header, 5)) else { return false };
    kind == 0x73 && size >= 13 && offset.checked_add(RAR4.len()).is_some_and(|start| fits(start, usize::from(size), len))
}

/// RAR 1.4: a self-extracting archive carries `RSFX` at byte 28 of the program, and the
/// main header is at least seven bytes long.
fn rar1_main_header(follows: &[u8], window: &[u8]) -> bool {
    window.get(28..32).is_some_and(|mark| mark == b"RSFX") && u16_at(follows, RAR1.len()).is_some_and(|size| size >= 7)
}

/// ZIP: a local file header is 30 bytes and then a name and an extra field of the lengths
/// it gives, all of it inside the file.
fn zip_local_header(follows: &[u8], offset: usize, len: u64) -> bool {
    match (u16_at(follows, 26), u16_at(follows, 28)) {
        (Some(name), Some(extra)) => fits(offset, 30 + usize::from(name) + usize::from(extra), len),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Search a file held in memory the way the scanner searches one on disk.
    fn scan(data: &[u8]) -> Option<(Format, usize)> {
        let window = data.get(..SFX_WINDOW).unwrap_or(data);
        let tail = data.get(data.len().saturating_sub(ZIP_TAIL)..).unwrap_or(data);
        scan_sfx(&Program { window, tail, len: data.len() as u64 })
    }

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(format!("tests/fixtures/{rel}")).unwrap()
    }

    /// A program of `len` bytes: the ELF magic and zeros.
    fn stub(len: usize) -> Vec<u8> {
        let mut data = b"\x7fELF".to_vec();
        data.resize(len, 0);
        data
    }

    #[test]
    fn detect_zip_local() {
        let data = b"PK\x03\x04rest of file";
        assert_eq!(detect(data), Some(Format::Zip));
    }

    #[test]
    fn detect_zip_eocd_only() {
        let data = b"PK\x05\x06\x00\x00";
        assert_eq!(detect(data), Some(Format::Zip));
    }

    #[test]
    fn detect_zip_spanned() {
        let data = b"PK\x07\x08data";
        assert_eq!(detect(data), Some(Format::Zip));
    }

    #[test]
    fn detect_rar1() {
        let data = b"RE~^data";
        assert_eq!(detect(data), Some(Format::Rar));
    }

    #[test]
    fn detect_rar4() {
        let data = b"Rar!\x1a\x07\x00data";
        assert_eq!(detect(data), Some(Format::Rar));
    }

    #[test]
    fn detect_rar5() {
        let data = b"Rar!\x1a\x07\x01\x00data";
        assert_eq!(detect(data), Some(Format::Rar));
    }

    #[test]
    fn detect_sevenz() {
        let mut data = vec![0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
        data.extend_from_slice(b"rest");
        assert_eq!(detect(&data), Some(Format::SevenZ));
    }

    #[test]
    fn detect_garbage_returns_none() {
        assert_eq!(detect(b"not an archive"), None);
        assert_eq!(detect(b""), None);
        assert_eq!(detect(b"PK"), None);
    }

    #[test]
    fn detect_needs_no_more_than_the_longest_signature() {
        for rel in ["zip-crypto/zipcrypto.zip", "rar-50/v730_p_m3.rar", "rar-30/v420_p_m3.rar", "rar-13/rar14-password-stored.rar", "7z-aes/flag.7z"] {
            let data = fixture(rel);
            assert_eq!(detect(&data[..SIGNATURE_MAX]), detect(&data), "{rel}");
            assert!(detect(&data).is_some(), "{rel}");
        }
    }

    #[test]
    fn sfx_finds_the_archive_in_every_self_extracting_fixture() {
        for (rel, expected) in [
            ("zip-crypto/zipcrypto_sfx.zip", (Format::Zip, 512)),
            ("7z-aes/gen_7z_sfx.7z", (Format::SevenZ, 43_432)),
            ("rar-30/v420_p_m3_sfx.sfx", (Format::Rar, 244_864)),
            ("rar-30/v420_hp_m3_sfx.sfx", (Format::Rar, 244_864)),
            ("rar-50/v730_p_m3_sfx.sfx", (Format::Rar, 244_864)),
            ("rar-50/v730_hp_m3_sfx.sfx", (Format::Rar, 244_864)),
        ] {
            assert_eq!(scan(&fixture(rel)), Some(expected), "{rel}");
        }
    }

    #[test]
    fn sfx_finds_embedded_zip_in_pe() {
        let mut data = b"MZ".to_vec();
        data.resize(100, 0x00);
        data.extend_from_slice(&fixture("zip-crypto/zipcrypto.zip"));
        assert_eq!(scan(&data), Some((Format::Zip, 100)));
    }

    #[test]
    fn sfx_finds_embedded_rar5_in_elf() {
        let mut data = stub(200);
        data.extend_from_slice(&fixture("rar-50/v730_p_m3.rar"));
        assert_eq!(scan(&data), Some((Format::Rar, 200)));
    }

    #[test]
    fn sfx_finds_embedded_rar4_and_7z() {
        let mut data = stub(300);
        data.extend_from_slice(&fixture("rar-30/v420_p_m3.rar"));
        assert_eq!(scan(&data), Some((Format::Rar, 300)));

        let mut data = stub(300);
        data.extend_from_slice(&fixture("7z-aes/flag.7z"));
        assert_eq!(scan(&data), Some((Format::SevenZ, 300)));
    }

    #[test]
    fn sfx_skips_non_executable() {
        let mut data = vec![0x00; 100];
        data.extend_from_slice(&fixture("zip-crypto/zipcrypto.zip"));
        assert_eq!(scan(&data), None);
    }

    #[test]
    fn sfx_searches_as_far_as_the_format_code() {
        // a two-megabyte program in front of a 7z archive: past the megabyte this once stopped at
        let mut data = stub(2 << 20);
        data.extend_from_slice(&fixture("7z-aes/flag.7z"));
        assert_eq!(scan(&data), Some((Format::SevenZ, 2 << 20)));
        assert_eq!(crate::formats::sevenz::line::archive_start(&data), Some(2 << 20), "the 7z code finds the same archive");

        // the last place a signature can lie, and one byte past it
        let archive = fixture("7z-aes/flag.7z");
        let mut data = stub(SFX_SCAN_LIMIT - SEVENZ.len());
        data.extend_from_slice(&archive);
        assert_eq!(scan(&data), Some((Format::SevenZ, SFX_SCAN_LIMIT - SEVENZ.len())));
        assert_eq!(crate::formats::sevenz::line::archive_start(&data), Some(SFX_SCAN_LIMIT - SEVENZ.len()));

        let mut data = stub(SFX_SCAN_LIMIT - SEVENZ.len() + 1);
        data.extend_from_slice(&archive);
        assert_eq!(scan(&data), None);
        assert_eq!(crate::formats::sevenz::line::archive_start(&data), None);
    }

    #[test]
    fn sfx_passes_over_a_signature_with_nothing_behind_it() {
        // PK\x03\x04 in the program, and the 7z archive behind it
        let mut data = b"MZ".to_vec();
        data.resize(1000, 0);
        data.extend_from_slice(ZIP_LOCAL);
        data.resize(4000, 0);
        data.extend_from_slice(&fixture("7z-aes/flag.7z"));
        assert_eq!(scan(&data), Some((Format::SevenZ, 4000)));

        // every signature, bare, in front of a real archive of another kind
        for (decoy, rel, kind) in [
            (RAR5, "zip-crypto/zipcrypto.zip", Format::Zip),
            (RAR4, "7z-aes/flag.7z", Format::SevenZ),
            (RAR1, "7z-aes/flag.7z", Format::SevenZ),
            (SEVENZ, "rar-50/v730_p_m3.rar", Format::Rar),
            (ZIP_LOCAL, "rar-30/v420_p_m3.rar", Format::Rar),
            (ZIP_EOCD, "rar-50/v730_p_m3.rar", Format::Rar),
            (ZIP_SPANNED, "7z-aes/flag.7z", Format::SevenZ),
        ] {
            let mut data = stub(64);
            data.extend_from_slice(decoy);
            data.extend_from_slice(b" marks the start of an archive. ");
            data.resize(512, 0);
            data.extend_from_slice(&fixture(rel));
            assert_eq!(scan(&data), Some((kind, 512)), "decoy {decoy:?} in front of {rel}");
        }
    }

    #[test]
    fn sfx_takes_the_archive_and_not_the_text_about_it() {
        // "Rar!" in the text of the program, then the archive
        let mut data = b"MZ\x90\x00 stub text mentioning Rar! archives ".to_vec();
        data.resize(44, 0);
        data.extend_from_slice(&fixture("rar-50/v730_p_m3.rar"));
        assert_eq!(scan(&data), Some((Format::Rar, 44)));
    }

    #[test]
    fn sfx_finds_nothing_in_a_program_of_signatures_alone() {
        let mut data = stub(16);
        for _ in 0..2000 {
            for &(sig, _, _) in SIGNATURES {
                data.extend_from_slice(sig);
                data.extend_from_slice(&[0x01, 0x80, 0x80, 0x00, 0x05]);
            }
        }
        assert_eq!(scan(&data), None);
    }

    #[test]
    fn rar5_header_check_reads_the_size_and_the_checksum() {
        let archive = fixture("rar-50/v730_p_m3.rar");
        assert!(rar5_first_header(&archive));

        let mut damaged = archive.clone();
        damaged[8] ^= 1;
        assert!(!rar5_first_header(&damaged), "a wrong CRC-32");
        assert!(!rar5_first_header(&archive[..14]), "a header cut short");
        assert!(!rar5_first_header(RAR5), "nothing behind the signature");

        // a size field of three continuation bytes never ends
        let mut endless = RAR5.to_vec();
        endless.extend_from_slice(&[0, 0, 0, 0, 0x80, 0x80, 0x80, 0x01]);
        assert!(!rar5_first_header(&endless));
    }

    #[test]
    fn rar1_counts_only_behind_a_program_marked_rsfx() {
        let archive = fixture("rar-13/rar14-password-stored.rar");
        let mut data = b"MZ".to_vec();
        data.resize(64, 0);
        data.extend_from_slice(&archive);
        assert_eq!(scan(&data), None, "no RSFX mark");

        data[28..32].copy_from_slice(b"RSFX");
        assert_eq!(scan(&data), Some((Format::Rar, 64)));
    }
}
