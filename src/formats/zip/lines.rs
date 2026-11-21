//! Hash format emission for ZIP archives.
//!
//! Four line formats, one per way a ZIP entry can be protected:
//!
//! - `$zip$1$` traditional encryption (ZipCrypto), hashcat mode 46100
//! - `$zip$2$` WinZip AES, hashcat mode 46200
//! - `$zip$3$` PKWARE strong encryption with AES, hashcat modes 46300, 46310 and 46320 by key size
//! - `$zip$4$` the three internal ZipCrypto keys, hashcat modes 46400 and 46410

use std::fmt::Write as _;

/// The most members a `$zip$1$` line tests.
pub(crate) const ZIP1_MAX_CHECKS: usize = 8;

/// The 12-byte encryption header of a ZipCrypto entry and what its end decrypts to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Zip1Check {
    /// The encrypted header as it is stored in front of the entry's data.
    pub header: [u8; 12],
    /// Whether the last two bytes are known, or only the last one.
    pub two_bytes: bool,
    /// The expected plaintext: the second-last byte in the low half, the last byte in the high half.
    pub value: u16,
    /// A second value the writer may have used instead, in the same layout.
    pub alternative: Option<u16>,
}

/// Everything a `$zip$1$` line carries.
#[derive(Debug, Clone)]
pub(crate) struct Zip1Input {
    /// One to eight header checks. The first belongs to the entry whose data follows.
    pub checks: Vec<Zip1Check>,
    /// Compression method of the first entry.
    pub method: u16,
    /// CRC-32 of the first entry's contents.
    pub crc32: u32,
    /// Size of the first entry's contents.
    pub unpacked: u64,
    /// Size of its encrypted stream without the 12-byte header.
    pub packed: u64,
    /// That stream, the start of it, or nothing.
    pub data: Vec<u8>,
}

/// Input data for a WinZip AES entry in a `$zip$2$` hash.
#[derive(Debug, Clone)]
pub(crate) struct ZipWinzipHashInput {
    /// AES strength: 1 = AES-128, 2 = AES-192, 3 = AES-256.
    pub strength: u8,
    /// PBKDF2 salt (8, 12, or 16 bytes depending on strength).
    pub salt: Vec<u8>,
    /// 2-byte password verification value from PBKDF2 output.
    pub password_verify: [u8; 2],
    /// HMAC-SHA1 truncated to 10 bytes (authentication code).
    pub auth_code: [u8; 10],
    /// The compression method the entry really uses (the header says 99).
    pub method: u16,
    /// Size of the ciphertext.
    pub packed: u64,
    /// The ciphertext, the start of it, or nothing.
    pub data: Vec<u8>,
}

/// Input data for a PKWARE strong encryption entry in a `$zip$3$` hash.
#[derive(Debug, Clone)]
pub(crate) struct ZipPkwareHashInput {
    /// Algorithm identifier from the decryption header (0x6601 to 0x6801).
    pub alg_id: u16,
    /// Key length in bits.
    pub bit_len: u16,
    /// Processing flags of the decryption header.
    pub flags: u16,
    /// Initialisation vector: the one the header stores, or the CRC-32 and size it stands for.
    pub iv: Vec<u8>,
    /// The encrypted random data, whole.
    pub erd: Vec<u8>,
    /// The encrypted validation data with its CRC-32, whole.
    pub vdata: Vec<u8>,
}

fn push_check(out: &mut String, check: &Zip1Check) {
    let show = |v: u16| if check.two_bytes { format!("{v:04x}") } else { format!("{:02x}", v >> 8) };
    let _ = write!(out, "*{}/{}", hex::encode(check.header), show(check.value));
    if let Some(alt) = check.alternative.filter(|a| show(*a) != show(check.value)) {
        let _ = write!(out, "/{}", show(alt));
    }
}

/// Emit a `$zip$1$` line.
///
/// `$zip$1$*N*check_1*...*check_N*method*crc32*unpacked*packed*data$/zip$`
#[must_use]
pub(crate) fn emit_zip1(input: &Zip1Input) -> String {
    let checks = input.checks.get(..input.checks.len().min(ZIP1_MAX_CHECKS)).unwrap_or(&input.checks);
    let mut out = format!("$zip$1$*{}", checks.len());
    for check in checks {
        push_check(&mut out, check);
    }
    let _ = write!(out, "*{}*{:08x}*{:x}*{:x}*{}$/zip$", input.method, input.crc32, input.unpacked, input.packed, hex::encode(&input.data));
    out
}

/// Emit a `$zip$2$` line.
///
/// `$zip$2$*strength*salt*verifier*auth*method*packed*data$/zip$`
#[must_use]
pub(crate) fn emit_zip2(input: &ZipWinzipHashInput) -> String {
    format!("$zip$2$*{}*{}*{}*{}*{}*{:x}*{}$/zip$", input.strength, hex::encode(&input.salt), hex::encode(input.password_verify), hex::encode(input.auth_code), input.method, input.packed, hex::encode(&input.data))
}

/// Emit a `$zip$3$` line.
///
/// `$zip$3$*algorithm*bits*flags*iv*erd*vdata$/zip$`
#[must_use]
pub(crate) fn emit_zip3(input: &ZipPkwareHashInput) -> String {
    format!("$zip$3$*{:04x}*{}*{:x}*{}*{}*{}$/zip$", input.alg_id, input.bit_len, input.flags, hex::encode(&input.iv), hex::encode(&input.erd), hex::encode(&input.vdata))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(two_bytes: bool, value: u16, alternative: Option<u16>) -> Zip1Check {
        Zip1Check { header: [0x11; 12], two_bytes, value, alternative }
    }

    #[test]
    fn zip1_one_byte_check_shows_the_last_byte() {
        let input = Zip1Input { checks: vec![check(false, 0xAB12, None)], method: 8, crc32: 0xDEAD_BEEF, unpacked: 0x20, packed: 3, data: vec![1, 2, 3] };
        assert_eq!(emit_zip1(&input), "$zip$1$*1*111111111111111111111111/ab*8*deadbeef*20*3*010203$/zip$");
    }

    #[test]
    fn zip1_two_byte_check_shows_both() {
        let input = Zip1Input { checks: vec![check(true, 0xAB12, None)], method: 0, crc32: 1, unpacked: 0, packed: 0, data: Vec::new() };
        assert_eq!(emit_zip1(&input), "$zip$1$*1*111111111111111111111111/ab12*0*00000001*0*0*$/zip$");
    }

    #[test]
    fn zip1_alternative_is_written_only_when_it_differs() {
        let both = Zip1Input { checks: vec![check(false, 0xAB00, Some(0xCD00))], method: 0, crc32: 0, unpacked: 0, packed: 0, data: Vec::new() };
        assert!(emit_zip1(&both).contains("/ab/cd*"));
        let same = Zip1Input { checks: vec![check(false, 0xAB00, Some(0xAB77))], method: 0, crc32: 0, unpacked: 0, packed: 0, data: Vec::new() };
        assert!(emit_zip1(&same).contains("/ab*"));
    }

    #[test]
    fn zip1_never_writes_more_than_eight_checks() {
        let input = Zip1Input { checks: vec![check(false, 0, None); 11], method: 0, crc32: 0, unpacked: 0, packed: 0, data: Vec::new() };
        let line = emit_zip1(&input);
        assert!(line.starts_with("$zip$1$*8*"));
        assert_eq!(line.matches('/').count(), 8 + 1);
    }

    #[test]
    fn zip2_fields() {
        let input = ZipWinzipHashInput { strength: 3, salt: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], password_verify: [0xAA, 0xBB], auth_code: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], method: 8, packed: 256, data: vec![0xFF; 4] };
        assert_eq!(emit_zip2(&input), "$zip$2$*3*0102030405060708090a0b0c0d0e0f10*aabb*0102030405060708090a*8*100*ffffffff$/zip$");
    }

    #[test]
    fn zip3_fields() {
        let input = ZipPkwareHashInput { alg_id: 0x660E, bit_len: 128, flags: 1, iv: vec![0xAA; 16], erd: vec![0xBB; 32], vdata: vec![0xCC; 20] };
        let line = emit_zip3(&input);
        assert!(line.starts_with("$zip$3$*660e*128*1*"));
        assert_eq!(line.matches('*').count(), 6);
        assert!(line.ends_with(&format!("*{}$/zip$", hex::encode([0xCC; 20]))));
    }
}
