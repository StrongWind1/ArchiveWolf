//! Hash format emission for RAR archives.
//!
//! Emits `$rar$15$`, `$rar$20$`, `$rar$30$` and `$rar$50$` format strings
//! for RAR 1.5, 2.0, 3.x-4.x and 5.0+ encrypted entries.

use std::fmt::Write as _;

/// Input data for a `$rar$15$` or `$rar$20$` hash (RAR 1.5/2.0 legacy ciphers).
///
/// Both formats share the same field layout: `$rar$NN$*crc*us*ds*method*data$/rar$`.
#[derive(Debug, Clone)]
pub(crate) struct RarLegacyHashInput {
    /// CRC32 of uncompressed data.
    pub crc32: u32,
    /// Uncompressed size in bytes.
    pub unpack_size: u64,
    /// Size of encrypted data included.
    pub data_size: u64,
    /// Compression method byte from the file header: 0x30 stored, 0x31-0x35 compressed.
    pub method: u8,
    /// Encrypted data bytes.
    pub data: Vec<u8>,
}

/// Emit a `$rar$15$` hash string (RAR 1.5 CRC32-based stream cipher).
#[must_use]
pub(crate) fn emit_rar_15(input: &RarLegacyHashInput) -> String {
    let mut out = String::with_capacity(256);
    let _ = write!(out, "$rar$15$*{:08x}*{:x}*{:x}*{:x}*{}$/rar$", input.crc32, input.unpack_size, input.data_size, input.method, hex::encode(&input.data));
    out
}

/// Emit a `$rar$20$` hash string (RAR 2.0 Feistel block cipher).
#[must_use]
pub(crate) fn emit_rar_20(input: &RarLegacyHashInput) -> String {
    let mut out = String::with_capacity(256);
    let _ = write!(out, "$rar$20$*{:08x}*{:x}*{:x}*{:x}*{}$/rar$", input.crc32, input.unpack_size, input.data_size, input.method, hex::encode(&input.data));
    out
}

/// Input data for a `$rar$30$` hash (RAR 3.x-4.x, AES-128-CBC).
#[derive(Debug, Clone)]
pub(crate) struct Rar30HashInput {
    /// 0 = header-encrypted (-hp), 1 = file-level (-p).
    pub hash_type: u8,
    /// 8-byte salt.
    pub salt: [u8; 8],
    /// CRC32: `0xc43d_7b00` for type 0, file CRC32 for type 1.
    pub crc32: u32,
    /// Packed (encrypted) size in bytes, multiple of 16.
    pub pack_size: u64,
    /// Unpacked size in bytes.
    pub unpack_size: u64,
    /// Compression method: 0 for header, 0x30-0x35 for file-level.
    pub method: u8,
    /// Encrypted data bytes.
    pub data: Vec<u8>,
}

/// Input data for a `$rar$50$` hash (RAR 5.0+/RAR 7, AES-256-CBC).
#[derive(Debug, Clone)]
pub(crate) struct Rar50HashInput {
    /// 0 = PswCheck-only, 1 = decrypt+checksum.
    pub hash_type: u8,
    /// 16-byte PBKDF2 salt.
    pub salt: [u8; 16],
    /// Log2 of PBKDF2 iteration count.
    pub lg2count: u8,
    /// 16-byte AES IV (zeros for type 0).
    pub iv: [u8; 16],
    /// 8-byte PswCheck (type 0 only).
    pub psw_check: Option<[u8; 8]>,
    /// Checksum type: 0=CRC32, 1=CRC32+HASHMAC, 2=BLAKE2sp, 3=BLAKE2sp+HASHMAC, 4=header structure.
    pub check_type: u8,
    /// CRC32 (type 1, checktype 0/1 only).
    pub crc32: Option<u32>,
    /// BLAKE2sp 32-byte digest (type 1, checktype 2/3 only).
    pub blake2sp: Option<[u8; 32]>,
    /// Packed size (type 1 only).
    pub pack_size: Option<u64>,
    /// Unpacked size (type 1 only).
    pub unpack_size: Option<u64>,
    /// Compression method (type 1 only).
    pub method: Option<u8>,
    /// Encrypted data (type 1 only).
    pub data: Option<Vec<u8>>,
}

/// Emit a `$rar$30$` hash string.
#[must_use]
pub(crate) fn emit_rar_30(input: &Rar30HashInput) -> String {
    let mut out = String::with_capacity(256);
    let _ = write!(out, "$rar$30$*{}*{}*{:08x}*{:x}*{:x}*{:x}*{}$/rar$", input.hash_type, hex::encode(input.salt), input.crc32, input.pack_size, input.unpack_size, input.method, hex::encode(&input.data));
    out
}

/// Emit a `$rar$50$` hash string.
#[must_use]
pub(crate) fn emit_rar_50(input: &Rar50HashInput) -> String {
    let mut out = String::with_capacity(512);
    let _ = write!(out, "$rar$50$*{}*{}*{}*{}", input.hash_type, hex::encode(input.salt), input.lg2count, hex::encode(input.iv));

    if let Some(pc) = &input.psw_check {
        let _ = write!(out, "*{}", hex::encode(pc));
    } else {
        let _ = write!(out, "*");
    }

    let _ = write!(out, "*{}", input.check_type);

    if input.hash_type == 1 {
        // checktype 2/3 use 64-hex BLAKE2sp digest; 0/1 use 8-hex CRC32
        let checksum_hex = if input.check_type >= 2 { input.blake2sp.map_or_else(String::new, hex::encode) } else { input.crc32.map_or_else(String::new, |c| format!("{c:08x}")) };
        let _ = write!(out, "*{checksum_hex}");
        let _ = write!(out, "*{}", input.pack_size.map_or_else(String::new, |p| format!("{p:x}")));
        let _ = write!(out, "*{}", input.unpack_size.map_or_else(String::new, |u| format!("{u:x}")));
        let _ = write!(out, "*{}", input.method.map_or_else(String::new, |m| format!("{m:x}")));
        let _ = write!(out, "*{}", input.data.as_ref().map_or_else(String::new, hex::encode));
    } else {
        let _ = write!(out, "*****");
    }

    let _ = write!(out, "$/rar$");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emit_rar_30_type0() {
        let input = Rar30HashInput { hash_type: 0, salt: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], crc32: 0xc43d_7b00, pack_size: 16, unpack_size: 0, method: 0, data: vec![0xAA; 16] };
        let hash = emit_rar_30(&input);
        assert!(hash.starts_with("$rar$30$*0*"));
        assert!(hash.ends_with("$/rar$"));
        assert!(hash.contains("*c43d7b00*"));
        assert!(hash.contains("*10*")); // 16 in hex
        assert!(hash.contains("*0*0*")); // unpack=0, method=0
    }

    #[test]
    fn test_emit_rar_30_type1() {
        let input = Rar30HashInput { hash_type: 1, salt: [0xFF; 8], crc32: 0x1234_5678, pack_size: 32, unpack_size: 100, method: 0x33, data: vec![0xBB; 32] };
        let hash = emit_rar_30(&input);
        assert!(hash.starts_with("$rar$30$*1*"));
        assert!(hash.contains("*12345678*"));
        assert!(hash.contains("*33*")); // method 0x33 = Normal compression, printed as hex "33"
    }

    #[test]
    fn test_emit_rar_50_type0() {
        let input = Rar50HashInput { hash_type: 0, salt: [0x11; 16], lg2count: 15, iv: [0; 16], psw_check: Some([0xAA; 8]), check_type: 0, crc32: None, blake2sp: None, pack_size: None, unpack_size: None, method: None, data: None };
        let hash = emit_rar_50(&input);
        assert!(hash.starts_with("$rar$50$*0*"));
        assert!(hash.ends_with("$/rar$"));
        assert!(hash.contains("*15*")); // lg2count
        assert!(hash.contains("*aaaaaaaaaaaaaaaa*")); // pswcheck
        assert!(hash.contains("*0*")); // check_type
        assert!(hash.ends_with("*0*****$/rar$")); // checktype, then five empty type-1 fields
        assert_eq!(hash.matches('*').count(), 11, "type 0 and type 1 carry the same 11 fields");
    }

    #[test]
    fn test_emit_rar_50_type1() {
        let input = Rar50HashInput { hash_type: 1, salt: [0x22; 16], lg2count: 20, iv: [0x33; 16], psw_check: None, check_type: 2, crc32: None, blake2sp: Some([0xDD; 32]), pack_size: Some(256), unpack_size: Some(512), method: Some(0), data: Some(vec![0xCC; 32]) };
        let hash = emit_rar_50(&input);
        assert!(hash.starts_with("$rar$50$*1*"));
        assert!(hash.contains("*20*")); // lg2count
        assert!(hash.contains("**2*")); // empty pswcheck, checktype 2
        assert!(hash.contains(&format!("*{}*", hex::encode([0xDD; 32])))); // blake2sp digest
        assert!(hash.contains("*100*")); // 256 hex
        assert!(hash.contains("*200*")); // 512 hex
        assert_eq!(hash.matches('*').count(), 11, "type 0 and type 1 carry the same 11 fields");
    }

    #[test]
    fn test_emit_rar_50_type0_no_pswcheck() {
        let input = Rar50HashInput { hash_type: 0, salt: [0; 16], lg2count: 10, iv: [0; 16], psw_check: None, check_type: 0, crc32: None, blake2sp: None, pack_size: None, unpack_size: None, method: None, data: None };
        let hash = emit_rar_50(&input);
        assert!(hash.contains("**0*")); // empty pswcheck, checktype 0
    }

    #[test]
    fn test_emit_rar_15() {
        let input = RarLegacyHashInput { crc32: 0xAABB_CCDD, unpack_size: 100, data_size: 64, method: 0x33, data: vec![0x42; 64] };
        let hash = emit_rar_15(&input);
        assert!(hash.starts_with("$rar$15$*aabbccdd*"));
        assert!(hash.ends_with("$/rar$"));
        assert!(hash.contains("*64*40*33*")); // us=100(0x64), ds=64(0x40), method 0x33
    }

    #[test]
    fn test_emit_rar_20() {
        let input = RarLegacyHashInput { crc32: 0x1234_5678, unpack_size: 256, data_size: 32, method: 0x30, data: vec![0xAB; 32] };
        let hash = emit_rar_20(&input);
        assert!(hash.starts_with("$rar$20$*12345678*"));
        assert!(hash.ends_with("$/rar$"));
        assert!(hash.contains("*100*20*30*")); // us=256(0x100), ds=32(0x20), stored
    }
}
