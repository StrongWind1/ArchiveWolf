//! The proof: whether keys decrypt an entry to the CRC-32 its archive stores.
//!
//! The entry is decrypted and unpacked in one pass over a range of its file. Nothing of it is
//! kept and nothing is written.

use std::io::Read;

use archivewolf_zip_crypto::Keys;

use super::pool::HEADER;
use super::pool::Target;
use crate::formats::limits::MAX_DECODER_MEMORY;
use crate::formats::source::Source;

/// The compression methods the proof unpacks (APPNOTE 4.4.5).
const STORED: u16 = 0;
const DEFLATE: u16 = 8;
const LZMA: u16 = 14;

/// How a proof came out.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Proof {
    /// The keys decrypt the entry to its CRC-32 and its size. The number is what that is
    /// worth, in bits: how unlikely it is of keys that are not the keys of the entry.
    Holds(f64),
    /// They do not.
    Fails,
    /// The entry cannot say: it is empty, or of a method the tool does not unpack.
    CannotSay,
}

/// A reader that decrypts what it reads.
struct Decrypting<R> {
    inner: R,
    keys: Keys,
}

impl<R: Read> Read for Decrypting<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buf)?;
        for byte in buf.iter_mut().take(count) {
            *byte = self.keys.decrypt(*byte);
        }
        Ok(count)
    }
}

/// The length and the CRC-32 of everything a reader gives, up to one byte more than `size`.
/// `None` when the reader fails, which is what a stream that is no stream does.
fn summary(reader: impl Read, size: u64) -> Option<(u64, u32)> {
    let mut reader = reader.take(size.saturating_add(1));
    let mut hasher = crc32fast::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut length = 0_u64;
    loop {
        let count = reader.read(&mut buffer).ok()?;
        if count == 0 {
            return Some((length, hasher.finalize()));
        }
        hasher.update(buffer.get(..count)?);
        length += count as u64;
    }
}

/// The keys after the encryption header of a target, when the last byte of the header
/// decrypts to a check byte of the entry.
#[must_use]
pub(crate) fn after_header(target: &Target, keys: Keys) -> Option<Keys> {
    let mut keys = keys;
    let mut last = 0;
    for &byte in &target.header {
        last = keys.decrypt(byte);
    }
    target.last_check().contains(last).then_some(keys)
}

/// Put keys to the proof on one entry: `keys` is the state at the start of its encryption
/// header, which is the state after the password.
#[must_use]
pub(crate) fn prove(source: &Source, target: &Target, keys: Keys) -> Proof {
    let Some(keys) = after_header(target, keys) else { return Proof::Fails };
    let entry = &target.entry;
    let (size, stream) = (entry.uncompressed_size, target.stream_len());
    if size == 0 {
        // the CRC-32 of nothing is the same under every key
        return Proof::CannotSay;
    }
    let Some(data) = target.start.checked_add(HEADER).and_then(|at| source.reader(at, stream).ok()) else { return Proof::Fails };
    let decrypting = Decrypting { inner: data, keys };
    let unpacked = match entry.compression_method {
        STORED if stream == size => summary(decrypting, size),
        STORED => return Proof::Fails,
        DEFLATE => summary(flate2::read::DeflateDecoder::new(decrypting), size),
        LZMA => lzma(decrypting, size),
        _ => return Proof::CannotSay,
    };
    match unpacked {
        Some((length, crc)) if length == size && crc == entry.crc32 => Proof::Holds(worth(entry.compression_method, size, stream)),
        _ => Proof::Fails,
    }
}

/// An LZMA entry: two bytes of version, the size of its properties, the properties, and the
/// stream (APPNOTE 5.8).
fn lzma(mut reader: impl Read, size: u64) -> Option<(u64, u32)> {
    let mut head = [0_u8; 9];
    reader.read_exact(&mut head).ok()?;
    let [_, _, 5, 0, model, d0, d1, d2, d3] = head else { return None };
    let dictionary = u32::try_from(u64::from(u32::from_le_bytes([d0, d1, d2, d3])).min(size)).ok()?.max(lzma_rust2::DICT_SIZE_MIN);
    if dictionary > MAX_DECODER_MEMORY {
        return None;
    }
    let decoder = lzma_rust2::LzmaReader::new_with_props(reader, size, model, dictionary, None).ok()?;
    summary(decoder, size)
}

/// The most a proof on a target can be worth, in bits: what [`prove`] gives when it holds, and
/// nothing for an entry that cannot say.
#[must_use]
pub(crate) fn worth_of(target: &Target) -> f64 {
    match target.entry.compression_method {
        STORED | DEFLATE | LZMA if target.entry.uncompressed_size > 0 => worth(target.entry.compression_method, target.entry.uncompressed_size, target.stream_len()),
        _ => 0.0,
    }
}

/// What a proof that holds is worth, in bits. The CRC-32 is 32 bits for a file of four bytes
/// or more. A packed stream that unpacks to the size it is said to have is worth more: two
/// bits for each of its bytes are taken for it, up to 32.
fn worth(method: u16, size: u64, stream: u64) -> f64 {
    let crc = 8.0 * f64::from(u32::try_from(size.min(4)).unwrap_or(4));
    let form = if method == STORED { 0.0 } else { 2.0 * f64::from(u32::try_from(stream.min(16)).unwrap_or(16)) };
    crc + form
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::attack::zip_crypto::pool::Pool;

    fn pool(fixture: &str) -> Pool {
        Pool::read(&[PathBuf::from(format!("tests/fixtures/zip-crypto/{fixture}"))], &|_| None).unwrap()
    }

    #[test]
    fn the_keys_of_the_password_decrypt_every_entry_to_its_crc_32() {
        // a stored and a Deflate entry of 7-Zip, under the password of the tutorial of bkcrack
        let secrets = pool("bkcrack-src_secrets.zip");
        let keys = Keys::from_password(b"W4sF0rgotten");
        for target in &secrets.targets {
            let proof = prove(secrets.source(target).unwrap(), target, keys);
            assert!(matches!(proof, Proof::Holds(bits) if bits >= 32.0), "{}: {proof:?}", target.name);
            // other keys do not, whether the check byte lets them through or not
            assert_eq!(prove(secrets.source(target).unwrap(), target, Keys::from_password(b"W4sForgotten")), Proof::Fails);
            assert_eq!(prove(secrets.source(target).unwrap(), target, Keys::new(keys.x, keys.y, keys.z ^ 1)), Proof::Fails);
        }
        // Deflate is worth more than stored data: its stream has to be a stream
        let deflate = prove(secrets.source(&secrets.targets[0]).unwrap(), &secrets.targets[0], keys);
        let stored = prove(secrets.source(&secrets.targets[1]).unwrap(), &secrets.targets[1], keys);
        assert_eq!((deflate, stored), (Proof::Holds(64.0), Proof::Holds(32.0)));
    }

    #[test]
    fn every_method_the_proof_unpacks_holds_under_its_password_and_the_others_cannot_say() {
        for (fixture, password, holds) in [
            ("gen_infozip_store.zip", "iz-store", true),
            ("gen_infozip_deflate.zip", "iz-deflate", true),
            ("gen_infozip_stream.zip", "iz-stream", true),
            ("gen_7z_zipcrypto_lzma.zip", "7z-zipcrypto_lzma", true),
            ("gen_own_zc_datadesc.zip", "own-dd", true),
            ("gen_7z_zipcrypto_bzip2.zip", "7z-zipcrypto_bzip2", false),
            ("gen_7z_zipcrypto_deflate64.zip", "7z-zipcrypto_deflate64", false),
            ("gen_7z_zipcrypto_xz.zip", "7z-zipcrypto_xz", false),
        ] {
            let pool = pool(fixture);
            let target = &pool.targets[0];
            let proof = prove(pool.source(target).unwrap(), target, Keys::from_password(password.as_bytes()));
            assert_eq!(matches!(proof, Proof::Holds(_)), holds, "{fixture}: {proof:?}");
            assert!(holds || proof == Proof::CannotSay, "{fixture}: {proof:?}");
            // keys the check byte rejects fail whatever the method
            assert_eq!(prove(pool.source(target).unwrap(), target, Keys::from_password(b"not the password")), Proof::Fails, "{fixture}");
        }
    }

    #[test]
    fn a_short_file_is_worth_less_than_32_bits() {
        assert!((worth(STORED, 1, 1) - 8.0).abs() < f64::EPSILON && (worth(STORED, 3, 3) - 24.0).abs() < f64::EPSILON && (worth(STORED, 4000, 4000) - 32.0).abs() < f64::EPSILON);
        assert!((worth(DEFLATE, 4000, 5) - 42.0).abs() < f64::EPSILON && (worth(DEFLATE, 4000, 900) - 64.0).abs() < f64::EPSILON);
    }
}
