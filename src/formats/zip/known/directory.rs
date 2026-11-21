//! What the directory of an archive gives away: a copy of an encrypted entry that is not
//! encrypted.
//!
//! The central directory holds the CRC-32 and the size of every entry in the clear. An entry
//! that is not encrypted, with the same CRC-32 and size as an encrypted one, is its content:
//! archives that were added to in two sittings have these.

use std::collections::HashMap;
use std::io::Read as _;

use super::claim::Certainty;
use super::claim::Claim;
use super::claim::Form;
use super::claim::Origin;
use super::method::Layout;
use crate::formats::source::Source;
use crate::formats::zip::data_extract::Data;
use crate::formats::zip::data_extract::locate;
use crate::formats::zip::encryption::ZipEncryption;
use crate::formats::zip::parser::ZipEntry;
use crate::formats::zip::parser::filename_lossy;

/// The most bytes of a copy that are kept for a claim: a longer run gains nothing.
pub(crate) const KEEP: u64 = 64 * 1024;

/// The methods a copy is read from.
const STORED: u16 = 0;
const DEFLATE: u16 = 8;

/// The first bytes of the content of an entry that is not encrypted, [`KEEP`] at most. `None`
/// when its data is not in the file or is of a method that is not unpacked here.
fn content_start(source: &Source, entry: &ZipEntry) -> Option<Vec<u8>> {
    let Data::Here(start) = locate(source, entry) else { return None };
    let want = entry.uncompressed_size.min(KEEP);
    let reader = source.reader(start, entry.compressed_size).ok()?;
    let mut content = Vec::new();
    let read = match entry.compression_method {
        STORED => reader.take(want).read_to_end(&mut content),
        DEFLATE => flate2::read::DeflateDecoder::new(reader).take(want).read_to_end(&mut content),
        _ => return None,
    };
    (read.is_ok() && content.len() as u64 == want).then_some(content)
}

/// The claims that copies give: for each encrypted entry of `zip-crypto` that has a copy, its
/// place in `entries` and what the copy says of its stream.
///
/// - A stored entry, or one that did not pack, is the content of its copy: certain, since the
///   CRC-32 and the size are those of the entry.
/// - A packed entry whose copy is packed with the same method to the same size was very
///   likely packed the same way: the packed stream of the copy is taken as it is.
#[must_use]
pub(crate) fn copies(source: &Source, entries: &[ZipEntry]) -> Vec<(usize, Claim)> {
    let mut plain: HashMap<(u32, u64), &ZipEntry> = HashMap::new();
    for entry in entries.iter().filter(|entry| entry.encryption == ZipEncryption::None && !entry.directory && entry.uncompressed_size > 0) {
        let _ = plain.entry((entry.crc32, entry.uncompressed_size)).or_insert(entry);
    }
    if plain.is_empty() {
        return Vec::new();
    }

    let mut claims = Vec::new();
    for (index, entry) in entries.iter().enumerate().filter(|(_, entry)| entry.encryption == ZipEncryption::ZipCrypto) {
        let Some(copy) = plain.get(&(entry.crc32, entry.uncompressed_size)) else { continue };
        let what = format!("copy that is not encrypted, {}", filename_lossy(copy));
        let layout = Layout::of(entry);
        let claim = if layout == Layout::Packed {
            // the same method and the same packed size: the stream of the copy, as it is
            let same = copy.compression_method == entry.compression_method && entry.compressed_size.checked_sub(12) == Some(copy.compressed_size);
            let Data::Here(start) = locate(source, copy) else { continue };
            same.then(|| source.read_at(start, copy.compressed_size.min(KEEP)).ok()).flatten().map(|stream| Claim::new(Origin::Directory, Certainty::Likely, what, Form::bytes(0, &stream)))
        } else {
            content_start(source, copy).and_then(|content| layout.place(&Form::bytes(0, &content), entry)).map(|form| Claim::new(Origin::Directory, Certainty::Certain, what, form))
        };
        claims.extend(claim.map(|claim| (index, claim)));
    }
    claims
}
