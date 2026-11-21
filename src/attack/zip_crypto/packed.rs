//! Packed entries: the stream of an entry from a file of the user, packed the way the writer
//! of the archive did.
//!
//! A file whose CRC-32 and size are those of a packed entry is the content of that entry, and
//! the stream of the entry is what its writer made of the file. The file is packed with every
//! packer the tool carries. One whose stream has the packed size of the entry is very likely
//! the packer of the entry, and its stream is taken as known. The start of every other stream
//! is a guess: two packers that differ in one choice agree until they make it.

use std::io::Read as _;
use std::path::Path;

use rayon::iter::IntoParallelRefIterator as _;
use rayon::iter::ParallelIterator as _;

use super::pack::Deflater;
use super::pack::Method;
use super::pack::Packer;
use super::pack::Strategy;
use super::pool::Pool;
use super::user::PackedMatch;
use crate::formats::zip::known::claim::Certainty;
use crate::formats::zip::known::claim::Claim;
use crate::formats::zip::known::claim::Form;
use crate::formats::zip::known::claim::Origin;
use crate::formats::zip::known::writer::Writer;

/// The method the packers write.
const DEFLATE: u16 = 8;

/// How much of a stream whose size is that of the entry is kept: the longest run a search is
/// given, and some bytes behind it to filter with.
const KEEP: usize = 4096 + 64;

/// How much of a stream of another size is tried as a run (section 7.2 of the design).
const START: usize = 32;

/// The largest file that is packed. Each packer reads it once.
pub(crate) const PACK_MAX: u64 = 1 << 30;

/// The packers that are tried for an entry, the most likely first: the packer of the writer,
/// at the level the flags of the entry name, before the others.
///
/// Bits 1 and 2 of the flags say whether a Deflate entry was packed at the normal, the
/// highest, a fast or the fastest setting (APPNOTE 4.4.4). Info-ZIP sets them at levels 1,
/// 2, 8 and 9; most writers never do. So they order the packers and exclude none.
#[must_use]
pub(crate) fn packers(writer: Writer, flags: u16) -> Vec<Packer> {
    let levels: [u8; 9] = match (flags >> 1) & 3 {
        1 => [9, 8, 7, 6, 5, 4, 3, 2, 1],
        2 | 3 => [1, 2, 3, 6, 4, 5, 7, 8, 9],
        _ => [6, 5, 7, 4, 3, 9, 8, 1, 2],
    };
    let info_zip = levels.map(|level| Packer::InfoZip { level });
    let zlib = |mem_level: u8| levels.map(move |level| Packer::Zlib { level, mem_level, strategy: Strategy::Default });
    let rare = [Strategy::Filtered, Strategy::Rle, Strategy::HuffmanOnly, Strategy::Fixed].map(|strategy| Packer::Zlib { level: 6, mem_level: 8, strategy });
    let mut all = Vec::new();
    if writer == Writer::InfoZip {
        all.extend(info_zip);
        all.extend(zlib(8));
    } else {
        all.extend(zlib(8));
        all.extend(info_zip);
    }
    all.extend(zlib(9));
    all.extend(rare);
    all
}

/// What a packer made of a file.
struct Stream {
    packer: Packer,
    /// How long the whole stream is.
    len: u64,
    /// Its first bytes, [`KEEP`] at most.
    start: Vec<u8>,
    /// Whether the program would have put the file itself into the archive, as method 0.
    stored: bool,
}

/// Pack a file with one packer, in memory that does not grow with the file: the stream is
/// counted, and only its start is kept.
fn pack(path: &Path, packer: Packer) -> std::io::Result<Stream> {
    let mut file = std::fs::File::open(path)?;
    let mut deflater = Deflater::new(packer);
    let mut buffer = vec![0_u8; 256 * 1024];
    let (mut out, mut start, mut len) = (Vec::new(), Vec::with_capacity(KEEP), 0_u64);
    let mut take = |out: &mut Vec<u8>| {
        len += out.len() as u64;
        start.extend(out.iter().take(KEEP.saturating_sub(start.len())));
        out.clear();
    };
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        deflater.update(buffer.get(..count).unwrap_or_default(), &mut out);
        take(&mut out);
    }
    let stored = deflater.finish(&mut out) == Method::Store;
    take(&mut out);
    Ok(Stream { packer, len, start, stored })
}

/// The claims that the files of packed entries give: each file is packed with every packer,
/// and what comes out is held against the packed size of its entry. `notes` gets one line for
/// each file that says how that went.
pub(crate) fn claims(pool: &Pool, matches: &[PackedMatch], notes: &mut Vec<String>) -> Vec<(usize, Claim)> {
    let mut claims = Vec::new();
    for matched in matches {
        let Some(target) = pool.targets.get(matched.target) else { continue };
        let name = matched.path.display();
        if target.entry.compression_method != DEFLATE {
            notes.push(format!("{name}: it is the content of {}, which is packed with a method the tool has no packer for", target.name));
            continue;
        }
        if target.entry.uncompressed_size > PACK_MAX {
            notes.push(format!("{name}: it is the content of {}, and larger than the {PACK_MAX} bytes that are packed", target.name));
            continue;
        }
        let writer = pool.archives.get(target.archive).map_or(Writer::Unknown, |archive| archive.writer);
        let tried = packers(writer, target.entry.flags);
        let streams: Vec<Stream> = tried.par_iter().filter_map(|packer| pack(&matched.path, *packer).ok()).collect();

        // a packer whose stream has the packed size of the entry: very likely the packer of the entry
        let mut seen: Vec<&[u8]> = Vec::new();
        let mut fitting = Vec::new();
        for stream in streams.iter().filter(|stream| stream.len == target.stream_len() && !stream.stored) {
            if !seen.contains(&stream.start.as_slice()) {
                seen.push(&stream.start);
                fitting.push(stream.packer.name());
                claims.push((matched.target, Claim::new(Origin::User, Certainty::Likely, format!("matched file {name}, packed as {} does", stream.packer.name()), Form::bytes(0, &stream.start))));
            }
        }
        // the start of every other stream: a guess, since packers agree until they choose differently
        let mut starts: Vec<&[u8]> = Vec::new();
        for stream in &streams {
            let Some(start) = stream.start.get(..START.min(stream.start.len())).filter(|start| start.len() >= 8) else { continue };
            if !seen.iter().any(|known| known.starts_with(start)) && !starts.contains(&start) {
                starts.push(start);
            }
        }
        if !starts.is_empty() {
            let forms = starts.iter().map(|start| Form::bytes(0, start)).collect();
            claims.push((matched.target, Claim { origin: Origin::User, certainty: Certainty::Guess, what: format!("start of the stream of {name} from a packer of another packed size"), forms }));
        }
        let unknown = if writer == Writer::SevenZip { " The archive was written by 7-Zip, whose packer the tool does not carry." } else { "" };
        notes.push(match fitting.as_slice() {
            [] => format!("{name}: packed with {} packers, and none gives the {} bytes of {}: the start of each stream is tried as a guess.{unknown}", streams.len(), target.stream_len(), target.name),
            fitting => format!("{name}: packed with {} packers, and {} of them give the {} bytes of {}: {}", streams.len(), fitting.len(), target.stream_len(), target.name, fitting.join("; ")),
        });
    }
    claims
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn the_packer_of_the_writer_at_the_level_of_the_flags_is_tried_first() {
        let of = |writer, flags| packers(writer, flags);
        assert_eq!(of(Writer::InfoZip, 0x0009)[0], Packer::InfoZip { level: 6 });
        assert_eq!(of(Writer::InfoZip, 0x000b)[0], Packer::InfoZip { level: 9 });
        assert_eq!(of(Writer::InfoZip, 0x000d)[0], Packer::InfoZip { level: 1 });
        assert_eq!(of(Writer::Unknown, 0x0001)[0], Packer::Zlib { level: 6, mem_level: 8, strategy: Strategy::Default });
        assert_eq!(of(Writer::SevenZip, 0x0001).len(), 9 + 9 + 9 + 4);
        // every packer once, whatever the order
        let mut all = of(Writer::InfoZip, 0x000b);
        all.sort_by_key(|packer| packer.name());
        all.dedup();
        assert_eq!(all.len(), 31);
    }

    #[test]
    fn a_file_is_packed_in_pieces_to_the_stream_its_packer_gives_in_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("text");
        let text: Vec<u8> = (0..40_000_u32).flat_map(|n| format!("line {n}: the quick brown fox jumps over the lazy dog\n").into_bytes()).collect();
        std::fs::write(&path, &text).unwrap();
        for packer in [Packer::InfoZip { level: 6 }, Packer::Zlib { level: 9, mem_level: 8, strategy: Strategy::Default }] {
            let whole = packer.pack(&text);
            let stream = pack(&path, packer).unwrap();
            assert_eq!((stream.len, stream.stored), (whole.len() as u64, false));
            assert_eq!(stream.start[..], whole[..KEEP]);
        }
        assert!(pack(&dir.path().join("absent"), Packer::InfoZip { level: 6 }).is_err());
    }

    #[test]
    fn the_file_of_a_packed_entry_gives_the_stream_of_the_entry_when_its_packer_is_carried() {
        // Info-ZIP packed `gen_infozip_deflate.zip` at level 9: its flags say so
        let pool = Pool::read(&[PathBuf::from("tests/fixtures/zip-crypto/gen_infozip_deflate.zip")], &|_| None).unwrap();
        let target = &pool.targets[0];
        assert_eq!((target.entry.compression_method, target.entry.flags), (8, 0x000b));
        // the content of the entry, from the keys of its password
        let mut keys = archivewolf_zip_crypto::Keys::from_password(b"iz-deflate");
        let stream: Vec<u8> = pool.cipher(target, -12, i64::MAX).unwrap().iter().map(|&byte| keys.decrypt(byte)).collect();
        let mut content = Vec::new();
        let _ = flate2::read::DeflateDecoder::new(&stream[12..]).read_to_end(&mut content).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("content");
        std::fs::write(&path, &content).unwrap();

        let mut notes = Vec::new();
        let claims = claims(&pool, &[PackedMatch { target: 0, path: path.clone() }], &mut notes);
        let likely: Vec<&Claim> = claims.iter().map(|(_, claim)| claim).filter(|claim| claim.certainty == Certainty::Likely).collect();
        assert!(!likely.is_empty(), "{notes:?}");
        // the first stream that fits is that of the entry, byte for byte, as far as it is kept
        assert!(likely[0].what.contains("packed as Info-ZIP level 9 does"), "{}", likely[0].what);
        assert_eq!(likely[0].forms, [Form::bytes(0, &stream[12..stream.len().min(12 + KEEP)])]);
        assert!(notes[0].contains(" of them give the ") && notes[0].contains("Info-ZIP level 9"), "{notes:?}");

        // a file of a method without a packer says so and gives nothing
        let bzip2 = Pool::read(&[PathBuf::from("tests/fixtures/zip-crypto/gen_infozip_bzip2.zip")], &|_| None).unwrap();
        let mut notes = Vec::new();
        assert!(super::claims(&bzip2, &[PackedMatch { target: 0, path }], &mut notes).is_empty());
        assert!(notes[0].contains("a method the tool has no packer for"), "{notes:?}");
    }
}
