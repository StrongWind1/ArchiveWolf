//! What the user gives: files, folders and archives that may hold content of the archive, and
//! bytes on the command line.
//!
//! The user does not say what a path is or which entry it belongs to. A file whose CRC-32 and
//! size are those of an entry is that entry. A file with the name of an entry is taken for a
//! version of it, and tried in windows. An archive is matched entry by entry. Everything the
//! user gives is input like the archive: it is read, never run, and nothing of it is printed
//! but its path.

use std::collections::HashMap;
use std::io::Read as _;
use std::io::Seek as _;
use std::io::SeekFrom;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;

use super::pool::Pool;
use super::pool::Target;
use crate::formats::source::Source;
use crate::formats::zip::data_extract::Data;
use crate::formats::zip::data_extract::locate;
use crate::formats::zip::encryption::ZipEncryption;
use crate::formats::zip::known::claim::Cells;
use crate::formats::zip::known::claim::Certainty;
use crate::formats::zip::known::claim::Claim;
use crate::formats::zip::known::claim::Form;
use crate::formats::zip::known::claim::Origin;
use crate::formats::zip::known::directory::KEEP;
use crate::formats::zip::known::method::Layout;
use crate::formats::zip::known::set::ByteSet;
use crate::formats::zip::parser::filename_lossy;
use crate::formats::zip::parser::parse;

/// The most files that are looked at under the paths of `--known`. A wrong path such as `/`
/// must not run for hours unseen.
pub(crate) const FILES_MAX: usize = 1_000_000;

/// The most positions bytes without a position are tried at.
const POSITIONS_MAX: u64 = 10_000;

/// The most bytes a class the user names is taken for.
const CLASS_SPAN: u64 = 4096;

/// How long a window of a similar file is.
const WINDOW: u64 = 1024;

/// How many windows are spread over a similar file, beside the one at its start and the one
/// at its end.
const WINDOWS_BETWEEN: u64 = 6;

/// What the user gave on the command line, as text.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Given<'a> {
    /// `--known PATH`.
    pub known: &'a [PathBuf],
    /// `--bytes ENTRY[@POS]=HEX`.
    pub bytes: &'a [String],
    /// `--text ENTRY[@POS]=STR`.
    pub text: &'a [String],
    /// `--text16 ENTRY[@POS]=STR`.
    pub text16: &'a [String],
    /// `--starts ENTRY=STR`.
    pub starts: &'a [String],
    /// `--ends ENTRY=STR`.
    pub ends: &'a [String],
    /// `--class ENTRY=CLASS`.
    pub class: &'a [String],
}

/// A file of the user that is the content of a packed entry: its stream is what a packer
/// makes of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PackedMatch {
    /// The entry, by its place in the pool.
    pub target: usize,
    /// The file.
    pub path: PathBuf,
}

/// What the paths and the bytes of the user come to.
#[derive(Debug, Default)]
pub(crate) struct FromUser {
    /// The claims, each with the entry it is of.
    pub claims: Vec<(usize, Claim)>,
    /// Files that are the content of packed entries.
    pub packed: Vec<PackedMatch>,
    /// What is to be said of the paths: what each was taken as, and what matched.
    pub notes: Vec<String>,
}

/// One item of the command line: the entries it names, a position when it has one, and its
/// value.
struct Item<'a> {
    targets: Vec<usize>,
    position: Option<i64>,
    value: &'a str,
}

/// Take an item apart: `ENTRY[@POS]=VALUE`. The entry may be left out when the archive has
/// one encrypted entry.
fn item<'a>(pool: &Pool, option: &str, text: &'a str) -> anyhow::Result<Item<'a>> {
    let (left, value) = text.split_once('=').with_context(|| format!("{option} {text}: the form is ENTRY[@POSITION]=VALUE"))?;
    let (pattern, position) = match left.rsplit_once('@') {
        Some((pattern, position)) if position.parse::<i64>().is_ok() => (pattern, position.parse::<i64>().ok()),
        _ => (left, None),
    };
    let targets = pool.named(pattern);
    if targets.is_empty() {
        if pattern.is_empty() {
            anyhow::bail!("{option} {text}: the archive has {} entries of zip-crypto, so the entry has to be named", pool.targets.len());
        }
        anyhow::bail!("{option} {text}: no entry of zip-crypto is named {pattern}");
    }
    Ok(Item { targets, position, value })
}

/// Bytes from hex digits, with or without spaces between them.
fn hex_bytes(option: &str, text: &str) -> anyhow::Result<Vec<u8>> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&digits).ok().filter(|bytes| !bytes.is_empty());
    bytes.with_context(|| format!("{option}: {text} is not bytes in hex, two digits each"))
}

/// A class by its name.
fn class(option: &str, name: &str) -> anyhow::Result<Cells> {
    match name {
        "text" => Ok(Cells::Fill(ByteSet::text(), CLASS_SPAN)),
        "ascii" => Ok(Cells::Fill(ByteSet::ascii(), CLASS_SPAN)),
        // characters of the first 256 in UTF-16, low byte first: every second byte is zero
        "utf16" => Ok(Cells::Sets((0..CLASS_SPAN).map(|at| if at % 2 == 0 { ByteSet::ANY } else { ByteSet::of(0) }).collect())),
        _ => anyhow::bail!("{option}: {name} is no class: text, ascii and utf16 are"),
    }
}

/// The content of the entries, by the bytes the user typed. `fixed` holds, for each entry,
/// what is said at a position; `floating` what is said to be somewhere.
#[derive(Default)]
struct Typed {
    fixed: HashMap<usize, Form>,
    floating: HashMap<usize, Vec<Vec<u8>>>,
}

impl Typed {
    /// Say that the content of an entry holds `cells` at a position of the file.
    fn put(&mut self, pool: &Pool, target: usize, at: i64, cells: Cells, said: &str) -> anyhow::Result<()> {
        let size = pool.targets.get(target).map_or(0, |target| target.entry.uncompressed_size);
        let fits = u64::try_from(at).is_ok_and(|at| at < size);
        anyhow::ensure!(fits, "{said}: the entry has {size} bytes, and that position is not among them");
        // a class runs to the end of the entry and not past it
        let cells = match cells {
            Cells::Fill(set, len) => Cells::Fill(set, len.min(size.saturating_sub(at.unsigned_abs()))),
            Cells::Sets(sets) => Cells::Sets(sets.into_iter().take(usize::try_from(size.saturating_sub(at.unsigned_abs())).unwrap_or(usize::MAX)).collect()),
            Cells::Bytes(bytes) => {
                anyhow::ensure!(at.unsigned_abs().saturating_add(bytes.len() as u64) <= size, "{said}: the entry has {size} bytes, and these run past its end");
                Cells::Bytes(bytes)
            },
        };
        let form = self.fixed.entry(target).or_default();
        anyhow::ensure!(form.add(at, cells), "{said}: that contradicts what else was given for the entry");
        Ok(())
    }
}

/// The claims of everything the user gave.
pub(crate) fn claims(pool: &Pool, given: &Given<'_>) -> anyhow::Result<FromUser> {
    let mut out = FromUser::default();
    typed(pool, given, &mut out)?;
    let mut budget = FILES_MAX;
    for path in given.known {
        known(pool, path, &mut budget, &mut out)?;
    }
    Ok(out)
}

/// The claims of the bytes given on the command line: one for each entry they name.
fn typed(pool: &Pool, given: &Given<'_>, out: &mut FromUser) -> anyhow::Result<()> {
    let mut all = Typed::default();
    let end_of = |target: usize, len: usize| pool.targets.get(target).and_then(|target| i64::try_from(target.entry.uncompressed_size).ok()?.checked_sub(i64::try_from(len).ok()?));
    // a position below zero counts from the end of the entry
    let place = |target: usize, position: i64| if position < 0 { end_of(target, 0).map_or(position, |size| size + position) } else { position };

    for (option, items, to_bytes) in [("--bytes", given.bytes, None), ("--text", given.text, Some(false)), ("--text16", given.text16, Some(true))] {
        for text in items {
            let item = item(pool, option, text)?;
            let bytes = match to_bytes {
                None => hex_bytes(option, item.value)?,
                Some(false) => item.value.as_bytes().to_vec(),
                Some(true) => item.value.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            };
            anyhow::ensure!(!bytes.is_empty(), "{option} {text}: nothing is given");
            for &target in &item.targets {
                match item.position {
                    Some(position) => all.put(pool, target, place(target, position), Cells::Bytes(bytes.clone()), &format!("{option} {text}"))?,
                    None => all.floating.entry(target).or_default().push(bytes.clone()),
                }
            }
        }
    }
    for (option, items, at_end) in [("--starts", given.starts, false), ("--ends", given.ends, true)] {
        for text in items {
            let item = item(pool, option, text)?;
            anyhow::ensure!(item.position.is_none() && !item.value.is_empty(), "{option} {text}: the form is ENTRY=TEXT");
            for &target in &item.targets {
                let at = if at_end { end_of(target, item.value.len()).unwrap_or(-1) } else { 0 };
                all.put(pool, target, at, Cells::Bytes(item.value.as_bytes().to_vec()), &format!("{option} {text}"))?;
            }
        }
    }
    for text in given.class {
        let item = item(pool, "--class", text)?;
        anyhow::ensure!(item.position.is_none(), "--class {text}: the form is ENTRY=CLASS");
        let cells = class("--class", item.value)?;
        for &target in &item.targets {
            all.put(pool, target, 0, cells.clone(), &format!("--class {text}"))?;
        }
    }

    let mut targets: Vec<usize> = all.fixed.keys().chain(all.floating.keys()).copied().collect();
    targets.sort_unstable();
    targets.dedup();
    for index in targets {
        let Some(target) = pool.targets.get(index) else { continue };
        let fixed = all.fixed.remove(&index).unwrap_or_default();
        let mut forms = Vec::new();
        match all.floating.remove(&index) {
            None => forms.extend(target.facts.layout.place(&fixed, &target.entry)),
            Some(floating) => {
                // bytes that are somewhere: every position is a form of its own
                for bytes in floating {
                    let last = target.entry.uncompressed_size.saturating_sub(bytes.len() as u64);
                    if last >= POSITIONS_MAX {
                        out.notes.push(format!("{}: bytes without a position are tried at the first {POSITIONS_MAX} of {} positions", target.name, last + 1));
                    }
                    for at in 0..=last.min(POSITIONS_MAX - 1) {
                        let moved = i64::try_from(at).ok().and_then(|at| fixed.merged(&Form::bytes(at, &bytes)));
                        forms.extend(moved.and_then(|form| target.facts.layout.place(&form, &target.entry)));
                    }
                }
            },
        }
        forms.retain(|form| !form.is_empty());
        if forms.is_empty() {
            out.notes.push(format!("{}: {}, so what is known of its content does not show in its stream", target.name, target.facts.layout.label()));
        } else {
            out.claims.push((index, Claim { origin: Origin::User, certainty: Certainty::Guess, what: "bytes given on the command line".to_owned(), forms }));
        }
    }
    Ok(())
}

/// The size and the CRC-32 of a file, read once in a stream.
fn crc_of(path: &Path) -> std::io::Result<u32> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = crc32fast::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            return Ok(hasher.finalize());
        }
        hasher.update(buffer.get(..count).unwrap_or_default());
    }
}

/// `len` bytes of a file from an offset on, or fewer when it ends first.
fn read_at(path: &Path, offset: u64, len: u64) -> std::io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let _ = file.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    let _ = file.take(len).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// The name of a path, for a note: nothing of a file reaches the terminal but this.
fn shown(path: &Path) -> String {
    path.display().to_string()
}

/// One path of `--known`: a file, a folder that is walked, or an archive that is also matched
/// entry by entry.
fn known(pool: &Pool, path: &Path, budget: &mut usize, out: &mut FromUser) -> anyhow::Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("--known {}: cannot be read", path.display()))?;
    let before = (out.claims.len(), out.packed.len());
    let mut files = 0_usize;
    if meta.is_dir() {
        // links are not followed: a folder is not left through one, and a loop of them ends
        for entry in walkdir::WalkDir::new(path).follow_links(false).sort_by_file_name().into_iter().filter_map(Result::ok).filter(|entry| entry.file_type().is_file()) {
            if *budget == 0 {
                out.notes.push(format!("--known {}: {FILES_MAX} files were looked at, and no more are", shown(path)));
                break;
            }
            *budget -= 1;
            files += 1;
            let size = entry.metadata().map_or(0, |meta| meta.len());
            file(pool, entry.path(), size, out);
        }
    } else {
        files = 1;
        file(pool, path, meta.len(), out);
        archive(pool, path, out);
    }
    let (exact, packed) = (out.claims.len() - before.0, out.packed.len() - before.1);
    let what = if meta.is_dir() { format!("a folder of {files} files") } else { "a file".to_owned() };
    out.notes.push(match (exact, packed) {
        (0, 0) => format!("--known {}: {what}, and nothing in it is the content of an entry, by CRC-32 and size, or a version of a stored one, by name", shown(path)),
        _ => format!("--known {}: {what}; {exact} claims from it, {packed} files that are the content of packed entries", shown(path)),
    });
    Ok(())
}

/// One file: the content of the entries that have its CRC-32 and its size, or a version of
/// the entries that have its name.
fn file(pool: &Pool, path: &Path, size: u64, out: &mut FromUser) {
    if size == 0 {
        return;
    }
    let same_size: Vec<usize> = pool.targets.iter().enumerate().filter(|(_, target)| target.entry.uncompressed_size == size).map(|(index, _)| index).collect();
    let crc = if same_size.is_empty() { None } else { crc_of(path).ok() };
    let exact: Vec<usize> = same_size.into_iter().filter(|&index| pool.targets.get(index).is_some_and(|target| Some(target.entry.crc32) == crc)).collect();

    for &index in &exact {
        let Some(target) = pool.targets.get(index) else { continue };
        let what = format!("matched file {} (CRC-32 and size)", shown(path));
        if target.facts.layout == Layout::Packed {
            out.packed.push(PackedMatch { target: index, path: path.to_path_buf() });
        }
        let Ok(start) = read_at(path, 0, KEEP) else { continue };
        if let Some(form) = target.facts.layout.place(&Form::bytes(0, &start), &target.entry).filter(|form| !form.is_empty()) {
            // a stored entry is its content; a packed one is what its content packs to, which is taken on trust
            let certainty = if target.facts.layout == Layout::Packed { Certainty::Guess } else { Certainty::Certain };
            out.claims.push((index, Claim::new(Origin::User, certainty, what, form)));
        }
    }
    if !exact.is_empty() {
        return;
    }

    // no entry is this file: the entries of its name may be other versions of it
    let name = path.file_name().map(|name| name.to_string_lossy().to_lowercase());
    for (index, target) in pool.targets.iter().enumerate() {
        let entry_name = filename_lossy(&target.entry).to_lowercase();
        if entry_name.rsplit('/').next().map(str::to_owned) != name {
            continue;
        }
        if target.facts.layout == Layout::Packed {
            // a packer writes a block from everything in it: another version has another stream from its first byte on
            out.notes.push(format!("--known {}: it has the name of {} and is not its content: {} bytes where the entry has {}, or another CRC-32. The entry is packed, and another version of a packed file says nothing of its stream", shown(path), target.name, size, target.entry.uncompressed_size));
            continue;
        }
        let forms = windows(path, size, target);
        if !forms.is_empty() {
            out.claims.push((index, Claim { origin: Origin::User, certainty: Certainty::Guess, what: format!("window of the similar file {}", shown(path)), forms }));
        }
    }
}

/// The windows of a similar file: stretches of it taken as known at the same position of the
/// entry. From the start, from the end counted backward, and spread between them; and when
/// the two do not have the same size, each also at its position counted from the end.
fn windows(path: &Path, size: u64, target: &Target) -> Vec<Form> {
    let entry_size = target.entry.uncompressed_size;
    let len = WINDOW.min(size).min(entry_size);
    if len < 16 {
        return Vec::new();
    }
    let last = size.min(entry_size) - len;
    // where a window lies in the file, and where it is taken to lie in the entry
    let mut places: Vec<(u64, u64)> = vec![(0, 0), (size - len, entry_size - len)];
    // between the first and the last, as many as lie apart from each other
    let between = WINDOWS_BETWEEN.min(last / len);
    for step in 1..=between {
        let at = last / (between + 1) * step;
        places.push((at, at));
        if size != entry_size {
            let from_end = size.min(entry_size) - at;
            places.push((size - from_end, entry_size - from_end));
        }
    }
    places.sort_unstable();
    places.dedup();
    places
        .into_iter()
        .filter_map(|(in_file, in_entry)| {
            let bytes = read_at(path, in_file, len).ok().filter(|bytes| bytes.len() as u64 == len)?;
            target.facts.layout.place(&Form::bytes(i64::try_from(in_entry).ok()?, &bytes), &target.entry).filter(|form| !form.is_empty())
        })
        .collect()
}

/// A path that is a ZIP archive: its entries are matched to the entries of the pool by CRC-32
/// and size, without unpacking anything but the start of a match.
fn archive(pool: &Pool, path: &Path, out: &mut FromUser) {
    let Ok(source) = Source::open(path, 0) else { return };
    let Ok(zip) = parse(&source) else { return };
    let mut encrypted = 0;
    for theirs in zip.entries.iter().filter(|entry| !entry.directory && entry.uncompressed_size > 0) {
        for (index, target) in pool.targets.iter().enumerate().filter(|(_, target)| target.entry.crc32 == theirs.crc32 && target.entry.uncompressed_size == theirs.uncompressed_size) {
            if theirs.encryption != ZipEncryption::None {
                encrypted += 1;
                continue;
            }
            let Data::Here(start) = locate(&source, theirs) else { continue };
            let name = filename_lossy(theirs);
            if target.facts.layout == Layout::Packed {
                // packed with the same method to the same size: very likely packed the same way
                if theirs.compression_method == target.entry.compression_method
                    && theirs.compressed_size == target.stream_len()
                    && let Ok(stream) = source.read_at(start, theirs.compressed_size.min(KEEP))
                {
                    out.claims.push((index, Claim::new(Origin::User, Certainty::Likely, format!("packed stream of {name} in {}", shown(path)), Form::bytes(0, &stream))));
                }
                continue;
            }
            let want = theirs.uncompressed_size.min(KEEP);
            let Ok(reader) = source.reader(start, theirs.compressed_size) else { continue };
            let mut content = Vec::new();
            let read = match theirs.compression_method {
                0 => reader.take(want).read_to_end(&mut content),
                8 => flate2::read::DeflateDecoder::new(reader).take(want).read_to_end(&mut content),
                _ => continue,
            };
            if read.is_ok()
                && content.len() as u64 == want
                && let Some(form) = target.facts.layout.place(&Form::bytes(0, &content), &target.entry).filter(|form| !form.is_empty())
            {
                out.claims.push((index, Claim::new(Origin::User, Certainty::Certain, format!("matched entry {name} of {} (CRC-32 and size)", shown(path)), form)));
            }
        }
    }
    if encrypted > 0 {
        out.notes.push(format!("--known {}: {encrypted} of its entries match and are encrypted themselves, which gives no bytes; if it is under the same password, give it beside the archive and not under --known", shown(path)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(fixture: &str) -> Pool {
        Pool::read(&[PathBuf::from(format!("tests/fixtures/zip-crypto/{fixture}"))], &|_| None).unwrap()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn bytes_on_the_command_line_are_one_claim_for_each_entry_they_name() {
        let pool = pool("bkcrack-src_secrets.zip");
        let (starts, class, bytes, ends) = (strings(&["spiral.svg=<?xml v"]), strings(&["spiral.svg=text"]), strings(&["spiral.svg@100=20 21"]), strings(&["*.svg=</svg>\n"]));
        let given = Given { starts: &starts, class: &class, bytes: &bytes, ends: &ends, ..Given::default() };
        let claims = claims(&pool, &given).unwrap();
        assert_eq!(claims.claims.len(), 1);
        let (target, claim) = &claims.claims[0];
        assert_eq!((*target, claim.origin, claim.certainty, claim.forms.len()), (1, Origin::User, Certainty::Guess, 1));
        let form = &claim.forms[0];
        assert_eq!(form.stretches(), [(0, 7), (100, 2), (1258, 7)]);
        assert_eq!((form.get(7), form.get(100), form.get(1265)), (Some(ByteSet::text()), Some(ByteSet::of(0x20)), None));
    }

    #[test]
    fn a_position_below_zero_counts_from_the_end_and_bytes_without_one_are_tried_everywhere() {
        let pool = pool("bkcrack-src_secrets.zip");
        let text = strings(&["spiral.svg@-6=</svg>"]);
        let claims = claims(&pool, &Given { text: &text, ..Given::default() }).unwrap();
        assert_eq!(claims.claims[0].1.forms[0].stretches(), [(1259, 6)]);

        let anywhere = strings(&["spiral.svg=3c3f786d6c"]);
        let claims = super::claims(&pool, &Given { bytes: &anywhere, ..Given::default() }).unwrap();
        assert_eq!(claims.claims[0].1.forms.len(), 1265 - 5 + 1);
        assert_eq!(claims.claims[0].1.forms[7].stretches(), [(7, 5)]);

        let wide = strings(&["spiral.svg@0=<?"]);
        let claims = super::claims(&pool, &Given { text16: &wide, ..Given::default() }).unwrap();
        assert_eq!(claims.claims[0].1.forms[0], Form::bytes(0, b"<\0?\0"));
    }

    #[test]
    fn what_is_given_wrongly_is_said_to_be_wrong_with_what_would_be_right() {
        let pool = pool("bkcrack-src_secrets.zip");
        let fault = |given: Given<'_>| format!("{:#}", claims(&pool, &given).unwrap_err());
        for (bytes, why) in [
            ("spiral.svg@0", "the form is ENTRY[@POSITION]=VALUE"),
            ("=00", "has 2 entries of zip-crypto, so the entry has to be named"),
            ("nothing.txt@0=00", "no entry of zip-crypto is named nothing.txt"),
            ("spiral.svg@0=xyz", "is not bytes in hex"),
            ("spiral.svg@0=0", "is not bytes in hex"),
            ("spiral.svg@5000=00", "that position is not among them"),
            ("spiral.svg@1264=0000", "run past its end"),
        ] {
            let bytes = strings(&[bytes]);
            assert!(fault(Given { bytes: &bytes, ..Given::default() }).contains(why), "{bytes:?}: {}", fault(Given { bytes: &bytes, ..Given::default() }));
        }
        let class = strings(&["spiral.svg=words"]);
        assert!(fault(Given { class: &class, ..Given::default() }).contains("is no class: text, ascii and utf16 are"));
        // two things that cannot both hold
        let (starts, bytes) = (strings(&["spiral.svg=<?xml"]), strings(&["spiral.svg@0=00"]));
        assert!(fault(Given { starts: &starts, bytes: &bytes, ..Given::default() }).contains("contradicts what else was given"));
        // what is known of the content of a packed entry does not show in its stream
        let starts = strings(&["advice.jpg=\u{ff}"]);
        let claims = claims(&pool, &Given { starts: &starts, ..Given::default() }).unwrap();
        assert!(claims.claims.is_empty() && claims.notes[0].contains("packed, so what is known of its content does not show in its stream"), "{:?}", claims.notes);
    }

    #[test]
    fn a_file_with_the_crc_32_and_the_size_of_an_entry_is_that_entry() {
        let pool = pool("bkcrack-src_secrets.zip");
        let dir = tempfile::tempdir().unwrap();
        // the content of `spiral.svg`, from the keys of the archive
        let mut keys = archivewolf_zip_crypto::Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31);
        let plain: Vec<u8> = pool.cipher(&pool.targets[1], -12, 2000).unwrap().iter().map(|&byte| keys.decrypt(byte)).collect();
        std::fs::write(dir.path().join("picture.svg"), &plain[12..]).unwrap();
        std::fs::write(dir.path().join("other.txt"), b"not in the archive").unwrap();
        std::fs::create_dir_all(dir.path().join("deeper")).unwrap();
        // a file of the name of the entry that is not the entry: a version of it
        let mut changed = plain[12..].to_vec();
        changed[600] ^= 1;
        std::fs::write(dir.path().join("deeper/spiral.svg"), &changed).unwrap();

        let known = [dir.path().to_path_buf()];
        let claims = claims(&pool, &Given { known: &known, ..Given::default() }).unwrap();
        let exact = claims.claims.iter().find(|(_, claim)| claim.certainty == Certainty::Certain).unwrap();
        assert_eq!((exact.0, exact.1.forms[0].stretches()), (1, vec![(0, 1265)]));
        assert!(exact.1.what.starts_with("matched file ") && exact.1.what.ends_with("picture.svg (CRC-32 and size)"), "{}", exact.1.what);
        let similar = claims.claims.iter().find(|(_, claim)| claim.certainty == Certainty::Guess).unwrap();
        assert!(similar.1.what.starts_with("window of the similar file "));
        // a file of 1,265 bytes has room for a window at its start and one at its end
        assert_eq!(similar.1.forms.len(), 2);
        assert_eq!((similar.1.forms[0].stretches(), similar.1.forms[1].stretches()), (vec![(0, 1024)], vec![(241, 1024)]));
        assert!(claims.notes.iter().any(|note| note.contains("a folder of 3 files; 2 claims from it")), "{:?}", claims.notes);

        // a path that matches nothing is no error: it is said what it was taken as
        let known = [dir.path().join("other.txt")];
        let nothing = super::claims(&pool, &Given { known: &known, ..Given::default() }).unwrap();
        assert!(nothing.claims.is_empty() && nothing.notes[0].contains("a file, and nothing in it is the content of an entry"));

        // another version of a packed entry, by its name: it gives nothing, and that is said
        std::fs::write(dir.path().join("advice.jpg"), b"not the picture of the archive").unwrap();
        let known = [dir.path().join("advice.jpg")];
        let version = super::claims(&pool, &Given { known: &known, ..Given::default() }).unwrap();
        assert!(version.claims.is_empty() && version.packed.is_empty());
        assert!(version.notes[0].contains("it has the name of advice.jpg and is not its content: 30 bytes where the entry has 54799") && version.notes[0].contains("The entry is packed"), "{:?}", version.notes);
        let absent = [dir.path().join("absent")];
        assert!(super::claims(&pool, &Given { known: &absent, ..Given::default() }).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_folder_is_not_left_through_a_link_and_a_loop_of_links_ends() {
        let pool = pool("bkcrack-src_secrets.zip");
        let (inside, outside) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let mut keys = archivewolf_zip_crypto::Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31);
        let plain: Vec<u8> = pool.cipher(&pool.targets[1], -12, 2000).unwrap().iter().map(|&byte| keys.decrypt(byte)).collect();
        // the file that is the entry lies outside the folder, and the folder has links to it:
        // one to the file, one to its folder. A third link leads back to the folder itself
        std::fs::write(outside.path().join("spiral.svg"), &plain[12..]).unwrap();
        std::fs::write(inside.path().join("notes.txt"), b"not in the archive").unwrap();
        std::os::unix::fs::symlink(outside.path().join("spiral.svg"), inside.path().join("link-to-the-file.svg")).unwrap();
        std::os::unix::fs::symlink(outside.path(), inside.path().join("link-out")).unwrap();
        std::os::unix::fs::symlink(inside.path(), inside.path().join("link-back")).unwrap();

        let known = [inside.path().to_path_buf()];
        let walked = claims(&pool, &Given { known: &known, ..Given::default() }).unwrap();
        assert!(walked.claims.is_empty(), "{:?}", walked.claims.iter().map(|(_, claim)| &claim.what).collect::<Vec<_>>());
        assert!(walked.notes.iter().any(|note| note.contains("a folder of 1 file")), "{:?}", walked.notes);

        // the folder that holds the file gives it
        let known = [outside.path().to_path_buf()];
        let found = claims(&pool, &Given { known: &known, ..Given::default() }).unwrap();
        assert!(found.claims.iter().any(|(target, claim)| *target == 1 && claim.certainty == Certainty::Certain));
    }

    #[test]
    fn an_archive_is_matched_entry_by_entry_without_unpacking_it() {
        // the same two files in an archive that is not encrypted, as 7-Zip packed them
        let pool = pool("bkcrack-src_secrets.zip");
        let known = [PathBuf::from("tests/fixtures/zip-crypto/bkcrack-src_secrets.zip")];
        let itself = claims(&pool, &Given { known: &known, ..Given::default() }).unwrap();
        // its own entries are encrypted: no bytes, and the user is told where it belongs
        assert!(itself.claims.is_empty());
        assert!(itself.notes.iter().any(|note| note.contains("2 of its entries match and are encrypted themselves")), "{:?}", itself.notes);
    }
}
