//! One archive, read by range.
//!
//! A [`Source`] stands for the bytes of one archive: a file from the offset where the archive
//! starts, or bytes in memory for a test. Nothing is read when it is opened. A parser asks for
//! the ranges it needs, so what a run holds in memory follows from the headers it reads and
//! not from the size of the file.
//!
//! Every offset a `Source` takes or gives is counted from the start of the archive, never from
//! the start of the file: a parser of a self-extracting archive sees the same offsets as a
//! parser of the bare archive. [`Source::offset`] says where that start lies in the file.
//!
//! A range that does not lie inside the archive is an error of the kind
//! [`ErrorKind::UnexpectedEof`], and it is found before anything is allocated or read. That
//! is the one error a parser can meet here for a reason that lies in the archive and not in
//! the file system: its headers point past the end of the file.
//!
//! Reads are positioned ([`std::os::unix::fs::FileExt`] and its Windows counterpart). The file
//! is not mapped into memory and has no position of its own, so one `Source` can be read from
//! several places at once.

use std::fs::File;
use std::io;
use std::io::BufRead;
use std::io::ErrorKind;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

/// How many bytes a [`Cursor`] fetches at a time.
const BLOCK: usize = 64 * 1024;

/// Where the bytes of a source are.
#[derive(Debug)]
enum Bytes {
    /// In a file that is open for reading.
    File(File),
    /// In memory.
    Memory(Vec<u8>),
}

/// The bytes of one archive, read by range.
#[derive(Debug)]
pub struct Source {
    bytes: Bytes,
    path: PathBuf,
    /// Where the archive starts in its file.
    start: u64,
    /// How many bytes follow from there.
    len: u64,
}

/// The error for a range that does not lie inside the archive.
fn outside() -> io::Error {
    io::Error::new(ErrorKind::UnexpectedEof, "the range does not lie inside the archive")
}

/// Read from `file` at `offset` into `buf`, as many bytes as one call gives.
#[cfg(unix)]
fn read_some(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

/// Read from `file` at `offset` into `buf`, as many bytes as one call gives.
#[cfg(windows)]
fn read_some(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

#[cfg(not(any(unix, windows)))]
compile_error!("a Source needs positioned reads, which this crate has for Unix and Windows only");

/// Fill `buf` from `file` at `offset`. A file that ends before `buf` is full is an error.
fn read_full(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match read_some(file, buf, offset) {
            Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "the file ends before the range does")),
            Ok(count) => {
                buf = std::mem::take(&mut buf).get_mut(count..).unwrap_or_default();
                offset = offset.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            },
            Err(error) if error.kind() == ErrorKind::Interrupted => {},
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl Source {
    /// Open the archive that starts `start` bytes into the file at `path`: 0 for a bare
    /// archive, the length of the program in front for a self-extracting one.
    ///
    /// The file is opened for reading and its length is taken. Nothing is read.
    pub fn open(path: &Path, start: u64) -> io::Result<Self> {
        let file = File::open(path)?;
        let total = file.metadata()?.len();
        let len = total.checked_sub(start).ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "the archive starts past the end of the file"))?;
        Ok(Self { bytes: Bytes::File(file), path: path.to_path_buf(), start, len })
    }

    /// An archive held in memory: for tests, and for the key search of `attack rar-13`, the one
    /// command that holds its archive. Its path is `<memory>` and it starts at offset 0.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        Self { bytes: Bytes::Memory(bytes), path: PathBuf::from("<memory>"), start: 0, len }
    }

    /// The bytes of an archive that is held in memory. `None` for one that is read from a file.
    #[must_use]
    pub fn held(&self) -> Option<&[u8]> {
        match &self.bytes {
            Bytes::Memory(bytes) => Some(bytes),
            Bytes::File(_) => None,
        }
    }

    /// The path of the file the archive is in.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Where the archive starts in its file. Every other offset is counted from here.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.start
    }

    /// How many bytes the archive has: from its start to the end of the file.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Whether the archive has no bytes at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The end of the range of `len` bytes at `offset`, or an error when the range does not
    /// lie inside the archive.
    fn range_end(&self, offset: u64, len: u64) -> io::Result<u64> {
        offset.checked_add(len).filter(|&end| end <= self.len).ok_or_else(outside)
    }

    /// Fill `buf` with the bytes at `offset`. An error when they do not all lie inside the
    /// archive, and nothing is read then.
    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let end = self.range_end(offset, u64::try_from(buf.len()).map_err(|_| outside())?)?;
        match &self.bytes {
            Bytes::File(file) => read_full(file, buf, self.start.checked_add(offset).ok_or_else(outside)?),
            Bytes::Memory(bytes) => {
                let from = usize::try_from(offset).ok().zip(usize::try_from(end).ok()).and_then(|(start, end)| bytes.get(start..end)).ok_or_else(outside)?;
                buf.copy_from_slice(from);
                Ok(())
            },
        }
    }

    /// The `len` bytes at `offset`. An error when they do not all lie inside the archive:
    /// that is checked before anything is allocated, so a length taken from a header can be
    /// passed as it is and costs nothing when it is a lie.
    ///
    /// A length that is true is allocated in full. A caller that reads the data of an entry
    /// holds it against its own limit first.
    pub fn read_at(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
        let _end = self.range_end(offset, len)?;
        let mut buf = vec![0_u8; usize::try_from(len).map_err(|_| outside())?];
        self.read_exact_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// The bytes at `offset`, `max` of them or as many as the archive has from there on. An
    /// error when `offset` lies past the end of the archive.
    pub fn read_up_to(&self, offset: u64, max: u64) -> io::Result<Vec<u8>> {
        let left = self.len.checked_sub(offset).ok_or_else(outside)?;
        self.read_at(offset, max.min(left))
    }

    /// A buffered reader that starts at `offset` and ends where the archive ends: for walking
    /// headers in order, a few bytes at a time, without a system call for each of them.
    #[must_use]
    pub fn cursor(&self, offset: u64) -> Cursor<'_> {
        Cursor { source: self, pos: offset, end: self.len, buf: Vec::new(), buf_start: 0 }
    }

    /// A buffered reader over the `len` bytes at `offset` and no further: the input of a
    /// decoder. An error when the range does not lie inside the archive.
    pub fn reader(&self, offset: u64, len: u64) -> io::Result<Cursor<'_>> {
        let end = self.range_end(offset, len)?;
        Ok(Cursor { source: self, pos: offset, end, buf: Vec::new(), buf_start: 0 })
    }
}

/// A buffered reader over a range of a [`Source`], with the readers for the fixed fields of a
/// header.
///
/// It is made by [`Source::cursor`] and [`Source::reader`]. It reads forward from its
/// position, 64 KiB at a time, and can be moved: a move inside what it holds costs
/// nothing. Reading past its end is an error of the kind [`ErrorKind::UnexpectedEof`] for the
/// readers of this type, and the end of the stream for [`Read`].
#[derive(Debug)]
pub struct Cursor<'a> {
    source: &'a Source,
    /// The position, as an offset into the archive.
    pos: u64,
    /// The offset this cursor does not read past.
    end: u64,
    /// The bytes of the archive from `buf_start` on that are held.
    buf: Vec<u8>,
    buf_start: u64,
}

impl Cursor<'_> {
    /// The position, as an offset into the archive.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.pos
    }

    /// How many bytes lie between the position and the end of this cursor.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.end.saturating_sub(self.pos)
    }

    /// Move to `position`, an offset into the archive. An error when it lies past the end of
    /// this cursor.
    pub fn seek(&mut self, position: u64) -> io::Result<()> {
        if position > self.end {
            return Err(outside());
        }
        self.pos = position;
        Ok(())
    }

    /// Move `count` bytes forward. An error when that leads past the end of this cursor.
    pub fn skip(&mut self, count: u64) -> io::Result<()> {
        self.seek(self.pos.checked_add(count).ok_or_else(outside)?)
    }

    /// The part of what is held that starts at the position, empty when the position lies
    /// outside it.
    fn held(&self) -> &[u8] {
        self.pos.checked_sub(self.buf_start).and_then(|skip| usize::try_from(skip).ok()).and_then(|skip| self.buf.get(skip..)).unwrap_or_default()
    }

    /// The next `len` bytes. An error when fewer are left: that is checked before anything is
    /// allocated, so a length taken from a header can be passed as it is.
    pub fn read_vec(&mut self, len: u64) -> io::Result<Vec<u8>> {
        if len > self.remaining() {
            return Err(outside());
        }
        let mut out = vec![0_u8; usize::try_from(len).map_err(|_| outside())?];
        self.read_exact(&mut out)?;
        Ok(out)
    }

    /// The next `N` bytes. An error when fewer are left, and the position stays where it is.
    pub fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        if u64::try_from(N).map_or(true, |len| len > self.remaining()) {
            return Err(outside());
        }
        let mut out = [0_u8; N];
        self.read_exact(&mut out)?;
        Ok(out)
    }

    /// The next byte.
    pub fn u8(&mut self) -> io::Result<u8> {
        self.array::<1>().map(|[byte]| byte)
    }

    /// The next two bytes as a little-endian number.
    pub fn u16_le(&mut self) -> io::Result<u16> {
        self.array().map(u16::from_le_bytes)
    }

    /// The next four bytes as a little-endian number.
    pub fn u32_le(&mut self) -> io::Result<u32> {
        self.array().map(u32::from_le_bytes)
    }

    /// The next eight bytes as a little-endian number.
    pub fn u64_le(&mut self) -> io::Result<u64> {
        self.array().map(u64::from_le_bytes)
    }
}

impl Read for Cursor<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // a read of a block or more goes straight to where it is wanted
        if self.held().is_empty() && buf.len() >= BLOCK {
            let count = usize::try_from(self.remaining()).map_or(buf.len(), |left| left.min(buf.len()));
            let Some(target) = buf.get_mut(..count) else { return Ok(0) };
            self.source.read_exact_at(self.pos, target)?;
            self.consume(count);
            return Ok(count);
        }
        let held = self.fill_buf()?;
        let count = held.len().min(buf.len());
        if let (Some(target), Some(from)) = (buf.get_mut(..count), held.get(..count)) {
            target.copy_from_slice(from);
        }
        self.consume(count);
        Ok(count)
    }
}

impl BufRead for Cursor<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.held().is_empty() && self.pos < self.end {
            let count = usize::try_from(self.remaining()).map_or(BLOCK, |left| left.min(BLOCK));
            self.buf.resize(count, 0);
            self.buf_start = self.pos;
            if let Err(error) = self.source.read_exact_at(self.pos, &mut self.buf) {
                self.buf.clear();
                return Err(error);
            }
        }
        Ok(self.held())
    }

    fn consume(&mut self, amount: usize) {
        self.pos = self.pos.saturating_add(u64::try_from(amount).unwrap_or(u64::MAX)).min(self.end);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    /// Bytes that say where they are: no two places of a megabyte hold the same four.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).flat_map(|at| u32::try_from(at).unwrap().to_le_bytes()).take(len).collect()
    }

    /// The same archive of `len` bytes three ways: in memory, as a file, and as a file behind a
    /// program of 300 bytes.
    fn sources(len: usize) -> (Vec<u8>, tempfile::TempDir, Vec<Source>) {
        let data = pattern(len);
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("bare.bin");
        std::fs::write(&bare, &data).unwrap();
        let behind = dir.path().join("behind.bin");
        let mut file = File::create(&behind).unwrap();
        file.write_all(&[0xEE; 300]).unwrap();
        file.write_all(&data).unwrap();
        drop(file);
        let all = vec![Source::from_bytes(data.clone()), Source::open(&bare, 0).unwrap(), Source::open(&behind, 300).unwrap()];
        (data, dir, all)
    }

    fn kind(result: io::Result<impl Sized>) -> Option<ErrorKind> {
        result.err().map(|error| error.kind())
    }

    #[test]
    fn a_source_says_where_it_is_and_how_long() {
        let (data, dir, all) = sources(1000);
        let [memory, bare, behind] = all.as_slice() else { panic!("three sources") };

        assert_eq!((memory.len(), memory.offset(), memory.is_empty()), (1000, 0, false));
        assert_eq!((bare.len(), bare.offset()), (1000, 0));
        assert_eq!((behind.len(), behind.offset()), (1000, 300), "the program in front does not count");
        assert_eq!(memory.path(), Path::new("<memory>"));
        assert_eq!(behind.path(), dir.path().join("behind.bin"));

        // an archive may start where the file ends, and not behind that
        assert!(Source::open(&dir.path().join("bare.bin"), 1000).unwrap().is_empty());
        assert_eq!(kind(Source::open(&dir.path().join("bare.bin"), 1001)), Some(ErrorKind::UnexpectedEof));
        assert_eq!(kind(Source::open(&dir.path().join("absent.bin"), 0)), Some(ErrorKind::NotFound));
        assert_eq!(data.len(), 1000);
    }

    #[test]
    fn an_exact_read_gives_the_range_or_an_error() {
        let (data, _dir, all) = sources(5000);
        for source in &all {
            assert_eq!(source.read_at(0, 5000).unwrap(), data);
            assert_eq!(source.read_at(4990, 10).unwrap(), data[4990..]);
            assert_eq!(source.read_at(123, 456).unwrap(), data[123..579]);
            assert!(source.read_at(5000, 0).unwrap().is_empty(), "nothing, at the very end");

            for (offset, len) in [(0, 5001), (4999, 2), (5001, 0), (5000, 1), (u64::MAX, 1), (1, u64::MAX), (u64::MAX, u64::MAX)] {
                assert_eq!(kind(source.read_at(offset, len)), Some(ErrorKind::UnexpectedEof), "{len} bytes at {offset}");
            }

            let mut four = [0_u8; 4];
            source.read_exact_at(4996, &mut four).unwrap();
            assert_eq!(four, data[4996..]);
            assert_eq!(kind(source.read_exact_at(4997, &mut four)), Some(ErrorKind::UnexpectedEof));
            assert_eq!(four, data[4996..], "a read that is refused leaves the buffer alone");
        }
    }

    /// A length of 2^63 from a header is refused by arithmetic: the test would not come back
    /// from an allocation of that size.
    #[test]
    fn a_length_that_is_a_lie_is_refused_before_anything_is_allocated() {
        let source = Source::from_bytes(vec![7; 64]);
        for len in [65, 1 << 40, 1 << 63, u64::MAX] {
            assert_eq!(kind(source.read_at(0, len)), Some(ErrorKind::UnexpectedEof));
            assert_eq!(kind(source.reader(0, len)), Some(ErrorKind::UnexpectedEof));
            assert_eq!(kind(source.cursor(0).read_vec(len)), Some(ErrorKind::UnexpectedEof));
        }
        assert_eq!(source.read_up_to(60, 1 << 63).unwrap(), [7; 4]);
    }

    #[test]
    fn a_read_of_up_to_so_many_bytes_stops_at_the_end() {
        let (data, _dir, all) = sources(5000);
        for source in &all {
            assert_eq!(source.read_up_to(0, 10).unwrap(), data[..10]);
            assert_eq!(source.read_up_to(4990, 100).unwrap(), data[4990..]);
            assert_eq!(source.read_up_to(0, u64::MAX).unwrap(), data);
            assert!(source.read_up_to(5000, 100).unwrap().is_empty());
            assert_eq!(kind(source.read_up_to(5001, 100)), Some(ErrorKind::UnexpectedEof));
        }
    }

    #[test]
    fn the_whole_archive_is_what_lies_behind_its_start() {
        let (data, _dir, all) = sources(70_000);
        for source in &all {
            assert_eq!(source.read_at(0, source.len()).unwrap(), data);
        }
    }

    /// A reader gives its range and nothing behind it, whatever sizes it is read in: smaller
    /// than a block, a block, larger than a block.
    #[test]
    fn a_reader_gives_its_range_in_any_pieces() {
        let (data, _dir, all) = sources(3 * BLOCK + 1234);
        for source in &all {
            for piece in [1, 7, 4096, BLOCK - 1, BLOCK, BLOCK + 1, 3 * BLOCK] {
                let mut reader = source.reader(100, 2 * BLOCK as u64 + 500).unwrap();
                let mut out = Vec::new();
                let mut buf = vec![0_u8; piece];
                loop {
                    let count = reader.read(&mut buf).unwrap();
                    if count == 0 {
                        break;
                    }
                    out.extend_from_slice(&buf[..count]);
                }
                assert_eq!(out, data[100..100 + 2 * BLOCK + 500], "in pieces of {piece}");
                assert_eq!((reader.position(), reader.remaining()), (100 + 2 * BLOCK as u64 + 500, 0));
            }

            let mut all_of_it = Vec::new();
            let _ = source.reader(0, source.len()).unwrap().read_to_end(&mut all_of_it).unwrap();
            assert_eq!(all_of_it, data);
            assert!(source.reader(source.len(), 0).unwrap().fill_buf().unwrap().is_empty());
        }
    }

    #[test]
    fn a_reader_feeds_a_decoder() {
        let text = b"the quick brown fox jumps over the lazy dog, ".repeat(4000);
        let mut encoder = flate2::write::DeflateEncoder::new(vec![0xEE; 40], flate2::Compression::best());
        encoder.write_all(&text).unwrap();
        let archive = encoder.finish().unwrap();
        let packed = u64::try_from(archive.len()).unwrap() - 40;

        let source = Source::from_bytes(archive);
        let mut out = Vec::new();
        let _ = flate2::bufread::DeflateDecoder::new(source.reader(40, packed).unwrap()).read_to_end(&mut out).unwrap();
        assert_eq!(out, text);
    }

    #[test]
    fn a_cursor_reads_the_fields_of_a_header() {
        let mut archive = vec![0xAB];
        archive.extend_from_slice(&0x1234_u16.to_le_bytes());
        archive.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        archive.extend_from_slice(&0x0102_0304_0506_0708_u64.to_le_bytes());
        archive.extend_from_slice(b"name.txt");
        let source = Source::from_bytes(archive);

        let mut cursor = source.cursor(0);
        assert_eq!(cursor.u8().unwrap(), 0xAB);
        assert_eq!(cursor.u16_le().unwrap(), 0x1234);
        assert_eq!(cursor.u32_le().unwrap(), 0xDEAD_BEEF);
        assert_eq!(cursor.u64_le().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!((cursor.position(), cursor.remaining()), (15, 8));
        assert_eq!(cursor.array::<4>().unwrap(), *b"name");
        assert_eq!(cursor.read_vec(4).unwrap(), b".txt");

        // at the end: every reader fails, and the position stays
        assert_eq!(cursor.remaining(), 0);
        assert_eq!(kind(cursor.u8()), Some(ErrorKind::UnexpectedEof));
        assert_eq!(kind(cursor.u32_le()), Some(ErrorKind::UnexpectedEof));
        assert_eq!(kind(cursor.read_vec(1)), Some(ErrorKind::UnexpectedEof));
        assert!(cursor.read_vec(0).unwrap().is_empty());
        assert_eq!(cursor.position(), 23);

        // a field that is cut off is not read by halves
        let mut cursor = source.cursor(21);
        assert_eq!(kind(cursor.u32_le()), Some(ErrorKind::UnexpectedEof));
        assert_eq!(cursor.position(), 21);
        assert_eq!(cursor.u16_le().unwrap(), u16::from_le_bytes(*b"xt"));
    }

    #[test]
    fn a_cursor_moves_inside_its_range_and_not_out_of_it() {
        let (data, _dir, all) = sources(2 * BLOCK + 100);
        for source in &all {
            let mut cursor = source.cursor(10);
            assert_eq!(cursor.array::<4>().unwrap(), data[10..14]);
            cursor.skip(6).unwrap();
            assert_eq!(cursor.array::<4>().unwrap(), data[20..24]);

            // back inside what is held, and far ahead of it
            cursor.seek(12).unwrap();
            assert_eq!(cursor.array::<4>().unwrap(), data[12..16]);
            cursor.seek(2 * BLOCK as u64 + 96).unwrap();
            assert_eq!(cursor.array::<4>().unwrap(), data[2 * BLOCK + 96..]);
            cursor.seek(BLOCK as u64 - 2).unwrap();
            assert_eq!(cursor.array::<4>().unwrap(), data[BLOCK - 2..BLOCK + 2], "across the end of a block");

            let end = source.len();
            cursor.seek(end).unwrap();
            assert_eq!(kind(cursor.seek(end + 1)), Some(ErrorKind::UnexpectedEof));
            assert_eq!(kind(cursor.skip(1)), Some(ErrorKind::UnexpectedEof));
            assert_eq!(kind(cursor.skip(u64::MAX)), Some(ErrorKind::UnexpectedEof));
            assert_eq!(cursor.position(), end);

            // a reader ends where its range ends, and is not moved past that either
            let mut reader = source.reader(50, 20).unwrap();
            assert_eq!(kind(reader.seek(71)), Some(ErrorKind::UnexpectedEof));
            reader.seek(66).unwrap();
            assert_eq!(reader.array::<4>().unwrap(), data[66..70]);
            assert_eq!(kind(reader.u8()), Some(ErrorKind::UnexpectedEof));
        }
    }

    /// A file that was cut short after it was opened: the range lies inside what the source
    /// was told, and the read says that the file ends.
    #[test]
    fn a_file_that_shrinks_is_an_error_and_not_a_short_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cut.bin");
        std::fs::write(&path, pattern(4000)).unwrap();
        let source = Source::open(&path, 0).unwrap();
        File::options().write(true).open(&path).unwrap().set_len(1000).unwrap();

        assert_eq!(source.read_at(0, 1000).unwrap(), pattern(4000)[..1000]);
        assert_eq!(kind(source.read_at(0, 4000)), Some(ErrorKind::UnexpectedEof));
        assert_eq!(kind(source.cursor(990).read_vec(20)), Some(ErrorKind::UnexpectedEof));
    }
}
