//! A catalogue of known files.
//!
//! The central directory gives the CRC-32 and the size of every entry in the clear. A list of
//! files that exist elsewhere, with the same two numbers for each, says which entries are
//! such files: the name each is known by, and its stronger hashes, with which the user can
//! find it. The file found is then given with `--known`, and is the whole attack.
//!
//! The list is text, one file on a line, with the fields apart by commas and a first line
//! that names them, as the file list of the reference data set of NIST has it
//! (`"SHA-1","MD5","CRC32","FileName","FileSize",...`). The columns are found by their names,
//! in any order: `CRC32` and `FileSize` have to be there, and `FileName`, `SHA-1` and `MD5`
//! are used when they are.
//!
//! Nothing is asked of anybody: the list is a file the user has. It is read in a stream, a
//! line at a time, and can be of any size.

use std::collections::HashMap;
use std::io::BufRead as _;
use std::io::Read as _;
use std::path::Path;

use anyhow::Context as _;

use super::pool::Pool;

/// The longest line that is read. What is longer is passed over, to its end.
const LINE_MAX: u64 = 64 * 1024;

/// How many rows of the list are kept for one entry. A file that many products ship has many.
pub(crate) const ROWS_FOR_ENTRY: usize = 3;

/// One row of the list that is an entry of the pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Known {
    /// The entry, by its place in the pool.
    pub target: usize,
    /// The name the list has for the file.
    pub name: Option<String>,
    /// Its SHA-1, as the list writes it.
    pub sha1: Option<String>,
    /// Its MD5, as the list writes it.
    pub md5: Option<String>,
}

/// What reading a list came to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Catalogue {
    /// How many rows were read, the first line not among them.
    pub rows: u64,
    /// How many of them could not be read as a row: no number where one belongs, or too long.
    pub passed_over: u64,
    /// The rows that are entries of the pool, in the order of the list.
    pub known: Vec<Known>,
}

/// The fields of one line: apart by commas, and a field in double quotes may hold commas, and
/// holds a double quote as two.
fn fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(next) = chars.next() {
        match next {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                let _ = chars.next();
            },
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

/// Where the columns of a list are, from its first line.
#[derive(Debug, Clone, Copy)]
struct Columns {
    crc32: usize,
    size: usize,
    name: Option<usize>,
    sha1: Option<usize>,
    md5: Option<usize>,
}

impl Columns {
    /// The columns a first line names. `None` when it names no CRC-32 or no size.
    fn of(line: &str) -> Option<Self> {
        let named: Vec<String> = fields(line).iter().map(|field| field.trim().to_ascii_lowercase().replace(['-', '_', ' '], "")).collect();
        let at = |names: &[&str]| named.iter().position(|field| names.contains(&field.as_str()));
        Some(Self { crc32: at(&["crc32", "crc"])?, size: at(&["filesize", "size"])?, name: at(&["filename", "name"]), sha1: at(&["sha1"]), md5: at(&["md5"]) })
    }
}

/// Read the next line of at most [`LINE_MAX`] bytes into `line`, without its end. Returns
/// whether there was one, and whether it was longer and is cut: the rest of it is passed over.
fn next_line(input: &mut impl std::io::BufRead, line: &mut Vec<u8>) -> std::io::Result<(bool, bool)> {
    line.clear();
    let read = input.by_ref().take(LINE_MAX).read_until(b'\n', line)?;
    if read == 0 {
        return Ok((false, false));
    }
    let whole = line.last() == Some(&b'\n');
    let cut = !whole && read as u64 == LINE_MAX;
    if cut {
        let mut rest = Vec::new();
        while input.by_ref().take(LINE_MAX).read_until(b'\n', &mut rest)? > 0 && rest.last() != Some(&b'\n') {
            rest.clear();
        }
    }
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        let _ = line.pop();
    }
    Ok((true, cut))
}

/// Read the list at `path`, and say which entries of the pool are in it.
pub(crate) fn read(path: &Path, pool: &Pool) -> anyhow::Result<Catalogue> {
    let shown = path.display();
    let file = std::fs::File::open(path).with_context(|| format!("--catalogue {shown}: the file cannot be opened"))?;
    let mut input = std::io::BufReader::new(file);
    let mut line = Vec::new();

    let (there, _) = next_line(&mut input, &mut line).with_context(|| format!("--catalogue {shown}: the file cannot be read"))?;
    // a list that was saved with a byte order mark starts with one
    let first = String::from_utf8_lossy(&line);
    let columns = there.then(|| Columns::of(first.trim_start_matches('\u{feff}'))).flatten();
    let Some(columns) = columns else {
        anyhow::bail!("--catalogue {shown}: the first line has to name the columns, CRC32 and FileSize among them, as in \"SHA-1\",\"MD5\",\"CRC32\",\"FileName\",\"FileSize\"");
    };

    // the entries by what the directory says of each: an empty one is every empty file
    let mut wanted: HashMap<(u32, u64), Vec<usize>> = HashMap::new();
    for (index, target) in pool.targets.iter().enumerate().filter(|(_, target)| target.entry.uncompressed_size > 0) {
        wanted.entry((target.entry.crc32, target.entry.uncompressed_size)).or_default().push(index);
    }

    let mut out = Catalogue::default();
    let mut kept: HashMap<usize, usize> = HashMap::new();
    loop {
        let (there, cut) = next_line(&mut input, &mut line).with_context(|| format!("--catalogue {shown}: the file cannot be read"))?;
        if !there {
            break;
        }
        out.rows += 1;
        let text = String::from_utf8_lossy(&line);
        let row = fields(&text);
        let number = |at: usize, radix: u32| row.get(at).and_then(|field| u64::from_str_radix(field.trim(), radix).ok());
        let Some((crc32, size)) = number(columns.crc32, 16).and_then(|crc32| u32::try_from(crc32).ok()).zip(number(columns.size, 10)).filter(|_| !cut) else {
            out.passed_over += 1;
            continue;
        };
        let Some(targets) = wanted.get(&(crc32, size)) else { continue };
        let field = |at: Option<usize>| at.and_then(|at| row.get(at)).map(|field| field.trim().to_owned()).filter(|field| !field.is_empty());
        for &target in targets {
            let count = kept.entry(target).or_insert(0);
            if *count < ROWS_FOR_ENTRY {
                *count += 1;
                out.known.push(Known { target, name: field(columns.name), sha1: field(columns.sha1), md5: field(columns.md5) });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// The archive of the tutorial of bkcrack. Its entries by their place in the pool:
    /// `advice.jpg`, 54,799 bytes, and `spiral.svg`, 1,265 bytes.
    fn pool() -> Pool {
        Pool::read(&[PathBuf::from("tests/fixtures/zip-crypto/bkcrack-src_secrets.zip")], &|_| None).unwrap()
    }

    fn list(text: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("files.csv");
        std::fs::write(&path, text).unwrap();
        (dir, path)
    }

    #[test]
    fn a_line_is_fields_apart_by_commas_with_quotes_around_those_that_hold_one() {
        assert_eq!(fields(r#""A1","b2",00C0FFEE,"a, b.txt",12"#), ["A1", "b2", "00C0FFEE", "a, b.txt", "12"]);
        assert_eq!(fields(r#""say ""hello"".txt",,"#), [r#"say "hello".txt"#, "", ""]);
        assert_eq!(fields(""), [""]);
    }

    #[test]
    fn the_entries_that_are_in_the_list_are_named_with_their_hashes() {
        let pool = pool();
        let (crc, size) = (pool.targets[1].entry.crc32, pool.targets[1].entry.uncompressed_size);
        assert_eq!((pool.targets[1].name.as_str(), size), ("spiral.svg", 1265));
        let text = format!(
            "\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\",\"FileSize\",\"ProductCode\"\r\n\
             \"0000000000000000000000000000000000000001\",\"00000000000000000000000000000001\",\"{crc:08X}\",\"drawing, the first.svg\",{size},1\r\n\
             \"0000000000000000000000000000000000000002\",\"00000000000000000000000000000002\",\"{crc:08X}\",\"other.svg\",{},1\r\n\
             \"0000000000000000000000000000000000000003\",\"00000000000000000000000000000003\",\"DEADBEEF\",\"spiral.svg\",{size},1\r\n\
             \"0000000000000000000000000000000000000004\",\"00000000000000000000000000000004\",\"not hex\",\"broken.svg\",{size},1\r\n",
            size + 1
        );
        let (_dir, path) = list(&text);
        let read = read(&path, &pool).unwrap();
        assert_eq!((read.rows, read.passed_over), (4, 1));
        // the CRC-32 and the size together name the file, and neither alone does
        assert_eq!(read.known, [Known { target: 1, name: Some("drawing, the first.svg".to_owned()), sha1: Some("0000000000000000000000000000000000000001".to_owned()), md5: Some("00000000000000000000000000000001".to_owned()) }]);
    }

    #[test]
    fn the_columns_are_found_by_their_names_in_any_order() {
        let pool = pool();
        let (crc, size) = (pool.targets[0].entry.crc32, pool.targets[0].entry.uncompressed_size);
        // a list of the two numbers and nothing else, with a byte order mark and no line end at its end
        let (_dir, path) = list(&format!("\u{feff}size,crc\n{size},{crc:08x}\n1,00000000\n{size},{crc:08x}\n{size},{crc:08x}\n{size},{crc:08x}"));
        let read = read(&path, &pool).unwrap();
        assert_eq!((read.rows, read.passed_over), (5, 0));
        // a file that the list has many times is kept a few times
        assert_eq!(read.known, vec![Known { target: 0, name: None, sha1: None, md5: None }; ROWS_FOR_ENTRY]);
    }

    #[test]
    fn a_list_without_the_two_numbers_is_refused_and_a_line_that_is_too_long_is_passed_over() {
        let pool = pool();
        for text in ["", "\"SHA-1\",\"MD5\",\"FileName\"\n", "just some text\nand more\n"] {
            let (_dir, path) = list(text);
            let refused = read(&path, &pool).unwrap_err().to_string();
            assert!(refused.contains("the first line has to name the columns, CRC32 and FileSize among them"), "{refused}");
        }
        assert!(read(Path::new("tests/fixtures/zip-crypto/absent.csv"), &pool).unwrap_err().to_string().contains("cannot be opened"));

        // a line of three times the limit, with a row that fits behind it
        let (crc, size) = (pool.targets[1].entry.crc32, pool.targets[1].entry.uncompressed_size);
        let long = "x".repeat(3 * usize::try_from(LINE_MAX).unwrap());
        let (_dir, path) = list(&format!("CRC32,FileSize,FileName\n{crc:08x},{size},{long}\n{crc:08x},{size},short.svg\n"));
        let read = read(&path, &pool).unwrap();
        assert_eq!((read.rows, read.passed_over), (2, 1));
        assert_eq!(read.known, [Known { target: 1, name: Some("short.svg".to_owned()), sha1: None, md5: None }]);
    }
}
