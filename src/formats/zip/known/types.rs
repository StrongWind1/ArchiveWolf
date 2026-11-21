//! What the name of an entry says of its content: the table of file types.
//!
//! The table is data, not code: `types.json`, one object for each row, read when the tool is
//! built and parsed when it is first asked. A row names the entries it is for and one or more
//! forms a file of that type starts and ends with, in a small language:
//!
//! ```text
//! form   = piece (";" piece)*
//! piece  = position ":" token+        a position below zero counts from the end of the file
//! token  = unit ["*" count]           a count repeats the unit; "*" alone runs to the end
//! unit   = HH                         a byte, as two hex digits
//!        | 'text'                     its bytes as they are written
//!        | ??                         a byte of which nothing is known
//!        | [HH HH-HH ...]             a byte that is one of these values
//!        | {size:le32}                the size of the file, or {size-8:be16} and the like
//!        | text | ascii | utf16       a byte of that class
//! ```
//!
//! Every row is held against real files of its type by the test at the end of this file: a
//! row that the files do not bear out is not in the table.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Deserialize;

use super::claim::Cells;
use super::claim::Form;
use super::set::ByteSet;

/// The table as it is written.
const TABLE: &str = include_str!("types.json");

/// The most bytes a class that runs to the end of a file is taken for. A class is a filter:
/// some tens of bytes of it tell a key from a wrong one, and no more are looked at.
const CLASS_MAX: u64 = 256;

/// The most bytes one form of a row may say something of.
const FORM_MAX: u64 = 8192;

/// One row of the table, as `types.json` holds it.
#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(test, serde(deny_unknown_fields))]
pub(crate) struct Row {
    /// The name of the type, as `--type` takes it.
    #[serde(rename = "type")]
    pub name: String,
    /// What a file of the type is, in the words of a plan: "a PNG image".
    pub what: String,
    /// The names of the entries the row is for: patterns in which `*` stands for any text, held
    /// against the whole name and against its last part, without regard to case.
    pub names: Vec<String>,
    /// Other types whose files also fit this row: a `.docx` file is a ZIP archive. It is what
    /// the test of the rows reads, and nothing else does.
    #[cfg(test)]
    #[serde(default)]
    pub kin: Vec<String>,
    /// The forms a file of the type may have, the most usual first.
    pub forms: Vec<String>,
}

/// The rows, parsed once. A table that does not parse is a defect of the build, which the
/// tests catch: the tool then has no rows.
static ROWS: LazyLock<Vec<Row>> = LazyLock::new(|| {
    let mut rows: Vec<Row> = serde_json::from_str(TABLE).unwrap_or_default();
    // a name is held against the patterns without regard to case: they are made lower case
    // here, once, and not for every entry of every archive
    for pattern in rows.iter_mut().flat_map(|row| &mut row.names) {
        pattern.make_ascii_lowercase();
    }
    rows
});

/// Every row of the table.
#[must_use]
pub(crate) fn rows() -> &'static [Row] {
    &ROWS
}

/// The row of a type by its name.
#[must_use]
pub(crate) fn by_type(name: &str) -> Option<&'static Row> {
    rows().iter().find(|row| row.name.eq_ignore_ascii_case(name))
}

/// The patterns of the table, laid out so that a name is looked up and not held against
/// each of them: an archive has as many names as it has entries.
struct Patterns {
    /// The patterns that are `*` and an ending, which is nearly all of them: each ending with
    /// the first row that has it.
    endings: HashMap<&'static str, usize>,
    /// How long the longest ending is, in bytes.
    longest: usize,
    /// The other patterns, each with its row.
    others: Vec<(usize, &'static str)>,
}

static PATTERNS: LazyLock<Patterns> = LazyLock::new(|| {
    let mut patterns = Patterns { endings: HashMap::new(), longest: 0, others: Vec::new() };
    for (index, row) in rows().iter().enumerate() {
        for pattern in &row.names {
            match pattern.strip_prefix('*').filter(|ending| !ending.is_empty() && !ending.contains('*')) {
                Some(ending) => {
                    patterns.longest = patterns.longest.max(ending.len());
                    let _ = patterns.endings.entry(ending).or_insert(index);
                },
                None => patterns.others.push((index, pattern)),
            }
        }
    }
    patterns
});

/// The row for an entry of this name: the first whose patterns fit.
#[must_use]
pub(crate) fn by_entry(name: &[u8]) -> Option<&'static Row> {
    let name = String::from_utf8_lossy(name).to_ascii_lowercase();
    let last = name.rsplit('/').next().unwrap_or(&name);
    let patterns = &*PATTERNS;
    // an ending fits the name that ends with it: every end of the name that is no longer than
    // the longest ending is looked up
    let by_ending = (name.len().saturating_sub(patterns.longest)..name.len()).filter_map(|at| patterns.endings.get(name.get(at..)?)).copied().min();
    let by_other = patterns.others.iter().filter(|(_, pattern)| fits(pattern, &name) || fits(pattern, last)).map(|(index, _)| *index).min();
    rows().get([by_ending, by_other].into_iter().flatten().min()?)
}

/// Whether `text` fits a pattern in which `*` stands for any text.
pub(crate) fn fits(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let Some(first) = parts.next() else { return text.is_empty() };
    let Some(mut rest) = text.strip_prefix(first) else { return false };
    let Some(mut part) = parts.next() else { return rest.is_empty() };
    // every part but the last stands somewhere in what is left, in its order, and the last at
    // its end: a part is taken for the last until another follows it
    for next in parts {
        match rest.find(part) {
            Some(at) => rest = rest.get(at + part.len()..).unwrap_or_default(),
            None => return false,
        }
        part = next;
    }
    rest.ends_with(part)
}

impl Row {
    /// The forms of the row for a file of `size` bytes, in positions of the file. A form that
    /// such a file is too short for is left out.
    #[must_use]
    pub(crate) fn forms(&self, size: u64) -> Vec<Form> {
        self.forms.iter().filter_map(|form| parse_form(form, size).ok().flatten()).collect()
    }
}

/// One form for a file of `size` bytes. `Ok(None)` when the file is too short for it, and an
/// error when the form is not written in the language of the table.
fn parse_form(text: &str, size: u64) -> Result<Option<Form>, String> {
    let mut form = Form::new();
    let mut said = 0_u64;
    for piece in pieces_of(text) {
        let (position, tokens) = piece.split_once(':').ok_or_else(|| format!("a piece without a position: {piece:?}"))?;
        let position: i64 = position.trim().parse().map_err(|_| format!("no position: {position:?}"))?;
        let from_end = u64::try_from(position).is_err();
        let Some(mut at) = (if from_end { size.checked_sub(position.unsigned_abs()) } else { u64::try_from(position).ok() }) else { return Ok(None) };

        for token in tokens_of(tokens)? {
            let (unit, repeat) = match token.rsplit_once('*') {
                Some((unit, count)) if !unit.is_empty() && !unit.starts_with('\'') && count.bytes().all(|byte| byte.is_ascii_digit()) => (unit, if count.is_empty() { None } else { Some(count.parse::<u64>().map_err(|_| format!("no count: {token:?}"))?) }),
                _ => (token.as_str(), Some(1)),
            };
            // a field of the size that this size does not fit: the form is not for such a file
            let Some(unit) = unit_of(unit, size)? else { return Ok(None) };
            let len = unit.len().max(1);
            // a unit without a count runs to the end of the file, as far as a class is taken
            let times = repeat.unwrap_or_else(|| (size.saturating_sub(at) / len).min(CLASS_MAX / len));
            for _ in 0..times {
                if at.checked_add(len).is_none_or(|end| end > size) {
                    return Ok(None);
                }
                if let Unit::Known(cells) = &unit {
                    said += len;
                    if said > FORM_MAX {
                        return Err(format!("a form that says more than {FORM_MAX} bytes: {text:?}"));
                    }
                    let place = i64::try_from(at).map_err(|_| "a position too large".to_owned())?;
                    if !form.add(place, cells.clone()) {
                        return Err(format!("a form that contradicts itself at {at}: {text:?}"));
                    }
                }
                at += len;
            }
        }
    }
    Ok(Some(form))
}

/// What one unit of a form says: cells, or a count of bytes of which nothing is known.
#[derive(Debug, Clone)]
enum Unit {
    Known(Cells),
    Holes(u64),
}

impl Unit {
    /// How many bytes the unit covers.
    fn len(&self) -> u64 {
        match self {
            Self::Known(cells) => cells.len(),
            Self::Holes(count) => *count,
        }
    }
}

/// The pieces of a form: what stands between semicolons that are not inside a quoted text.
fn pieces_of(text: &str) -> Vec<&str> {
    let mut pieces = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (at, c) in text.char_indices() {
        match c {
            '\'' => quoted = !quoted,
            ';' if !quoted => {
                pieces.push(text.get(start..at).unwrap_or_default());
                start = at + 1;
            },
            _ => {},
        }
    }
    pieces.push(text.get(start..).unwrap_or_default());
    pieces
}

/// The tokens of a piece: words between spaces, where a quoted text and a set in brackets are
/// one word each whatever they hold.
fn tokens_of(text: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut inside: Option<char> = None;
    for c in text.chars() {
        match (inside, c) {
            (Some('\''), '\'') | (Some('['), ']') | (Some('{'), '}') => {
                word.push(c);
                inside = None;
            },
            (None, '\'' | '[' | '{') => {
                word.push(c);
                inside = Some(c);
            },
            (None, c) if c.is_whitespace() => {
                if !word.is_empty() {
                    tokens.push(std::mem::take(&mut word));
                }
            },
            _ => word.push(c),
        }
    }
    if inside.is_some() {
        return Err(format!("a quote or a bracket that is not closed: {text:?}"));
    }
    if !word.is_empty() {
        tokens.push(word);
    }
    Ok(tokens)
}

/// A byte from two hex digits.
fn hex_byte(text: &str) -> Result<u8, String> {
    if text.len() == 2 { u8::from_str_radix(text, 16).map_err(|_| format!("no hex byte: {text:?}")) } else { Err(format!("no hex byte: {text:?}")) }
}

/// What one unit of a form says, for a file of `size` bytes. `Ok(None)` for a field of the
/// size that a file of this size has no value for.
fn unit_of(unit: &str, size: u64) -> Result<Option<Unit>, String> {
    if let Some(field) = unit.strip_prefix('{') {
        let field = field.strip_suffix('}').ok_or_else(|| format!("a field that is not closed: {unit:?}"))?;
        return Ok(size_field(field, size)?.map(|bytes| Unit::Known(Cells::Bytes(bytes))));
    }
    fixed_unit(unit).map(Some)
}

/// What a unit says that does not depend on the size of the file.
fn fixed_unit(unit: &str) -> Result<Unit, String> {
    if let Some(text) = unit.strip_prefix('\'') {
        let text = text.strip_suffix('\'').ok_or_else(|| format!("a text that is not closed: {unit:?}"))?;
        return Ok(Unit::Known(Cells::Bytes(text.as_bytes().to_vec())));
    }
    if let Some(items) = unit.strip_prefix('[') {
        let items = items.strip_suffix(']').ok_or_else(|| format!("a set that is not closed: {unit:?}"))?;
        let mut set = ByteSet::NONE;
        for item in items.split_whitespace() {
            let (low, high) = item.split_once('-').unwrap_or((item, item));
            let (low, high) = (hex_byte(low)?, hex_byte(high)?);
            if low > high {
                return Err(format!("a range that runs backward: {item:?}"));
            }
            set = set.union(ByteSet::from_values(low..=high));
        }
        if set == ByteSet::NONE {
            return Err(format!("an empty set: {unit:?}"));
        }
        return Ok(Unit::Known(Cells::Sets(vec![set])));
    }
    match unit {
        "??" => Ok(Unit::Holes(1)),
        "text" => Ok(Unit::Known(Cells::Fill(ByteSet::text(), 1))),
        "ascii" => Ok(Unit::Known(Cells::Fill(ByteSet::ascii(), 1))),
        // a character of the first 256 in UTF-16, low byte first: text, then zero
        "utf16" => Ok(Unit::Known(Cells::Sets(vec![ByteSet::text(), ByteSet::of(0)]))),
        _ => hex_byte(unit).map(|byte| Unit::Known(Cells::Bytes(vec![byte]))),
    }
}

/// A field that follows from the size of the file: `size`, `size-8` or `size+2`, then how it
/// is written: `le16`, `le32`, `be16` or `be32`. `Ok(None)` when the value does not fit the
/// field, or the file is shorter than what the field takes off.
fn size_field(field: &str, size: u64) -> Result<Option<Vec<u8>>, String> {
    let (value, encoding) = field.split_once(':').ok_or_else(|| format!("a field without its encoding: {field:?}"))?;
    let no_value = || format!("no value: {value:?}");
    let value = match value.strip_prefix("size") {
        Some("") => Some(size),
        Some(change) => {
            let amount: u64 = change.get(1..).unwrap_or_default().parse().map_err(|_| no_value())?;
            match change.as_bytes().first() {
                Some(b'-') => size.checked_sub(amount),
                Some(b'+') => size.checked_add(amount),
                _ => return Err(no_value()),
            }
        },
        None => return Err(no_value()),
    };
    let Some(value) = value else { return Ok(None) };
    Ok(match encoding {
        "le16" => u16::try_from(value).ok().map(|v| v.to_le_bytes().to_vec()),
        "be16" => u16::try_from(value).ok().map(|v| v.to_be_bytes().to_vec()),
        "le32" => u32::try_from(value).ok().map(|v| v.to_le_bytes().to_vec()),
        "be32" => u32::try_from(value).ok().map(|v| v.to_be_bytes().to_vec()),
        _ => return Err(format!("no encoding: {encoding:?}")),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn a_form_is_read_as_it_is_written() {
        let form = parse_form("0: 89 'PNG' 0D 0A 1A 0A 00*3 0D 'IHDR' 00 00 ??*2 [01 02 04 08 10]; -4: AE 42 60 82", 1000).unwrap().unwrap();
        assert_eq!(form.stretches(), [(0, 18), (996, 4)]);
        assert_eq!(form.get(20), Some(ByteSet::from_values([1, 2, 4, 8, 16])));
        assert_eq!((form.get(18), form.get(19)), (None, None));
        assert_eq!(form.get(999), Some(ByteSet::of(0x82)));

        // a field that follows from the size, and a class to the end
        let riff = parse_form("0: 'RIFF' {size-8:le32} 'WAVE'", 0x0001_0008).unwrap().unwrap();
        assert_eq!(riff, Form::bytes(0, b"RIFF\x00\x00\x01\x00WAVE"));
        let text = parse_form("0: '#!/bin/sh' 0A text*", 30).unwrap().unwrap();
        assert_eq!((text.stretches(), text.get(10), text.get(29), text.get(30)), (vec![(0, 10)], Some(ByteSet::text()), Some(ByteSet::text()), None));
        assert_eq!(parse_form("0: text*", 100_000).unwrap().unwrap().span(), Some((0, 256)));
        let wide = parse_form("0: FF FE utf16*3", 100).unwrap().unwrap();
        assert_eq!((wide.get(2), wide.get(3), wide.get(7), wide.get(8)), (Some(ByteSet::text()), Some(ByteSet::of(0)), Some(ByteSet::of(0)), None));
        assert_eq!(parse_form("0: {size:be16} [30-39 41]*2", 0x1234).unwrap().unwrap().get(3), Some(ByteSet::from_values((b'0'..=b'9').chain([b'A']))));
    }

    #[test]
    fn a_file_too_short_for_a_form_has_none_and_a_form_that_is_miswritten_is_an_error() {
        assert_eq!(parse_form("0: 'RIFF' {size-8:le32} 'WAVE'", 11).unwrap(), None);
        assert_eq!(parse_form("0: 01; -12: 00*12", 8).unwrap(), None);
        assert_eq!(parse_form("0: 'BM' {size:be16}", 70_000).unwrap(), None);
        for wrong in ["89 50", "x: 89", "0: 8", "0: 'open", "0: [30-", "0: [39-30]", "0: []", "0: {size}", "0: {size*2:le32}", "0: {size:le24}", "0: zz", "0: 01; 0: 02"] {
            assert!(parse_form(wrong, 1000).is_err(), "{wrong:?}");
        }
    }

    #[test]
    fn a_pattern_is_held_against_the_whole_name_and_its_last_part() {
        assert!(fits("*.png", "a/b/photo.png") && fits("*.png", ".png") && !fits("*.png", "photo.png.txt"));
        assert!(fits("mimetype", "mimetype") && !fits("mimetype", "mimetypes"));
        assert!(fits("__macosx/._*", "__macosx/._photo.jpg") && fits("*a*b*", "xxaxxbxx") && !fits("*a*b*", "xxbxxaxx"));
        assert!(fits("", "") && !fits("", "a") && fits("*", "anything"));
        assert!(fits("*.so.*", "libz.so.1") && !fits("*.so.*", "libz.so") && fits("a*a", "aa") && !fits("a*a", "a"));
    }

    #[test]
    fn a_name_is_looked_up_to_the_row_that_a_walk_over_every_pattern_finds() {
        // the first row with a pattern that fits the name or its last part, pattern by pattern
        let walked = |name: &str| {
            let name = name.to_ascii_lowercase();
            let last = name.rsplit('/').next().unwrap_or(&name).to_owned();
            rows().iter().find(|row| row.names.iter().any(|pattern| fits(pattern, &name) || fits(pattern, &last))).map(|row| row.name.as_str())
        };
        // a name for every pattern of the table, as it is, in a folder, in capitals, and with
        // something behind it that makes most of them fit no longer
        let mut names: Vec<String> = Vec::new();
        for pattern in rows().iter().flat_map(|row| &row.names) {
            let name = pattern.replace('*', "x");
            names.extend([name.clone(), format!("some/folder/{name}"), name.to_ascii_uppercase(), format!("{name}.bak"), format!("{name}/inside"), format!("x{name}")]);
        }
        // names that two rows could claim, names of no type, and names that are not ASCII
        names.extend(["a.tar.gz", "photo.png.txt", "dir.png/readme", "LICENSE", "license.txt", "libz.so.1", "LIB.SO.12.3", "noext", "", ".", "/", "a/", "\u{fc}n\u{ef}.PNG", "\u{65e5}\u{672c}.zip", "x.\u{fc}"].map(str::to_owned));
        assert!(names.len() > 1000);
        for name in &names {
            assert_eq!(by_entry(name.as_bytes()).map(|row| row.name.as_str()), walked(name), "{name:?}");
        }
        // most patterns are an ending, and those that are not are few enough to walk over
        assert!(PATTERNS.endings.len() > 150 && PATTERNS.others.len() < 20 && PATTERNS.longest < 16, "{} endings, {} others", PATTERNS.endings.len(), PATTERNS.others.len());
        // bytes that are no text are a name like another
        assert_eq!(by_entry(b"\xff\xfe.png").map(|row| row.name.as_str()), by_entry(b"a.png").map(|row| row.name.as_str()));
    }

    #[test]
    fn the_table_parses_and_every_row_can_be_found() {
        let rows: Vec<Row> = serde_json::from_str(TABLE).unwrap();
        assert!(rows.len() >= 30, "{} rows", rows.len());
        let mut names = BTreeSet::new();
        for row in &rows {
            assert!(names.insert(row.name.as_str()), "the type {} is in the table twice", row.name);
            assert!(!row.what.is_empty() && !row.names.is_empty() && !row.forms.is_empty(), "{}", row.name);
            for form in &row.forms {
                // a large file and a small one: a form is for one of them at least, and odd
                // sizes, so that no field of the size is a round number
                let large = parse_form(form, 1_234_567).unwrap_or_else(|fault| panic!("{}: {fault}", row.name));
                let small = parse_form(form, 40_001).unwrap_or_else(|fault| panic!("{}: {fault}", row.name));
                assert!(large.is_some() || small.is_some(), "{}: {form}", row.name);
            }
            for kin in &row.kin {
                assert!(rows.iter().any(|other| &other.name == kin), "{}: no type {kin}", row.name);
            }
            assert!(std::ptr::eq(by_type(&row.name).unwrap(), by_type(&row.name.to_ascii_uppercase()).unwrap()));
        }
        assert_eq!(by_entry(b"photos/IMG_0412.PNG").map(|row| row.name.as_str()), Some("png"));
        assert_eq!(by_entry(b"book.epub").map(|row| row.name.as_str()), Some("epub"));
        assert_eq!(by_entry(b"no extension at all").map(|row| row.name.as_str()), None);
        assert!(by_type("no-such-type").is_none());
    }

    /// One real file: its type, who wrote it, its size, and its first and last bytes.
    #[derive(Debug, Deserialize)]
    struct Sample {
        #[serde(rename = "type")]
        kind: String,
        writer: String,
        size: u64,
        head: String,
        tail: String,
    }

    impl Sample {
        /// The byte at a position of the file, when the sample holds it.
        fn at(&self, head: &[u8], tail: &[u8], position: u64) -> Option<u8> {
            let index = usize::try_from(position).ok()?;
            if let Some(&byte) = head.get(index) {
                return Some(byte);
            }
            let from_end = usize::try_from(self.size.checked_sub(position)?).ok()?;
            tail.len().checked_sub(from_end).and_then(|index| tail.get(index)).copied()
        }

        /// Whether the file has a form: every byte the form says something of is in its set.
        /// A byte the sample does not hold decides nothing.
        fn has(&self, form: &Form) -> bool {
            let (head, tail) = (hex::decode(&self.head).unwrap(), hex::decode(&self.tail).unwrap());
            form.pieces().iter().all(|piece| (0..piece.cells.len()).all(|index| u64::try_from(piece.at).ok().and_then(|at| self.at(&head, &tail, at + index)).is_none_or(|byte| piece.cells.get(index).is_some_and(|set| set.contains(byte)))))
        }
    }

    /// Every row is borne out by real files of its type from more than one writer, and holds
    /// for no file of a type that is not its kin (section 6.3 of the design, the first rule of
    /// the table). The files are in `tests/types/samples.json` by their first and last bytes,
    /// with where each is from; `tests/types/README.md` says how they were gathered.
    #[test]
    fn every_row_holds_for_real_files_of_its_type_and_for_no_other() {
        let samples: Vec<Sample> = serde_json::from_str(&std::fs::read_to_string("tests/types/samples.json").unwrap()).unwrap();
        let mut by_kind: BTreeMap<&str, Vec<&Sample>> = BTreeMap::new();
        for sample in &samples {
            by_kind.entry(sample.kind.as_str()).or_default().push(sample);
        }

        let mut faults = Vec::new();
        for row in rows() {
            let own = by_kind.get(row.name.as_str()).cloned().unwrap_or_default();
            let fitting: Vec<&&Sample> = own.iter().filter(|sample| row.forms(sample.size).iter().any(|form| !form.is_empty() && sample.has(form))).collect();
            let writers: BTreeSet<&str> = fitting.iter().map(|sample| sample.writer.as_str()).collect();
            if writers.len() < 2 {
                faults.push(format!("{}: holds for {} of {} files, from {} writers: a row needs files of two", row.name, fitting.len(), own.len(), writers.len()));
            }
            // a row that knows six bytes in a row or more claims something: no file of another type
            // may have it. A file is taken to be of its type when the row of that type holds for
            // it: the name alone does not make a certificate of a file that ends in `.key`
            for (kind, others) in &by_kind {
                let Some(other) = by_type(kind) else { continue };
                if *kind == row.name || row.kin.iter().any(|kin| kin == kind) || other.kin.contains(&row.name) {
                    continue;
                }
                for sample in others.iter().filter(|sample| other.forms(sample.size).iter().any(|form| !form.is_empty() && sample.has(form))) {
                    if row.forms(sample.size).iter().any(|form| form.stretches().iter().any(|&(_, len)| len >= 6) && sample.has(form)) {
                        faults.push(format!("{}: holds for a file of type {kind} written by {}", row.name, sample.writer));
                    }
                }
            }
        }
        assert!(faults.is_empty(), "{} rows of the table are not borne out:\n{}", faults.len(), faults.join("\n"));
    }
}
