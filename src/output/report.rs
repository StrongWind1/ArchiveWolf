//! The analysis of an archive as `info` prints it, a hash line as `hash --json` prints it, and
//! the notes `hash` writes to standard error.
//!
//! The text of `info` is for people and may change. The JSON object is the interface: it is the
//! [`Analysis`] as it serializes, and nothing here adds to it or takes from it.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::Serialize;

use super::sanitize;
use crate::analysis::Analysis;
use crate::analysis::Check;
use crate::analysis::CheckKind;
use crate::analysis::Cipher;
use crate::analysis::Counts;
use crate::analysis::Coverage;
use crate::analysis::Entries;
use crate::analysis::Entry;
use crate::analysis::EntryKind;
use crate::analysis::Finding;
use crate::analysis::Format;
use crate::analysis::Generation;
use crate::analysis::Headers;
use crate::analysis::Missing;
use crate::analysis::NoLine;
use crate::analysis::Parameters;
use crate::analysis::Scheme;
use crate::analysis::SchemeUse;
use crate::analysis::Split;
use crate::analysis::Volume;
use crate::line::Line;
use crate::line::Proves;
use crate::line::Tag;

/// How many entries a finding names before it says how many more there are.
const NAMES_SHOWN: usize = 3;

/// The analysis as one line of JSON.
#[must_use]
pub(crate) fn info_json(analysis: &Analysis) -> String {
    serde_json::to_string(analysis).unwrap_or_default()
}

/// One hash line as `hash --json` writes it.
#[derive(Debug, Serialize)]
struct LineRecord<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry: Option<usize>,
    scheme: Scheme,
    mode: u32,
    tag: Tag,
    proves: Proves,
    line: &'a str,
}

/// One hash line of the archive at `path` as one line of JSON: where it comes from, what reads
/// it, what it proves, and the line. `entry` is the place of its entry in the `entry_list` of
/// `info --json`, and is absent for a line built from the encrypted headers.
#[must_use]
pub(crate) fn line_json(path: &str, line: &Line) -> String {
    serde_json::to_string(&LineRecord { path, entry: line.entry, scheme: Scheme::of_line(line.tag), mode: line.mode, tag: line.tag, proves: line.proves, line: &line.text }).unwrap_or_default()
}

/// What an entry is called in text: its name, or for a 7-Zip folder its number and its first
/// file.
fn entry_label(analysis: &Analysis, index: usize) -> String {
    match analysis.entry_list.get(index) {
        Some(Entry { name: Some(name), .. }) => name.clone(),
        Some(Entry { kind: EntryKind::Folder, files, .. }) => files.first().map_or_else(|| format!("folder {index}"), |first| format!("folder {index} ({first})")),
        _ => format!("entry {index}"),
    }
}

/// Where a line comes from and what it is: its tag, its mode, what it proves and its entry.
/// The row of `info` for the line, and with the path in front the note `hash -v` writes for it.
#[must_use]
pub(crate) fn line_origin(analysis: &Analysis, tag: Tag, mode: u32, proves: Proves, entry: Option<usize>) -> String {
    let from = entry.map_or_else(|| "the headers".to_owned(), |index| entry_label(analysis, index));
    format!("{tag}, hashcat mode {mode}, {proves}, from {from}")
}

/// The note `hash` writes for a line that proves less than a checksum over the whole entry:
/// every weak line, and every line a format has a remark on. It ends in the advice to confirm
/// what such a line finds. `None` for a line without either.
#[must_use]
pub(crate) fn line_note(analysis: &Analysis, line: &Line) -> Option<String> {
    const CONFIRM: &str = "Confirm a password found with it by opening the archive.";
    let path = &analysis.path;
    let subject = line.entry.map_or_else(|| "the headers".to_owned(), |index| entry_label(analysis, index));
    match (line.proves, line.note) {
        (Proves::Weak { bits }, Some(note)) => Some(format!("{path}: weak line: {subject}: {note}: {bits} bits. {CONFIRM}")),
        (Proves::Weak { bits }, None) => Some(format!("{path}: weak line: {subject}: the line tests {bits} bits. {CONFIRM}")),
        (Proves::Exact | Proves::Structural, Some(note)) => Some(format!("{path}: note: {subject}: {note}. {CONFIRM}")),
        (Proves::Exact | Proves::Structural, None) => None,
    }
}

/// Who gets no line, and why, with the entries that have the same case of it together: a
/// scheme by its ID, entries by the names of the first few and the number of the others.
/// `wanted` picks the missing lines that are shown.
fn missing_groups(analysis: &Analysis, wanted: impl Fn(&Missing) -> bool) -> Vec<(String, &Missing)> {
    let mut groups: Vec<(&Missing, Vec<usize>)> = Vec::new();
    let mut places: HashMap<(Scheme, &NoLine), usize> = HashMap::new();
    for missing in analysis.no_line.iter().filter(|missing| wanted(missing)) {
        let Some(index) = missing.entry else {
            groups.push((missing, Vec::new()));
            continue;
        };
        let place = *places.entry((missing.scheme, &missing.why)).or_insert_with(|| {
            groups.push((missing, Vec::new()));
            groups.len() - 1
        });
        if let Some((_, entries)) = groups.get_mut(place) {
            entries.push(index);
        }
    }
    groups.into_iter().map(|(missing, entries)| (if entries.is_empty() { missing.scheme.to_string() } else { names_of(analysis, &entries) }, missing)).collect()
}

/// The notes `hash` writes for what gets no line: one for each scheme that gets none, and one
/// for each case among the entries, with the entries it holds for.
///
/// Without `all`, an entry is noted only when its scheme was left without a line in this
/// archive: where the scheme has its line, that an entry beside it cannot give one is in the
/// analysis and is no news to a run that asked for one line.
#[must_use]
pub(crate) fn no_line_notes(analysis: &Analysis, all: bool) -> Vec<String> {
    let served = |scheme: Scheme| analysis.lines.iter().any(|line| Scheme::of_line(line.tag) == scheme);
    missing_groups(analysis, |missing| all || !served(missing.scheme)).into_iter().map(|(subject, missing)| format!("{}: no line: {subject}: {} [{}]", analysis.path, missing.why, missing.reason())).collect()
}

/// `1 entry`, `3 entries`: the entries of a 7-Zip archive are folders.
fn counted(format: Format, count: usize) -> String {
    let unit = match (format, count) {
        (Format::SevenZ, 1) => "folder",
        (Format::SevenZ, _) => "folders",
        (_, 1) => "entry",
        _ => "entries",
    };
    format!("{count} {unit}")
}

/// The generation of the container as people write it.
const fn generation_label(generation: Generation) -> &'static str {
    match generation {
        Generation::Zip => "ZIP",
        Generation::Zip64 => "ZIP64",
        Generation::Rar1 => "RAR 1.4",
        Generation::Rar4 => "RAR 1.5 to 4",
        Generation::Rar5 => "RAR 5",
        Generation::SevenZ => "7z",
    }
}

/// A round count: `2^15` for a power of two, the number otherwise.
fn rounds_text(rounds: u64) -> String {
    if rounds > 1 && rounds.is_power_of_two() { format!("2^{}", rounds.trailing_zeros()) } else { rounds.to_string() }
}

/// One check as people write it.
fn check_text(check: &Check) -> String {
    let keyed = if check.keyed { "keyed " } else { "" };
    match (check.kind, check.bits) {
        (CheckKind::CheckByte, Some(bits)) if bits > 8 => format!("check bytes {bits} bits"),
        (CheckKind::Crc32 | CheckKind::Blake2sp | CheckKind::Structure, _) | (_, None) => format!("{keyed}{}", check.kind.label()),
        (_, Some(bits)) => format!("{keyed}{} {bits} bits", check.kind.label()),
    }
}

/// The parameters of a scheme as people write them, separated by commas.
fn parameters_text(parameters: &Parameters) -> String {
    let mut shown = Vec::new();
    if let Some(ae) = parameters.ae {
        shown.push(format!("AE-{ae}"));
    }
    match (parameters.cipher, parameters.key_bits) {
        (Some(Cipher::Aes), Some(bits)) => shown.push(format!("AES-{bits}")),
        // a cipher with one key size is named by its name
        (Some(cipher @ (Cipher::ZipCrypto | Cipher::Rar13 | Cipher::Rar15 | Cipher::Rar20)), _) | (Some(cipher), None) => shown.push(cipher.label().to_owned()),
        (Some(cipher), Some(bits)) => shown.push(format!("{} {bits} bits", cipher.label())),
        (None, _) => {},
    }
    if let Some(identifier) = parameters.identifier {
        shown.push(format!("identifier 0x{identifier:04x}"));
    }
    if let Some(kdf) = parameters.kdf {
        shown.push(kdf.rounds.map_or_else(|| kdf.name.label().to_owned(), |rounds| format!("{} {}", kdf.name.label(), rounds_text(rounds))));
    }
    shown.extend(parameters.check.iter().map(check_text));
    shown.join(", ")
}

/// One row of `schemes`: the ID of the variant, the parameters, and how many entries in how
/// many key groups.
fn scheme_text(format: Format, row: &SchemeUse) -> String {
    let parameters = parameters_text(&row.parameters);
    let mut text = if parameters.is_empty() { row.variant.clone() } else { format!("{}  {parameters}", row.variant) };
    if let Some(entries) = row.entries {
        let groups = row.key_groups.map_or_else(String::new, |groups| format!(", {groups} key group{}", if groups == 1 { "" } else { "s" }));
        let _ = write!(text, " ({}{groups})", counted(format, entries));
    }
    text
}

/// The entries by state and the coverage, on one line.
fn entries_text(format: Format, counts: &Counts, coverage: Coverage) -> String {
    if counts.total == 0 {
        return "none".to_owned();
    }
    let mut text = if counts.encrypted == 0 { format!("none of {} encrypted", counted(format, counts.total)) } else { format!("{} of {} encrypted", counts.encrypted, counted(format, counts.total)) };
    if counts.pseudo > 0 {
        let _ = write!(text, ", {} pseudo-encrypted", counts.pseudo);
    }
    if counts.undetermined > 0 {
        let _ = write!(text, ", {} not determined", counts.undetermined);
    }
    let coverage = match coverage {
        Coverage::None => "none",
        Coverage::Some => "some",
        Coverage::All => "all",
        Coverage::Unknown => "unknown",
    };
    format!("{text}; coverage {coverage}")
}

/// Entries as they are named in front of what is said of them: the first few by name, then
/// how many more.
fn names_of(analysis: &Analysis, entries: &[usize]) -> String {
    let mut names: Vec<String> = entries.iter().take(NAMES_SHOWN).map(|&index| entry_label(analysis, index)).collect();
    if entries.len() > NAMES_SHOWN {
        names.push(format!("and {} more", entries.len() - NAMES_SHOWN));
    }
    names.join(", ")
}

/// A finding with the entries it concerns in front.
fn finding_text(analysis: &Analysis, finding: &Finding) -> String {
    if finding.entries.is_empty() {
        return finding.found.to_string();
    }
    format!("{}: {}", names_of(analysis, &finding.entries), finding.found)
}

/// The first line of a block: the path, the container generation, and what else is known of
/// the archive as a whole.
fn head_text(analysis: &Analysis) -> String {
    let mut facts = vec![generation_label(analysis.generation).to_owned()];
    match analysis.volume {
        Some(Volume::First) => facts.push("first volume of a set".to_owned()),
        Some(Volume::Later) => facts.push("later volume of a set".to_owned()),
        Some(Volume::Incomplete) => facts.push("incomplete".to_owned()),
        Some(Volume::Single) | None => {},
    }
    if let Entries::Counts(counts) = analysis.entries {
        facts.push(counted(analysis.format, counts.total));
    }
    if analysis.offset > 0 {
        facts.push(format!("at offset {}", analysis.offset));
    }
    format!("{}   {}", analysis.path, facts.join(", "))
}

/// Add rows under one label: the label in front of the first, the others aligned below it.
fn push_rows(out: &mut Vec<String>, label: &str, rows: impl IntoIterator<Item = String>) {
    for (number, row) in rows.into_iter().enumerate() {
        out.push(format!("  {:<10}{row}", if number == 0 { label } else { "" }));
    }
}

/// The table of `--entries`: one row for each entry, the name last because it is the one
/// column whose width an archive decides.
fn entry_rows(analysis: &Analysis) -> Vec<String> {
    /// The columns whose cells stand to the right: the numbers.
    const RIGHT: [bool; 12] = [true, false, false, false, true, false, true, true, false, false, false, false];

    let dash = || "-".to_owned();
    let number = |value: Option<u64>| value.map_or_else(dash, |value| value.to_string());
    let mut table: Vec<[String; 12]> = vec![["#", "kind", "state", "variant", "group", "method", "packed", "size", "split", "line", "known", "name"].map(str::to_owned)];

    for (index, entry) in analysis.entry_list.iter().enumerate() {
        let kind = match entry.kind {
            EntryKind::File => "file",
            EntryKind::Directory => "directory",
            EntryKind::Service => "service",
            EntryKind::Folder => "folder",
        };
        let method = entry.method.as_ref().map_or_else(dash, |method| match (&method.name, method.number) {
            (Some(name), _) => name.clone(),
            (None, Some(number)) => number.to_string(),
            (None, None) => dash(),
        });
        let split = match entry.split {
            Some(Split::No) => "no",
            Some(Split::Before) => "before",
            Some(Split::After) => "after",
            Some(Split::Both) => "both",
            None => "-",
        };
        let line = entry.line.map_or_else(dash, |line| match line.0 {
            Ok(line) => format!("{} {}", line.tag, line.mode),
            Err(reason) => reason.to_string(),
        });
        let name = match (&entry.name, entry.files.as_slice()) {
            (Some(name), _) => name.clone(),
            (None, []) => dash(),
            (None, files) => {
                let mut shown: Vec<&str> = files.iter().take(NAMES_SHOWN).map(String::as_str).collect();
                let more = format!("and {} more", files.len().saturating_sub(NAMES_SHOWN));
                if files.len() > NAMES_SHOWN {
                    shown.push(&more);
                }
                shown.join(", ")
            },
        };
        table.push([
            index.to_string(),
            kind.to_owned(),
            entry.state.as_str().to_owned(),
            entry.variant().unwrap_or_else(dash),
            entry.key_group.map_or_else(dash, |group| group.to_string()),
            method,
            number(entry.packed),
            number(entry.size),
            split.to_owned(),
            line,
            // the bytes of an encrypted stream that the archive gives away: how many in a row, and how sure
            entry.known.map_or_else(dash, |known| format!("{} {}", known.run, known.certainty)),
            // sanitized here as well as with its row, so that the widths count what is shown
            sanitize(&name).into_owned(),
        ]);
    }

    let mut widths = [0_usize; 12];
    for row in &table {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    // numbers stand to the right of their column, the name runs free at the end
    table
        .iter()
        .map(|row| {
            let mut line = String::new();
            for (place, ((cell, &width), &right)) in row.iter().zip(&widths).zip(&RIGHT).enumerate() {
                if place > 0 {
                    line.push_str("  ");
                }
                if place + 1 == row.len() {
                    line.push_str(cell);
                } else if right {
                    let _ = write!(line, "{cell:>width$}");
                } else {
                    let _ = write!(line, "{cell:<width$}");
                }
            }
            line
        })
        .collect()
}

/// The analysis as a block of text: what the archive is, its headers, its entries and
/// coverage, its schemes with their parameters, its findings, and the lines `hash` writes for
/// it with their mode, or the reason there is none. With `entries`, a row for each entry.
///
/// Every line is passed through [`sanitize`], so nothing from the archive starts a line of its
/// own or acts on the terminal.
#[must_use]
pub(crate) fn info_text(analysis: &Analysis, entries: bool) -> String {
    let mut rows = vec![head_text(analysis)];

    let headers = match analysis.headers {
        Headers::Readable => "readable",
        Headers::Encrypted => "encrypted: names and sizes hidden",
    };
    push_rows(&mut rows, "headers", [headers.to_owned()]);
    // the family of the writer, when the headers name one
    push_rows(&mut rows, "writer", analysis.writer.filter(|writer| *writer != "unknown").map(str::to_owned));

    if let Entries::Counts(counts) = &analysis.entries {
        push_rows(&mut rows, "entries", [entries_text(analysis.format, counts, analysis.coverage)]);
    }

    let schemes = analysis.schemes.iter().map(|row| scheme_text(analysis.format, row));
    if analysis.mixed {
        push_rows(&mut rows, "schemes", std::iter::once("mixed".to_owned()).chain(schemes));
    } else {
        push_rows(&mut rows, if analysis.schemes.len() > 1 { "schemes" } else { "scheme" }, schemes);
    }

    push_rows(&mut rows, "findings", analysis.findings.iter().map(|finding| finding_text(analysis, finding)));

    if analysis.lines.is_empty() {
        let none = if analysis.is_encrypted() {
            "none"
        } else if analysis.coverage == Coverage::Unknown {
            // the listing is not whole: what is not listed may be encrypted
            "none: nothing that is listed is encrypted"
        } else {
            "none: nothing is encrypted"
        };
        push_rows(&mut rows, "line", [none.to_owned()]);
    } else {
        push_rows(&mut rows, "line", analysis.lines.iter().map(|line| line_origin(analysis, line.tag, line.mode, line.proves, line.entry)));
    }

    push_rows(&mut rows, "no line", missing_groups(analysis, |_| true).into_iter().map(|(subject, missing)| format!("{subject}: {}: {}", missing.reason(), missing.why)));

    if let Some(comment) = &analysis.comment {
        push_rows(&mut rows, "comment", [comment.clone()]);
    }

    if entries && !analysis.entry_list.is_empty() {
        push_rows(&mut rows, "list", entry_rows(analysis));
    }
    let mut out = String::new();
    for row in &rows {
        let _ = writeln!(out, "{}", sanitize(row));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::analysis::Analysed;
    use crate::analysis::HeaderState;
    use crate::analysis::Kdf;
    use crate::analysis::KdfName;
    use crate::analysis::Method;
    use crate::analysis::Parts;
    use crate::analysis::Protection;
    use crate::analysis::Salt;
    use crate::analysis::State;
    use crate::line::Note;

    fn zip_crypto() -> Protection {
        Protection { scheme: Scheme::ZipCrypto, parameters: Parameters { cipher: Some(Cipher::ZipCrypto), key_bits: Some(96), check: vec![Check::new(CheckKind::CheckByte, 8), Check::new(CheckKind::Crc32, 32)], ..Parameters::default() }, salt: Salt::None }
    }

    fn zip_winzip() -> Protection {
        Protection {
            scheme: Scheme::ZipWinzip,
            parameters: Parameters { ae: Some(2), cipher: Some(Cipher::Aes), key_bits: Some(256), kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha1, rounds: Some(1000) }), check: vec![Check::new(CheckKind::Verifier, 16), Check::new(CheckKind::Hmac, 80)], ..Parameters::default() },
            salt: Salt::Known(vec![7; 16]),
        }
    }

    fn rar_50() -> Protection {
        Protection {
            scheme: Scheme::Rar50,
            parameters: Parameters { cipher: Some(Cipher::Aes), key_bits: Some(256), kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 15) }), check: vec![Check::new(CheckKind::CheckValue, 64)], ..Parameters::default() },
            salt: Salt::Known(vec![1; 16]),
        }
    }

    fn file(name: &str, state: State, protection: Option<Protection>) -> Entry {
        Entry { name: Some(name.to_owned()), protection, ..Entry::new(EntryKind::File, state) }
    }

    /// The archive of the tests of the analysis, as far as the model holds it.
    fn report_zip() -> Analysed {
        let mut parts = Parts::new(Format::Zip, Generation::Zip);
        parts.entries = vec![
            file("a.txt", State::Encrypted, Some(zip_crypto())),
            file("b.txt", State::Encrypted, Some(zip_crypto())),
            file("notes.txt", State::PseudoEncrypted, None),
            file("c.txt", State::Encrypted, Some(zip_crypto())),
            Entry { method: Some(Method { name: Some("deflate".to_owned()), number: Some(8) }), packed: Some(1000), size: Some(4000), ..file("big.bin", State::Encrypted, Some(zip_winzip())) },
            file("readme.txt", State::Plain, None),
        ];
        parts.lines = vec![Line::new("$zip$1$*1*00/aa*8*cefd04dc*1c*1c*00$/zip$".to_owned(), Some(1), Proves::Exact).unwrap(), Line::new("$zip$2$*3*00*0000*00*8*0*$/zip$".to_owned(), Some(4), Proves::Structural).unwrap()];
        parts.assemble(Path::new("report.zip"))
    }

    #[test]
    fn an_archive_is_one_block() {
        let text = info_text(&report_zip().analysis, false);
        assert_eq!(
            text,
            "\
report.zip   ZIP, 6 entries
  headers   readable
  entries   4 of 6 entries encrypted, 1 pseudo-encrypted; coverage some
  schemes   mixed
            zip-crypto:check8  ZipCrypto, check byte 8 bits, CRC-32 (3 entries, 1 key group)
            zip-winzip:256:ae2  AE-2, AES-256, PBKDF2-HMAC-SHA1 1000, verifier 16 bits, authentication code 80 bits (1 entry, 1 key group)
  findings  notes.txt: marked encrypted and not encrypted: the data as it stands unpacks to the stored CRC-32
            more than one scheme in one archive: zip-crypto, zip-winzip
            notes.txt, readme.txt: 4 entries are encrypted, and 2 that hold data are not
            a.txt, b.txt, c.txt: zip-crypto falls without the password to 12 bytes of known plaintext
  line      $zip$1$, hashcat mode 46100, exact, from b.txt
            $zip$2$, hashcat mode 46200, structural, from big.bin
"
        );
        // no line of an archive is printed, only what names it
        assert!(!text.contains("$/zip$") && !text.contains("cefd04dc"), "{text}");
    }

    #[test]
    fn encrypted_headers_are_a_short_block() {
        let mut parts = Parts::new(Format::Rar, Generation::Rar5);
        parts.headers = HeaderState::Encrypted(rar_50());
        parts.lines = vec![Line::new("$rar$50$*0*00*15*00*00*0*****$/rar$".to_owned(), None, Proves::Exact).unwrap()];
        let analysis = parts.assemble(Path::new("backup.part1.rar")).analysis;
        assert_eq!(
            info_text(&analysis, true),
            "\
backup.part1.rar   RAR 5
  headers   encrypted: names and sizes hidden
  scheme    rar-50:headers:check  AES-256, PBKDF2-HMAC-SHA256 2^15, check value 64 bits
  line      $rar$50$, hashcat mode 46800, exact, from the headers
"
        );
    }

    #[test]
    fn an_archive_without_a_line_says_why_or_that_nothing_is_encrypted() {
        let mut parts = Parts::new(Format::Zip, Generation::Zip64);
        parts.offset = 4096;
        parts.entries = vec![file("a.txt", State::Plain, None)];
        parts.comment = Some("made by hand".to_owned());
        let text = info_text(&parts.assemble(Path::new("open.zip")).analysis, false);
        assert_eq!(text, "open.zip   ZIP64, 1 entry, at offset 4096\n  headers   readable\n  entries   none of 1 entry encrypted; coverage none\n  line      none: nothing is encrypted\n  comment   made by hand\n");

        let mut parts = Parts::new(Format::Rar, Generation::Rar1);
        parts.volume = Some(Volume::First);
        parts.entries = vec![file("OLD.TXT", State::Encrypted, Some(Protection::bare(Scheme::Rar13)))];
        parts.no_line = vec![Missing::for_scheme(Scheme::Rar13, NoLine::KeySearch), Missing::for_entry(Scheme::Rar13, 0, NoLine::Empty)];
        let text = info_text(&parts.assemble(Path::new("old.rar")).analysis, false);
        assert!(text.starts_with("old.rar   RAR 1.4, first volume of a set, 1 entry\n"), "{text}");
        assert!(text.contains("\n  scheme    rar-13 (1 entry, 1 key group)\n"), "{text}");
        assert!(text.contains("\n  line      none\n  no line   rar-13: no-mode: no hashcat mode exists for rar-13: `attack rar-13` searches its key\n            OLD.TXT: no-data: it is empty, so every password would match\n"), "{text}");
        assert!(text.contains("OLD.TXT: rar-13 falls without the password: `attack rar-13` searches its 2^23 keys"), "{text}");
    }

    #[test]
    fn an_archive_without_entries_says_so() {
        let analysis = Parts::new(Format::Zip, Generation::Zip).assemble(Path::new("empty.zip")).analysis;
        for entries in [false, true] {
            assert_eq!(info_text(&analysis, entries), "empty.zip   ZIP, 0 entries\n  headers   readable\n  entries   none\n  line      none: nothing is encrypted\n");
        }
        let parsed: serde_json::Value = serde_json::from_str(&info_json(&analysis)).unwrap();
        assert_eq!(parsed["entry_list"], serde_json::json!([]));
        assert_eq!(parsed["entries"]["total"], 0);
        assert!(parsed.get("comment").is_none());
    }

    #[test]
    fn the_rows_of_the_entries_come_when_they_are_asked_for() {
        let analysis = report_zip().analysis;
        let without = info_text(&analysis, false);
        let with = info_text(&analysis, true);
        assert!(with.starts_with(&without) && !without.contains("  list  "));
        let table: Vec<&str> = with[without.len()..].lines().collect();
        assert_eq!(
            table,
            [
                "  list      #  kind  state             variant             group  method   packed  size  split  line           known  name",
                "            0  file  encrypted         zip-crypto:check8       1  -             -     -  -      -              -      a.txt",
                "            1  file  encrypted         zip-crypto:check8       1  -             -     -  -      $zip$1$ 46100  -      b.txt",
                "            2  file  pseudo-encrypted  -                       -  -             -     -  -      -              -      notes.txt",
                "            3  file  encrypted         zip-crypto:check8       1  -             -     -  -      -              -      c.txt",
                "            4  file  encrypted         zip-winzip:256:ae2      2  deflate    1000  4000  -      $zip$2$ 46200  -      big.bin",
                "            5  file  plain             -                       -  -             -     -  -      -              -      readme.txt",
            ]
        );
    }

    #[test]
    fn the_writer_and_the_known_bytes_of_a_zip_crypto_archive_are_shown() {
        let mut parts = report_zip();
        let mut analysis = parts.analysis.clone();
        analysis.writer = Some("info-zip");
        analysis.entry_list[1].known = Some(crate::analysis::KnownBytes { source: "name", run: 19, certainty: "likely" });
        let text = info_text(&analysis, true);
        assert!(text.contains("  headers   readable\n  writer    info-zip\n"), "{text}");
        assert!(text.contains("  $zip$1$ 46100  19 likely  b.txt\n"), "{text}");
        // a writer the headers do not name is in the object and not in the text
        analysis.writer = Some("unknown");
        assert!(!info_text(&analysis, false).contains("writer"));
        parts.analysis = analysis;
        let object: serde_json::Value = serde_json::from_str(&info_json(&parts.analysis)).unwrap();
        assert_eq!(object["writer"], "unknown");
        assert_eq!(object["entry_list"][1]["known"], serde_json::json!({ "source": "name", "run": 19, "certainty": "likely" }));
        assert!(object["entry_list"][0].get("known").is_none());
    }

    #[test]
    fn a_folder_is_named_by_its_number_and_its_first_file() {
        let mut parts = Parts::new(Format::SevenZ, Generation::SevenZ);
        let folder = |files: &[&str]| Entry { files: files.iter().map(|&name| name.to_owned()).collect(), protection: Some(Protection::bare(Scheme::SevenZAes)), ..Entry::new(EntryKind::Folder, State::Encrypted) };
        parts.entries = vec![folder(&["a.txt", "b.txt", "c.txt", "d.txt", "e.txt"]), folder(&[])];
        parts.lines = vec![Line::new("$7z$*19**cefd04dc*1c**1*00*20*1c**00$/7z$".to_owned(), Some(0), Proves::Structural).unwrap()];
        parts.no_line = vec![Missing::for_entry(Scheme::SevenZAes, 1, NoLine::Empty)];
        let analysis = parts.assemble(Path::new("a.7z")).analysis;

        let text = info_text(&analysis, true);
        assert!(text.starts_with("a.7z   7z, 2 folders\n"), "{text}");
        assert!(text.contains("  entries   2 of 2 folders encrypted; coverage all\n"), "{text}");
        assert!(text.contains("  scheme    7z-aes:data (2 folders, 1 key group)\n"), "{text}");
        assert!(text.contains("  line      $7z$*, hashcat mode 46900, structural, from folder 0 (a.txt)\n"), "{text}");
        assert!(text.contains("  no line   folder 1: no-data: it is empty, so every password would match\n"), "{text}");
        assert!(text.contains("  $7z$* 46900  -      a.txt, b.txt, c.txt, and 2 more\n"), "{text}");
        assert!(text.lines().last().unwrap().ends_with("  no-data      -      -"), "{text}");
    }

    #[test]
    fn parameters_are_written_as_people_write_them() {
        assert_eq!(rounds_text(1 << 15), "2^15");
        assert_eq!(rounds_text(1 << 62), "2^62");
        assert_eq!(rounds_text(1000), "1000");
        assert_eq!(rounds_text(1), "1");
        assert_eq!(check_text(&Check::new(CheckKind::CheckByte, 8)), "check byte 8 bits");
        assert_eq!(check_text(&Check::new(CheckKind::CheckByte, 16)), "check bytes 16 bits");
        assert_eq!(check_text(&Check::new(CheckKind::Crc32, 32).keyed()), "keyed CRC-32");
        assert_eq!(check_text(&Check::new(CheckKind::Blake2sp, 256)), "BLAKE2sp");
        assert_eq!(check_text(&Check::structure()), "structure");

        let pkware = Parameters { cipher: Some(Cipher::Blowfish), key_bits: Some(128), kdf: Some(Kdf { name: KdfName::Sha1, rounds: None }), ..Parameters::default() };
        assert_eq!(parameters_text(&pkware), "Blowfish 128 bits, SHA-1");
        let unnamed = Parameters { identifier: Some(0x6699), key_bits: Some(128), ..Parameters::default() };
        assert_eq!(parameters_text(&unnamed), "identifier 0x6699");
        assert_eq!(parameters_text(&Parameters::default()), "");
    }

    #[test]
    fn a_hash_line_as_json_names_its_archive_its_entry_its_scheme_and_what_it_proves() {
        let line = Line::new("$zip$1$*1*00/aa*8*cefd04dc*1c*1c*00$/zip$".to_owned(), Some(3), Proves::Weak { bits: 8 }).unwrap();
        let json: serde_json::Value = serde_json::from_str(&line_json("dir/a.zip", &line)).unwrap();
        assert_eq!(json, serde_json::json!({ "path": "dir/a.zip", "entry": 3, "scheme": "zip-crypto", "mode": 46100, "tag": "$zip$1$", "proves": "weak", "line": "$zip$1$*1*00/aa*8*cefd04dc*1c*1c*00$/zip$" }));

        // a line from the headers names no entry
        let header = Line::new("$7z$*19**cefd04dc*1c**1*00*20*1c**00$/7z$".to_owned(), None, Proves::Structural).unwrap();
        let json: serde_json::Value = serde_json::from_str(&line_json("a.7z", &header)).unwrap();
        assert_eq!(json, serde_json::json!({ "path": "a.7z", "scheme": "7z-aes", "mode": 46900, "tag": "$7z$*", "proves": "structural", "line": "$7z$*19**cefd04dc*1c**1*00*20*1c**00$/7z$" }));
    }

    #[test]
    fn the_notes_of_hash_name_the_archive_and_the_entry() {
        let Analysed { analysis, lines } = report_zip();
        assert_eq!(line_note(&analysis, &lines[0]), None, "an exact line without a remark has no note");

        let weak = lines[0].clone().with_note(Note::NoDecoder { method: 9, checks: 1 });
        let weak = Line { proves: Proves::Weak { bits: 8 }, ..weak };
        assert_eq!(line_note(&analysis, &weak).unwrap(), "report.zip: weak line: b.txt: hashcat has no decoder for compression method 9, so the line tests only the check bytes of 1 header: 8 bits. Confirm a password found with it by opening the archive.");
        let bare = Line { note: None, ..weak };
        assert_eq!(line_note(&analysis, &bare).unwrap(), "report.zip: weak line: b.txt: the line tests 8 bits. Confirm a password found with it by opening the archive.");
        let remark = lines[0].clone().with_note(Note::StoredAlone);
        let noted = line_note(&analysis, &remark).unwrap();
        assert!(noted.starts_with("report.zip: note: b.txt: it is stored and the line carries no other header") && noted.ends_with("can hit a false match. Confirm a password found with it by opening the archive."), "{noted}");
        let header = Line { entry: None, ..remark };
        assert!(line_note(&analysis, &header).unwrap().starts_with("report.zip: note: the headers: "));
    }

    /// An archive with these entries, these lines and these missing lines.
    fn with_missing(entries: Vec<Entry>, lines: Vec<Line>, no_line: Vec<Missing>) -> Analysis {
        let mut parts = Parts::new(Format::Zip, Generation::Zip);
        (parts.entries, parts.lines, parts.no_line) = (entries, lines, no_line);
        parts.assemble(Path::new("report.zip")).analysis
    }

    #[test]
    fn what_gets_no_line_is_noted_by_case_with_the_entries_it_holds_for() {
        let sealed = |name: &str| file(name, State::Encrypted, Some(zip_winzip()));
        let entries = vec![sealed("a"), sealed("b"), sealed("c"), sealed("d"), sealed("e"), sealed("f")];
        let no_line = vec![
            Missing::for_entry(Scheme::ZipWinzip, 0, NoLine::Empty),
            Missing::for_entry(Scheme::ZipWinzip, 1, NoLine::MethodNumber { method: 1000 }),
            Missing::for_entry(Scheme::ZipWinzip, 2, NoLine::Empty),
            Missing::for_entry(Scheme::ZipWinzip, 3, NoLine::Empty),
            Missing::for_entry(Scheme::ZipWinzip, 4, NoLine::MethodNumber { method: 2000 }),
            Missing::for_entry(Scheme::ZipWinzip, 5, NoLine::Empty),
            Missing::for_scheme(Scheme::Rar13, NoLine::NoMode(Scheme::Rar13)),
        ];

        // no line of the scheme: every case is a note, the entries of a case together
        let bare = with_missing(entries.clone(), Vec::new(), no_line.clone());
        assert_eq!(
            no_line_notes(&bare, false),
            [
                "report.zip: no line: rar-13: no hashcat mode exists for rar-13 [no-mode]",
                "report.zip: no line: a, c, d, and 1 more: it is empty, so every password would match [no-data]",
                "report.zip: no line: b: its compression method 1000 has more digits than its hashcat mode reads [over-limit]",
                "report.zip: no line: e: its compression method 2000 has more digits than its hashcat mode reads [over-limit]",
            ]
        );
        let text = info_text(&bare, false);
        assert!(text.contains("  no line   rar-13: no-mode: no hashcat mode exists for rar-13\n            a, c, d, and 1 more: no-data: it is empty, so every password would match\n            b: over-limit: "), "{text}");

        // the scheme has its line: that entries beside it give none is no note of a run that
        // asked for one line, and is one of a run that asked for all
        let line = Line::new("$zip$2$*3*00*0000*00*8*0*$/zip$".to_owned(), Some(1), Proves::Exact).unwrap();
        let served = with_missing(entries, vec![line], no_line.into_iter().filter(|missing| missing.entry != Some(1)).collect());
        assert_eq!(no_line_notes(&served, false), ["report.zip: no line: rar-13: no hashcat mode exists for rar-13 [no-mode]"]);
        assert_eq!(no_line_notes(&served, true).len(), 3);
        assert!(info_text(&served, false).contains("a, c, d, and 1 more: no-data: "), "the analysis shows every case");
    }

    /// An analysis whose every string carries text that would forge output if printed raw.
    fn hostile() -> Analysed {
        let forged = "a.txt\n\n  line      $7z$*, hashcat mode 46900\n  \x1b[2Kfake\r\n  PASSWORD: hunter2";
        let mut parts = Parts::new(Format::Zip, Generation::Zip);
        parts.entries = vec![file(forged, State::PseudoEncrypted, None), file(&format!("{forged}.locked"), State::Encrypted, Some(zip_crypto()))];
        parts.lines = vec![Line::new("$zip$1$*1*00/aa*8*cefd04dc*1c*1c*00$/zip$".to_owned(), Some(1), Proves::Exact).unwrap().with_note(Note::StoredAlone)];
        parts.no_line = vec![Missing::for_entry(Scheme::ZipCrypto, 1, NoLine::Empty)];
        parts.comment = Some(format!("comment\n{forged}"));
        parts.assemble(Path::new(&format!("dir/{forged}.zip")))
    }

    #[test]
    fn text_never_gains_a_line_from_archive_text() {
        let Analysed { analysis, lines } = hostile();
        for entries in [false, true] {
            let text = info_text(&analysis, entries);
            // head, headers, entries, scheme, three findings, line, no line, comment; and with the entries a head and two rows
            assert_eq!(text.lines().count(), if entries { 13 } else { 10 }, "{text}");
            assert!(!text.chars().any(|ch| ch.is_control() && ch != '\n'), "a control character reached the output: {text:?}");
            for line in text.lines().map(str::trim_start) {
                assert!(!line.starts_with("PASSWORD:") && !line.starts_with("fake") && !line.starts_with("line      $7z$"), "forged line: {line}");
            }
            assert_eq!(text.lines().filter(|line| line.starts_with("  line ")).count(), 1, "{text}");
            assert!(text.contains("\\x1b[2Kfake"), "the escape character is shown, not sent: {text}");
        }
        // the notes are sanitized by whoever prints them, as one line each
        let note = line_note(&analysis, &lines[0]).unwrap();
        assert_eq!(sanitize(&note).lines().count(), 1);
        assert!(no_line_notes(&analysis, true).iter().all(|note| sanitize(note).lines().count() == 1));
    }

    #[test]
    fn json_keeps_archive_text_byte_for_byte() {
        let Analysed { analysis, lines } = hostile();
        let json = info_json(&analysis);
        assert_eq!(json.lines().count(), 1, "one archive is one line of JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["path"], analysis.path.as_str());
        assert_eq!(parsed["entry_list"][0]["name"], analysis.entry_list[0].name.as_deref().unwrap());
        assert_eq!(parsed["comment"], analysis.comment.as_deref().unwrap());
        assert_eq!(parsed["lines"], serde_json::json!([{ "mode": 46100, "tag": "$zip$1$", "entry": 1, "proves": "exact" }]), "mode, tag, entry and class, and no line");
        assert!(!json.contains("$/zip$"), "{json}");

        let record = line_json(&analysis.path, &lines[0]);
        assert_eq!(record.lines().count(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&record).unwrap();
        assert_eq!((&parsed["path"], &parsed["line"]), (&serde_json::Value::from(analysis.path.as_str()), &serde_json::Value::from(lines[0].text.as_str())));
    }
}
