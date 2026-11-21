//! What the proofs of the hash lines share: a run of
//! `archivewolf hash`, and the recorded lines under `tests/golden/`.
//!
//! Each of the three test files that include this module uses every item of it. An item one of
//! them left alone would be dead code in that file's crate.

use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

// A test crate is linked against every dependency of the package, and the lint
// `unused_crate_dependencies` wants each of them named. The proofs run the binary and other
// programs, and need none of these.
use anyhow as _;
use archivewolf as _;
use archivewolf_zip_crypto as _;
use assert_cmd as _;
use clap as _;
use crc32fast as _;
use flate2 as _;
use hex as _;
use lzma_rust2 as _;
use predicates as _;
use proptest as _;
use rayon as _;
use serde as _;
use serde_json::Value;
use sha2 as _;
use tempfile as _;
use tracing as _;
use tracing_subscriber as _;
use walkdir as _;

/// Where the fixtures are, seen from the root of the package, which is where cargo runs a test.
pub(crate) const FIXTURES: &str = "tests/fixtures";

/// Where the recorded lines and their manifest are.
pub(crate) const GOLDEN: &str = "tests/golden";

/// The text fields an entry of the manifest has. With `mode`, a number, they are all it has.
const TEXT_FIELDS: [&str; 6] = ["case", "fixture", "tag", "why", "crack_record", "crack"];

/// What the manifest says of all its lines together: when they were recorded, and what backs them.
const EVIDENCE_FIELDS: [&str; 3] = ["recorded", "extractors", "cracks"];

/// One recorded line: an entry of `tests/golden/manifest.json`, with its line in a file beside it.
#[derive(Debug)]
pub(crate) struct Recorded {
    fields: serde_json::Map<String, Value>,
}

impl Recorded {
    /// A text field of the entry. `recorded_lines` hands out no entry that lacks one of them.
    pub(crate) fn text(&self, field: &str) -> &str {
        self.fields.get(field).and_then(Value::as_str).unwrap_or_default()
    }

    /// The hashcat mode that reads the line.
    pub(crate) fn mode(&self) -> u32 {
        self.fields.get("mode").and_then(Value::as_u64).and_then(|mode| u32::try_from(mode).ok()).unwrap_or_default()
    }

    /// The archive the line was made from.
    pub(crate) fn fixture(&self) -> PathBuf {
        Path::new(FIXTURES).join(self.text("fixture"))
    }

    /// The recorded line, without the newline that ends its file. A file that holds anything but
    /// one line and its newline is an error.
    pub(crate) fn line(&self) -> Result<String, String> {
        let path = Path::new(GOLDEN).join(format!("{}.line", self.text("case")));
        let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        match text.strip_suffix('\n') {
            Some(line) if !line.is_empty() && !line.contains(['\n', '\r']) => Ok(line.to_owned()),
            _ => Err(format!("{}: not one line with a newline behind it", path.display())),
        }
    }
}

/// The entries of `tests/golden/manifest.json`, in its order.
///
/// A manifest that cannot be read, has no entry, has an entry with a missing, empty, mistyped or
/// unknown field, names a case twice, or lacks the account of its evidence is an error.
pub(crate) fn recorded_lines() -> Result<Vec<Recorded>, String> {
    let path = Path::new(GOLDEN).join("manifest.json");
    let fault = |what: String| format!("{}: {what}", path.display());
    let text = std::fs::read_to_string(&path).map_err(|error| fault(error.to_string()))?;
    let manifest: Value = serde_json::from_str(&text).map_err(|error| fault(error.to_string()))?;

    for field in EVIDENCE_FIELDS {
        if manifest.get("evidence").and_then(|evidence| evidence.get(field)).and_then(Value::as_str).is_none_or(str::is_empty) {
            return Err(fault(format!("no text in evidence.{field}")));
        }
    }

    let entries = manifest.get("lines").and_then(Value::as_array).ok_or_else(|| fault("no list named lines".to_owned()))?;
    let mut cases = BTreeSet::new();
    let mut recorded = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let fields = entry.as_object().ok_or_else(|| fault(format!("entry {index} is not an object")))?;
        for field in TEXT_FIELDS {
            if fields.get(field).and_then(Value::as_str).is_none_or(str::is_empty) {
                return Err(fault(format!("entry {index} has no text in {field}")));
            }
        }
        if fields.get("mode").and_then(Value::as_u64).and_then(|mode| u32::try_from(mode).ok()).is_none() {
            return Err(fault(format!("entry {index} has no number in mode")));
        }
        if let Some(unknown) = fields.keys().find(|name| *name != "mode" && !TEXT_FIELDS.contains(&name.as_str())) {
            return Err(fault(format!("entry {index} has a field this reader does not know: {unknown}")));
        }
        let entry = Recorded { fields: fields.clone() };
        if !cases.insert(entry.text("case").to_owned()) {
            return Err(fault(format!("the case {} is recorded twice", entry.text("case"))));
        }
        recorded.push(entry);
    }

    if recorded.is_empty() {
        return Err(fault("no line is recorded".to_owned()));
    }
    Ok(recorded)
}

/// A text cut down to what a person reads: all of it up to 120 characters, the start and the end
/// of anything longer, with its length.
pub(crate) fn trimmed(text: &str) -> String {
    let length = text.chars().count();
    if length <= 120 {
        return text.to_owned();
    }
    let start: String = text.chars().take(72).collect();
    let end: String = text.chars().skip(length.saturating_sub(24)).collect();
    format!("{start}...{end} ({length} characters)")
}

/// Where the output of two programs for one archive parts, short enough to read.
///
/// Each side is the name of its program and what it wrote, one hash line on a line. The answer
/// counts the lines of both, and for the first lines that differ names the first field that
/// differs (fields are split at `*`, counted from 1) and shows it from just before the place.
pub(crate) fn difference(ours: (&str, &str), theirs: (&str, &str)) -> String {
    let (our_lines, their_lines): (Vec<&str>, Vec<&str>) = (ours.1.lines().collect(), theirs.1.lines().collect());
    let width = ours.0.len().max(theirs.0.len());
    let mut report = vec![format!("    lines: {} {}, {} {}", ours.0, our_lines.len(), theirs.0, their_lines.len())];
    let differing: Vec<usize> = (0..our_lines.len().max(their_lines.len())).filter(|index| our_lines.get(*index) != their_lines.get(*index)).collect();
    for index in differing.iter().take(3) {
        let (place, our_part, their_part) = match (our_lines.get(*index), their_lines.get(*index)) {
            (Some(our_line), Some(their_line)) => {
                let field = our_line.split('*').zip(their_line.split('*')).position(|(a, b)| a != b).unwrap_or_else(|| our_line.split('*').count().min(their_line.split('*').count()));
                let (our_field, their_field) = (our_line.split('*').nth(field).unwrap_or_default(), their_line.split('*').nth(field).unwrap_or_default());
                let at = our_field.chars().zip(their_field.chars()).position(|(a, b)| a != b).unwrap_or_else(|| our_field.chars().count().min(their_field.chars().count()));
                let from = |text: &str| trimmed(&text.chars().skip(at.saturating_sub(16)).collect::<String>());
                (format!("field {}, from character {}", field.saturating_add(1), at.saturating_sub(16).saturating_add(1)), from(our_field), from(their_field))
            },
            (our_line, their_line) => ("the whole line".to_owned(), our_line.map_or_else(|| "nothing".to_owned(), |line| trimmed(line)), their_line.map_or_else(|| "nothing".to_owned(), |line| trimmed(line))),
        };
        report.push(format!("    line {}, {place}:\n      {:width$}  {our_part}\n      {:width$}  {their_part}", index.saturating_add(1), ours.0, theirs.0));
    }
    if differing.len() > 3 {
        report.push(format!("    and {} more lines differ", differing.len().saturating_sub(3)));
    }
    report.join("\n")
}

/// What `archivewolf hash FLAGS ARCHIVE` writes to standard output.
///
/// The run has to end with one of the three statuses a run over archives can end with: all
/// processed, nothing found, or an archive that could not be processed. Anything else, a panic
/// among it, is an error.
pub(crate) fn archivewolf_hash(flags: &[&str], archive: &Path) -> Result<Vec<u8>, String> {
    let output = Command::new(env!("CARGO_BIN_EXE_archivewolf")).arg("hash").args(flags).arg(archive).env_remove("RUST_LOG").output().map_err(|error| format!("archivewolf could not be started: {error}"))?;
    match output.status.code() {
        Some(0..=2) => Ok(output.stdout),
        _ => Err(format!("archivewolf hash {} {}: {}: {}", flags.join(" "), archive.display(), output.status, String::from_utf8_lossy(&output.stderr).trim())),
    }
}
