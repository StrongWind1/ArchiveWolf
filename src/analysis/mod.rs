//! The analysis of an archive: what is encrypted in it and how.
//!
//! [`Analysis`] is the object `info --json` prints, and its field names are those of the
//! specification, section 6. They are an interface: a name here does not change.
//!
//! A format does not build an `Analysis`. It fills [`Parts`] with what it read (the entries
//! with their state and their encryption, the headers, the lines it built and the cases in
//! which it built none) and [`Parts::assemble`] does what is the same for every format: it
//! counts the entries by state, works out coverage, groups entries into key groups and into
//! the rows of `schemes`, marks each entry with its line or its reason, and draws the findings
//! that follow from all that.
//!
//! An entry is named by its place in `entry_list`, counted from 0, wherever something refers
//! to one: the `entry` of a line, the `entries` of a finding, the `entry` of a missing line.
//! A name would not do: the entries of a 7-Zip archive are folders and have none, and two
//! entries of a ZIP archive can share one.

mod finding;
mod reason;
mod scheme;

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::path::Path;

pub use finding::Finding;
pub use finding::Found;
pub use finding::WeakHeader;
pub use reason::Missing;
pub use reason::NoLine;
pub use reason::Reason;
pub use reason::Untestable;
pub use scheme::Access;
pub use scheme::Check;
pub use scheme::CheckKind;
pub use scheme::Cipher;
pub use scheme::Kdf;
pub use scheme::KdfName;
pub use scheme::Parameters;
pub use scheme::Protection;
pub use scheme::Qualifier;
pub use scheme::Salt;
pub use scheme::Scheme;
pub use scheme::Scope;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeMap as _;

use crate::line::Line;
use crate::line::Proves;
use crate::line::Tag;

/// The format of an archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Format {
    /// ZIP.
    #[serde(rename = "zip")]
    Zip,
    /// RAR.
    #[serde(rename = "rar")]
    Rar,
    /// 7-Zip.
    #[serde(rename = "7z")]
    SevenZ,
}

/// The generation of the container of an archive: which layout of headers it has.
///
/// A generation is not a scheme. The names say so: none of them is the ID of a scheme, and the
/// three of RAR are the names WinRAR gives its formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Generation {
    /// ZIP without Zip64 records.
    #[serde(rename = "zip")]
    Zip,
    /// ZIP with Zip64 records.
    #[serde(rename = "zip64")]
    Zip64,
    /// The container of RAR 1.3 and 1.4, which starts with `RE~^`. Its scheme is `rar-13`.
    #[serde(rename = "rar1")]
    Rar1,
    /// The container of RAR 1.5 to 4.x, which WinRAR calls RAR4. Its schemes are `rar-15`,
    /// `rar-20` and `rar-30`.
    #[serde(rename = "rar4")]
    Rar4,
    /// The container of RAR 5 and 7, which WinRAR calls RAR5. Its scheme is `rar-50`.
    #[serde(rename = "rar5")]
    Rar5,
    /// 7-Zip.
    #[serde(rename = "7z")]
    SevenZ,
}

impl Generation {
    /// Every generation.
    pub const ALL: [Self; 6] = [Self::Zip, Self::Zip64, Self::Rar1, Self::Rar4, Self::Rar5, Self::SevenZ];
}

/// Whether the file is one volume of a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Volume {
    /// The whole archive.
    Single,
    /// The first volume of a set.
    First,
    /// A volume of a set that is not the first.
    Later,
    /// The headers point past the end of the file: it is cut short, or it is a first part whose
    /// other parts hold the rest.
    Incomplete,
}

/// Whether the listing of an archive can be read without the password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Headers {
    /// Names and sizes are in the clear.
    Readable,
    /// Names and sizes are encrypted: the entries cannot be told.
    Encrypted,
}

/// How many entries are in each state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize)]
pub struct Counts {
    /// All entries.
    pub total: usize,
    /// Entries in the state `encrypted`.
    pub encrypted: usize,
    /// Entries in the state `plain`.
    pub plain: usize,
    /// Entries in the state `pseudo-encrypted`.
    pub pseudo: usize,
    /// Entries in the state `undetermined`.
    pub undetermined: usize,
}

/// The entries of an archive by state, or `hidden` when its headers are encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Entries {
    /// The counts.
    Counts(Counts),
    /// The headers are encrypted: nothing is known about the entries.
    Hidden,
}

impl Serialize for Entries {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Counts(counts) => counts.serialize(serializer),
            Self::Hidden => serializer.serialize_str("hidden"),
        }
    }
}

/// How much of an archive is encrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    /// No entry.
    None,
    /// Some entries that hold data, and not all of them.
    Some,
    /// Every entry that holds data.
    All,
    /// The headers are encrypted, so the entries cannot be told.
    Unknown,
}

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// A file.
    File,
    /// A directory.
    Directory,
    /// A RAR service record.
    Service,
    /// A 7-Zip folder: one chain of coders over one or more files.
    Folder,
}

/// The state of an entry (specification, section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum State {
    /// The format does not mark the entry as encrypted.
    #[serde(rename = "plain")]
    Plain,
    /// The format marks it, and nothing shows otherwise.
    #[serde(rename = "encrypted")]
    Encrypted,
    /// ZIP only: the entry is marked, and its data as it stands unpacks to the CRC-32 the archive
    /// stores.
    #[serde(rename = "pseudo-encrypted")]
    PseudoEncrypted,
    /// The entry is marked, and what is needed to say more could not be read.
    #[serde(rename = "undetermined")]
    Undetermined,
}

impl State {
    /// Every state.
    pub const ALL: [Self; 4] = [Self::Plain, Self::Encrypted, Self::PseudoEncrypted, Self::Undetermined];

    /// The name of the state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Encrypted => "encrypted",
            Self::PseudoEncrypted => "pseudo-encrypted",
            Self::Undetermined => "undetermined",
        }
    }

    /// Whether the format marks the entry and nothing proves it open: `encrypted` and
    /// `undetermined`. Nothing encrypted is counted as unencrypted.
    #[must_use]
    pub const fn is_locked(self) -> bool {
        matches!(self, Self::Encrypted | Self::Undetermined)
    }
}

/// Whether an entry continues from or into another volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Split {
    /// The whole entry is in this file.
    No,
    /// It continues from the volume before.
    Before,
    /// It continues in the volume after.
    After,
    /// Both.
    Both,
}

impl Split {
    /// From the two flags a volume gives an entry.
    #[must_use]
    pub const fn from_flags(before: bool, after: bool) -> Self {
        match (before, after) {
            (false, false) => Self::No,
            (true, false) => Self::Before,
            (false, true) => Self::After,
            (true, true) => Self::Both,
        }
    }
}

/// How an entry is compressed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Method {
    /// The name of the method, when the tool has one for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The number the format stores for the method, when it stores one number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<u64>,
}

/// A line by what names it: its mode and its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct LineName {
    /// The hashcat mode that loads the line.
    pub mode: u32,
    /// The kind of the line.
    pub tag: Tag,
}

/// What `hash` makes of one entry: the line it writes for it, or the reason it writes none. In
/// the JSON object it is `mode` and `kind`, or `reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryLine(pub Result<LineName, Reason>);

impl Serialize for EntryLine {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Ok(line) => line.serialize(serializer),
            Err(reason) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("reason", reason)?;
                map.end()
            },
        }
    }
}

/// One entry of an archive (specification, section 6.2).
///
/// A format fills what it knows and leaves the rest absent. It leaves `key_group` and `hash`
/// alone: [`Parts::assemble`] sets them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// The name. Absent when the format gives the entry none: a 7-Zip folder has its `files`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// What the entry is.
    pub kind: EntryKind,
    /// The files a 7-Zip folder holds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// The state.
    pub state: State,
    /// How the entry is encrypted: `scheme`, `variant`, `cipher`, `key_bits`, `kdf`, `salt` and
    /// `check` in the JSON object. Absent for an entry that is not encrypted.
    #[serde(flatten)]
    pub protection: Option<Protection>,
    /// Entries with the same number share a derived key. Absent when the salt is not known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_group: Option<u32>,
    /// Compression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<Method>,
    /// Packed size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packed: Option<u64>,
    /// Unpacked size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Whether the entry continues from or into another volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split: Option<Split>,
    /// The line `hash` writes for the entry, or the reason it writes none. Absent for an entry
    /// that was not asked for a line: one that is not encrypted, or one that ranks behind the
    /// entry its scheme takes its line from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<EntryLine>,
    /// `zip-crypto`: the longest run of bytes of the encrypted stream that the archive itself
    /// gives away, when it is eight or more: what the known-plaintext attack starts from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known: Option<KnownBytes>,
}

/// Bytes of an encrypted stream that are known without its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KnownBytes {
    /// Where they come from: `method`, `name` or `directory`.
    pub source: &'static str,
    /// How many are known in a row, the check bytes of the entry among them.
    pub run: u64,
    /// How sure that is: `certain`, `derived`, `likely` or `guess`.
    pub certainty: &'static str,
}

impl Entry {
    /// The ID of the variant the entry is encrypted with. `None` for an entry that is not
    /// encrypted.
    #[must_use]
    pub fn variant(&self) -> Option<String> {
        self.protection.as_ref().map(|protection| protection.variant(Scope::Data))
    }

    /// An entry of which only its kind and its state are known.
    #[must_use]
    pub const fn new(kind: EntryKind, state: State) -> Self {
        Self { name: None, kind, files: Vec::new(), state, protection: None, key_group: None, method: None, packed: None, size: None, split: None, line: None, known: None }
    }

    /// Whether the entry counts for coverage: a file or a folder. A directory and a service
    /// record have no content of the user's to encrypt.
    #[must_use]
    pub const fn holds_data(&self) -> bool {
        matches!(self.kind, EntryKind::File | EntryKind::Folder)
    }
}

/// One row of `schemes`: a scheme as the archive uses it, with its parameters, the number of
/// entries under it and the number of key groups they form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SchemeUse {
    /// The scheme.
    pub scheme: Scheme,
    /// The ID of the variant: the scheme, its scope and its qualifiers.
    pub variant: String,
    /// Its parameters.
    #[serde(flatten)]
    pub parameters: Parameters,
    /// How many entries use it. Absent when the headers are encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<usize>,
    /// How many key groups they form. Absent when the headers are encrypted, and when the salt
    /// of one of the entries is not known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_groups: Option<usize>,
}

/// A line `hash` writes, as `info` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LineRef {
    /// The hashcat mode that loads the line.
    pub mode: u32,
    /// The kind of the line.
    pub tag: Tag,
    /// The entry it is built from. Absent for a line built from the encrypted headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<usize>,
    /// What it lets a cracker confirm a password by.
    pub proves: Proves,
}

/// The analysis of one archive (specification, section 6.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Analysis {
    /// The file.
    pub path: String,
    /// The format.
    pub format: Format,
    /// The generation of the container.
    pub generation: Generation,
    /// Where the archive starts in the file.
    pub offset: u64,
    /// Whether the file is one volume of a set. Absent while the parser does not read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<Volume>,
    /// ZIP: the family of the program that wrote the entries of `zip-crypto`, from the marks it
    /// leaves in the headers, or `unknown`. Absent for an archive that has no such entry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writer: Option<&'static str>,
    /// Header encryption.
    pub headers: Headers,
    /// The entries by state, or `hidden`.
    pub entries: Entries,
    /// How much of the archive is encrypted.
    pub coverage: Coverage,
    /// The schemes present, with their parameters.
    pub schemes: Vec<SchemeUse>,
    /// More than one scheme in the archive.
    pub mixed: bool,
    /// What a user should know beyond scheme and coverage.
    pub findings: Vec<Finding>,
    /// The lines `hash` writes.
    pub lines: Vec<LineRef>,
    /// The schemes and entries that get no line, and why.
    pub no_line: Vec<Missing>,
    /// The archive comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// The entries, in the order of the archive. Empty when the headers are encrypted.
    pub entry_list: Vec<Entry>,
}

impl Analysis {
    /// Whether anything in the archive is encrypted, or may be.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.headers == Headers::Encrypted || self.entry_list.iter().any(|entry| entry.state.is_locked())
    }
}

/// The headers of an archive as a format read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderState {
    /// The listing is in the clear.
    Readable,
    /// The listing is encrypted, and this is how.
    Encrypted(Protection),
}

/// What a format read from one archive. See the module for what becomes of it.
#[derive(Debug, Clone)]
pub struct Parts {
    /// The format.
    pub format: Format,
    /// The generation of the container.
    pub generation: Generation,
    /// Where the archive starts in the file.
    pub offset: u64,
    /// Whether the file is one volume of a set, when the parser can say.
    pub volume: Option<Volume>,
    /// ZIP: the family of the program that wrote the entries of `zip-crypto`.
    pub writer: Option<&'static str>,
    /// Whether the headers are encrypted, and how.
    pub headers: HeaderState,
    /// The archive comment.
    pub comment: Option<String>,
    /// The entries, in the order of the archive. A line and a missing line name an entry by its
    /// place in this list. Empty when the headers are encrypted.
    pub entries: Vec<Entry>,
    /// The lines that were built, in the order `hash` writes them.
    pub lines: Vec<Line>,
    /// The schemes and entries that were asked for a line and gave none.
    pub no_line: Vec<Missing>,
    /// Findings of the format that do not follow from the fields above. The ones that do are
    /// drawn by [`Parts::assemble`] and are not to be put here.
    pub findings: Vec<Finding>,
}

/// An archive as a format hands it back: its analysis, and its lines with their text.
#[derive(Debug, Clone)]
pub struct Analysed {
    /// The analysis. Its `lines` name them.
    pub analysis: Analysis,
    /// The lines.
    pub lines: Vec<Line>,
}

impl Parts {
    /// The parts of an archive of which nothing is known yet but its format: no entries, the
    /// headers readable, at offset 0.
    #[must_use]
    pub const fn new(format: Format, generation: Generation) -> Self {
        Self { format, generation, offset: 0, volume: None, writer: None, headers: HeaderState::Readable, comment: None, entries: Vec::new(), lines: Vec::new(), no_line: Vec::new(), findings: Vec::new() }
    }

    /// Build the analysis of the archive at `path`.
    #[must_use]
    pub fn assemble(self, path: &Path) -> Analysed {
        let Self { format, generation, offset, volume, writer, headers, comment, mut entries, mut lines, mut no_line, findings: found_by_format } = self;

        // a line is written once, however many entries give it
        let mut seen = BTreeSet::new();
        lines.retain(|line| seen.insert(line.text.clone()));

        let header_protection = match headers {
            HeaderState::Readable => None,
            HeaderState::Encrypted(protection) => {
                // nothing is known of the entries, whatever a format lists
                entries.clear();
                Some(protection)
            },
        };

        // what gets no line in the order of the archive: the schemes first, then the entries
        no_line.sort_by_key(|missing| missing.entry.map_or(0, |index| index.saturating_add(1)));

        number_key_groups(&mut entries);
        mark_entries(&mut entries, &lines, &no_line);

        let schemes = scheme_rows(header_protection.as_ref(), &entries);
        let names = scheme_names(&schemes);
        // the listing is not whole when the file ends before the archive does, or its headers
        // stop at bytes that are none
        let whole = volume != Some(Volume::Incomplete) && !found_by_format.iter().any(|finding| matches!(finding.found, Found::HeadersBroken { .. }));
        let coverage = coverage(header_protection.is_some(), whole, &entries);

        let mut findings = drawn_findings(&entries, &names, generation, coverage, volume, &lines, &no_line);
        findings.extend(found_by_format);

        let analysis = Analysis {
            path: path.display().to_string(),
            format,
            generation,
            offset,
            volume,
            writer,
            headers: if header_protection.is_some() { Headers::Encrypted } else { Headers::Readable },
            entries: if header_protection.is_some() { Entries::Hidden } else { Entries::Counts(count(&entries)) },
            coverage,
            mixed: names.len() > 1,
            schemes,
            findings,
            lines: lines.iter().map(|line| LineRef { mode: line.mode, tag: line.tag, entry: line.entry, proves: line.proves }).collect(),
            no_line,
            comment,
            entry_list: entries,
        };
        Analysed { analysis, lines }
    }
}

/// Count the entries by state.
fn count(entries: &[Entry]) -> Counts {
    let of = |state: State| entries.iter().filter(|entry| entry.state == state).count();
    Counts { total: entries.len(), encrypted: of(State::Encrypted), plain: of(State::Plain), pseudo: of(State::PseudoEncrypted), undetermined: of(State::Undetermined) }
}

/// How much of the archive is encrypted.
///
/// An entry that is marked counts, whatever it is. An entry that is not marked counts when it
/// holds data: a plain directory or service record does not make an archive partly encrypted.
/// When the listing is not `whole`, entries that are not listed may be either, so only `some`
/// can be established: that some entries are encrypted and some are not stays true whatever
/// else the archive holds.
fn coverage(headers_encrypted: bool, whole: bool, entries: &[Entry]) -> Coverage {
    if headers_encrypted {
        return Coverage::Unknown;
    }
    let locked = entries.iter().filter(|entry| entry.state.is_locked()).count();
    let open = entries.iter().filter(|entry| entry.holds_data() && !entry.state.is_locked()).count();
    match (locked, open) {
        (1.., 1..) => Coverage::Some,
        _ if !whole => Coverage::Unknown,
        (0, _) => Coverage::None,
        (_, 0) => Coverage::All,
    }
}

/// Give the entries that share a derived key the same number, from 1 on in the order of the
/// archive. An entry whose salt is not known gets none.
fn number_key_groups(entries: &mut [Entry]) {
    let mut numbers = HashMap::new();
    for entry in entries.iter_mut() {
        entry.key_group = None;
        if !entry.state.is_locked() {
            continue;
        }
        let Some(inputs) = entry.protection.as_ref().and_then(Protection::key_inputs) else { continue };
        let inputs = (inputs.0, inputs.1, inputs.2, inputs.3, inputs.4, inputs.5.to_vec());
        let next = u32::try_from(numbers.len()).map_or(u32::MAX, |count| count.saturating_add(1));
        entry.key_group = Some(*numbers.entry(inputs).or_insert(next));
    }
}

/// Mark each entry with the line built from it, or with the reason it gave none.
fn mark_entries(entries: &mut [Entry], lines: &[Line], no_line: &[Missing]) {
    for entry in entries.iter_mut() {
        entry.line = None;
    }
    for line in lines {
        if let Some(entry) = line.entry.and_then(|index| entries.get_mut(index))
            && entry.line.is_none()
        {
            entry.line = Some(EntryLine(Ok(LineName { mode: line.mode, tag: line.tag })));
        }
    }
    for missing in no_line {
        if let Some(entry) = missing.entry.and_then(|index| entries.get_mut(index))
            && entry.line.is_none()
        {
            entry.line = Some(EntryLine(Err(missing.reason())));
        }
    }
}

/// The rows of `schemes`: the scheme of the headers when they are encrypted, then each scheme
/// with each set of parameters the entries use, in the order of the archive.
fn scheme_rows(header: Option<&Protection>, entries: &[Entry]) -> Vec<SchemeUse> {
    if let Some(protection) = header {
        return vec![SchemeUse { scheme: protection.scheme, variant: protection.variant(Scope::Headers), parameters: protection.parameters.clone(), entries: None, key_groups: None }];
    }

    let mut rows: Vec<SchemeUse> = Vec::new();
    // the key groups of each row, and whether an entry of it has none
    let mut groups: Vec<(BTreeSet<u32>, bool)> = Vec::new();
    // a variant can turn on the salt, which is no parameter: an entry of `rar-30` without one
    let mut places: HashMap<(String, &Parameters), usize> = HashMap::new();

    for entry in entries.iter().filter(|entry| entry.state.is_locked()) {
        let Some(protection) = &entry.protection else { continue };
        let variant = protection.variant(Scope::Data);
        let place = *places.entry((variant.clone(), &protection.parameters)).or_insert_with(|| {
            rows.push(SchemeUse { scheme: protection.scheme, variant, parameters: protection.parameters.clone(), entries: Some(0), key_groups: None });
            groups.push((BTreeSet::new(), false));
            rows.len() - 1
        });
        if let (Some(row), Some((numbers, unknown))) = (rows.get_mut(place), groups.get_mut(place)) {
            row.entries = row.entries.map(|count| count + 1);
            match entry.key_group {
                Some(number) => {
                    let _ = numbers.insert(number);
                },
                None => *unknown = true,
            }
        }
    }

    for (row, (numbers, unknown)) in rows.iter_mut().zip(groups) {
        row.key_groups = (!unknown).then_some(numbers.len());
    }
    rows
}

/// The schemes of the rows by name, each once, in their order.
fn scheme_names(rows: &[SchemeUse]) -> Vec<Scheme> {
    let mut names = Vec::new();
    for row in rows {
        if !names.contains(&row.scheme) {
            names.push(row.scheme);
        }
    }
    names
}

/// The places of the entries `wanted` picks.
fn places(entries: &[Entry], wanted: impl Fn(&Entry) -> bool) -> Vec<usize> {
    entries.iter().enumerate().filter(|(_, entry)| wanted(entry)).map(|(index, _)| index).collect()
}

/// The findings that follow from the entries, the schemes, the lines and the missing lines, in
/// the order of the specification.
fn drawn_findings(entries: &[Entry], names: &[Scheme], generation: Generation, coverage: Coverage, volume: Option<Volume>, lines: &[Line], no_line: &[Missing]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let scheme_of = |entry: &Entry| entry.protection.as_ref().filter(|_| entry.state.is_locked()).map(|protection| protection.scheme);

    let pseudo = places(entries, |entry| entry.state == State::PseudoEncrypted);
    if !pseudo.is_empty() {
        findings.push(Finding::new(Found::PseudoEncryption, pseudo));
    }

    if names.len() > 1 {
        findings.push(Finding::new(Found::MixedSchemes(names.to_vec()), Vec::new()));
    }

    if coverage == Coverage::Some {
        let open = places(entries, |entry| entry.holds_data() && !entry.state.is_locked());
        let locked = entries.iter().filter(|entry| entry.state.is_locked()).count();
        findings.push(Finding::new(Found::Partial { encrypted: locked, plain: open.len() }, open));
    }

    for &scheme in names.iter().filter(|scheme| scheme.falls_without_password()) {
        // `attack rar-13` reads the container of RAR 1.3 and 1.4; an entry of the scheme in a later one is out of its reach
        let found = if scheme == Scheme::Rar13 && generation != Generation::Rar1 { Found::WeakSchemeOutOfReach } else { Found::WeakScheme(scheme) };
        findings.push(Finding::new(found, places(entries, |entry| scheme_of(entry) == Some(scheme))));
    }

    let sealed: Vec<&Missing> = no_line.iter().filter(|missing| missing.reason() == Reason::NoPassword).collect();
    if !sealed.is_empty() {
        findings.push(Finding::new(Found::Certificate, sealed.iter().filter_map(|missing| missing.entry).collect()));
    }

    let identifier_of = |entry: &Entry| entry.protection.as_ref().and_then(|protection| protection.parameters.identifier);
    let mut identifiers: Vec<Option<u64>> = Vec::new();
    for entry in entries.iter().filter(|entry| scheme_of(entry).is_some_and(Scheme::is_unknown)) {
        if !identifiers.contains(&identifier_of(entry)) {
            identifiers.push(identifier_of(entry));
        }
    }
    for identifier in identifiers {
        let unknown = places(entries, |entry| scheme_of(entry).is_some_and(Scheme::is_unknown) && identifier_of(entry) == identifier);
        findings.push(Finding::new(Found::UnknownScheme { identifier }, unknown));
    }

    let mut refused: Vec<(&NoLine, Vec<usize>)> = Vec::new();
    for missing in no_line.iter().filter(|missing| missing.reason() == Reason::UnsupportedParameters) {
        let place = refused.iter().position(|(case, _)| *case == &missing.why).unwrap_or_else(|| {
            refused.push((&missing.why, Vec::new()));
            refused.len() - 1
        });
        if let (Some(index), Some((_, under))) = (missing.entry, refused.get_mut(place)) {
            under.push(index);
        }
    }
    for (case, under) in refused {
        findings.push(Finding::new(Found::UnsupportedParameters(case.clone()), under));
    }

    let split = places(entries, |entry| entry.state.is_locked() && entry.split.is_some_and(|split| split != Split::No));
    if !split.is_empty() {
        findings.push(Finding::new(Found::SplitEntry, split));
    }

    if volume == Some(Volume::Incomplete) {
        findings.push(Finding::new(Found::Incomplete, Vec::new()));
    }

    for line in lines {
        // a weak line is a finding however many bits it tests: eight check bytes are 64 bits,
        // and still no byte of data stands behind them
        if let Proves::Weak { bits } = line.proves {
            findings.push(Finding::new(Found::WeakCheck { bits }, line.entry.into_iter().collect()));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::line::Note;

    fn file(name: &str, state: State) -> Entry {
        Entry { name: Some(name.to_owned()), ..Entry::new(EntryKind::File, state) }
    }

    fn zip_crypto() -> Protection {
        Protection { scheme: Scheme::ZipCrypto, parameters: Parameters { cipher: Some(Cipher::ZipCrypto), key_bits: Some(96), check: vec![Check::new(CheckKind::CheckByte, 8), Check::new(CheckKind::Crc32, 32)], ..Parameters::default() }, salt: Salt::None }
    }

    fn zip_winzip(salt: Salt) -> Protection {
        Protection {
            scheme: Scheme::ZipWinzip,
            parameters: Parameters { ae: Some(2), cipher: Some(Cipher::Aes), key_bits: Some(256), kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha1, rounds: Some(1000) }), check: vec![Check::new(CheckKind::Verifier, 16), Check::new(CheckKind::Hmac, 80)], ..Parameters::default() },
            salt,
        }
    }

    fn rar_50(salt: u8) -> Protection {
        Protection {
            scheme: Scheme::Rar50,
            parameters: Parameters { cipher: Some(Cipher::Aes), key_bits: Some(256), kdf: Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 15) }), check: vec![Check::new(CheckKind::CheckValue, 64)], ..Parameters::default() },
            salt: Salt::Known(vec![salt; 16]),
        }
    }

    fn locked(name: &str, protection: Protection) -> Entry {
        Entry { protection: Some(protection), ..file(name, State::Encrypted) }
    }

    fn line(text: &str, entry: Option<usize>, proves: Proves) -> Line {
        Line::new(text.to_owned(), entry, proves).unwrap()
    }

    fn assemble(parts: Parts) -> Analysis {
        parts.assemble(Path::new("dir/a.zip")).analysis
    }

    fn codes(analysis: &Analysis) -> Vec<&'static str> {
        analysis.findings.iter().map(Finding::code).collect()
    }

    /// A ZIP archive made up for these tests: six entries, four of them encrypted
    /// under two schemes, one marked and open, one plain.
    fn report_zip() -> Parts {
        let mut parts = Parts::new(Format::Zip, Generation::Zip);
        parts.entries = vec![locked("a.txt", zip_crypto()), locked("b.txt", zip_crypto()), file("notes.txt", State::PseudoEncrypted), locked("c.txt", zip_crypto()), locked("big.bin", zip_winzip(Salt::Known(vec![1; 16]))), file("readme.txt", State::Plain)];
        parts.lines = vec![line("$zip$1$*1*00/aa*8*cefd04dc*1c*1c*00$/zip$", Some(1), Proves::Exact), line("$zip$2$*3*00*0000*00*8*0*$/zip$", Some(4), Proves::Structural)];
        parts
    }

    #[test]
    fn an_archive_is_counted_by_state() {
        let analysis = assemble(report_zip());
        assert_eq!(analysis.path, "dir/a.zip");
        assert_eq!(analysis.entries, Entries::Counts(Counts { total: 6, encrypted: 4, plain: 1, pseudo: 1, undetermined: 0 }));
        assert_eq!((analysis.headers, analysis.coverage, analysis.mixed), (Headers::Readable, Coverage::Some, true));
        assert!(analysis.is_encrypted());
        assert_eq!(codes(&analysis), ["pseudo-encryption", "mixed-schemes", "partial", "weak-scheme"]);
    }

    #[test]
    fn the_rows_of_schemes_count_entries_and_key_groups() {
        let analysis = assemble(report_zip());
        let rows: Vec<(Scheme, Option<usize>, Option<usize>)> = analysis.schemes.iter().map(|row| (row.scheme, row.entries, row.key_groups)).collect();
        assert_eq!(rows, [(Scheme::ZipCrypto, Some(3), Some(1)), (Scheme::ZipWinzip, Some(1), Some(1))]);

        // entries under one scheme and one salt share a key; what is not encrypted has none
        let groups: Vec<Option<u32>> = analysis.entry_list.iter().map(|entry| entry.key_group).collect();
        assert_eq!(groups, [Some(1), Some(1), None, Some(1), Some(2), None]);
    }

    #[test]
    fn entries_that_differ_in_salt_or_parameters_are_separate_key_groups() {
        let mut parts = Parts::new(Format::Rar, Generation::Rar5);
        let mut slower = rar_50(7);
        slower.parameters.kdf = Some(Kdf { name: KdfName::Pbkdf2HmacSha256, rounds: Some(1 << 20) });
        // the same key as the first, with one check less: another row, the same group
        let mut unchecked = rar_50(7);
        unchecked.parameters.check.clear();
        parts.entries = vec![locked("a", rar_50(7)), locked("b", rar_50(8)), locked("c", rar_50(7)), locked("d", slower), locked("e", unchecked)];

        let analysis = assemble(parts);
        let groups: Vec<Option<u32>> = analysis.entry_list.iter().map(|entry| entry.key_group).collect();
        assert_eq!(groups, [Some(1), Some(2), Some(1), Some(3), Some(1)]);
        let rows: Vec<(Option<usize>, Option<usize>)> = analysis.schemes.iter().map(|row| (row.entries, row.key_groups)).collect();
        assert_eq!(rows, [(Some(3), Some(2)), (Some(1), Some(1)), (Some(1), Some(1))]);
        assert!(!analysis.mixed, "three rows of one scheme are one scheme");
        assert_eq!(analysis.coverage, Coverage::All);
        assert_eq!(codes(&analysis), Vec::<&str>::new());
    }

    #[test]
    fn a_salt_the_parser_does_not_keep_leaves_the_key_group_open() {
        let mut parts = Parts::new(Format::Zip, Generation::Zip);
        parts.entries = vec![locked("a", zip_winzip(Salt::Unknown)), locked("b", zip_winzip(Salt::Known(vec![2; 16])))];
        let analysis = assemble(parts);
        assert_eq!(analysis.entry_list.iter().map(|entry| entry.key_group).collect::<Vec<_>>(), [None, Some(1)]);
        assert_eq!((analysis.schemes[0].entries, analysis.schemes[0].key_groups), (Some(2), None), "how many groups cannot be said");
    }

    #[test]
    fn encrypted_headers_hide_the_entries() {
        let mut parts = Parts::new(Format::Rar, Generation::Rar5);
        parts.headers = HeaderState::Encrypted(rar_50(3));
        parts.entries = vec![file("left over", State::Plain)];
        parts.lines = vec![line("$rar$50$*0*00*15*00*00*0*****$/rar$", None, Proves::Exact)];

        let analysis = assemble(parts);
        assert_eq!((analysis.headers, analysis.entries, analysis.coverage), (Headers::Encrypted, Entries::Hidden, Coverage::Unknown));
        assert!(analysis.entry_list.is_empty() && analysis.is_encrypted());
        assert_eq!(analysis.schemes.len(), 1);
        assert_eq!((analysis.schemes[0].scheme, analysis.schemes[0].entries, analysis.schemes[0].key_groups), (Scheme::Rar50, None, None));
        assert_eq!(analysis.lines, [LineRef { mode: 46800, tag: Tag::Rar50, entry: None, proves: Proves::Exact }]);
        assert_eq!(codes(&analysis), Vec::<&str>::new());
    }

    #[test]
    fn coverage_is_over_the_entries_that_hold_data() {
        let coverage_of = |entries: Vec<Entry>| {
            let mut parts = Parts::new(Format::Zip, Generation::Zip);
            parts.entries = entries;
            let analysis = assemble(parts);
            (analysis.coverage, codes(&analysis).contains(&"partial"))
        };
        let directory = || Entry { name: Some("dir/".to_owned()), ..Entry::new(EntryKind::Directory, State::Plain) };
        let service = || Entry::new(EntryKind::Service, State::Plain);

        assert_eq!(coverage_of(Vec::new()), (Coverage::None, false));
        assert_eq!(coverage_of(vec![file("a", State::Plain), directory()]), (Coverage::None, false));
        assert_eq!(coverage_of(vec![file("a", State::PseudoEncrypted)]), (Coverage::None, false), "marked and open is not encrypted");
        assert_eq!(coverage_of(vec![locked("a", zip_crypto())]), (Coverage::All, false));
        assert_eq!(coverage_of(vec![locked("a", zip_crypto()), directory(), service()]), (Coverage::All, false), "a directory has nothing to encrypt");
        assert_eq!(coverage_of(vec![locked("a", zip_crypto()), file("b", State::Plain)]), (Coverage::Some, true));
        assert_eq!(coverage_of(vec![locked("a", zip_crypto()), file("b", State::PseudoEncrypted)]), (Coverage::Some, true));
        assert_eq!(coverage_of(vec![file("a", State::Undetermined)]), (Coverage::All, false), "what could not be determined is not reported as open");
        // an entry that is marked counts whatever it is
        let marked_directory = || Entry { name: Some("dir/".to_owned()), ..locked("dir/", zip_crypto()) };
        assert_eq!(coverage_of(vec![Entry { kind: EntryKind::Directory, ..marked_directory() }]), (Coverage::All, false));
        assert_eq!(coverage_of(vec![Entry { kind: EntryKind::Directory, ..marked_directory() }, file("b", State::Plain)]), (Coverage::Some, true));
    }

    /// A listing that is not whole says nothing of what it does not list: only that some
    /// entries are encrypted and some are not stays true whatever else the archive holds.
    #[test]
    fn a_listing_that_is_not_whole_leaves_the_coverage_unknown_unless_it_is_some() {
        let cut = |entries: Vec<Entry>| {
            let mut parts = Parts::new(Format::Rar, Generation::Rar4);
            parts.volume = Some(Volume::Incomplete);
            parts.entries = entries;
            assemble(parts).coverage
        };
        let broken = |entries: Vec<Entry>| {
            let mut parts = Parts::new(Format::Rar, Generation::Rar4);
            parts.entries = entries;
            parts.findings = vec![Finding::new(Found::HeadersBroken { at: 20, left: 300 }, Vec::new())];
            assemble(parts).coverage
        };
        for listing in [cut, broken] {
            assert_eq!(listing(Vec::new()), Coverage::Unknown);
            assert_eq!(listing(vec![file("a", State::Plain)]), Coverage::Unknown, "what is not listed may be encrypted");
            assert_eq!(listing(vec![locked("a", zip_crypto())]), Coverage::Unknown, "what is not listed may be plain");
            assert_eq!(listing(vec![locked("a", zip_crypto()), file("b", State::Plain)]), Coverage::Some);
        }
        // a header that fails its checksum and is read all the same leaves the listing whole
        let mut parts = Parts::new(Format::Rar, Generation::Rar4);
        parts.entries = vec![file("a", State::Plain)];
        parts.findings = vec![Finding::new(Found::HeaderChecksum { at: 20 }, Vec::new())];
        let analysis = assemble(parts);
        assert_eq!((analysis.coverage, codes(&analysis)), (Coverage::None, vec!["damaged"]));
    }

    #[test]
    fn the_partial_finding_names_the_entries_that_are_open() {
        let analysis = assemble(report_zip());
        let partial = analysis.findings.iter().find(|finding| finding.code() == "partial").unwrap();
        assert_eq!(partial.found, Found::Partial { encrypted: 4, plain: 2 });
        assert_eq!(partial.found.to_string(), "4 entries are encrypted, and 2 that hold data are not");
        assert_eq!(Found::Partial { encrypted: 1, plain: 1 }.to_string(), "1 entry is encrypted, and 1 that holds data is not");
        assert_eq!(partial.entries, [2, 5]);
        let pseudo = analysis.findings.iter().find(|finding| finding.code() == "pseudo-encryption").unwrap();
        assert_eq!(pseudo.entries, [2]);
        let mixed = analysis.findings.iter().find(|finding| finding.code() == "mixed-schemes").unwrap();
        assert_eq!(mixed.found, Found::MixedSchemes(vec![Scheme::ZipCrypto, Scheme::ZipWinzip]));
        let weak = analysis.findings.iter().find(|finding| finding.code() == "weak-scheme").unwrap();
        assert_eq!((&weak.found, weak.entries.as_slice()), (&Found::WeakScheme(Scheme::ZipCrypto), &[0, 1, 3][..]));
    }

    #[test]
    fn an_entry_is_marked_with_its_line_or_its_reason() {
        let mut parts = report_zip();
        parts.no_line = vec![Missing::for_entry(Scheme::ZipCrypto, 3, NoLine::Unreadable), Missing::for_entry(Scheme::ZipCrypto, 1, NoLine::Empty), Missing::for_scheme(Scheme::ZipPkware, NoLine::CentralDirectoryEncrypted)];
        let Analysed { analysis, lines } = parts.assemble(Path::new("a.zip"));

        let marks: Vec<Option<EntryLine>> = analysis.entry_list.iter().map(|entry| entry.line).collect();
        assert_eq!(marks, [None, Some(EntryLine(Ok(LineName { mode: 46100, tag: Tag::Zip1 }))), None, Some(EntryLine(Err(Reason::Damaged))), Some(EntryLine(Ok(LineName { mode: 46200, tag: Tag::Zip2 }))), None], "a line comes before a reason");

        // `info` names exactly the lines `hash` writes, in their order
        assert_eq!(analysis.lines.len(), lines.len());
        for (named, line) in analysis.lines.iter().zip(&lines) {
            assert_eq!((named.mode, named.tag, named.entry, named.proves), (line.mode, line.tag, line.entry, line.proves));
        }
        assert_eq!(analysis.no_line.len(), 3);
    }

    #[test]
    fn a_line_built_twice_is_kept_once() {
        let mut parts = Parts::new(Format::Rar, Generation::Rar4);
        let first = "$rar$15$*00000000*1*1*30*00$/rar$";
        let second = "$rar$15$*11111111*1*1*30*00$/rar$";
        parts.lines = vec![line(first, Some(0), Proves::Exact), line(second, Some(1), Proves::Exact), line(first, Some(2), Proves::Exact)];
        let Analysed { analysis, lines } = parts.assemble(Path::new("a.rar"));
        assert_eq!(lines.iter().map(|line| line.text.as_str()).collect::<Vec<_>>(), [first, second]);
        assert_eq!(analysis.lines.len(), 2);
    }

    #[test]
    fn findings_follow_from_the_missing_lines() {
        let mut parts = Parts::new(Format::SevenZ, Generation::SevenZ);
        parts.entries = vec![Entry::new(EntryKind::Folder, State::Encrypted), Entry::new(EntryKind::Folder, State::Encrypted), Entry::new(EntryKind::Folder, State::Encrypted)];
        parts.no_line = vec![Missing::for_entry(Scheme::SevenZAes, 0, NoLine::TooManyRounds { power: 30 }), Missing::for_entry(Scheme::SevenZAes, 2, NoLine::TooManyRounds { power: 30 }), Missing::for_entry(Scheme::SevenZAes, 1, NoLine::Certificate)];
        let analysis = assemble(parts);

        assert_eq!(codes(&analysis), ["certificate", "unsupported-parameters"]);
        assert_eq!(analysis.findings[0].entries, [1]);
        assert_eq!(analysis.findings[1], Finding::new(Found::UnsupportedParameters(NoLine::TooManyRounds { power: 30 }), vec![0, 2]), "one finding for one case");
    }

    #[test]
    fn a_weak_line_is_a_finding_however_many_bits_it_tests() {
        let finding_for = |proves: Proves| {
            let mut parts = Parts::new(Format::Zip, Generation::Zip);
            parts.entries = vec![locked("a", zip_winzip(Salt::Known(vec![1; 8])))];
            parts.lines = vec![line("$zip$2$*3*00*0000*00*8*0*$/zip$", Some(0), proves).with_note(Note::EmptyEntry { checks: 1 })];
            assemble(parts).findings
        };
        assert_eq!(finding_for(Proves::Weak { bits: 16 }), [Finding::new(Found::WeakCheck { bits: 16 }, vec![0])]);
        assert_eq!(finding_for(Proves::Weak { bits: 31 }).len(), 1);
        // eight check bytes of a ZIP archive: 64 bits, and no data behind them
        assert_eq!(finding_for(Proves::Weak { bits: 64 }), [Finding::new(Found::WeakCheck { bits: 64 }, vec![0])]);
        assert!(finding_for(Proves::Exact).is_empty() && finding_for(Proves::Structural).is_empty());
    }

    #[test]
    fn the_remaining_findings_follow_from_the_entries_and_the_volume() {
        let mut parts = Parts::new(Format::Rar, Generation::Rar1);
        parts.volume = Some(Volume::Incomplete);
        let unknown = Protection { scheme: Scheme::RarUnknown, parameters: Parameters { identifier: Some(1), ..Parameters::default() }, salt: Salt::None };
        parts.entries = vec![Entry { split: Some(Split::After), ..locked("a", Protection::bare(Scheme::Rar13)) }, Entry { split: Some(Split::No), ..locked("b", Protection::bare(Scheme::Rar13)) }, Entry { split: Some(Split::Both), ..file("c", State::Plain) }, locked("d", unknown)];
        parts.findings = vec![Finding::new(Found::Certificate, vec![9])];
        let analysis = assemble(parts);

        assert_eq!(codes(&analysis), ["mixed-schemes", "partial", "weak-scheme", "unknown-scheme", "split-entry", "incomplete", "certificate"], "what the format found comes last");
        let by_code = |code: &str| analysis.findings.iter().find(|finding| finding.code() == code).unwrap();
        assert_eq!(by_code("weak-scheme").found, Found::WeakScheme(Scheme::Rar13));
        assert_eq!(by_code("unknown-scheme"), &Finding::new(Found::UnknownScheme { identifier: Some(1) }, vec![3]));
        assert_eq!(by_code("split-entry").entries, [0], "an entry that is open is not a split encrypted entry");
        assert!(by_code("incomplete").entries.is_empty());
    }

    #[test]
    fn the_object_has_the_names_of_the_specification() {
        let mut parts = report_zip();
        parts.comment = Some("made by hand".to_owned());
        parts.offset = 4096;
        parts.no_line = vec![Missing::for_entry(Scheme::ZipCrypto, 3, NoLine::Unreadable)];
        parts.entries[4].method = Some(Method { name: Some("deflate".to_owned()), number: Some(8) });
        parts.entries[4].packed = Some(1000);
        parts.entries[4].size = Some(4000);
        parts.entries[4].split = Some(Split::No);
        let analysis = assemble(parts);
        let json = serde_json::to_value(&analysis).unwrap();

        let fields: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(fields, ["comment", "coverage", "entries", "entry_list", "findings", "format", "generation", "headers", "lines", "mixed", "no_line", "offset", "path", "schemes"], "no volume: no parser reads it yet");
        assert_eq!(json["format"], "zip");
        assert_eq!(json["generation"], "zip");
        assert_eq!(json["offset"], 4096);
        assert_eq!(json["headers"], "readable");
        assert_eq!(json["entries"], serde_json::json!({ "total": 6, "encrypted": 4, "plain": 1, "pseudo": 1, "undetermined": 0 }));
        assert_eq!(json["coverage"], "some");
        assert_eq!(json["mixed"], true);
        assert_eq!(json["lines"], serde_json::json!([{ "mode": 46100, "tag": "$zip$1$", "entry": 1, "proves": "exact" }, { "mode": 46200, "tag": "$zip$2$", "entry": 4, "proves": "structural" }]));
        assert_eq!(json["no_line"], serde_json::json!([{ "entry": 3, "reason": "damaged", "text": "its headers or its data cannot be read" }]));
        assert_eq!(
            json["schemes"][1],
            serde_json::json!({ "scheme": "zip-winzip", "variant": "zip-winzip:256:ae2", "ae": 2, "cipher": "aes", "key_bits": 256, "kdf": { "name": "pbkdf2-hmac-sha1", "rounds": 1000 }, "check": [{ "kind": "verifier", "bits": 16 }, { "kind": "hmac", "bits": 80 }], "entries": 1, "key_groups": 1 })
        );

        assert_eq!(
            json["entry_list"][4],
            serde_json::json!({
                "name": "big.bin", "kind": "file", "state": "encrypted",
                "scheme": "zip-winzip", "variant": "zip-winzip:256:ae2", "ae": 2, "cipher": "aes", "key_bits": 256, "kdf": { "name": "pbkdf2-hmac-sha1", "rounds": 1000 },
                "salt": "01010101010101010101010101010101", "key_group": 2,
                "check": [{ "kind": "verifier", "bits": 16 }, { "kind": "hmac", "bits": 80 }],
                "method": { "name": "deflate", "number": 8 }, "packed": 1000, "size": 4000, "split": "no",
                "line": { "mode": 46200, "tag": "$zip$2$" },
            })
        );
        assert_eq!(json["entry_list"][2], serde_json::json!({ "name": "notes.txt", "kind": "file", "state": "pseudo-encrypted" }));
        assert_eq!(json["entry_list"][3]["line"], serde_json::json!({ "reason": "damaged" }));
        assert_eq!(json["entry_list"][5], serde_json::json!({ "name": "readme.txt", "kind": "file", "state": "plain" }));
    }

    #[test]
    fn hidden_entries_and_a_folder_have_their_own_shape() {
        let mut parts = Parts::new(Format::SevenZ, Generation::SevenZ);
        parts.volume = Some(Volume::First);
        parts.headers = HeaderState::Encrypted(Protection::bare(Scheme::SevenZAes));
        let json = serde_json::to_value(assemble(parts)).unwrap();
        assert_eq!((&json["format"], &json["generation"], &json["volume"], &json["headers"], &json["entries"], &json["coverage"]), (&"7z".into(), &"7z".into(), &"first".into(), &"encrypted".into(), &"hidden".into(), &"unknown".into()));
        assert_eq!(json["schemes"], serde_json::json!([{ "scheme": "7z-aes", "variant": "7z-aes:headers", "check": [] }]));
        assert_eq!(json["entry_list"], serde_json::json!([]));

        let mut parts = Parts::new(Format::SevenZ, Generation::SevenZ);
        parts.entries = vec![Entry { files: vec!["a.txt".to_owned(), "b.txt".to_owned()], ..Entry::new(EntryKind::Folder, State::Plain) }];
        let json = serde_json::to_value(assemble(parts)).unwrap();
        assert_eq!(json["entry_list"], serde_json::json!([{ "kind": "folder", "files": ["a.txt", "b.txt"], "state": "plain" }]));
        assert_eq!(json["coverage"], "none");
    }

    #[test]
    fn the_states_and_the_split_are_named_as_the_specification_names_them() {
        let names: Vec<&str> = [State::Plain, State::Encrypted, State::PseudoEncrypted, State::Undetermined].iter().map(|state| state.as_str()).collect();
        assert_eq!(names, ["plain", "encrypted", "pseudo-encrypted", "undetermined"]);
        for state in [State::Plain, State::Encrypted, State::PseudoEncrypted, State::Undetermined] {
            assert_eq!(serde_json::to_value(state).unwrap(), state.as_str());
        }
        let splits: Vec<serde_json::Value> = [(false, false), (true, false), (false, true), (true, true)].iter().map(|&(before, after)| serde_json::to_value(Split::from_flags(before, after)).unwrap()).collect();
        assert_eq!(splits, ["no", "before", "after", "both"]);
        let volumes: Vec<serde_json::Value> = [Volume::Single, Volume::First, Volume::Later, Volume::Incomplete].iter().map(|volume| serde_json::to_value(volume).unwrap()).collect();
        assert_eq!(volumes, ["single", "first", "later", "incomplete"]);
        let kinds: Vec<serde_json::Value> = [EntryKind::File, EntryKind::Directory, EntryKind::Service, EntryKind::Folder].iter().map(|kind| serde_json::to_value(kind).unwrap()).collect();
        assert_eq!(kinds, ["file", "directory", "service", "folder"]);
        let coverages: Vec<serde_json::Value> = [Coverage::None, Coverage::Some, Coverage::All, Coverage::Unknown].iter().map(|coverage| serde_json::to_value(coverage).unwrap()).collect();
        assert_eq!(coverages, ["none", "some", "all", "unknown"]);
    }
}
