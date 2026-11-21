//! The extractors agree: the first of the three proofs that a line is right.
//!
//! The hashcat fork holds `zip2hashcat.py`, `rar2hashcat.py` and `7z2hashcat.py`, each on the
//! branch of its format, and each meant to write the lines ArchiveWolf writes. These tests read
//! the three files out of their branches, run each over every fixture of its format, and require
//! what it writes to be what `archivewolf hash` writes for the same file, byte for byte: for the
//! best line of each scheme, and for a line for every entry.
//!
//! They are run by `make test-extractors`, and take two things from the environment:
//!
//! - `ARCHIVEWOLF_HASHCAT_REPO`: the path of the hashcat fork. It is only read, with `git show`.
//!   A branch is taken from the repository itself, and from its `origin` when it has no such
//!   branch of its own.
//! - `ARCHIVEWOLF_PYTHON`: the interpreter that runs the extractors, with its arguments when it
//!   needs any, split at white space: `python3`, or `uv run --no-project python -I`.
//!
//! Without either, or with an interpreter that does not start, the tests fail. They never pass
//! by leaving the comparison out.

mod support;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

/// The environment variable that holds the path of the hashcat fork.
const REPOSITORY: &str = "ARCHIVEWOLF_HASHCAT_REPO";

/// The environment variable that holds the Python interpreter and its arguments.
const INTERPRETER: &str = "ARCHIVEWOLF_PYTHON";

/// The flag of an extractor that is what `--all` is to `archivewolf hash`. The `--help` of each
/// extractor has to list it, or the comparison of that form would compare something else.
const ALL: &str = "--all-hashes";

/// The files under `tests/fixtures` that are not archives.
const NOT_ARCHIVES: [&str; 2] = ["FIXTURES.md", "passwords.json"];

/// How many differences are printed in full. All of them are counted.
const SHOWN: usize = 20;

/// The differences that are known and wanted: a fix in ArchiveWolf that the extractor has not
/// got yet. Each entry names a fixture, the forms it differs in, and why. A difference that is
/// not listed fails the comparison, and so does a listed one that no longer differs.
const KNOWN_DIFFERENCES: &str = "tests/extractor_differences.json";

/// One archive format: where its extractor is, which fixtures are of it, and which line types
/// those fixtures have to give for the comparison to have covered them.
struct Format {
    name: &'static str,
    branch: &'static str,
    script: &'static str,
    /// File name extensions of its fixtures, in lower case.
    extensions: &'static [&'static str],
    tags: &'static [&'static str],
}

const FORMATS: [Format; 3] = [
    Format { name: "ZIP", branch: "feat/zip-modes", script: "zip2hashcat.py", extensions: &["zip"], tags: &["$zip$1$", "$zip$2$", "$zip$3$"] },
    Format { name: "RAR", branch: "feat/rar-modes", script: "rar2hashcat.py", extensions: &["rar", "sfx"], tags: &["$rar$15$", "$rar$20$", "$rar$30$", "$rar$50$"] },
    Format { name: "7-Zip", branch: "feat/7z-modes", script: "7z2hashcat.py", extensions: &["7z"], tags: &["$7z$"] },
];

/// The three extractors, read out of their branches into a directory that goes when this does.
struct Extractors {
    interpreter: Vec<String>,
    /// The script of each format, in the order of `FORMATS`.
    scripts: Vec<PathBuf>,
    /// Where each script was read from: the branch and its commit.
    origins: Vec<String>,
    directory: tempfile::TempDir,
}

/// What one run of an extractor gave.
struct Extracted {
    lines: String,
    notes: String,
}

/// One comparison: a fixture, in one of the two forms.
struct Compared {
    /// The fixture, by its path under the fixtures.
    fixture: String,
    format: usize,
    all: bool,
    /// Lines ArchiveWolf wrote, and lines the extractor wrote.
    lines: (usize, usize),
    /// The line types the extractor wrote.
    tags: Vec<&'static str>,
    /// What differs, when something does.
    difference: Option<String>,
}

/// The value of an environment variable. One that is not set or is empty is an error that says
/// what it has to hold.
fn variable(name: &str, holds: &str) -> Result<String, String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) | Err(std::env::VarError::NotPresent) => Err(format!("{name} is not set. It has to hold {holds}.")),
        Err(error) => Err(format!("{name}: {error}")),
    }
}

/// What a git command prints, run in the hashcat repository. Only commands that read are run.
fn git(repository: &Path, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git").arg("-C").arg(repository).args(arguments).env("GIT_OPTIONAL_LOCKS", "0").output().map_err(|error| format!("git could not be started: {error}"))?;
    if output.status.success() { String::from_utf8(output.stdout).map_err(|error| format!("git {}: {error}", arguments.join(" "))) } else { Err(format!("git -C {} {}: {}", repository.display(), arguments.join(" "), String::from_utf8_lossy(&output.stderr).trim())) }
}

impl Extractors {
    /// Read the three extractors out of the repository the environment names, and check that the
    /// interpreter the environment names runs each of them and that each still has the flag `ALL`.
    fn from_environment() -> Result<Self, String> {
        let repository = PathBuf::from(variable(REPOSITORY, "the path of the hashcat fork, whose branches feat/zip-modes, feat/rar-modes and feat/7z-modes hold the extractors")?);
        if !repository.is_dir() {
            return Err(format!("{REPOSITORY} is {}, which is not a directory.", repository.display()));
        }
        let interpreter: Vec<String> = variable(INTERPRETER, "the Python interpreter that runs the extractors, with its arguments if it needs any: python3, or uv run --no-project python -I")?.split_whitespace().map(str::to_owned).collect();
        let directory = tempfile::tempdir().map_err(|error| format!("no temporary directory: {error}"))?;

        let mut extractors = Self { interpreter, scripts: Vec::new(), origins: Vec::new(), directory };
        for format in &FORMATS {
            let commit = [format!("refs/heads/{}", format.branch), format!("refs/remotes/origin/{}", format.branch)]
                .iter()
                .find_map(|reference| git(&repository, &["rev-parse", "--verify", "--quiet", &format!("{reference}^{{commit}}")]).ok())
                .ok_or_else(|| format!("{}: no branch {}, of its own or of origin", repository.display(), format.branch))?;
            let commit = commit.trim();
            let source = git(&repository, &["show", &format!("{commit}:tools/{}", format.script)])?;
            let script = extractors.directory.path().join(format.script);
            std::fs::write(&script, source).map_err(|error| format!("{}: {error}", script.display()))?;
            extractors.scripts.push(script);
            extractors.origins.push(format!("tools/{} of {} at {commit}", format.script, format.branch));
        }

        for (index, format) in FORMATS.iter().enumerate() {
            let help = extractors.run(index, &["--help"])?;
            if !help.lines.contains(ALL) {
                return Err(format!("{} has no flag {ALL} any more. Its --help says:\n{}", format.script, help.lines));
            }
        }
        Ok(extractors)
    }

    /// Run the extractor of a format. One that cannot be started, is ended by a signal, ends
    /// with a status other than 0 and 1 (1 is its word for an archive it cannot read), or ends
    /// in a Python traceback, is an error.
    fn run(&self, format: usize, arguments: &[&str]) -> Result<Extracted, String> {
        let (Some(program), Some(script)) = (self.interpreter.first(), self.scripts.get(format)) else {
            return Err(format!("{INTERPRETER} names no program, or format {format} has no extractor"));
        };
        let command = format!("{} {} {}", self.interpreter.join(" "), script.display(), arguments.join(" "));
        let output = Command::new(program).args(self.interpreter.iter().skip(1)).arg(script).args(arguments).output().map_err(|error| format!("{INTERPRETER} is `{}`, and `{program}` could not be started: {error}", self.interpreter.join(" ")))?;
        let notes = String::from_utf8_lossy(&output.stderr).into_owned();
        if !matches!(output.status.code(), Some(0 | 1)) || notes.contains("Traceback (most recent call last)") {
            let said: Vec<&str> = notes.lines().collect();
            let end: Vec<String> = said.iter().skip(said.len().saturating_sub(4)).map(|line| format!("      {}", support::trimmed(line))).collect();
            return Err(format!("`{command}` failed, {}:\n{}", output.status, end.join("\n")));
        }
        Ok(Extracted { lines: String::from_utf8_lossy(&output.stdout).into_owned(), notes })
    }
}

/// The format a fixture is of, by the extension of its name.
fn format_of(fixture: &Path) -> Option<usize> {
    let extension = fixture.extension()?.to_str()?.to_ascii_lowercase();
    FORMATS.iter().position(|format| format.extensions.contains(&extension.as_str()))
}

/// Every file under a directory, in path order.
fn files_under(directory: &Path) -> Result<Vec<PathBuf>, String> {
    let (mut files, mut directories) = (Vec::new(), vec![directory.to_path_buf()]);
    while let Some(next) = directories.pop() {
        for entry in std::fs::read_dir(&next).map_err(|error| format!("{}: {error}", next.display()))? {
            let path = entry.map_err(|error| format!("{}: {error}", next.display()))?.path();
            if path.is_dir() {
                directories.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// The fixtures with the format of each, and the files no extractor is known for. The two files
/// that describe the fixtures are neither.
fn fixtures() -> Result<(Vec<(PathBuf, usize)>, Vec<PathBuf>), String> {
    let (mut archives, mut unknown) = (Vec::new(), Vec::new());
    for file in files_under(Path::new(support::FIXTURES))? {
        match format_of(&file) {
            Some(format) => archives.push((file, format)),
            None if NOT_ARCHIVES.iter().any(|name| file == Path::new(support::FIXTURES).join(name)) => {},
            None => unknown.push(file),
        }
    }
    Ok((archives, unknown))
}

/// The name of a form of the comparison.
const fn form_name(all: bool) -> &'static str {
    if all { "hash --all" } else { "hash" }
}

/// The known differences: for a fixture and a form, why it differs.
fn known_differences() -> Result<BTreeMap<(String, bool), String>, String> {
    let text = std::fs::read_to_string(KNOWN_DIFFERENCES).map_err(|fault| format!("{KNOWN_DIFFERENCES}: {fault}"))?;
    let listed: serde_json::Value = serde_json::from_str(&text).map_err(|fault| format!("{KNOWN_DIFFERENCES}: {fault}"))?;
    let mut known = BTreeMap::new();
    for entry in listed.as_array().ok_or_else(|| format!("{KNOWN_DIFFERENCES}: not a list"))? {
        let text_of = |field: &str| entry[field].as_str().map(str::to_owned).ok_or_else(|| format!("{KNOWN_DIFFERENCES}: an entry without `{field}`"));
        let (fixture, why) = (text_of("fixture")?, text_of("why")?);
        for form in entry["forms"].as_array().ok_or_else(|| format!("{KNOWN_DIFFERENCES}: {fixture}: no `forms`"))? {
            let all = match form.as_str() {
                Some("hash") => false,
                Some("hash --all") => true,
                _ => return Err(format!("{KNOWN_DIFFERENCES}: {fixture}: a form is `hash` or `hash --all`")),
            };
            if known.insert((fixture.clone(), all), why.clone()).is_some() {
                return Err(format!("{KNOWN_DIFFERENCES}: {fixture} is listed twice in one form"));
            }
        }
    }
    Ok(known)
}

/// Compare what ArchiveWolf and the extractor of its format write for one fixture. A run that
/// fails on either side is a difference like any other, so that every one is counted.
fn compare(extractors: &Extractors, fixture: &Path, format: usize, all: bool) -> Compared {
    let form = form_name(all);
    let name = fixture.strip_prefix(support::FIXTURES).unwrap_or(fixture).to_string_lossy().into_owned();
    let both = || -> Result<(String, Extracted, &Format), String> {
        let known = FORMATS.get(format).ok_or_else(|| format!("no format {format}"))?;
        let ours = String::from_utf8_lossy(&support::archivewolf_hash(if all { &["--all"] } else { &[] }, fixture)?).into_owned();
        let path = fixture.to_str().ok_or_else(|| "not a name an extractor can be given".to_owned())?;
        let arguments = if all { vec![ALL, path] } else { vec![path] };
        Ok((ours, extractors.run(format, &arguments)?, known))
    };
    match both() {
        Err(fault) => Compared { fixture: name, format, all, lines: (0, 0), tags: Vec::new(), difference: Some(format!("  {} ({form}):\n    {fault}", fixture.display())) },
        Ok((ours, theirs, known)) => {
            let difference = (ours != theirs.lines).then(|| {
                let mut parts = vec![format!("  {} ({form}):", fixture.display()), support::difference(("archivewolf", &ours), (known.script, &theirs.lines))];
                parts.extend(theirs.notes.lines().take(4).map(|note| format!("    {} says: {}", known.script, support::trimmed(note))));
                parts.join("\n")
            });
            let tags = known.tags.iter().copied().filter(|tag| theirs.lines.lines().any(|line| line.starts_with(*tag))).collect();
            Compared { fixture: name, format, all, lines: (ours.lines().count(), theirs.lines.lines().count()), tags, difference }
        },
    }
}

/// Compare every fixture in both forms, on as many threads as the machine has.
fn compare_all(extractors: &Extractors, archives: &[(PathBuf, usize)]) -> Result<Vec<Compared>, String> {
    let jobs: Vec<(&Path, usize, bool)> = archives.iter().flat_map(|(fixture, format)| [(fixture.as_path(), *format, false), (fixture.as_path(), *format, true)]).collect();
    let next = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);

    let mut compared = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    while let Some((fixture, format, all)) = jobs.get(next.fetch_add(1, Ordering::Relaxed)) {
                        done.push((*fixture, compare(extractors, fixture, *format, *all)));
                    }
                    done
                })
            })
            .collect();
        let mut compared = Vec::new();
        for worker in workers {
            compared.extend(worker.join().map_err(|_| "a comparison panicked".to_owned())?);
        }
        Ok::<_, String>(compared)
    })?;

    if compared.len() != jobs.len() {
        return Err(format!("{} comparisons were asked for and {} were made", jobs.len(), compared.len()));
    }
    compared.sort_by_key(|(fixture, compared)| (*fixture, compared.all));
    Ok(compared.into_iter().map(|(_, compared)| compared).collect())
}

/// One row for each format and form: how many files were compared, how many lines each side
/// wrote, and how many files differ.
fn table(compared: &[Compared]) -> String {
    let mut rows = Vec::new();
    for (index, format) in FORMATS.iter().enumerate() {
        for all in [false, true] {
            let of_form: Vec<&Compared> = compared.iter().filter(|one| one.format == index && one.all == all).collect();
            let (ours, theirs): (usize, usize) = of_form.iter().fold((0, 0), |sum, one| (sum.0.saturating_add(one.lines.0), sum.1.saturating_add(one.lines.1)));
            let differ = of_form.iter().filter(|one| one.difference.is_some()).count();
            rows.push(format!("  {:6} {:11} {:4} files   archivewolf {ours:4} lines   {} {theirs:4} lines   {differ} files differ", format.name, form_name(all), of_form.len(), format.script));
        }
    }
    rows.join("\n")
}

#[test]
#[ignore = "needs the hashcat fork and Python: `make test-extractors`"]
fn archivewolf_and_the_extractors_write_the_same_lines_for_every_fixture() {
    let extractors = Extractors::from_environment().unwrap_or_else(|fault| panic!("{fault}"));
    let (archives, unknown) = fixtures().unwrap_or_else(|fault| panic!("{fault}"));
    assert!(unknown.is_empty(), "no extractor is known for these files under {}: give their extension a format in this test, or list them as not archives: {unknown:?}", support::FIXTURES);

    let compared = compare_all(&extractors, &archives).unwrap_or_else(|fault| panic!("{fault}"));
    println!("The extractors: {}.\n{}", extractors.origins.join(", "), table(&compared));

    // nothing is proven by a comparison of nothing: every format has fixtures, and they give every line type it has
    for (index, format) in FORMATS.iter().enumerate() {
        for all in [false, true] {
            let of_form: Vec<&Compared> = compared.iter().filter(|one| one.format == index && one.all == all).collect();
            let tags: BTreeSet<&str> = of_form.iter().flat_map(|one| one.tags.iter().copied()).collect();
            assert!(!of_form.is_empty(), "{}: no fixture was compared", format.name);
            assert_eq!(tags, format.tags.iter().copied().collect(), "{}, all {all}: the line types {} wrote over all fixtures", format.name, format.script);
        }
    }

    // a difference is either listed, with its reason, or it fails; and what is listed has to differ still
    let known = known_differences().unwrap_or_else(|fault| panic!("{fault}"));
    let mut unlisted = Vec::new();
    let mut found = BTreeSet::new();
    for one in &compared {
        let Some(difference) = one.difference.as_deref() else { continue };
        let key = (one.fixture.clone(), one.all);
        if known.contains_key(&key) {
            let _ = found.insert(key);
        } else {
            unlisted.push(difference);
        }
    }
    println!("{} known differences, each a change the extractor has still to mirror:", found.len());
    for ((fixture, all), why) in &known {
        println!("  {fixture} ({}): {why}", form_name(*all));
    }
    assert!(
        unlisted.is_empty(),
        "{} of {} comparisons differ and are not listed in {KNOWN_DIFFERENCES}{}:\n{}",
        unlisted.len(),
        compared.len(),
        if unlisted.len() > SHOWN { format!(", the first {SHOWN} are shown") } else { String::new() },
        unlisted.iter().take(SHOWN).copied().collect::<Vec<_>>().join("\n")
    );
    let stale: Vec<String> = known.keys().filter(|key| !found.contains(*key)).map(|(fixture, all)| format!("  {fixture} ({})", form_name(*all))).collect();
    assert!(stale.is_empty(), "{} entries of {KNOWN_DIFFERENCES} no longer differ; take them off the list:\n{}", stale.len(), stale.join("\n"));
}

#[test]
#[ignore = "needs the hashcat fork and Python: `make test-extractors`"]
fn the_extractors_write_every_recorded_line() {
    let extractors = Extractors::from_environment().unwrap_or_else(|fault| panic!("{fault}"));
    let recorded = support::recorded_lines().unwrap_or_else(|fault| panic!("{fault}"));

    let mut faults = Vec::new();
    for entry in &recorded {
        let fixture = entry.fixture();
        let format = format_of(&fixture).unwrap_or_else(|| panic!("{}: no extractor is known for it", fixture.display()));
        let expected = entry.line().unwrap_or_else(|fault| panic!("{fault}"));
        let written = extractors.run(format, &[fixture.to_str().unwrap()]).unwrap_or_else(|fault| panic!("{fault}"));
        if !written.lines.lines().any(|line| line == expected) {
            faults.push(format!("  {} ({}, mode {}):\n{}", entry.text("case"), fixture.display(), entry.mode(), support::difference(("recorded", &expected), (FORMATS[format].script, &written.lines))));
        }
    }
    println!("{} recorded lines, {} of them not written by the extractor of their format.", recorded.len(), faults.len());
    assert!(faults.is_empty(), "{} of {} recorded lines are not what the extractor writes:\n{}", faults.len(), recorded.len(), faults.join("\n"));
}

#[test]
fn a_fixture_is_given_to_the_extractor_of_its_extension() {
    let script = |name: &str| format_of(Path::new(name)).map(|format| FORMATS[format].script);
    assert_eq!(script("tests/fixtures/zip-crypto/a.zip"), Some("zip2hashcat.py"));
    assert_eq!(script("tests/fixtures/rar-50/a.rar"), Some("rar2hashcat.py"));
    assert_eq!(script("tests/fixtures/rar-13/A.RAR"), Some("rar2hashcat.py"));
    assert_eq!(script("tests/fixtures/rar-50/a.sfx"), Some("rar2hashcat.py"));
    assert_eq!(script("tests/fixtures/7z-aes/a.7z"), Some("7z2hashcat.py"));
    assert_eq!(script("tests/fixtures/passwords.json"), None);
    assert_eq!(script("tests/fixtures/no_extension"), None);

    // and every file under the fixtures is an archive of a known format, or one of the two that describe them
    let (archives, unknown) = fixtures().unwrap();
    assert!(unknown.is_empty(), "{unknown:?}");
    for (index, format) in FORMATS.iter().enumerate() {
        assert!(archives.iter().any(|(_, of)| *of == index), "no {} fixture", format.name);
    }
}

#[test]
fn every_known_difference_names_a_fixture_and_says_why() {
    let known = known_differences().unwrap_or_else(|fault| panic!("{fault}"));
    for ((fixture, _), why) in &known {
        assert!(Path::new(support::FIXTURES).join(fixture).is_file(), "{fixture}: listed in {KNOWN_DIFFERENCES} and not a fixture");
        assert!(!why.is_empty(), "{fixture}: listed in {KNOWN_DIFFERENCES} without a reason");
    }
}
