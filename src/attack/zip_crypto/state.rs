//! What a run keeps so that another goes on from it.
//!
//! The candidates of a search stand in a fixed order, so how far a search came is one number:
//! the first candidate that was not searched. A run that is given `--state FILE` writes that
//! number every few seconds, with the attempts that ran to their end and the keys they left.
//! A run that is given `--resume` as well starts where the file says, and runs no attempt
//! again that ended without keys.
//!
//! An attempt is known by what it searches and not by its place in the plan, which depends on
//! the speed of the machine: the entry, the run and everything the search takes as known of
//! the stream. The file as a whole is known by the entries of the archives and by the part of
//! every search that the machine takes, and a file of anything else is refused.
//!
//! The file is written new beside itself and moved into its place, so a run that dies while
//! it writes leaves the state it had before. A run that dies between two writes loses the
//! candidates since the last one.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Mutex;

use anyhow::Context as _;
use archivewolf_zip_crypto::Keys;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest as _;

use super::headers::Special;
use super::plan::Attempt;
use super::pool::Pool;
use super::search::Found;
use crate::formats::zip::known::claim::Cells;

/// The form of the file. A file of another form is refused.
const VERSION: u32 = 1;

/// How many bytes of a SHA-256 name an attempt and a set of archives.
const NAME_BYTES: usize = 16;

/// The search that was running when the state was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Running {
    /// The attempt, by its name.
    attempt: String,
    /// Which of its searches, counted from zero.
    search: u64,
    /// The first candidate of that search that was not searched.
    next: u64,
}

/// Keys an attempt found that nothing proves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Left {
    /// The attempt, by its name.
    attempt: String,
    /// The three keys.
    keys: [u32; 3],
    /// The candidate that gave them.
    candidate: u64,
    /// How many bits speak for them.
    bits: f64,
}

/// The file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
struct Kept {
    /// The form of the file.
    version: u32,
    /// What the state is of: the entries of the archives, and the part of every search.
    of: String,
    /// The attempts that ran to their end without proved keys.
    ended: BTreeSet<String>,
    /// The keys they found that nothing proves.
    unproved: Vec<Left>,
    /// The search that was running.
    running: Option<Running>,
    /// Keys that are proved: the run that found them had its result.
    proved: Option<[u32; 3]>,
}

/// A hash over fields, each with its length in front, so that no two lists of fields give
/// the same bytes.
struct Mark(sha2::Sha256);

impl Mark {
    /// A hash of one kind of thing.
    fn new(kind: &str) -> Self {
        let mut mark = Self(sha2::Sha256::new());
        mark.bytes(kind.as_bytes());
        mark
    }

    fn number(&mut self, value: u64) {
        self.0.update(value.to_le_bytes());
    }

    fn bytes(&mut self, bytes: &[u8]) {
        self.number(bytes.len() as u64);
        self.0.update(bytes);
    }

    /// The name the fields give: the first bytes of the hash, in hex.
    fn name(self) -> String {
        self.0.finalize().iter().take(NAME_BYTES).fold(String::with_capacity(2 * NAME_BYTES), |mut name, byte| {
            let _ = write!(name, "{byte:02x}");
            name
        })
    }
}

/// The name of an attempt: the same for the same search of the same entry, whatever its place
/// in the plan and whatever claim it came from.
#[must_use]
pub(crate) fn name(attempt: &Attempt) -> String {
    let mut mark = Mark::new("attempt");
    match attempt.special {
        Some(Special::InfoZip { archive }) => {
            mark.bytes(b"info-zip");
            mark.number(archive as u64);
            return mark.name();
        },
        Some(Special::DotNet { archive }) => {
            mark.bytes(b"dot-net");
            mark.number(archive as u64);
            return mark.name();
        },
        Some(Special::Clocked { archive }) => {
            mark.bytes(b"clocked");
            mark.number(archive as u64);
            return mark.name();
        },
        None => {},
    }
    mark.number(attempt.target as u64);
    mark.bytes(attempt.path.as_str().as_bytes());
    mark.bytes(&attempt.run.at.to_le_bytes());
    mark.number(attempt.run.len);
    mark.number(attempt.run.searches);
    mark.number(u64::from(attempt.run.holes));
    mark.number(u64::from(attempt.short_only));
    for piece in attempt.form.pieces() {
        mark.bytes(&piece.at.to_le_bytes());
        match &piece.cells {
            Cells::Bytes(bytes) => {
                mark.bytes(b"bytes");
                mark.bytes(bytes);
            },
            Cells::Sets(sets) => {
                mark.bytes(b"sets");
                mark.number(sets.len() as u64);
                for set in sets {
                    mark.bytes(&set.to_bytes());
                }
            },
            Cells::Fill(set, len) => {
                mark.bytes(b"fill");
                mark.bytes(&set.to_bytes());
                mark.number(*len);
            },
        }
    }
    mark.name()
}

/// The name of what a state is of: the entries the attack works on, and the part of every
/// search that this machine takes.
fn of(pool: &Pool, slice: Option<(u32, u32)>) -> String {
    let mut mark = Mark::new("archives");
    let (part, parts) = slice.unwrap_or((1, 1));
    mark.number(u64::from(part));
    mark.number(u64::from(parts));
    for target in &pool.targets {
        mark.number(target.archive as u64);
        mark.bytes(target.name.as_bytes());
        mark.number(u64::from(target.entry.crc32));
        mark.number(target.entry.compressed_size);
        mark.number(target.entry.uncompressed_size);
        mark.bytes(&target.header);
    }
    mark.name()
}

/// The state of one run, in memory and in its file.
#[derive(Debug)]
pub(crate) struct State {
    path: PathBuf,
    kept: Mutex<Kept>,
}

impl State {
    /// The state of a run on the entries of `pool`, kept in the file at `path`.
    ///
    /// A run that starts anew takes a place where nothing is, as `-o` does. One that goes on
    /// reads the file, and refuses one that is not the state of these archives and of this
    /// part of the search. Either way the file is written once before anything is searched,
    /// so that a place that cannot be written ends the command at its start.
    pub(crate) fn open(path: &Path, pool: &Pool, slice: Option<(u32, u32)>, resume: bool) -> anyhow::Result<Self> {
        let shown = path.display();
        let there = std::fs::symlink_metadata(path).ok();
        anyhow::ensure!(!there.as_ref().is_some_and(|there| there.file_type().is_symlink()), "--state {shown}: a symbolic link is not followed");
        let of = of(pool, slice);
        let kept = if resume {
            let text = std::fs::read_to_string(path).with_context(|| format!("--resume: {shown} cannot be read"))?;
            let kept: Kept = serde_json::from_str(&text).with_context(|| format!("--resume: {shown} is not a state of this command"))?;
            anyhow::ensure!(kept.version == VERSION, "--resume: {shown} is a state of form {}, and this command reads form {VERSION}", kept.version);
            anyhow::ensure!(kept.of == of, "--resume: {shown} is the state of other archives, or of another part of the search (--slice): nothing of it holds here");
            kept
        } else {
            anyhow::ensure!(there.is_none(), "--state {shown}: the file exists. --resume goes on from it, and a run that starts anew takes a file that is not there");
            Kept { version: VERSION, of, ..Kept::default() }
        };
        let state = Self { path: path.to_owned(), kept: Mutex::new(kept) };
        state.change(|_| {})?;
        Ok(state)
    }

    /// Change what is kept, and write it.
    fn change(&self, change: impl FnOnce(&mut Kept)) -> anyhow::Result<()> {
        let Ok(mut kept) = self.kept.lock() else { anyhow::bail!("the state is held by a thread that failed") };
        change(&mut kept);
        let mut beside = self.path.clone().into_os_string();
        beside.push(".new");
        let beside = PathBuf::from(beside);
        let shown = self.path.display();
        // what a run that died while it wrote left behind: created new, a link is not followed
        drop(std::fs::remove_file(&beside));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&beside).with_context(|| format!("--state {shown}: {} cannot be created", beside.display()))?;
        let text = serde_json::to_string(&*kept).context("the state cannot be written as JSON")?;
        file.write_all(text.as_bytes()).and_then(|()| file.write_all(b"\n")).and_then(|()| file.sync_all()).with_context(|| format!("--state {shown}: {} cannot be written", beside.display()))?;
        drop(file);
        std::fs::rename(&beside, &self.path).with_context(|| format!("--state {shown}: the file cannot be put in its place"))
    }

    /// What is kept, read under its lock.
    fn read<T>(&self, read: impl FnOnce(&Kept) -> T) -> Option<T> {
        self.kept.lock().ok().map(|kept| read(&kept))
    }

    /// Whether the attempt ran to its end without proved keys in a run before.
    #[must_use]
    pub(crate) fn has_ended(&self, attempt: &str) -> bool {
        self.read(|kept| kept.ended.contains(attempt)).unwrap_or(false)
    }

    /// Where the attempt goes on: which of its searches, and from which candidate. `None` for
    /// an attempt that was not running when the state was written.
    #[must_use]
    pub(crate) fn point(&self, attempt: &str) -> Option<(u64, u64)> {
        self.read(|kept| kept.running.as_ref().filter(|running| running.attempt == attempt).map(|running| (running.search, running.next)))?
    }

    /// The keys the attempt found before that nothing proves.
    #[must_use]
    pub(crate) fn left_by(&self, attempt: &str) -> Vec<Found> {
        let found = |left: &Left| {
            let [x, y, z] = left.keys;
            Found { keys: Keys::new(x, y, z), candidate: usize::try_from(left.candidate).unwrap_or(usize::MAX), bits: left.bits, proved_on: None }
        };
        self.read(|kept| kept.unproved.iter().filter(|left| left.attempt == attempt).map(found).collect()).unwrap_or_default()
    }

    /// The keys a run before proved.
    #[must_use]
    pub(crate) fn proved(&self) -> Option<Keys> {
        self.read(|kept| kept.proved.map(|[x, y, z]| Keys::new(x, y, z)))?
    }

    /// The attempt came to candidate `next` of its search number `search`.
    pub(crate) fn came_to(&self, attempt: &str, search: u64, next: u64) -> anyhow::Result<()> {
        self.change(|kept| kept.running = Some(Running { attempt: attempt.to_owned(), search, next }))
    }

    /// The attempt found keys that nothing proves.
    pub(crate) fn left(&self, attempt: &str, found: &[Found]) -> anyhow::Result<()> {
        if found.is_empty() {
            return Ok(());
        }
        self.change(|kept| {
            for found in found {
                let keys = [found.keys.x, found.keys.y, found.keys.z];
                if !kept.unproved.iter().any(|left| left.attempt == attempt && left.keys == keys) {
                    kept.unproved.push(Left { attempt: attempt.to_owned(), keys, candidate: found.candidate as u64, bits: found.bits });
                }
            }
        })
    }

    /// The attempt ran to its end without proved keys.
    pub(crate) fn ended(&self, attempt: &str) -> anyhow::Result<()> {
        self.change(|kept| {
            let _ = kept.ended.insert(attempt.to_owned());
            if kept.running.as_ref().is_some_and(|running| running.attempt == attempt) {
                kept.running = None;
            }
        })
    }

    /// The run found proved keys.
    pub(crate) fn found(&self, keys: Keys) -> anyhow::Result<()> {
        self.change(|kept| kept.proved = Some([keys.x, keys.y, keys.z]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::zip_crypto::plan::Path as Way;
    use crate::formats::zip::known::claim::Certainty;
    use crate::formats::zip::known::claim::Form;
    use crate::formats::zip::known::claim::Origin;
    use crate::formats::zip::known::claim::Run;
    use crate::formats::zip::known::set::ByteSet;

    fn pool(name: &str) -> Pool {
        Pool::read(&[PathBuf::from(format!("tests/fixtures/zip-crypto/{name}"))], &|_| None).unwrap()
    }

    fn attempt(form: Form) -> Attempt {
        let run = form.best_run(false).unwrap();
        Attempt { target: 0, path: Way::Run, origin: Origin::User, certainty: Certainty::Likely, what: "bytes".to_owned(), form, run, candidates: 1.0, counted: false, chance: 0.5, behind: 0.0, short_only: false, special: None }
    }

    #[test]
    fn an_attempt_is_named_by_what_it_searches() {
        let first = attempt(Form::bytes(0, b"0123456789abcdef"));
        // where the claim came from, how it is worded and what it is estimated at change nothing
        let same = Attempt { origin: Origin::Name, certainty: Certainty::Guess, what: "other words".to_owned(), candidates: 9.0, counted: true, chance: 0.1, behind: 3.0, ..first.clone() };
        assert_eq!(name(&first), name(&same));
        assert_eq!(name(&first).len(), 2 * NAME_BYTES);

        // every part of the search does
        let mut others = vec![
            attempt(Form::bytes(0, b"0123456789abcdeX")),
            attempt(Form::bytes(1, b"0123456789abcdef")),
            Attempt { target: 1, ..first.clone() },
            Attempt { path: Way::ShortRun, ..first.clone() },
            Attempt { short_only: true, ..first.clone() },
            Attempt { run: Run { len: first.run.len - 1, ..first.run }, ..first.clone() },
            Attempt { special: Some(Special::InfoZip { archive: 0 }), ..first.clone() },
            Attempt { special: Some(Special::DotNet { archive: 0 }), ..first.clone() },
            Attempt { special: Some(Special::InfoZip { archive: 1 }), ..first.clone() },
        ];
        // a class behind the run, and a byte of the run that is one of two
        let mut classed = Form::bytes(0, b"0123456789abcdef");
        assert!(classed.add(16, Cells::Fill(ByteSet::text(), 100)));
        others.push(Attempt { form: classed, ..first.clone() });
        let mut either = Form::bytes(0, b"0123456789abcde");
        assert!(either.add(15, Cells::Sets(vec![ByteSet::from_values(*b"fF")])));
        others.push(Attempt { form: either, ..first.clone() });

        let mut names: Vec<String> = others.iter().map(name).collect();
        names.push(name(&first));
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn a_state_is_of_its_archives_and_of_its_part_of_the_search() {
        let (secrets, six) = (pool("bkcrack-src_secrets.zip"), pool("gen_infozip_six.zip"));
        assert_eq!(of(&secrets, None), of(&secrets, Some((1, 1))));
        assert_ne!(of(&secrets, None), of(&six, None));
        assert_ne!(of(&secrets, Some((1, 4))), of(&secrets, Some((2, 4))));
        assert_ne!(of(&secrets, Some((1, 4))), of(&secrets, Some((1, 2))));
    }

    #[test]
    fn what_a_run_keeps_is_what_the_next_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let pool = pool("bkcrack-src_secrets.zip");
        let keys = Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31);
        let left = Found { keys, candidate: 7, bits: 104.0, proved_on: Some(1) };

        let state = State::open(&path, &pool, None, false).unwrap();
        assert!(path.is_file());
        assert!(!state.has_ended("a") && state.point("a").is_none() && state.left_by("a").is_empty() && state.proved().is_none());
        state.came_to("a", 0, 4096).unwrap();
        state.left("a", &[left, left]).unwrap();
        state.left("a", &[]).unwrap();
        state.ended("a").unwrap();
        state.came_to("b", 3, 64).unwrap();
        drop(state);
        // nothing is left beside the file
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);

        // a run that starts anew does not take the place of a state that is there
        let refused = State::open(&path, &pool, None, false).unwrap_err().to_string();
        assert!(refused.contains("the file exists. --resume goes on from it"), "{refused}");

        let state = State::open(&path, &pool, None, true).unwrap();
        assert!(state.has_ended("a") && !state.has_ended("b"));
        assert_eq!(state.point("a"), None);
        assert_eq!(state.point("b"), Some((3, 64)));
        // the entry keys were proved on is not kept: they were not proved
        assert_eq!(state.left_by("a"), [Found { proved_on: None, ..left }]);
        assert!(state.left_by("b").is_empty());
        // the attempt that was running ends: nothing is running
        state.ended("b").unwrap();
        assert_eq!(state.point("b"), None);
        state.found(keys).unwrap();
        drop(state);
        assert_eq!(State::open(&path, &pool, None, true).unwrap().proved(), Some(keys));
    }

    #[test]
    fn a_state_of_something_else_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let (pool, other) = (pool("bkcrack-src_secrets.zip"), pool("gen_infozip_six.zip"));
        let refused = |resume: bool, slice| State::open(&path, &pool, slice, resume).unwrap_err().to_string();

        // nothing to go on from
        assert!(refused(true, None).contains("cannot be read"));
        drop(State::open(&path, &pool, Some((1, 4)), false).unwrap());
        // another part of the search, and other archives
        assert!(refused(true, Some((2, 4))).contains("another part of the search"));
        assert!(refused(true, None).contains("another part of the search"));
        assert!(State::open(&path, &other, Some((1, 4)), true).unwrap_err().to_string().contains("the state of other archives"));
        // a file that is no state, and one of another form
        std::fs::write(&path, "{ not json").unwrap();
        assert!(refused(true, None).contains("is not a state of this command"));
        std::fs::write(&path, serde_json::to_string(&Kept { version: VERSION + 1, of: of(&pool, None), ..Kept::default() }).unwrap()).unwrap();
        assert!(refused(true, None).contains("a state of form 2"));
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_the_place_of_the_state_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let (aim, link) = (dir.path().join("aim.json"), dir.path().join("state.json"));
        let pool = pool("bkcrack-src_secrets.zip");
        drop(State::open(&aim, &pool, None, false).unwrap());
        let before = std::fs::read(&aim).unwrap();
        std::os::unix::fs::symlink(&aim, &link).unwrap();
        for resume in [false, true] {
            let refused = State::open(&link, &pool, None, resume).unwrap_err().to_string();
            assert!(refused.contains("a symbolic link is not followed"), "{refused}");
        }
        assert_eq!(std::fs::read(&aim).unwrap(), before);
    }
}
