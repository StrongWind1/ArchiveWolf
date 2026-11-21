//! The runs over archives: scan the paths, analyse each archive, and print what `info` or `hash`
//! is asked for.
//!
//! Connects the scanner, the code of each format and the output. An archive is opened and
//! reported on its own: one that cannot be read, parsed or processed is named on standard error
//! and the run goes on with the next.
//!
//! Standard output is the result of a run. When whoever reads it closes it, as `head` does, the
//! run is over: it stops without a word and without a failure, with what it wrote.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::io::Write;
use std::path::PathBuf;

use crate::analysis::Analysed;
use crate::analysis::Format;
use crate::cli::ExitStatus;
use crate::formats::source::Source;
use crate::line::Lines;
use crate::output::info_json;
use crate::output::info_text;
use crate::output::line_json;
use crate::output::line_note;
use crate::output::line_origin;
use crate::output::no_line_notes;
use crate::output::sanitize;
use crate::scanner::ScanResult;
use crate::scanner::scan_paths;

/// What a run over the given paths came to. The exit status is computed from these counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunSummary {
    /// Archives that were found and handed to the code of their format.
    pub archives: usize,
    /// Archives that could not be processed, and paths that could not be read.
    pub failed: usize,
    /// Whether the result could not be written: an error on standard output other than its
    /// reader closing it.
    pub output_failed: bool,
}

impl RunSummary {
    /// The exit status of a run, by the order of precedence of the command-line contract:
    /// a failure (2) before success (0), and "nothing done" (1) only when no archive was
    /// processed at all or the result could not be written.
    #[must_use]
    pub const fn exit_status(&self) -> ExitStatus {
        if self.archives == 0 || self.output_failed {
            ExitStatus::NothingDone
        } else if self.failed > 0 {
            ExitStatus::ArchiveFailed
        } else {
            ExitStatus::Success
        }
    }
}

/// What `info` is asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InfoRequest {
    /// A row for each entry below the block of its archive.
    pub entries: bool,
    /// One JSON object for each archive in the place of the block.
    pub json: bool,
}

/// What `hash` is asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HashRequest {
    /// A line for every encrypted entry or folder, not only for the best one of each archive.
    pub all: bool,
    /// Only the lines of this hashcat mode.
    pub mode: Option<u32>,
    /// One JSON object for each line in the place of the line.
    pub json: bool,
    /// No notes on standard error: neither the count of lines nor what a line cannot prove.
    pub quiet: bool,
}

/// How writing the result of a run has gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    /// Everything so far was written.
    Open,
    /// The reader closed the output. That is the end of the run and no failure.
    Closed,
    /// The output failed in another way, which was said on standard error.
    Failed,
}

/// Where a run writes its result. The first error ends the writing: nothing is written after
/// it, and the run stops with the archive it is at.
struct Output<'a> {
    to: &'a mut dyn Write,
    flow: Flow,
}

impl<'a> Output<'a> {
    fn new(to: &'a mut dyn Write) -> Self {
        Self { to, flow: Flow::Open }
    }

    /// Write `text` and then `end`. `false` when that could not be written, now or before: the
    /// caller has nothing more to do.
    fn put(&mut self, text: &str, end: &str) -> bool {
        if self.flow != Flow::Open {
            return false;
        }
        match self.to.write_all(text.as_bytes()).and_then(|()| self.to.write_all(end.as_bytes())).and_then(|()| self.to.flush()) {
            Ok(()) => true,
            // `head` and its like close the pipe when they have what they want
            Err(error) if error.kind() == ErrorKind::BrokenPipe => {
                self.flow = Flow::Closed;
                false
            },
            Err(error) => {
                eprintln!("archivewolf: cannot write to standard output: {error}");
                self.flow = Flow::Failed;
                false
            },
        }
    }

    /// Write `text`, which brings its own line ends.
    fn write(&mut self, text: &str) -> bool {
        self.put(text, "")
    }

    /// Write `text` and end the line. A hash line can be megabytes long and is not copied for it.
    fn line(&mut self, text: &str) -> bool {
        self.put(text, "\n")
    }
}

/// Run `info`: for every archive its analysis, as a block of text or as one JSON object. The
/// lines it names are the ones `hash` writes without `--all`.
#[must_use]
pub fn run_info(paths: &[PathBuf], request: InfoRequest) -> RunSummary {
    run_info_to(paths, request, &mut std::io::stdout().lock())
}

/// [`run_info`] with the place its result goes to.
fn run_info_to(paths: &[PathBuf], request: InfoRequest, to: &mut dyn Write) -> RunSummary {
    let mut out = Output::new(to);
    let mut first = true;
    run(paths, Lines::Best, &mut out, |analysed, out| {
        if request.json {
            let _ = out.line(&info_json(&analysed.analysis));
        } else {
            // an empty line between two blocks
            if !first {
                let _ = out.line("");
            }
            first = false;
            let _ = out.write(&info_text(&analysed.analysis, request.entries));
        }
    })
}

/// Run `hash`: the hash lines of every archive on standard output, one on a line, in the order
/// of the paths, and nothing else there. Standard error gets a note for every scheme or entry
/// without a line and for every line that proves less than a full check, each with the path of
/// its archive, and at the end a count of the lines by mode.
#[must_use]
pub fn run_hash(paths: &[PathBuf], request: HashRequest) -> RunSummary {
    run_hash_to(paths, request, &mut std::io::stdout().lock())
}

/// [`run_hash`] with the place its lines go to.
fn run_hash_to(paths: &[PathBuf], request: HashRequest, to: &mut dyn Write) -> RunSummary {
    let mut out = Output::new(to);
    let mut written: BTreeMap<u32, usize> = BTreeMap::new();
    let mut care_noted = false;

    let summary = run(paths, if request.all { Lines::All } else { Lines::Best }, &mut out, |analysed, out| {
        let Analysed { analysis, lines } = analysed;
        if !request.quiet {
            for note in no_line_notes(analysis, request.all) {
                eprintln!("{}", sanitize(&note));
            }
        }
        for line in lines.iter().filter(|line| request.mode.is_none_or(|mode| line.mode == mode)) {
            if !request.quiet {
                if !care_noted {
                    eprintln!("Note: hash lines hold encrypted data of their archives. Handle them with the same care as the archives.");
                    care_noted = true;
                }
                if let Some(note) = line_note(analysis, line) {
                    eprintln!("{}", sanitize(&note));
                }
            }
            let text = if request.json { Cow::Owned(line_json(&analysis.path, line)) } else { sanitize(&line.text) };
            if !out.line(&text) {
                return;
            }
            // with `-v`, where each line comes from
            tracing::info!("{}: {}", analysis.path, line_origin(analysis, line.tag, line.mode, line.proves, line.entry));
            *written.entry(line.mode).or_default() += 1;
        }
    });

    // a run that was cut off by its reader ends without a word
    if !request.quiet && summary.archives > 0 && out.flow == Flow::Open {
        eprintln!("archivewolf: {}", count_by_mode(&written));
    }
    summary
}

/// How many lines were written, and how many of each mode: one sentence for standard error.
fn count_by_mode(written: &BTreeMap<u32, usize>) -> String {
    let total: usize = written.values().sum();
    if total == 0 {
        return "no hash lines".to_owned();
    }
    let by_mode: Vec<String> = written.iter().map(|(mode, count)| format!("{count} of mode {mode}")).collect();
    format!("{total} hash line{}: {}", if total == 1 { "" } else { "s" }, by_mode.join(", "))
}

/// Runs the work on one archive so that a panic in it ends that archive and not the process.
///
/// The parsers are written not to panic on any input. This is the second line: while an
/// archive is being processed, a panic is caught, its place and message are kept for one
/// line of output, and the banner of the default hook is not printed. Outside of that the
/// default hook runs as always.
pub(crate) mod isolate {
    use std::backtrace::Backtrace;
    use std::backtrace::BacktraceStatus;
    use std::panic::AssertUnwindSafe;
    use std::panic::PanicHookInfo;
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::Once;
    use std::sync::PoisonError;
    use std::thread::ThreadId;

    /// A panic that was caught.
    #[derive(Debug)]
    pub(crate) struct Panicked {
        /// Where it was raised and what it said, on one line.
        pub summary: String,
        /// The backtrace, when `RUST_BACKTRACE` asks for one.
        pub backtrace: Option<String>,
    }

    /// What the hook does while an archive is being processed.
    struct Capture {
        /// The thread that processes the archive.
        owner: ThreadId,
        /// The first panic seen.
        panicked: Option<Panicked>,
    }

    /// Set while an archive is being processed.
    static CAPTURE: Mutex<Option<Capture>> = Mutex::new(None);
    /// Held by the one caller that is processing an archive.
    static TURN: Mutex<()> = Mutex::new(());
    static HOOK: Once = Once::new();

    fn capture() -> MutexGuard<'static, Option<Capture>> {
        CAPTURE.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn describe(info: &PanicHookInfo<'_>) -> Panicked {
        let message = info.payload_as_str().unwrap_or("(no message)");
        let summary = info.location().map_or_else(|| format!("panicked: {message}"), |at| format!("panicked at {}:{}:{}: {message}", at.file(), at.line(), at.column()));
        let trace = Backtrace::capture();
        let backtrace = (trace.status() == BacktraceStatus::Captured).then(|| trace.to_string());
        Panicked { summary, backtrace }
    }

    /// Put a hook in front of the default one, once for the process.
    fn install_hook() {
        HOOK.call_once(|| {
            let default = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                let mut slot = capture();
                // the archive is processed on the thread that asked and on the worker pool
                let ours = slot.as_ref().is_some_and(|held| held.owner == std::thread::current().id() || rayon::current_thread_index().is_some());
                match slot.as_mut() {
                    Some(held) if ours => {
                        if held.panicked.is_none() {
                            held.panicked = Some(describe(info));
                        }
                    },
                    _ => {
                        drop(slot);
                        default(info);
                    },
                }
            }));
        });
    }

    /// Run `work`. A panic in it comes back as an error instead of unwinding further.
    pub(crate) fn run<T>(work: impl FnOnce() -> T) -> Result<T, Panicked> {
        install_hook();
        let _turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
        *capture() = Some(Capture { owner: std::thread::current().id(), panicked: None });
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(work));
        let held = capture().take();
        outcome.map_err(|_| held.and_then(|held| held.panicked).unwrap_or_else(|| Panicked { summary: "panicked".to_owned(), backtrace: None }))
    }
}

/// Say on standard error that `path` could not be dealt with, on one line.
fn report_failure(path: &std::path::Path, what: &str) {
    eprintln!("archivewolf: {}", sanitize(&format!("{}: {what}", path.display())));
}

/// Open one archive and run the code of its format over it.
///
/// The archive is opened here and closed when its analysis is built, so a run holds one archive
/// at a time. A ZIP archive is found from its end, and its parser takes the offsets of the
/// whole file. RAR and 7z start at their signature, with the program of a self-extracting
/// archive left off.
fn analyse(found: &ScanResult, wanted: Lines) -> anyhow::Result<Analysed> {
    let start = match found.kind {
        Format::Zip => 0,
        Format::Rar | Format::SevenZ => u64::try_from(found.sfx_offset)?,
    };
    let source = Source::open(&found.path, start).map_err(|error| anyhow::anyhow!("cannot read the file: {error}"))?;

    match found.kind {
        Format::Zip => crate::formats::zip::analyse::analyse(&source, wanted),
        Format::Rar => crate::formats::rar::analyse::analyse(&source, wanted),
        Format::SevenZ => crate::formats::sevenz::analyse::analyse(&source, wanted),
    }
}

/// Scan the paths and analyse every archive found, one at a time and each on its own: an
/// archive that cannot be read, parsed or processed is reported on one line and the run
/// goes on with the next. `print` gets every archive that was analysed, with its lines, and
/// the place to write to. The run ends when that place takes no more.
fn run(paths: &[PathBuf], wanted: Lines, out: &mut Output<'_>, mut print: impl FnMut(&Analysed, &mut Output<'_>)) -> RunSummary {
    let scan = scan_paths(paths);
    let mut summary = RunSummary::default();

    for error in &scan.errors {
        report_failure(&error.path, &error.message);
        summary.failed += 1;
    }
    // a file that was named and is no archive is said, and is no failure of the run
    for path in &scan.not_archives {
        tracing::warn!("{}: not an archive", path.display());
    }

    if scan.archives.is_empty() {
        eprintln!("archivewolf: no archives found in the given paths");
        eprintln!("  Hint: archives are detected by magic bytes, not file extension");
        return summary;
    }

    for found in &scan.archives {
        summary.archives += 1;
        match isolate::run(|| analyse(found, wanted)) {
            Ok(Ok(analysed)) => print(&analysed, out),
            Ok(Err(error)) => {
                report_failure(&found.path, &error.to_string());
                eprintln!("  Hint: the file may be damaged, or laid out in a way the tool does not read");
                summary.failed += 1;
            },
            Err(panicked) => {
                report_failure(&found.path, &format!("internal error: {}", panicked.summary));
                if let Some(backtrace) = &panicked.backtrace {
                    eprintln!("{backtrace}");
                }
                summary.failed += 1;
            },
        }
        if out.flow != Flow::Open {
            break;
        }
    }

    summary.output_failed = out.flow == Flow::Failed;
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_status_follows_the_order_of_precedence() {
        let run = |archives, failed| RunSummary { archives, failed, output_failed: false }.exit_status();

        assert_eq!(run(3, 0), ExitStatus::Success);
        assert_eq!(run(3, 1), ExitStatus::ArchiveFailed);
        assert_eq!(run(1, 1), ExitStatus::ArchiveFailed, "the one archive found did not parse");

        // nothing was processed at all: no archive found, or the path given does not exist
        assert_eq!(run(0, 0), ExitStatus::NothingDone);
        assert_eq!(run(0, 2), ExitStatus::NothingDone);

        // a result that could not be written is a run that failed as a whole
        assert_eq!(RunSummary { archives: 3, failed: 0, output_failed: true }.exit_status(), ExitStatus::NothingDone);
        assert_eq!(RunSummary { archives: 3, failed: 1, output_failed: true }.exit_status(), ExitStatus::NothingDone);
    }

    #[test]
    fn the_count_of_lines_names_every_mode() {
        assert_eq!(count_by_mode(&BTreeMap::new()), "no hash lines");
        assert_eq!(count_by_mode(&BTreeMap::from([(46100, 1)])), "1 hash line: 1 of mode 46100");
        assert_eq!(count_by_mode(&BTreeMap::from([(46900, 2), (46100, 3), (46320, 1)])), "6 hash lines: 3 of mode 46100, 1 of mode 46320, 2 of mode 46900");
    }

    #[test]
    fn a_panic_in_one_archive_is_caught_and_described() {
        let caught = isolate::run(|| -> u32 { panic!("entry {} is out of range", 7) }).unwrap_err();
        assert!(caught.summary.starts_with(&format!("panicked at {}:", file!())), "{}", caught.summary);
        assert!(caught.summary.ends_with(": entry 7 is out of range"), "{}", caught.summary);
        assert!(!caught.summary.contains('\n'), "{}", caught.summary);

        // and the next archive is processed as if nothing had happened
        assert_eq!(isolate::run(|| 41 + 1).unwrap(), 42);
    }

    #[test]
    fn a_panic_on_the_worker_pool_is_caught_too() {
        use rayon::iter::IntoParallelIterator as _;
        use rayon::iter::ParallelIterator as _;

        let caught = isolate::run(|| (0..64_u32).into_par_iter().map(|n| if n == 40 { panic!("worker {n} failed") } else { n }).sum::<u32>()).unwrap_err();
        assert!(caught.summary.contains("worker 40 failed"), "{}", caught.summary);
        assert_eq!(isolate::run(|| (0..64_u32).into_par_iter().sum::<u32>()).unwrap(), 2016);
    }

    #[test]
    fn overflow_in_a_parser_is_caught_like_any_panic() {
        // what an unchecked addition on a size from a file does with overflow checks on
        let size = std::hint::black_box(u32::MAX);
        let caught = isolate::run(|| size + std::hint::black_box(1)).unwrap_err();
        assert!(caught.summary.contains("attempt to add with overflow"), "{}", caught.summary);
    }

    #[test]
    fn one_archive_is_read_and_processed_from_its_signature() {
        use crate::analysis::Format;
        use crate::line::Tag;

        // a self-extracting RAR archive whose program mentions "Rar!" before the archive starts
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decoy.exe");
        let mut data = b"MZ\x90\x00 stub text mentioning Rar! archives ".to_vec();
        data.resize(44, 0);
        data.extend_from_slice(&std::fs::read("tests/fixtures/rar-50/v730_p_m3.rar").unwrap());
        std::fs::write(&path, &data).unwrap();

        let Analysed { analysis, lines } = analyse(&ScanResult { path: path.clone(), kind: Format::Rar, sfx_offset: 44 }, Lines::Best).unwrap();
        assert_eq!((analysis.format, analysis.offset), (Format::Rar, 44), "the archive starts behind the program");
        assert_eq!(analysis.path, path.display().to_string());
        assert_eq!(lines.len(), 1);
        assert_eq!((lines[0].tag, lines[0].mode), (Tag::Rar50, 46800));

        // the line is the one the bare archive gives
        let bare = analyse(&ScanResult { path: PathBuf::from("tests/fixtures/rar-50/v730_p_m3.rar"), kind: Format::Rar, sfx_offset: 0 }, Lines::Best).unwrap();
        assert_eq!(bare.lines[0].text, lines[0].text);
        assert_eq!(bare.analysis.offset, 0);

        // a file that is gone by the time it is processed is an error for that archive
        std::fs::remove_file(&path).unwrap();
        let error = analyse(&ScanResult { path, kind: Format::Rar, sfx_offset: 44 }, Lines::Best).unwrap_err();
        assert!(error.to_string().starts_with("cannot read the file"), "{error}");
    }

    #[test]
    fn a_run_counts_what_was_found_and_what_failed() {
        let dir = tempfile::tempdir().unwrap();
        let copy = |rel: &str, name: &str| {
            let _ = std::fs::copy(format!("tests/fixtures/{rel}"), dir.path().join(name)).unwrap();
        };
        copy("zip-crypto/zipcrypto.zip", "a.zip");
        copy("unencrypted/plain.7z", "b.7z");
        std::fs::write(dir.path().join("c.zip"), b"PK\x03\x04 and nothing that follows a local header").unwrap();

        let paths = [dir.path().to_path_buf()];
        let counted = |archives, failed| RunSummary { archives, failed, output_failed: false };
        let mut written = Vec::new();
        assert_eq!(run_info_to(&paths, InfoRequest { json: true, ..InfoRequest::default() }, &mut written), counted(3, 1));
        assert_eq!(String::from_utf8(written).unwrap().lines().count(), 2, "an object for each archive that was analysed");
        let mut written = Vec::new();
        assert_eq!(run_hash_to(&paths, HashRequest { quiet: true, ..HashRequest::default() }, &mut written), counted(3, 1));
        assert_eq!(String::from_utf8(written).unwrap().lines().count(), 1, "the line of the one archive that is encrypted");

        let missing = [dir.path().join("absent.zip")];
        let mut written = Vec::new();
        assert_eq!(run_info_to(&missing, InfoRequest::default(), &mut written), counted(0, 1));
        assert_eq!(run_hash_to(&missing, HashRequest::default(), &mut written), counted(0, 1));
        assert!(written.is_empty());
    }

    /// Standard output as a reader leaves it who has had enough: it takes so many lines and
    /// then fails every write with the error it is given.
    struct Reader {
        takes: usize,
        then: ErrorKind,
        got: Vec<u8>,
        refused: usize,
    }

    impl Write for Reader {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.got.split(|&byte| byte == b'\n').count() > self.takes {
                self.refused += 1;
                return Err(std::io::Error::from(self.then));
            }
            self.got.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Five archives, each with a line.
    fn five_archives() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a.zip", "b.zip", "c.zip", "d.zip", "e.zip"] {
            let _ = std::fs::copy("tests/fixtures/zip-crypto/zipcrypto.zip", dir.path().join(name)).unwrap();
        }
        dir
    }

    #[test]
    fn a_reader_that_closes_the_output_ends_the_run_and_is_no_failure() {
        let dir = five_archives();
        let paths = [dir.path().to_path_buf()];

        // the reader takes the first line and closes: the run stops at the second archive
        let mut reader = Reader { takes: 1, then: ErrorKind::BrokenPipe, got: Vec::new(), refused: 0 };
        let summary = run_hash_to(&paths, HashRequest { quiet: true, ..HashRequest::default() }, &mut reader);
        assert_eq!(summary, RunSummary { archives: 2, failed: 0, output_failed: false });
        assert_eq!(summary.exit_status(), ExitStatus::Success);
        let taken = String::from_utf8(reader.got).unwrap();
        assert!(taken.starts_with("$zip$1$*") && taken.ends_with("$/zip$\n") && taken.lines().count() == 1, "{taken}");
        assert_eq!(reader.refused, 1, "one write was tried after it and no more");

        let mut reader = Reader { takes: 1, then: ErrorKind::BrokenPipe, got: Vec::new(), refused: 0 };
        let summary = run_info_to(&paths, InfoRequest::default(), &mut reader);
        assert_eq!((summary, reader.refused), (RunSummary { archives: 2, failed: 0, output_failed: false }, 1));
        assert!(String::from_utf8(reader.got).unwrap().starts_with(&format!("{}   ZIP, 1 entry\n", dir.path().join("a.zip").display())));

        // a reader that never took anything
        let mut reader = Reader { takes: 0, then: ErrorKind::BrokenPipe, got: Vec::new(), refused: 0 };
        let summary = run_info_to(&paths, InfoRequest { json: true, ..InfoRequest::default() }, &mut reader);
        assert_eq!((summary, reader.refused), (RunSummary { archives: 1, failed: 0, output_failed: false }, 1));
    }

    #[test]
    fn an_output_that_fails_in_another_way_fails_the_run() {
        let dir = five_archives();
        let mut full = Reader { takes: 1, then: ErrorKind::StorageFull, got: Vec::new(), refused: 0 };
        let summary = run_hash_to(&[dir.path().to_path_buf()], HashRequest { quiet: true, ..HashRequest::default() }, &mut full);
        assert_eq!(summary, RunSummary { archives: 2, failed: 0, output_failed: true });
        assert_eq!(summary.exit_status(), ExitStatus::NothingDone);
        assert_eq!(full.refused, 1, "nothing is written after the first error");
    }

    /// Rule 6 of the specification over every fixture: an archive with something encrypted in
    /// it gets a line or a reason, and one with nothing encrypted gets neither.
    #[test]
    fn every_encrypted_fixture_gets_a_line_or_a_reason() {
        let scan = scan_paths(&[PathBuf::from("tests/fixtures")]);
        assert!(scan.archives.len() > 500, "{}", scan.archives.len());
        let mut encrypted = 0;
        for found in &scan.archives {
            for wanted in [Lines::Best, Lines::All] {
                let Ok(Analysed { analysis, lines }) = analyse(found, wanted) else { continue };
                if analysis.is_encrypted() {
                    encrypted += 1;
                    assert!(!lines.is_empty() || !analysis.no_line.is_empty(), "{}: encrypted, and neither a line nor a reason", analysis.path);
                } else {
                    assert!(lines.is_empty() && analysis.no_line.is_empty(), "{}: nothing is encrypted", analysis.path);
                }
                // what `info` names is what `hash` writes
                assert_eq!(analysis.lines.len(), lines.len(), "{}", analysis.path);
                assert!(lines.iter().all(|line| line.entry.is_none_or(|index| index < analysis.entry_list.len())), "{}: a line from an entry that is not listed", analysis.path);
            }
        }
        assert!(encrypted > 600, "{encrypted}");
    }
}
