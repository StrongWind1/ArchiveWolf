//! ArchiveWolf CLI entry point.
#![expect(unused_crate_dependencies, reason = "deps used by the library crate, not the binary")]

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use archivewolf::attack::rar_13;
use archivewolf::attack::zip_crypto;
use archivewolf::cli::AttackCommand;
use archivewolf::cli::Cli;
use archivewolf::cli::Command;
use archivewolf::cli::ExitStatus;
use archivewolf::output::sanitize;
use archivewolf::output::shell_quote;
use archivewolf::run::HashRequest;
use archivewolf::run::InfoRequest;
use clap::Parser as _;
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::FormatEvent;
use tracing_subscriber::fmt::FormatFields;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::registry::LookupSpan;

/// A note as the logger writes it: `archivewolf: ` and what the event says, on one line. No
/// time, no level and no colour: a note reads the same on every run and in a file as on a
/// terminal.
struct Note;

impl<S, N> FormatEvent<S, N> for Note
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &tracing::Event<'_>) -> std::fmt::Result {
        write!(writer, "archivewolf: ")?;
        ctx.field_format().format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// Standard error as the logger writes to it.
///
/// An event can carry a path or a name out of an archive. The logger hands over one event
/// at a time, so every control character but the final newline is written as an escape and
/// an event is always one line.
struct LogWriter;

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let (line, end) = text.strip_suffix('\n').map_or((&*text, ""), |line| (line, "\n"));
        let mut stderr = std::io::stderr().lock();
        stderr.write_all(sanitize(line).as_bytes())?;
        stderr.write_all(end.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::stderr().flush()
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(&cli);

    // The one place where the result of a command becomes the exit status of the process.
    // `ExitStatus::code` holds the numbers and `RunSummary::exit_status` their precedence.
    let status = run(&cli).unwrap_or_else(|error| {
        eprintln!("archivewolf: {}", sanitize(&format!("{error:#}")));
        ExitStatus::NothingDone
    });
    status.into()
}

fn init_logging(cli: &Cli) {
    let filter = if cli.quiet {
        "error"
    } else {
        match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    };

    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter))).with_ansi(false).event_format(Note).with_writer(|| LogWriter).init();
}

/// Print one line of a result. It can hold a path, so it is sanitized like every other line.
/// A reader that has closed standard output gets no more of it, and that is no failure.
fn say(line: &str) {
    drop(writeln!(std::io::stdout(), "{}", sanitize(line)));
}

fn run(cli: &Cli) -> anyhow::Result<ExitStatus> {
    match &cli.command {
        Command::Info { paths, entries, json } => Ok(archivewolf::run::run_info(paths, InfoRequest { entries: *entries, json: *json }).exit_status()),
        Command::Hash { paths, all, mode, json } => Ok(archivewolf::run::run_hash(paths, HashRequest { all: *all, mode: *mode, json: *json, quiet: cli.quiet }).exit_status()),
        Command::Attack(AttackCommand::Rar13 { archive, output, budget }) => attack_rar_13(archive, output, rar_13::Options { budget: *budget, quiet: cli.quiet }),
        Command::Attack(AttackCommand::ZipCrypto(args)) => zip_crypto::run(&zip_crypto::Options {
            archives: args.archives.clone(),
            known: args.known.clone(),
            bytes: args.bytes.clone(),
            text: args.text.clone(),
            text16: args.text16.clone(),
            starts: args.starts.clone(),
            ends: args.ends.clone(),
            class: args.class.clone(),
            kinds: args.kinds.clone(),
            catalogue: args.catalogue.clone(),
            keys: args.keys.as_deref().and_then(|words| <[u32; 3]>::try_from(words).ok()),
            entries: args.entries.clone(),
            only: args.only.clone(),
            no_guess: args.no_guess,
            deep: args.deep,
            plan: args.plan,
            budget: Some(args.budget),
            attempt_budget: args.attempt_budget,
            threads: args.threads.and_then(|threads| usize::try_from(threads).ok()),
            slice: args.slice,
            output: args.output.clone(),
            json: args.json,
            state: args.state.clone().map(|path| zip_crypto::StateFile { path, resume: args.resume }),
            verbose: cli.verbose,
            quiet: cli.quiet,
        }),
    }
}

/// A RAR 1.3 key as it is shown: three bytes in hex.
fn rar_13_key_hex(key: [u8; 3]) -> String {
    format!("{:02x} {:02x} {:02x}", key[0], key[1], key[2])
}

/// `attack rar-13`: search the key of a RAR 1.3 archive, show it, and write a decrypted copy
/// of the archive to `output`.
///
/// The place of the copy is looked at before the search, which can take minutes: a file or a
/// symbolic link that is there ends the command with nothing done. A search that leaves no
/// key, or several, writes nothing, and so does one that its budget stops.
fn attack_rar_13(archive: &Path, output: &Path, options: rar_13::Options) -> anyhow::Result<ExitStatus> {
    rar_13::check_output(output)?;
    let data = rar_13::read_archive(archive)?;

    let found = match rar_13::search(&data, options) {
        Ok(found) => found,
        Err(error) => {
            eprintln!("archivewolf: {}", sanitize(&format!("{}: {error:#}", archive.display())));
            return Ok(ExitStatus::ArchiveFailed);
        },
    };
    match found {
        rar_13::Search::Key { key, how } => {
            say(&format!("KEY RECOVERED: RAR 1.3 key = {} ({how})", rar_13_key_hex(key)));
            let count = rar_13::write_decrypted(&data, key, output)?;
            say(&format!("DECRYPTED: {count} RAR 1.3 entries → {}", output.display()));
            say(&format!("Extract with: unrar x -- {}", shell_quote(&output.display().to_string())));
            Ok(ExitStatus::Success)
        },
        rar_13::Search::Ambiguous(keys) => {
            let shown: Vec<String> = keys.iter().map(|key| rar_13_key_hex(*key)).collect();
            say(&format!("KEY AMBIGUOUS: {} RAR 1.3 keys satisfy the 16-bit entry checksum and the content does not single one out; no archive written", keys.len()));
            say(&format!("Candidate keys: {}", shown.join(", ")));
            Ok(ExitStatus::NoResult)
        },
        rar_13::Search::NoKey => {
            eprintln!("archivewolf: {}", sanitize(&format!("{}: no key satisfies the entry checksums: the archive is damaged, or its entries are not of rar-13; no archive written", archive.display())));
            Ok(ExitStatus::NoResult)
        },
        rar_13::Search::Stopped(why) => {
            eprintln!("archivewolf: {}", sanitize(&format!("{}: {why}; no archive written", archive.display())));
            Ok(ExitStatus::NoResult)
        },
        rar_13::Search::NothingEncrypted => anyhow::bail!("{}: no entry is encrypted, so there is no key to search for", archive.display()),
    }
}
