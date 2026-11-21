//! Command-line argument parsing and the exit status of the process.

use std::path::PathBuf;

use clap::Parser;
use clap::Subcommand;

use crate::line::Tag;

/// The exit status table, shown at the end of `--help`.
const EXIT_STATUS_HELP: &str = "\
Exit status:
  0  Every input was processed, and an attack that was asked for succeeded.
  1  Nothing was processed: no archive was found in the given paths, the
     result could not be written, or an attack could not start.
  2  At least one input could not be processed: a path cannot be read, an
     archive does not parse, or it hit an internal error. The others are
     still reported.
  3  An attack ended without a result: no key was found, several keys are
     left and nothing tells them apart, or its budget ended it.

When several apply, 2 comes before 3 and 3 before 0. Status 1 is returned only
when nothing was processed at all. A command line that cannot be parsed exits
with the status of the argument parser, which is 2.";

/// Analyser and hashcat hash converter for encrypted ZIP, RAR and 7-Zip archives.
#[derive(Debug, Parser)]
#[command(name = "archivewolf", version, about, long_about = None, after_long_help = EXIT_STATUS_HELP)]
pub struct Cli {
    /// More notes on standard error: -v says where each line comes from, -vv which files a walk
    /// passes over.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// No notes on standard error, errors only.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Say what is encrypted in each archive and how, and which hash lines `hash` writes for it.
    #[command(after_long_help = EXIT_STATUS_HELP)]
    Info {
        /// Paths to scan (files or directories).
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// A row for each entry below the block of its archive.
        #[arg(long)]
        entries: bool,

        /// One JSON object for each archive, on a line of its own, always with its entries.
        #[arg(long)]
        json: bool,
    },
    /// Write the hash lines for hashcat to standard output, one on a line, and nothing else there.
    #[command(after_long_help = EXIT_STATUS_HELP)]
    Hash {
        /// Paths to scan (files or directories).
        #[arg(required = true)]
        paths: Vec<PathBuf>,

        /// A line for every encrypted entry or folder, not only for the best one of each archive.
        #[arg(long)]
        all: bool,

        /// Only the lines of this hashcat mode. A mode `hash` writes no line for is refused.
        #[arg(long, value_name = "MODE", value_parser = mode_of_a_line)]
        mode: Option<u32>,

        /// One JSON object for each line: the path of its archive, its entry, its scheme, its mode,
        /// its tag, what it proves and the line.
        #[arg(long)]
        json: bool,
    },
    /// Recover the key of a scheme that falls without the password.
    #[command(subcommand)]
    Attack(AttackCommand),
}

/// A hashcat mode that `hash` writes lines for, from the text of `--mode`.
///
/// A number that is no such mode would pick nothing out of any run, and a run that prints
/// nothing and ends well looks like archives without lines: it is refused, with the modes
/// there are.
fn mode_of_a_line(text: &str) -> Result<u32, String> {
    let written: Vec<u32> = Tag::ALL.iter().filter(|tag| tag.written_by_hash()).flat_map(|tag| tag.modes()).copied().collect();
    let keys: Vec<u32> = Tag::ALL.iter().filter(|tag| !tag.written_by_hash()).flat_map(|tag| tag.modes()).copied().collect();
    match text.parse::<u32>() {
        Ok(mode) if written.contains(&mode) => Ok(mode),
        Ok(mode) if keys.contains(&mode) => Err(format!("mode {mode} loads the keys of zip-crypto, a line that no command writes yet")),
        _ => {
            let modes: Vec<String> = written.iter().map(u32::to_string).collect();
            Err(format!("`hash` writes lines for the modes {} and for no other", modes.join(", ")))
        },
    }
}

/// The attacks.
#[derive(Debug, Subcommand)]
pub enum AttackCommand {
    /// Search the 2^23 keys a RAR 1.3 password can give, and write a decrypted copy of the archive.
    #[command(name = "rar-13", after_long_help = EXIT_STATUS_HELP)]
    Rar13 {
        /// RAR 1.3 or 1.4 archive.
        archive: PathBuf,

        /// Where the decrypted copy of the archive is written. The file is created new: one that
        /// exists is never overwritten, and a symbolic link is never followed.
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,

        /// How long the search may take: a number with a unit, as in 90s, 10m or 2h, or `none`
        /// for no limit. A search that is measured to take longer is not started.
        #[arg(long, value_name = "TIME", default_value = "10m")]
        budget: crate::attack::rar_13::Budget,
    },
    /// Find the three keys of a ZIP archive under traditional encryption without its password.
    ///
    /// With nothing but the archive, the command works out what is known of it, says what it
    /// will try and what each attempt costs, and tries it. Every option gives it more to work
    /// with or sets a limit; none is needed.
    #[command(name = "zip-crypto", after_long_help = EXIT_STATUS_HELP)]
    ZipCrypto(Box<ZipCryptoArgs>),
}

/// The arguments of `attack zip-crypto`.
#[derive(Debug, clap::Args)]
pub struct ZipCryptoArgs {
    /// ZIP archives under one password. Known bytes of any entry find the keys, and the entries
    /// of all of them test the keys.
    #[arg(required = true, value_name = "ARCHIVE")]
    pub archives: Vec<PathBuf>,

    /// A file, a folder or an archive that may hold content of the archive.
    #[arg(long, value_name = "PATH", help_heading = "Giving what you know")]
    pub known: Vec<PathBuf>,

    /// Known bytes of an entry in hex, at a position or anywhere. A position below zero counts
    /// from the end.
    #[arg(long, value_name = "ENTRY[@POS]=HEX", help_heading = "Giving what you know")]
    pub bytes: Vec<String>,

    /// The same, as text.
    #[arg(long, value_name = "ENTRY[@POS]=STR", help_heading = "Giving what you know")]
    pub text: Vec<String>,

    /// The same, as text in UTF-16.
    #[arg(long, value_name = "ENTRY[@POS]=STR", help_heading = "Giving what you know")]
    pub text16: Vec<String>,

    /// The entry starts with this text.
    #[arg(long, value_name = "ENTRY=STR", help_heading = "Giving what you know")]
    pub starts: Vec<String>,

    /// The entry ends with this text.
    #[arg(long, value_name = "ENTRY=STR", help_heading = "Giving what you know")]
    pub ends: Vec<String>,

    /// Every byte of the entry is of this class: text, ascii or utf16.
    #[arg(long, value_name = "ENTRY=CLASS", help_heading = "Giving what you know")]
    pub class: Vec<String>,

    /// The entry is a file of this type, whatever its name says.
    #[arg(long = "type", value_name = "ENTRY=TYPE", help_heading = "Giving what you know")]
    pub kinds: Vec<String>,

    /// A list of files that exist elsewhere, as text with a first line that names its columns,
    /// CRC32 and FileSize among them: the entries that are in it are named, with the name and
    /// the hashes the list has for each.
    #[arg(long, value_name = "FILE", help_heading = "Giving what you know")]
    pub catalogue: Option<PathBuf>,

    /// Keys from an earlier run, as three words in hex: they are tested on every entry, and
    /// nothing is searched.
    #[arg(long, num_args = 3, value_names = ["X", "Y", "Z"], value_parser = key_word, help_heading = "Giving what you know")]
    pub keys: Option<Vec<u32>>,

    /// Only attempts on these entries.
    #[arg(long = "entry", value_name = "PATTERN", help_heading = "Choosing what is tried")]
    pub entries: Vec<String>,

    /// Only these paths: run, short-run, header, header-once.
    #[arg(long, value_name = "PATH,...", help_heading = "Choosing what is tried")]
    pub only: Vec<String>,

    /// Only claims that are certain or derived.
    #[arg(long, help_heading = "Choosing what is tried")]
    pub no_guess: bool,

    /// Also the attempts that take hours: runs with one byte that is not known.
    #[arg(long, help_heading = "Choosing what is tried")]
    pub deep: bool,

    /// Print the plan and stop.
    #[arg(long, help_heading = "Choosing what is tried")]
    pub plan: bool,

    /// For the whole command: a number with a unit, as in 90s, 15m or 2h, or `none`. An
    /// attempt that is measured to take longer than what is left is not started.
    #[arg(long, value_name = "TIME", default_value = "15m", help_heading = "Limits")]
    pub budget: crate::attack::Budget,

    /// For one attempt. Without it an attempt may take what is left of the budget.
    #[arg(long, value_name = "TIME", help_heading = "Limits")]
    pub attempt_budget: Option<crate::attack::Budget>,

    /// How many threads search. All there are, when it is not given.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..), help_heading = "Limits")]
    pub threads: Option<u32>,

    /// This machine's part of every search, when several machines share the work: 1/4 to 4/4.
    #[arg(long, value_name = "K/N", value_parser = slice, help_heading = "Limits")]
    pub slice: Option<(u32, u32)>,

    /// Write the archive without its password: the entries the keys open are decrypted and
    /// stay packed, the others are copied as they are. The file is created new: one that
    /// exists is never overwritten, and a symbolic link is never followed.
    #[arg(short, long, value_name = "FILE", help_heading = "Result")]
    pub output: Option<PathBuf>,

    /// The result as one JSON object. With -v, what happens on the way as a stream of events
    /// on standard error, one object on a line.
    #[arg(long, help_heading = "Result")]
    pub json: bool,

    /// Keep in this file how far the searches came: which attempts ended, and the candidate
    /// the running one has reached, written every ten seconds. The file is created new
    #[arg(long, value_name = "FILE", help_heading = "Stopping and going on")]
    pub state: Option<PathBuf>,

    /// Go on from the file of --state, which a run on the same archives left: attempts that
    /// ended without keys are not run again, and the one that was running starts where it was
    #[arg(long, requires = "state", help_heading = "Stopping and going on")]
    pub resume: bool,
}

/// One word of a key, from eight hex digits or fewer.
fn key_word(text: &str) -> Result<u32, String> {
    u32::from_str_radix(text.trim_start_matches("0x"), 16).map_err(|_| "a key is three words of up to eight hex digits, as in c4490e28 b414a23d 91404b31".to_owned())
}

/// A part of a search, from `K/N`.
fn slice(text: &str) -> Result<(u32, u32), String> {
    let form = || "a slice is a part and a count of parts, as in 2/4".to_owned();
    let (part, of) = text.split_once('/').ok_or_else(form)?;
    let (part, of): (u32, u32) = (part.parse().map_err(|_| form())?, of.parse().map_err(|_| form())?);
    if part >= 1 && part <= of { Ok((part, of)) } else { Err(format!("the part is a number from 1 to {of}")) }
}

/// The exit status of the process.
///
/// This is the only place that knows the numbers. A run over archives gets its status from
/// [`crate::run::RunSummary::exit_status`], which holds the order of precedence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Every input was processed, and an attack that was asked for succeeded.
    Success,
    /// Nothing was processed: no archive was found, a path does not exist, an output could not
    /// be created.
    NothingDone,
    /// At least one input could not be processed.
    ArchiveFailed,
    /// An attack ended without a result.
    NoResult,
}

impl ExitStatus {
    /// The number the process exits with.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::NothingDone => 1,
            Self::ArchiveFailed => 2,
            Self::NoResult => 3,
        }
    }
}

impl From<ExitStatus> for std::process::ExitCode {
    fn from(status: ExitStatus) -> Self {
        Self::from(status.code())
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;
    use clap::error::ErrorKind;

    use super::*;

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn exit_status_numbers_are_the_documented_ones() {
        assert_eq!(ExitStatus::Success.code(), 0);
        assert_eq!(ExitStatus::NothingDone.code(), 1);
        assert_eq!(ExitStatus::ArchiveFailed.code(), 2);
        assert_eq!(ExitStatus::NoResult.code(), 3);
    }

    #[test]
    fn long_help_documents_every_exit_status() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        for line in ["Exit status:", "  0  Every input", "  1  Nothing was processed", "  2  At least one input", "  3  An attack ended"] {
            assert!(help.contains(line), "--help lacks {line:?}:\n{help}");
        }
    }

    #[test]
    fn hash_takes_the_modes_it_writes_lines_for_and_refuses_every_other() {
        let mode_of = |text: &str| {
            Cli::try_parse_from(["archivewolf", "hash", "--mode", text, "a.zip"]).map(|cli| match cli.command {
                Command::Hash { mode, .. } => mode,
                _ => None,
            })
        };
        for mode in [46100, 46200, 46300, 46310, 46320, 46500, 46600, 46700, 46800, 46900] {
            assert_eq!(mode_of(&mode.to_string()).unwrap(), Some(mode));
        }
        // a mode of hashcat that loads another line, one that is none, and what is no number
        for other in ["13600", "17200", "11600", "0", "99999", "4610", "zip"] {
            let error = mode_of(other).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{other}");
            assert!(error.to_string().contains("46100, 46200, 46300, 46310, 46320, 46500, 46600, 46700, 46800, 46900 and for no other"), "{other}: {error}");
        }
        assert!(mode_of("-1").is_err() && mode_of("").is_err());
        // the two modes of the line that holds keys: `hash` writes none of it
        for keys in ["46400", "46410"] {
            assert!(mode_of(keys).unwrap_err().to_string().contains("loads the keys of zip-crypto"), "{keys}");
        }
    }

    #[test]
    fn the_three_commands_take_their_arguments() {
        let info = Cli::try_parse_from(["archivewolf", "info", "a.zip", "dir", "--json"]).unwrap();
        let Command::Info { paths, entries, json } = info.command else { panic!("not an info command") };
        assert_eq!((paths, entries, json), (vec![PathBuf::from("a.zip"), PathBuf::from("dir")], false, true));

        let listed = Cli::try_parse_from(["archivewolf", "info", "--entries", "a.zip"]).unwrap();
        let Command::Info { entries, json, .. } = listed.command else { panic!("not an info command") };
        assert_eq!((entries, json), (true, false));

        let hash = Cli::try_parse_from(["archivewolf", "-q", "hash", "--all", "--mode", "46100", "--json", "a.zip"]).unwrap();
        assert!(hash.quiet);
        let Command::Hash { paths, all, mode, json } = hash.command else { panic!("not a hash command") };
        assert_eq!((paths, all, mode, json), (vec![PathBuf::from("a.zip")], true, Some(46100), true));

        let plain = Cli::try_parse_from(["archivewolf", "hash", "a.zip", "-vv"]).unwrap();
        assert_eq!(plain.verbose, 2);
        let Command::Hash { all, mode, json, .. } = plain.command else { panic!("not a hash command") };
        assert_eq!((all, mode, json), (false, None, false));

        let attack = Cli::try_parse_from(["archivewolf", "attack", "rar-13", "old.rar", "-o", "copy.rar"]).unwrap();
        let Command::Attack(AttackCommand::Rar13 { archive, output, budget }) = attack.command else { panic!("not an attack") };
        assert_eq!((archive, output), (PathBuf::from("old.rar"), PathBuf::from("copy.rar")));
        assert_eq!(budget, crate::attack::rar_13::Budget::DEFAULT);
    }

    #[test]
    fn attack_rar_13_takes_a_budget_with_a_unit_or_none_and_refuses_any_other() {
        use std::time::Duration;

        use crate::attack::rar_13::Budget;

        let budget = |value: &str| {
            Cli::try_parse_from(["archivewolf", "attack", "rar-13", "old.rar", "-o", "copy.rar", "--budget", value]).map(|cli| match cli.command {
                Command::Attack(AttackCommand::Rar13 { budget, .. }) => budget,
                other => panic!("not an attack: {other:?}"),
            })
        };
        assert_eq!(budget("90s").unwrap(), Budget::Limit(Duration::from_secs(90)));
        assert_eq!(budget("10m").unwrap(), Budget::DEFAULT);
        assert_eq!(budget("2h").unwrap(), Budget::Limit(Duration::from_hours(2)));
        assert_eq!(budget("none").unwrap(), Budget::Unlimited);
        // ten minutes when it is not given
        assert_eq!(Budget::DEFAULT, Budget::Limit(Duration::from_mins(10)));

        for value in ["", "10", "m", "ten", "10d", "1.5h", "0s", "NONE", "10 m", "99999999999999999999h"] {
            let error = budget(value).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ValueValidation, "{value:?}");
            assert!(error.to_string().contains("--budget <TIME>"), "{value:?}: {error}");
        }
        // the flag has to have its value, a value with a sign is none, and it belongs to the attack alone
        let kind = |args: &[&str]| Cli::try_parse_from([&["archivewolf"], args].concat()).map(|_| ()).map_err(|error| error.kind());
        assert_eq!(kind(&["attack", "rar-13", "a.rar", "-o", "b.rar", "--budget"]), Err(ErrorKind::InvalidValue));
        assert_eq!(kind(&["attack", "rar-13", "a.rar", "-o", "b.rar", "--budget", "-5m"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["attack", "rar-13", "a.rar", "-o", "b.rar", "--budget=-5m"]), Err(ErrorKind::ValueValidation));
        assert_eq!(kind(&["hash", "--budget", "10m", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["info", "--budget", "none", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["--budget", "10m", "attack", "rar-13", "a.rar", "-o", "b.rar"]), Err(ErrorKind::UnknownArgument));
    }

    #[test]
    fn attack_zip_crypto_is_complete_with_one_archive_and_takes_what_the_user_knows() {
        use std::time::Duration;

        use crate::attack::Budget;

        let args = |words: &[&str]| {
            Cli::try_parse_from([&["archivewolf", "attack", "zip-crypto"], words].concat()).map(|cli| match cli.command {
                Command::Attack(AttackCommand::ZipCrypto(args)) => args,
                other => panic!("not the attack: {other:?}"),
            })
        };
        let plain = args(&["backup.zip"]).unwrap();
        assert_eq!((plain.archives.clone(), plain.budget, plain.attempt_budget), (vec![PathBuf::from("backup.zip")], Budget::Limit(Duration::from_mins(15)), None));
        assert!(plain.known.is_empty() && plain.keys.is_none() && plain.slice.is_none() && !plain.deep && !plain.plan && !plain.json && !plain.no_guess);

        let full = args(&[
            "a.zip",
            "b.zip",
            "--known",
            "docs",
            "--known",
            "old.zip",
            "--bytes",
            "a.bin@0=0001",
            "--text",
            "a.txt@-4=end.",
            "--text16",
            "w.reg@2=Windows",
            "--starts",
            "notes.txt=Dear Mr ",
            "--ends",
            "notes.txt=bye",
            "--class",
            "notes.txt=text",
            "--type",
            "x.dat=png",
            "--entry",
            "*.txt",
            "--only",
            "run,short-run",
            "--no-guess",
            "--deep",
            "--plan",
            "--budget",
            "2h",
            "--attempt-budget",
            "none",
            "--threads",
            "4",
            "--slice",
            "2/4",
            "--json",
            "-o",
            "open.zip",
        ])
        .unwrap();
        assert_eq!(full.archives.len(), 2);
        assert_eq!((full.known.len(), full.bytes.len(), full.starts[0].as_str(), full.kinds[0].as_str()), (2, 1, "notes.txt=Dear Mr ", "x.dat=png"));
        assert_eq!((full.budget, full.attempt_budget, full.threads, full.slice), (Budget::Limit(Duration::from_hours(2)), Some(Budget::Unlimited), Some(4), Some((2, 4))));
        assert!(full.deep && full.plan && full.json && full.no_guess);
        assert_eq!(full.output, Some(PathBuf::from("open.zip")));

        let keys = args(&["a.zip", "--keys", "c4490e28", "b414a23d", "0x91404b31"]).unwrap();
        assert_eq!(keys.keys, Some(vec![0xc449_0e28, 0xb414_a23d, 0x9140_4b31]));

        let kind = |words: &[&str]| args(words).map(|_| ()).map_err(|error| error.kind());
        assert_eq!(kind(&[]), Err(ErrorKind::MissingRequiredArgument));
        assert_eq!(kind(&["a.zip", "--keys", "1", "2"]), Err(ErrorKind::WrongNumberOfValues));
        assert_eq!(kind(&["a.zip", "--keys", "1", "2", "xyz"]), Err(ErrorKind::ValueValidation));
        for slice in ["0/4", "5/4", "2", "a/b", "2/0"] {
            assert_eq!(kind(&["a.zip", "--slice", slice]), Err(ErrorKind::ValueValidation), "{slice}");
        }
        assert_eq!(kind(&["a.zip", "--threads", "0"]), Err(ErrorKind::ValueValidation));
        assert_eq!(kind(&["a.zip", "--budget", "soon"]), Err(ErrorKind::ValueValidation));
        assert_eq!(kind(&["a.zip", "--password", "secret"]), Err(ErrorKind::UnknownArgument));
    }

    #[test]
    fn a_flag_is_taken_only_by_the_command_it_means_something_to() {
        let kind = |args: &[&str]| Cli::try_parse_from([&["archivewolf"], args].concat()).map(|_| ()).map_err(|error| error.kind());

        assert_eq!(kind(&["info", "--all", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["info", "--mode", "46100", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["hash", "--entries", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["--json", "info", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["--all", "hash", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["hash", "-o", "lines.txt", "a.zip"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["attack", "rar-13", "--json", "a.rar", "-o", "b.rar"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["hash", "--mode", "zip", "a.zip"]), Err(ErrorKind::ValueValidation));

        // an attack names its archive and the file it writes
        assert_eq!(kind(&["attack", "rar-13", "a.rar"]), Err(ErrorKind::MissingRequiredArgument));
        assert_eq!(kind(&["attack", "rar-13", "-o", "b.rar"]), Err(ErrorKind::MissingRequiredArgument));
        assert_eq!(kind(&["attack", "rar-13", "a.rar", "b.rar", "-o", "c.rar"]), Err(ErrorKind::UnknownArgument));
        assert_eq!(kind(&["info"]), Err(ErrorKind::MissingRequiredArgument));
        assert_eq!(kind(&["hash"]), Err(ErrorKind::MissingRequiredArgument));
    }

    #[test]
    fn the_commands_and_flags_of_the_earlier_design_are_gone() {
        let kind = |args: &[&str]| Cli::try_parse_from([&["archivewolf"], args].concat()).map(|_| ()).map_err(|error| error.kind());

        for command in [&["unlock", "a.zip"][..], &["advanced", "strip", "a.zip"], &["advanced", "extract", "a.zip"], &["advanced", "decrypt", "a.rar"], &["advanced", "collide", "a.zip"], &["attack", "zipcrypto", "a.zip"]] {
            assert_eq!(kind(command), Err(ErrorKind::InvalidSubcommand), "{command:?}");
        }
        for flags in [
            &["--format", "json", "info", "a.zip"][..],
            &["info", "--format", "hashcat", "a.zip"],
            &["hash", "--format", "plain", "a.zip"],
            &["--all-hashes", "info", "a.zip"],
            &["info", "--all-hashes", "a.zip"],
            &["hash", "--all-hashes", "a.zip"],
            &["info", "--password", "secret", "a.zip"],
            &["hash", "-p", "secret", "a.zip"],
            &["hash", "--password-file", "pw.txt", "a.zip"],
            &["info", "--output-dir", "out", "a.zip"],
            &["attack", "rar-13", "a.rar", "-o", "b.rar", "--password", "secret"],
            &["attack", "rar-13", "a.rar", "-o", "b.rar", "--password-file", "pw.txt"],
            &["attack", "rar-13", "a.rar", "-o", "b.rar", "--key0", "73", "--key1", "1f", "--key2", "3d"],
            &["attack", "rar-13", "a.rar", "--output-dir", "out"],
        ] {
            assert_eq!(kind(flags), Err(ErrorKind::UnknownArgument), "{flags:?}");
        }
    }
}
