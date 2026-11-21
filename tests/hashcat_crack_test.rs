//! The modes crack the lines: the second of the three proofs that a line is right.
//!
//! The lines are those recorded under `tests/golden/`, a handful for every mode, each one checked
//! first to be what `archivewolf hash` writes today. Every line goes to hashcat on its own, with a
//! list of three words of which the second is the password `tests/fixtures/passwords.json` has
//! for its fixture, and hashcat has to give that word back for that line.
//!
//! `make test-hashcat` runs the proof. It takes the path of the hashcat binary from
//! `ARCHIVEWOLF_HASHCAT`. The modes 46100 to 46900 are on three branches of the hashcat fork, so
//! a binary has some of them: the proof asks it for each, tests the ones it has, says which it
//! could not cover, and fails when the binary has none or when no binary is given. A second test
//! of that target is a check of the run and not of the modes: the same run has to crack the
//! example line hashcat itself gives for mode 13600, which every hashcat has.
//!
//! The tests of the default run hold the proof itself to that, with a bash script standing in
//! for hashcat: it answers for the modes it is told to have and reports whatever word it is told
//! to report. It tests no password, so those tests say nothing about the modes.

mod support;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;

/// The environment variable that holds the path of the hashcat binary.
const BINARY: &str = "ARCHIVEWOLF_HASHCAT";

/// The modes that read ArchiveWolf's lines.
const MODES: [u32; 12] = [46100, 46200, 46300, 46310, 46320, 46400, 46410, 46500, 46600, 46700, 46800, 46900];

/// The two words of a list that are not the password. The password stands between them.
const WRONG: [&str; 2] = ["archivewolf-wrong-1", "archivewolf-wrong-2"];

/// Seconds after which hashcat gives up on one line. Three words take less on any device.
const RUNTIME: &str = "600";

/// A recorded line that is to be cracked.
struct Planned {
    case: String,
    mode: u32,
    fixture: PathBuf,
    line: String,
    password: String,
}

/// What the manifest of recorded lines asks of this proof.
struct Plan {
    lines: Vec<Planned>,
    /// The recorded lines that are not cracked, each with the reason the manifest gives.
    left_out: Vec<(u32, String)>,
}

/// What a run of the proof found.
#[derive(Debug)]
struct Proof {
    version: String,
    /// The lines hashcat gave the right password for.
    cracked: Vec<String>,
    /// The lines it did not, each with what happened.
    failed: Vec<String>,
    /// The modes no line was cracked for, each with the reason.
    not_covered: Vec<(u32, String)>,
    /// The recorded lines of the modes this hashcat has that the manifest keeps out of the proof.
    left_out: Vec<(u32, String)>,
}

/// A hashcat to run: its program, and what goes in front of every argument. A binary has
/// nothing in front. The stand-in of the tests is a script run by `bash`, with what it is told.
struct Hashcat {
    program: OsString,
    leading: Vec<OsString>,
}

/// The passwords of the fixtures, by the path of a fixture under `tests/fixtures`.
fn passwords() -> Result<BTreeMap<String, String>, String> {
    let path = Path::new(support::FIXTURES).join("passwords.json");
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Read the manifest: which recorded lines are cracked, with which password, and which are not.
///
/// A line that is to be cracked and has no password, or a password a word list cannot hold, or is
/// no longer what `archivewolf hash` writes for its fixture, is an error.
fn plan() -> Result<Plan, String> {
    let passwords = passwords()?;
    let mut plan = Plan { lines: Vec::new(), left_out: Vec::new() };
    for entry in support::recorded_lines()? {
        let (case, mode, fixture) = (entry.text("case").to_owned(), entry.mode(), entry.fixture());
        match entry.text("crack") {
            "yes" => {
                let line = entry.line()?;
                let written = String::from_utf8_lossy(&support::archivewolf_hash(&["--mode", &mode.to_string()], &fixture)?).into_owned();
                if written != format!("{line}\n") {
                    return Err(format!("{case}: the recorded line is not what `archivewolf hash` writes for {}:\n{}", fixture.display(), support::difference(("recorded", &line), ("archivewolf", &written))));
                }
                let password = passwords.get(entry.text("fixture")).ok_or_else(|| format!("{case}: {} has no password in passwords.json", entry.text("fixture")))?.clone();
                if password.is_empty() || password.contains(['\n', '\r']) || WRONG.contains(&password.as_str()) {
                    return Err(format!("{case}: the password of {} cannot stand in a word list beside {WRONG:?}", entry.text("fixture")));
                }
                plan.lines.push(Planned { case, mode, fixture, line, password });
            },
            reason if reason.starts_with("no: ") => plan.left_out.push((mode, format!("{case} is left out, {}", reason.trim_start_matches("no: ")))),
            other => return Err(format!("{case}: crack is `{other}`, which is neither `yes` nor a reason that starts with `no: `")),
        }
    }
    Ok(plan)
}

/// The bytes a string of hex digits stands for.
fn bytes_of_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.is_ascii() || !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len()).step_by(2).map(|at| u8::from_str_radix(hex.get(at..at.checked_add(2)?)?, 16).ok()).collect()
}

/// What hashcat wrote to its output file with `--outfile-format 1,3`: for every cracked line the
/// line, a colon, and the word in hex. No line of ArchiveWolf's holds a colon, and hex holds
/// none, so the last colon parts the two.
fn cracks_of(outfile: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    outfile
        .lines()
        .map(|crack| {
            let (line, hex) = crack.rsplit_once(':').ok_or_else(|| format!("no colon in what hashcat wrote: {}", support::trimmed(crack)))?;
            let word = bytes_of_hex(hex).ok_or_else(|| format!("no hex behind the colon in what hashcat wrote: {}", support::trimmed(crack)))?;
            Ok((line.to_owned(), word))
        })
        .collect()
}

impl Hashcat {
    /// The binary the environment names, when it names one.
    fn from_environment() -> Option<Self> {
        std::env::var_os(BINARY).filter(|path| !path.is_empty()).map(|program| Self { program, leading: Vec::new() })
    }

    /// Run it. Not being able to start it is an error. How it ended is for the caller to judge.
    fn run(&self, arguments: &[OsString]) -> Result<Output, String> {
        Command::new(&self.program).args(&self.leading).args(arguments).stdin(Stdio::null()).output().map_err(|error| format!("{} could not be started: {error}", Path::new(&self.program).display()))
    }

    /// What it says its version is.
    fn version(&self) -> Result<String, String> {
        let output = self.run(&["--version".into()])?;
        let version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if output.status.success() && !version.is_empty() { Ok(format!("hashcat {version}")) } else { Err(format!("{} --version: {}, and it printed `{version}`. It is not a hashcat that runs.", Path::new(&self.program).display(), output.status)) }
    }

    /// What it says of a mode, when it has the mode: hashcat ends `--hash-info` for a mode it
    /// has no module for with an error status and says so on standard error.
    fn info(&self, mode: u32) -> Result<Option<String>, String> {
        let output = self.run(&["--hash-info".into(), "-m".into(), mode.to_string().into(), "--quiet".into()])?;
        let info = String::from_utf8_lossy(&output.stdout).into_owned();
        Ok((output.status.success() && info.contains(&format!("Hash mode #{mode}"))).then_some(info))
    }

    /// Give it one line and a list of three words, the password in the middle, and require the
    /// password back for that line. The files of the run are numbered `number` in `directory`.
    fn crack(&self, mode: u32, line: &str, password: &str, directory: &Path, number: usize) -> Result<(), String> {
        let file = |kind: &str| directory.join(format!("{number}.{kind}"));
        let (hashes, words, outfile) = (file("hash"), file("words"), file("out"));
        std::fs::write(&hashes, format!("{line}\n")).map_err(|error| format!("{}: {error}", hashes.display()))?;
        let [before, behind] = WRONG;
        std::fs::write(&words, format!("{before}\n{password}\n{behind}\n")).map_err(|error| format!("{}: {error}", words.display()))?;

        // no potfile, so that a line cracked before is cracked again, and nothing of the run is kept
        let session = format!("archivewolf-proof-{}-{number}", std::process::id());
        let mut arguments: Vec<OsString> = ["--quiet", "--potfile-disable", "--restore-disable", "--logfile-disable", "--session", &session, "--runtime", RUNTIME, "-a", "0", "-m", &mode.to_string(), "--outfile-format", "1,3", "-o"].iter().map(OsString::from).collect();
        arguments.extend([outfile.clone().into_os_string(), hashes.into_os_string(), words.into_os_string()]);
        let output = self.run(&arguments)?;

        let said = || {
            let all = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            let lines: Vec<&str> = all.lines().filter(|line| !line.trim().is_empty()).collect();
            lines.iter().skip(lines.len().saturating_sub(4)).map(|line| support::trimmed(line)).collect::<Vec<_>>().join(" | ")
        };
        match output.status.code() {
            Some(0) => {},
            Some(1) => return Err("hashcat went through the list and accepted none of the three words, the password among them".to_owned()),
            _ => return Err(format!("hashcat ended with {}: {}", output.status, said())),
        }
        let cracks = cracks_of(&std::fs::read_to_string(&outfile).unwrap_or_default())?;
        match cracks.as_slice() {
            [(cracked, word)] if cracked == line && word == password.as_bytes() => Ok(()),
            [(cracked, word)] if cracked == line => Err(format!("hashcat gave `{}` for the line, and its password is `{password}`", String::from_utf8_lossy(word))),
            [(cracked, _)] => Err(format!("hashcat gave a word for another line than the one it was given: {}", support::trimmed(cracked))),
            _ => Err(format!("hashcat ended as if it had cracked the line and wrote {} cracks", cracks.len())),
        }
    }
}

/// Crack every planned line of every mode the hashcat has.
///
/// No hashcat, one that does not run, one with none of the modes, and one with no mode that has
/// a planned line are errors. A line that is not cracked is in the answer, with what happened.
fn prove(hashcat: Option<&Hashcat>, plan: &Plan) -> Result<Proof, String> {
    let hashcat = hashcat.ok_or_else(|| format!("{BINARY} is not set. It has to hold the path of a hashcat binary built from the fork, with modes of 46100 to 46900."))?;
    let version = hashcat.version()?;
    let directory = tempfile::tempdir().map_err(|error| format!("no temporary directory: {error}"))?;

    let mut proof = Proof { version, cracked: Vec::new(), failed: Vec::new(), not_covered: Vec::new(), left_out: Vec::new() };
    let mut present = 0_usize;
    for mode in MODES {
        if hashcat.info(mode)?.is_none() {
            proof.not_covered.push((mode, "this hashcat does not have the mode".to_owned()));
            continue;
        }
        present = present.saturating_add(1);
        proof.left_out.extend(plan.left_out.iter().filter(|(of, _)| *of == mode).cloned());
        let lines: Vec<&Planned> = plan.lines.iter().filter(|planned| planned.mode == mode).collect();
        if lines.is_empty() {
            proof.not_covered.push((mode, "this hashcat has the mode, and no recorded line is cracked for it".to_owned()));
        }
        for planned in lines {
            let name = format!("mode {mode}, {} ({})", planned.case, planned.fixture.display());
            match hashcat.crack(mode, &planned.line, &planned.password, directory.path(), proof.cracked.len().saturating_add(proof.failed.len())) {
                Ok(()) => proof.cracked.push(name),
                Err(fault) => proof.failed.push(format!("{name}: {fault}")),
            }
        }
    }

    if present == 0 {
        return Err(format!("{} has none of the modes {MODES:?}. It is not built from a branch of the fork that has them.", proof.version));
    }
    if proof.cracked.is_empty() && proof.failed.is_empty() {
        return Err(format!("{} has no mode a line is recorded for, so nothing was tested.", proof.version));
    }
    Ok(proof)
}

impl Proof {
    /// What was cracked, what was not, and which modes were not covered.
    fn report(&self) -> String {
        let mut report = vec![format!("{}: {} lines cracked, {} not cracked, {} of {} modes not covered.", self.version, self.cracked.len(), self.failed.len(), self.not_covered.len(), MODES.len())];
        report.extend(self.cracked.iter().map(|line| format!("  cracked      {line}")));
        report.extend(self.failed.iter().map(|line| format!("  NOT CRACKED  {line}")));
        report.extend(self.not_covered.iter().map(|(mode, reason)| format!("  not covered  mode {mode}: {reason}")));
        report.extend(self.left_out.iter().map(|(mode, reason)| format!("  left out     mode {mode}: {reason}")));
        report.join("\n")
    }
}

#[test]
#[ignore = "needs a hashcat built from the fork: `make test-hashcat`"]
fn the_modes_crack_the_recorded_lines() {
    let plan = plan().unwrap_or_else(|fault| panic!("{fault}"));
    let proof = prove(Hashcat::from_environment().as_ref(), &plan).unwrap_or_else(|fault| panic!("{fault}"));
    println!("{}", proof.report());
    assert!(proof.failed.is_empty(), "{} of {} lines were not cracked:\n  {}", proof.failed.len(), proof.failed.len() + proof.cracked.len(), proof.failed.join("\n  "));
}

/// A check of this test and not of the modes: the hashcat that is given cracks the example line
/// it has for mode 13600 itself, through the same run and the same reading of its output as the
/// proof. Mode 13600 is in every hashcat, so this passes with one that is not built from the fork.
#[test]
#[ignore = "needs a hashcat: `make test-hashcat`"]
fn the_run_of_the_proof_cracks_the_example_line_hashcat_has_for_a_mode_of_its_own() {
    let hashcat = Hashcat::from_environment().unwrap_or_else(|| panic!("{BINARY} is not set. It has to hold the path of a hashcat binary."));
    let info = hashcat.info(13600).unwrap_or_else(|fault| panic!("{fault}")).expect("mode 13600");
    // a row of it is a name filled up with dots, a colon and the value
    let field = |name: &str| info.lines().filter_map(|row| row.split_once(": ")).find(|(key, _)| key.trim().trim_end_matches('.') == name).map_or_else(|| panic!("no {name} in:\n{info}"), |(_, value)| value.trim().to_owned());
    assert_eq!(field("Example.Hash.Format"), "plain");
    let directory = tempfile::tempdir().unwrap();
    let cracked = hashcat.crack(13600, &field("Example.Hash"), &field("Example.Pass"), directory.path(), 0);
    assert_eq!(cracked, Ok(()), "{}", hashcat.version().unwrap_or_default());

    // and with a list that does not hold the password, the same run is a failure
    let missed = hashcat.crack(13600, &field("Example.Hash"), "archivewolf-wrong-3", directory.path(), 1);
    assert_eq!(missed, Err("hashcat went through the list and accepted none of the three words, the password among them".to_owned()));
}

// ---------------------------------------------------------------------------
// The proof itself, held to its word with a stand-in for hashcat
// ---------------------------------------------------------------------------

/// The stand-in for hashcat: a bash script that is told the modes it has and what it answers, and
/// then takes the arguments of hashcat. It answers where the proof looks: `--version`,
/// `--hash-info -m MODE`, and a run over a file of lines and a file of words.
const STAND_IN: &str = r#"#!/usr/bin/env bash
# Stands in for hashcat in tests/hashcat_crack_test.rs. It tests no password.
#
#   hashcat-stand-in.sh MODES ANSWER [arguments of hashcat]
#
# MODES are the hash modes it is to have, separated by spaces. ANSWER is what it does with a
# line and a list of words:
#
#   password        report the second word of the list for the line, which is the password
#   wrong-word      report the first word for the line
#   another-line    report the second word for a line it was not given
#   nothing-found   end as hashcat ends when no word of the list was accepted
#   silent-success  end as if the line were cracked, and report nothing
#   broken          end as hashcat ends when it cannot run
set -euo pipefail

modes=" $1 "
answer="$2"
shift 2

info=0
mode=""
out=""
hashes=""
words=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      echo "v0.0.0-stand-in"
      exit 0
      ;;
    --hash-info) info=1 ;;
    -m)
      mode="$2"
      shift
      ;;
    -o)
      out="$2"
      shift
      ;;
    -a | --session | --runtime | --outfile-format) shift ;;
    -*) ;;
    *)
      if [[ -z "${hashes}" ]]; then hashes="$1"; else words="$1"; fi
      ;;
  esac
  shift
done

if [[ "${modes}" != *" ${mode} "* ]]; then
  echo "module_${mode}.so: cannot open shared object file: No such file or directory" >&2
  exit 254
fi
if [[ "${info}" == 1 ]]; then
  echo "Hash mode #${mode}"
  exit 0
fi

# Write what hashcat writes for a crack: a line, a colon, and word NUMBER of the list in hex.
report() {
  local number="$1" line="$2" word hex
  word="$(sed -n "${number}p" "${words}")"
  hex="$(printf '%s' "${word}" | od -An -v -tx1 | tr -d ' \n')"
  printf '%s:%s\n' "${line}" "${hex}" > "${out}"
}
given="$(< "${hashes}")"

case "${answer}" in
  password) report 2 "${given}" ;;
  wrong-word) report 1 "${given}" ;;
  another-line) report 2 "not-the-line-it-was-given" ;;
  nothing-found) exit 1 ;;
  silent-success) exit 0 ;;
  broken)
    echo "No devices found/left." >&2
    exit 255
    ;;
  *)
    echo "hashcat-stand-in.sh: no answer ${answer}" >&2
    exit 2
    ;;
esac
"#;

/// The stand-in reports the second word of the list for the line it was given: the password.
const REPORTS_THE_PASSWORD: &str = "password";

/// It reports the first word, which is not the password.
const REPORTS_A_WRONG_WORD: &str = "wrong-word";

/// It reports the password for a line it was not given.
const REPORTS_ANOTHER_LINE: &str = "another-line";

/// It ends as hashcat ends when no word of the list was accepted.
const FINDS_NOTHING: &str = "nothing-found";

/// It ends as if it had cracked the line, and reports nothing.
const CLAIMS_AND_REPORTS_NOTHING: &str = "silent-success";

/// It ends as hashcat ends when it cannot run at all.
const BREAKS: &str = "broken";

/// Write the stand-in into a directory, and give it the modes it is to have and its answer.
fn stand_in(directory: &Path, modes: &[u32], answer: &str) -> Result<Hashcat, String> {
    let path = directory.join("hashcat-stand-in.sh");
    std::fs::write(&path, STAND_IN).map_err(|error| format!("{}: {error}", path.display()))?;
    let modes: Vec<String> = modes.iter().map(u32::to_string).collect();
    Ok(Hashcat { program: "bash".into(), leading: vec![path.into_os_string(), modes.join(" ").into(), answer.into()] })
}

#[test]
fn without_a_hashcat_the_proof_fails_and_names_the_variable() {
    let fault = prove(None, &plan().unwrap()).expect_err("a proof without a hashcat");
    assert!(fault.contains("ARCHIVEWOLF_HASHCAT is not set"), "{fault}");
}

#[test]
fn a_hashcat_that_does_not_start_or_is_not_one_fails_the_proof() {
    let plan = plan().unwrap();
    let missing = Hashcat { program: "tests/fixtures/no-hashcat-here".into(), leading: Vec::new() };
    let fault = prove(Some(&missing), &plan).expect_err("a proof with a binary that is not there");
    assert!(fault.contains("tests/fixtures/no-hashcat-here could not be started"), "{fault}");

    // a program that runs and knows no --version
    let other = Hashcat { program: "bash".into(), leading: vec!["-c".into(), "exit 3".into()] };
    let fault = prove(Some(&other), &plan).expect_err("a proof with a program that is not hashcat");
    assert!(fault.contains("It is not a hashcat that runs"), "{fault}");
}

#[test]
fn a_hashcat_with_none_of_the_modes_fails_the_proof() {
    let directory = tempfile::tempdir().unwrap();
    let stock = stand_in(directory.path(), &[0, 13600, 17200], REPORTS_THE_PASSWORD).unwrap();
    let fault = prove(Some(&stock), &plan().unwrap()).expect_err("a proof with a hashcat that has no mode of the fork");
    assert!(fault.contains("hashcat v0.0.0-stand-in has none of the modes [46100, "), "{fault}");
}

#[test]
fn a_hashcat_with_only_modes_that_have_no_line_fails_the_proof() {
    let directory = tempfile::tempdir().unwrap();
    let keys_only = stand_in(directory.path(), &[46400, 46410], REPORTS_THE_PASSWORD).unwrap();
    let fault = prove(Some(&keys_only), &plan().unwrap()).expect_err("a proof that had nothing to test");
    assert!(fault.contains("nothing was tested"), "{fault}");
}

#[test]
fn the_modes_a_hashcat_has_are_tested_and_the_others_are_reported() {
    let plan = plan().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let zip_branch = stand_in(directory.path(), &[46100, 46200, 46300, 46310, 46320, 46400, 46410], REPORTS_THE_PASSWORD).unwrap();
    let proof = prove(Some(&zip_branch), &plan).unwrap();

    let planned = plan.lines.iter().filter(|planned| planned.mode < 46500).count();
    assert!(planned >= 10, "{planned} lines for the ZIP modes");
    assert_eq!((proof.cracked.len(), proof.failed.len()), (planned, 0), "{}", proof.report());
    for mode in [46100, 46200, 46300, 46310, 46320] {
        assert!(proof.cracked.iter().any(|line| line.starts_with(&format!("mode {mode}, "))), "mode {mode}: {}", proof.report());
    }

    // the RAR and 7-Zip modes are on other branches, and the two modes for keys have no line
    let not_covered: Vec<u32> = proof.not_covered.iter().map(|(mode, _)| *mode).collect();
    assert_eq!(not_covered, [46400, 46410, 46500, 46600, 46700, 46800, 46900], "{}", proof.report());
    let report = proof.report();
    assert!(report.starts_with(&format!("hashcat v0.0.0-stand-in: {planned} lines cracked, 0 not cracked, 7 of 12 modes not covered.")), "{report}");
    assert!(report.contains("not covered  mode 46400: this hashcat has the mode, and no recorded line is cracked for it"), "{report}");
    assert!(report.contains("left out     mode 46100: zip-crypto-header-only is left out, the line tests one byte"), "{report}");
    assert!(report.contains("left out     mode 46320: zip-pkware-securezip is left out, its password is not known"), "{report}");
    assert!(report.contains("not covered  mode 46900: this hashcat does not have the mode"), "{report}");
    assert!(report.contains("cracked      mode 46100, zip-crypto-deflate (tests/fixtures/zip-crypto/noradi.zip)"), "{report}");
}

#[test]
fn a_line_that_is_not_cracked_with_its_password_fails() {
    let plan = plan().unwrap();
    let expected = plan.lines.iter().filter(|planned| planned.mode == 46800).count();
    assert!(expected >= 2, "{expected} lines for mode 46800");

    for (answer, what) in [
        (REPORTS_A_WRONG_WORD, "hashcat gave `archivewolf-wrong-1` for the line, and its password is `gutenberg`"),
        (REPORTS_ANOTHER_LINE, "hashcat gave a word for another line than the one it was given: not-the-line-it-was-given"),
        (FINDS_NOTHING, "accepted none of the three words"),
        (CLAIMS_AND_REPORTS_NOTHING, "hashcat ended as if it had cracked the line and wrote 0 cracks"),
        (BREAKS, "hashcat ended with exit status: 255: No devices found/left."),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let proof = prove(Some(&stand_in(directory.path(), &[46800], answer).unwrap()), &plan).unwrap();
        assert_eq!((proof.cracked.len(), proof.failed.len()), (0, expected), "{answer}: {}", proof.report());
        assert!(proof.failed.iter().all(|line| line.starts_with("mode 46800, rar-50-") && line.contains(what)), "{answer}: {}", proof.report());
        assert!(proof.report().contains(&format!("0 lines cracked, {expected} not cracked, 11 of 12 modes not covered.")), "{}", proof.report());
    }
}

#[test]
fn what_hashcat_writes_for_a_crack_is_read_as_the_line_and_the_word() {
    let read = |outfile: &str| cracks_of(outfile);
    assert_eq!(read("$rar$15$*967e05a2*57*57*30*11$/rar$:68617368636174\n"), Ok(vec![("$rar$15$*967e05a2*57*57*30*11$/rar$".to_owned(), b"hashcat".to_vec())]));
    // a word with a colon and a word that is not text: both come as hex
    assert_eq!(read("$7z$*19**cefd04dc*1c**1*08*20*1c**e7$/7z$:703a772a6424\n"), Ok(vec![("$7z$*19**cefd04dc*1c**1*08*20*1c**e7$/7z$".to_owned(), b"p:w*d$".to_vec())]));
    assert_eq!(read("$zip$2$*1*00*00*00*0*0*$/zip$:ff00\n").map(|cracks| cracks[0].1.clone()), Ok(vec![0xff, 0x00]));
    assert_eq!(read("a:61\nb:62\n").map(|cracks| cracks.len()), Ok(2));
    assert_eq!(read(""), Ok(Vec::new()));

    assert!(read("no colon here\n").is_err());
    assert!(read("$zip$2$*1*00$/zip$:hashcat\n").is_err(), "a word that is not hex");
    assert!(read("$zip$2$*1*00$/zip$:616\n").is_err(), "half a byte");
    assert_eq!(bytes_of_hex(""), Some(Vec::new()));
}

#[test]
fn every_mode_with_a_line_has_lines_to_crack_and_each_has_its_password() {
    let plan = plan().unwrap();
    let lines_of = |mode: u32| plan.lines.iter().filter(|planned| planned.mode == mode).count();
    for mode in [46100, 46200, 46300, 46310, 46320, 46500, 46600, 46700, 46800, 46900] {
        assert!(lines_of(mode) >= 2, "mode {mode} has {} recorded lines to crack", lines_of(mode));
    }
    // `$zip$4$` is written by the tabled `attack zip-crypto` only: no fixture gives one
    for mode in [46400, 46410] {
        assert_eq!(lines_of(mode), 0, "mode {mode}");
    }
    assert_eq!(plan.lines.iter().filter(|planned| !MODES.contains(&planned.mode)).count(), 0, "a line for a mode that is not one of {MODES:?}");
    assert!(plan.left_out.iter().all(|(mode, reason)| MODES.contains(mode) && reason.contains(" is left out, ")), "{:?}", plan.left_out);
}
