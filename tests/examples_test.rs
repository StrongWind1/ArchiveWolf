//! The examples of the documents are what the tool prints.
//!
//! A block that is fenced as `console` in the README holds one command, on a line that starts
//! with `$ archivewolf`, and behind it what the command prints. This test runs every such
//! command from the root of the repository and compares.
//!
//! The guides of the tool are kept outside the repository and have such blocks too. When
//! `ARCHIVEWOLF_GUIDES` names their folder, their examples are run as well.
//!
//! A block shows either standard output alone, or the terminal as it is: the lines of standard
//! output and of standard error together, each stream in its order. A command that ends in
//! `> FILE` is run without the redirection, and its block shows standard error alone, since
//! that is what a terminal shows of it.

#![expect(unused_crate_dependencies, reason = "integration test")]

#[cfg(test)]
mod tests {
    use assert_cmd::Command;

    /// One example: where it stands, its command and what the document shows behind it.
    struct Example {
        place: String,
        command: String,
        shown: Vec<String>,
    }

    /// The examples of one document.
    fn examples_of(path: &str) -> Vec<Example> {
        let text = std::fs::read_to_string(path).unwrap_or_else(|fault| panic!("{path}: {fault}"));
        let mut examples = Vec::new();
        let mut lines = text.lines().enumerate();
        while let Some((number, line)) = lines.next() {
            if line != "```console" {
                continue;
            }
            let block: Vec<&str> = lines.by_ref().map(|(_, line)| line).take_while(|line| *line != "```").collect();
            let place = format!("{path}:{}", number + 1);
            let Some((first, shown)) = block.split_first() else { panic!("{place}: an empty console block") };
            let command = first.strip_prefix("$ archivewolf ").unwrap_or_else(|| panic!("{place}: a console block starts with `$ archivewolf ` and one command"));
            assert!(!shown.iter().any(|line| line.starts_with("$ ")), "{place}: a console block holds one command");
            examples.push(Example { place, command: command.to_owned(), shown: shown.iter().map(|line| (*line).to_owned()).collect() });
        }
        examples
    }

    /// The words of a command line as a shell splits them. The examples use single quotes and no
    /// other quoting.
    fn words(command: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut word = String::new();
        let mut quoted = false;
        let mut open = false;
        for c in command.chars() {
            match c {
                '\'' => {
                    quoted = !quoted;
                    open = true;
                },
                ' ' if !quoted => {
                    if open {
                        words.push(std::mem::take(&mut word));
                        open = false;
                    }
                },
                other => {
                    word.push(other);
                    open = true;
                },
            }
        }
        if open {
            words.push(word);
        }
        words
    }

    /// Whether `shown` is the lines of `out` and of `err` together, each stream in its order.
    fn is_terminal(shown: &[String], out: &[&str], err: &[&str]) -> bool {
        // reach[i] holds, for the lines shown so far, whether i lines of `out` can be among them
        let mut reach = vec![false; out.len() + 1];
        if let Some(none_yet) = reach.first_mut() {
            *none_yet = true;
        }
        for (count, line) in shown.iter().enumerate() {
            let mut next = vec![false; out.len() + 1];
            for taken in 0..=out.len().min(count) {
                if !reach.get(taken).copied().unwrap_or(false) {
                    continue;
                }
                if out.get(taken).is_some_and(|expected| expected == line)
                    && let Some(slot) = next.get_mut(taken + 1)
                {
                    *slot = true;
                }
                if err.get(count - taken).is_some_and(|expected| expected == line)
                    && let Some(slot) = next.get_mut(taken)
                {
                    *slot = true;
                }
            }
            reach = next;
        }
        shown.len() == out.len() + err.len() && reach.last().copied().unwrap_or(false)
    }

    #[test]
    fn every_console_block_of_the_documents_shows_what_the_tool_prints() {
        let mut documents = vec!["README.md".to_owned()];
        if let Some(folder) = std::env::var_os("ARCHIVEWOLF_GUIDES") {
            let files = std::fs::read_dir(&folder).unwrap_or_else(|fault| panic!("{}: {fault}", folder.to_string_lossy()));
            documents.extend(files.map(|entry| entry.unwrap().path()).filter(|path| path.extension().is_some_and(|extension| extension == "md")).map(|path| path.to_string_lossy().into_owned()));
        }
        documents.sort();

        let mut run = 0;
        let mut faults = Vec::new();
        for example in documents.iter().flat_map(|path| examples_of(path)) {
            let mut arguments = words(&example.command);
            let redirected = arguments.iter().position(|word| word == ">");
            if let Some(at) = redirected {
                arguments.truncate(at);
            }
            let output = Command::cargo_bin("archivewolf").unwrap().args(&arguments).output().unwrap();
            let (stdout, stderr) = (String::from_utf8_lossy(&output.stdout).into_owned(), String::from_utf8_lossy(&output.stderr).into_owned());
            let (out, err): (Vec<&str>, Vec<&str>) = (stdout.lines().collect(), stderr.lines().collect());
            run += 1;

            let shown = &example.shown;
            let matches = if redirected.is_some() { shown.iter().map(String::as_str).eq(err.iter().copied()) } else { shown.iter().map(String::as_str).eq(out.iter().copied()) || is_terminal(shown, &out, &err) };
            if !matches {
                faults.push(format!("{}: `archivewolf {}` prints\n{stdout}and on standard error\n{stderr}", example.place, example.command));
            }
        }
        assert!(run >= 10, "the README alone holds more examples than {run}");
        assert!(faults.is_empty(), "{} of {run} examples do not show what the tool prints:\n\n{}", faults.len(), faults.join("\n"));
    }

    #[test]
    fn a_block_is_held_to_both_streams_in_their_order() {
        let lines = |text: &[&str]| text.iter().map(|line| (*line).to_owned()).collect::<Vec<_>>();
        assert!(is_terminal(&lines(&["note", "a", "b", "count"]), &["a", "b"], &["note", "count"]));
        assert!(is_terminal(&lines(&["a", "note", "b", "count"]), &["a", "b"], &["note", "count"]));
        assert!(is_terminal(&lines(&[]), &[], &[]));
        assert!(is_terminal(&lines(&["x", "x"]), &["x"], &["x"]));
        // a line that is missing, one too many, and a stream out of its order
        assert!(!is_terminal(&lines(&["note", "a", "count"]), &["a", "b"], &["note", "count"]));
        assert!(!is_terminal(&lines(&["note", "a", "b", "count", "more"]), &["a", "b"], &["note", "count"]));
        assert!(!is_terminal(&lines(&["count", "a", "b", "note"]), &["a", "b"], &["note", "count"]));
        assert!(!is_terminal(&lines(&["b", "a"]), &["a", "b"], &[]));

        assert_eq!(words("hash --mode 46800 a.zip  'b c.rar' > out.hash"), ["hash", "--mode", "46800", "a.zip", "b c.rar", ">", "out.hash"]);
    }
}
