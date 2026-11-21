//! One name for one thing: the naming standard, held against the code, the fixtures, the
//! recorded lines and what the tool prints.
//!
//! A name is defined once, in the code. What the repository says of the names is held here in
//! every run: the README, the security policy and the notes of the fixtures.
//!
//! The guides of the tool are kept outside the repository. They show the names in tables that
//! are marked with `<!-- names: ... -->`. When `ARCHIVEWOLF_GUIDES` names their folder, this
//! file also fails when a table and the code differ, so a name cannot change in one place
//! only. Without it those tests hold nothing and pass.

#![expect(unused_crate_dependencies, reason = "integration test")]

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use archivewolf::analysis::Format;
    use archivewolf::analysis::Found;
    use archivewolf::analysis::Generation;
    use archivewolf::analysis::Reason;
    use archivewolf::analysis::Scheme;
    use archivewolf::analysis::Scope;
    use archivewolf::analysis::State;
    use archivewolf::line::Proves;
    use archivewolf::line::Tag;
    use assert_cmd::Command;
    use serde_json::Value;

    /// The folder of the guides, when the environment names one.
    fn guide_folder() -> Option<std::path::PathBuf> {
        std::env::var_os("ARCHIVEWOLF_GUIDES").map(std::path::PathBuf::from)
    }

    /// The path of one guide, by its file name.
    fn guide(name: &str) -> Option<String> {
        guide_folder().map(|folder| folder.join(name).to_string_lossy().into_owned())
    }

    /// The fixture directories that are not named after a scheme: they say what their archives
    /// have in common.
    const OTHER_FIXTURES: [&str; 5] = ["pseudo", "regress", "unencrypted", "unknown-pw", "unparseable"];

    /// The names the standard replaced. None of them stands in a document as a name any more.
    const REPLACED: [&str; 10] = ["zipcrypto", "zip-winzip-aes", "zip-strong", "winzip-aes", "pkware-ses", "rar13", "rar15", "rar20", "rar30", "rar50"];

    /// The guides, when their folder is named: none without it.
    fn guides() -> Vec<String> {
        let Some(folder) = guide_folder() else { return Vec::new() };
        let mut guides: Vec<String> = std::fs::read_dir(&folder).unwrap_or_else(|fault| panic!("{}: {fault}", folder.display())).map(|entry| entry.unwrap().path()).filter(|path| path.extension().is_some_and(|extension| extension == "md")).map(|path| path.to_string_lossy().into_owned()).collect();
        guides.sort();
        assert!(guides.len() >= 7, "{guides:?}");
        guides
    }

    /// The text of a document of the repository.
    fn document(path: &str) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|fault| panic!("{path}: {fault}"))
    }

    /// The rows of the table that `<!-- names: NAME -->` marks in `text`, each as its cells, without
    /// the row of headings and the row of dashes.
    fn marked_table(path: &str, text: &str, name: &str) -> Vec<Vec<String>> {
        let open = format!("<!-- names: {name} -->");
        let start = text.find(&open).unwrap_or_else(|| panic!("{path}: no table is marked `{open}`")) + open.len();
        let length = text[start..].find("<!-- /names -->").unwrap_or_else(|| panic!("{path}: the table `{name}` is not closed with `<!-- /names -->`"));
        let rows: Vec<Vec<String>> = text[start..start + length].lines().filter(|line| line.starts_with('|')).map(|line| line.trim_matches('|').split('|').map(|cell| cell.trim().to_owned()).collect()).collect();
        rows.get(2..).filter(|rows| !rows.is_empty()).unwrap_or_else(|| panic!("{path}: the table `{name}` has no rows")).to_vec()
    }

    /// The names in the first cells of the table that `name` marks: what stands in backticks there.
    fn first_column(path: &str, text: &str, name: &str) -> Vec<String> {
        marked_table(path, text, name).iter().filter_map(|row| row.first()).flat_map(|cell| in_backticks(cell)).collect()
    }

    /// Everything that stands in backticks in `text`.
    fn in_backticks(text: &str) -> Vec<String> {
        text.split('`').skip(1).step_by(2).map(str::to_owned).collect()
    }

    /// `words` as a document lists alternatives: each in backticks, the last behind `or`.
    fn alternatives(words: &[&str]) -> String {
        let quoted: Vec<String> = words.iter().map(|word| format!("`{word}`")).collect();
        match quoted.as_slice() {
            [] => String::new(),
            [only] => only.clone(),
            [front @ .., last] => format!("{} or {last}", front.join(", ")),
        }
    }

    /// The name a value has in the JSON object.
    fn json_name(value: impl serde::Serialize) -> String {
        serde_json::to_value(value).unwrap().as_str().unwrap().to_owned()
    }

    /// What `expected` and the table differ in, for a message that says how to mend the document.
    fn compare(path: &str, name: &str, table: &[Vec<String>], expected: &[Vec<String>]) {
        let render = |rows: &[Vec<String>]| rows.iter().map(|row| format!("| {} |", row.join(" | "))).collect::<Vec<_>>().join("\n");
        assert!(table == expected, "{path}: the table `{name}` is not what the code holds. It has to read:\n\n{}\n\nand it reads:\n\n{}\n", render(expected), render(table));
    }

    #[test]
    fn the_schemes_the_qualifiers_and_the_tags_of_the_standard_are_those_of_the_code() {
        let Some(standard) = guide("ARCHIVEWOLF.md") else { return };
        let (text, standard) = (document(&standard), standard.as_str());

        let schemes: Vec<Vec<String>> = Scheme::ALL
            .into_iter()
            .map(|scheme| {
                let tags: Vec<String> = Tag::ALL.into_iter().filter(|tag| Scheme::of_line(*tag) == scheme).map(|tag| format!("`{tag}`")).collect();
                vec![format!("`{scheme}`"), scheme.label().to_owned(), if scheme.has_scope() { "yes" } else { "no" }.to_owned(), if tags.is_empty() { "none".to_owned() } else { tags.join(", ") }]
            })
            .collect();
        compare(standard, "schemes", &marked_table(standard, &text, "schemes"), &schemes);

        let qualifiers: Vec<Vec<String>> = Scheme::ALL
            .into_iter()
            .map(|scheme| {
                let places: Vec<String> = scheme.qualifiers().iter().map(|place| format!("{}{}", alternatives(place.words), if place.optional { ", when it applies" } else { "" })).collect();
                vec![format!("`{scheme}`"), if places.is_empty() { "none".to_owned() } else { places.join("; then ") }]
            })
            .collect();
        compare(standard, "qualifiers", &marked_table(standard, &text, "qualifiers"), &qualifiers);

        let tags: Vec<Vec<String>> = Tag::ALL.into_iter().map(|tag| vec![format!("`{tag}`"), tag.modes().iter().map(u32::to_string).collect::<Vec<_>>().join(", "), format!("`{}`", Scheme::of_line(tag))]).collect();
        compare(standard, "tags", &marked_table(standard, &text, "tags"), &tags);
    }

    #[test]
    fn the_lists_of_names_in_the_standard_are_those_of_the_code() {
        let Some(standard) = guide("ARCHIVEWOLF.md") else { return };
        let (text, standard) = (document(&standard), standard.as_str());
        let lists: [(&str, Vec<String>); 6] = [
            ("scopes", Scope::ALL.into_iter().map(|scope| scope.as_str().to_owned()).collect()),
            ("generations", Generation::ALL.into_iter().map(json_name).collect()),
            ("states", State::ALL.into_iter().map(|state| state.as_str().to_owned()).collect()),
            ("findings", Found::CODES.iter().map(|code| (*code).to_owned()).collect()),
            ("proof classes", [Proves::Exact, Proves::Structural, Proves::Weak { bits: 0 }].into_iter().map(json_name).collect()),
            ("reasons", Reason::ALL.into_iter().map(|reason| reason.as_str().to_owned()).collect()),
        ];
        for (name, expected) in lists {
            assert_eq!(first_column(standard, &text, name), expected, "{standard}: the table `{name}` does not list what the code holds, in its order");
        }

        // a generation holds the schemes of its format, and every scheme with a name is in one
        let mut held = BTreeSet::new();
        for row in marked_table(standard, &text, "generations") {
            let [generation, _, schemes] = row.as_slice() else { panic!("{standard}: a row of the table of generations has three cells: {row:?}") };
            let format = match generation.as_str() {
                name if name.contains("zip") => "zip",
                name if name.contains("rar") => "rar",
                _ => "7z",
            };
            if schemes == "the same" {
                continue;
            }
            for id in in_backticks(schemes) {
                let scheme = Scheme::of_variant(&id).unwrap_or_else(|| panic!("{standard}: `{id}` in the table of generations is no scheme"));
                assert!(scheme.as_str() == id && id.starts_with(format), "{standard}: `{id}` is not a scheme of {format}");
                assert!(held.insert(id.clone()), "{standard}: `{id}` is held by two generations");
            }
        }
        let named: BTreeSet<String> = Scheme::ALL.into_iter().filter(|scheme| !scheme.is_unknown()).map(|scheme| scheme.to_string()).collect();
        assert_eq!(held, named);
    }

    #[test]
    fn every_scheme_has_its_fixture_directory_and_every_directory_is_a_scheme_or_one_of_five() {
        let mut expected: BTreeSet<String> = Scheme::ALL.into_iter().filter(|scheme| !scheme.is_unknown()).map(|scheme| scheme.to_string()).collect();
        expected.extend(OTHER_FIXTURES.iter().map(|name| (*name).to_owned()));
        let found: BTreeSet<String> = std::fs::read_dir("tests/fixtures").unwrap().map(Result::unwrap).filter(|entry| entry.path().is_dir()).map(|entry| entry.file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(found, expected, "a fixture directory is named by the ID of its scheme");
    }

    /// The analysis of every fixture, as `info --json` prints it.
    fn analyses() -> Vec<Value> {
        let output = Command::cargo_bin("archivewolf").unwrap().args(["-q", "info", "--json", "tests/fixtures"]).output().unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        let all: Vec<Value> = text.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert!(all.len() > 400, "the fixtures were not read: {} archives", all.len());
        all
    }

    /// The IDs in the registry of a format guide: what Part 2 of the guide lists as its variants.
    /// `None` when the guides are not at hand.
    fn registry(format: Format) -> Option<(String, Vec<String>)> {
        let (file, prefix) = match format {
            Format::Zip => ("ZIP.md", "zip-"),
            Format::Rar => ("RAR.md", "rar-"),
            Format::SevenZ => ("7Z.md", "7z-"),
        };
        let path = guide(file)?;
        let ids = first_column(&path, &document(&path), "variants");
        for id in &ids {
            assert!(Scheme::of_variant(id).is_some(), "{path}: `{id}` in the registry is no variant ID");
            assert!(id.starts_with(prefix), "{path}: `{id}` is not a variant of this format");
        }
        Some((path, ids))
    }

    #[test]
    fn every_scheme_and_variant_the_tool_prints_is_in_the_standard_and_in_the_guide_of_its_format() {
        // the registries of the three guides, or none without the guides
        let registries: Vec<(&str, (String, Vec<String>))> = [("zip", Format::Zip), ("rar", Format::Rar), ("7z", Format::SevenZ)].into_iter().filter_map(|(name, format)| Some((name, registry(format)?))).collect();
        let mut printed: BTreeSet<(String, String, String)> = BTreeSet::new();
        for analysis in analyses() {
            let format = analysis["format"].as_str().unwrap().to_owned();
            let rows = analysis["schemes"].as_array().unwrap().iter().chain(analysis["entry_list"].as_array().unwrap());
            for row in rows.filter(|row| row.get("scheme").is_some()) {
                let _ = printed.insert((format.clone(), row["scheme"].as_str().unwrap().to_owned(), row["variant"].as_str().unwrap().to_owned()));
            }
            // what names a scheme without a variant: a line that is missing, and a finding
            for missing in analysis["no_line"].as_array().unwrap().iter().filter_map(|missing| missing.get("scheme")) {
                let name = missing.as_str().unwrap();
                assert!(Scheme::ALL.iter().any(|scheme| scheme.as_str() == name), "{}: `{name}` is no scheme", analysis["path"]);
            }
        }
        assert!(printed.len() > 20, "the fixtures give more variants than {}", printed.len());

        for (format, scheme, variant) in &printed {
            let named = Scheme::of_variant(variant).unwrap_or_else(|| panic!("`{variant}` is printed and is no variant ID"));
            assert_eq!(named.as_str(), scheme, "`{variant}` is printed beside the scheme `{scheme}`");
            assert!(scheme.starts_with(&format!("{format}-")), "`{scheme}` is printed for an archive of {format}");
            if let Some((_, (path, ids))) = registries.iter().find(|(name, _)| name == format) {
                assert!(ids.iter().any(|id| variant == id || variant.starts_with(&format!("{id}:"))), "{path}: the registry does not list `{variant}`, which the tool prints for a fixture");
            }
        }

        // every scheme with a name is in the registry of its format, and has a fixture that gives it
        for scheme in Scheme::ALL.into_iter().filter(|scheme| !scheme.is_unknown()) {
            assert!(printed.iter().any(|(_, name, _)| name == scheme.as_str()), "no fixture gives the scheme `{scheme}`");
        }
        for scheme in Scheme::ALL.into_iter().filter(|_| !registries.is_empty()) {
            let listed = registries.iter().any(|(_, (_, ids))| ids.iter().any(|id| Scheme::of_variant(id) == Some(scheme)));
            assert!(listed, "no guide lists a variant of `{scheme}`");
        }
    }

    #[test]
    fn every_recorded_case_is_named_after_the_scheme_of_its_line() {
        let manifest: Value = serde_json::from_str(&document("tests/golden/manifest.json")).unwrap();
        let cases = manifest["lines"].as_array().unwrap();
        assert!(cases.len() > 30);
        for case in cases {
            let (name, tag) = (case["case"].as_str().unwrap(), case["tag"].as_str().unwrap());
            let scheme = Tag::ALL.into_iter().find(|known| known.as_str() == tag).map_or_else(|| panic!("{name}: `{tag}` is no tag"), Scheme::of_line);
            assert!(name.starts_with(&format!("{scheme}-")), "the case `{name}` holds a line of `{scheme}` and is not named after it");
            assert!(Path::new("tests/golden").join(format!("{name}.line")).is_file(), "{name}: no line is recorded");
            let fixture = case["fixture"].as_str().unwrap();
            assert!(Path::new("tests/fixtures").join(fixture).is_file(), "{name}: {fixture} is no fixture");
        }
    }

    #[test]
    fn no_document_names_a_scheme_by_a_name_the_standard_replaced() {
        let mut documents = vec!["README.md".to_owned(), "SECURITY.md".to_owned(), "tests/fixtures/FIXTURES.md".to_owned()];
        documents.extend(guides());
        let mut faults = Vec::new();
        for path in &documents {
            for (number, line) in document(path).lines().enumerate() {
                for name in in_backticks(line) {
                    // the name alone, or with what follows a name: parameters, a path, a qualifier
                    let first = name.split([':', '/', ' ']).next().unwrap_or_default();
                    if REPLACED.contains(&first) {
                        faults.push(format!("{path}:{}: `{name}`", number + 1));
                    }
                }
            }
        }
        assert!(faults.is_empty(), "a scheme is named by its ID:\n{}", faults.join("\n"));
    }

    #[test]
    fn every_variant_id_in_a_document_is_one_the_grammar_reads() {
        let mut faults = Vec::new();
        for path in guides().into_iter().chain(["README.md".to_owned(), "tests/fixtures/FIXTURES.md".to_owned()]) {
            for (number, line) in document(&path).lines().enumerate() {
                for name in in_backticks(line) {
                    // what starts as the ID of a scheme and goes on with a colon is meant as a variant ID
                    let Some((scheme, _)) = name.split_once(':') else { continue };
                    if Scheme::ALL.iter().any(|known| known.as_str() == scheme) && !name.contains(' ') && Scheme::of_variant(&name).is_none() {
                        faults.push(format!("{path}:{}: `{name}`", number + 1));
                    }
                }
            }
        }
        assert!(faults.is_empty(), "these are written as variant IDs and are none:\n{}", faults.join("\n"));
    }
}
