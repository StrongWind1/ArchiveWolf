//! What is known of the encrypted stream of a `zip-crypto` entry without its key.
//!
//! Everything here is read from the headers of an archive, and from the data of entries that
//! are not encrypted: `info` reports it, and `attack zip-crypto` starts from it. Nothing here
//! searches and nothing here takes a key.

pub(crate) mod claim;
pub(crate) mod directory;
pub(crate) mod header;
pub(crate) mod method;
pub(crate) mod set;
#[cfg(test)]
pub(crate) mod testing;
pub(crate) mod types;
pub(crate) mod writer;

use self::claim::Certainty;
use self::claim::Claim;
use self::claim::Form;
use self::claim::Origin;
use self::header::CheckBytes;
use self::method::Layout;
use self::types::Row;
use self::writer::Writer;
use super::parser::ZipEntry;

/// What the archive itself says of one encrypted entry.
#[derive(Debug, Clone)]
pub(crate) struct Facts {
    /// How the content of the entry lies in its stream.
    pub layout: Layout,
    /// The ways its encryption header may end, the surest first.
    pub checks: Vec<CheckBytes>,
    /// What its method and its name say of its stream, in positions of the stream.
    pub claims: Vec<Claim>,
    /// The type of file its name says, when the table has a row for it.
    pub kind: Option<&'static Row>,
    /// Whether the row of its type could not be used, because the entry is packed and its
    /// content does not show in its stream.
    pub kind_unused: bool,
}

/// What the headers of an archive say of the entry: its check bytes, the form its method
/// gives its stream, and what a file of its type starts and ends with. `kind` is the type the
/// user gave for the entry, which counts over its name.
#[must_use]
pub(crate) fn facts(entry: &ZipEntry, writer: Writer, kind: Option<&'static Row>) -> Facts {
    let layout = Layout::of(entry);
    let checks = header::check_bytes(entry, writer);
    let mut claims = method::claims(entry, writer);
    let kind = kind.or_else(|| types::by_entry(&entry.filename));
    let mut kind_unused = false;
    if let Some(row) = kind {
        // a start that is worked out through the fixed code of Deflate is one guess on another
        let certainty = if layout == Layout::Packed { Certainty::Guess } else { Certainty::Likely };
        let what = if layout == Layout::Packed { format!("start of {} in the fixed code of Deflate", row.what) } else { format!("signature of {}", row.what) };
        let forms: Vec<_> = row.forms(entry.uncompressed_size).iter().filter_map(|form| layout.place(form, entry)).filter(|form| !form.is_empty()).collect();
        kind_unused = forms.is_empty() && layout == Layout::Packed;
        if !forms.is_empty() {
            claims.push(Claim { origin: Origin::Name, certainty, what, forms });
        }
    }
    Facts { layout, checks, claims, kind, kind_unused }
}

/// The longest run of known bytes of an entry that a search could start from, with where it
/// comes from and how sure it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KnownRun {
    /// Where the bytes come from.
    pub origin: Origin,
    /// How sure the claim is, with the check bytes that go into the run.
    pub certainty: Certainty,
    /// How many bytes are known in a row.
    pub len: u64,
}

/// The run that the claims of an entry give with its check bytes: the longest, and of two
/// that are as long the surer. The forms of a claim are alternatives, the most usual first:
/// a claim counts with the first of its forms that gives a run, not with its longest. A claim
/// that is a guess does not count: what may be so is not known. `None` when no claim gives
/// eight bytes in a row.
#[must_use]
pub(crate) fn known_run(facts: &Facts, more: &[&Claim]) -> Option<KnownRun> {
    let way = facts.checks.first()?;
    let base = facts.claims.iter().filter(|claim| claim.origin == Origin::Method && claim.certainty >= Certainty::Derived).flat_map(|claim| &claim.forms).fold(Form::new(), |base, form| base.merged(form).unwrap_or(base));
    let mut best: Option<KnownRun> = None;
    for claim in facts.claims.iter().chain(more.iter().copied()).filter(|claim| claim.certainty > Certainty::Guess) {
        let Some(run) = claim.forms.iter().find_map(|form| form.merged(&base).and_then(|form| form.merged(&way.form)).and_then(|form| form.best_run(false))) else { continue };
        let found = KnownRun { origin: claim.origin, certainty: claim.certainty.min(way.certainty), len: run.len };
        if best.is_none_or(|so_far| (found.len, found.certainty) > (so_far.len, so_far.certainty)) {
            best = Some(found);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::testing::entry;
    use super::*;

    #[test]
    fn the_name_of_a_stored_entry_gives_the_start_of_its_stream() {
        let png = entry("photos/scan.PNG", 0, 1, 5000, 5012);
        let facts = facts(&png, Writer::SevenZip, None);
        assert_eq!((facts.layout, facts.kind.map(|row| row.name.as_str()), facts.kind_unused), (Layout::Stored, Some("png"), false));
        assert_eq!(facts.claims.len(), 1);
        assert_eq!((facts.claims[0].origin, facts.claims[0].certainty, facts.claims[0].what.as_str()), (Origin::Name, Certainty::Likely, "signature of a PNG image"));
        assert_eq!(facts.claims[0].forms[0].stretches().first(), Some(&(0, 18)));

        // with the check byte in front, a run of nineteen
        let with_check = facts.claims[0].forms[0].merged(&facts.checks[0].form).unwrap();
        let _: &Form = &with_check;
        assert_eq!(with_check.best_run(false).map(|run| (run.at, run.len)), Some((-1, 19)));
    }

    #[test]
    fn data_that_did_not_pack_has_its_signature_five_bytes_later() {
        let jpg = entry("a.jpg", 8, 1, 40_000, 40_017);
        let facts = facts(&jpg, Writer::Unknown, None);
        assert_eq!(facts.layout, Layout::StoredBlocks { blocks: 1 });
        // the header of the block from the method, the signature from the name
        assert_eq!(facts.claims.iter().map(|claim| claim.origin).collect::<Vec<_>>(), [Origin::Method, Origin::Name]);
        let jfif = facts.claims[1].forms[0].merged(&facts.claims[0].forms[0]).unwrap().merged(&facts.checks[0].form).unwrap();
        assert_eq!(jfif.best_run(false).map(|run| (run.at, run.len)), Some((-1, 18)));
        assert_eq!(jfif.get(5), Form::bytes(5, &[0xff]).get(5));
    }

    #[test]
    fn the_longest_run_of_an_entry_is_that_of_its_surest_longest_claim() {
        // a PNG image, stored: its signature with the check byte in front
        let png = facts(&entry("scan.png", 0, 1, 5000, 5012), Writer::SevenZip, None);
        assert_eq!(known_run(&png, &[]), Some(KnownRun { origin: Origin::Name, certainty: Certainty::Likely, len: 19 }));
        // a copy that is not encrypted is certain, and longer
        let copy = Claim::new(Origin::Directory, Certainty::Certain, "copy", Form::bytes(0, &[7; 300]));
        assert_eq!(known_run(&png, &[&copy]), Some(KnownRun { origin: Origin::Directory, certainty: Certainty::Certain, len: 301 }));
        // a packed entry and a text file have none
        assert_eq!(known_run(&facts(&entry("report.pdf", 8, 1, 500_000, 400_000), Writer::Unknown, None), &[]), None);
        assert_eq!(known_run(&facts(&entry("notes.txt", 0, 1, 5000, 5012), Writer::Unknown, None), &[]), None);
        // data that did not pack, in one stored block: the head of the block and the check byte are seven, not eight
        assert_eq!(known_run(&facts(&entry("data.bin", 8, 1, 1000, 1017), Writer::SevenZip, None), &[]), None);
        // the start of an LZMA stream is a guess at the version of its writer: not known
        assert_eq!(known_run(&facts(&entry("data.bin", 14, 1, 1000, 500), Writer::SevenZip, None), &[]), None);
        // the start of a bzip2 stream is the same whatever was packed
        assert_eq!(known_run(&facts(&entry("data.bin", 12, 1, 1000, 500), Writer::SevenZip, None), &[]), Some(KnownRun { origin: Origin::Method, certainty: Certainty::Likely, len: 11 }));
    }

    #[test]
    fn the_row_of_a_packed_entry_is_not_used_and_that_is_said() {
        let packed = entry("report.pdf", 8, 1, 500_000, 400_000);
        let facts = facts(&packed, Writer::Unknown, None);
        assert_eq!((facts.layout, facts.claims.len(), facts.kind_unused), (Layout::Packed, 0, true));
        // the type the user names counts over the name
        let forced = super::facts(&entry("data.bin", 0, 1, 5000, 5012), Writer::Unknown, types::by_type("png"));
        assert_eq!(forced.claims[0].what, "signature of a PNG image");
        assert!(super::facts(&entry("data.bin", 0, 1, 5000, 5012), Writer::Unknown, None).claims.is_empty());
    }

    #[test]
    fn a_small_packed_file_of_a_known_type_starts_as_its_type_does_in_the_fixed_code() {
        let small = entry("page.html", 8, 1, 120, 110);
        let facts = facts(&small, Writer::Unknown, None);
        assert_eq!((facts.claims[0].certainty, facts.kind_unused), (Certainty::Guess, false));
        assert!(facts.claims[0].what.starts_with("start of an HTML page in the fixed code"));
        assert!(facts.claims[0].forms.iter().all(|form| form.stretches().first().is_some_and(|&(at, len)| at == 0 && len >= 10)));
        // a start that repeats itself is packed as a repeat, and nothing follows from it
        let pem = super::facts(&entry("id_rsa", 8, 1, 120, 110), Writer::Unknown, None);
        assert!(pem.claims.is_empty() && pem.kind_unused);
    }
}
