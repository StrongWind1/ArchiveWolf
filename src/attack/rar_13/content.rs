//! What a file of a name starts with: the signatures the key search holds decrypted entries
//! against, when the checksum of an archive leaves several keys.
//!
//! A signature is taken only when it is four bytes or more, and every one here is the start
//! of every file of its kind: a file with one of these names that starts otherwise is not
//! recognised, which costs a pick and never gives a wrong one. Kinds whose files start with
//! fewer fixed bytes are left out (a program starts with `MZ`, a bitmap with `BM`), and so
//! are text files, which the search recognises as text.

/// The signatures of one kind of file: its names end in a dot and one of `extensions`, and it
/// starts with one of `starts`.
struct Kind {
    extensions: &'static [&'static str],
    starts: &'static [&'static [u8]],
}

const KINDS: &[Kind] = &[
    // archives: an office document, a Java archive and an electronic book are ZIP archives
    Kind { extensions: &["zip", "jar", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub"], starts: &[b"PK\x03\x04"] },
    Kind { extensions: &["rar"], starts: &[b"Rar!\x1a\x07", b"RE~^"] },
    Kind { extensions: &["7z"], starts: &[b"7z\xbc\xaf\x27\x1c"] },
    // pictures
    Kind { extensions: &["gif"], starts: &[b"GIF87a", b"GIF89a"] },
    Kind { extensions: &["png"], starts: &[b"\x89PNG\r\n\x1a\n"] },
    Kind { extensions: &["jpg", "jpeg"], starts: &[b"\xff\xd8\xff\xe0", b"\xff\xd8\xff\xe1", b"\xff\xd8\xff\xdb", b"\xff\xd8\xff\xee"] },
    Kind { extensions: &["tif", "tiff"], starts: &[b"II*\x00", b"MM\x00*"] },
    // sound and film in the RIFF container, and MIDI
    Kind { extensions: &["wav", "avi"], starts: &[b"RIFF"] },
    Kind { extensions: &["mid", "midi"], starts: &[b"MThd"] },
    // documents
    Kind { extensions: &["pdf"], starts: &[b"%PDF-"] },
    Kind { extensions: &["ps", "eps"], starts: &[b"%!PS"] },
    Kind { extensions: &["rtf"], starts: &[b"{\\rtf"] },
    // data
    Kind { extensions: &["db", "sqlite", "sqlite3"], starts: &[b"SQLite format 3\x00"] },
    Kind { extensions: &["class"], starts: &[b"\xca\xfe\xba\xbe"] },
];

/// The fewest bytes a signature of the table has: fewer fit a wrong key too often.
#[cfg(test)]
const SHORTEST: usize = 4;

/// Whether `content` starts with a signature that the name of its entry implies.
#[must_use]
pub(crate) fn starts_as_named(name: &[u8], content: &[u8]) -> bool {
    let name = String::from_utf8_lossy(name).to_ascii_lowercase();
    let Some((_, extension)) = name.rsplit_once('.') else { return false };
    KINDS.iter().filter(|kind| kind.extensions.contains(&extension)).flat_map(|kind| kind.starts).any(|start| content.starts_with(start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_recognised_by_the_start_its_name_implies() {
        assert!(starts_as_named(b"PICTURE.GIF", b"GIF89a\x10\x00\x10\x00"));
        assert!(starts_as_named(b"DIR\\OLD.ZIP", b"PK\x03\x04\x0a\x00"));
        assert!(starts_as_named(b"photo.jpeg", b"\xff\xd8\xff\xe1\x00\x10Exif"));
        assert!(starts_as_named(b"paper.pdf", b"%PDF-1.2"));
        // an office document is a ZIP archive: it starts as one, and not with a member of it
        assert!(starts_as_named(b"report.docx", b"PK\x03\x04\x14\x00"));
        assert!(!starts_as_named(b"report.docx", b"<?xml version=\"1.0\""));
    }

    #[test]
    fn nothing_else_is() {
        // another start, another name, no name, and a name without a kind
        assert!(!starts_as_named(b"PICTURE.GIF", b"GIF90a\x10\x00"));
        assert!(!starts_as_named(b"PICTURE.TXT", b"GIF89a\x10\x00"));
        assert!(!starts_as_named(b"", b"GIF89a"));
        assert!(!starts_as_named(b"GIF", b"GIF89a"));
        // content that is shorter than the signature
        assert!(!starts_as_named(b"a.png", b"\x89PNG"));
        // a kind whose files start with fewer than four fixed bytes says nothing
        assert!(!starts_as_named(b"OLD.ARJ", b"\x60\xea\x00\x00"));
        assert!(!starts_as_named(b"PROGRAM.EXE", b"MZ\x90\x00"));
    }

    #[test]
    fn every_signature_is_four_bytes_or_more_and_no_extension_stands_twice() {
        let mut seen = Vec::new();
        for kind in KINDS {
            for extension in kind.extensions {
                assert!(!seen.contains(extension), "{extension} stands twice");
                assert_eq!(*extension, extension.to_ascii_lowercase());
                seen.push(extension);
            }
        }
        for start in KINDS.iter().flat_map(|kind| kind.starts) {
            assert!(start.len() >= SHORTEST, "{start:?}");
        }
        assert!(KINDS.iter().all(|kind| !kind.starts.is_empty()));
    }
}
