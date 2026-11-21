//! What the commands print: the analysis as text and as JSON, a hash line as JSON, and the notes
//! `hash` writes beside its lines.
//!
//! Names, comments and paths come out of the archive or the file system, so nothing here trusts
//! them. Everything that is printed as text goes through [`sanitize`], line by line, and a
//! command meant to be pasted into a shell quotes its arguments with [`shell_quote`]. JSON is
//! escaped by the serializer and keeps every byte.

mod report;

use std::borrow::Cow;
use std::fmt::Write as _;

pub(crate) use report::info_json;
pub(crate) use report::info_text;
pub(crate) use report::line_json;
pub(crate) use report::line_note;
pub(crate) use report::line_origin;
pub(crate) use report::no_line_notes;

/// Whether a character can move the cursor, start a line or reorder the text around it.
///
/// The control characters (C0, DEL and C1), the two Unicode line separators, and the
/// bidirectional embedding, override and isolate characters.
fn acts_on_terminal(ch: char) -> bool {
    ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Write `ch` as an escape that shows what it is.
fn push_escape(out: &mut String, ch: char) {
    match ch {
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        _ if ch.is_ascii() => {
            let _ = write!(out, "\\x{:02x}", u32::from(ch));
        },
        _ => {
            let _ = write!(out, "\\u{{{:x}}}", u32::from(ch));
        },
    }
}

/// Replace every character `unsafe_char` names with its escape.
fn escape_where(text: &str, unsafe_char: impl Fn(char) -> bool) -> Cow<'_, str> {
    let Some(first) = text.find(&unsafe_char) else {
        return Cow::Borrowed(text);
    };
    let mut out = String::with_capacity(text.len().saturating_add(16));
    for (at, ch) in text.char_indices() {
        if at >= first && unsafe_char(ch) {
            push_escape(&mut out, ch);
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

/// Make text from an archive safe to print on a terminal.
///
/// Every control character is written as a visible escape: `\n`, `\r`, `\t`, `\x1b` for the
/// rest of C0 and DEL, `\u{9b}` for C1. So are the Unicode line separators and the characters
/// that reorder text. What comes back holds no character that moves the cursor or starts a
/// line, so one name can never be read as two lines of output. Text without such a character
/// is returned as it is.
///
/// Every line of plain output and every note on standard error is passed through this where
/// it is written, so the code that builds a message has nothing to do.
#[must_use]
pub fn sanitize(text: &str) -> Cow<'_, str> {
    escape_where(text, acts_on_terminal)
}

/// Quote `text` as one word of a POSIX shell command.
///
/// The text is put in single quotes, and a single quote in it is written `'\''`. Nothing is
/// special inside single quotes, so a name such as `x';touch PWNED;'.7z` stays one argument
/// when the printed command is pasted into `sh`, `bash`, `zsh` or `fish`.
///
/// This quotes and does nothing else: a control character stays as it is here and is escaped
/// by [`sanitize`] when the line is printed, which makes the command fail instead of acting
/// on the terminal.
#[must_use]
pub fn shell_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len().saturating_add(2));
    out.push('\'');
    for ch in text.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_every_control_character() {
        assert_eq!(sanitize("a\nb\rc\td"), "a\\nb\\rc\\td");
        assert_eq!(sanitize("\x1b[2K\x07\x00\x7f"), "\\x1b[2K\\x07\\x00\\x7f");
        assert_eq!(sanitize("\u{85}\u{9b}31m"), "\\u{85}\\u{9b}31m");
        assert_eq!(sanitize("a\u{2028}b\u{2029}c"), "a\\u{2028}b\\u{2029}c");
        assert_eq!(sanitize("\u{202e}txt.exe\u{2066}"), "\\u{202e}txt.exe\\u{2066}");

        // every code point of C0, DEL and C1, in the middle of a name
        for code in (0..0x20_u32).chain(0x7f..0xa0) {
            let ch = char::from_u32(code).unwrap();
            let clean = sanitize(&format!("name{ch}tail")).into_owned();
            assert!(!clean.chars().any(char::is_control), "U+{code:04X} left in {clean:?}");
            assert!(clean.starts_with("name\\") && clean.ends_with("tail"), "U+{code:04X}: {clean:?}");
        }
    }

    #[test]
    fn sanitize_leaves_ordinary_text_alone() {
        for text in ["", "plain.txt", "dir\\file name.txt", "пароль → ключ", "日本語.zip", "a'b\"c$d`e"] {
            assert!(matches!(sanitize(text), Cow::Borrowed(same) if same == text), "{text:?} was changed");
        }
    }

    #[test]
    fn shell_quote_keeps_one_word() {
        assert_eq!(shell_quote("plain.rar"), "'plain.rar'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("two words.7z"), "'two words.7z'");
        assert_eq!(shell_quote("x';touch PWNED;'.7z"), "'x'\\'';touch PWNED;'\\''.7z'");
        assert_eq!(shell_quote("$(id) `id` \"q\" \\"), "'$(id) `id` \"q\" \\'");
    }
}
