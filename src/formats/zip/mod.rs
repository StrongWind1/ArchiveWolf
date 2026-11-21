//! ZIP and ZIP64 archives: their analysis and their hash lines.
//!
//! `analyse` holds the one way in. The archive is read by range: `parser` finds its end,
//! walks its central directory and says which volume of a set the file is, `data_extract`
//! reads the few bytes of an entry that the analysis shows or a line carries, and `triage`
//! streams an entry through a decoder for the proof of pseudo-encryption. `encryption`
//! names the scheme an entry is marked with, `scoring` ranks the entries of a scheme, and
//! `lines` writes the text of the lines.

pub(crate) mod analyse;
#[cfg(test)]
mod coverage;
#[cfg(test)]
mod craft;
pub(crate) mod data_extract;
pub(crate) mod encryption;
pub(crate) mod extra_fields;
pub(crate) mod headers;
pub(crate) mod known;
pub(crate) mod lines;
#[cfg(test)]
mod mutation;
pub(crate) mod parser;
pub(crate) mod scoring;
pub(crate) mod triage;
