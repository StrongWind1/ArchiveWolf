//! The three archive formats, and what they share.
//!
//! Each format lives in a module of its own and has one way in, `analyse` in its `analyse.rs`:
//! a [`source::Source`] goes in, and the analysis of the archive and its hash lines come out
//! ([`crate::analysis::Analysed`]). What the formats share is here: the source they read from,
//! the limits and the bounded decoders.

pub mod decode;
pub mod limits;
pub mod rar;
pub mod sevenz;
pub mod source;
pub mod zip;

/// How far into a file an archive can start behind the program of a self-extracting archive.
///
/// The scanner and the format code read this one value, so a file the scanner accepts is a
/// file the parser finds its archive in. It is the distance 7-Zip itself searches.
pub(crate) const SFX_SCAN_LIMIT: usize = 1 << 23;
