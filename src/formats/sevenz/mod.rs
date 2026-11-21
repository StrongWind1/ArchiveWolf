//! 7-Zip archives: one reader of the format, the analysis of an archive, and its hash lines.
//!
//! 7-Zip has one encryption method, AES-256 with a key derived by SHA-256 (the coder
//! `06F10701`), over the data of a folder or over the header of the archive.

pub(crate) mod analyse;
#[cfg(test)]
pub(crate) mod craft;
pub(crate) mod line;
#[cfg(test)]
mod mutation;
pub(crate) mod reader;
