//! RAR archives: RAR 1.3 and 1.4, RAR 1.5 to 4.x, and RAR 5 and 7.
//!
//! `analyse::analyse` is the one way in. It reads the headers of an archive by range
//! (`headers`, with a parser for each generation in `rar1`, `rar4` and `rar5`), names the
//! encryption of every entry (`encryption`), holds each against what its hashcat mode loads
//! (`scoring`) and builds the lines (`data_extract`, `lines`). The one decoder here,
//! `unpack15`, unpacks the comment of a RAR 1.4 archive and serves the key search of RAR 1.3.

pub(crate) mod analyse;
pub(crate) mod data_extract;
pub(crate) mod encryption;
pub(crate) mod headers;
pub(crate) mod lines;
#[cfg(test)]
mod mutation;
pub(crate) mod rar1;
pub(crate) mod rar4;
pub(crate) mod rar5;
pub(crate) mod scoring;
#[cfg(test)]
pub(crate) mod testing;
pub(crate) mod unpack15;
