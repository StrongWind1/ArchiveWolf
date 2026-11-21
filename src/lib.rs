//! ArchiveWolf: analysis and hash conversion for encrypted ZIP, RAR and 7-Zip archives.
#![forbid(unsafe_code)]
#![expect(unused_crate_dependencies, reason = "dev-deps and bin-deps not used by lib crate")]

pub mod analysis;
pub mod attack;
pub mod cli;
pub mod formats;
pub mod line;
pub mod output;
pub mod run;
pub mod scanner;
