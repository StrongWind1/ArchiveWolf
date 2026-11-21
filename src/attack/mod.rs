//! Key recovery for the two schemes that fall without the password.
//!
//! This part ranks below analysis and conversion. Nothing outside this module depends on it,
//! except the command that starts an attack.

pub(crate) mod budget;
pub mod rar_13;
pub mod zip_crypto;

pub use self::budget::Budget;
