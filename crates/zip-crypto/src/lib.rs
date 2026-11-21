//! The cipher of ZIP traditional encryption (`zip-crypto`) and the key search of the
//! known-plaintext attack of Biham and Kocher on it.
//!
//! This crate is the part of ArchiveWolf's `attack zip-crypto` that has to be fast: the three
//! keys and their update, the reduction of the candidates for the third key, the kernels that
//! search one candidate, and the way from keys back to a password of six bytes or fewer, which
//! is a filter on the keys a search leaves. It knows nothing of archives. It is a crate of its
//! own because a vector kernel is entered through a call the compiler cannot check, which
//! the tool itself forbids, and so that it is built with optimisation in every profile.

mod kernel;
mod keys;
mod pairs;
mod password;
mod reduce;
mod tables;

pub use kernel::Hit;
pub use kernel::Kernel;
pub use kernel::Scratch;
pub use kernel::Window;
pub use keys::Keys;
pub use pairs::StreamPairs;
pub use password::has_short_password;
pub use password::short_passwords;
pub use reduce::Reduced;
pub use reduce::WINDOW;
pub use reduce::reduce;
pub use tables::MULT;
pub use tables::MULT_INV;
pub use tables::crc32;
pub use tables::crc32_inv;
pub use tables::stream_byte;
