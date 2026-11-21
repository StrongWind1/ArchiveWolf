//! The three keys of the cipher and their update in both directions.

use crate::tables::MULT;
use crate::tables::MULT_INV;
use crate::tables::crc32;
use crate::tables::crc32_inv;
use crate::tables::lsb;
use crate::tables::msb;
use crate::tables::stream_byte;

/// The state of the cipher: three words, called X, Y and Z in the literature and `key0`,
/// `key1` and `key2` in the specification of the format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Keys {
    /// The first key, a CRC-32 over the bytes that were encrypted.
    pub x: u32,
    /// The second key, which takes the low byte of the first.
    pub y: u32,
    /// The third key, a CRC-32 over the top bytes of the second. The stream byte comes from it.
    pub z: u32,
}

impl Keys {
    /// The keys before the first byte of a password.
    pub const INITIAL: Self = Self { x: 0x1234_5678, y: 0x2345_6789, z: 0x3456_7890 };

    /// Keys from their three words.
    #[must_use]
    pub const fn new(x: u32, y: u32, z: u32) -> Self {
        Self { x, y, z }
    }

    /// The keys after a password: the state every entry under that password starts from.
    #[must_use]
    pub fn from_password(password: &[u8]) -> Self {
        let mut keys = Self::INITIAL;
        for &byte in password {
            keys.update(byte);
        }
        keys
    }

    /// The keys after the byte `plain` was encrypted.
    #[inline]
    pub const fn update(&mut self, plain: u8) {
        self.x = crc32(self.x, plain);
        self.y = self.y.wrapping_add(lsb(self.x) as u32).wrapping_mul(MULT).wrapping_add(1);
        self.z = crc32(self.z, msb(self.y));
    }

    /// The keys before the byte that was encrypted to `cipher`: one update undone.
    #[inline]
    pub const fn update_backward(&mut self, cipher: u8) {
        self.z = crc32_inv(self.z, msb(self.y));
        self.y = self.y.wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(lsb(self.x) as u32);
        self.x = crc32_inv(self.x, cipher ^ stream_byte(self.z));
    }

    /// The byte of the key stream at this state.
    #[inline]
    #[must_use]
    pub const fn stream_byte(&self) -> u8 {
        stream_byte(self.z)
    }

    /// Decrypt one byte and move on.
    #[inline]
    pub const fn decrypt(&mut self, cipher: u8) -> u8 {
        let plain = cipher ^ self.stream_byte();
        self.update(plain);
        plain
    }

    /// Encrypt one byte and move on.
    #[inline]
    pub const fn encrypt(&mut self, plain: u8) -> u8 {
        let cipher = plain ^ self.stream_byte();
        self.update(plain);
        cipher
    }
}

impl core::fmt::Display for Keys {
    /// The three words in hex with spaces between, as every tool that takes keys reads them.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x} {:08x} {:08x}", self.x, self.y, self.z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_gives_the_keys_bkcrack_gives_for_it() {
        // the tutorial of bkcrack: these keys and this password belong together
        assert_eq!(Keys::from_password(b"W4sF0rgotten"), Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31));
        assert_eq!(Keys::from_password(b""), Keys::INITIAL);
        assert_eq!(Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31).to_string(), "c4490e28 b414a23d 91404b31");
    }

    #[test]
    fn an_update_run_backward_gives_the_state_back() {
        let start = Keys::from_password(b"roundtrip");
        let plain = b"abcdefgh\x00\xff";
        let mut keys = start;
        let cipher: Vec<u8> = plain.iter().map(|&byte| keys.encrypt(byte)).collect();
        assert_ne!(&cipher[..], &plain[..]);

        let mut forward = start;
        let decrypted: Vec<u8> = cipher.iter().map(|&byte| forward.decrypt(byte)).collect();
        assert_eq!(&decrypted[..], &plain[..]);
        assert_eq!(forward, keys);

        for &byte in cipher.iter().rev() {
            keys.update_backward(byte);
        }
        assert_eq!(keys, start);
    }
}
