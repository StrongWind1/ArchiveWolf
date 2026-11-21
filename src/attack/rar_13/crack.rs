//! RAR 1.3 (`CRYPT_RAR13`) cipher primitives.
//!
//! The cipher is a 3-byte additive stream: each byte is decrypted by
//! subtracting `key[0]` after updating the key triple:
//!
//! ```text
//! key[1] += key[2]
//! key[0] += key[1]
//! plaintext = ciphertext - key[0]
//! ```
//!
//! The key state is 24 bits, but a key derived from a password always has
//! `key[0]` and `key[1]` of equal parity (a sum and an XOR of the same
//! bytes), which leaves 2^23 reachable keys.
//!
//! Parts of this file follow the UnRAR source. Its license, paragraph 2, has to accompany such code:
//!
//! ```text
//! UnRAR source code may be used in any software to handle
//! RAR archives without limitations free of charge, but cannot be
//! used to develop RAR (WinRAR) compatible archiver and to
//! re-create RAR compression algorithm, which is proprietary.
//! Distribution of modified UnRAR source code in separate form
//! or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "UnRAR source code"
//! words, is included in license, or in documentation if license
//! is not available, and in source code comments of resulting package.
//! ```
//!
//! The full text is in `LICENSE-UNRAR.txt`.

/// Number of keys reachable from a password.
pub(crate) const KEY_SPACE: u32 = 1 << 23;

/// RAR 1.3 cipher state.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Rar13State {
    key: [u8; 3],
}

impl Rar13State {
    /// Create a cipher state from a raw 3-byte key.
    #[must_use]
    pub(crate) const fn new(key: [u8; 3]) -> Self {
        Self { key }
    }

    /// Decrypt a buffer in place.
    pub(crate) fn decrypt_in_place(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.key[1] = self.key[1].wrapping_add(self.key[2]);
            self.key[0] = self.key[0].wrapping_add(self.key[1]);
            *byte = byte.wrapping_sub(self.key[0]);
        }
    }

    /// `Checksum14` of what `cipher` decrypts to, with nothing kept of it.
    #[must_use]
    pub(crate) fn checksum_of(mut self, cipher: &[u8]) -> u16 {
        let mut sum = 0u16;
        for &byte in cipher {
            self.key[1] = self.key[1].wrapping_add(self.key[2]);
            self.key[0] = self.key[0].wrapping_add(self.key[1]);
            sum = sum.wrapping_add(u16::from(byte.wrapping_sub(self.key[0]))).rotate_left(1);
        }
        sum
    }

    /// Decrypt `src` into `dst`, replacing its contents.
    pub(crate) fn decrypt_into(mut self, src: &[u8], dst: &mut Vec<u8>) {
        dst.clear();
        dst.extend_from_slice(src);
        self.decrypt_in_place(dst);
    }
}

/// Derive the 3-byte key from a password (`SetKey13` in unrar).
#[cfg(test)]
#[must_use]
pub(crate) fn key_from_password(password: &[u8]) -> [u8; 3] {
    let mut key = [0u8; 3];
    for &p in password {
        key[0] = key[0].wrapping_add(p);
        key[1] ^= p;
        key[2] = key[2].wrapping_add(p).rotate_left(1);
    }
    key
}

/// Keys that share `key[1]` and `key[2]`: one for each `key[0]` of the parity of `key[1]`.
pub(crate) const LANES: usize = 128;

/// Groups of [`LANES`] keys that make up the key space.
pub(crate) const GROUPS: u32 = KEY_SPACE >> LANES.trailing_zeros();

/// The keys of the `group`-th group, for `group < GROUPS`. Every password-reachable key is
/// in one group, once.
///
/// The low byte of the group is `key[1]` and the high byte `key[2]`.
pub(crate) fn keys_in(group: u32) -> impl Iterator<Item = [u8; 3]> {
    let k1 = (group & 0xff) as u8;
    let k2 = ((group >> 8) & 0xff) as u8;
    (0..=0x7f_u8).map(move |lane| [(lane << 1) | (k1 & 1), k1, k2])
}

/// `Checksum14` of one stored entry under all the keys of a group at once.
///
/// Two keys of a group differ in `key[0]` alone, and `key[0]` is only ever added to: the bytes
/// one of them decrypts are the bytes of the other plus a constant. So the key stream is
/// computed once for the group, and the [`LANES`] sums advance side by side over arrays that
/// the compiler turns into vector operations.
#[derive(Debug, Clone)]
pub(crate) struct GroupSums {
    /// `key[0]` of each lane before the first byte.
    first: [u8; LANES],
    sums: [u16; LANES],
    /// The key of the lane whose `key[0]` started at zero.
    key: [u8; 3],
    group: u32,
}

impl GroupSums {
    /// The state of the `group`-th group before the first byte.
    #[must_use]
    pub(crate) fn new(group: u32) -> Self {
        let mut first = [0; LANES];
        let mut key = [0; 3];
        for (lane, [k0, k1, k2]) in first.iter_mut().zip(keys_in(group)) {
            *lane = k0;
            key = [0, k1, k2];
        }
        Self { first, sums: [0; LANES], key, group }
    }

    /// Decrypt the next bytes of the entry under every key of the group and add them to the sums.
    pub(crate) fn absorb(&mut self, cipher: &[u8]) {
        let [mut k0, mut k1, k2] = self.key;
        let mut sums = self.sums;
        for &byte in cipher {
            k1 = k1.wrapping_add(k2);
            k0 = k0.wrapping_add(k1);
            let plain = byte.wrapping_sub(k0);
            for (sum, first) in sums.iter_mut().zip(&self.first) {
                *sum = sum.wrapping_add(u16::from(plain.wrapping_sub(*first))).rotate_left(1);
            }
        }
        self.sums = sums;
        self.key = [k0, k1, k2];
    }

    /// The keys of the group under which the bytes absorbed so far sum to `checksum`.
    pub(crate) fn keys_with(&self, checksum: u16) -> impl Iterator<Item = [u8; 3]> + '_ {
        keys_in(self.group).zip(&self.sums).filter(move |&(_, &sum)| sum == checksum).map(|(key, _)| key)
    }
}

/// RAR 1.4 file checksum (`Checksum14` from unrar).
///
/// Additive checksum with 16-bit left rotate: for each byte,
/// `sum = (sum + byte) & 0xFFFF; sum = rotate_left(sum, 1)`.
/// NOT a CRC — it's a simple rolling checksum over the unpacked data.
#[must_use]
pub(crate) fn checksum14(data: &[u8]) -> u16 {
    let mut sum = 0u16;
    for &byte in data {
        sum = sum.wrapping_add(u16::from(byte));
        sum = sum.rotate_left(1);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_from_password_known_value() {
        assert_eq!(key_from_password(b""), [0, 0, 0]);
        // sum, xor and rotating sum of the bytes of "password"
        let key = key_from_password(b"password");
        assert_eq!(key[0], b"password".iter().fold(0u8, |a, &b| a.wrapping_add(b)));
        assert_eq!(key[1], b"password".iter().fold(0u8, |a, &b| a ^ b));
    }

    #[test]
    fn password_keys_have_equal_parity_and_are_in_their_group() {
        for pw in [&b"password"[..], b"a", b"Tr0ub4dor&3", b"\xff\x01\x80"] {
            let key = key_from_password(pw);
            assert_eq!(key[0] & 1, key[1] & 1);
            let group = u32::from(key[1]) | (u32::from(key[2]) << 8);
            assert_eq!(keys_in(group).filter(|&found| found == key).count(), 1);
        }
    }

    #[test]
    fn the_groups_hold_every_key_of_the_key_space_once() {
        let mut seen = vec![0u8; 1 << 24];
        for group in 0..GROUPS {
            assert_eq!(keys_in(group).count(), LANES);
            for [k0, k1, k2] in keys_in(group) {
                assert_eq!(k0 & 1, k1 & 1);
                seen[usize::from(k0) | (usize::from(k1) << 8) | (usize::from(k2) << 16)] += 1;
            }
        }
        // each key with the parity a password gives, and no key twice
        assert_eq!(seen.iter().map(|&count| u32::from(count)).sum::<u32>(), KEY_SPACE);
        assert!(seen.iter().all(|&count| count <= 1));
    }

    #[test]
    fn the_sums_of_a_group_are_the_checksums_under_its_keys() {
        let cipher: Vec<u8> = (0..1500u32).map(|i| i.wrapping_mul(2_654_435_761).to_le_bytes()[2]).collect();
        for group in [0, 1, 0x00ff, 0x1f73, 0x3d1f, 0x8000, GROUPS - 1] {
            // the same bytes in one piece, and in three
            let mut whole = GroupSums::new(group);
            whole.absorb(&cipher);
            let mut pieces = GroupSums::new(group);
            pieces.absorb(&cipher[..1]);
            pieces.absorb(&cipher[1..700]);
            pieces.absorb(&cipher[700..]);

            for (lane, key) in keys_in(group).enumerate() {
                let mut plain = Vec::new();
                Rar13State::new(key).decrypt_into(&cipher, &mut plain);
                let sum = checksum14(&plain);
                assert_eq!(Rar13State::new(key).checksum_of(&cipher), sum);
                assert_eq!(whole.sums[lane], sum, "group {group:#x} lane {lane}");
                assert_eq!(pieces.sums[lane], sum, "group {group:#x} lane {lane}");
                assert!(whole.keys_with(sum).any(|found| found == key));
            }
            // a sum names the keys that have it and no other
            let sum = whole.sums[5];
            let expected: Vec<[u8; 3]> = keys_in(group).zip(whole.sums).filter(|&(_, other)| other == sum).map(|(key, _)| key).collect();
            assert_eq!(whole.keys_with(sum).collect::<Vec<_>>(), expected);
        }
        // nothing absorbed: the checksum of no bytes, under every key
        assert_eq!(GroupSums::new(7).keys_with(0).count(), LANES);
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, RAR 1.3 world!";
        let key = key_from_password(b"secret");

        let mut encrypted = plaintext.to_vec();
        let mut k = key;
        for byte in &mut encrypted {
            k[1] = k[1].wrapping_add(k[2]);
            k[0] = k[0].wrapping_add(k[1]);
            *byte = byte.wrapping_add(k[0]);
        }

        let mut decrypted = Vec::new();
        Rar13State::new(key).decrypt_into(&encrypted, &mut decrypted);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn checksum14_known_value() {
        assert_eq!(checksum14(b""), 0);
        assert_eq!(checksum14(b"123456789"), 0xC78A);
    }
}
