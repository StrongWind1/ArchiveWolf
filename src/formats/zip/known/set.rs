//! A set of byte values: what is known of one byte of an encrypted stream.

use std::fmt;

/// A set of byte values. One value is a known byte, a few are alternatives, many are a
/// class, and all 256 say nothing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(crate) struct ByteSet([u64; 4]);

impl ByteSet {
    /// No value: two things that were said of a byte contradict each other.
    pub(crate) const NONE: Self = Self([0; 4]);
    /// Every value: nothing is known.
    pub(crate) const ANY: Self = Self([u64::MAX; 4]);

    /// The set of one value.
    #[must_use]
    pub(crate) const fn of(byte: u8) -> Self {
        let bit = 1_u64 << (byte & 63);
        match byte >> 6 {
            0 => Self([bit, 0, 0, 0]),
            1 => Self([0, bit, 0, 0]),
            2 => Self([0, 0, bit, 0]),
            _ => Self([0, 0, 0, bit]),
        }
    }

    /// The set of the values an iterator gives.
    #[must_use]
    pub(crate) fn from_values(values: impl IntoIterator<Item = u8>) -> Self {
        values.into_iter().fold(Self::NONE, |set, byte| set.union(Self::of(byte)))
    }

    /// Printable text: tab, line feed, carriage return and the 95 printable characters of
    /// ASCII.
    #[must_use]
    pub(crate) fn text() -> Self {
        Self::from_values([9, 10, 13].into_iter().chain(32..=126))
    }

    /// The 128 values of ASCII.
    #[must_use]
    pub(crate) fn ascii() -> Self {
        Self::from_values(0..=127)
    }

    /// The values whose `count` low bits are those of `value`: what is known of a byte when a
    /// stream that is packed in bits, from the low end of each byte, is known up to a point
    /// inside it.
    #[must_use]
    pub(crate) fn low_bits(value: u8, count: u32) -> Self {
        let mask = 1_u16.checked_shl(count).map_or(0xff, |bit| bit.wrapping_sub(1)).to_le_bytes()[0];
        Self::from_values((0..=255_u8).filter(|byte| byte & mask == value & mask))
    }

    /// Whether the set holds `byte`.
    #[must_use]
    pub(crate) const fn contains(self, byte: u8) -> bool {
        let [a, b, c, d] = self.0;
        let word = match byte >> 6 {
            0 => a,
            1 => b,
            2 => c,
            _ => d,
        };
        (word >> (byte & 63)) & 1 == 1
    }

    /// How many values the set holds.
    #[must_use]
    pub(crate) const fn len(self) -> u32 {
        let [a, b, c, d] = self.0;
        a.count_ones() + b.count_ones() + c.count_ones() + d.count_ones()
    }

    /// The one value of a set that holds one.
    #[must_use]
    pub(crate) fn only(self) -> Option<u8> {
        if self.len() == 1 { self.values().next() } else { None }
    }

    /// The values of the set, in rising order.
    pub(crate) fn values(self) -> impl Iterator<Item = u8> {
        (0..=255_u8).filter(move |&byte| self.contains(byte))
    }

    /// The values that are in both sets.
    #[must_use]
    pub(crate) fn intersect(self, other: Self) -> Self {
        let mut words = self.0;
        for (word, theirs) in words.iter_mut().zip(other.0) {
            *word &= theirs;
        }
        Self(words)
    }

    /// The values that are in either set.
    #[must_use]
    pub(crate) fn union(self, other: Self) -> Self {
        let mut words = self.0;
        for (word, theirs) in words.iter_mut().zip(other.0) {
            *word |= theirs;
        }
        Self(words)
    }

    /// The set as 32 bytes: bit `value % 8` of byte `value / 8` says whether `value` is in it.
    #[must_use]
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(8).zip(self.0) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// What the set is worth as a filter, in bits: a wrong key gives each of the 256 values
    /// alike, so it passes a set of `n` values with a chance of `n` in 256.
    #[must_use]
    pub(crate) fn bits(self) -> f64 {
        match self.len() {
            0 => 8.0,
            count => 8.0 - f64::from(count).log2(),
        }
    }
}

impl fmt::Debug for ByteSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.len(), self.only()) {
            (_, Some(byte)) => write!(f, "{byte:02x}"),
            (256, _) => f.write_str("??"),
            (count, _) if count <= 8 => {
                let values: Vec<String> = self.values().map(|byte| format!("{byte:02x}")).collect();
                write!(f, "[{}]", values.join(" "))
            },
            (count, _) => write!(f, "[{count} values]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_holds_what_was_put_into_it() {
        for byte in 0..=255_u8 {
            let set = ByteSet::of(byte);
            assert_eq!((set.len(), set.only()), (1, Some(byte)));
            assert!(set.contains(byte) && !set.contains(byte.wrapping_add(1)));
        }
        assert_eq!((ByteSet::NONE.len(), ByteSet::ANY.len()), (0, 256));
        assert_eq!(ByteSet::from_values([3, 200, 3, 64]).values().collect::<Vec<_>>(), [3, 64, 200]);
        assert_eq!(ByteSet::of(7).intersect(ByteSet::of(8)), ByteSet::NONE);
        assert_eq!(ByteSet::of(7).union(ByteSet::of(8)).len(), 2);
        assert_eq!(ByteSet::ANY.intersect(ByteSet::text()), ByteSet::text());
    }

    #[test]
    fn a_class_is_worth_what_a_wrong_key_passes_it_with() {
        assert_eq!(ByteSet::text().len(), 98);
        assert!(ByteSet::text().contains(b'\n') && ByteSet::text().contains(b'~') && !ByteSet::text().contains(0x7f) && !ByteSet::text().contains(0));
        assert!((ByteSet::text().bits() - 1.385).abs() < 0.01);
        assert!((ByteSet::of(0).bits() - 8.0).abs() < f64::EPSILON && ByteSet::ANY.bits().abs() < f64::EPSILON);
        assert!((ByteSet::ascii().bits() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn known_low_bits_leave_the_values_that_share_them() {
        // three bits of the head of a Deflate block: 32 values of the byte are left
        let set = ByteSet::low_bits(0b101, 3);
        assert_eq!(set.len(), 32);
        assert!(set.values().all(|byte| byte & 7 == 5));
        assert_eq!(ByteSet::low_bits(0xab, 8), ByteSet::of(0xab));
        assert_eq!(ByteSet::low_bits(0xab, 0), ByteSet::ANY);
        assert_eq!(ByteSet::low_bits(0xab, 7).len(), 2);
    }

    #[test]
    fn a_set_is_shown_as_a_claim_writes_it() {
        assert_eq!(format!("{:?} {:?} {:?} {:?}", ByteSet::of(0x1f), ByteSet::ANY, ByteSet::from_values([0x36, 0x39]), ByteSet::text()), "1f ?? [36 39] [98 values]");
    }
}
