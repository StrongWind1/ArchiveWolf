//! The pairs of third keys whose stream bytes differ by a given byte.
//!
//! An attack on a header that was encrypted twice knows the exclusive-or of two stream bytes
//! and the difference of the two third keys that gave them, and asks for the keys. This table
//! answers in one lookup. It is built here, and not where it is used, so that it is built
//! with optimisation in every profile: it has 2^20 values.

use crate::tables::mask;
use crate::tables::stream_byte;

/// How many low bits of bits 2 to 15 order the lists of one difference.
const LOW_BITS: u32 = 6;
/// How many lists there are: one for every difference and every value of the low bits.
const LISTS: usize = 1 << (14 + LOW_BITS);

/// For one byte, every pair of third keys whose stream bytes differ by that byte, listed by
/// what the two keys differ by.
///
/// Only bits 2 to 15 of a third key count for its stream byte, so a key is those bits here, a
/// word with every other bit clear. A stream byte comes from 64 keys, so 64 keys on average
/// have a partner at a given difference, and one of them on average has given bits 2 to 7.
#[derive(Debug, Clone)]
pub struct StreamPairs {
    /// Where the list of each difference and each value of bits 2 to 7 starts, and behind
    /// the last where it ends.
    starts: Box<[u32]>,
    /// The lists, one behind the other: bits 2 to 15 of a key.
    values: Box<[u16]>,
}

impl StreamPairs {
    /// The pairs of keys whose stream bytes differ by `byte`.
    #[must_use]
    pub fn new(byte: u8) -> Self {
        // the 64 keys that give each stream byte
        let mut by_stream = vec![[0_u16; 64]; 256];
        let mut filled = [0_usize; 256];
        for key in 0..1_u16 << 14 {
            let stream = usize::from(stream_byte(u32::from(key) << 2));
            by_stream[stream][filled[stream]] = key;
            filled[stream] += 1;
        }
        let list = |key: u16, other: u16| (usize::from(key ^ other) << LOW_BITS) | usize::from(key & 63);

        // every pair is counted, one list on, so that the running sums are where the lists
        // start, and then placed
        let mut starts = vec![0_u32; LISTS + 1];
        for (stream, keys) in by_stream.iter().enumerate() {
            for &key in keys {
                for &other in &by_stream[stream ^ usize::from(byte)] {
                    starts[list(key, other) + 1] += 1;
                }
            }
        }
        let mut total = 0;
        for start in &mut starts {
            total += *start;
            *start = total;
        }
        let mut next = starts.clone();
        let mut values = vec![0_u16; total as usize];
        for (stream, keys) in by_stream.iter().enumerate() {
            for &key in keys {
                for &other in &by_stream[stream ^ usize::from(byte)] {
                    let place = &mut next[list(key, other)];
                    values[*place as usize] = key << 2;
                    *place += 1;
                }
            }
        }
        Self { starts: starts.into_boxed_slice(), values: values.into_boxed_slice() }
    }

    /// The lists from `from` to the one before `to`.
    #[inline]
    fn lists(&self, from: usize, to: usize) -> &[u16] {
        &self.values[self.starts[from] as usize..self.starts[to] as usize]
    }

    /// The list of a difference and of bits 2 to 7 of a key.
    #[inline]
    const fn list(difference: u32, z: u32) -> usize {
        ((((difference & mask(2, 16)) >> 2) << LOW_BITS) | ((z & mask(2, 8)) >> 2)) as usize
    }

    /// Bits 2 to 15 of every key whose stream byte differs by the byte from that of the key
    /// that differs from it by `difference` in those bits: 64 on average.
    #[inline]
    #[must_use]
    pub fn of(&self, difference: u32) -> &[u16] {
        let first = Self::list(difference, 0);
        self.lists(first, first + (1 << LOW_BITS))
    }

    /// Those of them whose bits 2 to 7 are those of `z`: one on average.
    #[inline]
    #[must_use]
    pub fn of_low_bits(&self, difference: u32, z: u32) -> &[u16] {
        let list = Self::list(difference, z);
        self.lists(list, list + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_listed_under_its_difference_and_its_low_bits_and_nowhere_else() {
        for byte in [0x00_u8, 0x5a, 0xff] {
            let pairs = StreamPairs::new(byte);
            // every key has 64 partners: the keys of one other stream byte
            assert_eq!(pairs.values.len(), 1 << 20);
            for difference in [0_u32, 4, 0x0aa8, 0x5554, 0xfffc] {
                let fitting: Vec<u16> = (0..1_u16 << 14).map(|key| key << 2).filter(|&key| stream_byte(u32::from(key)) ^ stream_byte(u32::from(key) ^ difference) == byte).collect();
                let mut listed = pairs.of(difference).to_vec();
                listed.sort_unstable();
                assert_eq!(listed, fitting, "byte {byte:#x}, difference {difference:#x}");
                for low_bits in 0..64_u32 {
                    let mut listed = pairs.of_low_bits(difference, low_bits << 2).to_vec();
                    listed.sort_unstable();
                    assert_eq!(listed, fitting.iter().copied().filter(|&key| (u32::from(key) >> 2) & 63 == low_bits).collect::<Vec<_>>());
                }
                // the bits of a difference and of a key that do not count are not looked at
                assert_eq!(pairs.of(difference | 0xdead_0003), pairs.of(difference));
                assert_eq!(pairs.of_low_bits(difference | 0xdead_0003, 0xffff_ff03), pairs.of_low_bits(difference, 0));
            }
        }
        // no stream byte differs from itself, and every key is its own partner at no difference
        assert_eq!(StreamPairs::new(1).of(0), []);
        assert_eq!(StreamPairs::new(0).of(0).len(), 1 << 14);
    }
}
