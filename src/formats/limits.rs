//! Limits on what the bytes of an archive can make this crate allocate or compute.
//!
//! Every size and count in an archive is a claim by whoever wrote the file. A few bytes can claim
//! an entry of 2^63 bytes, a dictionary of 4 GiB or a billion files, and a few hundred kilobytes
//! can honestly unpack to many gigabytes. The numbers here are what such a claim is held against
//! before anything is allocated or unpacked for it.

/// The most output one decode may produce when the output is only counted and checksummed.
///
/// Such a decode holds no more than its decoder in memory, so this bounds time and not memory:
/// a gigabyte of Deflate is about a second of unpacking. An entry that unpacks to more is not
/// decoded at all. For the proof of pseudo-encryption that means the entry stays encrypted,
/// with the remark that the proof was not run.
pub const MAX_DECODE_OUTPUT: u64 = 1 << 30;

/// The most output one decode may produce when the caller keeps the bytes, so this bounds
/// memory.
///
/// A decoder holds no more than its output over again, for its dictionary, which keeps one
/// decode at about 260 MiB on top of what was read of the archive. A 7z header that is packed
/// several times is unpacked one layer at a time, and a layer is dropped before the next is
/// unpacked.
pub const MAX_DECODE_BUFFER: u64 = 1 << 27;

/// The largest dictionary a decoder is given, in bytes.
///
/// 256 MiB is the LZMA2 dictionary 7-Zip uses at its highest preset, so every archive made
/// with a preset fits. A stream that needs more is not unpacked.
pub const MAX_DECODER_MEMORY: u32 = 1 << 28;

/// The most bytes that are unpacked to look at the entries of one archive.
///
/// [`MAX_DECODE_OUTPUT`] is for one entry, and an archive has as many entries as it likes: the
/// 65,535 entries of a small ZIP file can all point at one stream of a few hundred bytes that
/// unpacks to a gigabyte. Four gigabytes are what four entries at the limit cost. What is left
/// over when they are used up is not decoded. See [`Budget`].
pub const MAX_ARCHIVE_WORK: u64 = 1 << 32;

/// The largest archive `attack rar-13` takes. The key search tests every key on the packed
/// data of an entry, so that command holds its archive in memory, which no other does.
pub const MAX_ATTACK_ARCHIVE: u64 = 1 << 30;

// What is kept in memory is never more than what may be unpacked at all, and one archive may
// cost a few entries at the limit and not as many as it can name.
const _: () = assert!(MAX_DECODE_BUFFER <= MAX_DECODE_OUTPUT && MAX_ARCHIVE_WORK >= MAX_DECODE_OUTPUT);

/// What is left of [`MAX_ARCHIVE_WORK`] while one archive is looked at.
///
/// A decode asks for its cost before it does any work: the bytes it can unpack at most, from
/// the headers. A decode that is refused does nothing, and what it would have shown is
/// reported as not determined, never as a verdict.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    left: u64,
}

impl Budget {
    /// The budget for one archive.
    #[must_use]
    pub const fn new() -> Self {
        Self { left: MAX_ARCHIVE_WORK }
    }

    /// Take `cost` off what is left. `false`, with nothing taken, when there is less than that.
    pub const fn take(&mut self, cost: u64) -> bool {
        match self.left.checked_sub(cost) {
            Some(left) => {
                self.left = left;
                true
            },
            None => false,
        }
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

/// The most elements a collection is given room for before any of them has been read.
const MAX_INITIAL_CAPACITY: usize = 1 << 16;

/// The capacity to start a collection with when a header says it will hold `count` elements.
///
/// `remaining` is how many bytes of input are left and `min_size` how many of them each element
/// takes at least. The result is never more than those bytes can hold and never more than 65,536,
/// so a count that is a lie costs nothing; a collection that really is larger grows as it is
/// filled.
pub(crate) fn capacity_for(count: impl TryInto<usize>, remaining: usize, min_size: usize) -> usize {
    let most = (remaining / min_size.max(1)).min(MAX_INITIAL_CAPACITY);
    count.try_into().map_or(most, |count| count.min(most))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_capacity_never_exceeds_what_the_input_can_hold() {
        assert_eq!(capacity_for(10_u64, 1000, 4), 10);
        assert_eq!(capacity_for(1_u64 << 62, 1000, 4), 250);
        assert_eq!(capacity_for(u64::MAX, 76, 1), 76);
        assert_eq!(capacity_for(u64::MAX, 0, 1), 0);
        assert_eq!(capacity_for(5_u64, 3, 8), 0);
    }

    #[test]
    fn a_budget_gives_out_what_it_has_and_no_more() {
        let mut budget = Budget::new();
        assert!(budget.take(0));
        assert!(budget.take(MAX_ARCHIVE_WORK - 10));
        assert!(!budget.take(11), "more than is left");
        assert!(budget.take(4), "a refusal takes nothing");
        assert!(budget.take(6));
        assert!(!budget.take(1));
        assert!(budget.take(0), "what costs nothing is never refused");
        assert!(!Budget::default().take(u64::MAX));

        // four entries at the limit of one entry, and not a fifth
        let mut budget = Budget::new();
        assert_eq!((0..5).map(|_| budget.take(MAX_DECODE_OUTPUT)).collect::<Vec<_>>(), [true, true, true, true, false]);
    }

    #[test]
    fn a_capacity_has_a_ceiling_of_its_own() {
        assert_eq!(capacity_for(u64::MAX, usize::MAX, 1), MAX_INITIAL_CAPACITY);
        assert_eq!(capacity_for(1_u64 << 40, 1 << 40, 0), MAX_INITIAL_CAPACITY);
        assert_eq!(capacity_for(u128::MAX, usize::MAX, 1), MAX_INITIAL_CAPACITY);
        assert_eq!(capacity_for(-1_i64, usize::MAX, 1), MAX_INITIAL_CAPACITY);
    }
}
