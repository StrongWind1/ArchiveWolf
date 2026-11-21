//! The reduction: from the key stream of a run of known bytes to the candidates for the third
//! key that every search starts from.
//!
//! This file is a port of parts of bkcrack-rs by Zach Shallbetter
//! (<https://github.com/zachshallbetter/bkcrack-rs>), which is a port to Rust of bkcrack by
//! Joachim Hotonnier (<https://github.com/kimci86/bkcrack>). It is an altered version and is
//! not the original software. That work is under the zlib licence, and so is what is taken
//! from it here: the notice and the full text are in `LICENSE-BKCRACK.txt`.

use crate::tables::has_z_low;
use crate::tables::z_before_10_32;
use crate::tables::z_low;

/// How many bytes of a run the search itself uses. A run is never shorter.
pub const WINDOW: usize = 8;

/// The candidates a run leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reduced {
    /// Bits 2 to 31 of the third key before the byte at `index` of the run, one value for
    /// each candidate, in the order the reduction leaves them. The order is fixed: a search
    /// over them can be cut into slices and taken up again.
    pub candidates: Vec<u32>,
    /// The place in the run the candidates belong to. The search uses the eight bytes that
    /// end there: `index - 7` to `index`.
    pub index: usize,
}

/// Below this many candidates the count of the best place is tracked.
const TRACK: usize = 1 << 16;
/// Below this many the walk stops soon after its best place.
const WAIT: usize = 1 << 8;

/// Reduce the candidates for the third key over the key stream of a run.
///
/// The walk starts at the last byte of the run with every value of bits 10 to 31 its stream
/// byte allows, and goes back one byte at a time. It stops at the place where the candidates
/// were fewest. A run of eight bytes is not reduced at all and leaves 2^22 candidates.
///
/// `None` for a run shorter than [`WINDOW`].
#[must_use]
pub fn reduce(stream: &[u8]) -> Option<Reduced> {
    let last = stream.len().checked_sub(1).filter(|&last| last >= WINDOW - 1)?;
    let mut index = last;
    let mut current: Vec<u32> = (0..1_u32 << 22).map(|z| z << 10).filter(|&z| has_z_low(stream[last], z)).collect();

    if last > WINDOW - 1 {
        let mut tracking = false;
        let mut best: Vec<u32> = Vec::new();
        let mut best_index = last;
        let mut best_size = TRACK;
        let mut waiting = false;
        let mut wait = 0_usize;
        let mut before: Vec<u32> = Vec::new();
        let mut seen = vec![0_u64; 1 << 16];

        let mut i = last;
        loop {
            before.clear();
            seen.fill(0);
            let mut size = 0_usize;
            let (here, there) = (stream[i], stream[i - 1]);
            for &z in &current {
                for &low in z_low(here, z) {
                    let z_before = z_before_10_32(z | u32::from(low));
                    let bit = (z_before >> 10) as usize;
                    let flag = 1_u64 << (bit & 63);
                    if seen[bit >> 6] & flag == 0 && has_z_low(there, z_before) {
                        seen[bit >> 6] |= flag;
                        before.push(z_before);
                        size += z_low(there, z_before).len();
                    }
                }
            }

            if size <= best_size {
                tracking = true;
                best_index = i - 1;
                best_size = size;
                waiting = false;
            } else if tracking {
                if best_index == i {
                    // the place before this one was the best so far: keep its candidates
                    core::mem::swap(&mut best, &mut current);
                    if best_size <= WAIT {
                        waiting = true;
                        wait = best_size * 4;
                    }
                }
                if waiting {
                    wait = wait.saturating_sub(1);
                    if wait == 0 {
                        break;
                    }
                }
            }

            core::mem::swap(&mut current, &mut before);
            if i == WINDOW {
                break;
            }
            i -= 1;
        }

        if tracking {
            if best_index != WINDOW - 1 {
                core::mem::swap(&mut current, &mut best);
            }
            index = best_index;
        } else {
            index = WINDOW - 1;
        }
    }

    // from bits 10 to 31 to bits 2 to 31: the low bits the stream byte allows. The values of
    // one candidate stay together, which is not the order of bkcrack: it puts the second and
    // third value of every candidate behind all the first ones. The set is the same.
    let stream_byte = stream[index];
    let mut candidates = Vec::with_capacity(current.len() + current.len() / 8);
    for &z in &current {
        candidates.extend(z_low(stream_byte, z).iter().map(|&low| z | u32::from(low)));
    }
    Some(Reduced { candidates, index })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::tables::mask;

    /// The key stream of `plain` under a password, with twelve bytes encrypted in front.
    fn stream_of(password: &[u8], plain: &[u8]) -> (Vec<u8>, Vec<Keys>) {
        let mut keys = Keys::from_password(password);
        for byte in 0..12 {
            let _ = keys.encrypt(byte);
        }
        let mut states = Vec::new();
        let stream = plain
            .iter()
            .map(|&byte| {
                states.push(keys);
                byte ^ keys.encrypt(byte)
            })
            .collect();
        (stream, states)
    }

    #[test]
    fn a_run_of_eight_leaves_every_candidate_its_last_byte_allows() {
        let (stream, states) = stream_of(b"eight", b"8 bytes!");
        let reduced = reduce(&stream).unwrap();
        assert_eq!((reduced.candidates.len(), reduced.index), (1 << 22, 7));
        assert!(reduced.candidates.contains(&(states[7].z & mask(2, 32))));
        assert!(reduce(&stream[..7]).is_none() && reduce(&[]).is_none());
    }

    #[test]
    fn the_right_candidate_survives_a_longer_run() {
        let plain: Vec<u8> = (0..64_u8).map(|i| i.wrapping_mul(7).wrapping_add(3)).collect();
        let (stream, states) = stream_of(b"correct horse", &plain);
        let mut last = usize::MAX;
        for length in [9, 12, 16, 24, 40, 64] {
            let reduced = reduce(&stream[..length]).unwrap();
            assert!((7..length).contains(&reduced.index), "{length}: {}", reduced.index);
            assert!(reduced.candidates.contains(&(states[reduced.index].z & mask(2, 32))), "{length} bytes");
            assert!(reduced.candidates.len() < last, "{length} bytes leave fewer than a shorter run");
            last = reduced.candidates.len();
        }
        // the same run gives the same candidates in the same order
        assert_eq!(reduce(&stream), reduce(&stream));
    }
}
