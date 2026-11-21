//! `new Random()` on the .NET Framework, which is seeded with a clock.
//!
//! `SharpZipLib` to 1.3.0 and `DotNetZip` make a `new Random()` for every entry and fill its
//! encryption header from it. On the .NET Framework that generator is seeded with
//! `Environment.TickCount`: the milliseconds since the machine started, as Windows counts
//! them (`mscorlib/system/random.cs` of the reference source).
//!
//! - **The count stands still between two interrupts of the timer.** Windows adds to it at
//!   every interrupt, which comes every 15.625 ms on nearly every machine, so the count is
//!   `125 * n / 8` rounded down, for the number `n` of the interrupt. A year of running is
//!   2^31 interrupts.
//! - **Entries that are written between two interrupts have one header**, before and after
//!   encryption: they are one *group*, and a group is one seed.
//! - **The first bytes of the groups do not find the clock.** The first value of the
//!   generator is a line in its seed, so what the first bytes of two groups differ by says
//!   how many interrupts lie between them and next to nothing of the first: one clock in two
//!   thousand fits them, which is a million in a year.
//! - **The second and third bytes do.** Every header is encrypted from the same keys, the
//!   keys after the password. The second byte of each group is encrypted with a stream byte
//!   that depends on those keys and on the first byte of the group, and the third with one
//!   that depends on the first two: bytes that are known once a clock is guessed. Twenty
//!   groups say so much of the keys that a wrong clock contradicts itself: [`holds`] finds
//!   that out in a millisecond, where a search for the keys takes a minute. One wrong clock
//!   in 256 of those that fit the first bytes gives the same second byte in every group as
//!   the right one, which is why the third byte is asked as well, and one in 65,536 the
//!   same third: such a clock is told by the search for the keys, which finds none.
//!
//! What comes out is the count at every group, and with it eleven bytes of every header as
//! they were before encryption. The keys then follow from one header by the search of the
//! known-plaintext attack.

use std::ops::Range;
use std::sync::LazyLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use archivewolf_zip_crypto::Keys;

use super::Control;
use super::dotnet;
use super::spread;

/// How many interrupts of the timer the search goes through for the first group: a little
/// over a year of running without a restart.
pub const INTERRUPTS: u64 = 1 << 31;

/// The fewest groups the search is run on. With fewer, too many values of the third key
/// fit the second bytes of every group for a wrong clock to be told in a millisecond.
pub const MIN_GROUPS: usize = 12;

/// The most groups that are held against a clock. More would add nothing: a wrong clock
/// fails within the first few.
pub const MAX_GROUPS: usize = 32;

/// The most interrupts between two groups that are allowed for: half a second.
pub const GAP: usize = 32;

/// How many interrupts one piece of the search holds.
const PIECE: u64 = 1 << 16;

/// The most clocks that are kept when a search leaves several.
const FOUND_MAX: usize = 8;

/// The multiplier of the second key.
const MULTIPLIER: u32 = 0x0808_8405;

/// How many values bits 2 to 15 of a third key can have.
const LOW: usize = 1 << 14;

/// The count of milliseconds at an interrupt of the timer: `125 * n / 8`, as far as 32 bits
/// hold it.
#[must_use]
pub const fn tick_count(interrupt: u64) -> u32 {
    let [a, b, c, d, ..] = (interrupt * 125 / 8).to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

/// The seed of `new Random()` at a count: `Environment.TickCount` is the count as a number
/// with a sign, and is negative from the 25th day of running on.
#[must_use]
pub const fn seed_at(tick_count: u32) -> i32 {
    tick_count.cast_signed()
}

/// The first byte that a generator gives which was made at a count.
fn first_byte(tick_count: u32) -> u8 {
    dotnet::first_sample(seed_at(tick_count)).to_le_bytes()[0]
}

/// The table of the CRC-32 that the cipher steps with.
static CRC: LazyLock<[u32; 256]> = LazyLock::new(|| {
    std::array::from_fn(|byte| {
        let mut keys = Keys::new(0, 0, 0);
        // the first key after a byte, from a first key of zero, is the entry of the byte
        keys.update(u8::try_from(byte).unwrap_or_default());
        keys.x
    })
});

/// What the tables of [`holds`] are made of.
struct Tables {
    /// For each stream byte, the values that bits 2 to 15 of the third key can have: 64.
    low: Vec<Vec<u16>>,
    /// The same as a set of 2^14 bits.
    is_low: Vec<[u64; LOW / 64]>,
    /// For each stream byte, the values of bits 10 to 23 of the third key before a step
    /// that some top byte of the second key leads from to a third key with that stream byte,
    /// as a set of 2^14 bits.
    before: Vec<[u64; LOW / 64]>,
}

static TABLES: LazyLock<Tables> = LazyLock::new(|| {
    let mut low: Vec<Vec<u16>> = vec![Vec::new(); 256];
    for value in 0..LOW {
        let third = u32::try_from(value << 2).unwrap_or_default();
        if let Some(values) = low.get_mut(usize::from(Keys::new(0, 0, third).stream_byte())) {
            values.push(u16::try_from(value).unwrap_or_default());
        }
    }
    // a step of the third key: bits 2 to 15 behind it are bits 10 to 23 in front of it,
    // exclusive-or bits 2 to 15 of a table entry
    let entries: Vec<usize> = CRC.iter().map(|entry| ((entry >> 2) as usize) & (LOW - 1)).collect();
    let before = low
        .iter()
        .map(|values| {
            let mut set = [0_u64; LOW / 64];
            for &value in values {
                for &entry in &entries {
                    let at = usize::from(value) ^ entry;
                    if let Some(word) = set.get_mut(at / 64) {
                        *word |= 1 << (at % 64);
                    }
                }
            }
            set
        })
        .collect();
    let is_low = low
        .iter()
        .map(|values| {
            let mut set = [0_u64; LOW / 64];
            for &value in values {
                if let Some(word) = set.get_mut(usize::from(value) / 64) {
                    *word |= 1 << (value % 64);
                }
            }
            set
        })
        .collect();
    Tables { low, is_low, before }
});

/// Whether a value is in a set of 2^14 bits.
fn has(set: &[u64; LOW / 64], value: usize) -> bool {
    set.get(value / 64).is_some_and(|word| (word >> (value % 64)) & 1 == 1)
}

/// What is known of one group for a clock: the first three bytes of its header before
/// encryption, and the stream bytes they were encrypted with.
#[derive(Debug, Clone, Copy)]
struct Group {
    plain: [u8; 3],
    stream: [u8; 3],
}

/// The entry of the CRC table for a byte.
fn crc(byte: u8) -> u32 {
    CRC.get(usize::from(byte)).copied().unwrap_or_default()
}

/// The stretch of a number that has one top byte after something is added to it: where it
/// starts, when the top byte is `top` and what is added is `added`.
const fn stretch_start(top: u8, added: u32) -> u32 {
    ((top as u32) << 24).wrapping_sub(added)
}

/// What two stretches of 2^24 numbers and under have in common on the circle of 2^32: the
/// one from `at` of length `len`, and the one of full length from `start`.
const fn in_both(stretch: Option<(u32, u32)>, start: u32) -> Option<(u32, u32)> {
    /// How long the stretch of numbers is that have one top byte.
    const FULL: u32 = 1 << 24;
    let Some((at, len)) = stretch else { return Some((start, FULL)) };
    let ahead = start.wrapping_sub(at);
    let behind = at.wrapping_sub(start);
    if ahead < len {
        let left = len - ahead;
        Some((start, if left < FULL { left } else { FULL }))
    } else if behind < FULL {
        let left = FULL - behind;
        Some((at, if len < left { len } else { left }))
    } else {
        None
    }
}

/// Whether the headers of the groups can have been written at these counts: `counts` has
/// the tick count of each group and `headers` its header as it stands in the archive.
///
/// Every header is encrypted from the same keys. The stream byte of the second byte of a
/// group is that of the third key after one step, and the step is taken with the top byte
/// of the second key, which the first byte of the group moves. So:
///
/// 1. The second stream byte of each group allows 63 values in 100 for bits 10 to 23 of the
///    third key after the password. What every group allows is one value in 64, or none.
/// 2. For each of them, each group names the top byte of its second key after its first
///    byte. That byte is the top byte of a product which the low two bytes of the first
///    key and the second key decide: for the right low bytes all groups agree on where the
///    second key lies, and for wrong ones the third or fourth group does not.
/// 3. The same once more with the third stream byte, which takes the top byte of the third
///    key and the third byte of the first: with them every group names the top byte of its
///    second key after its second byte, and all have to agree again.
///
/// A clock that gives other bytes than the clock of the archive in the second or third place
/// of its headers passes with a chance far below one in the count of clocks there are.
#[must_use]
pub fn holds(counts: &[u32], headers: &[[u8; 12]]) -> bool {
    let tables = &*TABLES;
    let groups: Vec<Group> = counts
        .iter()
        .zip(headers)
        .take(MAX_GROUPS)
        .map(|(&count, header)| {
            let [a, b, c, ..] = dotnet::header_bytes(seed_at(count));
            let [in_a, in_b, in_c, ..] = *header;
            Group { plain: [a, b, c], stream: [in_a ^ a, in_b ^ b, in_c ^ c] }
        })
        .collect();
    let Some(&Group { stream: [stream, ..], .. }) = groups.first() else { return false };
    if groups.iter().any(|group| group.stream[0] != stream) {
        return false;
    }

    // 1. bits 10 to 23 of the third key: what every group allows
    let mut allowed = [u64::MAX; LOW / 64];
    for group in &groups {
        let Some(set) = tables.before.get(usize::from(group.stream[1])) else { return false };
        for (word, of_group) in allowed.iter_mut().zip(set) {
            *word &= of_group;
        }
    }
    if groups.len() < 6 {
        return false;
    }
    let Some(first_values) = tables.low.get(usize::from(stream)) else { return false };
    for upper in (0..LOW).filter(|upper| has(&allowed, *upper)) {
        // the bytes that the third key can step with to give each group its second stream
        // byte: one or two for each group
        let steps: Vec<Vec<u8>> = groups.iter().map(|group| steps_to(group.stream[1], upper)).collect();
        // bits 2 to 9 of the third key, from its first stream byte: bits 10 to 15 are given
        for &value in first_values.iter().filter(|value| usize::from(**value) >> 8 == upper & 0x3f) {
            for low_bits in 0..4_u32 {
                // the low 24 bits of the third key after the password
                let third = low_bits | (u32::from(value) << 2) | (u32::try_from(upper >> 6).unwrap_or_default() << 16);
                if second_byte_fits(&groups, &steps, third, |low, second, taken| third_byte_fits(&groups, taken, third, low, second)) {
                    return true;
                }
            }
        }
    }
    false
}

/// The bytes that a third key can step with to reach a stream byte: `upper` is bits 10 to 23
/// of the key before the step, which are bits 2 to 15 behind it but for the table entry of
/// the byte.
fn steps_to(stream: u8, upper: usize) -> Vec<u8> {
    let Some(wanted) = TABLES.is_low.get(usize::from(stream)) else { return Vec::new() };
    (0..=255_u8).filter(|&index| has(wanted, upper ^ ((crc(index) >> 2) as usize & (LOW - 1)))).collect()
}

/// Whether one of the candidates of each group can be taken so that the stretches they
/// stand for all have a number in common: `start` gives the stretch of a candidate of a
/// group, by their places. The candidates that were taken are left in `taken`.
fn agree(candidates: &[Vec<u8>], start: &impl Fn(usize, u8) -> u32, stretch: Option<(u32, u32)>, taken: &mut Vec<u8>) -> bool {
    let Some(of_group) = candidates.get(taken.len()) else { return true };
    let group = taken.len();
    for &candidate in of_group {
        if let Some(common) = in_both(stretch, start(group, candidate)) {
            taken.push(candidate);
            if agree(candidates, start, Some(common), taken) {
                return true;
            }
            let _ = taken.pop();
        }
    }
    false
}

/// Step 2 of [`holds`]: every low two bytes of the first key for which some second key gives
/// each group the top byte of its second key after its first byte. `steps` has the bytes the
/// third key of each group can step with, `third` is the low 24 bits of the third key, and
/// `also` is asked of each pair of bytes that fits, with the step that was taken for each
/// group: the answer is whether it said yes to one.
fn second_byte_fits(groups: &[Group], steps: &[Vec<u8>], third: u32, mut also: impl FnMut(u8, u8, &[u8]) -> bool) -> bool {
    let low_of_third = third.to_le_bytes()[0];
    let mut taken = Vec::with_capacity(groups.len());
    for low in 0..=255_u8 {
        // the low byte of the first key after the first byte of each group, but for the
        // second byte of the first key, which is the same in all
        let of_table: Vec<u8> = groups.iter().map(|group| crc(low ^ group.plain[0]).to_le_bytes()[0]).collect();
        for second in 0..=255_u8 {
            // the stretch in which the second key, times the multiplier, has to lie: the top
            // byte of the second key after the step is the byte of the step, exclusive-or
            // the low byte of the third key
            let start = |group: usize, step: u8| stretch_start(step ^ low_of_third, u32::from(of_table.get(group).copied().unwrap_or_default() ^ second).wrapping_mul(MULTIPLIER).wrapping_add(1));
            taken.clear();
            if agree(steps, &start, None, &mut taken) && also(low, second, &taken) {
                return true;
            }
        }
    }
    false
}

/// Step 3 of [`holds`]: whether some top byte of the third key and some third byte of the
/// first key give each group its third stream byte. `taken` has the byte the third key of
/// each group stepped with, `third` is the low 24 bits of the third key, and `low` and
/// `second` the low two bytes of the first.
fn third_byte_fits(groups: &[Group], taken: &[u8], third: u32, low: u8, second: u8) -> bool {
    // for each group: what its first step adds to the second key, and the low byte of the
    // first key after its second step, but for the third byte of the first key
    let moves: Vec<(u32, u8)> = groups
        .iter()
        .map(|group| {
            let entry = crc(low ^ group.plain[0]);
            let first_low = entry.to_le_bytes()[0] ^ second;
            (u32::from(first_low).wrapping_mul(MULTIPLIER).wrapping_add(1), entry.to_le_bytes()[1] ^ crc(first_low ^ group.plain[1]).to_le_bytes()[0])
        })
        .collect();
    let mut chosen = Vec::with_capacity(groups.len());
    for top in 0..=255_u32 {
        // the third key of each group after its first byte, and the bytes it can step with
        // to its third stream byte
        let after_first: Vec<u32> = taken.iter().map(|step| ((third | (top << 24)) >> 8) ^ crc(*step)).collect();
        let steps: Vec<Vec<u8>> = groups.iter().zip(&after_first).map(|(group, key)| steps_to(group.stream[2], (key >> 10) as usize & (LOW - 1))).collect();
        if steps.iter().any(Vec::is_empty) {
            continue;
        }
        for third_of_first in 0..=255_u8 {
            // the second key after the second step is the one after the first, plus the low
            // byte of the first key, times the multiplier, plus one: its top byte holds the
            // second key after the password, times the multiplier twice, within a stretch
            let start = |group: usize, step: u8| {
                let (added, partly) = moves.get(group).copied().unwrap_or_default();
                let key = after_first.get(group).copied().unwrap_or_default();
                stretch_start(step ^ key.to_le_bytes()[0], added.wrapping_add(u32::from(partly ^ third_of_first)).wrapping_mul(MULTIPLIER).wrapping_add(1))
            };
            chosen.clear();
            if agree(&steps, &start, None, &mut chosen) {
                return true;
            }
        }
    }
    false
}

/// The tick count at every group, for every clock in `interrupts` that the headers of the
/// groups fit: the first bytes of the groups, held against each other, and then [`holds`].
///
/// `headers` has the header of each group as it stands in the archive, in the order the
/// groups were written. Up to [`GAP`] interrupts may lie between one group and the next,
/// and only the first [`MAX_GROUPS`] groups are looked at: an answer has a count for each
/// of those. `control.done` is advanced by one for every interrupt: the total is the length
/// of the range.
///
/// The search ends with the first piece of the range that holds a clock: an answer is the
/// number of the interrupt at the first group, and the counts. A caller whose search for the
/// keys finds none with a clock goes on behind that interrupt.
#[must_use]
pub fn clocks(headers: &[[u8; 12]], interrupts: Range<u64>, control: Control<'_>) -> Vec<(u64, Vec<u32>)> {
    let headers = headers.get(..headers.len().min(MAX_GROUPS)).unwrap_or_default();
    let (Some(base), true) = (headers.first().and_then(|header| header.first()), interrupts.start < interrupts.end) else { return Vec::new() };
    // what the first byte of each later group differs from that of the first group by
    let wanted: Vec<u8> = headers.iter().skip(1).filter_map(|header| header.first()).map(|byte| byte ^ base).collect();
    let reach = (GAP * wanted.len()) as u64;
    let pieces = (interrupts.end - interrupts.start).div_ceil(PIECE);
    // a clock that holds is the clock: the pieces behind it are not searched
    let ended = AtomicBool::new(false);
    let mut found = spread(pieces, control, |piece, found: &mut Vec<(u64, Vec<u32>)>| {
        let from = interrupts.start + piece * PIECE;
        let to = (from + PIECE).min(interrupts.end);
        if ended.load(Ordering::Relaxed) {
            control.advance(to - from);
            return;
        }
        // the first byte at every interrupt of the piece, and as far behind it as the groups can reach
        let bytes: Vec<u8> = (from..to + reach).map(|interrupt| first_byte(tick_count(interrupt))).collect();
        for start in 0..usize::try_from(to - from).unwrap_or(0) {
            let mut places = vec![start];
            follow(&bytes, start, &wanted, &mut places, &mut |places| {
                let counts: Vec<u32> = places.iter().map(|place| tick_count(from + *place as u64)).collect();
                if found.len() < FOUND_MAX && holds(&counts, headers) {
                    found.push((from + places.first().map_or(0, |place| *place as u64), counts));
                    ended.store(true, Ordering::Relaxed);
                }
            });
        }
        control.advance(to - from);
    });
    found.sort_unstable();
    found.truncate(FOUND_MAX);
    found
}

/// Go on from the last group that has a place: every interrupt within the gap whose first
/// byte is what the next group wants, and from there the groups behind it. A sequence that
/// reaches the last group is given to `each`. A place is an interrupt, counted from the
/// start of `bytes`.
fn follow(bytes: &[u8], start: usize, wanted: &[u8], places: &mut Vec<usize>, each: &mut impl FnMut(&[usize])) {
    let Some((&next, rest)) = wanted.split_first() else {
        each(places);
        return;
    };
    let (Some(&base), Some(&at)) = (bytes.get(start), places.last()) else { return };
    for step in 1..=GAP {
        if bytes.get(at + step).is_some_and(|byte| byte ^ base == next) {
            places.push(at + step);
            follow(bytes, start, rest, places, each);
            let _ = places.pop();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;

    /// The headers that a writer makes for groups at these counts, under a password: eleven
    /// bytes of the generator and a check byte, encrypted once from the keys of the password.
    fn written(counts: &[u32], password: &[u8]) -> Vec<[u8; 12]> {
        counts
            .iter()
            .zip(0_u8..)
            .map(|(&count, check)| {
                let mut keys = Keys::from_password(password);
                let mut header = [0_u8; 12];
                for (slot, plain) in header.iter_mut().zip(dotnet::header_bytes(seed_at(count)).into_iter().chain([check.wrapping_mul(37)])) {
                    *slot = keys.encrypt(plain);
                }
                header
            })
            .collect()
    }

    /// The counts of twenty groups from an interrupt on, a step or two apart.
    fn counts_from(interrupt: u64) -> Vec<u32> {
        let mut at = interrupt;
        (0..20_u64)
            .map(|group| {
                at += 1 + (group * 7 + interrupt) % 2;
                tick_count(at)
            })
            .collect()
    }

    #[test]
    fn the_count_moves_with_the_timer() {
        // the counts a program printed on Windows Server 2022, one for each interrupt: 15 or 16 apart
        let printed = [1_582_937_484_u32, 1_582_937_500, 1_582_937_515, 1_582_937_531, 1_582_937_546, 1_582_937_562, 1_582_937_578, 1_582_937_593, 1_582_937_609, 1_582_937_625];
        let interrupt = u64::from(printed[0]) * 8 / 125 + 1;
        assert_eq!((0..10).map(|step| tick_count(interrupt + step)).collect::<Vec<_>>(), printed);
        // a count is negative as a seed from the 25th day on
        assert!(seed_at(tick_count(100_000_000)) > 0 && seed_at(tick_count(140_000_000)) < 0);
    }

    #[test]
    fn the_generator_gives_the_header_bytes_of_the_framework() {
        // a header that SharpZipLib 1.3.0 wrote on the .NET Framework 4.8 at this count,
        // decrypted with the keys of its password: eleven bytes of the generator
        assert_eq!(dotnet::header_bytes(seed_at(1_582_937_562)), [0x35, 0x11, 0x3c, 0xed, 0xf3, 0x6d, 0x5b, 0xe3, 0x08, 0xf6, 0x49]);
        // and one that DotNetZip 1.16 wrote
        assert_eq!(dotnet::header_bytes(seed_at(1_582_938_125)), [0xed, 0x90, 0x4c, 0x2e, 0x2a, 0xec, 0x24, 0x6f, 0x52, 0x80, 0x62]);
    }

    #[test]
    fn the_headers_hold_for_their_clock_and_for_no_other_that_fits_their_first_bytes() {
        let interrupt = 101_308_003;
        let counts = counts_from(interrupt);
        let headers = written(&counts, b"a password of the framework");
        assert!(holds(&counts, &headers));

        // every clock near it that fits the first bytes of all groups: the search by first
        // bytes alone finds some, and the headers hold for the true one alone
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let control = Control { stop: &stop, done: &done, threads: 4 };
        let wanted: Vec<u8> = headers.iter().skip(1).map(|header| header[0] ^ headers[0][0]).collect();
        let from = interrupt - 40_000;
        let bytes: Vec<u8> = (from..from + 80_000 + (GAP * wanted.len()) as u64).map(|at| first_byte(tick_count(at))).collect();
        let mut fitting = 0;
        for start in 0..80_000 {
            let mut places = vec![start];
            follow(&bytes, start, &wanted, &mut places, &mut |_| fitting += 1);
        }
        assert!(fitting >= 2, "{fitting} clocks fit the first bytes");
        assert_eq!(clocks(&headers, from..from + 80_000, control), [(interrupt + 1 + interrupt % 2, counts)]);
    }

    #[test]
    #[ignore = "long: make test-zip-crypto"]
    fn the_clock_of_the_recorded_archives_is_found_near_the_count_their_writer_logged() {
        use crate::attack::zip_crypto::pool::Pool;
        // two archives written on the .NET Framework 4.8 of Windows Server 2022, one by each
        // library, with the tick count that the program printed in front of its first entry
        for (fixture, password, logged) in [("gen_sharpziplib_netfx.zip", &b"sharp-on-the-framework"[..], 1_586_105_140_u32), ("gen_dotnetzip_netfx.zip", b"dotnetzip-on-the-framework", 1_586_105_515)] {
            let pool = Pool::read(&[std::path::PathBuf::from(format!("tests/fixtures/zip-crypto/{fixture}"))], &|_| None).unwrap();
            let mut targets: Vec<_> = pool.targets.iter().collect();
            targets.sort_by_key(|target| target.start);
            // the groups: entries that were written between two steps of the clock have one header
            let mut headers: Vec<[u8; 12]> = Vec::new();
            for target in targets {
                if headers.last().is_none_or(|last| last[..10] != target.header[..10]) {
                    headers.push(target.header);
                }
            }
            assert!(headers.len() >= MIN_GROUPS, "{fixture}: {} groups", headers.len());

            let near = u64::from(logged) * 8 / 125;
            let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
            let found = clocks(&headers, near - 2000..near + 2000, Control { stop: &stop, done: &done, threads: 4 });
            let [(interrupt, counts)] = found.as_slice() else { panic!("{fixture}: {} clocks", found.len()) };
            // within a few steps of what was logged, and a count for every group
            assert!(counts[0] >= logged && counts[0] - logged < 64 && tick_count(*interrupt) == counts[0], "{fixture}: {}", counts[0]);
            assert_eq!(counts.len(), headers.len().min(MAX_GROUPS));
            // the bytes of the generator at each count, encrypted under the keys of the
            // password, are the first eleven bytes of the header of the group
            for (count, header) in counts.iter().zip(&headers) {
                let mut keys = Keys::from_password(password);
                let written: Vec<u8> = dotnet::header_bytes(seed_at(*count)).iter().map(|byte| keys.encrypt(*byte)).collect();
                assert_eq!(written, header[..11], "{fixture}: the group at {count}");
            }
        }
    }

    #[test]
    fn headers_of_another_password_and_too_few_groups_find_no_clock() {
        let counts = counts_from(5_000_000);
        let headers = written(&counts, b"one password");
        // the same counts with the headers of other counts
        let other = written(&counts_from(5_000_300), b"one password");
        assert!(!holds(&counts, &other));
        assert!(!holds(&[], &[]));
        // four groups name too little of the keys for the test to say anything
        assert!(!holds(&counts[..4], &headers[..4]));
    }
}
