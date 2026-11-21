//! From the keys back to the password: every password of six bytes or fewer that gives three
//! keys, worked out from them with no search.
//!
//! This file is a port of parts of bkcrack by Joachim Hotonnier
//! (<https://github.com/kimci86/bkcrack>). It is an altered version and is not the original
//! software. That work is under the zlib licence, and so is what is taken from it here: the
//! notice and the full text are in `LICENSE-BKCRACK.txt`.
//!
//! The method is the one of Biham and Kocher (1994, section 3.6) as bkcrack does it. Six bytes
//! are 48 bits and the keys are 96, so six updates between two known states leave nothing to
//! guess. The states are at places 0 to 6: place 0 is where the six updates start, place 6 is
//! the keys that are asked about, and byte `i` of the six leads from place `i` to place
//! `i + 1`.
//!
//! 1. The second key at place 5 follows from the keys: its update is undone, and the low byte
//!    of the first key that went into it is known.
//! 2. The third key at place 4 follows, by two steps of the CRC undone with the top bytes of
//!    the second key at places 6 and 5. Four steps lie between it and the third key at place
//!    0, and four bytes went into them: the top bytes of the second key at places 1 to 4. One
//!    run of four bytes and no other leads from the one value to the other, so these top
//!    bytes are known, whatever the two values are.
//! 3. From place 5 down, the second key one place back is one of 256 values, one for each low
//!    byte of the first key. Its top byte is known, and so is the top byte two places back,
//!    which the same low byte reaches through one more multiplication. The table of the
//!    reference kernel lists the low bytes that can give that top byte. A low byte that fits
//!    both gives all of the second key one place back.
//! 4. The second key at place 0 is known whole. What is left of it at place 1 is the low byte
//!    of the first key there, and it has to be a byte.
//! 5. The first key at place 6 is known. One step of the CRC undone gives the first key one
//!    place back, exclusive-or the byte of the password, and the low byte of that key is on
//!    the list, which gives the byte. At place 0 the first key has to be the one of the
//!    start: 24 bits that nothing has used before.
//!
//! Every test on the way is one that the right six bytes pass, and what comes out has been
//! held against all 96 bits at both ends, so it leads from the one state to the other. The
//! design holds the proof that the method as bkcrack does it misses no password of six bytes
//! or fewer.
//!
//! A shorter password is found as bkcrack finds it. The initial keys are moved back, one
//! update by a zero byte undone for each byte the password lacks, so that six updates lie
//! between the start and the keys again. The password is then what stands behind the zero
//! bytes.
//!
//! The code is not bkcrack line for line in four places, and in none of them does it drop
//! six bytes that bkcrack keeps.
//!
//! - The top bytes of step 2 come from one exclusive-or, where bkcrack walks the third key
//!   forward from place 0 and reads them off one at a time ([`second_key_tops`]).
//! - bkcrack makes a set for the keys, in a pass over every last byte: the values that bits
//!   16 to 31 of the third key at place 0 can have. It asks the set before anything else.
//!   That pays where many starts are held against the same keys, as in its search for a
//!   longer password. Here the starts are seven and the keys are many, and the set says no
//!   more than that step 3 finds a low byte at place 5, so it is not made.
//! - Step 3 asks one test before it walks its list: whether any byte at all gives the top
//!   byte one place back ([`top_in_reach`]). It fails only where every byte of the list
//!   would fail the test of bkcrack on that top byte, and nearly all keys end there.
//! - bkcrack cuts the front off the six bytes of a shorter password without looking at it.
//!   Here the front has to be the zero bytes. Six bytes with another front do not pass
//!   through the initial keys, and what stands behind them is no password. A password of
//!   that length leads to the keys from behind the zero bytes too, and is found there.

use crate::Keys;
use crate::tables::MAX_DIFF_24;
use crate::tables::MULT_INV;
use crate::tables::crc32_inv;
use crate::tables::fiber2;
use crate::tables::lsb;
use crate::tables::mask;
use crate::tables::msb;

/// The longest password that follows from its keys alone, and the count of updates one
/// inversion runs through.
const LONGEST: usize = 6;

/// The byte that stands in front of a password shorter than [`LONGEST`].
const FILL: u8 = 0;

/// For each length of a password, the keys six updates before its keys: the initial keys with
/// one update by [`FILL`] undone for each byte it is shorter than [`LONGEST`].
static STARTS: [Keys; LONGEST + 1] = starts();

/// The table of [`STARTS`], from the initial keys at its end back to its front.
const fn starts() -> [Keys; LONGEST + 1] {
    let mut table = [Keys::INITIAL; LONGEST + 1];
    let mut length = LONGEST;
    while length > 0 {
        let after = table[length];
        let z = crc32_inv(after.z, msb(after.y));
        let y = after.y.wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(lsb(after.x) as u32);
        let x = crc32_inv(after.x, FILL);
        table[length - 1] = Keys::new(x, y, z);
        length -= 1;
    }
    table
}

/// Every password of `max_len` bytes or fewer that gives `keys`, shortest first.
///
/// Usually none or one; more than one only by collision. Nothing is searched: the passwords
/// follow from the keys, and each one that is returned gives them. Six bytes are as far as
/// that goes, so a `max_len` above six counts as six.
#[must_use]
pub fn short_passwords(keys: Keys, max_len: usize) -> Vec<Vec<u8>> {
    let mut passwords = Vec::new();
    each_password(keys, max_len, |password| passwords.push(password.to_vec()));
    passwords
}

/// Whether [`short_passwords`] would return a password, without making the list.
///
/// This is the question a filter asks of every key it is given, and nearly every key has
/// none: of the 2^96 keys at most 2^48 have a password of six bytes. Nothing is allocated,
/// whatever the answer.
#[must_use]
pub fn has_short_password(keys: Keys, max_len: usize) -> bool {
    let mut any = false;
    each_password(keys, max_len, |_| any = true);
    any
}

/// Hands every password of `max_len` bytes or fewer that gives `keys` to `found`, shortest
/// first.
fn each_password(keys: Keys, max_len: usize, mut found: impl FnMut(&[u8])) {
    let end = End::of(keys);
    for (length, &start) in STARTS.iter().enumerate().take(max_len.saturating_add(1)) {
        each_six(start, end, |six| {
            let (front, password) = six.split_at(LONGEST - length);
            if front.iter().all(|&byte| byte == FILL) {
                found(password);
            }
        });
    }
}

/// What keys say of the six updates that led to them, whatever those started from.
#[derive(Clone, Copy)]
struct End {
    /// The first key at place 6.
    x6: u32,
    /// The second key at place 5.
    y5: u32,
    /// The third key at place 4 taken back four steps of the CRC with no byte: the third key
    /// at place 0, but for the top bytes of the second key at places 1 to 4.
    z0: u32,
}

impl End {
    /// The end that `keys` are, as the state at place 6.
    fn of(keys: Keys) -> Self {
        let y5 = keys.y.wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(u32::from(lsb(keys.x)));
        let z4 = crc32_inv(crc32_inv(keys.z, msb(keys.y)), msb(y5));
        Self { x6: keys.x, y5, z0: crc32_inv(crc32_inv(crc32_inv(crc32_inv(z4, 0), 0), 0), 0) }
    }
}

/// Hands to `found` every six bytes that lead from the keys `start` to the keys of `end`.
///
/// The four loops are the four levels of bkcrack's recursion, from place 5 down to place 2.
fn each_six(start: Keys, end: End, mut found: impl FnMut([u8; LONGEST])) {
    let [top1, top2, top3, top4] = second_key_tops(start.z, end.z0);
    for (x5, y4) in fits(end.y5, top4, top3) {
        for (x4, y3) in fits(y4, top3, top2) {
            for (x3, y2) in fits(y3, top2, top1) {
                for (x2, y1) in fits(y2, top1, start.y & mask(24, 32)) {
                    // the second key at place 0 is known whole: what it leaves of the one at
                    // place 1 is the low byte of the first key there, and has to be a byte
                    let x1 = y1.wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(start.y);
                    if x1 <= 0xff {
                        let (six, x0) = first_key(end.x6, [lsb(start.x), lsb(x1), x2, x3, x4, x5]);
                        if x0 == start.x {
                            found(six);
                        }
                    }
                }
            }
        }
    }
}

/// The top bytes of the second key at places 1 to 4, each at the top of a word, from the
/// third key at place 0 and the third key at place 4 taken back four steps with no byte.
///
/// A step of the CRC undone is linear. It puts the byte that went into the step at the bottom
/// of the word, and each further step undone moves that byte up by one and changes nothing
/// else of it. So the third key at place 0 is the one at place 4 taken back with no byte,
/// exclusive-or the four top bytes, one in each byte of the word: that of place 1 lowest,
/// that of place 4 at the top. These are the bytes bkcrack finds, since no other four lead
/// from the one value to the other.
fn second_key_tops(z0: u32, z0_no_byte: u32) -> [u32; 4] {
    (z0 ^ z0_no_byte).to_le_bytes().map(|top| u32::from(top) << 24)
}

/// The low bytes of the first key at a place that fit what is known of the second key, each
/// with the second key one place back that it gives.
///
/// `y` is the second key at the place, `top` its top byte one place back and `top_before` its
/// top byte two places back, each at the top of a word. This is one level of bkcrack's
/// recursion, with the lookup and the window of the reference kernel behind it.
fn fits(y: u32, top: u32, top_before: u32) -> impl Iterator<Item = (u8, u32)> {
    let fy = y.wrapping_sub(1).wrapping_mul(MULT_INV);
    let ffy = fy.wrapping_sub(1).wrapping_mul(MULT_INV);
    let list = if top_in_reach(fy, top) { fiber2(msb(ffy.wrapping_sub(top_before))) } else { &[] };
    list.iter().filter_map(move |&x| {
        let before = fy.wrapping_sub(u32::from(x));
        (ffy.wrapping_sub(MULT_INV.wrapping_mul(u32::from(x))).wrapping_sub(top_before) <= MAX_DIFF_24 && msb(before) == msb(top)).then_some((x, before))
    })
}

/// Whether some byte taken from `fy` leaves a word with the top byte of `top`.
///
/// The second key one place back is `fy` less the low byte of the first key, and its top byte
/// is known. Less a byte `x`, `fy` has that top byte when it lies `x` to `x + 2^24 - 1` above
/// `top`: for some byte, when it lies 0 to `2^24 + 254` above. Outside of that no byte passes
/// the test of [`fits`] on the top byte, and there is no list to walk. One comparison settles
/// it for 255 of 256 starts that do not lead to the keys, which is what makes the answer that
/// there is no password fast.
const fn top_in_reach(fy: u32, top: u32) -> bool {
    fy.wrapping_sub(top) <= MAX_DIFF_24
}

/// The six bytes that the first key at place 6 and its low bytes at places 0 to 5 give, and
/// the first key at place 0 that follows from them.
fn first_key(x6: u32, low: [u8; LONGEST]) -> ([u8; LONGEST], u32) {
    let mut x = x6;
    let mut six = [0_u8; LONGEST];
    for (byte, low) in six.iter_mut().zip(low).rev() {
        // a step undone with no byte is the first key one place back, exclusive-or the byte
        let mixed = crc32_inv(x, 0);
        *byte = lsb(mixed) ^ low;
        x = mixed ^ u32::from(*byte);
    }
    (six, x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::MULT;
    use crate::tables::crc32;

    /// A small generator with a fixed seed, so that a test is the same on every run.
    struct Random(u64);

    impl Random {
        /// The next 64 bits (splitmix64).
        fn bits(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        /// A word.
        fn word(&mut self) -> u32 {
            u32::try_from(self.bits() >> 32).unwrap()
        }

        /// Three keys with nothing behind them.
        fn keys(&mut self) -> Keys {
            Keys::new(self.word(), self.word(), self.word())
        }

        /// A password of `length` bytes, each of them any of the 256.
        fn password(&mut self, length: usize) -> Vec<u8> {
            (0..length).map(|_| self.bits().to_le_bytes()[7]).collect()
        }
    }

    /// The passwords of the keys of `password`, each one held against the keys, and the short
    /// answer held against the list.
    fn recovered(password: &[u8], max_len: usize) -> Vec<Vec<u8>> {
        let keys = Keys::from_password(password);
        let passwords = short_passwords(keys, max_len);
        for found in &passwords {
            assert!(found.len() <= max_len.min(LONGEST), "{found:02x?} is longer than {max_len}");
            assert_eq!(Keys::from_password(found), keys, "{found:02x?} does not give the keys of {password:02x?}");
        }
        assert_eq!(has_short_password(keys, max_len), !passwords.is_empty());
        passwords
    }

    /// The keys after `bytes`, from `start`.
    fn after(start: Keys, bytes: &[u8]) -> Keys {
        let mut keys = start;
        for &byte in bytes {
            keys.update(byte);
        }
        keys
    }

    /// Every six bytes the inversion finds between two states, each held against both.
    fn sixes(start: Keys, end: Keys) -> Vec<[u8; LONGEST]> {
        let mut found = Vec::new();
        each_six(start, End::of(end), |six| found.push(six));
        for six in &found {
            assert_eq!(after(start, six), end, "{six:02x?} does not lead from {start} to {end}");
        }
        found
    }

    #[test]
    fn six_updates_lead_from_each_start_to_the_initial_keys() {
        assert_eq!(STARTS[LONGEST], Keys::INITIAL);
        for (length, &start) in STARTS.iter().enumerate() {
            assert_eq!(after(start, &[FILL; LONGEST][length..]), Keys::INITIAL, "length {length}");
        }
    }

    #[test]
    fn the_top_bytes_carry_the_third_key_from_place_0_to_place_4() {
        let mut random = Random(1);
        for _ in 0..100_000 {
            let (z0, z4) = (random.word(), random.word());
            let z0_no_byte = crc32_inv(crc32_inv(crc32_inv(crc32_inv(z4, 0), 0), 0), 0);
            let mut z = z0;
            for top in second_key_tops(z0, z0_no_byte) {
                assert_eq!(top & mask(0, 24), 0);
                z = crc32(z, msb(top));
            }
            assert_eq!(z, z4);
        }
    }

    #[test]
    fn the_early_test_fails_only_where_no_byte_gives_the_top_byte() {
        let plainly = |fy: u32, top: u32| (0..=255_u32).any(|x| msb(fy.wrapping_sub(x)) == msb(top));
        // the ends of the reach and the values beside them
        for top in [0_u32, 0x0100_0000, 0x7f00_0000, 0x8000_0000, 0xff00_0000] {
            for above in [0, 1, 0xfe, 0xff, 0x100, 0x00ff_ffff, 0x0100_0000, 0x0100_00fd, MAX_DIFF_24, 0x0100_00ff, 0x0100_0100, 0x0200_0000, 0x8000_0000, 0xff00_0000, 0xffff_ff00, u32::MAX] {
                let fy = top.wrapping_add(above);
                assert_eq!(top_in_reach(fy, top), plainly(fy, top), "{above:#x} above {top:#x}");
                assert_eq!(top_in_reach(fy, top), above <= MAX_DIFF_24);
            }
        }
        let mut random = Random(7);
        for _ in 0..500_000 {
            let (fy, top) = (random.word(), random.word() & mask(24, 32));
            assert_eq!(top_in_reach(fy, top), plainly(fy, top), "{fy:#x} and {top:#x}");
            // and near the reach, where one draw in four is inside it
            let fy = top.wrapping_add(random.word() >> 6);
            assert_eq!(top_in_reach(fy, top), plainly(fy, top), "{fy:#x} and {top:#x}");
        }
    }

    /// The lookup and the early test are there for speed. What [`fits`] gives is what the two
    /// tests of bkcrack pass of all 256 bytes.
    #[test]
    fn the_lookup_and_the_early_test_drop_no_byte_that_fits() {
        let plainly = |y: u32, top: u32, top_before: u32| {
            let fy = y.wrapping_sub(1).wrapping_mul(MULT_INV);
            let ffy = fy.wrapping_sub(1).wrapping_mul(MULT_INV);
            let fit = |x: u8| ffy.wrapping_sub(MULT_INV.wrapping_mul(u32::from(x))).wrapping_sub(top_before) <= MAX_DIFF_24 && msb(fy.wrapping_sub(u32::from(x))) == msb(top);
            (0..=255_u8).filter(|&x| fit(x)).map(|x| (x, fy.wrapping_sub(u32::from(x)))).collect::<Vec<_>>()
        };
        let mut random = Random(8);
        // three places of a second key as the cipher makes them: the byte between is found
        for _ in 0..500_000 {
            let [low_before, low, ..] = random.word().to_le_bytes();
            let y_two_before = random.word();
            let y_before = y_two_before.wrapping_add(u32::from(low_before)).wrapping_mul(MULT).wrapping_add(1);
            let y = y_before.wrapping_add(u32::from(low)).wrapping_mul(MULT).wrapping_add(1);
            let (top, top_before) = (y_before & mask(24, 32), y_two_before & mask(24, 32));
            let found: Vec<_> = fits(y, top, top_before).collect();
            assert!(found.contains(&(low, y_before)));
            assert_eq!(found, plainly(y, top, top_before));
        }
        // and words with nothing behind them, where nearly every list is empty
        let mut some = 0;
        for _ in 0..2_000_000 {
            let (y, top, top_before) = (random.word(), random.word() & mask(24, 32), random.word() & mask(24, 32));
            let found: Vec<_> = fits(y, top, top_before).collect();
            assert_eq!(found, plainly(y, top, top_before));
            some += usize::from(!found.is_empty());
        }
        assert!(some > 1_000, "{some} lists of random words held a byte");
    }

    #[test]
    fn the_six_bytes_between_any_two_states_are_found() {
        let mut random = Random(9);
        for _ in 0..300_000 {
            let start = random.keys();
            let six = random.password(LONGEST);
            assert_eq!(sixes(start, after(start, &six)), [&six[..]]);
        }
        for _ in 0..300_000 {
            let (start, end) = (random.keys(), random.keys());
            assert!(sixes(start, end).is_empty(), "{start} to {end}");
        }
    }

    /// A start one bit away from the state the six bytes began at passes many of the tests on
    /// the way, the last ones on each key among them, and nothing leads from it to the end.
    /// But for a bit in the low byte of the first key: the first step of the CRC takes that
    /// byte exclusive-or the first of the six, so the same bit in that byte makes up for it.
    #[test]
    fn a_start_one_bit_away_leads_to_the_end_only_where_a_byte_makes_up_for_it() {
        let mut random = Random(11);
        for _ in 0..2_000 {
            let start = random.keys();
            let six = random.password(LONGEST);
            let end = after(start, &six);
            for bit in 0..32 {
                for near in [Keys::new(start.x, start.y ^ (1 << bit), start.z), Keys::new(start.x, start.y, start.z ^ (1 << bit))] {
                    assert!(sixes(near, end).is_empty(), "{near} beside {start}");
                }
                let near = Keys::new(start.x ^ (1 << bit), start.y, start.z);
                if bit < 8 {
                    let mut other = six.clone();
                    other[0] ^= 1 << bit;
                    assert_eq!(sixes(near, end), [&other[..]], "{near} beside {start}");
                } else {
                    assert!(sixes(near, end).is_empty(), "{near} beside {start}");
                }
            }
        }
    }

    #[test]
    fn every_password_of_two_bytes_or_fewer_is_found() {
        assert_eq!(recovered(b"", LONGEST), [b""]);
        for first in 0..=255_u8 {
            assert_eq!(recovered(&[first], LONGEST), [[first]]);
            for second in 0..=255_u8 {
                assert_eq!(recovered(&[first, second], LONGEST), [[first, second]]);
            }
        }
    }

    #[test]
    fn a_password_of_any_bytes_is_found_at_every_length() {
        let mut random = Random(2);
        for length in 0..=LONGEST {
            for _ in 0..100_000 {
                let password = random.password(length);
                let passwords = recovered(&password, LONGEST);
                assert!(passwords.contains(&password), "{password:02x?} is not among {passwords:02x?}");
            }
        }
    }

    /// The fill byte is a byte a password may hold, at its front as anywhere.
    #[test]
    fn a_password_of_zero_bytes_is_found_with_its_length() {
        for length in 0..=LONGEST {
            let zeros = vec![FILL; length];
            assert_eq!(recovered(&zeros, LONGEST), [&zeros[..]]);
            for behind in 1..=LONGEST - length {
                let mut password = zeros.clone();
                password.extend((1..=behind).map(|byte| u8::try_from(byte).unwrap()));
                assert_eq!(recovered(&password, LONGEST), [&password[..]]);
            }
        }
    }

    /// Six bytes that lead to the keys from a start that was moved back, and not through the
    /// initial keys: the inversion finds them, and what stands behind their front is no
    /// password.
    #[test]
    fn six_bytes_with_another_front_are_no_password() {
        let mut random = Random(10);
        for (length, &start) in STARTS.iter().enumerate().take(LONGEST) {
            for _ in 0..20_000 {
                let mut six = random.password(LONGEST);
                if six[..LONGEST - length].iter().all(|&byte| byte == FILL) {
                    six[0] = !FILL;
                }
                let keys = after(start, &six);
                assert_eq!(sixes(start, keys), [&six[..]]);
                assert_ne!(Keys::from_password(&six[LONGEST - length..]), keys);
                assert!(short_passwords(keys, LONGEST).is_empty() && !has_short_password(keys, LONGEST), "{six:02x?} at length {length}");
            }
        }
    }

    #[test]
    fn no_password_longer_than_the_limit_is_returned() {
        assert!(recovered(b"sixsix", 5).is_empty());
        assert_eq!(recovered(b"sixsix", 6), [b"sixsix"]);
        assert_eq!(recovered(b"sixsix", 7), [b"sixsix"]);
        assert_eq!(recovered(b"sixsix", usize::MAX), [b"sixsix"]);
        assert!(recovered(b"", 0) == [b""] && recovered(b"a", 0).is_empty());

        let mut random = Random(3);
        for length in 0..=LONGEST {
            for _ in 0..5_000 {
                let password = random.password(length);
                let all = recovered(&password, LONGEST);
                for max_len in 0..=LONGEST + 1 {
                    let within: Vec<Vec<u8>> = all.iter().filter(|found| found.len() <= max_len).cloned().collect();
                    assert_eq!(recovered(&password, max_len), within, "{password:02x?} with at most {max_len} bytes");
                    assert_eq!(within.contains(&password), length <= max_len);
                }
            }
        }
    }

    #[test]
    fn the_keys_of_a_longer_password_have_no_short_one() {
        // the tutorial of bkcrack: the password has twelve bytes
        let tutorial = Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31);
        assert_eq!(tutorial, Keys::from_password(b"W4sF0rgotten"));
        assert!(!has_short_password(tutorial, LONGEST) && short_passwords(tutorial, LONGEST).is_empty());

        let mut random = Random(4);
        for length in 7..=12 {
            for _ in 0..100_000 {
                let password = random.password(length);
                assert!(recovered(&password, LONGEST).is_empty(), "{password:02x?}");
            }
        }
    }

    #[test]
    fn random_keys_have_no_short_password() {
        let mut random = Random(5);
        for _ in 0..4_000_000 {
            let keys = random.keys();
            assert!(!has_short_password(keys, LONGEST), "{keys}");
        }
        for _ in 0..100_000 {
            let keys = random.keys();
            assert!(short_passwords(keys, LONGEST).is_empty(), "{keys}");
        }
    }

    /// Keys one bit away from the keys of a short password pass many of the tests on the way,
    /// and have none.
    #[test]
    fn keys_one_bit_from_those_of_a_short_password_have_none() {
        let mut random = Random(6);
        for length in 0..=LONGEST {
            for _ in 0..500 {
                let keys = Keys::from_password(&random.password(length));
                for bit in 0..32 {
                    for near in [Keys::new(keys.x ^ (1 << bit), keys.y, keys.z), Keys::new(keys.x, keys.y ^ (1 << bit), keys.z), Keys::new(keys.x, keys.y, keys.z ^ (1 << bit))] {
                        assert!(!has_short_password(near, LONGEST) && short_passwords(near, LONGEST).is_empty(), "{near} beside {keys}");
                    }
                }
            }
        }
    }
}
