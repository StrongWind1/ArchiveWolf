//! The vector kernel for a processor without AVX-512: the flat loops of the scalar kernel,
//! eight lists at a time.
//!
//! It does what the kernel of sixteen lists does, with what AVX2 has for it. There are no
//! mask registers: a comparison leaves a register of lanes that are all ones or all zeroes,
//! and its sign bits are taken out as eight bits. There is no comparison of unsigned words:
//! `a <= b` is asked as "the smaller of the two is `a`". There is no compress: the lists that
//! are left are moved to the front of a register by a permutation, which a table gives for
//! each of the 256 sets of lanes.
//!
//! The CRC steps of the last test have no gather either. A step is linear, so the entry of
//! the CRC table for a byte is the exclusive-or of the entries for its four pieces of two
//! bits. A piece has four values and an entry four bytes: the sixteen bytes of one piece are
//! one table of a byte shuffle, which gives each byte of each lane its byte of the entry.
//!
//! The functions here are compiled for a processor with AVX2 and are safe to call from each
//! other. Unsafe code is in three places: where eight words are read from an array, where
//! they are written to one, and where the table of the kernel is gathered from.

use core::arch::x86_64::__m256i;
use core::arch::x86_64::_mm256_add_epi32;
use core::arch::x86_64::_mm256_and_si256;
use core::arch::x86_64::_mm256_castsi256_ps;
use core::arch::x86_64::_mm256_cmpeq_epi32;
use core::arch::x86_64::_mm256_cmpgt_epi32;
use core::arch::x86_64::_mm256_i32gather_epi32;
use core::arch::x86_64::_mm256_loadu_si256;
use core::arch::x86_64::_mm256_min_epu32;
use core::arch::x86_64::_mm256_movemask_ps;
use core::arch::x86_64::_mm256_mullo_epi32;
use core::arch::x86_64::_mm256_or_si256;
use core::arch::x86_64::_mm256_permutevar8x32_epi32;
use core::arch::x86_64::_mm256_set1_epi32;
use core::arch::x86_64::_mm256_setr_epi32;
use core::arch::x86_64::_mm256_shuffle_epi8;
use core::arch::x86_64::_mm256_slli_epi32;
use core::arch::x86_64::_mm256_srli_epi32;
use core::arch::x86_64::_mm256_storeu_si256;
use core::arch::x86_64::_mm256_sub_epi32;
use core::arch::x86_64::_mm256_xor_si256;

use super::BLOCK;
use super::Hit;
use super::Lists;
use super::Scratch;
use super::Window;
use super::finish;
use super::z_lists;
use crate::Keys;
use crate::tables::CRC;
use crate::tables::CRC_INV;
use crate::tables::FIT;
use crate::tables::FIT_BITS;
use crate::tables::MAX_DIFF_24;
use crate::tables::MAX_DIFF_26;
use crate::tables::MULT_INV;
use crate::tables::mask;

/// How many lists a register holds, as a count of words and as a step of the second key.
const LANES: usize = 8;
const STEP: u32 = 8;

/// The gather below takes its index from the top twelve bits of a word.
const _: () = assert!(FIT_BITS == 12 && FIT.len() == 1 << 12);

/// A block is a whole number of registers.
const _: () = assert!(BLOCK.is_multiple_of(STEP) && STEP as usize == LANES);

/// For every set of lanes, the permutation that moves its lanes to the front of a register,
/// in their order. What it puts behind them is not used.
static FRONT: [[u32; LANES]; 256] = {
    let mut table = [[0_u32; LANES]; 256];
    let mut set = 0;
    while set < 256 {
        let mut at = 0;
        let mut lane: u32 = 0;
        while lane < 8 {
            if (set >> lane) & 1 == 1 {
                table[set][at] = lane;
                at += 1;
            }
            lane += 1;
        }
        set += 1;
    }
    table
};

/// The same word in every lane.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn splat(word: u32) -> __m256i {
    _mm256_set1_epi32(word.cast_signed())
}

/// Eight words as a register.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn register(words: &[u32; LANES]) -> __m256i {
    // SAFETY: `words` is eight words that may be read, and this load asks for no alignment.
    unsafe { _mm256_loadu_si256(core::ptr::from_ref(words).cast()) }
}

/// Eight words of an array, from `at` on.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn load(words: &[u32], at: usize) -> __m256i {
    register(&words[at..].as_chunks::<LANES>().0[0])
}

/// Eight words into an array, from `at` on.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn store(words: &mut [u32], at: usize, lanes: __m256i) {
    let chunk: &mut [u32; LANES] = &mut words[at..].as_chunks_mut::<LANES>().0[0];
    // SAFETY: `chunk` is eight words that may be written, and this store asks for no alignment.
    unsafe { _mm256_storeu_si256(core::ptr::from_mut(chunk).cast(), lanes) }
}

/// The entry of the kernel table for the top twelve bits of each lane.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn fit(d: __m256i) -> __m256i {
    let index = _mm256_srli_epi32::<20>(d);
    // SAFETY: every index is a word shifted right by 20 bits, so below 4096, which is the
    // length of the table, and the scale is the size of its entries.
    unsafe { _mm256_i32gather_epi32::<4>(FIT.as_ptr().cast(), index) }
}

/// The lanes in which `a` is not above `b`, as unsigned words: all ones there, zero elsewhere.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn not_above(a: __m256i, b: __m256i) -> __m256i {
    _mm256_cmpeq_epi32(_mm256_min_epu32(a, b), a)
}

/// The lanes of a comparison as eight bits, lane 0 the lowest.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn bits(lanes: __m256i) -> usize {
    (_mm256_movemask_ps(_mm256_castsi256_ps(lanes)).cast_unsigned() & 0xff) as usize
}

/// The lanes of `set` at the front of the register, in their order.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx2")]
fn front(lanes: __m256i, set: usize) -> __m256i {
    _mm256_permutevar8x32_epi32(lanes, register(&FRONT[set]))
}

/// The entries of a table of 256 words that is linear in its index, for the four values of
/// each piece of two bits of the index, as tables of a byte shuffle: byte `4 * j + c` of the
/// table of piece `m` is byte `j` of the entry for `c << (2 * m)`. Eight words are the table
/// twice, since a shuffle works in each half of a register by itself.
const fn pieces(table: &[u32; 256]) -> [[u32; LANES]; 4] {
    let mut out = [[0_u32; LANES]; 4];
    let mut piece = 0;
    while piece < 4 {
        let mut byte = 0;
        while byte < 4 {
            let mut word = 0;
            let mut value = 0;
            while value < 4 {
                word |= ((table[value << (2 * piece)] >> (8 * byte)) & 0xff) << (8 * value);
                value += 1;
            }
            out[piece][byte] = word;
            out[piece][byte + 4] = word;
            byte += 1;
        }
        piece += 1;
    }
    out
}

/// The pieces of the CRC table and of its inverse.
static CRC_PIECES: [[u32; LANES]; 4] = pieces(&CRC);
static CRC_INV_PIECES: [[u32; LANES]; 4] = pieces(&CRC_INV);

/// What is the same for every block of one search.
struct Constants {
    /// The CRC table and its inverse, as the tables of [`pieces`].
    crc: [__m256i; 4],
    crc_inv: [__m256i; 4],
    /// The shuffles that put the low byte of each lane, and its top byte, into all four of
    /// its bytes.
    low_to_all: __m256i,
    top_to_all: __m256i,
    /// The two low bits of every byte, and the place of each byte in its lane times four.
    piece: __m256i,
    place: __m256i,
    inv: __m256i,
    one: __m256i,
    low_byte: __m256i,
    max_24: __m256i,
    max_26: __m256i,
    lane: __m256i,
}

impl Constants {
    /// The constants, each in every lane of a register.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[target_feature(enable = "avx2")]
    fn new() -> Self {
        Self {
            crc: [register(&CRC_PIECES[0]), register(&CRC_PIECES[1]), register(&CRC_PIECES[2]), register(&CRC_PIECES[3])],
            crc_inv: [register(&CRC_INV_PIECES[0]), register(&CRC_INV_PIECES[1]), register(&CRC_INV_PIECES[2]), register(&CRC_INV_PIECES[3])],
            low_to_all: register(&[0x0000_0000, 0x0404_0404, 0x0808_0808, 0x0c0c_0c0c, 0x0000_0000, 0x0404_0404, 0x0808_0808, 0x0c0c_0c0c]),
            top_to_all: register(&[0x0303_0303, 0x0707_0707, 0x0b0b_0b0b, 0x0f0f_0f0f, 0x0303_0303, 0x0707_0707, 0x0b0b_0b0b, 0x0f0f_0f0f]),
            piece: splat(0x0303_0303),
            place: splat(0x0c08_0400),
            inv: splat(MULT_INV),
            one: splat(1),
            low_byte: splat(0xff),
            max_24: splat(MAX_DIFF_24),
            max_26: splat(MAX_DIFF_26),
            lane: _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7),
        }
    }

    /// The lanes of the first `left` lists, eight at most: all ones there, zero elsewhere.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn live(&self, left: usize) -> __m256i {
        _mm256_cmpgt_epi32(splat(u32::try_from(left).map_or(STEP, |left| left.min(STEP))), self.lane)
    }

    /// The entry of a table for the byte that stands in all four bytes of each lane, from
    /// the tables of its pieces.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn entry(&self, index: __m256i, tables: &[__m256i; 4]) -> __m256i {
        // the two bits of a piece, in every byte, with the place of the byte above them
        let at = |shifted: __m256i| _mm256_or_si256(_mm256_and_si256(shifted, self.piece), self.place);
        let low = _mm256_xor_si256(_mm256_shuffle_epi8(tables[0], at(index)), _mm256_shuffle_epi8(tables[1], at(_mm256_srli_epi32::<2>(index))));
        let high = _mm256_xor_si256(_mm256_shuffle_epi8(tables[2], at(_mm256_srli_epi32::<4>(index))), _mm256_shuffle_epi8(tables[3], at(_mm256_srli_epi32::<6>(index))));
        _mm256_xor_si256(low, high)
    }

    /// The entry of the CRC table for the low byte of each lane exclusive-or `byte`.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn crc_entry(&self, x: __m256i, byte: u8) -> __m256i {
        self.entry(_mm256_shuffle_epi8(_mm256_xor_si256(x, splat(u32::from(byte))), self.low_to_all), &self.crc)
    }

    /// One CRC step undone in each lane, for the byte `byte`.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[inline]
    #[target_feature(enable = "avx2")]
    fn crc_back(&self, x: __m256i, byte: u8) -> __m256i {
        let entry = self.entry(_mm256_shuffle_epi8(x, self.top_to_all), &self.crc_inv);
        _mm256_xor_si256(_mm256_xor_si256(_mm256_slli_epi32::<8>(x), entry), splat(u32::from(byte)))
    }
}

///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[target_feature(enable = "avx2,popcnt")]
pub(super) fn search(window: &Window, z7: u32, scratch: &mut Scratch, hits: &mut Vec<Hit>) -> u64 {
    let constants = Constants::new();
    let Scratch { lists, stack } = scratch;
    let mut count = 0;
    z_lists(window, z7, stack, |z, tops| {
        let mut first = 0;
        while first < 1 << 16 {
            count += block(&constants, window, (z, tops), first, lists, hits);
            first += BLOCK;
        }
    });
    count
}

/// One block, as the scalar kernel does it, eight lists at a time.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[target_feature(enable = "avx2,popcnt")]
fn block(c: &Constants, window: &Window, (z, tops): (&[u32; 8], &[u32; 8]), first: u32, lists: &mut Lists, hits: &mut Vec<Hit>) -> u64 {
    let [y_in, y_out] = &mut lists.y;
    let [x_in, x_out] = &mut lists.x;
    let [origin_in, origin_out] = &mut lists.origin;

    // the first level: every second key at place 7 whose predecessor has the top byte of place 6
    let top = splat(tops[7]);
    let base = (MULT_INV.wrapping_mul(tops[7] >> 24) << 24).wrapping_sub(MULT_INV);
    let step = _mm256_mullo_epi32(c.lane, splat(MULT_INV << 8));
    let wanted = splat(tops[6].wrapping_add(MAX_DIFF_24));
    let mut n = 0;
    let mut middle = first;
    while middle < first + BLOCK {
        let product = _mm256_add_epi32(splat(base.wrapping_add((MULT_INV << 8).wrapping_mul(middle))), step);
        let d = _mm256_sub_epi32(wanted, product);
        let mut entry = fit(d);
        // how many bytes the entry holds: none, one or two
        let held = _mm256_srli_epi32::<16>(entry);
        let middles = _mm256_slli_epi32::<8>(_mm256_add_epi32(splat(middle), c.lane));
        for slot in 0..2 {
            let have = _mm256_cmpgt_epi32(held, splat(slot));
            if bits(have) == 0 {
                break;
            }
            let byte = _mm256_and_si256(entry, c.low_byte);
            let fits = bits(_mm256_and_si256(have, not_above(_mm256_sub_epi32(d, _mm256_mullo_epi32(byte, c.inv)), c.max_24)));
            store(y_in, n, front(_mm256_or_si256(_mm256_or_si256(top, middles), byte), fits));
            n += fits.count_ones() as usize;
            entry = _mm256_srli_epi32::<8>(entry);
        }
        middle += STEP;
    }
    origin_in[..n].copy_from_slice(&y_in[..n]);
    x_in[..n].fill(0);

    // places 7 to 4: the second key one place back, and the low byte of the first key
    for place in (4..=7).rev() {
        let known = splat(tops[place - 2]);
        let top_before = splat(tops[place - 1] >> 24);
        let mut out = 0;
        let mut list = 0;
        while list < n {
            let live = c.live(n - list);
            let bytes = _mm256_slli_epi32::<8>(load(x_in, list));
            let origin = load(origin_in, list);
            let fy = _mm256_mullo_epi32(_mm256_sub_epi32(load(y_in, list), c.one), c.inv);
            let d = _mm256_sub_epi32(_mm256_mullo_epi32(_mm256_sub_epi32(fy, c.one), c.inv), known);
            let mut entry = fit(d);
            let held = _mm256_srli_epi32::<16>(entry);
            for slot in 0..2 {
                let have = _mm256_and_si256(live, _mm256_cmpgt_epi32(held, splat(slot)));
                if bits(have) == 0 {
                    break;
                }
                let byte = _mm256_and_si256(entry, c.low_byte);
                let before = _mm256_sub_epi32(fy, byte);
                let fits = _mm256_and_si256(have, not_above(_mm256_sub_epi32(d, _mm256_mullo_epi32(byte, c.inv)), c.max_24));
                let keep = bits(_mm256_and_si256(fits, _mm256_cmpeq_epi32(_mm256_srli_epi32::<24>(before), top_before)));
                store(y_out, out, front(before, keep));
                store(x_out, out, front(_mm256_or_si256(bytes, byte), keep));
                store(origin_out, out, front(origin, keep));
                out += keep.count_ones() as usize;
                entry = _mm256_srli_epi32::<8>(entry);
            }
            list += LANES;
        }
        core::mem::swap(y_in, y_out);
        core::mem::swap(x_in, x_out);
        core::mem::swap(origin_in, origin_out);
        n = out;
    }

    // the first key from its four low bytes, and the test against six bits of the second
    let plain = &window.plain;
    let known = splat(tops[1] & mask(26, 32));
    let high = splat(mask(8, 32));
    let mut list = 0;
    while list < n {
        let bytes = load(x_in, list);
        let y3 = load(y_in, list);
        let b4 = _mm256_and_si256(bytes, c.low_byte);
        let b5 = _mm256_and_si256(_mm256_srli_epi32::<8>(bytes), c.low_byte);
        let b6 = _mm256_and_si256(_mm256_srli_epi32::<16>(bytes), c.low_byte);
        let b7 = _mm256_srli_epi32::<24>(bytes);
        let x5 = _mm256_or_si256(_mm256_and_si256(c.crc_entry(b4, plain[4]), high), b5);
        let x6 = _mm256_or_si256(_mm256_and_si256(_mm256_xor_si256(_mm256_srli_epi32::<8>(x5), c.crc_entry(x5, plain[5])), high), b6);
        let x7 = _mm256_or_si256(_mm256_and_si256(_mm256_xor_si256(_mm256_srli_epi32::<8>(x6), c.crc_entry(x6, plain[6])), high), b7);
        let mut x3 = x7;
        for place in (3..=6).rev() {
            x3 = c.crc_back(x3, plain[place]);
        }
        let y2 = _mm256_sub_epi32(_mm256_mullo_epi32(_mm256_sub_epi32(y3, c.one), c.inv), _mm256_and_si256(x3, c.low_byte));
        let difference = _mm256_sub_epi32(_mm256_mullo_epi32(_mm256_sub_epi32(y2, c.one), c.inv), known);
        let mut passed = bits(_mm256_and_si256(c.live(n - list), not_above(difference, c.max_26)));
        if passed != 0 {
            let (mut at_7, mut at_3) = ([0_u32; LANES], [0_u32; LANES]);
            store(&mut at_7, 0, x7);
            store(&mut at_3, 0, x3);
            while passed != 0 {
                let lane = passed.trailing_zeros() as usize;
                passed &= passed - 1;
                finish(window, Keys::new(at_7[lane], origin_in[list + lane], z[7]), Keys::new(at_3[lane], y_in[list + lane], z[3]), hits);
            }
        }
        list += LANES;
    }
    n as u64
}
