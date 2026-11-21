//! The vector kernel: the flat loops of the scalar kernel, sixteen lists at a time.
//!
//! A level is two multiplications, one lookup, two comparisons and a compress of the lists
//! that are left, the same for every list, so sixteen are done in one register. The lookup is
//! a gather from the table of the kernel. The CRC steps of the last test have no table: a
//! step is linear, so the entry for a byte is the exclusive-or of the entries for its bits.
//!
//! The functions here are compiled for a processor with AVX-512 and are safe to call from
//! each other. Unsafe code is in three places: where sixteen words are read from an array,
//! where they are written to one, and where the table is gathered from.

use core::arch::x86_64::__m512i;
use core::arch::x86_64::__mmask16;
use core::arch::x86_64::_mm512_add_epi32;
use core::arch::x86_64::_mm512_and_epi32;
use core::arch::x86_64::_mm512_cmpgt_epu32_mask;
use core::arch::x86_64::_mm512_i32gather_epi32;
use core::arch::x86_64::_mm512_loadu_si512;
use core::arch::x86_64::_mm512_mask_cmpeq_epi32_mask;
use core::arch::x86_64::_mm512_mask_cmpgt_epu32_mask;
use core::arch::x86_64::_mm512_mask_cmple_epu32_mask;
use core::arch::x86_64::_mm512_mask_xor_epi32;
use core::arch::x86_64::_mm512_maskz_compress_epi32;
use core::arch::x86_64::_mm512_mullo_epi32;
use core::arch::x86_64::_mm512_or_epi32;
use core::arch::x86_64::_mm512_set1_epi32;
use core::arch::x86_64::_mm512_setr_epi32;
use core::arch::x86_64::_mm512_setzero_si512;
use core::arch::x86_64::_mm512_slli_epi32;
use core::arch::x86_64::_mm512_srli_epi32;
use core::arch::x86_64::_mm512_storeu_si512;
use core::arch::x86_64::_mm512_sub_epi32;
use core::arch::x86_64::_mm512_test_epi32_mask;
use core::arch::x86_64::_mm512_xor_epi32;

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

/// The gather below takes its index from the top twelve bits of a word.
const _: () = assert!(FIT_BITS == 12 && FIT.len() == 1 << 12);

/// The same word in every lane.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx512f")]
fn splat(word: u32) -> __m512i {
    _mm512_set1_epi32(word.cast_signed())
}

/// Sixteen words of an array, from `at` on.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx512f")]
fn load(words: &[u32], at: usize) -> __m512i {
    let chunk: &[u32; 16] = &words[at..].as_chunks::<16>().0[0];
    // SAFETY: `chunk` is sixteen words that may be read, and this load asks for no alignment.
    unsafe { _mm512_loadu_si512(core::ptr::from_ref(chunk).cast()) }
}

/// Sixteen words into an array, from `at` on.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx512f")]
fn store(words: &mut [u32], at: usize, lanes: __m512i) {
    let chunk: &mut [u32; 16] = &mut words[at..].as_chunks_mut::<16>().0[0];
    // SAFETY: `chunk` is sixteen words that may be written, and this store asks for no alignment.
    unsafe { _mm512_storeu_si512(core::ptr::from_mut(chunk).cast(), lanes) }
}

/// The entry of the kernel table for the top twelve bits of each lane.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[inline]
#[target_feature(enable = "avx512f")]
fn fit(d: __m512i) -> __m512i {
    let index = _mm512_srli_epi32::<20>(d);
    // SAFETY: every index is a word shifted right by 20 bits, so below 4096, which is the
    // length of the table, and the scale is the size of its entries.
    unsafe { _mm512_i32gather_epi32::<4>(index, FIT.as_ptr().cast()) }
}

/// The lanes of the first `left` lists, sixteen at most.
#[inline]
const fn live(left: usize) -> __mmask16 {
    if left >= 16 { 0xffff } else { (1 << left) - 1 }
}

/// What is the same for every block of one search.
struct Constants {
    /// The entry of the CRC table for each bit of a byte, and of its inverse for each bit of
    /// a top byte.
    crc: [__m512i; 8],
    crc_inv: [__m512i; 8],
    /// Each bit of a low byte, and of a top byte.
    bit: [__m512i; 8],
    top_bit: [__m512i; 8],
    inv: __m512i,
    one: __m512i,
    low_byte: __m512i,
    max_24: __m512i,
    max_26: __m512i,
    lane: __m512i,
}

impl Constants {
    /// The constants, each in every lane of a register.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[target_feature(enable = "avx512f")]
    fn new() -> Self {
        let mut constants = Self {
            crc: [_mm512_setzero_si512(); 8],
            crc_inv: [_mm512_setzero_si512(); 8],
            bit: [_mm512_setzero_si512(); 8],
            top_bit: [_mm512_setzero_si512(); 8],
            inv: splat(MULT_INV),
            one: splat(1),
            low_byte: splat(0xff),
            max_24: splat(MAX_DIFF_24),
            max_26: splat(MAX_DIFF_26),
            lane: _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        };
        for bit in 0..8 {
            constants.crc[bit] = splat(CRC[1 << bit]);
            constants.crc_inv[bit] = splat(CRC_INV[1 << bit]);
            constants.bit[bit] = splat(1 << bit);
            constants.top_bit[bit] = splat(1 << (24 + bit));
        }
        constants
    }

    /// The entry of the CRC table for the low byte of each lane exclusive-or `byte`.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn crc_entry(&self, x: __m512i, byte: u8) -> __m512i {
        let index = _mm512_xor_epi32(x, splat(u32::from(byte)));
        let mut entry = _mm512_setzero_si512();
        for bit in 0..8 {
            entry = _mm512_mask_xor_epi32(entry, _mm512_test_epi32_mask(index, self.bit[bit]), entry, self.crc[bit]);
        }
        entry
    }

    /// One CRC step undone in each lane, for the byte `byte`.
    ///
    /// # Safety
    ///
    /// The processor has to have the features this function is compiled for. A function that is
    /// compiled for them calls it as a safe one.
    #[inline]
    #[target_feature(enable = "avx512f")]
    fn crc_back(&self, x: __m512i, byte: u8) -> __m512i {
        let mut entry = _mm512_setzero_si512();
        for bit in 0..8 {
            entry = _mm512_mask_xor_epi32(entry, _mm512_test_epi32_mask(x, self.top_bit[bit]), entry, self.crc_inv[bit]);
        }
        _mm512_xor_epi32(_mm512_xor_epi32(_mm512_slli_epi32::<8>(x), entry), splat(u32::from(byte)))
    }
}

///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[target_feature(enable = "avx512f,avx512bw,avx512dq,avx512vl,bmi2,popcnt")]
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

/// One block, as the scalar kernel does it, sixteen lists at a time.
///
/// # Safety
///
/// The processor has to have the features this function is compiled for. A function that is
/// compiled for them calls it as a safe one.
#[target_feature(enable = "avx512f,avx512bw,avx512dq,avx512vl,bmi2,popcnt")]
fn block(c: &Constants, window: &Window, (z, tops): (&[u32; 8], &[u32; 8]), first: u32, lists: &mut Lists, hits: &mut Vec<Hit>) -> u64 {
    let [y_in, y_out] = &mut lists.y;
    let [x_in, x_out] = &mut lists.x;
    let [origin_in, origin_out] = &mut lists.origin;

    // the first level: every second key at place 7 whose predecessor has the top byte of place 6
    let top = splat(tops[7]);
    let base = (MULT_INV.wrapping_mul(tops[7] >> 24) << 24).wrapping_sub(MULT_INV);
    let step = _mm512_mullo_epi32(c.lane, splat(MULT_INV << 8));
    let wanted = splat(tops[6].wrapping_add(MAX_DIFF_24));
    let mut n = 0;
    let mut middle = first;
    while middle < first + BLOCK {
        let product = _mm512_add_epi32(splat(base.wrapping_add((MULT_INV << 8).wrapping_mul(middle))), step);
        let d = _mm512_sub_epi32(wanted, product);
        let mut entry = fit(d);
        let held = _mm512_srli_epi32::<16>(entry);
        let middles = _mm512_slli_epi32::<8>(_mm512_add_epi32(splat(middle), c.lane));
        for slot in 0..2 {
            let have = _mm512_cmpgt_epu32_mask(held, splat(slot));
            if have == 0 {
                break;
            }
            let byte = _mm512_and_epi32(entry, c.low_byte);
            let fits = _mm512_mask_cmple_epu32_mask(have, _mm512_sub_epi32(d, _mm512_mullo_epi32(byte, c.inv)), c.max_24);
            store(y_in, n, _mm512_maskz_compress_epi32(fits, _mm512_or_epi32(_mm512_or_epi32(top, middles), byte)));
            n += fits.count_ones() as usize;
            entry = _mm512_srli_epi32::<8>(entry);
        }
        middle += 16;
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
            let bytes = _mm512_slli_epi32::<8>(load(x_in, list));
            let origin = load(origin_in, list);
            let fy = _mm512_mullo_epi32(_mm512_sub_epi32(load(y_in, list), c.one), c.inv);
            let d = _mm512_sub_epi32(_mm512_mullo_epi32(_mm512_sub_epi32(fy, c.one), c.inv), known);
            let mut entry = fit(d);
            let held = _mm512_srli_epi32::<16>(entry);
            for slot in 0..2 {
                let have = _mm512_mask_cmpgt_epu32_mask(live(n - list), held, splat(slot));
                if have == 0 {
                    break;
                }
                let byte = _mm512_and_epi32(entry, c.low_byte);
                let before = _mm512_sub_epi32(fy, byte);
                let fits = _mm512_mask_cmple_epu32_mask(have, _mm512_sub_epi32(d, _mm512_mullo_epi32(byte, c.inv)), c.max_24);
                let keep = _mm512_mask_cmpeq_epi32_mask(fits, _mm512_srli_epi32::<24>(before), top_before);
                store(y_out, out, _mm512_maskz_compress_epi32(keep, before));
                store(x_out, out, _mm512_maskz_compress_epi32(keep, _mm512_or_epi32(bytes, byte)));
                store(origin_out, out, _mm512_maskz_compress_epi32(keep, origin));
                out += keep.count_ones() as usize;
                entry = _mm512_srli_epi32::<8>(entry);
            }
            list += 16;
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
        let b4 = _mm512_and_epi32(bytes, c.low_byte);
        let b5 = _mm512_and_epi32(_mm512_srli_epi32::<8>(bytes), c.low_byte);
        let b6 = _mm512_and_epi32(_mm512_srli_epi32::<16>(bytes), c.low_byte);
        let b7 = _mm512_srli_epi32::<24>(bytes);
        let x5 = _mm512_or_epi32(_mm512_and_epi32(c.crc_entry(b4, plain[4]), high), b5);
        let x6 = _mm512_or_epi32(_mm512_and_epi32(_mm512_xor_epi32(_mm512_srli_epi32::<8>(x5), c.crc_entry(x5, plain[5])), high), b6);
        let x7 = _mm512_or_epi32(_mm512_and_epi32(_mm512_xor_epi32(_mm512_srli_epi32::<8>(x6), c.crc_entry(x6, plain[6])), high), b7);
        let mut x3 = x7;
        for place in (3..=6).rev() {
            x3 = c.crc_back(x3, plain[place]);
        }
        let y2 = _mm512_sub_epi32(_mm512_mullo_epi32(_mm512_sub_epi32(y3, c.one), c.inv), _mm512_and_epi32(x3, c.low_byte));
        let difference = _mm512_sub_epi32(_mm512_mullo_epi32(_mm512_sub_epi32(y2, c.one), c.inv), known);
        let mut passed = _mm512_mask_cmple_epu32_mask(live(n - list), difference, c.max_26);
        if passed != 0 {
            let (mut at_7, mut at_3) = ([0_u32; 16], [0_u32; 16]);
            store(&mut at_7, 0, x7);
            store(&mut at_3, 0, x3);
            while passed != 0 {
                let lane = passed.trailing_zeros() as usize;
                passed &= passed - 1;
                finish(window, Keys::new(at_7[lane], origin_in[list + lane], z[7]), Keys::new(at_3[lane], y_in[list + lane], z[3]), hits);
            }
        }
        list += 16;
    }
    n as u64
}
