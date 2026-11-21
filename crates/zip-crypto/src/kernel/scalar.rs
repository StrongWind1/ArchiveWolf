//! The scalar kernel: the search as flat loops over arrays, a block of lists at a time.
//!
//! Each level reads the array of partial lists of the level above and writes its own. The
//! question of a level, which byte makes a product fall in a window, is answered by one
//! lookup in the table of the kernel and one exact test for each byte it holds.

use super::BLOCK;
use super::Hit;
use super::Lists;
use super::Scratch;
use super::Window;
use super::finish;
use super::z_lists;
use crate::Keys;
use crate::tables::FIT;
use crate::tables::FIT_BITS;
use crate::tables::MAX_DIFF_24;
use crate::tables::MAX_DIFF_26;
use crate::tables::MULT_INV;
use crate::tables::PRODUCT;
use crate::tables::crc32;
use crate::tables::crc32_inv;
use crate::tables::mask;

pub(super) fn search(window: &Window, z7: u32, scratch: &mut Scratch, hits: &mut Vec<Hit>) -> u64 {
    let Scratch { lists, stack } = scratch;
    let mut count = 0;
    z_lists(window, z7, stack, |z, tops| {
        let mut first = 0;
        while first < 1 << 16 {
            count += block(window, z, tops, first, lists, hits);
            first += BLOCK;
        }
    });
    count
}

/// One block: the values `first` to `first + BLOCK - 1` of the middle of the second key at
/// place 7, through all levels and the test of the first key. Returns its count of lists.
fn block(window: &Window, z: &[u32; 8], tops: &[u32; 8], first: u32, lists: &mut Lists, hits: &mut Vec<Hit>) -> u64 {
    let shift = 32 - FIT_BITS;
    let [y_in, y_out] = &mut lists.y;
    let [x_in, x_out] = &mut lists.x;
    let [origin_in, origin_out] = &mut lists.origin;

    // the first level: every second key at place 7 whose predecessor has the top byte of place 6
    let top = tops[7];
    let base = (MULT_INV.wrapping_mul(top >> 24) << 24).wrapping_sub(MULT_INV);
    let mut n = 0;
    for middle in first..first + BLOCK {
        let product = base.wrapping_add((MULT_INV << 8).wrapping_mul(middle));
        // the product of the byte has to lie in `d - MAX_DIFF_24..=d`
        let d = tops[6].wrapping_sub(product).wrapping_add(MAX_DIFF_24);
        let entry = FIT[(d >> shift) as usize];
        for slot in 0..entry >> 16 {
            let byte = (entry >> (8 * slot)) & 0xff;
            if d.wrapping_sub(PRODUCT[byte as usize]) <= MAX_DIFF_24 {
                let value = top | (middle << 8) | byte;
                y_in[n] = value;
                origin_in[n] = value;
                x_in[n] = 0;
                n += 1;
            }
        }
    }

    // places 7 to 4: the second key one place back, and the low byte of the first key
    for place in (4..=7).rev() {
        let (known, top_before) = (tops[place - 2], tops[place - 1] >> 24);
        let mut out = 0;
        for list in 0..n {
            let fy = y_in[list].wrapping_sub(1).wrapping_mul(MULT_INV);
            let d = fy.wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(known);
            let entry = FIT[(d >> shift) as usize];
            for slot in 0..entry >> 16 {
                let byte = (entry >> (8 * slot)) & 0xff;
                let before = fy.wrapping_sub(byte);
                if d.wrapping_sub(PRODUCT[byte as usize]) <= MAX_DIFF_24 && before >> 24 == top_before {
                    y_out[out] = before;
                    x_out[out] = (x_in[list] << 8) | byte;
                    origin_out[out] = origin_in[list];
                    out += 1;
                }
            }
        }
        core::mem::swap(y_in, y_out);
        core::mem::swap(x_in, x_out);
        core::mem::swap(origin_in, origin_out);
        n = out;
    }

    // the first key from its four low bytes, and the test against six bits of the second
    let plain = &window.plain;
    let known = tops[1] & mask(26, 32);
    for list in 0..n {
        let bytes = x_in[list];
        let x5 = (crc32(bytes & 0xff, plain[4]) & mask(8, 32)) | ((bytes >> 8) & 0xff);
        let x6 = (crc32(x5, plain[5]) & mask(8, 32)) | ((bytes >> 16) & 0xff);
        let x7 = (crc32(x6, plain[6]) & mask(8, 32)) | (bytes >> 24);
        let mut x3 = x7;
        for place in (3..=6).rev() {
            x3 = crc32_inv(x3, plain[place]);
        }
        let y3 = y_in[list];
        if y3.wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(x3 & 0xff).wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(known) <= MAX_DIFF_26 {
            finish(window, Keys::new(x7, origin_in[list], z[7]), Keys::new(x3, y3, z[3]), hits);
        }
    }
    n as u64
}
