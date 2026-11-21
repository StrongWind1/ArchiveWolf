//! The reference kernel: the search of bkcrack as it is written there, one list at a time.
//!
//! This file is a port of parts of bkcrack-rs by Zach Shallbetter
//! (<https://github.com/zachshallbetter/bkcrack-rs>), which is a port to Rust of bkcrack by
//! Joachim Hotonnier (<https://github.com/kimci86/bkcrack>). It is an altered version and is
//! not the original software. That work is under the zlib licence, and so is what is taken
//! from it here: the notice and the full text are in `LICENSE-BKCRACK.txt`.

use super::Hit;
use super::Window;
use super::finish;
use super::z_lists;
use crate::Keys;
use crate::reduce::WINDOW;
use crate::tables::MAX_DIFF_24;
use crate::tables::MAX_DIFF_26;
use crate::tables::MULT_INV;
use crate::tables::crc32;
use crate::tables::crc32_inv;
use crate::tables::fiber2;
use crate::tables::fiber3;
use crate::tables::lsb;
use crate::tables::mask;
use crate::tables::msb;

/// One list of each key, as far as it is known.
struct Lists<'a> {
    window: &'a Window,
    z: [u32; WINDOW],
    y: [u32; WINDOW],
    x: [u32; WINDOW],
    count: u64,
    hits: &'a mut Vec<Hit>,
}

pub(super) fn search(window: &Window, z7: u32, hits: &mut Vec<Hit>) -> u64 {
    let mut stack = Vec::with_capacity(64);
    let mut count = 0;
    z_lists(window, z7, &mut stack, |z, tops| {
        let mut lists = Lists { window, z: *z, y: *tops, x: [0; WINDOW], count: 0, hits };
        lists.second_key();
        count += lists.count;
    });
    count
}

impl Lists<'_> {
    /// Every value of the second key at place 7 whose predecessor has the top byte of place 6.
    fn second_key(&mut self) {
        let top = self.y[7] & mask(24, 32);
        let mut product = (MULT_INV.wrapping_mul(u32::from(msb(top))) << 24).wrapping_sub(MULT_INV);
        let mut middle = 0_u32;
        while middle < 1 << 24 {
            let target = msb(self.y[6]).wrapping_sub(msb(product));
            for &low in fiber3(target) {
                if product.wrapping_add(MULT_INV.wrapping_mul(u32::from(low))).wrapping_sub(self.y[6] & mask(24, 32)) <= MAX_DIFF_24 {
                    self.y[7] = u32::from(low) | middle | top;
                    self.back(7);
                }
            }
            middle += 1 << 8;
            product = product.wrapping_add(MULT_INV << 8);
        }
    }

    /// One place back: the second key before place `i`, and the low byte of the first key there.
    fn back(&mut self, i: usize) {
        if i == 3 {
            self.count += 1;
            self.first_key();
            return;
        }
        let fy = self.y[i].wrapping_sub(1).wrapping_mul(MULT_INV);
        let ffy = fy.wrapping_sub(1).wrapping_mul(MULT_INV);
        let known = self.y[i - 2] & mask(24, 32);
        for &x in fiber2(msb(ffy.wrapping_sub(known))) {
            let before = fy.wrapping_sub(u32::from(x));
            if ffy.wrapping_sub(MULT_INV.wrapping_mul(u32::from(x))).wrapping_sub(known) <= MAX_DIFF_24 && msb(before) == msb(self.y[i - 1]) {
                self.y[i - 1] = before;
                self.x[i] = u32::from(x);
                self.back(i - 1);
            }
        }
    }

    /// The first key from its four low bytes, and the test against six bits of the second.
    fn first_key(&mut self) {
        let plain = &self.window.plain;
        for i in 5..=7 {
            self.x[i] = (crc32(self.x[i - 1], plain[i - 1]) & mask(8, 32)) | u32::from(lsb(self.x[i]));
        }
        let mut x = self.x[7];
        for i in (3..=6).rev() {
            x = crc32_inv(x, plain[i]);
        }
        // the top byte of place 1 is known in six of its bits: the third key at place 0 lacks two
        let known = self.y[1] & mask(26, 32);
        if self.y[3].wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(u32::from(lsb(x))).wrapping_sub(1).wrapping_mul(MULT_INV).wrapping_sub(known) > MAX_DIFF_26 {
            return;
        }
        finish(self.window, Keys::new(self.x[7], self.y[7], self.z[7]), Keys::new(x, self.y[3], self.z[3]), self.hits);
    }
}
