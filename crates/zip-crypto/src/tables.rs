//! The tables of the cipher and of the search, all built when the crate is compiled.
//!
//! This file is a port of parts of bkcrack-rs by Zach Shallbetter
//! (<https://github.com/zachshallbetter/bkcrack-rs>), which is a port to Rust of bkcrack by
//! Joachim Hotonnier (<https://github.com/kimci86/bkcrack>). It is an altered version and is
//! not the original software. That work is under the zlib licence, and so is what is taken
//! from it here: the notice and the full text are in `LICENSE-BKCRACK.txt`.

/// The multiplier of the second key.
pub const MULT: u32 = 0x0808_8405;
/// Its inverse modulo 2^32.
pub const MULT_INV: u32 = 0xd94f_a8cd;

const _: () = assert!(MULT.wrapping_mul(MULT_INV) == 1);

/// The polynomial of the CRC-32, reflected.
const POLYNOMIAL: u32 = 0xedb8_8320;

/// The largest difference a product may have from the value it is held against when 24 bits
/// of it are unknown: the unknown bits, and the byte that is added on the way.
pub(crate) const MAX_DIFF_24: u32 = mask(0, 24) + 0xff;
/// The same when 26 bits are unknown.
pub(crate) const MAX_DIFF_26: u32 = mask(0, 26) + 0xff;

/// A word with the bits `begin` to `end - 1` set.
#[must_use]
pub(crate) const fn mask(begin: u32, end: u32) -> u32 {
    (u32::MAX << begin) & (u32::MAX >> (32 - end))
}

/// The low byte of a word.
#[must_use]
pub(crate) const fn lsb(x: u32) -> u8 {
    x.to_le_bytes()[0]
}

/// The top byte of a word.
#[must_use]
pub(crate) const fn msb(x: u32) -> u8 {
    x.to_le_bytes()[3]
}

const fn crc_tables() -> ([u32; 256], [u32; 256]) {
    let mut forward = [0_u32; 256];
    let mut inverse = [0_u32; 256];
    let mut byte = 0_u32;
    while byte < 256 {
        let mut crc = byte;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 0 { crc >> 1 } else { (crc >> 1) ^ POLYNOMIAL };
            bit += 1;
        }
        forward[byte as usize] = crc;
        inverse[(crc >> 24) as usize] = (crc << 8) ^ byte;
        byte += 1;
    }
    (forward, inverse)
}

/// One step of the CRC-32 for each byte, and what undoes it for each top byte.
pub(crate) static CRC: [u32; 256] = crc_tables().0;
pub(crate) static CRC_INV: [u32; 256] = crc_tables().1;

/// One step of the CRC-32: `x` after the byte `b`.
#[inline]
#[must_use]
pub const fn crc32(x: u32, b: u8) -> u32 {
    (x >> 8) ^ CRC[(lsb(x) ^ b) as usize]
}

/// The step undone: `crc32_inv(crc32(x, b), b) == x`.
#[inline]
#[must_use]
pub const fn crc32_inv(x: u32, b: u8) -> u32 {
    (x << 8) ^ CRC_INV[msb(x) as usize] ^ b as u32
}

/// The stream byte that the third key `z` gives. Only its bits 2 to 15 count.
#[inline]
#[must_use]
pub const fn stream_byte(z: u32) -> u8 {
    STREAM[((z & mask(2, 16)) >> 2) as usize]
}

const fn stream_of(z_2_16: u32) -> u8 {
    lsb((z_2_16 | 2).wrapping_mul(z_2_16 | 3) >> 8)
}

const fn stream_table() -> [u8; 1 << 14] {
    let mut table = [0_u8; 1 << 14];
    let mut index = 0_u32;
    while index < 1 << 14 {
        table[index as usize] = stream_of(index << 2);
        index += 1;
    }
    table
}

/// The stream byte for each value of bits 2 to 15 of the third key.
static STREAM: [u8; 1 << 14] = stream_table();

/// For a stream byte and bits 10 to 15 of the third key, the values of its bits 2 to 15 that
/// give the byte: `Z_LOW.1[Z_LOW.0[k * 64 + g]..Z_LOW.0[k * 64 + g + 1]]`, about one each.
static Z_LOW: ([u16; 256 * 64 + 1], [u16; 1 << 14]) = {
    let mut offsets = [0_u16; 256 * 64 + 1];
    let mut values = [0_u16; 1 << 14];
    // how many values each bucket holds, one place up, then where each bucket starts
    let mut index = 0_u32;
    while index < 1 << 14 {
        let z = index << 2;
        offsets[stream_of(z) as usize * 64 + (z >> 10) as usize + 1] += 1;
        index += 1;
    }
    let mut bucket = 0;
    while bucket < 256 * 64 {
        offsets[bucket + 1] += offsets[bucket];
        bucket += 1;
    }
    let mut filled = [0_u16; 256 * 64];
    index = 0;
    while index < 1 << 14 {
        let z = index << 2;
        let bucket = stream_of(z) as usize * 64 + (z >> 10) as usize;
        values[(offsets[bucket] + filled[bucket]) as usize] = (z & 0xffff) as u16;
        filled[bucket] += 1;
        index += 1;
    }
    (offsets, values)
};

/// The values of bits 2 to 15 of a third key that give the stream byte `k`, when its bits 10
/// to 15 are those of `z`.
#[inline]
#[must_use]
pub(crate) fn z_low(k: u8, z: u32) -> &'static [u16] {
    let bucket = usize::from(k) * 64 + ((z >> 10) & 63) as usize;
    &Z_LOW.1[usize::from(Z_LOW.0[bucket])..usize::from(Z_LOW.0[bucket + 1])]
}

/// Whether any value of bits 2 to 15 gives the stream byte `k` with bits 10 to 15 of `z`.
#[inline]
#[must_use]
pub(crate) fn has_z_low(k: u8, z: u32) -> bool {
    let bucket = usize::from(k) * 64 + ((z >> 10) & 63) as usize;
    Z_LOW.0[bucket] != Z_LOW.0[bucket + 1]
}

/// The top byte of the second key at a position, from the third key there and the one before.
#[inline]
#[must_use]
pub(crate) const fn y_top(z: u32, z_before: u32) -> u32 {
    (crc32_inv(z, 0) ^ z_before) << 24
}

/// Bits 10 to 31 of the third key one position back.
#[inline]
#[must_use]
pub(crate) const fn z_before_10_32(z_2_32: u32) -> u32 {
    crc32_inv(z_2_32, 0) & mask(10, 32)
}

/// The product of the inverse multiplier with each byte.
const fn products() -> [u32; 256] {
    let mut table = [0_u32; 256];
    let mut x = 0_u32;
    while x < 256 {
        table[x as usize] = MULT_INV.wrapping_mul(x);
        x += 1;
    }
    table
}

pub(crate) static PRODUCT: [u32; 256] = products();

/// For each top byte of a product with the inverse multiplier, the bytes whose product has
/// that top byte or one of its `width - 1` neighbours below: the lookups of the reference
/// kernel, as lists with their offsets.
const fn fibers<const N: usize>(width: usize) -> ([u16; 257], [u8; N]) {
    let products = products();
    let mut offsets = [0_u16; 257];
    let mut values = [0_u8; N];
    // a byte whose product has the top byte m is listed under m - (width - 2) to m + 1
    let mut x = 0;
    while x < 256 {
        let m = msb(products[x]) as usize;
        let mut step = 0;
        while step < width {
            offsets[(m + 256 + 1 - step) % 256 + 1] += 1;
            step += 1;
        }
        x += 1;
    }
    let mut target = 0;
    while target < 256 {
        offsets[target + 1] += offsets[target];
        target += 1;
    }
    let mut filled = [0_u16; 256];
    x = 0;
    while x < 256 {
        let m = msb(products[x]) as usize;
        // in the order bkcrack fills its vectors: the lowest target first
        let mut step = width;
        while step > 0 {
            step -= 1;
            let target = (m + 256 + 1 - step) % 256;
            values[(offsets[target] + filled[target]) as usize] = x.to_le_bytes()[0];
            filled[target] += 1;
        }
        x += 1;
    }
    (offsets, values)
}

static FIBER2: ([u16; 257], [u8; 512]) = fibers(2);
static FIBER3: ([u16; 257], [u8; 768]) = fibers(3);

/// The bytes whose product with the inverse multiplier has the top byte `target` or the one
/// below it.
#[inline]
#[must_use]
pub(crate) fn fiber2(target: u8) -> &'static [u8] {
    let target = usize::from(target);
    &FIBER2.1[usize::from(FIBER2.0[target])..usize::from(FIBER2.0[target + 1])]
}

/// The same with the top byte above `target` as well.
#[inline]
#[must_use]
pub(crate) fn fiber3(target: u8) -> &'static [u8] {
    let target = usize::from(target);
    &FIBER3.1[usize::from(FIBER3.0[target])..usize::from(FIBER3.0[target + 1])]
}

/// How many bits of a difference index the table of the fast kernels.
pub(crate) const FIT_BITS: u32 = 12;

/// The one table of the fast kernels. The question at every level of the search is which
/// byte `x` puts `d - MULT_INV * x` in the window `0..=MAX_DIFF_24`. The table is indexed by
/// the top [`FIT_BITS`] bits of `d` and holds every byte that fits some `d` of that bucket:
/// the first in bits 0 to 7, the second in bits 8 to 15, and how many in bits 16 and 17.
///
/// A bucket never holds a third byte. That is proved for this multiplier and this window,
/// and the build fails here if it were not so:
/// a third byte would have nowhere to go, and a key would be lost without an error.
const fn fit_table() -> [u32; 1 << FIT_BITS] {
    let products = products();
    let mut table = [0_u32; 1 << FIT_BITS];
    let shift = 32 - FIT_BITS;
    let mut x = 0_u32;
    while x < 256 {
        // `d` ranges over the product to the product plus the window
        let low = products[x as usize] as u64;
        let mut bucket = low >> shift;
        let last = (low + MAX_DIFF_24 as u64) >> shift;
        while bucket <= last {
            let slot = (bucket & ((1 << FIT_BITS) - 1)) as usize;
            let count = table[slot] >> 16;
            assert!(count < 2, "a bucket of the kernel table would take a third byte");
            table[slot] = (table[slot] & 0xffff) | (x << (8 * count)) | ((count + 1) << 16);
            bucket += 1;
        }
        x += 1;
    }
    table
}

pub(crate) static FIT: [u32; 1 << FIT_BITS] = fit_table();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_crc_step_and_its_inverse_undo_each_other() {
        for state in [0_u32, 1, 0x1234_5678, 0xffff_ffff, 0xdead_beef] {
            for byte in 0..=255_u8 {
                assert_eq!(crc32_inv(crc32(state, byte), byte), state);
                assert_eq!(crc32(crc32_inv(state, byte), byte), state);
            }
        }
        assert_eq!((CRC[0], CRC[0xff]), (0, 0x2d02_ef8d));
    }

    #[test]
    fn every_third_key_is_listed_under_its_stream_byte_and_nowhere_else() {
        let mut listed = 0;
        for k in 0..=255_u8 {
            for group in 0..64_u32 {
                let values = z_low(k, group << 10);
                assert_eq!(has_z_low(k, group << 10), !values.is_empty());
                for &z in values {
                    assert_eq!(stream_byte(u32::from(z)), k);
                    assert_eq!(u32::from(z) >> 10, group);
                    assert_eq!(z & 3, 0);
                }
                listed += values.len();
            }
        }
        assert_eq!(listed, 1 << 14);
        // a stream byte fits exactly 64 values of the fourteen bits
        for k in 0..=255_u8 {
            assert_eq!((0..64_u32).map(|group| z_low(k, group << 10).len()).sum::<usize>(), 64);
        }
    }

    #[test]
    fn the_fibers_hold_the_bytes_bkcrack_looks_up() {
        for target in 0..=255_u8 {
            for &x in fiber2(target) {
                let m = msb(PRODUCT[usize::from(x)]);
                assert!(m == target || m.wrapping_add(1) == target);
            }
            for &x in fiber3(target) {
                let m = msb(PRODUCT[usize::from(x)]);
                assert!(m == target || m.wrapping_add(1) == target || m.wrapping_sub(1) == target);
            }
        }
        for x in 0..=255_u8 {
            let m = msb(PRODUCT[usize::from(x)]);
            assert!(fiber2(m).contains(&x) && fiber2(m.wrapping_add(1)).contains(&x));
            assert!(fiber3(m.wrapping_sub(1)).contains(&x) && fiber3(m).contains(&x) && fiber3(m.wrapping_add(1)).contains(&x));
        }
    }

    /// The table of the fast kernels holds every byte the exact test behind it can accept.
    #[test]
    fn the_kernel_table_holds_every_byte_that_fits() {
        let mut two = 0;
        for (bucket, &entry) in FIT.iter().enumerate() {
            let count = entry >> 16;
            assert!(count <= 2);
            two += usize::from(count == 2);
            let held = [entry & 0xff, (entry >> 8) & 0xff];
            // the ends of the bucket and a spread of values inside it
            let base = u32::try_from(bucket).unwrap() << (32 - FIT_BITS);
            for d in (0..1_u32 << (32 - FIT_BITS)).step_by(4099).chain([(1 << (32 - FIT_BITS)) - 1]).map(|low| base | low) {
                for x in 0..256_u32 {
                    if d.wrapping_sub(PRODUCT[x as usize]) <= MAX_DIFF_24 {
                        assert!(held[..count as usize].contains(&x), "bucket {bucket}: {x} fits {d:#x} and is not held");
                    }
                }
            }
        }
        assert!(two > 0, "some buckets hold two bytes");
    }
}
