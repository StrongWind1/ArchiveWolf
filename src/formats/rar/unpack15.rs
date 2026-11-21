//! RAR 1.3-1.5 decompressor (`Unpack15`).
//!
//! Adaptive Huffman + LZ scheme with a 64 KiB window, used by `rar1`
//! archives and by `rar4` entries with `UnpVer` 15. Needed to verify a
//! candidate key or password against a compressed entry, because the header
//! checksum covers the unpacked data.
//!
//! Decoder logic and tables follow the `rars` crate (Apache-2.0), which in
//! turn follows unrar's `unpack15.cpp`.
//!
//! Parts of this file follow the UnRAR source. Its license, paragraph 2, has to accompany such code:
//!
//! ```text
//! UnRAR source code may be used in any software to handle
//! RAR archives without limitations free of charge, but cannot be
//! used to develop RAR (WinRAR) compatible archiver and to
//! re-create RAR compression algorithm, which is proprietary.
//! Distribution of modified UnRAR source code in separate form
//! or as a part of other software is permitted, provided that
//! full text of this paragraph, starting from "UnRAR source code"
//! words, is included in license, or in documentation if license
//! is not available, and in source code comments of resulting package.
//! ```
//!
//! The full text is in `LICENSE-UNRAR.txt`.

const DEC_L1: [u16; 11] = [0x8000, 0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf200, 0xffff];
const POS_L1: [u16; 13] = [0, 0, 0, 2, 3, 5, 7, 11, 16, 20, 24, 32, 32];
const DEC_L2: [u16; 10] = [0xa000, 0xc000, 0xd000, 0xe000, 0xea00, 0xee00, 0xf000, 0xf200, 0xf240, 0xffff];
const POS_L2: [u16; 13] = [0, 0, 0, 0, 5, 7, 9, 13, 18, 22, 26, 34, 36];
const DEC_HF0: [u16; 9] = [0x8000, 0xc000, 0xe000, 0xf200, 0xf200, 0xf200, 0xf200, 0xf200, 0xffff];
const POS_HF0: [u16; 13] = [0, 0, 0, 0, 0, 8, 16, 24, 33, 33, 33, 33, 33];
const DEC_HF1: [u16; 8] = [0x2000, 0xc000, 0xe000, 0xf000, 0xf200, 0xf200, 0xf7e0, 0xffff];
const POS_HF1: [u16; 13] = [0, 0, 0, 0, 0, 0, 4, 44, 60, 76, 80, 80, 127];
const DEC_HF2: [u16; 8] = [0x1000, 0x2400, 0x8000, 0xc000, 0xfa00, 0xffff, 0xffff, 0xffff];
const POS_HF2: [u16; 13] = [0, 0, 0, 0, 0, 0, 2, 7, 53, 117, 233, 0, 0];
const DEC_HF3: [u16; 7] = [0x0800, 0x2400, 0xee00, 0xfe80, 0xffff, 0xffff, 0xffff];
const POS_HF3: [u16; 13] = [0, 0, 0, 0, 0, 0, 0, 2, 16, 218, 251, 0, 0];
const DEC_HF4: [u16; 6] = [0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff];
const POS_HF4: [u16; 13] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 0];

const SHORT_LEN1: [u8; 16] = [1, 3, 4, 4, 5, 6, 7, 8, 8, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR1: [u8; 15] = [0x00, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];
const SHORT_LEN2: [u8; 16] = [2, 3, 3, 3, 4, 4, 5, 6, 6, 4, 4, 5, 6, 6, 4, 0];
const SHORT_XOR2: [u8; 15] = [0x00, 0x40, 0x60, 0xa0, 0xd0, 0xe0, 0xf0, 0xf8, 0xfc, 0xc0, 0x80, 0x90, 0x98, 0x9c, 0xb0];

/// Window size: matches reach at most 64 KiB back.
const WINDOW: usize = 0x1_0000;

/// Result of decoding one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Decoded {
    /// Whole input bytes the decoder consumed.
    pub consumed: usize,
}

/// `Unpack15` decoder state. One instance decodes a solid chain in order.
#[derive(Clone)]
pub(crate) struct Unpack15 {
    /// Output of the chain so far; the tail doubles as the LZ window.
    out: Vec<u8>,
    member_start: usize,
    target: usize,
    ch_set: [u16; 256],
    ch_set_a: [u16; 256],
    ch_set_b: [u16; 256],
    ch_set_c: [u16; 256],
    n_to_pl: [u8; 256],
    n_to_pl_b: [u8; 256],
    n_to_pl_c: [u8; 256],
    avr_plc: u32,
    avr_plc_b: u32,
    avr_ln1: u32,
    avr_ln2: u32,
    avr_ln3: u32,
    max_dist3: u32,
    nhfb: u32,
    nlzb: u32,
    num_huf: u32,
    buf60: u32,
    st_mode: bool,
    l_count: u32,
    flag_buf: u32,
    flags_cnt: i32,
    old_dist: [u32; 4],
    old_dist_ptr: usize,
    last_dist: u32,
    last_length: u32,
    bit_pos: usize,
}

/// Decoding stopped: the stream is not valid for the requested output size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Invalid;

#[expect(clippy::indexing_slicing, reason = "table indices are masked to table size or bounded by the sentinel entries")]
#[expect(clippy::cast_possible_truncation, reason = "values are masked to their target width")]
impl Unpack15 {
    pub(crate) fn new() -> Self {
        let mut d = Self {
            out: Vec::new(),
            member_start: 0,
            target: 0,
            ch_set: [0; 256],
            ch_set_a: [0; 256],
            ch_set_b: [0; 256],
            ch_set_c: [0; 256],
            n_to_pl: [0; 256],
            n_to_pl_b: [0; 256],
            n_to_pl_c: [0; 256],
            avr_plc: 0,
            avr_plc_b: 0,
            avr_ln1: 0,
            avr_ln2: 0,
            avr_ln3: 0,
            max_dist3: 0,
            nhfb: 0,
            nlzb: 0,
            num_huf: 0,
            buf60: 0,
            st_mode: false,
            l_count: 0,
            flag_buf: 0,
            flags_cnt: 0,
            old_dist: [0; 4],
            old_dist_ptr: 0,
            last_dist: 0,
            last_length: 0,
            bit_pos: 0,
        };
        d.reset();
        d
    }

    /// Bytes produced by the most recent `decode` call.
    pub(crate) fn member(&self) -> &[u8] {
        self.out.get(self.member_start..).unwrap_or_default()
    }

    /// Decode one member of `target` unpacked bytes from `input`.
    ///
    /// `solid` keeps the window and adaptive tables from the previous member.
    /// Fails when the stream overruns `target` or consumes more bits than `input` holds.
    ///
    /// `target` is what a header says and is held against nothing here: no memory is set
    /// aside for it. The output grows with what the stream produces, and a stream of `n`
    /// bytes ends after `8 * n` bits whatever it was said to unpack to.
    pub(crate) fn decode(&mut self, input: &[u8], target: usize, solid: bool) -> Result<Decoded, Invalid> {
        if solid {
            if self.out.len() > WINDOW {
                let cut = self.out.len() - WINDOW;
                drop(self.out.drain(..cut));
            }
        } else {
            self.reset();
        }
        self.member_start = self.out.len();
        self.target = self.member_start.saturating_add(target);
        self.flags_cnt = -2;
        self.flag_buf = 0;
        self.st_mode = false;
        self.l_count = 0;
        self.bit_pos = 0;

        let limit = input.len().saturating_mul(8);
        while self.out.len() < self.target {
            self.step(input)?;
            if self.bit_pos > limit {
                return Err(Invalid);
            }
        }
        Ok(Decoded { consumed: self.bit_pos.div_ceil(8).min(input.len()) })
    }

    fn reset(&mut self) {
        self.out.clear();
        self.avr_plc_b = 0;
        self.avr_ln1 = 0;
        self.avr_ln2 = 0;
        self.avr_ln3 = 0;
        self.num_huf = 0;
        self.buf60 = 0;
        self.avr_plc = 0x3500;
        self.max_dist3 = 0x2001;
        self.nhfb = 0x80;
        self.nlzb = 0x80;
        self.old_dist = [u32::MAX; 4];
        self.old_dist_ptr = 0;
        self.last_dist = u32::MAX;
        self.last_length = 0;
        for i in 0..256usize {
            self.ch_set[i] = (i as u16) << 8;
            self.ch_set_b[i] = (i as u16) << 8;
            self.ch_set_a[i] = i as u16;
            self.ch_set_c[i] = u16::from(0u8.wrapping_sub(i as u8)) << 8;
        }
        self.n_to_pl = [0; 256];
        self.n_to_pl_b = [0; 256];
        self.n_to_pl_c = [0; 256];
        corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
    }

    /// Next 16 bits of the stream, zero-filled past the end.
    fn bits(&self, input: &[u8]) -> u32 {
        let byte = self.bit_pos / 8;
        let b = |i: usize| u32::from(input.get(byte + i).copied().unwrap_or(0));
        let word = (b(0) << 16) | (b(1) << 8) | b(2);
        (word >> (8 - (self.bit_pos % 8))) & 0xffff
    }

    fn take_flag_bit(&mut self, input: &[u8]) -> bool {
        self.flags_cnt -= 1;
        if self.flags_cnt < 0 {
            self.get_flags_buf(input);
            self.flags_cnt = 7;
        }
        let set = self.flag_buf & 0x80 != 0;
        self.flag_buf = (self.flag_buf << 1) & 0xff;
        set
    }

    fn step(&mut self, input: &[u8]) -> Result<(), Invalid> {
        if self.flags_cnt == -2 {
            self.get_flags_buf(input);
            self.flags_cnt = 8;
        }
        if self.st_mode {
            return self.huff_decode(input);
        }
        // Flag bits: 1 = the currently likelier of long-match/literal,
        // 01 = the other one, 00 = short match.
        let lz_likelier = self.nlzb > self.nhfb;
        if self.take_flag_bit(input) {
            return if lz_likelier { self.long_lz(input) } else { self.huff_decode(input) };
        }
        let second = self.take_flag_bit(input);
        match (second, lz_likelier) {
            (true, true) => self.huff_decode(input),
            (true, false) => self.long_lz(input),
            (false, _) => self.short_lz(input),
        }
    }

    fn short_lz(&mut self, input: &[u8]) -> Result<(), Invalid> {
        self.num_huf = 0;
        let mut bit_field = self.bits(input);
        if self.l_count == 2 {
            self.bit_pos += 1;
            if bit_field >= 0x8000 {
                return self.copy_string(self.last_dist, self.last_length);
            }
            bit_field = (bit_field << 1) & 0xffff;
            self.l_count = 0;
        }

        let bit_byte = (bit_field >> 8) as u8;
        let use_first = self.avr_ln1 < 37;
        let mut pos = 0usize;
        loop {
            let (len, xor) = if use_first { (self.short_len1(pos), SHORT_XOR1[pos]) } else { (self.short_len2(pos), SHORT_XOR2[pos]) };
            let mask = !(0xffu16 >> len) as u8;
            if (bit_byte ^ xor) & mask == 0 {
                self.bit_pos += len as usize;
                break;
            }
            pos += 1;
            if pos >= SHORT_XOR1.len() {
                return Err(Invalid);
            }
        }

        let mut length = pos as u32;
        if length >= 9 {
            if length == 9 {
                self.l_count += 1;
                return self.copy_string(self.last_dist, self.last_length);
            }
            if length == 14 {
                self.l_count = 0;
                length = self.decode_num(input, 3, &DEC_L2, &POS_L2) + 5;
                let distance = (self.bits(input) >> 1) | 0x8000;
                self.bit_pos += 15;
                self.last_length = length;
                self.last_dist = distance;
                return self.copy_string(distance, length);
            }

            self.l_count = 0;
            let save_length = length;
            let distance = self.old_dist[self.old_dist_ptr.wrapping_sub((length - 9) as usize) & 3];
            length = self.decode_num(input, 2, &DEC_L1, &POS_L1) + 2;
            if length == 0x101 && save_length == 10 {
                self.buf60 ^= 1;
                return Ok(());
            }
            if distance > 256 {
                length += 1;
            }
            if distance >= self.max_dist3 {
                length += 1;
            }
            self.remember_match(distance, length);
            return self.copy_string(distance, length);
        }

        self.l_count = 0;
        self.avr_ln1 += length;
        self.avr_ln1 -= self.avr_ln1 >> 4;

        let place = (self.decode_num(input, 5, &DEC_HF2, &POS_HF2) & 0xff) as usize;
        let mut distance = u32::from(self.ch_set_a[place]);
        if place > 0 {
            self.ch_set_a.swap(place, place - 1);
        }
        length += 2;
        distance += 1;
        self.remember_match(distance, length);
        self.copy_string(distance, length)
    }

    fn long_lz(&mut self, input: &[u8]) -> Result<(), Invalid> {
        self.num_huf = 0;
        self.nlzb += 16;
        if self.nlzb > 0xff {
            self.nlzb = 0x90;
            self.nhfb >>= 1;
        }
        let old_avr2 = self.avr_ln2;

        let bit_field = self.bits(input);
        let mut length = if self.avr_ln2 >= 122 {
            self.decode_num(input, 3, &DEC_L2, &POS_L2)
        } else if self.avr_ln2 >= 64 {
            self.decode_num(input, 2, &DEC_L1, &POS_L1)
        } else if bit_field < 0x100 {
            self.bit_pos += 16;
            bit_field
        } else {
            let zeros = (bit_field << 16).leading_zeros();
            self.bit_pos += (zeros + 1) as usize;
            zeros
        };

        self.avr_ln2 += length;
        self.avr_ln2 -= self.avr_ln2 >> 5;

        let place = if self.avr_plc_b > 0x28ff {
            self.decode_num(input, 5, &DEC_HF2, &POS_HF2)
        } else if self.avr_plc_b > 0x06ff {
            self.decode_num(input, 5, &DEC_HF1, &POS_HF1)
        } else {
            self.decode_num(input, 4, &DEC_HF0, &POS_HF0)
        };

        self.avr_plc_b += place;
        self.avr_plc_b -= self.avr_plc_b >> 8;

        let idx = (place & 0xff) as usize;
        let mut distance;
        let mut new_place;
        loop {
            distance = u32::from(self.ch_set_b[idx]);
            let slot = (distance & 0xff) as usize;
            new_place = usize::from(self.n_to_pl_b[slot]);
            self.n_to_pl_b[slot] = self.n_to_pl_b[slot].wrapping_add(1);
            distance += 1;
            if distance.trailing_zeros() >= 8 {
                corr_huff(&mut self.ch_set_b, &mut self.n_to_pl_b);
            } else {
                break;
            }
        }
        self.ch_set_b[idx] = self.ch_set_b[new_place];
        self.ch_set_b[new_place] = distance as u16;

        distance = ((distance & 0xff00) | (self.bits(input) >> 8)) >> 1;
        self.bit_pos += 7;

        let old_avr3 = self.avr_ln3;
        if length != 1 && length != 4 {
            if length == 0 && distance <= self.max_dist3 {
                self.avr_ln3 += 1;
                self.avr_ln3 -= self.avr_ln3 >> 8;
            } else if self.avr_ln3 > 0 {
                self.avr_ln3 -= 1;
            }
        }
        length += 3;
        if distance >= self.max_dist3 {
            length += 1;
        }
        if distance <= 256 {
            length += 8;
        }
        self.max_dist3 = if old_avr3 > 0xb0 || (self.avr_plc >= 0x2a00 && old_avr2 < 0x40) { 0x7f00 } else { 0x2001 };

        self.remember_match(distance, length);
        self.copy_string(distance, length)
    }

    fn huff_decode(&mut self, input: &[u8]) -> Result<(), Invalid> {
        let bit_field = self.bits(input);

        let mut place = if self.avr_plc > 0x75ff {
            self.decode_num(input, 8, &DEC_HF4, &POS_HF4)
        } else if self.avr_plc > 0x5dff {
            self.decode_num(input, 6, &DEC_HF3, &POS_HF3)
        } else if self.avr_plc > 0x35ff {
            self.decode_num(input, 5, &DEC_HF2, &POS_HF2)
        } else if self.avr_plc > 0x0dff {
            self.decode_num(input, 5, &DEC_HF1, &POS_HF1)
        } else {
            self.decode_num(input, 4, &DEC_HF0, &POS_HF0)
        } & 0xff;

        if self.st_mode {
            if place == 0 && bit_field > 0x0fff {
                place = 0x100;
            }
            if place == 0 {
                let field = self.bits(input);
                self.bit_pos += 1;
                if field & 0x8000 != 0 {
                    self.num_huf = 0;
                    self.st_mode = false;
                    return Ok(());
                }
                let length = if field & 0x4000 != 0 { 4 } else { 3 };
                self.bit_pos += 1;
                let mut distance = self.decode_num(input, 5, &DEC_HF2, &POS_HF2);
                distance = (distance << 5) | (self.bits(input) >> 11);
                self.bit_pos += 5;
                return self.copy_string(distance, length);
            }
            place -= 1;
        } else {
            if self.num_huf >= 16 && self.flags_cnt == 0 {
                self.st_mode = true;
            }
            self.num_huf += 1;
        }

        self.avr_plc += place;
        self.avr_plc -= self.avr_plc >> 8;
        self.nhfb += 16;
        if self.nhfb > 0xff {
            self.nhfb = 0x90;
            self.nlzb >>= 1;
        }

        let idx = (place & 0xff) as usize;
        self.put_byte((self.ch_set[idx] >> 8) as u8)?;

        let mut cur;
        let mut new_place;
        loop {
            cur = u32::from(self.ch_set[idx]);
            let slot = (cur & 0xff) as usize;
            new_place = usize::from(self.n_to_pl[slot]);
            self.n_to_pl[slot] = self.n_to_pl[slot].wrapping_add(1);
            cur += 1;
            if cur & 0xff > 0xa1 {
                corr_huff(&mut self.ch_set, &mut self.n_to_pl);
            } else {
                break;
            }
        }
        self.ch_set[idx] = self.ch_set[new_place];
        self.ch_set[new_place] = cur as u16;
        Ok(())
    }

    fn get_flags_buf(&mut self, input: &[u8]) {
        let place = self.decode_num(input, 5, &DEC_HF2, &POS_HF2) as usize;
        if place >= self.ch_set_c.len() {
            return;
        }
        let mut flags;
        let mut new_place;
        loop {
            flags = u32::from(self.ch_set_c[place]);
            let slot = (flags & 0xff) as usize;
            new_place = usize::from(self.n_to_pl_c[slot]);
            self.n_to_pl_c[slot] = self.n_to_pl_c[slot].wrapping_add(1);
            self.flag_buf = flags >> 8;
            flags += 1;
            if flags.trailing_zeros() >= 8 {
                corr_huff(&mut self.ch_set_c, &mut self.n_to_pl_c);
            } else {
                break;
            }
        }
        self.ch_set_c[place] = self.ch_set_c[new_place];
        self.ch_set_c[new_place] = flags as u16;
    }

    fn decode_num(&mut self, input: &[u8], mut start_pos: u32, dec_tab: &[u16], pos_tab: &[u16; 13]) -> u32 {
        let num = self.bits(input) & 0xfff0;
        let mut i = 0usize;
        while u32::from(dec_tab[i]) <= num {
            start_pos += 1;
            i += 1;
        }
        self.bit_pos += start_pos as usize;
        let base = if i > 0 { u32::from(dec_tab[i - 1]) } else { 0 };
        ((num - base) >> (16 - start_pos)) + u32::from(pos_tab[start_pos as usize])
    }

    fn copy_string(&mut self, distance: u32, length: u32) -> Result<(), Invalid> {
        let distance = distance as usize;
        if self.out.len() + length as usize > self.target {
            return Err(Invalid);
        }
        let length = length as usize;
        if distance == 0 || distance > WINDOW || distance > self.out.len() {
            // Reaches before the start of the data: the window is zero-filled.
            // A match that starts there but runs into real bytes copies them.
            for _ in 0..length {
                let byte = if distance == 0 || distance > WINDOW || distance > self.out.len() { 0 } else { self.out[self.out.len() - distance] };
                self.out.push(byte);
            }
        } else if distance >= length {
            let start = self.out.len() - distance;
            self.out.extend_from_within(start..start + length);
        } else {
            for _ in 0..length {
                let byte = self.out[self.out.len() - distance];
                self.out.push(byte);
            }
        }
        Ok(())
    }

    fn put_byte(&mut self, byte: u8) -> Result<(), Invalid> {
        if self.out.len() >= self.target {
            return Err(Invalid);
        }
        self.out.push(byte);
        Ok(())
    }

    const fn remember_match(&mut self, distance: u32, length: u32) {
        self.old_dist[self.old_dist_ptr] = distance;
        self.old_dist_ptr = (self.old_dist_ptr + 1) & 3;
        self.last_length = length;
        self.last_dist = distance;
    }

    fn short_len1(&self, pos: usize) -> u32 {
        if pos == 1 { self.buf60 + 3 } else { u32::from(SHORT_LEN1[pos]) }
    }

    fn short_len2(&self, pos: usize) -> u32 {
        if pos == 3 { self.buf60 + 3 } else { u32::from(SHORT_LEN2[pos]) }
    }
}

#[expect(clippy::indexing_slicing, reason = "fixed 256-entry tables indexed below 256")]
fn corr_huff(char_set: &mut [u16; 256], num_to_place: &mut [u8; 256]) {
    let mut pos = 0usize;
    for rank in (0..=7u16).rev() {
        for _ in 0..32 {
            char_set[pos] = (char_set[pos] & !0xff) | rank;
            pos += 1;
        }
    }
    *num_to_place = [0; 256];
    for rank in (0..=6usize).rev() {
        num_to_place[rank] = u8::try_from((7 - rank) * 32).unwrap_or(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_target_consumes_nothing() {
        let mut d = Unpack15::new();
        assert_eq!(d.decode(&[], 0, false), Ok(Decoded { consumed: 0 }));
        assert!(d.member().is_empty());
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(Unpack15::new().decode(&[], 4096, false).is_err());
    }

    /// A header can say that a few bytes unpack to 2^63. Nothing is set aside for that: the
    /// stream ends where its input ends, and what was produced until then is all that is held.
    /// A reservation of the declared size ended the process here, by an allocation that fails
    /// or by a capacity that overflows.
    #[test]
    fn a_declared_size_is_not_reserved() {
        for target in [1 << 32, 1 << 44, usize::MAX / 2 + 1, usize::MAX] {
            for input in [&[0x55_u8; 64][..], &[0x00; 64], &[0xFF; 64], &[0xA7; 4096]] {
                let mut decoder = Unpack15::new();
                assert_eq!(decoder.decode(input, target, false), Err(Invalid), "{} bytes said to unpack to {target}", input.len());
                // a match gives 257 bytes at most for the few bits it takes
                assert!(decoder.out.capacity() <= input.len() * 8 * 2 * 257, "{} bytes are held for {} of input", decoder.out.capacity(), input.len());
            }
        }
    }

    /// The same for a member that continues a solid chain: its target is counted from what the
    /// chain has produced, and that sum has to stay a number.
    #[test]
    fn a_declared_size_does_not_overflow_behind_a_solid_member() {
        let data = std::fs::read("tests/fixtures/unencrypted/rar14-solid.rar").unwrap();
        let head = usize::from(u16::from_le_bytes([data[4], data[5]]));
        let mut pos = head;
        let mut decoder = Unpack15::new();
        let mut first = None;
        while first.is_none() {
            let pack = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let unp = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let hsize = usize::from(u16::from_le_bytes([data[pos + 10], data[pos + 11]]));
            if data[pos + 20] != 0 {
                first = Some(decoder.decode(&data[pos + hsize..pos + hsize + pack], unp, false).unwrap());
            }
            pos += hsize + pack;
        }
        assert!(!decoder.member().is_empty());
        assert_eq!(decoder.decode(&[0x55; 64], usize::MAX, true), Err(Invalid));
    }

    #[test]
    fn unencrypted_rar1_fixture_decodes_to_header_checksum() {
        // rar14-solid.rar is an unencrypted solid RAR 1.4 archive; decode the
        // chain and compare every member against its header checksum.
        let data = std::fs::read("tests/fixtures/unencrypted/rar14-solid.rar").unwrap();
        let head = usize::from(u16::from_le_bytes([data[4], data[5]]));
        let solid = data[6] & 0x08 != 0;
        let mut d = Unpack15::new();
        let mut chained = false;
        let mut pos = head;
        let mut checked = 0;
        while pos + 21 <= data.len() {
            let pack = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let unp = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            let sum = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
            let hsize = usize::from(u16::from_le_bytes([data[pos + 10], data[pos + 11]]));
            let method = data[pos + 20];
            let body = &data[pos + hsize..pos + hsize + pack];
            let plain = if method == 0 {
                body.to_vec()
            } else {
                let decoded = d.decode(body, unp, solid && chained).unwrap();
                assert!(decoded.consumed + 1 >= body.len());
                chained = true;
                d.member().to_vec()
            };
            assert_eq!(plain.len(), unp);
            let mut acc = 0u16;
            for &b in &plain {
                acc = acc.wrapping_add(u16::from(b)).rotate_left(1);
            }
            assert_eq!(acc, sum);
            checked += 1;
            pos += hsize + pack;
        }
        assert!(checked > 0);
    }
}
