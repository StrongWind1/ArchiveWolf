//! The search for repeats: the window over the input, the hash chains of the strings in it,
//! and the four ways of turning the input into literals and matches.
//!
//! This file is a port to Rust of `deflate.c` of zlib 1.3.2, Copyright (C) 1995-2026 Jean-loup
//! Gailly and Mark Adler, and of `deflate.c` of Zip 3.0, Copyright (c) 1990-2007 Info-ZIP. It
//! is an altered version: it is not the original software of either, and it is not a release
//! of Info-ZIP. What is taken from zlib is under the zlib licence, whose notice stands below
//! these lines, and what is taken from Zip is under the Info-ZIP licence, whose text is in
//! `LICENSE-INFOZIP.txt`.
//!
//! zlib's `deflate.c` descends from the one of zip, and the search is the same in both: the
//! same window of 64 KiB that slides by half, the same chains, the same table of settings
//! for the nine levels. The size of the hash table is what differs, and it is a field of
//! [`Settings`]. The rest of the differences are in the blocks, in `trees.rs`.
//!
//! One thing is not as in zlib. `fill_window` of zlib slides the window whenever the search
//! is within 262 bytes of its end and has fewer than 262 bytes ahead: when the window is
//! full, and also when the caller has only not given the next piece of input yet. So where
//! the window slides depends on where the caller cuts the input, and in rare cases so does
//! the stream: a block that began in the half that slid away can no longer be written as a
//! stored block. Measured with zlib 1.3.2: 200,000 random bytes at memory level 9 and
//! `Z_HUFFMAN_ONLY`, given in two calls, come out 35 bytes longer than in one call when the
//! cut is at any of the positions 65,274 to 65,533. Here the window slides only when it is
//! full, or when the input has ended. That is where zlib slides it when it has the whole
//! input in one call, and it is how zip reads a file. So the stream is that of one call,
//! however the input is cut. A piece whose length is a multiple of 512 bytes never ends
//! where zlib slides early, so a writer that reads its files in such pieces gets the stream
//! of one call from zlib as well.

// The notice of zlib, from its `LICENSE`:
//
//   (C) 1995-2026 Jean-loup Gailly and Mark Adler
//
//   This software is provided 'as-is', without any express or implied
//   warranty.  In no event will the authors be held liable for any damages
//   arising from the use of this software.
//
//   Permission is granted to anyone to use this software for any purpose,
//   including commercial applications, and to alter it and redistribute it
//   freely, subject to the following restrictions:
//
//   1. The origin of this software must not be misrepresented; you must not
//      claim that you wrote the original software. If you use this software
//      in a product, an acknowledgment in the product documentation would be
//      appreciated but is not required.
//   2. Altered source versions must be plainly marked as such, and must not be
//      misrepresented as being the original software.
//   3. This notice may not be removed or altered from any source distribution.
//
//   Jean-loup Gailly        Mark Adler
//   jloup@gzip.org          madler@alumni.caltech.edu

use super::at;
use super::low16;
use super::put;
use super::trees::Blocks;
use super::trees::Rules;

/// The size of the window that matches reach back in (`WSIZE` of zip, `w_size` of zlib for
/// 15 window bits, which is what both programs write ZIP entries with).
const WSIZE: usize = 0x8000;

/// The window holds twice that (`window_size`).
const WINDOW_SIZE: usize = 2 * WSIZE;

/// The mask that takes a position to its entry in the chain table (`w_mask`).
const WMASK: usize = WSIZE - 1;

/// The shortest match (`MIN_MATCH`).
const MIN_MATCH: usize = 3;

/// The longest match (`MAX_MATCH`).
const MAX_MATCH: usize = 258;

/// The bytes that have to lie ahead of a position before it is searched, unless the input
/// has ended (`MIN_LOOKAHEAD`).
const MIN_LOOKAHEAD: usize = MAX_MATCH + MIN_MATCH + 1;

/// The greatest distance of a match (`MAX_DIST`).
const MAX_DIST: usize = WSIZE - MIN_LOOKAHEAD;

/// A match of three bytes that lies further back than this is not taken (`TOO_FAR`).
const TOO_FAR: usize = 4096;

/// The end of a hash chain (`NIL`). Position 0 of the window is therefore never matched.
const NIL: usize = 0;

/// One row of `configuration_table`, which is the same in zlib and in zip.
#[derive(Debug, Clone, Copy, Default)]
struct Config {
    /// A match this long shortens the search for a better one (`good_length`).
    good_length: usize,
    /// No better match is looked for after one this long. For the levels without lazy
    /// matching: no string inside a match longer than this is put into the chains (`max_lazy`).
    max_lazy: usize,
    /// A match this long ends the search (`nice_length`).
    nice_length: usize,
    /// The number of strings of a chain that are tried (`max_chain`).
    max_chain: usize,
    /// The level uses lazy matching (`deflate_slow` and not `deflate_fast`).
    lazy: bool,
}

/// A row of the table.
const fn config(good_length: usize, max_lazy: usize, nice_length: usize, max_chain: usize, lazy: bool) -> Config {
    Config { good_length, max_lazy, nice_length, max_chain, lazy }
}

/// `configuration_table`: the settings of levels 0 to 9. Level 0 stores and is not offered.
const CONFIGURATION: [Config; 10] = [
    config(0, 0, 0, 0, false),
    config(4, 4, 8, 4, false),
    config(4, 5, 16, 8, false),
    config(4, 6, 32, 32, false),
    config(4, 4, 16, 16, true),
    config(8, 16, 32, 32, true),
    config(8, 16, 128, 128, true),
    config(8, 32, 128, 256, true),
    config(32, 128, 258, 1024, true),
    config(32, 258, 258, 4096, true),
];

/// The way the input is turned into literals and matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Finder {
    /// What the level says: `deflate_fast` for levels 1 to 3 and `deflate_slow` from 4 on.
    Level,
    /// Matches of distance one only: runs of one byte (`deflate_rle`).
    Rle,
    /// No matches (`deflate_huff`).
    Huffman,
}

/// What a packer is made of.
#[derive(Debug, Clone, Copy)]
pub(super) struct Settings {
    /// The level, 1 to 9.
    pub level: u8,
    /// The number of bits of a hash value: the memory level of zlib plus seven, and
    /// `HASH_BITS` of zip, which is 15.
    pub hash_bits: u32,
    /// The way matches are found.
    pub finder: Finder,
    /// Matches of five bytes and under are not taken (`Z_FILTERED` of zlib).
    pub filtered: bool,
    /// A block is also ended where zip guesses that it pays (`ct_tally` of zip, levels 3 to 9).
    pub guesses_end: bool,
    /// What the blocks are made by.
    pub rules: Rules,
}

/// Why a search loop returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pause {
    /// The input given so far is used up, and more may come.
    NeedInput,
    /// The input has ended and all of it is in the blocks.
    End,
}

/// The state of one stream (`deflate_state` of zlib, the globals of zip).
#[derive(Debug)]
pub(super) struct Engine {
    /// The window: the last 32 KiB of input at least, and the bytes ahead (`window`).
    window: Vec<u8>,
    /// For each position, taken modulo the size of the window, the position before it whose
    /// string has the same hash value (`prev`).
    prev: Vec<u16>,
    /// For each hash value, the last position whose string has it (`head`).
    head: Vec<u16>,
    /// The hash value of the string that is put in next (`ins_h`).
    ins_h: usize,
    /// The mask of a hash value (`hash_mask`).
    hash_mask: usize,
    /// The bits a hash value moves up for each byte, so that three bytes fill it (`hash_shift`).
    hash_shift: u32,
    /// The position in the window of the byte that is searched next (`strstart`).
    strstart: usize,
    /// The number of bytes of input in the window from there on (`lookahead`).
    lookahead: usize,
    /// The position in the window where the block that is being made starts. Below zero when
    /// the window has slid past that start (`block_start`).
    block_start: isize,
    /// The length of the match at this position (`match_length`).
    match_length: usize,
    /// The length of the match at the position before (`prev_length`).
    prev_length: usize,
    /// Where the match at this position starts (`match_start`). The C code lets it wrap when
    /// the window slides past it, and takes the distance of the match by a subtraction that
    /// wraps back. So does this.
    match_start: usize,
    /// Where the match at the position before starts (`prev_match`).
    prev_match: usize,
    /// The byte before this position is not yet in the block (`match_available`).
    match_available: bool,
    /// The settings of the level.
    config: Config,
    /// The way matches are found.
    finder: Finder,
    /// See [`Settings::filtered`].
    filtered: bool,
    /// See [`Settings::guesses_end`].
    guesses_end: bool,
    /// The block that is being made, and the output.
    blocks: Blocks,
}

impl Engine {
    /// The state before the first byte (`deflateInit2` and `lm_init` of zlib, `lm_init` of zip).
    pub(super) fn new(settings: &Settings) -> Self {
        let hash_size = 1_usize << settings.hash_bits;
        Self {
            window: vec![0; WINDOW_SIZE],
            prev: vec![0; WSIZE],
            head: vec![0; hash_size],
            ins_h: 0,
            hash_mask: hash_size - 1,
            hash_shift: settings.hash_bits.div_ceil(3),
            strstart: 0,
            lookahead: 0,
            block_start: 0,
            match_length: MIN_MATCH - 1,
            prev_length: MIN_MATCH - 1,
            match_start: 0,
            prev_match: 0,
            match_available: false,
            config: at(&CONFIGURATION, usize::from(settings.level)),
            finder: settings.finder,
            filtered: settings.filtered,
            guesses_end: settings.guesses_end,
            blocks: Blocks::new(settings.rules),
        }
    }

    /// Whether the program stores the file as a whole instead of writing the stream. Known
    /// once the input has ended.
    pub(super) fn stores_file(&self) -> bool {
        self.blocks.stores_file()
    }

    /// Takes input, and writes the blocks that it completes. `last` says that the input has
    /// ended: the blocks that are left are written and the stream is closed (`deflate` of
    /// zlib with `Z_NO_FLUSH` and with `Z_FINISH`).
    pub(super) fn deflate(&mut self, mut input: &[u8], last: bool, out: &mut Vec<u8>) {
        let pause = match self.finder {
            Finder::Level if self.config.lazy => self.deflate_slow(&mut input, last, out),
            Finder::Level => self.deflate_fast(&mut input, last, out),
            Finder::Rle => self.deflate_rle(&mut input, last, out),
            Finder::Huffman => self.deflate_huff(&mut input, last, out),
        };
        if pause == Pause::End {
            self.flush_block(out, true);
        }
    }

    /// Takes the next byte into the hash value (`UPDATE_HASH`).
    fn update_hash(&mut self, byte: u8) {
        self.ins_h = ((self.ins_h << self.hash_shift) ^ usize::from(byte)) & self.hash_mask;
    }

    /// Puts the string at a position at the head of its chain, and returns the head it
    /// replaces: the last position before it with the same hash value (`INSERT_STRING`).
    fn insert_string(&mut self, position: usize) -> usize {
        self.update_hash(at(&self.window, position + MIN_MATCH - 1));
        let before = at(&self.head, self.ins_h);
        put(&mut self.prev, position & WMASK, before);
        put(&mut self.head, self.ins_h, low16(position));
        usize::from(before)
    }

    /// Starts the hash value over at the string at `strstart`, with its first two bytes.
    fn restart_hash(&mut self) {
        self.ins_h = usize::from(at(&self.window, self.strstart));
        self.update_hash(at(&self.window, self.strstart + 1));
    }

    /// Moves the upper half of the window to the lower one, and every position with it
    /// (`slide_hash` and the head of `fill_window`). `more` is the free space at the end.
    fn slide(&mut self, more: usize) {
        self.window.copy_within(WSIZE..WINDOW_SIZE - more, 0);
        self.match_start = self.match_start.wrapping_sub(WSIZE);
        self.strstart -= WSIZE;
        self.block_start -= WSIZE.cast_signed();
        for position in self.head.iter_mut().chain(self.prev.iter_mut()) {
            *position = position.saturating_sub(0x8000);
        }
    }

    /// Takes input into the window, as much as fits, and slides the window first when that
    /// is due (`fill_window`). Called when fewer bytes lie ahead than the `wanted` ones that
    /// the search does not go on without.
    fn fill_window(&mut self, wanted: usize, input: &mut &[u8], last: bool) {
        loop {
            let mut more = WINDOW_SIZE - self.lookahead - self.strstart;
            // zlib and zip slide here whenever `strstart` is this far. With the whole input at
            // hand that is when the window is full or the input has ended: see the top of the file.
            if self.strstart >= WSIZE + MAX_DIST && (more == 0 || last) {
                self.slide(more);
                more += WSIZE;
            }
            let (taken, rest) = input.split_at(input.len().min(more));
            if taken.is_empty() {
                break;
            }
            let free = self.strstart + self.lookahead;
            if let Some(space) = self.window.get_mut(free..free + taken.len()) {
                space.copy_from_slice(taken);
            }
            *input = rest;
            self.lookahead += taken.len();
            if self.lookahead >= MIN_MATCH {
                self.restart_hash();
            }
            if self.lookahead >= wanted || input.is_empty() {
                break;
            }
        }
    }

    /// Fills the window when fewer than `wanted` bytes lie ahead, and says whether the search
    /// has to stop there: for more input, or because the input has ended.
    fn refill(&mut self, wanted: usize, input: &mut &[u8], last: bool) -> Option<Pause> {
        if self.lookahead >= wanted {
            return None;
        }
        self.fill_window(wanted, input, last);
        if self.lookahead < wanted && !last {
            return Some(Pause::NeedInput);
        }
        (self.lookahead == 0).then_some(Pause::End)
    }

    /// The number of bytes the block stands for so far.
    fn block_length(&self) -> u64 {
        u64::try_from(self.strstart.cast_signed() - self.block_start).unwrap_or(0)
    }

    /// Takes a literal into the block. Returns whether the block ends here.
    fn tally_lit(&mut self, byte: u8) -> bool {
        let full = self.blocks.tally_lit(byte);
        full || (self.guesses_end && self.blocks.guesses_end(self.block_length()))
    }

    /// Takes a match into the block. Returns whether the block ends here.
    fn tally_dist(&mut self, dist: usize, length: usize) -> bool {
        let full = self.blocks.tally_dist(dist, length - MIN_MATCH);
        full || (self.guesses_end && self.blocks.guesses_end(self.block_length()))
    }

    /// Ends the block at `strstart` (`FLUSH_BLOCK_ONLY` of zlib, `FLUSH_BLOCK` of zip).
    fn flush_block(&mut self, out: &mut Vec<u8>, last: bool) {
        let buf = usize::try_from(self.block_start).ok().and_then(|start| self.window.get(start..self.strstart));
        self.blocks.flush_block(out, buf, self.block_length(), last);
        self.block_start = self.strstart.cast_signed();
    }

    /// The length of the longest match of the string at `strstart` among the strings of its
    /// chain, from `cur_match` back. A match that is not longer than the one of the position
    /// before does not count: the result is then the length of that one. Sets `match_start`
    /// (`longest_match`).
    ///
    /// The C code compares up to 258 bytes whatever lies ahead, and cuts the result down to
    /// the bytes of input afterwards. This compares the bytes of input only. The result is
    /// the same: `nice_match` is never above the bytes ahead, so the first string that agrees
    /// in all of them ends the search in both. The C code also leaves out the third byte of
    /// a string whose first two agree, which the equal hash value makes equal. This compares
    /// it with the rest.
    fn longest_match(&mut self, mut cur_match: usize) -> usize {
        let mut best_len = self.prev_length;
        let max_len = MAX_MATCH.min(self.lookahead);
        // the match before reaches the end of the input: nothing here is longer
        if best_len >= max_len {
            return best_len.min(self.lookahead);
        }
        let mut chain_length = self.config.max_chain;
        if self.prev_length >= self.config.good_length {
            chain_length >>= 2;
        }
        let nice_match = self.config.nice_length.min(self.lookahead);
        let limit = self.strstart.saturating_sub(MAX_DIST);
        let Some(scan) = self.window.get(self.strstart..self.strstart + max_len) else { return best_len };
        let mut scan_end1 = at(scan, best_len - 1);
        let mut scan_end = at(scan, best_len);

        loop {
            if let Some(candidate) = self.window.get(cur_match..cur_match + max_len)
                && at(candidate, best_len) == scan_end
                && at(candidate, best_len - 1) == scan_end1
                && candidate.first() == scan.first()
                && candidate.get(1) == scan.get(1)
            {
                let len = common_prefix(scan, candidate);
                if len > best_len {
                    self.match_start = cur_match;
                    best_len = len;
                    if len >= nice_match {
                        break;
                    }
                    scan_end1 = at(scan, best_len - 1);
                    scan_end = at(scan, best_len);
                }
            }
            cur_match = usize::from(at(&self.prev, cur_match & WMASK));
            chain_length -= 1;
            if cur_match <= limit || chain_length == 0 {
                break;
            }
        }
        best_len
    }

    /// One position of `deflate_fast`: the longest match there, or a literal.
    fn step_fast(&mut self, out: &mut Vec<u8>) {
        let mut hash_head = NIL;
        if self.lookahead >= MIN_MATCH {
            hash_head = self.insert_string(self.strstart);
        }
        if hash_head != NIL && self.strstart - hash_head <= MAX_DIST {
            self.match_length = self.longest_match(hash_head);
        }
        let flush;
        if self.match_length >= MIN_MATCH {
            flush = self.tally_dist(self.strstart.wrapping_sub(self.match_start), self.match_length);
            self.lookahead -= self.match_length;
            // the strings inside a short match go into the chains, those of a long one do not
            if self.match_length <= self.config.max_lazy && self.lookahead >= MIN_MATCH {
                for _ in 1..self.match_length {
                    self.strstart += 1;
                    let _: usize = self.insert_string(self.strstart);
                }
                self.strstart += 1;
            } else {
                self.strstart += self.match_length;
                self.restart_hash();
            }
            self.match_length = 0;
        } else {
            flush = self.tally_lit(at(&self.window, self.strstart));
            self.lookahead -= 1;
            self.strstart += 1;
        }
        if flush {
            self.flush_block(out, false);
        }
    }

    /// The levels without lazy matching (`deflate_fast`).
    fn deflate_fast(&mut self, input: &mut &[u8], last: bool, out: &mut Vec<u8>) -> Pause {
        loop {
            if let Some(pause) = self.refill(MIN_LOOKAHEAD, input, last) {
                return pause;
            }
            self.step_fast(out);
        }
    }

    /// One position of `deflate_slow`: the match found at the position before is taken
    /// unless the one found here is longer.
    fn step_slow(&mut self, out: &mut Vec<u8>) {
        let mut hash_head = NIL;
        if self.lookahead >= MIN_MATCH {
            hash_head = self.insert_string(self.strstart);
        }
        self.prev_length = self.match_length;
        self.prev_match = self.match_start;
        self.match_length = MIN_MATCH - 1;

        if hash_head != NIL && self.prev_length < self.config.max_lazy && self.strstart - hash_head <= MAX_DIST {
            self.match_length = self.longest_match(hash_head);
            if self.match_length <= 5 && (self.filtered || (self.match_length == MIN_MATCH && self.strstart.wrapping_sub(self.match_start) > TOO_FAR)) {
                self.match_length = MIN_MATCH - 1;
            }
        }

        if self.prev_length >= MIN_MATCH && self.match_length <= self.prev_length {
            // the strings of the match go into the chains as far as three bytes of input follow them
            let max_insert = self.strstart + self.lookahead - MIN_MATCH;
            let flush = self.tally_dist((self.strstart - 1).wrapping_sub(self.prev_match), self.prev_length);
            self.lookahead -= self.prev_length - 1;
            for _ in 2..self.prev_length {
                self.strstart += 1;
                if self.strstart <= max_insert {
                    let _: usize = self.insert_string(self.strstart);
                }
            }
            self.match_available = false;
            self.match_length = MIN_MATCH - 1;
            self.strstart += 1;
            if flush {
                self.flush_block(out, false);
            }
        } else if self.match_available {
            if self.tally_lit(at(&self.window, self.strstart - 1)) {
                self.flush_block(out, false);
            }
            self.strstart += 1;
            self.lookahead -= 1;
        } else {
            self.match_available = true;
            self.strstart += 1;
            self.lookahead -= 1;
        }
    }

    /// The levels with lazy matching (`deflate_slow` of zlib, `deflate` of zip).
    fn deflate_slow(&mut self, input: &mut &[u8], last: bool, out: &mut Vec<u8>) -> Pause {
        loop {
            match self.refill(MIN_LOOKAHEAD, input, last) {
                None => self.step_slow(out),
                Some(Pause::NeedInput) => return Pause::NeedInput,
                Some(Pause::End) => break,
            }
        }
        if self.match_available {
            let _: bool = self.tally_lit(at(&self.window, self.strstart - 1));
            self.match_available = false;
        }
        Pause::End
    }

    /// Runs of one byte and nothing else (`deflate_rle`).
    fn deflate_rle(&mut self, input: &mut &[u8], last: bool, out: &mut Vec<u8>) -> Pause {
        loop {
            if let Some(pause) = self.refill(MAX_MATCH + 1, input, last) {
                return pause;
            }
            // how often the byte before this position repeats from here on
            let mut run = 0;
            if self.lookahead >= MIN_MATCH && self.strstart > 0 {
                let before = at(&self.window, self.strstart - 1);
                let ahead = self.window.get(self.strstart..self.strstart + MAX_MATCH.min(self.lookahead)).unwrap_or_default();
                run = ahead.iter().take_while(|byte| **byte == before).count();
            }
            let flush;
            if run >= MIN_MATCH {
                flush = self.tally_dist(1, run);
                self.lookahead -= run;
                self.strstart += run;
            } else {
                flush = self.tally_lit(at(&self.window, self.strstart));
                self.lookahead -= 1;
                self.strstart += 1;
            }
            if flush {
                self.flush_block(out, false);
            }
        }
    }

    /// Literals only (`deflate_huff`).
    fn deflate_huff(&mut self, input: &mut &[u8], last: bool, out: &mut Vec<u8>) -> Pause {
        loop {
            if let Some(pause) = self.refill(1, input, last) {
                return pause;
            }
            let flush = self.tally_lit(at(&self.window, self.strstart));
            self.lookahead -= 1;
            self.strstart += 1;
            if flush {
                self.flush_block(out, false);
            }
        }
    }
}

/// The number of bytes that two strings of the same length agree in from their start.
fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    let (a_words, a_rest) = a.as_chunks::<8>();
    let (b_words, b_rest) = b.as_chunks::<8>();
    let mut len = 0;
    for (x, y) in a_words.iter().zip(b_words) {
        let differ = u64::from_le_bytes(*x) ^ u64::from_le_bytes(*y);
        if differ != 0 {
            return len + usize::try_from(differ.trailing_zeros() / 8).unwrap_or(0);
        }
        len += 8;
    }
    len + a_rest.iter().zip(b_rest).take_while(|(x, y)| x == y).count()
}
