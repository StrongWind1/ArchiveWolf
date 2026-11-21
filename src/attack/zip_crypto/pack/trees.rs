//! The blocks of a Deflate stream: the symbols of one block, its Huffman codes, the choice
//! between a stored, a fixed and a dynamic block, and the bit output.
//!
//! This file is a port to Rust of `trees.c` of zlib 1.3.2, Copyright (C) 1995-2026 Jean-loup
//! Gailly, with the two rules that `trees.c` of Zip 3.0, Copyright (c) 1990-2007 Info-ZIP, has
//! and zlib has not. It is an altered version: it is not the original software of either, and
//! it is not a release of Info-ZIP. What is taken from zlib is under the zlib licence, whose
//! notice stands below these lines, and what is taken from Zip is under the Info-ZIP licence,
//! whose text is in `LICENSE-INFOZIP.txt`.
//!
//! The two programs build their codes the same way: zlib's `trees.c` descends from the one of
//! zip. They differ in when a block ends, and in what a file that did not pack becomes. zip
//! ends a block where it guesses that this pays ([`Blocks::guesses_end`]), and it stores a
//! file that is one block and no smaller for it ([`Rules::stores_file`]). The number of
//! symbols that fills a block is a setting in zlib and fixed in zip ([`Rules::block_symbols`]).

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

use std::sync::LazyLock;

use super::at;
use super::low8;
use super::low16;
use super::put;

/// No code is longer than this many bits (`MAX_BITS`).
const MAX_BITS: usize = 15;

/// No code of the bit length tree is longer than this many bits (`MAX_BL_BITS`).
const MAX_BL_BITS: u16 = 7;

/// The number of codes for the lengths of matches (`LENGTH_CODES`).
const LENGTH_CODES: usize = 29;

/// The number of literal bytes (`LITERALS`).
const LITERALS: usize = 256;

/// The code that ends a block (`END_BLOCK`).
const END_BLOCK: usize = 256;

/// The number of literal and length codes, the end of block among them (`L_CODES`).
const L_CODES: usize = LITERALS + 1 + LENGTH_CODES;

/// The number of distance codes (`D_CODES`).
const D_CODES: usize = 30;

/// The number of codes that carry the bit lengths of the other two trees (`BL_CODES`).
const BL_CODES: usize = 19;

/// The size of the heap that a tree is built in, and of the largest tree (`HEAP_SIZE`).
const HEAP_SIZE: usize = 2 * L_CODES + 1;

/// The bit length code that repeats the length before it three to six times (`REP_3_6`).
const REP_3_6: usize = 16;

/// The bit length code that repeats a length of zero three to ten times (`REPZ_3_10`).
const REPZ_3_10: usize = 17;

/// The bit length code that repeats a length of zero 11 to 138 times (`REPZ_11_138`).
const REPZ_11_138: usize = 18;

/// The extra bits of each length code (`extra_lbits`).
const EXTRA_LBITS: [u8; LENGTH_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];

/// The extra bits of each distance code (`extra_dbits`).
const EXTRA_DBITS: [u8; D_CODES] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// The extra bits of each bit length code (`extra_blbits`).
const EXTRA_BLBITS: [u8; BL_CODES] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];

/// The order in which the lengths of the bit length codes are sent (`bl_order`).
const BL_ORDER: [u8; BL_CODES] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// One entry of a tree (`ct_data`). Both fields hold two things in turn, as the unions of the
/// C code do, and the code relies on that: building a tree reads the parent of a node and
/// then writes its length into the same field.
#[derive(Debug, Clone, Copy, Default)]
struct Node {
    /// The count of the symbol, and once the tree is built its code.
    fc: u16,
    /// The parent of the node while the tree is built, and then the length of its code.
    dl: u16,
}

/// The count of a symbol, or its code.
fn fc(tree: &[Node], n: usize) -> u16 {
    at(tree, n).fc
}

/// The parent of a node, or the length of its code.
fn dl(tree: &[Node], n: usize) -> u16 {
    at(tree, n).dl
}

/// Sets the count of a symbol, or its code.
fn set_fc(tree: &mut [Node], n: usize, value: u16) {
    if let Some(node) = tree.get_mut(n) {
        node.fc = value;
    }
}

/// Sets the parent of a node, or the length of its code.
fn set_dl(tree: &mut [Node], n: usize, value: u16) {
    if let Some(node) = tree.get_mut(n) {
        node.dl = value;
    }
}

/// Adds to the count of a symbol. The counts are 16 bits wide in both programs.
fn count(tree: &mut [Node], n: usize, by: u16) {
    if let Some(node) = tree.get_mut(n) {
        node.fc = node.fc.wrapping_add(by);
    }
}

/// Changes one count of a table by a difference. The counts wrap, as they do in the C code.
fn adjust(counts: &mut [u16], index: usize, by: i16) {
    if let Some(entry) = counts.get_mut(index) {
        *entry = entry.wrapping_add_signed(by);
    }
}

/// The first `len` bits of a code in reverse order (`bi_reverse`).
fn bi_reverse(code: u16, len: u16) -> u16 {
    code.reverse_bits().checked_shr(16 - u32::from(len)).unwrap_or(0)
}

/// Gives every symbol of a tree its code, from the lengths of the codes and the number of
/// codes of each length (`gen_codes`).
fn gen_codes(tree: &mut [Node], max_code: usize, bl_count: &[u16; MAX_BITS + 1]) {
    let mut next_code = [0_u16; MAX_BITS + 1];
    let mut code = 0_usize;
    for bits in 1..=MAX_BITS {
        code = (code + usize::from(at(bl_count, bits - 1))) << 1;
        put(&mut next_code, bits, low16(code));
    }
    for node in tree.iter_mut().take(max_code + 1) {
        let len = node.dl;
        if len == 0 {
            continue;
        }
        let next = at(&next_code, usize::from(len));
        node.fc = bi_reverse(next, len);
        put(&mut next_code, usize::from(len), next.wrapping_add(1));
    }
}

/// The tables that do not depend on the input (`tr_static_init`): the fixed codes of the
/// format, and the code of every length and distance.
#[derive(Debug)]
struct Tables {
    /// The fixed literal and length codes (`static_ltree`). Codes 286 and 287 do not exist,
    /// and are in the table because the code values come out right only with them.
    static_ltree: [Node; L_CODES + 2],
    /// The fixed distance codes, all of five bits (`static_dtree`).
    static_dtree: [Node; D_CODES],
    /// The length code of a match length less three (`_length_code`).
    length_code: [u8; 256],
    /// The distance code of a distance less one: of the distance itself below 256, and of
    /// its top eight bits from there on (`_dist_code`).
    dist_code: [u8; 512],
    /// The first match length less three of each length code (`base_length`).
    base_length: [u16; LENGTH_CODES],
    /// The first distance less one of each distance code (`base_dist`).
    base_dist: [u16; D_CODES],
}

/// The tables, made at the first use.
static TABLES: LazyLock<Tables> = LazyLock::new(Tables::new);

impl Tables {
    /// Builds the tables as `tr_static_init` of zlib and `ct_init` of zip do.
    fn new() -> Self {
        let mut tables = Self { static_ltree: [Node::default(); L_CODES + 2], static_dtree: [Node::default(); D_CODES], length_code: [0; 256], dist_code: [0; 512], base_length: [0; LENGTH_CODES], base_dist: [0; D_CODES] };

        // every length is given to its code, and length 258 to code 28, which has no extra bits
        let mut length = 0_u16;
        for (code, extra) in (0_u8..28).zip(EXTRA_LBITS) {
            put(&mut tables.base_length, usize::from(code), length);
            for _ in 0..(1_u16 << extra) {
                put(&mut tables.length_code, usize::from(length), code);
                length += 1;
            }
        }
        put(&mut tables.length_code, usize::from(length - 1), 28);

        // the distances below 256 one by one, the others by their top eight bits
        let mut dist = 0_u16;
        for (code, extra) in (0_u8..16).zip(EXTRA_DBITS) {
            put(&mut tables.base_dist, usize::from(code), dist);
            for _ in 0..(1_u16 << extra) {
                put(&mut tables.dist_code, usize::from(dist), code);
                dist += 1;
            }
        }
        dist >>= 7;
        for (code, extra) in (0_u8..).zip(EXTRA_DBITS).skip(16) {
            put(&mut tables.base_dist, usize::from(code), dist << 7);
            for _ in 0..(1_u16 << (extra - 7)) {
                put(&mut tables.dist_code, 256 + usize::from(dist), code);
                dist += 1;
            }
        }

        // the fixed codes: their lengths are part of the format
        let mut bl_count = [0_u16; MAX_BITS + 1];
        for (n, node) in tables.static_ltree.iter_mut().enumerate() {
            node.dl = match n {
                0..=143 | 280.. => 8,
                144..=255 => 9,
                _ => 7,
            };
            adjust(&mut bl_count, usize::from(node.dl), 1);
        }
        gen_codes(&mut tables.static_ltree, L_CODES + 1, &bl_count);
        for (n, node) in (0_u16..).zip(tables.static_dtree.iter_mut()) {
            *node = Node { fc: bi_reverse(n, 5), dl: 5 };
        }
        tables
    }

    /// The distance code of a distance less one (`d_code`).
    fn d_code(&self, dist: u16) -> usize {
        let dist = usize::from(dist);
        usize::from(if dist < 256 { at(&self.dist_code, dist) } else { at(&self.dist_code, 256 + (dist >> 7)) })
    }
}

/// What a tree is built with besides its counts (`static_tree_desc`).
#[derive(Debug, Clone, Copy)]
struct Desc<'a> {
    /// The fixed codes of the same symbols, for the trees that have them.
    static_tree: Option<&'a [Node]>,
    /// The extra bits of each code.
    extra_bits: &'a [u8],
    /// The first symbol that `extra_bits` is about.
    extra_base: usize,
    /// The number of symbols.
    elems: usize,
    /// The longest code allowed.
    max_length: u16,
}

/// What the building of a tree works in, and what it adds up (the fields `heap`, `depth`,
/// `bl_count`, `opt_len` and `static_len` of zlib's state).
#[derive(Debug)]
struct Work {
    /// The heap: `heap[1]` is the node with the smallest count, and the sons of `heap[n]` are
    /// `heap[2n]` and `heap[2n + 1]`. Its top end collects the nodes in the order they left.
    heap: [usize; HEAP_SIZE],
    /// The number of nodes in the heap.
    heap_len: usize,
    /// The lowest index of the top end.
    heap_max: usize,
    /// The depth of the subtree under each node, which decides between equal counts.
    depth: [u8; HEAP_SIZE],
    /// The number of codes of each length.
    bl_count: [u16; MAX_BITS + 1],
    /// The length of the block in bits with the codes built for it. The C code lets it wrap
    /// below zero for a moment where it forces a code into a tree, and so does this.
    opt_len: u64,
    /// The length of the block in bits with the fixed codes.
    static_len: u64,
}

impl Work {
    /// Whether node `n` comes before node `m`: a smaller count, or an equal count and a
    /// subtree that is not deeper (`smaller`).
    fn smaller(&self, tree: &[Node], n: usize, m: usize) -> bool {
        let (count_n, count_m) = (fc(tree, n), fc(tree, m));
        count_n < count_m || (count_n == count_m && at(&self.depth, n) <= at(&self.depth, m))
    }

    /// Moves the node at `k` down the heap until both its sons come after it (`pqdownheap`).
    fn pqdownheap(&mut self, tree: &[Node], mut k: usize) {
        let v = at(&self.heap, k);
        let mut j = k << 1;
        while j <= self.heap_len {
            if j < self.heap_len && self.smaller(tree, at(&self.heap, j + 1), at(&self.heap, j)) {
                j += 1;
            }
            let son = at(&self.heap, j);
            if self.smaller(tree, v, son) {
                break;
            }
            put(&mut self.heap, k, son);
            k = j;
            j <<= 1;
        }
        put(&mut self.heap, k, v);
    }

    /// Builds the Huffman tree of the counts in `tree`, gives every symbol the length and the
    /// value of its code, and adds the bits of the block to `opt_len` and `static_len`.
    /// Returns the largest symbol that has a code (`build_tree`).
    fn build_tree(&mut self, tree: &mut [Node], desc: &Desc<'_>) -> usize {
        let mut max_code = None;
        self.heap_len = 0;
        self.heap_max = HEAP_SIZE;
        for n in 0..desc.elems {
            if fc(tree, n) == 0 {
                set_dl(tree, n, 0);
            } else {
                self.heap_len += 1;
                put(&mut self.heap, self.heap_len, n);
                max_code = Some(n);
                put(&mut self.depth, n, 0);
            }
        }

        // The format wants two codes in a tree at least. A tree with fewer gets symbol 0 or 1
        // with a count of one, and the bit that costs is taken off again in advance.
        while self.heap_len < 2 {
            let node = match max_code {
                Some(largest) if largest >= 2 => 0,
                smaller => {
                    let next = smaller.map_or(0, |largest| largest + 1);
                    max_code = Some(next);
                    next
                },
            };
            self.heap_len += 1;
            put(&mut self.heap, self.heap_len, node);
            set_fc(tree, node, 1);
            put(&mut self.depth, node, 0);
            self.opt_len = self.opt_len.wrapping_sub(1);
            if let Some(static_tree) = desc.static_tree {
                self.static_len = self.static_len.wrapping_sub(u64::from(dl(static_tree, node)));
            }
        }
        let max_code = max_code.unwrap_or(0);

        for n in (1..=self.heap_len / 2).rev() {
            self.pqdownheap(tree, n);
        }

        // the two nodes with the smallest counts become the sons of a new node, until one is left
        let mut node = desc.elems;
        loop {
            let n = at(&self.heap, 1);
            let moved = at(&self.heap, self.heap_len);
            put(&mut self.heap, 1, moved);
            self.heap_len -= 1;
            self.pqdownheap(tree, 1);
            let m = at(&self.heap, 1);

            self.heap_max -= 1;
            put(&mut self.heap, self.heap_max, n);
            self.heap_max -= 1;
            put(&mut self.heap, self.heap_max, m);

            set_fc(tree, node, fc(tree, n).wrapping_add(fc(tree, m)));
            let deeper = at(&self.depth, n).max(at(&self.depth, m));
            put(&mut self.depth, node, deeper.wrapping_add(1));
            let parent = low16(node);
            set_dl(tree, n, parent);
            set_dl(tree, m, parent);

            put(&mut self.heap, 1, node);
            node += 1;
            self.pqdownheap(tree, 1);
            if self.heap_len < 2 {
                break;
            }
        }
        self.heap_max -= 1;
        let root = at(&self.heap, 1);
        put(&mut self.heap, self.heap_max, root);

        self.gen_bitlen(tree, desc, max_code);
        gen_codes(tree, max_code, &self.bl_count);
        max_code
    }

    /// Gives every symbol the length of its code: its depth in the tree, and less where the
    /// tree is deeper than the longest code allowed (`gen_bitlen`).
    fn gen_bitlen(&mut self, tree: &mut [Node], desc: &Desc<'_>, max_code: usize) {
        self.bl_count = [0; MAX_BITS + 1];
        set_dl(tree, at(&self.heap, self.heap_max), 0);

        let mut overflow = 0_i32;
        for h in self.heap_max + 1..HEAP_SIZE {
            let n = at(&self.heap, h);
            let mut bits = dl(tree, usize::from(dl(tree, n))) + 1;
            if bits > desc.max_length {
                bits = desc.max_length;
                overflow += 1;
            }
            set_dl(tree, n, bits);
            if n > max_code {
                continue;
            }
            adjust(&mut self.bl_count, usize::from(bits), 1);
            let xbits = if n >= desc.extra_base { u64::from(at(desc.extra_bits, n - desc.extra_base)) } else { 0 };
            let f = u64::from(fc(tree, n));
            self.opt_len = self.opt_len.wrapping_add(f * (u64::from(bits) + xbits));
            if let Some(static_tree) = desc.static_tree {
                self.static_len = self.static_len.wrapping_add(f * (u64::from(dl(static_tree, n)) + xbits));
            }
        }
        if overflow == 0 {
            return;
        }

        // too deep: one leaf moves down a level and takes a leaf of the last level as its brother
        let max_length = usize::from(desc.max_length);
        while overflow > 0 {
            let mut bits = max_length - 1;
            while bits > 0 && at(&self.bl_count, bits) == 0 {
                bits -= 1;
            }
            adjust(&mut self.bl_count, bits, -1);
            adjust(&mut self.bl_count, bits + 1, 2);
            adjust(&mut self.bl_count, max_length, -1);
            overflow -= 2;
        }

        // the lengths are dealt out again, the longest to the symbols with the smallest counts
        let mut h = HEAP_SIZE;
        for bits in (1..=desc.max_length).rev() {
            let mut n = at(&self.bl_count, usize::from(bits));
            while n != 0 && h > 0 {
                h -= 1;
                let m = at(&self.heap, h);
                if m > max_code {
                    continue;
                }
                let len = dl(tree, m);
                if len != bits {
                    let change = u64::from(bits).wrapping_sub(u64::from(len)).wrapping_mul(u64::from(fc(tree, m)));
                    self.opt_len = self.opt_len.wrapping_add(change);
                    set_dl(tree, m, bits);
                }
                n -= 1;
            }
        }
    }
}

/// The bits that are not yet a whole number of bytes, and the output of the rest (`bi_buf`,
/// `bi_valid` and `send_bits`). Bits go out lowest first.
#[derive(Debug, Default)]
struct BitWriter {
    /// The bits not yet written, the oldest lowest.
    buf: u64,
    /// The number of them, below 32 between calls.
    valid: u32,
}

impl BitWriter {
    /// Writes the low `length` bits of `value`, at most 16 (`send_bits`).
    fn send(&mut self, out: &mut Vec<u8>, value: u16, length: u16) {
        self.buf |= u64::from(value) << self.valid;
        self.valid += u32::from(length);
        if self.valid >= 32 {
            let [a, b, c, d, ..] = self.buf.to_le_bytes();
            out.extend_from_slice(&[a, b, c, d]);
            self.buf >>= 32;
            self.valid -= 32;
        }
    }

    /// Writes the code of a symbol (`send_code`).
    fn send_code(&mut self, out: &mut Vec<u8>, node: Node) {
        self.send(out, node.fc, node.dl);
    }

    /// Writes the bits that are left and fills the last byte with zero bits (`bi_windup`).
    fn windup(&mut self, out: &mut Vec<u8>) {
        let bytes = self.buf.to_le_bytes();
        let pending = usize::try_from(self.valid.div_ceil(8)).unwrap_or(0);
        out.extend(bytes.iter().take(pending));
        self.buf = 0;
        self.valid = 0;
    }
}

/// Where the two programs differ in their blocks.
#[derive(Debug, Clone, Copy)]
pub(super) struct Rules {
    /// The number of symbols that ends a block: one less than `lit_bufsize` of zlib, which
    /// comes from its memory level, and one less than `LIT_BUFSIZE` of zip.
    pub block_symbols: usize,
    /// Every block that is not stored has the fixed codes (`Z_FIXED` of zlib).
    pub fixed: bool,
    /// A file that is one block and is not smaller packed is stored by the program as a
    /// whole, with method 0 (`flush_block` of zip). Nothing is written differently for that:
    /// the fact is kept, for [`Blocks::stores_file`].
    pub stores_file: bool,
}

/// The symbols of the block that is being made, the trees, and the bits on their way out.
#[derive(Debug)]
pub(super) struct Blocks {
    /// The tables that do not depend on the input.
    tables: &'static Tables,
    /// The literal and length tree of the block (`dyn_ltree`).
    dyn_ltree: [Node; HEAP_SIZE],
    /// The distance tree of the block (`dyn_dtree`).
    dyn_dtree: [Node; 2 * D_CODES + 1],
    /// The tree of the bit lengths of the other two (`bl_tree`).
    bl_tree: [Node; 2 * BL_CODES + 1],
    /// What a tree is built in.
    work: Work,
    /// The distance of every symbol of the block, zero for a literal (`sym_buf` of zlib,
    /// `d_buf` and `flag_buf` of zip).
    dists: Vec<u16>,
    /// The byte of every literal, and the length less three of every match (`l_buf`).
    lits: Vec<u8>,
    /// The number of matches in the block (`matches` of zlib, `last_dist` of zip).
    matches: usize,
    /// The bit output.
    bits: BitWriter,
    /// What the program does its own way.
    rules: Rules,
    /// A block has been written.
    written: bool,
    /// The program stores this file as a whole: see [`Rules::stores_file`].
    stores_file: bool,
}

impl Blocks {
    /// The state before the first symbol (`_tr_init`).
    pub(super) fn new(rules: Rules) -> Self {
        let mut blocks = Self {
            tables: &TABLES,
            dyn_ltree: [Node::default(); HEAP_SIZE],
            dyn_dtree: [Node::default(); 2 * D_CODES + 1],
            bl_tree: [Node::default(); 2 * BL_CODES + 1],
            work: Work { heap: [0; HEAP_SIZE], heap_len: 0, heap_max: 0, depth: [0; HEAP_SIZE], bl_count: [0; MAX_BITS + 1], opt_len: 0, static_len: 0 },
            dists: Vec::with_capacity(rules.block_symbols),
            lits: Vec::with_capacity(rules.block_symbols),
            matches: 0,
            bits: BitWriter::default(),
            rules,
            written: false,
            stores_file: false,
        };
        blocks.init_block();
        blocks
    }

    /// Whether the program stores the file as a whole instead of writing the stream. Known
    /// once the last block is flushed.
    pub(super) fn stores_file(&self) -> bool {
        self.stores_file
    }

    /// Starts a block: no symbols, and one end of block to count (`init_block`).
    fn init_block(&mut self) {
        for node in self.dyn_ltree.iter_mut().take(L_CODES) {
            node.fc = 0;
        }
        for node in self.dyn_dtree.iter_mut().take(D_CODES) {
            node.fc = 0;
        }
        for node in self.bl_tree.iter_mut().take(BL_CODES) {
            node.fc = 0;
        }
        set_fc(&mut self.dyn_ltree, END_BLOCK, 1);
        self.work.opt_len = 0;
        self.work.static_len = 0;
        self.dists.clear();
        self.lits.clear();
        self.matches = 0;
    }

    /// Takes a literal into the block. Returns whether the block is full (`_tr_tally_lit`).
    pub(super) fn tally_lit(&mut self, byte: u8) -> bool {
        self.dists.push(0);
        self.lits.push(byte);
        count(&mut self.dyn_ltree, usize::from(byte), 1);
        self.lits.len() >= self.rules.block_symbols
    }

    /// Takes a match into the block: its distance, and its length less three. Returns whether
    /// the block is full (`_tr_tally_dist`).
    pub(super) fn tally_dist(&mut self, dist: usize, length: usize) -> bool {
        let dist = low16(dist);
        let length = low8(length);
        self.dists.push(dist);
        self.lits.push(length);
        self.matches += 1;
        count(&mut self.dyn_ltree, usize::from(at(&self.tables.length_code, usize::from(length))) + LITERALS + 1, 1);
        count(&mut self.dyn_dtree, self.tables.d_code(dist.wrapping_sub(1)), 1);
        self.lits.len() >= self.rules.block_symbols
    }

    /// The guess of zip, made after every 4096 symbols, that the block is better ended here:
    /// under half of its symbols are matches, and its bytes pack to under half (`ct_tally`
    /// of zip: "Try to guess if it is profitable to stop the current block here"). `in_length`
    /// is the number of bytes the block stands for so far.
    pub(super) fn guesses_end(&self, in_length: u64) -> bool {
        let last_lit = self.lits.len();
        if last_lit & 0xfff != 0 {
            return false;
        }
        let symbols = u64::try_from(last_lit).unwrap_or(u64::MAX);
        let mut out_length = symbols * 8;
        for (node, extra) in self.dyn_dtree.iter().zip(EXTRA_DBITS) {
            out_length += u64::from(node.fc) * (5 + u64::from(extra));
        }
        out_length >>= 3;
        self.matches < last_lit / 2 && out_length < in_length / 2
    }

    /// Counts the codes that the lengths of a tree are sent with (`scan_tree`).
    fn scan_tree(bl_tree: &mut [Node], tree: &mut [Node], max_code: usize) {
        let mut prevlen = None;
        let mut nextlen = dl(tree, 0);
        let mut run = 0_u16;
        let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };
        // the guard: no length is equal to it, so the last run ends at the last code
        set_dl(tree, max_code + 1, 0xffff);

        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = dl(tree, n + 1);
            run += 1;
            if run < max_count && curlen == nextlen {
                continue;
            }
            if run < min_count {
                count(bl_tree, usize::from(curlen), run);
            } else if curlen != 0 {
                if prevlen != Some(curlen) {
                    count(bl_tree, usize::from(curlen), 1);
                }
                count(bl_tree, REP_3_6, 1);
            } else if run <= 10 {
                count(bl_tree, REPZ_3_10, 1);
            } else {
                count(bl_tree, REPZ_11_138, 1);
            }
            run = 0;
            prevlen = Some(curlen);
            (max_count, min_count) = Self::run_limits(curlen, nextlen);
        }
    }

    /// The longest and the shortest run that a repeat code is used for, from the length the
    /// run before was of and the one this run is of (the tail of the loops of `scan_tree` and
    /// `send_tree`).
    fn run_limits(curlen: u16, nextlen: u16) -> (u16, u16) {
        if nextlen == 0 {
            (138, 3)
        } else if curlen == nextlen {
            (6, 3)
        } else {
            (7, 4)
        }
    }

    /// Writes the lengths of a tree with the codes of the bit length tree (`send_tree`).
    fn send_tree(&mut self, out: &mut Vec<u8>, literals: bool, max_code: usize) {
        let tree: &[Node] = if literals { &self.dyn_ltree } else { &self.dyn_dtree };
        let mut prevlen = None;
        let mut nextlen = dl(tree, 0);
        let mut run = 0_u16;
        let (mut max_count, mut min_count) = if nextlen == 0 { (138, 3) } else { (7, 4) };

        for n in 0..=max_code {
            let curlen = nextlen;
            nextlen = dl(tree, n + 1);
            run += 1;
            if run < max_count && curlen == nextlen {
                continue;
            }
            let code = at(&self.bl_tree, usize::from(curlen));
            if run < min_count {
                for _ in 0..run {
                    self.bits.send_code(out, code);
                }
            } else if curlen != 0 {
                if prevlen != Some(curlen) {
                    self.bits.send_code(out, code);
                    run -= 1;
                }
                self.bits.send_code(out, at(&self.bl_tree, REP_3_6));
                self.bits.send(out, run.wrapping_sub(3), 2);
            } else if run <= 10 {
                self.bits.send_code(out, at(&self.bl_tree, REPZ_3_10));
                self.bits.send(out, run - 3, 3);
            } else {
                self.bits.send_code(out, at(&self.bl_tree, REPZ_11_138));
                self.bits.send(out, run - 11, 7);
            }
            run = 0;
            prevlen = Some(curlen);
            (max_count, min_count) = Self::run_limits(curlen, nextlen);
        }
    }

    /// Builds the tree of the bit lengths, and returns the index in [`BL_ORDER`] of the last
    /// length that has to be sent (`build_bl_tree`).
    fn build_bl_tree(&mut self, l_max_code: usize, d_max_code: usize) -> usize {
        Self::scan_tree(&mut self.bl_tree, &mut self.dyn_ltree, l_max_code);
        Self::scan_tree(&mut self.bl_tree, &mut self.dyn_dtree, d_max_code);
        let _: usize = self.work.build_tree(&mut self.bl_tree, &Desc { static_tree: None, extra_bits: &EXTRA_BLBITS, extra_base: 0, elems: BL_CODES, max_length: MAX_BL_BITS });

        // the format wants four of the lengths at least
        let mut max_blindex = BL_CODES - 1;
        while max_blindex >= 3 && dl(&self.bl_tree, usize::from(at(&BL_ORDER, max_blindex))) == 0 {
            max_blindex -= 1;
        }
        let sent = u64::try_from(max_blindex + 1).unwrap_or(0);
        self.work.opt_len = self.work.opt_len.wrapping_add(3 * sent + 5 + 5 + 4);
        max_blindex
    }

    /// Writes the head of a dynamic block: the three counts, the lengths of the bit length
    /// codes, and the two trees (`send_all_trees`).
    fn send_all_trees(&mut self, out: &mut Vec<u8>, l_max_code: usize, d_max_code: usize, max_blindex: usize) {
        self.bits.send(out, low16((l_max_code + 1).saturating_sub(257)), 5);
        self.bits.send(out, low16(d_max_code), 5);
        self.bits.send(out, low16((max_blindex + 1).saturating_sub(4)), 4);
        for symbol in BL_ORDER.iter().take(max_blindex + 1) {
            self.bits.send(out, dl(&self.bl_tree, usize::from(*symbol)), 3);
        }
        self.send_tree(out, true, l_max_code);
        self.send_tree(out, false, d_max_code);
    }

    /// Writes the symbols of the block and the end of block, with the fixed codes or with the
    /// codes built for the block (`compress_block`).
    fn compress_block(&mut self, out: &mut Vec<u8>, fixed: bool) {
        let tables = self.tables;
        let (ltree, dtree): (&[Node], &[Node]) = if fixed { (&tables.static_ltree, &tables.static_dtree) } else { (&self.dyn_ltree, &self.dyn_dtree) };
        for (&dist, &lc) in self.dists.iter().zip(&self.lits) {
            if dist == 0 {
                self.bits.send_code(out, at(ltree, usize::from(lc)));
                continue;
            }
            let code = usize::from(at(&tables.length_code, usize::from(lc)));
            self.bits.send_code(out, at(ltree, code + LITERALS + 1));
            let extra = at(&EXTRA_LBITS, code);
            if extra != 0 {
                self.bits.send(out, u16::from(lc).wrapping_sub(at(&tables.base_length, code)), u16::from(extra));
            }
            let dist = dist - 1;
            let code = tables.d_code(dist);
            self.bits.send_code(out, at(dtree, code));
            let extra = at(&EXTRA_DBITS, code);
            if extra != 0 {
                self.bits.send(out, dist.wrapping_sub(at(&tables.base_dist, code)), u16::from(extra));
            }
        }
        self.bits.send_code(out, at(ltree, END_BLOCK));
    }

    /// Writes a stored block: the bytes of the input as they are (`_tr_stored_block` of zlib,
    /// `copy_block` of zip).
    fn stored_block(&mut self, out: &mut Vec<u8>, buf: &[u8], last: bool) {
        self.bits.send(out, u16::from(last), 3);
        self.bits.windup(out);
        let [low, high, ..] = buf.len().to_le_bytes();
        out.extend_from_slice(&[low, high, !low, !high]);
        out.extend_from_slice(buf);
    }

    /// Ends the block: writes it the shortest of the three ways, and starts the next
    /// (`_tr_flush_block` of zlib, `flush_block` of zip). `buf` holds the bytes the block
    /// stands for, or nothing when the window no longer has them all, and `stored_len` is
    /// their number in both cases. `last` ends the stream.
    pub(super) fn flush_block(&mut self, out: &mut Vec<u8>, buf: Option<&[u8]>, stored_len: u64, last: bool) {
        let tables = self.tables;
        let l_max_code = self.work.build_tree(&mut self.dyn_ltree, &Desc { static_tree: Some(&tables.static_ltree), extra_bits: &EXTRA_LBITS, extra_base: LITERALS + 1, elems: L_CODES, max_length: 15 });
        let d_max_code = self.work.build_tree(&mut self.dyn_dtree, &Desc { static_tree: Some(&tables.static_dtree), extra_bits: &EXTRA_DBITS, extra_base: 0, elems: D_CODES, max_length: 15 });
        let max_blindex = self.build_bl_tree(l_max_code, d_max_code);

        // the lengths in bytes, with the three bits of the block header
        let mut opt_lenb = self.work.opt_len.wrapping_add(3 + 7) >> 3;
        let static_lenb = self.work.static_len.wrapping_add(3 + 7) >> 3;
        if static_lenb <= opt_lenb || self.rules.fixed {
            opt_lenb = static_lenb;
        }

        // zip: "If compression failed and this is the first and last block, the whole file is
        // transformed into a stored file". It does so only where it can seek back to rewrite
        // the header of the entry. The stream goes on here as it does where zip cannot.
        if self.rules.stores_file && last && !self.written && stored_len <= opt_lenb {
            self.stores_file = true;
        }

        match buf {
            Some(buf) if stored_len.saturating_add(4) <= opt_lenb => self.stored_block(out, buf, last),
            _ if static_lenb == opt_lenb => {
                self.bits.send(out, 2 + u16::from(last), 3);
                self.compress_block(out, true);
            },
            _ => {
                self.bits.send(out, 4 + u16::from(last), 3);
                self.send_all_trees(out, l_max_code, d_max_code, max_blindex);
                self.compress_block(out, false);
            },
        }
        self.init_block();
        self.written = true;
        if last {
            self.bits.windup(out);
        }
    }
}
