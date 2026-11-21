//! A packed stream as a filter: whether bytes can be the start of a Deflate stream.
//!
//! A wrong key turns a packed stream into noise, and noise is seldom a valid stream: the block
//! type is the reserved one in a quarter of all cases, a stored block has a length and a
//! complement that do not match in all but one of 65,536, and the code lengths of a dynamic
//! block do not make a code in nearly all. The test reads the head of the first block and no
//! more: it costs some tens of steps and removes most wrong keys before the proof.

/// The order in which a dynamic block stores the lengths of its code length code (RFC 1951,
/// section 3.2.7).
const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Bits of a stream, taken from the low end of each byte.
struct Bits<'a> {
    bytes: &'a [u8],
    at: usize,
    hold: u32,
    count: u32,
}

impl Bits<'_> {
    /// The next `count` bits, 16 at most. `None` when the bytes end first.
    fn take(&mut self, count: u32) -> Option<u32> {
        while self.count < count {
            self.hold |= u32::from(*self.bytes.get(self.at)?) << self.count;
            self.at += 1;
            self.count += 8;
        }
        let value = self.hold & ((1 << count) - 1);
        self.hold >>= count;
        self.count -= count;
        Some(value)
    }
}

/// What the lengths of a prefix code come to.
enum Code {
    /// More codes than the lengths leave room for.
    Over,
    /// Room that no code fills, with more than one code or a code longer than one bit: only a
    /// code of one bit alone may leave room.
    Incomplete,
    /// A code a decoder takes.
    Usable,
}

/// Whether lengths of up to `max` bits make a prefix code, by the rule of zlib's
/// `inflate_table`.
fn code_of(lengths: &[u8], max: u32) -> Code {
    let mut left = 1_i64;
    let mut longest = 0;
    let mut used = 0;
    for bits in 1..=max {
        let count = lengths.iter().filter(|&&length| u32::from(length) == bits).count();
        if count > 0 {
            longest = bits;
            used += count;
        }
        left = left * 2 - i64::try_from(count).unwrap_or(i64::MAX);
        if left < 0 {
            return Code::Over;
        }
    }
    if left > 0 && (used != 1 || longest != 1) && used != 0 { Code::Incomplete } else { Code::Usable }
}

/// A decoder for a code of up to seven bits: the symbol of each code, by the canonical order.
/// `None` when the lengths make no usable code.
fn small_decoder(lengths: &[u8; 19]) -> Option<Vec<(u32, u32, usize)>> {
    if !matches!(code_of(lengths, 7), Code::Usable) {
        return None;
    }
    let mut codes = Vec::new();
    let mut code = 0_u32;
    for bits in 1..=7_u32 {
        for (symbol, _) in lengths.iter().enumerate().filter(|(_, length)| u32::from(**length) == bits) {
            codes.push((bits, code, symbol));
            code += 1;
        }
        code <<= 1;
    }
    Some(codes)
}

/// Whether `stream` can be the start of a Deflate stream. `true` when its first block header
/// is one a decoder takes, and when the bytes end before that can be said.
#[must_use]
pub(crate) fn can_start(stream: &[u8]) -> bool {
    head_is_valid(stream).unwrap_or(true)
}

/// `Some(false)` for a head no decoder takes, `Some(true)` for one it takes, `None` when the
/// bytes end first.
fn head_is_valid(stream: &[u8]) -> Option<bool> {
    let mut bits = Bits { bytes: stream, at: 0, hold: 0, count: 0 };
    let _last = bits.take(1)?;
    match bits.take(2)? {
        // stored: the rest of the byte is skipped, then the length and its complement
        0 => {
            let length = stream.get(1..3)?;
            let complement = stream.get(3..5)?;
            Some(length.iter().zip(complement).all(|(a, b)| *a == !*b))
        },
        // the fixed code: nothing in its head can be wrong
        1 => Some(true),
        2 => {
            let literals = bits.take(5)? + 257;
            let distances = bits.take(5)? + 1;
            let count = usize::try_from(bits.take(4)? + 4).ok()?;
            if literals > 286 || distances > 30 {
                return Some(false);
            }
            let mut lengths = [0_u8; 19];
            for &symbol in ORDER.iter().take(count) {
                *lengths.get_mut(symbol)? = u8::try_from(bits.take(3)?).ok()?;
            }
            let Some(decoder) = small_decoder(&lengths) else { return Some(false) };
            dynamic_lengths(&mut bits, &decoder, usize::try_from(literals).ok()?, usize::try_from(distances).ok()?)
        },
        _ => Some(false),
    }
}

/// Read the code lengths of a dynamic block with the code of the code lengths, and say
/// whether they make the two codes of a block.
fn dynamic_lengths(bits: &mut Bits<'_>, decoder: &[(u32, u32, usize)], literals: usize, distances: usize) -> Option<bool> {
    let mut all: Vec<u8> = Vec::with_capacity(literals + distances);
    while all.len() < literals + distances {
        // one symbol: bits are taken one at a time, the first being the top bit of the code
        let (mut code, mut length, mut symbol) = (0_u32, 0_u32, None);
        while symbol.is_none() {
            code = (code << 1) | bits.take(1)?;
            length += 1;
            if length > 7 {
                return Some(false);
            }
            symbol = decoder.iter().find(|(bits, value, _)| *bits == length && *value == code).map(|(_, _, symbol)| *symbol);
        }
        let (value, repeat) = match symbol? {
            16 => {
                let Some(&last) = all.last() else { return Some(false) };
                (last, 3 + bits.take(2)?)
            },
            17 => (0, 3 + bits.take(3)?),
            18 => (0, 11 + bits.take(7)?),
            length => (u8::try_from(length).ok()?, 1),
        };
        if all.len() + usize::try_from(repeat).ok()? > literals + distances {
            return Some(false);
        }
        all.extend(std::iter::repeat_n(value, usize::try_from(repeat).ok()?));
    }
    let (literal_lengths, distance_lengths) = all.split_at_checked(literals)?;
    // a block has to be able to end, and both codes have to be codes
    if literal_lengths.get(256).is_none_or(|&end| end == 0) {
        return Some(false);
    }
    Some(matches!(code_of(literal_lengths, 15), Code::Usable) && matches!(code_of(distance_lengths, 15), Code::Usable))
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn packed(data: &[u8], level: u32) -> Vec<u8> {
        let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(level));
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// Bytes that look like noise, the same every run.
    fn noise(count: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..count)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[3]
            })
            .collect()
    }

    #[test]
    fn the_start_of_every_real_stream_is_taken() {
        let text: Vec<u8> = (0..4000_u32).flat_map(|n| format!("line {n}: the quick brown fox\n").into_bytes()).collect();
        for data in [&b""[..], b"a", b"hello hello hello hello", &text, &noise(70_000, 9)] {
            for level in [0, 1, 6, 9] {
                let stream = packed(data, level);
                for probe in [1, 2, 5, 16, 64, 200] {
                    assert!(can_start(&stream[..probe.min(stream.len())]), "{} bytes at level {level}, {probe} of them", data.len());
                }
            }
        }
    }

    #[test]
    fn noise_is_seldom_the_start_of_a_stream() {
        let mut taken = 0;
        let trials = 20_000_u64;
        for trial in 0..trials {
            if can_start(&noise(64, trial * 7919 + 1)) {
                taken += 1;
            }
        }
        // a quarter is the fixed code, which says nothing; of the rest hardly any is left
        assert!((4_500..5_500).contains(&taken), "{taken} of {trials}");
        // bytes that end before the head is read decide nothing
        assert!(can_start(&[]) && can_start(&[0x05]) && can_start(&[0x00, 0x01]));
        // the reserved block type, and a stored block whose complement is wrong
        assert!(!can_start(&[0x07]) && !can_start(&[0x01, 0x05, 0x00, 0xfa, 0xfe]) && can_start(&[0x01, 0x05, 0x00, 0xfa, 0xff]));
    }
}
