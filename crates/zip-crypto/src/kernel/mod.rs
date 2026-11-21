//! The search for one candidate: every state of the cipher that fits eight known bytes in a
//! row and has the candidate as its third key before the last of them.
//!
//! There are four kernels and they answer alike: the same keys for the same candidate, and
//! the same count of lists made on the way. The reference is the search of bkcrack as it is
//! written there. The other three do the same work as flat loops over arrays: one list at a
//! time, eight at a time with AVX2, and sixteen at a time with AVX-512.

#[cfg(target_arch = "x86_64")]
mod avx2;
#[cfg(target_arch = "x86_64")]
mod avx512;
mod port;
mod scalar;

use crate::Keys;
use crate::reduce::WINDOW;

/// Eight known bytes in a row with the stream bytes that encrypted them: what a kernel works
/// on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// The stream bytes: each known byte exclusive-or its byte in the archive.
    pub stream: [u8; WINDOW],
    /// The known bytes.
    pub plain: [u8; WINDOW],
}

impl Window {
    /// The window that ends at `index` of a run, from the run and its stream bytes. `None`
    /// when the run does not hold the eight bytes that end there.
    #[must_use]
    pub fn of(plain: &[u8], stream: &[u8], index: usize) -> Option<Self> {
        let start = index.checked_sub(WINDOW - 1)?;
        let end = index.checked_add(1)?;
        Some(Self { stream: stream.get(start..end)?.try_into().ok()?, plain: plain.get(start..end)?.try_into().ok()? })
    }
}

/// One state of the cipher that fits a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hit {
    /// The keys before the first byte of the window.
    pub before: Keys,
    /// The keys after its last byte.
    pub after: Keys,
}

/// How many values of the second key a fast kernel takes through all its levels at once. The
/// arrays of a block stay in the cache of a core.
const BLOCK: u32 = 512;

/// The most lists a block can hold at any level: each value of the block has at most two
/// bytes that fit at the first level, and each list at most two at each of the four below.
const CAPACITY: usize = BLOCK as usize * 2 * 16;

/// What one thread needs for a search, and keeps from one candidate to the next.
#[derive(Debug)]
pub struct Scratch {
    /// The partial lists of the block that is worked on.
    lists: Lists,
    /// The lists of the third key that are not complete yet.
    stack: Vec<(usize, [u32; WINDOW])>,
}

/// The partial lists of a block, each array twice: the level that is read and the one that is
/// written.
#[derive(Debug)]
struct Lists {
    /// The second key of each list.
    y: [Vec<u32>; 2],
    /// The low bytes of the first key that each list has gathered so far.
    x: [Vec<u32>; 2],
    /// The second key each list started from, at place 7.
    origin: [Vec<u32>; 2],
}

impl Scratch {
    /// The arrays of one thread: under 400 KiB.
    #[must_use]
    pub fn new() -> Self {
        // a vector kernel reads and writes up to sixteen words at a time, to the end of a list and past it
        let array = || vec![0_u32; CAPACITY + 16];
        Self { lists: Lists { y: [array(), array()], x: [array(), array()], origin: [array(), array()] }, stack: Vec::with_capacity(64) }
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

/// A way to do the search of one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kernel {
    /// The search of bkcrack as it is written there: a recursion over one list at a time. It
    /// is what the others are tested against.
    Reference,
    /// The same search as flat loops over arrays, with one table that gives the byte that
    /// fits. It runs on every processor.
    Scalar,
    /// The flat loops eight lists at a time, for a processor with AVX2.
    Avx2,
    /// The flat loops sixteen lists at a time, for a processor with AVX-512 (F, BW, DQ, VL)
    /// and BMI2.
    Avx512,
}

impl Kernel {
    /// Every kernel, the reference first.
    pub const ALL: [Self; 4] = [Self::Reference, Self::Scalar, Self::Avx2, Self::Avx512];

    /// The kernel of the widest registers this processor has. Which of two vector kernels
    /// is the faster depends on the processor: [`Kernel::vector`] lists both for a caller
    /// that measures.
    #[must_use]
    pub fn best() -> Self {
        Self::vector().first().copied().unwrap_or(Self::Scalar)
    }

    /// The vector kernels this processor runs, the one of the widest registers first.
    #[must_use]
    pub fn vector() -> Vec<Self> {
        [Self::Avx512, Self::Avx2].into_iter().filter(|kernel| kernel.is_supported()).collect()
    }

    /// The kernel of a name, as [`Kernel::name`] gives it.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kernel| kernel.name() == name)
    }

    /// Whether this processor runs the kernel.
    #[must_use]
    pub fn is_supported(self) -> bool {
        match self {
            Self::Reference | Self::Scalar => true,
            Self::Avx2 => avx2_is_there(),
            Self::Avx512 => avx512_is_there(),
        }
    }

    /// The name of the kernel, as a plan and a note show it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Reference => "reference",
            Self::Scalar => "scalar",
            Self::Avx2 => "avx2",
            Self::Avx512 => "avx512",
        }
    }

    /// Search one candidate: `z7` is bits 2 to 31 of the third key before the last byte of
    /// the window. Every state that fits the window is added to `hits`. Returns how many lists
    /// of the second key were completed, which is the same for every kernel.
    ///
    /// A kernel the processor does not run is replaced by the scalar one.
    pub fn search(self, window: &Window, z7: u32, scratch: &mut Scratch, hits: &mut Vec<Hit>) -> u64 {
        match self {
            Self::Reference => port::search(window, z7, hits),
            Self::Avx512 if avx512_is_there() => avx512_search(window, z7, scratch, hits),
            Self::Avx2 if avx2_is_there() => avx2_search(window, z7, scratch, hits),
            Self::Scalar | Self::Avx2 | Self::Avx512 => scalar::search(window, z7, scratch, hits),
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn avx512_is_there() -> bool {
    std::arch::is_x86_feature_detected!("avx512f") && std::arch::is_x86_feature_detected!("avx512bw") && std::arch::is_x86_feature_detected!("avx512dq") && std::arch::is_x86_feature_detected!("avx512vl") && std::arch::is_x86_feature_detected!("bmi2") && std::arch::is_x86_feature_detected!("popcnt")
}

#[cfg(not(target_arch = "x86_64"))]
const fn avx512_is_there() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn avx512_search(window: &Window, z7: u32, scratch: &mut Scratch, hits: &mut Vec<Hit>) -> u64 {
    // SAFETY: the one caller has just asked the processor for every feature the kernel is
    // compiled with (`avx512_is_there`), and the kernel needs nothing else of its caller.
    unsafe { avx512::search(window, z7, scratch, hits) }
}

#[cfg(not(target_arch = "x86_64"))]
fn avx512_search(window: &Window, z7: u32, scratch: &mut Scratch, hits: &mut Vec<Hit>) -> u64 {
    scalar::search(window, z7, scratch, hits)
}

#[cfg(target_arch = "x86_64")]
fn avx2_is_there() -> bool {
    std::arch::is_x86_feature_detected!("avx2") && std::arch::is_x86_feature_detected!("popcnt")
}

#[cfg(not(target_arch = "x86_64"))]
const fn avx2_is_there() -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn avx2_search(window: &Window, z7: u32, scratch: &mut Scratch, hits: &mut Vec<Hit>) -> u64 {
    // SAFETY: the one caller has just asked the processor for every feature the kernel is
    // compiled with (`avx2_is_there`), and the kernel needs nothing else of its caller.
    unsafe { avx2::search(window, z7, scratch, hits) }
}

#[cfg(not(target_arch = "x86_64"))]
fn avx2_search(window: &Window, z7: u32, scratch: &mut Scratch, hits: &mut Vec<Hit>) -> u64 {
    scalar::search(window, z7, scratch, hits)
}

/// The lists of the third key for a candidate: the values at the eight places of the window,
/// completed back from the candidate, a few for each. `each` is called with every complete
/// list and with the top bytes of the second key that follow from it, for places 1 to 7.
fn z_lists(window: &Window, z7: u32, stack: &mut Vec<(usize, [u32; WINDOW])>, mut each: impl FnMut(&[u32; WINDOW], &[u32; WINDOW])) {
    use crate::tables::crc32_inv;
    use crate::tables::mask;
    use crate::tables::y_top;
    use crate::tables::z_before_10_32;
    use crate::tables::z_low;

    stack.clear();
    let mut first = [0_u32; WINDOW];
    first[WINDOW - 1] = z7;
    stack.push((WINDOW - 1, first));
    while let Some((i, mut z)) = stack.pop() {
        if i == 0 {
            let mut tops = [0_u32; WINDOW];
            for place in 1..WINDOW {
                tops[place] = y_top(z[place], z[place - 1]);
            }
            each(&z, &tops);
            continue;
        }
        let before = z_before_10_32(z[i]);
        // pushed in reverse, so that the lists come out in the order a recursion makes them
        for &low in z_low(window.stream[i - 1], before).iter().rev() {
            z[i - 1] = before | u32::from(low);
            z[i] = (z[i] & mask(2, 32)) | ((crc32_inv(z[i] & mask(2, 32), 0) ^ z[i - 1]) >> 8);
            stack.push((i - 1, z));
        }
    }
}

/// The end of every kernel: a list that passed the test of its first key gives the keys
/// before place 7 and before place 3 of the window. They are taken to the end of the window
/// and back to its start, and the three bytes in front of place 3 have to come out right.
#[inline]
fn finish(window: &Window, at_7: Keys, at_3: Keys, hits: &mut Vec<Hit>) {
    let mut before = at_3;
    for place in (0..3).rev() {
        before.update_backward(window.plain[place] ^ window.stream[place]);
        if before.stream_byte() != window.stream[place] {
            return;
        }
    }
    let mut after = at_7;
    after.update(window.plain[WINDOW - 1]);
    hits.push(Hit { before, after });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reduce::reduce;
    use crate::tables::mask;

    /// A window under a password, with the candidate that is right for it.
    fn case(password: &[u8], plain: [u8; WINDOW]) -> (Window, u32, Hit) {
        let mut keys = Keys::from_password(password);
        for byte in 0..12 {
            let _ = keys.encrypt(byte);
        }
        let before = keys;
        let mut stream = [0_u8; WINDOW];
        let mut z7 = 0;
        for (place, &byte) in plain.iter().enumerate() {
            if place == WINDOW - 1 {
                z7 = keys.z & mask(2, 32);
            }
            stream[place] = byte ^ keys.encrypt(byte);
        }
        (Window { stream, plain }, z7, Hit { before, after: keys })
    }

    #[test]
    fn every_kernel_finds_the_keys_of_the_right_candidate() {
        for (password, plain) in [(&b"secret"[..], *b"8 bytes!"), (b"", [0; 8]), (b"a much longer password than six", [0xff, 0, 0x80, 0x7f, 1, 2, 3, 0xfe])] {
            let (window, z7, right) = case(password, plain);
            let mut scratch = Scratch::new();
            let mut answers = Vec::new();
            for kernel in Kernel::ALL {
                let mut hits = Vec::new();
                let lists = kernel.search(&window, z7, &mut scratch, &mut hits);
                assert!(hits.contains(&right), "{}: the right keys are not among {} hits", kernel.name(), hits.len());
                hits.sort_unstable();
                answers.push((lists, hits));
            }
            assert!(answers.iter().all(|answer| answer == &answers[0]), "the kernels differ");
        }
    }

    #[test]
    fn the_kernels_agree_on_candidates_that_are_wrong() {
        let (window, _, _) = case(b"agree", *b"\x89PNG\r\n\x1a\n");
        let candidates = reduce(&window.stream).unwrap().candidates;
        let mut scratch = Scratch::new();
        let (mut lists_made, mut fitting) = (0, 0);
        for &z7 in candidates.iter().step_by(candidates.len() / 24) {
            let mut answers = Vec::new();
            for kernel in Kernel::ALL {
                let mut hits = Vec::new();
                let lists = kernel.search(&window, z7, &mut scratch, &mut hits);
                hits.sort_unstable();
                answers.push((lists, hits));
            }
            assert!(answers.iter().all(|answer| answer == &answers[0]), "the kernels differ on {z7:#x}");
            lists_made += answers[0].0;
            fitting += answers[0].1.len();
        }
        // about 54,000 lists for a candidate, of which about a thousand fit all eight bytes
        assert!(lists_made > 24 * 20_000 && fitting > 24 * 300, "{lists_made} lists, {fitting} keys");
    }

    #[test]
    fn a_kernel_the_processor_lacks_is_never_the_best() {
        assert!(Kernel::best().is_supported());
        assert!(Kernel::Scalar.is_supported() && Kernel::Reference.is_supported());
        assert_eq!(Kernel::ALL.map(Kernel::name), ["reference", "scalar", "avx2", "avx512"]);
        assert!(Kernel::vector().iter().all(|kernel| kernel.is_supported()) && Kernel::vector().first().is_none_or(|first| *first == Kernel::best()));
        assert_eq!((Kernel::named("avx2"), Kernel::named("scalar"), Kernel::named("sse")), (Some(Kernel::Avx2), Some(Kernel::Scalar), None));
    }

    #[test]
    fn a_window_is_the_eight_bytes_that_end_at_its_index() {
        let plain: Vec<u8> = (0..20).collect();
        let stream: Vec<u8> = (100..120).collect();
        let window = Window::of(&plain, &stream, 12).unwrap();
        assert_eq!((window.plain, window.stream), ([5, 6, 7, 8, 9, 10, 11, 12], [105, 106, 107, 108, 109, 110, 111, 112]));
        assert!(Window::of(&plain, &stream, 6).is_none() && Window::of(&plain, &stream, 20).is_none());
        assert!(Window::of(&plain, &stream, 7).is_some() && Window::of(&plain, &stream, 19).is_some());
    }
}
