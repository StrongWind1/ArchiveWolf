//! The kernels on the case the design of `attack zip-crypto` was measured on.
//!
//! `tests/data/spiral.cipher.bin` is the entry `spiral.svg` of the example archive of bkcrack with
//! its encryption header, and `spiral.plain21.bin` its check byte and its first twenty bytes. The
//! numbers held here are those that bkcrack 1.8.1 and the model that is proved in Lean give for
//! the same case.

#[cfg(test)]
mod tests {
    use archivewolf_zip_crypto::Hit;
    use archivewolf_zip_crypto::Kernel;
    use archivewolf_zip_crypto::Keys;
    use archivewolf_zip_crypto::Scratch;
    use archivewolf_zip_crypto::Window;
    use archivewolf_zip_crypto::reduce;

    /// Where the first known byte lies in the entry: the check byte, the last of the header.
    const OFFSET: usize = 11;

    /// The keys of the archive, as the tutorial of bkcrack gives them.
    const KEYS: Keys = Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31);

    /// The place of the right candidate among the candidates.
    const RIGHT: usize = 273_594;

    fn case() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let cipher = std::fs::read("tests/data/spiral.cipher.bin").unwrap();
        let plain = std::fs::read("tests/data/spiral.plain21.bin").unwrap();
        let stream = plain.iter().zip(&cipher[OFFSET..]).map(|(p, c)| p ^ c).collect();
        (cipher, plain, stream)
    }

    /// The keys at the start of the entry, for a hit whose window starts at `start` of the entry.
    fn at_the_start(cipher: &[u8], start: usize, hit: &Hit) -> Keys {
        let mut keys = hit.before;
        for &byte in cipher[..start].iter().rev() {
            keys.update_backward(byte);
        }
        keys
    }

    #[test]
    fn the_reduction_leaves_the_candidates_bkcrack_leaves_with_the_right_one_in_its_place() {
        let (cipher, _, stream) = case();
        let reduced = reduce(&stream).unwrap();
        assert_eq!((reduced.candidates.len(), reduced.index), (542_303, 7));

        // the third key before the last byte of the window, from the keys of the archive
        let mut keys = KEYS;
        for &byte in &cipher[..OFFSET + reduced.index] {
            let _ = keys.decrypt(byte);
        }
        assert_eq!(reduced.candidates.iter().position(|&z| z == keys.z & !3), Some(RIGHT));
    }

    #[test]
    fn every_kernel_makes_the_same_lists_and_finds_the_keys_of_the_archive() {
        let (cipher, plain, stream) = case();
        let reduced = reduce(&stream).unwrap();
        let window = Window::of(&plain, &stream, reduced.index).unwrap();
        let start = OFFSET + reduced.index - 7;

        let mut scratch = Scratch::new();
        for kernel in Kernel::ALL {
            let (mut around_40, mut around_400) = (0, 0);
            let mut found = Vec::new();
            for (place, &z7) in reduced.candidates.iter().enumerate().skip(RIGHT - 200).take(400) {
                let mut hits = Vec::new();
                let lists = kernel.search(&window, z7, &mut scratch, &mut hits);
                around_400 += lists;
                if (RIGHT - 20..RIGHT + 20).contains(&place) {
                    around_40 += lists;
                }
                // a hit fits the eight bytes of the window: the rest of the run tells the key from it
                for hit in hits {
                    let mut keys = hit.after;
                    if cipher[start + 8..OFFSET + plain.len()].iter().zip(&plain[reduced.index + 1..]).all(|(&c, &p)| keys.decrypt(c) == p) {
                        found.push((place, at_the_start(&cipher, start, &hit)));
                    }
                }
            }
            assert_eq!((around_40, around_400), (2_097_137, 21_758_357), "{}", kernel.name());
            assert_eq!(found, [(RIGHT, KEYS)], "{}", kernel.name());
        }
    }
}
