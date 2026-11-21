//! What one candidate costs with each kernel, on one thread alone and with all threads busy:
//! `cargo run --release -p archivewolf-zip-crypto --example speed`. With the names of kernels
//! behind it, as in `-- avx2 scalar`, only those are timed.
//!
//! The case is synthetic and fixed: a run of eight bytes under one password. The numbers are
//! processor time for a candidate that is searched to its end.
//!
//! The last line is the way from keys back to a password of six bytes or fewer, on one thread:
//! what it costs to learn that random keys have none, which a filter pays for every key it is
//! given, and what it costs to work out a password of six bytes from its keys.

use std::hint::black_box;
use std::time::Instant;

use archivewolf_zip_crypto::Kernel;
use archivewolf_zip_crypto::Keys;
use archivewolf_zip_crypto::Scratch;
use archivewolf_zip_crypto::Window;
use archivewolf_zip_crypto::has_short_password;
use archivewolf_zip_crypto::reduce;
use archivewolf_zip_crypto::short_passwords;

fn main() {
    let plain = *b"speed-of";
    let mut keys = Keys::from_password(b"a fixed case");
    let mut stream = [0_u8; 8];
    for (slot, &byte) in stream.iter_mut().zip(&plain) {
        *slot = byte ^ keys.encrypt(byte);
    }
    let window = Window { stream, plain };
    let Some(reduced) = reduce(&stream) else { return };
    let threads = std::thread::available_parallelism().map_or(1, |count| u32::try_from(count.get()).unwrap_or(1));
    let count: u32 = 256;

    let asked: Vec<String> = std::env::args().skip(1).collect();
    for kernel in Kernel::ALL.into_iter().filter(|kernel| kernel.is_supported() && (asked.is_empty() || asked.iter().any(|name| name == kernel.name()))) {
        let run = |offset: usize| {
            let mut scratch = Scratch::new();
            let mut hits = Vec::new();
            let mut lists = 0;
            for &z7 in reduced.candidates.iter().skip(offset * 30_011).take(count as usize) {
                hits.clear();
                lists += kernel.search(&window, z7, &mut scratch, &mut hits);
            }
            lists
        };
        let alone = Instant::now();
        let lists = run(0);
        let alone = alone.elapsed().as_secs_f64();
        let busy = Instant::now();
        std::thread::scope(|scope| {
            for thread in 0..threads {
                let _ = scope.spawn(move || run(thread as usize));
            }
        });
        let busy = busy.elapsed().as_secs_f64();
        println!("{:9}  {:.3} ms alone, {:.3} ms with {threads} threads busy, {:.0} candidates a second in all ({} lists a candidate)", kernel.name(), 1e3 * alone / f64::from(count), 1e3 * busy / f64::from(count), f64::from(count * threads) / busy, lists / u64::from(count));
    }
    if asked.is_empty() {
        password();
    }
}

/// The way from keys back to a password of six bytes or fewer, on one thread: the answer that
/// there is none for keys that have none, and the password for the keys of one of six bytes.
fn password() {
    // splitmix64 from a fixed seed: the same keys on every run
    let mut state = 0_u64;
    let mut bytes = move || {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        (z ^ (z >> 31)).to_le_bytes()
    };
    let mut word = || {
        let bytes = bytes();
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    };

    let none: u32 = 1 << 22;
    let keys: Vec<Keys> = (0..none).map(|_| Keys::new(word(), word(), word())).collect();
    let clock = Instant::now();
    let had = keys.iter().filter(|&&keys| has_short_password(black_box(keys), 6)).count();
    let filter = clock.elapsed().as_secs_f64();

    let six: u32 = 1 << 18;
    let keys: Vec<Keys> = (0..six).map(|_| Keys::from_password(&bytes()[..6])).collect();
    let clock = Instant::now();
    let found: usize = keys.iter().map(|&keys| short_passwords(black_box(keys), 6).len()).sum();
    let recovery = clock.elapsed().as_secs_f64();

    println!("{:9}  {:.1} ns for keys that have none of six bytes or fewer ({had} of {none} had one), {:.1} ns for the password of six bytes ({found} for {six} keys)", "password", 1e9 * filter / f64::from(none), 1e9 * recovery / f64::from(six));
}
