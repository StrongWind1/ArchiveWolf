//! The header paths of the attack on ZIP traditional encryption: what the twelve bytes of the
//! encryption headers give away when their writer did not fill them from a generator nobody
//! can predict.
//!
//! Three kinds of writers leave their headers open, and each has its module here.
//!
//! - Info-ZIP and what is built on its code fill ten bytes from `rand()` and encrypt them
//!   twice. The seed is found from the first byte of each header, for the `rand()` of each C
//!   library that `zip` is built against: [`glibc`], [`bsd`] for macOS, [`musl`] and
//!   [`msvcrt`] for Windows. [`infozip`] holds the filter that the seed gives for every key,
//!   and [`stay`] is the attack of Stay that goes from the headers to the keys.
//! - DotNetZip and SharpZipLib fill the header from `System.Random` and encrypt it once.
//!   [`dotnet`] finds the seed on the runtimes that seed it from one generator of the thread,
//!   and [`netfx`] on the .NET Framework, which seeds it with a clock: with it the bytes of
//!   every header are known as they were before encryption.
//! - `yeka/zip` writes a constant. [`yeka`] recognises it and holds its filter.
//!
//! Everything here works on header bytes and a few numbers. Nothing reads a file, parses an
//! archive or prints. A search that can take long is given a [`Control`].

pub mod bsd;
pub mod clocked;
pub mod dotnet;
pub mod fpc;
pub mod glibc;
pub mod infozip;
pub mod msvcrt;
pub mod musl;
pub mod netfx;
pub mod stay;
pub mod yeka;

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// What a long search shares with the caller that started it.
///
/// A search returns what it found. When `stop` was set before it reached its end, that is
/// what it had found so far, and the caller, who set the flag, knows that the result is not
/// the whole of it.
#[derive(Debug, Clone, Copy)]
pub struct Control<'a> {
    /// Set by the caller to end the search early. Every thread reads it between two pieces
    /// of work, each of which takes a millisecond or two at most in an optimised build.
    pub stop: &'a AtomicBool,
    /// Advanced by the search as it goes, by every thread after each piece of work. Every
    /// search documents the total it counts to. The search does not set it back to zero.
    pub done: &'a AtomicU64,
    /// How many threads the search runs on. Zero is taken as one.
    pub threads: usize,
}

impl Control<'_> {
    /// Whether the caller has ended the search.
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Count `units` of work as done.
    fn advance(&self, units: u64) {
        let _ = self.done.fetch_add(units, Ordering::Relaxed);
    }
}

/// The `rand()` of a C library after `srand(seed)`, as far as `zip` uses it.
///
/// The generator of glibc is not one of these: setting it up takes hundreds of steps, and
/// [`glibc`] has a search of its own for it. These are the ones whose first value is a
/// product away from the seed.
pub trait Generator {
    /// The generator as `srand(seed)` leaves it.
    fn seeded(seed: u32) -> Self;

    /// The next value of `rand()`.
    fn rand(&mut self) -> u32;

    /// The seed that stands for every seed that gives the same values: the smallest of them.
    /// A generator that gives other values for every seed has each seed stand for itself.
    #[must_use]
    fn stream_of(seed: u32) -> u32 {
        seed
    }
}

/// The byte Info-ZIP takes of a value of `rand()` for an encryption header: bits 7 to 14.
#[must_use]
pub const fn header_byte(value: u32) -> u8 {
    (value >> 7).to_le_bytes()[0]
}

/// The ten bytes Info-ZIP drew for each of the first `entries` encrypted entries it wrote in
/// a run that was seeded with `seed`, before it encrypted them.
#[must_use]
pub fn header_bytes<G: Generator>(seed: u32, entries: usize) -> Vec<[u8; glibc::HEADER_BYTES]> {
    let mut generator = G::seeded(seed);
    (0..entries).map(|_| std::array::from_fn(|_| header_byte(generator.rand()))).collect()
}

/// Whether `seed` gives the first header byte of every entry: `first` holds the first byte of
/// the encryption header of each entry, in the order the entries were written. The first
/// byte of a header is a byte of the generator as it was drawn: the two passes of encryption
/// cancel there.
#[must_use]
pub fn fits<G: Generator>(seed: u32, first: &[u8]) -> bool {
    let mut generator = G::seeded(seed);
    first.iter().all(|&byte| {
        let drawn = header_byte(generator.rand());
        for _ in 1..glibc::HEADER_BYTES {
            let _ = generator.rand();
        }
        drawn == byte
    })
}

/// Every seed of a generator that gives the first header byte of every entry, among all
/// 2^32, in rising order. Seeds of one stream are all among them: [`Generator::stream_of`]
/// tells which belong together.
///
/// `first` is as for [`fits`]. Each entry is 8 bits of test against the 32 bits of a seed:
/// five entries leave the right stream alone. With no entry there is nothing to test, and
/// nothing is returned. `control.done` is advanced by one for every seed: the total is 2^32.
#[must_use]
pub fn seeds<G: Generator>(first: &[u8], control: Control<'_>) -> Vec<u32> {
    /// How many seeds one piece of the search holds.
    const PIECE: u64 = 1 << 16;
    let Some(&wanted) = first.first() else { return Vec::new() };
    let mut found = spread((1 << 32) / PIECE, control, |piece, found| {
        for seed in (piece * PIECE..(piece + 1) * PIECE).filter_map(|seed| u32::try_from(seed).ok()) {
            // the first value of a seed decides for 255 seeds of 256
            if header_byte(G::seeded(seed).rand()) == wanted && fits::<G>(seed, first) {
                found.push(seed);
            }
        }
        control.advance(PIECE);
    });
    found.sort_unstable();
    found
}

/// Where the entries of a run lie among the headers their writer drew, when it drew more
/// than it wrote.
///
/// `zip` draws the header of a file before it reads the file. A file it cannot read to its
/// end is given up and leaves no entry, and its header is drawn all the same: the entries
/// behind it are then one header further on in the values of the generator than their place
/// in the archive says. `drawn` holds the first byte of every header the generator gives, in
/// the order drawn, and `first` the first byte of the header of every entry. The answer is
/// the header each entry has, by its number among those drawn, with the first entry at the
/// first header and at most `spare` headers left out between the others, and of the ways
/// there are the one that leaves out fewest. `None` when there is no way.
#[must_use]
pub fn places(drawn: &[u8], first: &[u8], spare: usize) -> Option<Vec<usize>> {
    /// Go on behind the entries that have a place: the next entry at each header that
    /// `left` still allows and whose first byte is its own.
    fn follow(drawn: &[u8], first: &[u8], left: usize, places: &mut Vec<usize>) -> bool {
        let Some(&wanted) = first.get(places.len()) else { return left == 0 };
        let Some(&last) = places.last() else { return false };
        for skipped in 0..=left {
            let at = last + 1 + skipped;
            if drawn.get(at) == Some(&wanted) {
                places.push(at);
                if follow(drawn, first, left - skipped, places) {
                    return true;
                }
                let _ = places.pop();
            }
        }
        false
    }
    if drawn.first()? != first.first()? {
        return None;
    }
    (0..=spare).find_map(|skipped| {
        let mut places = vec![0];
        follow(drawn, first, skipped, &mut places).then_some(places)
    })
}

/// How many headers a writer may have drawn and not written for a search to say anything of
/// an archive of `entries` entries: the most with which a seed that is not the seed fits
/// less than once in four searches of all 2^32. None with four entries, whose first bytes
/// are as many bits as a seed has.
#[must_use]
pub fn spare_for(entries: usize) -> usize {
    let free = entries.saturating_sub(4).min(8);
    // the ways to leave `spare` headers out in front of the entries behind the first: a
    // binomial coefficient, held against 256 to the power of the entries beyond four
    let ways = |spare: usize| (1..=spare).fold(1.0_f64, |ways, step| ways * f64::from(u32::try_from(entries - 1 + step).unwrap_or(u32::MAX)) / f64::from(u32::try_from(step).unwrap_or(1)));
    let room = 256.0_f64.powi(i32::try_from(free).unwrap_or(8)) / 4.0;
    (0..=8).rev().find(|&spare| (0..=spare).map(ways).sum::<f64>() <= room).unwrap_or(0)
}

/// The first byte of each of the first `draws` headers a writer draws after `seed`.
#[must_use]
pub fn drawn<G: Generator>(seed: u32, draws: usize) -> Vec<u8> {
    let mut generator = G::seeded(seed);
    (0..draws)
        .map(|_| {
            let first = header_byte(generator.rand());
            for _ in 1..glibc::HEADER_BYTES {
                let _ = generator.rand();
            }
            first
        })
        .collect()
}

/// Every seed of a generator that gives the first header byte of every entry when up to
/// `spare` headers were drawn and not written, among all 2^32, in rising order. As [`seeds`]
/// otherwise: `control.done` counts to 2^32.
#[must_use]
pub fn seeds_with_gaps<G: Generator>(first: &[u8], spare: usize, control: Control<'_>) -> Vec<u32> {
    /// How many seeds one piece of the search holds.
    const PIECE: u64 = 1 << 16;
    let Some(&wanted) = first.first() else { return Vec::new() };
    let mut found = spread((1 << 32) / PIECE, control, |piece, found| {
        for seed in (piece * PIECE..(piece + 1) * PIECE).filter_map(|seed| u32::try_from(seed).ok()) {
            if header_byte(G::seeded(seed).rand()) == wanted && places(&drawn::<G>(seed, first.len() + spare), first, spare).is_some() {
                found.push(seed);
            }
        }
        control.advance(PIECE);
    });
    found.sort_unstable();
    found
}

/// Run `work` once for each of the pieces `0..pieces` on the threads of `control`, and gather
/// what the pieces put into their lists.
///
/// The threads take the pieces one after the other from a shared counter, so the order of
/// what comes back depends on the run: a caller sorts it. No piece is started once the search
/// was stopped.
fn spread<T, F>(pieces: u64, control: Control<'_>, work: F) -> Vec<T>
where
    T: Send,
    F: Fn(u64, &mut Vec<T>) + Sync,
{
    let next = AtomicU64::new(0);
    let threads = u64::try_from(control.threads).unwrap_or(u64::MAX).clamp(1, pieces.max(1));
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut found = Vec::new();
                    while !control.stopped() {
                        let piece = next.fetch_add(1, Ordering::Relaxed);
                        if piece >= pieces {
                            break;
                        }
                        work(piece, &mut found);
                    }
                    found
                })
            })
            .collect();
        // a thread that panicked passes its panic on to the caller
        workers.into_iter().flat_map(|worker| worker.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))).collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::zip_crypto::pool::Pool;

    /// The headers that the tests of this module hold are those of the fixtures: the twelve
    /// bytes in front of the data of every entry, in the order the entries lie in the archive.
    #[test]
    fn the_recorded_headers_are_those_of_the_fixtures() {
        let recorded: [(&str, &[[u8; 12]]); 16] = [
            ("gen_doublecmd_first.zip", &fpc::tests::FIRST_HEADERS),
            ("gen_doublecmd_second.zip", &fpc::tests::SECOND_HEADERS),
            ("gen_ziparchive_glibc.zip", &clocked::tests::ZIPARCHIVE_GLIBC),
            ("gen_ziparchive_win.zip", &clocked::tests::ZIPARCHIVE_WIN),
            ("gen_ziputils_win.zip", &clocked::tests::ZIPUTILS_WIN),
            ("gen_infozip_musl.zip", &musl::tests::HEADERS),
            ("gen_infozip_win.zip", &msvcrt::tests::HEADERS),
            ("gen_minizip_glibc.zip", &infozip::tests::MINIZIP_HEADERS),
            ("gen_infozip_six.zip", &infozip::tests::SIX_HEADERS),
            ("gen_infozip_four.zip", &infozip::tests::FOUR_HEADERS),
            ("gen_sharpziplib_net5.zip", &dotnet::tests::SHARP_NET5),
            ("gen_dotnetzip_net5.zip", &dotnet::tests::DOTNETZIP_NET5),
            ("gen_sharpziplib_net9.zip", &dotnet::tests::SHARP_NET9),
            ("gen_yeka_a.zip", &yeka::tests::HEADERS),
            ("gen_yeka_b.zip", &yeka::tests::HEADERS),
            ("gen_yeka_c.zip", &yeka::tests::OTHER_HEADERS),
        ];
        for (name, headers) in recorded {
            let pool = Pool::read(&[std::path::PathBuf::from(format!("tests/fixtures/zip-crypto/{name}"))], &|_| None).unwrap();
            let mut targets: Vec<_> = pool.targets.iter().collect();
            targets.sort_by_key(|target| target.start);
            let found: Vec<[u8; 12]> = targets.iter().map(|target| target.header).collect();
            assert_eq!(found, headers, "{name}");
        }
    }

    #[test]
    fn entries_are_placed_among_the_headers_that_were_drawn() {
        let drawn = [10, 20, 30, 40, 50, 60, 70, 80];
        // every entry the next header
        assert_eq!(places(&drawn, &[10, 20, 30], 0), Some(vec![0, 1, 2]));
        // one header drawn and not written, in front of the third entry
        assert_eq!(places(&drawn, &[10, 20, 40, 50], 0), None);
        assert_eq!(places(&drawn, &[10, 20, 40, 50], 1), Some(vec![0, 1, 3, 4]));
        // two in different places, and what is allowed is all that is left out
        assert_eq!(places(&drawn, &[10, 30, 40, 60], 2), Some(vec![0, 2, 3, 5]));
        assert_eq!(places(&drawn, &[10, 30, 40, 60], 1), None);
        // the first entry is the first header, and an entry that is no header has no place
        assert_eq!(places(&drawn, &[20, 30], 4), None);
        assert_eq!(places(&drawn, &[10, 99], 6), None);
        assert_eq!(places(&[], &[10], 3), None);
        // of two ways the one that leaves out fewer: the same byte is drawn twice
        assert_eq!(places(&[1, 2, 3, 2, 3], &[1, 2, 3], 2), Some(vec![0, 1, 2]));
        assert_eq!(places(&[1, 9, 3, 2, 3], &[1, 2, 3], 2), Some(vec![0, 3, 4]));
    }

    #[test]
    fn a_search_allows_for_headers_only_where_it_still_says_something() {
        // four entries are as many bits as a seed has: nothing can be left out
        assert_eq!([3, 4, 5, 6, 12, 40].map(spare_for), [0, 0, 3, 8, 8, 8]);
    }

    #[test]
    fn a_run_that_drew_a_header_it_did_not_write_is_placed_with_the_gap() {
        // the headers of a run of macOS with seven draws, of which the fourth left no entry
        let seed = 0x5ee0_8ad2;
        let all = drawn::<bsd::Rand>(seed, 7);
        let first: Vec<u8> = all.iter().enumerate().filter(|(draw, _)| *draw != 3).map(|(_, byte)| *byte).collect();
        assert!(!fits::<bsd::Rand>(seed, &first));
        assert_eq!(places(&drawn::<bsd::Rand>(seed, first.len() + 3), &first, 3), Some(vec![0, 1, 2, 4, 5, 6]));
        // the bytes of the entries are those of the headers at their places
        let bytes = header_bytes::<bsd::Rand>(seed, 7);
        assert_eq!(bytes.iter().map(|header| header[0]).collect::<Vec<_>>(), all);
    }

    #[test]
    fn every_piece_is_run_once_on_any_number_of_threads() {
        for threads in [0, 1, 3, 16] {
            let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
            let control = Control { stop: &stop, done: &done, threads };
            let mut pieces = spread(100, control, |piece, found| {
                found.push(piece);
                control.advance(2);
            });
            pieces.sort_unstable();
            assert_eq!(pieces, (0..100).collect::<Vec<_>>());
            assert_eq!(done.load(Ordering::Relaxed), 200);
        }
    }

    #[test]
    fn a_search_that_was_stopped_starts_no_piece() {
        let (stop, done) = (AtomicBool::new(true), AtomicU64::new(0));
        let control = Control { stop: &stop, done: &done, threads: 4 };
        assert_eq!(spread(100, control, |piece, found| found.push(piece)), Vec::<u64>::new());
        assert_eq!(spread(0, Control { stop: &AtomicBool::new(false), ..control }, |piece, found| found.push(piece)), Vec::<u64>::new());
    }
}
