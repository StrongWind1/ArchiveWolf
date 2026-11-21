//! One search: a run of known bytes of one entry, the candidates it leaves, and everything
//! that tells the key from the keys that fit the run by chance.
//!
//! The run makes candidates. Everything else that is known is a filter, applied to every key
//! a candidate gives, the cheapest first: the known bytes and classes beside the run, the
//! start of a packed stream, the check bytes of other entries, and at the end the proof.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use archivewolf_zip_crypto::Hit;
use archivewolf_zip_crypto::Kernel;
use archivewolf_zip_crypto::Keys;
use archivewolf_zip_crypto::Reduced;
use archivewolf_zip_crypto::Scratch;
use archivewolf_zip_crypto::WINDOW;
use archivewolf_zip_crypto::Window;
use archivewolf_zip_crypto::has_short_password;
use archivewolf_zip_crypto::reduce;

use super::deflate::can_start;
use super::pool::Pool;
use super::pool::Target;
use super::proof::Proof;
use super::proof::prove;
use super::proof::worth_of;
use super::seed::yeka;
use crate::formats::zip::known::claim::Form;
use crate::formats::zip::known::claim::RUN_MAX;
use crate::formats::zip::known::set::ByteSet;
use crate::formats::zip::known::writer::Writer;

/// How far behind the start of a run the filters of a search reach: the run as long as it may
/// be, and the classes behind it. What a claim says further on is left to the proof, which
/// decrypts the whole entry in any case.
pub(crate) const FILTER_SPAN: i64 = 4096 + 512;

const _: () = assert!(RUN_MAX == 4096);

/// How much of a packed stream is held against the form of its method.
const PROBE: i64 = 64;
/// The same as a count of bytes, with the encryption header in front.
const PROBE_HELD: usize = 12 + 64;

/// How many candidates a thread takes at a time.
const CHUNK: usize = 32;

/// How many other entries a key is held against by their check bytes.
const OTHERS_MAX: usize = 64;

/// How many keys that only the check bytes of other entries speak against are kept for the
/// proof at the end of a search.
const SET_ASIDE_MAX: usize = 4096;

/// How many keys that pass everything and cannot be proved are kept.
const UNPROVED_MAX: usize = 16;

/// The bits a key has: three words of 32.
const KEY_BITS: f64 = 96.0;

/// How many bits more than a key has have to speak for keys before they are called proved:
/// a search with a wrong claim then gives wrong keys once in 65,536 times.
pub(crate) const MARGIN: f64 = 16.0;

/// The longest password that is worked out from keys while a search runs.
const SHORT_PASSWORD: usize = 6;

/// What a search was told to do besides searching.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Control<'a> {
    /// The kernel.
    pub kernel: Kernel,
    /// How many threads search.
    pub threads: usize,
    /// Set from outside to end the search at the next candidate.
    pub stop: &'a AtomicBool,
    /// How many candidates are done, for whoever shows the progress.
    pub done: &'a AtomicU64,
    /// Whether a key that has a password of six bytes or fewer counts as that much more
    /// evidence, and such a password is looked for.
    pub short_password: bool,
}

/// Keys a search found, with what speaks for them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Found {
    /// The keys at the start of the entry: the state after the password.
    pub keys: Keys,
    /// The candidate that gave them, by its place among the candidates.
    pub candidate: usize,
    /// How many bits speak for them: the run, the filters, the proof.
    pub bits: f64,
    /// The entry they were proved on, by its place in the pool, when the entry of the search
    /// could not say.
    pub proved_on: Option<usize>,
}

/// How a search ended.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Outcome {
    /// Keys that are proved: they decrypt an entry to its CRC-32, and enough speaks for them.
    pub proved: Option<Found>,
    /// Keys that passed every filter and the proof, with fewer bits than proved keys need;
    /// and keys that passed every filter where no entry could give a proof.
    pub unproved: Vec<Found>,
    /// How many candidates were searched.
    pub candidates: u64,
    /// How many keys fit the eight bytes of the window.
    pub fitting: u64,
    /// How many of them passed every filter and reached a proof.
    pub put_to_proof: u64,
    /// Whether the search was stopped from outside before its end.
    pub stopped: bool,
}

impl Outcome {
    /// Take in how the next stretch of the same search ended.
    pub(crate) fn add(&mut self, next: Self) {
        self.proved = self.proved.or(next.proved);
        self.unproved.extend(next.unproved);
        self.unproved.sort_by(|a, b| b.bits.total_cmp(&a.bits).then(a.candidate.cmp(&b.candidate)));
        self.unproved.truncate(UNPROVED_MAX);
        self.candidates += next.candidates;
        self.fitting += next.fitting;
        self.put_to_proof += next.put_to_proof;
        self.stopped = next.stopped;
    }
}

/// A search that is ready to run: the run is reduced to its candidates and the filters are
/// laid out around its window.
#[derive(Debug)]
pub(crate) struct Search<'a> {
    pool: &'a Pool,
    target: &'a Target,
    /// The stream of the entry as it stands in the archive, from position -12 on.
    cipher: Vec<u8>,
    /// The candidates and the window they belong to.
    reduced: Reduced,
    window: Window,
    /// The position of the first byte of the window.
    window_at: i64,
    /// What each byte behind the window has to be, by position: 0 for anything, 1 to 256 for
    /// a byte, more for a set.
    forward: Vec<u16>,
    /// The same in front of the window, from the byte before it back to position -12.
    backward: Vec<u16>,
    sets: Vec<ByteSet>,
    /// Whether the stream is Deflate, and is held against the form of a block header.
    probe: bool,
    /// The encryption headers of other entries, with what their last byte has to decrypt to.
    others: Vec<(usize, [u8; 12], ByteSet)>,
    /// How many bits the run and the filters around it are worth.
    bits: f64,
    /// How many searches this one is one of: the alternatives of its run.
    searches: u64,
    /// Whether the writer of the archive puts a constant in front of every entry, encrypted
    /// twice: keys have to turn the constant into the ten bytes that stand there, which is a
    /// filter of 72 bits that needs nothing else (section 8.6 of the design).
    constant_header: bool,
    /// Whether so little is known that no proof could make keys proved: then the one thing
    /// that can is a password of six bytes or fewer, and keys without one are dropped before
    /// the proof, which would only cost time.
    short_only: bool,
}

impl<'a> Search<'a> {
    /// Make a search ready: `run` is the known bytes from position `run_at` on, eight or
    /// more, and `form` everything that is known of the entry, the run among it.
    ///
    /// `None` when the entry does not hold the run, which a claim made for another entry
    /// would do.
    pub(crate) fn new(pool: &'a Pool, target_index: usize, form: &Form, run_at: i64, run: &[u8], searches: u64) -> Option<Self> {
        let target = pool.targets.get(target_index)?;
        let run_end = run_at.checked_add(i64::try_from(run.len()).ok()?)?;
        let limit = run_at.saturating_add(FILTER_SPAN);
        let filters = form.clipped(-12, limit);
        let deflate = matches!(target.entry.compression_method, 8 | 9);
        let held_end = filters.span().map_or(run_end, |(_, end)| end.max(run_end)).max(if deflate { PROBE } else { 0 });
        let cipher = pool.cipher(target, -12, held_end).ok()?;
        let at = |position: i64| usize::try_from(position.checked_add(12)?).ok();

        let stream: Vec<u8> = run.iter().zip(cipher.get(at(run_at)?..)?).map(|(plain, cipher)| plain ^ cipher).collect();
        if stream.len() != run.len() {
            return None;
        }
        let reduced = reduce(&stream)?;
        let window = Window::of(run, &stream, reduced.index)?;
        let window_at = run_at + i64::try_from(reduced.index + 1 - WINDOW).ok()?;
        let window_end = window_at + i64::try_from(WINDOW).ok()?;

        // the filters, laid out from the window outward
        let mut search = Self {
            pool,
            target,
            cipher,
            reduced,
            window,
            window_at,
            forward: Vec::new(),
            backward: vec![0; at(window_at)?],
            sets: Vec::new(),
            probe: deflate,
            others: Vec::new(),
            bits: 0.0,
            searches,
            constant_header: pool.archives.get(target.archive).is_some_and(|archive| archive.writer == Writer::Yeka),
            short_only: false,
        };
        for piece in filters.pieces() {
            for index in 0..piece.cells.len() {
                let position = piece.at.checked_add(i64::try_from(index).ok()?)?;
                if let Some(set) = piece.cells.get(index) {
                    search.put(position, window_end, set);
                }
            }
        }
        // the run as it is taken for this search counts over what the form says of its bytes
        for (position, &byte) in (run_at..).zip(run) {
            search.put(position, window_end, ByteSet::of(byte));
        }
        while search.forward.last() == Some(&0) {
            let _ = search.forward.pop();
        }
        if at(window_end)?.checked_add(search.forward.len())? > search.cipher.len() {
            return None;
        }
        search.bits = 64.0 + search.forward.iter().chain(&search.backward).map(|&code| search.worth(code)).sum::<f64>() + if search.constant_header { 72.0 } else { 0.0 };

        search.others = pool.targets.iter().enumerate().filter(|(index, _)| *index != target_index).take(OTHERS_MAX).map(|(index, other)| (index, other.header, other.last_check())).collect();
        // the most that can speak for keys: every other entry under the same password, by its
        // check byte and by its own proof
        let proofs: f64 = search.others.iter().filter_map(|(index, _, _)| pool.targets.get(*index)).map(worth_of).sum::<f64>() + worth_of(target);
        let at_most = search.bits + 8.0 * f64::from(u32::try_from(search.others.len()).unwrap_or(0)) + proofs - search.alternatives();
        search.short_only = at_most < KEY_BITS + MARGIN;
        Some(search)
    }

    /// Say what the byte at a position has to be. The bytes of the window are the kernel's.
    fn put(&mut self, position: i64, window_end: i64, set: ByteSet) {
        if set == ByteSet::ANY || (self.window_at..window_end).contains(&position) {
            return;
        }
        let code = if let Some(byte) = set.only() {
            u16::from(byte) + 1
        } else {
            let index = self.sets.iter().position(|known| *known == set).unwrap_or_else(|| {
                self.sets.push(set);
                self.sets.len() - 1
            });
            u16::try_from(index + 257).unwrap_or(0)
        };
        if position >= window_end {
            let Ok(index) = usize::try_from(position - window_end) else { return };
            if self.forward.len() <= index {
                self.forward.resize(index + 1, 0);
            }
            if let Some(slot) = self.forward.get_mut(index) {
                *slot = code;
            }
        } else if let Some(slot) = usize::try_from(self.window_at - 1 - position).ok().and_then(|index| self.backward.get_mut(index)) {
            *slot = code;
        }
    }

    /// What a filter is worth, in bits.
    fn worth(&self, code: u16) -> f64 {
        match code {
            0 => 0.0,
            1..=256 => 8.0,
            _ => self.sets.get(usize::from(code) - 257).map_or(0.0, |set| set.bits()),
        }
    }

    /// Whether a byte passes a filter.
    #[inline]
    fn passes(&self, code: u16, byte: u8) -> bool {
        match code {
            0 => true,
            1..=256 => code == u16::from(byte) + 1,
            _ => self.sets.get(usize::from(code) - 257).is_some_and(|set| set.contains(byte)),
        }
    }

    /// The candidates of the search.
    #[must_use]
    pub(crate) fn candidates(&self) -> usize {
        self.reduced.candidates.len()
    }

    /// The place in the run that the candidates belong to: each has bits 2 to 31 of the
    /// third key in front of the byte there.
    #[must_use]
    pub(crate) const fn index(&self) -> usize {
        self.reduced.index
    }

    /// Drop every candidate that `keeps` says no to, on `threads` threads: what is known
    /// beside the run and can be told of a third key alone. The order of the rest stays.
    pub(crate) fn keep_only(&mut self, threads: usize, keeps: impl Fn(u32) -> bool + Sync) {
        let candidates = std::mem::take(&mut self.reduced.candidates);
        let each = candidates.len().div_ceil(threads.max(1)).max(1);
        let keeps = &keeps;
        self.reduced.candidates = std::thread::scope(|scope| {
            let workers: Vec<_> = candidates.chunks(each).map(|chunk| scope.spawn(move || chunk.iter().copied().filter(|candidate| keeps(*candidate)).collect::<Vec<u32>>())).collect();
            // a thread that panicked passes its panic on to the caller
            workers.into_iter().flat_map(|worker| worker.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))).collect()
        });
    }

    /// How many bits the run and the filters beside it are worth.
    #[must_use]
    pub(crate) const fn bits(&self) -> f64 {
        self.bits
    }

    /// Whether so little is known of the entry that keys can only be proved by a password
    /// of six bytes or fewer.
    #[must_use]
    pub(crate) const fn short_only(&self) -> bool {
        self.short_only
    }

    /// The place of a candidate among the candidates.
    #[cfg(test)]
    fn place_of(&self, z7: u32) -> Option<usize> {
        self.reduced.candidates.iter().position(|&candidate| candidate == z7)
    }

    /// What the alternatives of the run cost, in bits: each search of a run with
    /// alternatives is one more chance for a wrong key.
    fn alternatives(&self) -> f64 {
        if self.searches > 1 { f64::from(u32::try_from(self.searches).unwrap_or(u32::MAX)).log2() } else { 0.0 }
    }

    /// The keys at the start of the entry for a state that fits the window, when it passes
    /// every filter beside the window.
    #[inline]
    fn start_keys(&self, hit: &Hit) -> Option<Keys> {
        let window_end = usize::try_from(self.window_at + 12).ok()? + WINDOW;
        let mut keys = hit.after;
        for (&code, &cipher) in self.forward.iter().zip(self.cipher.get(window_end..)?) {
            let plain = keys.decrypt(cipher);
            if !self.passes(code, plain) {
                return None;
            }
        }
        let mut keys = hit.before;
        for (&code, &cipher) in self.backward.iter().zip(self.cipher.get(..window_end - WINDOW)?.iter().rev()) {
            keys.update_backward(cipher);
            if !self.passes(code, cipher ^ keys.stream_byte()) {
                return None;
            }
        }
        Some(keys)
    }

    /// Whether the stream that keys give starts as its packing method says.
    fn stream_fits(&self, start: Keys) -> bool {
        if !self.probe {
            return true;
        }
        let mut keys = start;
        let plain: Vec<u8> = self.cipher.iter().take(PROBE_HELD).map(|&byte| keys.decrypt(byte)).collect();
        plain.get(12..).is_none_or(can_start)
    }

    /// How many of the other entries have a check byte that keys give, and how many have not.
    /// Keys that the first few entries all speak against are not held against the rest: a
    /// wrong key is known by then, and the right key of an archive under several passwords
    /// is set aside for the proof in either case.
    fn others(&self, start: Keys) -> (usize, usize) {
        const FIRST: usize = 8;
        let mut fit = 0;
        for (count, (_, header, last)) in self.others.iter().enumerate() {
            if count == FIRST && fit == 0 {
                return (0, FIRST);
            }
            let mut keys = start;
            let mut plain = 0;
            for &byte in header {
                plain = keys.decrypt(byte);
            }
            fit += usize::from(last.contains(plain));
        }
        (fit, self.others.len() - fit)
    }

    /// Put keys that passed every filter to the proof: on the entry of the search, and when
    /// that cannot say, on the first other entry that can.
    fn prove(&self, start: Keys) -> (Proof, Option<usize>) {
        let Some(source) = self.pool.source(self.target) else { return (Proof::Fails, None) };
        match prove(source, self.target, start) {
            Proof::CannotSay => {},
            proof => return (proof, None),
        }
        for (index, _, _) in &self.others {
            let Some((other, source)) = self.pool.targets.get(*index).and_then(|other| Some((other, self.pool.source(other)?))) else { continue };
            if let Proof::Holds(bits) = prove(source, other, start) {
                return (Proof::Holds(bits), Some(*index));
            }
        }
        (Proof::CannotSay, None)
    }

    /// What the other entries add to a proof that holds and is not enough by itself: each of
    /// them that the keys decrypt to its own CRC-32 speaks for the keys as the first did.
    /// They are asked in the order of their size, the smallest first, until `wanted` bits are
    /// together. An entry the keys do not open adds nothing and takes nothing away: it may be
    /// under another password.
    fn further_proofs(&self, start: Keys, proved_on: Option<usize>, wanted: f64) -> f64 {
        // the entry of the search has given its proof, unless it could not say
        let mut rest: Vec<(usize, &Target)> = self.others.iter().filter(|(index, _, _)| Some(*index) != proved_on).filter_map(|(index, _, _)| Some((*index, self.pool.targets.get(*index)?))).collect();
        rest.sort_by_key(|(index, other)| (other.stream_len(), *index));
        let mut bits = 0.0;
        for (_, other) in rest {
            if bits >= wanted {
                break;
            }
            if let Some(source) = self.pool.source(other)
                && let Proof::Holds(worth) = prove(source, other, start)
            {
                bits += worth;
            }
        }
        bits
    }

    /// What speaks for keys that passed everything, in bits, and whether that is enough to
    /// call them proved.
    fn judge(&self, start: Keys, candidate: usize, fit_others: usize, short: bool) -> Judged {
        let (proof, proved_on) = self.prove(start);
        let proof_bits = match proof {
            Proof::Fails => return Judged::Wrong,
            Proof::Holds(bits) => bits,
            Proof::CannotSay => 0.0,
        };
        let mut bits = self.bits + proof_bits + 8.0 * f64::from(u32::try_from(fit_others).unwrap_or(0)) - self.alternatives();
        // of 2^96 keys, 2^48 have a password of six bytes or fewer
        if short {
            bits += 48.0;
        }
        if matches!(proof, Proof::Holds(_)) && bits < KEY_BITS + MARGIN {
            bits += self.further_proofs(start, proved_on, KEY_BITS + MARGIN - bits);
        }
        let found = Found { keys: start, candidate, bits, proved_on };
        if matches!(proof, Proof::Holds(_)) && bits >= KEY_BITS + MARGIN { Judged::Proved(found) } else { Judged::Unproved(found) }
    }

    /// Run the search over the candidates `from` to `until - 1`, on the threads of `control`,
    /// to the first proved key or to the end.
    pub(crate) fn run(&self, control: &Control<'_>, from: usize, until: usize) -> Outcome {
        let until = until.min(self.candidates());
        let next = AtomicUsize::new(from);
        let found = AtomicBool::new(false);
        let (fitting, put_to_proof) = (AtomicU64::new(0), AtomicU64::new(0));
        let shared = Mutex::new(Shared::default());

        std::thread::scope(|scope| {
            for _ in 0..control.threads.max(1) {
                drop(scope.spawn(|| {
                    let mut scratch = Scratch::new();
                    let mut hits = Vec::with_capacity(2048);
                    loop {
                        if found.load(Ordering::Relaxed) || control.stop.load(Ordering::Relaxed) {
                            return;
                        }
                        let first = next.fetch_add(CHUNK, Ordering::Relaxed);
                        let Some(chunk) = self.reduced.candidates.get(first.min(until)..first.saturating_add(CHUNK).min(until)).filter(|chunk| !chunk.is_empty()) else { return };
                        let mut fit = 0;
                        for (candidate, &z7) in (first..).zip(chunk) {
                            hits.clear();
                            let _ = control.kernel.search(&self.window, z7, &mut scratch, &mut hits);
                            fit += hits.len() as u64;
                            for hit in &hits {
                                let Some(start) = self.start_keys(hit).filter(|start| self.stream_fits(*start)) else { continue };
                                if self.constant_header && !yeka::fits(start, &self.target.header) {
                                    continue;
                                }
                                // the password is asked for where it decides something, and once: the
                                // inversion costs ten nanoseconds, and a proof the pass over an entry
                                let mut asked: Option<bool> = None;
                                let mut short = || *asked.get_or_insert_with(|| control.short_password && has_short_password(start, SHORT_PASSWORD));
                                if self.short_only && control.short_password && !short() {
                                    continue;
                                }
                                let (fit_others, against) = self.others(start);
                                if fit_others == 0 && against > 0 && !short() {
                                    // only entries that may be under another password speak against it
                                    if let Ok(mut shared) = shared.lock()
                                        && shared.set_aside.len() < SET_ASIDE_MAX
                                    {
                                        shared.set_aside.push((start, candidate));
                                    }
                                    continue;
                                }
                                let _ = put_to_proof.fetch_add(1, Ordering::Relaxed);
                                match self.judge(start, candidate, fit_others, short()) {
                                    Judged::Wrong => {},
                                    Judged::Proved(keys) => {
                                        if let Ok(mut shared) = shared.lock() {
                                            let _ = shared.proved.get_or_insert(keys);
                                        }
                                        found.store(true, Ordering::Relaxed);
                                    },
                                    Judged::Unproved(keys) => {
                                        if let Ok(mut shared) = shared.lock()
                                            && shared.unproved.len() < UNPROVED_MAX
                                        {
                                            shared.unproved.push(keys);
                                        }
                                    },
                                }
                            }
                        }
                        let _ = fitting.fetch_add(fit, Ordering::Relaxed);
                        let _ = control.done.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                    }
                }));
            }
        });

        let mut shared = shared.into_inner().unwrap_or_default();
        let stopped = control.stop.load(Ordering::Relaxed) && shared.proved.is_none();
        let mut put = put_to_proof.load(Ordering::Relaxed);
        // a filter that takes one password for all entries never has the last word: when no
        // key was found, the keys it alone rejected are put to the proof
        if shared.proved.is_none() && !stopped {
            for (start, candidate) in std::mem::take(&mut shared.set_aside) {
                put += 1;
                match self.judge(start, candidate, 0, false) {
                    Judged::Wrong => {},
                    Judged::Proved(keys) => {
                        shared.proved = Some(keys);
                        break;
                    },
                    Judged::Unproved(keys) => shared.unproved.push(keys),
                }
            }
        }
        shared.unproved.sort_by(|a, b| b.bits.total_cmp(&a.bits).then(a.candidate.cmp(&b.candidate)));
        shared.unproved.truncate(UNPROVED_MAX);
        let searched = (next.load(Ordering::Relaxed).min(until).saturating_sub(from)) as u64;
        Outcome { proved: shared.proved, unproved: shared.unproved, candidates: if stopped { control.done.load(Ordering::Relaxed).min(searched) } else { searched }, fitting: fitting.load(Ordering::Relaxed), put_to_proof: put, stopped }
    }
}

/// What the threads of a search share.
#[derive(Debug, Default)]
struct Shared {
    proved: Option<Found>,
    unproved: Vec<Found>,
    set_aside: Vec<(Keys, usize)>,
}

/// What became of keys that reached the proof.
enum Judged {
    Wrong,
    Proved(Found),
    Unproved(Found),
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::formats::zip::known::claim::Cells;

    /// The archive of the tutorial of bkcrack: `advice.jpg` packed and `spiral.svg` stored,
    /// under one password.
    fn secrets() -> Pool {
        Pool::read(&[PathBuf::from("tests/fixtures/zip-crypto/bkcrack-src_secrets.zip")], &|_| None).unwrap()
    }

    const KEYS: Keys = Keys::new(0xc449_0e28, 0xb414_a23d, 0x9140_4b31);

    /// The stream of `spiral.svg` as it was before it was encrypted, from position -12 on.
    fn plain(pool: &Pool) -> Vec<u8> {
        let mut keys = KEYS;
        pool.cipher(&pool.targets[1], -12, 2000).unwrap().iter().map(|&byte| keys.decrypt(byte)).collect()
    }

    fn control<'a>(stop: &'a AtomicBool, done: &'a AtomicU64) -> Control<'a> {
        Control { kernel: Kernel::best(), threads: 4, stop, done, short_password: false }
    }

    #[test]
    fn a_long_run_gives_the_keys_and_the_proof_calls_them_proved() {
        let pool = secrets();
        let plain = plain(&pool);
        // 600 bytes of the file, from its first byte on
        let run = &plain[12..612];
        let search = Search::new(&pool, 1, &Form::bytes(0, run), 0, run, 1).unwrap();
        assert!(search.candidates() < 20_000, "{}", search.candidates());
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let outcome = search.run(&control(&stop, &done), 0, usize::MAX);
        let found = outcome.proved.unwrap();
        assert_eq!((found.keys, found.proved_on), (KEYS, None));
        assert!(found.bits > 4000.0 && !outcome.stopped && outcome.unproved.is_empty());
        assert!(outcome.put_to_proof == 1 && outcome.fitting > 0);
        // the candidate that gave them is the one the same search gives again
        assert_eq!(search.run(&control(&stop, &done), found.candidate, found.candidate + 1).proved.map(|found| found.keys), Some(KEYS));
        assert!(search.run(&control(&stop, &done), found.candidate + 1, usize::MAX).proved.is_none());
    }

    #[test]
    fn a_run_that_is_wrong_in_one_byte_finds_nothing() {
        let pool = secrets();
        let mut run = plain(&pool)[12..612].to_vec();
        run[300] ^= 1;
        let search = Search::new(&pool, 1, &Form::bytes(0, &run), 0, &run, 1).unwrap();
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let outcome = search.run(&control(&stop, &done), 0, usize::MAX);
        assert_eq!((outcome.proved, outcome.unproved.len(), outcome.stopped), (None, 0, false));
        assert_eq!(outcome.candidates, search.candidates() as u64);
        assert_eq!(done.load(Ordering::Relaxed), outcome.candidates);
    }

    #[test]
    fn filters_beside_the_window_and_far_from_it_reject_what_does_not_fit() {
        let pool = secrets();
        let plain = plain(&pool);
        let run = &plain[112..412];
        let right = |form: &Form| {
            let search = Search::new(&pool, 1, form, 100, run, 1).unwrap();
            let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
            search.run(&control(&stop, &done), 0, usize::MAX).proved.map(|found| found.keys)
        };
        let base = Form::bytes(100, run);
        assert_eq!(right(&base), Some(KEYS));
        // a class the file is of, a byte in front of the run and the check byte: still the keys
        let mut more = base.clone();
        assert!(more.add(400, Cells::Fill(ByteSet::text(), 600)) && more.add(0, Cells::Bytes(plain[12..17].to_vec())) && more.add(-1, Cells::Bytes(vec![plain[11]])));
        assert_eq!(right(&more), Some(KEYS));
        // a byte that is not there, behind the run or in front of it: no keys
        for (at, byte) in [(450_i64, plain[462] ^ 0x20), (3, plain[15] ^ 1), (-1, plain[11] ^ 0x80)] {
            let mut wrong = base.clone();
            assert!(wrong.add(at, Cells::Bytes(vec![byte])));
            assert_eq!(right(&wrong), None, "a wrong byte at {at}");
        }
        // what a claim says far behind the run is left to the proof
        let mut far = base.clone();
        assert!(far.add(100 + FILTER_SPAN + 5, Cells::Bytes(vec![0xff])));
        assert_eq!(right(&far), Some(KEYS));
    }

    #[test]
    fn a_search_is_stopped_from_outside_and_says_how_far_it_came() {
        let pool = secrets();
        let plain = plain(&pool);
        let run = &plain[12..36];
        let search = Search::new(&pool, 1, &Form::bytes(0, run), 0, run, 1).unwrap();
        let (stop, done) = (AtomicBool::new(true), AtomicU64::new(0));
        let outcome = search.run(&control(&stop, &done), 0, usize::MAX);
        assert!(outcome.stopped && outcome.proved.is_none() && outcome.candidates == 0);
    }

    /// The one stored entry of an archive, the keys of its password, and a search that knows
    /// eight bytes of it and nothing else, with the place of the right candidate.
    fn eight_known<'a>(pool: &'a Pool, password: &[u8]) -> (Search<'a>, Keys, usize) {
        eight_known_of(pool, 0, password)
    }

    /// The same for the entry at a place in the pool: eight bytes of it, from position 100 on.
    fn eight_known_of<'a>(pool: &'a Pool, target: usize, password: &[u8]) -> (Search<'a>, Keys, usize) {
        let start = Keys::from_password(password);
        let mut keys = start;
        let mut third = Vec::new();
        let plain: Vec<u8> = pool
            .cipher(&pool.targets[target], -12, 400)
            .unwrap()
            .iter()
            .map(|&byte| {
                third.push(keys.z);
                keys.decrypt(byte)
            })
            .collect();
        // the eight bytes at positions 100 to 107: the window is the run
        let run = &plain[112..120];
        let search = Search::new(pool, target, &Form::bytes(100, run), 100, run, 1).unwrap();
        let place = search.place_of(third[119] & !3).unwrap();
        (search, start, place)
    }

    #[test]
    fn another_entry_that_the_keys_open_makes_a_proof_of_eight_bytes() {
        // two entries under one password of twelve bytes, and eight bytes of the stored one
        // are known. The run is 64 bits, its CRC-32 is 32 and the check byte of the other
        // entry is 8: 104, where 112 are asked for
        let pool = secrets();
        let (search, keys, place) = eight_known_of(&pool, 1, b"W4sF0rgotten");
        assert_eq!(keys, KEYS);
        // the other entry can give a proof of its own, so there is enough to prove keys with,
        // and every key that fits is asked, not only those of a short password
        assert!(!search.short_only());
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let outcome = search.run(&Control { short_password: true, ..control(&stop, &done) }, place, place + 1);
        let found = outcome.proved.unwrap();
        assert_eq!((found.keys, found.candidate, found.proved_on), (KEYS, place, None));
        // the keys unpack the other entry to its CRC-32 as well: 32 bits, and 32 for a
        // Deflate stream that came to its end where it should
        assert!((found.bits - (64.0 + 32.0 + 8.0 + 64.0)).abs() < 1e-9, "{}", found.bits);

        // the same search on an archive of one entry can prove nothing
        let alone = Pool::read(&[PathBuf::from("tests/fixtures/zip-crypto/gen_7z_zipcrypto_copy.zip")], &|_| None).unwrap();
        assert!(eight_known(&alone, b"7z-zipcrypto_copy").0.short_only());
    }

    #[test]
    fn eight_bytes_and_nothing_else_give_the_keys_of_a_short_password_and_of_no_other() {
        let one = |fixture: &str| Pool::read(&[PathBuf::from(format!("tests/fixtures/zip-crypto/{fixture}"))], &|_| None).unwrap();
        let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
        let with_password = Control { short_password: true, ..control(&stop, &done) };

        // a password of six bytes: of the thousand keys that fit the run, the one that has a
        // password is put to the proof, and the 48 bits of that make it proved
        let pool = one("gen_own_zc_stored.zip");
        let (search, keys, place) = eight_known(&pool, b"own-zc");
        assert!(search.short_only() && search.candidates() == 1 << 22);
        let outcome = search.run(&with_password, place, place + 1);
        let found = outcome.proved.unwrap();
        assert_eq!((found.keys, found.candidate), (keys, place));
        assert!((found.bits - (64.0 + 32.0 + 48.0)).abs() < 1e-9, "{}", found.bits);
        assert!(outcome.fitting > 100 && outcome.put_to_proof == 1, "{outcome:?}");

        // a password of seventeen bytes: the CRC-32 alone is 32 bits, as many as the keys that fit
        // the run by chance have, so its keys are not put to a proof that could not prove them
        let pool = one("gen_7z_zipcrypto_copy.zip");
        let (search, keys, place) = eight_known(&pool, b"7z-zipcrypto_copy");
        assert!(search.short_only());
        let outcome = search.run(&with_password, place, place + 1);
        assert_eq!((outcome.proved, outcome.unproved.len(), outcome.put_to_proof), (None, 0, 0));
        // when passwords are not asked for, the keys pass the proof and are still not proved
        let outcome = search.run(&control(&stop, &done), place, place + 1);
        assert_eq!(outcome.proved, None);
        assert_eq!(outcome.unproved.iter().map(|found| (found.keys, found.bits.to_bits())).collect::<Vec<_>>(), [(keys, 96.0_f64.to_bits())]);
    }

    #[test]
    fn a_run_the_entry_does_not_hold_makes_no_search() {
        let pool = secrets();
        let run = [0_u8; 64];
        assert!(Search::new(&pool, 1, &Form::bytes(1200, &run), 1200, &run, 1).is_some());
        assert!(Search::new(&pool, 1, &Form::bytes(1250, &run), 1250, &run, 1).is_none());
        assert!(Search::new(&pool, 1, &Form::bytes(0, &run[..7]), 0, &run[..7], 1).is_none());
        assert!(Search::new(&pool, 7, &Form::bytes(0, &run), 0, &run, 1).is_none());
    }
}
