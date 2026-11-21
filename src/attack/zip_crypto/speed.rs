//! How fast this machine searches: the cost of a candidate, measured once and kept.
//!
//! Every estimate of a plan is a count of candidates divided by this rate. It is measured on
//! a fixed case with every thread busy, since a thread costs more when all of them work, and
//! kept in the cache directory of the user with the name of the processor: it is measured
//! again when the processor or the count of threads is another, or the kernel that was kept
//! is not one this build has.
//!
//! The kernel is chosen by the same measurement. Which of the kernels a processor runs is the
//! fastest depends on the processor: wide registers lower the clock of some, and a gather is
//! slow on others. So every kernel the processor runs is measured, each for its share of the
//! two seconds, and the fastest is the one that searches.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use archivewolf_zip_crypto::Kernel;
use archivewolf_zip_crypto::Keys;
use archivewolf_zip_crypto::Scratch;
use archivewolf_zip_crypto::Window;
use archivewolf_zip_crypto::reduce;
use serde::Deserialize;
use serde::Serialize;

/// How long the rate is measured for.
const MEASURE: Duration = Duration::from_secs(2);

/// How long the searches of a run have to take together before what they did is taken for
/// the speed of the machine: fifteen times what the measurement takes.
const SETTLED: Duration = Duration::from_secs(30);

/// How far the rate of a run may lie from the rate that is kept before the kept one is
/// corrected: by a quarter, up or down.
const OFF: f64 = 1.25;

/// The file the rate is kept in, below the cache directory of the user.
const CACHE_FILE: &str = "archivewolf/zip-crypto-speed.json";

/// What is kept of a measurement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Kept {
    processor: String,
    kernel: String,
    threads: usize,
    rate: f64,
}

/// How fast the machine searches.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Speed {
    /// The kernel that was measured to be the fastest of those the processor runs.
    pub kernel: Kernel,
    /// The threads it runs on.
    pub threads: usize,
    /// Candidates searched to their end in a second, on all those threads together.
    pub rate: f64,
    /// Whether the rate was measured by this run, and not read from the cache.
    pub measured_now: bool,
}

/// The name of the processor, as far as the system tells it.
fn processor() -> String {
    let named = std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|text| text.lines().find(|line| line.starts_with("model name")).and_then(|line| line.split_once(':')).map(|(_, name)| name.trim().to_owned()));
    named.unwrap_or_else(|| std::env::consts::ARCH.to_owned())
}

/// Where the rate is kept: below the cache directory of the user, when the system names one.
fn cache_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from).filter(|path| path.is_absolute()).or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from)).or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join(CACHE_FILE))
}

/// Measure the rate: every thread searches candidates of a fixed case to their end for
/// [`MEASURE`], and the candidates of all of them are counted.
fn measure(kernel: Kernel, threads: usize, time: Duration) -> f64 {
    let plain = *b"speed-of";
    let mut keys = Keys::from_password(b"a fixed case");
    let mut stream = [0_u8; 8];
    for (slot, &byte) in stream.iter_mut().zip(&plain) {
        *slot = byte ^ keys.encrypt(byte);
    }
    let window = Window { stream, plain };
    let Some(reduced) = reduce(&stream) else { return 1.0 };
    let (stop, done) = (AtomicBool::new(false), AtomicU64::new(0));
    let start = Instant::now();
    std::thread::scope(|scope| {
        for thread in 0..threads.max(1) {
            let (reduced, stop, done, window) = (&reduced, &stop, &done, &window);
            drop(scope.spawn(move || {
                let mut scratch = Scratch::new();
                let mut hits = Vec::new();
                // each thread takes its own stretch of the candidates
                for &z7 in reduced.candidates.iter().skip(thread * 30_011) {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    hits.clear();
                    let _ = kernel.search(window, z7, &mut scratch, &mut hits);
                    let _ = done.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        std::thread::sleep(time);
        stop.store(true, Ordering::Relaxed);
    });
    let seconds = start.elapsed().as_secs_f64().max(1e-6);
    f64::from(u32::try_from(done.load(Ordering::Relaxed)).unwrap_or(u32::MAX)).max(1.0) / seconds
}

/// The rate the searches of a run had, when it says more than the rate that is kept:
/// `candidates` searched to their end in `time`, on all threads. `None` for a run that was too
/// short to say, and for one that did about what the kept rate promised.
#[must_use]
pub(crate) fn observed(kept: f64, candidates: u64, time: Duration) -> Option<f64> {
    if time < SETTLED || candidates == 0 {
        return None;
    }
    let rate = f64::from(u32::try_from(candidates).unwrap_or(u32::MAX)) / time.as_secs_f64();
    (rate > kept * OFF || rate < kept / OFF).then_some(rate)
}

/// Write a rate to the cache, for this processor, a kernel and a count of threads. The cache
/// is a convenience: a directory that cannot be written costs a measurement next time.
pub(crate) fn keep(kernel: Kernel, threads: usize, rate: f64) {
    if let Some(path) = cache_path()
        && let Some(directory) = path.parent()
        && std::fs::create_dir_all(directory).is_ok()
        && let Ok(text) = serde_json::to_string(&Kept { processor: processor(), kernel: kernel.name().to_owned(), threads, rate })
    {
        // written beside its place and moved there: another run never reads half of it
        let beside = path.with_extension(format!("{}.tmp", std::process::id()));
        if std::fs::write(&beside, text).is_ok() {
            drop(std::fs::rename(&beside, &path));
        }
    }
}

/// The kernels that search: every one the processor runs but the reference, which is there
/// to test the others against.
fn kernels() -> Vec<Kernel> {
    let mut kernels = Kernel::vector();
    kernels.push(Kernel::Scalar);
    kernels
}

/// The fastest of `kernels` on `threads` threads, with its rate: each is measured for its
/// share of `time`. Of two that are as fast, the first.
fn fastest(kernels: &[Kernel], threads: usize, time: Duration) -> (Kernel, f64) {
    let share = time / u32::try_from(kernels.len().max(1)).unwrap_or(1);
    kernels.iter().map(|&kernel| (kernel, measure(kernel, threads, share))).fold((Kernel::Scalar, 0.0), |best, measured| if measured.1 > best.1 { measured } else { best })
}

/// The speed of this machine on `threads` threads: from the cache when it holds a
/// measurement of this processor and count of threads with a kernel the processor runs,
/// measured otherwise. `before` is called when a measurement starts, so that the two seconds
/// are not silent.
pub(crate) fn speed(threads: usize, before: impl FnOnce()) -> Speed {
    let processor = processor();
    let path = cache_path();
    let kept: Option<Kept> = path.as_ref().and_then(|path| std::fs::read_to_string(path).ok()).and_then(|text| serde_json::from_str(&text).ok());
    if let Some(kept) = kept.filter(|kept| kept.processor == processor && kept.threads == threads && kept.rate.is_finite() && kept.rate > 0.0)
        && let Some(kernel) = Kernel::named(&kept.kernel).filter(|kernel| kernels().contains(kernel))
    {
        return Speed { kernel, threads, rate: kept.rate, measured_now: false };
    }
    before();
    let (kernel, rate) = fastest(&kernels(), threads, MEASURE);
    keep(kernel, threads, rate);
    Speed { kernel, threads, rate, measured_now: true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_measurement_counts_candidates_that_were_searched() {
        let rate = measure(Kernel::best(), 2, Duration::from_millis(150));
        // a candidate takes between a tenth of a millisecond and a tenth of a second on anything
        assert!((20.0..200_000.0).contains(&rate), "{rate}");
    }

    #[test]
    fn the_kernel_that_searches_is_the_fastest_of_those_the_processor_runs() {
        let kernels = kernels();
        // the scalar kernel is always among them, and the reference never
        assert!(kernels.contains(&Kernel::Scalar) && !kernels.contains(&Kernel::Reference) && kernels.iter().all(|kernel| kernel.is_supported()));
        let (kernel, rate) = fastest(&kernels, 2, Duration::from_millis(300));
        assert!(kernels.contains(&kernel) && rate > 0.0);
        // one kernel to choose from is the choice
        assert_eq!(fastest(&[Kernel::Scalar], 1, Duration::from_millis(60)).0, Kernel::Scalar);
    }

    #[test]
    fn a_long_search_corrects_the_rate_and_a_short_one_does_not() {
        let minute = Duration::from_mins(1);
        // a rate that was measured while the machine was busy with something else
        assert_eq!(observed(7367.0, 864_000, minute), Some(14_400.0));
        // and one that was measured on a machine that is busy now
        assert_eq!(observed(21_000.0, 600_000, minute), Some(10_000.0));
        // within a quarter of what was kept: the kept rate stands
        assert_eq!(observed(10_000.0, 660_000, minute), None);
        assert_eq!(observed(10_000.0, 500_000, minute), None);
        assert!(observed(10_000.0, 760_000, minute).is_some() && observed(10_000.0, 470_000, minute).is_some());
        // too short to say, and nothing searched
        assert_eq!(observed(7367.0, 400_000, Duration::from_secs(29)), None);
        assert_eq!(observed(7367.0, 0, minute), None);
    }

    #[test]
    fn what_is_kept_is_read_back() {
        let kept = Kept { processor: processor(), kernel: "scalar".to_owned(), threads: 3, rate: 1234.5 };
        let text = serde_json::to_string(&kept).unwrap();
        assert_eq!(serde_json::from_str::<Kept>(&text).unwrap(), kept);
        assert!(!processor().is_empty());
    }
}
