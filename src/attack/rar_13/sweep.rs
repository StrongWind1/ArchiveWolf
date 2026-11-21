//! One pass over the key space: every key is tested on one entry, under a clock, with the
//! rate measured before it starts and the progress noted while it runs.
//!
//! What a key is tested on is an [`Oracle`]. The pass hands it the key space one group of
//! keys at a time, on every thread of the pool, and stops giving out groups when the clock
//! runs out.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use rayon::prelude::IntoParallelIterator as _;
use rayon::prelude::ParallelIterator as _;

use super::crack::GROUPS;
use super::crack::KEY_SPACE;
use crate::attack::budget::about;
use crate::output::sanitize;

/// How long the rate of a pass is measured for at first: long enough to tell a pass of a
/// second from one of an hour.
const GLANCE: Duration = Duration::from_millis(5);
/// A pass that the first measurement puts under this is started on that measurement,
const SHORT_PASS: Duration = Duration::from_secs(2);
/// and a longer one is measured again, for this long: its time may be held against a budget.
const MEASURE_FOR: Duration = Duration::from_millis(40);
/// The progress of a pass is noted this many times over the time it is expected to take,
const NOTES_IN_A_PASS: u32 = 20;
/// but not more often than this,
const SHORTEST_PAUSE: Duration = Duration::from_secs(1);
/// and not more seldom.
const LONGEST_PAUSE: Duration = Duration::from_secs(30);

/// The notes of the search on standard error. `-q` turns them off.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Notes {
    pub(crate) quiet: bool,
}

impl Notes {
    /// Write one note. It can hold the name of an entry, so it is made safe for a terminal.
    pub(crate) fn say(self, text: &str) {
        if !self.quiet {
            eprintln!("archivewolf: {}", sanitize(text));
        }
    }
}

/// The time a search has left.
#[derive(Debug)]
pub(crate) struct Clock {
    deadline: Option<Instant>,
    out: AtomicBool,
}

impl Clock {
    /// A clock that runs out at `deadline`, or never.
    pub(crate) const fn until(deadline: Option<Instant>) -> Self {
        Self { deadline, out: AtomicBool::new(false) }
    }

    /// Whether the time is up. Once it is, it stays so.
    pub(crate) fn out(&self) -> bool {
        if self.out.load(Ordering::Relaxed) {
            return true;
        }
        let late = self.deadline.is_some_and(|deadline| Instant::now() >= deadline);
        if late {
            self.out.store(true, Ordering::Relaxed);
        }
        late
    }
}

/// What every key is tested on in a pass.
pub(crate) trait Oracle: Sync {
    /// What one thread keeps between groups.
    type Scratch: Send;

    /// A fresh scratch.
    fn scratch(&self) -> Self::Scratch;

    /// The work of testing one key, in units of the oracle's own choosing. Never zero.
    fn work_per_key(&self) -> u64;

    /// Test the keys of one group and push those that pass onto `passed`.
    ///
    /// `did` is told of the work as it is done, in the units of [`Self::work_per_key`] and in
    /// pieces small enough to follow. The first piece is always done. The clock is looked at
    /// after each piece: when it is out, the group is left unfinished and what it pushed
    /// counts for nothing.
    fn group(&self, group: u32, scratch: &mut Self::Scratch, clock: &Clock, did: &mut dyn FnMut(u64), passed: &mut Vec<[u8; 3]>);
}

/// The work a pass does in a second, on all threads together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rate {
    /// Units of work in 10^9 seconds.
    per_gigasecond: u128,
    /// Threads that were measured.
    pub(crate) threads: usize,
}

impl Rate {
    /// The rate of threads that each did `work` units in `time`.
    fn of(threads: &[(u64, Duration)]) -> Self {
        let per_gigasecond = threads.iter().map(|&(work, time)| u128::from(work) * 1_000_000_000_000_000_000 / time.as_nanos().max(1)).fold(0, u128::saturating_add);
        Self { per_gigasecond, threads: threads.len() }
    }

    /// A rate at which every pass takes no time, for a test that wants a search started
    /// whatever it costs.
    #[cfg(test)]
    pub(crate) const UNMEASURED: Self = Self { per_gigasecond: u128::MAX, threads: 1 };

    /// How long `work` units take at this rate.
    pub(crate) fn time_for(self, work: u128) -> Duration {
        let nanos = work.saturating_mul(1_000_000_000_000_000_000) / self.per_gigasecond.max(1);
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

/// The work of testing every key on `oracle`.
pub(crate) fn work_of_a_pass(oracle: &impl Oracle) -> u128 {
    u128::from(KEY_SPACE) * u128::from(oracle.work_per_key())
}

/// Measure the rate of a pass over `oracle`: every thread of the pool tests keys from all
/// over the key space for a moment, and each is timed by itself.
///
/// The moment is as short as the pass allows: a pass of a second is not held up for the
/// time it takes to measure one of an hour well.
pub(crate) fn measure(oracle: &impl Oracle) -> Rate {
    let glance = measure_for(oracle, GLANCE);
    if glance.time_for(work_of_a_pass(oracle)) < SHORT_PASS { glance } else { measure_for(oracle, MEASURE_FOR) }
}

/// The rate of a pass over `oracle`, from `moment` of it on every thread of the pool.
fn measure_for(oracle: &impl Oracle, moment: Duration) -> Rate {
    let threads: Vec<(u64, Duration)> = rayon::broadcast(|context| {
        let mut scratch = oracle.scratch();
        let mut passed = Vec::new();
        let mut work = 0u64;
        let mut sample = u32::try_from(context.index()).unwrap_or(0).wrapping_mul(0x0101_0101);
        // each thread has the moment to itself, from when it starts
        let start = Instant::now();
        let moment = Clock::until(start.checked_add(moment));
        while !moment.out() {
            sample = sample.wrapping_mul(0x9E37_79B1).wrapping_add(0x7F4A_7C15);
            oracle.group((sample >> 8) % GROUPS, &mut scratch, &moment, &mut |did| work = work.saturating_add(did), &mut passed);
            passed.clear();
        }
        (work, start.elapsed())
    });
    Rate::of(&threads)
}

/// How far a pass has got, and the notes of that on standard error.
#[derive(Debug)]
pub(crate) struct Progress {
    notes: Notes,
    work_per_key: u64,
    done: AtomicU64,
    start: Instant,
    pause: Duration,
    /// Milliseconds from the start at which the next note is due.
    next_note: AtomicU64,
}

impl Progress {
    /// The progress of a pass that starts now and is expected to take `expected`.
    pub(crate) fn start(notes: Notes, work_per_key: u64, expected: Duration) -> Self {
        let pause = (expected / NOTES_IN_A_PASS).clamp(SHORTEST_PAUSE, LONGEST_PAUSE);
        Self { notes, work_per_key: work_per_key.max(1), done: AtomicU64::new(0), start: Instant::now(), pause, next_note: AtomicU64::new(millis(pause)) }
    }

    /// Keys that have been tested, counting the work on unfinished groups as keys.
    pub(crate) fn keys_tested(&self) -> u64 {
        (self.done.load(Ordering::Relaxed) / self.work_per_key).min(u64::from(KEY_SPACE))
    }

    /// Whether every key has been tested.
    fn complete(&self) -> bool {
        u128::from(self.done.load(Ordering::Relaxed)) >= u128::from(KEY_SPACE) * u128::from(self.work_per_key)
    }

    /// Count `work` units as done, and note the progress when a note is due.
    fn add(&self, work: u64) {
        let _ = self.done.fetch_add(work, Ordering::Relaxed);
        if !self.notes.quiet
            && let Some(note) = self.note_at(self.start.elapsed())
        {
            self.notes.say(&note);
        }
    }

    /// The note that is due `elapsed` after the start, when one is: the first is due a
    /// pause after the start, and each further one a pause after the one before.
    fn note_at(&self, elapsed: Duration) -> Option<String> {
        let now = millis(elapsed);
        let due = self.next_note.load(Ordering::Relaxed);
        // of the threads that see a note due, one writes it and the others go on
        let ours = now >= due && self.next_note.compare_exchange(due, now.saturating_add(millis(self.pause)), Ordering::Relaxed, Ordering::Relaxed).is_ok();
        ours.then(|| progress_line(self.keys_tested(), elapsed))
    }
}

fn millis(time: Duration) -> u64 {
    u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
}

/// The percentage `tested` is of the key space, rounded down.
pub(crate) fn percent(tested: u64) -> u64 {
    tested.saturating_mul(100) / u64::from(KEY_SPACE)
}

/// A note of progress: how many keys are tested after `elapsed`, and how long the rest takes
/// at that pace.
fn progress_line(tested: u64, elapsed: Duration) -> String {
    let left = u64::from(KEY_SPACE).saturating_sub(tested);
    let rest = match tested {
        0 => String::new(),
        _ => format!(", {} left", about(Duration::from_nanos(u64::try_from(elapsed.as_nanos().saturating_mul(u128::from(left)) / u128::from(tested)).unwrap_or(u64::MAX)))),
    };
    format!("{tested} of {KEY_SPACE} keys tested ({}%){rest}", percent(tested))
}

/// How a pass ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Swept {
    /// Every key was tested. These passed, in ascending order.
    All(Vec<[u8; 3]>),
    /// The clock ran out first, with this many keys tested.
    Stopped {
        /// Keys tested.
        tested: u64,
    },
}

/// Test every key on `oracle`, on all threads of the pool, until `clock` runs out.
pub(crate) fn sweep(oracle: &impl Oracle, clock: &Clock, progress: &Progress) -> Swept {
    let mut passed: Vec<[u8; 3]> = (0..GROUPS)
        .into_par_iter()
        .map_init(
            || oracle.scratch(),
            |scratch, group| {
                let mut passed = Vec::new();
                if !clock.out() {
                    oracle.group(group, scratch, clock, &mut |did| progress.add(did), &mut passed);
                }
                passed
            },
        )
        .flatten_iter()
        .collect();
    // the count decides, not the clock: a clock that runs out after the last group was
    // finished has stopped nothing
    if !progress.complete() {
        return Swept::Stopped { tested: progress.keys_tested() };
    }
    passed.sort_unstable();
    Swept::All(passed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::rar_13::crack::keys_in;

    /// An oracle that passes the keys whose three bytes add up to `sum`, and takes `work`
    /// units for each key in two pieces.
    struct BySum {
        sum: u8,
        work: u64,
    }

    impl Oracle for BySum {
        type Scratch = ();

        fn scratch(&self) {}

        fn work_per_key(&self) -> u64 {
            self.work
        }

        fn group(&self, group: u32, (): &mut (), clock: &Clock, did: &mut dyn FnMut(u64), passed: &mut Vec<[u8; 3]>) {
            let keys: Vec<[u8; 3]> = keys_in(group).collect();
            for half in keys.chunks(keys.len() / 2) {
                passed.extend(half.iter().filter(|key| key.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte)) == self.sum));
                did(u64::try_from(half.len()).unwrap() * self.work);
                if clock.out() {
                    return;
                }
            }
        }
    }

    /// An oracle that stops the clock it is given when it reaches the group in the middle.
    struct StopsHalfway<'a>(&'a Clock);

    impl Oracle for StopsHalfway<'_> {
        type Scratch = ();

        fn scratch(&self) {}

        fn work_per_key(&self) -> u64 {
            1
        }

        fn group(&self, group: u32, (): &mut (), _: &Clock, did: &mut dyn FnMut(u64), passed: &mut Vec<[u8; 3]>) {
            if group == GROUPS / 2 {
                self.0.out.store(true, Ordering::Relaxed);
                return;
            }
            passed.extend(keys_in(group).take(1));
            did(128);
        }
    }

    const QUIET: Notes = Notes { quiet: true };

    #[test]
    fn a_pass_tests_every_key_once_and_returns_those_that_pass_in_order() {
        let oracle = BySum { sum: 0x5a, work: 3 };
        let progress = Progress::start(QUIET, oracle.work_per_key(), Duration::ZERO);
        let Swept::All(passed) = sweep(&oracle, &Clock::until(None), &progress) else { panic!("stopped") };
        // of the keys with the parity that a password gives, one in 256 has any one sum
        assert_eq!(u32::try_from(passed.len()).unwrap(), KEY_SPACE / 256);
        assert!(passed.is_sorted_by(|one, next| one < next));
        assert!(passed.iter().all(|key| key[0].wrapping_add(key[1]).wrapping_add(key[2]) == 0x5a && key[0] & 1 == key[1] & 1));
        assert_eq!(progress.keys_tested(), u64::from(KEY_SPACE));
    }

    #[test]
    fn a_clock_that_is_out_stops_the_pass_and_the_keys_it_found_count_for_nothing() {
        let oracle = BySum { sum: 0, work: 1 };

        // out before the first group
        let progress = Progress::start(QUIET, 1, Duration::ZERO);
        assert_eq!(sweep(&oracle, &Clock::until(Some(Instant::now())), &progress), Swept::Stopped { tested: 0 });

        // out in the middle: the groups that were finished are counted, and no key is returned
        let clock = Clock::until(None);
        let progress = Progress::start(QUIET, 1, Duration::ZERO);
        let Swept::Stopped { tested } = sweep(&StopsHalfway(&clock), &clock, &progress) else { panic!("not stopped") };
        assert!(tested < u64::from(KEY_SPACE), "{tested}");
        assert_eq!(tested % 128, 0);
        assert!(clock.out());
    }

    #[test]
    fn a_clock_that_runs_out_after_the_last_key_has_stopped_nothing() {
        let oracle = BySum { sum: 1, work: 1 };
        let clock = Clock::until(None);
        let progress = Progress::start(QUIET, 1, Duration::ZERO);
        // every group is done before the clock is looked at again
        let swept = sweep(&oracle, &clock, &progress);
        clock.out.store(true, Ordering::Relaxed);
        assert!(matches!(swept, Swept::All(ref passed) if !passed.is_empty()));
        assert!(progress.complete());
    }

    #[test]
    fn a_clock_runs_out_at_its_deadline_and_stays_out() {
        assert!(!Clock::until(None).out());
        assert!(!Clock::until(Instant::now().checked_add(Duration::from_hours(1))).out());
        let clock = Clock::until(Some(Instant::now()));
        assert!(clock.out() && clock.out());
    }

    #[test]
    fn the_rate_is_measured_on_every_thread_and_gives_the_time_of_a_pass() {
        let oracle = BySum { sum: 0, work: 7 };
        let rate = measure(&oracle);
        assert_eq!(rate.threads, rayon::current_num_threads());
        assert!(rate.per_gigasecond > 0);
        assert_eq!(work_of_a_pass(&oracle), u128::from(KEY_SPACE) * 7);
        // twice the work takes twice the time
        let once = rate.time_for(work_of_a_pass(&oracle));
        let twice = rate.time_for(work_of_a_pass(&oracle) * 2);
        assert!(once > Duration::ZERO && twice >= once && twice <= once * 2 + Duration::from_nanos(1), "{once:?} {twice:?}");

        // two threads that each do 1000 units a second do a pass of 2^23 units in 4194 seconds
        let rate = Rate::of(&[(500, Duration::from_millis(500)), (2000, Duration::from_secs(2))]);
        assert_eq!(rate.time_for(u128::from(KEY_SPACE)).as_secs(), 4194);
        // nothing measured is no rate to divide by, and no time is no time to divide by
        assert!(Rate::of(&[]).time_for(1) >= Duration::from_hours(24 * 365 * 30), "longer than any budget is meant for");
        assert!(Rate::of(&[(1, Duration::ZERO)]).time_for(1) < Duration::from_secs(1));
    }

    #[test]
    fn a_note_of_progress_says_how_many_keys_and_how_long_the_rest_takes() {
        assert_eq!(progress_line(0, Duration::from_secs(1)), "0 of 8388608 keys tested (0%)");
        assert_eq!(progress_line(2_097_152, Duration::from_secs(10)), "2097152 of 8388608 keys tested (25%), about 30 seconds left");
        assert_eq!(progress_line(8_388_607, Duration::from_mins(10)), "8388607 of 8388608 keys tested (99%), under a second left");
        assert_eq!(progress_line(1, Duration::from_secs(1)), "1 of 8388608 keys tested (0%), about 97 days 2 hours left");
        assert_eq!(percent(0), 0);
        assert_eq!(percent(u64::from(KEY_SPACE)), 100);
    }

    #[test]
    fn progress_counts_work_as_keys_and_notes_no_more_often_than_its_pause() {
        let progress = Progress::start(QUIET, 87, Duration::from_mins(10));
        assert_eq!(progress.pause, Duration::from_secs(30));
        assert_eq!(Progress::start(QUIET, 1, Duration::ZERO).pause, Duration::from_secs(1));
        assert_eq!(Progress::start(QUIET, 1, Duration::from_secs(100)).pause, Duration::from_secs(5));
        assert_eq!(Progress::start(QUIET, 1, Duration::MAX).pause, Duration::from_secs(30));

        progress.add(87 * 1000 + 86);
        assert_eq!(progress.keys_tested(), 1000);
        assert!(!progress.complete());
        progress.add(87 * (u64::from(KEY_SPACE) - 1000));
        assert_eq!(progress.keys_tested(), u64::from(KEY_SPACE));
        assert!(progress.complete());
    }

    #[test]
    fn a_note_of_progress_is_due_a_pause_after_the_start_and_a_pause_after_the_last() {
        // expected to take 100 seconds: a note every five
        let progress = Progress::start(QUIET, 1, Duration::from_secs(100));
        progress.add(2_097_152);
        assert_eq!(progress.note_at(Duration::from_millis(4999)), None);
        assert_eq!(progress.note_at(Duration::from_secs(5)).as_deref(), Some("2097152 of 8388608 keys tested (25%), about 15 seconds left"));
        // the note is written once, by the thread that saw it due first
        assert_eq!(progress.note_at(Duration::from_secs(5)), None);
        assert_eq!(progress.note_at(Duration::from_millis(9999)), None);
        progress.add(2_097_152);
        assert_eq!(progress.note_at(Duration::from_secs(12)).as_deref(), Some("4194304 of 8388608 keys tested (50%), about 12 seconds left"));
        // five seconds after the note that was late, not after the time it was due
        assert_eq!(progress.note_at(Duration::from_millis(16_999)), None);
        assert!(progress.note_at(Duration::from_secs(17)).is_some());
    }
}
