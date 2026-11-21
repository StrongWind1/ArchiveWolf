//! How long an attack may run: as the command line gives it, and as a message says it.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// The time an attack may take, by the clock on the wall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Budget {
    /// The attack is stopped when this much time has passed.
    Limit(Duration),
    /// The attack runs until it ends by itself.
    Unlimited,
}

impl Budget {
    /// The budget when the command line names none: ten minutes.
    pub const DEFAULT: Self = Self::Limit(Duration::from_mins(10));
}

impl FromStr for Budget {
    type Err = String;

    /// `none`, or a whole number of seconds, minutes or hours: `90s`, `10m`, `2h`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text == "none" {
            return Ok(Self::Unlimited);
        }
        let form = || "a budget is a number with a unit, as in 90s, 10m or 2h, or `none` for no limit".to_owned();
        let (number, unit) = text.char_indices().next_back().map(|(at, _)| text.split_at(at)).ok_or_else(form)?;
        let scale: u64 = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            _ => return Err(form()),
        };
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(form());
        }
        let seconds = number.parse::<u64>().ok().and_then(|count| count.checked_mul(scale)).ok_or_else(|| "that is longer than a budget can be: `none` is no limit".to_owned())?;
        if seconds == 0 {
            return Err("a budget of no time ends the search before it starts".to_owned());
        }
        Ok(Self::Limit(Duration::from_secs(seconds)))
    }
}

impl fmt::Display for Budget {
    /// The budget in words: `10 minutes`, `1 hour 30 minutes`, or `none`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit(time) => f.write_str(&in_words(*time)),
            Self::Unlimited => f.write_str("none"),
        }
    }
}

/// A span of time in words, to the second and in its two largest units: `under a second`,
/// `45 seconds`, `2 minutes 10 seconds`, `1 hour 20 minutes`, `3 days`.
pub(crate) fn in_words(time: Duration) -> String {
    const UNITS: [(&str, u64); 5] = [("year", 365 * 86400), ("day", 86400), ("hour", 3600), ("minute", 60), ("second", 1)];
    let count = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });

    let seconds = time.as_secs().saturating_add(u64::from(time.subsec_millis() >= 500));
    if seconds == 0 {
        return "under a second".to_owned();
    }
    let mut left = seconds;
    let mut parts = UNITS.iter().map(|&(unit, size)| {
        let n = left / size;
        left %= size;
        (n, unit)
    });
    // the largest unit there is something of, and the one below it when there is something of that
    let Some((n, unit)) = parts.find(|&(n, _)| n > 0) else { return "under a second".to_owned() };
    match parts.next() {
        Some((below, smaller)) if below > 0 => format!("{} {}", count(n, unit), count(below, smaller)),
        _ => count(n, unit),
    }
}

/// A span of time that is an estimate: `about 2 minutes 10 seconds`, `under a second`.
pub(crate) fn about(time: Duration) -> String {
    let words = in_words(time);
    if time < Duration::from_millis(500) { words } else { format!("about {words}") }
}

/// A budget, as `--budget` takes it, that is enough for a search that needs `needed`: half as
/// much again, and rounded up to ten seconds, a minute or an hour.
pub(crate) fn enough_for(needed: Duration) -> String {
    let seconds = needed.as_secs().saturating_add(u64::from(needed.subsec_nanos() > 0)).max(1);
    // no more than a budget can be, rounded up
    let seconds = seconds.saturating_add(seconds / 2).min(u64::MAX / 2);
    if seconds < 120 {
        format!("{}s", seconds.div_ceil(10).saturating_mul(10))
    } else if seconds < 120 * 60 {
        format!("{}m", seconds.div_ceil(60))
    } else {
        format!("{}h", seconds.div_ceil(3600))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_is_a_number_with_a_unit_or_none() {
        assert_eq!("90s".parse(), Ok(Budget::Limit(Duration::from_secs(90))));
        assert_eq!("10m".parse(), Ok(Budget::DEFAULT));
        assert_eq!("2h".parse(), Ok(Budget::Limit(Duration::from_hours(2))));
        assert_eq!("1s".parse(), Ok(Budget::Limit(Duration::from_secs(1))));
        assert_eq!("007m".parse(), Ok(Budget::Limit(Duration::from_mins(7))));
        assert_eq!("none".parse(), Ok(Budget::Unlimited));
        // the longest that fits
        assert_eq!(format!("{}s", u64::MAX).parse(), Ok(Budget::Limit(Duration::from_secs(u64::MAX))));
    }

    #[test]
    fn anything_else_is_refused_with_the_form_a_budget_has() {
        for text in ["", "10", "m", "s", "10 m", " 10m", "10m ", "10M", "10min", "1.5h", "-5m", "+5m", "1e3s", "10d", "ten", "None", "NONE", "inf", "0x10s", "10m30s", "\u{664}m", "5\u{43c}"] {
            let error = text.parse::<Budget>().unwrap_err();
            assert!(error.contains("a number with a unit") && error.contains("none"), "{text:?}: {error}");
        }
        // no time at all is no budget
        for text in ["0s", "0m", "0h", "000s"] {
            assert!(text.parse::<Budget>().unwrap_err().contains("no time"), "{text:?}");
        }
        // more seconds than the number holds
        for text in [format!("{}0s", u64::MAX), format!("{}m", u64::MAX), format!("{}h", u64::MAX / 3600 + 1)] {
            assert!(text.parse::<Budget>().unwrap_err().contains("longer than a budget can be"), "{text:?}");
        }
    }

    #[test]
    fn a_span_of_time_is_said_in_its_two_largest_units() {
        let words = |seconds: u64| in_words(Duration::from_secs(seconds));
        assert_eq!(in_words(Duration::ZERO), "under a second");
        assert_eq!(in_words(Duration::from_millis(499)), "under a second");
        assert_eq!(in_words(Duration::from_millis(500)), "1 second");
        assert_eq!(in_words(Duration::from_millis(1499)), "1 second");
        assert_eq!(words(2), "2 seconds");
        assert_eq!(words(60), "1 minute");
        assert_eq!(words(61), "1 minute 1 second");
        assert_eq!(words(130), "2 minutes 10 seconds");
        assert_eq!(words(3600), "1 hour");
        assert_eq!(words(3601), "1 hour");
        assert_eq!(words(4800), "1 hour 20 minutes");
        assert_eq!(words(86400 * 3), "3 days");
        assert_eq!(words(86400 * 3 + 7200 + 59), "3 days 2 hours");
        assert_eq!(words(86400 * 365 * 2 + 86400), "2 years 1 day");
        assert!(in_words(Duration::MAX).ends_with(" days"), "{}", in_words(Duration::MAX));

        assert_eq!(about(Duration::from_millis(499)), "under a second");
        assert_eq!(about(Duration::from_millis(500)), "about 1 second");
        assert_eq!(about(Duration::from_mins(80)), "about 1 hour 20 minutes");

        assert_eq!(Budget::DEFAULT.to_string(), "10 minutes");
        assert_eq!(Budget::Limit(Duration::from_mins(90)).to_string(), "1 hour 30 minutes");
        assert_eq!(Budget::Unlimited.to_string(), "none");
    }

    #[test]
    fn a_budget_that_is_suggested_is_one_the_command_line_takes_and_is_enough() {
        assert_eq!(enough_for(Duration::ZERO), "10s");
        assert_eq!(enough_for(Duration::from_millis(1)), "10s");
        assert_eq!(enough_for(Duration::from_secs(45)), "70s");
        assert_eq!(enough_for(Duration::from_secs(53)), "80s");
        assert_eq!(enough_for(Duration::from_millis(53_001)), "90s");
        assert_eq!(enough_for(Duration::from_secs(80)), "2m");
        assert_eq!(enough_for(Duration::from_mins(10)), "15m");
        assert_eq!(enough_for(Duration::from_mins(80)), "2h");
        assert_eq!(enough_for(Duration::from_hours(24)), "36h");
        for seconds in [0, 1, 9, 79, 80, 81, 119, 600, 4799, 4800, 4801, 7200, 100_000, u64::MAX / 4000, u64::MAX] {
            let needed = Duration::from_secs(seconds);
            let Ok(Budget::Limit(suggested)) = enough_for(needed).parse::<Budget>() else { panic!("{seconds}: {}", enough_for(needed)) };
            assert!(suggested > needed || seconds > u64::MAX / 4000, "{seconds}: {suggested:?}");
        }
    }
}
