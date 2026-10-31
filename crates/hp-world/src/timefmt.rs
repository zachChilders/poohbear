//! Calendar math and `date`-style formatting, without a time library. All
//! times are UTC, which is what the emulated host reports.

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i64,
    /// 1..=12
    pub month: u32,
    /// 1..=31
    pub day: u32,
    pub hour: u32,
    pub min: u32,
    pub sec: u32,
    /// 0 = Sunday
    pub wday: u32,
}

impl Civil {
    /// Convert seconds since the Unix epoch (Howard Hinnant's algorithm).
    pub fn from_epoch(secs: i64) -> Civil {
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        Civil {
            year,
            month,
            day,
            hour: (rem / 3600) as u32,
            min: (rem % 3600 / 60) as u32,
            sec: (rem % 60) as u32,
            wday: (days + 4).rem_euclid(7) as u32,
        }
    }

    pub fn month_name(&self) -> &'static str {
        MONTHS[(self.month - 1) as usize]
    }

    pub fn day_name(&self) -> &'static str {
        DAYS[self.wday as usize]
    }
}

/// `date` with no format: `Fri Oct 31 18:22:09 UTC 2025`.
pub fn date_default(secs: i64) -> String {
    let c = Civil::from_epoch(secs);
    format!(
        "{} {} {:>2} {:02}:{:02}:{:02} UTC {}",
        c.day_name(),
        c.month_name(),
        c.day,
        c.hour,
        c.min,
        c.sec,
        c.year
    )
}

/// The `ls -l` date column: `Oct 28 09:14` for recent files, `Oct 28  2024`
/// for files more than about six months from `now`.
pub fn ls_date(mtime: i64, now: i64) -> String {
    let c = Civil::from_epoch(mtime);
    let six_months = 182 * 86_400;
    if (now - mtime).abs() > six_months {
        format!("{} {:>2}  {}", c.month_name(), c.day, c.year)
    } else {
        format!("{} {:>2} {:02}:{:02}", c.month_name(), c.day, c.hour, c.min)
    }
}

/// A small `strftime`: %Y %m %d %H %M %S %s %F %T %a %b %Z %e %y %%.
/// Unknown directives are kept as-is, like GNU date.
pub fn strftime(fmt: &str, secs: i64) -> String {
    let c = Civil::from_epoch(secs);
    let mut out = String::new();
    let mut chars = fmt.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('Y') => out.push_str(&c.year.to_string()),
            Some('y') => out.push_str(&format!("{:02}", c.year.rem_euclid(100))),
            Some('m') => out.push_str(&format!("{:02}", c.month)),
            Some('d') => out.push_str(&format!("{:02}", c.day)),
            Some('e') => out.push_str(&format!("{:>2}", c.day)),
            Some('H') => out.push_str(&format!("{:02}", c.hour)),
            Some('M') => out.push_str(&format!("{:02}", c.min)),
            Some('S') => out.push_str(&format!("{:02}", c.sec)),
            Some('s') => out.push_str(&secs.to_string()),
            Some('F') => out.push_str(&format!("{}-{:02}-{:02}", c.year, c.month, c.day)),
            Some('T') => out.push_str(&format!("{:02}:{:02}:{:02}", c.hour, c.min, c.sec)),
            Some('a') => out.push_str(c.day_name()),
            Some('b') => out.push_str(c.month_name()),
            Some('Z') => out.push_str("UTC"),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_conversion_handles_known_dates() {
        let c = Civil::from_epoch(0);
        assert_eq!(
            (c.year, c.month, c.day, c.wday),
            (1970, 1, 1, 4),
            "a Thursday"
        );
        let c = Civil::from_epoch(1_761_934_929); // 2025-10-31 18:22:09 UTC, a Friday
        assert_eq!(
            (c.year, c.month, c.day, c.hour, c.min, c.sec, c.wday),
            (2025, 10, 31, 18, 22, 9, 5)
        );
        let leap = Civil::from_epoch(951_782_400); // 2000-02-29
        assert_eq!((leap.year, leap.month, leap.day), (2000, 2, 29));
        let before = Civil::from_epoch(-86_400);
        assert_eq!((before.year, before.month, before.day), (1969, 12, 31));
    }

    #[test]
    fn date_default_matches_gnu_date() {
        assert_eq!(date_default(1_761_934_929), "Fri Oct 31 18:22:09 UTC 2025");
        assert_eq!(
            date_default(1_757_000_000),
            "Thu Sep  4 15:33:20 UTC 2025",
            "single digit days are space padded"
        );
    }

    #[test]
    fn ls_dates_show_the_time_when_recent_and_the_year_when_old() {
        let now = 1_761_934_929;
        assert_eq!(ls_date(now - 86_400, now), "Oct 30 18:22");
        assert_eq!(ls_date(1_729_000_000, now), "Oct 15  2024");
        assert_eq!(ls_date(now + 10, now), "Oct 31 18:22");
    }

    #[test]
    fn strftime_supports_the_common_directives() {
        let t = 1_761_934_929;
        assert_eq!(strftime("%Y-%m-%d %H:%M:%S", t), "2025-10-31 18:22:09");
        assert_eq!(strftime("%F %T %Z", t), "2025-10-31 18:22:09 UTC");
        assert_eq!(strftime("%s", t), "1761934929");
        assert_eq!(strftime("%a %b %e %y 100%%", t), "Fri Oct 31 25 100%");
        assert_eq!(strftime("%Q and %", t), "%Q and %", "unknown kept as-is");
    }
}
