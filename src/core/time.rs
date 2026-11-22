//! The stack's clock: monotonic time as a count of nanoseconds in one
//! integer.
//!
//! `std::time::Instant` and `Duration` carry seconds and nanoseconds
//! separately, so every comparison, subtraction and scaling on them is
//! two-part arithmetic with carries (and, for scaling a `Duration`, 128-bit
//! division). The stack does that arithmetic for every packet and every
//! poll: ageing ARP entries, checking deadlines, smoothing round-trip
//! times. Here each of those is one integer operation.
//!
//! [`Instant`] and [`Duration`] offer the subset of the standard types'
//! methods the stack uses, under the same names, so code reads the same.
//! Sums and products saturate rather than overflow; a `u64` of nanoseconds
//! covers 584 years.

use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

/// A span of time, in nanoseconds.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(u64);

impl Duration {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    pub const fn from_micros(micros: u64) -> Self {
        Self(micros.saturating_mul(1_000))
    }

    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1_000_000))
    }

    pub const fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    /// As the standard type returns it, for code written against either.
    pub const fn as_nanos(self) -> u128 {
        self.0 as u128
    }

    pub const fn as_micros(self) -> u128 {
        (self.0 / 1_000) as u128
    }

    pub const fn as_millis(self) -> u128 {
        (self.0 / 1_000_000) as u128
    }

    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000_000
    }

    pub fn as_secs_f64(self) -> f64 {
        self.0 as f64 / 1e9
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    pub const fn abs_diff(self, other: Self) -> Self {
        Self(self.0.abs_diff(other.0))
    }

    pub const fn saturating_sub(self, other: Self) -> Self {
        Self(self.0.saturating_sub(other.0))
    }
}

impl From<std::time::Duration> for Duration {
    fn from(duration: std::time::Duration) -> Self {
        Self(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
    }
}

impl From<Duration> for std::time::Duration {
    fn from(duration: Duration) -> Self {
        Self::from_nanos(duration.0)
    }
}

impl Add for Duration {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

/// Saturates at zero, where the standard type panics.
impl Sub for Duration {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.saturating_sub(rhs)
    }
}

impl Mul<u32> for Duration {
    type Output = Self;
    fn mul(self, rhs: u32) -> Self {
        Self(self.0.saturating_mul(u64::from(rhs)))
    }
}

impl Div<u32> for Duration {
    type Output = Self;
    fn div(self, rhs: u32) -> Self {
        Self(self.0 / u64::from(rhs))
    }
}

impl std::fmt::Debug for Duration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::time::Duration::from(*self).fmt(f)
    }
}

/// A point on the monotonic clock, in nanoseconds since an arbitrary
/// origin (boot). Comparable between threads of one process.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// Reads the monotonic clock (one vDSO call, no system call).
    pub fn now() -> Self {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid timespec to write to. CLOCK_MONOTONIC
        // always exists, so the call cannot fail.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        Self(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
    }

    /// Time since `earlier`, or zero if `earlier` is the later of the two.
    pub const fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    /// Time since `earlier`, or `None` if `earlier` is the later of the two.
    pub const fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        match self.0.checked_sub(earlier.0) {
            Some(nanos) => Some(Duration(nanos)),
            None => None,
        }
    }

    /// Same as [`saturating_duration_since`](Self::saturating_duration_since).
    pub const fn duration_since(self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }

    /// Time from this instant to now.
    pub fn elapsed(self) -> Duration {
        Self::now().saturating_duration_since(self)
    }
}

impl Add<Duration> for Instant {
    type Output = Self;
    fn add(self, rhs: Duration) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl Sub<Duration> for Instant {
    type Output = Self;
    fn sub(self, rhs: Duration) -> Self {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

impl Sub for Instant {
    type Output = Duration;
    fn sub(self, rhs: Self) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

impl std::fmt::Debug for Instant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Instant({}ns)", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_convert_scale_and_saturate() {
        assert_eq!(Duration::from_secs(2), Duration::from_millis(2_000));
        assert_eq!(Duration::from_millis(3), Duration::from_micros(3_000));
        assert_eq!(Duration::from_micros(5), Duration::from_nanos(5_000));
        let d = Duration::from_millis(200);
        assert_eq!(d * 2, Duration::from_millis(400));
        assert_eq!(d * 7 / 8, Duration::from_millis(175));
        assert_eq!(d / 4, Duration::from_millis(50));
        assert_eq!(
            d.abs_diff(Duration::from_millis(350)),
            Duration::from_millis(150)
        );
        assert_eq!(d + d, Duration::from_millis(400));
        assert_eq!(d - Duration::from_secs(1), Duration::ZERO);
        assert_eq!(
            d.clamp(Duration::from_secs(1), Duration::from_secs(2)),
            Duration::from_secs(1)
        );
        assert_eq!(
            (d.as_nanos(), d.as_micros(), d.as_millis()),
            (200_000_000, 200_000, 200)
        );
        assert_eq!(Duration::from_secs(90).as_secs(), 90);
        assert_eq!(Duration::MAX * 2, Duration::MAX);
        assert_eq!(Duration::MAX + d, Duration::MAX);
        assert_eq!(Duration::from_secs(u64::MAX), Duration::MAX);

        let std = std::time::Duration::from_micros(1_500);
        assert_eq!(Duration::from(std), Duration::from_micros(1_500));
        assert_eq!(std::time::Duration::from(Duration::from_micros(1_500)), std);
        assert_eq!(format!("{:?}", Duration::from_millis(1500)), "1.5s");
    }

    #[test]
    fn instants_order_and_subtract_without_underflow() {
        let start = Instant::now();
        let later = start + Duration::from_secs(1);
        assert!(later > start);
        assert_eq!(later - start, Duration::from_secs(1));
        assert_eq!(
            later.saturating_duration_since(start),
            Duration::from_secs(1)
        );
        assert_eq!(start.saturating_duration_since(later), Duration::ZERO);
        assert_eq!(start.checked_duration_since(later), None);
        assert_eq!(
            later.checked_duration_since(start),
            Some(Duration::from_secs(1))
        );
        assert_eq!(later - Duration::from_secs(1), start);
        let mut moving = start;
        moving += Duration::from_millis(5);
        assert_eq!(moving - start, Duration::from_millis(5));

        // The clock does not run backwards, and it runs.
        let a = Instant::now();
        let b = Instant::now();
        assert!(b >= a);
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(a.elapsed() >= Duration::from_millis(2));
    }
}
