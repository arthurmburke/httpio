//! Modular sequence-number arithmetic (RFC 9293 §3.4): comparisons must
//! account for wraparound, so "less than" is defined via signed distance
//! rather than a plain numeric `<`.

use std::cmp::Ordering;
use std::fmt;
use std::ops::{Add, Sub};

#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Seq(pub u32);

impl Seq {
    pub fn new(v: u32) -> Self {
        Seq(v)
    }

    /// Signed distance `self - other`, wrapping correctly across the
    /// 32-bit sequence space.
    pub fn distance(self, other: Seq) -> i32 {
        self.0.wrapping_sub(other.0) as i32
    }

    pub fn lt(self, other: Seq) -> bool {
        self.distance(other) < 0
    }
    pub fn leq(self, other: Seq) -> bool {
        self.distance(other) <= 0
    }
    pub fn gt(self, other: Seq) -> bool {
        self.distance(other) > 0
    }
    pub fn geq(self, other: Seq) -> bool {
        self.distance(other) >= 0
    }

    /// True if `self` falls in `[start, end)` modulo wraparound.
    pub fn in_range(self, start: Seq, end: Seq) -> bool {
        self.geq(start) && self.lt(end)
    }
}

impl Add<u32> for Seq {
    type Output = Seq;
    fn add(self, rhs: u32) -> Seq {
        Seq(self.0.wrapping_add(rhs))
    }
}

impl Sub<u32> for Seq {
    type Output = Seq;
    fn sub(self, rhs: u32) -> Seq {
        Seq(self.0.wrapping_sub(rhs))
    }
}

impl PartialOrd for Seq {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Seq {
    /// Total order consistent with `lt`/`gt` above. Only meaningful for
    /// sequence numbers that are actually within the same "window" of
    /// each other (i.e. not compared across more than half the sequence
    /// space apart) -- true of every comparison this stack performs.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.distance(*other) {
            0 => Ordering::Equal,
            d if d < 0 => Ordering::Less,
            _ => Ordering::Greater,
        }
    }
}

impl fmt::Debug for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Seq({})", self.0)
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
