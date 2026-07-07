//! A faster hashset implementation using the GxHash Hasher. This is
//! not cryptographically secure, but is faster than the default hasher.
pub type HashSet<K> = std::collections::HashSet<K, gxhash::GxBuildHasher>;
