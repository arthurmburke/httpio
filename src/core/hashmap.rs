//! A faster hashmap implementation using the GxHash Hasher. This is
//! not cryptographically secure, but is faster than the default hasher.
pub type HashMap<K, V> = std::collections::HashMap<K, V, gxhash::GxBuildHasher>;
