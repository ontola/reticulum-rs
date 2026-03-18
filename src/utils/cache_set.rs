//! A fixed-capacity cache with set semantics.
//!
//! CacheSet is a data structure that combines the properties of a HashSet
//! with a fixed capacity. When the capacity is reached, inserting a new
//! element evicts the oldest element (FIFO eviction policy).
//!
//! # Usage
//!
//! ```
//! use reticulum::utils::cache_set::CacheSet;
//!
//! let mut cache = CacheSet::new(3);
//!
//! cache.insert(&1);
//! cache.insert(&2);
//! cache.insert(&3);
//!
//! assert!(cache.contains(&1));
//! assert!(cache.contains(&2));
//! assert!(cache.contains(&3));
//!
//! // Adding a 4th element evicts the oldest (1)
//! cache.insert(&4);
//!
//! assert!(!cache.contains(&1)); // Evicted
//! assert!(cache.contains(&4));   // Still there
//! ```

use std::collections::{HashSet, VecDeque};

/// A fixed-capacity cache with FIFO eviction.
///
/// CacheSet combines a HashSet for O(1) membership checks with a VecDeque
/// for maintaining insertion order. When the capacity is reached and a new
/// element is inserted, the oldest element is automatically evicted.
///
/// # Type Parameters
///
/// - `T`: The element type, must be hashable, equatable, and cloneable
///
/// # Example
///
/// ```
/// use reticulum::utils::cache_set::CacheSet;
///
/// let mut cache: CacheSet<String> = CacheSet::new(100);
///
/// cache.insert(&"item1".to_string());
/// cache.insert(&"item2".to_string());
///
/// assert!(cache.contains(&"item1".to_string()));
/// ```
pub struct CacheSet<T: std::hash::Hash + Eq + Clone> {
    capacity: usize,
    set: HashSet<T>,
    queue: VecDeque<T>,
}

impl<T: std::hash::Hash + Eq + Clone> CacheSet<T> {
    /// Creates a new CacheSet with the specified capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The maximum number of elements to store
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::utils::cache_set::CacheSet;
    ///
    /// let cache = CacheSet::<i32>::new(10);
    /// ```
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            set: HashSet::new(),
            queue: VecDeque::new(),
        }
    }

    /// Inserts a value into the cache.
    ///
    /// If the cache is at capacity, the oldest element is evicted.
    /// If the value already exists, it is not inserted and false is returned.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to insert
    ///
    /// # Returns
    ///
    /// * `true` - If the value was inserted
    /// * `false` - If the value already existed
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::utils::cache_set::CacheSet;
    ///
    /// let mut cache = CacheSet::new(2);
    ///
    /// assert!(cache.insert(&1));
    /// assert!(!cache.insert(&1)); // Already exists
    /// ```
    pub fn insert(&mut self, value: &T) -> bool {
        if self.set.contains(&value) {
            return false;
        }

        if self.set.len() == self.capacity {
            if let Some(oldest) = self.queue.pop_front() {
                self.set.remove(&oldest);
            }
        }

        self.set.insert(value.clone());
        self.queue.push_back(value.clone());

        return true;
    }

    /// Checks if the cache contains a value.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to check for
    ///
    /// # Returns
    ///
    /// * `true` - If the value exists in the cache
    /// * `false` - Otherwise
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::utils::cache_set::CacheSet;
    ///
    /// let mut cache = CacheSet::new(10);
    /// cache.insert(&42);
    ///
    /// assert!(cache.contains(&42));
    /// assert!(!cache.contains(&99));
    /// ```
    pub fn contains(&self, value: &T) -> bool {
        self.set.contains(&value)
    }
}
