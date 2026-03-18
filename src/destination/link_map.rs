//! Mapping from destination addresses to link IDs.
//!
//! This module provides the LinkMap which maps destination addresses
//! to their corresponding link IDs. It provides:
//!
//! - Fast lookup of link IDs by destination address
//! - Insertion and removal of mappings
//!
//! # Overview
//!
//! LinkMap is used to track which links are associated with which
//! destination addresses. When sending data to a destination, the
//! link ID can be looked up to find the active link.
//!
//! # Usage
//!
//! This is used internally by the Transport to manage link addressing.

use std::collections::HashMap;

use crate::hash::AddressHash;

use super::link::LinkId;

/// A map from destination addresses to link IDs.
///
/// LinkMap provides O(1) lookup of link IDs given a destination
/// address. This is used to quickly find the active link for
/// a destination when sending data.
pub struct LinkMap {
    /// Internal map from addresses to link IDs.
    map: HashMap<AddressHash, LinkId>,
}

impl LinkMap {
    /// Creates a new empty LinkMap.
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::destination::link_map::LinkMap;
    ///
    /// let map = LinkMap::new();
    /// ```
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Resolves a destination address to a link ID.
    ///
    /// Looks up the link ID associated with a destination address.
    ///
    /// # Arguments
    ///
    /// * `address` - The destination address to look up
    ///
    /// # Returns
    ///
    /// * `Some(LinkId)` - If a link exists for this address
    /// * `None` - If no link exists for this address
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::destination::link_map::LinkMap;
    /// use reticulum::hash::AddressHash;
    ///
    /// let mut map = LinkMap::new();
    /// // ... add entries ...
    /// let link_id = map.resolve(&AddressHash::new_empty());
    /// ```
    pub fn resolve(&self, address: &AddressHash) -> Option<LinkId> {
        self.map.get(address).copied()
    }

    /// Inserts a mapping from address to link ID.
    ///
    /// Associates a destination address with a link ID.
    ///
    /// # Arguments
    ///
    /// * `address` - The destination address
    /// * `id` - The link ID to associate with this address
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::destination::link_map::LinkMap;
    /// use reticulum::hash::AddressHash;
    ///
    /// let mut map = LinkMap::new();
    /// // ... create link_id ...
    /// map.insert(&AddressHash::new_empty(), &link_id);
    /// ```
    pub fn insert(&mut self, address: &AddressHash, id: &LinkId) {
        self.map.insert(*address, *id);
    }

    /// Removes a mapping for a destination address.
    ///
    /// Removes the association between a destination address and its link.
    ///
    /// # Arguments
    ///
    /// * `address` - The destination address to remove
    ///
    /// # Example
    ///
    /// ```
    /// use reticulum::destination::link_map::LinkMap;
    /// use reticulum::hash::AddressHash;
    ///
    /// let mut map = LinkMap::new();
    /// map.remove(&AddressHash::new_empty());
    /// ```
    pub fn remove(&mut self, address: &AddressHash) {
        self.map.remove(address);
    }
}
