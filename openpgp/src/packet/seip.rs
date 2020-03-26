//! Symmetrically Encrypted Integrity Protected data packets.
//!
//! An encrypted data packet is a container.  See [Section 5.13 of RFC
//! 4880] for details.
//!
//! [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13

use crate::packet;
use crate::Packet;

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [Section 5.13 of RFC
/// 4880] for details.
///
/// [Section 5.13 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.13
#[derive(Clone, Debug)]
pub struct SEIP1 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,

    /// This is a container packet.
    container: packet::Container,
}

impl std::ops::Deref for SEIP1 {
    type Target = packet::Container;
    fn deref(&self) -> &Self::Target {
        &self.container
    }
}

impl std::ops::DerefMut for SEIP1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.container
    }
}

impl PartialEq for SEIP1 {
    fn eq(&self, other: &SEIP1) -> bool {
        self.container == other.container
    }
}

impl Eq for SEIP1 {}

impl std::hash::Hash for SEIP1 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.container, state);
    }
}

impl SEIP1 {
    /// Creates a new SEIP1 packet.
    pub fn new() -> Self {
        Self {
            common: Default::default(),
            container: Default::default(),
        }
    }
}

impl From<SEIP1> for super::SEIP {
    fn from(p: SEIP1) -> Self {
        super::SEIP::V1(p)
    }
}

impl From<SEIP1> for Packet {
    fn from(s: SEIP1) -> Self {
        Packet::SEIP(s.into())
    }
}
