//! Packet container support.
//!
//! Some packets contain other packets.  This creates a tree
//! structure.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::slice;
use std::vec;

use crate::{
    Packet,
    crypto::hash,
    packet::Iter,
    types::HashAlgorithm,
};

/// Holds zero or more OpenPGP packets.
///
/// This is used by OpenPGP container packets, like the compressed
/// data packet, to store the containing packets.
#[derive(Clone)]
pub(crate) struct Container {
    /// Used by container packets (such as the encryption and
    /// compression packets) to reference their immediate children.
    /// This results in a tree structure.
    ///
    /// This is automatically populated when using the `PacketPile`
    /// deserialization routines, e.g., [`PacketPile::from_file`].  By
    /// default, it is *not* automatically filled in by the
    /// [`PacketParser`] deserialization routines; this needs to be
    /// done manually.
    ///
    ///   [`PacketPile`]: ../struct.PacketPile.html
    ///   [`PacketPile::from_file`]: ../struct.PacketPile.html#method.from_file
    ///   [`PacketParser`]: ../parse/struct.PacketParser.html
    pub(crate) packets: Vec<Packet>,

    /// Holds a packet's body.
    ///
    /// We conceptually divide packets into two parts: the header and
    /// the body.  Whereas the header is read eagerly when the packet
    /// is deserialized, the body is only read on demand.
    ///
    /// A packet's body is stored here either when configured via
    /// [`PacketParserBuilder::buffer_unread_content`], when one of
    /// the [`PacketPile`] deserialization routines is used, or on demand
    /// for a particular packet using the
    /// [`PacketParser::buffer_unread_content`] method.
    ///
    ///   [`PacketParserBuilder::buffer_unread_content`]: ../parse/struct.PacketParserBuilder.html#method.buffer_unread_content
    ///   [`PacketPile`]: ../struct.PacketPile.html
    ///   [`PacketParser::buffer_unread_content`]: ../parse/struct.PacketParser.html#method.buffer_unread_content
    ///
    /// There are three different types of packets:
    ///
    ///   - Packets like the [`UserID`] and [`Signature`] packets,
    ///     don't actually have a body.  These packets don't use this
    ///     field.
    ///
    ///   [`UserID`]: ../packet/struct.UserID.html
    ///   [`Signature`]: ../packet/signature/struct.Signature.html
    ///
    ///   - One packet, the literal data packet, includes unstructured
    ///     data.  That data is stored in [`Literal`].
    ///
    ///   [`Literal`]: ../packet/struct.Literal.html
    ///
    ///   - Some packets are containers.  If the parser does not parse
    ///     the packet's child, either because the caller used
    ///     [`PacketParser::next`] to get the next packet, or the
    ///     maximum recursion depth was reached, then the packets can
    ///     be stored here as a byte stream.  (If the caller so
    ///     chooses, the content can be parsed later using the regular
    ///     deserialization routines, since the content is just an
    ///     OpenPGP message.)
    ///
    ///   [`PacketParser::next`]: ../parse/struct.PacketParser.html#method.next
    ///
    /// Note: if some of a packet's data is processed, and the
    /// `PacketParser` is configured to buffer unread content, then
    /// this is not the packet's entire content; it is just the unread
    /// content.
    body: Vec<u8>,

    /// We compute a digest over the body to implement comparison.
    body_digest: Vec<u8>,
}

// Pick the fastest hash function from the SHA2 family for the
// architectures word size.  On 64-bit architectures, SHA512 is almost
// twice as fast, but on 32-bit ones, SHA256 is faster.
#[cfg(target_pointer_width = "64")]
const CONTAINER_BODY_HASH: HashAlgorithm = HashAlgorithm::SHA512;
#[cfg(not(target_pointer_width = "64"))]
const CONTAINER_BODY_HASH: HashAlgorithm = HashAlgorithm::SHA256;

impl PartialEq for Container {
    fn eq(&self, other: &Container) -> bool {
        self.packets == other.packets
            && self.body_digest == other.body_digest
    }
}

impl Eq for Container {}

impl Hash for Container {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.packets.hash(state);
        self.body_digest.hash(state);
    }
}

impl Default for Container {
    fn default() -> Self {
        Self {
            packets: Vec::with_capacity(0),
            body: Vec::with_capacity(0),
            body_digest: Self::empty_body_digest(),
        }
    }
}

impl From<Vec<Packet>> for Container {
    fn from(packets: Vec<Packet>) -> Self {
        Self {
            packets,
            body: Vec::with_capacity(0),
            body_digest: Self::empty_body_digest(),
        }
    }
}

impl fmt::Debug for Container {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let threshold = 16;
        let prefix = &self.body[..std::cmp::min(threshold, self.body.len())];
        let mut prefix_fmt = crate::fmt::hex::encode(prefix);
        if self.body.len() > threshold {
            prefix_fmt.push_str("...");
        }
        prefix_fmt.push_str(&format!(" ({} bytes)", self.body.len())[..]);

        f.debug_struct("Container")
            .field("packets", &self.packets)
            .field("body", &prefix_fmt)
            .field("body_digest", &self.body_digest())
            .finish()
    }
}

impl Container {
    /// Returns a reference to this Packet's children.
    pub fn children_ref(&self) -> &[Packet] {
        &self.packets
    }

    /// Returns a mutable reference to this Packet's children.
    pub fn children_mut(&mut self) -> &mut Vec<Packet> {
        &mut self.packets
    }

    /// Returns an iterator over the packet's descendants.  The
    /// descendants are visited in depth-first order.
    pub fn descendants(&self) -> Iter {
        return Iter {
            // Iterate over each packet in the message.
            children: self.children(),
            child: None,
            grandchildren: None,
            depth: 0,
        };
    }

    /// Returns an iterator over the packet's immediate children.
    pub fn children<'a>(&'a self) -> slice::Iter<'a, Packet> {
        self.packets.iter()
    }

    /// Returns an `IntoIter` over the packet's immediate children.
    pub fn into_children(self) -> vec::IntoIter<Packet> {
        self.packets.into_iter()
    }

    /// Retrieves the packet's body.
    ///
    /// Packets can store a sequence of bytes as body, e.g. if the
    /// maximum recursion level is reached while parsing a sequence of
    /// packets, the container's body is stored as is.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Sets the packet's body.
    ///
    /// Setting the body clears the old body, or any of the packet's
    /// descendants.
    pub fn set_body(&mut self, data: Vec<u8>) -> Vec<u8> {
        self.packets.clear();
        let mut h = Self::make_body_hash();
        h.update(&data);
        self.set_body_hash(h);
        std::mem::replace(&mut self.body, data)
    }

    /// Returns the hash for the empty body.
    fn empty_body_digest() -> Vec<u8> {
        lazy_static!{
            static ref DIGEST: Vec<u8> = {
                let mut h = Container::make_body_hash();
                let mut d = vec![0; h.digest_size()];
                h.digest(&mut d);
                d
            };
        }

        DIGEST.clone()
    }

    /// Creates a hash context for hashing the body.
    pub(crate) // For parse.rs
    fn make_body_hash() -> hash::Context {
        CONTAINER_BODY_HASH.context()
            .expect("CONTAINER_BODY_HASH must be implemented")
    }

    /// Hashes content that has been streamed.
    pub(crate) // For parse.rs
    fn set_body_hash(&mut self, mut h: hash::Context) {
        self.body_digest.resize(h.digest_size(), 0);
        h.digest(&mut self.body_digest);
    }

    pub(crate)
    fn body_digest(&self) -> String {
        crate::fmt::hex::encode(&self.body_digest)
    }

    pub(crate) // For parse.rs
    fn body_mut(&mut self) -> &mut Vec<u8> {
        &mut self.body
    }

    // Converts an indentation level to whitespace.
    fn indent(depth: usize) -> &'static str {
        use std::cmp;

        let s = "                                                  ";
        return &s[0..cmp::min(depth, s.len())];
    }

    // Pretty prints the container to stderr.
    //
    // This function is primarily intended for debugging purposes.
    //
    // `indent` is the number of spaces to indent the output.
    pub(crate) fn pretty_print(&self, indent: usize) {
        for (i, p) in self.packets.iter().enumerate() {
            eprintln!("{}{}: {:?}",
                      Self::indent(indent), i + 1, p);
            if let Some(ref children) = self.packets[i].container_ref() {
                children.pretty_print(indent + 1);
            }
        }
    }
}

macro_rules! the_common_container_forwards {
    () => {
        /// Returns a reference to the container.
        pub(crate) fn container_ref(&self) -> &packet::Container {
            &self.container
        }

        /// Returns a mutable reference to the container.
        pub(crate) fn container_mut(&mut self) -> &mut packet::Container {
            &mut self.container
        }

        /// Gets a reference to the this packet's body.
        pub fn body(&self) -> &[u8] {
            self.container.body()
        }

        /// Gets a mutable reference to the this packet's body.
        pub fn body_mut(&mut self) -> &mut Vec<u8> {
            self.container.body_mut()
        }

        /// Sets the this packet's body.
        pub fn set_body(&mut self, data: Vec<u8>) -> Vec<u8> {
            self.container.set_body(data)
        }
    };
}

macro_rules! impl_body_forwards {
    ($typ:ident) => {
        /// This packet implements the unprocessed container
        /// interface.
        ///
        /// Container packets like this one can contain unprocessed
        /// data.
        impl $typ {
            the_common_container_forwards!();
        }
    };
}

macro_rules! impl_container_forwards {
    ($typ:ident) => {
        /// This packet implements the container interface.
        ///
        /// Container packets can contain other packets, unprocessed
        /// data, or both.
        impl $typ {
            the_common_container_forwards!();

            /// Returns a reference to this Packet's children.
            pub fn children_ref(&self) -> &[Packet] {
                self.container.children_ref()
            }

            /// Returns a mutable reference to this Packet's children.
            pub fn children_mut(&mut self) -> &mut Vec<Packet> {
                self.container.children_mut()
            }

            /// Returns an iterator over the packet's immediate children.
            pub fn children<'a>(&'a self) -> impl Iterator<Item = &'a Packet> {
                self.container.children()
            }

            /// Returns an iterator over all of the packet's descendants, in
            /// depth-first order.
            pub fn descendants(&self) -> super::Iter {
                self.container.descendants()
            }
        }
    };
}

impl Packet {
    pub(crate) // for packet_pile.rs
    fn container_ref(&self) -> Option<&Container> {
        match self {
            Packet::CompressedData(p) => Some(p.container_ref()),
            Packet::SEIP(p) => Some(p.container_ref()),
            Packet::AED(p) => Some(p.container_ref()),
            Packet::Literal(p) => Some(p.container_ref()),
            Packet::Unknown(p) => Some(p.container_ref()),
            _ => None,
        }
    }

    pub(crate) // for packet_pile.rs
    fn container_mut(&mut self) -> Option<&mut Container> {
        match self {
            Packet::CompressedData(p) => Some(p.container_mut()),
            Packet::SEIP(p) => Some(p.container_mut()),
            Packet::AED(p) => Some(p.container_mut()),
            Packet::Literal(p) => Some(p.container_mut()),
            Packet::Unknown(p) => Some(p.container_mut()),
            _ => None,
        }
    }

    /// Returns an iterator over the packet's immediate children.
    pub(crate) fn children<'a>(&'a self) -> impl Iterator<Item = &'a Packet> {
        self.container_ref().map(|c| c.children()).unwrap_or_else(|| [].iter())
    }

    /// Returns an iterator over all of the packet's descendants, in
    /// depth-first order.
    pub(crate) fn descendants(&self) -> Iter {
        self.container_ref().map(|c| c.descendants()).unwrap_or_default()
    }

    /// Retrieves the packet's body.
    ///
    /// Packets can store a sequence of bytes as body, e.g. if the
    /// maximum recursion level is reached while parsing a sequence of
    /// packets, the container's body is stored as is.
    pub(crate) fn body(&self) -> Option<&[u8]> {
        self.container_ref().map(|c| c.body())
    }
}
