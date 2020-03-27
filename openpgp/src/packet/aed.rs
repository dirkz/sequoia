//! AEAD encrypted data packets.

use crate::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use crate::packet;
use crate::Packet;
use crate::Error;
use crate::Result;

/// Holds an AEAD encrypted data packet.
///
/// An AEAD encrypted data packet is a container.  See [Section 5.16
/// of RFC 4880bis] for details.
///
/// [Section 5.16 of RFC 4880bis]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.16
///
/// This feature is [experimental](../../index.html#experimental-features).
///
/// # A note on equality
///
/// An unprocessed (encrypted) `SEIP` packet is never considered equal
/// to a processed (decrypted) one.  Likewise, a processed (decrypted)
/// packet is never considered equal to a structured (parsed) one.
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AED1 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// Symmetric algorithm.
    sym_algo: SymmetricAlgorithm,
    /// AEAD algorithm.
    aead: AEADAlgorithm,
    /// Chunk size.
    chunk_size: usize,
    /// Initialization vector for the AEAD algorithm.
    iv: Box<[u8]>,

    /// This is a container packet.
    container: packet::Container,
}

impl std::ops::Deref for AED1 {
    type Target = packet::Container;
    fn deref(&self) -> &Self::Target {
        &self.container
    }
}

impl std::ops::DerefMut for AED1 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.container
    }
}

impl AED1 {
    /// Creates a new AED1 object.
    pub fn new(sym_algo: SymmetricAlgorithm,
               aead: AEADAlgorithm,
               chunk_size: usize,
               iv: Box<[u8]>) -> Result<Self> {
        if chunk_size.count_ones() != 1 {
            return Err(Error::InvalidArgument(
                format!("chunk size is not a power of two: {}", chunk_size))
                .into());
        }

        if chunk_size < 64 {
            return Err(Error::InvalidArgument(
                format!("chunk size is too small: {}", chunk_size))
                .into());
        }

        Ok(AED1 {
            common: Default::default(),
            sym_algo,
            aead,
            chunk_size,
            iv,
            container: Default::default(),
        })
    }

    /// Gets the symmetric algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.sym_algo
    }

    /// Sets the sym_algo algorithm.
    pub fn set_symmetric_algo(&mut self, sym_algo: SymmetricAlgorithm)
                              -> SymmetricAlgorithm {
        ::std::mem::replace(&mut self.sym_algo, sym_algo)
    }

    /// Gets the AEAD algorithm.
    pub fn aead(&self) -> AEADAlgorithm {
        self.aead
    }

    /// Sets the AEAD algorithm.
    pub fn set_aead(&mut self, aead: AEADAlgorithm) -> AEADAlgorithm {
        ::std::mem::replace(&mut self.aead, aead)
    }

    /// Gets the chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Gets the chunk size.
    pub fn set_chunk_size(&mut self, chunk_size: usize) -> Result<()> {
        if chunk_size.count_ones() != 1 {
            return Err(Error::InvalidArgument(
                format!("chunk size is not a power of two: {}", chunk_size))
                .into());
        }

        if chunk_size < 64 {
            return Err(Error::InvalidArgument(
                format!("chunk size is too small: {}", chunk_size))
                .into());
        }

        self.chunk_size = chunk_size;
        Ok(())
    }

    /// Gets the size of a chunk with digest.
    pub fn chunk_digest_size(&self) -> Result<usize> {
        Ok(self.chunk_size + self.aead.digest_size()?)
    }

    /// Gets the initialization vector for the AEAD algorithm.
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    /// Sets the initialization vector for the AEAD algorithm.
    pub fn set_iv(&mut self, iv: Box<[u8]>) -> Box<[u8]> {
        ::std::mem::replace(&mut self.iv, iv)
    }
}

impl From<AED1> for Packet {
    fn from(p: AED1) -> Self {
        super::AED::from(p).into()
    }
}

impl From<AED1> for super::AED {
    fn from(p: AED1) -> Self {
        super::AED::V1(p)
    }
}
