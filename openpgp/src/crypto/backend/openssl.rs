//! Implementation of Sequoia crypto API using the OpenSSL cryptographic library.
use std::convert::TryFrom;

use crate::types::*;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Returns a short, human-readable description of the backend.
pub fn backend() -> String {
    "OpenSSL".to_string()
}

/// Fills the given buffer with random data.
pub fn random(buf: &mut [u8]) {
    // random is expected to always work or panic on wrong data.
    // This is similar to what other backends do like CNG or Rust
    // see: https://docs.rs/rand/latest/rand/trait.RngCore.html#tymethod.fill_bytes
    openssl::rand::rand_bytes(buf).expect("rand_bytes to work");
}

impl PublicKeyAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match self {
            RSAEncryptSign | RSAEncrypt | RSASign => true,
            DSA => true,
            ECDH | ECDSA | EdDSA => true,
            ElGamalEncrypt | ElGamalEncryptSign |
            Private(_) | Unknown(_)
                => false,
        }
    }
}

impl Curve {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        if matches!(self, Curve::Ed25519 | Curve::Cv25519) {
            // 25519-based algorithms are special-cased and supported
            true
        } else {
            // the rest of EC algorithms are supported via the same
            // codepath
            if let Ok(nid) = openssl::nid::Nid::try_from(self) {
                openssl::ec::EcGroup::from_curve_name(nid).is_ok()
            } else {
                false
            }
        }
    }
}

impl AEADAlgorithm {
    /// Returns the best AEAD mode supported by the backend.
    ///
    /// This SHOULD return OCB, which is the mandatory-to-implement
    /// algorithm and the most performing one, but fall back to any
    /// supported algorithm.
    pub(crate) const fn const_default() -> AEADAlgorithm {
        AEADAlgorithm::OCB
    }

    pub(crate) fn is_supported_by_backend(&self) -> bool {
        match self {
            AEADAlgorithm::EAX => false,
            AEADAlgorithm::OCB => true,
            AEADAlgorithm::GCM => true,
            AEADAlgorithm::Private(_) |
            AEADAlgorithm::Unknown(_) => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn supports_symmetric_algo(&self, algo: &SymmetricAlgorithm) -> bool {
        match &self {
            AEADAlgorithm::EAX => false,
            AEADAlgorithm::OCB =>
                match algo {
                    // OpenSSL supports OCB only with AES
                    // see: https://wiki.openssl.org/index.php/OCB
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 => true,
                    _ => false,
                },
            AEADAlgorithm::GCM =>
                match algo {
                    // OpenSSL supports GCM only with AES
                    // see: https://wiki.openssl.org/index.php/GCM
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 => true,
                    _ => false,
                },
            AEADAlgorithm::Private(_) |
            AEADAlgorithm::Unknown(_) => false,
        }
    }
}
