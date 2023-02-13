//! Common secret key related operations.

use std::time::SystemTime;

use crate::{
    Result,
    packet::key::{self, Key4, Key6, SecretParts},
    types::{
        Curve,
        HashAlgorithm,
        SymmetricAlgorithm,
    },
};

impl<R> Key6<SecretParts, R>
    where R: key::KeyRole,
{

    /// Creates a new OpenPGP secret key packet for an existing X25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_cv25519<H, S, T>(private_key: &[u8],
                                          hash: H, sym: S, ctime: T)
        -> Result<Self> where H: Into<Option<HashAlgorithm>>,
                              S: Into<Option<SymmetricAlgorithm>>,
                              T: Into<Option<SystemTime>>
    {
        Key4::import_secret_cv25519(private_key, hash, sym, ctime)
            .map(Key6::from_common)
    }

    /// Creates a new OpenPGP secret key packet for an existing Ed25519 key.
    ///
    /// The ECDH key will use hash algorithm `hash` and symmetric
    /// algorithm `sym`.  If one or both are `None` secure defaults
    /// will be used.  The key will have it's creation date set to
    /// `ctime` or the current time if `None` is given.
    pub fn import_secret_ed25519<T>(private_key: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        Key4::import_secret_ed25519(private_key, ctime)
            .map(Key6::from_common)
    }

    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    #[allow(clippy::many_single_char_names)]
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T)
        -> Result<Self> where T: Into<Option<SystemTime>>
    {
        Key4::import_secret_rsa(d, p, q, ctime)
            .map(Key6::from_common)
    }

    /// Generates a new RSA key with a public modulos of size `bits`.
    pub fn generate_rsa(bits: usize) -> Result<Self> {
        Key4::generate_rsa(bits)
            .map(Key6::from_common)
    }

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self> {
        Key4::generate_ecc(for_signing, curve)
            .map(Key6::from_common)
    }
}
