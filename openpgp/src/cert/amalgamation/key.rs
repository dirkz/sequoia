//! Keys, their associated signatures, and some useful methods.
//!
//! A [`KeyAmalgamation`] is similar to a [`ComponentAmalgamation`],
//! but a `KeyAmalgamation` includes some additional functionality
//! that is needed to correctly implement a [`Key`] component's
//! semantics.  In particular, unlike other components where the
//! binding signature stores the component's meta-data, a Primary Key
//! doesn't have a binding signature (it is the thing that other
//! components are bound to!), and, as a consequence, the associated
//! meta-data is stored elsewhere.
//!
//! Unfortunately, a primary Key's meta-data is usually not stored on
//! a direct key signature, which would be convenient as it is located
//! at the same place as a binding signature would be, but on the
//! primary User ID's binding signature.  This requires some
//! acrobatics on the implementation side to realize the correct
//! semantics.  In particular, a `Key` needs to memorize its role
//! (i.e., whether it is a primary key or a subkey) in order to know
//! whether to consider its own self signatures or the primary User
//! ID's self signatures when looking for its meta-data.
//!
//! Ideally, a `KeyAmalgamation`'s role would be encoded in its type.
//! This increases safety, and reduces the run-time overhead.
//! However, we want [`Cert::keys`] to return an iterator over all
//! keys; we don't want the user to have to specially handle the
//! primary key when that fact is not relevant.  This means that
//! `Cert::keys` has to erase the returned `Key`s' roles: all items in
//! an iterator must have the same type.  To support this, we have to
//! keep track of a `KeyAmalgamation`'s role at run-time.
//!
//! But, just because we need to erase a `KeyAmalgamation`'s role to
//! implement `Cert::keys` doesn't mean that we have to always erase
//! it.  To achieve this, we use three data types:
//! [`PrimaryKeyAmalgamation`], [`SubordinateKeyAmalgamation`], and
//! [`ErasedKeyAmalgamation`].  The first two encode the role
//! information in their type, and the last one stores it at run time.
//! We provide conversion functions to convert the static type
//! information into dynamic type information, and vice versa.
//!
//! Note: `KeyBundle`s and `KeyAmalgamation`s have a notable
//! difference: whereas a `KeyBundle`'s role is a marker, a
//! `KeyAmalgamation`'s role determines its semantics.  A consequence
//! of this is that it is not possible to convert a
//! `PrimaryKeyAmalgamation` into a `SubordinateAmalgamation`s, or
//! vice versa even though we support changing a `KeyBundle`'s role:
//!
//! ```
//! # use std::convert::TryInto;
//! # extern crate sequoia_openpgp as openpgp;
//! # use openpgp::cert::prelude::*;
//! # use openpgp::packet::prelude::*;
//! # let (cert, _) = CertBuilder::new()
//! #     .add_userid("Alice")
//! #     .add_signing_subkey()
//! #     .add_transport_encryption_subkey()
//! #     .generate().unwrap();
//! // This works:
//! cert.primary_key().bundle().role_as_subordinate();
//!
//! // But this doesn't:
//! let ka: ErasedKeyAmalgamation<_> = cert.keys().nth(0).expect("primary key");
//! let ka: openpgp::Result<SubordinateKeyAmalgamation<key::PublicParts>> = ka.try_into();
//! assert!(ka.is_err());
//! ```
//!
//! The use of the prefix `Erased` instead of `Unspecified`
//! (cf. [`KeyRole::UnspecifiedRole`]) emphasizes this.
//!
//! # Selecting Keys
//!
//! It is essential to choose the right keys, and to make sure that
//! they appropriate.  Below, we present some guidelines for the most
//! common situations.
//!
//! ## Encrypting and Signing Messages
//!
//! As a general rule of thumb, when encrypting or signing a message,
//! you want to use keys that are alive, not revoked, and have the
//! appropriate capabilities right now.  For example, the following
//! code shows how to find a key, which is appropriate for signing a
//! message:
//!
//! ```rust
//! # extern crate sequoia_openpgp as openpgp;
//! # use openpgp::Result;
//! # use openpgp::cert::prelude::*;
//! use openpgp::types::RevocationStatus;
//! use sequoia_openpgp::policy::StandardPolicy;
//!
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! #     let (cert, _) =
//! #         CertBuilder::general_purpose(None, Some("alice@example.org"))
//! #         .generate()?;
//! #     let mut i = 0;
//! let p = &StandardPolicy::new();
//!
//! let cert = cert.with_policy(p, None)?;
//!
//! if let RevocationStatus::Revoked(_) = cert.revocation_status() {
//!     // The certificate is revoked, don't use any keys from it.
//! #   unreachable!();
//! } else if let Err(_) = cert.alive() {
//!     // The certificate is not alive, don't use any keys from it.
//! #   unreachable!();
//! } else {
//!     for ka in cert.keys() {
//!         if let RevocationStatus::Revoked(_) = ka.revocation_status() {
//!             // The key is revoked.
//! #           unreachable!();
//!         } else if let Err(_) = ka.alive() {
//!             // The key is not alive.
//! #           unreachable!();
//!         } else if ! ka.for_signing() {
//!             // The key is not signing capable.
//!         } else {
//!             // Use it!
//! #           i += 1;
//!         }
//!     }
//! }
//! # assert_eq!(i, 1);
//! #     Ok(())
//! # }
//! ```
//!
//! ## Verifying a Message
//!
//! When verifying a message, you only want to use keys that were
//! alive, not revoked, and signing capable *when the message was
//! signed*.  These are the keys that the signer would have used, and
//! they reflect the signer's policy when they made the signature.
//! (See the [`Policy` discussion] for an explanation.)
//!
//! For version 4 Signature packets, the `Signature Creation Time`
//! subpacket indicates when the signature was allegedly created.  For
//! the purpose of finding the key to verify the signature, this time
//! stamp should be trusted: if the key is authenticated and the
//! signature is valid, then the time stamp is valid; if the signature
//! is not valid, then forging the time stamp won't help an attacker.
//!
//! ```rust
//! # extern crate sequoia_openpgp as openpgp;
//! # use openpgp::Result;
//! # use openpgp::cert::prelude::*;
//! use openpgp::types::RevocationStatus;
//! use sequoia_openpgp::policy::StandardPolicy;
//!
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! let p = &StandardPolicy::new();
//!
//! #     let (cert, _) =
//! #         CertBuilder::general_purpose(None, Some("alice@example.org"))
//! #         .generate()?;
//! #     let timestamp = None;
//! #     let issuer = cert.fingerprint();
//! #     let mut i = 0;
//! let cert = cert.with_policy(p, timestamp)?;
//! if let RevocationStatus::Revoked(_) = cert.revocation_status() {
//!     // The certificate is revoked, don't use any keys from it.
//! #   unreachable!();
//! } else if let Err(_) = cert.alive() {
//!     // The certificate is not alive, don't use any keys from it.
//! #   unreachable!();
//! } else {
//!     for ka in cert.keys().key_handle(issuer) {
//!         if let RevocationStatus::Revoked(_) = ka.revocation_status() {
//!             // The key is revoked, don't use it!
//! #           unreachable!();
//!         } else if let Err(_) = ka.alive() {
//!             // The key was not alive when the signature was made!
//!             // Something fishy is going on.
//! #           unreachable!();
//!         } else if ! ka.for_signing() {
//!             // The key was not signing capable!  Better be safe
//!             // than sorry.
//! #           unreachable!();
//!         } else {
//!             // Try verifying the message with this key.
//! #           i += 1;
//!         }
//!     }
//! }
//! #     assert_eq!(i, 1);
//! #     Ok(())
//! # }
//! ```
//!
//! ## Decrypting a Message
//!
//! When decrypting a message, it seems like one ought to only keys
//! that were alive, not revoked, and encryption-capable when the
//! message was encrypted.  Unfortunately, we don't know when a
//! message was encrypted.  But anyway, due to the slow propagation of
//! revocation certificates, we can't assume that senders won't
//! mistakenly use a revoked key.
//!
//! However, wanting to decrypt a message encrypted using an expired
//! or revoked key is reasonable.  If someone is trying to decrypt a
//! message using an expired key, then they are the certificate
//! holder, and probably attempting to access archived data using a
//! key that they themselves revoked!  We don't want to prevent that.
//!
//! We do, however, want to check whether a key is really encryption
//! capable.  [This discussion] explains why using a signing key to
//! decrypt a message can be dangerous.  Since we need a binding
//! signature to determine this, but we don't have the time that the
//! message was encrypted, we need a workaround.  One approach would
//! be to check whether the key is encryption capable now.  Since a
//! key's key flags don't typically change, this will correctly filter
//! out keys that are not encryption capable.  But, it will skip keys
//! whose self signature has expired.  But that is not a problem
//! either: no one sets self signatures to expire; if anything, they
//! set keys to expire.  Thus, this will not result in incorrectly
//! failing to decrypt messages in practice, and is a reasonable
//! approach.
//!
//! ```rust
//! # extern crate sequoia_openpgp as openpgp;
//! # use openpgp::Result;
//! # use openpgp::cert::prelude::*;
//! use sequoia_openpgp::policy::StandardPolicy;
//!
//! # fn main() { f().unwrap(); }
//! # fn f() -> Result<()> {
//! let p = &StandardPolicy::new();
//!
//! #     let (cert, _) =
//! #         CertBuilder::general_purpose(None, Some("alice@example.org"))
//! #         .generate()?;
//! let decryption_keys = cert.keys().with_policy(p, None)
//!     .for_storage_encryption().for_transport_encryption()
//!     .collect::<Vec<_>>();
//! #     Ok(())
//! # }
//! ```
//!
//! [`KeyAmalgamation`]: struct.KeyAmalgamation.html
//! [`ComponentAmalgamation`]: ../struct.ComponentAmalgamation.html
//! [`Key`]: ../../../packet/key/index.html
//! [`Cert::keys`]: ../../struct.Cert.html#method.keys
//! [`PrimaryKeyAmalgamation`]: ../type.PrimaryKeyAmalgamation.html
//! [`SubordinateKeyAmalgamation`]: ../type.SubordinateKeyAmalgamation.html
//! [`ErasedKeyAmalgamation`]: ../type.ErasedKeyAmalgamation.html
//! [`KeyRole::UnspecifiedRole`]: ../../../packet/key/trait.KeyRole.html
//! [`Policy` discussion]: ../index.html
//! [This discussion]: https://crypto.stackexchange.com/a/12138
use std::time;
use std::time::SystemTime;
use std::ops::Deref;
use std::borrow::Borrow;
use std::convert::TryFrom;
use std::convert::TryInto;

use anyhow::Context;

use crate::{
    Cert,
    cert::bundle::KeyBundle,
    cert::amalgamation::{
        ComponentAmalgamation,
        ValidAmalgamation,
        ValidateAmalgamation,
    },
    cert::ValidCert,
    crypto::{hash::Hash, Signer},
    Error,
    packet::Key,
    packet::key,
    packet::signature,
    packet::Signature,
    policy::Policy,
    Result,
    SignatureType,
    types::HashAlgorithm,
    types::KeyFlags,
    types::RevocationStatus,
};

mod iter;
pub use iter::{
    KeyAmalgamationIter,
    ValidKeyAmalgamationIter,
};

/// Whether the key is a primary key.
///
/// This trait is an implementation detail.  It exists so that we can
/// have a blanket implementation of [`ValidAmalgamation`] for
/// [`ValidKeyAmalgamation`], for instance, even though we only have
/// specialized implementations of `PrimaryKey`.
///
/// [`ValidAmalgamation`]: ../trait.ValidAmalgamation.html
/// [`ValidKeyAmalgamation`]: struct.ValidKeyAmalgamation.html
pub trait PrimaryKey<'a, P, R>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    /// Returns whether the key amalgamation is a primary key
    /// amalgamation.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let fpr = cert.fingerprint();
    /// // This works if the type is concrete:
    /// let ka: PrimaryKeyAmalgamation<_> = cert.primary_key();
    /// assert!(ka.primary());
    ///
    /// // Or if it has been erased:
    /// for (i, ka) in cert.keys().enumerate() {
    ///     let ka: ErasedKeyAmalgamation<_> = ka;
    ///     if i == 0 {
    ///         // The primary key is always the first key returned by
    ///         // `Cert::keys`.
    ///         assert!(ka.primary());
    ///     } else {
    ///         // The rest are subkeys.
    ///         assert!(! ka.primary());
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    fn primary(&self) -> bool;
}

/// A key, and its associated data, and useful methods.
///
/// A `KeyAmalgamation` is like a [`ComponentAmalgamation`], but
/// specialized for keys.  Due to the requirement to keep track of the
/// key's role when it is erased ([see the module's documentation] for
/// more details), this is a different data structure rather than a
/// specialized type alias.
///
/// Generally, you won't use this type directly, but instead use
/// [`PrimaryKeyAmalgamation`], [`SubordinateKeyAmalgamation`], or
/// [`ErasedKeyAmalgamation`].
///
/// A `KeyAmalgamation` is returned by [`Cert::primary_key`], and
/// [`Cert::keys`].
///
/// `KeyAmalgamation` implements [`ValidateAmalgamation`], which
/// allows you to turn a `KeyAmalgamation` into a
/// [`ValidKeyAmalgamation`] using [`KeyAmalgamation::with_policy`].
///
/// # Examples
///
/// Iterating over all keys:
///
/// ```
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::policy::StandardPolicy;
/// #
/// # fn main() -> openpgp::Result<()> {
/// #     let p = &StandardPolicy::new();
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
/// #         .generate()?;
/// #     let fpr = cert.fingerprint();
/// for ka in cert.keys() {
///     let ka: ErasedKeyAmalgamation<_> = ka;
/// }
/// #     Ok(())
/// # }
/// ```
///
/// Getting the primary key:
///
/// ```
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::policy::StandardPolicy;
/// #
/// # fn main() -> openpgp::Result<()> {
/// #     let p = &StandardPolicy::new();
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
/// #         .generate()?;
/// #     let fpr = cert.fingerprint();
/// let ka: PrimaryKeyAmalgamation<_> = cert.primary_key();
/// #     Ok(())
/// # }
/// ```
///
/// Iterating over just the subkeys:
///
/// ```
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// # use openpgp::policy::StandardPolicy;
/// #
/// # fn main() -> openpgp::Result<()> {
/// #     let p = &StandardPolicy::new();
/// #     let (cert, _) =
/// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
/// #         .generate()?;
/// #     let fpr = cert.fingerprint();
/// // We can skip the primary key (it's always first):
/// for ka in cert.keys().skip(1) {
///     let ka: ErasedKeyAmalgamation<_> = ka;
/// }
///
/// // Or use `subkeys`, which returns a more accurate type:
/// for ka in cert.keys().subkeys() {
///     let ka: SubordinateKeyAmalgamation<_> = ka;
/// }
/// #     Ok(())
/// # }
/// ```
///
/// [`ComponentAmalgamation`]: ../struct.ComponentAmalgamation.html
/// [see the module's documentation]: index.html
/// [`PrimaryKeyAmalgamation`]: type.PrimaryKeyAmalgamation.html
/// [`SubordinateKeyAmalgamation`]: type.SubordinateKeyAmalgamation.html
/// [`ErasedKeyAmalgamation`]: type.ErasedKeyAmalgamation.html
/// [`Cert::primary_key`]: ../../../cert/struct.Cert.html#method.primary_key
/// [`Cert::keys`]: ../../../cert/struct.Cert.html#method.keys
/// [`ValidateAmalgamation`]: ../trait.ValidateAmalgamation.html
/// [`ValidKeyAmalgamation`]: struct.ValidKeyAmalgamation.html
/// [`KeyAmalgamation::with_policy`]: ../trait.ValidateAmalgamation.html#method.with_policy
#[derive(Debug)]
pub struct KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    ca: ComponentAmalgamation<'a, Key<P, R>>,
    primary: R2,
}

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, P, R, R2> Clone for KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    fn clone(&self) -> Self {
        Self {
            ca: self.ca.clone(),
            primary: self.primary,
        }
    }
}


/// A primary key amalgamation.
///
/// A specialized version of [`KeyAmalgamation`].
///
/// [`KeyAmalgamation`]: struct.KeyAmalgamation.html
pub type PrimaryKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::PrimaryRole, ()>;

/// A subordinate key amalgamation.
///
/// A specialized version of [`KeyAmalgamation`].
///
/// [`KeyAmalgamation`]: struct.KeyAmalgamation.html
pub type SubordinateKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::SubordinateRole, ()>;

/// An amalgamation whose role is not known at compile time.
///
/// A specialized version of [`KeyAmalgamation`].
///
/// Unlike a [`Key`] or a [`KeyBundle`] with an unspecified role, an
/// `ErasedKeyAmalgamation` remembers its role; it is just not exposed
/// to the type system.  For details, see the [module-level
/// documentation].
///
/// [`KeyAmalgamation`]: struct.KeyAmalgamation.html
/// [`Key`]: ../../../packet/key/index.html
/// [`KeyBundle`]: ../../bundle/index.html
/// [module-level documentation]: index.html
pub type ErasedKeyAmalgamation<'a, P>
    = KeyAmalgamation<'a, P, key::UnspecifiedRole, bool>;


impl<'a, P, R, R2> Deref for KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
{
    type Target = ComponentAmalgamation<'a, Key<P, R>>;

    fn deref(&self) -> &Self::Target {
        &self.ca
    }
}


impl<'a, P> ValidateAmalgamation<'a, Key<P, key::PrimaryRole>>
    for PrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidPrimaryKeyAmalgamation<'a, P>;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let ka : ErasedKeyAmalgamation<P> = self.into();
        Ok(ka.with_policy(policy, time)?
               .try_into().expect("conversion is symmetric"))
    }
}

impl<'a, P> ValidateAmalgamation<'a, Key<P, key::SubordinateRole>>
    for SubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidSubordinateKeyAmalgamation<'a, P>;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let ka : ErasedKeyAmalgamation<P> = self.into();
        Ok(ka.with_policy(policy, time)?
               .try_into().expect("conversion is symmetric"))
    }
}

impl<'a, P> ValidateAmalgamation<'a, Key<P, key::UnspecifiedRole>>
    for ErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = ValidErasedKeyAmalgamation<'a, P>;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T)
        -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);

        // We need to make sure the certificate is okay.  This means
        // checking the primary key.  But, be careful: we don't need
        // to double check.
        if ! self.primary() {
            let pka = PrimaryKeyAmalgamation::new(self.cert());
            pka.with_policy(policy, time).context("primary key")?;
        }

        let binding_signature = self.binding_signature(policy, time)?;
        let cert = self.ca.cert();
        let vka = ValidErasedKeyAmalgamation {
            ka: KeyAmalgamation {
                ca: self.ca.parts_into_public(),
                primary: self.primary,
            },
            // We need some black magic to avoid infinite
            // recursion: a ValidCert must be valid for the
            // specified policy and reference time.  A ValidCert
            // is consider valid if the primary key is valid.
            // ValidCert::with_policy checks that by calling this
            // function.  So, if we call ValidCert::with_policy
            // here we'll recurse infinitely.
            //
            // But, hope is not lost!  We know that if we get
            // here, we've already checked that the primary key is
            // valid (see above), or that we're in the process of
            // evaluating the primary key's validity and we just
            // need to check the user's policy.  So, it is safe to
            // create a ValidCert from scratch.
            cert: ValidCert {
                cert: cert,
                policy: policy,
                time: time,
            },
            binding_signature
        };
        policy.key(&vka)?;
        Ok(ValidErasedKeyAmalgamation {
            ka: KeyAmalgamation {
                ca: P::convert_key_amalgamation(
                    vka.ka.ca.parts_into_unspecified()).expect("roundtrip"),
                primary: vka.ka.primary,
            },
            cert: vka.cert,
            binding_signature,
        })
    }
}

impl<'a, P> PrimaryKey<'a, P, key::PrimaryRole>
    for PrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        true
    }
}

impl<'a, P> PrimaryKey<'a, P, key::SubordinateRole>
    for SubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        false
    }
}

impl<'a, P> PrimaryKey<'a, P, key::UnspecifiedRole>
    for ErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        self.primary
    }
}


impl<'a, P: 'a + key::KeyParts> From<PrimaryKeyAmalgamation<'a, P>>
    for ErasedKeyAmalgamation<'a, P>
{
    fn from(ka: PrimaryKeyAmalgamation<'a, P>) -> Self {
        ErasedKeyAmalgamation {
            ca: ka.ca.role_into_unspecified(),
            primary: true,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<SubordinateKeyAmalgamation<'a, P>>
    for ErasedKeyAmalgamation<'a, P>
{
    fn from(ka: SubordinateKeyAmalgamation<'a, P>) -> Self {
        ErasedKeyAmalgamation {
            ca: ka.ca.role_into_unspecified(),
            primary: false,
        }
    }
}


// We can infallibly convert part X to part Y for everything but
// Public -> Secret and Unspecified -> Secret.
macro_rules! impl_conversion {
    ($s:ident, $primary:expr, $p1:path, $p2:path) => {
        impl<'a> From<$s<'a, $p1>>
            for ErasedKeyAmalgamation<'a, $p2>
        {
            fn from(ka: $s<'a, $p1>) -> Self {
                ErasedKeyAmalgamation {
                    ca: ka.ca.into(),
                    primary: $primary,
                }
            }
        }
    }
}

impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::SecretParts, key::PublicParts);
impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(PrimaryKeyAmalgamation, true,
                 key::UnspecifiedParts, key::PublicParts);

impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::SecretParts, key::PublicParts);
impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(SubordinateKeyAmalgamation, false,
                 key::UnspecifiedParts, key::PublicParts);


impl<'a, P, P2> TryFrom<ErasedKeyAmalgamation<'a, P>>
    for PrimaryKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(ka: ErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        if ka.primary {
            Ok(Self {
                ca: P2::convert_key_amalgamation(
                    ka.ca.role_into_primary().parts_into_unspecified())?,
                primary: (),
            })
        } else {
            Err(Error::InvalidArgument(
                "can't convert a SubordinateKeyAmalgamation \
                 to a PrimaryKeyAmalgamation".into()).into())
        }
    }
}

impl<'a, P, P2> TryFrom<ErasedKeyAmalgamation<'a, P>>
    for SubordinateKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(ka: ErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        if ka.primary {
            Err(Error::InvalidArgument(
                "can't convert a PrimaryKeyAmalgamation \
                 to a SubordinateKeyAmalgamation".into()).into())
        } else {
            Ok(Self {
                ca: P2::convert_key_amalgamation(
                    ka.ca.role_into_subordinate().parts_into_unspecified())?,
                primary: (),
            })
        }
    }
}

impl<'a> PrimaryKeyAmalgamation<'a, key::PublicParts> {
    pub(crate) fn new(cert: &'a Cert) -> Self {
        PrimaryKeyAmalgamation {
            ca: ComponentAmalgamation::new(cert, &cert.primary),
            primary: (),
        }
    }
}

impl<'a, P: 'a + key::KeyParts> SubordinateKeyAmalgamation<'a, P> {
    pub(crate) fn new(
        cert: &'a Cert, bundle: &'a KeyBundle<P, key::SubordinateRole>)
        -> Self
    {
        SubordinateKeyAmalgamation {
            ca: ComponentAmalgamation::new(cert, bundle),
            primary: (),
        }
    }
}

impl<'a, P: 'a + key::KeyParts> ErasedKeyAmalgamation<'a, P> {
    /// Returns the key's binding signature as of the reference time,
    /// if any.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should instead do: `ka.with_policy(policy,
    /// time)?.binding_signature()`.
    fn binding_signature<T>(&self, policy: &'a dyn Policy, time: T)
        -> Result<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        if self.primary {
            self.cert().primary_userid_relaxed(policy, time, false)
                .map(|u| u.binding_signature())
                .or_else(|e0| {
                    // Lookup of the primary user id binding failed.
                    // Look for direct key signatures.
                    self.cert().primary_key().bundle()
                        .binding_signature(policy, time)
                        .or_else(|e1| {
                            // Both lookups failed.  Keep the more
                            // meaningful error.
                            if let Some(Error::NoBindingSignature(_))
                                = e1.downcast_ref()
                            {
                                Err(e0) // Return the original error.
                            } else {
                                Err(e1)
                            }
                        })
                })
        } else {
            self.bundle().binding_signature(policy, time)
        }
    }
}


impl<'a, P, R, R2> KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,

{
    /// Returns the `KeyAmalgamation`'s `ComponentAmalgamation`.
    pub fn component_amalgamation(&self)
        -> &ComponentAmalgamation<'a, Key<P, R>> {
        &self.ca
    }

    /// Returns the `KeyAmalgamation`'s key.
    ///
    /// Normally, a type implementing `KeyAmalgamation` eventually
    /// derefs to a `Key`, however, this method provides a more
    /// accurate lifetime.  See the documentation for
    /// `ComponentAmalgamation::component` for an explanation.
    pub fn key(&self) -> &'a Key<P, R> {
        self.ca.component()
    }
}

/// A `KeyAmalgamation` plus a `Policy` and a reference time.
///
/// In the same way that a [`ValidComponentAmalgamation`] extends a
/// [`ComponentAmalgamation`], a `ValidKeyAmalgamation` extends a
/// [`KeyAmalgamation`]: a `ValidKeyAmalgamation` combines a
/// `KeyAmalgamation`, a [`Policy`], and a reference time.  This
/// allows it to implement the [`ValidAmalgamation`] trait, which
/// provides methods like [`ValidAmalgamation::binding_signature`] that require a
/// `Policy` and a reference time.  Although `KeyAmalgamation` could
/// implement these methods by requiring that the caller explicitly
/// pass them in, embedding them in the `ValidKeyAmalgamation` helps
/// ensure that multipart operations, even those that span multiple
/// functions, use the same `Policy` and reference time.
///
/// A `ValidKeyAmalgamation` can be obtained by transforming a
/// `KeyAmalgamation` using [`ValidateAmalgamation::with_policy`].  A
/// [`KeyAmalgamationIter`] can also be changed to yield
/// `ValidKeyAmalgamation`s.
///
/// A `ValidKeyAmalgamation` is guaranteed to come from a valid
/// certificate, and have a valid and live *binding* signature at the
/// specified reference time.  Note: this only means that the binding
/// signatures are live; it says nothing about whether the
/// *certificate* or the *`Key`* is live and non-revoked.  If you care
/// about those things, you need to check them separately.
///
/// # Examples:
///
/// Find all non-revoked, live, signing-capable keys:
///
/// ```
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::cert::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::types::RevocationStatus;
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
///
/// # let (cert, _) = CertBuilder::new()
/// #     .add_userid("Alice")
/// #     .add_signing_subkey()
/// #     .add_transport_encryption_subkey()
/// #     .generate().unwrap();
/// // `with_policy` ensures that the certificate and any components
/// // that it returns have valid *binding signatures*.  But, we still
/// // need to check that the certificate and `Key` are not revoked,
/// // and live.
/// //
/// // Note: `ValidKeyAmalgamation::revocation_status`, etc. use the
/// // embedded policy and timestamp.  Even though we used `None` for
/// // the timestamp (i.e., now), they are guaranteed to use the same
/// // timestamp, because `with_policy` eagerly transforms it into
/// // the current time.
/// let cert = cert.with_policy(p, None)?;
/// if let RevocationStatus::Revoked(_revs) = cert.revocation_status() {
///     // Revoked by the certificate holder.  (If we care about
///     // designated revokers, then we need to check those
///     // ourselves.)
/// #   unreachable!();
/// } else if let Err(_err) = cert.alive() {
///     // Certificate was created in the future or is expired.
/// #   unreachable!();
/// } else {
///     // `ValidCert::keys` returns `ValidKeyAmalgamation`s.
///     for ka in cert.keys() {
///         if let RevocationStatus::Revoked(_revs) = ka.revocation_status() {
///             // Revoked by the key owner.  (If we care about
///             // designated revokers, then we need to check those
///             // ourselves.)
/// #           unreachable!();
///         } else if let Err(_err) = ka.alive() {
///             // Key was created in the future or is expired.
/// #           unreachable!();
///         } else if ! ka.for_signing() {
///             // We're looking for a signing-capable key, skip this one.
///         } else {
///             // Use it!
///         }
///     }
/// }
/// # Ok(()) }
/// ```
///
/// [`ValidComponentAmalgamation`]: ../struct.ValidComponentAmalgamation.html
/// [`ComponentAmalgamation`]: ../struct.ComponentAmalgamation.html
/// [`KeyAmalgamation`]: struct.KeyAmalgamation.html
/// [`Policy`]: ../../../policy/index.html
/// [`ValidAmalgamation`]: ../trait.ValidAmalgamation.html
/// [`ValidAmalgamation::binding_signature`]: ../trait.ValidAmalgamation.html#method.binding_signature
/// [`ValidateAmalgamation::with_policy`]: ../trait.ValidateAmalgamation.html#tymethod.with_policy
/// [`KeyAmalgamationIter`]: struct.KeyAmalgamationIter.html
#[derive(Debug, Clone)]
pub struct ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    // Ouch, ouch, ouch!  ka is a `KeyAmalgamation`, which contains a
    // reference to a `Cert`.  `cert` is a `ValidCert` and contains a
    // reference to the same `Cert`!  We do this so that
    // `ValidKeyAmalgamation` can deref to a `KeyAmalgamation` and
    // `ValidKeyAmalgamation::cert` can return a `&ValidCert`.

    ka: KeyAmalgamation<'a, P, R, R2>,
    cert: ValidCert<'a>,

    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}

/// A Valid primary Key, and its associated data.
///
/// A specialized version of [`ValidKeyAmalgamation`].
///
/// [`ValidKeyAmalgamation`]: struct.ValidKeyAmalgamation.html
pub type ValidPrimaryKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::PrimaryRole, ()>;

/// A Valid subkey, and its associated data.
///
/// A specialized version of [`ValidKeyAmalgamation`].
///
/// [`ValidKeyAmalgamation`]: struct.ValidKeyAmalgamation.html
pub type ValidSubordinateKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::SubordinateRole, ()>;

/// A valid key whose role is not known at compile time.
///
/// A specialized version of [`ValidKeyAmalgamation`].
///
/// [`ValidKeyAmalgamation`]: struct.ValidKeyAmalgamation.html
pub type ValidErasedKeyAmalgamation<'a, P>
    = ValidKeyAmalgamation<'a, P, key::UnspecifiedRole, bool>;


impl<'a, P, R, R2> Deref for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    type Target = KeyAmalgamation<'a, P, R, R2>;

    fn deref(&self) -> &Self::Target {
        &self.ka
    }
}


impl<'a, P, R, R2> From<ValidKeyAmalgamation<'a, P, R, R2>>
    for KeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
{
    fn from(vka: ValidKeyAmalgamation<'a, P, R, R2>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        vka.ka
    }
}

impl<'a, P: 'a + key::KeyParts> From<ValidPrimaryKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: ValidPrimaryKeyAmalgamation<'a, P>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        ValidErasedKeyAmalgamation {
            ka: vka.ka.into(),
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        }
    }
}

impl<'a, P: 'a + key::KeyParts> From<ValidSubordinateKeyAmalgamation<'a, P>>
    for ValidErasedKeyAmalgamation<'a, P>
{
    fn from(vka: ValidSubordinateKeyAmalgamation<'a, P>) -> Self {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        ValidErasedKeyAmalgamation {
            ka: vka.ka.into(),
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        }
    }
}

// We can infallibly convert part X to part Y for everything but
// Public -> Secret and Unspecified -> Secret.
macro_rules! impl_conversion {
    ($s:ident, $p1:path, $p2:path) => {
        impl<'a> From<$s<'a, $p1>>
            for ValidErasedKeyAmalgamation<'a, $p2>
        {
            fn from(vka: $s<'a, $p1>) -> Self {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                ValidErasedKeyAmalgamation {
                    ka: vka.ka.into(),
                    cert: vka.cert,
                    binding_signature: vka.binding_signature,
                }
            }
        }
    }
}

impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::SecretParts, key::PublicParts);
impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(ValidPrimaryKeyAmalgamation,
                 key::UnspecifiedParts, key::PublicParts);

impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::SecretParts, key::PublicParts);
impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::SecretParts, key::UnspecifiedParts);
impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::PublicParts, key::UnspecifiedParts);
impl_conversion!(ValidSubordinateKeyAmalgamation,
                 key::UnspecifiedParts, key::PublicParts);


impl<'a, P, P2> TryFrom<ValidErasedKeyAmalgamation<'a, P>>
    for ValidPrimaryKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(vka: ValidErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
        Ok(ValidPrimaryKeyAmalgamation {
            ka: vka.ka.try_into()?,
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        })
    }
}

impl<'a, P, P2> TryFrom<ValidErasedKeyAmalgamation<'a, P>>
    for ValidSubordinateKeyAmalgamation<'a, P2>
    where P: 'a + key::KeyParts,
          P2: 'a + key::KeyParts,
{
    type Error = anyhow::Error;

    fn try_from(vka: ValidErasedKeyAmalgamation<'a, P>) -> Result<Self> {
        Ok(ValidSubordinateKeyAmalgamation {
            ka: vka.ka.try_into()?,
            cert: vka.cert,
            binding_signature: vka.binding_signature,
        })
    }
}


impl<'a, P> ValidateAmalgamation<'a, Key<P, key::PrimaryRole>>
    for ValidPrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = Self;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized
    {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.ka.with_policy(policy, time)
            .map(|vka| {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                vka
            })
    }
}

impl<'a, P> ValidateAmalgamation<'a, Key<P, key::SubordinateRole>>
    for ValidSubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = Self;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized
    {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.ka.with_policy(policy, time)
            .map(|vka| {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                vka
            })
    }
}


impl<'a, P> ValidateAmalgamation<'a, Key<P, key::UnspecifiedRole>>
    for ValidErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    type V = Self;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized
    {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.ka.with_policy(policy, time)
            .map(|vka| {
                assert!(std::ptr::eq(vka.ka.cert(), vka.cert.cert()));
                vka
            })
    }
}


impl<'a, P, R, R2> ValidAmalgamation<'a, Key<P, R>>
    for ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: PrimaryKey<'a, P, R>,
{
    fn cert(&self) -> &ValidCert<'a> {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        &self.cert
    }

    fn time(&self) -> SystemTime {
        self.cert.time()
    }

    fn policy(&self) -> &'a dyn Policy {
        assert!(std::ptr::eq(self.ka.cert(), self.cert.cert()));
        self.cert.policy()
    }

    fn binding_signature(&self) -> &'a Signature {
        self.binding_signature
    }

    fn revocation_status(&self) -> RevocationStatus<'a> {
        if self.primary() {
            self.cert.revocation_status()
        } else {
            self.bundle()._revocation_status(self.policy(), self.time(),
                                             true, Some(self.binding_signature))
        }
    }
}


impl<'a, P> PrimaryKey<'a, P, key::PrimaryRole>
    for ValidPrimaryKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        true
    }
}

impl<'a, P> PrimaryKey<'a, P, key::SubordinateRole>
    for ValidSubordinateKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        false
    }
}

impl<'a, P> PrimaryKey<'a, P, key::UnspecifiedRole>
    for ValidErasedKeyAmalgamation<'a, P>
    where P: 'a + key::KeyParts
{
    fn primary(&self) -> bool {
        self.ka.primary
    }
}


impl<'a, P, R, R2> ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: ValidAmalgamation<'a, Key<P, R>>
{
    /// Returns whether the key is alive as of the amalgamation's
    /// reference time.
    ///
    /// A `ValidKeyAmalgamation` is guaranteed to have a live binding
    /// signature.  This is independent of whether the component is
    /// live.
    ///
    /// This function considers both the binding signature and the
    /// direct key signature.  Information in the binding signature
    /// takes precedence over the direct key signature.  See [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    ///
    /// For a definition of liveness, see the [`key_alive`] method.
    ///
    /// [`key_alive`]: ../../../packet/signature/subpacket/struct.SubpacketAreas.html#method.key_alive
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// let ka = cert.primary_key().with_policy(p, None)?;
    /// if let Err(_err) = ka.alive() {
    ///     // Not alive.
    /// #   unreachable!();
    /// }
    /// # Ok(()) }
    /// ```
    pub fn alive(&self) -> Result<()>
    {
        let sig = {
            let binding : &Signature = self.binding_signature();
            if binding.key_validity_period().is_some() {
                Some(binding)
            } else {
                self.direct_key_signature().ok()
            }
        };
        if let Some(sig) = sig {
            sig.key_alive(self.key(), self.time())
        } else {
            // There is no key expiration time on the binding
            // signature.  This key does not expire.
            Ok(())
        }
    }

    /// Returns the wrapped `KeyAmalgamation`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// let ka = cert.primary_key();
    ///
    /// // `with_policy` takes ownership of `ka`.
    /// let vka = ka.with_policy(p, None)?;
    ///
    /// // And here we get it back:
    /// let ka = vka.into_key_amalgamation();
    /// # Ok(()) }
    /// ```
    pub fn into_key_amalgamation(self) -> KeyAmalgamation<'a, P, R, R2> {
        self.ka
    }

}

impl<'a, P, R, R2> ValidKeyAmalgamation<'a, P, R, R2>
    where P: 'a + key::KeyParts,
          R: 'a + key::KeyRole,
          R2: Copy,
          Self: PrimaryKey<'a, P, R>,
{
    /// Sets the key to expire in delta seconds.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    ///
    /// This function exists to facilitate testing, which is why it is
    /// not exported.
    pub(crate) fn set_validity_period_as_of(&self,
                                            primary_signer: &mut dyn Signer,
                                            expiration: Option<time::Duration>,
                                            now: time::SystemTime)
        -> Result<Vec<Signature>>
    {
        let hash_algo = HashAlgorithm::SHA512;
        let mut sigs = Vec::new();

        // There are two cases to consider.  If we are extending the
        // validity of the primary key, we also need to create new
        // binding signatures for all userids.
        if self.primary() {
            // First, update or create a direct key signature.
            let template = self.direct_key_signature()
                .unwrap_or_else(|_| self.binding_signature())
                .clone();

            let mut builder = signature::SignatureBuilder::from(template)
                .set_type(SignatureType::DirectKey);
            builder.remove_all(
                signature::subpacket::SubpacketTag::PrimaryUserID);

            // Generate the signature.
            let mut hash = hash_algo.context()?;
            self.cert().primary_key().hash(&mut hash);
            sigs.push(builder
                      .set_key_validity_period(expiration)?
                      .set_signature_creation_time(now)?
                      .sign_hash(primary_signer, hash)?);

            // Second, generate a new binding signature for every
            // userid.  We need to be careful not to change the
            // primary userid, so we make it explicit using the
            // primary userid subpacket.
            for userid in self.cert().userids().revoked(false) {
                // To extend the validity of the subkey, create a new
                // binding signature with updated key validity period.
                let binding_signature = userid.binding_signature();
                let mut hash = hash_algo.context()?;
                self.cert().primary.key().hash(&mut hash);
                userid.hash(&mut hash);
                sigs.push(signature::SignatureBuilder::from(binding_signature.clone())
                          .set_key_validity_period(expiration)?
                          .set_signature_creation_time(now)?
                          .set_primary_userid(
                              self.cert().primary_userid().map(|primary| {
                                  userid.userid() == primary.userid()
                              }).unwrap_or(false))?
                          .sign_hash(primary_signer, hash)?);
            }
        } else {
            // To extend the validity of the subkey, create a new
            // binding signature with updated key validity period.
            let mut hash = hash_algo.context()?;
            self.cert().primary.key().hash(&mut hash);
            self.key().hash(&mut hash);
            sigs.push(signature::SignatureBuilder::from(self.binding_signature().clone())
                      .set_key_validity_period(expiration)?
                      .set_signature_creation_time(now)?
                      .sign_hash(primary_signer, hash)?);
        }

        Ok(sigs)
    }

    /// Creates signatures that cause the key to expire at the specified time.
    ///
    /// This function creates new binding signatures that cause the
    /// key to expire at the specified time when integrated into the
    /// certificate.  For subkeys, only a single `Signature` is
    /// returned.  For the primary key, however, it is necessary to
    /// create a new self-signature for each non-revoked User ID, and
    /// to create a direct key signature.  This is needed, because the
    /// primary User ID is first consulted when determining the
    /// primary key's expiration time, and certificates can be
    /// distributed with a possibly empty subset of User IDs.
    ///
    /// Setting a key's expiry time means updating an existing binding
    /// signature---when looking up information, only one binding
    /// signature is normally considered, and we don't want to drop
    /// the other information stored in the current binding signature.
    /// This function uses the binding signature determined by
    /// `ValidKeyAmalgamation`'s policy and reference time for this.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let t = time::SystemTime::now() - time::Duration::from_secs(10);
    /// # let (cert, _) = CertBuilder::new()
    /// #     .set_creation_time(t)
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// let vc = cert.with_policy(p, None)?;
    ///
    /// // Assert that the keys are not expired.
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_ok());
    /// }
    ///
    /// // Make the keys expire in a week.
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(7 * 24 * 60 * 60);
    ///
    /// // We assume that the secret key material is available, and not
    /// // password protected.
    /// let mut signer = vc.primary_key()
    ///     .key().clone().parts_into_secret()?.into_keypair()?;
    ///
    /// let sigs = vc.keys()
    ///     .flat_map(|ka| {
    ///         ka.set_expiration_time(&mut signer, Some(t)).unwrap()
    ///     })
    ///     // The iterator needs to run to completion before we
    ///     // Cert::merge_packets, because the iterator has a reference
    ///     // to cert (via vc), but Cert::merge_packets needs to  take
    ///     // ownership of it.
    ///     .collect::<Vec<_>>();
    /// let cert = cert.merge_packets(sigs)?;
    ///
    /// // They aren't expired yet.
    /// let vc = cert.with_policy(p, None)?;
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_ok());
    /// }
    ///
    /// // But in two weeks, they will be...
    /// let t = time::SystemTime::now()
    ///     + time::Duration::from_secs(2 * 7 * 24 * 60 * 60);
    /// let vc = cert.with_policy(p, t)?;
    /// for ka in vc.keys() {
    ///     assert!(ka.alive().is_err());
    /// }
    /// # Ok(()) }
    pub fn set_expiration_time(&self,
                               primary_signer: &mut dyn Signer,
                               expiration: Option<time::SystemTime>)
        -> Result<Vec<Signature>>
    {
        let expiration =
            if let Some(e) = expiration.map(crate::types::normalize_systemtime)
        {
            let ct = self.creation_time();
            match e.duration_since(ct) {
                Ok(v) => Some(v),
                Err(_) => return Err(Error::InvalidArgument(
                    format!("Expiration time {:?} predates creation time \
                             {:?}", e, ct)).into()),
            }
        } else {
            None
        };

        self.set_validity_period_as_of(primary_signer, expiration,
                                       time::SystemTime::now())
    }

    /// Returns the key's `Key Flags`.
    ///
    /// A Key's [`Key Flags`] holds information about the key.  As of
    /// RFC 4880, this information is primarily concerned with the
    /// key's capabilities (e.g., whether it may be used for signing).
    /// The other information that has been defined is: whether the
    /// key has been split using something like [SSS], and whether the
    /// primary key material is held by multiple parties.  In
    /// practice, the latter two flags are ignored.
    ///
    /// As per [Section 5.2.3.3 of RFC 4880], when looking for the
    /// `Key Flags`, the key's binding signature is first consulted
    /// (in the case of the primary Key, this is the binding signature
    /// of the primary User ID).  If the `Key Flags` subpacket is not
    /// present, then the direct key signature is consulted.
    ///
    /// Since the key flags are taken from the active self signature,
    /// a key's flags may change depending on the policy and the
    /// reference time.
    ///
    ///   [`Key Flags`]: https://tools.ietf.org/html/rfc4880#section-5.2.3.21
    ///   [SSS]: https://de.wikipedia.org/wiki/Shamir%E2%80%99s_Secret_Sharing
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p: &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let cert = cert.with_policy(p, None)?;
    /// let ka = cert.primary_key();
    /// println!("Primary Key's Key Flags: {:?}", ka.key_flags());
    /// # assert!(ka.key_flags().unwrap().for_certification());
    /// # Ok(()) }
    /// ```
    pub fn key_flags(&self) -> Option<KeyFlags> {
        self.map(|s| s.key_flags())
    }

    /// Returns whether the key has at least one of the specified key
    /// flags.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that may be used for transport encryption (data in
    /// motion) *or* storage encryption (data at rest):
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.has_any_key_flag(KeyFlags::empty()
    ///        .set_storage_encryption(true)
    ///        .set_transport_encryption(true))
    ///     {
    ///         // `ka` is encryption capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [`ValidKeyAmalgamation::key_flags`]: #method.key_flags
    pub fn has_any_key_flag<F>(&self, flags: F) -> bool
        where F: Borrow<KeyFlags>
    {
        let our_flags = self.key_flags().unwrap_or_default();
        !(&our_flags & flags.borrow()).is_empty()
    }

    /// Returns whether the key is certification capable.
    ///
    /// Note: [Section 12.1 of RFC 4880] says that the primary key is
    /// certification capable independent of the `Key Flags`
    /// subpacket:
    ///
    /// > In a V4 key, the primary key MUST be a key capable of
    /// > certification.
    ///
    /// This function only reflects what is stored in the `Key Flags`
    /// packet; it does not implicitly set this flag.  In practice,
    /// there are keys whose primary key's `Key Flags` do not have the
    /// certification capable flag set.  Some versions of netpgp, for
    /// instance, create keys like this.  Sequoia's higher-level
    /// functionality correctly handles these keys by always
    /// considering the primary key to be certification capable.
    /// Users of this interface should too.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are certification capable:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.primary() || ka.for_certification() {
    ///         // `ka` is certification capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [Section 12.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.21
    /// [`ValidKeyAmalgamation::key_flags`]: #method.key_flags
    pub fn for_certification(&self) -> bool {
        self.has_any_key_flag(KeyFlags::default().set_certification(true))
    }

    /// Returns whether the key is signing capable.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are signing capable:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_signing() {
    ///         // `ka` is signing capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [`ValidKeyAmalgamation::key_flags`]: #method.key_flags
    pub fn for_signing(&self) -> bool {
        self.has_any_key_flag(KeyFlags::default().set_signing(true))
    }

    /// Returns whether the key is authentication capable.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are authentication capable:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_authentication() {
    ///         // `ka` is authentication capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [`ValidKeyAmalgamation::key_flags`]: #method.key_flags
    pub fn for_authentication(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::default().set_authentication(true))
    }

    /// Returns whether the key is storage-encryption capable.
    ///
    /// OpenPGP distinguishes two types of encryption keys: those for
    /// storage ([data at rest]) and those for transport ([data in
    /// transit]).  Most OpenPGP implementations, however, don't
    /// distinguish between them in practice.  Instead, when they
    /// create a new encryption key, they just set both flags.
    /// Likewise, when encrypting a message, it is not typically
    /// possible to indicate the type of protection that is needed.
    /// Sequoia supports creating keys with only one of these flags
    /// set, and makes it easy to select the right type of key when
    /// encrypting messages.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are storage-encryption capable:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_storage_encryption() {
    ///         // `ka` is storage-encryption capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [data at rest]: https://en.wikipedia.org/wiki/Data_at_rest
    /// [data in transit]: https://en.wikipedia.org/wiki/Data_in_transit
    /// [`ValidKeyAmalgamation::key_flags`]: #method.key_flags
    pub fn for_storage_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::default().set_storage_encryption(true))
    }

    /// Returns whether the key is transport-encryption capable.
    ///
    /// OpenPGP distinguishes two types of encryption keys: those for
    /// storage ([data at rest]) and those for transport ([data in
    /// transit]).  Most OpenPGP implementations, however, don't
    /// distinguish between them in practice.  Instead, when they
    /// create a new encryption key, they just set both flags.
    /// Likewise, when encrypting a message, it is not typically
    /// possible to indicate the type of protection that is needed.
    /// Sequoia supports creating keys with only one of these flags
    /// set, and makes it easy to select the right type of key when
    /// encrypting messages.
    ///
    /// The key flags are looked up as described in
    /// [`ValidKeyAmalgamation::key_flags`].
    ///
    /// # Examples
    ///
    /// Finds keys that are transport-encryption capable:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// for ka in cert.keys().with_policy(p, None) {
    ///     if ka.for_transport_encryption() {
    ///         // `ka` is transport-encryption capable.
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// [data at rest]: https://en.wikipedia.org/wiki/Data_at_rest
    /// [data in transit]: https://en.wikipedia.org/wiki/Data_in_transit
    /// [`ValidKeyAmalgamation::key_flags`]: #method.key_flags
    pub fn for_transport_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::default().set_transport_encryption(true))
    }

    /// Returns how long the key is live.
    ///
    /// This returns how long the key is live relative to its creation
    /// time.  Use [`ValidKeyAmalgamation::key_expiration_time`] to
    /// get the key's absolute expiry time.
    ///
    /// This function considers both the binding signature and the
    /// direct key signature.  Information in the binding signature
    /// takes precedence over the direct key signature.  See [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// use std::convert::TryInto;
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::Timestamp;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// // OpenPGP Timestamps have a one-second resolution.  Since we
    /// // want to round trip the time, round it down.
    /// let now: Timestamp = time::SystemTime::now().try_into()?;
    /// let now: time::SystemTime = now.try_into()?;
    ///
    /// let a_week = time::Duration::from_secs(7 * 24 * 60 * 60);
    /// let a_week_later = now + a_week;
    ///
    /// let (cert, _) =
    ///     CertBuilder::general_purpose(None, Some("alice@example.org"))
    ///     .set_creation_time(now)
    ///     .set_expiration_time(a_week_later)
    ///     .generate()?;
    ///
    /// assert_eq!(cert.primary_key().with_policy(p, None)?.key_validity_period(),
    ///            Some(a_week));
    /// # Ok(()) }
    /// ```
    ///
    ///   [`ValidKeyAmalgamation::key_expiration_time`]: #method.key_expiration_time
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    pub fn key_validity_period(&self) -> Option<std::time::Duration> {
        self.map(|s| s.key_validity_period())
    }

    /// Returns the key's expiration time.
    ///
    /// If this function returns `None`, the key does not expire.
    ///
    /// This returns the key's expiration time.  Use
    /// [`ValidKeyAmalgamation::key_validity_period`] to get the
    /// duration of the key's lifetime.
    ///
    /// This function considers both the binding signature and the
    /// direct key signature.  Information in the binding signature
    /// takes precedence over the direct key signature.  See [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time;
    /// use std::convert::TryInto;
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::Timestamp;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// // OpenPGP Timestamps have a one-second resolution.  Since we
    /// // want to round trip the time, round it down.
    /// let now: Timestamp = time::SystemTime::now().try_into()?;
    /// let now: time::SystemTime = now.try_into()?;
    //
    /// let a_week = time::Duration::from_secs(7 * 24 * 60 * 60);
    /// let a_week_later = now + a_week;
    ///
    /// let (cert, _) =
    ///     CertBuilder::general_purpose(None, Some("alice@example.org"))
    ///     .set_creation_time(now)
    ///     .set_expiration_time(a_week_later)
    ///     .generate()?;
    ///
    /// assert_eq!(cert.primary_key().with_policy(p, None)?.key_expiration_time(),
    ///            Some(a_week_later));
    /// # Ok(()) }
    /// ```
    ///
    ///   [`ValidKeyAmalgamation::key_validity_period`]: #method.key_validity_period
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    pub fn key_expiration_time(&self) -> Option<time::SystemTime> {
        match self.key_validity_period() {
            Some(vp) if vp.as_secs() > 0 => Some(self.key().creation_time() + vp),
            _ => None,
        }
    }

    // NOTE: If you add a method to ValidKeyAmalgamation that takes
    // ownership of self, then don't forget to write a forwarder for
    // it for ValidPrimaryKeyAmalgamation.
}


#[cfg(test)]
mod test {
    use crate::policy::StandardPolicy as P;
    use crate::cert::prelude::*;
    use crate::packet::Packet;

    use super::*;

    #[test]
    fn expire_subkeys() {
        let p = &P::new();

        // Timeline:
        //
        // -1: Key created with no key expiration.
        // 0: Setkeys set to expire in 1 year
        // 1: Subkeys expire

        let now = time::SystemTime::now();
        let a_year = time::Duration::from_secs(365 * 24 * 60 * 60);
        let in_a_year = now + a_year;
        let in_two_years = now + 2 * a_year;

        let (cert, _) = CertBuilder::new()
            .set_creation_time(now - a_year)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate().unwrap();

        for ka in cert.keys().with_policy(p, None) {
            assert!(ka.alive().is_ok());
        }

        let mut primary = cert.primary_key().key().clone()
            .parts_into_secret().unwrap().into_keypair().unwrap();

        // Only expire the subkeys.
        let sigs = cert.keys().subkeys().with_policy(p, None)
            .flat_map(|ka| {
                ka.set_expiration_time(&mut primary, Some(in_a_year))
                    .unwrap()
                    .into_iter()
                    .map(Into::into)
            })
            .collect::<Vec<Packet>>();
        let cert = cert.merge_packets(sigs).unwrap();

        for ka in cert.keys().with_policy(p, None) {
            assert!(ka.alive().is_ok());
        }

        // Primary should not be expired two years from now.
        assert!(cert.primary_key().with_policy(p, in_two_years).unwrap()
                .alive().is_ok());
        // But the subkeys should be.
        for ka in cert.keys().subkeys().with_policy(p, in_two_years) {
            assert!(ka.alive().is_err());
        }
    }
}
