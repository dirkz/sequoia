//! OpenPGP Certificates.

use std::io;
use std::cmp;
use std::cmp::Ordering;
use std::path::Path;
use std::mem;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::time;

use crate::{
    crypto::{hash::Hash, Signer},
    Error,
    Result,
    RevocationStatus,
    SignatureType,
    HashAlgorithm,
    packet,
    packet::Signature,
    packet::signature,
    packet::Key,
    packet::key,
    packet::UserID,
    packet::UserAttribute,
    packet::Unknown,
    Packet,
    PacketPile,
    KeyID,
    Fingerprint,
};
use crate::parse::{Parse, PacketParserResult, PacketParser};
use crate::types::{
    ReasonForRevocation,
};

mod amalgamation;
mod builder;
mod bindings;
pub mod components;
use components::{
    ComponentBinding,
    PrimaryKeyBinding,
    KeyBindingIter,
    UserIDBinding,
    UnknownBindingIter,
};
mod component_iter;
pub use component_iter::{
    ComponentIter,
};
mod keyiter;
mod key_amalgamation;
mod parser;
mod revoke;

pub use self::builder::{CertBuilder, CipherSuite};

pub use keyiter::{KeyIter, ValidKeyIter};
pub use key_amalgamation::KeyAmalgamation;

pub use parser::{
    KeyringValidity,
    KeyringValidator,
    CertParser,
    CertValidity,
    CertValidator,
};

pub use revoke::{
    SubkeyRevocationBuilder,
    CertRevocationBuilder,
    UserAttributeRevocationBuilder,
    UserIDRevocationBuilder,
};

const TRACE : bool = false;

// Helper functions.

/// Compare the creation time of two signatures.  Order them so that
/// the more recent signature is first.
fn canonical_signature_order(a: Option<time::SystemTime>, b: Option<time::SystemTime>)
                             -> Ordering {
    // Note: None < Some, so the normal ordering is:
    //
    //   None, Some(old), Some(new)
    //
    // Reversing the ordering puts the signatures without a creation
    // time at the end, which is where they belong.
    a.cmp(&b).reverse()
}

fn sig_cmp(a: &Signature, b: &Signature) -> Ordering {
    match canonical_signature_order(a.signature_creation_time(),
                                    b.signature_creation_time()) {
        Ordering::Equal => a.mpis().cmp(b.mpis()),
        r => r
    }
}

impl fmt::Display for Cert {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.primary().fingerprint())
    }
}

/// A collection of `ComponentBindings`.
///
/// Note: we need this, because we can't `impl Vec<ComponentBindings>`.
#[derive(Debug, Clone, PartialEq)]
struct ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    bindings: Vec<ComponentBinding<C>>,
}

impl<C> Deref for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    type Target = Vec<ComponentBinding<C>>;

    fn deref(&self) -> &Self::Target {
        &self.bindings
    }
}

impl<C> DerefMut for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    fn deref_mut(&mut self) -> &mut Vec<ComponentBinding<C>> {
        &mut self.bindings
    }
}

impl<C> Into<Vec<ComponentBinding<C>>> for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    fn into(self) -> Vec<ComponentBinding<C>> {
        self.bindings
    }
}

impl<C> IntoIterator for ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    type Item = ComponentBinding<C>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.bindings.into_iter()
    }
}

impl<C> ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    fn new() -> Self {
        Self { bindings: vec![] }
    }
}

impl<C> ComponentBindings<C>
    where ComponentBinding<C>: cmp::PartialEq
{
    // Sort and dedup the components.
    //
    // `cmp` is a function to sort the components for deduping.
    //
    // `merge` is a function that merges the first component into the
    // second component.
    fn sort_and_dedup<F, F2>(&mut self, cmp: F, merge: F2)
        where F: Fn(&C, &C) -> Ordering,
              F2: Fn(&mut C, &mut C)
    {
        // We dedup by component (not bindings!).  To do this, we need
        // to sort the bindings by their components.

        self.bindings.sort_unstable_by(
            |a, b| cmp(&a.component, &b.component));

        self.bindings.dedup_by(|a, b| {
            if cmp(&a.component, &b.component) == Ordering::Equal {
                // Merge.
                merge(&mut a.component, &mut b.component);

                // Recall: if a and b are equal, a will be dropped.
                b.self_signatures.append(&mut a.self_signatures);
                b.certifications.append(&mut a.certifications);
                b.self_revocations.append(&mut a.self_revocations);
                b.other_revocations.append(&mut a.self_revocations);

                true
            } else {
                false
            }
        });

        // And sort the certificates.
        for b in self.bindings.iter_mut() {
            b.sort_and_dedup();
        }
    }
}

/// A vecor of key (primary or subkey, public or private) and any
/// associated signatures.
type KeyBindings<KeyPart, KeyRole> = ComponentBindings<Key<KeyPart, KeyRole>>;

/// A vector of subkeys and any associated signatures.
type SubkeyBindings<KeyPart> = KeyBindings<KeyPart, key::SubordinateRole>;

/// A vector of key (primary or subkey, public or private) and any
/// associated signatures.
#[allow(dead_code)]
type GenericKeyBindings
    = ComponentBindings<Key<key::UnspecifiedParts, key::UnspecifiedRole>>;

/// A vector of User ID bindings and any associated signatures.
type UserIDBindings = ComponentBindings<UserID>;

/// A vector of User Attribute bindings and any associated signatures.
type UserAttributeBindings = ComponentBindings<UserAttribute>;

/// A vector of unknown components and any associated signatures.
///
/// Note: all signatures are stored as certifications.
type UnknownBindings = ComponentBindings<Unknown>;


/// A OpenPGP Certificate.
///
/// A Certificate (see [RFC 4880, section 11.1]) can be used to verify
/// signatures and encrypt data.  It can be stored in a keystore and
/// uploaded to keyservers.
///
/// Certs are always canonicalized in the sense that only elements
/// (user id, user attribute, subkey) with at least one valid
/// self-signature are preserved.  Also, invalid self-signatures are
/// dropped.  The self-signatures are sorted so that the newest
/// self-signature comes first.  Components are sorted, but in an
/// undefined manner (i.e., when parsing the same Cert multiple times,
/// the components will be in the same order, but we reserve the right
/// to change the sort function between versions).  Third-party
/// certifications are *not* validated, as the keys are not available;
/// they are simply passed through as is.
///
/// [RFC 4880, section 11.1]: https://tools.ietf.org/html/rfc4880#section-11.1
///
/// # Secret keys
///
/// Any key in a `Cert` may have a secret key attached to it.  To
/// protect secret keys from being leaked, secret keys are not written
/// out if a `Cert` is serialized.  To also serialize the secret keys,
/// you need to use [`Cert::as_tsk()`] to get an object that writes
/// them out during serialization.
///
/// [`Cert::as_tsk()`]: #method.as_tsk
///
/// # Filtering certificates
///
/// To filter certificates, iterate over all components, clone what
/// you want to keep, and reassemble the certificate.  The following
/// example simply copies all the packets, and can be adopted to
/// suit your policy:
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
/// use openpgp::{Cert, cert::CertBuilder};
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// fn identity_filter(cert: &Cert) -> Result<Cert> {
///     // Iterate over all of the Cert components, pushing packets we
///     // want to keep into the accumulator.
///     let mut acc = Vec::new();
///
///     // Primary key and related signatures.
///     acc.push(cert.primary().clone().into());
///     for s in cert.direct_signatures()  { acc.push(s.clone().into()) }
///     for s in cert.certifications()     { acc.push(s.clone().into()) }
///     for s in cert.self_revocations()   { acc.push(s.clone().into()) }
///     for s in cert.other_revocations()  { acc.push(s.clone().into()) }
///
///     // UserIDs and related signatures.
///     for c in cert.userids().bindings() {
///         acc.push(c.userid().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // UserAttributes and related signatures.
///     for c in cert.user_attributes().bindings() {
///         acc.push(c.user_attribute().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // Subkeys and related signatures.
///     for c in cert.keys().subkeys() {
///         acc.push(c.key().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // Unknown components and related signatures.
///     for c in cert.unknowns() {
///         acc.push(c.unknown().clone().into());
///         for s in c.self_signatures()   { acc.push(s.clone().into()) }
///         for s in c.certifications()    { acc.push(s.clone().into()) }
///         for s in c.self_revocations()  { acc.push(s.clone().into()) }
///         for s in c.other_revocations() { acc.push(s.clone().into()) }
///     }
///
///     // Any signatures that we could not associate with a component.
///     for s in cert.bad_signatures()     { acc.push(s.clone().into()) }
///
///     // Finally, parse into Cert.
///     Cert::from_packet_pile(acc.into())
/// }
///
/// let (cert, _) =
///     CertBuilder::general_purpose(None, Some("alice@example.org"))
///     .generate()?;
/// assert_eq!(cert, identity_filter(&cert)?);
/// #     Ok(())
/// # }
/// ```
///
/// # Example
///
/// ```rust
/// # extern crate sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::parse::{Parse, PacketParserResult, PacketParser};
/// use openpgp::Cert;
///
/// # fn main() { f().unwrap(); }
/// # fn f() -> Result<()> {
/// #     let ppr = PacketParser::from_bytes(&b""[..])?;
/// match Cert::from_packet_parser(ppr) {
///     Ok(cert) => {
///         println!("Key: {}", cert.primary());
///         for binding in cert.userids().bindings() {
///             println!("User ID: {}", binding.userid());
///         }
///     }
///     Err(err) => {
///         eprintln!("Error parsing Cert: {}", err);
///     }
/// }
///
/// #     Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Cert {
    primary: PrimaryKeyBinding<key::PublicParts>,

    userids: UserIDBindings,
    user_attributes: UserAttributeBindings,
    subkeys: SubkeyBindings<key::PublicParts>,

    // Unknown components, e.g., some UserAttribute++ packet from the
    // future.
    unknowns: UnknownBindings,
    // Signatures that we couldn't find a place for.
    bad: Vec<packet::Signature>,
}

impl std::str::FromStr for Cert {
    type Err = failure::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

impl<'a> Parse<'a, Cert> for Cert {
    /// Returns the first Cert encountered in the reader.
    fn from_reader<R: io::Read>(reader: R) -> Result<Self> {
        Cert::from_packet_parser(PacketParser::from_reader(reader)?)
    }

    /// Returns the first Cert encountered in the file.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Cert::from_packet_parser(PacketParser::from_file(path)?)
    }

    /// Returns the first Cert found in `buf`.
    ///
    /// `buf` must be an OpenPGP-encoded message.
    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D) -> Result<Self> {
        Cert::from_packet_parser(PacketParser::from_bytes(data)?)
    }
}

impl Cert {
    /// Returns a reference to the primary key binding.
    ///
    /// Note: information about the primary key is often stored on the
    /// primary User ID's self signature.  Since these signatures are
    /// associated with the UserID and not the primary key, that
    /// information is not contained in the key binding.  Instead, you
    /// should use methods like `Cert::primary_key_signature()` to get
    /// information about the primary key.
    pub fn primary(&self) -> &key::PublicKey {
        &self.primary.key()
    }

    /// Returns the primary key's current self-signature as of `t`.
    ///
    /// If the current self-signature is from a User ID binding (and
    /// not a direct signature), this also returns the User ID binding
    /// and its revocation status as of `t`.
    fn primary_key_signature_full<T>(&self, t: T)
        -> Option<(&Signature, Option<(&UserIDBinding, RevocationStatus)>)>
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into()
            .unwrap_or_else(|| time::SystemTime::now());

        // 1. Self-signature from the non-revoked primary UserID.
        let primary_userid = self.userids().primary(t).map(|ca| {
            (ca.binding(),
             ca.binding_signature()
             .expect("primary userid must have a binding signature"),
             ca.revoked())
        });
        if let Some((ref u, ref s, ref r)) = primary_userid {
            if !destructures_to!(RevocationStatus::Revoked(_) = r) {
                return Some((s, Some((u, r.clone()))));
            }
        }

        // 2. Direct signature.
        if let Some(s) = self.primary.binding_signature(t) {
            return Some((s, None));
        }

        // 3. All User IDs are revoked.
        if let Some((u, s, r)) = primary_userid {
            assert!(destructures_to!(RevocationStatus::Revoked(_) = &r));
            return Some((s, Some((u, r))));
        }

        // 4. No user ids and no direct signatures.
        None
    }

    /// Returns the primary key's current self-signature.
    ///
    /// The primary key's current self-signature as of `t` is, in
    /// order of preference:
    ///
    ///   - The binding signature of the primary User ID at time `t`,
    ///     if the primary User ID is not revoked at time `t`.
    ///
    ///   - The newest, live, direct self signature at time `t`.
    ///
    ///   - The binding signature of the primary User ID at time `t`
    ///     (this can only happen if there are only revoked User IDs
    ///     at time `t`).
    ///
    /// If there are no applicable signatures, `None` is returned.
    pub fn primary_key_signature<T>(&self, t: T) -> Option<&Signature>
        where T: Into<Option<time::SystemTime>>
    {
        if let Some((sig, _)) = self.primary_key_signature_full(t) {
            Some(sig)
        } else {
            None
        }
    }

    /// The direct signatures.
    ///
    /// The signatures are validated, and they are reverse sorted by
    /// their creation time (newest first).
    pub fn direct_signatures(&self) -> &[Signature] {
        &self.primary.self_signatures()
    }

    /// Third-party certifications.
    ///
    /// The signatures are *not* validated.  They are reverse sorted by
    /// their creation time (newest first).
    pub fn certifications(&self) -> &[Signature] {
        &self.primary.certifications()
    }

    /// Revocations issued by the key itself.
    ///
    /// The revocations are validated, and they are reverse sorted by
    /// their creation time (newest first).
    pub fn self_revocations(&self) -> &[Signature] {
        &self.primary.self_revocations()
    }

    /// Revocations issued by other keys.
    ///
    /// The revocations are *not* validated.  They are reverse sorted
    /// by their creation time (newest first).
    pub fn other_revocations(&self) -> &[Signature] {
        &self.primary.other_revocations()
    }

    /// Returns the Cert's revocation status at time `t`.
    ///
    /// A Cert is revoked at time `t` if:
    ///
    ///   - There is a live revocation at time `t` that is newer than
    ///     all live self signatures at time `t`, or
    ///
    ///   - There is a hard revocation (even if it is not live at
    ///     time `t`, and even if there is a newer self-signature).
    ///
    /// Note: Certs and subkeys have different criteria from User IDs
    /// and User Attributes.
    ///
    /// Note: this only returns whether this Cert is revoked; it does
    /// not imply anything about the Cert or other components.
    pub fn revoked<T>(&self, t: T) -> RevocationStatus
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        self.primary._revoked(true, self.primary_key_signature(t), t)
    }

    /// Revokes the Cert in place.
    ///
    /// Note: to just generate a revocation certificate, use the
    /// `CertRevocationBuilder`.
    ///
    /// If you want to revoke an individual component, use
    /// `SubkeyRevocationBuilder`, `UserIDRevocationBuilder`, or
    /// `UserAttributeRevocationBuilder`, as appropriate.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::RevocationStatus;
    /// use openpgp::types::{ReasonForRevocation, SignatureType};
    /// use openpgp::cert::{CipherSuite, CertBuilder};
    /// use openpgp::crypto::KeyPair;
    /// use openpgp::parse::Parse;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()>
    /// # {
    /// let (mut cert, _) = CertBuilder::new()
    ///     .set_cipher_suite(CipherSuite::Cv25519)
    ///     .generate()?;
    /// assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
    ///            cert.revoked(None));
    ///
    /// let mut keypair = cert.primary().clone()
    ///     .mark_parts_secret()?.into_keypair()?;
    /// let cert = cert.revoke_in_place(&mut keypair,
    ///                               ReasonForRevocation::KeyCompromised,
    ///                               b"It was the maid :/")?;
    /// if let RevocationStatus::Revoked(sigs) = cert.revoked(None) {
    ///     assert_eq!(sigs.len(), 1);
    ///     assert_eq!(sigs[0].typ(), SignatureType::KeyRevocation);
    ///     assert_eq!(sigs[0].reason_for_revocation(),
    ///                Some((ReasonForRevocation::KeyCompromised,
    ///                      "It was the maid :/".as_bytes())));
    /// } else {
    ///     unreachable!()
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn revoke_in_place(self, primary_signer: &mut dyn Signer,
                           code: ReasonForRevocation, reason: &[u8])
        -> Result<Cert>
    {
        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(code, reason)?
            .build(primary_signer, &self, None)?;
        self.merge_packets(vec![sig.into()])
    }

    /// Returns whether or not the Cert is alive at `t`.
    pub fn alive<T>(&self, t: T) -> Result<()>
        where T: Into<Option<time::SystemTime>>
    {
        let t = t.into();
        if let Some(sig) = self.primary_key_signature(t) {
            sig.key_alive(self.primary(), t)
        } else {
            Err(Error::MalformedCert("No primary key signature".into()).into())
        }
    }

    /// Sets the key to expire in delta seconds.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    ///
    /// This function exists to facilitate testing, which is why it is
    /// not exported.
    fn set_expiry_as_of(self, primary_signer: &mut dyn Signer,
                        expiration: Option<time::Duration>,
                        now: time::SystemTime)
        -> Result<Cert>
    {
        let sig = {
            let (template, userid) = self
                .primary_key_signature_full(Some(now))
                .ok_or(Error::MalformedCert("No self-signature".into()))?;

            // Recompute the signature.
            let hash_algo = HashAlgorithm::SHA512;
            let mut hash = hash_algo.context()?;

            self.primary().hash(&mut hash);
            if let Some((userid, _)) = userid {
                userid.userid().hash(&mut hash);
            } else {
                assert_eq!(template.typ(), SignatureType::DirectKey);
            }

            // Generate the signature.
            signature::Builder::from(template.clone())
                .set_key_expiration_time(expiration)?
                .set_signature_creation_time(now)?
                .sign_hash(primary_signer, hash)?
        };

        self.merge_packets(vec![sig.into()])
    }

    /// Sets the key to expire in delta.
    ///
    /// Note: the time is relative to the key's creation time, not the
    /// current time!
    pub fn set_expiry(self, primary_signer: &mut dyn Signer,
                      expiration: Option<time::Duration>)
        -> Result<Cert>
    {
        self.set_expiry_as_of(primary_signer, expiration,
                              time::SystemTime::now())
    }

    /// Returns an iterator over the Cert's `UserIDBinding`s.
    pub fn userids(&self) -> ComponentIter<UserID> {
        fn make_iter(c: &Cert)
                     -> std::slice::Iter<ComponentBinding<UserID>> {
            c.userids.iter()
        }
        ComponentIter::new(self, make_iter)
    }

    /// Returns an iterator over the Cert's valid `UserAttributeBinding`s.
    ///
    /// A valid `UserIDAttributeBinding` has at least one good
    /// self-signature.
    pub fn user_attributes(&self) -> ComponentIter<UserAttribute> {
        fn make_iter(c: &Cert)
                     -> std::slice::Iter<ComponentBinding<UserAttribute>> {
            c.user_attributes.iter()
        }
        ComponentIter::new(self, make_iter)
    }

    /// Returns an iterator over the Cert's valid subkeys.
    ///
    /// A valid `KeyBinding` has at least one good self-signature.
    pub(crate) fn subkeys(&self) -> KeyBindingIter<key::PublicParts,
                                            key::SubordinateRole>
    {
        KeyBindingIter { iter: Some(self.subkeys.iter()) }
    }

    /// Returns an iterator over the Cert's valid unknown components.
    ///
    /// A valid `UnknownBinding` has at least one good self-signature.
    pub fn unknowns(&self) -> UnknownBindingIter {
        UnknownBindingIter { iter: Some(self.unknowns.iter()) }
    }

    /// Returns a slice containing all bad signatures.
    ///
    /// Bad signatures are signatures that we could not associate with
    /// one of the components.
    pub fn bad_signatures(&self) -> &[Signature] {
        &self.bad
    }

    /// Returns an iterator over the certificate's keys.
    ///
    /// That is, this returns an iterator over the primary key and any
    /// subkeys.
    pub fn keys(&self) -> KeyIter<key::PublicParts, key::UnspecifiedRole>
    {
        KeyIter::new(self)
    }

    /// Returns the Cert found in the packet stream.
    ///
    /// If there are more packets after the Cert, e.g. because the
    /// packet stream is a keyring, this function will return
    /// `Error::MalformedCert`.
    pub fn from_packet_parser(ppr: PacketParserResult) -> Result<Self> {
        let mut parser = parser::CertParser::from_packet_parser(ppr);
        if let Some(cert_result) = parser.next() {
            if parser.next().is_some() {
                Err(Error::MalformedCert(
                    "Additional packets found, is this a keyring?".into()
                ).into())
            } else {
                cert_result
            }
        } else {
            Err(Error::MalformedCert("No data".into()).into())
        }
    }

    /// Returns the first Cert found in the `PacketPile`.
    pub fn from_packet_pile(p: PacketPile) -> Result<Self> {
        let mut i = parser::CertParser::from_iter(p.into_children());
        match i.next() {
            Some(Ok(cert)) => Ok(cert),
            Some(Err(err)) => Err(err),
            None => Err(Error::MalformedCert("No data".into()).into()),
        }
    }

    fn canonicalize(mut self) -> Self {
        tracer!(TRACE, "canonicalize", 0);

        // The very first thing that we do is verify the
        // self-signatures.  There are a few things that we need to be
        // aware of:
        //
        //  - Signatures may be invalid.  These should be dropped.
        //
        //  - Signatures may be out of order.  These should be
        //    reordered so that we have the latest self-signature and
        //    we don't drop a userid or subkey that is actually
        //    valid.

        // We collect bad signatures here in self.bad.  Below, we'll
        // test whether they are just out of order by checking them
        // against all userids and subkeys.  Furthermore, this may be
        // a partial Cert that is merged into an older copy.

        // desc: a description of the component
        // binding: the binding to check
        // sigs: a vector of sigs in $binding to check
        // verify_method: the method to call on a signature to verify it
        // verify_args: additional arguments to pass to verify_method
        macro_rules! check {
            ($desc:expr, $binding:expr, $sigs:ident,
             $verify_method:ident, $($verify_args:expr),*) => ({
                t!("check!({}, {}, {:?}, {}, ...)",
                   $desc, stringify!($binding), $binding.$sigs,
                   stringify!($verify_method));
                for sig in mem::replace(&mut $binding.$sigs, Vec::new())
                    .into_iter()
                {
                    if let Ok(()) = sig.$verify_method(self.primary.key(),
                                                       self.primary.key(),
                                                       $($verify_args),*) {
                        $binding.$sigs.push(sig);
                    } else {
                        t!("Sig {:02X}{:02X}, type = {} doesn't belong to {}",
                           sig.digest_prefix()[0], sig.digest_prefix()[1],
                           sig.typ(), $desc);

                        self.bad.push(sig);
                    }
                }
            });
            ($desc:expr, $binding:expr, $sigs:ident,
             $verify_method:ident) => ({
                check!($desc, $binding, $sigs, $verify_method,)
            });
        }

        // The same as check!, but for third party signatures.  If we
        // do have the key that made the signature, we can verify it
        // like in check!.  Otherwise, we use the hash prefix as
        // heuristic approximating the verification.
        macro_rules! check_3rd_party {
            ($desc:expr,            // a description of the component
             $binding:expr,         // the binding to check
             $sigs:ident,           // a vector of sigs in $binding to check
             $lookup_fn:expr,       // a function to lookup keys
             $verify_method:ident,  // the method to call to verify it
             $hash_method:ident,    // the method to call to compute the hash
             $($verify_args:expr),* // additional arguments to pass to the above
            ) => ({
                t!("check_3rd_party!({}, {}, {:?}, {}, {}, ...)",
                   $desc, stringify!($binding), $binding.$sigs,
                   stringify!($verify_method), stringify!($hash_method));
                for sig in mem::replace(&mut $binding.$sigs, Vec::new())
                    .into_iter()
                {
                    // Use hash prefix as heuristic.
                    if let Ok(hash) = Signature::$hash_method(
                        &sig, self.primary.key(), $($verify_args),*) {
                        if &sig.digest_prefix()[..] == &hash[..2] {
                            // See if we can get the key for a
                            // positive verification.
                            if let Some(key) = $lookup_fn(&sig) {
                                if let Ok(()) = sig.$verify_method(
                                    &key, self.primary.key(), $($verify_args),*)
                                {
                                    $binding.$sigs.push(sig);
                                } else {
                                    t!("Sig {:02X}{:02X}, type = {} \
                                        doesn't belong to {}",
                                       sig.digest_prefix()[0],
                                       sig.digest_prefix()[1],
                                       sig.typ(), $desc);

                                    self.bad.push(sig);
                                }
                            } else {
                                // No key, we need to trust our heuristic.
                                $binding.$sigs.push(sig);
                            }
                        } else {
                            t!("Sig {:02X}{:02X}, type = {} \
                                doesn't belong to {}",
                               sig.digest_prefix()[0], sig.digest_prefix()[1],
                               sig.typ(), $desc);

                            self.bad.push(sig);
                        }
                    } else {
                        // Hashing failed, we likely don't support
                        // the hash algorithm.
                        t!("Sig {:02X}{:02X}, type = {}: \
                            Hashing failed",
                           sig.digest_prefix()[0], sig.digest_prefix()[1],
                           sig.typ());

                        self.bad.push(sig);
                    }
                }
            });
            ($desc:expr, $binding:expr, $sigs:ident, $lookup_fn:expr,
             $verify_method:ident, $hash_method:ident) => ({
                 check_3rd_party!($desc, $binding, $sigs, $lookup_fn,
                                  $verify_method, $hash_method, )
            });
        }

        // Placeholder lookup function.
        fn lookup_fn(_: &Signature)
                     -> Option<Key<key::PublicParts, key::UnspecifiedRole>> {
            None
        }

        check!("primary key",
               self.primary, self_signatures, verify_direct_key);
        check!("primary key",
               self.primary, self_revocations, verify_primary_key_revocation);
        check_3rd_party!("primary key",
                         self.primary, certifications, lookup_fn,
                         verify_direct_key, hash_direct_key);
        check_3rd_party!("primary key",
                         self.primary, other_revocations, lookup_fn,
                         verify_primary_key_revocation, hash_direct_key);

        for binding in self.userids.iter_mut() {
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid().value())),
                   binding, self_signatures, verify_userid_binding,
                   binding.userid());
            check!(format!("userid \"{}\"",
                           String::from_utf8_lossy(binding.userid().value())),
                   binding, self_revocations, verify_userid_revocation,
                   binding.userid());
            check_3rd_party!(
                format!("userid \"{}\"",
                        String::from_utf8_lossy(binding.userid().value())),
                binding, certifications, lookup_fn,
                verify_userid_binding, hash_userid_binding,
                binding.userid());
            check_3rd_party!(
                format!("userid \"{}\"",
                        String::from_utf8_lossy(binding.userid().value())),
                binding, other_revocations, lookup_fn,
                verify_userid_revocation, hash_userid_binding,
                binding.userid());
        }

        for binding in self.user_attributes.iter_mut() {
            check!("user attribute",
                   binding, self_signatures, verify_user_attribute_binding,
                   binding.user_attribute());
            check!("user attribute",
                   binding, self_revocations, verify_user_attribute_revocation,
                   binding.user_attribute());
            check_3rd_party!(
                "user attribute",
                binding, certifications, lookup_fn,
                verify_user_attribute_binding, hash_user_attribute_binding,
                binding.user_attribute());
            check_3rd_party!(
                "user attribute",
                binding, other_revocations, lookup_fn,
                verify_user_attribute_revocation, hash_user_attribute_binding,
                binding.user_attribute());
        }

        for binding in self.subkeys.iter_mut() {
            check!(format!("subkey {}", binding.key().keyid()),
                   binding, self_signatures, verify_subkey_binding,
                   binding.key());
            check!(format!("subkey {}", binding.key().keyid()),
                   binding, self_revocations, verify_subkey_revocation,
                   binding.key());
            check_3rd_party!(
                format!("subkey {}", binding.key().keyid()),
                binding, certifications, lookup_fn,
                verify_subkey_binding, hash_subkey_binding,
                binding.key());
            check_3rd_party!(
                format!("subkey {}", binding.key().keyid()),
                binding, other_revocations, lookup_fn,
                verify_subkey_revocation, hash_subkey_binding,
                binding.key());
        }

        // See if the signatures that didn't validate are just out of
        // place.

        'outer: for sig in mem::replace(&mut self.bad, Vec::new()) {
            macro_rules! check_one {
                ($desc:expr, $sigs:expr, $sig:expr,
                 $verify_method:ident, $($verify_args:expr),*) => ({
                     t!("check_one!({}, {:?}, {:?}, {}, ...)",
                        $desc, $sigs, $sig,
                        stringify!($verify_method));
                     if let Ok(())
                         = $sig.$verify_method(self.primary.key(),
                                               self.primary.key(),
                                               $($verify_args),*)
                     {
                         t!("Sig {:02X}{:02X}, {:?} \
                             was out of place.  Belongs to {}.",
                            $sig.digest_prefix()[0],
                            $sig.digest_prefix()[1],
                            $sig.typ(), $desc);

                         $sigs.push($sig);
                         continue 'outer;
                     }
                 });
                ($desc:expr, $sigs:expr, $sig:expr,
                 $verify_method:ident) => ({
                    check_one!($desc, $sigs, $sig, $verify_method,)
                });
            }

            // The same as check_one!, but for third party signatures.
            // If we do have the key that made the signature, we can
            // verify it like in check!.  Otherwise, we use the hash
            // prefix as heuristic approximating the verification.
            macro_rules! check_one_3rd_party {
                ($desc:expr,            // a description of the component
                 $sigs:expr,            // where to put $sig if successful
                 $sig:ident,            // the signature to check
                 $lookup_fn:expr,       // a function to lookup keys
                 $verify_method:ident,  // the method to verify it
                 $hash_method:ident,    // the method to compute the hash
                 $($verify_args:expr),* // additional arguments for the above
                ) => ({
                    t!("check_one_3rd_party!({}, {}, {:?}, {}, {}, ...)",
                       $desc, stringify!($sigs), $sig,
                       stringify!($verify_method), stringify!($hash_method));
                    if let Some(key) = $lookup_fn(&sig) {
                        if let Ok(()) = sig.$verify_method(&key,
                                                           self.primary.key(),
                                                           $($verify_args),*)
                        {
                            t!("Sig {:02X}{:02X}, {:?} \
                                was out of place.  Belongs to {}.",
                               $sig.digest_prefix()[0],
                               $sig.digest_prefix()[1],
                               $sig.typ(), $desc);

                            $sigs.push($sig);
                            continue 'outer;
                        }
                    } else {
                        // Use hash prefix as heuristic.
                        if let Ok(hash) = Signature::$hash_method(
                            &sig, self.primary.key(), $($verify_args),*) {
                            if &sig.digest_prefix()[..] == &hash[..2] {
                                t!("Sig {:02X}{:02X}, {:?} \
                                    was out of place.  Likely belongs to {}.",
                                   $sig.digest_prefix()[0],
                                   $sig.digest_prefix()[1],
                                   $sig.typ(), $desc);

                                $sigs.push($sig);
                                continue 'outer;
                            }
                        }
                    }
                });
                ($desc:expr, $sigs:expr, $sig:ident, $lookup_fn:expr,
                 $verify_method:ident, $hash_method:ident) => ({
                     check_one_3rd_party!($desc, $sigs, $sig, $lookup_fn,
                                          $verify_method, $hash_method, )
                 });
            }

            use SignatureType::*;
            match sig.typ() {
                DirectKey => {
                    check_one!("primary key", self.primary.self_signatures,
                               sig, verify_direct_key);
                    check_one_3rd_party!(
                        "primary key", self.primary.certifications, sig,
                        lookup_fn,
                        verify_direct_key, hash_direct_key);
                },

                KeyRevocation => {
                    check_one!("primary key", self.primary.self_revocations,
                               sig, verify_primary_key_revocation);
                    check_one_3rd_party!(
                        "primary key", self.primary.other_revocations, sig,
                        lookup_fn, verify_primary_key_revocation,
                        hash_direct_key);
                },

                GenericCertification | PersonaCertification
                    | CasualCertification | PositiveCertification =>
                {
                    for binding in self.userids.iter_mut() {
                        check_one!(format!("userid \"{}\"",
                                           String::from_utf8_lossy(
                                               binding.userid().value())),
                                   binding.self_signatures, sig,
                                   verify_userid_binding, binding.userid());
                        check_one_3rd_party!(
                            format!("userid \"{}\"",
                                    String::from_utf8_lossy(
                                        binding.userid().value())),
                            binding.certifications, sig, lookup_fn,
                            verify_userid_binding, hash_userid_binding,
                            binding.userid());
                    }

                    for binding in self.user_attributes.iter_mut() {
                        check_one!("user attribute",
                                   binding.self_signatures, sig,
                                   verify_user_attribute_binding,
                                   binding.user_attribute());
                        check_one_3rd_party!(
                            "user attribute",
                            binding.certifications, sig, lookup_fn,
                            verify_user_attribute_binding,
                            hash_user_attribute_binding,
                            binding.user_attribute());
                    }
                },

                CertificationRevocation => {
                    for binding in self.userids.iter_mut() {
                        check_one!(format!("userid \"{}\"",
                                           String::from_utf8_lossy(
                                               binding.userid().value())),
                                   binding.self_revocations, sig,
                                   verify_userid_revocation,
                                   binding.userid());
                        check_one_3rd_party!(
                            format!("userid \"{}\"",
                                    String::from_utf8_lossy(
                                        binding.userid().value())),
                            binding.other_revocations, sig, lookup_fn,
                            verify_userid_revocation, hash_userid_binding,
                            binding.userid());
                    }

                    for binding in self.user_attributes.iter_mut() {
                        check_one!("user attribute",
                                   binding.self_revocations, sig,
                                   verify_user_attribute_revocation,
                                   binding.user_attribute());
                        check_one_3rd_party!(
                            "user attribute",
                            binding.other_revocations, sig, lookup_fn,
                            verify_user_attribute_revocation,
                            hash_user_attribute_binding,
                            binding.user_attribute());
                    }
                },

                SubkeyBinding => {
                    for binding in self.subkeys.iter_mut() {
                        check_one!(format!("subkey {}", binding.key().keyid()),
                                   binding.self_signatures, sig,
                                   verify_subkey_binding, binding.key());
                        check_one_3rd_party!(
                            format!("subkey {}", binding.key().keyid()),
                            binding.certifications, sig, lookup_fn,
                            verify_subkey_binding, hash_subkey_binding,
                            binding.key());
                    }
                },

                SubkeyRevocation => {
                    for binding in self.subkeys.iter_mut() {
                        check_one!(format!("subkey {}", binding.key().keyid()),
                                   binding.self_revocations, sig,
                                   verify_subkey_revocation, binding.key());
                        check_one_3rd_party!(
                            format!("subkey {}", binding.key().keyid()),
                            binding.other_revocations, sig, lookup_fn,
                            verify_subkey_revocation, hash_subkey_binding,
                            binding.key());
                    }
                },

                typ => {
                    t!("Odd signature type: {:?}", typ);
                },
            }

            // Keep them for later.
            t!("Self-sig {:02X}{:02X}, {:?} doesn't belong \
                to any known component or is bad.",
               sig.digest_prefix()[0], sig.digest_prefix()[1],
               sig.typ());
            self.bad.push(sig);
        }

        if self.bad.len() > 0 {
            t!("{}: ignoring {} bad self-signatures",
               self.primary().keyid(), self.bad.len());
        }

        // Only keep user ids / user attributes / subkeys with at
        // least one valid self-signature or self-revocation.
        self.userids.retain(|userid| {
            userid.self_signatures.len() > 0 || userid.self_revocations.len() > 0
        });
        t!("Retained {} userids", self.userids.len());

        self.user_attributes.retain(|ua| {
            ua.self_signatures.len() > 0 || ua.self_revocations.len() > 0
        });
        t!("Retained {} user_attributes", self.user_attributes.len());

        self.subkeys.retain(|subkey| {
            subkey.self_signatures.len() > 0 || subkey.self_revocations.len() > 0
        });
        t!("Retained {} subkeys", self.subkeys.len());


        self.primary.sort_and_dedup();

        self.bad.sort_by(sig_cmp);
        self.bad.dedup();

        self.userids.sort_and_dedup(UserID::cmp, |_, _| {});
        self.user_attributes.sort_and_dedup(UserAttribute::cmp, |_, _| {});
        // XXX: If we have two keys with the same public parts and
        // different non-empty secret parts, then one will be dropped
        // (non-deterministicly)!
        //
        // This can happen if:
        //
        //   - One is corrupted
        //   - There are two versions that are encrypted differently
        self.subkeys.sort_and_dedup(Key::public_cmp,
            |ref mut a, ref mut b| {
                // Recall: if a and b are equal, a will be dropped.
                if b.secret().is_none() && a.secret().is_some() {
                    b.set_secret(a.set_secret(None));
                }
            });
        self.unknowns.sort_and_dedup(Unknown::best_effort_cmp, |_, _| {});

        // XXX: Check if the sigs in other_sigs issuer are actually
        // designated revokers for this key (listed in a "Revocation
        // Key" subpacket in *any* non-revoked self-signature).  Only
        // if that is the case should a sig be considered a potential
        // revocation.  (This applies to
        // self.primary_other_revocations as well as
        // self.userids().other_revocations, etc.)  If not, put the
        // sig on the bad list.
        //
        // Note: just because the Cert doesn't indicate that a key is a
        // designed revoker doesn't mean that it isn't---we might just
        // be missing the signature.  In other words, this is a policy
        // decision, but given how easy it could be to create rogue
        // revocations, is probably the better to reject such
        // signatures than to keep them around and have many keys
        // being shown as "potentially revoked".

        // XXX Do some more canonicalization.

        self
    }

    /// Returns the Cert's fingerprint.
    pub fn fingerprint(&self) -> Fingerprint {
        self.primary().fingerprint()
    }

    /// Returns the Cert's keyid.
    pub fn keyid(&self) -> KeyID {
        self.primary().keyid()
    }

    /// Converts the Cert into an iterator over a sequence of packets.
    ///
    /// This method discards invalid components and bad signatures.
    pub fn into_packets(self) -> impl Iterator<Item=Packet> {
        self.primary.into_packets()
            .chain(self.userids.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.user_attributes.into_iter().flat_map(|b| b.into_packets()))
            .chain(self.subkeys.into_iter().flat_map(|b| b.into_packets()))
    }

    /// Converts the Cert into a `PacketPile`.
    ///
    /// This method discards invalid components and bad signatures.
    pub fn into_packet_pile(self) -> PacketPile {
        PacketPile::from(self.into_packets().collect::<Vec<Packet>>())
    }

    /// Merges `other` into `self`.
    ///
    /// If `other` is a different key, then an error is returned.
    pub fn merge(mut self, mut other: Cert) -> Result<Self> {
        if self.primary().fingerprint()
            != other.primary().fingerprint()
        {
            // The primary key is not the same.  There is nothing to
            // do.
            return Err(Error::InvalidArgument(
                "Primary key mismatch".into()).into());
        }

        if self.primary.key().secret().is_none() && other.primary.key().secret().is_some() {
            self.primary.key_mut().set_secret(other.primary.key_mut().set_secret(None));
        }

        self.primary.self_signatures.append(
            &mut other.primary.self_signatures);
        self.primary.certifications.append(
            &mut other.primary.certifications);
        self.primary.self_revocations.append(
            &mut other.primary.self_revocations);
        self.primary.other_revocations.append(
            &mut other.primary.other_revocations);

        self.userids.append(&mut other.userids);
        self.user_attributes.append(&mut other.user_attributes);
        self.subkeys.append(&mut other.subkeys);
        self.bad.append(&mut other.bad);

        Ok(self.canonicalize())
    }

    /// Adds packets to the Cert.
    ///
    /// This recanonicalizes the Cert.  If the packets are invalid,
    /// they are dropped.
    ///
    /// If a key is merged in that already exists in the cert, it
    /// replaces the key.  This way, secret key material can be added,
    /// removed, encrypted, or decrypted.
    pub fn merge_packets(self, packets: Vec<Packet>) -> Result<Self> {
        let mut combined = self.into_packets().collect::<Vec<_>>();

        fn replace_or_push<P, R>(acc: &mut Vec<Packet>, k: Key<P, R>)
            where P: key::KeyParts,
                  R: key::KeyRole,
                  Packet: From<packet::Key<P, R>>,
        {
            for q in acc.iter_mut() {
                let replace = match q {
                    Packet::PublicKey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    Packet::SecretKey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    Packet::PublicSubkey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    Packet::SecretSubkey(k_) =>
                        k_.public_cmp(&k) == Ordering::Equal,
                    _ => false,
                };

                if replace {
                    *q = k.into();
                    return;
                }
            }
            acc.push(k.into());
        };

        for p in packets.into_iter() {
            match p {
                Packet::PublicKey(k) => replace_or_push(&mut combined, k),
                Packet::SecretKey(k) => replace_or_push(&mut combined, k),
                Packet::PublicSubkey(k) => replace_or_push(&mut combined, k),
                Packet::SecretSubkey(k) => replace_or_push(&mut combined, k),
                p => combined.push(p),
            }
        }

        Cert::from_packet_pile(PacketPile::from(combined))
    }

    /// Returns whether at least one of the keys includes a secret
    /// part.
    pub fn is_tsk(&self) -> bool {
        if self.primary().secret().is_some() {
            return true;
        }
        self.subkeys().any(|sk| {
            sk.binding_signature(None).is_some() && sk.key().secret().is_some()
        })
    }
}

#[cfg(test)]
mod test {
    use crate::serialize::Serialize;
    use super::*;

    use crate::{
        KeyID,
        types::KeyFlags,
    };

    fn parse_cert(data: &[u8], as_message: bool) -> Result<Cert> {
        if as_message {
            let pile = PacketPile::from_bytes(data).unwrap();
            Cert::from_packet_pile(pile)
        } else {
            Cert::from_bytes(data)
        }
    }

    #[test]
    fn broken() {
        use crate::types::Timestamp;
        for i in 0..2 {
            let cert = parse_cert(crate::tests::key("testy-broken-no-pk.pgp"),
                                i == 0);
            assert_match!(Error::MalformedCert(_)
                          = cert.err().unwrap().downcast::<Error>().unwrap());

            // According to 4880, a Cert must have a UserID.  But, we
            // don't require it.
            let cert = parse_cert(crate::tests::key("testy-broken-no-uid.pgp"),
                                i == 0);
            assert!(cert.is_ok());

            // We have:
            //
            //   [ pk, user id, sig, subkey ]
            let cert = parse_cert(crate::tests::key("testy-broken-no-sig-on-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(cert.primary.key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(cert.userids.len(), 1);
            assert_eq!(cert.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(cert.userids[0].self_signatures.len(), 1);
            assert_eq!(cert.userids[0].self_signatures[0].digest_prefix(),
                       &[ 0xc6, 0x8f ]);
            assert_eq!(cert.user_attributes.len(), 0);
            assert_eq!(cert.subkeys.len(), 0);
        }
    }

    #[test]
    fn basics() {
        use crate::types::Timestamp;
        for i in 0..2 {
            let cert = parse_cert(crate::tests::key("testy.pgp"),
                                i == 0).unwrap();
            assert_eq!(cert.primary.key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(cert.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(cert.userids.len(), 1, "number of userids");
            assert_eq!(cert.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(cert.userids[0].self_signatures.len(), 1);
            assert_eq!(cert.userids[0].self_signatures[0].digest_prefix(),
                       &[ 0xc6, 0x8f ]);

            assert_eq!(cert.user_attributes.len(), 0);

            assert_eq!(cert.subkeys.len(), 1, "number of subkeys");
            assert_eq!(cert.subkeys[0].key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(cert.subkeys[0].self_signatures[0].digest_prefix(),
                       &[ 0xb7, 0xb9 ]);

            let cert = parse_cert(crate::tests::key("testy-no-subkey.pgp"),
                                i == 0).unwrap();
            assert_eq!(cert.primary.key().creation_time(),
                       Timestamp::from(1511355130).into());
            assert_eq!(cert.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");

            assert_eq!(cert.user_attributes.len(), 0);

            assert_eq!(cert.userids.len(), 1, "number of userids");
            assert_eq!(cert.userids[0].userid().value(),
                       &b"Testy McTestface <testy@example.org>"[..]);
            assert_eq!(cert.userids[0].self_signatures.len(), 1);
            assert_eq!(cert.userids[0].self_signatures[0].digest_prefix(),
                       &[ 0xc6, 0x8f ]);

            assert_eq!(cert.subkeys.len(), 0, "number of subkeys");

            let cert = parse_cert(crate::tests::key("testy.asc"), i == 0).unwrap();
            assert_eq!(cert.fingerprint().to_hex(),
                       "3E8877C877274692975189F5D03F6F865226FE8B");
        }
    }

    #[test]
    fn only_a_public_key() {
        // Make sure the Cert parser can parse a key that just consists
        // of a public key---no signatures, no user ids, nothing.
        let cert = Cert::from_bytes(crate::tests::key("testy-only-a-pk.pgp")).unwrap();
        assert_eq!(cert.userids.len(), 0);
        assert_eq!(cert.user_attributes.len(), 0);
        assert_eq!(cert.subkeys.len(), 0);
    }

    #[test]
    fn merge() {
        use crate::tests::key;
        let cert_base = Cert::from_bytes(key("bannon-base.gpg")).unwrap();

        // When we merge it with itself, we should get the exact same
        // thing.
        let merged = cert_base.clone().merge(cert_base.clone()).unwrap();
        assert_eq!(cert_base, merged);

        let cert_add_uid_1
            = Cert::from_bytes(key("bannon-add-uid-1-whitehouse.gov.gpg"))
                .unwrap();
        let cert_add_uid_2
            = Cert::from_bytes(key("bannon-add-uid-2-fox.com.gpg"))
                .unwrap();
        // Duplicate user id, but with a different self-sig.
        let cert_add_uid_3
            = Cert::from_bytes(key("bannon-add-uid-3-whitehouse.gov-dup.gpg"))
                .unwrap();

        let cert_all_uids
            = Cert::from_bytes(key("bannon-all-uids.gpg"))
            .unwrap();
        // We have four User ID packets, but one has the same User ID,
        // just with a different self-signature.
        assert_eq!(cert_all_uids.userids.len(), 3);

        // Merge in order.
        let merged = cert_base.clone().merge(cert_add_uid_1.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap()
            .merge(cert_add_uid_3.clone()).unwrap();
        assert_eq!(cert_all_uids, merged);

        // Merge in reverse order.
        let merged = cert_base.clone()
            .merge(cert_add_uid_3.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap()
            .merge(cert_add_uid_1.clone()).unwrap();
        assert_eq!(cert_all_uids, merged);

        let cert_add_subkey_1
            = Cert::from_bytes(key("bannon-add-subkey-1.gpg")).unwrap();
        let cert_add_subkey_2
            = Cert::from_bytes(key("bannon-add-subkey-2.gpg")).unwrap();
        let cert_add_subkey_3
            = Cert::from_bytes(key("bannon-add-subkey-3.gpg")).unwrap();

        let cert_all_subkeys
            = Cert::from_bytes(key("bannon-all-subkeys.gpg")).unwrap();

        // Merge the first user, then the second, then the third.
        let merged = cert_base.clone().merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap();
        assert_eq!(cert_all_subkeys, merged);

        // Merge the third user, then the second, then the first.
        let merged = cert_base.clone().merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap();
        assert_eq!(cert_all_subkeys, merged);

        // Merge a lot.
        let merged = cert_base.clone()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap();
        assert_eq!(cert_all_subkeys, merged);

        let cert_all
            = Cert::from_bytes(key("bannon-all-uids-subkeys.gpg"))
            .unwrap();

        // Merge all the subkeys with all the uids.
        let merged = cert_all_subkeys.clone()
            .merge(cert_all_uids.clone()).unwrap();
        assert_eq!(cert_all, merged);

        // Merge all uids with all the subkeys.
        let merged = cert_all_uids.clone()
            .merge(cert_all_subkeys.clone()).unwrap();
        assert_eq!(cert_all, merged);

        // All the subkeys and the uids in a mixed up order.
        let merged = cert_base.clone()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap()
            .merge(cert_add_uid_1.clone()).unwrap()
            .merge(cert_add_subkey_3.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_uid_3.clone()).unwrap()
            .merge(cert_add_subkey_2.clone()).unwrap()
            .merge(cert_add_subkey_1.clone()).unwrap()
            .merge(cert_add_uid_2.clone()).unwrap();
        assert_eq!(cert_all, merged);

        // Certifications.
        let cert_donald_signs_base
            = Cert::from_bytes(key("bannon-the-donald-signs-base.gpg"))
            .unwrap();
        let cert_donald_signs_all
            = Cert::from_bytes(key("bannon-the-donald-signs-all-uids.gpg"))
            .unwrap();
        let cert_ivanka_signs_base
            = Cert::from_bytes(key("bannon-ivanka-signs-base.gpg"))
            .unwrap();
        let cert_ivanka_signs_all
            = Cert::from_bytes(key("bannon-ivanka-signs-all-uids.gpg"))
            .unwrap();

        assert!(cert_donald_signs_base.userids.len() == 1);
        assert!(cert_donald_signs_base.userids[0].self_signatures.len() == 1);
        assert!(cert_base.userids[0].certifications.len() == 0);
        assert!(cert_donald_signs_base.userids[0].certifications.len() == 1);

        let merged = cert_donald_signs_base.clone()
            .merge(cert_ivanka_signs_base.clone()).unwrap();
        assert!(merged.userids.len() == 1);
        assert!(merged.userids[0].self_signatures.len() == 1);
        assert!(merged.userids[0].certifications.len() == 2);

        let merged = cert_donald_signs_base.clone()
            .merge(cert_donald_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].self_signatures.len() == 1);
        // There should be two certifications from the Donald on the
        // first user id.
        assert!(merged.userids[0].certifications.len() == 2);
        assert!(merged.userids[1].certifications.len() == 1);
        assert!(merged.userids[2].certifications.len() == 1);

        let merged = cert_donald_signs_base.clone()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_base.clone()).unwrap()
            .merge(cert_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].self_signatures.len() == 1);
        // There should be two certifications from each of the Donald
        // and Ivanka on the first user id, and one each on the rest.
        assert!(merged.userids[0].certifications.len() == 4);
        assert!(merged.userids[1].certifications.len() == 2);
        assert!(merged.userids[2].certifications.len() == 2);

        // Same as above, but redundant.
        let merged = cert_donald_signs_base.clone()
            .merge(cert_ivanka_signs_base.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_base.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_donald_signs_all.clone()).unwrap()
            .merge(cert_ivanka_signs_all.clone()).unwrap();
        assert!(merged.userids.len() == 3);
        assert!(merged.userids[0].self_signatures.len() == 1);
        // There should be two certifications from each of the Donald
        // and Ivanka on the first user id, and one each on the rest.
        assert!(merged.userids[0].certifications.len() == 4);
        assert!(merged.userids[1].certifications.len() == 2);
        assert!(merged.userids[2].certifications.len() == 2);
    }

    #[test]
    fn out_of_order_self_sigs_test() {
        // neal-out-of-order.pgp contains all of the self-signatures,
        // but some are out of order.  The canonicalization step
        // should reorder them.
        //
        // original order/new order:
        //
        //  1/ 1. pk
        //  2/ 2. user id #1: neal@walfield.org (good)
        //  3/ 3. sig over user ID #1
        //
        //  4/ 4. user id #2: neal@gnupg.org (good)
        //  5/ 7. sig over user ID #3
        //  6/ 5. sig over user ID #2
        //
        //  7/ 6. user id #3: neal@g10code.com (bad)
        //
        //  8/ 8. user ID #4: neal@pep.foundation (bad)
        //  9/11. sig over user ID #5
        //
        // 10/10. user id #5: neal@pep-project.org (bad)
        // 11/ 9. sig over user ID #4
        //
        // 12/12. user ID #6: neal@sequoia-pgp.org (good)
        // 13/13. sig over user ID #6
        //
        // ----------------------------------------------
        //
        // 14/14. signing subkey #1: 7223B56678E02528 (good)
        // 15/15. sig over subkey #1
        // 16/16. sig over subkey #1
        //
        // 17/17. encryption subkey #2: C2B819056C652598 (good)
        // 18/18. sig over subkey #2
        // 19/21. sig over subkey #3
        // 20/22. sig over subkey #3
        //
        // 21/20. auth subkey #3: A3506AFB820ABD08 (bad)
        // 22/19. sig over subkey #2

        let cert = Cert::from_bytes(crate::tests::key("neal-sigs-out-of-order.pgp"))
            .unwrap();

        let mut userids = cert.userids()
            .map(|u| String::from_utf8_lossy(u.value()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Neal H. Walfield <neal@g10code.com>",
                      "Neal H. Walfield <neal@gnupg.org>",
                      "Neal H. Walfield <neal@pep-project.org>",
                      "Neal H. Walfield <neal@pep.foundation>",
                      "Neal H. Walfield <neal@sequoia-pgp.org>",
                      "Neal H. Walfield <neal@walfield.org>",
                   ]);

        let mut subkeys = cert.subkeys()
            .map(|sk| Some(sk.key().keyid()))
            .collect::<Vec<Option<KeyID>>>();
        subkeys.sort();
        assert_eq!(subkeys,
                   &[ KeyID::from_hex("7223B56678E02528").ok(),
                      KeyID::from_hex("A3506AFB820ABD08").ok(),
                      KeyID::from_hex("C2B819056C652598").ok(),
                   ]);

        // DKG's key has all of the self-signatures moved to the last
        // subkey; all user ids/user attributes/subkeys have nothing.
        let cert =
            Cert::from_bytes(crate::tests::key("dkg-sigs-out-of-order.pgp")).unwrap();

        let mut userids = cert.userids()
            .map(|u| String::from_utf8_lossy(u.value()).into_owned())
            .collect::<Vec<String>>();
        userids.sort();

        assert_eq!(userids,
                   &[ "Daniel Kahn Gillmor <dkg-debian.org@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@aclu.org>",
                      "Daniel Kahn Gillmor <dkg@astro.columbia.edu>",
                      "Daniel Kahn Gillmor <dkg@debian.org>",
                      "Daniel Kahn Gillmor <dkg@fifthhorseman.net>",
                      "Daniel Kahn Gillmor <dkg@openflows.com>",
                   ]);

        assert_eq!(cert.user_attributes.len(), 1);

        let mut subkeys = cert.subkeys()
            .map(|sk| Some(sk.key().keyid()))
            .collect::<Vec<Option<KeyID>>>();
        subkeys.sort();
        assert_eq!(subkeys,
                   &[ KeyID::from_hex(&"1075 8EBD BD7C FAB5"[..]).ok(),
                      KeyID::from_hex(&"1258 68EA 4BFA 08E4"[..]).ok(),
                      KeyID::from_hex(&"1498 ADC6 C192 3237"[..]).ok(),
                      KeyID::from_hex(&"24EC FF5A FF68 370A"[..]).ok(),
                      KeyID::from_hex(&"3714 7292 14D5 DA70"[..]).ok(),
                      KeyID::from_hex(&"3B7A A7F0 14E6 9B5A"[..]).ok(),
                      KeyID::from_hex(&"5B58 DCF9 C341 6611"[..]).ok(),
                      KeyID::from_hex(&"A524 01B1 1BFD FA5C"[..]).ok(),
                      KeyID::from_hex(&"A70A 96E1 439E A852"[..]).ok(),
                      KeyID::from_hex(&"C61B D3EC 2148 4CFF"[..]).ok(),
                      KeyID::from_hex(&"CAEF A883 2167 5333"[..]).ok(),
                      KeyID::from_hex(&"DC10 4C4E 0CA7 57FB"[..]).ok(),
                      KeyID::from_hex(&"E3A3 2229 449B 0350"[..]).ok(),
                   ]);

    }

    // lutz's key is a v3 key.
    //
    // dkg's includes some v3 signatures.
    #[test]
    fn v3_packets() {
        let dkg = crate::tests::key("dkg.gpg");
        let lutz = crate::tests::key("lutz.gpg");

        // v3 primary keys are not supported.
        let cert = Cert::from_bytes(lutz);
        assert_match!(Error::MalformedCert(_)
                      = cert.err().unwrap().downcast::<Error>().unwrap());

        let cert = Cert::from_bytes(dkg);
        assert!(cert.is_ok(), "dkg.gpg: {:?}", cert);
    }

    #[test]
    fn keyring_with_v3_public_keys() {
        let dkg = crate::tests::key("dkg.gpg");
        let lutz = crate::tests::key("lutz.gpg");

        let cert = Cert::from_bytes(dkg);
        assert!(cert.is_ok(), "dkg.gpg: {:?}", cert);

        // Key ring with two good keys
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, true ]);

        // Key ring with a good key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false ]);

        // Key ring with a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ false, true ]);

        // Key ring with a good key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false, true ]);

        // Key ring with a good key, a bad key, and a bad key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false, false ]);

        // Key ring with a good key, a bad key, a bad key, and a good key.
        let mut combined = vec![];
        combined.extend_from_slice(&dkg[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&lutz[..]);
        combined.extend_from_slice(&dkg[..]);
        let certs = CertParser::from_bytes(&combined[..]).unwrap()
            .map(|certr| certr.is_ok())
            .collect::<Vec<bool>>();
        assert_eq!(certs, &[ true, false, false, true ]);
    }

    #[test]
    fn merge_with_incomplete_update() {
        let cert = Cert::from_bytes(crate::tests::key("about-to-expire.expired.pgp"))
            .unwrap();
        assert!(! cert.primary_key_signature(None).unwrap()
                .key_alive(cert.primary(), None).is_ok());

        let update =
            Cert::from_bytes(crate::tests::key("about-to-expire.update-no-uid.pgp"))
            .unwrap();
        let cert = cert.merge(update).unwrap();
        assert!(cert.primary_key_signature(None).unwrap()
                .key_alive(cert.primary(), None).is_ok());
    }

    #[test]
    fn packet_pile_roundtrip() {
        // Make sure Cert::from_packet_pile(Cert::to_packet_pile(cert))
        // does a clean round trip.

        let cert = Cert::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-direct-revocation.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-userid-revocation.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-subkey-revocation.pgp")).unwrap();
        let cert2
            = Cert::from_packet_pile(cert.clone().into_packet_pile()).unwrap();
        assert_eq!(cert, cert2);
    }

    #[test]
    fn merge_packets() {
        use crate::armor;
        use crate::packet::Tag;

        // Merge the revocation certificate into the Cert and make sure
        // it shows up.
        let cert = Cert::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();

        let rev = crate::tests::key("already-revoked.rev");
        let rev = PacketPile::from_reader(armor::Reader::new(&rev[..], None))
            .unwrap();

        let rev : Vec<Packet> = rev.into_children().collect();
        assert_eq!(rev.len(), 1);
        assert_eq!(rev[0].tag(), Tag::Signature);

        let packets_pre_merge = cert.clone().into_packets().count();
        let cert = cert.merge_packets(rev).unwrap();
        let packets_post_merge = cert.clone().into_packets().count();
        assert_eq!(packets_post_merge, packets_pre_merge + 1);
    }

    #[test]
    fn set_expiry() {
        let (cert, _) = CertBuilder::autocrypt(None, Some("Test"))
            .generate().unwrap();

        let now = cert.primary().creation_time();
        let a_sec = time::Duration::new(1, 0);

        let expiry_orig = cert.primary_key_signature(None).unwrap()
            .key_expiration_time()
            .expect("Keys expire by default.");

        let mut keypair = cert.primary().clone().mark_parts_secret()
            .unwrap().into_keypair().unwrap();

        // Clear the expiration.
        let as_of1 = now + time::Duration::new(10, 0);
        let cert = cert.set_expiry_as_of(
            &mut keypair,
            None,
            as_of1).unwrap();
        {
            // If t < as_of1, we should get the original expiry.
            assert_eq!(cert.primary_key_signature(now).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            assert_eq!(cert.primary_key_signature(as_of1 - a_sec).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            // If t >= as_of1, we should get the new expiry.
            assert_eq!(cert.primary_key_signature(as_of1).unwrap()
                           .key_expiration_time(),
                       None);
        }

        // Shorten the expiry.  (The default expiration should be at
        // least a few weeks, so removing an hour should still keep us
        // over 0.)
        let expiry_new = expiry_orig - time::Duration::new(60 * 60, 0);
        assert!(expiry_new > time::Duration::new(0, 0));

        let as_of2 = as_of1 + time::Duration::new(10, 0);
        let cert = cert.set_expiry_as_of(
            &mut keypair,
            Some(expiry_new),
            as_of2).unwrap();
        {
            // If t < as_of1, we should get the original expiry.
            assert_eq!(cert.primary_key_signature(now).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            assert_eq!(cert.primary_key_signature(as_of1 - a_sec).unwrap()
                           .key_expiration_time(),
                       Some(expiry_orig));
            // If as_of1 <= t < as_of2, we should get the second
            // expiry (None).
            assert_eq!(cert.primary_key_signature(as_of1).unwrap()
                           .key_expiration_time(),
                       None);
            assert_eq!(cert.primary_key_signature(as_of2 - a_sec).unwrap()
                           .key_expiration_time(),
                       None);
            // If t <= as_of2, we should get the new expiry.
            assert_eq!(cert.primary_key_signature(as_of2).unwrap()
                           .key_expiration_time(),
                       Some(expiry_new));
        }
    }

    #[test]
    fn direct_key_sig() {
        use crate::types::SignatureType;
        // XXX: testing sequoia against itself isn't optimal, but I couldn't
        // find a tool to generate direct key signatures :-(

        let (cert1, _) = CertBuilder::new().generate().unwrap();
        let mut buf = Vec::default();

        cert1.serialize(&mut buf).unwrap();
        let cert2 = Cert::from_bytes(&buf).unwrap();

        assert_eq!(cert2.primary_key_signature(None).unwrap().typ(),
                   SignatureType::DirectKey);
        assert_eq!(cert2.userids().count(), 0);
    }

    #[test]
    fn revoked() {
        fn check(cert: &Cert, direct_revoked: bool,
                 userid_revoked: bool, subkey_revoked: bool) {
            // If we have a user id---even if it is revoked---we have
            // a primary key signature.
            let typ = cert.primary_key_signature(None).unwrap().typ();
            assert_eq!(typ, SignatureType::PositiveCertification,
                       "{:#?}", cert);

            let revoked = cert.revoked(None);
            if direct_revoked {
                assert_match!(RevocationStatus::Revoked(_) = revoked,
                              "{:#?}", cert);
            } else {
                assert_eq!(revoked, RevocationStatus::NotAsFarAsWeKnow,
                           "{:#?}", cert);
            }

            for userid in cert.userids().policy(None) {
                let typ = userid.binding_signature().unwrap().typ();
                assert_eq!(typ, SignatureType::PositiveCertification,
                           "{:#?}", cert);

                let revoked = userid.revoked();
                if userid_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", cert);
                }
            }

            for subkey in cert.subkeys() {
                let typ = subkey.binding_signature(None).unwrap().typ();
                assert_eq!(typ, SignatureType::SubkeyBinding,
                           "{:#?}", cert);

                let revoked = subkey.revoked(None);
                if subkey_revoked {
                    assert_match!(RevocationStatus::Revoked(_) = revoked);
                } else {
                    assert_eq!(RevocationStatus::NotAsFarAsWeKnow, revoked,
                               "{:#?}", cert);
                }
            }
        }

        let cert = Cert::from_bytes(crate::tests::key("already-revoked.pgp")).unwrap();
        check(&cert, false, false, false);

        let d = Cert::from_bytes(
            crate::tests::key("already-revoked-direct-revocation.pgp")).unwrap();
        check(&d, true, false, false);

        check(&cert.clone().merge(d.clone()).unwrap(), true, false, false);
        // Make sure the merge order does not matter.
        check(&d.clone().merge(cert.clone()).unwrap(), true, false, false);

        let u = Cert::from_bytes(
            crate::tests::key("already-revoked-userid-revocation.pgp")).unwrap();
        check(&u, false, true, false);

        check(&cert.clone().merge(u.clone()).unwrap(), false, true, false);
        check(&u.clone().merge(cert.clone()).unwrap(), false, true, false);

        let k = Cert::from_bytes(
            crate::tests::key("already-revoked-subkey-revocation.pgp")).unwrap();
        check(&k, false, false, true);

        check(&cert.clone().merge(k.clone()).unwrap(), false, false, true);
        check(&k.clone().merge(cert.clone()).unwrap(), false, false, true);

        // direct and user id revocation.
        check(&d.clone().merge(u.clone()).unwrap(), true, true, false);
        check(&u.clone().merge(d.clone()).unwrap(), true, true, false);

        // direct and subkey revocation.
        check(&d.clone().merge(k.clone()).unwrap(), true, false, true);
        check(&k.clone().merge(d.clone()).unwrap(), true, false, true);

        // user id and subkey revocation.
        check(&u.clone().merge(k.clone()).unwrap(), false, true, true);
        check(&k.clone().merge(u.clone()).unwrap(), false, true, true);

        // direct, user id and subkey revocation.
        check(&d.clone().merge(u.clone().merge(k.clone()).unwrap()).unwrap(),
              true, true, true);
        check(&d.clone().merge(k.clone().merge(u.clone()).unwrap()).unwrap(),
              true, true, true);
    }

    #[test]
    fn revoke() {
        let (cert, _) = CertBuilder::autocrypt(None, Some("Test"))
            .generate().unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   cert.revoked(None));

        let mut keypair = cert.primary().clone().mark_parts_secret()
            .unwrap().into_keypair().unwrap();

        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::KeyCompromised,
                b"It was the maid :/").unwrap()
            .build(&mut keypair, &cert, None)
            .unwrap();
        assert_eq!(sig.typ(), SignatureType::KeyRevocation);
        assert_eq!(sig.issuer(), Some(&cert.primary().keyid()));
        assert_eq!(sig.issuer_fingerprint(),
                   Some(&cert.primary().fingerprint()));

        let cert = cert.merge_packets(vec![sig.into()]).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(None));


        // Have other revoke cert.
        let (other, _) = CertBuilder::autocrypt(None, Some("Test 2"))
            .generate().unwrap();

        let mut keypair = other.primary().clone().mark_parts_secret()
            .unwrap().into_keypair().unwrap();

        let sig = CertRevocationBuilder::new()
            .set_reason_for_revocation(
                ReasonForRevocation::KeyCompromised,
                b"It was the maid :/").unwrap()
            .build(&mut keypair, &cert, None)
            .unwrap();

        assert_eq!(sig.typ(), SignatureType::KeyRevocation);
        assert_eq!(sig.issuer(), Some(&other.primary().keyid()));
        assert_eq!(sig.issuer_fingerprint(),
                   Some(&other.primary().fingerprint()));
    }

    #[test]
    fn revoke_subkey() {
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .generate().unwrap();

        let sig = {
            let subkey = cert.subkeys().nth(0).unwrap();
            assert_eq!(RevocationStatus::NotAsFarAsWeKnow, subkey.revoked(None));

            let mut keypair = cert.primary().clone().mark_parts_secret()
                .unwrap().into_keypair().unwrap();
            SubkeyRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::UIDRetired,
                    b"It was the maid :/").unwrap()
                .build(&mut keypair, &cert, subkey.key(), None)
                .unwrap()
        };
        assert_eq!(sig.typ(), SignatureType::SubkeyRevocation);
        let cert = cert.merge_packets(vec![sig.into()]).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   cert.revoked(None));

        let subkey = cert.subkeys().nth(0).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = subkey.revoked(None));
    }

    #[test]
    fn revoke_uid() {
        let (cert, _) = CertBuilder::new()
            .add_userid("Test1")
            .add_userid("Test2")
            .generate().unwrap();

        let sig = {
            let uid = cert.userids().policy(None).nth(1).unwrap();
            assert_eq!(RevocationStatus::NotAsFarAsWeKnow, uid.revoked());

            let mut keypair = cert.primary().clone().mark_parts_secret()
                .unwrap().into_keypair().unwrap();
            UserIDRevocationBuilder::new()
                .set_reason_for_revocation(
                    ReasonForRevocation::UIDRetired,
                    b"It was the maid :/").unwrap()
                .build(&mut keypair, &cert, uid.userid(), None)
                .unwrap()
        };
        assert_eq!(sig.typ(), SignatureType::CertificationRevocation);
        let cert = cert.merge_packets(vec![sig.into()]).unwrap();
        assert_eq!(RevocationStatus::NotAsFarAsWeKnow,
                   cert.revoked(None));

        let uid = cert.userids().policy(None).nth(1).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = uid.revoked());
    }

    #[test]
    fn key_revoked() {
        use crate::types::Features;
        use crate::packet::key::Key4;
        use crate::types::Curve;
        use rand::{thread_rng, Rng, distributions::Open01};
        /*
         * t1: 1st binding sig ctime
         * t2: soft rev sig ctime
         * t3: 2nd binding sig ctime
         * t4: hard rev sig ctime
         *
         * [0,t1): invalid, but not revoked
         * [t1,t2): valid (not revocations)
         * [t2,t3): revoked (soft revocation)
         * [t3,t4): valid again (new self sig)
         * [t4,inf): hard revocation (hard revocation)
         *
         * One the hard revocation is merged, then the Cert is
         * considered revoked at all times.
         */
        let t1 = time::UNIX_EPOCH + time::Duration::new(946681200, 0);  // 2000-1-1
        let t2 = time::UNIX_EPOCH + time::Duration::new(978303600, 0);  // 2001-1-1
        let t3 = time::UNIX_EPOCH + time::Duration::new(1009839600, 0); // 2002-1-1
        let t4 = time::UNIX_EPOCH + time::Duration::new(1041375600, 0); // 2003-1-1

        let mut key: key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        key.set_creation_time(t1).unwrap();
        let mut pair = key.clone().into_keypair().unwrap();
        let (bind1, rev1, bind2, rev2) = {
            let bind1 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t1).unwrap()
                .set_key_expiration_time(Some(time::Duration::new(10 * 52 * 7 * 24 * 60 * 60, 0))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            let rev1 = signature::Builder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(t2).unwrap()
                .set_reason_for_revocation(ReasonForRevocation::KeySuperseded,
                                           &b""[..]).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            let bind2 = signature::Builder::new(SignatureType::DirectKey)
                .set_features(&Features::sequoia()).unwrap()
                .set_key_flags(&KeyFlags::default()).unwrap()
                .set_signature_creation_time(t3).unwrap()
                .set_key_expiration_time(Some(time::Duration::new(10 * 52 * 7 * 24 * 60 * 60, 0))).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            let rev2 = signature::Builder::new(SignatureType::KeyRevocation)
                .set_signature_creation_time(t4).unwrap()
                .set_reason_for_revocation(ReasonForRevocation::KeyCompromised,
                                           &b""[..]).unwrap()
                .set_issuer_fingerprint(key.fingerprint()).unwrap()
                .set_issuer(key.keyid()).unwrap()
                .sign_direct_key(&mut pair).unwrap();

            (bind1, rev1, bind2, rev2)
        };
        let pk : key::PublicKey = key.into();
        let cert = Cert::from_packet_pile(PacketPile::from(vec![
            pk.into(),
            bind1.into(),
            bind2.into(),
            rev1.into()
        ])).unwrap();

        let f1: f32 = thread_rng().sample(Open01);
        let f2: f32 = thread_rng().sample(Open01);
        let f3: f32 = thread_rng().sample(Open01);
        let te1 = t1 - time::Duration::new((60. * 60. * 24. * 300.0 * f1) as u64, 0);
        let t12 = t1 + time::Duration::new((60. * 60. * 24. * 300.0 * f2) as u64, 0);
        let t23 = t2 + time::Duration::new((60. * 60. * 24. * 300.0 * f3) as u64, 0);
        let t34 = t3 + time::Duration::new((60. * 60. * 24. * 300.0 * f3) as u64, 0);

        assert_eq!(cert.revoked(te1), RevocationStatus::NotAsFarAsWeKnow);
        assert_eq!(cert.revoked(t12), RevocationStatus::NotAsFarAsWeKnow);
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(t23));
        assert_eq!(cert.revoked(t34), RevocationStatus::NotAsFarAsWeKnow);

        // Merge in the hard revocation.
        let cert = cert.merge_packets(vec![ rev2.into() ]).unwrap();
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(te1));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(t12));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(t23));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(t34));
        assert_match!(RevocationStatus::Revoked(_) = cert.revoked(t4));
        assert_match!(RevocationStatus::Revoked(_)
                      = cert.revoked(time::SystemTime::now()));
    }

    #[test]
    fn key_revoked2() {
        tracer!(true, "cert_revoked2", 0);

        fn cert_revoked<T>(cert: &Cert, t: T) -> bool
            where T: Into<Option<time::SystemTime>>
        {
            !destructures_to!(RevocationStatus::NotAsFarAsWeKnow
                              = cert.revoked(t))
        }

        fn subkey_revoked<T>(cert: &Cert, t: T) -> bool
            where T: Into<Option<time::SystemTime>>
        {
            !destructures_to!(RevocationStatus::NotAsFarAsWeKnow
                              = cert.subkeys().nth(0).unwrap().revoked(t))
        }

        let tests : [(&str, Box<dyn Fn(&Cert, _) -> bool>); 2] = [
            ("cert", Box::new(cert_revoked)),
            ("subkey", Box::new(subkey_revoked)),
        ];

        for (f, revoked) in tests.iter()
        {
            t!("Checking {} revocation", f);

            t!("Normal key");
            let cert = Cert::from_bytes(
                crate::tests::key(
                    &format!("really-revoked-{}-0-public.pgp", f))).unwrap();
            let selfsig0 = cert.primary_key_signature(None).unwrap()
                .signature_creation_time().unwrap();

            assert!(!revoked(&cert, Some(selfsig0)));
            assert!(!revoked(&cert, None));

            t!("Soft revocation");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-1-soft-revocation.pgp", f))
                ).unwrap()).unwrap();
            // A soft revocation made after `t` is ignored when
            // determining whether the key is revoked at time `t`.
            assert!(!revoked(&cert, Some(selfsig0)));
            assert!(revoked(&cert, None));

            t!("New self signature");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-2-new-self-sig.pgp", f))
                ).unwrap()).unwrap();
            assert!(!revoked(&cert, Some(selfsig0)));
            // Newer self-sig override older soft revocations.
            assert!(!revoked(&cert, None));

            t!("Hard revocation");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-3-hard-revocation.pgp", f))
                ).unwrap()).unwrap();
            // Hard revocations trump all.
            assert!(revoked(&cert, Some(selfsig0)));
            assert!(revoked(&cert, None));

            t!("New self signature");
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-4-new-self-sig.pgp", f))
                ).unwrap()).unwrap();
            assert!(revoked(&cert, Some(selfsig0)));
            assert!(revoked(&cert, None));
        }
    }

    #[test]
    fn userid_revoked2() {
        fn check_userids<T>(cert: &Cert, revoked: bool, t: T)
            where T: Into<Option<time::SystemTime>>, T: Copy
        {
            assert_match!(RevocationStatus::NotAsFarAsWeKnow
                          = cert.revoked(None));

            let mut slim_shady = false;
            let mut eminem = false;
            for b in cert.userids().policy(t) {
                if b.userid().value() == b"Slim Shady" {
                    assert!(!slim_shady);
                    slim_shady = true;

                    if revoked {
                        assert_match!(RevocationStatus::Revoked(_)
                                      = b.revoked());
                    } else {
                        assert_match!(RevocationStatus::NotAsFarAsWeKnow
                                      = b.revoked());
                    }
                } else {
                    assert!(!eminem);
                    eminem = true;

                    assert_match!(RevocationStatus::NotAsFarAsWeKnow
                                  = b.revoked());
                }
            }

            assert!(slim_shady);
            assert!(eminem);
        }

        fn check_uas<T>(cert: &Cert, revoked: bool, t: T)
            where T: Into<Option<time::SystemTime>>, T: Copy
        {
            assert_match!(RevocationStatus::NotAsFarAsWeKnow
                          = cert.revoked(None));

            assert_eq!(cert.user_attributes().count(), 1);
            let ua = cert.user_attributes().bindings().nth(0).unwrap();
            if revoked {
                assert_match!(RevocationStatus::Revoked(_)
                              = ua.revoked(t));
            } else {
                assert_match!(RevocationStatus::NotAsFarAsWeKnow
                              = ua.revoked(t));
            }
        }

        tracer!(true, "userid_revoked2", 0);

        let tests : [(&str, Box<dyn Fn(&Cert, bool, _)>); 2] = [
            ("userid", Box::new(check_userids)),
            ("user-attribute", Box::new(check_uas)),
        ];

        for (f, check) in tests.iter()
        {
            t!("Checking {} revocation", f);

            t!("Normal key");
            let cert = Cert::from_bytes(
                crate::tests::key(
                    &format!("really-revoked-{}-0-public.pgp", f))).unwrap();

            let now = time::SystemTime::now();
            let selfsig0
                = cert.userids().policy(now).map(|b| {
                    b.binding_signature().unwrap()
                        .signature_creation_time().unwrap()
                })
                .max().unwrap();

            check(&cert, false, selfsig0);
            check(&cert, false, now);

            // A soft-revocation.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-1-soft-revocation.pgp", f))
                ).unwrap()).unwrap();

            check(&cert, false, selfsig0);
            check(&cert, true, now);

            // A new self signature.  This should override the soft-revocation.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-2-new-self-sig.pgp", f))
                ).unwrap()).unwrap();

            check(&cert, false, selfsig0);
            check(&cert, false, now);

            // A hard revocation.  Unlike for Certs, this does NOT trumps
            // everything.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-3-hard-revocation.pgp", f))
                ).unwrap()).unwrap();

            check(&cert, false, selfsig0);
            check(&cert, true, now);

            // A newer self siganture.
            let cert = cert.merge(
                Cert::from_bytes(
                    crate::tests::key(
                        &format!("really-revoked-{}-4-new-self-sig.pgp", f))
                ).unwrap()).unwrap();

            check(&cert, false, selfsig0);
            check(&cert, false, now);
        }
    }

    #[test]
    fn unrevoked() {
        let cert =
            Cert::from_bytes(crate::tests::key("un-revoked-userid.pgp")).unwrap();

        for uid in cert.userids().policy(None) {
            assert_eq!(uid.revoked(), RevocationStatus::NotAsFarAsWeKnow);
        }
    }

    #[test]
    fn is_tsk() {
        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked.pgp")).unwrap();
        assert!(! cert.is_tsk());

        let cert = Cert::from_bytes(
            crate::tests::key("already-revoked-private.pgp")).unwrap();
        assert!(cert.is_tsk());
    }

    #[test]
    fn export_only_exports_public_key() {
        let cert = Cert::from_bytes(
            crate::tests::key("testy-new-private.pgp")).unwrap();
        assert!(cert.is_tsk());

        let mut v = Vec::new();
        cert.serialize(&mut v).unwrap();
        let cert = Cert::from_bytes(&v).unwrap();
        assert!(! cert.is_tsk());
    }

    // Make sure that when merging two Certs, the primary key and
    // subkeys with and without a private key are merged.
    #[test]
    fn public_private_merge() {
        let (tsk, _) = CertBuilder::autocrypt(None, Some("foo@example.com"))
            .generate().unwrap();
        // tsk is now a cert, but it still has its private bits.
        assert!(tsk.primary.key().secret().is_some());
        assert!(tsk.is_tsk());
        let subkey_count = tsk.subkeys().len();
        assert!(subkey_count > 0);
        assert!(tsk.subkeys().all(|k| k.key().secret().is_some()));

        // This will write out the tsk as a cert, i.e., without any
        // private bits.
        let mut cert_bytes = Vec::new();
        tsk.serialize(&mut cert_bytes).unwrap();

        // Reading it back in, the private bits have been stripped.
        let cert = Cert::from_bytes(&cert_bytes[..]).unwrap();
        assert!(cert.primary.key().secret().is_none());
        assert!(!cert.is_tsk());
        assert!(cert.subkeys().all(|k| k.key().secret().is_none()));

        let merge1 = cert.clone().merge(tsk.clone()).unwrap();
        assert!(merge1.is_tsk());
        assert!(merge1.primary.key().secret().is_some());
        assert_eq!(merge1.subkeys().len(), subkey_count);
        assert!(merge1.subkeys().all(|k| k.key().secret().is_some()));

        let merge2 = tsk.clone().merge(cert.clone()).unwrap();
        assert!(merge2.is_tsk());
        assert!(merge2.primary.key().secret().is_some());
        assert_eq!(merge2.subkeys().len(), subkey_count);
        assert!(merge2.subkeys().all(|k| k.key().secret().is_some()));
    }

    #[test]
    fn issue_120() {
        let cert = "
-----BEGIN PGP ARMORED FILE-----

xcBNBFoVcvoBCACykTKOJddF8SSUAfCDHk86cNTaYnjCoy72rMgWJsrMLnz/V16B
J9M7l6nrQ0JMnH2Du02A3w+kNb5q97IZ/M6NkqOOl7uqjyRGPV+XKwt0G5mN/ovg
8630BZAYS3QzavYf3tni9aikiGH+zTFX5pynTNfYRXNBof3Xfzl92yad2bIt4ITD
NfKPvHRko/tqWbclzzEn72gGVggt1/k/0dKhfsGzNogHxg4GIQ/jR/XcqbDFR3RC
/JJjnTOUPGsC1y82Xlu8udWBVn5mlDyxkad5laUpWWg17anvczEAyx4TTOVItLSu
43iPdKHSs9vMXWYID0bg913VusZ2Ofv690nDABEBAAHNJFRlc3R5IE1jVGVzdGZh
Y2UgPHRlc3R5QGV4YW1wbGUub3JnPsLAlAQTAQgAPhYhBD6Id8h3J0aSl1GJ9dA/
b4ZSJv6LBQJaFXL6AhsDBQkDwmcABQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJ
ENA/b4ZSJv6Lxo8H/1XMt+Nqa6e0SG/up3ypKe5nplA0p/9j/s2EIsP8S8uPUd+c
WS17XOmPwkNDmHeL3J6hzwL74NlYSLEtyf7WoOV74xAKQA9WkqaKPHCtpll8aFWA
ktQDLWTPeKuUuSlobAoRtO17ZmheSQzmm7JYt4Ahkxt3agqGT05OsaAey6nIKqpq
ArokvdHTZ7AFZeSJIWmuCoT9M1lo3LAtLnRGOhBMJ5dDIeOwflJwNBXlJVi4mDPK
+fumV0MbSPvZd1/ivFjSpQyudWWtv1R1nAK7+a4CPTGxPvAQkLtRsL/V+Q7F3BJG
jAn4QVx8p4t3NOPuNgcoZpLBE3sc4Nfs5/CphMLHwE0EWhVy+gEIALSpjYD+tuWC
rj6FGP6crQjQzVlH+7axoM1ooTwiPs4fzzt2iLw3CJyDUviM5F9ZBQTei635RsAR
a/CJTSQYAEU5yXXxhoe0OtwnuvsBSvVT7Fox3pkfNTQmwMvkEbodhfKpqBbDKCL8
f5A8Bb7aISsLf0XRHWDkHVqlz8LnOR3f44wEWiTeIxLc8S1QtwX/ExyW47oPsjs9
ShCmwfSpcngH/vGBRTO7WeI54xcAtKSm/20B/MgrUl5qFo17kUWot2C6KjuZKkHk
3WZmJwQz+6rTB11w4AXt8vKkptYQCkfat2FydGpgRO5dVg6aWNJefOJNkC7MmlzC
ZrrAK8FJ6jcAEQEAAcLAdgQYAQgAIBYhBD6Id8h3J0aSl1GJ9dA/b4ZSJv6LBQJa
FXL6AhsMAAoJENA/b4ZSJv6Lt7kH/jPr5wg8lcamuLj4lydYiLttvvTtDTlD1TL+
IfwVARB/ruoerlEDr0zX1t3DCEcvJDiZfOqJbXtHt70+7NzFXrYxfaNFmikMgSQT
XqHrMQho4qpseVOeJPWGzGOcrxCdw/ZgrWbkDlAU5KaIvk+M4wFPivjbtW2Ro2/F
J4I/ZHhJlIPmM+hUErHC103b08pBENXDQlXDma7LijH5kWhyfF2Ji7Ft0EjghBaW
AeGalQHjc5kAZu5R76Mwt06MEQ/HL1pIvufTFxkr/SzIv8Ih7Kexb0IrybmfD351
Pu1xwz57O4zo1VYf6TqHJzVC3OMvMUM2hhdecMUe5x6GorNaj6g=
=1Vzu
-----END PGP ARMORED FILE-----
";
        assert!(Cert::from_bytes(cert).is_err());
    }

    #[test]
    fn missing_uids() {
        let (cert, _) = CertBuilder::new()
            .add_userid("test1@example.com")
            .add_userid("test2@example.com")
            .add_transport_encryption_subkey()
            .add_certification_subkey()
            .generate().unwrap();
        assert_eq!(cert.subkeys().len(), 2);
        let pile = cert
            .into_packet_pile()
            .into_children()
            .filter(|pkt| {
                match pkt {
                    &Packet::PublicKey(_) | &Packet::PublicSubkey(_) => true,
                    &Packet::Signature(ref sig) => {
                        sig.typ() == SignatureType::DirectKey
                            || sig.typ() == SignatureType::SubkeyBinding
                    }
                    e => {
                        eprintln!("{:?}", e);
                        false
                    }
                }
            })
        .collect::<Vec<_>>();
        eprintln!("parse back");
        let cert = Cert::from_packet_pile(PacketPile::from(pile)).unwrap();

        assert_eq!(cert.subkeys().len(), 2);
    }

    #[test]
    fn signature_order() {
        let neal = Cert::from_bytes(crate::tests::key("neal.pgp")).unwrap();

        // This test is useless if we don't have some lists with more
        // than one signature.
        let mut cmps = 0;

        for uid in neal.userids().bindings() {
            for sigs in [
                uid.self_signatures(),
                    uid.certifications(),
                uid.self_revocations(),
                uid.other_revocations()
            ].iter() {
                for sigs in sigs.windows(2) {
                    cmps += 1;
                    assert!(sigs[0].signature_creation_time()
                            >= sigs[1].signature_creation_time());
                }
            }

            // Make sure we return the most recent first.
            assert_eq!(uid.self_signatures().first().unwrap(),
                       uid.binding_signature(None).unwrap());
        }

        assert!(cmps > 0);
    }

    #[test]
    fn cert_reject_keyrings() {
        let mut keyring = Vec::new();
        keyring.extend_from_slice(crate::tests::key("neal.pgp"));
        keyring.extend_from_slice(crate::tests::key("neal.pgp"));
        assert!(Cert::from_bytes(&keyring).is_err());
    }

    #[test]
    fn cert_is_send_and_sync() {
        fn f<T: Send + Sync>(_: T) {}
        f(Cert::from_bytes(crate::tests::key("testy-new.pgp")).unwrap());
    }

    #[test]
    fn primary_userid() {
        // 'really-revoked-userid' has two user ids.  One of them is
        // revoked and then restored.  Neither of the user ids has the
        // primary userid bit set.
        //
        // This test makes sure that Cert::primary_userid prefers
        // unrevoked user ids to revoked user ids, even if the latter
        // have newer self signatures.

        let cert = Cert::from_bytes(
            crate::tests::key("really-revoked-userid-0-public.pgp")).unwrap();

        let now = time::SystemTime::now();
        let selfsig0
            = cert.userids().policy(now).map(|b| {
                b.binding_signature().unwrap()
                    .signature_creation_time().unwrap()
            })
            .max().unwrap();

        // The self-sig for:
        //
        //   Slim Shady: 2019-09-14T14:21
        //   Eminem:     2019-09-14T14:22
        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"Eminem");

        // A soft-revocation for "Slim Shady".
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-1-soft-revocation.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"Eminem");

        // A new self signature for "Slim Shady".  This should
        // override the soft-revocation.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-2-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"Slim Shady");

        // A hard revocation for "Slim Shady".
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-3-hard-revocation.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"Eminem");

        // A newer self siganture for "Slim Shady". Unlike for Certs, this
        // does NOT trump everything.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("really-revoked-userid-4-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"Eminem");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"Slim Shady");

        // Play with the primary user id flag.

        let cert = Cert::from_bytes(
            crate::tests::key("primary-key-0-public.pgp")).unwrap();
        let selfsig0
            = cert.userids().policy(now).map(|b| {
                b.binding_signature().unwrap()
                    .signature_creation_time().unwrap()
            })
            .max().unwrap();

        // There is only a single User ID.
        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"aaaaa");


        // Add a second user id.  Since neither is marked primary, the
        // newer one should be considered primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-1-add-userid-bbbbb.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"bbbbb");

        // Mark aaaaa as primary.  It is now primary and the newest one.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-2-make-aaaaa-primary.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"aaaaa");

        // Update the preferences on bbbbb.  It is now the newest, but
        // it is not marked as primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-3-make-bbbbb-new-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"aaaaa");

        // Mark bbbbb as primary.  It is now the newest and marked as
        // primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-4-make-bbbbb-primary.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"bbbbb");

        // Update the preferences on aaaaa.  It is now has the newest
        // self sig, but that self sig does not say that it is
        // primary.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-5-make-aaaaa-self-sig.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"bbbbb");

        // Hard revoke aaaaa.  Unlike with Certs, a hard revocation is
        // not treated specially.
        let cert = cert.merge(
            Cert::from_bytes(
                crate::tests::key("primary-key-6-revoked-aaaaa.pgp")
            ).unwrap()).unwrap();

        assert_eq!(cert.userids().primary(selfsig0).unwrap().userid().value(), b"aaaaa");
        assert_eq!(cert.userids().primary(now).unwrap().userid().value(), b"bbbbb");
    }

    #[test]
    fn binding_signature_lookup() {
        // Check that searching for the right binding signature works
        // even when there are signatures with the same time.

        use crate::types::Features;
        use crate::packet::key::Key4;
        use crate::types::Curve;

        let a_sec = time::Duration::new(1, 0);
        let time_zero = time::UNIX_EPOCH;

        let t1 = time::UNIX_EPOCH + time::Duration::new(946681200, 0);  // 2000-1-1
        let t2 = time::UNIX_EPOCH + time::Duration::new(978303600, 0);  // 2001-1-1
        let t3 = time::UNIX_EPOCH + time::Duration::new(1009839600, 0); // 2002-1-1
        let t4 = time::UNIX_EPOCH + time::Duration::new(1041375600, 0); // 2003-1-1

        let key: key::SecretKey
            = Key4::generate_ecc(true, Curve::Ed25519).unwrap().into();
        let mut pair = key.clone().into_keypair().unwrap();
        let pk : key::PublicKey = key.clone().into();
        let mut cert = Cert::from_packet_pile(PacketPile::from(vec![
            pk.into(),
        ])).unwrap();

        for (t, offset) in &[ (t2, 0), (t4, 0), (t3, 100), (t1, 300) ] {
            for i in 0..100 {
                let binding = signature::Builder::new(SignatureType::DirectKey)
                    .set_features(&Features::sequoia()).unwrap()
                    .set_key_flags(&KeyFlags::default()).unwrap()
                    .set_signature_creation_time(t1).unwrap()
                    // Vary this...
                    .set_key_expiration_time(Some(
                        time::Duration::new((1 + i) * 24 * 60 * 60, 0)))
                    .unwrap()
                    .set_issuer_fingerprint(key.fingerprint()).unwrap()
                    .set_issuer(key.keyid()).unwrap()
                    .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512]).unwrap()
                    .set_signature_creation_time(*t).unwrap()
                    .sign_direct_key(&mut pair).unwrap();

                let binding : Packet = binding.into();

                cert = cert.merge_packets(vec![ binding ]).unwrap();
                // A time that matches multiple signatures.
                assert_eq!(cert.primary_key_signature(*t),
                           cert.direct_signatures().get(*offset));
                // A time that doesn't match any signature.
                assert_eq!(cert.primary_key_signature(*t + a_sec),
                           cert.direct_signatures().get(*offset));

                // The current time, which should use the first signature.
                assert_eq!(cert.primary_key_signature(None),
                           cert.direct_signatures().get(0));

                // The beginning of time, which should return no
                // binding signatures.
                assert_eq!(cert.primary_key_signature(time_zero), None);
            }
        }
    }

    #[test]
    fn keysigning_party() {
        use crate::cert::packet::signature;

        for cs in &[ CipherSuite::Cv25519,
                     CipherSuite::RSA3k,
                     CipherSuite::P256,
                     CipherSuite::P384,
                     CipherSuite::P521,
                     CipherSuite::RSA2k,
                     CipherSuite::RSA4k ]
        {
            let (alice, _) = CertBuilder::new()
                .set_cipher_suite(*cs)
                .add_userid("alice@foo.com")
                .generate().unwrap();

            let (bob, _) = CertBuilder::new()
                .set_cipher_suite(*cs)
                .add_userid("bob@bar.com")
                .add_signing_subkey()
                .generate().unwrap();

            assert_eq!(bob.userids().len(), 1);
            let bob_userid_binding = bob.userids().bindings().nth(0).unwrap();
            assert_eq!(bob_userid_binding.userid().value(), b"bob@bar.com");

            let sig_template
                = signature::Builder::new(SignatureType::GenericCertification)
                      .set_trust_signature(255, 120)
                      .unwrap();

            // Have alice cerify the binding "bob@bar.com" and bob's key.
            let alice_certifies_bob
                = bob_userid_binding.userid().bind(
                    &mut alice.primary().clone().mark_parts_secret()
                        .unwrap().into_keypair().unwrap(),
                    &bob,
                    sig_template).unwrap();

            let bob
                = bob.merge_packets(vec![ alice_certifies_bob.clone().into() ])
                .unwrap();

            // Make sure the certification is merged, and put in the right
            // place.
            assert_eq!(bob.userids().len(), 1);
            let bob_userid_binding = bob.userids().bindings().nth(0).unwrap();
            assert_eq!(bob_userid_binding.userid().value(), b"bob@bar.com");

            // Canonicalizing Bob's cert without having Alice's key
            // has to resort to a heuristic to order third party
            // signatures.  However, since we know the signature's
            // type (GenericCertification), we know that it can only
            // go to the only userid, so there is no ambiguity in this
            // case.
            assert_eq!(bob_userid_binding.certifications(),
                       &[ alice_certifies_bob.clone() ]);

            // Make sure the certification is correct.
            alice_certifies_bob
                .verify_userid_binding(&alice.primary().clone(),
                                       &bob.primary().clone(),
                                       bob_userid_binding.userid()).unwrap();
        }
   }

    #[test]
    fn decrypt_secrets() {
        let (cert, _) = CertBuilder::new()
            .add_transport_encryption_subkey()
            .set_password(Some(String::from("streng geheim").into()))
            .generate().unwrap();
        assert_eq!(cert.keys().secret().count(), 2);
        assert_eq!(cert.keys().unencrypted_secret().count(), 0);

        let mut primary = cert.primary().clone();
        let algo = primary.pk_algo();
        primary.secret_mut().unwrap()
            .decrypt_in_place(algo, &"streng geheim".into()).unwrap();
        let cert = cert.merge_packets(vec![
            primary.mark_parts_secret().unwrap().mark_role_primary().into()
        ]).unwrap();

        assert_eq!(cert.keys().secret().count(), 2);
        assert_eq!(cert.keys().unencrypted_secret().count(), 1);
    }
}
