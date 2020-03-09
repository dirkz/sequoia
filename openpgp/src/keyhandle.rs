use std::convert::TryFrom;
use std::cmp;
use std::cmp::Ordering;
use std::borrow::Borrow;

use crate::{
    Error,
    Fingerprint,
    KeyID,
    Result,
};

/// Identifies OpenPGP keys.
///
/// An `KeyHandle` is either a `Fingerprint` or a `KeyID`.
#[derive(Debug, Clone, Hash)]
pub enum KeyHandle {
    /// A Fingerprint.
    Fingerprint(Fingerprint),
    /// A KeyID.
    KeyID(KeyID),
}

impl std::fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyHandle::Fingerprint(v) => v.fmt(f),
            KeyHandle::KeyID(v) => v.fmt(f),
        }
    }
}

impl From<KeyID> for KeyHandle {
    fn from(i: KeyID) -> Self {
        KeyHandle::KeyID(i)
    }
}

impl From<&KeyID> for KeyHandle {
    fn from(i: &KeyID) -> Self {
        KeyHandle::KeyID(i.clone())
    }
}

impl From<KeyHandle> for KeyID {
    fn from(i: KeyHandle) -> Self {
        match i {
            KeyHandle::Fingerprint(i) => i.into(),
            KeyHandle::KeyID(i) => i,
        }
    }
}

impl From<&KeyHandle> for KeyID {
    fn from(i: &KeyHandle) -> Self {
        match i {
            KeyHandle::Fingerprint(i) => i.clone().into(),
            KeyHandle::KeyID(i) => i.clone(),
        }
    }
}

impl From<Fingerprint> for KeyHandle {
    fn from(i: Fingerprint) -> Self {
        KeyHandle::Fingerprint(i)
    }
}

impl From<&Fingerprint> for KeyHandle {
    fn from(i: &Fingerprint) -> Self {
        KeyHandle::Fingerprint(i.clone())
    }
}

impl TryFrom<KeyHandle> for Fingerprint {
    type Error = anyhow::Error;
    fn try_from(i: KeyHandle) -> Result<Self> {
        match i {
            KeyHandle::Fingerprint(i) => Ok(i),
            KeyHandle::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}

impl TryFrom<&KeyHandle> for Fingerprint {
    type Error = anyhow::Error;
    fn try_from(i: &KeyHandle) -> Result<Self> {
        match i {
            KeyHandle::Fingerprint(i) => Ok(i.clone()),
            KeyHandle::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}

impl PartialOrd for KeyHandle {
    fn partial_cmp(&self, other: &KeyHandle) -> Option<Ordering> {
        let a = self.as_slice();
        let b = other.as_slice();

        let l = cmp::min(a.len(), b.len());

        // Do a little endian comparison so that for v4 keys (where
        // the KeyID is a suffix of the Fingerprint) equivalent KeyIDs
        // and Fingerprints sort next to each other.
        for (a, b) in a[a.len()-l..].iter().zip(b[b.len()-l..].iter()) {
            let cmp = a.cmp(b);
            if cmp != Ordering::Equal {
                return Some(cmp);
            }
        }

        if a.len() == b.len() {
            Some(Ordering::Equal)
        } else {
            // One (a KeyID) is the suffix of the other (a
            // Fingerprint).
            None
        }
    }
}

impl PartialEq for KeyHandle {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl KeyHandle {
    /// Converts the key handle to a hexadecimal number.
    pub fn to_hex(&self) -> String {
        match self {
            KeyHandle::Fingerprint(i) => i.to_hex(),
            KeyHandle::KeyID(i) => i.to_hex(),
        }
    }

    /// Returns a reference to the raw identifier.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            KeyHandle::Fingerprint(i) => i.as_slice(),
            KeyHandle::KeyID(i) => i.as_slice(),
        }
    }

    /// Returns whether `self` and `other` could be aliases of each other.
    ///
    /// `KeyHandle`'s `PartialEq` implementation cannot assert that a
    /// `Fingerprint` and a `KeyID` are equal, because distinct
    /// fingerprints may have the same `KeyID`, and `PartialEq` must
    /// be [transitive], i.e.,
    ///
    /// ```text
    /// a == b and b == c implies a == c.
    /// ```
    ///
    /// [transitive]: https://doc.rust-lang.org/std/cmp/trait.PartialEq.html
    ///
    /// That is, if `fpr1` and `fpr2` are distinct fingerprints with the
    /// same key ID then:
    ///
    /// ```text
    /// fpr1 == keyid and fpr2 == keyid, but fpr1 != fpr2.
    /// ```
    ///
    /// In these cases (and only these cases) `KeyHandle`'s
    /// `PartialOrd` implementation returns `None` to correctly
    /// indicate that a comparison is not possible.
    ///
    /// This definition of equality makes searching for a given
    /// `KeyHandle` using `PartialEq` awkward.  This function fills
    /// that gap.  It answers the question: given two `KeyHandles`,
    /// could they be aliases?  That is, it implements the desired,
    /// non-transitive equality relation:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use openpgp::KeyID;
    /// # use openpgp::KeyHandle;
    /// #
    /// # let fpr1 : KeyHandle
    /// #     = Fingerprint::from_hex(
    /// #           "8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9")
    /// #       .unwrap().into();
    /// #
    /// # let fpr2 : KeyHandle
    /// #     = Fingerprint::from_hex(
    /// #           "0123 4567 8901 2345 6789  0123 AACB 3243 6300 52D9")
    /// #       .unwrap().into();
    /// #
    /// # let keyid : KeyHandle = KeyID::from_hex("AACB 3243 6300 52D9")
    /// #     .unwrap().into();
    /// #
    /// // fpr1 and fpr2 are different fingerprints with the same KeyID.
    /// assert!(! fpr1.eq(&fpr2));
    /// assert!(fpr1.aliases(&keyid));
    /// assert!(fpr2.aliases(&keyid));
    /// assert!(! fpr1.aliases(&fpr2));
    /// ```
    pub fn aliases<H>(&self, other: H) -> bool
        where H: Borrow<KeyHandle>
    {
        // This works, because the PartialOrd implementation only
        // returns None if one value is a fingerprint and the other is
        // a key id that matches the fingerprint's key id.
        self.partial_cmp(other.borrow()).unwrap_or(Ordering::Equal)
            == Ordering::Equal
    }
}
