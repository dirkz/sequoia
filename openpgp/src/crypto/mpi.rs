//! Multi Precision Integers.

use std::fmt;
use std::cmp::Ordering;

#[cfg(any(test, feature = "quickcheck"))]
use quickcheck::{Arbitrary, Gen};
#[cfg(any(test, feature = "quickcheck"))]
use rand::Rng;

use crate::types::{
    Curve,
    HashAlgorithm,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
};
use crate::crypto::hash::{self, Hash};
use crate::crypto::mem::{secure_cmp, Protected};
use crate::serialize::Marshal;

use crate::Error;
use crate::Result;

/// Holds a single MPI.
#[derive(Clone)]
pub struct MPI {
    /// Integer value as big-endian.
    value: Box<[u8]>,
}

impl From<Vec<u8>> for MPI {
    fn from(v: Vec<u8>) -> Self {
        Self::new(&v)
    }
}

impl MPI {
    /// Creates a new MPI.
    ///
    /// This function takes care of leading zeros.
    pub fn new(value: &[u8]) -> Self {
        let mut leading_zeros = 0;
        for b in value {
            leading_zeros += b.leading_zeros() as usize;
            if *b != 0 {
                break;
            }
        }

        let offset = leading_zeros / 8;
        let value = Vec::from(&value[offset..]).into_boxed_slice();

        MPI {
            value,
        }
    }

    /// Creates new MPI for EC point.
    pub fn new_weierstrass(x: &[u8], y: &[u8], field_bits: usize) -> Self {
        let field_sz = if field_bits % 8 > 0 { 1 } else { 0 } + field_bits / 8;
        let mut val = vec![0x0u8; 1 + 2 * field_sz];
        let x_missing = field_sz - x.len();
        let y_missing = field_sz - y.len();

        val[0] = 0x4;
        val[1 + x_missing..1 + field_sz].copy_from_slice(x);
        val[1 + field_sz + y_missing..].copy_from_slice(y);

        MPI{
            value: val.into_boxed_slice(),
        }
    }

    /// Returns the length of the MPI in bits.
    pub fn bits(&self) -> usize {
        self.value.len() * 8
            - self.value.get(0).map(|&b| b.leading_zeros() as usize)
                  .unwrap_or(0)
    }

    /// Returns the value of this MPI.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Dissects this MPI describing a point into the individual
    /// coordinates.
    ///
    /// # Errors
    ///
    /// Returns `Error::UnsupportedEllipticCurve` if the curve is not
    /// supported, `Error::MalformedMPI` if the point is formatted
    /// incorrectly.
    pub fn decode_point(&self, curve: &Curve) -> Result<(&[u8], &[u8])> {
        use nettle::{ed25519, curve25519};
        use self::Curve::*;
        match &curve {
            Ed25519 | Cv25519 => {
                assert_eq!(curve25519::CURVE25519_SIZE,
                           ed25519::ED25519_KEY_SIZE);
                // This curve uses a custom compression format which
                // only contains the X coordinate.
                if self.value().len() != 1 + curve25519::CURVE25519_SIZE {
                    return Err(Error::MalformedMPI(
                        format!("Bad size of Curve25519 key: {} expected: {}",
                                self.value().len(),
                                1 + curve25519::CURVE25519_SIZE)).into());
                }

                if self.value().get(0).map(|&b| b != 0x40).unwrap_or(true) {
                    return Err(Error::MalformedMPI(
                        "Bad encoding of Curve25519 key".into()).into());
                }

                Ok((&self.value()[1..], &[]))
            },

            _ => {

                // Length of one coordinate in bytes, rounded up.
                let coordinate_length = (curve.len()? + 7) / 8;

                // Check length of Q.
                let expected_length =
                    1 // 0x04.
                    + (2 // (x, y)
                       * coordinate_length);

                if self.value().len() != expected_length {
                    return Err(Error::MalformedMPI(
                        format!("Invalid length of MPI: {} (expected {})",
                                self.value().len(), expected_length)).into());
                }

                if self.value().get(0).map(|&b| b != 0x04).unwrap_or(true) {
                    return Err(Error::MalformedMPI(
                        format!("Bad prefix: {:?} (expected Some(0x04))",
                                self.value().get(0))).into());
                }

                Ok((&self.value()[1..1 + coordinate_length],
                    &self.value()[1 + coordinate_length..]))
            },
        }
    }

    pub(crate) fn secure_memzero(&mut self) {
        unsafe {
            ::memsec::memzero(self.value.as_mut_ptr(), self.value.len());
        }
    }

    fn secure_memcmp(&self, other: &Self) -> Ordering {
        let cmp = unsafe {
            if self.value.len() == other.value.len() {
                ::memsec::memcmp(self.value.as_ptr(), other.value.as_ptr(),
                                 other.value.len())
            } else {
                self.value.len() as i32 - other.value.len() as i32
            }
        };

        match cmp {
            0 => Ordering::Equal,
            x if x < 0 => Ordering::Less,
            _ => Ordering::Greater,
        }
    }
}

impl fmt::Debug for MPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
            "{} bits: {}", self.bits(),
            crate::fmt::to_hex(&*self.value, true)))
    }
}

impl Hash for MPI {
    /// Update the Hash with a hash of the MPIs.
    fn hash(&self, hash: &mut hash::Context) {
        let len = self.bits() as u16;

        hash.update(&len.to_be_bytes());
        hash.update(&self.value);
    }
}

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for MPI {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        loop {
            let buf = <Vec<u8>>::arbitrary(g);

            if !buf.is_empty() && buf[0] != 0 {
                break MPI::new(&buf);
            }
        }
    }
}

impl PartialOrd for MPI {
    fn partial_cmp(&self, other: &MPI) -> Option<Ordering> {
        Some(self.secure_memcmp(other))
    }
}

impl Ord for MPI {
    fn cmp(&self, other: &MPI) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialEq for MPI {
    fn eq(&self, other: &MPI) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MPI {}

impl std::hash::Hash for MPI {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

/// Holds a single MPI containing secrets.
///
/// The memory will be cleared when the object is dropped.
#[derive(Clone)]
pub struct ProtectedMPI {
    /// Integer value as big-endian.
    value: Protected,
}

impl From<Vec<u8>> for ProtectedMPI {
    fn from(m: Vec<u8>) -> Self {
        MPI::from(m).into()
    }
}

impl From<Protected> for ProtectedMPI {
    fn from(m: Protected) -> Self {
        MPI::new(&m).into()
    }
}

impl From<MPI> for ProtectedMPI {
    fn from(m: MPI) -> Self {
        ProtectedMPI {
            value: m.value.into(),
        }
    }
}

impl std::hash::Hash for ProtectedMPI {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.value.hash(state);
    }
}

impl ProtectedMPI {
    /// Returns the length of the MPI in bits.
    pub fn bits(&self) -> usize {
        self.value.len() * 8
            - self.value.get(0).map(|&b| b.leading_zeros() as usize)
                  .unwrap_or(0)
    }

    /// Returns the value of this MPI.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for ProtectedMPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            f.write_fmt(format_args!(
                "{} bits: {}", self.bits(),
                crate::fmt::to_hex(&*self.value, true)))
        } else {
            f.write_str("<Redacted>")
        }
    }
}

/// Holds a public key.
///
/// Provides a typed and structured way of storing multiple MPIs (and
/// the occasional elliptic curve) in packets.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum PublicKey {
    /// RSA public key.
    RSA {
        /// Public exponent
        e: MPI,
        /// Public modulo N = pq.
        n: MPI,
    },

    /// NIST DSA public key.
    DSA {
        /// Prime of the ring Zp.
        p: MPI,
        /// Order of `g` in Zp.
        q: MPI,
        /// Public generator of Zp.
        g: MPI,
        /// Public key g^x mod p.
        y: MPI,
    },

    /// ElGamal public key.
    ElGamal {
        /// Prime of the ring Zp.
        p: MPI,
        /// Generator of Zp.
        g: MPI,
        /// Public key g^x mod p.
        y: MPI,
    },

    /// DJBs "Twisted" Edwards curve DSA public key.
    EdDSA {
        /// Curve we're using. Must be curve 25519.
        curve: Curve,
        /// Public point.
        q: MPI,
    },

    /// NISTs Elliptic curve DSA public key.
    ECDSA {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI,
    },

    /// Elliptic curve ElGamal public key.
    ECDH {
        /// Curve we're using.
        curve: Curve,
        /// Public point.
        q: MPI,
        /// Hash algorithm used for key derivation.
        hash: HashAlgorithm,
        /// Algorithm used w/the derived key.
        sym: SymmetricAlgorithm,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl PublicKey {
    /// Returns the length of the public key in bits.
    ///
    /// For finite field crypto this returns the size of the field we
    /// operate in, for ECC it returns `Curve::bits()`.
    ///
    /// Note: This information is useless and should not be used to
    /// gauge the security of a particular key. This function exists
    /// only because some legacy PGP application like HKP need it.
    ///
    /// Returns `None` for unknown keys and curves.
    pub fn bits(&self) -> Option<usize> {
        use self::PublicKey::*;
        match self {
            &RSA { ref n,.. } => Some(n.bits()),
            &DSA { ref p,.. } => Some(p.bits()),
            &ElGamal { ref p,.. } => Some(p.bits()),
            &EdDSA { ref curve,.. } => curve.bits(),
            &ECDSA { ref curve,.. } => curve.bits(),
            &ECDH { ref curve,.. } => curve.bits(),
            &Unknown { .. } => None,
            __Nonexhaustive => unreachable!(),
        }
    }

    /// Returns, if known, the public-key algorithm for this public
    /// key.
    pub fn algo(&self) -> Option<PublicKeyAlgorithm> {
        use self::PublicKey::*;
        match self {
            RSA { .. } => Some(PublicKeyAlgorithm::RSAEncryptSign),
            DSA { .. } => Some(PublicKeyAlgorithm::DSA),
            ElGamal { .. } => Some(PublicKeyAlgorithm::ElGamalEncrypt),
            EdDSA { .. } => Some(PublicKeyAlgorithm::EdDSA),
            ECDSA { .. } => Some(PublicKeyAlgorithm::ECDSA),
            ECDH { .. } => Some(PublicKeyAlgorithm::ECDH),
            Unknown { .. } => None,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl Hash for PublicKey {
    /// Update the Hash with a hash of the MPIs.
    fn hash(&self, hash: &mut hash::Context) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for PublicKey {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use self::PublicKey::*;
        match g.gen_range(0, 6) {
            0 => RSA {
                e: MPI::arbitrary(g),
                n: MPI::arbitrary(g),
            },

            1 => DSA {
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g),
            },

            2 => ElGamal {
                p: MPI::arbitrary(g),
                g: MPI::arbitrary(g),
                y: MPI::arbitrary(g),
            },

            3 => EdDSA {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
            },

            4 => ECDSA {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
            },

            5 => ECDH {
                curve: Curve::arbitrary(g),
                q: MPI::arbitrary(g),
                hash: HashAlgorithm::arbitrary(g),
                sym: SymmetricAlgorithm::arbitrary(g),
            },

            _ => unreachable!(),
        }
    }
}

/// Holds a secret key.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// packets.
// Deriving Hash here is okay: PartialEq is manually implemented to
// ensure that secrets are compared in constant-time.
#[derive(Clone, Hash)]
pub enum SecretKeyMaterial {
    /// RSA secret key.
    RSA {
        /// Secret exponent, inverse of e in Phi(N).
        d: ProtectedMPI,
        /// Smaller secret prime.
        p: ProtectedMPI,
        /// Larger secret prime.
        q: ProtectedMPI,
        /// Inverse of p mod q.
        u: ProtectedMPI,
    },

    /// NIST DSA secret key.
    DSA {
        /// Secret key log_g(y) in Zp.
        x: ProtectedMPI,
    },

    /// ElGamal secret key.
    ElGamal {
        /// Secret key log_g(y) in Zp.
        x: ProtectedMPI,
    },

    /// DJBs "Twisted" Edwards curve DSA secret key.
    EdDSA {
        /// Secret scalar.
        scalar: ProtectedMPI,
    },

    /// NISTs Elliptic curve DSA secret key.
    ECDSA {
        /// Secret scalar.
        scalar: ProtectedMPI,
    },

    /// Elliptic curve ElGamal secret key.
    ECDH {
        /// Secret scalar.
        scalar: ProtectedMPI,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[ProtectedMPI]>,
        /// Any data that failed to parse.
        rest: Protected,
    },

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl fmt::Debug for SecretKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if cfg!(debug_assertions) {
            match self {
                &SecretKeyMaterial::RSA{ ref d, ref p, ref q, ref u } =>
                    write!(f, "RSA {{ d: {:?}, p: {:?}, q: {:?}, u: {:?} }}", d, p, q, u),
                &SecretKeyMaterial::DSA{ ref x } =>
                    write!(f, "DSA {{ x: {:?} }}", x),
                &SecretKeyMaterial::ElGamal{ ref x } =>
                    write!(f, "ElGamal {{ x: {:?} }}", x),
                &SecretKeyMaterial::EdDSA{ ref scalar } =>
                    write!(f, "EdDSA {{ scalar: {:?} }}", scalar),
                &SecretKeyMaterial::ECDSA{ ref scalar } =>
                    write!(f, "ECDSA {{ scalar: {:?} }}", scalar),
                &SecretKeyMaterial::ECDH{ ref scalar } =>
                    write!(f, "ECDH {{ scalar: {:?} }}", scalar),
                &SecretKeyMaterial::Unknown{ ref mpis, ref rest } =>
                    write!(f, "Unknown {{ mips: {:?}, rest: {:?} }}", mpis, rest),
                SecretKeyMaterial::__Nonexhaustive => unreachable!(),
            }
        } else {
            match self {
                &SecretKeyMaterial::RSA{ .. } =>
                    f.write_str("RSA { <Redacted> }"),
                &SecretKeyMaterial::DSA{ .. } =>
                    f.write_str("DSA { <Redacted> }"),
                &SecretKeyMaterial::ElGamal{ .. } =>
                    f.write_str("ElGamal { <Redacted> }"),
                &SecretKeyMaterial::EdDSA{ .. } =>
                    f.write_str("EdDSA { <Redacted> }"),
                &SecretKeyMaterial::ECDSA{ .. } =>
                    f.write_str("ECDSA { <Redacted> }"),
                &SecretKeyMaterial::ECDH{ .. } =>
                    f.write_str("ECDH { <Redacted> }"),
                &SecretKeyMaterial::Unknown{ .. } =>
                    f.write_str("Unknown { <Redacted> }"),
                SecretKeyMaterial::__Nonexhaustive => unreachable!(),
            }
        }
    }
}

fn secure_mpi_cmp(a: &ProtectedMPI, b: &ProtectedMPI) -> Ordering {
    let ord1 = a.bits().cmp(&b.bits());
    let ord2 = secure_cmp(&a.value, &b.value);

    if ord1 == Ordering::Equal { ord2 } else { ord1 }
}

impl PartialOrd for SecretKeyMaterial {
    fn partial_cmp(&self, other: &SecretKeyMaterial) -> Option<Ordering> {
        use std::iter;

        fn discriminant(sk: &SecretKeyMaterial) -> usize {
            match sk {
                &SecretKeyMaterial::RSA{ .. } => 0,
                &SecretKeyMaterial::DSA{ .. } => 1,
                &SecretKeyMaterial::ElGamal{ .. } => 2,
                &SecretKeyMaterial::EdDSA{ .. } => 3,
                &SecretKeyMaterial::ECDSA{ .. } => 4,
                &SecretKeyMaterial::ECDH{ .. } => 5,
                &SecretKeyMaterial::Unknown{ .. } => 6,
                SecretKeyMaterial::__Nonexhaustive => unreachable!(),
            }
        }

        let ret = match (self, other) {
            (&SecretKeyMaterial::RSA{ d: ref d1, p: ref p1, q: ref q1, u: ref u1 }
            ,&SecretKeyMaterial::RSA{ d: ref d2, p: ref p2, q: ref q2, u: ref u2 }) => {
                let o1 = secure_mpi_cmp(d1, d2);
                let o2 = secure_mpi_cmp(p1, p2);
                let o3 = secure_mpi_cmp(q1, q2);
                let o4 = secure_mpi_cmp(u1, u2);

                if o1 != Ordering::Equal { return Some(o1); }
                if o2 != Ordering::Equal { return Some(o2); }
                if o3 != Ordering::Equal { return Some(o3); }
                o4
            }
            (&SecretKeyMaterial::DSA{ x: ref x1 }
            ,&SecretKeyMaterial::DSA{ x: ref x2 }) => {
                secure_mpi_cmp(x1, x2)
            }
            (&SecretKeyMaterial::ElGamal{ x: ref x1 }
            ,&SecretKeyMaterial::ElGamal{ x: ref x2 }) => {
                secure_mpi_cmp(x1, x2)
            }
            (&SecretKeyMaterial::EdDSA{ scalar: ref scalar1 }
            ,&SecretKeyMaterial::EdDSA{ scalar: ref scalar2 }) => {
                secure_mpi_cmp(scalar1, scalar2)
            }
            (&SecretKeyMaterial::ECDSA{ scalar: ref scalar1 }
            ,&SecretKeyMaterial::ECDSA{ scalar: ref scalar2 }) => {
                secure_mpi_cmp(scalar1, scalar2)
            }
            (&SecretKeyMaterial::ECDH{ scalar: ref scalar1 }
            ,&SecretKeyMaterial::ECDH{ scalar: ref scalar2 }) => {
                secure_mpi_cmp(scalar1, scalar2)
            }
            (&SecretKeyMaterial::Unknown{ mpis: ref mpis1, rest: ref rest1 }
            ,&SecretKeyMaterial::Unknown{ mpis: ref mpis2, rest: ref rest2 }) => {
                let o1 = secure_cmp(rest1, rest2);
                let on = mpis1.iter().zip(mpis2.iter()).map(|(a,b)| {
                    secure_mpi_cmp(a, b)
                }).collect::<Vec<_>>();

                iter::once(&o1)
                    .chain(on.iter())
                    .find(|&&x| x != Ordering::Equal)
                    .cloned()
                    .unwrap_or(Ordering::Equal)
            }

            (a, b) => {
                let ret = discriminant(a).cmp(&discriminant(b));

                assert!(ret != Ordering::Equal);
                ret
            }
        };

        Some(ret)
    }
}

impl Ord for SecretKeyMaterial {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialEq for SecretKeyMaterial {
    fn eq(&self, other: &Self) -> bool { self.cmp(other) == Ordering::Equal }
}

impl Eq for SecretKeyMaterial {}

impl SecretKeyMaterial {
    /// Returns, if known, the public-key algorithm for this secret
    /// key.
    pub fn algo(&self) -> Option<PublicKeyAlgorithm> {
        use self::SecretKeyMaterial::*;
        match self {
            RSA { .. } => Some(PublicKeyAlgorithm::RSAEncryptSign),
            DSA { .. } => Some(PublicKeyAlgorithm::DSA),
            ElGamal { .. } => Some(PublicKeyAlgorithm::ElGamalEncrypt),
            EdDSA { .. } => Some(PublicKeyAlgorithm::EdDSA),
            ECDSA { .. } => Some(PublicKeyAlgorithm::ECDSA),
            ECDH { .. } => Some(PublicKeyAlgorithm::ECDH),
            Unknown { .. } => None,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl Hash for SecretKeyMaterial {
    /// Update the Hash with a hash of the MPIs.
    fn hash(&self, hash: &mut hash::Context) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for SecretKeyMaterial {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 6) {
            0 => SecretKeyMaterial::RSA {
                d: MPI::arbitrary(g).into(),
                p: MPI::arbitrary(g).into(),
                q: MPI::arbitrary(g).into(),
                u: MPI::arbitrary(g).into(),
            },

            1 => SecretKeyMaterial::DSA {
                x: MPI::arbitrary(g).into(),
            },

            2 => SecretKeyMaterial::ElGamal {
                x: MPI::arbitrary(g).into(),
            },

            3 => SecretKeyMaterial::EdDSA {
                scalar: MPI::arbitrary(g).into(),
            },

            4 => SecretKeyMaterial::ECDSA {
                scalar: MPI::arbitrary(g).into(),
            },

            5 => SecretKeyMaterial::ECDH {
                scalar: MPI::arbitrary(g).into(),
            },

            _ => unreachable!(),
        }
    }
}

/// Holds a ciphertext.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// packets.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Ciphertext {
    /// RSA ciphertext.
    RSA {
        ///  m^e mod N.
        c: MPI,
    },

    /// ElGamal ciphertext
    ElGamal {
        /// Ephemeral key.
        e: MPI,
        /// .
        c: MPI,
    },

    /// Elliptic curve ElGamal public key.
    ECDH {
        /// Ephemeral key.
        e: MPI,
        /// Symmetrically encrypted session key.
        key: Box<[u8]>,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Ciphertext {
    /// Returns, if known, the public-key algorithm for this
    /// ciphertext.
    pub fn pk_algo(&self) -> Option<PublicKeyAlgorithm> {
        use self::Ciphertext::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { .. } => Some(PublicKeyAlgorithm::RSAEncryptSign),
            &ElGamal { .. } => Some(PublicKeyAlgorithm::ElGamalEncrypt),
            &ECDH { .. } => Some(PublicKeyAlgorithm::ECDH),
            &Unknown { .. } => None,
            __Nonexhaustive => unreachable!(),
        }
    }
}

impl Hash for Ciphertext {
    /// Update the Hash with a hash of the MPIs.
    fn hash(&self, hash: &mut hash::Context) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for Ciphertext {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 3) {
            0 => Ciphertext::RSA {
                c: MPI::arbitrary(g),
            },

            1 => Ciphertext::ElGamal {
                e: MPI::arbitrary(g),
                c: MPI::arbitrary(g)
            },

            2 => Ciphertext::ECDH {
                e: MPI::arbitrary(g),
                key: <Vec<u8>>::arbitrary(g).into_boxed_slice()
            },
            _ => unreachable!(),
        }
    }
}

/// Holds a signature.
///
/// Provides a typed and structured way of storing multiple MPIs in
/// packets.
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Signature {
    /// RSA signature.
    RSA {
        /// Signature m^d mod N.
        s: MPI,
    },

    /// NIST's DSA signature.
    DSA {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// ElGamal signature.
    ElGamal {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// DJB's "Twisted" Edwards curve DSA signature.
    EdDSA {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// NIST's Elliptic curve DSA signature.
    ECDSA {
        /// `r` value.
        r: MPI,
        /// `s` value.
        s: MPI,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },

    /// This marks this enum as non-exhaustive.  Do not use this
    /// variant.
    #[doc(hidden)] __Nonexhaustive,
}

impl Hash for Signature {
    /// Update the Hash with a hash of the MPIs.
    fn hash(&self, hash: &mut hash::Context) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

#[cfg(any(test, feature = "quickcheck"))]
impl Arbitrary for Signature {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 4) {
            0 => Signature::RSA  {
                s: MPI::arbitrary(g),
            },

            1 => Signature::DSA {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g),
            },

            2 => Signature::EdDSA  {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g),
            },

            3 => Signature::ECDSA  {
                r: MPI::arbitrary(g),
                s: MPI::arbitrary(g),
            },

            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;

    quickcheck! {
        fn mpi_roundtrip(mpi: MPI) -> bool {
            let mut buf = Vec::new();
            mpi.serialize(&mut buf).unwrap();
            MPI::from_bytes(&buf).unwrap() == mpi
        }
    }

    quickcheck! {
        fn pk_roundtrip(pk: PublicKey) -> bool {
            use std::io::Cursor;
            use crate::PublicKeyAlgorithm::*;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            pk.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let pk_ = match &pk {
                PublicKey::RSA { .. } =>
                    PublicKey::parse(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                PublicKey::DSA { .. } =>
                    PublicKey::parse(
                        DSA, cur.into_inner()).unwrap(),
                PublicKey::ElGamal { .. } =>
                    PublicKey::parse(
                        ElGamalEncrypt, cur.into_inner()).unwrap(),
                PublicKey::EdDSA { .. } =>
                    PublicKey::parse(
                        EdDSA, cur.into_inner()).unwrap(),
                PublicKey::ECDSA { .. } =>
                    PublicKey::parse(
                        ECDSA, cur.into_inner()).unwrap(),
                PublicKey::ECDH { .. } =>
                    PublicKey::parse(
                        ECDH, cur.into_inner()).unwrap(),

                PublicKey::Unknown { .. } => unreachable!(),
                PublicKey::__Nonexhaustive => unreachable!(),
            };

            pk == pk_
        }
    }

    #[test]
    fn pk_bits() {
        for (name, key_no, bits) in &[
            ("testy.pgp", 0, 2048),
            ("testy-new.pgp", 1, 256),
            ("dennis-simon-anton.pgp", 0, 2048),
            ("dsa2048-elgamal3072.pgp", 1, 3072),
            ("emmelie-dorothea-dina-samantha-awina-ed25519.pgp", 0, 256),
            ("erika-corinna-daniela-simone-antonia-nistp256.pgp", 0, 256),
            ("erika-corinna-daniela-simone-antonia-nistp384.pgp", 0, 384),
            ("erika-corinna-daniela-simone-antonia-nistp521.pgp", 0, 521),
        ] {
            let cert = crate::Cert::from_bytes(crate::tests::key(name)).unwrap();
            let ka = cert.keys().nth(*key_no).unwrap();
            assert_eq!(ka.key().mpis().bits().unwrap(), *bits,
                       "Cert {}, key no {}", name, *key_no);
        }
    }

    quickcheck! {
        fn sk_roundtrip(sk: SecretKeyMaterial) -> bool {
            use std::io::Cursor;
            use crate::PublicKeyAlgorithm::*;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            sk.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let sk_ = match &sk {
                SecretKeyMaterial::RSA { .. } =>
                    SecretKeyMaterial::parse(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                SecretKeyMaterial::DSA { .. } =>
                    SecretKeyMaterial::parse(
                        DSA, cur.into_inner()).unwrap(),
                SecretKeyMaterial::EdDSA { .. } =>
                    SecretKeyMaterial::parse(
                        EdDSA, cur.into_inner()).unwrap(),
                SecretKeyMaterial::ECDSA { .. } =>
                    SecretKeyMaterial::parse(
                        ECDSA, cur.into_inner()).unwrap(),
                SecretKeyMaterial::ECDH { .. } =>
                    SecretKeyMaterial::parse(
                        ECDH, cur.into_inner()).unwrap(),
                SecretKeyMaterial::ElGamal { .. } =>
                    SecretKeyMaterial::parse(
                        ElGamalEncrypt, cur.into_inner()).unwrap(),

                SecretKeyMaterial::Unknown { .. } => unreachable!(),
                SecretKeyMaterial::__Nonexhaustive => unreachable!(),
            };

            sk == sk_
        }
    }

    quickcheck! {
        fn ct_roundtrip(ct: Ciphertext) -> bool {
            use std::io::Cursor;
            use crate::PublicKeyAlgorithm::*;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            ct.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let ct_ = match &ct {
                Ciphertext::RSA { .. } =>
                    Ciphertext::parse(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                Ciphertext::ElGamal { .. } =>
                    Ciphertext::parse(
                        ElGamalEncrypt, cur.into_inner()).unwrap(),
                Ciphertext::ECDH { .. } =>
                    Ciphertext::parse(
                        ECDH, cur.into_inner()).unwrap(),

                Ciphertext::Unknown { .. } => unreachable!(),
                Ciphertext::__Nonexhaustive => unreachable!(),
            };

            ct == ct_
        }
    }

    quickcheck! {
        fn signature_roundtrip(sig: Signature) -> bool {
            use std::io::Cursor;
            use crate::PublicKeyAlgorithm::*;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            sig.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let sig_ = match &sig {
                Signature::RSA { .. } =>
                    Signature::parse(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                Signature::DSA { .. } =>
                    Signature::parse(
                        DSA, cur.into_inner()).unwrap(),
                Signature::ElGamal { .. } =>
                    Signature::parse(
                        ElGamalEncryptSign, cur.into_inner()).unwrap(),
                Signature::EdDSA { .. } =>
                    Signature::parse(
                        EdDSA, cur.into_inner()).unwrap(),
                Signature::ECDSA { .. } =>
                    Signature::parse(
                        ECDSA, cur.into_inner()).unwrap(),

                Signature::Unknown { .. } => unreachable!(),
                Signature::__Nonexhaustive => unreachable!(),
            };

            sig == sig_
        }
    }
}
