//! Multi Precision Integers.

use std::fmt;
use std::io::Write;
use quickcheck::{Arbitrary, Gen};
use rand::Rng;

use constants::{
    SymmetricAlgorithm,
    HashAlgorithm,
    Curve,
};
use serialize::Serialize;

use nettle::Hash;

/// Holds a single MPI.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MPI {
    /// Length of the integer in bits.
    pub bits: usize,
    /// Integer value as big-endian.
    pub value: Box<[u8]>,
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
            bits: value.len() * 8 - leading_zeros % 8,
            value: value,
        }
    }

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash>(&self, hash: &mut H) {
        let len = &[(self.bits >> 8) as u8 & 0xFF, self.bits as u8];

        hash.update(len);
        hash.update(&self.value);
    }

    fn secure_memzero(&mut self) {
        unsafe {
            ::memsec::memzero(self.value.as_mut_ptr(), self.value.len());
        }
    }
}

impl fmt::Debug for MPI {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!(
                "{} bits: {}", self.bits, ::conversions::to_hex(&*self.value, true)))
    }
}

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

    /// Elgamal public key.
    Elgamal {
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

    /// Elliptic curve Elgamal public key.
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
}

impl PublicKey {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::PublicKey::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref e, ref n } =>
                2 + e.value.len() + 2 + n.value.len(),

            &DSA { ref p, ref q, ref g, ref y } =>
                2 + p.value.len() + 2 + q.value.len() +
                2 + g.value.len() + 2 + y.value.len(),

            &Elgamal { ref p, ref g, ref y } =>
                2 + p.value.len() +
                2 + g.value.len() + 2 + y.value.len(),

            &EdDSA { ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len(),

            &ECDSA { ref curve, ref q } =>
                2 + q.value.len() +
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len(),

            &ECDH { ref curve, ref q, .. } =>
                // one length octet plus the ASN.1 OID
                1 + curve.oid().len() +
                2 + q.value.len() +
                // one octet length, one reserved and two algorithm identifier.
                4,

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

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

            2 => Elgamal {
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
#[derive(Clone, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum SecretKey {
    /// RSA secret key.
    RSA {
        /// Secret exponent, inverse of e in Phi(N).
        d: MPI,
        /// Larger secret prime.
        p: MPI,
        /// Smaller secret prime.
        q: MPI,
        /// Inverse of p mod q.
        u: MPI,
    },

    /// NIST DSA secret key.
    DSA {
        /// Secret key log_g(y) in Zp.
        x: MPI,
    },

    /// Elgamal secret key.
    Elgamal {
        /// Secret key log_g(y) in Zp.
        x: MPI,
    },

    /// DJBs "Twisted" Edwards curve DSA secret key.
    EdDSA {
        /// Secret scalar.
        scalar: MPI,
    },

    /// NISTs Elliptic curve DSA secret key.
    ECDSA {
        /// Secret scalar.
        scalar: MPI,
    },

    /// Elliptic curve Elgamal secret key.
    ECDH {
        /// Secret scalar.
        scalar: MPI,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        use self::SecretKey::*;
        match self {
            RSA { ref mut d, ref mut p, ref mut q, ref mut u } => {
                d.secure_memzero();
                p.secure_memzero();
                q.secure_memzero();
                u.secure_memzero();
            },
            DSA { ref mut x } =>
                x.secure_memzero(),
            Elgamal { ref mut x } =>
                x.secure_memzero(),
            EdDSA { ref mut scalar } =>
                scalar.secure_memzero(),
            ECDSA { ref mut scalar } =>
                scalar.secure_memzero(),
            ECDH { ref mut scalar } =>
                scalar.secure_memzero(),
            Unknown { ref mut mpis, ref mut rest } => {
                mpis.iter_mut().for_each(|m| m.secure_memzero());
                unsafe {
                    ::memsec::memzero(rest.as_mut_ptr(), rest.len());
                }
            },
        }
    }
}

impl SecretKey {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::SecretKey::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref d, ref p, ref q, ref u } =>
                2 + d.value.len() + 2 + q.value.len() +
                2 + p.value.len() + 2 + u.value.len(),

            &DSA { ref x } => 2 + x.value.len(),

            &Elgamal { ref x } => 2 + x.value.len(),

            &EdDSA { ref scalar } => 2 + scalar.value.len(),

            &ECDSA { ref scalar } => 2 + scalar.value.len(),

            &ECDH { ref scalar } => 2 + scalar.value.len(),

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

impl Arbitrary for SecretKey {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 6) {
            0 => SecretKey::RSA {
                d: MPI::arbitrary(g),
                p: MPI::arbitrary(g),
                q: MPI::arbitrary(g),
                u: MPI::arbitrary(g),
            },

            1 => SecretKey::DSA {
                x: MPI::arbitrary(g),
            },

            2 => SecretKey::Elgamal {
                x: MPI::arbitrary(g),
            },

            3 => SecretKey::EdDSA {
                scalar: MPI::arbitrary(g),
            },

            4 => SecretKey::ECDSA {
                scalar: MPI::arbitrary(g),
            },

            5 => SecretKey::ECDH {
                scalar: MPI::arbitrary(g),
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

    /// Elgamal ciphertext
    Elgamal {
        /// Ephemeral key.
        e: MPI,
        /// .
        c: MPI,
    },

    /// Elliptic curve Elgamal public key.
    ECDH {
        /// Ephemeral key.
        e: MPI,
        /// Symmetrically encrypted poition.
        key: Box<[u8]>,
    },

    /// Unknown number of MPIs for an unknown algorithm.
    Unknown {
        /// The successfully parsed MPIs.
        mpis: Box<[MPI]>,
        /// Any data that failed to parse.
        rest: Box<[u8]>,
    },
}

impl Ciphertext {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::Ciphertext::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref c } =>
                2 + c.value.len(),

            &Elgamal { ref e, ref c } =>
                2 + e.value.len() + 2 + c.value.len(),

            &ECDH { ref e, ref key } =>
                2 + e.value.len() +
                // one length octet plus ephemeral key
                1 + key.len(),

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

impl Arbitrary for Ciphertext {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        match g.gen_range(0, 3) {
            0 => Ciphertext::RSA {
                c: MPI::arbitrary(g),
            },

            1 => Ciphertext::Elgamal {
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

    /// Elgamal signature.
    Elgamal {
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
}

impl Signature {
    /// Number of octets all MPIs of this instance occupy when serialized.
    pub fn serialized_len(&self) -> usize {
        use self::Signature::*;

        // Fields are mostly MPIs that consist of two octets length
        // plus the big endian value itself. All other field types are
        // commented.
        match self {
            &RSA { ref s } =>
                2 + s.value.len(),

            &DSA { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &Elgamal { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &EdDSA { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &ECDSA { ref r, ref s } =>
                2 + r.value.len() + 2 + s.value.len(),

            &Unknown { ref mpis, ref rest } =>
                mpis.iter().map(|m| 2 + m.value.len()).sum::<usize>()
                + rest.len(),
        }
    }

    /// Update the Hash with a hash of the MPIs.
    pub fn hash<H: Hash + Write>(&self, hash: &mut H) {
        self.serialize(hash).expect("hashing does not fail")
    }
}

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

    quickcheck! {
        fn mpi_roundtrip(mpi: MPI) -> bool {
            use std::io::Cursor;
            use serialize::Serialize;

            let mut buf = Vec::new();
            mpi.serialize(&mut buf).unwrap();
            MPI::parse_naked(Cursor::new(buf)).unwrap() == mpi
        }
    }

    quickcheck! {
        fn pk_roundtrip(pk: PublicKey) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            pk.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let pk_ = match &pk {
                PublicKey::RSA { .. } =>
                    PublicKey::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                PublicKey::DSA { .. } =>
                    PublicKey::parse_naked(
                        DSA, cur.into_inner()).unwrap(),
                PublicKey::Elgamal { .. } =>
                    PublicKey::parse_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),
                PublicKey::EdDSA { .. } =>
                    PublicKey::parse_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                PublicKey::ECDSA { .. } =>
                    PublicKey::parse_naked(
                        ECDSA, cur.into_inner()).unwrap(),
                PublicKey::ECDH { .. } =>
                    PublicKey::parse_naked(
                        ECDH, cur.into_inner()).unwrap(),

                PublicKey::Unknown { .. } => unreachable!(),
            };

            pk == pk_
        }
    }

    quickcheck! {
        fn sk_roundtrip(sk: SecretKey) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            sk.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let sk_ = match &sk {
                SecretKey::RSA { .. } =>
                    SecretKey::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                SecretKey::DSA { .. } =>
                    SecretKey::parse_naked(
                        DSA, cur.into_inner()).unwrap(),
                SecretKey::EdDSA { .. } =>
                    SecretKey::parse_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                SecretKey::ECDSA { .. } =>
                    SecretKey::parse_naked(
                        ECDSA, cur.into_inner()).unwrap(),
                SecretKey::ECDH { .. } =>
                    SecretKey::parse_naked(
                        ECDH, cur.into_inner()).unwrap(),
                SecretKey::Elgamal { .. } =>
                    SecretKey::parse_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),

                SecretKey::Unknown { .. } => unreachable!(),
            };

            sk == sk_
        }
    }

    quickcheck! {
        fn ct_roundtrip(ct: Ciphertext) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            ct.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let ct_ = match &ct {
                Ciphertext::RSA { .. } =>
                    Ciphertext::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                Ciphertext::Elgamal { .. } =>
                    Ciphertext::parse_naked(
                        ElgamalEncrypt, cur.into_inner()).unwrap(),
                Ciphertext::ECDH { .. } =>
                    Ciphertext::parse_naked(
                        ECDH, cur.into_inner()).unwrap(),

                Ciphertext::Unknown { .. } => unreachable!(),
            };

            ct == ct_
        }
    }

    quickcheck! {
        fn signature_roundtrip(sig: Signature) -> bool {
            use std::io::Cursor;
            use PublicKeyAlgorithm::*;
            use serialize::Serialize;

            let buf = Vec::<u8>::default();
            let mut cur = Cursor::new(buf);

            sig.serialize(&mut cur).unwrap();

            #[allow(deprecated)]
            let sig_ = match &sig {
                Signature::RSA { .. } =>
                    Signature::parse_naked(
                        RSAEncryptSign, cur.into_inner()).unwrap(),
                Signature::DSA { .. } =>
                    Signature::parse_naked(
                        DSA, cur.into_inner()).unwrap(),
                Signature::Elgamal { .. } =>
                    Signature::parse_naked(
                        ElgamalEncryptSign, cur.into_inner()).unwrap(),
                Signature::EdDSA { .. } =>
                    Signature::parse_naked(
                        EdDSA, cur.into_inner()).unwrap(),
                Signature::ECDSA { .. } =>
                    Signature::parse_naked(
                        ECDSA, cur.into_inner()).unwrap(),

                Signature::Unknown { .. } => unreachable!(),
            };

            sig == sig_
        }
    }
}
