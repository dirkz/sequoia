//! Functions for parsing MPIs.

use std::io::Read;
use crate::{
    Result,
    Error,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
    HashAlgorithm,
};
use crate::constants::Curve;
use crate::crypto::mpis::{self, MPI};
use crate::parse::{
    PacketHeaderParser,
    Cookie,
};

impl mpis::PublicKey {
    /// Parses a set of OpenPGP MPIs representing a public key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse<T: AsRef<[u8]>>(
        algo: PublicKeyAlgorithm, buf: T)
        -> Result<Self>
    {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = buffered_reader::Generic::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::_parse(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a public key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn _parse<'a>(algo: PublicKeyAlgorithm,
                            php: &mut PacketHeaderParser<'a>)
        -> Result<Self>
    {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match algo {
            RSAEncryptSign | RSAEncrypt | RSASign => {
                let n = MPI::parse("rsa_public_n_len", "rsa_public_n", php)?;
                let e = MPI::parse("rsa_public_e_len", "rsa_public_e", php)?;

                Ok(mpis::PublicKey::RSA { e: e, n: n })
            }

            DSA => {
                let p = MPI::parse("dsa_public_p_len", "dsa_public_p", php)?;
                let q = MPI::parse("dsa_public_q_len", "dsa_public_q", php)?;
                let g = MPI::parse("dsa_public_g_len", "dsa_public_g", php)?;
                let y = MPI::parse("dsa_public_y_len", "dsa_public_y", php)?;

                Ok(mpis::PublicKey::DSA {
                    p: p,
                    q: q,
                    g: g,
                    y: y,
                })
            }

            ElgamalEncrypt | ElgamalEncryptSign => {
                let p = MPI::parse("elgamal_public_p_len", "elgamal_public_p",
                                   php)?;
                let g = MPI::parse("elgamal_public_g_len", "elgamal_public_g",
                                   php)?;
                let y = MPI::parse("elgamal_public_y_len", "elgamal_public_y",
                                   php)?;

                Ok(mpis::PublicKey::Elgamal {
                    p: p,
                    g: g,
                    y: y,
                })
            }

            EdDSA => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("eddsa_public_len", "eddsa_public", php)?;

                Ok(mpis::PublicKey::EdDSA {
                    curve: Curve::from_oid(&curve),
                    q: q
                })
            }

            ECDSA => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("ecdsa_public_len", "ecdsa_public", php)?;

                Ok(mpis::PublicKey::ECDSA {
                    curve: Curve::from_oid(&curve),
                    q: q
                })
            }

            ECDH => {
                let curve_len = php.parse_u8("curve_len")? as usize;
                let curve = php.parse_bytes("curve", curve_len)?;
                let q = MPI::parse("ecdh_public_len", "ecdh_public", php)?;
                let kdf_len = php.parse_u8("kdf_len")?;

                if kdf_len != 3 {
                    return Err(Error::MalformedPacket(
                            "wrong kdf length".into()).into());
                }

                let _reserved = php.parse_u8("kdf_reserved")?;
                let hash: HashAlgorithm = php.parse_u8("kdf_hash")?.into();
                let sym: SymmetricAlgorithm = php.parse_u8("kek_symm")?.into();

                Ok(mpis::PublicKey::ECDH {
                    curve: Curve::from_oid(&curve),
                    q: q,
                    hash: hash,
                    sym: sym
                })
            }

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = MPI::parse("unknown_parameter_len",
                                               "unknown_parameter", php) {
                    mpis.push(mpi);
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpis::PublicKey::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into_boxed_slice(),
                })
            }
        }
    }
}

impl mpis::SecretKeyMaterial {
    /// Parses secret key MPIs for `algo` plus their SHA1 checksum. Fails if the
    /// checksum is wrong.
    pub fn parse_chksumd<T: Read>(algo: PublicKeyAlgorithm, cur: T)
                                  -> Result<Self> {
        use std::io::Cursor;
        use crate::serialize::Serialize;

        // read mpis
        let bio = buffered_reader::Generic::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        let mpis = Self::_parse(algo, &mut php)?;

        // read expected sha1 hash of the mpis
        let their_chksum = php.parse_bytes("checksum", 20)?;
        let mut cur = Cursor::new(vec![]);

        // compute sha1 hash
        mpis.serialize(&mut cur)?;
        let buf = cur.into_inner();
        let mut hsh = HashAlgorithm::SHA1.context().unwrap();

        hsh.update(&buf);
        let mut our_chksum = [0u8; 20];
        hsh.digest(&mut our_chksum);

        if our_chksum != their_chksum[..] {
            Err(Error::MalformedMPI("checksum wrong".to_string()).into())
        } else {
            Ok(mpis)
        }
    }

    /// Parses a set of OpenPGP MPIs representing a secret key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse<T: AsRef<[u8]>>(algo: PublicKeyAlgorithm, buf: T)
                                 -> Result<Self>
    {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = buffered_reader::Generic::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::_parse(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a secret key.
    ///
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn _parse<'a>(algo: PublicKeyAlgorithm,
                             php: &mut PacketHeaderParser<'a>)
                             -> Result<Self>
    {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match algo {
            RSAEncryptSign | RSAEncrypt | RSASign => {
                let d = MPI::parse("rsa_secret_d_len", "rsa_secret_d", php)?;
                let p = MPI::parse("rsa_secret_p_len", "rsa_secret_p", php)?;
                let q = MPI::parse("rsa_secret_q_len", "rsa_secret_q", php)?;
                let u = MPI::parse("rsa_secret_u_len", "rsa_secret_u", php)?;

                Ok(mpis::SecretKeyMaterial::RSA {
                    d: d.into(),
                    p: p.into(),
                    q: q.into(),
                    u: u.into(),
                })
            }

            DSA => {
                let x = MPI::parse("dsa_secret_len", "dsa_secret", php)?;

                Ok(mpis::SecretKeyMaterial::DSA {
                    x: x.into(),
                })
            }

            ElgamalEncrypt | ElgamalEncryptSign => {
                let x = MPI::parse("elgamal_secret_len", "elgamal_secret",
                                   php)?;

                Ok(mpis::SecretKeyMaterial::Elgamal {
                    x: x.into(),
                })
            }

            EdDSA => {
                Ok(mpis::SecretKeyMaterial::EdDSA {
                    scalar: MPI::parse("eddsa_secret_len", "eddsa_secret", php)?
                                .into()
                })
            }

            ECDSA => {
                Ok(mpis::SecretKeyMaterial::ECDSA {
                    scalar: MPI::parse("ecdsa_secret_len", "ecdsa_secret", php)?
                                .into()
                })
            }

            ECDH => {
                Ok(mpis::SecretKeyMaterial::ECDH {
                    scalar: MPI::parse("ecdh_secret_len", "ecdh_secret", php)?
                                .into()
                })
            }

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = MPI::parse("unknown_parameter_len",
                                               "unknown_parameter", php) {
                    mpis.push(mpi.into());
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpis::SecretKeyMaterial::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into(),
                })
            }
        }
    }
}

impl mpis::Ciphertext {
    /// Parses a set of OpenPGP MPIs representing a ciphertext.
    ///
    /// Expects MPIs for a public key algorithm `algo`s ciphertext.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse<T: AsRef<[u8]>>(algo: PublicKeyAlgorithm, buf: T)
                                 -> Result<Self> {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = buffered_reader::Generic::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::_parse(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a ciphertext.
    ///
    /// Expects MPIs for a public key algorithm `algo`s ciphertext.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn _parse<'a>(algo: PublicKeyAlgorithm,
                             php: &mut PacketHeaderParser<'a>)
                             -> Result<Self> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match algo {
            RSAEncryptSign | RSAEncrypt => {
                let c = MPI::parse("rsa_ciphertext_len", "rsa_ciphertext",
                                   php)?;

                Ok(mpis::Ciphertext::RSA {
                    c: c,
                })
            }

            ElgamalEncrypt | ElgamalEncryptSign => {
                let e = MPI::parse("elgamal_e_len", "elgamal_e", php)?;
                let c = MPI::parse("elgamal_c_len", "elgamal_c", php)?;

                Ok(mpis::Ciphertext::Elgamal {
                    e: e,
                    c: c,
                })
            }

            ECDH => {
                let e = MPI::parse("ecdh_e_len", "ecdh_e", php)?;
                let key_len = php.parse_u8("ecdh_esk_len")? as usize;
                let key = Vec::from(&php.parse_bytes("ecdh_esk", key_len)?
                                    [..key_len]);

                Ok(mpis::Ciphertext::ECDH {
                    e: e, key: key.into_boxed_slice()
                })
            }

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = MPI::parse("unknown_parameter_len",
                                               "unknown_parameter", php) {
                    mpis.push(mpi);
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpis::Ciphertext::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into_boxed_slice(),
                })
            }

            RSASign | DSA | EdDSA | ECDSA => Err(Error::InvalidArgument(
                format!("not an encryption algorithm: {:?}", algo)).into()),
        }
    }
}

impl mpis::Signature {
    /// Parses a set of OpenPGP MPIs representing a signature.
    ///
    /// Expects MPIs for a public key algorithm `algo`s signature.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub fn parse<T: AsRef<[u8]>>(algo: PublicKeyAlgorithm, buf: T)
                                 -> Result<Self> {
        use std::io::Cursor;

        let cur = Cursor::new(buf);
        let bio = buffered_reader::Generic::with_cookie(
            cur, None, Cookie::default());
        let mut php = PacketHeaderParser::new_naked(Box::new(bio));
        Self::_parse(algo, &mut php)
    }

    /// Parses a set of OpenPGP MPIs representing a signature.
    ///
    /// Expects MPIs for a public key algorithm `algo`s signature.
    /// See [Section 3.2 of RFC 4880] for details.
    ///
    ///   [Section 3.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-3.2
    pub(crate) fn _parse<'a>(algo: PublicKeyAlgorithm,
                             php: &mut PacketHeaderParser<'a>)
                             -> Result<Self> {
        use crate::PublicKeyAlgorithm::*;

        #[allow(deprecated)]
        match algo {
            RSAEncryptSign | RSASign => {
                let s = MPI::parse("rsa_signature_len", "rsa_signature", php)?;

                Ok(mpis::Signature::RSA {
                    s: s,
                })
            }

            DSA => {
                let r = MPI::parse("dsa_signature_r_len", "dsa_signature_r",
                                   php)?;
                let s = MPI::parse("dsa_signature_s_len", "dsa_signature_s",
                                   php)?;

                Ok(mpis::Signature::DSA {
                    r: r,
                    s: s,
                })
            }

            ElgamalEncryptSign => {
                let r = MPI::parse("elgamal_signature_r_len",
                                   "elgamal_signature_r", php)?;
                let s = MPI::parse("elgamal_signature_s_len",
                                   "elgamal_signature_s", php)?;

                Ok(mpis::Signature::Elgamal {
                    r: r,
                    s: s,
                })
            }

            EdDSA => {
                let r = MPI::parse("eddsa_signature_r_len", "eddsa_signature_r",
                                   php)?;
                let s = MPI::parse("eddsa_signature_s_len", "eddsa_signature_s",
                                   php)?;

                Ok(mpis::Signature::EdDSA {
                    r: r,
                    s: s,
                })
            }

            ECDSA => {
                let r = MPI::parse("ecdsa_signature_r_len", "ecdsa_signature_r",
                                   php)?;
                let s = MPI::parse("ecdsa_signature_s_len", "ecdsa_signature_s",
                                   php)?;

                Ok(mpis::Signature::ECDSA {
                    r: r,
                    s: s,
                })
            }

            Unknown(_) | Private(_) => {
                let mut mpis = Vec::new();
                while let Ok(mpi) = MPI::parse("unknown_parameter_len",
                                               "unknown_parameter", php) {
                    mpis.push(mpi);
                }
                let rest = php.parse_bytes_eof("rest")?;

                Ok(mpis::Signature::Unknown {
                    mpis: mpis.into_boxed_slice(),
                    rest: rest.into_boxed_slice(),
                })
            }

            RSAEncrypt | ElgamalEncrypt | ECDH => Err(Error::InvalidArgument(
                format!("not a signature algorithm: {:?}", algo)).into()),
        }
    }
}

#[test]
fn mpis_parse_test() {
    use super::Parse;
    use crate::PublicKeyAlgorithm::*;

    // Dummy RSA public key.
    {
        let buf = b"\x00\x01\x01\x00\x02\x02".to_vec();
        let mpis = mpis::PublicKey::parse(RSAEncryptSign, buf).unwrap();

        //assert_eq!(mpis.serialized_len(), 6);
        match &mpis {
            &mpis::PublicKey::RSA{ ref n, ref e } => {
                assert_eq!(n.bits(), 1);
                assert_eq!(n.value()[0], 1);
                assert_eq!(n.value().len(), 1);
                assert_eq!(e.bits(), 2);
                assert_eq!(e.value()[0], 2);
                assert_eq!(e.value().len(), 1);
            }

            _ => assert!(false),
        }
    }

    // The number 2.
    {
        let buf = b"\x00\x02\x02".to_vec();
        let mpis = mpis::Ciphertext::parse(RSAEncryptSign, buf).unwrap();

        assert_eq!(mpis.serialized_len(), 3);
    }

    // The number 511.
    let mpi = MPI::from_bytes(b"\x00\x09\x01\xff").unwrap();
    assert_eq!(mpi.value().len(), 2);
    assert_eq!(mpi.bits(), 9);
    assert_eq!(mpi.value()[0], 1);
    assert_eq!(mpi.value()[1], 0xff);

    // The number 1, incorrectly encoded (the length should be 1,
    // not 2).
    assert!(MPI::from_bytes(b"\x00\x02\x01").is_err());
}
