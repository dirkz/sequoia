//! PublicKey-Encrypted Session Key packets.
//!
//! The session key is needed to decrypt the actual ciphertext.  See
//! [Section 5.1 of RFC 4880] for details.
//!
//!   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Error;
use crate::packet::key;
use crate::packet::Key;
use crate::KeyID;
use crate::crypto::Decryptor;
use crate::crypto::mpi::Ciphertext;
use crate::Packet;
use crate::PublicKeyAlgorithm;
use crate::Result;
use crate::SymmetricAlgorithm;
use crate::crypto::SessionKey;
use crate::packet;

mod v6;
pub use v6::PKESK6;

/// Holds an asymmetrically encrypted session key.
///
/// The session key is needed to decrypt the actual ciphertext.  See
/// [Section 5.1 of RFC 4880] for details.
///
///   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PKESK3 {
    /// CTB header fields.
    pub(crate) common: packet::Common,
    /// Key ID of the key this is encrypted to.
    recipient: KeyID,
    /// Public key algorithm used to encrypt the session key.
    pk_algo: PublicKeyAlgorithm,
    /// The encrypted session key.
    esk: Ciphertext,
}

assert_send_and_sync!(PKESK3);

impl PKESK3 {
    /// Creates a new PKESK3 packet.
    pub fn new(recipient: KeyID, pk_algo: PublicKeyAlgorithm,
               encrypted_session_key: Ciphertext)
               -> Result<PKESK3> {
        Ok(PKESK3 {
            common: Default::default(),
            recipient,
            pk_algo,
            esk: encrypted_session_key,
        })
    }

    /// Creates a new PKESK3 packet for the given recipient.
    ///
    /// The given symmetric algorithm must match the algorithm that is
    /// used to encrypt the payload.
    pub fn for_recipient<P, R>(algo: SymmetricAlgorithm,
                               session_key: &SessionKey,
                               recipient: &Key<P, R>)
        -> Result<PKESK3>
        where P: key::KeyParts,
              R: key::KeyRole,
    {
        Ok(PKESK3{
            common: Default::default(),
            recipient: recipient.keyid(),
            pk_algo: recipient.pk_algo(),
            esk: packet::PKESK::encrypt_common(
                Some(algo), session_key,
                recipient.parts_as_unspecified().role_as_unspecified())?,
        })
    }

    /// Gets the recipient.
    pub fn recipient(&self) -> &KeyID {
        &self.recipient
    }

    /// Sets the recipient.
    pub fn set_recipient(&mut self, recipient: KeyID) -> KeyID {
        ::std::mem::replace(&mut self.recipient, recipient)
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, algo: PublicKeyAlgorithm) -> PublicKeyAlgorithm {
        ::std::mem::replace(&mut self.pk_algo, algo)
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> &Ciphertext {
        &self.esk
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Ciphertext) -> Ciphertext {
        ::std::mem::replace(&mut self.esk, esk)
    }

    /// Decrypts the encrypted session key.
    ///
    /// If the symmetric algorithm used to encrypt the message is
    /// known in advance, it should be given as argument.  This allows
    /// us to reduce the side-channel leakage of the decryption
    /// operation for RSA.
    ///
    /// Returns the session key and symmetric algorithm used to
    /// encrypt the following payload.
    ///
    /// Returns `None` on errors.  This prevents leaking information
    /// to an attacker, which could lead to compromise of secret key
    /// material with certain algorithms (RSA).  See [Section 14 of
    /// RFC 4880].
    ///
    ///   [Section 14 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-14
    pub fn decrypt(&self, decryptor: &mut dyn Decryptor,
                   sym_algo_hint: Option<SymmetricAlgorithm>)
        -> Option<(SymmetricAlgorithm, SessionKey)>
    {
        self.decrypt_insecure(decryptor, sym_algo_hint).ok()
    }

    fn decrypt_insecure(&self, decryptor: &mut dyn Decryptor,
                        sym_algo_hint: Option<SymmetricAlgorithm>)
        -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        packet::PKESK::decrypt_common(&self.esk, decryptor, sym_algo_hint, true)
    }
}

/// Returns whether the given `algo` requires checksumming, and
/// whether the cipher octet is prepended to the encrypted session
/// key, or it is prepended to the plain session key and then
/// encrypted.
fn classify_pk_algo(algo: PublicKeyAlgorithm, seipdv1: bool)
                    -> Result<(bool, bool, bool)>
{
    #[allow(deprecated)]
    match algo {
        // Classical encryption: plaintext includes the cipher
        // octet and is checksummed.
        PublicKeyAlgorithm::RSAEncryptSign |
        PublicKeyAlgorithm::RSAEncrypt |
        PublicKeyAlgorithm::ElGamalEncrypt |
        PublicKeyAlgorithm::ElGamalEncryptSign |
        PublicKeyAlgorithm::ECDH =>
            Ok((true, false, seipdv1)),

        // Corner case: for X25519 and X448 we have to prepend
        // the cipher octet to the ciphertext instead of
        // encrypting it.
        PublicKeyAlgorithm::X25519 |
        PublicKeyAlgorithm::X448 =>
            Ok((false, seipdv1, false)),

        a @ PublicKeyAlgorithm::RSASign |
        a @ PublicKeyAlgorithm::DSA |
        a @ PublicKeyAlgorithm::ECDSA |
        a @ PublicKeyAlgorithm::EdDSA |
        a @ PublicKeyAlgorithm::Ed25519 |
        a @ PublicKeyAlgorithm::Ed448 |
        a @ PublicKeyAlgorithm::Private(_) |
        a @ PublicKeyAlgorithm::Unknown(_) =>
            Err(Error::UnsupportedPublicKeyAlgorithm(a).into()),
    }
}


impl packet::PKESK {
    fn encrypt_common(algo: Option<SymmetricAlgorithm>,
                      session_key: &SessionKey,
                      recipient: &Key<key::UnspecifiedParts,
                                      key::UnspecifiedRole>)
                      -> Result<Ciphertext>
    {
        let (checksummed, unencrypted_cipher_octet, encrypted_cipher_octet) =
            classify_pk_algo(recipient.pk_algo(), algo.is_some())?;

        // We may need to prefix the cipher specifier to the session
        // key, and we may add a two-octet checksum.
        let mut psk = Vec::with_capacity(
            encrypted_cipher_octet.then(|| 1).unwrap_or(0)
                + session_key.len()
                + checksummed.then(|| 2).unwrap_or(0));
        if let Some(algo) = algo {
            if encrypted_cipher_octet {
                psk.push(algo.into());
            }
        }
        psk.extend_from_slice(session_key);

        if checksummed {
            // Compute the sum modulo 65536, i.e. as u16.
            let checksum = session_key
                .iter()
                .cloned()
                .map(u16::from)
                .fold(0u16, u16::wrapping_add);

            psk.extend_from_slice(&checksum.to_be_bytes());
        }

        // Make sure it is cleaned up when dropped.
        let psk: SessionKey = psk.into();
        let mut esk = recipient.encrypt(&psk)?;

        if let Some(algo) = algo {
            if unencrypted_cipher_octet {
                match esk {
                    Ciphertext::X25519 { ref mut key, .. } |
                    Ciphertext::X448 { ref mut key, .. } => {
                        let mut new_key = Vec::with_capacity(1 + key.len());
                        new_key.push(algo.into());
                        new_key.extend_from_slice(key);
                        *key = new_key.into();
                    },
                    _ => unreachable!("We only prepend the cipher octet \
                                       for X25519 and X448"),
                };
            }
        }

        Ok(esk)
    }

    fn decrypt_common(ciphertext: &Ciphertext,
                      decryptor: &mut dyn Decryptor,
                      sym_algo_hint: Option<SymmetricAlgorithm>,
                      seipdv1: bool)
                      -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        let (checksummed, unencrypted_cipher_octet, encrypted_cipher_octet) =
            classify_pk_algo(decryptor.public().pk_algo(), seipdv1)?;

        //dbg!((checksummed, unencrypted_cipher_octet, encrypted_cipher_octet));

        let mut sym_algo: Option<SymmetricAlgorithm> = None;
        let modified_ciphertext;
        let esk;
        if unencrypted_cipher_octet {
            match ciphertext {
                Ciphertext::X25519 { e, key, } => {
                    sym_algo =
                        Some((*key.get(0).ok_or_else(
                            || Error::MalformedPacket("Short ESK".into()))?)
                             .into());
                    modified_ciphertext = Ciphertext::X25519 {
                        e: e.clone(),
                        key: key[1..].into(),
                    };
                    esk = &modified_ciphertext;
                },
                Ciphertext::X448 { e, key, } => {
                    sym_algo =
                        Some((*key.get(0).ok_or_else(
                            || Error::MalformedPacket("Short ESK".into()))?)
                             .into());
                    modified_ciphertext = Ciphertext::X448 {
                        e: e.clone(),
                        key: key[1..].into(),
                    };
                    esk = &modified_ciphertext;
                },

                _ => {
                    // We only prepend the cipher octet for X25519 and
                    // X448, yet we're trying to decrypt a ciphertext
                    // that uses a different algorithm, clearly
                    // something has gone wrong and will fail when we
                    // try to decrypt it downstream.
                    esk = ciphertext;
                },
            }
        } else {
            esk = ciphertext;
        }

        let plaintext_len = if let Some(s) = sym_algo_hint {
            Some(encrypted_cipher_octet.then(|| 1).unwrap_or(0)
                 + s.key_size()?
                 + checksummed.then(|| 2).unwrap_or(0))
        } else {
            None
        };
        let plain = decryptor.decrypt(esk, plaintext_len)?;
        let key_rgn = encrypted_cipher_octet.then(|| 1).unwrap_or(0)
            ..plain.len().saturating_sub(checksummed.then(|| 2).unwrap_or(0));
        if encrypted_cipher_octet {
            sym_algo = Some(plain[0].into());
        }
        let sym_algo = sym_algo.or(sym_algo_hint)
            .ok_or_else(|| Error::InvalidOperation(
                "No symmetric algorithm discovered or given".into()))?;
        let mut key: SessionKey = vec![0u8; sym_algo.key_size()?].into();

        if key_rgn.len() != sym_algo.key_size()? {
            return Err(Error::MalformedPacket(
                format!("session key has the wrong size (got: {}, expected: {})",
                        key_rgn.len(), sym_algo.key_size()?)).into())
        }

        key.copy_from_slice(&plain[key_rgn]);

        if checksummed {
            let our_checksum
                = key.iter().map(|&x| x as usize).sum::<usize>() & 0xffff;
            let their_checksum = (plain[plain.len() - 2] as usize) << 8
                | (plain[plain.len() - 1] as usize);

            if their_checksum != our_checksum {
                return Err(Error::MalformedPacket(
                    "key checksum wrong".to_string()).into());
            }
        }
        Ok((sym_algo, key))
    }
}

impl From<PKESK3> for super::PKESK {
    fn from(p: PKESK3) -> Self {
        super::PKESK::V3(p)
    }
}

impl From<PKESK3> for Packet {
    fn from(p: PKESK3) -> Self {
        Packet::PKESK(p.into())
    }
}

#[cfg(test)]
impl Arbitrary for super::PKESK {
    fn arbitrary(g: &mut Gen) -> Self {
        if bool::arbitrary(g) {
            PKESK3::arbitrary(g).into()
        } else {
            PKESK6::arbitrary(g).into()
        }
    }
}

#[cfg(test)]
impl Arbitrary for PKESK3 {
    fn arbitrary(g: &mut Gen) -> Self {
        let (ciphertext, pk_algo) = loop {
            let ciphertext = Ciphertext::arbitrary(g);
            if let Some(pk_algo) = ciphertext.pk_algo() {
                break (ciphertext, pk_algo);
            }
        };

        PKESK3::new(KeyID::arbitrary(g), pk_algo, ciphertext).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Cert;
    use crate::PacketPile;
    use crate::packet::*;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;
    use crate::types::Curve;

    quickcheck! {
        fn roundtrip(p: PKESK3) -> bool {
            let q = PKESK3::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    #[test]
    fn decrypt_rsa() {
        if ! PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
            eprintln!("Skipping test, algorithm is not supported.");
            return;
        }

        let cert = Cert::from_bytes(
            crate::tests::key("testy-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy.gpg")).unwrap();
        let mut keypair =
            cert.subkeys().next().unwrap()
            .key().clone().parts_into_secret().unwrap().into_keypair().unwrap();

        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();

        let plain = pkesk.decrypt(&mut keypair, None).unwrap();
        let plain_ =
            pkesk.decrypt(&mut keypair, Some(SymmetricAlgorithm::AES256))
            .unwrap();
        assert_eq!(plain, plain_);

        eprintln!("plain: {:?}", plain);
    }

    #[test]
    fn decrypt_ecdh_cv25519() {
        if ! (PublicKeyAlgorithm::EdDSA.is_supported()
              && Curve::Ed25519.is_supported()
              && PublicKeyAlgorithm::ECDH.is_supported()
              && Curve::Cv25519.is_supported()) {
            eprintln!("Skipping test, algorithm is not supported.");
            return;
        }

        let cert = Cert::from_bytes(
            crate::tests::key("testy-new-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-new.pgp")).unwrap();
        let mut keypair =
            cert.subkeys().next().unwrap()
            .key().clone().parts_into_secret().unwrap().into_keypair().unwrap();

        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();

        let plain = pkesk.decrypt(&mut keypair, None).unwrap();
        let plain_ =
            pkesk.decrypt(&mut keypair, Some(SymmetricAlgorithm::AES256))
            .unwrap();
        assert_eq!(plain, plain_);

        eprintln!("plain: {:?}", plain);
    }

    #[test]
    fn decrypt_ecdh_nistp256() {
        if ! (PublicKeyAlgorithm::ECDSA.is_supported()
              && PublicKeyAlgorithm::ECDH.is_supported()
              && Curve::NistP256.is_supported()) {
            eprintln!("Skipping test, algorithm is not supported.");
            return;
        }

        let cert = Cert::from_bytes(
            crate::tests::key("testy-nistp256-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-nistp256.pgp")).unwrap();
        let mut keypair =
            cert.subkeys().next().unwrap()
            .key().clone().parts_into_secret().unwrap().into_keypair().unwrap();

        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();

        let plain = pkesk.decrypt(&mut keypair, None)
            .expect("ECDH decryption using P-256 key should work");
        let plain_ =
            pkesk.decrypt(&mut keypair, Some(SymmetricAlgorithm::AES256))
            .unwrap();
        assert_eq!(plain, plain_);

        eprintln!("plain: {:?}", plain);
    }

    #[test]
    fn decrypt_ecdh_nistp384() {
        if ! (PublicKeyAlgorithm::ECDSA.is_supported()
              && PublicKeyAlgorithm::ECDH.is_supported()
              && Curve::NistP384.is_supported()) {
            eprintln!("Skipping test, algorithm is not supported.");
            return;
        }

        let cert = Cert::from_bytes(
            crate::tests::key("testy-nistp384-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-nistp384.pgp")).unwrap();
        let mut keypair =
            cert.subkeys().next().unwrap()
            .key().clone().parts_into_secret().unwrap().into_keypair().unwrap();

        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();

        let plain = pkesk.decrypt(&mut keypair, None)
            .expect("ECDH decryption using P-384 key should work");
        let plain_ =
            pkesk.decrypt(&mut keypair, Some(SymmetricAlgorithm::AES256))
            .unwrap();
        assert_eq!(plain, plain_);

        eprintln!("plain: {:?}", plain);
    }

    #[test]
    fn decrypt_elgamal() -> Result<()> {
        if ! (PublicKeyAlgorithm::DSA.is_supported()
              && PublicKeyAlgorithm::ElGamalEncrypt.is_supported()) {
            eprintln!("Skipping test, algorithm is not supported.");
            return Ok(());
        }

        let cert = Cert::from_bytes(
            crate::tests::key("dsa2048-elgamal3072-private.pgp"))?;
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-dsa2048-elgamal3072.pgp"))?;
        let mut keypair =
            cert.subkeys().next().unwrap()
            .key().clone().parts_into_secret()?.into_keypair()?;

        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();

        let plain = pkesk.decrypt(&mut keypair, None).unwrap();
        let plain_ =
            pkesk.decrypt(&mut keypair, Some(SymmetricAlgorithm::AES256))
            .unwrap();
        assert_eq!(plain, plain_);

        eprintln!("plain: {:?}", plain);
        Ok(())
    }

    #[test]
    fn decrypt_ecdh_nistp521() {
        if ! (PublicKeyAlgorithm::ECDSA.is_supported()
              && PublicKeyAlgorithm::ECDH.is_supported()
              && Curve::NistP521.is_supported()) {
            eprintln!("Skipping test, algorithm is not supported.");
            return;
        }

        let cert = Cert::from_bytes(
            crate::tests::key("testy-nistp521-private.pgp")).unwrap();
        let pile = PacketPile::from_bytes(
            crate::tests::message("encrypted-to-testy-nistp521.pgp")).unwrap();
        let mut keypair =
            cert.subkeys().next().unwrap()
            .key().clone().parts_into_secret().unwrap().into_keypair().unwrap();

        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();

        let plain = pkesk.decrypt(&mut keypair, None)
            .expect("ECDH decryption using P-521 key should work");
        let plain_ =
            pkesk.decrypt(&mut keypair, Some(SymmetricAlgorithm::AES256))
            .unwrap();
        assert_eq!(plain, plain_);

        eprintln!("plain: {:?}", plain);
    }


    #[test]
    fn decrypt_with_short_cv25519_secret_key() {
        if ! (PublicKeyAlgorithm::ECDH.is_supported()
              && Curve::Cv25519.is_supported()) {
            eprintln!("Skipping test, algorithm is not supported.");
            return;
        }

        use super::PKESK3;
        use crate::crypto::SessionKey;
        use crate::{HashAlgorithm, SymmetricAlgorithm};
        use crate::packet::key::{Key4, UnspecifiedRole};

        // 20 byte sec key
        let mut secret_key = [
            0x0,0x0,
            0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
            0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x2,
            0x1,0x2,0x2,0x2,0x2,0x2,0x2,0x2,0x0,0x0
        ];
        // Ensure that the key is at least somewhat valid, according to the
        // generation procedure specified in "Responsibilities of the user":
        // https://cr.yp.to/ecdh/curve25519-20060209.pdf#page=5
        // Only perform the bit-twiddling on the last byte. This is done so that
        // we can still have somewhat defined multiplication while still testing
        // the "short" key logic.
        // secret_key[0] &= 0xf8;
        secret_key[31] &= 0x7f;
        secret_key[31] |= 0x40;

        let key: Key<_, UnspecifiedRole> = Key4::import_secret_cv25519(
            &secret_key,
            HashAlgorithm::SHA256,
            SymmetricAlgorithm::AES256,
            None,
        ).unwrap().into();

        let sess_key = SessionKey::new(32);
        let pkesk = PKESK3::for_recipient(SymmetricAlgorithm::AES256, &sess_key,
                                          &key).unwrap();
        let mut keypair = key.into_keypair().unwrap();
        pkesk.decrypt(&mut keypair, None).unwrap();
    }

    /// Insufficient validation of RSA ciphertexts crash Nettle.
    ///
    /// See CVE-2021-3580.
    #[test]
    fn cve_2021_3580_ciphertext_too_long() -> Result<()> {
        if ! PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
            eprintln!("Skipping test, algorithm is not supported.");
            return Ok(());
        }

        // Get (any) 2k RSA key.
        let cert = Cert::from_bytes(
            crate::tests::key("testy-private.pgp"))?;
        let mut keypair = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;

        let pile = PacketPile::from_bytes(b"-----BEGIN PGP ARMORED FILE-----

wcDNAwAAAAAAAAAAAQwGI5SkpcRMjkiOKx332kxv+2Xh4y1QTefPilKOPOlHYFa0
rnnLaQVEACKJNQ38YuCFUvtpK4IN2grjlj71IP24+KDp3ZuVWnVTS6JcyE10Y9iq
uGvKdS0C17XCze2LD4ouVOrUZHGXpeDT47w6DsHb/0UE85h56wpk2CzO1XFQzHxX
HR2DDLqqeFVzTv0peYiQfLHl7kWXijTNEqmYhFCzxuICXzuClAAJM+fVIRfcm2tm
2R4AxOQGv9DlWfZwbkpKfj/uuo0CAe21n4NT+NzdVgPlff/hna3yGgPe1B+vjq4e
jfxHg+pvo/HTLkV+c2HAGbM1bCb/5TedGd1nAMSAIOu/J/WQp/l3HtEv63HaVPZJ
JInJ6L/KyPwjm/ieZx5EWOLJgFRWGCrBGnb8T81lkFey7uZR5Xiq+9KoUhHQFw8N
joc0YUVyhUBVFf4B0zVZRUfqZyJtJ07Sl5xppI12U1HQCTjn7Fp8BHMPKuBotYzv
1Q4f00k6Txctw+LDRM17/w==
=VtwB
-----END PGP ARMORED FILE-----
")?;
        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();
        // Boom goes the assertion.
        let _ = pkesk.decrypt(&mut keypair, None);

        Ok(())
    }

    /// Insufficient validation of RSA ciphertexts crash Nettle.
    ///
    /// See CVE-2021-3580.
    #[test]
    fn cve_2021_3580_zero_ciphertext() -> Result<()> {
        if ! PublicKeyAlgorithm::RSAEncryptSign.is_supported() {
            eprintln!("Skipping test, algorithm is not supported.");
            return Ok(());
        }

        // Get (any) 2k RSA key.
        let cert = Cert::from_bytes(
            crate::tests::key("testy-private.pgp"))?;
        let mut keypair = cert.primary_key().key().clone()
            .parts_into_secret()?.into_keypair()?;

        let pile = PacketPile::from_bytes(b"-----BEGIN PGP ARMORED FILE-----

wQwDAAAAAAAAAAABAAA=
=H/1T
-----END PGP ARMORED FILE-----
")?;
        let pkesk: &PKESK =
            pile.descendants().next().unwrap().downcast_ref().unwrap();
        // Boom goes the memory safety.
        let _ = pkesk.decrypt(&mut keypair, None);

        Ok(())
    }
}
