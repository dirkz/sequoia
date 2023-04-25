//! Symmetric-Key Encrypted Session Key Packets.
//!
//! SKESK packets hold symmetrically encrypted session keys.  The
//! session key is needed to decrypt the actual ciphertext.  See
//! [Section 5.3 of RFC 4880] for details.
//!
//! [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3

use std::ops::{Deref, DerefMut};

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::Result;
use crate::crypto::{
    self,
    S2K,
    Password,
    SessionKey,
    backend::{Backend, interface::Kdf},
};
use crate::crypto::aead::CipherOp;
use crate::Error;
use crate::types::{
    AEADAlgorithm,
    SymmetricAlgorithm,
};
use crate::packet::{self, SKESK};
use crate::Packet;

impl SKESK {
    /// Derives the key inside this SKESK from `password`. Returns a
    /// tuple of the symmetric cipher to use with the key and the key
    /// itself.
    pub fn decrypt(&self, password: &Password)
        -> Result<(Option<SymmetricAlgorithm>, SessionKey)>
    {
        match self {
            SKESK::V4(s) => s.decrypt(password)
                .map(|(algo, sk)| (Some(algo), sk)),
            SKESK::V6(ref s) =>
                Ok((None, s.decrypt(password)?)),
        }
    }
}

#[cfg(test)]
impl Arbitrary for SKESK {
    fn arbitrary(g: &mut Gen) -> Self {
        if bool::arbitrary(g) {
            SKESK::V4(SKESK4::arbitrary(g))
        } else {
            SKESK::V6(SKESK6::arbitrary(g))
        }
    }
}

/// Holds an symmetrically encrypted session key version 4.
///
/// Holds an symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Section 5.3 of RFC
/// 4880] for details.
///
/// [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.3
#[derive(Clone, Debug)]
pub struct SKESK4 {
    /// CTB header fields.
    pub(crate) common: packet::Common,
    /// Packet version. Must be 4 or 5.
    ///
    /// This struct is also used by SKESK6, hence we have a version
    /// field.
    version: u8,
    /// Symmetric algorithm used to encrypt the session key.
    sym_algo: SymmetricAlgorithm,
    /// Key derivation method for the symmetric key.
    s2k: S2K,
    /// The encrypted session key.
    ///
    /// If we recognized the S2K object during parsing, we can
    /// successfully parse the data into S2K and ciphertext.  However,
    /// if we do not recognize the S2K type, we do not know how large
    /// its parameters are, so we cannot cleanly parse it, and have to
    /// accept that the S2K's body bleeds into the rest of the data.
    esk: std::result::Result<Option<Box<[u8]>>, // optional ciphertext.
                             Box<[u8]>>,        // S2K body + maybe ciphertext.
}
assert_send_and_sync!(SKESK4);

// Because the S2K and ESK cannot be cleanly separated at parse time,
// we need to carefully compare and hash SKESK4 packets.

impl PartialEq for SKESK4 {
    fn eq(&self, other: &SKESK4) -> bool {
        self.version == other.version
            && self.sym_algo == other.sym_algo
            // Treat S2K and ESK as opaque blob.
            && {
                // XXX: This would be nicer without the allocations.
                use crate::serialize::MarshalInto;
                let mut a = self.s2k.to_vec().unwrap();
                let mut b = other.s2k.to_vec().unwrap();
                a.extend_from_slice(self.raw_esk());
                b.extend_from_slice(other.raw_esk());
                a == b
            }
    }
}

impl Eq for SKESK4 {}

impl std::hash::Hash for SKESK4 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
        self.sym_algo.hash(state);
        // Treat S2K and ESK as opaque blob.
        // XXX: This would be nicer without the allocations.
        use crate::serialize::MarshalInto;
        let mut a = self.s2k.to_vec().unwrap();
        a.extend_from_slice(self.raw_esk());
        a.hash(state);
    }
}

impl SKESK4 {
    /// Creates a new SKESK version 4 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub fn new(esk_algo: SymmetricAlgorithm, s2k: S2K,
               esk: Option<Box<[u8]>>) -> Result<SKESK4> {
        Self::new_raw(esk_algo, s2k, Ok(esk.and_then(|esk| {
            if esk.len() == 0 { None } else { Some(esk) }
        })))
    }

    /// Creates a new SKESK version 4 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub(crate) fn new_raw(esk_algo: SymmetricAlgorithm, s2k: S2K,
                          esk: std::result::Result<Option<Box<[u8]>>,
                                                   Box<[u8]>>)
                          -> Result<SKESK4> {
        Ok(SKESK4{
            common: Default::default(),
            version: 4,
            sym_algo: esk_algo,
            s2k,
            esk,
        })
    }

    /// Creates a new SKESK4 packet with the given password.
    ///
    /// This function takes two [`SymmetricAlgorithm`] arguments: The
    /// first, `payload_algo`, is the algorithm used to encrypt the
    /// message's payload (i.e. the one used in the [`SEIP`] or
    /// [`AED`] packet), and the second, `esk_algo`, is used to
    /// encrypt the session key.  Usually, one should use the same
    /// algorithm, but if they differ, the `esk_algo` should be at
    /// least as strong as the `payload_algo` as not to weaken the
    /// security of the payload encryption.
    ///
    ///   [`SymmetricAlgorithm`]: crate::types::SymmetricAlgorithm
    ///   [`SEIP`]: super::SEIP
    ///   [`AED`]: super::AED
    pub fn with_password(payload_algo: SymmetricAlgorithm,
                         esk_algo: SymmetricAlgorithm,
                         s2k: S2K,
                         session_key: &SessionKey, password: &Password)
                         -> Result<SKESK4> {
        if session_key.len() != payload_algo.key_size()? {
            return Err(Error::InvalidArgument(format!(
                "Invalid size of session key, got {} want {}",
                session_key.len(), payload_algo.key_size()?)).into());
        }

        // Derive key and make a cipher.
        let key = s2k.derive_key(password, esk_algo.key_size()?)?;
        let block_size = esk_algo.block_size()?;
        let iv = vec![0u8; block_size];
        let mut cipher = esk_algo.make_encrypt_cfb(&key[..], iv)?;

        // We need to prefix the cipher specifier to the session key.
        let mut psk: SessionKey = vec![0; 1 + session_key.len()].into();
        psk[0] = payload_algo.into();
        psk[1..].copy_from_slice(session_key);
        let mut esk = vec![0u8; psk.len()];

        for (pt, ct) in psk[..].chunks(block_size)
            .zip(esk.chunks_mut(block_size)) {
                cipher.encrypt(ct, pt)?;
        }

        SKESK4::new(esk_algo, s2k, Some(esk.into()))
    }

    /// Gets the symmetric encryption algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.sym_algo
    }

    /// Sets the symmetric encryption algorithm.
    pub fn set_symmetric_algo(&mut self, algo: SymmetricAlgorithm) -> SymmetricAlgorithm {
        ::std::mem::replace(&mut self.sym_algo, algo)
    }

    /// Gets the key derivation method.
    pub fn s2k(&self) -> &S2K {
        &self.s2k
    }

    /// Sets the key derivation method.
    pub fn set_s2k(&mut self, s2k: S2K) -> S2K {
        ::std::mem::replace(&mut self.s2k, s2k)
    }

    /// Gets the encrypted session key.
    ///
    /// If the [`S2K`] mechanism is not supported by Sequoia, this
    /// function will fail.  Note that the information is not lost,
    /// but stored in the packet.  If the packet is serialized again,
    /// it is written out.
    ///
    ///   [`S2K`]: super::super::crypto::S2K
    pub fn esk(&self) -> Result<Option<&[u8]>> {
        self.esk.as_ref()
            .map(|esko| esko.as_ref().map(|esk| &esk[..]))
            .map_err(|_| Error::MalformedPacket(
                format!("Unknown S2K: {:?}", self.s2k)).into())
    }

    /// Returns the encrypted session key, possibly including the body
    /// of the S2K object.
    pub(crate) fn raw_esk(&self) -> &[u8] {
        match self.esk.as_ref() {
            Ok(Some(esk)) => &esk[..],
            Ok(None) => &[][..],
            Err(s2k_esk) => &s2k_esk[..],
        }
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Option<Box<[u8]>>) -> Option<Box<[u8]>> {
        ::std::mem::replace(
            &mut self.esk,
            Ok(esk.and_then(|esk| {
                if esk.len() == 0 { None } else { Some(esk) }
            })))
            .unwrap_or(None)
    }

    /// Derives the key inside this SKESK4 from `password`.
    ///
    /// Returns a tuple of the symmetric cipher to use with the key
    /// and the key itself.
    pub fn decrypt(&self, password: &Password)
        -> Result<(SymmetricAlgorithm, SessionKey)>
    {
        let key = self.s2k.derive_key(password, self.sym_algo.key_size()?)?;

        if let Some(esk) = self.esk()? {
            // Use the derived key to decrypt the ESK. Unlike SEP &
            // SEIP we have to use plain CFB here.
            let blk_sz = self.sym_algo.block_size()?;
            let iv = vec![0u8; blk_sz];
            let mut dec  = self.sym_algo.make_decrypt_cfb(&key[..], iv)?;
            let mut plain: SessionKey = vec![0u8; esk.len()].into();
            let cipher = esk;

            for (pl, ct)
                in plain[..].chunks_mut(blk_sz).zip(cipher.chunks(blk_sz))
            {
                dec.decrypt(pl, ct)?;
            }

            // Get the algorithm from the front.
            let sym = SymmetricAlgorithm::from(plain[0]);
            Ok((sym, plain[1..].into()))
        } else {
            // No ESK, we return the derived key.
            Ok((self.sym_algo, key))
        }
    }
}

impl From<SKESK4> for super::SKESK {
    fn from(p: SKESK4) -> Self {
        super::SKESK::V4(p)
    }
}

impl From<SKESK4> for Packet {
    fn from(s: SKESK4) -> Self {
        Packet::SKESK(SKESK::V4(s))
    }
}

#[cfg(test)]
impl Arbitrary for SKESK4 {
    fn arbitrary(g: &mut Gen) -> Self {
        SKESK4::new(SymmetricAlgorithm::arbitrary(g),
                    S2K::arbitrary(g),
                    Option::<Vec<u8>>::arbitrary(g).map(|v| v.into()))
            .unwrap()
    }
}

/// Holds an symmetrically encrypted session key version 5.
///
/// Holds an symmetrically encrypted session key.  The session key is
/// needed to decrypt the actual ciphertext.  See [Section 5.3 of RFC
/// 4880bis] for details.
///
/// [Section 5.3 of RFC 4880]: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.3
///
/// This feature is [experimental](super::super#experimental-features).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SKESK6 {
    /// Common fields.
    pub(crate) skesk4: SKESK4,
    /// AEAD algorithm.
    aead_algo: AEADAlgorithm,
    /// Initialization vector for the AEAD algorithm.
    aead_iv: Box<[u8]>,
}
assert_send_and_sync!(SKESK6);

impl Deref for SKESK6 {
    type Target = SKESK4;

    fn deref(&self) -> &Self::Target {
        &self.skesk4
    }
}

impl DerefMut for SKESK6 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.skesk4
    }
}

impl SKESK6 {
    /// Creates a new SKESK version 5 packet.
    ///
    /// The given symmetric algorithm is the one used to encrypt the
    /// session key.
    pub fn new(sym_algo: SymmetricAlgorithm,
               aead_algo: AEADAlgorithm,
               s2k: S2K,
               aead_iv: Box<[u8]>,
               esk: Box<[u8]>)
               -> Result<Self> {
        Ok(SKESK6 {
            skesk4: SKESK4 {
                common: Default::default(),
                version: 6,
                sym_algo,
                s2k,
                esk: Ok(Some(esk)),
            },
            aead_algo,
            aead_iv,
        })
    }

    /// Creates a new SKESK version 5 packet with the given password.
    ///
    /// This function takes two [`SymmetricAlgorithm`] arguments: The
    /// first, `payload_algo`, is the algorithm used to encrypt the
    /// message's payload (i.e. the one used in the [`SEIP`] or
    /// [`AED`] packet), and the second, `esk_algo`, is used to
    /// encrypt the session key.  Usually, one should use the same
    /// algorithm, but if they differ, the `esk_algo` should be at
    /// least as strong as the `payload_algo` as not to weaken the
    /// security of the payload encryption.
    ///
    ///   [`SymmetricAlgorithm`]: crate::types::SymmetricAlgorithm
    ///   [`SEIP`]: super::SEIP
    ///   [`AED`]: super::AED
    pub fn with_password(payload_algo: SymmetricAlgorithm,
                         esk_algo: SymmetricAlgorithm,
                         esk_aead: AEADAlgorithm, s2k: S2K,
                         session_key: &SessionKey, password: &Password)
                         -> Result<Self> {
        if session_key.len() != payload_algo.key_size()? {
            return Err(Error::InvalidArgument(format!(
                "Invalid size of session key, got {} want {}",
                session_key.len(), payload_algo.key_size()?)).into());
        }

        // Derive key and make a cipher.
        let ad = [0xc3, 6, esk_algo.into(), esk_aead.into()];
        let key = s2k.derive_key(password, esk_algo.key_size()?)?;

        let mut kek: SessionKey = vec![0; esk_algo.key_size()?].into();
        Backend::hkdf_sha256(&key, None, &ad, &mut kek)?;


        // Encrypt the session key with the KEK.
        let mut iv = vec![0u8; esk_aead.nonce_size()?];
        crypto::random(&mut iv);
        let mut ctx =
            esk_aead.context(esk_algo, &kek, &ad, &iv, CipherOp::Encrypt)?;
        let mut esk_digest =
            vec![0u8; session_key.len() + esk_aead.digest_size()?];
        ctx.encrypt_seal(&mut esk_digest, session_key)?;

        // Attach digest to the ESK, we model it as one.
        SKESK6::new(esk_algo, esk_aead, s2k, iv.into_boxed_slice(),
                    esk_digest.into())
    }

    /// Derives the key inside this `SKESK6` from `password`.
    ///
    /// Returns a tuple containing a placeholder symmetric cipher and
    /// the key itself.  `SKESK6` packets do not contain the symmetric
    /// cipher algorithm and instead rely on the `AED` packet that
    /// contains it.
    pub fn decrypt(&self, password: &Password)
                   -> Result<SessionKey> {
        let key = self.s2k().derive_key(password,
                                        self.symmetric_algo().key_size()?)?;

        let mut kek: SessionKey =
            vec![0; self.symmetric_algo().key_size()?].into();
        let ad = [0xc3,
                  6 /* Version.  */,
                  self.symmetric_algo().into(),
                  self.aead_algo.into()];
        Backend::hkdf_sha256(&key, None, &ad, &mut kek)?;

        // Use the derived key to decrypt the ESK.
        let mut cipher = self.aead_algo.context(
            self.symmetric_algo(), &kek, &ad, self.aead_iv(),
            CipherOp::Decrypt)?;

        let mut plain: SessionKey =
            vec![0; self.esk().len() - self.aead_algo.digest_size()?].into();
        cipher.decrypt_verify(&mut plain, self.esk())?;
        Ok(plain)
    }

    /// Gets the AEAD algorithm.
    pub fn aead_algo(&self) -> AEADAlgorithm {
        self.aead_algo
    }

    /// Sets the AEAD algorithm.
    pub fn set_aead_algo(&mut self, algo: AEADAlgorithm) -> AEADAlgorithm {
        ::std::mem::replace(&mut self.aead_algo, algo)
    }

    /// Gets the AEAD initialization vector.
    pub fn aead_iv(&self) -> &[u8] {
        &self.aead_iv
    }

    /// Sets the AEAD initialization vector.
    pub fn set_aead_iv(&mut self, iv: Box<[u8]>) -> Box<[u8]> {
        ::std::mem::replace(&mut self.aead_iv, iv)
    }

    /// Gets the encrypted session key.
    pub fn esk(&self) -> &[u8] {
        self.skesk4.raw_esk()
    }

    /// Sets the encrypted session key.
    pub fn set_esk(&mut self, esk: Box<[u8]>) -> Box<[u8]> {
        ::std::mem::replace(&mut self.esk, Ok(Some(esk)))
            .expect("v6 SKESK can always be parsed")
            .expect("v6 SKESK packets always have an ESK")
    }
}

impl From<SKESK6> for super::SKESK {
    fn from(p: SKESK6) -> Self {
        super::SKESK::V6(p)
    }
}

impl From<SKESK6> for Packet {
    fn from(s: SKESK6) -> Self {
        Packet::SKESK(SKESK::V6(s))
    }
}

#[cfg(test)]
impl Arbitrary for SKESK6 {
    fn arbitrary(g: &mut Gen) -> Self {
        let algo = AEADAlgorithm::const_default();
        let mut iv = vec![0u8; algo.nonce_size().unwrap()];
        for b in iv.iter_mut() {
            *b = u8::arbitrary(g);
        }
        let esk_len =
            (u8::arbitrary(g) % 64) as usize + algo.digest_size().unwrap();
        let mut esk = vec![0u8; esk_len];
        for b in esk.iter_mut() {
            *b = u8::arbitrary(g);
        }
        SKESK6::new(SymmetricAlgorithm::arbitrary(g),
                    algo,
                    S2K::arbitrary(g),
                    iv.into(),
                    esk.into())
            .unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::PacketPile;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    quickcheck! {
        fn roundtrip_v4(p: SKESK4) -> bool {
            let p = SKESK::from(p);
            let q = SKESK::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    quickcheck! {
        fn roundtrip_v6(p: SKESK6) -> bool {
            let p = SKESK::from(p);
            let q = SKESK::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    /// This sample packet is from RFCXXX.
    #[test]
    fn v6skesk_aes128_ocb() -> Result<()> {
        sample_skesk6_packet(
            SymmetricAlgorithm::AES128,
            AEADAlgorithm::OCB,
            "crypto-refresh/v6skesk-aes128-ocb.pgp",
            b"\xe8\x0d\xe2\x43\xa3\x62\xd9\x3b\
              \x9d\xc6\x07\xed\xe9\x6a\x73\x56",
            b"\x28\xe7\x9a\xb8\x23\x97\xd3\xc6\
              \x3d\xe2\x4a\xc2\x17\xd7\xb7\x91")
    }

    /// This sample packet is from RFCXXX.
    #[test]
    fn v6skesk_aes128_eax() -> Result<()> {
        sample_skesk6_packet(
            SymmetricAlgorithm::AES128,
            AEADAlgorithm::EAX,
            "crypto-refresh/v6skesk-aes128-eax.pgp",
            b"\x15\x49\x67\xe5\x90\xaa\x1f\x92\
              \x3e\x1c\x0a\xc6\x4c\x88\xf2\x3d",
            b"\x38\x81\xba\xfe\x98\x54\x12\x45\
              \x9b\x86\xc3\x6f\x98\xcb\x9a\x5e")
    }

    /// This sample packet is from RFCXXX.
    #[test]
    fn v6skesk_aes128_gcm() -> Result<()> {
        sample_skesk6_packet(
            SymmetricAlgorithm::AES128,
            AEADAlgorithm::GCM,
            "crypto-refresh/v6skesk-aes128-gcm.pgp",
            b"\x25\x02\x81\x71\x5b\xba\x78\x28\
              \xef\x71\xef\x64\xc4\x78\x47\x53",
            b"\x19\x36\xfc\x85\x68\x98\x02\x74\
              \xbb\x90\x0d\x83\x19\x36\x0c\x77")
    }

    fn sample_skesk6_packet(cipher: SymmetricAlgorithm,
                            aead: AEADAlgorithm,
                            name: &str,
                            derived_key: &[u8],
                            session_key: &[u8])
                            -> Result<()> {
        let password: Password = String::from("password").into();
        let packets: Vec<Packet> =
            PacketPile::from_bytes(
                crate::tests::file(name))?
            .into_children().collect();
        assert_eq!(packets.len(), 2);
        if let Packet::SKESK(SKESK::V6(ref s)) = packets[0] {
            let derived = s.s2k().derive_key(
                &password, s.symmetric_algo().key_size()?)?;
            eprintln!("derived: {:x?}", &derived[..]);
            assert_eq!(&derived[..], derived_key);

            if aead.is_supported()
                && aead.supports_symmetric_algo(&cipher)
            {
                let sk = s.decrypt(&password)?;
                eprintln!("sk: {:x?}", &sk[..]);
                assert_eq!(&sk[..], session_key);
            } else {
                eprintln!("{}-{} is not supported, skipping decryption.",
                          cipher, aead);
            }
        } else {
            panic!("bad packet, expected v6 SKESK: {:?}", packets[0]);
        }

        Ok(())
    }

    /// Tests various S2K methods, with and without encrypted session
    /// key.
    #[test]
    fn skesk4_s2k_variants() -> Result<()> {
        use std::io::Read;
        use crate::{
            Cert,
            Fingerprint,
            packet::{SKESK, PKESK},
            parse::stream::*,
        };

        struct H();
        impl VerificationHelper for H {
            fn get_certs(&mut self, _ids: &[crate::KeyHandle])
                         -> Result<Vec<Cert>> {
                Ok(Vec::new())
            }

            fn check(&mut self, _m: MessageStructure)
                     -> Result<()> {
                Ok(())
            }
        }

        impl DecryptionHelper for H {
            fn decrypt<D>(&mut self, _: &[PKESK], skesks: &[SKESK],
                          _: Option<SymmetricAlgorithm>,
                          mut decrypt: D) -> Result<Option<Fingerprint>>
            where D: FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool
            {
                assert_eq!(skesks.len(), 1);
                let (cipher, sk) = skesks[0].decrypt(&"password".into())?;
                assert_eq!(cipher, Some(SymmetricAlgorithm::AES256));
                let r = decrypt(cipher, &sk);
                assert!(r);
                Ok(None)
            }
        }

        let p = &crate::policy::StandardPolicy::new();
        for variant in &["simple", "salted", "iterated.min", "iterated.max"] {
            for esk in &["", ".esk"] {
                let name = format!("s2k/{}{}.pgp", variant, esk);
                eprintln!("{}", name);
                let mut verifier = DecryptorBuilder::from_bytes(
                    crate::tests::message(&name))?
                    .with_policy(p, None, H())?;
                let mut b = Vec::new();
                verifier.read_to_end(&mut b)?;
                assert_eq!(&b, b"Hello World :)");
            }
        }

        Ok(())
    }
}
