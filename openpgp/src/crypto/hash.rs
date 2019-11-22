//! Functionality to hash packets, and generate hashes.

use crate::HashAlgorithm;
use crate::packet::Key;
use crate::packet::UserID;
use crate::packet::UserAttribute;
use crate::packet::key;
use crate::packet::key::Key4;
use crate::packet::Signature;
use crate::packet::signature::{self, Signature4};
use crate::Error;
use crate::Result;
use crate::conversions::Time;

use nettle;
use nettle::Hash as NettleHash;

use std::fs::{File, OpenOptions};
use std::io::{self, Write};

// If set to e.g. Some("/tmp/hash"), we will dump everything that is
// hashed to files /tmp/hash-N, where N is a number.
const DUMP_HASHED_VALUES: Option<&str> = None;

/// State of a hash function.
#[derive(Clone)]
pub struct Context {
    algo: HashAlgorithm,
    ctx: Box<dyn nettle::Hash>,
}

impl Context {
    /// Returns the algorithm.
    pub fn algo(&self) -> HashAlgorithm {
        self.algo
    }

    /// Size of the digest in bytes
    pub fn digest_size(&self) -> usize {
        self.ctx.digest_size()
    }

    /// Writes data into the hash function.
    pub fn update<D: AsRef<[u8]>>(&mut self, data: D) {
        self.ctx.update(data.as_ref());
    }

    /// Finalizes the hash function and writes the digest into the
    /// provided slice.
    ///
    /// Resets the hash function contexts.
    ///
    /// `digest` must be at least `self.digest_size()` bytes large,
    /// otherwise the digest will be truncated.
    pub fn digest<D: AsMut<[u8]>>(&mut self, mut digest: D) {
        self.ctx.digest(digest.as_mut());
    }
}

impl io::Write for Context {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        match self {
            HashAlgorithm::SHA1 => true,
            HashAlgorithm::SHA224 => true,
            HashAlgorithm::SHA256 => true,
            HashAlgorithm::SHA384 => true,
            HashAlgorithm::SHA512 => true,
            HashAlgorithm::RipeMD => false,
            HashAlgorithm::MD5 => false,
            HashAlgorithm::Private(_) => false,
            HashAlgorithm::Unknown(_) => false,
        }
    }

    /// Creates a new Nettle hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    ///   [`HashAlgorithm::is_supported`]: #method.is_supported
    pub fn context(self) -> Result<Context> {
        use nettle::hash::*;
        use nettle::hash::insecure_do_not_use::Sha1;

        let c: Result<Box<dyn nettle::Hash>> = match self {
            HashAlgorithm::SHA1 => Ok(Box::new(Sha1::default())),
            HashAlgorithm::SHA224 => Ok(Box::new(Sha224::default())),
            HashAlgorithm::SHA256 => Ok(Box::new(Sha256::default())),
            HashAlgorithm::SHA384 => Ok(Box::new(Sha384::default())),
            HashAlgorithm::SHA512 => Ok(Box::new(Sha512::default())),
            HashAlgorithm::MD5 | HashAlgorithm::RipeMD =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
        };

        if let Some(prefix) = DUMP_HASHED_VALUES {
            c.map(|c: Box<dyn nettle::Hash>| {
                Context {
                    algo: self,
                    ctx: Box::new(HashDumper::new(c, prefix)),
                }
            })
        } else {
            c.map(|c| Context { algo: self, ctx: c })
        }
    }

    /// Returns the ASN.1 OID of this hash algorithm.
    pub fn oid(self) -> Result<&'static [u8]> {
        use nettle::rsa;

        match self {
            HashAlgorithm::SHA1 => Ok(rsa::ASN1_OID_SHA1),
            HashAlgorithm::SHA224 => Ok(rsa::ASN1_OID_SHA224),
            HashAlgorithm::SHA256 => Ok(rsa::ASN1_OID_SHA256),
            HashAlgorithm::SHA384 => Ok(rsa::ASN1_OID_SHA384),
            HashAlgorithm::SHA512 => Ok(rsa::ASN1_OID_SHA512),
            HashAlgorithm::MD5 | HashAlgorithm::RipeMD =>
                Err(Error::UnsupportedHashAlgorithm(self.into()).into()),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
        }
    }
}

struct HashDumper {
    h: Box<dyn nettle::Hash>,
    sink: File,
    filename: String,
    written: usize,
}

impl HashDumper {
    fn new(h: Box<dyn nettle::Hash>, prefix: &str) -> Self {
        let mut n = 0;
        let mut filename;
        let sink = loop {
            filename = format!("{}-{}", prefix, n);
            match OpenOptions::new().write(true).create_new(true)
                .open(&filename)
            {
                Ok(f) => break f,
                Err(_) => n += 1,
            }
        };
        eprintln!("HashDumper: Writing to {}...", &filename);
        HashDumper {
            h: h,
            sink: sink,
            filename: filename,
            written: 0,
        }
    }
}

impl Drop for HashDumper {
    fn drop(&mut self) {
        eprintln!("HashDumper: Wrote {} bytes to {}...", self.written,
                  self.filename);
    }
}

impl nettle::Hash for HashDumper {
    fn digest_size(&self) -> usize {
        self.h.digest_size()
    }
    fn update(&mut self, data: &[u8]) {
        self.h.update(data);
        self.sink.write_all(data).unwrap();
        self.written += data.len();
    }
    fn digest(&mut self, digest: &mut [u8]) {
        self.h.digest(digest);
    }
    fn box_clone(&self) -> Box<dyn nettle::Hash> {
        Box::new(Self::new(self.h.box_clone(), &DUMP_HASHED_VALUES.unwrap()))
    }
}

/// Hashes OpenPGP packets and related types.
pub trait Hash {
    /// Updates the given hash with this object.
    fn hash(&self, hash: &mut Context);
}

impl Hash for UserID {
    /// Update the Hash with a hash of the user id.
    fn hash(&self, hash: &mut Context) {
        let mut header = [0; 5];

        header[0] = 0xB4;
        let len = self.value().len() as u32;
        header[1] = (len >> 24) as u8;
        header[2] = (len >> 16) as u8;
        header[3] = (len >> 8) as u8;
        header[4] = (len) as u8;

        hash.update(&header[..]);
        hash.update(self.value());
    }
}

impl Hash for UserAttribute {
    /// Update the Hash with a hash of the user attribute.
    fn hash(&self, hash: &mut Context) {
        let mut header = [0; 5];

        header[0] = 0xD1;
        let len = self.value().len() as u32;
        header[1] = (len >> 24) as u8;
        header[2] = (len >> 16) as u8;
        header[3] = (len >> 8) as u8;
        header[4] = (len) as u8;

        hash.update(&header[..]);
        hash.update(self.value());
    }
}

impl<P, R> Hash for Key4<P, R>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    /// Update the Hash with a hash of the key.
    fn hash(&self, hash: &mut Context) {
        // We hash 8 bytes plus the MPIs.  But, the len doesn't
        // include the tag (1 byte) or the length (2 bytes).
        let len = (9 - 3) + self.mpis().serialized_len();

        let mut header : Vec<u8> = Vec::with_capacity(9);

        // Tag.  Note: we use this whether
        header.push(0x99);

        // Length (big endian).
        header.push(((len >> 8) & 0xFF) as u8);
        header.push((len & 0xFF) as u8);

        // Version.
        header.push(4);

        // Creation time.
        let creation_time = self.creation_time().to_pgp()
            .unwrap_or(0);
        header.push((creation_time >> 24) as u8);
        header.push((creation_time >> 16) as u8);
        header.push((creation_time >> 8) as u8);
        header.push((creation_time >> 0) as u8);

        // Algorithm.
        header.push(self.pk_algo().into());

        hash.update(&header[..]);

        // MPIs.
        self.mpis().hash(hash);
    }
}

impl Hash for Signature {
    /// Adds the `Signature` to the provided hash context.
    fn hash(&self, hash: &mut Context) {
        match self {
            Signature::V4(sig) => sig.hash(hash),
        }
    }
}

impl Hash for Signature4 {
    /// Adds the `Signature` to the provided hash context.
    fn hash(&self, hash: &mut Context) {
        self.fields.hash(hash);
    }
}

impl Hash for signature::Builder {
    /// Adds the `Signature` to the provided hash context.
    fn hash(&self, hash: &mut Context) {
        // A version 4 signature packet is laid out as follows:
        //
        //   version - 1 byte                    \
        //   type - 1 byte                        \
        //   pk_algo - 1 byte                      \
        //   hash_algo - 1 byte                      Included in the hash
        //   hashed_area_len - 2 bytes (big endian)/
        //   hashed_area                         _/
        //   ...                                 <- Not included in the hash

        let mut header = [0u8; 6];

        // Version.
        header[0] = 4;
        header[1] = self.typ().into();
        header[2] = self.pk_algo().into();
        header[3] = self.hash_algo().into();

        // The length of the hashed area, as a 16-bit endian number.
        let len = self.hashed_area().data.len();
        header[4] = (len >> 8) as u8;
        header[5] = len as u8;

        hash.update(&header[..]);

        hash.update(&self.hashed_area().data[..]);

        // A version 4 signature trailer is:
        //
        //   version - 1 byte
        //   0xFF (constant) - 1 byte
        //   amount - 4 bytes (big endian)
        //
        // The amount field is the amount of hashed from this
        // packet (this excludes the message content, and this
        // trailer).
        //
        // See https://tools.ietf.org/html/rfc4880#section-5.2.4
        let mut trailer = [0u8; 6];

        trailer[0] = 0x4;
        trailer[1] = 0xff;
        // The signature packet's length, not including the previous
        // two bytes and the length.
        let len = header.len() + self.hashed_area().data.len();
        trailer[2] = (len >> 24) as u8;
        trailer[3] = (len >> 16) as u8;
        trailer[4] = (len >> 8) as u8;
        trailer[5] = len as u8;

        hash.update(&trailer[..]);
    }
}

/// Hashing-related functionality.
impl Signature {
    /// Computes the message digest of standalone signatures.
    pub fn standalone_hash<'a, S>(sig: S) -> Result<Vec<u8>>
        where S: Into<&'a signature::Builder>
    {
        let sig = sig.into();
        let mut h = sig.hash_algo().context()?;

        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Computes the message digest of timestamp signatures.
    pub fn timestamp_hash<'a, S>(sig: S) -> Result<Vec<u8>>
        where S: Into<&'a signature::Builder>
    {
        Self::standalone_hash(sig)
    }

    /// Returns the message digest of the primary key binding over the
    /// specified primary key.
    pub fn primary_key_binding_hash<'a, S>(sig: S, key: &key::PublicKey)
        -> Result<Vec<u8>>
        where S: Into<&'a signature::Builder>
    {

        let sig = sig.into();
        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Returns the message digest of the subkey binding over the
    /// specified primary key and subkey.
    pub fn subkey_binding_hash<'a, P, S>(sig: S,
                                         key: &key::PublicKey,
                                         subkey: &Key<P, key::SubordinateRole>)
        -> Result<Vec<u8>>
        where P: key::KeyParts,
              S: Into<&'a signature::Builder>
    {

        let sig = sig.into();
        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        subkey.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Returns the message digest of the user ID binding over the
    /// specified primary key, user ID, and signature.
    pub fn userid_binding_hash<'a, S>(sig: S,
                                      key: &key::PublicKey,
                                      userid: &UserID)
        -> Result<Vec<u8>>
        where S: Into<&'a signature::Builder>
    {
        let sig = sig.into();
        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        userid.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }

    /// Returns the message digest of the user attribute binding over
    /// the specified primary key, user attribute, and signature.
    pub fn user_attribute_binding_hash<'a, S>(sig: S,
                                              key: &key::PublicKey,
                                              ua: &UserAttribute)
        -> Result<Vec<u8>>
        where S: Into<&'a signature::Builder>
    {

        let sig = sig.into();
        let mut h = sig.hash_algo().context()?;

        key.hash(&mut h);
        ua.hash(&mut h);
        sig.hash(&mut h);

        let mut digest = vec![0u8; h.digest_size()];
        h.digest(&mut digest);
        Ok(digest)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::TPK;
    use crate::parse::Parse;

    #[test]
    fn hash_verification() {
        fn check(tpk: TPK) -> (usize, usize, usize) {
            let mut userid_sigs = 0;
            for (i, binding) in tpk.userids().enumerate() {
                for selfsig in binding.self_signatures() {
                    let h = Signature::userid_binding_hash(
                        selfsig,
                        tpk.primary(),
                        binding.userid()).unwrap();
                    if &h[..2] != selfsig.hash_prefix() {
                        eprintln!("{:?}: {:?} / {:?}",
                                  i, binding.userid(), selfsig);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(&h[..2], selfsig.hash_prefix());
                    userid_sigs += 1;
                }
            }
            let mut ua_sigs = 0;
            for (i, binding) in tpk.user_attributes().enumerate() {
                for selfsig in binding.self_signatures() {
                    let h = Signature::user_attribute_binding_hash(
                        selfsig,
                        tpk.primary(),
                        binding.user_attribute()).unwrap();
                    if &h[..2] != selfsig.hash_prefix() {
                        eprintln!("{:?}: {:?} / {:?}",
                                  i, binding.user_attribute(), selfsig);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(&h[..2], selfsig.hash_prefix());
                    ua_sigs += 1;
                }
            }
            let mut subkey_sigs = 0;
            for (i, binding) in tpk.subkeys().enumerate() {
                for selfsig in binding.self_signatures() {
                    let h = Signature::subkey_binding_hash(
                        selfsig,
                        tpk.primary(),
                        binding.key()).unwrap();
                    if &h[..2] != selfsig.hash_prefix() {
                        eprintln!("{:?}: {:?}", i, binding);
                        eprintln!("  Hash: {:?}", h);
                    }
                    assert_eq!(h[0], selfsig.hash_prefix()[0]);
                    assert_eq!(h[1], selfsig.hash_prefix()[1]);
                    subkey_sigs += 1;
                }
            }

            (userid_sigs, ua_sigs, subkey_sigs)
        }

        check(TPK::from_bytes(crate::tests::key("hash-algos/SHA224.gpg")).unwrap());
        check(TPK::from_bytes(crate::tests::key("hash-algos/SHA256.gpg")).unwrap());
        check(TPK::from_bytes(crate::tests::key("hash-algos/SHA384.gpg")).unwrap());
        check(TPK::from_bytes(crate::tests::key("hash-algos/SHA512.gpg")).unwrap());
        check(TPK::from_bytes(crate::tests::key("bannon-all-uids-subkeys.gpg")).unwrap());
        let (_userid_sigs, ua_sigs, _subkey_sigs)
            = check(TPK::from_bytes(crate::tests::key("dkg.gpg")).unwrap());
        assert!(ua_sigs > 0);
    }
}
