//! Streaming packet serialization.

use std::fmt;
use std::io::{self, Write};
use nettle::{Hash, Yarrow};

use {
    Error,
    SymmetricAlgorithm,
    HashAlgorithm,
    Literal,
    MDC,
    OnePassSig,
    PKESK,
    Result,
    SKESK,
    Signature,
    Tag,
    TPK,
};
use ctb::CTB;
use packet::BodyLength;
use super::{
    PartialBodyFilter,
    Serialize,
    writer,
};
use constants::{
    CompressionAlgorithm,
};

/// Cookie must be public because the writers are.
#[doc(hidden)]
#[derive(Debug)]
pub struct Cookie {
    level: usize,
    private: Private,
}

#[derive(Debug)]
enum Private {
    Nothing,
    Signer,
}

impl Cookie {
    fn new(level: usize) -> Self {
        Cookie {
            level: level,
            private: Private::Nothing,
        }
    }
}

/// Wraps a `std::io::Write`r for use with the streaming subsystem.
///
/// XXX: This interface will likely change.
pub fn wrap<'a, W: 'a + io::Write>(w: W) -> writer::Stack<'a, Cookie> {
    writer::Generic::new(w, Cookie::new(0))
}


/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
///
/// # Example
///
/// ```
/// use openpgp::Tag;
/// use openpgp::serialize::stream::{wrap, ArbitraryWriter};
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let mut o = vec![];
/// {
///     let mut w = ArbitraryWriter::new(wrap(&mut o), Tag::Literal)?;
///     w.write_all(b"t")?;                   // type
///     w.write_all(b"\x00")?;                // filename length
///     w.write_all(b"\x00\x00\x00\x00")?;    // date
///     w.write_all(b"Hello world.")?;        // body
/// }
/// assert_eq!(b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.", o.as_slice());
/// # Ok(())
/// # }
pub struct ArbitraryWriter<'a> {
    inner: writer::Stack<'a, Cookie>,
}

impl<'a> ArbitraryWriter<'a> {
    /// Creates a new writer with the given tag.
    pub fn new(mut inner: writer::Stack<'a, Cookie>, tag: Tag)
               -> Result<writer::Stack<'a, Cookie>> {
        let level = inner.cookie_ref().level + 1;
        CTB::new(tag).serialize(&mut inner)?;
        Ok(Box::new(ArbitraryWriter {
            inner: PartialBodyFilter::new(inner, Cookie::new(level))
        }))
    }
}

impl<'a> fmt::Debug for ArbitraryWriter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ArbitraryWriter")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> Write for ArbitraryWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> writer::Stackable<'a, Cookie> for ArbitraryWriter<'a> {
    fn into_inner(self: Box<Self>) -> Result<Option<writer::Stack<'a, Cookie>>> {
        Box::new(self.inner).into_inner()
    }
    fn pop(&mut self) -> Result<Option<writer::Stack<'a, Cookie>>> {
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::Stack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        self.inner.inner_ref()
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        self.inner.inner_mut()
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        self.inner.cookie_mut()
    }
}

/// Signs a packet stream.
///
/// Writes a one-pass-signature packet, then hashes the data stream,
/// then writes a signature packet.
pub struct Signer<'a> {
    // The underlying writer.
    //
    // Because this writer implements `Drop`, we cannot move the inner
    // writer out of this writer.  We therefore wrap it with `Option`
    // so that we can `take()` it.
    //
    // Furthermore, the LiteralWriter will pop us off the stack, and
    // take our inner reader.  If that happens, we only update the
    // digests.
    inner: Option<writer::Stack<'a, Cookie>>,
    signature: Signature,
    hashes: Vec<(HashAlgorithm, Box<Hash>)>,
    cookie: Cookie,
}

impl<'a> Signer<'a> {
    /// Creates a writer.
    ///
    /// XXX: Currently, the writer depends on a template to create the
    /// signature, because we cannot compute signatures yet.
    pub fn new(mut inner: writer::Stack<'a, Cookie>, template: &Signature)
               -> Result<writer::Stack<'a, Cookie>> {
        let n = 1;  // XXX generalize
        let mut algos = Vec::new();
        // First, construct and serialize an one pass signature
        // packet.
        let mut ops = OnePassSig::new(template.sigtype)
            .pk_algo(template.pk_algo)
            .hash_algo(template.hash_algo)
            .issuer(template.issuer_fingerprint().unwrap() // XXX
                    .to_keyid());
        ops.last = 1;
        ops.serialize(&mut inner)?;
        algos.push(HashAlgorithm::from(template.hash_algo));

        let mut hashes = Vec::with_capacity(n);
        for algo in algos {
            hashes.push((algo, algo.context()?));
        }
        // xxx: sort hashes
        let level = inner.cookie_ref().level + 1;
        Ok(Box::new(Signer {
            inner: Some(inner),
            signature: template.clone(),
            hashes: hashes,
            cookie: Cookie {
                level: level,
                private: Private::Signer,
            },
        }))
    }

    fn emit_signatures(&mut self) -> Result<()> {
        if let Private::Signer = self.cookie.private {
            let (_, ref mut hash) = self.hashes[0];	// xxx clone hash

            // A version 4 signature packet is laid out as follows:
            //
            //   version - 1 byte                    \
            //   sigtype - 1 byte                     \
            //   pk_algo - 1 byte                      \
            //   hash_algo - 1 byte                      Included in the hash
            //   hashed_area_len - 2 bytes (big endian)/
            //   hashed_area                         _/
            //   ...                                 <- Not included in the hash
            let header: [ u8; 6 ] = [
                self.signature.version,
                self.signature.sigtype.into(),
                self.signature.pk_algo.into(),
                self.signature.hash_algo.into(),
                ((self.signature.hashed_area.data.len() >> 8) & 0xff) as u8,
                ((self.signature.hashed_area.data.len() >> 0) & 0xff) as u8,
            ];
            hash.update(&header);
            hash.update(&self.signature.hashed_area.data);

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
            let header_amount = 6 + self.signature.hashed_area.data.len();
            let trailer: [ u8; 6 ] = [
                0x04,
                0xFF,
                ((header_amount >> 24) & 0xff) as u8,
                ((header_amount >> 16) & 0xff) as u8,
                ((header_amount >>  8) & 0xff) as u8,
                ((header_amount >>  0) & 0xff) as u8
            ];
            hash.update(&trailer);

            let mut digest = vec![0u8; hash.digest_size()];
            hash.digest(&mut digest);

            self.signature.hash_prefix[0] = digest[0];
            self.signature.hash_prefix[1] = digest[1];

            if let Some(ref mut w) = self.inner {
                self.signature.serialize(w)
            } else {
                Ok(())
            }
        } else {
            panic!("bad cookie")
        }
    }
}

impl<'a> Drop for Signer<'a> {
    fn drop(&mut self) {
        let _ = self.emit_signatures();
    }
}

impl<'a> fmt::Debug for Signer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Signer")
            .field("inner", &self.inner)
            .field("cookie", &self.cookie)
            .finish()
    }
}

impl<'a> Write for Signer<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = match self.inner.as_mut() {
            Some(ref mut w) => w.write(buf),
            // When we are popped off the stack, we have no inner
            // writer.  Just hash all bytes.
            None => Ok(buf.len()),
        };

        if let Ok(amount) = written {
            for &mut (_, ref mut h) in self.hashes.iter_mut() {
                h.update(&buf[..amount]);
            }
        }

        written
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(ref mut w) => w.flush(),
            // When we are popped off the stack, we have no inner
            // writer.  Just do nothing.
            None => Ok(()),
        }
    }
}

impl<'a> writer::Stackable<'a, Cookie> for Signer<'a> {
    fn pop(&mut self) -> Result<Option<writer::Stack<'a, Cookie>>> {
        Ok(self.inner.take())
    }
    fn mount(&mut self, new: writer::Stack<'a, Cookie>) {
        self.inner = Some(new);
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        if let Some(ref i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn into_inner(mut self: Box<Self>)
                  -> Result<Option<writer::Stack<'a, Cookie>>> {
        self.emit_signatures()?;
        Ok(self.inner.take())
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        ::std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        &mut self.cookie
    }
}


/// Writes a literal data packet.
///
/// The body will be written using partial length encoding, or, if the
/// body is short, using full length encoding.
///
/// # Example
///
/// ```
/// use openpgp::serialize::stream::{wrap, LiteralWriter};
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let mut o = vec![];
/// {
///     let mut w = LiteralWriter::new(wrap(&mut o), 't', None, 0)?;
///     w.write_all(b"Hello world.")?;
/// }
/// assert_eq!(b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.", o.as_slice());
/// # Ok(())
/// # }
/// ```
pub struct LiteralWriter<'a> {
    inner: writer::Stack<'a, Cookie>,
    signature_writer: Option<writer::Stack<'a, Cookie>>,
}

impl<'a> LiteralWriter<'a> {
    /// Creates a new literal writer.
    pub fn new(mut inner: writer::Stack<'a, Cookie>,
               format: char, filename: Option<&[u8]>, date: u32)
               -> Result<writer::Stack<'a, Cookie>> {
        let level = inner.cookie_ref().level + 1;

        let mut template = Literal::new(format).date(date);

        if let Some(f) = filename {
            template = template.filename_from_bytes(f);
        }

        // For historical reasons, signatures over literal data
        // packets only include the body without metadata or framing.
        // Therefore, we check whether the writer is a
        // Signer, and if so, we pop it off the stack and
        // store it in 'self.signature_writer'.
        let signer_above =
            if let &Cookie {
                private: Private::Signer{..},
                ..
            } = inner.cookie_ref() {
                true
            } else {
                false
            };

        let mut signature_writer = None;
        if signer_above {
            let stack = inner.pop()?;
            // We know a signer has an inner stackable.
            let stack = stack.unwrap();
            signature_writer = Some(inner);
            inner = stack;
        }

        // Not hashed by the signature_writer (see above).
        CTB::new(Tag::Literal).serialize(&mut inner)?;

        // Neither is any framing added by the PartialBodyFilter.
        let mut inner
            = PartialBodyFilter::new(inner, Cookie::new(level));

        // Nor the headers.
        template.serialize_headers(&mut inner, false)?;

        Ok(Box::new(Self {
            inner: inner,
            signature_writer: signature_writer,
        }))
    }
}

impl<'a> fmt::Debug for LiteralWriter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LiteralWriter")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> Write for LiteralWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf);

        // Any successful written bytes needs to be hashed too.
        if let (&Ok(ref amount), &mut Some(ref mut sig))
            = (&written, &mut self.signature_writer) {
                sig.write_all(&buf[..*amount])?;
            };
        written
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> writer::Stackable<'a, Cookie> for LiteralWriter<'a> {
    fn into_inner(mut self: Box<Self>)
                  -> Result<Option<writer::Stack<'a, Cookie>>> {
        let signer = self.signature_writer.take();
        let stack = self.inner
            .into_inner()?.unwrap(); // Peel off the PartialBodyFilter.

        if let Some(mut signer) = signer {
            // We stashed away a Signer.  Reattach it to the
            // stack and return it.
            signer.mount(stack);
            Ok(Some(signer))
        } else {
            Ok(Some(stack))
        }
    }

    fn pop(&mut self) -> Result<Option<writer::Stack<'a, Cookie>>> {
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::Stack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        self.inner.inner_ref()
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        self.inner.inner_mut()
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        self.inner.cookie_mut()
    }
}

/// Compresses a packet stream.
///
/// Writes a compressed data packet containing all packets written to
/// this writer.
///
/// # Example
///
/// ```
/// use openpgp::serialize::stream::{wrap, Compressor, LiteralWriter};
/// use openpgp::CompressionAlgorithm;
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let mut o = vec![];
/// {
///     let w = Compressor::new(wrap(&mut o),
///                             CompressionAlgorithm::Uncompressed)?;
///     let mut w = LiteralWriter::new(w, 't', None, 0)?;
///     w.write_all(b"Hello world.")?;
/// }
/// assert_eq!(b"\xc8\x15\x00\xcb\x12t\x00\x00\x00\x00\x00Hello world.",
///            o.as_slice());
/// # Ok(())
/// # }
pub struct Compressor<'a> {
    inner: writer::Stack<'a, Cookie>,
}

impl<'a> Compressor<'a> {
    /// Creates a new compressor using the given algorithm.
    pub fn new(mut inner: writer::Stack<'a, Cookie>, algo: CompressionAlgorithm)
               -> Result<writer::Stack<'a, Cookie>> {
        let level = inner.cookie_ref().level + 1;

        // Packet header.
        CTB::new(Tag::CompressedData).serialize(&mut inner)?;

        let mut inner: writer::Stack<'a, Cookie>
            = PartialBodyFilter::new(inner, Cookie::new(level));

        // Compressed data header.
        inner.write_u8(algo.into())?;

        // Create an appropriate filter.
        let inner: writer::Stack<'a, Cookie> = match algo {
            CompressionAlgorithm::Uncompressed =>
                writer::Identity::new(inner, Cookie::new(level)),
            CompressionAlgorithm::Zip =>
                writer::ZIP::new(inner, Cookie::new(level)),
            CompressionAlgorithm::Zlib =>
                writer::ZLIB::new(inner, Cookie::new(level)),
            CompressionAlgorithm::BZip2 =>
                writer::BZ::new(inner, Cookie::new(level)),
            _ => unimplemented!(),
        };

        Ok(Box::new(Self{inner: inner}))
    }
}

impl<'a> fmt::Debug for Compressor<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Compressor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> io::Write for Compressor<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a> writer::Stackable<'a, Cookie> for Compressor<'a> {
    fn into_inner(self: Box<Self>) -> Result<Option<writer::Stack<'a, Cookie>>> {
        Box::new(self.inner).into_inner()?.unwrap().into_inner()
    }
    fn pop(&mut self) -> Result<Option<writer::Stack<'a, Cookie>>> {
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::Stack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        self.inner.inner_ref()
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        self.inner.inner_mut()
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.inner.cookie_set(cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        self.inner.cookie_ref()
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        self.inner.cookie_mut()
    }
}

/// Encrypts a packet stream.
pub struct Encryptor<'a> {
    inner: Option<writer::Stack<'a, Cookie>>,
    hash: Box<Hash>,
    cookie: Cookie,
}

/// Specifies whether to encrypt for archival purposes or for
/// transport.
pub enum EncryptionMode {
    /// Encrypt data for long-term storage.
    ///
    /// This should be used for things that should be decryptable for
    /// a long period of time, e.g. backups, archives, etc.
    AtRest,

    /// Encrypt data for transport.
    ///
    /// This should be used to protect a message in transit.  The
    /// recipient is expected to take additional steps if she wants to
    /// be able to decrypt it later on, e.g. store the decrypted
    /// session key, or re-encrypt the session key with a different
    /// key.
    ForTransport,
}

impl<'a> Encryptor<'a> {
    /// Creates a new encryptor.
    ///
    /// The stream will be encrypted using a generated session key,
    /// which will be encrypted using the given passwords, and all
    /// encryption-capable subkeys of the given TPKs.
    ///
    /// The stream is encrypted using AES256, regardless of any key
    /// preferences.
    ///
    /// # Example
    ///
    /// ```
    /// #[macro_use] extern crate openpgp; // For armored!
    /// use openpgp::serialize::stream::{
    ///     wrap, Encryptor, EncryptionMode, LiteralWriter,
    /// };
    /// # use openpgp::Result;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// let tpk = openpgp::TPK::from_reader(armored!(
    /// #   &( // We do some acrobatics here to abbreviate the TPK.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
    /// #    ".to_owned() /*
    ///      ...
    /// #    */ +"
    /// #    VGQs6IHLq70mAizBJ4VznUVqVOh/NhOlapXi6/TKpjHvttdg45o6Pgqa0Kx64luT
    /// #    ZY+TEKyILcdBdhr3CzsEILnQst5jadgMvU9fnT/EkJIvxtWPlUzU5R7nnALO626x
    /// #    2M5Pj3k0h3ZNHMmYQQtReX/RP/xUh2SfOYG6i/MCclIlee8BXHB9k0bW2NAX2W7H
    /// #    rLDGPm1LzmyqxFGDvDvfPlYZ5nN2cbGsv3w75LDzv75kMhVnkZsrUjnHjVRzFq7q
    /// #    fSIpxlvJMEMKSIJ/TFztQoOBO5OlBb5qzYPpABEBAAG0F+G8iM+BzrnPg8+Ezr/P
    /// #    hM6tzrvOt8+CiQFUBBMBCAA+FiEEfcpYtU6xQxad3uFfJH9tq8hJFP4FAlpxtsAC
    /// #    GwMFCQPCZwAFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQJH9tq8hJFP49hgf+
    /// #    IKvec0RkD9EHSLFc6AKDm/knaI4AIH0isZTz9jRCF8H/j3h8QVUE+/0jtCcyvR6F
    /// #    TGVSfO3pelDPYGIjDFI3aA6H/UlhZWzYRXZ+QQRrV0zwvLna3XjiW8ib3Ky+5bpQ
    /// #    0uVeee30u+U3SnaCL9QB4+UvwVvAxRuk49Z0Q8TsRrQyQNYpeZDN7uNrvA134cf6
    /// #    6pLUvzPG4lMLIvSXFuHou704EhT7NS3wAzFtjMrsLLieVqtbEi/kBaJTQSZQwjVB
    /// #    sE/Z8lp1heKw/33Br3cB63n4cTf0FdoFywDBhCAMU7fKboU5xBpm5bQJ4ck6j6w+
    /// #    BKG1FiQRR6PCUeb6GjxVOrkBDQRacbbAAQgAw538MMb/pRdpt7PTgBCedw+rU9fh
    /// #    onZYKwmCO7wz5VrVf8zIVvWKxhX6fBTSAy8mxaYbeL/3woQ9Leuo8f0PQNs9zw1N
    /// #    mdH+cnm2KQmL9l7/HQKMLgEAu/0C/q7ii/j8OMYitaMUyrwy+OzW3nCal/uJHIfj
    /// #    bdKx29MbKgF/zaBs8mhTvf/Tu0rIVNDPEicwijDEolGSGebZxdGdHJA31uayMHDK
    /// #    /mwySJViMZ8b+Lzc/dRgNbQoY6yjsjso7U9OZpQK1fooHOSQS6iLsSSsZLcGPD+7
    /// #    m7j3jwq68SIJPMsu0O8hdjFWL4Cfj815CwptAxRGkp00CIusAabO7m8DzwARAQAB
    /// #    iQE2BBgBCAAgFiEEfcpYtU6xQxad3uFfJH9tq8hJFP4FAlpxtsACGwwACgkQJH9t
    /// #    q8hJFP5rmQgAoYOUXolTiQmWipJTdMG/VZ5X7mL8JiBWAQ11K1o01cZCMlziyHnJ
    /// #    xJ6Mqjb6wAFpYBtqysJG/vfjc/XEoKgfFs7+zcuEnt41xJQ6tl/L0VTxs+tEwjZu
    /// #    Rp/owB9GCkqN9+xNEnlH77TLW1UisW+l0F8CJ2WFOj4lk9rcXcLlEdGmXfWIlVCb
    /// #    2/o0DD+HDNsF8nWHpDEy0mcajkgIUTvXQaDXKbccX6Wgep8dyBP7YucGmRPd9Z6H
    /// #    bGeT3KvlJlH5kthQ9shsmT14gYwGMR6rKpNUXmlpetkjqUK7pGVaHGgJWUZ9QPGU
    ///      awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    ///      =lAie
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// # )
    /// )).unwrap();
    /// let mut o = vec![];
    /// let encryptor = Encryptor::new(wrap(&mut o),
    ///                                &["совершенно секретно".as_bytes()],
    ///                                &[&tpk],
    ///                                EncryptionMode::AtRest)
    ///     .expect("Failed to create encryptor");
    /// let mut w = LiteralWriter::new(encryptor, 't', None, 0)?;
    /// w.write_all(b"Hello world.")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(mut inner: writer::Stack<'a, Cookie>,
               passwords: &[&[u8]], tpks: &[&TPK],
               encryption_mode: EncryptionMode)
               -> Result<writer::Stack<'a, Cookie>> {
        let mut rng = Yarrow::default();
        let level = inner.cookie_ref().level + 1;
        let algo = SymmetricAlgorithm::AES256;

        // Generate a session key.
        let mut sk = vec![0; algo.key_size().unwrap()];
        rng.random(&mut sk);

        // Write the PKESK packet(s).
        for tpk in tpks {
            let subkeys = tpk.subkeys().filter(|skb| {
                // The first signature is the most recent binding
                // signature.
                skb.selfsigs().next()
                    .map(|sig| match encryption_mode {
                        EncryptionMode::AtRest =>
                            sig.key_flags().can_encrypt_at_rest(),
                        EncryptionMode::ForTransport =>
                            sig.key_flags().can_encrypt_for_transport(),
                    })
                    .unwrap_or(false)
            });

            let mut count = 0;
            for key in subkeys {
                let skesk = PKESK::new(algo, &sk, key.subkey())?;
                skesk.serialize(&mut inner)?;
                count += 1;
            }

            if count == 0 {
                return Err(Error::InvalidOperation(
                    format!("Key {} has no suitable encryption subkey",
                            tpk)).into());
            }
        }

        // Write the SKESK packet(s).
        for password in passwords {
            let skesk = SKESK::new(algo, Default::default(),
                                   &sk, password).unwrap();
            skesk.serialize(&mut inner)?;
        }

        // Write the SEIP packet.
        CTB::new(Tag::SEIP).serialize(&mut inner)?;
        let mut inner: writer::Stack<'a, Cookie>
            = PartialBodyFilter::new(inner, Cookie::new(level));
        inner.write(&[1])?; // Version.

        // Assuming 'algo' is good, this cannot fail.
        let encryptor = writer::Encryptor::new(
            inner,
            Cookie::new(level),
            algo,
            &sk,
        ).unwrap();

        // The hash for the MDC must include the initialization
        // vector, hence we build the object here.
        let mut encryptor = Box::new(Self{
            inner: Some(encryptor),
            hash: HashAlgorithm::SHA1.context().unwrap(),
            cookie: Cookie::new(level),
        });

        // Write the initialization vector, and the quick-check bytes.
        let mut iv = vec![0; algo.block_size().unwrap()];
        rng.random(&mut iv);
        encryptor.write_all(&iv)?;
        encryptor.write_all(&iv[iv.len() - 2..])?;

        Ok(encryptor)
    }

    /// Emits the MDC packet and recovers the original writer.
    fn emit_mdc(&mut self) -> Result<writer::Stack<'a, Cookie>> {
        if let Some(mut w) = self.inner.take() {
            // Write the MDC, which must be the last packet inside the
            // encrypted packet stream.  The hash includes the MDC's
            // CTB and length octet.
            let mut header = Vec::new();
            CTB::new(Tag::MDC).serialize(&mut header)?;
            BodyLength::Full(20).serialize(&mut header)?;

            self.hash.update(&header);
            MDC::new(&mut self.hash).serialize(&mut w)?;

            // Now recover the original writer.  First, strip the
            // Encryptor.
            let mut w = w.into_inner()?.unwrap();
            // And the partial body filter.
            let mut w = w.into_inner()?.unwrap();

            Ok(w)
        } else {
            Err(Error::InvalidOperation(
                "Inner writer already taken".into()).into())
        }
    }
}

impl<'a> Drop for Encryptor<'a> {
    fn drop(&mut self) {
        let _ = self.emit_mdc();
    }
}

impl<'a> fmt::Debug for Encryptor<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Encryptor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a> Write for Encryptor<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = match self.inner.as_mut() {
            Some(ref mut w) => w.write(buf),
            None => Ok(buf.len()),
        };
        if let Ok(amount) = written {
            self.hash.update(&buf[..amount]);
        }
        written
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(ref mut w) => w.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> writer::Stackable<'a, Cookie> for Encryptor<'a> {
    fn pop(&mut self) -> Result<Option<writer::Stack<'a, Cookie>>> {
        unimplemented!()
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::Stack<'a, Cookie>) {
        unimplemented!()
    }
    fn inner_ref(&self) -> Option<&writer::Stackable<'a, Cookie>> {
        if let Some(ref i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_mut(&mut self) -> Option<&mut writer::Stackable<'a, Cookie>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn into_inner(mut self: Box<Self>) -> Result<Option<writer::Stack<'a, Cookie>>> {
        Ok(Some(self.emit_mdc()?))
    }
    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        ::std::mem::replace(&mut self.cookie, cookie)
    }
    fn cookie_ref(&self) -> &Cookie {
        &self.cookie
    }
    fn cookie_mut(&mut self) -> &mut Cookie {
        &mut self.cookie
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use super::super::{Message, Packet, CompressedData};
    use super::super::parse::PacketParser;
    use super::*;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../tests/data/messages/", $x)) };
    }

    #[test]
    fn arbitrary() {
        let mut o = vec![];
        {
            let mut ustr = ArbitraryWriter::new(wrap(&mut o), Tag::Literal).unwrap();
            ustr.write_all(b"t").unwrap(); // type
            ustr.write_all(b"\x00").unwrap(); // fn length
            ustr.write_all(b"\x00\x00\x00\x00").unwrap(); // date
            ustr.write_all(b"Hello world.").unwrap(); // body
        }

        let mut pp = PacketParser::from_bytes(&o).unwrap().unwrap();
        if let Packet::Literal(ref l) = pp.packet {
                assert_eq!(l.format, 't' as u8);
                assert_eq!(l.filename, None);
                assert_eq!(l.date, 0);
        } else {
            panic!("Unexpected packet type.");
        }

        let mut body = vec![];
        pp.read_to_end(&mut body).unwrap();
        assert_eq!(&body, b"Hello world.");

        // Make sure it is the only packet.
        let (_packet, _packet_depth, tmp, _pp_depth)
            = pp.recurse().unwrap();
        assert!(tmp.is_none());
    }

    // Create some crazy nesting structures, serialize the messages,
    // reparse them, and make sure we get the same result.
    #[test]
    fn stream_0() {
        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "one (3 bytes)" })
        //  2: Literal(Literal { body: "two (3 bytes)" })
        // 2: Literal(Literal { body: "three (5 bytes)" })
        let mut reference = Vec::new();
        reference.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(Literal::new('t').body(b"one".to_vec()).to_packet())
                .push(Literal::new('t').body(b"two".to_vec()).to_packet())
                .to_packet());
        reference.push(Literal::new('t').body(b"three".to_vec()).to_packet());

        let mut o = vec![];
        {
            let c = Compressor::new(
                wrap(&mut o), CompressionAlgorithm::Uncompressed).unwrap();
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            write!(ls, "one").unwrap();
            let c = ls.into_inner().unwrap().unwrap(); // Pop the LiteralWriter.
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            write!(ls, "two").unwrap();
            let c = ls.into_inner().unwrap().unwrap(); // Pop the LiteralWriter.
            let c = c.into_inner().unwrap().unwrap(); // Pop the Compressor.
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            write!(ls, "three").unwrap();
        }

        let m = Message::from_packets(reference);
        let m2 = Message::from_bytes(&o).unwrap();
        if m != m2 {
            eprintln!("REFERENCE...");
            m.pretty_print();
            eprintln!("REPARSED...");
            m2.pretty_print();
            panic!("Reparsed packet does not match reference packet!");
        }
    }

    // Create some crazy nesting structures, serialize the messages,
    // reparse them, and make sure we get the same result.
    #[test]
    fn stream_1() {
        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "one (3 bytes)" })
        //   2: Literal(Literal { body: "two (3 bytes)" })
        //  2: CompressedData(CompressedData { algo: 0 })
        //   1: Literal(Literal { body: "three (5 bytes)" })
        //   2: Literal(Literal { body: "four (4 bytes)" })
        let mut reference = Vec::new();
        reference.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(Literal::new('t').body(b"one".to_vec()).to_packet())
                      .push(Literal::new('t').body(b"two".to_vec()).to_packet())
                      .to_packet())
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(Literal::new('t').body(b"three".to_vec()).to_packet())
                      .push(Literal::new('t').body(b"four".to_vec()).to_packet())
                      .to_packet())
                .to_packet());

        let mut o = vec![];
        {
            let c0 = Compressor::new(
                wrap(&mut o), CompressionAlgorithm::Uncompressed).unwrap();
            let c = Compressor::new(
                c0, CompressionAlgorithm::Uncompressed).unwrap();
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            write!(ls, "one").unwrap();
            let c = ls.into_inner().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            write!(ls, "two").unwrap();
            let c = ls.into_inner().unwrap().unwrap();
            let c0 = c.into_inner().unwrap().unwrap();
            let c = Compressor::new(
                c0, CompressionAlgorithm::Uncompressed).unwrap();
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            write!(ls, "three").unwrap();
            let c = ls.into_inner().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            write!(ls, "four").unwrap();
        }

        let m = Message::from_packets(reference);
        let m2 = Message::from_bytes(&o).unwrap();
        if m != m2 {
            eprintln!("REFERENCE...");
            m.pretty_print();
            eprintln!("REPARSED...");
            m2.pretty_print();
            panic!("Reparsed packet does not match reference packet!");
        }
    }

    #[test]
    fn stream_big() {
        let mut zeros = Vec::<u8>::new();
        zeros.resize(4 * 1024, 0);
        let mut o = vec![];
        {
            let c = Compressor::new(wrap(&mut o),
                                    CompressionAlgorithm::BZip2).unwrap();
            let mut ls = LiteralWriter::new(c, 't', None, 0).unwrap();
            // Write 64 megabytes of zeroes.
            for _ in 0 .. 16 * 1024 {
                ls.write_all(&zeros).unwrap();
            }
        }
        assert!(o.len() < 100);
    }

    #[test]
    fn signature() {
        // signed-1.gpg contains: [ one-pass-sig ][ literal ][ signature ].
        let (mut one_pass_sig, mut literal, mut signature) = (None, None, None);
        let mut ppo = PacketParser::from_bytes(bytes!("signed-1.gpg")).unwrap();
        while let Some(mut pp) = ppo {
            pp.buffer_unread_content().unwrap();
            // Get the packet.
            let (packet, _packet_depth, tmp, _pp_depth) = pp.next().unwrap();
            match packet {
                Packet::Literal(l) => literal = Some(l),
                Packet::OnePassSig(o) => one_pass_sig = Some(o),
                Packet::Signature(s) => signature = Some(s),
                _ => unreachable!(),
            };
            // Next?
            ppo = tmp;
        }
        let (one_pass_sig, literal, signature)
            = (one_pass_sig.unwrap(), literal.unwrap(), signature.unwrap());

        let mut signature_blinded = signature.clone();
        signature_blinded.hash_prefix = [0, 0];
        let mut o = vec![];
        {
            let c = Signer::new(wrap(&mut o), &signature_blinded)
                .unwrap();
            let mut ls = LiteralWriter::new(
                c, literal.format as char, literal.filename.as_ref().map(|f| f.as_slice()),
                literal.date).unwrap();
            ls.write_all(literal.common.body.as_ref().unwrap()).unwrap();
        }

        let mut ppo = PacketParser::from_bytes(&o).unwrap();
        while let Some(mut pp) = ppo {
            pp.buffer_unread_content().unwrap();
            // Get the packet.
            let (packet, _packet_depth, tmp, _pp_depth) = pp.next().unwrap();
            match packet {
                Packet::Literal(l) => assert_eq!(l, literal),
                Packet::OnePassSig(o) => assert_eq!(o, one_pass_sig),
                Packet::Signature(s) => assert_eq!(s, signature),
                _ => unreachable!(),
            };
            // Next?
            ppo = tmp;
        }
    }

    #[test]
    fn encryptor() {
        let passwords = ["streng geheim".as_bytes(),
                         "top secret".as_bytes()];
        let message = b"Hello world.";

        // Write a simple encrypted message...
        let mut o = vec![];
        {
            let encryptor = Encryptor::new(wrap(&mut o), &passwords, &[],
                                           EncryptionMode::ForTransport)
                .unwrap();
            let mut literal = LiteralWriter::new(encryptor, 'b', None, 0)
                .unwrap();
            literal.write_all(message).unwrap();
        }

        // ... and recover it...
        #[derive(Debug, PartialEq)]
        enum State {
            Start,
            Decrypted(Vec<(u8, Vec<u8>)>),
            Deciphered,
            MDC,
            Done,
        }

        // ... with every password.
        for password in &passwords {
            let mut state = State::Start;
            let mut ppo = PacketParser::from_bytes(&o).unwrap();
            while let Some(mut pp) = ppo {
                state = match state {
                    // Look for the SKESK packet.
                    State::Start =>
                        if let Packet::SKESK(ref skesk) = pp.packet {
                            match skesk.decrypt(password) {
                                Ok((algo, key))
                                    => State::Decrypted(
                                        vec![(algo.into(), key)]),
                                Err(e) =>
                                    panic!("Decryption failed: {}", e),
                            }
                        } else {
                            panic!("Unexpected packet: {:?}", pp.packet)
                        },

                    // Look for the SEIP packet.
                    State::Decrypted(mut keys) =>
                        match pp.packet {
                            Packet::SEIP(_) =>
                                loop {
                                    if let Some((algo, key)) = keys.pop() {
	                                let r = pp.decrypt(algo.into(),
                                                           &key[..]);
                                        if r.is_ok() {
                                            break State::Deciphered;
                                        }
                                    } else {
                                        panic!("seip decryption failed");
                                    }
                                },
                            Packet::SKESK(ref skesk) =>
                                match skesk.decrypt(password) {
                                    Ok((algo, key)) => {
                                        keys.push((algo.into(), key));
                                        State::Decrypted(keys)
                                    },
                                    Err(e) =>
                                        panic!("Decryption failed: {}", e),
                                },
                            _ =>
                                panic!("Unexpected packet: {:?}", pp.packet),
                        },

                    // Look for the literal data packet.
                    State::Deciphered =>
                        if let Packet::Literal(_) = pp.packet {
                            let mut body = Vec::new();
                            pp.read_to_end(&mut body).unwrap();
                            assert_eq!(&body, message);
                            State::MDC
                        } else {
                            panic!("Unexpected packet: {:?}", pp.packet)
                        },

                    // Look for the MDC packet.
                    State::MDC =>
                        if let Packet::MDC(ref mdc) = pp.packet {
                            assert_eq!(mdc.hash, mdc.computed_hash);
                            State::Done
                        } else {
                            panic!("Unexpected packet: {:?}", pp.packet)
                        },

                    State::Done =>
                        panic!("Unexpected packet: {:?}", pp.packet),
                };

                // Next?
                let (_, _, tmp, _) = pp.recurse().unwrap();
                ppo = tmp;
            }
            assert_eq!(state, State::Done);
        }
    }
}
