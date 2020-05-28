//! Streaming packet serialization.
//!
//! This interface provides a convenient way to create signed and/or
//! encrypted OpenPGP messages (see [Section 11.3 of RFC 4880]) and is
//! the preferred interface to generate messages using Sequoia.  It
//! takes advantage of OpenPGP's streaming nature to avoid unnecessary
//! buffering.
//!
//!   [Section 11.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.3
//!
//! To use this interface, a sink implementing [`io::Write`] is
//! wrapped by [`Message::new`] returning a streaming [`Message`].
//! The writer stack is a structure to compose filters that create the
//! desired message structure.  There are a number of filters that can
//! be freely combined:
//!
//!   - [`Armorer`] applies ASCII-Armor to the stream,
//!   - [`Encryptor`] encrypts data fed into it,
//!   - [`Compressor`] compresses data,
//!   - [`Padder`] pads data,
//!   - [`Signer`] signs data,
//!   - [`LiteralWriter`] wraps literal data (i.e. the payload) into
//!     a literal data packet,
//!   - and finally, [`ArbitraryWriter`] can be used to create
//!     arbitrary packets for testing purposes.
//!
//!   [`io::Write`]: https://doc.rust-lang.org/nightly/std/io/trait.Write.html
//!   [`Message::new`]: struct.Message.html#method.new
//!   [`Message`]: struct.Message.html
//!   [`Armorer`]: struct.Armorer.html
//!   [`Encryptor`]: struct.Encryptor.html
//!   [`Compressor`]: struct.Compressor.html
//!   [`Padder`]: padding/struct.Padder.html
//!   [`Signer`]: struct.Signer.html
//!   [`LiteralWriter`]: struct.LiteralWriter.html
//!   [`ArbitraryWriter`]: struct.ArbitraryWriter.html
//!
//! The most common structure is an encrypted, compressed, and signed
//! message.  This structure is [supported] by all OpenPGP
//! implementations.  See the example below on how to create this
//! structure.
//!
//!   [supported]: https://tests.sequoia-pgp.org/#Unusual_Message_Structure
//!
//! # Examples
//!
//! This example demonstrates how to create the simplest possible
//! OpenPGP message (see [Section 11.3 of RFC 4880]) containing just a
//! literal data packet (see [Section 5.9 of RFC 4880]):
//!
//!   [Section 5.9 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.9
//!
//! ```
//! # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
//! use std::io::Write;
//! use sequoia_openpgp as openpgp;
//! use openpgp::serialize::stream::{Message, LiteralWriter};
//!
//! let mut sink = vec![];
//! {
//!     let message = Message::new(&mut sink);
//!     let mut message = LiteralWriter::new(message).build()?;
//!     message.write_all(b"Hello world.")?;
//!     message.finalize()?;
//! }
//! assert_eq!(b"\xcb\x12b\x00\x00\x00\x00\x00Hello world.", sink.as_slice());
//! # Ok(()) }
//! ```
//!
//! This example demonstrates how to create the most common OpenPGP
//! message structure (see [Section 11.3 of RFC 4880]).  The plaintext
//! is first signed, then compressed, encrypted, and finally ASCII
//! armored.  Our example pads the plaintext instead of compressing
//! it, but the resulting message structure is the same.
//!
//! ```
//! # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
//! use std::io::Write;
//! use sequoia_openpgp as openpgp;
//! use openpgp::policy::StandardPolicy;
//! use openpgp::cert::prelude::*;
//! use openpgp::serialize::stream::{
//!     Message, Armorer, Encryptor, Signer, LiteralWriter,
//!     padding::{Padder, padme},
//! };
//! # use openpgp::parse::Parse;
//!
//! let p = &StandardPolicy::new();
//!
//! let sender: Cert = // ...
//! #     Cert::from_bytes(&include_bytes!(
//! #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
//! let signing_keypair = sender.keys().secret()
//!     .with_policy(p, None).alive().revoked(false).for_signing()
//!     .nth(0).unwrap()
//!     .key().clone().into_keypair()?;
//!
//! let recipient: Cert = // ...
//! #     sender.clone();
//! // Note: One certificate may contain several suitable encryption keys.
//! let recipients =
//!     recipient.keys().with_policy(p, None).alive().revoked(false)
//!     // Or `for_storage_encryption()`, for data at rest.
//!     .for_transport_encryption()
//!     .map(|ka| ka.key());
//!
//! # let mut sink = vec![];
//! let message = Message::new(&mut sink);
//! let message = Armorer::new(message).build()?;
//! let message = Encryptor::for_recipients(message, recipients).build()?;
//! // Reduce metadata leakage by concealing the message size.
//! let message = Padder::new(message, padme)?;
//! let message = Signer::new(message, signing_keypair)
//!     // Prevent Surreptitious Forwarding.
//!     .add_intended_recipient(&recipient)
//!     .build()?;
//! let mut message = LiteralWriter::new(message).build()?;
//! message.write_all(b"Hello world.")?;
//! message.finalize()?;
//! # Ok(()) }
//! ```

use std::fmt;
use std::io::{self, Write};
use std::time::SystemTime;

use crate::{
    armor,
    crypto,
    Error,
    Fingerprint,
    HashAlgorithm,
    KeyID,
    Result,
    crypto::Password,
    crypto::SessionKey,
    packet::prelude::*,
    packet::signature,
    packet::key,
    cert::prelude::*,
};
use crate::packet::header::CTB;
use crate::packet::header::BodyLength;
use super::{
    Marshal,
};
use crate::types::{
    AEADAlgorithm,
    CompressionAlgorithm,
    CompressionLevel,
    DataFormat,
    SignatureType,
    SymmetricAlgorithm,
};

pub(crate) mod writer;
#[cfg(feature = "compression-deflate")]
pub mod padding;
mod partial_body;
use partial_body::PartialBodyFilter;

/// Cookie must be public because the writers are.
#[derive(Debug)]
struct Cookie {
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
            level,
            private: Private::Nothing,
        }
    }
}

impl Default for Cookie {
    fn default() -> Self {
        Cookie::new(0)
    }
}

/// Streams an OpenPGP message.
///
/// Wraps an [`io::Write`]r for use with the streaming subsystem.  The
/// `Message` is a stack of filters that create the desired message
/// structure.  Literal data must be framed using the
/// [`LiteralWriter`] filter.  Once all the has been written, the
/// `Message` must be finalized using [`Message::finalize`].
///
///   [`io::Write`]: https://doc.rust-lang.org/nightly/std/io/trait.Write.html
///   [`LiteralWriter`]: struct.LiteralWriter.html
///   [`Message::finalize`]: #method.finalize
#[derive(Debug)]
pub struct Message<'a>(writer::BoxStack<'a, Cookie>);

impl<'a> Message<'a> {
    /// Starts streaming an OpenPGP message.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// # let mut sink = vec![]; // Vec<u8> implements io::Write.
    /// let message = Message::new(&mut sink);
    /// // Construct the writer stack here.
    /// let mut message = LiteralWriter::new(message).build()?;
    /// // Write literal data to `message` here.
    /// // ...
    /// // Finalize the message.
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn new<W: 'a + io::Write>(w: W) -> Message<'a> {
        writer::Generic::new(w, Cookie::new(0))
    }

    /// Finalizes the topmost writer, returning the underlying writer.
    ///
    /// Finalizes the topmost writer, i.e. flushes any buffered data,
    /// and pops it of the stack.  This allows for fine-grained
    /// control of the resulting message, but must be done with great
    /// care.  If done improperly, the resulting message may be
    /// malformed.
    ///
    /// # Example
    ///
    /// This demonstrates how to create a compressed, signed message
    /// from a detached signature.
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use std::convert::TryFrom;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::packet::{Packet, Signature, one_pass_sig::OnePassSig3};
    /// # use openpgp::parse::Parse;
    /// use openpgp::serialize::Serialize;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    ///
    /// let data: &[u8] = // ...
    /// # &include_bytes!(
    /// # "../../tests/data/messages/a-cypherpunks-manifesto.txt")[..];
    /// let sig: Signature = // ...
    /// # if let Packet::Signature(s) = Packet::from_bytes(&include_bytes!(
    /// # "../../tests/data/messages/a-cypherpunks-manifesto.txt.ed25519.sig")[..])?
    /// # { s } else { panic!() };
    ///
    /// # let mut sink = vec![]; // Vec<u8> implements io::Write.
    /// let message = Message::new(&mut sink);
    /// let mut message = Compressor::new(message).build()?;
    ///
    /// // First, write a one-pass-signature packet.
    /// Packet::from(OnePassSig3::try_from(&sig)?)
    ///     .serialize(&mut message)?;
    ///
    /// // Then, add the literal data.
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(data)?;
    ///
    /// // Finally, pop the `LiteralWriter` off the stack to write the
    /// // signature.
    /// let mut message = message.finalize_one()?.unwrap();
    /// Packet::from(sig).serialize(&mut message)?;
    ///
    /// // Finalize the message.
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn finalize_one(self) -> Result<Option<Message<'a>>> {
        Ok(self.0.into_inner()?.map(|bs| Self::from(bs)))
    }

    /// Finalizes the message.
    ///
    /// Finalizes all writers on the stack, flushing any buffered
    /// data.
    ///
    /// # Note
    ///
    /// Failing to finalize the message may result in corrupted
    /// messages.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// # let mut sink = vec![]; // Vec<u8> implements io::Write.
    /// let message = Message::new(&mut sink);
    /// // Construct the writer stack here.
    /// let mut message = LiteralWriter::new(message).build()?;
    /// // Write literal data to `message` here.
    /// // ...
    /// // Finalize the message.
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn finalize(self) -> Result<()> {
        let mut stack = self;
        while let Some(s) = stack.finalize_one()? {
            stack = s;
        }
        Ok(())
    }
}

impl<'a> From<&'a mut dyn io::Write> for Message<'a> {
    fn from(w: &'a mut dyn io::Write) -> Self {
        writer::Generic::new(w, Cookie::new(0))
    }
}


/// Applies ASCII Armor to the message.
///
/// ASCII armored data (see [Section 6 of RFC 4880]) is a OpenPGP data
/// stream that has been base64-encoded and decorated with a header,
/// footer, and optional headers representing key-value pairs.  It can
/// be safely transmitted over protocols that can only transmit
/// printable characters, and can handled by end users (e.g. copied
/// and pasted).
///
///   [Section 6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-6
pub struct Armorer<'a> {
    kind: armor::Kind,
    headers: Vec<(String, String)>,
    inner: Message<'a>,
}

impl<'a> Armorer<'a> {
    /// Creates a new armoring filter.
    ///
    /// By default, the type of the armored data is set to
    /// [`armor::Kind`]`::Message`.  To change it, use
    /// [`Armorer::kind`].  To add headers to the armor, use
    /// [`Armorer::add_header`].
    ///
    ///   [`armor::Kind`]: ../../armor/enum.Kind.html
    ///   [`Armorer::kind`]: #method.kind
    ///   [`Armorer::add_header`]: #method.add_header
    ///
    /// # Examples
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Armorer, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Armorer::new(message)
    ///         // Customize the `Armorer` here.
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!("-----BEGIN PGP MESSAGE-----\n\
    ///             \n\
    ///             yxJiAAAAAABIZWxsbyB3b3JsZC4=\n\
    ///             =6nHv\n\
    ///             -----END PGP MESSAGE-----\n",
    ///            std::str::from_utf8(&sink)?);
    /// # Ok(()) }
    pub fn new(inner: Message<'a>) -> Self {
        Self {
            kind: armor::Kind::Message,
            headers: Vec::with_capacity(0),
            inner,
        }
    }

    /// Changes the kind of armoring.
    ///
    /// The armor header and footer changes depending on the type of
    /// wrapped data.  See [`armor::Kind`] for the possible values.
    ///
    ///   [`armor::Kind`]: ../../armor/enum.Kind.html
    ///
    /// # Examples
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::armor;
    /// use openpgp::serialize::stream::{Message, Armorer, Signer};
    /// # use sequoia_openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair
    /// #     = cert.keys().secret()
    /// #           .with_policy(p, None).alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().into_keypair()?;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Armorer::new(message)
    ///         .kind(armor::Kind::Signature)
    ///         .build()?;
    ///     let mut signer = Signer::new(message, signing_keypair)
    ///         .detached()
    ///         .build()?;
    ///
    ///     // Write the data directly to the `Signer`.
    ///     signer.write_all(b"Make it so, number one!")?;
    ///     // In reality, just io::copy() the file to be signed.
    ///     signer.finalize()?;
    /// }
    ///
    /// assert!(std::str::from_utf8(&sink)?
    ///         .starts_with("-----BEGIN PGP SIGNATURE-----\n"));
    /// # Ok(()) }
    pub fn kind(mut self, kind: armor::Kind) -> Self {
        self.kind = kind;
        self
    }

    /// Adds a header to the armor block.
    ///
    /// There are a number of defined armor header keys (see [Section
    /// 6 of RFC 4880]), but in practice, any key may be used, as
    /// implementations should simply ignore unknown keys.
    ///
    ///   [Section 6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-6
    ///
    /// # Examples
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Armorer, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Armorer::new(message)
    ///         .add_header("Comment", "No comment.")
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!("-----BEGIN PGP MESSAGE-----\n\
    ///             Comment: No comment.\n\
    ///             \n\
    ///             yxJiAAAAAABIZWxsbyB3b3JsZC4=\n\
    ///             =6nHv\n\
    ///             -----END PGP MESSAGE-----\n",
    ///            std::str::from_utf8(&sink)?);
    /// # Ok(()) }
    pub fn add_header<K, V>(mut self, key: K, value: V) -> Self
        where K: AsRef<str>,
              V: AsRef<str>,
    {
        self.headers.push((key.as_ref().to_string(),
                           value.as_ref().to_string()));
        self
    }

    /// Builds the armor writer, returning the writer stack.
    ///
    /// # Examples
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Armorer, LiteralWriter};
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Armorer::new(message)
    ///     // Customize the `Armorer` here.
    ///     .build()?;
    /// # Ok(()) }
    pub fn build(self) -> Result<Message<'a>> {
        let level = self.inner.as_ref().cookie_ref().level;
        writer::Armorer::new(
            self.inner,
            Cookie::new(level + 1),
            self.kind,
            self.headers,
        )
    }
}

impl<'a> fmt::Debug for Armorer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Armorer")
            .field("inner", &self.inner)
            .field("kind", &self.kind)
            .field("headers", &self.headers)
            .finish()
    }
}


/// Writes an arbitrary packet.
///
/// This writer can be used to construct arbitrary OpenPGP packets.
/// This is mainly useful for testing.  The body will be written using
/// partial length encoding, or, if the body is short, using full
/// length encoding.
pub struct ArbitraryWriter<'a> {
    inner: writer::BoxStack<'a, Cookie>,
}

impl<'a> ArbitraryWriter<'a> {
    /// Creates a new writer with the given tag.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::packet::Tag;
    /// use openpgp::serialize::stream::{Message, ArbitraryWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = ArbitraryWriter::new(message, Tag::Literal)?;
    ///     message.write_all(b"t")?;                   // type
    ///     message.write_all(b"\x00")?;                // filename length
    ///     message.write_all(b"\x00\x00\x00\x00")?;    // date
    ///     message.write_all(b"Hello world.")?;        // body
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    pub fn new(mut inner: Message<'a>, tag: Tag)
               -> Result<Message<'a>> {
        let level = inner.as_ref().cookie_ref().level + 1;
        CTB::new(tag).serialize(&mut inner)?;
        Ok(Message::from(Box::new(ArbitraryWriter {
            inner: PartialBodyFilter::new(inner, Cookie::new(level)).into()
        })))
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
    fn into_inner(self: Box<Self>) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        Box::new(self.inner).into_inner()
    }
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_mut())
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
    fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// Signs a message.
///
/// Signs a message with every [`crypto::Signer`] added to the
/// streaming signer.
///
///   [`crypto::Signer`]: ../../crypto/trait.Signer.html
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
    inner: Option<writer::BoxStack<'a, Cookie>>,
    signers: Vec<Box<dyn crypto::Signer + 'a>>,
    intended_recipients: Vec<Fingerprint>,
    detached: bool,
    template: signature::SignatureBuilder,
    creation_time: Option<SystemTime>,
    hash: crypto::hash::Context,
    cookie: Cookie,
    position: u64,
}

impl<'a> Signer<'a> {
    /// Creates a signer.
    ///
    /// Signs the message with the given [`crypto::Signer`].  To
    /// create more than one signature, add more [`crypto::Signer`]s
    /// using [`Signer::add_signer`].  Properties of the signatures
    /// can be tweaked using the methods of this type.  Notably, to
    /// generate a detached signature (see [Section 11.4 of RFC
    /// 4880]), use [`Signer::detached`].  For even more control over
    /// the generated signatures, use [`Signer::with_template`].
    ///
    ///   [`crypto::Signer`]: ../../crypto/trait.Signer.html
    ///   [`Signer::add_signer`]: #method.add_signer
    ///   [Section 11.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.4
    ///   [`Signer::detached`]: #method.detached
    ///   [`Signer::with_template`]: #method.with_template
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::{Read, Write};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    /// let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// let signing_keypair = cert.keys().secret()
    ///     .with_policy(p, None).alive().revoked(false).for_signing()
    ///     .nth(0).unwrap()
    ///     .key().clone().into_keypair()?;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Signer::new(message, signing_keypair)
    ///         // Customize the `Signer` here.
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Make it so, number one!")?;
    ///     message.finalize()?;
    /// }
    ///
    /// // Now check the signature.
    /// struct Helper<'a>(&'a openpgp::Cert);
    /// impl<'a> VerificationHelper for Helper<'a> {
    ///     fn get_certs(&mut self, _: &[openpgp::KeyHandle])
    ///                        -> openpgp::Result<Vec<openpgp::Cert>> {
    ///         Ok(vec![self.0.clone()])
    ///     }
    ///
    ///     fn check(&mut self, structure: MessageStructure)
    ///              -> openpgp::Result<()> {
    ///         if let MessageLayer::SignatureGroup { ref results } =
    ///             structure.iter().nth(0).unwrap()
    ///         {
    ///             results.get(0).unwrap().as_ref().unwrap();
    ///             Ok(())
    ///         } else { panic!() }
    ///     }
    /// }
    ///
    /// let mut verifier = VerifierBuilder::from_bytes(&sink)?
    ///     .with_policy(p, None, Helper(&cert))?;
    ///
    /// let mut message = String::new();
    /// verifier.read_to_string(&mut message)?;
    /// assert_eq!(&message, "Make it so, number one!");
    /// # Ok(()) }
    /// ```
    pub fn new<S>(inner: Message<'a>, signer: S) -> Self
        where S: crypto::Signer + 'a
    {
        Self::with_template(inner, signer,
                            signature::SignatureBuilder::new(SignatureType::Binary))
    }

    /// Creates a signer with a given signature template.
    ///
    /// Signs the message with the given [`crypto::Signer`] like
    /// [`Signer::new`], but allows more control over the generated
    /// signatures.  The given [`signature::SignatureBuilder`] is used to
    /// create all the signatures.
    ///
    /// For every signature, the creation time is set to the current
    /// time or the one specified using [`Signer::creation_time`], the
    /// intended recipients are added (see
    /// [`Signer::add_intended_recipient`]), the issuer and issuer
    /// fingerprint subpackets are set according to the signing key,
    /// and the hash algorithm set using [`Signer::hash_algo`] is used
    /// to create the signature.
    ///
    ///   [`crypto::Signer`]: ../../crypto/trait.Signer.html
    ///   [`Signer::new`]: #method.new
    ///   [`signature::SignatureBuilder`]: ../../packet/signature/struct.Builder.html
    ///   [`Signer::creation_time`]: #method.creation_time
    ///   [`Signer::hash_algo`]: #method.hash_algo
    ///   [`Signer::add_intended_recipient`]: #method.add_intended_recipient
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::{Read, Write};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SignatureType;
    /// use openpgp::packet::signature;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    /// #
    /// # let p = &StandardPolicy::new();
    /// # let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    /// # let mut sink = vec![];
    ///
    /// let message = Message::new(&mut sink);
    /// let message = Signer::with_template(
    ///     message, signing_keypair,
    ///     signature::SignatureBuilder::new(SignatureType::Text)
    ///         .add_notation("issuer@starfleet.command", "Jean-Luc Picard",
    ///                       None, true)?)
    ///     // Further customize the `Signer` here.
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn with_template<S, T>(inner: Message<'a>, signer: S, template: T)
                               -> Self
        where S: crypto::Signer + 'a,
              T: Into<signature::SignatureBuilder>,
    {
        let inner = writer::BoxStack::from(inner);
        let level = inner.cookie_ref().level + 1;
        Signer {
            inner: Some(inner),
            signers: vec![Box::new(signer)],
            intended_recipients: Vec::new(),
            detached: false,
            template: template.into(),
            creation_time: None,
            hash: HashAlgorithm::default().context().unwrap(),
            cookie: Cookie {
                level,
                private: Private::Signer,
            },
            position: 0,
        }
    }

    /// Creates a signer for a detached signature.
    ///
    /// Changes the `Signer` to create a detached signature (see
    /// [Section 11.4 of RFC 4880]).  Note that the literal data *must
    /// not* be wrapped using the [`LiteralWriter`].
    ///
    ///   [Section 11.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.4
    ///   [`LiteralWriter`]: ../struct.LiteralWriter.html
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer};
    /// use sequoia_openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair
    /// #     = cert.keys().secret()
    /// #           .with_policy(p, None).alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().into_keypair()?;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut signer = Signer::new(message, signing_keypair)
    ///         .detached()
    ///         // Customize the `Signer` here.
    ///         .build()?;
    ///
    ///     // Write the data directly to the `Signer`.
    ///     signer.write_all(b"Make it so, number one!")?;
    ///     // In reality, just io::copy() the file to be signed.
    ///     signer.finalize()?;
    /// }
    ///
    /// // Now check the signature.
    /// struct Helper<'a>(&'a openpgp::Cert);
    /// impl<'a> VerificationHelper for Helper<'a> {
    ///     fn get_certs(&mut self, _: &[openpgp::KeyHandle])
    ///                        -> openpgp::Result<Vec<openpgp::Cert>> {
    ///         Ok(vec![self.0.clone()])
    ///     }
    ///
    ///     fn check(&mut self, structure: MessageStructure)
    ///              -> openpgp::Result<()> {
    ///         if let MessageLayer::SignatureGroup { ref results } =
    ///             structure.iter().nth(0).unwrap()
    ///         {
    ///             results.get(0).unwrap().as_ref().unwrap();
    ///             Ok(())
    ///         } else { panic!() }
    ///     }
    /// }
    ///
    /// let mut verifier = DetachedVerifierBuilder::from_bytes(&sink)?
    ///     .with_policy(p, None, Helper(&cert))?;
    ///
    /// verifier.verify_bytes(b"Make it so, number one!")?;
    /// # Ok(()) }
    /// ```
    pub fn detached(mut self) -> Self {
        self.detached = true;
        self
    }

    /// Adds an additional signer.
    ///
    /// Can be used multiple times.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    /// # let additional_signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)
    ///     .add_signer(additional_signing_keypair)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_signer<S>(mut self, signer: S) -> Self
        where S: crypto::Signer + 'a
    {
        self.signers.push(Box::new(signer));
        self
    }

    /// Adds an intended recipient.
    ///
    /// Indicates that the given certificate is an intended recipient
    /// of this message.  Can be used multiple times.  This prevents
    /// [*Surreptitious Forwarding*] of encrypted and signed messages,
    /// i.e. forwarding a signed message using a different encryption
    /// context.
    ///
    ///   [*Surreptitious Forwarding*]: http://world.std.com/~dtd/sign_encrypt/sign_encrypt7.html
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::crypto::KeyPair;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    /// let recipient: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy.pgp")[..])?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)
    ///     .add_intended_recipient(&recipient)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_intended_recipient(mut self, recipient: &Cert) -> Self {
        self.intended_recipients.push(recipient.fingerprint());
        self
    }

    /// Sets the hash algorithm to use for the signatures.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::HashAlgorithm;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert = Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair = cert.keys().secret()
    /// #     .with_policy(p, None).alive().revoked(false).for_signing()
    /// #     .nth(0).unwrap()
    /// #     .key().clone().into_keypair()?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)
    ///     .hash_algo(HashAlgorithm::SHA384)?
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn hash_algo(mut self, algo: HashAlgorithm) -> Result<Self> {
        self.hash = algo.context()?;
        Ok(self)
    }

    /// Sets the signature's creation time to `time`.
    ///
    /// Note: it is up to the caller to make sure the signing keys are
    /// actually valid as of `time`.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Timestamp;
    /// use openpgp::serialize::stream::{Message, Signer, LiteralWriter};
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// let p = &StandardPolicy::new();
    /// let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// let signing_key = cert.keys().secret()
    ///     .with_policy(p, None).alive().revoked(false).for_signing()
    ///     .nth(0).unwrap()
    ///     .key();
    /// let signing_keypair = signing_key.clone().into_keypair()?;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)
    ///     .creation_time(Timestamp::now()
    ///                    .round_down(None, signing_key.creation_time())?)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Make it so, number one!")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn creation_time<T: Into<SystemTime>>(mut self, creation_time: T)
                                              -> Self
    {
        self.creation_time = Some(creation_time.into());
        self
    }

    /// Builds the signer, returning the writer stack.
    ///
    /// The most useful filter to push to the writer stack next is the
    /// [`LiteralWriter`].  Note, if you are creating a signed OpenPGP
    /// message (see [Section 11.3 of RFC 4880]), literal data *must*
    /// be wrapped using the [`LiteralWriter`].  On the other hand, if
    /// you are creating a detached signature (see [Section 11.4 of
    /// RFC 4880]), the literal data *must not* be wrapped using the
    /// [`LiteralWriter`].
    ///
    ///   [`LiteralWriter`]: ../struct.LiteralWriter.html
    ///   [Section 11.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.3
    ///   [Section 11.4 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-11.4
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Timestamp;
    /// use openpgp::serialize::stream::{Message, Signer};
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::{Result, Cert};
    /// # use openpgp::packet::prelude::*;
    /// # use openpgp::parse::Parse;
    /// # use openpgp::parse::stream::*;
    ///
    /// # let p = &StandardPolicy::new();
    /// # let cert: Cert = // ...
    /// #     Cert::from_bytes(&include_bytes!(
    /// #     "../../tests/data/keys/testy-new-private.pgp")[..])?;
    /// # let signing_keypair
    /// #     = cert.keys().secret()
    /// #           .with_policy(p, None).alive().revoked(false).for_signing()
    /// #           .nth(0).unwrap()
    /// #           .key().clone().into_keypair()?;
    /// #
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Signer::new(message, signing_keypair)
    ///     // Customize the `Signer` here.
    ///     .build()?;
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>>
    {
        assert!(self.signers.len() > 0, "The constructor adds a signer.");
        assert!(self.inner.is_some(), "The constructor adds an inner writer.");

        if ! self.detached {
            // For every key we collected, build and emit a one pass
            // signature packet.
            for (i, keypair) in self.signers.iter().enumerate() {
                let key = keypair.public();
                let mut ops = OnePassSig3::new(SignatureType::Binary);
                ops.set_pk_algo(key.pk_algo());
                ops.set_hash_algo(self.hash.algo());
                ops.set_issuer(key.keyid());
                ops.set_last(i == self.signers.len() - 1);
                Packet::OnePassSig(ops.into())
                    .serialize(self.inner.as_mut().unwrap())?;
            }
        }

        Ok(Message::from(Box::new(self)))
    }

    fn emit_signatures(&mut self) -> Result<()> {
        if let Some(ref mut sink) = self.inner {
            // Emit the signatures in reverse, so that the
            // one-pass-signature and signature packets "bracket" the
            // message.
            for signer in self.signers.iter_mut() {
                // Part of the signature packet is hashed in,
                // therefore we need to clone the hash.
                let hash = self.hash.clone();

                // Make and hash a signature packet.
                let mut sig = self.template.clone()
                    .set_signature_creation_time(
                        self.creation_time
                            .unwrap_or_else(SystemTime::now))?
                    .set_issuer_fingerprint(signer.public().fingerprint())?
                    // GnuPG up to (and including) 2.2.8 requires the
                    // Issuer subpacket to be present.
                    .set_issuer(signer.public().keyid())?;

                if ! self.intended_recipients.is_empty() {
                    sig = sig.set_intended_recipients(
                        self.intended_recipients.clone())?;
                }

                // Compute the signature.
                let sig = sig.sign_hash(signer.as_mut(), hash)?;

                // And emit the packet.
                Packet::Signature(sig).serialize(sink)?;
            }
        }
        Ok(())
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
            // If we are creating a normal signature, pass data
            // through.
            Some(ref mut w) if ! self.detached => w.write(buf),
            // If we are creating a detached signature, just hash all
            // bytes.
            Some(_) => Ok(buf.len()),
            // When we are popped off the stack, we have no inner
            // writer.  Just hash all bytes.
            None => Ok(buf.len()),
        };

        if let Ok(amount) = written {
            self.hash.update(&buf[..amount]);
            self.position += amount as u64;
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
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        Ok(self.inner.take())
    }
    fn mount(&mut self, new: writer::BoxStack<'a, Cookie>) {
        self.inner = Some(new);
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        self.inner.as_ref().map(|r| r.as_ref())
    }
    fn into_inner(mut self: Box<Self>)
                  -> Result<Option<writer::BoxStack<'a, Cookie>>> {
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
    fn position(&self) -> u64 {
        self.position
    }
}


/// Writes a literal data packet.
///
/// Literal data, i.e. the payload or plaintext, must be wrapped in a
/// literal data packet to be transported over OpenPGP (see [Section
/// 5.9 of RFC 4880]).  The body will be written using partial length
/// encoding, or, if the body is short, using full length encoding.
///
///   [Section 5.9 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.9
///
/// # Note on metadata
///
/// A literal data packet can communicate some metadata: a hint as to
/// what kind of data is transported, the original file name, and a
/// timestamp.  Note that this metadata will not be authenticated by
/// signatures (but will be authenticated by a SEIP/MDC container),
/// and are therefore unreliable and should not be trusted.
///
/// Therefore, it is good practice not to set this metadata when
/// creating a literal data packet, and not to interpret it when
/// consuming one.
pub struct LiteralWriter<'a> {
    template: Literal,
    inner: writer::BoxStack<'a, Cookie>,
    signature_writer: Option<writer::BoxStack<'a, Cookie>>,
}

impl<'a> LiteralWriter<'a> {
    /// Creates a new literal writer.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         // Customize the `LiteralWriter` here.
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12b\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn new(inner: Message<'a>) -> Self {
        LiteralWriter {
            template: Literal::new(DataFormat::default()),
            inner: writer::BoxStack::from(inner),
            signature_writer: None,
        }
    }

    /// Sets the data format.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::DataFormat;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         .format(DataFormat::Text)
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12t\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn format(mut self, format: DataFormat) -> Self {
        self.template.set_format(format);
        self
    }

    /// Sets the filename.
    ///
    /// The standard does not specify the encoding.  Filenames must
    /// not be longer than 255 bytes.  Returns an error if the given
    /// name is longer than that.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         .filename("foobar")?
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x18b\x06foobar\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn filename<B: AsRef<[u8]>>(mut self, filename: B) -> Result<Self> {
        self.template.set_filename(filename.as_ref())?;
        Ok(self)
    }

    /// Sets the date.
    ///
    /// This date may be the modification date or the creation date.
    /// Returns an error if the given date is not representable by
    /// OpenPGP.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::Timestamp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         .date(Timestamp::from(1585925313))?
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12b\x00\x5e\x87\x4c\xc1Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn date<T: Into<SystemTime>>(mut self, timestamp: T) -> Result<Self>
    {
        self.template.set_date(Some(timestamp.into()))?;
        Ok(self)
    }

    /// Builds the literal writer, returning the writer stack.
    ///
    /// The next step is to write the payload to the writer stack.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, LiteralWriter};
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let mut message = LiteralWriter::new(message)
    ///         // Customize the `LiteralWriter` here.
    ///         .build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xcb\x12b\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>> {
        let level = self.inner.cookie_ref().level + 1;

        // For historical reasons, signatures over literal data
        // packets only include the body without metadata or framing.
        // Therefore, we check whether the writer is a
        // Signer, and if so, we pop it off the stack and
        // store it in 'self.signature_writer'.
        let signer_above =
            if let &Cookie {
                private: Private::Signer{..},
                ..
            } = self.inner.cookie_ref() {
                true
            } else {
                false
            };

        if signer_above {
            let stack = self.inner.pop()?;
            // We know a signer has an inner stackable.
            let stack = stack.unwrap();
            self.signature_writer = Some(self.inner);
            self.inner = stack;
        }

        // Not hashed by the signature_writer (see above).
        CTB::new(Tag::Literal).serialize(&mut self.inner)?;

        // Neither is any framing added by the PartialBodyFilter.
        self.inner
            = PartialBodyFilter::new(Message::from(self.inner),
                                     Cookie::new(level)).into();

        // Nor the headers.
        self.template.serialize_headers(&mut self.inner, false)?;

        Ok(Message::from(Box::new(self)))
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
                  -> Result<Option<writer::BoxStack<'a, Cookie>>> {
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

    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_mut())
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
    fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// Compresses a message.
///
/// Writes a compressed data packet containing all packets written to
/// this writer.
pub struct Compressor<'a> {
    algo: CompressionAlgorithm,
    level: CompressionLevel,
    inner: writer::BoxStack<'a, Cookie>,
}

impl<'a> Compressor<'a> {
    /// Creates a new compressor using the default algorithm and
    /// compression level.
    ///
    /// To change the compression algorithm use [`Compressor::algo`].
    /// Use [`Compressor::level`] to change the compression level.
    ///
    ///   [`Compressor::algo`]: #method.algo
    ///   [`Compressor::level`]: #method.level
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::CompressionAlgorithm;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Compressor::new(message)
    ///     // Customize the `Compressor` here.
    /// #   .algo(CompressionAlgorithm::Uncompressed)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn new(inner: Message<'a>) -> Self {
        Self {
            algo: Default::default(),
            level: Default::default(),
            inner: inner.into(),
        }
    }

    /// Sets the compression algorithm.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::CompressionAlgorithm;
    ///
    /// let mut sink = vec![];
    /// {
    ///     let message = Message::new(&mut sink);
    ///     let message = Compressor::new(message)
    ///         .algo(CompressionAlgorithm::Uncompressed)
    ///         .build()?;
    ///     let mut message = LiteralWriter::new(message).build()?;
    ///     message.write_all(b"Hello world.")?;
    ///     message.finalize()?;
    /// }
    /// assert_eq!(b"\xc8\x15\x00\xcb\x12b\x00\x00\x00\x00\x00Hello world.",
    ///            sink.as_slice());
    /// # Ok(()) }
    /// ```
    pub fn algo(mut self, algo: CompressionAlgorithm) -> Self {
        self.algo = algo;
        self
    }

    /// Sets the compression level.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::{CompressionAlgorithm, CompressionLevel};
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Compressor::new(message)
    /// #   .algo(CompressionAlgorithm::Uncompressed)
    ///     .level(CompressionLevel::fastest())
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn level(mut self, level: CompressionLevel) -> Self {
        self.level = level;
        self
    }

    /// Builds the compressor, returning the writer stack.
    ///
    /// The most useful filter to push to the writer stack next is the
    /// [`Signer`] or the [`LiteralWriter`].  Finally, literal data
    /// *must* be wrapped using the [`LiteralWriter`].
    ///
    ///   [`Signer`]: struct.Signer.html
    ///   [`LiteralWriter`]: struct.LiteralWriter.html
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{Message, Compressor, LiteralWriter};
    /// use openpgp::types::CompressionAlgorithm;
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Compressor::new(message)
    ///     // Customize the `Compressor` here.
    /// #   .algo(CompressionAlgorithm::Uncompressed)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>> {
        let level = self.inner.cookie_ref().level + 1;

        // Packet header.
        CTB::new(Tag::CompressedData).serialize(&mut self.inner)?;
        let inner: Message<'a>
            = PartialBodyFilter::new(Message::from(self.inner),
                                     Cookie::new(level));

        Self::new_naked(inner, self.algo, self.level, level)
    }


    /// Creates a new compressor using the given algorithm.
    pub(crate) // For CompressedData::serialize.
    fn new_naked(mut inner: Message<'a>,
                 algo: CompressionAlgorithm,
                 compression_level: CompressionLevel,
                 level: usize)
                 -> Result<Message<'a>>
    {
        // Compressed data header.
        inner.as_mut().write_u8(algo.into())?;

        // Create an appropriate filter.
        let inner: Message<'a> = match algo {
            CompressionAlgorithm::Uncompressed => {
                // Avoid warning about unused value if compiled
                // without any compression support.
                let _ = compression_level;
                writer::Identity::new(inner, Cookie::new(level))
            },
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zip =>
                writer::ZIP::new(inner, Cookie::new(level), compression_level),
            #[cfg(feature = "compression-deflate")]
            CompressionAlgorithm::Zlib =>
                writer::ZLIB::new(inner, Cookie::new(level), compression_level),
            #[cfg(feature = "compression-bzip2")]
            CompressionAlgorithm::BZip2 =>
                writer::BZ::new(inner, Cookie::new(level), compression_level),
            a =>
                return Err(Error::UnsupportedCompressionAlgorithm(a).into()),
        };

        Ok(Message::from(Box::new(Self {
            algo,
            level: compression_level,
            inner: inner.into(),
        })))
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
    fn into_inner(self: Box<Self>) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        Box::new(self.inner).into_inner()?.unwrap().into_inner()
    }
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        Some(self.inner.as_mut())
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
    fn position(&self) -> u64 {
        self.inner.position()
    }
}

/// A recipient of an encrypted message.
///
/// OpenPGP messages are encrypted with the subkeys of recipients,
/// identified by the keyid of said subkeys in the [`recipient`] field
/// of [`PKESK`] packets (see [Section 5.1 of RFC 4880]).  The keyid
/// may be a wildcard (as returned by [`KeyID::wildcard()`]) to
/// obscure the identity of the recipient.
///
///   [`recipient`]: ../../packet/enum.PKESK.html#method.recipient
///   [`PKESK`]: ../../packet/enum.PKESK.html
///   [Section 5.1 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.1
///   [`KeyID::wildcard()`]: ../../../struct.KeyID.html#method.wildcard
///
/// Note that several subkeys in a certificate may be suitable
/// encryption subkeys.  OpenPGP does not specify what should happen
/// in this case.  Some implementations arbitrarily pick one
/// encryption subkey, while others use all of them.  This crate does
/// not dictate a policy, but allows for arbitrary policies.  We do,
/// however, suggest to encrypt to all suitable subkeys.
#[derive(Debug)]
pub struct Recipient<'a> {
    keyid: KeyID,
    key: &'a Key<key::PublicParts, key::UnspecifiedRole>,
}

impl<'a, P, R> From<&'a Key<P, R>> for Recipient<'a>
    where P: key::KeyParts,
          R: key::KeyRole,
{
    fn from(key: &'a Key<P, R>) -> Self {
        Self::new(key.keyid(), key.parts_as_public().role_as_unspecified())
    }
}

impl<'a, P, R, R2> From<ValidKeyAmalgamation<'a, P, R, R2>>
    for Recipient<'a>
    where P: key::KeyParts,
          R: key::KeyRole,
          R2: Copy,
{
    fn from(ka: ValidKeyAmalgamation<'a, P, R, R2>) -> Self {
        ka.key().into()
    }
}

impl<'a> Recipient<'a> {
    /// Creates a new recipient with an explicit recipient keyid.
    ///
    /// Note: If you don't want to change the recipient keyid,
    /// `Recipient`s can be created from [`Key`] and
    /// [`ValidKeyAmalgamation`] using [`From`].
    ///
    ///   [`Key`]: ../../packet/enum.Key.html
    ///   [`ValidKeyAmalgamation`]: ../../cert/amalgamation/key/struct.ValidKeyAmalgamation.html
    ///   [`From`]: https://doc.rust-lang.org/std/convert/trait.From.html
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Recipient, Message, Encryptor,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    ///
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
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
    /// #    awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    /// #    =lAie
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption()
    ///     .map(|ka| Recipient::new(ka.key().keyid(), ka.key()));
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::for_recipients(message, recipients).build()?;
    /// # let _ = message;
    /// # Ok(()) }
    /// ```
    pub fn new<P, R>(keyid: KeyID, key: &'a Key<P, R>) -> Recipient<'a>
        where P: key::KeyParts,
              R: key::KeyRole,
    {
        Recipient {
            keyid,
            key: key.parts_as_public().role_as_unspecified(),
        }
    }

    /// Gets the recipient keyid.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::Recipient;
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    ///
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
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
    /// #    awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    /// #    =lAie
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption()
    ///     .map(Into::into)
    ///     .collect::<Vec<Recipient>>();
    ///
    /// assert_eq!(recipients[0].keyid(),
    ///            &"EA6E 3770 628A 713C".parse()?);
    /// # Ok(()) }
    /// ```
    pub fn keyid(&self) -> &KeyID {
        &self.keyid
    }

    /// Sets the recipient keyid.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::KeyID;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Recipient, Message, Encryptor,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    ///
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
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
    /// #    awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    /// #    =lAie
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption()
    ///     .map(|ka| {
    ///         let mut r: Recipient = ka.into();
    ///         // Set the recipient keyid to the wildcard id.
    ///         r.set_keyid(KeyID::wildcard());
    ///         r
    ///     });
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::for_recipients(message, recipients).build()?;
    /// # let _ = message;
    /// # Ok(()) }
    /// ```
    pub fn set_keyid(&mut self, keyid: KeyID) -> KeyID {
        std::mem::replace(&mut self.keyid, keyid)
    }
}

/// Encrypts a message.
///
/// The stream will be encrypted using a generated session key, which
/// will be encrypted using the given passwords, and for all given
/// recipients.
pub struct Encryptor<'a> {
    // XXX: Opportunity for optimization.  Previously, this writer
    // implemented `Drop`, so we could not move the inner writer out
    // of this writer.  We therefore wrapped it with `Option` so that
    // we can `take()` it.  This writer no longer implements Drop, so
    // we could avoid the Option here.
    inner: Option<writer::BoxStack<'a, Cookie>>,
    recipients: Vec<Recipient<'a>>,
    passwords: Vec<Password>,
    sym_algo: SymmetricAlgorithm,
    aead_algo: Option<AEADAlgorithm>,
    hash: crypto::hash::Context,
    cookie: Cookie,
}

impl<'a> Encryptor<'a> {
    /// Creates a new encryptor for the given recipients.
    ///
    /// To add more recipients, use [`Encryptor::add_recipient`].  To
    /// add a password, use [`Encryptor::add_password`].  To change
    /// the symmetric encryption algorithm, use
    /// [`Encryptor::sym_algo`].  To enable the experimental AEAD
    /// encryption, use [`Encryptor::aead_algo`].
    ///
    ///   [`Encryptor::add_recipient`]: #method.add_recipient
    ///   [`Encryptor::add_password`]: #method.add_password
    ///   [`Encryptor::sym_algo`]: #method.sym_algo
    ///   [`Encryptor::aead_algo`]: #method.aead_algo
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
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
    /// #    awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    /// #    =lAie
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption();
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::for_recipients(message, recipients).build()?;
    /// let mut w = LiteralWriter::new(message).build()?;
    /// w.write_all(b"Hello world.")?;
    /// w.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn for_recipients<R>(inner: Message<'a>, recipients: R) -> Self
        where R: IntoIterator,
              R::Item: Into<Recipient<'a>>,
    {
            Self {
            inner: Some(inner.into()),
            recipients: recipients.into_iter().map(|r| r.into()).collect(),
            passwords: Vec::new(),
            sym_algo: Default::default(),
            aead_algo: Default::default(),
            hash: HashAlgorithm::SHA1.context().unwrap(),
            cookie: Default::default(), // Will be fixed in build.
        }
    }

    /// Creates a new encryptor for the given passwords.
    ///
    /// To add more passwords, use [`Encryptor::add_password`].  To
    /// add an recipient, use [`Encryptor::add_recipient`].  To change
    /// the symmetric encryption algorithm, use
    /// [`Encryptor::sym_algo`].  To enable the experimental AEAD
    /// encryption, use [`Encryptor::aead_algo`].
    ///
    ///   [`Encryptor::add_recipient`]: #method.add_recipient
    ///   [`Encryptor::add_password`]: #method.add_password
    ///   [`Encryptor::sym_algo`]: #method.sym_algo
    ///   [`Encryptor::aead_algo`]: #method.aead_algo
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message = Encryptor::with_passwords(
    ///     message, Some("совершенно секретно")).build()?;
    /// let mut w = LiteralWriter::new(message).build()?;
    /// w.write_all(b"Hello world.")?;
    /// w.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn with_passwords<P>(inner: Message<'a>, passwords: P) -> Self
        where P: IntoIterator,
              P::Item: Into<Password>,
    {
        Self {
            inner: Some(inner.into()),
            recipients: Vec::new(),
            passwords: passwords.into_iter().map(|p| p.into()).collect(),
            sym_algo: Default::default(),
            aead_algo: Default::default(),
            hash: HashAlgorithm::SHA1.context().unwrap(),
            cookie: Default::default(), // Will be fixed in build.
        }
    }

    /// Adds recipients.
    ///
    /// The resulting message can be encrypted by any recipient and
    /// with any password.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
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
    /// #    awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    /// #    =lAie
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption();
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///     .add_recipients(recipients)
    ///     .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_recipients<R>(mut self, recipients: R) -> Self
        where R: IntoIterator,
              R::Item: Into<Recipient<'a>>,
    {
        for r in recipients {
            self.recipients.push(r.into());
        }
        self
    }

    /// Adds passwords to encrypt with.
    ///
    /// The resulting message can be encrypted with any password and
    /// by any recipient.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    /// use openpgp::policy::StandardPolicy;
    /// # use openpgp::parse::Parse;
    /// let p = &StandardPolicy::new();
    ///
    /// let cert = Cert::from_bytes(
    /// #   // We do some acrobatics here to abbreviate the Cert.
    ///     "-----BEGIN PGP PUBLIC KEY BLOCK-----
    ///
    ///      mQENBFpxtsABCADZcBa1Q3ZLZnju18o0+t8LoQuIIeyeUQ0H45y6xUqyrD5HSkVM
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
    /// #    awwPdWWvZSyXJAPZ9lC5sTKwMJDwIxILug==
    /// #    =lAie
    /// #    -----END PGP PUBLIC KEY BLOCK-----"
    /// #    /*
    ///      ...
    ///      -----END PGP PUBLIC KEY BLOCK-----"
    /// #    */
    /// )?;
    ///
    /// let recipients =
    ///     cert.keys().with_policy(p, None).alive().revoked(false)
    ///     // Or `for_storage_encryption()`, for data at rest.
    ///     .for_transport_encryption();
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::for_recipients(message, recipients)
    ///         .add_passwords(Some("совершенно секретно"))
    ///         .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn add_passwords<P>(mut self, passwords: P) -> Self
        where P: IntoIterator,
              P::Item: Into<Password>,
    {
        for p in passwords {
            self.passwords.push(p.into());
        }
        self
    }

    /// Sets the symmetric algorithm to use.
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SymmetricAlgorithm;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///         .symmetric_algo(SymmetricAlgorithm::AES128)
    ///         .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn symmetric_algo(mut self, algo: SymmetricAlgorithm) -> Self {
        self.sym_algo = algo;
        self
    }

    /// Enables AEAD and sets the AEAD algorithm to use.
    ///
    /// This feature is [experimental](../../index.html#experimental-features).
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::AEADAlgorithm;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///         .aead_algo(AEADAlgorithm::EAX)
    ///         .build()?;
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn aead_algo(mut self, algo: AEADAlgorithm) -> Self {
        self.aead_algo = Some(algo);
        self
    }

    // The default chunk size.
    //
    // A page, 3 per mille overhead.
    const AEAD_CHUNK_SIZE : usize = 4096;

    /// Builds the encryptor, returning the writer stack.
    ///
    /// The most useful filters to push to the writer stack next are
    /// the [`Padder`] or [`Compressor`], and after that the
    /// [`Signer`].  Finally, literal data *must* be wrapped using the
    /// [`LiteralWriter`].
    ///
    ///   [`Compressor`]: struct.Compressor.html
    ///   [`Padder`]: padding/struct.Padder.html
    ///   [`Signer`]: struct.Signer.html
    ///   [`LiteralWriter`]: struct.LiteralWriter.html
    ///
    /// # Example
    ///
    /// ```
    /// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
    /// use std::io::Write;
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::serialize::stream::{
    ///     Message, Encryptor, LiteralWriter,
    /// };
    ///
    /// # let mut sink = vec![];
    /// let message = Message::new(&mut sink);
    /// let message =
    ///     Encryptor::with_passwords(message, Some("совершенно секретно"))
    ///         // Customize the `Encryptor` here.
    ///         .build()?;
    ///
    /// // Optionally add a `Padder` or `Compressor` here.
    /// // Optionally add a `Signer` here.
    ///
    /// let mut message = LiteralWriter::new(message).build()?;
    /// message.write_all(b"Hello world.")?;
    /// message.finalize()?;
    /// # Ok(()) }
    /// ```
    pub fn build(mut self) -> Result<Message<'a>> {
        if self.recipients.len() + self.passwords.len() == 0 {
            return Err(Error::InvalidOperation(
                "Neither recipients nor passwords given".into()).into());
        }

        struct AEADParameters {
            algo: AEADAlgorithm,
            chunk_size: usize,
            nonce: Box<[u8]>,
        }

        let aead = if let Some(algo) = self.aead_algo {
            let mut nonce = vec![0; algo.iv_size()?];
            crypto::random(&mut nonce);
            Some(AEADParameters {
                algo,
                chunk_size: Self::AEAD_CHUNK_SIZE,
                nonce: nonce.into_boxed_slice(),
            })
        } else {
            None
        };

        let mut inner = self.inner.take().expect("Added in constructors");
        let level = inner.as_ref().cookie_ref().level + 1;

        // Generate a session key.
        let sk = SessionKey::new(self.sym_algo.key_size()?);

        // Write the PKESK packet(s).
        for recipient in self.recipients.iter() {
            let mut pkesk =
                PKESK3::for_recipient(self.sym_algo, &sk, recipient.key)?;
            pkesk.set_recipient(recipient.keyid.clone());
            Packet::PKESK(pkesk.into()).serialize(&mut inner)?;
        }

        // Write the SKESK packet(s).
        for password in self.passwords.iter() {
            if let Some(aead) = aead.as_ref() {
                let skesk = SKESK5::with_password(self.sym_algo, aead.algo,
                                                  Default::default(),
                                                  &sk, password).unwrap();
                Packet::SKESK(skesk.into()).serialize(&mut inner)?;
            } else {
                let skesk = SKESK4::with_password(self.sym_algo,
                                                  Default::default(),
                                                  &sk, password).unwrap();
                Packet::SKESK(skesk.into()).serialize(&mut inner)?;
            }
        }

        if let Some(aead) = aead {
            // Write the AED packet.
            CTB::new(Tag::AED).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(Message::from(inner),
                                                   Cookie::new(level));
            let aed = AED1::new(self.sym_algo, aead.algo,
                                aead.chunk_size as u64, aead.nonce)?;
            aed.serialize_headers(&mut inner)?;

            writer::AEADEncryptor::new(
                inner.into(),
                Cookie::new(level),
                aed.symmetric_algo(),
                aed.aead(),
                aead.chunk_size,
                aed.iv(),
                &sk,
            )
        } else {
            // Write the SEIP packet.
            CTB::new(Tag::SEIP).serialize(&mut inner)?;
            let mut inner = PartialBodyFilter::new(Message::from(inner),
                                                   Cookie::new(level));
            inner.write_all(&[1])?; // Version.

            // Install encryptor.
            self.inner = Some(writer::Encryptor::new(
                inner.into(),
                Cookie::new(level),
                self.sym_algo,
                &sk,
            )?.into());
            self.cookie = Cookie::new(level);

            // Write the initialization vector, and the quick-check
            // bytes.  The hash for the MDC must include the
            // initialization vector, hence we must write this to
            // self after installing the encryptor at self.inner.
            let mut iv = vec![0; self.sym_algo.block_size()?];
            crypto::random(&mut iv);
            self.write_all(&iv)?;
            self.write_all(&iv[iv.len() - 2..])?;

            Ok(Message::from(Box::new(self)))
        }
    }

    /// Emits the MDC packet and recovers the original writer.
    fn emit_mdc(&mut self) -> Result<writer::BoxStack<'a, Cookie>> {
        if let Some(mut w) = self.inner.take() {
            // Write the MDC, which must be the last packet inside the
            // encrypted packet stream.  The hash includes the MDC's
            // CTB and length octet.
            let mut header = Vec::new();
            CTB::new(Tag::MDC).serialize(&mut header)?;
            BodyLength::Full(20).serialize(&mut header)?;

            self.hash.update(&header);
            Packet::MDC(MDC::from(self.hash.clone())).serialize(&mut w)?;

            // Now recover the original writer.  First, strip the
            // Encryptor.
            let w = w.into_inner()?.unwrap();
            // And the partial body filter.
            let w = w.into_inner()?.unwrap();

            Ok(w)
        } else {
            Err(Error::InvalidOperation(
                "Inner writer already taken".into()).into())
        }
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
    fn pop(&mut self) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        unreachable!("Only implemented by Signer")
    }
    /// Sets the inner stackable.
    fn mount(&mut self, _new: writer::BoxStack<'a, Cookie>) {
        unreachable!("Only implemented by Signer")
    }
    fn inner_ref(&self) -> Option<&dyn writer::Stackable<'a, Cookie>> {
        self.inner.as_ref().map(|r| r.as_ref())
    }
    fn inner_mut(&mut self) -> Option<&mut dyn writer::Stackable<'a, Cookie>> {
        if let Some(ref mut i) = self.inner {
            Some(i)
        } else {
            None
        }
    }
    fn into_inner(mut self: Box<Self>) -> Result<Option<writer::BoxStack<'a, Cookie>>> {
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
    fn position(&self) -> u64 {
        self.inner.as_ref().map(|i| i.position()).unwrap_or(0)
    }
}

#[cfg(test)]
mod test {
    use std::io::Read;
    use crate::{Packet, PacketPile, packet::CompressedData};
    use crate::parse::{Parse, PacketParserResult, PacketParser};
    use super::*;
    use crate::types::DataFormat::Text as T;
    use crate::policy::Policy;
    use crate::policy::StandardPolicy as P;

    #[test]
    fn arbitrary() {
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let mut ustr = ArbitraryWriter::new(m, Tag::Literal).unwrap();
            ustr.write_all(b"t").unwrap(); // type
            ustr.write_all(b"\x00").unwrap(); // fn length
            ustr.write_all(b"\x00\x00\x00\x00").unwrap(); // date
            ustr.write_all(b"Hello world.").unwrap(); // body
            ustr.finalize().unwrap();
        }

        let mut pp = PacketParser::from_bytes(&o).unwrap().unwrap();
        if let Packet::Literal(ref l) = pp.packet {
                assert_eq!(l.format(), DataFormat::Text);
                assert_eq!(l.filename(), None);
                assert_eq!(l.date(), None);
        } else {
            panic!("Unexpected packet type.");
        }

        let mut body = vec![];
        pp.read_to_end(&mut body).unwrap();
        assert_eq!(&body, b"Hello world.");

        // Make sure it is the only packet.
        let (_, ppr) = pp.recurse().unwrap();
        assert!(ppr.is_none());
    }

    // Create some crazy nesting structures, serialize the messages,
    // reparse them, and make sure we get the same result.
    #[test]
    fn stream_0() {
        // 1: CompressedData(CompressedData { algo: 0 })
        //  1: Literal(Literal { body: "one (3 bytes)" })
        //  2: Literal(Literal { body: "two (3 bytes)" })
        // 2: Literal(Literal { body: "three (5 bytes)" })
        let mut one = Literal::new(T);
        one.set_body(b"one".to_vec());
        let mut two = Literal::new(T);
        two.set_body(b"two".to_vec());
        let mut three = Literal::new(T);
        three.set_body(b"three".to_vec());
        let mut reference = Vec::new();
        reference.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(one.into())
                .push(two.into())
                .into());
        reference.push(three.into());

        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c = Compressor::new(m)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "one").unwrap();
            let c = ls.finalize_one().unwrap().unwrap(); // Pop the LiteralWriter.
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "two").unwrap();
            let c = ls.finalize_one().unwrap().unwrap(); // Pop the LiteralWriter.
            let c = c.finalize_one().unwrap().unwrap(); // Pop the Compressor.
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "three").unwrap();
            ls.finalize().unwrap();
        }

        let pile = PacketPile::from(reference);
        let pile2 = PacketPile::from_bytes(&o).unwrap();
        if pile != pile2 {
            eprintln!("REFERENCE...");
            pile.pretty_print();
            eprintln!("REPARSED...");
            pile2.pretty_print();
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
        let mut one = Literal::new(T);
        one.set_body(b"one".to_vec());
        let mut two = Literal::new(T);
        two.set_body(b"two".to_vec());
        let mut three = Literal::new(T);
        three.set_body(b"three".to_vec());
        let mut four = Literal::new(T);
        four.set_body(b"four".to_vec());
        let mut reference = Vec::new();
        reference.push(
            CompressedData::new(CompressionAlgorithm::Uncompressed)
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(one.into())
                      .push(two.into())
                      .into())
                .push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                      .push(three.into())
                      .push(four.into())
                      .into())
                .into());

        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c0 = Compressor::new(m)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let c = Compressor::new(c0)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "one").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "two").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let c0 = c.finalize_one().unwrap().unwrap();
            let c = Compressor::new(c0)
                .algo(CompressionAlgorithm::Uncompressed).build().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "three").unwrap();
            let c = ls.finalize_one().unwrap().unwrap();
            let mut ls = LiteralWriter::new(c).format(T).build().unwrap();
            write!(ls, "four").unwrap();
            ls.finalize().unwrap();
        }

        let pile = PacketPile::from(reference);
        let pile2 = PacketPile::from_bytes(&o).unwrap();
        if pile != pile2 {
            eprintln!("REFERENCE...");
            pile.pretty_print();
            eprintln!("REPARSED...");
            pile2.pretty_print();
            panic!("Reparsed packet does not match reference packet!");
        }
    }

    #[cfg(feature = "compression-bzip2")]
    #[test]
    fn stream_big() {
        let zeros = vec![0; 1024 * 1024 * 4];
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let c = Compressor::new(m)
                .algo(CompressionAlgorithm::BZip2).build().unwrap();
            let mut ls = LiteralWriter::new(c).build().unwrap();
            // Write 64 megabytes of zeroes.
            for _ in 0 .. 16 {
                ls.write_all(&zeros).unwrap();
            }
        }
        assert!(o.len() < 1024);
    }

    #[test]
    fn signature() {
        let p = &P::new();
        use crate::crypto::KeyPair;
        use std::collections::HashMap;
        use crate::Fingerprint;

        let mut keys: HashMap<Fingerprint, key::UnspecifiedPublic> = HashMap::new();
        for tsk in &[
            Cert::from_bytes(crate::tests::key("testy-private.pgp")).unwrap(),
            Cert::from_bytes(crate::tests::key("testy-new-private.pgp")).unwrap(),
        ] {
            for key in tsk.keys().with_policy(p, crate::frozen_time())
                .for_signing().map(|ka| ka.key())
            {
                keys.insert(key.fingerprint(), key.clone());
            }
        }

        let mut o = vec![];
        {
            let mut signers = keys.iter().map(|(_, key)| {
                key.clone().parts_into_secret().unwrap().into_keypair()
                    .expect("expected unencrypted secret key")
            }).collect::<Vec<KeyPair>>();

            let m = Message::new(&mut o);
            let mut signer = Signer::new(m, signers.pop().unwrap());
            for s in signers.into_iter() {
                signer = signer.add_signer(s);
            }
            let signer = signer.build().unwrap();
            let mut ls = LiteralWriter::new(signer).build().unwrap();
            ls.write_all(b"Tis, tis, tis.  Tis is important.").unwrap();
            let _ = ls.finalize().unwrap();
        }

        let mut ppr = PacketParser::from_bytes(&o).unwrap();
        let mut good = 0;
        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(ref sig) = pp.packet {
                let key = keys.get(&sig.issuer_fingerprint().unwrap())
                    .unwrap();
                sig.verify(key).unwrap();
                good += 1;
            }

            // Get the next packet.
            ppr = pp.recurse().unwrap().1;
        }
        assert_eq!(good, 2);
    }

    #[test]
    fn encryptor() {
        let passwords = vec!["streng geheim".into(),
                             "top secret".into()];
        let message = b"Hello world.";

        // Write a simple encrypted message...
        let mut o = vec![];
        {
            let m = Message::new(&mut o);
            let encryptor = Encryptor::with_passwords(m, passwords.clone())
                .build().unwrap();
            let mut literal = LiteralWriter::new(encryptor).build()
                .unwrap();
            literal.write_all(message).unwrap();
            literal.finalize().unwrap();
        }

        // ... and recover it...
        #[derive(Debug, PartialEq)]
        enum State {
            Start,
            Decrypted(Vec<(SymmetricAlgorithm, SessionKey)>),
            Deciphered,
            MDC,
            Done,
        }

        // ... with every password.
        for password in &passwords {
            let mut state = State::Start;
            let mut ppr = PacketParser::from_bytes(&o).unwrap();
            while let PacketParserResult::Some(mut pp) = ppr {
                state = match state {
                    // Look for the SKESK packet.
                    State::Start =>
                        if let Packet::SKESK(ref skesk) = pp.packet {
                            match skesk.decrypt(password) {
                                Ok((algo, key))
                                    => State::Decrypted(
                                        vec![(algo, key)]),
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
                                        let r = pp.decrypt(algo, &key);
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
                                        keys.push((algo, key));
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
                            assert_eq!(mdc.digest(), mdc.computed_digest());
                            State::Done
                        } else {
                            panic!("Unexpected packet: {:?}", pp.packet)
                        },

                    State::Done =>
                        panic!("Unexpected packet: {:?}", pp.packet),
                };

                // Next?
                ppr = pp.recurse().unwrap().1;
            }
            assert_eq!(state, State::Done);
        }
    }

    #[test]
    fn aead_messages() -> Result<()> {
        // AEAD data is of the form:
        //
        //   [ chunk1 ][ tag1 ] ... [ chunkN ][ tagN ][ tag ]
        //
        // All chunks are the same size except for the last chunk, which may
        // be shorter.
        //
        // In `Decryptor::read_helper`, we read a chunk and a tag worth of
        // data at a time.  Because only the last chunk can be shorter, if
        // the amount read is less than `chunk_size + tag_size`, then we know
        // that we've read the last chunk.
        //
        // Unfortunately, this is not sufficient: if the last chunk is
        // `chunk_size - tag size` bytes large, then when we read it, we'll
        // read `chunk_size + tag_size` bytes, because we'll have also read
        // the final tag!
        //
        // Make sure we handle this situation correctly.

        use std::cmp;

        use crate::parse::{
            stream::{
                DecryptorBuilder,
                DecryptionHelper,
                VerificationHelper,
                MessageStructure,
            },
        };
        use crate::cert::prelude::*;
        use crate::serialize::stream::{LiteralWriter, Message};

        let (tsk, _) = CertBuilder::new()
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_transport_encryption_subkey()
            .generate().unwrap();

        struct Helper<'a> {
            policy: &'a dyn Policy,
            tsk: &'a Cert,
        };
        impl<'a> VerificationHelper for Helper<'a> {
            fn get_certs(&mut self, _ids: &[crate::KeyHandle])
                               -> Result<Vec<Cert>> {
                Ok(Vec::new())
            }
            fn check(&mut self, _structure: MessageStructure) -> Result<()> {
                Ok(())
            }
        }
        impl<'a> DecryptionHelper for Helper<'a> {
            fn decrypt<D>(&mut self, pkesks: &[PKESK], _skesks: &[SKESK],
                          sym_algo: Option<SymmetricAlgorithm>,
                          mut decrypt: D) -> Result<Option<crate::Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
            {
                let mut keypair = self.tsk.keys().with_policy(self.policy, None)
                    .for_transport_encryption()
                    .map(|ka| ka.key()).next().unwrap()
                    .clone().parts_into_secret().unwrap()
                    .into_keypair().unwrap();
                pkesks[0].decrypt(&mut keypair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key));
                Ok(None)
            }
        }

        let p = &P::new();

        for chunks in 0..3 {
            for msg_len in
                      cmp::max(24, chunks * Encryptor::AEAD_CHUNK_SIZE) - 24
                          ..chunks * Encryptor::AEAD_CHUNK_SIZE + 24
            {
                eprintln!("Encrypting message of size: {}", msg_len);

                let mut content : Vec<u8> = Vec::new();
                for i in 0..msg_len {
                    content.push(b'0' + ((i % 10) as u8));
                }

                let mut msg = vec![];
                {
                    let m = Message::new(&mut msg);
                    let recipients = tsk
                        .keys().with_policy(p, None)
                        .for_storage_encryption().for_transport_encryption();
                    let encryptor = Encryptor::for_recipients(m, recipients)
                        .aead_algo(AEADAlgorithm::EAX)
                        .build().unwrap();
                    let mut literal = LiteralWriter::new(encryptor).build()
                        .unwrap();
                    literal.write_all(&content).unwrap();
                    literal.finalize().unwrap();
                }

                for &read_len in &[
                    37,
                    Encryptor::AEAD_CHUNK_SIZE - 1,
                    Encryptor::AEAD_CHUNK_SIZE,
                    100 * Encryptor::AEAD_CHUNK_SIZE
                ] {
                    for &do_err in &[ false, true ] {
                        let mut msg = msg.clone();
                        if do_err {
                            let l = msg.len() - 1;
                            if msg[l] == 0 {
                                msg[l] = 1;
                            } else {
                                msg[l] = 0;
                            }
                        }

                        let h = Helper { policy: p, tsk: &tsk };
                        // Note: a corrupted message is only guaranteed
                        // to error out before it returns EOF.
                        let mut v = match DecryptorBuilder::from_bytes(&msg)?
                            .with_policy(p, None, h)
                        {
                            Ok(v) => v,
                            Err(_) if do_err => continue,
                            Err(err) => panic!("Decrypting message: {}", err),
                        };

                        let mut buffer = Vec::new();
                        buffer.resize(read_len, 0);

                        let mut decrypted_content = Vec::new();
                        loop {
                            match v.read(&mut buffer[..read_len]) {
                                Ok(0) if do_err =>
                                    panic!("Expected an error, got EOF"),
                                Ok(0) => break,
                                Ok(len) =>
                                    decrypted_content.extend_from_slice(
                                        &buffer[..len]),
                                Err(_) if do_err => break,
                                Err(err) =>
                                    panic!("Decrypting data: {:?}", err),
                            }
                        }

                        if do_err {
                            // If we get an error once, we should get
                            // one again.
                            for _ in 0..3 {
                                assert!(v.read(&mut buffer[..read_len]).is_err());
                            }
                        }

                        // We only corrupted the final tag, so we
                        // should get all of the content.
                        assert_eq!(msg_len, decrypted_content.len());
                        assert_eq!(content, decrypted_content);
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn signature_at_time() {
        // Generates a signature with a specific Signature Creation
        // Time.
        use crate::cert::prelude::*;
        use crate::serialize::stream::{LiteralWriter, Message};
        use crate::crypto::KeyPair;

        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .add_signing_subkey()
            .set_cipher_suite(CipherSuite::Cv25519)
            .generate().unwrap();

        // What we're going to sign with.
        let ka = cert.keys().with_policy(p, None).for_signing().nth(0).unwrap();

        // A timestamp later than the key's creation.
        let timestamp = ka.key().creation_time()
            + std::time::Duration::from_secs(14 * 24 * 60 * 60);
        assert!(ka.key().creation_time() < timestamp);

        let mut o = vec![];
        {
            let signer_keypair : KeyPair =
                ka.key().clone().parts_into_secret().unwrap().into_keypair()
                    .expect("expected unencrypted secret key");

            let m = Message::new(&mut o);
            let signer = Signer::new(m, signer_keypair);
            let signer = signer.creation_time(timestamp);
            let signer = signer.build().unwrap();

            let mut ls = LiteralWriter::new(signer).build().unwrap();
            ls.write_all(b"Tis, tis, tis.  Tis is important.").unwrap();
            let signer = ls.finalize_one().unwrap().unwrap();
            let _ = signer.finalize_one().unwrap().unwrap();
        }

        let mut ppr = PacketParser::from_bytes(&o).unwrap();
        let mut good = 0;
        while let PacketParserResult::Some(pp) = ppr {
            if let Packet::Signature(ref sig) = pp.packet {
                assert_eq!(sig.signature_creation_time(), Some(timestamp));
                sig.verify(ka.key()).unwrap();
                good += 1;
            }

            // Get the next packet.
            ppr = pp.recurse().unwrap().1;
        }
        assert_eq!(good, 1);
    }
}
