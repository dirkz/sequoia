//! Padding for OpenPGP messages.
//!
//! To reduce the amount of information leaked via the message length,
//! encrypted OpenPGP messages should be padded.
//!
//! # Padding in OpenPGP
//!
//! There are a number of ways to pad messages within the boundaries
//! of the OpenPGP protocol, keeping an eye on backwards-compatibility
//! with common implementations:
//!
//!   - Add a decoy notation to a signature packet (up to about 60k)
//!
//!   - Add a signature with a private algorithm and store the decoy
//!     traffic in the MPIs (up to 4 GB)
//!
//!   - Use a compression container and store the decoy traffic in a
//!     chunk that decompresses to the empty string (unlimited)
//!
//!   - Use a bunch of marker packets, which are ignored (each packet:
//!     3 bytes for the body, 5 bytes for the header)
//!
//!   - Apparently, GnuPG understands a comment packet (tag: 61),
//!     which is not standardized (up to 64k)
//!
//! We believe that padding the compressed data stream is the best
//! option, because as far as OpenPGP is concerned, it is completely
//! transparent for the recipient (for example, no weird packets are
//! inserted).
//!
//! Cursory testing (OpenKeychain, GnuPG) revealed no problems.
//!
//! To be effective, the padding layer must be placed inside the
//! encryption container.  To increase compatibility, the padding
//! layer must not be signed.  That is to say, the message structure
//! should be `(encryption (padding ops literal signature))`, the
//! exact structure GnuPG emits by default.
use std::fmt;
use std::io::{self, Write};

use crate::{
    Result,
    packet::prelude::*,
};
use crate::packet::header::CTB;
use super::{
    PartialBodyFilter,
    Serialize,
    writer,
    stream::Cookie,
};
use crate::types::{
    CompressionAlgorithm,
};

/// Pads a packet stream.
///
/// Writes a compressed data packet containing all packets written to
/// this writer, and pads it according to the given policy.
///
/// The policy is a `Fn(u64) -> u64`, that given the number of bytes
/// written to this writer `N`, computes the size the compression
/// container should be padded up to.  It is an error to return a
/// number that is smaller than `N`.
///
/// # Compatibility
///
/// This implementation uses the [DEFLATE] compression format.  The
/// packet structure contains a flag signaling the end of the stream
/// (see [Section 3.2.3 of RFC 1951]), and any data appended after
/// that is not part of the stream.
///
/// [DEFLATE]: https://tools.ietf.org/html/rfc1951
/// [Section 3.2.3 of RFC 1951]: https://tools.ietf.org/html/rfc1951#page-9
///
/// [Section 9.3 of RFC 4880] recommends that this algorithm should be
/// implemented, therefore support across various implementations
/// should be good.
///
/// [Section 9.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-9.3
///
/// # Example
///
/// This example illustrates the use of `Padder` with the [Padmé]
/// policy.  Note that for brevity, the encryption and signature
/// filters are omitted.
///
/// [Padmé]: fn.padme.html
///
/// ```
/// extern crate sequoia_openpgp as openpgp;
/// use std::io::Write;
/// use openpgp::serialize::stream::{Message, LiteralWriter};
/// use openpgp::serialize::padding::{Padder, padme};
/// use openpgp::types::CompressionAlgorithm;
/// # use openpgp::Result;
/// # f().unwrap();
/// # fn f() -> Result<()> {
///
/// let mut unpadded = vec![];
/// {
///     let message = Message::new(&mut unpadded);
///     // XXX: Insert Encryptor here.
///     // XXX: Insert Signer here.
///     let mut w = LiteralWriter::new(message).build()?;
///     w.write_all(b"Hello world.")?;
///     w.finalize()?;
/// }
///
/// let mut padded = vec![];
/// {
///     let message = Message::new(&mut padded);
///     // XXX: Insert Encryptor here.
///     let padder = Padder::new(message, padme)?;
///     // XXX: Insert Signer here.
///     let mut w = LiteralWriter::new(padder).build()?;
///     w.write_all(b"Hello world.")?;
///     w.finalize()?;
/// }
/// assert!(unpadded.len() < padded.len());
/// # Ok(())
/// # }
pub struct Padder<'a, P: Fn(u64) -> u64 + 'a> {
    inner: writer::BoxStack<'a, Cookie>,
    policy: P,
}

impl<'a, P: Fn(u64) -> u64 + 'a> Padder<'a, P> {
    /// Creates a new padder with the given policy.
    pub fn new(inner: writer::Stack<'a, Cookie>, p: P)
               -> Result<writer::Stack<'a, Cookie>> {
        let mut inner = writer::BoxStack::from(inner);
        let level = inner.cookie_ref().level + 1;

        // Packet header.
        CTB::new(Tag::CompressedData).serialize(&mut inner)?;
        let mut inner: writer::Stack<'a, Cookie>
            = PartialBodyFilter::new(writer::Stack::from(inner),
                                     Cookie::new(level));

        // Compressed data header.
        inner.as_mut().write_u8(CompressionAlgorithm::Zip.into())?;

        // Create an appropriate filter.
        let inner: writer::Stack<'a, Cookie> =
            writer::ZIP::new(inner, Cookie::new(level),
                             writer::CompressionLevel::none());

        Ok(writer::Stack::from(Box::new(Self {
            inner: inner.into(),
            policy: p,
        })))
    }
}

impl<'a, P: Fn(u64) -> u64 + 'a> fmt::Debug for Padder<'a, P> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Padder")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, P: Fn(u64) -> u64 + 'a> io::Write for Padder<'a, P> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<'a, P: Fn(u64) -> u64 + 'a> writer::Stackable<'a, Cookie> for Padder<'a, P>
{
    fn into_inner(self: Box<Self>)
                  -> Result<Option<writer::BoxStack<'a, Cookie>>> {
        // Make a note of the amount of data written to this filter.
        let uncompressed_size = self.position();

        // Pop-off us and the compression filter, leaving only our
        // partial body encoder on the stack.  This finalizes the
        // compression.
        let mut pb_writer = Box::new(self.inner).into_inner()?.unwrap();

        // Compressed size is what we've actually written out, modulo
        // partial body encoding.
        let compressed_size = pb_writer.position();

        // Sometimes, the compression step expands the data.  Handle
        // this by padding the maximum of both sizes.
        let size = std::cmp::max(uncompressed_size, compressed_size);

        // Compute the amount of padding required according to the
        // given policy.
        let padded_size = (self.policy)(size);
        if padded_size < size {
            return Err(crate::Error::InvalidOperation(
                format!("Padding policy({}) returned {}: smaller than argument",
                        size, padded_size)).into());
        }
        let mut amount = padded_size - compressed_size;

        if false {
            eprintln!("u: {}, c: {}, amount: {}",
                      uncompressed_size, compressed_size, amount);
        }

        // Write 'amount' of padding.
        const BUFFER_SIZE: usize = 4096;
        let mut padding = vec![0; BUFFER_SIZE];
        while amount > 0 {
            let n = std::cmp::min(BUFFER_SIZE as u64, amount) as usize;
            crate::crypto::random(&mut padding[..n]);
            pb_writer.write_all(&padding[..n])?;
            amount -= n as u64;
        }

        pb_writer.into_inner()
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

/// Padmé padding scheme.
///
/// Padmé leaks at most O(log log M) bits of information (with M being
/// the maximum length of all messages) with an overhead of at most
/// 12%, decreasing with message size.
///
/// This scheme leaks the same order of information as padding to the
/// next power of two, while avoiding an overhead of up to 100%.
///
/// See Section 4 of [Reducing Metadata Leakage from Encrypted Files
/// and Communication with
/// PURBs](https://bford.info/pub/sec/purb.pdf).
pub fn padme(l: u64) -> u64 {
    if l < 2 {
        return 1; // Avoid cornercase.
    }

    let e = log2(l);               // l's floating-point exponent
    let s = log2(e as u64) + 1;    // # of bits to represent e
    let z = e - s;                 // # of low bits to set to 0
    let m = (1 << z) - 1;          // mask of z 1's in LSB
    (l + (m as u64)) & !(m as u64) // round up using mask m to clear last z bits
}

/// Compute the log2 of an integer.  (This is simply the most
/// significant bit.)  Note: log2(0) = -Inf, but this function returns
/// log2(0) as 0 (which is the closest number that we can represent).
fn log2(x: u64) -> usize {
    if x == 0 {
        0
    } else {
        63 - x.leading_zeros() as usize
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn log2_test() {
        for i in 0..64 {
            assert_eq!(log2(1u64 << i), i);
            if i > 0 {
                assert_eq!(log2((1u64 << i) - 1), i - 1);
                assert_eq!(log2((1u64 << i) + 1), i);
            }
        }
    }

    fn padme_multiplicative_overhead(p: u64) -> f32 {
        let c = padme(p);
        let (p, c) = (p as f32, c as f32);
        (c - p) / p
    }

    #[test]
    fn padme_max_overhead() {
        assert!(0.111 < padme_multiplicative_overhead(9));
        assert!(padme_multiplicative_overhead(9) < 0.112);
    }

    quickcheck! {
        fn padme_overhead(l: u32) -> bool {
            if l < 2 {
                return true; // Avoid cornercase.
            }

            let o = padme_multiplicative_overhead(l as u64);
            let l_ = l as f32;
            let e = l_.log2().floor();     // l's floating-point exponent
            let s = e.log2().floor() + 1.; // # of bits to represent e
            let max_overhead = (2.0_f32.powf(e-s) - 1.) / l_;

            assert!(o < 0.112);
            assert!(o <= max_overhead,
                    "padme({}): overhead {} exceeds maximum overhead {}",
                    l, o, max_overhead);
            true
        }
    }

    /// Asserts that we can consume the padded messages.
    #[test]
    fn roundtrip() {
        use std::io::Write;
        use crate::parse::Parse;
        use crate::serialize::stream::*;

        let mut msg = vec![0; rand::random::<usize>() % 1024];
        crate::crypto::random(&mut msg);

        let mut padded = vec![];
        {
            let message = Message::new(&mut padded);
            let padder = Padder::new(message, padme).unwrap();
            let mut w = LiteralWriter::new(padder).build().unwrap();
            w.write_all(&msg).unwrap();
            w.finalize().unwrap();
        }

        let m = crate::Message::from_bytes(&padded).unwrap();
        assert_eq!(m.body().unwrap().body().unwrap(), &msg[..]);
    }

    /// Asserts that no actual compression is done.
    ///
    /// We want to avoid having the size of the data stream depend on
    /// the data's compressibility, therefore it is best to disable
    /// the compression.
    #[test]
    fn no_compression() {
        use std::io::Write;
        use crate::serialize::stream::*;
        const MSG: &[u8] = b"@@@@@@@@@@@@@@";
        let mut padded = vec![];
        {
            let message = Message::new(&mut padded);
            let padder = Padder::new(message, padme).unwrap();
            let mut w = LiteralWriter::new(padder).build().unwrap();
            w.write_all(MSG).unwrap();
            w.finalize().unwrap();
        }

        assert!(padded.windows(MSG.len()).any(|ch| ch == MSG),
                "Could not find uncompressed message");
    }
}
