//! A `BufferedReader` is a super-powered `Read`er.
//!
//! Like the [`BufRead`] trait, the `BufferedReader` trait has an
//! internal buffer that is directly exposed to the user.  This design
//! enables two performance optimizations.  First, the use of an
//! internal buffer amortizes system calls.  Second, exposing the
//! internal buffer allows the user to work with data in place, which
//! avoids another copy.
//!
//! The [`BufRead`] trait, however, has a significant limitation for
//! parsers: the user of a [`BufRead`] object can't control the amount
//! of buffering.  This is essential for being able to conveniently
//! work with data in place, and being able to lookahead without
//! consuming data.  The result is that either the sizing has to be
//! handled by the instantiator of the [`BufRead`] object---assuming
//! the [`BufRead`] object provides such a mechanism---which is a
//! layering violation, or the parser has to fallback to buffering if
//! the internal buffer is too small, which eliminates most of the
//! advantages of the [`BufRead`] abstraction.  The `BufferedReader`
//! trait addresses this shortcoming by allowing the user to control
//! the size of the internal buffer.
//!
//! The `BufferedReader` trait also has some functionality,
//! specifically, a generic interface to work with a stack of
//! `BufferedReader` objects, that simplifies using multiple parsers
//! simultaneously.  This is helpful when one parser deals with
//! framing (e.g., something like [HTTP's chunk transfer encoding]),
//! and another decodes the actual objects.  It is also useful when
//! objects are nested.
//!
//! # Details
//!
//! Because the [`BufRead`] trait doesn't provide a mechanism for the
//! user to size the interal buffer, a parser can't generally be sure
//! that the internal buffer will be large enough to allow it to work
//! with all data in place.
//!
//! Using the standard [`BufRead`] implementation, [`BufReader`], the
//! instantiator can set the size of the internal buffer at creation
//! time.  Unfortunately, this mechanism is ugly, and not always
//! adequate.  First, the parser is typically not the instantiator.
//! Thus, the instantiator needs to know about the implementation
//! details of all of the parsers, which turns an implementation
//! detail into a cross-cutting concern.  Second, when working with
//! dynamically sized data, the maximum amount of the data that needs
//! to be worked with in place may not be known apriori, or the
//! maximum amount may be significantly larger than the typical
//! amount.  This leads to poorly sized buffers.
//!
//! Alternatively, the code that uses, but does not instantiate a
//! [`BufRead`] object, can be changed to stream the data, or to
//! fallback to reading the data into a local buffer if the internal
//! buffer is too small.  Both of these approaches increase code
//! complexity, and the latter approach is contrary to the
//! [`BufRead`]'s goal of reducing unnecessary copying.
//!
//! The `BufferedReader` trait solves this problem by allowing the
//! user to dynamically (i.e., at read time, not open time) ensure
//! that the internal buffer has a certain amount of data.
//!
//! The ability to control the size of the internal buffer is also
//! essential to straightforward support for speculative lookahead.
//! The reason that speculative lookahead with a [`BufRead`] object is
//! difficult is that speculative lookahead is /speculative/, i.e., if
//! the parser backtracks, the data that was read must not be
//! consumed.  Using a [`BufRead`] object, this is not possible if the
//! amount of lookahead is larger than the internal buffer.  That is,
//! if the amount of lookahead data is larger than the [`BufRead`]'s
//! internal buffer, the parser first has to `BufRead::consume`() some
//! data to be able to examine more data.  But, if the parser then
//! decides to backtrack, it has no way to return the unused data to
//! the [`BufRead`] object.  This forces the parser to manage a buffer
//! of read, but unconsumed data, which significantly complicates the
//! code.
//!
//! The `BufferedReader` trait also simplifies working with a stack of
//! `BufferedReader`s in two ways.  First, the `BufferedReader` trait
//! provides *generic* methods to access the underlying
//! `BufferedReader`.  Thus, even when dealing with a trait object, it
//! is still possible to recover the underlying `BufferedReader`.
//! Second, the `BufferedReader` provides a mechanism to associate
//! generic state with each `BufferedReader` via a cookie.  Although
//! it is possible to realize this functionality using a custom trait
//! that extends the `BufferedReader` trait and wraps existing
//! `BufferedReader` implementations, this approach eliminates a lot
//! of error-prone, boilerplate code.
//!
//! # Examples
//!
//! The following examples show not only how to use a
//! `BufferedReader`, but also better illustrate the aforementioned
//! limitations of a [`BufRead`]er.
//!
//! Consider a file consisting of a sequence of objects, which are
//! laid out as follows.  Each object has a two byte header that
//! indicates the object's size in bytes.  The object immediately
//! follows the header.  Thus, if we had two objects: "foobar" and
//! "xyzzy", in that order, the file would look like this:
//!
//! ```text
//! 0 6 f o o b a r 0 5 x y z z y
//! ```
//!
//! Here's how we might parse this type of file using a
//! `BufferedReader`:
//!
//! ```
//! use buffered_reader::*;
//! use buffered_reader::BufferedReaderFile;
//!
//! fn parse_object(content: &[u8]) {
//!     // Parse the object.
//!     # let _ = content;
//! }
//!
//! # f(); fn f() -> Result<(), std::io::Error> {
//! # const FILENAME : &str = "/dev/null";
//! let mut br = BufferedReaderFile::open(FILENAME)?;
//!
//! // While we haven't reached EOF (i.e., we can read at
//! // least one byte).
//! while br.data(1)?.len() > 0 {
//!     // Get the object's length.
//!     let len = br.read_be_u16()? as usize;
//!     // Get the object's content.
//!     let content = br.data_consume_hard(len)?;
//!
//!     // Parse the actual object using a real parser.  Recall:
//!     // `data_hard`() may return more than the requested amount (but
//!     // it will never return less).
//!     parse_object(&content[..len]);
//! }
//! # Ok(()) }
//! ```
//!
//! Note that `content` is actually a pointer to the
//! `BufferedReader`'s internal buffer.  Thus, getting some data
//! doesn't require copying the data into a local buffer, which is
//! often discarded immediately after the data is parsed.
//!
//! Further, `data`() (and the other related functions) are guaranteed
//! to return at least the requested amount of data.  There are two
//! exceptions: if an error occurs, or the end of the file is reached.
//! Thus, only the cases that actually need to be handled by the user
//! are actually exposed; there is no need to call something like
//! `read`() in a loop to ensure the whole object is available.
//!
//! Because reading is separate from consuming data, it is possible to
//! get a chunk of data, inspect it, and then consume only what is
//! needed.  As mentioned above, this is only possible with a
//! [`BufRead`] object if the internal buffer happens to be large
//! enough.  Using a `BufferedReader`, this is always possible,
//! assuming the data fits in memory.
//!
//! In our example, we actually have two parsers: one that deals with
//! the framing, and one for the actual objects.  The above code
//! buffers the objects in their entirety, and then passes a slice
//! containing the object to the object parser.  If the object parser
//! also worked with a `BufferedReader` object, then less buffering
//! will usually be needed, and the two parsers could run
//! simultaneously.  This is particularly useful when the framing is
//! more complicated like [HTTP's chunk transfer encoding].  Then,
//! when the object parser reads data, the frame parser is invoked
//! lazily.  This is done by implementing the `BufferedReader` trait
//! for the framing parser, and stacking the `BufferedReader`s.
//!
//! For our next example, we rewrite the previous code asssuming that
//! the object parser reads from a `BufferedReader` object.  Since the
//! framing parser is really just a limit on the object's size, we
//! don't need to implement a special `BufferedReader`, but can use a
//! `BufferedReaderLimitor` to impose an upper limit on the amount
//! that it can read.  After the object parser has finished, we drain
//! the object reader.  This pattern is particularly helpful when
//! individual objects that contain errors should be skipped.
//!
//! ```
//! use buffered_reader::*;
//! use buffered_reader::BufferedReaderFile;
//!
//! fn parse_object<R: BufferedReader<()>>(br: &mut R) {
//!     // Parse the object.
//!     # let _ = br;
//! }
//!
//! # f(); fn f() -> Result<(), std::io::Error> {
//! # const FILENAME : &str = "/dev/null";
//! let mut br : Box<BufferedReader<()>>
//!     = Box::new(BufferedReaderFile::open(FILENAME)?);
//!
//! // While we haven't reached EOF (i.e., we can read at
//! // least one byte).
//! while br.data(1)?.len() > 0 {
//!     // Get the object's length.
//!     let len = br.read_be_u16()? as u64;
//!
//!     // Set up a limit.
//!     br = Box::new(BufferedReaderLimitor::new(br, len));
//!
//!     // Parse the actual object using a real parser.
//!     parse_object(&mut br);
//!
//!     // If the parser didn't consume the whole object, e.g., due to
//!     // a parse error, drop the rest.
//!     br.drop_eof();
//!
//!     // Recover the framing parser's `BufferedReader`.
//!     br = br.into_inner().unwrap();
//! }
//! # Ok(()) }
//! ```
//!
//! Of particular note is the generic functionality for dealing with
//! stacked `BufferedReader`s: the `into_inner`() method is not bound
//! to the implementation, which is often not be available due to type
//! erasure, but is provided by the trait.
//!
//! In addition to utility `BufferedReader`s like the
//! `BufferedReaderLimitor`, this crate also includes a few
//! general-purpose parsers, like the `BufferedReaderZip`
//! decompressor.
//!
//! [`BufRead`]: https://doc.rust-lang.org/stable/std/io/trait.BufRead.html
//! [`BufReader`]: https://doc.rust-lang.org/stable/std/io/struct.BufReader.html
//! [HTTP's chunk transfer encoding]: https://en.wikipedia.org/wiki/Chunked_transfer_encoding

#[cfg(feature = "compression-deflate")]
extern crate flate2;
#[cfg(feature = "compression-bzip2")]
extern crate bzip2;
extern crate libc;

use std::io;
use std::io::{Error, ErrorKind};
use std::cmp;
use std::fmt;

mod generic;
mod memory;
mod limitor;
mod reserve;
mod dup;
mod eof;
#[cfg(feature = "compression-deflate")]
mod decompress_deflate;
#[cfg(feature = "compression-bzip2")]
mod decompress_bzip2;

pub use self::generic::BufferedReaderGeneric;
pub use self::memory::BufferedReaderMemory;
pub use self::limitor::BufferedReaderLimitor;
pub use self::reserve::BufferedReaderReserve;
pub use self::dup::BufferedReaderDup;
pub use self::eof::BufferedReaderEOF;
#[cfg(feature = "compression-deflate")]
pub use self::decompress_deflate::BufferedReaderDeflate;
#[cfg(feature = "compression-deflate")]
pub use self::decompress_deflate::BufferedReaderZlib;
#[cfg(feature = "compression-bzip2")]
pub use self::decompress_bzip2::BufferedReaderBzip;

// These are the different BufferedReaderFile implementations.  We
// include the modules unconditionally, so that we catch bitrot early.
#[allow(dead_code)]
mod file_generic;
#[allow(dead_code)]
#[cfg(unix)]
mod file_unix;

// Then, we select the appropriate version to re-export.
#[cfg(not(unix))]
pub use self::file_generic::BufferedReaderFile;
#[cfg(unix)]
pub use self::file_unix::BufferedReaderFile;

// The default buffer size.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

/// The generic `BufferReader` interface.
pub trait BufferedReader<C> : io::Read + fmt::Debug {
    /// Returns a reference to the internal buffer.
    ///
    /// Note: this returns the same data as `self.data(0)`, but it
    /// does so without mutably borrowing self:
    ///
    /// ```
    /// # f(); fn f() -> Result<(), std::io::Error> {
    /// use buffered_reader::*;
    /// use buffered_reader::BufferedReaderMemory;
    ///
    /// let mut br = BufferedReaderMemory::new(&b"0123456789"[..]);
    ///
    /// let first = br.data(10)?.len();
    /// let second = br.buffer().len();
    /// // `buffer` must return exactly what `data` returned.
    /// assert_eq!(first, second);
    /// # Ok(()) }
    /// ```
    fn buffer(&self) -> &[u8];

    /// Ensures that the internal buffer has at least `amount` bytes
    /// of data, and returns it.
    ///
    /// If the internal buffer contains less than `amount` bytes of
    /// data, the internal buffer is first filled.
    ///
    /// The returned slice will have *at least* `amount` bytes unless
    /// EOF has been reached or an error occurs, in which case the
    /// returned slice will contain the rest of the file.
    ///
    /// If an error occurs, it is not discarded, but saved.  It is
    /// returned when `data` (or a related function) is called and the
    /// internal buffer is empty.
    ///
    /// This function does not advance the cursor.  To advance the
    /// cursor, use `consume()`.
    ///
    /// Note: If the internal buffer already contains at least
    /// `amount` bytes of data, then `BufferedReader` implementations
    /// are guaranteed to simply return the internal buffer.  As such,
    /// multiple calls to `data` for the same `amount` will return the
    /// same slice.
    ///
    /// Further, `BufferedReader` implementations are guaranteed to
    /// not shrink the internal buffer.  Thus, once some data has been
    /// returned, it will always be returned until it is consumed.
    /// As such, the following must hold:
    ///
    /// If `BufferedReader` receives `EINTR` when `read`ing, it will
    /// automatically retry reading.
    ///
    /// ```
    /// # f(); fn f() -> Result<(), std::io::Error> {
    /// use buffered_reader::*;
    /// use buffered_reader::BufferedReaderMemory;
    ///
    /// let mut br = BufferedReaderMemory::new(&b"0123456789"[..]);
    ///
    /// let first = br.data(10)?.len();
    /// let second = br.data(5)?.len();
    /// // Even though less data is requested, the second call must
    /// // return the same slice as the first call.
    /// assert_eq!(first, second);
    /// # Ok(()) }
    /// ```
    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error>;

    /// Like `data()`, but returns an error if there is not at least
    /// `amount` bytes available.
    ///
    /// `data_hard()` is a variant of `data()` that returns at least
    /// `amount` bytes of data or an error.  Thus, unlike `data()`,
    /// which will return less than `amount` bytes of data if EOF is
    /// encountered, `data_hard()` returns an error, specifically,
    /// `io::ErrorKind::UnexpectedEof`.
    ///
    /// # Examples
    ///
    /// ```
    /// # f(); fn f() -> Result<(), std::io::Error> {
    /// use buffered_reader::*;
    /// use buffered_reader::BufferedReaderMemory;
    ///
    /// let mut br = BufferedReaderMemory::new(&b"0123456789"[..]);
    ///
    /// // Trying to read more than there is available results in an error.
    /// assert!(br.data_hard(20).is_err());
    /// // Whereas with data(), everything through EOF is returned.
    /// assert_eq!(br.data(20)?.len(), 10);
    /// # Ok(()) }
    /// ```
    fn data_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        let result = self.data(amount);
        if let Ok(buffer) = result {
            if buffer.len() < amount {
                return Err(Error::new(ErrorKind::UnexpectedEof,
                                      "unexpected EOF"));
            }
        }
        return result;
    }

    /// Returns all of the data until EOF.  Like `data()`, this does not
    /// actually consume the data that is read.
    ///
    /// In general, you shouldn't use this function as it can cause an
    /// enormous amount of buffering.  But, if you know that the
    /// amount of data is limited, this is acceptable.
    ///
    /// # Examples
    ///
    /// ```
    /// # f(); fn f() -> Result<(), std::io::Error> {
    /// use buffered_reader::*;
    /// use buffered_reader::BufferedReaderGeneric;
    ///
    /// const AMOUNT : usize = 100 * 1024 * 1024;
    /// let buffer = vec![0u8; AMOUNT];
    /// let mut br = BufferedReaderGeneric::new(&buffer[..], None);
    ///
    /// // Normally, only a small amount will be buffered.
    /// assert!(br.data(10)?.len() <= AMOUNT);
    ///
    /// // `data_eof` buffers everything.
    /// assert_eq!(br.data_eof()?.len(), AMOUNT);
    ///
    /// // Now that everything is buffered, buffer(), data(), and
    /// // data_hard() will also return everything.
    /// assert_eq!(br.buffer().len(), AMOUNT);
    /// assert_eq!(br.data(10)?.len(), AMOUNT);
    /// assert_eq!(br.data_hard(10)?.len(), AMOUNT);
    /// # Ok(()) }
    /// ```
    fn data_eof(&mut self) -> Result<&[u8], io::Error> {
        // Don't just read std::usize::MAX bytes at once.  The
        // implementation might try to actually allocate a buffer that
        // large!  Instead, try with increasingly larger buffers until
        // the read is (strictly) shorter than the specified size.
        let mut s = DEFAULT_BUF_SIZE;
        while s < std::usize::MAX {
            match self.data(s) {
                Ok(ref buffer) => {
                    if buffer.len() < s {
                        // We really want to do
                        //
                        //   return Ok(buffer);
                        //
                        // But, the borrower checker won't let us:
                        //
                        //  error[E0499]: cannot borrow `*self` as
                        //  mutable more than once at a time.
                        //
                        // Instead, we break out of the loop, and then
                        // call self.data(s) again.  This extra call
                        // won't have any significant cost, because
                        // the buffer is already prepared.
                        s = buffer.len();
                        break;
                    } else {
                        s *= 2;
                    }
                }
                Err(err) =>
                    return Err(err),
            }
        }

        let buffer = self.buffer();
        assert_eq!(buffer.len(), s);
        return Ok(buffer);
    }

    /// Consumes some of the data.
    ///
    /// This advances the internal cursor by `amount`.  It is an error
    /// to call this function to consume data that hasn't been
    /// returned by `data()` or a related function.
    ///
    /// Note: It is safe to call this function to consume more data
    /// than requested in a previous call to `data()`, but only if
    /// `data()` also returned that data.
    ///
    /// This function returns the internal buffer *including* the
    /// consumed data.  Thus, the `BufferedReader` implementation must
    /// continue to buffer the consumed data until the reference goes
    /// out of scope.
    ///
    /// # Examples
    ///
    /// ```
    /// # f(); fn f() -> Result<(), std::io::Error> {
    /// use buffered_reader::*;
    /// use buffered_reader::BufferedReaderGeneric;
    ///
    /// const AMOUNT : usize = 100 * 1024 * 1024;
    /// let buffer = vec![0u8; AMOUNT];
    /// let mut br = BufferedReaderGeneric::new(&buffer[..], None);
    ///
    /// let amount = {
    ///     // We want at least 1024 bytes, but we'll be happy with
    ///     // more or less.
    ///     let buffer = br.data(1024)?;
    ///     // Parse the data or something.
    ///     let used = buffer.len();
    ///     used
    /// };
    /// let buffer = br.consume(amount);
    /// # Ok(()) }
    /// ```
    fn consume(&mut self, amount: usize) -> &[u8];

    /// A convenience function that combines `data()` and `consume()`.
    ///
    /// If less than `amount` bytes are available, this function
    /// consumes what is available.
    ///
    /// Note: Due to lifetime issues, it is not possible to call
    /// `data()`, work with the returned buffer, and then call
    /// `consume()` in the same scope, because both `data()` and
    /// `consume()` take a mutable reference to the `BufferedReader`.
    /// This function makes this common pattern easier.
    ///
    /// # Examples
    ///
    /// ```
    /// # f(); fn f() -> Result<(), std::io::Error> {
    /// use buffered_reader::*;
    /// use buffered_reader::BufferedReaderMemory;
    ///
    /// let orig = b"0123456789";
    /// let mut br = BufferedReaderMemory::new(&orig[..]);
    ///
    /// // We need a new scope for each call to `data_consume()`, because
    /// // the `buffer` reference locks `br`.
    /// {
    ///     let buffer = br.data_consume(3)?;
    ///     assert_eq!(buffer, &orig[..buffer.len()]);
    /// }
    ///
    /// // Note that the cursor has advanced.
    /// {
    ///     let buffer = br.data_consume(3)?;
    ///     assert_eq!(buffer, &orig[3..3 + buffer.len()]);
    /// }
    ///
    /// // Like `data()`, `data_consume()` may return and consume less
    /// // than request if there is no more data available.
    /// {
    ///     let buffer = br.data_consume(10)?;
    ///     assert_eq!(buffer, &orig[6..6 + buffer.len()]);
    /// }
    ///
    /// {
    ///     let buffer = br.data_consume(10)?;
    ///     assert_eq!(buffer.len(), 0);
    /// }
    /// # Ok(()) }
    /// ```
    fn data_consume(&mut self, amount: usize)
                    -> Result<&[u8], std::io::Error> {
        let amount = cmp::min(amount, self.data(amount)?.len());

        let buffer = self.consume(amount);
        assert!(buffer.len() >= amount);
        Ok(buffer)
    }

    /// A convenience function that effectively combines `data_hard()`
    /// and `consume()`.
    ///
    /// This function is identical to `data_consume()`, but internally
    /// uses `data_hard()` instead of `data()`.
    fn data_consume_hard(&mut self, amount: usize)
        -> Result<&[u8], io::Error>
    {
        let len = self.data_hard(amount)?.len();
        assert!(len >= amount);

        let buffer = self.consume(amount);
        assert!(buffer.len() >= amount);
        Ok(buffer)
    }

    /// A convenience function for reading a 16-bit unsigned integer
    /// in big endian format.
    fn read_be_u16(&mut self) -> Result<u16, std::io::Error> {
        let input = self.data_consume_hard(2)?;
        return Ok(((input[0] as u16) << 8) + (input[1] as u16));
    }

    /// A convenience function for reading a 32-bit unsigned integer
    /// in big endian format.
    fn read_be_u32(&mut self) -> Result<u32, std::io::Error> {
        let input = self.data_consume_hard(4)?;
        return Ok(((input[0] as u32) << 24) + ((input[1] as u32) << 16)
                  + ((input[2] as u32) << 8) + (input[3] as u32));
    }

    /// Reads until either `terminal` is encountered or EOF.
    ///
    /// Returns either a `&[u8]` terminating in `terminal` or the rest
    /// of the data, if EOF was encountered.
    ///
    /// Note: this function does *not* consume the data.
    ///
    /// # Examples
    ///
    /// ```
    /// # f(); fn f() -> Result<(), std::io::Error> {
    /// use buffered_reader::*;
    /// use buffered_reader::BufferedReaderMemory;
    ///
    /// let orig = b"0123456789";
    /// let mut br = BufferedReaderMemory::new(&orig[..]);
    ///
    /// {
    ///     let s = br.read_to(b'3')?;
    ///     assert_eq!(s, b"0123");
    /// }
    ///
    /// // `read_to()` doesn't consume the data.
    /// {
    ///     let s = br.read_to(b'5')?;
    ///     assert_eq!(s, b"012345");
    /// }
    ///
    /// // Even if there is more data in the internal buffer, only
    /// // the data through the match is returned.
    /// {
    ///     let s = br.read_to(b'1')?;
    ///     assert_eq!(s, b"01");
    /// }
    ///
    /// // If the terminal is not found, everything is returned...
    /// {
    ///     let s = br.read_to(b'A')?;
    ///     assert_eq!(s, orig);
    /// }
    ///
    /// // If we consume some data, the search starts at the cursor,
    /// // not the beginning of the file.
    /// br.consume(3);
    ///
    /// {
    ///     let s = br.read_to(b'5')?;
    ///     assert_eq!(s, b"345");
    /// }
    /// # Ok(()) }
    /// ```
    fn read_to(&mut self, terminal: u8) -> Result<&[u8], std::io::Error> {
        let mut n = 128;
        let len;

        loop {
            let data = self.data(n)?;

            if let Some(newline)
                = data.iter().position(|c| *c == terminal)
            {
                len = newline + 1;
                break;
            } else if data.len() < n {
                // EOF.
                len = data.len();
                break;
            } else {
                // Read more data.
                n = cmp::max(2 * n, data.len() + 1024);
            }
        }

        Ok(&self.buffer()[..len])
    }

    /// Like `data_consume_hard()`, but returns the data in a
    /// caller-owned buffer.
    ///
    /// `BufferedReader` implementations may optimize this to avoid a
    /// copy by directly returning the internal buffer.
    fn steal(&mut self, amount: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut data = self.data_consume_hard(amount)?;
        assert!(data.len() >= amount);
        if data.len() > amount {
            data = &data[..amount];
        }
        return Ok(data.to_vec());
    }

    /// Like `steal()`, but instead of stealing a fixed number of
    /// bytes, steals all of the data until the end of file.
    fn steal_eof(&mut self) -> Result<Vec<u8>, std::io::Error> {
        let len = self.data_eof()?.len();
        let data = self.steal(len)?;
        return Ok(data);
    }

    /// Like `steal_eof()`, but instead of returning the data, the
    /// data is discarded.
    ///
    /// On success, returns whether any data (i.e., at least one byte)
    /// was discarded.
    ///
    /// Note: whereas `steal_eof()` needs to buffer all of the data,
    /// this function reads the data a chunk at a time, and then
    /// discards it.  A consequence of this is that an error may occur
    /// after we have consumed some of the data.
    fn drop_eof(&mut self) -> Result<bool, std::io::Error> {
        let mut at_least_one_byte = false;
        loop {
            match self.data_consume(DEFAULT_BUF_SIZE) {
                Ok(ref buffer) => {
                    if buffer.len() > 0 {
                        at_least_one_byte = true;
                    }

                    if buffer.len() < DEFAULT_BUF_SIZE {
                        // EOF.
                        break;
                    }
                }
                Err(err) =>
                    return Err(err),
            }
        }

        Ok(at_least_one_byte)
    }

    /// Returns the underlying reader, if any.
    ///
    /// To allow this to work with `BufferedReader` traits, it is
    /// necessary for `Self` to be boxed.
    ///
    /// This can lead to the following unusual code:
    ///
    /// ```text
    /// let inner = Box::new(br).into_inner();
    /// ```
    fn into_inner<'a>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'a>>
        where Self: 'a;

    /// Returns a mutable reference to the inner `BufferedReader`, if
    /// any.
    ///
    /// It is a very bad idea to read any data from the inner
    /// `BufferedReader`, because this `BufferedReader` may have some
    /// data buffered.  However, this function can be useful to get
    /// the cookie.
    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>>;

    /// Returns a reference to the inner `BufferedReader`, if any.
    fn get_ref(&self) -> Option<&BufferedReader<C>>;

    /// Sets the `BufferedReader`'s cookie and returns the old value.
    fn cookie_set(&mut self, cookie: C) -> C;

    /// Returns a reference to the `BufferedReader`'s cookie.
    fn cookie_ref(&self) -> &C;

    /// Returns a mutable reference to the `BufferedReader`'s cookie.
    fn cookie_mut(&mut self) -> &mut C;
}

/// A generic implementation of `std::io::Read::read` appropriate for
/// any `BufferedReader` implementation.
///
/// This function implements the `std::io::Read::read` method in terms
/// of the `data_consume` method.  We can't use the `io::std::Read`
/// interface, because the `BufferedReader` may have buffered some
/// data internally (in which case a read will not return the buffered
/// data, but the following data).
///
/// This implementation is generic.  When deriving a `BufferedReader`,
/// you can include the following:
///
/// ```text
/// impl<'a, T: BufferedReader> std::io::Read for BufferedReaderXXX<'a, T> {
///     fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
///         return buffered_reader_generic_read_impl(self, buf);
///     }
/// }
/// ```
///
/// It would be nice if we could do:
///
/// ```text
/// impl <T: BufferedReader> std::io::Read for T { ... }
/// ```
///
/// but, alas, Rust doesn't like that ("error[E0119]: conflicting
/// implementations of trait `std::io::Read` for type `&mut _`").
pub fn buffered_reader_generic_read_impl<T: BufferedReader<C>, C>
        (bio: &mut T, buf: &mut [u8]) -> Result<usize, io::Error> {
    match bio.data_consume(buf.len()) {
        Ok(inner) => {
            let amount = cmp::min(buf.len(), inner.len());
            buf[0..amount].copy_from_slice(&inner[0..amount]);
            return Ok(amount);
        },
        Err(err) => return Err(err),
    }
}

/// Make a `Box<BufferedReader>` look like a BufferedReader.
impl <'a, C> BufferedReader<C> for Box<BufferedReader<C> + 'a> {
    fn buffer(&self) -> &[u8] {
        return self.as_ref().buffer();
    }

    fn data(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.as_mut().data(amount);
    }

    fn data_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.as_mut().data_hard(amount);
    }

    fn data_eof(&mut self) -> Result<&[u8], io::Error> {
        return self.as_mut().data_eof();
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        return self.as_mut().consume(amount);
    }

    fn data_consume(&mut self, amount: usize)
                    -> Result<&[u8], std::io::Error> {
        return self.as_mut().data_consume(amount);
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8], io::Error> {
        return self.as_mut().data_consume_hard(amount);
    }

    fn read_be_u16(&mut self) -> Result<u16, std::io::Error> {
        return self.as_mut().read_be_u16();
    }

    fn read_be_u32(&mut self) -> Result<u32, std::io::Error> {
        return self.as_mut().read_be_u32();
    }

    fn read_to(&mut self, terminal: u8) -> Result<&[u8], std::io::Error>
    {
        return self.as_mut().read_to(terminal);
    }

    fn steal(&mut self, amount: usize) -> Result<Vec<u8>, std::io::Error> {
        return self.as_mut().steal(amount);
    }

    fn steal_eof(&mut self) -> Result<Vec<u8>, std::io::Error> {
        return self.as_mut().steal_eof();
    }

    fn drop_eof(&mut self) -> Result<bool, std::io::Error> {
        return self.as_mut().drop_eof();
    }

    fn get_mut(&mut self) -> Option<&mut BufferedReader<C>> {
        // Strip the outer box.
        self.as_mut().get_mut()
    }

    fn get_ref(&self) -> Option<&BufferedReader<C>> {
        // Strip the outer box.
        self.as_ref().get_ref()
    }

    fn into_inner<'b>(self: Box<Self>) -> Option<Box<BufferedReader<C> + 'b>>
            where Self: 'b {
        // Strip the outer box.
        (*self).into_inner()
    }

    fn cookie_set(&mut self, cookie: C) -> C {
        self.as_mut().cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &C {
        self.as_ref().cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut C {
        self.as_mut().cookie_mut()
    }
}

// The file was created as follows:
//
//   for i in $(seq 0 9999); do printf "%04d\n" $i; done > buffered-reader-test.txt
#[cfg(test)]
fn buffered_reader_test_data_check<'a, T: BufferedReader<C> + 'a, C>(bio: &mut T) {
    use std::str;

    for i in 0 .. 10000 {
        let consumed = {
            // Each number is 4 bytes plus a newline character.
            let d = bio.data_hard(5);
            if d.is_err() {
                println!("Error for i == {}: {:?}", i, d);
            }
            let d = d.unwrap();
            assert!(d.len() >= 5);
            assert_eq!(format!("{:04}\n", i), str::from_utf8(&d[0..5]).unwrap());

            5
        };

        bio.consume(consumed);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn buffered_reader_eof_test() {
        let data : &[u8] = include_bytes!("buffered-reader-test.txt");

        // Make sure data_eof works.
        {
            let mut bio = BufferedReaderMemory::new(data);
            let amount = {
                bio.data_eof().unwrap().len()
            };
            bio.consume(amount);
            assert_eq!(bio.data(1).unwrap().len(), 0);
        }

        // Try it again with a limitor.
        {
            let bio = Box::new(BufferedReaderMemory::new(data));
            let mut bio2 = BufferedReaderLimitor::new(
                bio, (data.len() / 2) as u64);
            let amount = {
                bio2.data_eof().unwrap().len()
            };
            assert_eq!(amount, data.len() / 2);
            bio2.consume(amount);
            assert_eq!(bio2.data(1).unwrap().len(), 0);
        }
    }

    #[cfg(test)]
    fn buffered_reader_read_test_aux<'a, T: BufferedReader<C> + 'a, C>
        (mut bio: T, data: &[u8]) {
        let mut buffer = [0; 99];

        // Make sure the test file has more than buffer.len() bytes
        // worth of data.
        assert!(buffer.len() < data.len());

        // The number of reads we'll have to perform.
        let iters = (data.len() + buffer.len() - 1) / buffer.len();
        // Iterate more than the number of required reads to check
        // what happens when we try to read beyond the end of the
        // file.
        for i in 1..iters + 2 {
            let data_start = (i - 1) * buffer.len();

            // We don't want to just check that read works in
            // isolation.  We want to be able to mix .read and .data
            // calls.
            {
                let result = bio.data(buffer.len());
                let buffer = result.unwrap();
                if buffer.len() > 0 {
                    assert_eq!(buffer,
                               &data[data_start..data_start + buffer.len()]);
                }
            }

            // Now do the actual read.
            let result = bio.read(&mut buffer[..]);
            let got = result.unwrap();
            if got > 0 {
                assert_eq!(&buffer[0..got],
                           &data[data_start..data_start + got]);
            }

            if i > iters {
                // We should have read everything.
                assert!(got == 0);
            } else if i == iters {
                // The last read.  This may be less than buffer.len().
                // But it should include at least one byte.
                assert!(0 < got);
                assert!(got <= buffer.len());
            } else {
                assert_eq!(got, buffer.len());
            }
        }
    }

    #[test]
    fn buffered_reader_read_test() {
        let data : &[u8] = include_bytes!("buffered-reader-test.txt");

        {
            let bio = BufferedReaderMemory::new(data);
            buffered_reader_read_test_aux (bio, data);
        }

        {
            use std::path::PathBuf;
            use std::fs::File;

            let path : PathBuf = [env!("CARGO_MANIFEST_DIR"),
                                  "src",
                                  "buffered-reader-test.txt"]
                .iter().collect();

            let mut f = File::open(&path).expect(&path.to_string_lossy());
            let bio = BufferedReaderGeneric::new(&mut f, None);
            buffered_reader_read_test_aux (bio, data);
        }
    }
}
