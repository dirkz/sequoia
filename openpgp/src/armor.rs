//! ASCII Armor.
//!
//! This module deals with ASCII Armored data (see [Section 6 of RFC
//! 4880]).
//!
//!   [Section 6 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-6
//!
//! # Scope
//!
//! This implements a subset of the ASCII Armor specification.  Not
//! supported multipart messages.
//!
//! # Memory allocations
//!
//! Both the reader and the writer allocate memory in the order of the
//! size of chunks read or written.
//!
//! # Examples
//!
//! ```rust, no_run
//! # fn main() -> sequoia_openpgp::Result<()> {
//! use sequoia_openpgp as openpgp;
//! use std::fs::File;
//! use openpgp::armor::{Reader, ReaderMode, Kind};
//!
//! let mut file = File::open("somefile.asc")?;
//! let mut r = Reader::new(&mut file, ReaderMode::Tolerant(Some(Kind::File)));
//! # Ok(()) }
//! ```

use base64;
use buffered_reader::BufferedReader;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::io::{Result, Error, ErrorKind};
use std::path::Path;
use std::cmp;
use std::str;
use std::borrow::Cow;

#[cfg(test)]
use quickcheck::{Arbitrary, Gen};

use crate::packet::prelude::*;
use crate::packet::header::{BodyLength, CTBNew, CTBOld};
use crate::parse::Cookie;
use crate::serialize::MarshalInto;

mod base64_utils;
use base64_utils::*;

/// The encoded output stream must be represented in lines of no more
/// than 76 characters each (see (see [RFC 4880, section
/// 6.3](https://tools.ietf.org/html/rfc4880#section-6.3).  GnuPG uses
/// 64.
pub(crate) const LINE_LENGTH: usize = 64;

const LINE_ENDING: &str = "\n";

/// Specifies the type of data (see [RFC 4880, section 6.2]).
///
/// [RFC 4880, section 6.2]: https://tools.ietf.org/html/rfc4880#section-6.2
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Kind {
    /// A generic OpenPGP message.  (Since its structure hasn't been
    /// validated, in this crate's terminology, this is just a
    /// `PacketPile`.)
    Message,
    /// A certificate.
    PublicKey,
    /// A transferable secret key.
    SecretKey,
    /// A detached signature.
    Signature,
    /// A generic file.  This is a GnuPG extension.
    File,
}
assert_send_and_sync!(Kind);

#[cfg(test)]
impl Arbitrary for Kind {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        use self::Kind::*;
        match u8::arbitrary(g) % 5 {
            0 => Message,
            1 => PublicKey,
            2 => SecretKey,
            3 => Signature,
            4 => File,
            _ => unreachable!(),
        }
    }
}

impl Kind {
    /// Detects the header returning the kind and length of the
    /// header.
    fn detect_header(blurb: &[u8]) -> Option<(Self, usize)> {
        let (leading_dashes, rest) = dash_prefix(blurb);

        // Skip over "BEGIN PGP "
        if ! rest.starts_with(b"BEGIN PGP ") {
            return None;
        }
        let rest = &rest[b"BEGIN PGP ".len()..];

        // Detect kind.
        let kind = if rest.starts_with(b"MESSAGE") {
            Kind::Message
        } else if rest.starts_with(b"PUBLIC KEY BLOCK") {
            Kind::PublicKey
        } else if rest.starts_with(b"PRIVATE KEY BLOCK") {
            Kind::SecretKey
        } else if rest.starts_with(b"SIGNATURE") {
            Kind::Signature
        } else if rest.starts_with(b"ARMORED FILE") {
            Kind::File
        } else {
            return None;
        };

        let (trailing_dashes, _) = dash_prefix(&rest[kind.blurb().len()..]);
        Some((kind,
              leading_dashes.len()
              + b"BEGIN PGP ".len() + kind.blurb().len()
              + trailing_dashes.len()))
    }

    /// Detects the footer returning length of the footer.
    fn detect_footer(&self, blurb: &[u8]) -> Option<usize> {
        let (leading_dashes, rest) = dash_prefix(blurb);

        // Skip over "END PGP "
        if ! rest.starts_with(b"END PGP ") {
            return None;
        }
        let rest = &rest[b"END PGP ".len()..];

        let ident = self.blurb().as_bytes();
        if ! rest.starts_with(ident) {
            return None;
        }

        let (trailing_dashes, _) = dash_prefix(&rest[ident.len()..]);
        Some(leading_dashes.len()
             + b"END PGP ".len() + ident.len()
             + trailing_dashes.len())
    }

    fn blurb(&self) -> &str {
        match self {
            &Kind::Message => "MESSAGE",
            &Kind::PublicKey => "PUBLIC KEY BLOCK",
            &Kind::SecretKey => "PRIVATE KEY BLOCK",
            &Kind::Signature => "SIGNATURE",
            &Kind::File => "ARMORED FILE",
        }
    }

    fn begin(&self) -> String {
        format!("-----BEGIN PGP {}-----", self.blurb())
    }

    fn end(&self) -> String {
        format!("-----END PGP {}-----", self.blurb())
    }
}

/// A filter that applies ASCII Armor to the data written to it.
pub struct Writer<W: Write> {
    sink: W,
    kind: Kind,
    stash: Vec<u8>,
    column: usize,
    crc: CRC,
    header: Vec<u8>,
    dirty: bool,
}
assert_send_and_sync!(Writer<W> where W: Write);

impl<W: Write> Writer<W> {
    /// Constructs a new filter for the given type of data.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Read, Write, Cursor};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::armor::{Writer, Kind};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let mut writer = Writer::new(Vec::new(), Kind::File)?;
    /// writer.write_all(b"Hello world!")?;
    /// let buffer = writer.finalize()?;
    /// assert_eq!(
    ///     String::from_utf8_lossy(&buffer),
    ///     "-----BEGIN PGP ARMORED FILE-----
    ///
    /// SGVsbG8gd29ybGQh
    /// =s4Gu
    /// -----END PGP ARMORED FILE-----
    /// ");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(inner: W, kind: Kind) -> Result<Self> {
        Self::with_headers(inner, kind, Option::<(&str, &str)>::None)
    }

    /// Constructs a new filter for the given type of data.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{Read, Write, Cursor};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::armor::{Writer, Kind};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let mut writer = Writer::with_headers(Vec::new(), Kind::File,
    ///     vec![("Key", "Value")])?;
    /// writer.write_all(b"Hello world!")?;
    /// let buffer = writer.finalize()?;
    /// assert_eq!(
    ///     String::from_utf8_lossy(&buffer),
    ///     "-----BEGIN PGP ARMORED FILE-----
    /// Key: Value
    ///
    /// SGVsbG8gd29ybGQh
    /// =s4Gu
    /// -----END PGP ARMORED FILE-----
    /// ");
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_headers<I, K, V>(inner: W, kind: Kind, headers: I)
                                 -> Result<Self>
        where I: IntoIterator<Item = (K, V)>,
              K: AsRef<str>,
              V: AsRef<str>,
    {
        let mut w = Writer {
            sink: inner,
            kind,
            stash: Vec::<u8>::with_capacity(2),
            column: 0,
            crc: CRC::new(),
            header: Vec::with_capacity(128),
            dirty: false,
        };

        {
            let mut cur = Cursor::new(&mut w.header);
            write!(&mut cur, "{}{}", kind.begin(), LINE_ENDING)?;

            for h in headers {
                write!(&mut cur, "{}: {}{}", h.0.as_ref(), h.1.as_ref(),
                       LINE_ENDING)?;
            }

            // A blank line separates the headers from the body.
            write!(&mut cur, "{}", LINE_ENDING)?;
        }

        Ok(w)
    }

    /// Returns a reference to the inner writer.
    pub fn get_ref(&self) -> &W {
        &self.sink
    }

    /// Returns a mutable reference to the inner writer.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.sink
    }

    fn finalize_headers(&mut self) -> Result<()> {
        if ! self.dirty {
            self.dirty = true;
            self.sink.write_all(&self.header)?;
            // Release memory.
            crate::vec_truncate(&mut self.header, 0);
            self.header.shrink_to_fit();
        }
        Ok(())
    }

    /// Writes the footer.
    ///
    /// This function needs to be called explicitly before the writer is dropped.
    pub fn finalize(mut self) -> Result<W> {
        if ! self.dirty {
            // No data was written to us, don't emit anything.
            return Ok(self.sink);
        }
        self.finalize_armor()?;
        Ok(self.sink)
    }

    /// Writes the footer.
    fn finalize_armor(&mut self) -> Result<()> {
        if ! self.dirty {
            // No data was written to us, don't emit anything.
            return Ok(());
        }
        self.finalize_headers()?;

        // Write any stashed bytes and pad.
        if self.stash.len() > 0 {
            self.sink.write_all(base64::encode_config(
                &self.stash, base64::STANDARD).as_bytes())?;
            self.column += 4;
        }

        // Inserts a line break if necessary.
        //
        // Unfortunately, we cannot use
        //self.linebreak()?;
        //
        // Therefore, we inline it here.  This is a bit sad.
        assert!(self.column <= LINE_LENGTH);
        if self.column == LINE_LENGTH {
            write!(self.sink, "{}", LINE_ENDING)?;
            self.column = 0;
        }

        if self.column > 0 {
            write!(self.sink, "{}", LINE_ENDING)?;
        }

        // 24-bit CRC
        let crc = self.crc.finalize();
        let bytes = &crc.to_be_bytes()[1..4];

        // CRC and footer.
        write!(self.sink, "={}{}{}{}",
               base64::encode_config(&bytes, base64::STANDARD_NO_PAD),
               LINE_ENDING, self.kind.end(), LINE_ENDING)?;

        self.dirty = false;
        Ok(())
    }

    /// Inserts a line break if necessary.
    fn linebreak(&mut self) -> Result<()> {
        assert!(self.column <= LINE_LENGTH);
        if self.column == LINE_LENGTH {
            write!(self.sink, "{}", LINE_ENDING)?;
            self.column = 0;
        }
        Ok(())
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.finalize_headers()?;

        // Update CRC on the unencoded data.
        self.crc.update(buf);

        let mut input = buf;
        let mut written = 0;

        // First of all, if there are stashed bytes, fill the stash
        // and encode it.  If writing out the stash fails below, we
        // might end up with a stash of size 3.
        assert!(self.stash.len() <= 3);
        if self.stash.len() > 0 {
            while self.stash.len() < 3 {
                if input.len() == 0 {
                    /* We exhausted the input.  Return now, any
                     * stashed bytes are encoded when finalizing the
                     * writer.  */
                    return Ok(written);
                }
                self.stash.push(input[0]);
                input = &input[1..];
                written += 1;
            }
            assert_eq!(self.stash.len(), 3);

            // If this fails for some reason, and the caller retries
            // the write, we might end up with a stash of size 3.
            self.sink
                .write_all(base64::encode_config(
                    &self.stash, base64::STANDARD_NO_PAD).as_bytes())?;
            self.column += 4;
            self.linebreak()?;
            crate::vec_truncate(&mut self.stash, 0);
        }

        // Ensure that a multiple of 3 bytes are encoded, stash the
        // rest from the end of input.
        while input.len() % 3 > 0 {
            self.stash.push(input[input.len()-1]);
            input = &input[..input.len()-1];
            written += 1;
        }
        // We popped values from the end of the input, fix the order.
        self.stash.reverse();
        assert!(self.stash.len() < 3);

        // We know that we have a multiple of 3 bytes, encode them and write them out.
        assert!(input.len() % 3 == 0);
        let encoded = base64::encode_config(input, base64::STANDARD_NO_PAD);
        written += input.len();
        let mut enc = encoded.as_bytes();
        while enc.len() > 0 {
            let n = cmp::min(LINE_LENGTH - self.column, enc.len());
            self.sink
                .write_all(&enc[..n])?;
            enc = &enc[n..];
            self.column += n;
            self.linebreak()?;
        }

        assert_eq!(written, buf.len());
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        self.sink.flush()
    }
}

/// How an ArmorReader should act.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReaderMode {
    /// Makes the armor reader tolerant of simple errors.
    ///
    /// The armor reader will be tolerant of common formatting errors,
    /// such as incorrect line folding, but the armor header line
    /// (e.g., `----- BEGIN PGP MESSAGE -----`) and the footer must be
    /// intact.
    ///
    /// If a Kind is specified, then only ASCII Armor blocks with the
    /// appropriate header are recognized.
    ///
    /// This mode is appropriate when reading from a file.
    Tolerant(Option<Kind>),

    /// Makes the armor reader very tolerant of errors.
    ///
    /// Unlike in `Tolerant` mode, in this mode, the armor reader
    /// doesn't require an armor header line.  Instead, it examines
    /// chunks that look like valid base64 data, and attempts to parse
    /// them.
    ///
    /// Although this mode looks for OpenPGP fingerprints before
    /// invoking the full parser, due to the number of false
    /// positives, this mode of operation is CPU intense, particularly
    /// on large text files.  It is primarily appropriate when reading
    /// text that the user cut and pasted into a text area.
    VeryTolerant,
}
assert_send_and_sync!(ReaderMode);

/// A filter that strips ASCII Armor from a stream of data.
pub struct Reader<'a> {
    reader: buffered_reader::Generic<IoReader<'a>, Cookie>,
}
assert_send_and_sync!(Reader<'_>);

impl<'a> fmt::Debug for Reader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("armor::Reader")
            .field("reader", self.reader.reader_ref())
            .finish()
    }
}

impl<'a> fmt::Display for Reader<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "armor::Reader")
    }
}

#[derive(Debug)]
struct IoReader<'a> {
    source: Box<dyn BufferedReader<Cookie> + 'a>,
    kind: Option<Kind>,
    mode: ReaderMode,
    buffer: Vec<u8>,
    crc: CRC,
    expect_crc: Option<u32>,
    initialized: bool,
    headers: Vec<(String, String)>,
    finalized: bool,
    prefix: Vec<u8>,
    prefix_remaining: usize,
}
assert_send_and_sync!(IoReader<'_>);

impl Default for ReaderMode {
    fn default() -> Self {
        ReaderMode::Tolerant(None)
    }
}

impl<'a> Reader<'a> {
    /// Constructs a new filter for the given type of data.
    ///
    /// [ASCII Armor], designed to protect OpenPGP data in transit,
    /// has been a source of problems if the armor structure is
    /// damaged.  For example, copying data manually from one program
    /// to another might introduce or drop newlines.
    ///
    /// By default, the reader operates in robust mode.  It will
    /// extract the first armored OpenPGP data block it can find, even
    /// if the armor frame is damaged, or missing.
    ///
    /// To select strict mode, specify a kind argument.  In strict
    /// mode, the reader will match on the armor frame.  The reader
    /// ignores any data in front of the Armor Header Line, as long as
    /// the line the header is only prefixed by whitespace.
    ///
    ///   [ASCII Armor]: https://tools.ietf.org/html/rfc4880#section-6.2
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Read};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::Message;
    /// use openpgp::armor::{Reader, ReaderMode};
    /// use openpgp::parse::Parse;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let data = "yxJiAAAAAABIZWxsbyB3b3JsZCE="; // base64 over literal data packet
    ///
    /// let mut cursor = io::Cursor::new(&data);
    /// let mut reader = Reader::new(&mut cursor, ReaderMode::VeryTolerant);
    ///
    /// let mut buf = Vec::new();
    /// reader.read_to_end(&mut buf)?;
    ///
    /// let message = Message::from_bytes(&buf)?;
    /// assert_eq!(message.body().unwrap().body(),
    ///            b"Hello world!");
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Or, in strict mode:
    ///
    /// ```
    /// use std::io::{self, Result, Read};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::armor::{Reader, ReaderMode, Kind};
    ///
    /// # fn main() -> Result<()> {
    /// let data =
    ///     "-----BEGIN PGP ARMORED FILE-----
    ///
    ///      SGVsbG8gd29ybGQh
    ///      =s4Gu
    ///      -----END PGP ARMORED FILE-----";
    ///
    /// let mut cursor = io::Cursor::new(&data);
    /// let mut reader = Reader::new(&mut cursor, ReaderMode::Tolerant(Some(Kind::File)));
    ///
    /// let mut content = String::new();
    /// reader.read_to_string(&mut content)?;
    /// assert_eq!(content, "Hello world!");
    /// assert_eq!(reader.kind(), Some(Kind::File));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new<R, M>(inner: R, mode: M) -> Self
        where R: 'a + Read + Send + Sync,
              M: Into<Option<ReaderMode>>
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(inner, None,
                                                           Default::default())),
            mode, Default::default())
    }

    /// Creates a `Reader` from an `io::Read`er.
    pub fn from_reader<R, M>(reader: R, mode: M) -> Self
        where R: 'a + Read + Send + Sync,
              M: Into<Option<ReaderMode>>
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Generic::with_cookie(reader, None,
                                                           Default::default())),
            mode, Default::default())
    }

    /// Creates a `Reader` from a file.
    pub fn from_file<P, M>(path: P, mode: M) -> Result<Self>
        where P: AsRef<Path>,
              M: Into<Option<ReaderMode>>
    {
        Ok(Self::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path,
                                                        Default::default())?),
            mode, Default::default()))
    }

    /// Creates a `Reader` from a buffer.
    pub fn from_bytes<M>(bytes: &'a [u8], mode: M) -> Self
        where M: Into<Option<ReaderMode>>
    {
        Self::from_buffered_reader(
            Box::new(buffered_reader::Memory::with_cookie(bytes,
                                                          Default::default())),
            mode, Default::default())
    }

    pub(crate) fn from_buffered_reader<M>(
        inner: Box<dyn BufferedReader<Cookie> + 'a>, mode: M, cookie: Cookie)
        -> Self
        where M: Into<Option<ReaderMode>>
    {
        let mode = mode.into().unwrap_or(Default::default());

        let io_reader = IoReader {
            source: inner,
            kind: None,
            mode,
            buffer: Vec::<u8>::with_capacity(1024),
            crc: CRC::new(),
            expect_crc: None,
            headers: Vec::new(),
            initialized: false,
            finalized: false,
            prefix: Vec::with_capacity(0),
            prefix_remaining: 0,
        };

        Reader {
            reader: buffered_reader::Generic::with_cookie(io_reader,
                                                          None,
                                                          cookie),
        }
    }

    /// Returns the kind of data this reader is for.
    ///
    /// Useful if the kind of data is not known in advance.  If the
    /// header has not been encountered yet (try reading some data
    /// first!), this function returns None.
    pub fn kind(&self) -> Option<Kind> {
        self.reader.reader_ref().kind
    }

    /// Returns the armored headers.
    ///
    /// The tuples contain a key and a value.
    ///
    /// Note: if a key occurs multiple times, then there are multiple
    /// entries in the vector with the same key; values with the same
    /// key are *not* combined.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::{self, Read};
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::armor::{Reader, ReaderMode, Kind};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let data =
    ///     "-----BEGIN PGP ARMORED FILE-----
    ///      First: value
    ///      Header: value
    ///
    ///      SGVsbG8gd29ybGQh
    ///      =s4Gu
    ///      -----END PGP ARMORED FILE-----";
    ///
    /// let mut cursor = io::Cursor::new(&data);
    /// let mut reader = Reader::new(&mut cursor, ReaderMode::Tolerant(Some(Kind::File)));
    ///
    /// let mut content = String::new();
    /// reader.read_to_string(&mut content)?;
    /// assert_eq!(reader.headers()?,
    ///    &[("First".into(), "value".into()),
    ///      ("Header".into(), "value".into())]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn headers(&mut self) -> Result<&[(String, String)]> {
        self.reader.reader_mut().initialize()?;
        Ok(&self.reader.reader_ref().headers[..])
    }
}

impl<'a> IoReader<'a> {
    /// Consumes the header if not already done.
    fn initialize(&mut self) -> Result<()> {
        if self.initialized { return Ok(()) }

        // The range of the first 6 bits of a message is limited.
        // Save cpu cycles by only considering base64 data that starts
        // with one of those characters.
        lazy_static::lazy_static!{
            static ref START_CHARS_VERY_TOLERANT: Vec<u8> = {
                let mut valid_start = Vec::new();
                for &tag in &[ Tag::PKESK, Tag::SKESK,
                              Tag::OnePassSig, Tag::Signature,
                              Tag::PublicKey, Tag::SecretKey,
                              Tag::CompressedData, Tag::Literal,
                              Tag::Marker,
                ] {
                    let mut ctb = [ 0u8; 1 ];
                    let mut o = [ 0u8; 4 ];

                    CTBNew::new(tag).serialize_into(&mut ctb[..]).unwrap();
                    base64::encode_config_slice(&ctb[..], base64::STANDARD, &mut o[..]);
                    valid_start.push(o[0]);

                    CTBOld::new(tag, BodyLength::Full(0)).unwrap()
                        .serialize_into(&mut ctb[..]).unwrap();
                    base64::encode_config_slice(&ctb[..], base64::STANDARD, &mut o[..]);
                    valid_start.push(o[0]);
                }

                // Add all first bytes of Unicode characters from the
                // "Dash Punctuation" category.
                let mut b = [0; 4]; // Enough to hold any UTF-8 character.
                for d in dashes() {
                    d.encode_utf8(&mut b);
                    valid_start.push(b[0]);
                }

                // If there are no dashes at all, match on the BEGIN.
                valid_start.push(b'B');

                valid_start.sort();
                valid_start.dedup();
                valid_start
            };

            static ref START_CHARS_TOLERANT: Vec<u8> = {
                let mut valid_start = Vec::new();
                // Add all first bytes of Unicode characters from the
                // "Dash Punctuation" category.
                let mut b = [0; 4]; // Enough to hold any UTF-8 character.
                for d in dashes() {
                    d.encode_utf8(&mut b);
                    valid_start.push(b[0]);
                }

                // If there are no dashes at all, match on the BEGIN.
                valid_start.push(b'B');

                valid_start.sort();
                valid_start.dedup();
                valid_start
            };
        }

        // Look for the Armor Header Line, skipping any garbage in the
        // process.
        let mut found_blob = false;
        let start_chars = if self.mode != ReaderMode::VeryTolerant {
            &START_CHARS_TOLERANT[..]
        } else {
            &START_CHARS_VERY_TOLERANT[..]
        };

        let mut lines = 0;
        let mut prefix = Vec::new();
        let n = 'search: loop {
            if lines > 0 {
                // Find the start of the next line.
                self.source.drop_through(&[b'\n'], true)?;
                crate::vec_truncate(&mut prefix, 0);
            }
            lines += 1;

            // Ignore leading whitespace, etc.
            while match self.source.data_hard(1)?[0] {
                // Skip some whitespace (previously .is_ascii_whitespace())
                b' ' | b'\t' | b'\r' | b'\n' => true,
                // Also skip common quote characters
                b'>' | b'|' | b']' | b'}' => true,
                // Do not skip anything else
                _ => false,
            } {
                let c = self.source.data(1)?[0];
                if c == b'\n' {
                    // We found a newline while walking whitespace, reset prefix
                    crate::vec_truncate(&mut prefix, 0);
                } else {
                    prefix.push(self.source.data_hard(1)?[0]);
                }
                self.source.consume(1);
            }

            // Don't bother if the first byte is not plausible.
            let start = self.source.data_hard(1)?[0];
            if !start_chars.binary_search(&start).is_ok()
            {
                self.source.consume(1);
                continue;
            }

            {
                let mut input = self.source.data(128)?;
                let n = input.len();

                if n == 0 {
                    return Err(
                        Error::new(ErrorKind::InvalidInput,
                                   "Reached EOF looking for Armor Header Line"));
                }
                if n > 128 {
                    input = &input[..128];
                }

                // Possible ASCII-armor header.
                if let Some((kind, len)) = Kind::detect_header(&input) {
                    let mut expected_kind = None;
                    if let ReaderMode::Tolerant(Some(kind)) = self.mode {
                        expected_kind = Some(kind);
                    }

                    if expected_kind == None {
                        // Found any!
                        self.kind = Some(kind);
                        break 'search len;
                    }

                    if expected_kind == Some(kind) {
                        // Found it!
                        self.kind = Some(kind);
                        break 'search len;
                    }
                }

                if self.mode == ReaderMode::VeryTolerant {
                    // The user did not specify what kind of data she
                    // wants.  We aggressively try to decode any data,
                    // even if we do not see a valid header.
                    if is_armored_pgp_blob(input) {
                        found_blob = true;
                        break 'search 0;
                    }
                }
            }
        };
        self.source.consume(n);

        if found_blob {
            // Skip the rest of the initialization.
            self.initialized = true;
            self.prefix_remaining = prefix.len();
            self.prefix = prefix;
            return Ok(());
        }

        self.prefix = prefix;
        self.read_headers()
    }

    /// Reads headers and finishes the initialization.
    fn read_headers(&mut self) -> Result<()> {
        // We consumed the header above, but not any trailing
        // whitespace and the trailing new line.  We do that now.
        // Other data between the header and the new line are not
        // allowed.  But, instead of failing, we try to recover, by
        // stopping at the first non-whitespace character.
        let n = {
            let line = self.source.read_to('\n' as u8)?;
            line.iter().position(|&c| {
                !c.is_ascii_whitespace()
            }).unwrap_or(line.len())
        };
        self.source.consume(n);

        let next_prefix =
            &self.source.data_hard(self.prefix.len())?[..self.prefix.len()];
        if self.prefix != next_prefix {
            // If the next line doesn't start with the same prefix, we assume
            // it was garbage on the front and drop the prefix so long as it
            // was purely whitespace.  Any non-whitespace remains an error
            // while searching for the armor header if it's not repeated.
            if self.prefix.iter().all(|b| (*b as char).is_ascii_whitespace()) {
                crate::vec_truncate(&mut self.prefix, 0);
            } else {
                // Nope, we have actually failed to read this properly
                return Err(
                    Error::new(ErrorKind::InvalidInput,
                               "Inconsistent quoting of armored data"));
            }
        }

        // Read the key-value headers.
        let mut n = 0;
        // Sometimes, we find a truncated prefix.  In these cases, the
        // length is not prefix.len(), but this.
        let mut prefix_len = None;
        let mut lines = 0;
        loop {
            // Skip any known prefix on lines.
            //
            // IMPORTANT: We need to buffer the prefix so that we can
            // consume it here.  So at every point in this loop where
            // the control flow wraps around, we need to make sure
            // that we buffer the prefix in addition to the line.
            self.source.consume(
                prefix_len.take().unwrap_or_else(|| self.prefix.len()));

            self.source.consume(n);

            // Buffer the next line.
            let line = self.source.read_to('\n' as u8)?;
            n = line.len();
            lines += 1;

            let line = str::from_utf8(line);
            // Ignore---don't error out---lines that are not valid UTF8.
            if line.is_err() {
                // Buffer the next line and the prefix that is going
                // to be consumed in the next iteration.
                let next_prefix =
                    &self.source.data_hard(n + self.prefix.len())?
                        [n..n + self.prefix.len()];
                if self.prefix != next_prefix {
                    return Err(
                        Error::new(ErrorKind::InvalidInput,
                                   "Inconsistent quoting of armored data"));
                }
                continue;
            }

            let line = line.unwrap();

            // The line almost certainly ends with \n: the only reason
            // it couldn't is if we encountered EOF.  We need to strip
            // it.  But, if it ends with \r\n, then we also want to
            // strip the \r too.
            let line = if line.ends_with(&"\r\n"[..]) {
                // \r\n.
                &line[..line.len() - 2]
            } else if line.ends_with("\n") {
                // \n.
                &line[..line.len() - 1]
            } else {
                // EOF.
                line
            };

            /* Process headers.  */
            let key_value = line.splitn(2, ": ").collect::<Vec<&str>>();
            if key_value.len() == 1 {
                if line.trim_start().len() == 0 {
                    // Empty line.
                    break;
                } else if lines == 1 {
                    // This is the first line and we don't have a
                    // key-value pair.  It seems more likely that
                    // we're just missing a newline and this invalid
                    // header is actually part of the body.
                    n = 0;
                    break;
                }
            } else {
                let key = key_value[0].trim_start();
                let value = key_value[1];

                self.headers.push((key.into(), value.into()));
            }

            // Buffer the next line and the prefix that is going to be
            // consumed in the next iteration.
            let next_prefix =
                &self.source.data_hard(n + self.prefix.len())?
                    [n..n + self.prefix.len()];

            // Sometimes, we find a truncated prefix.
            let l = common_prefix(&self.prefix, next_prefix);
            let full_prefix = l == self.prefix.len();
            if ! (full_prefix
                  // Truncation is okay if the rest of the prefix
                  // contains only whitespace.
                  || self.prefix[l..].iter().all(|c| c.is_ascii_whitespace()))
            {
                return Err(
                    Error::new(ErrorKind::InvalidInput,
                               "Inconsistent quoting of armored data"));
            }
            if ! full_prefix {
                // Make sure to only consume the truncated prefix in
                // the next loop iteration.
                prefix_len = Some(l);
            }
        }
        self.source.consume(n);

        self.initialized = true;
        self.prefix_remaining = self.prefix.len();
        Ok(())
    }
}

/// Computes the length of the common prefix.
fn common_prefix<A: AsRef<[u8]>, B: AsRef<[u8]>>(a: A, b: B) -> usize {
    a.as_ref().iter().zip(b.as_ref().iter()).take_while(|(a, b)| a == b).count()
}

impl<'a> IoReader<'a> {
    fn read_armored_data(&mut self, buf: &mut [u8]) -> Result<usize> {
        let (consumed, decoded) = if self.buffer.len() > 0 {
            // We have something buffered, use that.

            let amount = cmp::min(buf.len(), self.buffer.len());
            buf[..amount].copy_from_slice(&self.buffer[..amount]);
            crate::vec_drain_prefix(&mut self.buffer, amount);

            (0, amount)
        } else {
            // We need to decode some data.  We consider three cases,
            // all a function of the size of `buf`:
            //
            //   - Tiny: if `buf` can hold less than three bytes, then
            //     we almost certainly have to double buffer: except
            //     at the very end, a base64 chunk consists of 3 bytes
            //     of data.
            //
            //     Note: this happens if the caller does `for c in
            //     Reader::new(...).bytes() ...`.  Then it reads one
            //     byte of decoded data at a time.
            //
            //   - Small: if the caller only requests a few bytes at a
            //     time, we may as well double buffer to reduce
            //     decoding overhead.
            //
            //   - Large: if `buf` is large, we can decode directly
            //     into `buf` and avoid double buffering.  But,
            //     because we ignore whitespace, it is hard to
            //     determine exactly how much data to read to
            //     maximally fill `buf`.

            // We use 64, because ASCII-armor text usually contains 64
            // characters of base64 data per line, and this prevents
            // turning the borrow into an own.
            const THRESHOLD : usize = 64;

            let to_read =
                cmp::max(
                    // Tiny or small:
                    THRESHOLD + 2,

                    // Large: a heuristic:

                    base64_size(buf.len())
                    // Assume about 2 bytes of whitespace (crlf) per
                    // 64 character line.
                        + 2 * ((buf.len() + 63) / 64));

            let base64data = self.source.data(to_read)?;
            let base64data = if base64data.len() > to_read {
                &base64data[..to_read]
            } else {
                base64data
            };

            let (base64data, consumed, prefix_remaining)
                = base64_filter(Cow::Borrowed(base64data),
                                // base64_size rounds up, but we want
                                // to round down as we have to double
                                // buffer partial chunks.
                                cmp::max(THRESHOLD, buf.len() / 3 * 4),
                                self.prefix_remaining,
                                self.prefix.len());

            // We shouldn't have any partial chunks.
            assert_eq!(base64data.len() % 4, 0);

            let decoded = if base64data.len() / 4 * 3 > buf.len() {
                // We need to double buffer.  Decode into a vector.
                // (Note: the computed size *might* be a slight
                // overestimate, because the last base64 chunk may
                // include padding.)
                self.buffer = base64::decode_config(
                    &base64data, base64::STANDARD)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

                self.crc.update(&self.buffer);

                let copied = cmp::min(buf.len(), self.buffer.len());
                buf[..copied].copy_from_slice(&self.buffer[..copied]);
                crate::vec_drain_prefix(&mut self.buffer, copied);

                copied
            } else {
                // We can decode directly into the caller-supplied
                // buffer.
                let decoded = base64::decode_config_slice(
                    &base64data, base64::STANDARD, buf)
                    .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

                self.crc.update(&buf[..decoded]);

                decoded
            };

            self.prefix_remaining = prefix_remaining;

            (consumed, decoded)
        };

        self.source.consume(consumed);
        if decoded == 0 {
            self.finalized = true;

            /* Look for CRC.  The CRC is optional.  */
            let consumed = {
                // Skip whitespace.
                while self.source.data(1)?.len() > 0
                    && self.source.buffer()[0].is_ascii_whitespace()
                {
                    self.source.consume(1);
                }

                let data = self.source.data(5)?;
                let data = if data.len() > 5 {
                    &data[..5]
                } else {
                    data
                };

                if data.len() == 5
                    && data[0] == '=' as u8
                    && data[1..5].iter().all(is_base64_char)
                {
                    /* Found.  */
                    let crc = match base64::decode_config(
                        &data[1..5], base64::STANDARD)
                    {
                        Ok(d) => d,
                        Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e)),
                    };

                    assert_eq!(crc.len(), 3);
                    let crc =
                        (crc[0] as u32) << 16
                        | (crc[1] as u32) << 8
                        | crc[2] as u32;

                    self.expect_crc = Some(crc);
                    5
                } else {
                    0
                }
            };
            self.source.consume(consumed);

            // Skip any expected prefix
            self.source.data_consume_hard(self.prefix.len())?;
            // Look for a footer.
            let consumed = {
                // Skip whitespace.
                while self.source.data(1)?.len() > 0
                    && self.source.buffer()[0].is_ascii_whitespace()
                {
                    self.source.consume(1);
                }

                // If we had a header, we require a footer.
                if let Some(kind) = self.kind {
                    let footer_lookahead = 128; // Why not.
                    let got = self.source.data(footer_lookahead)?;
                    let got = if got.len() > footer_lookahead {
                        &got[..footer_lookahead]
                    } else {
                        got
                    };
                    if let Some(footer_len) = kind.detect_footer(got) {
                        footer_len
                    } else {
                        return Err(Error::new(ErrorKind::InvalidInput,
                                              "Invalid ASCII Armor footer."));
                    }
                } else {
                    0
                }
            };
            self.source.consume(consumed);

            if let Some(crc) = self.expect_crc {
                if self.crc.finalize() != crc {
                    return Err(Error::new(ErrorKind::InvalidInput,
                                          "Bad CRC sum."));
                }
            }
        }

        Ok(decoded)
    }
}

impl<'a> Read for IoReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if ! self.initialized {
            self.initialize()?;
        }

        if buf.len() == 0 {
            // Short-circuit here.  Otherwise, we copy 0 bytes into
            // the buffer, which means we decoded 0 bytes, and we
            // wrongfully assume that we reached the end of the
            // armored block.
            return Ok(0);
        }

        if self.finalized {
            assert_eq!(self.buffer.len(), 0);
            return Ok(0);
        }

        self.read_armored_data(buf)
    }
}

impl<'a> Read for Reader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.reader.read(buf)
    }
}

impl<'a> BufferedReader<Cookie> for Reader<'a> {
    fn buffer(&self) -> &[u8] {
        self.reader.buffer()
    }

    fn data(&mut self, amount: usize) -> Result<&[u8]> {
        self.reader.data(amount)
    }

    fn consume(&mut self, amount: usize) -> &[u8] {
        self.reader.consume(amount)
    }

    fn data_consume(&mut self, amount: usize) -> Result<&[u8]> {
        self.reader.data_consume(amount)
    }

    fn data_consume_hard(&mut self, amount: usize) -> Result<&[u8]> {
        self.reader.data_consume_hard(amount)
    }

    fn consummated(&mut self) -> bool {
        self.reader.consummated()
    }

    fn get_mut(&mut self) -> Option<&mut dyn BufferedReader<Cookie>> {
        Some(&mut self.reader.reader_mut().source)
    }

    fn get_ref(&self) -> Option<&dyn BufferedReader<Cookie>> {
        Some(&self.reader.reader_ref().source)
    }

    fn into_inner<'b>(self: Box<Self>)
                      -> Option<Box<dyn BufferedReader<Cookie> + 'b>>
        where Self: 'b {
        Some(self.reader.into_reader().source)
    }

    fn cookie_set(&mut self, cookie: Cookie) -> Cookie {
        self.reader.cookie_set(cookie)
    }

    fn cookie_ref(&self) -> &Cookie {
        self.reader.cookie_ref()
    }

    fn cookie_mut(&mut self) -> &mut Cookie {
        self.reader.cookie_mut()
    }
}

const CRC24_INIT: u32 = 0xB704CE;
const CRC24_POLY: u32 = 0x1864CFB;

#[derive(Debug)]
struct CRC {
    n: u32,
}

/// Computes the CRC-24, (see [RFC 4880, section 6.1]).
///
/// [RFC 4880, section 6.1]: https://tools.ietf.org/html/rfc4880#section-6.1
impl CRC {
    fn new() -> Self {
        CRC { n: CRC24_INIT }
    }

    fn update(&mut self, buf: &[u8]) -> &Self {
        for octet in buf {
            self.n ^= (*octet as u32) << 16;
            for _ in 0..8 {
                self.n <<= 1;
                if self.n & 0x1000000 > 0 {
                    self.n ^= CRC24_POLY;
                }
            }
        }
        self
    }

    fn finalize(&self) -> u32 {
        self.n & 0xFFFFFF
    }
}

/// Returns all character from Unicode's "Dash Punctuation" category.
fn dashes() -> impl Iterator<Item = char> {
    ['\u{002D}', // - (Hyphen-Minus)
     '\u{058A}', // ֊ (Armenian Hyphen)
     '\u{05BE}', // ־ (Hebrew Punctuation Maqaf)
     '\u{1400}', // ᐀ (Canadian Syllabics Hyphen)
     '\u{1806}', // ᠆ (Mongolian Todo Soft Hyphen)
     '\u{2010}', // ‐ (Hyphen)
     '\u{2011}', // ‑ (Non-Breaking Hyphen)
     '\u{2012}', // ‒ (Figure Dash)
     '\u{2013}', // – (En Dash)
     '\u{2014}', // — (Em Dash)
     '\u{2015}', // ― (Horizontal Bar)
     '\u{2E17}', // ⸗ (Double Oblique Hyphen)
     '\u{2E1A}', // ⸚ (Hyphen with Diaeresis)
     '\u{2E3A}', // ⸺ (Two-Em Dash)
     '\u{2E3B}', // ⸻ (Three-Em Dash)
     '\u{2E40}', // ⹀ (Double Hyphen)
     '\u{301C}', // 〜 (Wave Dash)
     '\u{3030}', // 〰 (Wavy Dash)
     '\u{30A0}', // ゠ (Katakana-Hiragana Double Hyphen)
     '\u{FE31}', // ︱ (Presentation Form For Vertical Em Dash)
     '\u{FE32}', // ︲ (Presentation Form For Vertical En Dash)
     '\u{FE58}', // ﹘ (Small Em Dash)
     '\u{FE63}', // ﹣ (Small Hyphen-Minus)
     '\u{FF0D}', // － (Fullwidth Hyphen-Minus)
    ].iter().cloned()
}

/// Splits the given slice into a prefix of dashes and the rest.
///
/// Accepts any character from Unicode's "Dash Punctuation" category.
/// Assumes that the prefix containing the dashes is ASCII or UTF-8.
fn dash_prefix(d: &[u8]) -> (&[u8], &[u8]) {
    // First, compute a valid UTF-8 prefix.
    let p = match std::str::from_utf8(d) {
        Ok(u) => u,
        Err(e) => std::str::from_utf8(&d[..e.valid_up_to()])
            .expect("valid up to this point"),
    };
    let mut prefix_len = 0;
    for c in p.chars() {
        // Keep going while we see characters from the Category "Dash
        // Punctuation".
        match c {
            '\u{002D}' // - (Hyphen-Minus)
                | '\u{058A}' // ֊ (Armenian Hyphen)
                | '\u{05BE}' // ־ (Hebrew Punctuation Maqaf)
                | '\u{1400}' // ᐀ (Canadian Syllabics Hyphen)
                | '\u{1806}' // ᠆ (Mongolian Todo Soft Hyphen)
                | '\u{2010}' // ‐ (Hyphen)
                | '\u{2011}' // ‑ (Non-Breaking Hyphen)
                | '\u{2012}' // ‒ (Figure Dash)
                | '\u{2013}' // – (En Dash)
                | '\u{2014}' // — (Em Dash)
                | '\u{2015}' // ― (Horizontal Bar)
                | '\u{2E17}' // ⸗ (Double Oblique Hyphen)
                | '\u{2E1A}' // ⸚ (Hyphen with Diaeresis)
                | '\u{2E3A}' // ⸺ (Two-Em Dash)
                | '\u{2E3B}' // ⸻ (Three-Em Dash)
                | '\u{2E40}' // ⹀ (Double Hyphen)
                | '\u{301C}' // 〜 (Wave Dash)
                | '\u{3030}' // 〰 (Wavy Dash)
                | '\u{30A0}' // ゠ (Katakana-Hiragana Double Hyphen)
                | '\u{FE31}' // ︱ (Presentation Form For Vertical Em Dash)
                | '\u{FE32}' // ︲ (Presentation Form For Vertical En Dash)
                | '\u{FE58}' // ﹘ (Small Em Dash)
                | '\u{FE63}' // ﹣ (Small Hyphen-Minus)
                | '\u{FF0D}' // － (Fullwidth Hyphen-Minus)
              => prefix_len += c.len_utf8(),
            _ => break,
        }
    }

    (&d[..prefix_len], &d[prefix_len..])
}

#[cfg(test)]
mod test {
    use std::io::{Cursor, Read, Write};
    use super::CRC;
    use super::Kind;
    use super::Writer;

    #[test]
    fn crc() {
        let b = b"foobarbaz";
        let crcs = [
            0xb704ce,
            0x6d2804,
            0xa2d10d,
            0x4fc255,
            0x7aafca,
            0xc79c46,
            0x7334de,
            0x77dc72,
            0x000f65,
            0xf40d86,
        ];

        for len in 0..b.len() + 1 {
            assert_eq!(CRC::new().update(&b[..len]).finalize(), crcs[len]);
        }
    }

    macro_rules! t {
        ( $path: expr ) => {
            include_bytes!(concat!("../tests/data/armor/", $path))
        }
    }
    macro_rules! vectors {
        ( $prefix: expr, $suffix: expr ) => {
            &[t!(concat!($prefix, "-0", $suffix)),
              t!(concat!($prefix, "-1", $suffix)),
              t!(concat!($prefix, "-2", $suffix)),
              t!(concat!($prefix, "-3", $suffix)),
              t!(concat!($prefix, "-47", $suffix)),
              t!(concat!($prefix, "-48", $suffix)),
              t!(concat!($prefix, "-49", $suffix)),
              t!(concat!($prefix, "-50", $suffix)),
              t!(concat!($prefix, "-51", $suffix))]
        }
    }

    const TEST_BIN: &[&[u8]] = vectors!("test", ".bin");
    const TEST_ASC: &[&[u8]] = vectors!("test", ".asc");
    const LITERAL_BIN: &[&[u8]] = vectors!("literal", ".bin");
    const LITERAL_ASC: &[&[u8]] = vectors!("literal", ".asc");
    const LITERAL_NO_HEADER_ASC: &[&[u8]] =
        vectors!("literal", "-no-header.asc");
    const LITERAL_NO_HEADER_WITH_CHKSUM_ASC: &[&[u8]] =
        vectors!("literal", "-no-header-with-chksum.asc");
    const LITERAL_NO_NEWLINES_ASC: &[&[u8]] =
        vectors!("literal", "-no-newlines.asc");

    #[test]
    fn enarmor() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let mut w =
                Writer::new(Vec::new(), Kind::File).unwrap();
            w.write(&[]).unwrap();  // Avoid zero-length optimization.
            w.write_all(bin).unwrap();
            let buf = w.finalize().unwrap();
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(asc));
        }
    }

    #[test]
    fn enarmor_bytewise() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let mut w = Writer::new(Vec::new(), Kind::File).unwrap();
            w.write(&[]).unwrap();  // Avoid zero-length optimization.
            for b in bin.iter() {
                w.write(&[*b]).unwrap();
            }
            let buf = w.finalize().unwrap();
            assert_eq!(String::from_utf8_lossy(&buf),
                       String::from_utf8_lossy(asc));
        }
    }

    #[test]
    fn drop_writer() {
        // No ASCII frame shall be emitted if the writer is dropped
        // unused.
        assert!(Writer::new(Vec::new(), Kind::File).unwrap()
                .finalize().unwrap().is_empty());

        // However, if the user insists, we will encode a zero-byte
        // string.
        let mut w = Writer::new(Vec::new(), Kind::File).unwrap();
        w.write(&[]).unwrap();
        let buf = w.finalize().unwrap();
        assert_eq!(
            &buf[..],
            &b"-----BEGIN PGP ARMORED FILE-----\n\
               \n\
               =twTO\n\
               -----END PGP ARMORED FILE-----\n"[..]);
    }

    use super::{Reader, ReaderMode};

    #[test]
    fn dearmor_robust() {
        for (i, reference) in LITERAL_BIN.iter().enumerate() {
            for test in &[LITERAL_ASC[i],
                          LITERAL_NO_HEADER_WITH_CHKSUM_ASC[i],
                          LITERAL_NO_HEADER_ASC[i],
                          LITERAL_NO_NEWLINES_ASC[i]] {
                let mut r = Reader::new(Cursor::new(test),
                                        ReaderMode::VeryTolerant);
                let mut dearmored = Vec::<u8>::new();
                r.read_to_end(&mut dearmored).unwrap();

                assert_eq!(&dearmored, reference);
            }
        }
    }

    #[test]
    fn dearmor_binary() {
        for bin in TEST_BIN.iter() {
            let mut r = Reader::new(
                Cursor::new(bin), ReaderMode::Tolerant(Some(Kind::Message)));
            let mut buf = [0; 5];
            let e = r.read(&mut buf);
            assert!(e.is_err());
        }
    }

    #[test]
    fn dearmor_wrong_kind() {
        let mut r = Reader::new(
            Cursor::new(&include_bytes!("../tests/data/armor/test-0.asc")[..]),
            ReaderMode::Tolerant(Some(Kind::Message)));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_crc() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-0.bad-crc.asc")[..]),
            ReaderMode::Tolerant(Some(Kind::File)));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor_wrong_footer() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-2.bad-footer.asc")[..]
            ),
            ReaderMode::Tolerant(Some(Kind::File)));
        let mut read = 0;
        loop {
            let mut buf = [0; 5];
            match r.read(&mut buf) {
                Ok(0) => panic!("Reached EOF, but expected an error!"),
                Ok(r) => read += r,
                Err(_) => break,
            }
        }
        assert!(read <= 2);
    }

    #[test]
    fn dearmor_no_crc() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-1.no-crc.asc")[..]),
            ReaderMode::Tolerant(Some(Kind::File)));
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.unwrap() == 1 && buf[0] == 0xde);
    }

    #[test]
    fn dearmor_with_header() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers.asc")[..]
            ),
            ReaderMode::Tolerant(Some(Kind::File)));
        assert_eq!(r.headers().unwrap(),
                   &[("Comment".into(), "Some Header".into()),
                     ("Comment".into(), "Another one".into())]);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_ok());
        assert_eq!(e.unwrap(), 3);
        assert_eq!(&buf[..3], TEST_BIN[3]);
    }

    #[test]
    fn dearmor_any() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert_eq!(r.kind(), Some(Kind::File));
        assert!(e.is_ok());
        assert_eq!(e.unwrap(), 3);
        assert_eq!(&buf[..3], TEST_BIN[3]);
    }

    #[test]
    fn dearmor_with_garbage() {
        let armored =
            include_bytes!("../tests/data/armor/test-3.with-headers.asc");
        // Slap some garbage in front and make sure it still reads ok.
        let mut b: Vec<u8> = "Some\ngarbage\nlines\n\t\r  ".into();
        b.extend_from_slice(armored);
        let mut r = Reader::new(Cursor::new(b), ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert_eq!(r.kind(), Some(Kind::File));
        assert!(e.is_ok());
        assert_eq!(e.unwrap(), 3);
        assert_eq!(&buf[..3], TEST_BIN[3]);

        // Again, but this time add a non-whitespace character in the
        // line of the header.
        let mut b: Vec<u8> = "Some\ngarbage\nlines\n\t.\r  ".into();
        b.extend_from_slice(armored);
        let mut r = Reader::new(Cursor::new(b), ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    #[test]
    fn dearmor() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let mut r = Reader::new(
                Cursor::new(asc),
                ReaderMode::Tolerant(Some(Kind::File)));
            let mut dearmored = Vec::<u8>::new();
            r.read_to_end(&mut dearmored).unwrap();

            assert_eq!(&dearmored, bin);
        }
    }

    #[test]
    fn dearmor_bytewise() {
        for (bin, asc) in TEST_BIN.iter().zip(TEST_ASC.iter()) {
            let r = Reader::new(
                Cursor::new(asc),
                ReaderMode::Tolerant(Some(Kind::File)));
            let mut dearmored = Vec::<u8>::new();
            for c in r.bytes() {
                dearmored.push(c.unwrap());
            }

            assert_eq!(&dearmored, bin);
        }
    }

    #[test]
    fn dearmor_yuge() {
        let yuge_key = crate::tests::key("yuge-key-so-yuge-the-yugest.asc");
        let mut r = Reader::new(Cursor::new(&yuge_key[..]),
                                ReaderMode::VeryTolerant);
        let mut dearmored = Vec::<u8>::new();
        r.read_to_end(&mut dearmored).unwrap();

        let r = Reader::new(Cursor::new(&yuge_key[..]),
                            ReaderMode::VeryTolerant);
        let mut dearmored = Vec::<u8>::new();
        for c in r.bytes() {
            dearmored.push(c.unwrap());
        }
    }

    #[test]
    fn dearmor_quoted() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers-quoted.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert_eq!(r.kind(), Some(Kind::File));
        assert!(e.is_ok());
        assert_eq!(e.unwrap(), 3);
        assert_eq!(&buf[..3], TEST_BIN[3]);
    }

    #[test]
    fn dearmor_quoted_stripped() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers-quoted-stripped.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert_eq!(r.kind(), Some(Kind::File));
        assert!(e.is_ok());
        assert_eq!(e.unwrap(), 3);
        assert_eq!(&buf[..3], TEST_BIN[3]);
    }

    #[test]
    fn dearmor_quoted_a_lot() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers-quoted-a-lot.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert_eq!(r.kind(), Some(Kind::File));
        assert!(e.is_ok());
        assert_eq!(e.unwrap(), 3);
        assert_eq!(&buf[..3], TEST_BIN[3]);
    }

    #[test]
    fn dearmor_quoted_badly() {
        let mut r = Reader::new(
            Cursor::new(
                &include_bytes!("../tests/data/armor/test-3.with-headers-quoted-badly.asc")[..]
            ),
            ReaderMode::VeryTolerant);
        let mut buf = [0; 5];
        let e = r.read(&mut buf);
        assert!(e.is_err());
    }

    quickcheck! {
        fn roundtrip(kind: Kind, payload: Vec<u8>) -> bool {
            if payload.is_empty() {
                // Empty payloads do not emit an armor framing unless
                // one does an explicit empty write (and .write_all()
                // does not).
                return true;
            }

            let mut w = Writer::new(Vec::new(), kind).unwrap();
            w.write_all(&payload).unwrap();
            let encoded = w.finalize().unwrap();

            let mut recovered = Vec::new();
            Reader::new(Cursor::new(&encoded),
                        ReaderMode::Tolerant(Some(kind)))
                .read_to_end(&mut recovered)
                .unwrap();

            let mut recovered_any = Vec::new();
            Reader::new(Cursor::new(&encoded), ReaderMode::VeryTolerant)
                .read_to_end(&mut recovered_any)
                .unwrap();

            payload == recovered && payload == recovered_any
        }
    }

    /// Tests issue #404, zero-sized reads break reader.
    ///
    /// See: https://gitlab.com/sequoia-pgp/sequoia/-/issues/404
    #[test]
    fn zero_sized_read() {
        let mut r = Reader::from_bytes(crate::tests::file("armor/test-1.asc"),
                                       None);
        let mut buf = Vec::new();
        r.read(&mut buf).unwrap();
        r.read(&mut buf).unwrap();
    }

    /// Crash in armor parser due to indexing not aligned with UTF-8
    /// characters.
    ///
    /// See: https://gitlab.com/sequoia-pgp/sequoia/-/issues/515
    #[test]
    fn issue_515() {
        let data = [63, 9, 45, 10, 45, 10, 45, 45, 45, 45, 45, 66, 69,
                    71, 73, 78, 32, 80, 71, 80, 32, 77, 69, 83, 83,
                    65, 71, 69, 45, 45, 45, 45, 45, 45, 152, 152, 152,
                    152, 152, 152, 255, 29, 152, 152, 152, 152, 152,
                    152, 152, 152, 152, 152, 10, 91, 45, 10, 45, 14,
                    0, 36, 0, 0, 30, 122, 4, 2, 204, 152];

        let mut reader = Reader::from_bytes(&data[..], None);
        let mut buf = Vec::new();
        // `data` is malformed, expect an error.
        reader.read_to_end(&mut buf).unwrap_err();
    }

    /// Crash in armor parser due to improper use of the buffered
    /// reader protocol when consuming quoting prefix.
    ///
    /// See: https://gitlab.com/sequoia-pgp/sequoia/-/issues/516
    #[test]
    fn issue_516() {
        let data = [
            144, 32, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 125, 13, 125,
            125, 93, 125, 125, 93, 125, 13, 13, 125, 125, 45, 45, 45,
            45, 45, 66, 69, 71, 73, 78, 32, 80, 71, 80, 32, 77, 69,
            83, 83, 65, 71, 69, 45, 45, 45, 45, 45, 125, 13, 125,
            125, 93, 125, 125, 93, 125, 13, 13, 125, 125, 45, 0, 0,
            0, 0, 0, 0, 0, 0, 125, 205, 21, 1, 21, 21, 21, 1, 1, 1,
            1, 21, 149, 21, 21, 21, 21, 32, 4, 141, 141, 141, 141,
            202, 74, 11, 125, 8, 21, 50, 50, 194, 48, 147, 93, 174,
            23, 23, 23, 23, 23, 23, 147, 147, 147, 23, 23, 23, 23,
            23, 23, 48, 125, 125, 93, 125, 13, 125, 125, 125, 93,
            125, 125, 13, 13, 125, 125, 13, 13, 93, 125, 13, 125, 45,
            125, 125, 45, 45, 66, 69, 71, 73, 78, 32, 80, 71, 45, 45,
            125, 10, 45, 45, 0, 0, 10, 45, 45, 210, 10, 0, 0, 87, 0,
            0, 0, 150, 10, 0, 0, 241, 87, 45, 0, 0, 121, 121, 10, 10,
            21, 58];
        let mut reader = Reader::from_bytes(&data[..], None);
        let mut buf = Vec::new();
        // `data` is malformed, expect an error.
        reader.read_to_end(&mut buf).unwrap_err();
    }

    /// Crash in armor parser due to improper use of the buffered
    /// reader protocol when consuming quoting prefix.
    ///
    /// See: https://gitlab.com/sequoia-pgp/sequoia/-/issues/517
    #[test]
    fn issue_517() {
        let data = [13, 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 80,
                    71, 80, 32, 77, 69, 83, 83, 65, 71, 69, 45, 45, 45,
                    45, 45, 10, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13,
                    13, 13, 139];
        let mut reader = Reader::from_bytes(&data[..], None);
        let mut buf = Vec::new();
        // `data` is malformed, expect an error.
        reader.read_to_end(&mut buf).unwrap_err();
    }

    #[test]
    fn common_prefix() {
        use super::common_prefix as cp;
        assert_eq!(cp("", ""), 0);
        assert_eq!(cp("a", ""), 0);
        assert_eq!(cp("", "a"), 0);
        assert_eq!(cp("a", "a"), 1);
        assert_eq!(cp("aa", "a"), 1);
        assert_eq!(cp("a", "aa"), 1);
        assert_eq!(cp("ac", "ab"), 1);
    }

    /// A certificate was mangled turning -- into n-dash, --- into
    /// m-dash.  Fun with Unicode.
    #[test]
    fn issue_610() {
        let mut buf = Vec::new();
        // First, we now accept any dash character, not only '-'.
        let mut reader = Reader::from_bytes(
            crate::tests::file("armor/test-3.unicode-dashes.asc"), None);
        reader.read_to_end(&mut buf).unwrap();

        // Second, the transformation changed the number of dashes.
        let mut reader = Reader::from_bytes(
            crate::tests::file("armor/test-3.unbalanced-dashes.asc"), None);
        reader.read_to_end(&mut buf).unwrap();

        // Third, as it is not about the dashes, we even accept none.
        let mut reader = Reader::from_bytes(
            crate::tests::file("armor/test-3.no-dashes.asc"), None);
        reader.read_to_end(&mut buf).unwrap();
    }
}
