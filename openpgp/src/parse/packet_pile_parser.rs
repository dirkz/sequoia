use std::convert::TryFrom;
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use crate::{
    Result,
    Packet,
    PacketPile,
};
use crate::parse::{
    PacketParserBuilder,
    PacketParserResult,
    PacketParser,
    Parse,
    Cookie
};
use buffered_reader::BufferedReader;

/// Parses an OpenPGP stream with the convenience of
/// [`PacketPile::from_file`] and the flexibility of a
/// [`PacketParser`].
///
///   [`PacketPile::from_file`]: ../struct.PacketPile.html#impl-Parse<%27a%2C%20PacketPile>
///   [`PacketParser`]: struct.PacketParser.html
///
/// Like [`PacketPile::from_file`] (and unlike [`PacketParser`]), a
/// `PacketPileParser` parses an OpenPGP message and returns a
/// [`PacketPile`].  But, unlike [`PacketPile::from_file`] (and like
/// [`PacketParser`]), it allows the caller to inspect each packet as
/// it is being parsed.
///
///   [`PacketPile`]: ../struct.PacketPile.html
///
/// Thus, using a `PacketPileParser`, it is possible to decide on a
/// per-packet basis whether to stream, buffer or drop the packet's
/// body, whether to recurse into a container, or whether to abort
/// processing, for example.  And, `PacketPileParser` conveniently packs
/// the packets into a [`PacketPile`].
///
/// If old packets don't need to be retained, then [`PacketParser`]
/// should be preferred.  If no per-packet processing needs to be
/// done, then [`PacketPile::from_file`] will be slightly faster.
///
/// # Examples
///
/// ```rust
/// # fn main() -> sequoia_openpgp::Result<()> {
/// use sequoia_openpgp as openpgp;
/// use openpgp::parse::{Parse, PacketPileParser};
///
/// // Parse a message.
/// let message_data: &[u8] = // ...
/// #    include_bytes!("../../tests/data/keys/public-key.gpg");
/// # let mut n = 0;
/// let mut ppp = PacketPileParser::from_bytes(message_data)?;
/// while let Some(pp) = ppp.as_ref() {
///     eprintln!("{:?}", pp);
///     ppp.recurse()?;
/// #   n += 1;
/// }
///
/// let pile = ppp.finish();
/// pile.pretty_print();
/// # assert_eq!(n, 61);
/// # assert_eq!(pile.children().len(), 61);
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PacketPileParser<'a> {
    /// The current packet.
    ppr: PacketParserResult<'a>,

    /// The packet pile that has been assembled so far.
    pile: PacketPile,
}

impl<'a> Deref for PacketPileParser<'a> {
    type Target = PacketParserResult<'a>;

    fn deref(&self) -> &Self::Target {
        &self.ppr
    }
}

impl<'a> DerefMut for PacketPileParser<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ppr
    }
}

impl<'a> TryFrom<PacketParserBuilder<'a>> for PacketPileParser<'a> {
    type Error = anyhow::Error;

    /// Finishes configuring the `PacketParser` and returns a
    /// `PacketPileParser`.
    fn try_from(ppb: PacketParserBuilder<'a>) -> Result<PacketPileParser<'a>> {
        Self::from_packet_parser(ppb.build()?)
    }
}

impl<'a> Parse<'a, PacketPileParser<'a>> for PacketPileParser<'a> {
    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the `io::Read` object.
    fn from_reader<R: io::Read + 'a>(reader: R)
             -> Result<PacketPileParser<'a>> {
        let bio = Box::new(buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default()));
        PacketPileParser::from_buffered_reader(bio)
    }

    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the file named by `path`.
    fn from_file<P: AsRef<Path>>(path: P)
            -> Result<PacketPileParser<'a>> {
        PacketPileParser::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path, Cookie::default())?))
    }

    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the provided buffer.
    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D)
            -> Result<PacketPileParser<'a>> {
        let bio = Box::new(buffered_reader::Memory::with_cookie(
            data.as_ref(), Cookie::default()));
        PacketPileParser::from_buffered_reader(bio)
    }
}

impl<'a> PacketPileParser<'a> {
    /// Creates a `PacketPileParser` from a *fresh* `PacketParser`.
    fn from_packet_parser(ppr: PacketParserResult<'a>)
        -> Result<PacketPileParser<'a>>
    {
        Ok(PacketPileParser {
            pile: Default::default(),
            ppr: ppr,
        })
    }

    /// Creates a `PacketPileParser` to parse the OpenPGP message stored
    /// in the `BufferedReader` object.
    pub(crate) fn from_buffered_reader(bio: Box<dyn BufferedReader<Cookie> + 'a>)
            -> Result<PacketPileParser<'a>> {
        Self::from_packet_parser(PacketParser::from_buffered_reader(bio)?)
    }

    /// Inserts the next packet into the `PacketPile`.
    fn insert_packet(&mut self, packet: Packet, position: isize) {
        // Find the right container.
        let mut container = self.pile.top_level_mut();

        assert!(position >= 0);

        for i in 0..position {
            // The most recent child.
            let tmp = container;
            let packets_len = tmp.children_ref().expect("is a container").len();
            let p = &mut tmp.children_mut()
                .expect("is a container")
                [packets_len - 1];
            if p.children().expect("is a container").next().is_none() {
                assert!(i == position - 1,
                        "Internal inconsistency while building message.");
            }

            container = p.container_mut().unwrap();
        }

        container.children_mut().unwrap().push(packet);
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one, recursing if possible.
    ///
    /// This method is similar to the [`next()`] method (see that
    /// method for more details), but if the current packet is a
    /// container (and we haven't reached the maximum recursion depth,
    /// and the user hasn't started reading the packet's contents), we
    /// recurse into the container, and return a `PacketParser` for
    /// its first child.  Otherwise, we return the next packet in the
    /// packet stream.  If this function recurses, then the new
    /// packet's recursion depth will be `last_recursion_depth() + 1`;
    /// because we always visit interior nodes, we can't recurse more
    /// than one level at a time.
    ///
    ///   [`next()`]: #method.next
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::parse::{Parse, PacketPileParser};
    ///
    /// // Parse a message.
    /// let message_data: &[u8] = // ...
    /// #    include_bytes!("../../tests/data/messages/compressed-data-algo-0.pgp");
    /// let mut ppp = PacketPileParser::from_bytes(message_data)?;
    /// while let Some(pp) = ppp.as_ref() {
    ///     // Do something interesting with `pp` here.
    ///
    ///     // Start parsing the next packet, recursing.
    ///     ppp.recurse()?;
    /// }
    ///
    /// let pile = ppp.finish();
    /// # Ok(()) }
    /// ```
    pub fn recurse(&mut self) -> Result<()> {
        match self.ppr.take() {
            PacketParserResult::Some(pp) => {
                let recursion_depth = pp.recursion_depth();
                let (packet, ppr) = pp.recurse()?;
                self.insert_packet(
                    packet,
                    recursion_depth as isize);
                self.ppr = ppr;
            }
            eof @ PacketParserResult::EOF(_) => {
                self.ppr = eof;
            }
        }

        Ok(())
    }

    /// Finishes parsing the current packet and starts parsing the
    /// next one.
    ///
    /// This function finishes parsing the current packet.  By
    /// default, any unread content is dropped.  (See
    /// [`PacketParsererBuilder`] for how to configure this.)  It then
    /// creates a new packet parser for the next packet.  If the
    /// current packet is a container, this function does *not*
    /// recurse into the container, but skips any packets it contains.
    /// To recurse into the container, use the [`recurse()`] method.
    ///
    ///   [`PacketParsererBuilder`]: struct.PacketParserBuilder.html
    ///   [`recurse()`]: #method.recurse
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::parse::{Parse, PacketPileParser};
    ///
    /// // Parse a message.
    /// let message_data: &[u8] = // ...
    /// #    include_bytes!("../../tests/data/messages/compressed-data-algo-0.pgp");
    /// let mut ppp = PacketPileParser::from_bytes(message_data)?;
    /// while let Some(pp) = ppp.as_ref() {
    ///     // Do something interesting with `pp` here.
    ///
    ///     // Start parsing the next packet.
    ///     ppp.next()?;
    /// }
    ///
    /// let pile = ppp.finish();
    /// # Ok(()) }
    /// ```
    pub fn next(&mut self) -> Result<()> {
        match self.ppr.take() {
            PacketParserResult::Some(pp) => {
                let recursion_depth = pp.recursion_depth();
                let (packet, ppr) = pp.next()?;
                self.insert_packet(
                    packet,
                    recursion_depth as isize);
                self.ppr = ppr;
            },
            eof @ PacketParserResult::EOF(_) => {
                self.ppr = eof
            },
        }

        Ok(())
    }

    /// Returns the current packet's recursion depth.
    ///
    /// A top-level packet has a recursion depth of 0.  Packets in a
    /// top-level container have a recursion depth of 1.  Etc.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::Packet;
    /// use openpgp::parse::{Parse, PacketPileParser};
    ///
    /// // Parse a simple compressed message.
    /// let message_data: &[u8] = // ...
    /// #    include_bytes!("../../tests/data/messages/compressed-data-algo-0.pgp");
    /// let mut ppp = PacketPileParser::from_bytes(message_data)?;
    /// while let Some(pp) = ppp.as_ref() {
    ///     match pp.packet {
    ///         Packet::CompressedData(_) =>
    ///             assert_eq!(ppp.recursion_depth(), Some(0)),
    ///         Packet::Literal(_) =>
    ///             assert_eq!(ppp.recursion_depth(), Some(1)),
    ///         _ => unreachable!(),
    ///     }
    ///
    ///     // Alternatively, the recursion depth can be queried
    ///     // from the packet parser.
    ///     assert_eq!(ppp.recursion_depth(), Some(pp.recursion_depth()));
    ///
    ///     // Start parsing the next packet.
    ///     ppp.next()?;
    /// }
    ///
    /// let pile = ppp.finish();
    /// # Ok(()) }
    /// ```
    pub fn recursion_depth(&self) -> Option<isize> {
        if let PacketParserResult::Some(ref pp) = self.ppr {
            Some(pp.recursion_depth())
        } else {
            None
        }
    }

    /// Returns whether the message has been completely parsed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::Packet;
    /// use openpgp::parse::{Parse, PacketPileParser};
    ///
    /// // Parse a message.
    /// let message_data: &[u8] = // ...
    /// #    include_bytes!("../../tests/data/messages/compressed-data-algo-0.pgp");
    /// let mut ppp = PacketPileParser::from_bytes(message_data)?;
    /// while ppp.is_some() {
    ///     // Start parsing the next packet.
    ///     ppp.next()?;
    /// }
    ///
    /// assert!(ppp.is_done());
    /// let pile = ppp.finish();
    /// # Ok(()) }
    /// ```
    pub fn is_done(&self) -> bool {
        self.ppr.is_none()
    }

    /// Finishes parsing the message and returns the assembled
    /// `PacketPile`.
    ///
    /// This function can be called at any time, not only when the
    /// message has been completely parsed.  If the packet sequence has not
    /// been completely parsed, this function aborts processing, and
    /// the returned `PacketPile` just contains those packets that were
    /// completely processed; the packet that is currently being
    /// processed is not included in the `PacketPile`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> sequoia_openpgp::Result<()> {
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::Packet;
    /// use openpgp::parse::{Parse, PacketPileParser};
    ///
    /// // Parse a message.
    /// let message_data: &[u8] = // ...
    /// #    include_bytes!("../../tests/data/messages/compressed-data-algo-0.pgp");
    /// let mut ppp = PacketPileParser::from_bytes(message_data)?;
    /// ppp.next()?;
    ///
    /// let pp = ppp.finish();
    /// assert_eq!(pp.children().count(), 1);
    /// # Ok(()) }
    /// ```
    pub fn finish(self) -> PacketPile {
        return self.pile;
    }
}

#[test]
fn test_recurse() -> Result<()> {
    let mut count = 0;
    let mut ppp =
        PacketPileParser::from_bytes(crate::tests::key("public-key.gpg"))?;
    while ppp.is_some() {
        count += 1;
        ppp.recurse().unwrap();
    }
    assert_eq!(count, 61);
    Ok(())
}

#[test]
fn test_next() -> Result<()> {
    let mut count = 0;
    let mut ppp =
        PacketPileParser::from_bytes(crate::tests::key("public-key.gpg"))?;
    while ppp.is_some() {
        count += 1;
        ppp.next().unwrap();
    }
    assert_eq!(count, 61);
    Ok(())
}

/// Check that we can use the read interface to stream the contents of
/// a packet.
#[cfg(feature = "compression-deflate")]
#[test]
fn message_parser_reader_interface() {
    use std::io::Read;

    let expected = crate::tests::manifesto();

    // A message containing a compressed packet that contains a
    // literal packet.
    let mut ppp = PacketPileParser::from_bytes(
        crate::tests::message("compressed-data-algo-1.gpg")).unwrap();
    let mut count = 0;
    while let Some(pp) = ppp.as_mut() {
        if let Packet::Literal(_) = pp.packet {
            assert_eq!(count, 1); // The *second* packet.

            // Check that we can read the packet's contents.  We do this one
            // byte at a time to exercise the cursor implementation.
            for i in 0..expected.len() {
                let mut buf = [0u8; 1];
                let r = pp.read(&mut buf).unwrap();
                assert_eq!(r, 1);
                assert_eq!(buf[0], expected[i]);
            }
            // And, now an EOF.
            let mut buf = [0u8; 1];
            let r = pp.read(&mut buf).unwrap();
            assert_eq!(r, 0);
        }
        ppp.recurse().unwrap();
        count += 1;
    }
    assert_eq!(count, 2);
}
