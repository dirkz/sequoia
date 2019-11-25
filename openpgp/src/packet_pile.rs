use std::fmt;
use std::slice;
use std::vec;
use std::io;
use std::path::Path;

use buffered_reader::BufferedReader;

use crate::Result;
use crate::Error;
use crate::Packet;
use crate::packet::{self, Container};
use crate::PacketPile;
use crate::parse::PacketParserResult;
use crate::parse::PacketParserBuilder;
use crate::parse::Parse;
use crate::parse::Cookie;


impl fmt::Debug for PacketPile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("PacketPile")
            .field("packets", &self.top_level.packets)
            .finish()
    }
}

impl<'a> Parse<'a, PacketPile> for PacketPile {
    /// Deserializes the OpenPGP message stored in a `std::io::Read`
    /// object.
    ///
    /// Although this method is easier to use to parse a sequence of
    /// OpenPGP packets than a [`PacketParser`] or a
    /// [`PacketPileParser`], this interface buffers the whole message
    /// in memory.  Thus, the caller must be certain that the
    /// *deserialized* message is not too large.
    ///
    /// Note: this interface *does* buffer the contents of packets.
    ///
    ///   [`PacketParser`]: parse/struct.PacketParser.html
    ///   [`PacketPileParser`]: parse/struct.PacketPileParser.html
    fn from_reader<R: 'a + io::Read>(reader: R) -> Result<PacketPile> {
        let bio = buffered_reader::Generic::with_cookie(
            reader, None, Cookie::default());
        PacketPile::from_buffered_reader(Box::new(bio))
    }

    /// Deserializes the OpenPGP message stored in the file named by
    /// `path`.
    ///
    /// See `from_reader` for more details and caveats.
    fn from_file<P: AsRef<Path>>(path: P) -> Result<PacketPile> {
        PacketPile::from_buffered_reader(
            Box::new(buffered_reader::File::with_cookie(path, Cookie::default())?))
    }

    /// Deserializes the OpenPGP message stored in the provided buffer.
    ///
    /// See `from_reader` for more details and caveats.
    fn from_bytes<D: AsRef<[u8]> + ?Sized>(data: &'a D) -> Result<PacketPile> {
        let bio = buffered_reader::Memory::with_cookie(
            data.as_ref(), Cookie::default());
        PacketPile::from_buffered_reader(Box::new(bio))
    }
}

impl std::str::FromStr for PacketPile {
    type Err = failure::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_bytes(s.as_bytes())
    }
}

impl From<Vec<Packet>> for PacketPile {
    fn from(p: Vec<Packet>) -> Self {
        PacketPile { top_level: Container { packets: p } }
    }
}

impl From<Packet> for PacketPile {
    fn from(p: Packet) -> Self {
        Self::from(vec![p])
    }
}

impl PacketPile {
    /// Pretty prints the message to stderr.
    ///
    /// This function is primarily intended for debugging purposes.
    pub fn pretty_print(&self) {
        self.top_level.pretty_print(0);
    }

    /// Returns a reference to the packet at the location described by
    /// `pathspec`.
    ///
    /// `pathspec` is a slice of the form `[ 0, 1, 2 ]`.  Each element
    /// is the index of packet in a container.  Thus, the previous
    /// path specification means: return the third child of the second
    /// child of the first top-level packet.  In other words, the
    /// starred packet in the following tree:
    ///
    /// ```text
    ///         PacketPile
    ///        /     |     \
    ///       0      1      2  ...
    ///     /   \
    ///    /     \
    ///  0         1  ...
    ///        /   |   \  ...
    ///       0    1    2
    ///                 *
    /// ```
    ///
    /// And, `[ 10 ]` means return the 11th top-level packet.
    ///
    /// Note: there is no packet at the root.  Thus, the path `[]`
    /// returns None.
    pub fn path_ref(&self, pathspec: &[usize]) -> Option<&Packet> {
        let mut packet : Option<&Packet> = None;

        let mut cont = Some(&self.top_level);
        for i in pathspec {
            if let Some(ref c) = cont.take() {
                if *i < c.packets.len() {
                    let p = &c.packets[*i];
                    packet = Some(p);
                    cont = p.children_ref();
                    continue;
                }
            }

            return None;
        }
        return packet;
    }

    /// Returns a mutable reference to the packet at the location
    /// described by `pathspec`.
    ///
    /// See the description of the `path_spec` for more details.
    pub fn path_ref_mut(&mut self, pathspec: &[usize]) -> Option<&mut Packet> {
        let mut container = &mut self.top_level;

        for (level, &i) in pathspec.iter().enumerate() {
            let tmp = container;

            if i >= tmp.packets.len() {
                return None;
            }

            let p = &mut tmp.packets[i];

            if level == pathspec.len() - 1 {
                return Some(p)
            }

            container = p.children_mut().unwrap();
        }

        None
    }

    /// Replaces the specified packets at the location described by
    /// `pathspec` with `packets`.
    ///
    /// If a packet is a container, the sub-tree rooted at the
    /// container is removed.
    ///
    /// Note: the number of packets to remove need not match the
    /// number of packets to insert.
    ///
    /// The removed packets are returned.
    ///
    /// If the path was invalid, then `Error::IndexOutOfRange` is
    /// returned instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::{Result, types::{CompressionAlgorithm, DataFormat},
    /// #     Packet, PacketPile, packet::Literal, packet::CompressedData};
    ///
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// // A compressed data packet that contains a literal data packet.
    /// let mut literal = Literal::new(DataFormat::Text);
    /// literal.set_body(b"old".to_vec());
    /// let mut pile = PacketPile::from(Packet::from(
    ///     CompressedData::new(CompressionAlgorithm::Uncompressed)
    ///         .push(literal.into())));
    ///
    /// // Replace the literal data packet.
    /// let mut literal = Literal::new(DataFormat::Text);
    /// literal.set_body(b"new".to_vec());
    /// pile.replace(
    ///     &[ 0, 0 ], 1,
    ///     [ literal.into() ].to_vec())
    ///     .unwrap();
    /// # if let Some(Packet::Literal(lit)) = pile.path_ref(&[0, 0]) {
    /// #     assert_eq!(lit.body(), Some(&b"new"[..]), "{:#?}", lit);
    /// # } else {
    /// #     panic!("Unexpected packet!");
    /// # }
    /// #     Ok(())
    /// # }
    /// ```
    pub fn replace(&mut self, pathspec: &[usize], count: usize,
                   mut packets: Vec<Packet>)
        -> Result<Vec<Packet>>
    {
        let mut container = &mut self.top_level;

        for (level, &i) in pathspec.iter().enumerate() {
            let tmp = container;

            if level == pathspec.len() - 1 {
                if i + count > tmp.packets.len() {
                    return Err(Error::IndexOutOfRange.into());
                }

                // Out with the old...
                let old = tmp.packets
                    .drain(i..i + count)
                    .collect::<Vec<Packet>>();
                assert_eq!(old.len(), count);

                // In with the new...

                let mut tail = tmp.packets
                    .drain(i..)
                    .collect::<Vec<Packet>>();

                tmp.packets.append(&mut packets);
                tmp.packets.append(&mut tail);

                return Ok(old)
            }

            if i >= tmp.packets.len() {
                return Err(Error::IndexOutOfRange.into());
            }

            let p = &mut tmp.packets[i];
            if p.children_ref().is_none() {
                match p {
                    Packet::CompressedData(_) | Packet::SEIP(_) => {
                        // We have a container with no children.
                        // That's okay.  We can create the container.
                        p.set_children(Some(Container::new()));
                    },
                    _ => {
                        return Err(Error::IndexOutOfRange.into());
                    }
                }
            }

            container = p.children_mut().unwrap();
        }

        return Err(Error::IndexOutOfRange.into());
    }

    /// Returns an iterator over all of the packet's descendants, in
    /// depth-first order.
    pub fn descendants(&self) -> packet::Iter {
        self.top_level.descendants()
    }

    /// Returns an iterator over the top-level packets.
    pub fn children<'a>(&'a self) -> slice::Iter<'a, Packet> {
        self.top_level.children()
    }

    /// Returns an `IntoIter` over the top-level packets.
    pub fn into_children(self) -> vec::IntoIter<Packet> {
        self.top_level.into_children()
    }


    pub(crate) fn from_buffered_reader<'a>(bio: Box<dyn BufferedReader<Cookie> + 'a>)
            -> Result<PacketPile> {
        PacketParserBuilder::from_buffered_reader(bio)?
            .buffer_unread_content()
            .into_packet_pile()
    }

    /// Reads all of the packets from a `PacketParser`, and turns them
    /// into a message.
    ///
    /// Note: this assumes that `ppr` points to a top-level packet.
    pub fn from_packet_parser<'a>(ppr: PacketParserResult<'a>)
        -> Result<PacketPile>
    {
        // Things are not going to work out if we don't start with a
        // top-level packet.  We should only pop until
        // ppo.recursion_depth and leave the rest of the message, but
        // it is hard to imagine that that is what the caller wants.
        // Instead of hiding that error, fail fast.
        if let PacketParserResult::Some(ref pp) = ppr {
            assert_eq!(pp.recursion_depth(), 0);
        }

        // Create a top-level container.
        let mut top_level = Container::new();

        let mut last_position = 0;

        if ppr.is_none() {
            // Empty message.
            return Ok(PacketPile::from(Vec::new()));
        }
        let mut pp = ppr.unwrap();

        'outer: loop {
            let (mut packet, mut ppr) = pp.recurse()?;
            let mut position = ppr.last_recursion_depth().unwrap() as isize;

            let mut relative_position : isize = position - last_position;
            assert!(relative_position <= 1);

            // Find the right container for `packet`.
            let mut container = &mut top_level;
            // If we recurse, don't create the new container here.
            for _ in 0..(position - if relative_position > 0 { 1 } else { 0 }) {
                // Do a little dance to prevent container from
                // being reborrowed and preventing us from
                // assigning to it.
                let tmp = container;
                let packets_len = tmp.packets.len();
                let p = &mut tmp.packets[packets_len - 1];

                container = p.children_mut().unwrap();
            }

            if relative_position < 0 {
                relative_position = 0;
            }

            // If next packet will be inserted in the same container
            // or the current container's child, we don't need to walk
            // the tree from the root.
            loop {
                if relative_position == 1 {
                    // Create a new container.
                    let tmp = container;
                    let i = tmp.packets.len() - 1;
                    assert!(tmp.packets[i].children_ref().is_none());
                    tmp.packets[i].set_children(Some(Container::new()));
                    container = tmp.packets[i].children_mut().unwrap();
                }

                container.packets.push(packet);

                if ppr.is_none() {
                    break 'outer;
                }

                pp = ppr.unwrap();

                last_position = position;
                position = pp.recursion_depth() as isize;
                relative_position = position - last_position;
                if position < last_position {
                    // There was a pop, we need to restart from the
                    // root.
                    break;
                }

                let (packet_, ppr_) = pp.recurse()?;
                packet = packet_;
                ppr = ppr_;
                assert_eq!(position,
                           ppr.last_recursion_depth().unwrap() as isize);
            }
        }

        return Ok(PacketPile { top_level: top_level });
    }
}

impl<'a> PacketParserBuilder<'a> {
    /// Finishes configuring the `PacketParser` and returns a fully
    /// parsed message.
    ///
    /// Note: calling this function does not change the default
    /// settings `PacketParserSettings`.  Thus, by default, the
    /// content of packets will *not* be buffered.
    ///
    /// Note: to avoid denial of service attacks, the `PacketParser`
    /// interface should be preferred unless the size of the message
    /// is known to fit in memory.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// # use openpgp::PacketPile;
    /// # use openpgp::parse::{Parse, PacketParser, PacketParserBuilder};
    /// # f(include_bytes!("../tests/data/keys/public-key.gpg"));
    /// #
    /// # fn f(message_data: &[u8]) -> Result<PacketPile> {
    /// let message = PacketParserBuilder::from_bytes(message_data)?
    ///     .buffer_unread_content()
    ///     .into_packet_pile()?;
    /// # return Ok(message);
    /// # }
    /// ```
    pub fn into_packet_pile(self) -> Result<PacketPile> {
        PacketPile::from_packet_parser(self.finalize()?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::types::CompressionAlgorithm;
    use crate::types::DataFormat::Text;
    use crate::packet::Literal;
    use crate::packet::CompressedData;
    use crate::packet::seip::SEIP1;
    use crate::packet::Tag;
    use crate::parse::{Parse, PacketParser};

    #[test]
    fn deserialize_test_1 () {
        // XXX: This test should be more thorough.  Right now, we mostly
        // just rely on the fact that an assertion is not thrown.

        // A flat message.
        let pile = PacketPile::from_bytes(crate::tests::key("public-key.gpg"))
            .unwrap();
        eprintln!("PacketPile has {} top-level packets.",
                  pile.children().len());
        eprintln!("PacketPile: {:?}", pile);

        let mut count = 0;
        for (i, p) in pile.descendants().enumerate() {
            eprintln!("{}: {:?}", i, p);
            count += 1;
        }

        assert_eq!(count, 61);
    }

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn deserialize_test_2 () {
        // A message containing a compressed packet that contains a
        // literal packet.
        let pile = PacketPile::from_bytes(
            crate::tests::message("compressed-data-algo-1.gpg")).unwrap();
        eprintln!("PacketPile has {} top-level packets.",
                  pile.children().len());
        eprintln!("PacketPile: {:?}", pile);

        let mut count = 0;
        for (i, p) in pile.descendants().enumerate() {
            eprintln!("{}: {:?}", i, p);
            count += 1;
        }
        assert_eq!(count, 2);
    }

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn deserialize_test_3 () {
        let pile =
            PacketPile::from_bytes(crate::tests::message("signed.gpg")).unwrap();
        eprintln!("PacketPile has {} top-level packets.",
                  pile.children().len());
        eprintln!("PacketPile: {:?}", pile);

        let mut count = 0;
        for (i, p) in pile.descendants().enumerate() {
            count += 1;
            eprintln!("{}: {:?}", i, p);
        }
        // We expect 6 packets.
        assert_eq!(count, 6);
    }

    // dkg's key contains packets from different OpenPGP
    // implementations.  And, it even includes some v3 signatures.
    //
    // lutz's key is a v3 key.
    #[test]
    fn torture() {
        let data = crate::tests::key("dkg.gpg");
        let mut ppp = PacketParserBuilder::from_bytes(data).unwrap()
            //.trace()
            .buffer_unread_content()
            .into_packet_pile_parser().unwrap();

        while ppp.recurse() {
            //let pp = ppp.ppo.as_mut().unwrap();
            //eprintln!("{:?}", pp);
        }
        let pile = ppp.finish();
        //pile.pretty_print();
        assert_eq!(pile.children().len(), 1450);

        let data = crate::tests::key("lutz.gpg");
        let mut ppp = PacketParserBuilder::from_bytes(data).unwrap()
            //.trace()
            .buffer_unread_content()
            .into_packet_pile_parser().unwrap();

        while ppp.recurse() {
            if let PacketParserResult::Some(ref pp) = ppp.ppr {
                eprintln!("{:?}", pp);
            } else {
                // If PacketPileParser::recurse returns true, then
                // ppp.ppr is not EOF.
                unreachable!();
            }
        }
        let pile = ppp.finish();
        pile.pretty_print();
        assert_eq!(pile.children().len(), 77);
    }

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn compression_quine_test_1 () {
        // Use the PacketPile::from_file interface to parse an OpenPGP
        // quine.
        let max_recursion_depth = 128;
        let pile = PacketParserBuilder::from_bytes(
            crate::tests::message("compression-quine.gpg")).unwrap()
            .max_recursion_depth(max_recursion_depth)
            .into_packet_pile().unwrap();

        let mut count = 0;
        for (i, p) in pile.descendants().enumerate() {
            count += 1;
            if false {
                eprintln!("{}: p: {:?}", i, p);
            }
        }

        assert_eq!(count, 1 + max_recursion_depth);
    }

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn compression_quine_test_2 () {
        // Use the iterator interface to parse an OpenPGP quine.
        let max_recursion_depth = 255;
        let mut ppr : PacketParserResult
            = PacketParserBuilder::from_bytes(
                crate::tests::message("compression-quine.gpg")).unwrap()
                .max_recursion_depth(max_recursion_depth)
                .finalize().unwrap();

        let mut count = 0;
        loop {
            if let PacketParserResult::Some(pp2) = ppr {
                count += 1;

                let pp2 = pp2.recurse().unwrap().1;
                let packet_depth = pp2.last_recursion_depth().unwrap();
                assert_eq!(packet_depth, count - 1);
                if pp2.is_some() {
                    assert_eq!(pp2.recursion_depth(), Some(count));
                }
                ppr = pp2;
            } else {
                break;
            }
        }
        assert_eq!(count, 1 + max_recursion_depth as isize);
    }

    #[cfg(feature = "compression-deflate")]
    #[test]
    fn consume_content_1 () {
        use std::io::Read;
        // A message containing a compressed packet that contains a
        // literal packet.  When we read some of the compressed
        // packet, we expect recurse() to not recurse.

        let ppr = PacketParserBuilder::from_bytes(
                crate::tests::message("compressed-data-algo-1.gpg")).unwrap()
            .buffer_unread_content()
            .finalize().unwrap();

        let mut pp = ppr.unwrap();
        if let Packet::CompressedData(_) = pp.packet {
        } else {
            panic!("Expected a compressed packet!");
        }

        // Read some of the body of the compressed packet.
        let mut data = [0u8; 1];
        let amount = pp.read(&mut data).unwrap();
        assert_eq!(amount, 1);

        // recurse should now not recurse.  Since there is nothing
        // following the compressed packet, ppr should be EOF.
        let (packet, ppr) = pp.next().unwrap();
        assert!(ppr.is_none());

        // Get the rest of the content and put the initial byte that
        // we stole back.
        let mut content = packet.body().unwrap().to_vec();
        content.insert(0, data[0]);

        let content = &content.into_boxed_slice()[..];
        let ppr = PacketParser::from_bytes(content).unwrap();
        let pp = ppr.unwrap();
        if let Packet::Literal(_) = pp.packet {
        } else {
            panic!("Expected a literal packet!");
        }

        // And we're done...
        let ppr = pp.next().unwrap().1;
        assert!(ppr.is_none());
    }

    #[test]
    fn path_ref() {
        // 0: SEIP
        //  0: CompressedData
        //   0: Literal("one")
        //   1: Literal("two")
        //   2: Literal("three")
        //   3: Literal("four")
        let mut packets : Vec<Packet> = Vec::new();

        let text = [ &b"one"[..], &b"two"[..],
                      &b"three"[..], &b"four"[..] ].to_vec();

        let mut cd = CompressedData::new(CompressionAlgorithm::Uncompressed);
        for t in text.iter() {
            let mut lit = Literal::new(Text);
            lit.set_body(t.to_vec());
            cd = cd.push(lit.into())
        }

        let mut seip = SEIP1::new();
        seip.set_children(Some(Container::new()));
        seip.children_mut().unwrap().push(cd.into());
        packets.push(seip.into());

        eprintln!("{:#?}", packets);

        let mut pile = PacketPile::from(packets);

        assert_eq!(pile.path_ref(&[ 0 ]).unwrap().tag(), Tag::SEIP);
        assert_eq!(pile.path_ref_mut(&[ 0 ]).unwrap().tag(), Tag::SEIP);
        assert_eq!(pile.path_ref(&[ 0, 0 ]).unwrap().tag(),
                   Tag::CompressedData);
        assert_eq!(pile.path_ref_mut(&[ 0, 0 ]).unwrap().tag(),
                   Tag::CompressedData);

        for (i, t) in text.into_iter().enumerate() {
            assert_eq!(pile.path_ref(&[ 0, 0, i ]).unwrap().tag(),
                       Tag::Literal);
            assert_eq!(pile.path_ref_mut(&[ 0, 0, i ]).unwrap().tag(),
                       Tag::Literal);

            assert_eq!(pile.path_ref(&[ 0, 0, i ]).unwrap().body(),
                       Some(t));
            assert_eq!(pile.path_ref_mut(&[ 0, 0, i ]).unwrap().body(),
                       Some(t));
        }

        // Try a few out of bounds accesses.
        assert!(pile.path_ref(&[ 0, 0, 4 ]).is_none());
        assert!(pile.path_ref_mut(&[ 0, 0, 4 ]).is_none());

        assert!(pile.path_ref(&[ 0, 0, 5 ]).is_none());
        assert!(pile.path_ref_mut(&[ 0, 0, 5 ]).is_none());

        assert!(pile.path_ref(&[ 0, 1 ]).is_none());
        assert!(pile.path_ref_mut(&[ 0, 1 ]).is_none());

        assert!(pile.path_ref(&[ 0, 2 ]).is_none());
        assert!(pile.path_ref_mut(&[ 0, 2 ]).is_none());

        assert!(pile.path_ref(&[ 1 ]).is_none());
        assert!(pile.path_ref_mut(&[ 1 ]).is_none());

        assert!(pile.path_ref(&[ 2 ]).is_none());
        assert!(pile.path_ref_mut(&[ 2 ]).is_none());

        assert!(pile.path_ref(&[ 0, 1, 0 ]).is_none());
        assert!(pile.path_ref_mut(&[ 0, 1, 0 ]).is_none());

        assert!(pile.path_ref(&[ 0, 2, 0 ]).is_none());
        assert!(pile.path_ref_mut(&[ 0, 2, 0 ]).is_none());
    }

    #[test]
    fn replace() {
        // 0: Literal("one")
        // =>
        // 0: Literal("two")
        let mut one = Literal::new(Text);
        one.set_body(b"one".to_vec());
        let mut two = Literal::new(Text);
        two.set_body(b"two".to_vec());
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(one.into());

        assert!(packets.iter().map(|p| p.tag()).collect::<Vec<Tag>>()
                == [ Tag::Literal ]);

        let mut pile = PacketPile::from(packets.clone());
        pile.replace(
            &[ 0 ], 1,
            [ two.into()
            ].to_vec()).unwrap();

        let children = pile.into_children().collect::<Vec<Packet>>();
        assert_eq!(children.len(), 1, "{:#?}", children);
        if let Packet::Literal(ref literal) = children[0] {
            assert_eq!(literal.body(), Some(&b"two"[..]),
                       "{:#?}", literal);
        } else {
            panic!("WTF");
        }

        // We start with four packets, and replace some of them with
        // up to 3 packets.
        let initial
            = [ &b"one"[..], &b"two"[..], &b"three"[..], &b"four"[..] ].to_vec();
        let inserted
            = [ &b"a"[..], &b"b"[..], &b"c"[..] ].to_vec();

        let mut packets : Vec<Packet> = Vec::new();
        for text in initial.iter() {
            let mut lit = Literal::new(Text);
            lit.set_body(text.to_vec());
            packets.push(lit.into())
        }

        for start in 0..initial.len() + 1 {
            for delete in 0..initial.len() - start + 1 {
                for insert in 0..inserted.len() + 1 {
                    let mut pile = PacketPile::from(packets.clone());

                    let mut replacement : Vec<Packet> = Vec::new();
                    for &text in inserted[0..insert].iter() {
                        let mut lit = Literal::new(Text);
                        lit.set_body(text.to_vec());
                        replacement.push(lit.into());
                    }

                    pile.replace(&[ start ], delete, replacement).unwrap();

                    let values = pile
                        .children()
                        .map(|p| {
                            if let Packet::Literal(ref literal) = p {
                                literal.body().unwrap()
                            } else {
                                panic!("Expected a literal packet, got: {:?}", p);
                            }
                        })
                        .collect::<Vec<&[u8]>>();

                    assert_eq!(values.len(), initial.len() - delete + insert);

                    assert_eq!(values[..start],
                               initial[..start]);
                    assert_eq!(values[start..start + insert],
                               inserted[..insert]);
                    assert_eq!(values[start + insert..],
                               initial[start + delete..]);
                }
            }
        }


        // Like above, but the packets to replace are not at the
        // top-level, but in a compressed data packet.

        let initial
            = [ &b"one"[..], &b"two"[..], &b"three"[..], &b"four"[..] ].to_vec();
        let inserted
            = [ &b"a"[..], &b"b"[..], &b"c"[..] ].to_vec();

        let mut cd = CompressedData::new(CompressionAlgorithm::Uncompressed);
        for l in initial.iter() {
            let mut lit = Literal::new(Text);
            lit.set_body(l.to_vec());
            cd = cd.push(lit.into());
        }

        for start in 0..initial.len() + 1 {
            for delete in 0..initial.len() - start + 1 {
                for insert in 0..inserted.len() + 1 {
                    let mut pile = PacketPile::from(
                        vec![ cd.clone().into() ]);

                    let mut replacement : Vec<Packet> = Vec::new();
                    for &text in inserted[0..insert].iter() {
                        let mut lit = Literal::new(Text);
                        lit.set_body(text.to_vec());
                        replacement.push(lit.into());
                    }

                    pile.replace(&[ 0, start ], delete, replacement).unwrap();

                    let top_level = pile.children().collect::<Vec<&Packet>>();
                    assert_eq!(top_level.len(), 1);

                    let values = top_level[0]
                        .children()
                        .map(|p| {
                            if let Packet::Literal(ref literal) = p {
                                literal.body().unwrap()
                            } else {
                                panic!("Expected a literal packet, got: {:?}", p);
                            }
                        })
                        .collect::<Vec<&[u8]>>();

                    assert_eq!(values.len(), initial.len() - delete + insert);

                    assert_eq!(values[..start],
                               initial[..start]);
                    assert_eq!(values[start..start + insert],
                               inserted[..insert]);
                    assert_eq!(values[start + insert..],
                               initial[start + delete..]);
                }
            }
        }

        // Make sure out-of-range accesses error out.
        let mut one = Literal::new(Text);
        one.set_body(b"one".to_vec());
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(one.into());
        let mut pile = PacketPile::from(packets.clone());

        assert!(pile.replace(&[ 1 ], 0, Vec::new()).is_ok());
        assert!(pile.replace(&[ 2 ], 0, Vec::new()).is_err());
        assert!(pile.replace(&[ 0 ], 2, Vec::new()).is_err());
        assert!(pile.replace(&[ 0, 0 ], 0, Vec::new()).is_err());
        assert!(pile.replace(&[ 0, 1 ], 0, Vec::new()).is_err());

        // Try the same thing, but with a container.
        let mut packets : Vec<Packet> = Vec::new();
        packets.push(CompressedData::new(CompressionAlgorithm::Uncompressed)
                     .into());
        let mut pile = PacketPile::from(packets.clone());

        assert!(pile.replace(&[ 1 ], 0, Vec::new()).is_ok());
        assert!(pile.replace(&[ 2 ], 0, Vec::new()).is_err());
        assert!(pile.replace(&[ 0 ], 2, Vec::new()).is_err());
        // Since this is a container, this should be okay.
        assert!(pile.replace(&[ 0, 0 ], 0, Vec::new()).is_ok());
        assert!(pile.replace(&[ 0, 1 ], 0, Vec::new()).is_err());
    }

    #[test]
    fn packet_pile_is_send_and_sync() {
        fn f<T: Send + Sync>(_: T) {}
        f(PacketPile::from(vec![]));
    }
}
