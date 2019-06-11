use Result;
use TPK;
use packet::{Key, Tag};
use serialize::{PacketRef, Serialize, SerializeInto, generic_serialize_into};

impl Serialize for TPK {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        PacketRef::PublicKey(self.primary()).serialize(o)?;

        for s in self.selfsigs() {
            PacketRef::Signature(s).serialize(o)?;
        }
        for s in self.self_revocations() {
            PacketRef::Signature(s).serialize(o)?;
        }
        for s in self.other_revocations() {
            PacketRef::Signature(s).serialize(o)?;
        }
        for s in self.certifications() {
            PacketRef::Signature(s).serialize(o)?;
        }

        for u in self.userids.iter() {
            PacketRef::UserID(u.userid()).serialize(o)?;
            for s in u.self_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.selfsigs() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.other_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.certifications() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for u in self.user_attributes.iter() {
            PacketRef::UserAttribute(u.user_attribute()).serialize(o)?;
            for s in u.self_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.selfsigs() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.other_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.certifications() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for k in self.subkeys.iter() {
            PacketRef::PublicSubkey(k.subkey()).serialize(o)?;
            for s in k.self_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in k.selfsigs() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in k.other_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in k.certifications() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for u in self.unknowns.iter() {
            PacketRef::Unknown(&u.unknown).serialize(o)?;

            for s in u.sigs.iter() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for s in self.bad.iter() {
            PacketRef::Signature(s).serialize(o)?;
        }

        Ok(())
    }
}

impl SerializeInto for TPK {
    fn serialized_len(&self) -> usize {
        let mut l = 0;
        l += PacketRef::PublicKey(self.primary()).serialized_len();

        for s in self.selfsigs() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.self_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.other_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.certifications() {
            l += PacketRef::Signature(s).serialized_len();
        }

        for u in self.userids.iter() {
            l += PacketRef::UserID(u.userid()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.user_attributes.iter() {
            l += PacketRef::UserAttribute(u.user_attribute()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for k in self.subkeys.iter() {
            l += PacketRef::PublicSubkey(k.subkey()).serialized_len();

            for s in k.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.unknowns.iter() {
            l += PacketRef::Unknown(&u.unknown).serialized_len();

            for s in u.sigs.iter() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for s in self.bad.iter() {
            l += PacketRef::Signature(s).serialized_len();
        }

        l
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(generic_serialize_into(self, buf).unwrap())
    }
}

impl TPK {
    /// Derive a [`TSK`] object from this key.
    ///
    /// This object writes out secret keys during serialization.
    ///
    /// [`TSK`]: serialize/struct.TSK.html
    pub fn as_tsk<'a>(&'a self) -> TSK<'a> {
        TSK::new(self)
    }
}

/// A reference to a TPK that allows serialization of secret keys.
///
/// To avoid accidental leakage `TPK::serialize()` skips secret keys.
/// To serialize `TPK`s with secret keys, use [`TPK::as_tsk()`] to
/// create a `TSK`, which is a shim on top of the `TPK`, and serialize
/// this.
///
/// [`TPK::as_tsk()`]: ../struct.TPK.html#method.as_tsk
///
/// # Example
/// ```
/// # use sequoia_openpgp::{*, tpk::*, parse::Parse, serialize::Serialize};
/// # f().unwrap();
/// # fn f() -> Result<()> {
/// let (tpk, _) = TPKBuilder::new().generate()?;
/// assert!(tpk.is_tsk());
///
/// let mut buf = Vec::new();
/// tpk.as_tsk().serialize(&mut buf)?;
///
/// let tpk_ = TPK::from_bytes(&buf)?;
/// assert!(tpk_.is_tsk());
/// assert_eq!(tpk, tpk_);
/// # Ok(()) }
pub struct TSK<'a> {
    tpk: &'a TPK,
    filter: Option<Box<'a + Fn(&'a Key) -> bool>>,
}

impl<'a> TSK<'a> {
    /// Creates a new view for the given `TPK`.
    fn new(tpk: &'a TPK) -> Self {
        Self {
            tpk: tpk,
            filter: None,
        }
    }

    /// Filters which secret keys to export using the given predicate.
    ///
    /// Note that the given filter replaces any existing filter.
    ///
    /// # Example
    /// ```
    /// # use sequoia_openpgp::{*, tpk::*, parse::Parse, serialize::Serialize};
    /// # f().unwrap();
    /// # fn f() -> Result<()> {
    /// let (tpk, _) = TPKBuilder::new().add_signing_subkey().generate()?;
    /// assert_eq!(tpk.keys_valid().secret(true).count(), 2);
    ///
    /// // Only write out the primary key's secret.
    /// let mut buf = Vec::new();
    /// tpk.as_tsk().set_filter(|k| k == tpk.primary()).serialize(&mut buf)?;
    ///
    /// let tpk_ = TPK::from_bytes(&buf)?;
    /// assert_eq!(tpk_.keys_valid().secret(true).count(), 1);
    /// assert!(tpk_.primary().secret().is_some());
    /// # Ok(()) }
    pub fn set_filter<P>(mut self, predicate: P) -> Self
        where P: 'a + Fn(&'a Key) -> bool
    {
        self.filter = Some(Box::new(predicate));
        self
    }
}

impl<'a> Serialize for TSK<'a> {
    fn serialize(&self, o: &mut dyn std::io::Write) -> Result<()> {
        // Serializes public or secret key depending on the filter.
        let serialize_key =
            |o: &mut dyn std::io::Write, key: &'a Key, tag_public, tag_secret|
        {
            let tag = if key.secret().is_some()
                && self.filter.as_ref().map(|f| f(key)).unwrap_or(true) {
                tag_secret
            } else {
                tag_public
            };

            let packet = match tag {
                Tag::PublicKey => PacketRef::PublicKey(key),
                Tag::PublicSubkey => PacketRef::PublicSubkey(key),
                Tag::SecretKey => PacketRef::SecretKey(key),
                Tag::SecretSubkey => PacketRef::SecretSubkey(key),
                _ => unreachable!(),
            };

            packet.serialize(o)
        };
        serialize_key(o, &self.tpk.primary, Tag::PublicKey, Tag::SecretKey)?;

        for s in self.tpk.primary_selfsigs.iter() {
            PacketRef::Signature(s).serialize(o)?;
        }
        for s in self.tpk.primary_self_revocations.iter() {
            PacketRef::Signature(s).serialize(o)?;
        }
        for s in self.tpk.primary_certifications.iter() {
            PacketRef::Signature(s).serialize(o)?;
        }
        for s in self.tpk.primary_other_revocations.iter() {
            PacketRef::Signature(s).serialize(o)?;
        }

        for u in self.tpk.userids() {
            PacketRef::UserID(u.userid()).serialize(o)?;
            for s in u.self_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.selfsigs() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.other_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.certifications() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for u in self.tpk.user_attributes() {
            PacketRef::UserAttribute(u.user_attribute()).serialize(o)?;
            for s in u.self_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.selfsigs() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.other_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in u.certifications() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for k in self.tpk.subkeys() {
            serialize_key(o, k.subkey(), Tag::PublicSubkey, Tag::SecretSubkey)?;
            for s in k.self_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in k.selfsigs() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in k.other_revocations() {
                PacketRef::Signature(s).serialize(o)?;
            }
            for s in k.certifications() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for u in self.tpk.unknowns.iter() {
            PacketRef::Unknown(&u.unknown).serialize(o)?;

            for s in u.sigs.iter() {
                PacketRef::Signature(s).serialize(o)?;
            }
        }

        for s in self.tpk.bad.iter() {
            PacketRef::Signature(s).serialize(o)?;
        }

        Ok(())
    }
}

impl<'a> SerializeInto for TSK<'a> {
    fn serialized_len(&self) -> usize {
        let mut l = 0;

        // Serializes public or secret key depending on the filter.
        let serialized_len_key = |key: &'a Key, tag_public, tag_secret|
        {
            let tag = if key.secret().is_some()
                && self.filter.as_ref().map(|f| f(key)).unwrap_or(true) {
                tag_secret
            } else {
                tag_public
            };

            let packet = match tag {
                Tag::PublicKey => PacketRef::PublicKey(key),
                Tag::PublicSubkey => PacketRef::PublicSubkey(key),
                Tag::SecretKey => PacketRef::SecretKey(key),
                Tag::SecretSubkey => PacketRef::SecretSubkey(key),
                _ => unreachable!(),
            };

            packet.serialized_len()
        };
        l += serialized_len_key(&self.tpk.primary,
                                Tag::PublicKey, Tag::SecretKey);

        for s in self.tpk.selfsigs() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.tpk.self_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.tpk.other_revocations() {
            l += PacketRef::Signature(s).serialized_len();
        }
        for s in self.tpk.certifications() {
            l += PacketRef::Signature(s).serialized_len();
        }

        for u in self.tpk.userids.iter() {
            l += PacketRef::UserID(u.userid()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.tpk.user_attributes.iter() {
            l += PacketRef::UserAttribute(u.user_attribute()).serialized_len();

            for s in u.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in u.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for k in self.tpk.subkeys.iter() {
            l += serialized_len_key(k.subkey(),
                                    Tag::PublicSubkey, Tag::SecretSubkey);

            for s in k.self_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.selfsigs() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.other_revocations() {
                l += PacketRef::Signature(s).serialized_len();
            }
            for s in k.certifications() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for u in self.tpk.unknowns.iter() {
            l += PacketRef::Unknown(&u.unknown).serialized_len();

            for s in u.sigs.iter() {
                l += PacketRef::Signature(s).serialized_len();
            }
        }

        for s in self.tpk.bad.iter() {
            l += PacketRef::Signature(s).serialized_len();
        }

        l
    }

    fn serialize_into(&self, buf: &mut [u8]) -> Result<usize> {
        generic_serialize_into(self, buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use parse::Parse;
    use serialize::Serialize;

    /// Demonstrates that public keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_tpk() {
        for test in ::tests::TPKS {
            let tpk = match TPK::from_bytes(test.bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            assert!(! tpk.is_tsk());
            let buf = tpk.as_tsk().to_vec().unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}.pgp failed", test);
        }
    }

    /// Demonstrates that secret keys and all components are
    /// serialized.
    #[test]
    fn roundtrip_tsk() {
        for test in ::tests::TSKS {
            let tpk = TPK::from_bytes(test.bytes).unwrap();
            assert!(tpk.is_tsk());

            let mut buf = Vec::new();
            tpk.as_tsk().serialize(&mut buf).unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}-private.pgp failed", test);

            // This time, use a trivial filter.
            let mut buf = Vec::new();
            tpk.as_tsk().set_filter(|_| true).serialize(&mut buf).unwrap();
            let tpk_ = TPK::from_bytes(&buf).unwrap();

            assert_eq!(tpk, tpk_, "roundtripping {}-private.pgp failed", test);
        }
    }

    /// Demonstrates that TSK::serialize() with the right filter
    /// reduces to TPK::serialize().
    #[test]
    fn reduce_to_tpk_serialize() {
        for test in ::tests::TSKS {
            let tpk = TPK::from_bytes(test.bytes).unwrap();
            assert!(tpk.is_tsk());

            // First, use TPK::serialize().
            let mut buf_tpk = Vec::new();
            tpk.serialize(&mut buf_tpk).unwrap();

            // When serializing using TSK::serialize, filter out all
            // secret keys.
            let mut buf_tsk = Vec::new();
            tpk.as_tsk().set_filter(|_| false).serialize(&mut buf_tsk).unwrap();

            // Check for equality.
            let tpk_ = TPK::from_bytes(&buf_tpk).unwrap();
            let tsk_ = TPK::from_bytes(&buf_tsk).unwrap();
            assert_eq!(tpk_, tsk_,
                       "reducing failed on {}-private.pgp: not TPK::eq",
                       test);

            // Check for identinty.
            assert_eq!(buf_tpk, buf_tsk,
                       "reducing failed on {}-private.pgp: serialized identity",
                       test);
        }
    }
}
