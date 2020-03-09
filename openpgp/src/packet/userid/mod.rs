use std::fmt;
use std::str;
use std::hash::{Hash, Hasher};
use std::cell::RefCell;
use std::cmp::Ordering;
use std::sync::Mutex;

use quickcheck::{Arbitrary, Gen};
use anyhow::Context;
use regex::Regex;

use crate::Result;
use crate::packet;
use crate::Packet;
use crate::Error;

/// A conventionally parsed UserID.
///
/// Informally, conventional UserIDs are of the form:
///
///   - First Last (Comment) <name@example.org>
///   - First Last <name@example.org>
///   - First Last
///   - name@example.org <name@example.org>
///   - <name@example.org>
///   - name@example.org
///
///   - Name (Comment) <scheme://hostname/path>
///   - Name (Comment) <mailto:user@example.org>
///   - Name <scheme://hostname/path>
///   - <scheme://hostname/path>
///   - scheme://hostname/path
///
/// Names consist of UTF-8 non-control characters and may include
/// punctuation.  For instance, the following names are valid:
///
///   - Acme Industries, Inc.
///   - Michael O'Brian
///   - Smith, John
///   - e.e. cummings
///
/// (Note: according to RFC 2822 and its successors, all of these
/// would need to be quoted.  Conventionally, no implementation quotes
/// names.)
///
/// Conventional User IDs are UTF-8.  RFC 2822 only covers US-ASCII
/// and allows character set switching using RFC 2047.  For example,
/// an RFC 2822 parser would parse:
///
///    - Bj=?utf-8?q?=C3=B6?=rn Bj=?utf-8?q?=C3=B6?=rnson
///
/// "Björn Björnson".  Nobody uses this in practice, and, as such,
/// this extension is not supported by this parser.
///
/// Comments can include any UTF-8 text except parentheses.  Thus, the
/// following is not a valid comment even though the parentheses are
/// balanced:
///
///   - (foo (bar))
///
/// URIs
/// ----
///
/// The URI parser recognizes URIs using a regular expression similar
/// to the one recommended in [RFC 3986] with the following extensions
/// and restrictions:
///
///   - UTF-8 characters are in the range \u{80}-\u{10ffff} are
///     allowed wherever percent-encoded characters are allowed (i.e.,
///     everywhere but the schema).
///
///   - The scheme component and its trailing ":" are required.
///
///   - The URI must have an authority component ("//domain") or a
///     path component ("/path/to/resource").
///
///   - Although the RFC does not allow it, in practice, the '[' and
///     ']' characters are allowed wherever percent-encoded characters
///     are allowed (i.e., everywhere but the schema).
///
/// URIs are neither normalized nor interpreted.  For instance, dot
/// segments are not removed, escape sequences are not decoded, etc.
///
/// Note: the recommended regular expression is less strict than the
/// grammar.  For instance, a percent encoded character must consist
/// of three characters: the percent character followed by two hex
/// digits.  The parser that we use does not enforce this either.
///
///   [RFC 3986]: https://tools.ietf.org/html/rfc3986
///
/// Formal Grammar
/// --------------
///
/// Formally, the following grammar is used to decompose a User ID:
///
///   WS                 = 0x20 (space character)
///
///   comment-specials   = "<" / ">" /   ; RFC 2822 specials - "(" and ")"
///                        "[" / "]" /
///                        ":" / ";" /
///                        "@" / "\" /
///                        "," / "." /
///                        DQUOTE
///
///   atext-specials     = "(" / ")" /   ; RFC 2822 specials - "<" and ">".
///                        "[" / "]" /
///                        ":" / ";" /
///                        "@" / "\" /
///                        "," / "." /
///                        DQUOTE
///
///   atext              = ALPHA / DIGIT /   ; Any character except controls,
///                        "!" / "#" /       ;  SP, and specials.
///                        "$" / "%" /       ;  Used for atoms
///                        "&" / "'" /
///                        "*" / "+" /
///                        "-" / "/" /
///                        "=" / "?" /
///                        "^" / "_" /
///                        "`" / "{" /
///                        "|" / "}" /
///                        "~" /
///                        \u{80}-\u{10ffff} ; Non-ascii, non-control UTF-8
///
///   dot_atom_text      = 1*atext *("." *atext)
///
///   name-char-start    = atext / atext-specials
///
///   name-char-rest     = atext / atext-specials / WS
///
///   name               = name-char-start *name-char-rest
///
///   comment-char       = atext / comment-specials / WS
///
///   comment-content    = *comment-char
///
///   comment            = "(" *WS comment-content *WS ")"
///
///   addr-spec          = dot-atom-text "@" dot-atom-text
///
///   uri                = See [RFC 3986] and the note on URIs above.
///
///   pgp-uid-convention = addr-spec /
///                        uri /
///                        *WS [name] *WS [comment] *WS "<" addr-spec ">" /
///                        *WS [name] *WS [comment] *WS "<" uri ">" /
///                        *WS name *WS [comment] *WS
#[derive(Clone, Debug)]
pub struct ConventionallyParsedUserID {
    userid: String,

    name: Option<(usize, usize)>,
    comment: Option<(usize, usize)>,
    email: Option<(usize, usize)>,
    uri: Option<(usize, usize)>,
}

impl ConventionallyParsedUserID {
    /// Parses the userid according to the usual conventions.
    pub fn new<S>(userid: S) -> Result<Self>
        where S: Into<String>
    {
        Self::parse(userid.into())
    }

    /// Returns the User ID's name component, if any.
    pub fn name(&self) -> Option<&str> {
        self.name.map(|(s, e)| &self.userid[s..e])
    }

    /// Returns the User ID's comment field, if any.
    pub fn comment(&self) -> Option<&str> {
        self.comment.map(|(s, e)| &self.userid[s..e])
    }

    /// Returns the User ID's email component, if any.
    pub fn email(&self) -> Option<&str> {
        self.email.map(|(s, e)| &self.userid[s..e])
    }

    /// Returns the User ID's URI component, if any.
    ///
    /// Note: the URI is returned as is; dot segments are not removed,
    /// escape sequences are not unescaped, etc.
    pub fn uri(&self) -> Option<&str> {
        self.uri.map(|(s, e)| &self.userid[s..e])
    }

    fn parse(userid: String) -> Result<Self> {
        lazy_static!{
            static ref USER_ID_PARSER: Regex = {
                // Whitespace.
                let ws_bare = " ";
                let ws = format!("[{}]", ws_bare);
                let optional_ws = format!("(?:{}*)", ws);

                // Specials minus ( and ).
                let comment_specials_bare = r#"<>\[\]:;@\\,.""#;
                let _comment_specials
                    = format!("[{}]", comment_specials_bare);

                let atext_specials_bare = r#"()\[\]:;@\\,.""#;
                let _atext_specials =
                    format!("[{}]", atext_specials_bare);

                // "Text"
                let atext_bare
                    = "-A-Za-z0-9!#$%&'*+/=?^_`{|}~\u{80}-\u{10ffff}";
                let atext = format!("[{}]", atext_bare);

                // An atext with dots and the added restriction that
                // it may not start or end with a dot.
                let dot_atom_text
                    = format!(r"(?:{}+(?:\.{}+)*)", atext, atext);


                let name_char_start
                    = format!("[{}{}]",
                              atext_bare, atext_specials_bare);
                let name_char_rest
                    = format!("[{}{}{}]",
                              atext_bare, atext_specials_bare, ws_bare);
                // We need to minimize the match as otherwise we
                // swallow any comment.
                let name
                    = format!("(?:{}{}*?)", name_char_start, name_char_rest);

                let comment_char
                    = format!("[{}{}{}]",
                              atext_bare, comment_specials_bare, ws_bare);

                let comment = |prefix| {
                    format!(r#"(?:\({}(?P<{}_comment>{}*?){}\))"#,
                            optional_ws, prefix, comment_char, optional_ws)
                };

                let addr_spec
                    = format!("(?:{}@{})", dot_atom_text, dot_atom_text);

                let uri = |prefix| {
                    // The regex suggested from the RFC:
                    //
                    // ^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?
                    //   ^schema         ^authority ^path      ^query     ^fragment
                    //
                    // Since only the path component is required, and
                    // the path matches everything but the '?' and '#'
                    // characters, this regular expression will match
                    // almost any string.
                    //
                    // This regular expression is good for picking
                    // apart strings that are known to be URIs.  But,
                    // we want to detect URIs and distinguish them
                    // from things that are almost certainly not URIs,
                    // like email addresses.
                    //
                    // As such, we require the URI to have a
                    // well-formed schema, and the schema must be
                    // followed by a non-empty component.  Further, we
                    // restrict the alphabet to approximately what the
                    // grammar permits.

                    // Looking at the productions for the schema,
                    // authority, path, query, and fragment
                    // components, we can distil the following useful
                    // alphabets (the symbols are drawn from the
                    // following pct-encoded, unreserved, gen-delims,
                    // sub-delims, pchar, and IP-literal productions):
                    let symbols = "-{}0-9._~%!$&'()*+,;=:@\\[\\]";
                    let ascii_alpha = "a-zA-Z";
                    let utf8_alpha = "a-zA-Z\u{80}-\u{10ffff}";

                    // We strictly match the schema production:
                    //
                    // scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
                    let schema
                        = format!("(?:[{}][-+.{}0-9]*:)",
                                  ascii_alpha, ascii_alpha);

                    // The symbols that can occur in a fragment are a
                    // superset of those that can occur in a query and
                    // its delimiters.  Likewise, the symbols that can
                    // occur in a query are a superset of those that
                    // can occur in a path and its delimiters.  The
                    // symbols that can occur in a path are *almost* a
                    // subset of those that can occur in an authority:
                    // '[' and ']' can occur in an authority component
                    // (via the IP-literal production, e.g.,
                    // '[2001:db8::7]'), but not in a path.  But, URI
                    // parsers appear to accept '[' and ']' as part of
                    // a path.  So, we accept them too.
                    //
                    // Given this, a fragment matches all components
                    // and everything that precedes it.  Since we
                    // don't need to distinguish the individual parts
                    // here, matching what follows the schema in a URI
                    // is straightforward:
                    let rest = format!("(?:[{}{}/\\?#]+)",
                                       symbols, utf8_alpha);

                    format!("(?P<{}_uri>{}{})",
                            prefix, schema, rest)
                };

                let raw_addr_spec
                    = format!("(?P<raw_addr_spec>{})", addr_spec);

                let raw_uri = format!("(?:{})", uri("raw"));

                // whitespace is ignored.  It is allowed (but not
                // required) at the start and between components, but
                // it is not allowed after the closing '>'.  space is
                // not allowed.
                let wrapped_addr_spec
                    = format!("{}(?P<wrapped_addr_spec_name>{})?{}\
                               (?:{})?{}\
                               <(?P<wrapped_addr_spec>{})>",
                              optional_ws, name, optional_ws,
                              comment("wrapped_addr_spec"), optional_ws,
                              addr_spec);

                let wrapped_uri
                    = format!("{}(?P<wrapped_uri_name>{})?{}\
                               (?:{})?{}\
                               <(?:{})>",
                              optional_ws, name, optional_ws,
                              comment("wrapped_uri"), optional_ws,
                              uri("wrapped"));

                let bare_name
                    = format!("{}(?P<bare_name>{}){}\
                               (?:{})?{}",
                              optional_ws, name, optional_ws,
                              comment("bare"), optional_ws);

                // Note: bare-name has to come after addr-spec-raw as
                // prefer addr-spec-raw to bare-name when the match is
                // ambiguous.
                let pgp_uid_convention
                    = format!("^(?:{}|{}|{}|{}|{})$",
                              raw_addr_spec, raw_uri,
                              wrapped_addr_spec, wrapped_uri,
                              bare_name);

                Regex::new(&pgp_uid_convention).unwrap()
            };
        }

        // The regex is anchored at the start and at the end so we
        // have either 0 or 1 matches.
        if let Some(cap) = USER_ID_PARSER.captures_iter(&userid).nth(0) {
            let to_range = |m: regex::Match| (m.start(), m.end());

            // We need to figure out which branch matched.  Match on a
            // required capture for each branch.

            if let Some(email) = cap.name("raw_addr_spec") {
                // raw-addr-spec
                let email = Some(to_range(email));

                Ok(ConventionallyParsedUserID {
                    userid: userid,
                    name: None,
                    comment: None,
                    email: email,
                    uri: None,
                })
            } else if let Some(uri) = cap.name("raw_uri") {
                // raw-uri
                let uri = Some(to_range(uri));

                Ok(ConventionallyParsedUserID {
                    userid: userid,
                    name: None,
                    comment: None,
                    email: None,
                    uri: uri,
                })
            } else if let Some(email) = cap.name("wrapped_addr_spec") {
                // wrapped-addr-spec
                let name = cap.name("wrapped_addr_spec_name").map(to_range);
                let comment = cap.name("wrapped_addr_spec_comment").map(to_range);
                let email = Some(to_range(email));

                Ok(ConventionallyParsedUserID {
                    userid: userid,
                    name: name,
                    comment: comment,
                    email: email,
                    uri: None,
                })
            } else if let Some(uri) = cap.name("wrapped_uri") {
                // uri-wrapped
                let name = cap.name("wrapped_uri_name").map(to_range);
                let comment = cap.name("wrapped_uri_comment").map(to_range);
                let uri = Some(to_range(uri));

                Ok(ConventionallyParsedUserID {
                    userid: userid,
                    name: name,
                    comment: comment,
                    email: None,
                    uri: uri,
                })
            } else if let Some(name) = cap.name("bare_name") {
                // name-bare
                let name = to_range(name);
                let comment = cap.name("bare_comment").map(to_range);

                Ok(ConventionallyParsedUserID {
                    userid: userid,
                    name: Some(name),
                    comment: comment,
                    email: None,
                    uri: None,
                })
            } else {
                panic!("Unexpected result");
            }
        } else {
            return Err(Error::InvalidArgument(
                "Failed to parse UserID".into()).into());
        }
    }
}

/// Holds a UserID packet.
///
/// See [Section 5.11 of RFC 4880] for details.
///
///   [Section 5.11 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
pub struct UserID {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,
    /// The user id.
    ///
    /// According to [RFC 4880], the text is by convention UTF-8 encoded
    /// and in "mail name-addr" form, i.e., "Name (Comment)
    /// <email@example.com>".
    ///
    ///   [RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.11
    ///
    /// Use `UserID::default()` to get a UserID with a default settings.
    value: Vec<u8>,

    parsed: Mutex<RefCell<Option<ConventionallyParsedUserID>>>,
}

impl From<Vec<u8>> for UserID {
    fn from(u: Vec<u8>) -> Self {
        UserID {
            common: Default::default(),
            value: u,
            parsed: Mutex::new(RefCell::new(None)),
        }
    }
}

impl From<&[u8]> for UserID {
    fn from(u: &[u8]) -> Self {
        u.to_vec().into()
    }
}

impl<'a> From<&'a str> for UserID {
    fn from(u: &'a str) -> Self {
        let b = u.as_bytes();
        let mut v = Vec::with_capacity(b.len());
        v.extend_from_slice(b);
        v.into()
    }
}

impl From<String> for UserID {
    fn from(u: String) -> Self {
        let u = &u[..];
        u.into()
    }
}

impl<'a> From<::std::borrow::Cow<'a, str>> for UserID {
    fn from(u: ::std::borrow::Cow<'a, str>) -> Self {
        let b = u.as_bytes();
        let mut v = Vec::with_capacity(b.len());
        v.extend_from_slice(b);
        v.into()
    }
}

impl fmt::Display for UserID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let userid = String::from_utf8_lossy(&self.value[..]);
        write!(f, "{}", userid)
    }
}

impl fmt::Debug for UserID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let userid = String::from_utf8_lossy(&self.value[..]);

        f.debug_struct("UserID")
            .field("value", &userid)
            .finish()
    }
}

impl PartialEq for UserID {
    fn eq(&self, other: &UserID) -> bool {
        self.value == other.value
    }
}

impl Eq for UserID {
}

impl PartialOrd for UserID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UserID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl Hash for UserID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We hash only the data; the cache does not implement hash.
        self.value.hash(state);
    }
}

impl Clone for UserID {
    fn clone(&self) -> Self {
        self.value.clone().into()
    }
}

impl UserID {
    fn assemble<S>(name: Option<S>, comment: Option<S>,
                   address: S, check_address: bool)
        -> Result<Self>
        where S: AsRef<str>,
    {
        let mut value = String::with_capacity(64);

        // Make sure the individual components are valid.
        if let Some(ref name) = name {
            let name = name.as_ref();
            match ConventionallyParsedUserID::new(name.to_string()) {
                Err(err) =>
                    return Err(err.context(format!(
                        "Validating name ({:?})",
                        name)).into()),
                Ok(p) => {
                    if !(p.name().is_some()
                         && p.comment().is_none()
                         && p.email().is_none()) {
                        return Err(Error::InvalidArgument(
                            format!("Invalid name ({:?})", name)
                                .into()).into());
                    }
                }
            }

            value.push_str(name);
        }

        if let Some(ref comment) = comment {
            let comment = comment.as_ref();
            match ConventionallyParsedUserID::new(
                format!("x ({})", comment))
            {
                Err(err) =>
                    return Err(err.context(format!(
                        "Validating comment ({:?})",
                        comment)).into()),
                Ok(p) => {
                    if !(p.name().is_none()
                         && p.comment().is_some()
                         && p.email().is_none()) {
                    return Err(Error::InvalidArgument(
                        format!("Invalid comment ({:?})", comment)
                            .into()).into());
                    }
                }
            }

            if value.len() > 0 {
                value.push_str(" ");
            }
            value.push_str("(");
            value.push_str(comment);
            value.push_str(")");
        }

        if check_address {
            let address = address.as_ref();
            match ConventionallyParsedUserID::new(
                format!("<{}>", address))
            {
                Err(err) =>
                    return Err(err.context(format!(
                        "Validating address ({:?})",
                        address)).into()),
                Ok(p) => {
                    if !(p.name().is_none()
                         && p.comment().is_none()
                         && p.email().is_some()) {
                        return Err(Error::InvalidArgument(
                            format!("Invalid address address ({:?})", address)
                                .into()).into());
                    }
                }
            }
        }

        let something = value.len() > 0;
        if something {
            value.push_str(" <");
        }
        value.push_str(address.as_ref());
        if something {
            value.push_str(">");
        }

        if check_address {
            // Make sure the combined thing is valid.
            match ConventionallyParsedUserID::new(value.clone())
            {
                Err(err) =>
                    return Err(err.context(format!(
                        "Validating User ID ({:?})",
                        value)).into()),
                Ok(p) => {
                    if !(p.name().is_none() == name.is_none()
                         && p.comment().is_none() == comment.is_none()
                         && p.email().is_some()) {
                        return Err(Error::InvalidArgument(
                            format!("Invalid User ID ({:?})", value)
                                .into()).into());
                    }
                }
            }
        }

        Ok(UserID::from(value))
    }

    /// Constructs a User ID.
    ///
    /// This does a basic check and any necessary escaping to form a de
    /// facto User ID.
    ///
    /// Only the address is required.  If a comment is supplied, then
    /// a name is also required.
    ///
    /// If you already have a User ID value, then you can just
    /// use `UserID::from()`.
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::packet::UserID;
    /// assert_eq!(UserID::from_address(
    ///                "John Smith".into(),
    ///                None, "boat@example.org").unwrap().value(),
    ///            &b"John Smith <boat@example.org>"[..]);
    /// ```
    pub fn from_address<O, S>(name: O, comment: O, email: S)
        -> Result<Self>
        where S: AsRef<str>,
              O: Into<Option<S>>
    {
        Self::assemble(name.into(), comment.into(), email, true)
    }

    /// Constructs a User ID.
    ///
    /// This does a basic check and any necessary escaping to form a de
    /// facto User ID modulo the address, which is not checked.
    ///
    /// This is useful when you want to specify a URI instead of an
    /// email address.
    ///
    /// If you already have a User ID value, then you can just
    /// use `UserID::from()`.
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::packet::UserID;
    /// assert_eq!(UserID::from_unchecked_address(
    ///                "NAS".into(),
    ///                None, "ssh://host.example.org").unwrap().value(),
    ///            &b"NAS <ssh://host.example.org>"[..]);
    /// ```
    pub fn from_unchecked_address<O, S>(name: O, comment: O, address: S)
        -> Result<Self>
        where S: AsRef<str>,
              O: Into<Option<S>>
    {
        Self::assemble(name.into(), comment.into(), address, false)
    }

    /// Gets the user ID packet's value.
    pub fn value(&self) -> &[u8] {
        self.value.as_slice()
    }

    fn do_parse(&self) -> Result<()> {
        if self.parsed.lock().unwrap().borrow().is_none() {
            let s = str::from_utf8(&self.value)?;

            *self.parsed.lock().unwrap().borrow_mut() =
              Some(match ConventionallyParsedUserID::new(s) {
                Ok(puid) => puid,
                Err(err) => {
                    // Return the error from the NameAddrOrOther parser.
                    let err : anyhow::Error = err.into();
                    return Err(err).context(format!(
                        "Failed to parse User ID: {:?}", s))?;
                }
            });
        }
        Ok(())
    }

    /// Parses the User ID according to de facto conventions, and
    /// returns the name component, if any.
    pub fn name(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.lock().unwrap().borrow() {
            Some(ref puid) => Ok(puid.name().map(|s| s.to_string())),
            None => unreachable!(),
        }
    }

    /// Parses the User ID according to de facto conventions, and
    /// returns the comment field, if any.
    pub fn comment(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.lock().unwrap().borrow() {
            Some(ref puid) => Ok(puid.comment().map(|s| s.to_string())),
            None => unreachable!(),
        }
    }

    /// Parses the User ID according to de facto conventions, and
    /// returns the email address, if any.
    pub fn email(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.lock().unwrap().borrow() {
            Some(ref puid) => Ok(puid.email().map(|s| s.to_string())),
            None => unreachable!(),
        }
    }

    /// Parses the User ID according to de facto conventions, and
    /// returns the URI, if any.
    pub fn uri(&self) -> Result<Option<String>> {
        self.do_parse()?;
        match *self.parsed.lock().unwrap().borrow() {
            Some(ref puid) => Ok(puid.uri().map(|s| s.to_string())),
            None => unreachable!(),
        }
    }

    /// Returns a normalized version of the UserID's email address.
    ///
    /// Normalized email addresses are primarily needed when email
    /// addresses are compared.
    ///
    /// Note: normalized email addresses are still valid email
    /// addresses.
    ///
    /// This function normalizes an email address by doing [puny-code
    /// normalization] on the domain, and lowercasing the local part in
    /// the so-called [empty locale].
    ///
    /// Note: this normalization procedure is the same as the
    /// normalization procedure recommended by [Autocrypt].
    ///
    ///   [puny-code normalization]: https://tools.ietf.org/html/rfc5891.html#section-4.4
    ///   [empty locale]: https://www.w3.org/International/wiki/Case_folding
    ///   [Autocrypt]: https://autocrypt.org/level1.html#e-mail-address-canonicalization
    pub fn email_normalized(&self) -> Result<Option<String>> {
        match self.email() {
            e @ Err(_) => e,
            Ok(None) => Ok(None),
            Ok(Some(address)) => {
                let mut iter = address.split('@');
                let localpart = iter.next().expect("Invalid email address");
                let domain = iter.next().expect("Invalid email address");
                assert!(iter.next().is_none(), "Invalid email address");

                // Normalize Unicode in domains.
                let domain = idna::domain_to_ascii(domain)
                    .map_err(|e| anyhow::anyhow!(
                        "punycode conversion failed: {:?}", e))?;

                // Join.
                let address = format!("{}@{}", localpart, domain);

                // Convert to lowercase without tailoring, i.e. without taking
                // any locale into account.  See:
                //
                //  - https://www.w3.org/International/wiki/Case_folding
                //  - https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
                //  - http://www.unicode.org/versions/Unicode7.0.0/ch03.pdf#G33992
                let address = address.to_lowercase();

                Ok(Some(address))
            }
        }
    }
}

impl From<UserID> for Packet {
    fn from(s: UserID) -> Self {
        Packet::UserID(s)
    }
}

impl Arbitrary for UserID {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        Vec::<u8>::arbitrary(g).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Parse;
    use crate::serialize::MarshalInto;

    quickcheck! {
        fn roundtrip(p: UserID) -> bool {
            let q = UserID::from_bytes(&p.to_vec().unwrap()).unwrap();
            assert_eq!(p, q);
            true
        }
    }

    #[test]
    fn decompose() {
        tracer!(true, "decompose", 0);

        fn c(userid: &str,
             name: Option<&str>, comment: Option<&str>,
             email: Option<&str>, uri: Option<&str>)
            -> bool
        {
            match ConventionallyParsedUserID::new(userid) {
                Ok(puid) => {
                    let good = puid.name() == name
                        && puid.comment() == comment
                        && puid.email() == email
                        && puid.uri() == uri;

                    if ! good {
                        t!("userid: {}", userid);
                        t!(" -> {:?}", puid);
                        t!("  {:?} {}= {:?}",
                           puid.name(),
                           if puid.name() == name { "=" } else { "!" },
                           name);
                        t!("  {:?} {}= {:?}",
                           puid.comment(),
                           if puid.comment() == comment { "=" } else { "!" },
                           comment);
                        t!("  {:?} {}= {:?}",
                           puid.email(),
                           if puid.email() == email { "=" } else { "!" },
                           email);
                        t!("  {:?} {}= {:?}",
                           puid.uri(),
                           if puid.uri() == uri { "=" } else { "!" },
                           uri);

                        t!(" -> BAD PARSE");
                    }
                    good
                }
                Err(err) => {
                    t!("userid: {} -> PARSE ERROR: {:?}", userid, err);
                    false
                }
            }
        }

        let mut g = true;

        // Conventional User IDs:
        g &= c("First Last (Comment) <name@example.org>",
          Some("First Last"), Some("Comment"), Some("name@example.org"), None);
        g &= c("First Last <name@example.org>",
          Some("First Last"), None, Some("name@example.org"), None);
        g &= c("First Last", Some("First Last"), None, None, None);
        g &= c("name@example.org <name@example.org>",
          Some("name@example.org"), None, Some("name@example.org"), None);
        g &= c("<name@example.org>",
          None, None, Some("name@example.org"), None);
        g &= c("name@example.org",
          None, None, Some("name@example.org"), None);

        // Examples from dkg's mail:
        g &= c("Björn Björnson <bjoern@example.net>",
          Some("Björn Björnson"), None, Some("bjoern@example.net"), None);
        // We explicitly don't support RFC 2047 so the following is
        // correctly not escaped.
        g &= c("Bj=?utf-8?q?=C3=B6?=rn Bj=?utf-8?q?=C3=B6?=rnson \
           <bjoern@example.net>",
          Some("Bj=?utf-8?q?=C3=B6?=rn Bj=?utf-8?q?=C3=B6?=rnson"),
          None, Some("bjoern@example.net"), None);
        g &= c("Acme Industries, Inc. <info@acme.example>",
          Some("Acme Industries, Inc."), None, Some("info@acme.example"), None);
        g &= c("Michael O'Brian <obrian@example.biz>",
          Some("Michael O'Brian"), None, Some("obrian@example.biz"), None);
        g &= c("Smith, John <jsmith@example.com>",
          Some("Smith, John"), None, Some("jsmith@example.com"), None);
        g &= c("mariag@example.org",
          None, None, Some("mariag@example.org"), None);
        g &= c("joe@example.net <joe@example.net>",
          Some("joe@example.net"), None, Some("joe@example.net"), None);
        g &= c("иван.сергеев@пример.рф",
          None, None, Some("иван.сергеев@пример.рф"), None);
        g &= c("Dörte@Sörensen.example.com",
          None, None, Some("Dörte@Sörensen.example.com"), None);

        // Some craziness.

        g &= c("Vorname Nachname, Dr.",
               Some("Vorname Nachname, Dr."), None, None, None);
        g &= c("Vorname Nachname, Dr. <dr@example.org>",
               Some("Vorname Nachname, Dr."), None, Some("dr@example.org"), None);

        // Only the last comment counts as a comment.  The rest if
        // part of the name.
        g &= c("Foo (Bar) (Baz)",
          Some("Foo (Bar)"), Some("Baz"), None, None);
        // The same with extra whitespace.
        g &= c("Foo  (Bar)  (Baz)",
          Some("Foo  (Bar)"), Some("Baz"), None, None);
        g &= c("Foo  (Bar  (Baz)",
          Some("Foo  (Bar"), Some("Baz"), None, None);

        // Make sure whitespace is stripped.
        g &= c("  Name   Last   (   some  comment )   <name@example.org>",
               Some("Name   Last"), Some("some  comment"),
               Some("name@example.org"), None);

        // Make sure an email is a comment is recognized as a comment.
        g &= c(" Name Last (email@example.org)",
               Some("Name Last"), Some("email@example.org"), None, None);

        // Quoting in the local part of the email address is not
        // allowed, but it is recognized as a name.  That's fine.
        g &= c("\"user\"@example.org",
               Some("\"user\"@example.org"), None, None, None);
        // Even unbalanced quotes.
        g &= c("\"user@example.org",
               Some("\"user@example.org"), None, None, None);

        g &= c("Henry Ford (CEO) <henry@ford.com>",
               Some("Henry Ford"), Some("CEO"), Some("henry@ford.com"), None);

        g &= c("Thomas \"Tomakin\" (DHC) <thomas@clh.co.uk>",
               Some("Thomas \"Tomakin\""), Some("DHC"),
               Some("thomas@clh.co.uk"), None);

        g &= c("Aldous L. Huxley <huxley@old-world.org>",
               Some("Aldous L. Huxley"), None,
               Some("huxley@old-world.org"), None);


        // Some URIs.

        // Examples from https://tools.ietf.org/html/rfc3986#section-1.1.2
        g &= c("<ftp://ftp.is.co.za/rfc/rfc1808.txt>",
               None, None,
               None, Some("ftp://ftp.is.co.za/rfc/rfc1808.txt"));

        g &= c("<http://www.ietf.org/rfc/rfc2396.txt>",
               None, None,
               None, Some("http://www.ietf.org/rfc/rfc2396.txt"));

        g &= c("<ldap://[2001:db8::7]/c=GB?objectClass?one>",
               None, None,
               None, Some("ldap://[2001:db8::7]/c=GB?objectClass?one"));

        g &= c("<mailto:John.Doe@example.com>",
               None, None,
               None, Some("mailto:John.Doe@example.com"));

        g &= c("<news:comp.infosystems.www.servers.unix>",
               None, None,
               None, Some("news:comp.infosystems.www.servers.unix"));

        g &= c("<tel:+1-816-555-1212>",
               None, None,
               None, Some("tel:+1-816-555-1212"));

        g &= c("<telnet://192.0.2.16:80/>",
               None, None,
               None, Some("telnet://192.0.2.16:80/"));

        g &= c("<urn:oasis:names:specification:docbook:dtd:xml:4.1.2>",
               None, None,
               None, Some("urn:oasis:names:specification:docbook:dtd:xml:4.1.2"));



        g &= c("Foo's ssh server <ssh://hostname>",
               Some("Foo's ssh server"), None,
               None, Some("ssh://hostname"));

        g &= c("Foo (ssh server) <ssh://hostname>",
               Some("Foo"), Some("ssh server"),
               None, Some("ssh://hostname"));

        g &= c("<ssh://hostname>",
               None, None,
               None, Some("ssh://hostname"));

        g &= c("Warez <ftp://127.0.0.1>",
               Some("Warez"), None,
               None, Some("ftp://127.0.0.1"));

        g &= c("ssh://hostname",
               None, None,
               None, Some("ssh://hostname"));

        g &= c("ssh:hostname",
               None, None,
               None, Some("ssh:hostname"));

        g &= c("Frank Füber <ssh://ïntérnätïònál.eu>",
               Some("Frank Füber"), None,
               None, Some("ssh://ïntérnätïònál.eu"));

        g &= c("ssh://ïntérnätïònál.eu",
               None, None,
               None, Some("ssh://ïntérnätïònál.eu"));

        g &= c("<foo://domain.org>",
               None, None,
               None, Some("foo://domain.org"));

        g &= c("<foo-bar://domain.org>",
               None, None,
               None, Some("foo-bar://domain.org"));

        g &= c("<foo+bar://domain.org>",
               None, None,
               None, Some("foo+bar://domain.org"));

        g &= c("<foo.bar://domain.org>",
               None, None,
               None, Some("foo.bar://domain.org"));

        g &= c("<foo.bar://domain.org#anchor?query>",
               None, None,
               None, Some("foo.bar://domain.org#anchor?query"));

        // Is it an email address or a URI?  It should show up as a URI.
        g &= c("<foo://user:password@domain.org>",
               None, None,
               None, Some("foo://user:password@domain.org"));

        // Ports...
        g &= c("<foo://domain.org:348>",
               None, None,
               None, Some("foo://domain.org:348"));

        g &= c("<foo://domain.org:348/>",
               None, None,
               None, Some("foo://domain.org:348/"));

        // Some test vectors from
        // https://github.com/cweb/iri-tests/blob/master/iris.txt
        g &= c("<http://[:]>", None, None, None, Some("http://[:]"));
        g &= c("<http://2001:db8::1>", None, None, None, Some("http://2001:db8::1"));
        g &= c("<http://[www.google.com]/>", None, None, None, Some("http://[www.google.com]/"));
        g &= c("<http:////////user:@google.com:99?foo>", None, None, None, Some("http:////////user:@google.com:99?foo"));
        g &= c("<http:path>", None, None, None, Some("http:path"));
        g &= c("<http:/path>", None, None, None, Some("http:/path"));
        g &= c("<http:host>", None, None, None, Some("http:host"));
        g &= c("<http://user:pass@foo:21/bar;par?b#c>", None, None, None,
               Some("http://user:pass@foo:21/bar;par?b#c"));
        g &= c("<http:foo.com>", None, None, None, Some("http:foo.com"));
        g &= c("<http://f:/c>", None, None, None, Some("http://f:/c"));
        g &= c("<http://f:0/c>", None, None, None, Some("http://f:0/c"));
        g &= c("<http://f:00000000000000/c>", None, None, None, Some("http://f:00000000000000/c"));
        g &= c("<http://f:&#x000A;/c>", None, None, None, Some("http://f:&#x000A;/c"));
        g &= c("<http://f:fifty-two/c>", None, None, None, Some("http://f:fifty-two/c"));
        g &= c("<foo://>", None, None, None, Some("foo://"));
        g &= c("<http://a:b@c:29/d>", None, None, None, Some("http://a:b@c:29/d"));
        g &= c("<http::@c:29>", None, None, None, Some("http::@c:29"));
        g &= c("<http://&amp;a:foo(b]c@d:2/>", None, None, None, Some("http://&amp;a:foo(b]c@d:2/"));
        g &= c("<http://iris.test.ing/re&#x301;sume&#x301;/re&#x301;sume&#x301;.html>", None, None, None, Some("http://iris.test.ing/re&#x301;sume&#x301;/re&#x301;sume&#x301;.html"));
        g &= c("<http://google.com/foo[bar]>", None, None, None, Some("http://google.com/foo[bar]"));

        if !g {
            panic!("Parse error");
        }
    }

    // Make sure we can't parse non conventional User IDs.
    #[test]
    fn decompose_non_conventional() {
        // Empty string is not allowed.
        assert!(ConventionallyParsedUserID::new("").is_err());
        // Likewise, only whitespace.
        assert!(ConventionallyParsedUserID::new(" ").is_err());
        assert!(ConventionallyParsedUserID::new("   ").is_err());

        // Double dots are not allowed.
        assert!(ConventionallyParsedUserID::new(
            "<a..b@example.org>").is_err());
        // Nor are dots at the start or end of the local part.
        assert!(ConventionallyParsedUserID::new(
            "<dr.@example.org>").is_err());
        assert!(ConventionallyParsedUserID::new(
            "<.drb@example.org>").is_err());

        assert!(ConventionallyParsedUserID::new(
            "<hallo> <hello@example.org>").is_err());
        assert!(ConventionallyParsedUserID::new(
            "<hallo <hello@example.org>").is_err());
        assert!(ConventionallyParsedUserID::new(
            "hallo> <hello@example.org>").is_err());

        // No @.
        assert!(ConventionallyParsedUserID::new(
            "foo <example.org>").is_err());
        // Two @s.
        assert!(ConventionallyParsedUserID::new(
            "Huxley <huxley@@old-world.org>").is_err());

        // Unfortunately, the following is accepted as a name:
        //
        // assert!(ConventionallyParsedUserID::new(
        //     "huxley@@old-world.org").is_err());

        // No local part.
        assert!(ConventionallyParsedUserID::new(
            "foo <@example.org>").is_err());

        // No leading/ending dot in the email address.
        assert!(ConventionallyParsedUserID::new(
            "<huxley@.old-world.org>").is_err());
        assert!(ConventionallyParsedUserID::new(
            "<huxley@old-world.org.>").is_err());

        // Unfortunately, the following are recognized as names:
        //
        // assert!(ConventionallyParsedUserID::new(
        //     "huxley@.old-world.org").is_err());
        // assert!(ConventionallyParsedUserID::new(
        //     "huxley@old-world.org.").is_err());

        // Need something in the local part.
        assert!(ConventionallyParsedUserID::new(
            "<@old-world.org>").is_err());

        // Unfortunately, the following is recognized as a name:
        //
        // assert!(ConventionallyParsedUserID::new(
        //     "@old-world.org").is_err());


        // URI schemas must be ASCII.
        assert!(ConventionallyParsedUserID::new(
            "<über://domain.org>").is_err());

        // Whitespace is not allowed.
        assert!(ConventionallyParsedUserID::new(
            "<http://some domain.org>").is_err());
    }

    #[test]
    fn email_normalized() {
        fn c(value: &str, expected: &str) {
            let u = UserID::from(value);
            let got = u.email_normalized().unwrap().unwrap();
            assert_eq!(expected, got);
        }

        c("Henry Ford (CEO) <henry@ford.com>", "henry@ford.com");
        c("Henry Ford (CEO) <Henry@Ford.com>", "henry@ford.com");
        c("Henry Ford (CEO) <Henry@Ford.com>", "henry@ford.com");
        c("hans@bücher.tld", "hans@xn--bcher-kva.tld");
        c("hANS@bücher.tld", "hans@xn--bcher-kva.tld");
    }

    #[test]
    fn from_address() {
        assert_eq!(UserID::from_address(None, None, "foo@bar.com")
                       .unwrap().value(),
                   b"foo@bar.com");
        assert!(UserID::from_address(None, None, "foo@@bar.com").is_err());
        assert_eq!(UserID::from_address("Foo Q. Bar".into(), None, "foo@bar.com")
                      .unwrap().value(),
                   b"Foo Q. Bar <foo@bar.com>");
    }
}
