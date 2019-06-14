//! OpenPGP Web Key Directory client.
//!
//! A Web Key Directory is a Web service that can be queried with email
//! addresses to obtain the associated OpenPGP keys.
//!
//! It is specified in [draft-koch].
//!
//! See the [get example].
//!
//! [draft-koch]: https://datatracker.ietf.org/doc/html/draft-koch-openpgp-webkey-service/#section-3.1
//! [get example]: get#example
//!


// XXX: We might want to merge the 2 structs in the future and move the
// functions to methods.
extern crate tempfile;
extern crate tokio_core;

use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use hyper::Uri;
// Hash implements the traits for Sha1
// Sha1 is used to obtain a 20 bytes digest that after zbase32 encoding can
// be used as file name
use nettle::{
    Hash, hash::insecure_do_not_use::Sha1,
};
use tokio_core::reactor::Core;
use url;

use openpgp::TPK;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use openpgp::tpk::TPKParser;

use super::{Result, Error, async};


/// Stores the local_part and domain of an email address.
pub struct EmailAddress {
    local_part: String,
    domain: String,
}


impl EmailAddress {
    /// Returns an EmailAddress from an email address string.
    ///
    /// From [draft-koch]:
    ///
    ///```text
    /// To help with the common pattern of using capitalized names
    /// (e.g. "Joe.Doe@example.org") for mail addresses, and under the
    /// premise that almost all MTAs treat the local-part case-insensitive
    /// and that the domain-part is required to be compared
    /// case-insensitive anyway, all upper-case ASCII characters in a User
    /// ID are mapped to lowercase.  Non-ASCII characters are not changed.
    ///```
    fn from<S: AsRef<str>>(email_address: S) -> Result<Self> {
        // Ensure that is a valid email address by parsing it and return the
        // errors that it returns.
        // This is also done in hagrid.
        let email_address = email_address.as_ref();
        let v: Vec<&str> = email_address.split('@').collect();
        if v.len() != 2 {
            return Err(Error::MalformedEmail(email_address.into()).into())
        };

        // Convert to lowercase without tailoring, i.e. without taking any
        // locale into account. See:
        // https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
        let email = EmailAddress {
            local_part: v[0].to_lowercase(),
            domain: v[1].to_lowercase()
        };
        Ok(email)
    }
}


/// Stores the parts needed to create a Web Key Directory URL.
///
/// NOTE: This is a different `Url` than [`url::Url`] (`url` crate) that is
/// actually returned with the method [to_url](#method.to_url)
#[derive(Debug, Clone)]
pub struct Url {
    domain: String,
    local_encoded: String,
    local_part: String,
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.build(None))
    }
}

impl Url {
    /// Returns a [`Url`] from an email address string.
    pub fn from<S: AsRef<str>>(email_address: S) -> Result<Self> {
        let email = EmailAddress::from(email_address)?;
        let local_encoded = encode_local_part(&email.local_part);
        let url = Url {
            domain : email.domain,
            local_encoded : local_encoded,
            local_part : email.local_part,
        };
        Ok(url)
    }

    /// Returns an URL string from a [`Url`].
    pub fn build<T>(&self, direct_method: T) -> String
            where T: Into<Option<bool>> {
        let direct_method = direct_method.into().unwrap_or(false);
        if direct_method {
            format!("https://{}/.well-known/openpgpkey/hu/{}?l={}:443",
                    self.domain, self.local_encoded, self.local_part)
        } else {
            format!("https://openpgpkey.{}/.well-known/openpgpkey/{}/hu/{}\
                    ?l={}:443", self.domain, self.domain, self.local_encoded,
                    self.local_part)
        }
    }

    /// Returns an [`url::Url`].
    pub fn to_url<T>(&self, direct_method: T) -> Result<url::Url>
            where T: Into<Option<bool>> {
        let url_string = self.build(direct_method);
        let url_url = url::Url::parse(url_string.as_str())?;
        Ok(url_url)
    }

    /// Returns an [`hyper::Uri`].
    pub fn to_uri<T>(&self, direct_method: T) -> Result<Uri>
            where T: Into<Option<bool>> {
        let url_string = self.build(direct_method);
        let uri = url_string.as_str().parse::<Uri>()?;
        Ok(uri)
    }

    /// Returns a [`PathBuf`].
    pub fn to_file_path<T>(&self, direct_method: T) -> Result<PathBuf>
        where T: Into<Option<bool>>
    {
        // Create the directories string.
        let direct_method = direct_method.into().unwrap_or(false);
        let url = self.to_url(direct_method)?;
        // Can not create path_buf as:
        // let path_buf: PathBuf = [url.domain().unwrap(), url.path()]
        //    .iter().collect();
        // or:
        // let mut path_buf = PathBuf::new();
        // path_buf.push(url.domain().unwrap());
        // path_buf.push(url.path());
        // Because the domain part will disapear, dunno why.
        // url.to_file_path() would not create the directory with the domain,
        // but expect the hostname to match the domain.
        // Ignore the query part of the url, take only the domain and path.
        let string = format!("{}{}", url.domain().unwrap(), url.path());
        let path_buf = PathBuf::from(string);
        Ok(path_buf)
    }
}


/// Returns a 32 characters string from the local part of an email address
///
/// [draft-koch]:
///     The so mapped local-part is hashed using the SHA-1 algorithm. The
///     resulting 160 bit digest is encoded using the Z-Base-32 method as
///     described in [RFC6189], section 5.1.6. The resulting string has a
///     fixed length of 32 octets.
fn encode_local_part<S: AsRef<str>>(local_part: S) -> String {
    let mut hasher = Sha1::default();
    hasher.update(local_part.as_ref().as_bytes());
    // Declare and assign a 20 bytes length vector to use in hasher.result
    let mut local_hash = vec![0; 20];
    hasher.digest(&mut local_hash);
    // After z-base-32 encoding 20 bytes, it will be 32 bytes long.
    zbase32::encode_full_bytes(&local_hash[..])
}


/// Parse an HTTP response body that may contain TPKs and filter them based on
/// whether they contain a userid with the given email address.
///
/// From [draft-koch]:
///
/// ```text
/// The key needs to carry a User ID packet ([RFC4880]) with that mail
/// address.
/// ```
pub(crate) fn parse_body<S: AsRef<str>>(body: &[u8], email_address: S)
        -> Result<Vec<TPK>> {
    let email_address = email_address.as_ref();
    // This will fail on the first packet that can not be parsed.
    let packets = TPKParser::from_bytes(&body)?;
    // Collect only the correct packets.
    let tpks: Vec<TPK> = packets.flatten().collect();
    // Collect only the TPKs that contain the email in any of their userids
    let valid_tpks: Vec<TPK> = tpks.iter()
        // XXX: This filter could become a TPK method, but it adds other API
        // method to maintain
        .filter(|tpk| {tpk.userids()
            .any(|uidb|
                if let Ok(Some(a)) = uidb.userid().address() {
                    a == email_address
                } else { false })
        }).cloned().collect();
    if valid_tpks.is_empty() {
        Err(Error::EmailNotInUserids(email_address.into()).into())
    } else {
        Ok(valid_tpks)
    }
}


/// Retrieves the TPKs that contain userids with a given email address
/// from a Web Key Directory URL.
///
/// This function calls the [async::wkd::get](../async/wkd/fn.get.html)
/// function.
///
/// # Example
///
/// ```
/// extern crate sequoia_net;
/// use sequoia_net::wkd;
///
/// let email_address = "foo@bar.baz";
/// let tpks = wkd::get(&email_address);
/// ```
// This function must have the same signature as async::wkd::get.
// XXX: Maybe implement WkdServer and AWkdClient.
pub fn get<S: AsRef<str>>(email_address: S) -> Result<Vec<TPK>> {
    let mut core = Core::new()?;
    core.run(async::wkd::get(&email_address))
}

/// Generates a Web Key Directory for the given domain and keys.
///
/// The owner of the directory and files will be the user that runs this
/// command.
/// This command only works on Unix-like systems.
pub fn generate<S, T, P>(domain: S, buffer: &[u8], base_path: P,
                      direct_method: T)
    -> Result<()>
    where S: AsRef<str>,
          T: Into<Option<bool>>,
          P: AsRef<Path>
{
    let domain = domain.as_ref();
    let base_path = base_path.as_ref();
    println!("Generating WKD for domain {}.", domain);

    // Create the directories first, instead of creating it for every file.
    // Since the email local part would be the file name which is not created
    // now, it does not matter here.
    let file_path = Url::from(&format!("whatever@{}", domain))?
        .to_file_path(direct_method)?;
    // The parent will be the directory without the file name.
    // This can not fail, otherwise file_path would have fail.
    let dir_path = base_path.join(
        Path::new(&file_path).parent().unwrap());
    // With fs::create_dir_all the permissions can't be set.
    fs::DirBuilder::new()
        .mode(0o744)
        .recursive(true)
        .create(&dir_path)?;

    // Create the files.
    // This is very similar to parse_body, but here the userids must contain
    // a domain, not be equal to an email address.
    let parser = TPKParser::from_bytes(&buffer)?;
    let tpks: Vec<TPK> = parser.flatten().collect();
    for tpk in tpks {
        let mut tpk_bytes: Vec<u8> = Vec::new();
        for uidb in tpk.userids() {
            if let Some(address) = uidb.userid().address()? {
                let wkd_url = Url::from(&address)?;
                if wkd_url.domain == domain {
                    // Since dir_path contains all the hierarchy, only the file
                    // name is needed.
                    let file_path = dir_path.join(wkd_url.local_encoded);
                    let mut file = fs::File::create(&file_path)?;
                    // Set Read/write for owner and read for others.
                    file.metadata()?.permissions().set_mode(0o644);
                    tpk.serialize(&mut tpk_bytes)?;
                    file.write_all(&tpk_bytes)?;
                    println!("Key {} published for {} in {}",
                             tpk.fingerprint().to_string(), address,
                             file_path.as_path().to_str().unwrap());
                }
            }
        }
    }
    Ok(())
}


#[cfg(test)]
mod tests {
    use openpgp::serialize::Serialize;
    use openpgp::tpk::TPKBuilder;

    use super::*;

    #[test]
    fn encode_local_part_succed() {
        let encoded_part = encode_local_part("test1");
        assert_eq!("stnkabub89rpcphiz4ppbxixkwyt1pic", encoded_part);
        assert_eq!(32, encoded_part.len());
    }


    #[test]
    fn email_address_from() {
        let email_address = EmailAddress::from("test1@example.com").unwrap();
        assert_eq!(email_address.domain, "example.com");
        assert_eq!(email_address.local_part, "test1");
        assert!(EmailAddress::from("thisisnotanemailaddress").is_err());
    }

    #[test]
    fn url_roundtrip() {
        // Advanced method
        let expected_url =
            "https://openpgpkey.example.com/\
             .well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1:443";
        let wkd_url = Url::from("test1@example.com").unwrap();
        assert_eq!(expected_url, wkd_url.clone().to_string());
        assert_eq!(url::Url::parse(expected_url).unwrap(),
                   wkd_url.clone().to_url(None).unwrap());
        assert_eq!(expected_url.parse::<Uri>().unwrap(),
                   wkd_url.clone().to_uri(None).unwrap());

        // Direct method
        let expected_url =
            "https://example.com/\
             .well-known/openpgpkey/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic?l=test1:443";
        assert_eq!(expected_url, wkd_url.clone().build(true));
        assert_eq!(url::Url::parse(expected_url).unwrap(),
                   wkd_url.clone().to_url(true).unwrap());
        assert_eq!(expected_url.parse::<Uri>().unwrap(),
                   wkd_url.to_uri(true).unwrap());
    }

    #[test]
    fn url_to_file_path() {
        // Advanced method
        let expected_path =
            "openpgpkey.example.com/\
             .well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic";
        let wkd_url = Url::from("test1@example.com").unwrap();
        assert_eq!(expected_path,
            wkd_url.clone().to_file_path(None).unwrap().to_str().unwrap());

        // Direct method
        let expected_path =
            "example.com/\
             .well-known/openpgpkey/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic";
        assert_eq!(expected_path,
            wkd_url.to_file_path(true).unwrap().to_str().unwrap());
    }

    #[test]
    fn test_parse_body() {
        let (tpk, _) = TPKBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();
        let mut buffer: Vec<u8> = Vec::new();
        tpk.serialize(&mut buffer).unwrap();
        // FIXME!!!!
        let valid_tpks = parse_body(&buffer, "juga@sequoia-pgp.org");
        // The userid is not in the TPK
        assert!(valid_tpks.is_err());
        // XXX: add userid to the tpk, instead of creating a new one
        // tpk.add_userid("juga@sequoia.org");
        let (tpk, _) = TPKBuilder::new()
            .add_userid("test@example.example")
            .add_userid("juga@sequoia-pgp.org")
            .generate()
            .unwrap();
        tpk.serialize(&mut buffer).unwrap();
        let valid_tpks = parse_body(&buffer, "juga@sequoia-pgp.org");
        assert!(valid_tpks.is_ok());
        assert!(valid_tpks.unwrap().len() == 1);
        // XXX: Test with more TPKs
    }

    #[test]
    fn wkd_generate() {
       let (tpk, _) = TPKBuilder::new()
            .add_userid("test1@example.example")
            .add_userid("juga@sequoia-pgp.org")
            .generate()
            .unwrap();
        let (tpk2, _) = TPKBuilder::new()
            .add_userid("justus@sequoia-pgp.org")
            .generate()
            .unwrap();
        let mut tpk_bytes: Vec<u8> = Vec::new();
        let mut tpk2_bytes: Vec<u8> = Vec::new();
        tpk.serialize(&mut tpk_bytes).unwrap();
        tpk2.serialize(&mut tpk2_bytes).unwrap();
        tpk_bytes.extend(tpk2_bytes);

        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path();
        let result = generate("sequoia-pgp.org", &tpk_bytes, &dir_path, None);
        assert!(result.is_ok());

        // justus and juga files will be generated, but not test one.
        let path = dir_path.join(
            "openpgpkey.sequoia-pgp.org/\
             .well-known/openpgpkey/sequoia-pgp.org/hu\
             /jwp7xjqkdujgz5op6bpsoypg34pnrgmq");
        assert_eq!(path.parent().unwrap().metadata().unwrap().permissions()
                   .mode(),16868);  // 744
        assert!(path.is_file());
        assert_eq!(path.metadata().unwrap().permissions().mode(),33188); // 644
        let path = dir_path.join(
            "openpgpkey.sequoia-pgp.org/\
             .well-known/openpgpkey/sequoia-pgp.org/hu\
             /7t1uqk9cwh1955776rc4z1gqf388566j");
        assert!(path.is_file());
        assert_eq!(path.metadata().unwrap().permissions().mode(),33188);
        let path = dir_path.join(
            "openpgpkey.example.com/\
             .well-known/openpgpkey/example.com/hu/\
             stnkabub89rpcphiz4ppbxixkwyt1pic");
        assert!(!path.is_file());
    }
}
