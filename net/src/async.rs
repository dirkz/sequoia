//! Asynchronously access keyservers.
//!
//! This module exposes the same interface, but for use within an
//! asynchronous framework.

use failure;
use futures::{future, Future, Stream};
use hyper::client::{ResponseFuture, HttpConnector};
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use hyper::{self, Client, Body, StatusCode, Request};
use hyper_tls::HttpsConnector;
use native_tls::{Certificate, TlsConnector};
use percent_encoding::{percent_encode, DEFAULT_ENCODE_SET};
use std::convert::From;
use std::io::Cursor;
use tokio_core::reactor::Handle;
use url::Url;

use openpgp::TPK;
use openpgp::{KeyID, armor, serialize::Serialize};
use openpgp::parse::Parse;
use sequoia_core::{Context, NetworkPolicy};
use wkd;

use super::{Error, Result};

define_encode_set! {
    /// Encoding used for submitting keys.
    ///
    /// The SKS keyserver as of version 1.1.6 is a bit picky with
    /// respect to the encoding.
    pub KEYSERVER_ENCODE_SET = [DEFAULT_ENCODE_SET] | {'-', '+', '/' }
}

/// For accessing keyservers using HKP.
pub struct KeyServer {
    client: Box<AClient>,
    uri: Url,
}

const DNS_WORKER: usize = 4;

impl KeyServer {
    /// Returns a handle for the given URI.
    pub fn new(ctx: &Context, uri: &str, _handle: &Handle) -> Result<Self> {
        let uri: Url = uri.parse()
            .or_else(|_| format!("hkps://{}", uri).parse())?;

        let client: Box<AClient> = match uri.scheme() {
            "hkp" => Box::new(Client::new()),
            "hkps" => {
                Box::new(Client::builder()
                         .build(HttpsConnector::new(DNS_WORKER)?))
            },
            _ => return Err(Error::MalformedUri.into()),
        };

        Self::make(ctx, client, uri)
    }

    /// Returns a handle for the given URI.
    ///
    /// `cert` is used to authenticate the server.
    pub fn with_cert(ctx: &Context, uri: &str, cert: Certificate,
                     _handle: &Handle) -> Result<Self> {
        let uri: Url = uri.parse()?;

        let client: Box<AClient> = {
            let mut tls = TlsConnector::builder();
            tls.add_root_certificate(cert);
            let tls = tls.build()?;

            let mut http = HttpConnector::new(DNS_WORKER);
            http.enforce_http(false);
            Box::new(Client::builder()
                     .build(HttpsConnector::from((http, tls))))
        };

        Self::make(ctx, client, uri)
    }

    /// Returns a handle for the SKS keyserver pool.
    ///
    /// The pool `hkps://hkps.pool.sks-keyservers.net` provides HKP
    /// services over https.  It is authenticated using a certificate
    /// included in this library.  It is a good default choice.
    pub fn sks_pool(ctx: &Context, handle: &Handle) -> Result<Self> {
        let uri = "hkps://hkps.pool.sks-keyservers.net";
        let cert = Certificate::from_der(
            include_bytes!("sks-keyservers.netCA.der")).unwrap();
        Self::with_cert(ctx, uri, cert, handle)
    }

    /// Common code for the above functions.
    fn make(ctx: &Context, client: Box<AClient>, uri: Url) -> Result<Self> {
        let s = uri.scheme();
        match s {
            "hkp" => ctx.network_policy().assert(NetworkPolicy::Insecure),
            "hkps" => ctx.network_policy().assert(NetworkPolicy::Encrypted),
            _ => return Err(Error::MalformedUri.into())
        }?;
        let uri =
            format!("{}://{}:{}",
                    match s {"hkp" => "http", "hkps" => "https",
                             _ => unreachable!()},
                    uri.host().ok_or(Error::MalformedUri)?,
                    match s {
                        "hkp" => uri.port().or(Some(11371)),
                        "hkps" => uri.port().or(Some(443)),
                        _ => unreachable!(),
                    }.unwrap()).parse()?;

        Ok(KeyServer{client: client, uri: uri})
    }

    /// Retrieves the key with the given `keyid`.
    pub fn get(&mut self, keyid: &KeyID)
               -> Box<Future<Item=TPK, Error=failure::Error> + 'static> {
        let uri = self.uri.join(
            &format!("pks/lookup?op=get&options=mr&search=0x{}",
                     keyid.to_hex()));
        if let Err(e) = uri {
            // This shouldn't happen, but better safe than sorry.
            return Box::new(future::err(Error::from(e).into()));
        }

        Box::new(self.client.do_get(uri.unwrap())
                 .from_err()
                 .and_then(|res| {
                     let status = res.status();
                     res.into_body().concat2().from_err()
                         .and_then(move |body| match status {
                             StatusCode::OK => {
                                 let c = Cursor::new(body.as_ref());
                                 let r = armor::Reader::new(
                                     c, Some(armor::Kind::PublicKey));
                                 future::done(TPK::from_reader(r))
                             },
                             StatusCode::NOT_FOUND =>
                                 future::err(Error::NotFound.into()),
                             n => future::err(Error::HttpStatus(n).into()),
                         })
                 }))
    }

    /// Sends the given key to the server.
    pub fn send(&mut self, key: &TPK)
                -> Box<Future<Item=(), Error=failure::Error> + 'static> {
        use openpgp::armor::{Writer, Kind};

        let uri =
            match self.uri.join("pks/add") {
                Err(e) =>
                // This shouldn't happen, but better safe than sorry.
                    return Box::new(future::err(Error::from(e).into())),
                Ok(u) => u,
            };

        let mut armored_blob = vec![];
        {
            let mut w = match Writer::new(&mut armored_blob,
                                          Kind::PublicKey, &[]) {
                Err(e) => return Box::new(future::err(e.into())),
                Ok(w) => w,
            };

            if let Err(e) = key.serialize(&mut w) {
                return Box::new(future::err(e));
            }
        }

        // Prepare to send url-encoded data.
        let mut post_data = b"keytext=".to_vec();
        post_data.extend_from_slice(percent_encode(&armored_blob, KEYSERVER_ENCODE_SET)
                                    .collect::<String>().as_bytes());
        let length = post_data.len();

        let mut request = match Request::post(url2uri(uri))
            .body(Body::from(post_data))
        {
            Ok(r) => r,
            Err(e) => return Box::new(future::err(Error::from(e).into())),
        };
        request.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"));
        request.headers_mut().insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&format!("{}", length))
                .expect("cannot fail: only ASCII characters"));

        Box::new(self.client.do_request(request)
                 .from_err()
                 .and_then(|res| {
                     match res.status() {
                         StatusCode::OK => future::ok(()),
                         StatusCode::NOT_FOUND => future::err(Error::ProtocolViolation.into()),
                         n => future::err(Error::HttpStatus(n).into()),
                     }
                 }))
    }
}

trait AClient {
    fn do_get(&mut self, uri: Url) -> ResponseFuture;
    fn do_request(&mut self, request: Request<Body>) -> ResponseFuture;
}

impl AClient for Client<HttpConnector> {
    fn do_get(&mut self, uri: Url) -> ResponseFuture {
        self.get(url2uri(uri))
    }
    fn do_request(&mut self, request: Request<Body>) -> ResponseFuture {
        self.request(request)
    }
}

impl AClient for Client<HttpsConnector<HttpConnector>> {
    fn do_get(&mut self, uri: Url) -> ResponseFuture {
        self.get(url2uri(uri))
    }
    fn do_request(&mut self, request: Request<Body>) -> ResponseFuture {
        self.request(request)
    }
}

pub(crate) fn url2uri(uri: Url) -> hyper::Uri {
    format!("{}", uri).parse().unwrap()
}


/// Retrieves the trasferable public key from a Web Key Directory URL.
///
/// From [draft-koch]:
/// The HTTP GET method MUST return the binary representation of the
/// OpenPGP key for the given mail address.  The key needs to carry a
/// User ID packet ([RFC4880]) with that mail address.
// Maybe this function should be in wkd.rs?
pub fn async_get_tpk_from_wkd_url(url: Url, email_address: String)
           -> Box<Future<Item=TPK, Error=failure::Error> + 'static> {
    let uri = url2uri(url);
    // WKD URL must use TLS
    let https = HttpsConnector::new(4).expect("TLS initialization failed");
    let client = Client::builder().build::<_, hyper::Body>(https);
    Box::new(client.get(uri)
        .from_err()
        .and_then(|res| {
        let status = res.status();
        println!("status {:?}", status);
        res.into_body().concat2().from_err()
        .and_then(|body| {
            // println!("{:?}", body);
            match TPK::from_bytes(&body) {
                Ok(tpk) => {
                    // Checks that a one of the userids in the transpferable
                    // public key match the email address.
                    // Move move this out of this function?
                    if wkd::is_email_in_userids(&tpk, email_address) {
                        future::done(Ok(tpk))
                    } else {
                        // Maybe return other error?
                        future::err(Error::NotFound.into())
                    }
                },
                Err(e) => future::err(e.into()),
            }
        })
    }))
}
