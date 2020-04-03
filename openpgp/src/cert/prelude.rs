//! Brings most relevant types and traits into scope for working with
//! certificates.
//!
//! Less often used types and types that are more likely to lead to a
//! naming conflict are not brought into scope.
//!
//! Traits are brought into scope anonymously.
//!
//! ```
//! # #![allow(unused_imports)]
//! # extern crate sequoia_openpgp as openpgp;
//! use openpgp::cert::prelude::*;
//! ```

#![allow(unused_imports)]
pub use crate::cert::{
    Cert,
    CertBuilder,
    CertParser,
    CertRevocationBuilder,
    CertValidator,
    CertValidity,
    CipherSuite,
    KeyringValidator,
    KeyringValidity,
    Preferences as _,
    SubkeyRevocationBuilder,
    UserAttributeRevocationBuilder,
    UserIDRevocationBuilder,
    ValidCert,
    amalgamation::ComponentAmalgamation,
    amalgamation::ComponentAmalgamationIter,
    amalgamation::ErasedKeyAmalgamation,
    amalgamation::KeyAmalgamation,
    amalgamation::KeyAmalgamationIter,
    amalgamation::PrimaryKey as _,
    amalgamation::PrimaryKeyAmalgamation,
    amalgamation::SubordinateKeyAmalgamation,
    amalgamation::ValidAmalgamation as _,
    amalgamation::ValidComponentAmalgamation,
    amalgamation::ValidComponentAmalgamationIter,
    amalgamation::ValidErasedKeyAmalgamation,
    amalgamation::ValidKeyAmalgamation,
    amalgamation::ValidKeyAmalgamationIter,
    amalgamation::ValidPrimaryKeyAmalgamation,
    amalgamation::ValidSubordinateKeyAmalgamation,
    amalgamation::ValidateAmalgamation as _,
    bundle::ComponentBundle,
    bundle::KeyBundle,
    bundle::PrimaryKeyBundle,
    bundle::SubkeyBundle,
    bundle::UnknownBundle,
    bundle::UserAttributeBundle,
    bundle::UserIDBundle,
};
