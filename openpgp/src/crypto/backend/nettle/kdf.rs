use nettle::{
    kdf::hkdf,
    hash::Sha256,
};

use crate::{
    Result,
    crypto::{
        SessionKey,
        backend::interface::Kdf,
    },
};

impl Kdf for super::Backend {
    fn hkdf_sha256(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
                   -> Result<()>
    {
        assert!(okm.len() <= 255 * 32);
        const NO_SALT: [u8; 32] = [0; 32];
        let salt = salt.unwrap_or(&NO_SALT);
        hkdf::<Sha256>(&ikm[..], salt, info, okm);
        Ok(())
    }
}