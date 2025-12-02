use hex::ToHex;
use sha2::{Digest, Sha256};

use crate::tjx_cryper_all::CryperOutput;
use crate::ApiError;

#[derive(Clone, Debug)]
pub struct EncodedLayer {
    pub encoded: String,
    pub base: CryperOutput,
}

pub(crate) fn derive_encoded(base: &CryperOutput, secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base.name_hash.as_bytes());
    hasher.update(base.salt.as_bytes());
    hasher.update(secret);
    hasher.finalize().encode_hex::<String>()
}

pub fn encode_more(base: CryperOutput, secret: &[u8]) -> Result<EncodedLayer, ApiError> {
    Ok(EncodedLayer {
        encoded: derive_encoded(&base, secret),
        base,
    })
}
