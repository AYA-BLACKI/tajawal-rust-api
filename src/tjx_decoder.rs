use hex::ToHex;
use sha2::{Digest, Sha256};

use crate::tjx_decorder_cripted_coder::EncodedLayer;
use crate::ApiError;

#[derive(Clone, Debug)]
pub struct DecodedLayer {
    pub decoded: String,
    pub encoded_layer: EncodedLayer,
}

pub(crate) fn derive_decoded(encoded: &str, secret: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(encoded.as_bytes());
    hasher.update(secret);
    hasher.finalize().encode_hex::<String>()
}

pub fn decode_key(layer: EncodedLayer, secret: &[u8]) -> Result<DecodedLayer, ApiError> {
    Ok(DecodedLayer {
        decoded: derive_decoded(&layer.encoded, secret),
        encoded_layer: layer,
    })
}
