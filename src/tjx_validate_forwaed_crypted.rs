use hex::ToHex;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::tjx_decoder::DecodedLayer;
use crate::ApiError;

#[derive(Clone, Debug)]
pub struct ForwardMac {
    pub mac: String,
    pub decoded_layer: DecodedLayer,
}

pub(crate) fn derive_forward_mac(
    name_hash: &str,
    salt: &str,
    encoded: &str,
    decoded: &str,
    secret: &[u8],
) -> Result<String, ApiError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| ApiError::Internal)?;
    mac.update(name_hash.as_bytes());
    mac.update(salt.as_bytes());
    mac.update(encoded.as_bytes());
    mac.update(decoded.as_bytes());
    Ok(mac.finalize().into_bytes().encode_hex::<String>())
}

pub fn forward_mac(layer: DecodedLayer, secret: &[u8]) -> Result<ForwardMac, ApiError> {
    Ok(ForwardMac {
        mac: derive_forward_mac(
            &layer.encoded_layer.base.name_hash,
            &layer.encoded_layer.base.salt,
            &layer.encoded_layer.encoded,
            &layer.decoded,
            secret,
        )?,
        decoded_layer: layer,
    })
}
