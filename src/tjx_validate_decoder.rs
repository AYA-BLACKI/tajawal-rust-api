use crate::ApiError;
use crate::tjx_validate_forwaed_crypted::ForwardMac;

#[derive(Clone, Debug)]
pub struct ValidateBundle {
    pub name_hash: String,
    pub salt: String,
    pub forward_mac: String,
    pub decoded: String,
    pub encoded: String,
}

pub fn assemble_bundle(mac: ForwardMac) -> Result<ValidateBundle, ApiError> {
    Ok(ValidateBundle {
        name_hash: mac.decoded_layer.encoded_layer.base.name_hash.clone(),
        salt: mac.decoded_layer.encoded_layer.base.salt.clone(),
        forward_mac: mac.mac.clone(),
        decoded: mac.decoded_layer.decoded.clone(),
        encoded: mac.decoded_layer.encoded_layer.encoded.clone(),
    })
}
