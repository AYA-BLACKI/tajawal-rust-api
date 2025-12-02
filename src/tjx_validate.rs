use crate::tjx_validate_decoder::ValidateBundle;
use crate::{ApiError, SerialClaims};
use time::OffsetDateTime;

#[derive(Clone, Debug)]
pub struct ClaimsInput {
    pub bundle: ValidateBundle,
    pub ttl_seconds: usize,
    pub iss: String,
    pub aud: String,
}

pub fn build_claims(input: ClaimsInput) -> Result<SerialClaims, ApiError> {
    let now = OffsetDateTime::now_utc().unix_timestamp() as usize;
    let exp = now + input.ttl_seconds;
    Ok(SerialClaims {
        name_hash: input.bundle.name_hash.clone(),
        salt: input.bundle.salt.clone(),
        forward_mac: input.bundle.forward_mac.clone(),
        encoded: input.bundle.encoded.clone(),
        decoded: input.bundle.decoded.clone(),
        serial: true,
        exp,
        aud: Some(input.aud),
        iss: Some(input.iss),
    })
}
