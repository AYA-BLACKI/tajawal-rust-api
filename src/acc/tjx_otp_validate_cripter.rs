use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Further encrypt and sign the forwarded key, producing a final validation token.
pub fn encrypt_validation(otp: &str, secret: &[u8]) -> Result<String, String> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| "invalid secret for validation encrypt")?;
    mac.update(format!("final:{otp}").as_bytes());
    let sig = mac.finalize().into_bytes();
    let payload = [format!("final:{otp}").as_bytes(), b".", sig.as_slice()].concat();
    Ok(format!("tjx{}", URL_SAFE_NO_PAD.encode(payload)))
}
