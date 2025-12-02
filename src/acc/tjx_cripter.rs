use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Encrypt/encapsulate the OTP into a signed token with `tjx` prefix.
pub fn encrypt_otp(otp: &str, secret: &[u8]) -> Result<String, String> {
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| "invalid secret for otp encryption")?;
    mac.update(otp.as_bytes());
    let sig = mac.finalize().into_bytes();
    let payload = [otp.as_bytes(), b".", sig.as_slice()].concat();
    Ok(format!("tjx{}", URL_SAFE_NO_PAD.encode(payload)))
}
