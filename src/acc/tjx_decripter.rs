use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Decrypt/validate the signed token with `tjx` prefix and return the OTP.
pub fn decrypt_token(token: &str, secret: &[u8]) -> Result<String, String> {
    let trimmed = token
        .strip_prefix("tjx")
        .ok_or_else(|| "token missing tjx prefix".to_string())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map_err(|_| "failed to decode token".to_string())?;
    let split = decoded
        .split(|b| *b == b'.')
        .map(|s| s.to_vec())
        .collect::<Vec<_>>();
    if split.len() != 2 {
        return Err("invalid token format".into());
    }
    let otp = split[0].clone();
    let sig = split[1].clone();

    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|_| "invalid secret for otp decryption")?;
    mac.update(&otp);
    mac.verify_slice(&sig)
        .map_err(|_| "otp signature mismatch".to_string())?;

    String::from_utf8(otp).map_err(|_| "invalid otp encoding".into())
}
