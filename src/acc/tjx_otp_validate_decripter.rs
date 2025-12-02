use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Decrypt and validate the final validation token, returning the OTP if valid.
pub fn decrypt_validation(token: &str, secret: &[u8]) -> Result<String, String> {
    let trimmed = token
        .strip_prefix("tjx")
        .ok_or_else(|| "validation token missing tjx prefix".to_string())?;
    let decoded = URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map_err(|_| "failed to decode validation token".to_string())?;
    let split = decoded
        .split(|b| *b == b'.')
        .map(|s| s.to_vec())
        .collect::<Vec<_>>();
    if split.len() != 2 {
        return Err("invalid validation token format".into());
    }
    let payload = split[0].clone();
    let sig = split[1].clone();

    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| "invalid secret for validation decrypt".to_string())?;
    mac.update(&payload);
    mac.verify_slice(&sig)
        .map_err(|_| "validation signature mismatch".to_string())?;

    let payload_str =
        String::from_utf8(payload).map_err(|_| "invalid validation payload encoding".to_string())?;
    let otp = payload_str
        .strip_prefix("final:")
        .ok_or_else(|| "invalid validation payload".to_string())?;
    Ok(otp.to_string())
}
