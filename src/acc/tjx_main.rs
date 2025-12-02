use std::env;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::{
    tjx_cripter::encrypt_otp,
    tjx_decripter::decrypt_token,
    tjx_forwarder_cripter::forward_to_decrypter,
    tjx_forwarder_decripter::analyze_and_forward,
    tjx_otp::generate_otp,
    tjx_otp_validate_cripter::encrypt_validation,
    tjx_otp_validate_decripter::decrypt_validation,
};

const OTP_SECRET_ENV: &str = "OTP_SECRET";

fn load_secret() -> Result<Vec<u8>, String> {
    let val = env::var(OTP_SECRET_ENV)
        .map_err(|_| "OTP_SECRET env var missing; set a strong secret for OTP crypto".to_string())?;
    if val.trim().is_empty() {
        return Err("OTP_SECRET cannot be empty".into());
    }
    Ok(val.into_bytes())
}

/// Full pipeline: generate OTP, encrypt, forward, analyze, and produce final validation token.
pub fn generate_otp_bundle() -> Result<(String, String), String> {
    let secret = load_secret()?;
    let otp = generate_otp();
    let encrypted = encrypt_otp(&otp, &secret)?;
    let forwarded = forward_to_decrypter(&encrypted);
    let decrypted = decrypt_token(&forwarded, &secret)?;
    // analyze and re-key
    let analyzed = analyze_and_forward(&decrypted);
    let validated = encrypt_validation(&analyzed, &secret)?;
    Ok((otp, validated))
}

/// Verify a final validation token and ensure it matches an expected OTP.
pub fn verify_otp_token(validation_token: &str, expected_otp: &str) -> Result<(), String> {
    let secret = load_secret()?;
    let analyzed = decrypt_validation(validation_token, &secret)?;
    let recovered = analyzed
        .strip_prefix("tjx")
        .and_then(|rest| URL_SAFE_NO_PAD.decode(rest.as_bytes()).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| s.strip_prefix("validated:").map(|v| v.to_string()))
        .ok_or_else(|| "invalid analyzed payload".to_string())?;

    if recovered != expected_otp {
        return Err("otp mismatch".into());
    }
    Ok(())
}
