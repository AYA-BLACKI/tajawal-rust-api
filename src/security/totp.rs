use data_encoding::BASE32_NOPAD;
use oath::totp_raw_now;
use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("invalid code")]
    InvalidCode,
}

pub fn generate_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    BASE32_NOPAD.encode(&bytes)
}

pub fn verify_totp(secret_b32: &str, code: &str, step: u64, digits: usize) -> Result<(), TotpError> {
    let secret = BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .map_err(|_| TotpError::InvalidCode)?;
    let expected = totp_raw_now(&secret, step, 0, digits)
        .map_err(|_| TotpError::InvalidCode)?;
    let Ok(parsed) = code.parse::<u64>() else {
        return Err(TotpError::InvalidCode);
    };
    if parsed == expected {
        Ok(())
    } else {
        Err(TotpError::InvalidCode)
    }
}

pub fn otpauth_url(issuer: &str, account: &str, secret_b32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        urlencoding::encode(issuer),
        urlencoding::encode(account),
        secret_b32,
        urlencoding::encode(issuer),
    )
}
