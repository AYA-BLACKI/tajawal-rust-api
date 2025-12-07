use data_encoding::BASE32_NOPAD;
use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

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
    let Ok(parsed) = code.parse::<u32>() else {
        return Err(TotpError::InvalidCode);
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| TotpError::InvalidCode)?.as_secs();
    let counter = now / step;
    let expected = hotp(&secret, counter, digits)?;
    let adjacent = hotp(&secret, counter.saturating_sub(1), digits)?;
    if parsed == expected || parsed == adjacent {
        Ok(())
    } else {
        Err(TotpError::InvalidCode)
    }
}

fn hotp(secret: &[u8], counter: u64, digits: usize) -> Result<u32, TotpError> {
    let mut msg = [0u8; 8];
    msg.copy_from_slice(&counter.to_be_bytes());
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).map_err(|_| TotpError::InvalidCode)?;
    mac.update(&msg);
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let bin_code = ((result[offset] as u32 & 0x7f) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);
    let otp = bin_code % 10u32.pow(digits as u32);
    Ok(otp)
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
