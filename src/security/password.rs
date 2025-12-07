use argon2::{
    Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use once_cell::sync::Lazy;
use rand::rngs::OsRng;
use thiserror::Error;

static ARGON2: Lazy<Argon2<'static>> = Lazy::new(|| {
    let params = Params::new(64 * 1024, 3, 4, None).expect("params");
    Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params)
});

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("hash error: {0}")]
    Hash(String),
    #[error("verify error")]
    Verify,
}

pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    ARGON2
        .hash_password(plain.as_bytes(), &salt)
        .map(|p| p.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

pub fn verify_password(plain: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(hash).map_err(|e| PasswordError::Hash(e.to_string()))?;
    Ok(ARGON2.verify_password(plain.as_bytes(), &parsed).is_ok())
}
