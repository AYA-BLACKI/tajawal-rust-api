use hex::ToHex;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::tjx_checker::CheckedContext;
use crate::ApiError;

const SALT_BYTES: usize = 16;

#[derive(Clone, Debug)]
pub struct CryperOutput {
    pub name_hash: String,
    pub salt: String,
}

/// Derive a stable fingerprint from the canonical name and caller context using a supplied salt.
pub(crate) fn derive_name_hash(
    canonical_name: &str,
    user_agent: Option<&str>,
    client_ip: Option<&str>,
    salt: &str,
    secret: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_name.as_bytes());
    if let Some(agent) = user_agent {
        hasher.update(agent.as_bytes());
    }
    if let Some(ip) = client_ip {
        hasher.update(ip.as_bytes());
    }
    hasher.update(salt.as_bytes());
    hasher.update(secret);
    hasher.finalize().encode_hex::<String>()
}

pub fn build_fingerprint(ctx: CheckedContext, secret: &[u8]) -> Result<CryperOutput, ApiError> {
    let mut salt_bytes = [0u8; SALT_BYTES];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt = salt_bytes.encode_hex::<String>();
    let name_hash = derive_name_hash(
        &ctx.canonical_name,
        ctx.user_agent.as_deref(),
        ctx.client_ip.as_deref(),
        &salt,
        secret,
    );

    Ok(CryperOutput { name_hash, salt })
}
