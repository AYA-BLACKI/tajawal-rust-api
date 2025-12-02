use jsonwebtoken::{Algorithm, EncodingKey, Header};
use tracing::error;

use crate::{
    ApiError, SERIAL_AUD, SERIAL_ISS,
    tjx_checker::{CheckedContext, enforce},
    tjx_cryper_all::build_fingerprint,
    tjx_decoder::decode_key,
    tjx_decorder_cripted_coder::encode_more,
    tjx_finder::{FinderContext, check_basic},
    tjx_validate::ClaimsInput,
    tjx_validate::build_claims,
    tjx_validate_decoder::assemble_bundle,
    tjx_validate_forwaed_crypted::forward_mac,
};

pub fn build_serial_token(
    name: &str,
    secret: &[u8],
    encoding: &EncodingKey,
    user_agent: Option<String>,
    client_ip: Option<String>,
) -> Result<String, ApiError> {
    let checked = build_checked_context(name, user_agent, client_ip)?;
    let fingerprint = build_fingerprint(checked, secret)?;
    let encoded = encode_more(fingerprint, secret)?;
    let decoded = decode_key(encoded, secret)?;
    let forward = forward_mac(decoded, secret)?;
    let bundle = assemble_bundle(forward)?;
    let claims = build_claims(ClaimsInput {
        bundle,
        ttl_seconds: 15 * 60,
        iss: SERIAL_ISS.to_string(),
        aud: SERIAL_AUD.to_string(),
    })?;

    let token =
        jsonwebtoken::encode(&Header::new(Algorithm::HS256), &claims, encoding).map_err(|err| {
            error!("failed to sign serial token: {err}");
            ApiError::Internal
        })?;

    Ok(token)
}

pub(crate) fn build_checked_context(
    name: &str,
    user_agent: Option<String>,
    client_ip: Option<String>,
) -> Result<CheckedContext, ApiError> {
    let context = FinderContext {
        name: name.to_string(),
        user_agent,
        client_ip,
    };
    enforce(check_basic(context)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};

    use crate::tjx_cryper_all::{derive_name_hash, CryperOutput};
    use crate::tjx_decorder_cripted_coder::derive_encoded;
    use crate::tjx_decoder::derive_decoded;
    use crate::tjx_validate_forwaed_crypted::derive_forward_mac;

    #[test]
    fn checked_context_canonicalizes_and_validates() {
        let ctx = build_checked_context(
            "  Alice   Beta  ",
            Some("Mozilla/5.0".to_string()),
            Some("203.0.113.5".to_string()),
        )
        .expect("context should pass validation");

        assert_eq!(ctx.canonical_name, "alice beta");
        assert_eq!(ctx.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(ctx.client_ip.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn serial_token_layers_remain_consistent() {
        let secret = b"test-secret-for-serials";
        let encoding = EncodingKey::from_secret(secret);
        let token = build_serial_token(
            "Example User",
            secret,
            &encoding,
            Some("Mozilla/5.0".into()),
            Some("203.0.113.9".into()),
        )
        .expect("token should be built");

        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[SERIAL_AUD]);
        validation.validate_nbf = false;
        let claims = jsonwebtoken::decode::<crate::SerialClaims>(
            &token,
            &DecodingKey::from_secret(secret),
            &validation,
        )
        .expect("token should decode")
        .claims;

        let checked = build_checked_context(
            "Example User",
            Some("Mozilla/5.0".into()),
            Some("203.0.113.9".into()),
        )
        .expect("context should pass validation");

        let expected_name_hash = derive_name_hash(
            &checked.canonical_name,
            checked.user_agent.as_deref(),
            checked.client_ip.as_deref(),
            &claims.salt,
            secret,
        );
        assert_eq!(claims.name_hash, expected_name_hash);

        let base = CryperOutput {
            name_hash: claims.name_hash.clone(),
            salt: claims.salt.clone(),
        };
        let expected_encoded = derive_encoded(&base, secret);
        assert_eq!(claims.encoded, expected_encoded);

        let expected_decoded = derive_decoded(&claims.encoded, secret);
        assert_eq!(claims.decoded, expected_decoded);

        let expected_mac = derive_forward_mac(
            &claims.name_hash,
            &claims.salt,
            &claims.encoded,
            &claims.decoded,
            secret,
        )
        .expect("forward mac should compute");
        assert_eq!(claims.forward_mac, expected_mac);
        assert!(claims.serial);
    }

    #[test]
    fn checked_context_rejects_numbers_and_banned_words() {
        assert!(build_checked_context("Bad123", None, None).is_err());
        assert!(build_checked_context("Root User", None, None).is_err());
        assert!(build_checked_context("zebi bad", None, None).is_err());
        assert!(build_checked_context("test for test for test", None, None).is_err());
        assert!(build_checked_context("awdwdawd awdawdawd awdawda", None, None).is_err());
        assert!(build_checked_context("Same Same", None, None).is_err());
        assert!(build_checked_context("Onlyone", None, None).is_err());
    }
}
