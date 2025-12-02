use std::collections::HashMap;

use axum::http::HeaderMap;
use axum::{Json, extract::State};
use hex::ToHex;
use rand::{RngCore, rngs::OsRng};
use time::OffsetDateTime;

use crate::{
    ApiError, AppState, Challenge, ChallengeRequest, ChallengeResponse, sign_challenge,
};

const CHALLENGE_TTL: i64 = 5 * 60; // 5 minutes

pub async fn request_challenge(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let decrypted_name = state.decrypt_name(&payload.encrypted_name)?;
    let checked = crate::tjx_main_forwarder_logic::build_checked_context(
        &decrypted_name,
        crate::extract_user_agent(&headers),
        crate::extract_client_ip(&headers),
    )?;
    let canonical = checked.canonical_name.clone();

    let mut id_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut id_bytes);
    let challenge_id = id_bytes.encode_hex::<String>();
    let signature = sign_challenge(&challenge_id, &canonical, &state.serial_secret)?;

    let expires_at =
        OffsetDateTime::now_utc().saturating_add(time::Duration::seconds(CHALLENGE_TTL));

    let challenge = Challenge {
        canonical_name: canonical,
        signature: signature.clone(),
        challenge_id: challenge_id.clone(),
        expires_at,
        user_agent: checked.user_agent,
        client_ip: checked.client_ip,
    };

    let mut guard = state.challenges.write().await;
    guard.insert(challenge_id.clone(), challenge);

    Ok(Json(ChallengeResponse {
        challenge_id,
        signature,
    }))
}

pub async fn purge_expired(map: &mut HashMap<String, Challenge>) {
    let now = OffsetDateTime::now_utc();
    map.retain(|_, c| c.expires_at > now);
}
