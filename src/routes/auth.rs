use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use time::{Duration, OffsetDateTime};
use sha2::{Digest, Sha256};

use crate::security::{jwt::JwtManager, password, totp};
use crate::state::AppState;
use crate::security::{rate_limit, risk};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/request-password-reset", post(request_password_reset))
        .route("/auth/reset-password", post(reset_password))
        .route("/auth/mfa/totp/setup", post(mfa_setup))
        .route("/auth/mfa/totp/verify", post(mfa_verify))
}

#[derive(Deserialize)]
struct RegisterPayload {
    email: String,
    password: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
}

const REFRESH_TTL_DAYS: i64 = 30;

fn validate_email(email: &str) -> bool {
    email.contains('@') && email.len() <= 255
}

fn validate_password(password: &str) -> bool {
    password.len() >= 12
}

async fn register(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterPayload>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    if let Some(ip) = risk::extract_ip(&headers) {
        if !rate_limit::check(&ip, 20, 60) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limited".into()));
        }
        if !risk::risk_check(Some(&ip), headers.get("user-agent").and_then(|h| h.to_str().ok())) {
            return Err((StatusCode::FORBIDDEN, "Risk check failed".into()));
        }
    }
    if !validate_email(&payload.email) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email".into()));
    }
    if !validate_password(&payload.password) {
        return Err((StatusCode::BAD_REQUEST, "Password too weak (min 12 chars)".into()));
    }

    let hash = password::hash_password(&payload.password).map_err(internal_error)?;
    let user_id = Uuid::new_v4();

    let res = sqlx::query(
        "INSERT INTO users (id, email, password_hash, name, role, created_at, updated_at, banned)
         VALUES ($1, $2, $3, $4, 'user', now(), now(), false)",
    )
    .bind(user_id)
    .bind(&payload.email)
    .bind(&hash)
    .bind(&payload.name)
    .execute(&state.db)
    .await;

    if let Err(e) = res {
        return Err(map_db_error(e));
    }

    let access = state
        .jwt
        .issue_access(&user_id.to_string(), Some("user".into()))
        .map_err(internal_error)?;
    let (refresh_token, refresh_hash) = generate_refresh_token();
    store_refresh_token(
        &state,
        user_id,
        &refresh_hash,
        None,
        None,
        None,
    )
    .await?;

    Ok(Json(TokenResponse {
        access_token: access,
        refresh_token,
    }))
}

#[derive(Deserialize)]
struct LoginPayload {
    email: String,
    password: String,
}

async fn login(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    if let Some(ip) = risk::extract_ip(&headers) {
        if !rate_limit::check(&ip, 30, 60) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limited".into()));
        }
        if !risk::risk_check(Some(&ip), headers.get("user-agent").and_then(|h| h.to_str().ok())) {
            return Err((StatusCode::FORBIDDEN, "Risk check failed".into()));
        }
    }
    if !validate_email(&payload.email) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email".into()));
    }

    let row = sqlx::query(
        "SELECT id, password_hash, role, banned FROM users WHERE email = $1",
    )
    .bind(&payload.email)
    .fetch_optional(&state.db)
    .await
    .map_err(internal_error)?;

    let row = match row {
        Some(r) => r,
        None => return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into())),
    };

    let user_id: Uuid = row.get("id");
    let stored_hash: String = row.get("password_hash");
    let role: String = row.get("role");
    let banned: bool = row.get("banned");
    if banned {
        return Err((StatusCode::FORBIDDEN, "User banned".into()));
    }

    let valid = password::verify_password(&payload.password, &stored_hash).map_err(internal_error)?;
    if !valid {
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()));
    }

    let access = state
        .jwt
        .issue_access(&user_id.to_string(), Some(role))
        .map_err(internal_error)?;
    let (refresh_token, refresh_hash) = generate_refresh_token();
    store_refresh_token(
        &state,
        user_id,
        &refresh_hash,
        None,
        None,
        None,
    )
    .await?;

    Ok(Json(TokenResponse {
        access_token: access,
        refresh_token,
    }))
}

#[derive(Deserialize)]
struct RefreshPayload {
    refresh_token: String,
}

async fn refresh(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RefreshPayload>,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    if let Some(ip) = risk::extract_ip(&headers) {
        if !rate_limit::check(&ip, 60, 60) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limited".into()));
        }
        if !risk::risk_check(Some(&ip), headers.get("user-agent").and_then(|h| h.to_str().ok())) {
            return Err((StatusCode::FORBIDDEN, "Risk check failed".into()));
        }
    }
    let hash = hash_refresh_token(&payload.refresh_token);
    let row = sqlx::query(
        "SELECT user_id, revoked_at, expires_at, id FROM refresh_tokens WHERE token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await
    .map_err(internal_error)?;

    let row = match row {
        Some(r) => r,
        None => return Err((StatusCode::UNAUTHORIZED, "Invalid token".into())),
    };

    let revoked: Option<OffsetDateTime> = row.get("revoked_at");
    let expires_at: OffsetDateTime = row.get("expires_at");
    if revoked.is_some() || expires_at < OffsetDateTime::now_utc() {
        return Err((StatusCode::UNAUTHORIZED, "Token expired/revoked".into()));
    }

    let user_id: Uuid = row.get("user_id");
    let access = state
        .jwt
        .issue_access(&user_id.to_string(), Some("user".into()))
        .map_err(internal_error)?;

    // rotate
    let (new_refresh, new_hash) = generate_refresh_token();
    let old_id: Uuid = row.get("id");
    revoke_refresh_token(&state, old_id).await?;
    store_refresh_token(
        &state,
        user_id,
        &new_hash,
        None,
        None,
        Some(old_id),
    )
    .await?;

    Ok(Json(TokenResponse {
        access_token: access,
        refresh_token: new_refresh,
    }))
}

#[derive(Deserialize)]
struct LogoutPayload {
    refresh_token: Option<String>,
}

async fn logout(
    State(state): State<std::sync::Arc<AppState>>,
    Json(payload): Json<LogoutPayload>,
) -> Result<&'static str, (StatusCode, String)> {
    if let Some(rt) = payload.refresh_token {
        let hash = hash_refresh_token(&rt);
        let _ = sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1")
            .bind(&hash)
            .execute(&state.db)
            .await
            .map_err(internal_error)?;
    }
    Ok("logged out")
}

#[derive(Deserialize)]
struct RequestResetPayload {
    email: String,
}

async fn request_password_reset(Json(_payload): Json<RequestResetPayload>) -> &'static str {
    "reset requested"
}

#[derive(Deserialize)]
struct ResetPayload {
    reset_token: String,
    new_password: String,
}

async fn reset_password(Json(_payload): Json<ResetPayload>) -> &'static str {
    "reset done"
}

#[derive(Deserialize)]
struct TotpSetupRequest {
    user_id: Uuid,
    email: String,
}

#[derive(Serialize)]
struct TotpSetupResponse {
    secret: String,
    otpauth_url: String,
}

async fn mfa_setup(
    State(state): State<std::sync::Arc<AppState>>,
    Json(payload): Json<TotpSetupRequest>,
) -> Result<Json<TotpSetupResponse>, (StatusCode, String)> {
    let secret = totp::generate_secret();
    let url = totp::otpauth_url("Tajawal", &payload.email, &secret);

    sqlx::query(
        "INSERT INTO mfa_totp (user_id, secret_b32, enabled, created_at)
         VALUES ($1, $2, false, now())
         ON CONFLICT (user_id) DO UPDATE SET secret_b32 = EXCLUDED.secret_b32, enabled = false, created_at = now()",
    )
    .bind(payload.user_id)
    .bind(&secret)
    .execute(&state.db)
    .await
    .map_err(internal_error)?;

    Ok(Json(TotpSetupResponse {
        secret,
        otpauth_url: url,
    }))
}

#[derive(Deserialize)]
struct TotpVerifyRequest {
    user_id: Uuid,
    code: String,
}

async fn mfa_verify(
    State(state): State<std::sync::Arc<AppState>>,
    Json(payload): Json<TotpVerifyRequest>,
) -> Result<&'static str, (StatusCode, String)> {
    let row = sqlx::query("SELECT secret_b32 FROM mfa_totp WHERE user_id = $1")
        .bind(payload.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(internal_error)?;

    let secret: String = match row {
        Some(r) => r.get("secret_b32"),
        None => return Err((StatusCode::BAD_REQUEST, "No TOTP setup found".into())),
    };

    totp::verify_totp(&secret, &payload.code, 30, 6)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid code".into()))?;

    sqlx::query("UPDATE mfa_totp SET enabled = true WHERE user_id = $1")
        .bind(payload.user_id)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

    Ok("mfa verified")
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn map_db_error(err: sqlx::Error) -> (StatusCode, String) {
    if let sqlx::Error::Database(db_err) = &err {
        if db_err.constraint().is_some() {
            return (StatusCode::CONFLICT, "Email already exists".into());
        }
    }
    internal_error(err)
}

fn generate_refresh_token() -> (String, String) {
    let raw = format!("{}-{}", Uuid::new_v4(), Uuid::new_v4());
    let hash = hash_refresh_token(&raw);
    (raw, hash)
}

fn hash_refresh_token(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

async fn store_refresh_token(
    state: &std::sync::Arc<AppState>,
    user_id: Uuid,
    token_hash: &str,
    user_agent: Option<String>,
    ip: Option<String>,
    rotated_from: Option<Uuid>,
) -> Result<(), (StatusCode, String)> {
    let expires_at = OffsetDateTime::now_utc() + Duration::days(REFRESH_TTL_DAYS);
    sqlx::query(
        "INSERT INTO refresh_tokens (id, user_id, token_hash, created_at, expires_at, revoked_at, user_agent, ip, rotated_from)
         VALUES ($1, $2, $3, now(), $4, NULL, $5, $6, $7)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .bind(user_agent)
    .bind(ip)
    .bind(rotated_from)
    .execute(&state.db)
    .await
    .map_err(internal_error)?;
    Ok(())
}

async fn revoke_refresh_token(
    state: &std::sync::Arc<AppState>,
    token_id: Uuid,
) -> Result<(), (StatusCode, String)> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1")
        .bind(token_id)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;
    Ok(())
}
