use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
    response::{IntoResponse, Response},
    http::header::SET_COOKIE,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;
use time::{Duration, OffsetDateTime};
use sha2::{Digest, Sha256};
use cookie::{Cookie, SameSite};
use cookie::time::Duration as CookieDuration;
use std::sync::Arc;

use crate::security::{jwt::JwtManager, password, totp};
use crate::state::AppState;
use crate::security::{rate_limit, risk};

pub fn router() -> Router<Arc<AppState>> {
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
) -> Result<Response, (StatusCode, String)> {
    if let Some(ip) = risk::extract_ip(&headers) {
        if !rate_limit::check(&ip, 20, 60) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".into()));
        }
        match risk::risk_check(&state.db, None, Some(&ip), headers.get("user-agent").and_then(|h| h.to_str().ok())).await {
            risk::RiskDecision::Allow => {}
            risk::RiskDecision::Block(reason) => return Err((StatusCode::FORBIDDEN, reason.into())),
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
        headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
        risk::extract_ip(&headers),
        None,
    )
    .await?;

    Ok(token_response(access, refresh_token, &state))
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
) -> Result<Response, (StatusCode, String)> {
    if let Some(ip) = risk::extract_ip(&headers) {
        if !rate_limit::check(&ip, 30, 60) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".into()));
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
        sqlx::query("UPDATE users SET failed_login_count = coalesce(failed_login_count,0)+1, last_failed_at = now() WHERE id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await
            .ok();
        return Err((StatusCode::UNAUTHORIZED, "Invalid credentials".into()));
    }

    let ip = risk::extract_ip(&headers);
    match risk::risk_check(&state.db, Some(user_id), ip.as_deref(), headers.get("user-agent").and_then(|h| h.to_str().ok())).await {
        risk::RiskDecision::Allow => {}
        risk::RiskDecision::Block(reason) => return Err((StatusCode::FORBIDDEN, reason.into())),
    }

    sqlx::query("UPDATE users SET failed_login_count = 0, last_failed_at = NULL WHERE id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .ok();

    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    let _ = sqlx::query("INSERT INTO login_logs (id, user_id, ip, user_agent, success, created_at) VALUES ($1, $2, $3, $4, true, now())")
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(ip.clone())
        .bind(ua.clone())
        .execute(&state.db)
        .await;

    let access = state
        .jwt
        .issue_access(&user_id.to_string(), Some(role))
        .map_err(internal_error)?;
    let (refresh_token, refresh_hash) = generate_refresh_token();
    store_refresh_token(
        &state,
        user_id,
        &refresh_hash,
        ua.clone(),
        ip.clone(),
        None,
    )
    .await?;

    Ok(token_response(access, refresh_token, &state))
}

#[derive(Deserialize)]
struct RefreshPayload {
    refresh_token: String,
}

async fn refresh(
    State(state): State<std::sync::Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RefreshPayload>,
) -> Result<Response, (StatusCode, String)> {
    let ip = risk::extract_ip(&headers);
    if let Some(ref ip) = ip {
        if !rate_limit::check(&ip, 60, 60) {
            return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".into()));
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
    match risk::risk_check(&state.db, Some(user_id), ip.as_deref(), headers.get("user-agent").and_then(|h| h.to_str().ok())).await {
        risk::RiskDecision::Allow => {}
        risk::RiskDecision::Block(reason) => return Err((StatusCode::FORBIDDEN, reason.into())),
    }
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
        headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
        risk::extract_ip(&headers),
        Some(old_id),
    )
    .await?;

    Ok(token_response(access, new_refresh, &state))
}

#[derive(Deserialize)]
struct LogoutPayload {
    refresh_token: Option<String>,
}

async fn logout(
    State(state): State<std::sync::Arc<AppState>>,
    Json(payload): Json<LogoutPayload>,
) -> Result<Response, (StatusCode, String)> {
    if let Some(rt) = payload.refresh_token {
        let hash = hash_refresh_token(&rt);
        let _ = sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1")
            .bind(&hash)
            .execute(&state.db)
            .await
            .map_err(internal_error)?;
    }
    let mut res = Json(TokenResponse {
        access_token: "".into(),
        refresh_token: "".into(),
    })
    .into_response();
    clear_cookies(&mut res, &state.security);
    Ok(res)
}

#[derive(Deserialize)]
struct RequestResetPayload {
    email: String,
}

async fn request_password_reset(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RequestResetPayload>,
) -> Result<&'static str, (StatusCode, String)> {
    let row = sqlx::query("SELECT id FROM users WHERE email = $1")
        .bind(&payload.email)
        .fetch_optional(&state.db)
        .await
        .map_err(internal_error)?;
    let Some(user_id): Option<Uuid> = row.map(|r| r.get("id")) else {
        return Ok("reset requested");
    };

    let (token, token_hash) = generate_refresh_token();
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(30);
    sqlx::query("INSERT INTO password_resets (user_id, token_hash, expires_at, used) VALUES ($1, $2, $3, false)
                 ON CONFLICT (user_id) DO UPDATE SET token_hash = EXCLUDED.token_hash, expires_at = EXCLUDED.expires_at, used = false")
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

    tracing::info!("Password reset token issued for {}: {}", payload.email, token);
    Ok("reset requested")
}

#[derive(Deserialize)]
struct ResetPayload {
    reset_token: String,
    new_password: String,
}

async fn reset_password(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResetPayload>,
) -> Result<Response, (StatusCode, String)> {
    if !validate_password(&payload.new_password) {
        return Err((StatusCode::BAD_REQUEST, "Password too weak (min 12 chars)".into()));
    }

    let token_hash = hash_refresh_token(&payload.reset_token);
    let row = sqlx::query(
        "SELECT user_id, expires_at, used FROM password_resets WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(internal_error)?;

    let row = match row {
        Some(r) => r,
        None => return Err((StatusCode::UNAUTHORIZED, "Invalid reset token".into())),
    };
    let expires_at: OffsetDateTime = row.get("expires_at");
    let used: bool = row.get("used");
    if used || expires_at < OffsetDateTime::now_utc() {
        return Err((StatusCode::UNAUTHORIZED, "Reset token expired".into()));
    }
    let user_id: Uuid = row.get("user_id");

    let new_hash = password::hash_password(&payload.new_password).map_err(internal_error)?;
    sqlx::query("UPDATE users SET password_hash = $1, failed_login_count = 0, last_failed_at = NULL WHERE id = $2")
        .bind(new_hash)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(internal_error)?;

    sqlx::query("UPDATE password_resets SET used = true WHERE token_hash = $1")
        .bind(&token_hash)
        .execute(&state.db)
        .await
        .ok();

    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1")
        .bind(user_id)
        .execute(&state.db)
        .await
        .ok();

    let access = state.jwt.issue_access(&user_id.to_string(), Some("user".into())).map_err(internal_error)?;
    let (refresh_token, refresh_hash) = generate_refresh_token();
    store_refresh_token(&state, user_id, &refresh_hash, None, None, None).await?;

    Ok(token_response(access, refresh_token, &state))
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

fn token_response(access: String, refresh: String, state: &std::sync::Arc<AppState>) -> Response {
    let body = Json(TokenResponse {
        access_token: access.clone(),
        refresh_token: refresh.clone(),
    });
    let mut res = body.into_response();
    attach_cookies(&mut res, state, &access, &refresh);
    res
}

fn attach_cookies(res: &mut Response, state: &std::sync::Arc<AppState>, access: &str, refresh: &str) {
    let cfg = &state.security;
    let same_site = if cfg.same_site_strict { SameSite::Strict } else { SameSite::Lax };
    let access_cookie = Cookie::build((cfg.access_cookie_name.clone(), access.to_string()))
        .http_only(true)
        .secure(cfg.secure_cookies)
        .same_site(same_site)
        .max_age(CookieDuration::minutes(5))
        .path("/")
        .build()
        .to_string();
    let refresh_cookie = Cookie::build((cfg.refresh_cookie_name.clone(), refresh.to_string()))
        .http_only(true)
        .secure(cfg.secure_cookies)
        .same_site(same_site)
        .max_age(CookieDuration::days(REFRESH_TTL_DAYS))
        .path("/")
        .build()
        .to_string();
    res.headers_mut().append(SET_COOKIE, access_cookie.parse().unwrap());
    res.headers_mut().append(SET_COOKIE, refresh_cookie.parse().unwrap());
}

fn clear_cookies(res: &mut Response, cfg: &crate::security::config::SecurityConfig) {
    let same_site = if cfg.same_site_strict { SameSite::Strict } else { SameSite::Lax };
    let access_cookie = Cookie::build((cfg.access_cookie_name.clone(), ""))
        .http_only(true)
        .secure(cfg.secure_cookies)
        .same_site(same_site)
        .max_age(CookieDuration::seconds(0))
        .path("/")
        .build()
        .to_string();
    let refresh_cookie = Cookie::build((cfg.refresh_cookie_name.clone(), ""))
        .http_only(true)
        .secure(cfg.secure_cookies)
        .same_site(same_site)
        .max_age(CookieDuration::seconds(0))
        .path("/")
        .build()
        .to_string();
    res.headers_mut().append(SET_COOKIE, access_cookie.parse().unwrap());
    res.headers_mut().append(SET_COOKIE, refresh_cookie.parse().unwrap());
}
