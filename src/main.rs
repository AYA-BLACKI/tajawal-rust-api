use std::{
    collections::{HashMap, HashSet},
    env, net::SocketAddr, sync::Arc,
};

use axum::{
    Json, Router, async_trait,
    extract::{FromRequestParts, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use axum_extra::{
    headers::{Authorization, authorization::Bearer},
    typed_header::TypedHeader,
};
use base64::{engine::general_purpose, Engine as _};
use dotenvy::dotenv;
use hex::ToHex;
use hmac::{Hmac, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
use rand::rngs::OsRng;
use rsa::{
    Oaep,
    Pkcs1v15Encrypt,
    pkcs8::{EncodePublicKey, LineEnding},
    RsaPrivateKey, RsaPublicKey,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio::{net::TcpListener, sync::RwLock};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info};

const SERIAL_AUD: &str = "serial_access";
const SERIAL_ISS: &str = "tjlx-auth";
const DASHBOARD_LOCK_COOKIE: &str = "dashboard_lock";
const SENSITIVE_NAMES: &[&str] = &[
    "admin", "root", "support", "system", "owner", "fuck", "shit", "bitch", "test", "dummy",
    "hacker", "attack", "exploit", "spam",
];

mod tjx_challenge;
mod tjx_checker;
mod tjx_cryper_all;
mod tjx_decoder;
mod tjx_decorder_cripted_coder;
mod tjx_finder;
mod tjx_main_forwarder_logic;
mod tjx_validate;
mod tjx_validate_decoder;
mod tjx_validate_forwaed_crypted;
mod acc;

#[derive(Deserialize)]
struct SignupRequest {
    email: String,
    name: String,
    password: String,
    phone: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    token: Option<String>,
    user: PublicUser,
}

#[derive(Debug, Deserialize, Clone)]
struct Claims {
    sub: String,
    email: Option<String>,
    #[allow(dead_code)]
    exp: usize,
    #[allow(dead_code)]
    aud: Option<String>,
    #[allow(dead_code)]
    iss: Option<String>,
}

#[derive(Serialize)]
struct PublicUser {
    id: String,
    email: Option<String>,
    name: Option<String>,
    phone: Option<String>,
}

#[derive(Deserialize)]
struct SupabaseAuthResponse {
    access_token: Option<String>,
    user: Option<SupabaseUser>,
}

#[derive(Deserialize)]
struct SupabaseUser {
    id: String,
    email: Option<String>,
    user_metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct SupabaseAdminUser {
    email: Option<String>,
    phone: Option<String>,
    email_confirmed_at: Option<String>,
    phone_confirmed_at: Option<String>,
}

#[derive(Deserialize)]
struct SupabaseErrorBody {
    error: Option<String>,
    error_description: Option<String>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    encrypted_name: String,
}

#[derive(Deserialize)]
struct SerialRequest {
    challenge_id: String,
    signature: String,
}

#[derive(Serialize)]
struct SerialResponse {
    serial_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChallengeResponse {
    challenge_id: String,
    signature: String,
}

#[derive(Deserialize)]
struct VerifyContactRequest {
    email: Option<String>,
    phone: Option<String>,
}

#[derive(Deserialize)]
struct ConfirmContactRequest {
    email: Option<String>,
    phone: Option<String>,
    otp: String,
}

#[derive(Clone)]
struct PendingContactOtp {
    email: Option<String>,
    phone: Option<String>,
    otp: String,
    expires_at: OffsetDateTime,
}

#[derive(Clone)]
struct VerifiedContacts {
    email: Option<String>,
    phone: Option<String>,
    verified_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
struct Challenge {
    canonical_name: String,
    signature: String,
    challenge_id: String,
    expires_at: OffsetDateTime,
    user_agent: Option<String>,
    client_ip: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SerialClaims {
    name_hash: String,
    salt: String,
    forward_mac: String,
    encoded: String,
    decoded: String,
    serial: bool,
    exp: usize,
    aud: Option<String>,
    iss: Option<String>,
}

#[derive(Clone)]
struct AppState {
    supabase: SupabaseConfig,
    jwt_decoding: DecodingKey,
    jwt_validation: Validation,
    serial_decoding: DecodingKey,
    serial_encoding: EncodingKey,
    serial_validation: Validation,
    serial_secret: Vec<u8>,
    challenges: Arc<RwLock<HashMap<String, Challenge>>>,
    rsa_private: Arc<RsaPrivateKey>,
    rsa_public_pem: String,
    name_change_history: Arc<RwLock<HashMap<String, OffsetDateTime>>>,
    pending_contact_otps: Arc<RwLock<HashMap<String, PendingContactOtp>>>,
    verified_contacts: Arc<RwLock<HashMap<String, VerifiedContacts>>>,
    banned_accounts: Arc<RwLock<HashSet<String>>>,
}

#[derive(Clone)]
struct SupabaseConfig {
    url: String,
    anon_key: String,
    service_role_key: String,
    client: Client,
}

#[derive(Debug, Error)]
enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Banned,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()),
            ApiError::Banned => (StatusCode::FORBIDDEN, "Account banned".to_string()),
            ApiError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong".into(),
            ),
        };
        let body = Json(serde_json::json!({ "error": message }));
        (status, body).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    init_tracing();
    dotenv().ok(); // load .env if present for local dev

    let supabase = build_supabase_config()?;
    let (jwt_decoding, jwt_validation) = build_jwt_validation()?;
    let (serial_decoding, serial_encoding, serial_validation, serial_secret) =
        build_serial_validation()?;
    let (rsa_private, rsa_public_pem) = build_rsa_keys()?;
    let state = Arc::new(AppState {
        supabase,
        jwt_decoding,
        jwt_validation,
        serial_decoding,
        serial_encoding,
        serial_validation,
        serial_secret,
        challenges: Arc::new(RwLock::new(HashMap::new())),
        rsa_private,
        rsa_public_pem,
        name_change_history: Arc::new(RwLock::new(HashMap::new())),
        pending_contact_otps: Arc::new(RwLock::new(HashMap::new())),
        verified_contacts: Arc::new(RwLock::new(HashMap::new())),
        banned_accounts: Arc::new(RwLock::new(HashSet::new())),
    });
    let port = env::var("PORT")
        .ok()
        .and_then(|p| match p.parse::<u16>() {
            Ok(p) => Some(p),
            Err(err) => {
                error!("PORT is set but invalid ({err}); defaulting to 8080");
                None
            }
        })
        .unwrap_or(8080);

    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(vec![
            HeaderValue::from_static("https://tajawalbeta.netlify.app"),
            HeaderValue::from_static("https://tajawalet.netlify.app"),
            HeaderValue::from_static("http://localhost:5173"),
        ]))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::HeaderName::from_static("x-serial-token"),
        ])
        .allow_credentials(true);

    let app = Router::new()
        .route("/health", get(health_plain))
        .route("/api/health", get(health))
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/login", post(login))
        .route("/api/profile/contact/confirm", post(confirm_contact_verification))
        .route(
            "/api/access/challenge",
            post(tjx_challenge::request_challenge),
        )
        .route("/api/access/serial", post(issue_serial_token))
        .route("/api/access/serial/verify", get(verify_serial_token))
        .route("/api/access/public-key", get(public_key))
        .route("/api/profile/contact/verify", post(request_contact_verification))
        .route("/api/profile/name", post(update_profile_name))
        .route("/api/dashboard", get(protected_dashboard))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    info!("Auth API listening on {}", addr);
    let listener = TcpListener::bind(addr).await.map_err(|err| {
        error!("failed to bind listener: {err}");
        ApiError::Internal
    })?;
    axum::serve(listener, app).await.map_err(|err| {
        error!("server error: {err}");
        ApiError::Internal
    })
}

async fn health_plain() -> impl IntoResponse {
    "OK"
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn public_key(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({ "public_key_pem": state.rsa_public_pem }))
}

async fn signup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<SignupRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    if is_dashboard_locked(&headers) {
        return Err(ApiError::Unauthorized);
    }
    if payload.email.trim().is_empty() || payload.password.trim().len() < 8 {
        return Err(ApiError::BadRequest(
            "Email and an 8+ character password are required".into(),
        ));
    }

    let validated_name = validate_display_name(&payload.name)?;

    let session = supabase_sign_up(&state.supabase, &payload, &validated_name).await?;
    let user = to_public_user(session.user.as_ref().ok_or_else(|| {
        ApiError::BadRequest("Please confirm your email to activate the account.".into())
    })?);

    Ok(Json(AuthResponse {
        token: session.access_token,
        user,
    }))
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    if is_dashboard_locked(&headers) {
        return Err(ApiError::Unauthorized);
    }
    if payload.email.trim().is_empty() || payload.password.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Email and password are required".into(),
        ));
    }

    let session = supabase_sign_in(&state.supabase, &payload).await?;
    let token = session.access_token.ok_or(ApiError::Unauthorized)?;
    let user = to_public_user(session.user.as_ref().ok_or(ApiError::Unauthorized)?);

    Ok(Json(AuthResponse {
        token: Some(token),
        user,
    }))
}

async fn issue_serial_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<SerialRequest>,
) -> Result<Json<SerialResponse>, ApiError> {
    let user_agent = extract_user_agent(&headers);
    let client_ip = extract_client_ip(&headers);

    let mut guard = state.challenges.write().await;
    tjx_challenge::purge_expired(&mut guard).await;
    let challenge = guard
        .remove(&payload.challenge_id)
        .ok_or(ApiError::Unauthorized)?;

    if challenge.expires_at < OffsetDateTime::now_utc() {
        return Err(ApiError::Unauthorized);
    }

    if challenge.signature != payload.signature {
        return Err(ApiError::Unauthorized);
    }

    if !context_matches(&challenge.user_agent, &user_agent)
        || !context_matches(&challenge.client_ip, &client_ip)
    {
        return Err(ApiError::Unauthorized);
    }

    // recompute signature to ensure provided signature matches secret and name
    let expected_sig = sign_challenge(
        &challenge.challenge_id,
        &challenge.canonical_name,
        &state.serial_secret,
    )?;
    if expected_sig != payload.signature {
        return Err(ApiError::Unauthorized);
    }

    let token = tjx_main_forwarder_logic::build_serial_token(
        &challenge.canonical_name,
        &state.serial_secret,
        &state.serial_encoding,
        challenge.user_agent.clone(),
        challenge.client_ip.clone(),
    )?;
    Ok(Json(SerialResponse {
        serial_token: token,
    }))
}

async fn protected_dashboard(user: AuthUser) -> Result<(HeaderMap, Json<serde_json::Value>), ApiError> {
    let Claims { email, sub, .. } = user.0;
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::SET_COOKIE, dashboard_lock_cookie());
    Ok((headers, Json(serde_json::json!({
        "status": "ok",
        "user_id": sub,
        "email": email,
        "message": "Protected dashboard data"
    }))))
}

async fn update_profile_name(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<UpdateNameRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = user.0.sub.clone();

    // Ban check
    {
        let banned = state.banned_accounts.read().await;
        if banned.contains(&user_id) {
            return Err(ApiError::Banned);
        }
    }

    // Require email + phone to attempt name change.
    if body.email.trim().is_empty() || body.phone.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "Email and phone are required before changing your name".into(),
        ));
    }

    // Ensure email + phone are verified locally.
    {
        let verified = state.verified_contacts.read().await;
        let entry = verified.get(&user_id);
        let email_ok = entry
            .and_then(|v| v.email.as_ref())
            .map(|e| e == body.email.trim())
            .unwrap_or(false);
        let phone_ok = entry
            .and_then(|v| v.phone.as_ref())
            .map(|p| p == body.phone.trim())
            .unwrap_or(false);
        if !email_ok || !phone_ok {
            return Err(ApiError::BadRequest(
                "Please verify both email and phone before changing your name.".into(),
            ));
        }
    }

    const NAME_CHANGE_COOLDOWN: Duration = Duration::days(90);
    let now = OffsetDateTime::now_utc();
    // Enforce cooldown between name changes.
    {
        let history = state.name_change_history.read().await;
        if let Some(last_change) = history.get(&user_id) {
            if now - *last_change < NAME_CHANGE_COOLDOWN {
                return Err(ApiError::Conflict(
                    "Name can only be changed once every 90 days after verifying email and phone".into(),
                ));
            }
        }
    }

    let candidate = format!("{} {}", body.first_name.trim(), body.last_name.trim());
    // Validate name and check sensitivity
    if is_sensitive_name(&candidate) {
        let mut banned = state.banned_accounts.write().await;
        banned.insert(user_id.clone());
        return Err(ApiError::Banned);
    }

    // Reuse existing validator for structure/banned words.
    validate_display_name(&candidate)?;

    // Record the change time to enforce cooldown.
    {
        let mut history = state.name_change_history.write().await;
        history.insert(user_id.clone(), now);
    }

    // In a real system we'd persist this to Supabase; for now just acknowledge.
    Ok(Json(serde_json::json!({
        "status": "ok",
        "name": candidate,
        "locked": true
    })))
}

async fn verify_serial_token(
    State(state): State<Arc<AppState>>,
    serial: SerialAuth,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !serial.0.serial {
        return Err(ApiError::Unauthorized);
    }

    let base = crate::tjx_cryper_all::CryperOutput {
        name_hash: serial.0.name_hash.clone(),
        salt: serial.0.salt.clone(),
    };
    let encoded_expected =
        crate::tjx_decorder_cripted_coder::derive_encoded(&base, &state.serial_secret);

    if encoded_expected != serial.0.encoded {
        return Err(ApiError::Unauthorized);
    }

    let decoded_expected =
        crate::tjx_decoder::derive_decoded(&serial.0.encoded, &state.serial_secret);

    if decoded_expected != serial.0.decoded {
        return Err(ApiError::Unauthorized);
    }

    let mac_expected = crate::tjx_validate_forwaed_crypted::derive_forward_mac(
        &serial.0.name_hash,
        &serial.0.salt,
        &serial.0.encoded,
        &serial.0.decoded,
        &state.serial_secret,
    )?;

    if mac_expected != serial.0.forward_mac {
        return Err(ApiError::Unauthorized);
    }

    Ok(Json(serde_json::json!({ "status": "ok" })))
}

async fn request_contact_verification(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<VerifyContactRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if body.email.as_deref().map(|s| s.trim().is_empty()).unwrap_or(true)
        && body.phone.as_deref().map(|s| s.trim().is_empty()).unwrap_or(true)
    {
        return Err(ApiError::BadRequest(
            "Provide at least one of email or phone to verify".into(),
        ));
    }

    let otp = crate::acc::tjx_otp::generate_otp();
    let expires_at = OffsetDateTime::now_utc() + Duration::minutes(10);
    let pending = PendingContactOtp {
        email: body.email.as_ref().map(|s| s.trim().to_string()),
        phone: body.phone.as_ref().map(|s| s.trim().to_string()),
        otp: otp.clone(),
        expires_at,
    };

    {
        let mut map = state.pending_contact_otps.write().await;
        map.insert(user.0.sub.clone(), pending);
    }

    let echo_otp = env::var("OTP_ECHO")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true); // default to true so users can see OTP immediately during integration

    // In a real system, send OTP via email/SMS here. For testing, optionally echo the OTP.
    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": "OTP sent to provided contact methods",
        "expires_in_minutes": 10,
        "otp": if echo_otp { Some(otp) } else { None },
    })))
}

async fn confirm_contact_verification(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(body): Json<ConfirmContactRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let otp = body.otp.trim();
    if otp.is_empty() {
        return Err(ApiError::BadRequest("OTP is required".into()));
    }

    let pending = {
        let map = state.pending_contact_otps.read().await;
        map.get(&user.0.sub).cloned()
    };

    let pending = pending.ok_or_else(|| ApiError::BadRequest("No pending OTP for this user".into()))?;
    if OffsetDateTime::now_utc() > pending.expires_at {
        return Err(ApiError::BadRequest("OTP expired, please request a new one".into()));
    }

    if pending.otp != otp {
        return Err(ApiError::BadRequest("Invalid OTP".into()));
    }

    // Optional: ensure the same email/phone are being confirmed.
    if let Some(expected) = pending.email.as_ref() {
        if let Some(submitted) = body.email.as_ref() {
            if expected != submitted.trim() {
                return Err(ApiError::BadRequest("Email does not match pending verification".into()));
            }
        }
    }
    if let Some(expected) = pending.phone.as_ref() {
        if let Some(submitted) = body.phone.as_ref() {
            if expected != submitted.trim() {
                return Err(ApiError::BadRequest("Phone does not match pending verification".into()));
            }
        }
    }

    {
        let mut verified = state.verified_contacts.write().await;
        verified.insert(
            user.0.sub.clone(),
            VerifiedContacts {
                email: pending.email.clone(),
                phone: pending.phone.clone(),
                verified_at: OffsetDateTime::now_utc(),
            },
        );
    }
    {
        let mut map = state.pending_contact_otps.write().await;
        map.remove(&user.0.sub);
    }

    Ok(Json(serde_json::json!({
        "status": "ok",
        "verified_email": pending.email,
        "verified_phone": pending.phone,
    })))
}

fn to_public_user(user: &SupabaseUser) -> PublicUser {
    let meta = user.user_metadata.as_ref().and_then(|v| v.as_object());
    let name = meta
        .and_then(|m| m.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let phone = meta
        .and_then(|m| m.get("phone"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    PublicUser {
        id: user.id.clone(),
        email: user.email.clone(),
        name,
        phone,
    }
}

async fn supabase_sign_up(
    config: &SupabaseConfig,
    payload: &SignupRequest,
    validated_name: &str,
) -> Result<SupabaseAuthResponse, ApiError> {
    let endpoint = format!("{}/auth/v1/signup", config.url.trim_end_matches('/'));
    let body = serde_json::json!({
        "email": payload.email,
        "password": payload.password,
        "data": {
            "name": validated_name,
            "phone": payload.phone,
        }
    });

    let response = config
        .client
        .post(endpoint)
        .header("apikey", &config.service_role_key)
        .bearer_auth(&config.service_role_key)
        .json(&body)
        .send()
        .await
        .map_err(|err| {
            error!("signup request failed: {err}");
            ApiError::Internal
        })?;

    parse_supabase_response(response, false).await
}

async fn supabase_sign_in(
    config: &SupabaseConfig,
    payload: &LoginRequest,
) -> Result<SupabaseAuthResponse, ApiError> {
    let endpoint = format!(
        "{}/auth/v1/token?grant_type=password",
        config.url.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "email": payload.email,
        "password": payload.password,
    });

    let response = config
        .client
        .post(endpoint)
        .header("apikey", &config.anon_key)
        .bearer_auth(&config.anon_key)
        .json(&body)
        .send()
        .await
        .map_err(|err| {
            error!("login request failed: {err}");
            ApiError::Internal
        })?;

    parse_supabase_response(response, true).await
}

async fn parse_supabase_response(
    response: reqwest::Response,
    require_token: bool,
) -> Result<SupabaseAuthResponse, ApiError> {
    let status = response.status();
    let bytes = response.bytes().await.map_err(|err| {
        error!("failed reading supabase response: {err}");
        ApiError::Internal
    })?;

    if status.is_success() {
        let parsed: SupabaseAuthResponse = serde_json::from_slice(&bytes).map_err(|err| {
            error!(
                "failed parsing supabase session: {err}, body: {}",
                String::from_utf8_lossy(&bytes)
            );
            ApiError::Internal
        })?;

        if require_token && parsed.access_token.is_none() {
            error!("supabase login missing access_token");
            return Err(ApiError::Unauthorized);
        }

        if !require_token && parsed.access_token.is_none() {
            // Email confirmation likely required; let frontend handle a graceful message without token.
            info!("signup returned no session; likely email confirmation is required");
        }

        Ok(parsed)
    } else {
        let fallback = String::from_utf8_lossy(&bytes).into_owned();
        let parsed: Option<SupabaseErrorBody> = serde_json::from_slice(&bytes).ok();

        let message = parsed
            .and_then(|p| p.message.or(p.error_description).or(p.error))
            .unwrap_or_else(|| fallback.clone());

        error!("supabase returned {}: {}", status, message);

        match status {
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
                if message.to_lowercase().contains("already registered") {
                    Err(ApiError::Conflict("User already exists".into()))
                } else {
                    Err(ApiError::BadRequest(message))
                }
            }
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(ApiError::Unauthorized),
            StatusCode::CONFLICT => Err(ApiError::Conflict(message)),
            StatusCode::TOO_MANY_REQUESTS => Err(ApiError::BadRequest(message)),
            _ => Err(ApiError::Internal),
        }
    }
}

async fn fetch_supabase_admin_user(
    config: &SupabaseConfig,
    user_id: &str,
) -> Result<SupabaseAdminUser, ApiError> {
    let endpoint = format!(
        "{}/auth/v1/admin/users/{}",
        config.url.trim_end_matches('/'),
        user_id
    );

    let response = config
        .client
        .get(endpoint)
        .header("apikey", &config.service_role_key)
        .bearer_auth(&config.service_role_key)
        .send()
        .await
        .map_err(|err| {
            error!("admin user fetch failed: {err}");
            ApiError::Internal
        })?;

    if !response.status().is_success() {
        error!("admin user fetch returned {}", response.status());
        return Err(ApiError::Unauthorized);
    }

    response.json().await.map_err(|err| {
        error!("failed parsing admin user: {err}");
        ApiError::Internal
    })
}

async fn send_email_verification(
    config: &SupabaseConfig,
    email: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    let endpoint = format!("{}/auth/v1/otp", config.url.trim_end_matches('/'));
    let body = serde_json::json!({
        "email": email,
        "create_user": false,
        "data": { "user_id": user_id },
    });

    let response = config
        .client
        .post(endpoint)
        .header("apikey", &config.service_role_key)
        .bearer_auth(&config.service_role_key)
        .json(&body)
        .send()
        .await
        .map_err(|err| {
            error!("email verification request failed: {err}");
            ApiError::Internal
        })?;

    if !response.status().is_success() {
        error!("email verification request returned {}", response.status());
        return Err(ApiError::BadRequest(
            "Failed to send email verification. Please try again.".into(),
        ));
    }

    Ok(())
}

async fn send_phone_verification(
    config: &SupabaseConfig,
    phone: &str,
    user_id: &str,
) -> Result<(), ApiError> {
    let endpoint = format!("{}/auth/v1/otp", config.url.trim_end_matches('/'));
    let body = serde_json::json!({
        "phone": phone,
        "create_user": false,
        "channel": "sms",
        "data": { "user_id": user_id },
    });

    let response = config
        .client
        .post(endpoint)
        .header("apikey", &config.service_role_key)
        .bearer_auth(&config.service_role_key)
        .json(&body)
        .send()
        .await
        .map_err(|err| {
            error!("phone verification request failed: {err}");
            ApiError::Internal
        })?;

    if !response.status().is_success() {
        error!("phone verification request returned {}", response.status());
        return Err(ApiError::BadRequest(
            "Failed to send phone verification. Please try again.".into(),
        ));
    }

    Ok(())
}

fn build_supabase_config() -> Result<SupabaseConfig, ApiError> {
    let url = env::var("SUPABASE_URL").map_err(|err| {
        error!("SUPABASE_URL missing: {err}");
        ApiError::Internal
    })?;
    let anon_key = env::var("SUPABASE_ANON_KEY").map_err(|err| {
        error!("SUPABASE_ANON_KEY missing: {err}");
        ApiError::Internal
    })?;
    let service_role_key = env::var("SUPABASE_SERVICE_ROLE_KEY").map_err(|err| {
        error!("SUPABASE_SERVICE_ROLE_KEY missing: {err}");
        ApiError::Internal
    })?;
    let client = Client::builder().build().map_err(|err| {
        error!("failed building http client: {err}");
        ApiError::Internal
    })?;

    Ok(SupabaseConfig {
        url,
        anon_key,
        service_role_key,
        client,
    })
}

fn build_jwt_validation() -> Result<(DecodingKey, Validation), ApiError> {
    let secret = env::var("SUPABASE_JWT_SECRET").map_err(|err| {
        error!("SUPABASE_JWT_SECRET missing: {err}");
        ApiError::Internal
    })?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&["authenticated"]);
    validation.validate_exp = true;
    validation.validate_nbf = false;

    let decoding = DecodingKey::from_secret(secret.as_bytes());
    Ok((decoding, validation))
}

fn build_serial_validation() -> Result<(DecodingKey, EncodingKey, Validation, Vec<u8>), ApiError> {
    let secret = env::var("SERIAL_JWT_SECRET")
        .or_else(|_| env::var("SUPABASE_JWT_SECRET"))
        .map_err(|err| {
            error!("serial signing secret missing: {err}");
            ApiError::Internal
        })?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[SERIAL_AUD]);
    validation.validate_exp = true;
    validation.validate_nbf = false;

    let decoding = DecodingKey::from_secret(secret.as_bytes());
    let encoding = EncodingKey::from_secret(secret.as_bytes());
    let secret_bytes = secret.into_bytes();

    Ok((decoding, encoding, validation, secret_bytes))
}

fn build_rsa_keys() -> Result<(Arc<RsaPrivateKey>, String), ApiError> {
    let mut rng = OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).map_err(|err| {
        error!("failed to generate rsa key: {err}");
        ApiError::Internal
    })?;
    let public = RsaPublicKey::from(&private);
    let pem = public
        .to_public_key_pem(LineEnding::LF)
        .map_err(|err| {
            error!("failed to encode rsa public key: {err}");
            ApiError::Internal
        })?;
    Ok((Arc::new(private), pem))
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();
}

pub(crate) fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

pub(crate) fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    const IP_HEADERS: [&str; 3] = ["x-forwarded-for", "x-real-ip", "cf-connecting-ip"];
    for name in IP_HEADERS {
        if let Some(value) = headers.get(name).and_then(|h| h.to_str().ok()) {
            if let Some(first) = value.split(',').map(str::trim).find(|v| !v.is_empty()) {
                return Some(first.to_string());
            }
        }
    }
    None
}

fn context_matches(expected: &Option<String>, actual: &Option<String>) -> bool {
    match (expected, actual) {
        (Some(exp), Some(act)) => exp == act,
        (Some(_), None) => false,
        _ => true,
    }
}

fn is_sensitive_name(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    SENSITIVE_NAMES.iter().any(|term| lowered.contains(term))
}

fn is_dashboard_locked(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .map(|cookie_str| {
          cookie_str
            .split(';')
            .any(|c| c.trim_start().starts_with(DASHBOARD_LOCK_COOKIE))
        })
        .unwrap_or(false)
}

fn dashboard_lock_cookie() -> HeaderValue {
    let value = format!("{DASHBOARD_LOCK_COOKIE}=1; Max-Age=31536000; Path=/; HttpOnly; Secure; SameSite=Strict");
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

impl AppState {
    pub(crate) fn decrypt_name(&self, encrypted_b64: &str) -> Result<String, ApiError> {
        let bytes = general_purpose::STANDARD
            .decode(encrypted_b64)
            .map_err(|_| ApiError::BadRequest("Invalid encrypted name".into()))?;
        // Try OAEP first
        let decrypted = self
            .rsa_private
            .decrypt(Oaep::new::<Sha256>(), &bytes)
            .or_else(|_| self.rsa_private.decrypt(Pkcs1v15Encrypt, &bytes))
            .map_err(|_| ApiError::Unauthorized)?;
        let name = String::from_utf8(decrypted)
            .map_err(|_| ApiError::BadRequest("Invalid name encoding".into()))?;
        Ok(name)
    }
}

// Guardrails for display names collected during auth flows.
fn validate_display_name(raw: &str) -> Result<String, ApiError> {
    const MAX_LEN: usize = 48;
    const MIN_LEN: usize = 2;
    const BANNED_SUBSTRINGS: &[&str] = &[
        "admin",
        "root",
        "support",
        "system",
        "owner",
        "fuck",
        "shit",
        "bitch",
        "test",
        "testing",
        "dummy",
        "first name",
        "firstname",
        "last name",
        "lastname",
        "second name",
        "secondname",
        "secondame",
        "zebi",
        "tabon",
        "l7wa",
        "l9alwa",
        "zbi",
        "tbonmok",
        "tbnmk",
        "zmla",
        "klawi",
        "khorza",
        "kalwa",
    ];

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("Name is required".into()));
    }
    let collapsed = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    let tokens: Vec<_> = collapsed.split(' ').collect();
    if tokens.len() != 2 {
        return Err(ApiError::BadRequest(
            "Please enter a first and last name with one space between".into(),
        ));
    }
    if tokens[0].eq_ignore_ascii_case(tokens[1]) {
        return Err(ApiError::BadRequest(
            "First and last name cannot be identical".into(),
        ));
    }
    if tokens.iter().any(|t| t.chars().count() < MIN_LEN || t.chars().count() > 32) {
        return Err(ApiError::BadRequest(
            "Each name part must be between 2 and 32 characters".into(),
        ));
    }
    let len = collapsed.chars().count();
    if len < MIN_LEN || len > MAX_LEN {
        return Err(ApiError::BadRequest("Name length is invalid".into()));
    }
    if collapsed.chars().any(|c| c.is_ascii_digit()) {
        return Err(ApiError::BadRequest("Name cannot contain numbers".into()));
    }
    if !collapsed
        .chars()
        .all(|c| c.is_ascii_alphabetic() || matches!(c, ' ' | '-' | '\'' | '.'))
    {
        return Err(ApiError::BadRequest(
            "Name contains unsupported characters".into(),
        ));
    }
    let lowered = collapsed.to_ascii_lowercase();
    if BANNED_SUBSTRINGS
        .iter()
        .any(|bad| lowered.contains(bad))
    {
        return Err(ApiError::BadRequest(
            "Name contains inappropriate content".into(),
        ));
    }
    let unique_tokens: HashSet<_> = tokens.iter().copied().collect();
    if tokens.len() >= 4 && unique_tokens.len() <= 2 {
        return Err(ApiError::BadRequest(
            "Name is too repetitive to be valid".into(),
        ));
    }
    let letters_only: String = lowered.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let unique_letters: HashSet<_> = letters_only.chars().collect();
    if letters_only.len() >= 10 && unique_letters.len() <= 4 {
        return Err(ApiError::BadRequest(
            "Name appears invalid; please enter a real name".into(),
        ));
    }

    Ok(collapsed)
}

#[derive(Clone)]
struct AuthUser(Claims);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let TypedHeader(Authorization(bearer)) =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
                .await
                .map_err(|_| ApiError::Unauthorized)?;

        let token = bearer.token();
        let app_state = state.clone();
        let data = jsonwebtoken::decode::<Claims>(
            token,
            &app_state.jwt_decoding,
            &app_state.jwt_validation,
        )
        .map_err(|err| {
            error!("jwt decode failed: {err}");
            ApiError::Unauthorized
        })?;

        Ok(AuthUser(data.claims))
    }
}

#[derive(Clone)]
struct SerialAuth(SerialClaims);

#[derive(Deserialize)]
struct UpdateNameRequest {
    first_name: String,
    last_name: String,
    email: String,
    phone: String,
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for SerialAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("x-serial-token")
            .and_then(|h| h.to_str().ok())
            .ok_or(ApiError::Unauthorized)?;

        let data = jsonwebtoken::decode::<SerialClaims>(
            token,
            &state.serial_decoding,
            &state.serial_validation,
        )
        .map_err(|err| {
            error!("serial token decode failed: {err}");
            ApiError::Unauthorized
        })?;

        Ok(SerialAuth(data.claims))
    }
}

fn sign_challenge(id: &str, canonical_name: &str, secret: &[u8]) -> Result<String, ApiError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| ApiError::Internal)?;
    mac.update(id.as_bytes());
    mac.update(canonical_name.as_bytes());
    Ok(mac.finalize().into_bytes().encode_hex::<String>())
}

#[cfg(test)]
mod tests {
    use super::validate_display_name;

    #[test]
    fn display_name_is_normalized_and_validated() {
        let validated = validate_display_name("  Alice   Doe  ").expect("should validate");
        assert_eq!(validated, "Alice Doe");
    }

    #[test]
    fn display_name_rejects_numbers() {
        assert!(validate_display_name("Bob123").is_err());
    }

    #[test]
    fn display_name_rejects_banned_words() {
        assert!(validate_display_name("Root User").is_err());
        assert!(validate_display_name("zebi user").is_err());
        assert!(validate_display_name("test for test").is_err());
        assert!(validate_display_name("awdwdawd awdawdawd awdawda").is_err());
    }

    #[test]
    fn display_name_requires_first_and_last() {
        assert!(validate_display_name("Single").is_err());
        assert!(validate_display_name("Same same").is_err());
        assert!(validate_display_name("John   Doe").is_ok());
        assert!(validate_display_name("Jo Do").is_ok());
    }
}
