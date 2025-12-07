use axum::{http::StatusCode, middleware::Next, response::Response};
use std::sync::Arc;

use crate::{security::jwt::JwtManager, state::AppState};
use cookie::Cookie;

pub async fn auth_middleware(
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let state = req
        .extensions()
        .get::<Arc<AppState>>()
        .cloned()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let jwt: &JwtManager = &state.jwt;

    if let Some(token) = bearer_from_header(req.headers()) {
        if let Ok(claims) = jwt.verify(&token) {
            req.extensions_mut().insert(claims);
            return Ok(next.run(req).await);
        }
    }

    if let Some(token) = cookie_token(req.headers(), &state.security.access_cookie_name) {
        if let Ok(claims) = jwt.verify(&token) {
            req.extensions_mut().insert(claims);
            return Ok(next.run(req).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

fn bearer_from_header(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn cookie_token(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in cookie_header.split(';') {
        if let Ok(parsed) = Cookie::parse(part.trim().to_string()) {
            if parsed.name() == name {
                return Some(parsed.value().to_string());
            }
        }
    }
    None
}
