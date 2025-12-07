use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
    middleware::Next,
};
use std::sync::Arc;

use crate::{security::jwt::JwtManager, state::AppState};

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next<Body>,
) -> Result<Response, StatusCode> {
    let jwt: &JwtManager = &state.jwt;

    if let Some(auth_header) = req.headers().get(axum::http::header::AUTHORIZATION) {
        if let Ok(header_str) = auth_header.to_str() {
            if let Some(token) = header_str.strip_prefix("Bearer ") {
                match jwt.verify(token) {
                    Ok(claims) => {
                        req.extensions_mut().insert(claims);
                        return Ok(next.run(req).await);
                    }
                    Err(_) => return Err(StatusCode::UNAUTHORIZED),
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
