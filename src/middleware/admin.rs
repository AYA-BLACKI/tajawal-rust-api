use axum::{
    http::StatusCode,
    response::Response,
    middleware::Next,
};
use crate::security::jwt::Claims;
use crate::state::AppState;
use std::sync::Arc;
use sqlx::Row;

pub async fn admin_only(
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let state = req
        .extensions()
        .get::<Arc<AppState>>()
        .cloned()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let claims = req.extensions().get::<Claims>().cloned();
    let Some(c) = claims else { return Err(StatusCode::UNAUTHORIZED); };

    let row = sqlx::query("SELECT role FROM users WHERE id = $1")
        .bind(&c.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match row {
        Some(r) => {
            let role: String = r.get("role");
            if role == "admin" {
                Ok(next.run(req).await)
            } else {
                Err(StatusCode::FORBIDDEN)
            }
        }
        None => Err(StatusCode::UNAUTHORIZED),
    }
}
