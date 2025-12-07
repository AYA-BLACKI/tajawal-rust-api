use axum::{
    body::Body,
    http::StatusCode,
    response::Response,
    middleware::Next,
    RequestPartsExt,
};
use crate::security::jwt::Claims;
use crate::state::AppState;
use std::sync::Arc;
use sqlx::Row;

pub async fn admin_only(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    mut req: axum::http::Request<Body>,
    next: Next<Body>,
) -> Result<Response, StatusCode> {
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
