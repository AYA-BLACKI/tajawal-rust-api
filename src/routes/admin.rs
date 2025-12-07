use axum::{Router, routing::get, Json};
use serde::Serialize;
use std::sync::Arc;
use crate::state::AppState;
use crate::security::jwt::Claims;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/users", get(list_users))
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    build: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok", build: "secure-backend" })
}

#[derive(Serialize)]
struct UserEntry {
    id: String,
    email: String,
    role: String,
}

async fn list_users(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> Result<Json<Vec<UserEntry>>, (axum::http::StatusCode, String)> {
    let rows = sqlx::query("SELECT id, email, role FROM users ORDER BY created_at DESC LIMIT 20")
        .fetch_all(&state.db)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let data = rows.into_iter().map(|r| UserEntry {
        id: r.get::<uuid::Uuid, _>("id").to_string(),
        email: r.get("email"),
        role: r.get("role"),
    }).collect();

    Ok(Json(data))
}
