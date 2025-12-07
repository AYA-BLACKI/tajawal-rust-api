use axum::{routing::get, Router, middleware::from_fn_with_state};
use crate::{state::AppState, middleware};
use crate::security::jwt::Claims;
use axum::Json;

mod auth;

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(auth::router())
        .route(
            "/me",
            get(me).layer(from_fn_with_state(
                |state: std::sync::Arc<AppState>, req, next| middleware::auth::auth_middleware(state, req, next),
            )),
        )
}

async fn me(
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
) -> Json<Claims> {
    Json(claims)
}
