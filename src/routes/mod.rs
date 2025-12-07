use axum::{routing::get, Router, middleware::from_fn_with_state};
use crate::{state::AppState, middleware};
use crate::security::jwt::Claims;
use axum::Json;
use std::sync::Arc;

mod auth;
mod admin;

pub fn router() -> Router<Arc<AppState>> {
    let auth_layer = from_fn_with_state(
        |state: Arc<AppState>, req, next| middleware::auth::auth_middleware(state, req, next),
    );
    let admin_layer = from_fn_with_state(
        |state: Arc<AppState>, req, next| middleware::admin::admin_only(state, req, next),
    );

    let rate_cfg = middleware::rate_limit::RateLimitConfig { max_requests: 10, window_secs: 60 };
    let rate_layer = from_fn_with_state(move |state: Arc<AppState>, req, next| {
        middleware::rate_limit::rate_limit_with_config(state, req, next, rate_cfg.clone())
    });

    Router::new()
        .merge(auth::router().layer(rate_layer))
        .route("/me", get(me).layer(auth_layer.clone()))
        .route("/dashboard", get(me).layer(auth_layer.clone()))
        .nest(
            "/admin",
            admin::router()
                .layer(admin_layer)
                .layer(auth_layer),
        )
}

async fn me(
    axum::extract::Extension(claims): axum::extract::Extension<Claims>,
) -> Json<Claims> {
    Json(claims)
}
