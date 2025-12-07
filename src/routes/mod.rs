use axum::{routing::get, Router, middleware::from_fn};
use crate::{state::AppState, middleware};
use crate::security::jwt::Claims;
use axum::Json;
use std::sync::Arc;

mod auth;
mod admin;

pub fn router() -> Router<Arc<AppState>> {
    let auth_layer = from_fn(middleware::auth::auth_middleware);
    let admin_layer = from_fn(middleware::admin::admin_only);
    let rate_layer = from_fn(middleware::rate_limit::rate_limit_with_config);

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
