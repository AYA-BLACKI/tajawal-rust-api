mod routes;
mod security;
mod infra;
mod middleware;
mod domain;
mod state;

use axum::{routing::get, Router};
use infra::db::connect;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db = connect().await?;
    let jwt = security::jwt::JwtManager::default();
    let shared_state = state::AppState::new(db, jwt);

    let app = Router::new()
        .merge(routes::router())
        .route("/health", get(|| async { "OK" }))
        .layer(TraceLayer::new_for_http())
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr).serve(app.into_make_service()).await?;
    Ok(())
}
