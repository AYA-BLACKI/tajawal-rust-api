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
use security::config::SecurityConfig;
use infra::supabase::SupabaseCtx;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db = connect().await?;
    let jwt = security::jwt::JwtManager::default();
    let security = SecurityConfig::default();
    let supabase = SupabaseCtx::from_env()?;
    let shared_state = state::AppState::new(db, jwt, security, supabase);

    let app = Router::new()
        .merge(routes::router())
        .route("/health", get(|| async { "OK" }))
        .layer(TraceLayer::new_for_http())
        .with_state(shared_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}
