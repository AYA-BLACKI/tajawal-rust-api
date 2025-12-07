use axum::{
    body::Body,
    http::Request,
    response::Response,
    middleware::Next,
    http::StatusCode,
    extract::State,
};
use dashmap::DashMap;
use std::time::{Duration, Instant};
use std::sync::Arc;
use once_cell::sync::Lazy;

use crate::state::AppState;

#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_secs: u64,
}

#[derive(Default)]
struct Bucket {
    count: u32,
    window_start: Instant,
}

static BUCKETS: Lazy<DashMap<String, Bucket>> = Lazy::new(DashMap::new);

pub async fn rate_limit_with_config(
    State(_state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next<Body>,
    config: RateLimitConfig,
) -> Result<Response, (StatusCode, String)> {
    let path = req.uri().path().to_string();
    let ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let key = format!("{}:{}", ip, path);

    let mut entry = BUCKETS.entry(key).or_insert_with(|| Bucket {
        count: 0,
        window_start: Instant::now(),
    });

    if entry.window_start.elapsed() > Duration::from_secs(config.window_secs) {
        entry.count = 0;
        entry.window_start = Instant::now();
    }

    if entry.count >= config.max_requests {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".into()));
    }

    entry.count += 1;

    Ok(next.run(req).await)
}
