use axum::{http::Request, http::StatusCode, middleware::Next, response::Response};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::state::AppState;

const MAX_REQUESTS: u32 = 10;
const WINDOW_SECS: u64 = 60;

struct Bucket {
    count: u32,
    window_start: Instant,
}

static BUCKETS: Lazy<DashMap<String, Bucket>> = Lazy::new(DashMap::new);

pub async fn rate_limit_with_config(
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let _state = req.extensions().get::<Arc<AppState>>().cloned();
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

    if entry.window_start.elapsed() > Duration::from_secs(WINDOW_SECS) {
        entry.count = 0;
        entry.window_start = Instant::now();
    }

    if entry.count >= MAX_REQUESTS {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".into()));
    }

    entry.count += 1;

    Ok(next.run(req).await)
}
