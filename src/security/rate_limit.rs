use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

static RATE_LIMITER: Lazy<Mutex<HashMap<String, (u32, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub fn check(ip: &str, limit: u32, window_secs: u64) -> bool {
    let mut map = RATE_LIMITER.lock().unwrap();
    let entry = map.entry(ip.to_string()).or_insert((0, Instant::now()));
    if entry.1.elapsed() > Duration::from_secs(window_secs) {
        *entry = (0, Instant::now());
    }
    if entry.0 >= limit {
        return false;
    }
    entry.0 += 1;
    true
}
