use axum::http::HeaderMap;

pub fn risk_check(ip: Option<&str>, user_agent: Option<&str>) -> bool {
    // Placeholder: allow all, ready for IP reputation and UA heuristics
    if let Some(ip) = ip {
        if ip.starts_with("127.") || ip == "::1" {
            return true;
        }
    }
    let _ = user_agent;
    true
}

pub fn extract_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            return val.split(',').next().map(|s| s.trim().to_string());
        }
    }
    None
}
