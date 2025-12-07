use axum::http::HeaderMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::infra::db::Db;
use sqlx::Row;

pub enum RiskDecision {
    Allow,
    Block(&'static str),
}

pub async fn risk_check(
    db: &Db,
    user_id: Option<Uuid>,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> RiskDecision {
    // Banned users
    if let Some(uid) = user_id {
        if let Ok(Some(_)) = sqlx::query("SELECT 1 FROM banned_users WHERE user_id = $1")
            .bind(uid)
            .fetch_optional(db)
            .await
        {
            return RiskDecision::Block("user_banned");
        }
    }

    // Banned IP
    if let Some(ip) = ip {
        if let Ok(Some(_)) = sqlx::query("SELECT 1 FROM banned_users WHERE ip = $1")
            .bind(ip)
            .fetch_optional(db)
            .await
        {
            return RiskDecision::Block("ip_banned");
        }
    }

    // Brute force: recent failures
    if let Some(uid) = user_id {
        if let Ok(row) =
            sqlx::query("SELECT failed_login_count, last_failed_at FROM users WHERE id = $1")
                .bind(uid)
                .fetch_optional(db)
                .await
        {
            if let Some(r) = row {
                let count: i64 = r.get("failed_login_count");
                let last_failed: Option<OffsetDateTime> = r.get("last_failed_at");
                if count >= 5 {
                    if let Some(ts) = last_failed {
                        if ts > OffsetDateTime::now_utc() - time::Duration::minutes(15) {
                            return RiskDecision::Block("too_many_failures");
                        }
                    }
                }
            }
        }
    }

    // Basic UA/IP heuristics placeholder
    let _ = user_agent;
    let _ = ip;
    RiskDecision::Allow
}

pub fn extract_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(val) = forwarded.to_str() {
            return val.split(',').next().map(|s| s.trim().to_string());
        }
    }
    None
}
