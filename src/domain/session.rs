use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Option<String>,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub mfa_passed: bool,
    pub suspicious: bool,
}
