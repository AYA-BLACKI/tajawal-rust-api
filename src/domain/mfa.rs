use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSecret {
    pub user_id: Uuid,
    pub secret_b32: String,
    pub enabled: bool,
    pub created_at: OffsetDateTime,
}
