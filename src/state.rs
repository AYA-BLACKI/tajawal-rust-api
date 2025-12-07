use std::sync::Arc;

use crate::infra::db::Db;
use crate::security::jwt::JwtManager;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub jwt: JwtManager,
}

impl AppState {
    pub fn new(db: Db, jwt: JwtManager) -> Arc<Self> {
        Arc::new(Self { db, jwt })
    }
}
