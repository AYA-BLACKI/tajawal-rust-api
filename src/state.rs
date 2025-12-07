use std::sync::Arc;

use crate::infra::db::Db;
use crate::infra::supabase::SupabaseCtx;
use crate::security::jwt::JwtManager;
use crate::security::config::SecurityConfig;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub jwt: JwtManager,
    pub security: SecurityConfig,
    pub supabase: SupabaseCtx,
}

impl AppState {
    pub fn new(db: Db, jwt: JwtManager, security: SecurityConfig, supabase: SupabaseCtx) -> Arc<Self> {
        Arc::new(Self { db, jwt, security, supabase })
    }
}
