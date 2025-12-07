use sqlx::postgres::PgPoolOptions;
use tracing::warn;

pub type Db = sqlx::PgPool;

pub async fn connect() -> anyhow::Result<Db> {
    let url = std::env::var("DATABASE_URL")
        .ok()
        .or_else(derive_supabase_db_url)
        .or_else(fallback_pooler_url)
        .expect("DATABASE_URL missing");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;
    Ok(pool)
}

fn derive_supabase_db_url() -> Option<String> {
    let supabase_url = std::env::var("SUPABASE_URL").ok()?;
    let service_role = std::env::var("SUPABASE_SERVICE_ROLE_KEY").ok()?;
    let host = supabase_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let db_host = format!("db.{}", host);
    let password = urlencoding::encode(&service_role);
    let derived = format!(
        "postgresql://postgres:{}@{}:{}/postgres",
        password,
        db_host,
        5432
    );
    warn!("DATABASE_URL missing; derived Supabase DB URL from SUPABASE_URL");
    Some(derived)
}

fn fallback_pooler_url() -> Option<String> {
    // User-provided pooled connection string (Supabase pooler)
    // host: aws-1-eu-west-3.pooler.supabase.com
    // port: 6543
    // user: postgres.bucxjpuvlsgdmxlmhxnj
    // database: postgres
    let url = "postgresql://postgres.bucxjpuvlsgdmxlmhxnj:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJ1Y3hqcHV2bHNnZG14bG1oeG5qIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2Mjg3OTI3MSwiZXhwIjoyMDc4NDU1MjcxfQ.WX0-MzLYiWZVA-dTUDy9gFC6qIJxA-8D35Bffnt9_nk@aws-1-eu-west-3.pooler.supabase.com:6543/postgres".to_string();
    warn!("DATABASE_URL missing; using hardcoded pooler URL for Supabase");
    Some(url)
}
