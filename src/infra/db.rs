use sqlx::postgres::PgPoolOptions;
use tracing::warn;

pub type Db = sqlx::PgPool;

pub async fn connect() -> anyhow::Result<Db> {
    let url = std::env::var("DATABASE_URL").ok().or_else(derive_supabase_db_url).expect("DATABASE_URL missing");
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
