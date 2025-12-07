use anyhow::Context;
use sqlx::postgres::PgPoolOptions;
use tracing::warn;

pub type Db = sqlx::PgPool;

pub async fn connect() -> anyhow::Result<Db> {
    let url = std::env::var("DATABASE_URL")
        .ok()
        .or_else(derive_supabase_db_url)
        .ok_or_else(|| anyhow::anyhow!(
            "DATABASE_URL missing. Set DATABASE_URL or Supabase env vars (SUPABASE_URL + SUPABASE_DB_PASSWORD)."
        ))?;
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .with_context(
            || "failed to connect to database; check DATABASE_URL/Supabase credentials",
        )?;
    Ok(pool)
}

fn derive_supabase_db_url() -> Option<String> {
    let (supabase_url, supabase_source) = supabase_url_from_env().or_else(|| {
        std::env::var("SUPABASE_PROJECT_REF")
            .ok()
            .map(|r| (format!("https://{r}.supabase.co"), "SUPABASE_PROJECT_REF"))
    })?;
    let project_ref = supabase_project_ref(&supabase_url)?;
    let host = std::env::var("SUPABASE_DB_HOST")
        .unwrap_or_else(|_| format!("db.{}.supabase.co", project_ref));
    let port: u16 = std::env::var("SUPABASE_DB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| {
            if host.contains("pooler.supabase.com") {
                6543
            } else {
                5432
            }
        });
    let user = std::env::var("SUPABASE_DB_USER").unwrap_or_else(|_| {
        if host.contains("pooler.supabase.com") {
            format!("postgres.{}", project_ref)
        } else {
            "postgres".to_string()
        }
    });
    let (password, password_source) = supabase_db_password()?;

    if password_source == "SUPABASE_SERVICE_ROLE_KEY" {
        warn!(
            "SUPABASE_DB_PASSWORD missing; falling back to SUPABASE_SERVICE_ROLE_KEY. Set SUPABASE_DB_PASSWORD to your database password."
        );
    }

    warn!(
        "DATABASE_URL missing; deriving Supabase connection using {supabase_source} (host={host}, user={user}, port={port})"
    );

    Some(format!(
        "postgresql://{}:{}@{}:{}/postgres",
        user,
        urlencoding::encode(&password),
        host,
        port
    ))
}

fn supabase_db_password() -> Option<(String, &'static str)> {
    let candidates: [(&str, &str); 4] = [
        ("SUPABASE_DB_PASSWORD", "SUPABASE_DB_PASSWORD"),
        ("DATABASE_PASSWORD", "DATABASE_PASSWORD"),
        ("SUPABASE_PASSWORD", "SUPABASE_PASSWORD"),
        ("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_ROLE_KEY"),
    ];

    for (env, source) in candidates {
        if let Ok(val) = std::env::var(env) {
            if !val.trim().is_empty() {
                return Some((val, source));
            }
        }
    }
    None
}

fn supabase_url_from_env() -> Option<(String, &'static str)> {
    for (key, source) in [
        ("SUPABASE_URL", "SUPABASE_URL"),
        ("VITE_SUPABASE_URL", "VITE_SUPABASE_URL"),
        ("REACT_APP_SUPABASE_URL", "REACT_APP_SUPABASE_URL"),
    ] {
        if let Ok(val) = std::env::var(key) {
            if !val.trim().is_empty() {
                return Some((val, source));
            }
        }
    }
    None
}

fn supabase_project_ref(url: &str) -> Option<String> {
    let host = url.split("://").nth(1)?;
    host.split('.').next().map(|s| s.to_string())
}
