use sqlx::postgres::PgPoolOptions;

pub type Db = sqlx::PgPool;

pub async fn connect() -> anyhow::Result<Db> {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL missing");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;
    Ok(pool)
}
