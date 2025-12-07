use reqwest::Client;

#[derive(Clone)]
pub struct SupabaseCtx {
    pub url: String,
    pub anon_key: String,
    pub service_role_key: String,
    pub jwt_secret: String,
    pub http: Client,
}

impl SupabaseCtx {
    pub fn from_env() -> anyhow::Result<Self> {
        let url = std::env::var("SUPABASE_URL")
            .map_err(|_| anyhow::anyhow!("SUPABASE_URL missing"))?;
        let anon_key = std::env::var("SUPABASE_ANON_KEY")
            .map_err(|_| anyhow::anyhow!("SUPABASE_ANON_KEY missing"))?;
        let service_role_key = std::env::var("SUPABASE_SERVICE_ROLE_KEY")
            .map_err(|_| anyhow::anyhow!("SUPABASE_SERVICE_ROLE_KEY missing"))?;
        let jwt_secret = std::env::var("SUPABASE_JWT_SECRET")
            .map_err(|_| anyhow::anyhow!("SUPABASE_JWT_SECRET missing"))?;

        let http = Client::builder()
            .user_agent("tajawal-rust-backend")
            .build()?;

        Ok(Self {
            url,
            anon_key,
            service_role_key,
            jwt_secret,
            http,
        })
    }

    pub fn service_auth_header(&self) -> String {
        format!("Bearer {}", self.service_role_key)
    }
}
