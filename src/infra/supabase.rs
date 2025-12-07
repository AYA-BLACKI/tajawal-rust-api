use reqwest::Client;
use tracing::warn;

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
        let url = first_env(&[
            "SUPABASE_URL",
            "VITE_SUPABASE_URL",
            "REACT_APP_SUPABASE_URL",
        ])
        .ok_or_else(|| {
            anyhow::anyhow!("Supabase URL missing (set SUPABASE_URL or VITE_SUPABASE_URL)")
        })?;
        let anon_key = first_env(&[
            "SUPABASE_ANON_KEY",
            "SUPABASE_KEY",
            "SUPABASE_PUBLIC_ANON_KEY",
            "SUPABASE_PUBLISHABLE_KEY",
            "VITE_SUPABASE_PUBLISHABLE_DEFAULT_KEY",
            "REACT_APP_SUPABASE_PUBLISHABLE_DEFAULT_KEY",
        ])
        .ok_or_else(|| anyhow::anyhow!("Supabase anon/publishable key missing"))?;
        let service_role_key = first_env(&["SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_KEY", "SERVICE_ROLE_KEY"])
            .unwrap_or_else(|| {
                warn!("SUPABASE_SERVICE_ROLE_KEY not set; service-level Supabase calls will be unavailable");
                String::new()
            });
        let jwt_secret = first_env(&["SUPABASE_JWT_SECRET", "JWT_SECRET", "LEGACY_JWT_SECRET"])
            .or_else(|| {
                if !service_role_key.is_empty() {
                    warn!("SUPABASE_JWT_SECRET missing; falling back to service role key");
                    Some(service_role_key.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("SUPABASE_JWT_SECRET missing"))?;

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

fn first_env(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(val) = std::env::var(key) {
            if !val.trim().is_empty() {
                return Some(val);
            }
        }
    }
    None
}
