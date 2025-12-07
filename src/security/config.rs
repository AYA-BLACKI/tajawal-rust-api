use cookie::SameSite;
use tracing::warn;

#[derive(Clone)]
pub struct SecurityConfig {
    pub access_cookie_name: String,
    pub refresh_cookie_name: String,
    pub secure_cookies: bool,
    pub same_site: SameSite,
}

impl SecurityConfig {
    pub fn from_env() -> Self {
        let access_cookie_name =
            env_string("ACCESS_COOKIE_NAME").unwrap_or_else(|| "access_token".into());
        let refresh_cookie_name =
            env_string("REFRESH_COOKIE_NAME").unwrap_or_else(|| "refresh_token".into());

        let mut secure_cookies = env_bool("COOKIE_SECURE").unwrap_or(true);
        let same_site = env_same_site().unwrap_or(SameSite::None);

        if same_site == SameSite::None && !secure_cookies {
            warn!("SameSite=None requires secure cookies; forcing COOKIE_SECURE=true");
            secure_cookies = true;
        }

        SecurityConfig {
            access_cookie_name,
            refresh_cookie_name,
            secure_cookies,
            same_site,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn env_bool(key: &str) -> Option<bool> {
    std::env::var(key).ok().and_then(|v| {
        let val = v.trim().to_ascii_lowercase();
        match val.as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        }
    })
}

fn env_same_site() -> Option<SameSite> {
    std::env::var("COOKIE_SAMESITE").ok().and_then(|v| {
        match v.trim().to_ascii_lowercase().as_str() {
            "none" => Some(SameSite::None),
            "lax" => Some(SameSite::Lax),
            "strict" => Some(SameSite::Strict),
            _ => None,
        }
    })
}
