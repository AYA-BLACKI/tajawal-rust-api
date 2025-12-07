#[derive(Clone)]
pub struct SecurityConfig {
    pub access_cookie_name: String,
    pub refresh_cookie_name: String,
    pub secure_cookies: bool,
    pub same_site_strict: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            access_cookie_name: "access_token".into(),
            refresh_cookie_name: "refresh_token".into(),
            secure_cookies: true,
            same_site_strict: true,
        }
    }
}
