use jsonwebtoken::{encode, decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub role: Option<String>,
    pub jti: String,
}

#[derive(Clone)]
pub struct JwtManager {
    secret: String,
    ttl: Duration,
}

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("token error: {0}")]
    Token(String),
}

impl Default for JwtManager {
    fn default() -> Self {
        let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-change-me".into());
        Self {
            secret,
            ttl: Duration::minutes(5),
        }
    }
}

impl JwtManager {
    pub fn issue_access(&self, subject: &str, role: Option<String>) -> Result<String, JwtError> {
        let now = OffsetDateTime::now_utc();
        let claims = Claims {
            sub: subject.to_string(),
            exp: (now + self.ttl).unix_timestamp(),
            iat: now.unix_timestamp(),
            role,
            jti: uuid::Uuid::new_v4().to_string(),
        };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| JwtError::Token(e.to_string()))
    }

    pub fn verify(&self, token: &str) -> Result<Claims, JwtError> {
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        )
        .map_err(|e| JwtError::Token(e.to_string()))?;
        Ok(data.claims)
    }
}
