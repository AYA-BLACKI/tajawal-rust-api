use std::collections::HashSet;

use crate::ApiError;

#[derive(Clone, Debug)]
pub struct FinderContext {
    pub name: String,
    pub user_agent: Option<String>,
    pub client_ip: Option<String>,
}

pub fn check_basic(ctx: FinderContext) -> Result<FinderContext, ApiError> {
    const MIN_LEN: usize = 2;
    const MAX_LEN: usize = 48;
    const BANNED_SUBSTRINGS: &[&str] = &[
        "admin",
        "root",
        "support",
        "system",
        "owner",
        "fuck",
        "shit",
        "bitch",
        "zebi",
        "tabon",
        "l7wa",
        "l9alwa",
        "zbi",
        "tbonmok",
        "tbnmk",
        "zmla",
        "klawi",
        "khorza",
        "kalwa",
        "test",
        "testing",
        "dummy",
        "first name",
        "firstname",
        "last name",
        "lastname",
        "second name",
        "secondname",
        "secondame",
    ];

    let trimmed = ctx.name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("Name is required".into()));
    }
    let name = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    let tokens: Vec<_> = name.split(' ').collect();
    if tokens.len() != 2 {
        return Err(ApiError::BadRequest(
            "Please enter a first and last name with one space between".into(),
        ));
    }
    if tokens[0].eq_ignore_ascii_case(tokens[1]) {
        return Err(ApiError::BadRequest(
            "First and last name cannot be identical".into(),
        ));
    }
    if tokens.iter().any(|t| t.chars().count() < MIN_LEN || t.chars().count() > 32) {
        return Err(ApiError::BadRequest(
            "Each name part must be between 2 and 32 characters".into(),
        ));
    }

    let name_len = name.chars().count();
    if name_len < MIN_LEN || name_len > MAX_LEN {
        return Err(ApiError::BadRequest("Name length is invalid".into()));
    }
    if name.chars().any(|c| c.is_ascii_digit()) {
        return Err(ApiError::BadRequest("Name cannot contain numbers".into()));
    }
    if name.chars().any(|c| c.is_control()) || name.contains(['<', '>', '{', '}', '`']) {
        return Err(ApiError::BadRequest(
            "Name contains unsupported characters".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphabetic() || matches!(c, ' ' | '-' | '.' | '\''))
    {
        return Err(ApiError::BadRequest(
            "Name contains unsupported symbols".into(),
        ));
    }
    let lowered = name.to_ascii_lowercase();
    if BANNED_SUBSTRINGS.iter().any(|bad| lowered.contains(bad)) {
        return Err(ApiError::BadRequest(
            "Name contains inappropriate content".into(),
        ));
    }
    let tokens: Vec<_> = lowered.split(' ').collect();
    let unique_tokens: HashSet<_> = tokens.iter().copied().collect();
    if tokens.len() >= 4 && unique_tokens.len() <= 2 {
        return Err(ApiError::BadRequest(
            "Name is too repetitive to be valid".into(),
        ));
    }
    let letters_only: String = lowered.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let unique_letters: HashSet<_> = letters_only.chars().collect();
    if letters_only.len() >= 10 && unique_letters.len() <= 4 {
        return Err(ApiError::BadRequest(
            "Name appears invalid; please enter a real name".into(),
        ));
    }

    let user_agent = normalize_agent(ctx.user_agent)?;
    let client_ip = normalize_ip(ctx.client_ip)?;

    Ok(FinderContext {
        name: name.to_string(),
        user_agent,
        client_ip,
    })
}

fn normalize_agent(agent: Option<String>) -> Result<Option<String>, ApiError> {
    if let Some(raw) = agent {
        let ua = raw.trim();
        if ua.is_empty() {
            return Ok(None);
        }
        if ua.chars().count() > 512 {
            return Err(ApiError::BadRequest("User agent is too long".into()));
        }

        let lowered = ua.to_ascii_lowercase();
        let banned_signals = [
            "curl",
            "wget",
            "postman",
            "insomnia",
            "python-requests",
            "httpclient",
            "okhttp",
            "headless",
            "phantom",
            "selenium",
            "playwright",
            "fetch",
        ];

        if banned_signals.iter().any(|sig| lowered.contains(sig)) {
            return Err(ApiError::Unauthorized);
        }

        return Ok(Some(ua.to_string()));
    }

    Ok(None)
}

fn normalize_ip(ip: Option<String>) -> Result<Option<String>, ApiError> {
    if let Some(raw) = ip {
        let parsed = raw.trim();
        if parsed.is_empty() {
            return Ok(None);
        }
        if parsed.chars().count() > 64 || parsed.chars().any(|c| c.is_control()) {
            return Err(ApiError::BadRequest("Client IP is invalid".into()));
        }
        return Ok(Some(parsed.to_string()));
    }

    Ok(None)
}
