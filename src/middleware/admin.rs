use axum::{
    body::Body,
    http::StatusCode,
    response::Response,
    middleware::Next,
    RequestPartsExt,
};
use crate::security::jwt::Claims;

pub async fn admin_only(mut req: axum::http::Request<Body>, next: Next<Body>) -> Result<Response, StatusCode> {
    let claims = req.extensions().get::<Claims>().cloned();
    match claims {
        Some(c) if c.role.as_deref() == Some("admin") => Ok(next.run(req).await),
        _ => Err(StatusCode::FORBIDDEN),
    }
}
