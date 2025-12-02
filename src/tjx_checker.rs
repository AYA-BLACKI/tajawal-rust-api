use crate::ApiError;
use crate::tjx_finder::FinderContext;

#[derive(Clone, Debug)]
pub struct CheckedContext {
    pub canonical_name: String,
    pub user_agent: Option<String>,
    pub client_ip: Option<String>,
}

pub fn enforce(ctx: FinderContext) -> Result<CheckedContext, ApiError> {
    let canonical = ctx
        .name
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    Ok(CheckedContext {
        canonical_name: canonical,
        user_agent: ctx.user_agent,
        client_ip: ctx.client_ip,
    })
}
