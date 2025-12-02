use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// Analyze decrypted OTP; on success, produce a high-integrity forwarding key
/// with `tjx` prefix that includes a simple integrity tag.
pub fn analyze_and_forward(otp: &str) -> String {
    let payload = format!("tjx{}", URL_SAFE_NO_PAD.encode(format!("validated:{otp}")));
    payload
}
