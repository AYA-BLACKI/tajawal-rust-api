/// Forwarder for encrypted OTP tokens; here it simply passes through,
/// but is kept as a hook for future routing or auditing.
pub fn forward_to_decrypter(encrypted: &str) -> String {
    encrypted.to_string()
}
