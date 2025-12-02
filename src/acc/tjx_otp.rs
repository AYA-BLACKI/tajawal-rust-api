use rand::Rng;

/// Generate a simple 6-digit OTP as a string.
pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(0..1_000_000);
    format!("{code:06}")
}
