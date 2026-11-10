//! C ABI over the SDK (M5).

pub const CRATE: &str = "cosmos-ffi";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, env!("CARGO_PKG_NAME"));
    }
}
