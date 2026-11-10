//! Sessions, channels and the async record API (M1+).

pub const CRATE: &str = "cosmos-core";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, env!("CARGO_PKG_NAME"));
    }
}
