//! Optional Steam signaling and SDR relay path (M3).

pub const CRATE: &str = "cosmos-steam";

#[cfg(test)]
mod tests {
    #[test]
    fn crate_name() {
        assert_eq!(super::CRATE, env!("CARGO_PKG_NAME"));
    }
}
