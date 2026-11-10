//! `include/cosmos.h` is cbindgen output and must match the code.
//! Regenerate with `COSMOS_BLESS=1 cargo test -p cosmos-ffi --test header`.

use std::path::Path;

#[test]
fn checked_in_header_matches_cbindgen() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = dir.join("../..");
    let cfg = cbindgen::Config::from_file(dir.join("cbindgen.toml")).unwrap();
    let mut out = vec![];
    cbindgen::Builder::new()
        .with_crate(dir)
        .with_config(cfg)
        .generate()
        .expect("cbindgen")
        .write(&mut out);
    let fresh = String::from_utf8(out).unwrap().replace("\r\n", "\n");
    let path = root.join("include/cosmos.h");
    if std::env::var_os("COSMOS_BLESS").is_some() {
        std::fs::write(&path, &fresh).unwrap();
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default().replace("\r\n", "\n");
    assert!(have == fresh, "include/cosmos.h is stale; rerun with COSMOS_BLESS=1");
}
