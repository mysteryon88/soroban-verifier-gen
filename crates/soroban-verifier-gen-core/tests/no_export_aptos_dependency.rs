use std::fs;

#[test]
fn core_does_not_depend_on_old_format_crate() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let cargo_toml = fs::read_to_string(format!("{manifest_dir}/Cargo.toml")).unwrap();
    let lib_rs = fs::read_to_string(format!("{manifest_dir}/src/lib.rs")).unwrap();
    let old_name = ["export", "ap", "tos", "verifier", "core"];
    let old_package = old_name.join("-");
    let old_import = old_name.join("_");

    assert!(!cargo_toml.contains(&old_package));
    assert!(!lib_rs.contains(&old_import));
}
