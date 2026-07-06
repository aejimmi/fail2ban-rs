use super::*;

use std::path::Path;

#[test]
fn test_load_db_missing_file_returns_none() {
    let result = load_db(Path::new("/nonexistent/path/GeoLite2-ASN.mmdb"), "ASN");
    assert!(result.is_none(), "missing file should return None");
}

#[test]
fn test_load_db_directory_returns_none() {
    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let result = load_db(dir.path(), "ASN");
    assert!(result.is_none(), "directory path should return None");
}

#[cfg(unix)]
#[test]
fn test_load_db_world_writable_returns_none() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let path = dir.path().join("test.mmdb");
    std::fs::write(&path, b"").expect("failed to create temp file");

    let mut perms = std::fs::metadata(&path)
        .expect("failed to stat temp file")
        .permissions();
    perms.set_mode(0o666); // world-writable
    std::fs::set_permissions(&path, perms).expect("failed to set permissions");

    let result = load_db(&path, "ASN");
    assert!(
        result.is_none(),
        "world-writable .mmdb file must be rejected"
    );
}

#[cfg(unix)]
#[test]
fn test_load_db_valid_fixture_loads() {
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/GeoLite2-ASN-Test.mmdb");
    let result = load_db(&fixture, "ASN");
    assert!(
        result.is_some(),
        "valid, normally-permissioned fixture should load successfully"
    );
}
