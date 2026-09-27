use super::*;

use tempfile::TempDir;

fn write(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    path
}

// --- from_file ---------------------------------------------------------

#[test]
fn test_from_file_missing_returns_none() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("nope.log");
    assert!(FileIdentity::from_file(&path).is_none());
}

#[test]
fn test_from_file_stable_across_reads() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"one\ntwo\n");
    let a = FileIdentity::from_file(&path).unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert_eq!(a, b);
}

#[test]
fn test_from_file_empty_file_has_identity() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "empty.log", b"");
    // An empty file must still fingerprint (empty first-line hash), not None.
    assert!(FileIdentity::from_file(&path).is_some());
}

// --- from_handle (unix) --------------------------------------------------

#[cfg(unix)]
#[test]
fn test_from_handle_empty_file() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "empty.log", b"");
    let file = std::fs::File::open(&path).unwrap();
    let id = FileIdentity::from_handle(&file).expect("empty file must fingerprint");
    assert_eq!(id.size, 0);
}

#[cfg(unix)]
#[test]
fn test_from_handle_no_trailing_newline_hashes_whole_short_file() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"no newline here");
    let file = std::fs::File::open(&path).unwrap();
    let id = FileIdentity::from_handle(&file).unwrap();
    // Reading the same short, newline-less content twice must match.
    let file2 = std::fs::File::open(&path).unwrap();
    let id2 = FileIdentity::from_handle(&file2).unwrap();
    assert_eq!(id, id2);
}

#[cfg(unix)]
#[test]
fn test_from_handle_does_not_move_file_cursor() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"one\ntwo\nthree\n");
    let mut file = std::fs::File::open(&path).unwrap();
    // Seek to a nonzero offset first.
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(4)).unwrap();
    let _ = FileIdentity::from_handle(&file);
    let mut rest = String::new();
    file.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "two\nthree\n", "from_handle must not move the cursor");
}

#[cfg(unix)]
#[test]
fn test_from_handle_line_exactly_at_buffer_boundary() {
    // A first line with no newline, exactly MAX_LINE_LEN + 1 bytes long — the
    // read loop must fill the buffer completely without panicking on the
    // final `read_at` call (filled == buf.len()).
    let dir = TempDir::new().unwrap();
    let content = vec![b'x'; MAX_LINE_LEN + 1];
    let path = write(&dir, "big.log", &content);
    let file = std::fs::File::open(&path).unwrap();
    let id = FileIdentity::from_handle(&file).expect("must fingerprint a maxed-out first line");
    assert_eq!(id.size, (MAX_LINE_LEN + 1) as u64);
}

#[cfg(unix)]
#[test]
fn test_from_handle_matches_from_file_when_unrotated() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"first\nsecond\n");
    let file = std::fs::File::open(&path).unwrap();
    let via_handle = FileIdentity::from_handle(&file).unwrap();
    let via_path = FileIdentity::from_file(&path).unwrap();
    assert_eq!(via_handle, via_path);
}

// --- can_resume ----------------------------------------------------------

#[test]
fn test_can_resume_same_file_offset_within_size() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"0123456789");
    let old = FileIdentity::from_file(&path).unwrap();
    let current = FileIdentity::from_file(&path).unwrap();
    assert!(old.can_resume(&current, 5));
    assert!(old.can_resume(&current, 10), "offset == size is resumable");
}

#[test]
fn test_can_resume_offset_beyond_current_size_is_false() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"0123456789");
    let old = FileIdentity::from_file(&path).unwrap();
    let current = FileIdentity::from_file(&path).unwrap();
    assert!(!old.can_resume(&current, 11));
}

#[test]
fn test_can_resume_different_first_line_is_false() {
    let dir = TempDir::new().unwrap();
    let path_a = write(&dir, "a.log", b"AAAA\nrest\n");
    let path_b = write(&dir, "b.log", b"BBBB\nrest\n");
    let old = FileIdentity::from_file(&path_a).unwrap();
    let current = FileIdentity::from_file(&path_b).unwrap();
    assert!(!old.can_resume(&current, 0));
}

#[cfg(unix)]
#[test]
fn test_can_resume_different_inode_is_false_even_if_hash_matches() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"same\n");
    let old = FileIdentity::from_file(&path).unwrap();
    // Keep the old inode allocated while creating its replacement. Deleting
    // the file first allows the filesystem to reuse its inode immediately.
    std::fs::rename(&path, dir.path().join("rotated.log")).unwrap();
    let current_path = write(&dir, "a.log", b"same\n");
    let current = FileIdentity::from_file(&current_path).unwrap();
    assert_ne!(old.inode, current.inode);
    assert!(
        !old.can_resume(&current, 0),
        "identical content on a new inode must not be resumable"
    );
}

// --- is_rotated ------------------------------------------------------------

#[test]
fn test_is_rotated_identical_file_is_false() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"one\ntwo\n");
    let a = FileIdentity::from_file(&path).unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(!a.is_rotated(&b));
}

#[test]
fn test_is_rotated_grown_same_first_line_is_false() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"one\n");
    let a = FileIdentity::from_file(&path).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap();
    std::io::Write::write_all(&mut f, b"two\n").unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(!a.is_rotated(&b));
}

#[test]
fn test_is_rotated_shrunk_is_true() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"one\ntwo\n");
    let a = FileIdentity::from_file(&path).unwrap();
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.set_len(4).unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(a.is_rotated(&b));
}

#[test]
fn test_is_rotated_different_first_line_same_size_is_true() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"AAAA\nrest\n");
    let a = FileIdentity::from_file(&path).unwrap();
    std::fs::write(&path, b"BBBB\nrest\n").unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(a.is_rotated(&b));
}

#[cfg(unix)]
#[test]
fn test_is_rotated_replaced_file_different_inode_is_true() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"same\n");
    let a = FileIdentity::from_file(&path).unwrap();
    let tmp = dir.path().join("new.log");
    std::fs::write(&tmp, b"same\n").unwrap();
    std::fs::rename(&tmp, &path).unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(
        a.is_rotated(&b),
        "identical content on a new inode is still a rotation"
    );
}

// --- unknown first line (D3) ---------------------------------------------

#[test]
fn test_is_rotated_empty_then_first_line_is_false() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"");
    let a = FileIdentity::from_file(&path).unwrap();
    assert!(a.first_line_hash.is_none());
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"first\n"))
        .unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(b.first_line_hash.is_some());
    assert!(!a.is_rotated(&b), "first line completing is growth");
}

#[test]
fn test_is_rotated_unterminated_then_completed_is_false() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"partial");
    let a = FileIdentity::from_file(&path).unwrap();
    assert!(a.first_line_hash.is_none());
    std::fs::write(&path, b"partial line\nmore\n").unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(!a.is_rotated(&b));
}

#[test]
fn test_is_rotated_complete_then_unterminated_is_true() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"one\n");
    let a = FileIdentity::from_file(&path).unwrap();
    std::fs::write(&path, b"a much longer unterminated line").unwrap();
    let b = FileIdentity::from_file(&path).unwrap();
    assert!(a.is_rotated(&b));
}

#[test]
fn test_can_resume_unknown_first_line_accepts_completed_line() {
    let dir = TempDir::new().unwrap();
    let path = write(&dir, "a.log", b"");
    let old = FileIdentity::from_file(&path).unwrap();
    std::fs::write(&path, b"first\n").unwrap();
    let current = FileIdentity::from_file(&path).unwrap();
    assert!(old.can_resume(&current, 0));
    assert!(
        !current.can_resume(&old, 0),
        "known -> unknown is not resumable"
    );
}
