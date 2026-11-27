use super::*;

use std::io::Write;

use tempfile::TempDir;

use crate::detect::date::{DateFormat, DateParser};

const LINE_A: &str =
    "Jan 15 10:30:00 server sshd[1]: Failed password for root from 192.168.1.1 port 22\n";
const LINE_B: &str =
    "Jan 15 10:30:01 server sshd[1]: Failed password for root from 192.168.1.2 port 22\n";
const LINE_C: &str =
    "Jan 15 10:30:02 server sshd[1]: Failed password for root from 192.168.1.3 port 22\n";

fn ctx(tx: mpsc::Sender<Failure>) -> ReadCtx {
    ReadCtx {
        jail_id: "test".to_string(),
        matcher: JailMatcher::new(&[r"Failed password for .* from <HOST>".to_string()]).unwrap(),
        date_parser: DateParser::new(DateFormat::Syslog).unwrap(),
        ignore_list: IgnoreList::new(&[], false).unwrap(),
        tx,
        save_ban_logs: false,
    }
}

fn append(path: &PathBuf, bytes: &[u8]) {
    let mut f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
}

/// One poll cycle: rotation check, then read everything available.
fn poll(path: &PathBuf, st: &mut TailState, ctx: &ReadCtx) {
    let (file, identity) = (&mut st.file, &mut st.identity);
    assert!(maybe_rotate(
        path,
        file,
        identity,
        &mut st.carry,
        &mut st.line,
        ctx
    ));
    assert!(read_available(
        &mut st.file,
        &mut st.carry,
        &mut st.line,
        ctx
    ));
}

fn start(path: &PathBuf) -> TailState {
    let file = std::fs::File::open(path).unwrap();
    TailState {
        identity: handle_identity(&file, path),
        file: std::io::BufReader::new(file),
        carry: Vec::new(),
        line: String::new(),
    }
}

fn drain_ips(rx: &mut mpsc::Receiver<Failure>) -> Vec<String> {
    let mut ips = Vec::new();
    while let Ok(f) = rx.try_recv() {
        ips.push(f.ip.to_string());
    }
    ips
}

/// D3: identity captured on an empty file must not turn the first line's
/// arrival into a "rotation" that re-reads (and double-counts) every line.
#[test]
fn test_maybe_rotate_empty_file_then_lines_counted_once() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, b"").unwrap();
    let (tx, mut rx) = mpsc::channel(16);
    let ctx = ctx(tx);
    let mut st = start(&path);

    append(&path, LINE_A.as_bytes());
    poll(&path, &mut st, &ctx);
    append(&path, LINE_B.as_bytes());
    poll(&path, &mut st, &ctx);
    append(&path, LINE_C.as_bytes());
    poll(&path, &mut st, &ctx);
    poll(&path, &mut st, &ctx);

    assert_eq!(
        drain_ips(&mut rx),
        vec!["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    );
}

/// D3: identity captured while the first line is unterminated must not
/// trigger a reopen once that line completes.
#[test]
fn test_maybe_rotate_unterminated_first_line_counted_once() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    let (head, tail) = LINE_A.split_at(30);
    std::fs::write(&path, head).unwrap();
    let (tx, mut rx) = mpsc::channel(16);
    let ctx = ctx(tx);
    let mut st = start(&path);
    poll(&path, &mut st, &ctx);

    append(&path, tail.as_bytes());
    poll(&path, &mut st, &ctx);
    append(&path, LINE_B.as_bytes());
    poll(&path, &mut st, &ctx);
    poll(&path, &mut st, &ctx);

    assert_eq!(drain_ips(&mut rx), vec!["192.168.1.1", "192.168.1.2"]);
}

/// D3: a genuine truncate-and-rewrite is still detected as a rotation.
#[test]
fn test_maybe_rotate_truncation_still_reopens() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, format!("{LINE_A}{LINE_B}")).unwrap();
    let (tx, mut rx) = mpsc::channel(16);
    let ctx = ctx(tx);
    let mut st = start(&path);
    poll(&path, &mut st, &ctx);
    assert_eq!(drain_ips(&mut rx).len(), 2);

    std::fs::write(&path, LINE_C).unwrap();
    poll(&path, &mut st, &ctx);
    assert_eq!(drain_ips(&mut rx), vec!["192.168.1.3"]);
}

/// D5: the startup identity describes the open handle, not whatever file
/// the path names by now.
#[cfg(unix)]
#[test]
fn test_handle_identity_describes_open_handle_not_path() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, LINE_A).unwrap();
    let file = std::fs::File::open(&path).unwrap();
    let replacement = dir.path().join("new.log");
    std::fs::write(&replacement, LINE_B).unwrap();
    std::fs::rename(&replacement, &path).unwrap();

    let id = handle_identity(&file, &path).unwrap();
    assert_eq!(Some(id.clone()), FileIdentity::from_handle(&file));
    let path_id = FileIdentity::from_file(&path).unwrap();
    assert!(id.is_rotated(&path_id), "rotation must remain detectable");
}

/// D5: a missing identity is retried on the next rotation check instead of
/// disabling rotation detection forever.
#[test]
fn test_maybe_rotate_retries_missing_identity() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("auth.log");
    std::fs::write(&path, LINE_A).unwrap();
    let (tx, _rx) = mpsc::channel(16);
    let ctx = ctx(tx);
    let mut st = start(&path);
    st.identity = None;

    poll(&path, &mut st, &ctx);
    assert!(st.identity.is_some(), "identity must be re-captured");
}
