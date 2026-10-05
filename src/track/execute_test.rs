use super::*;

#[test]
fn test_persist_then_apply_failed_write_skips_apply() {
    let mut indexed_and_counted = false;
    let result = persist_then_apply(
        &mut indexed_and_counted,
        |_| Err(Error::persistence("injected WAL failure")),
        |state| *state = true,
    );
    assert!(matches!(result, Err(Error::Persistence { .. })));
    assert!(!indexed_and_counted);
}

#[test]
fn test_persist_then_apply_successful_write_applies() {
    let mut indexed_and_counted = false;
    let result = persist_then_apply(
        &mut indexed_and_counted,
        |_| Ok(()),
        |state| {
            *state = true;
            7
        },
    );
    assert_eq!(result.unwrap(), 7);
    assert!(indexed_and_counted);
}
