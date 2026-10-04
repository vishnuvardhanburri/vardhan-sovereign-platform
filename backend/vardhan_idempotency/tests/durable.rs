use std::time::{SystemTime, UNIX_EPOCH};
use vardhan_idempotency::durable::DurableIdempotencyRegistry;
use vardhan_idempotency::IdempotencyKey;

fn temp_path() -> std::path::PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("vardhan-idempotency-{stamp}.json"))
}

#[test]
fn durable_registry_rejects_duplicate_after_reopen() {
    let path = temp_path();
    let key = IdempotencyKey::new("request-1");
    let first = DurableIdempotencyRegistry::new(&path);
    first.check_and_register("tenant-a", &key, "tx-1", 60_000).unwrap().unwrap();
    drop(first);

    let reopened = DurableIdempotencyRegistry::new(&path);
    let duplicate = reopened.check_and_register("tenant-a", &key, "tx-2", 60_000).unwrap().unwrap_err();
    assert_eq!(duplicate.original_transaction_id, "tx-1");

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn durable_registry_is_tenant_isolated() {
    let path = temp_path();
    let key = IdempotencyKey::new("request-1");
    let registry = DurableIdempotencyRegistry::new(&path);
    registry.check_and_register("tenant-a", &key, "tx-a", 60_000).unwrap().unwrap();
    registry.check_and_register("tenant-b", &key, "tx-b", 60_000).unwrap().unwrap();

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
}

#[test]
fn failed_record_can_be_reused() {
    let path = temp_path();
    let key = IdempotencyKey::new("request-1");
    let registry = DurableIdempotencyRegistry::new(&path);
    registry.check_and_register("tenant-a", &key, "tx-a", 60_000).unwrap().unwrap();
    registry.fail("tenant-a", &key).unwrap();
    registry.check_and_register("tenant-a", &key, "tx-b", 60_000).unwrap().unwrap();

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
}
