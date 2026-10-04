pub mod durable;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(s: &str) -> Self {
        Self(s.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdempotencyStatus {
    Pending,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdempotencyRecord {
    pub transaction_id: String,
    pub tenant_id: String,
    pub registered_at_ms: u64,
    pub expires_at_ms: u64,
    pub status: IdempotencyStatus,
}

#[derive(Debug, Clone)]
pub struct DuplicateDetected {
    pub original_transaction_id: String,
    pub registered_at_ms: u64,
}

pub struct IdempotencyRegistry {
    store: HashMap<(String, String), IdempotencyRecord>,
}

impl IdempotencyRegistry {
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    pub fn check_and_register(
        &mut self,
        tenant_id: &str,
        key: &IdempotencyKey,
        transaction_id: &str,
        window_ms: u64,
    ) -> Result<(), DuplicateDetected> {
        self.purge_expired();

        let map_key = (tenant_id.to_string(), key.as_str().to_string());
        let now = Self::now_ms();
        if let Some(record) = self.store.get(&map_key) {
            if record.expires_at_ms > now {
                return Err(DuplicateDetected {
                    original_transaction_id: record.transaction_id.clone(),
                    registered_at_ms: record.registered_at_ms,
                });
            }
        }

        let expires_at_ms = now.saturating_add(window_ms);
        self.store.insert(
            map_key,
            IdempotencyRecord {
                transaction_id: transaction_id.to_string(),
                tenant_id: tenant_id.to_string(),
                registered_at_ms: now,
                expires_at_ms,
                status: IdempotencyStatus::Pending,
            },
        );
        Ok(())
    }

    pub fn complete(&mut self, tenant_id: &str, key: &IdempotencyKey) {
        let map_key = (tenant_id.to_string(), key.as_str().to_string());
        if let Some(record) = self.store.get_mut(&map_key) {
            record.status = IdempotencyStatus::Completed;
        }
    }

    pub fn fail(&mut self, tenant_id: &str, key: &IdempotencyKey) {
        let map_key = (tenant_id.to_string(), key.as_str().to_string());
        if let Some(record) = self.store.get_mut(&map_key) {
            record.status = IdempotencyStatus::Failed;
        }
    }

    pub fn purge_expired(&mut self) {
        let now = Self::now_ms();
        self.store.retain(|_, record| record.expires_at_ms > now);
    }
}

impl Default for IdempotencyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_new_key_registers_successfully() {
        let mut reg = IdempotencyRegistry::new();
        let key = IdempotencyKey::new("key1");
        assert!(reg.check_and_register("tenant1", &key, "tx1", 1000).is_ok());
    }

    #[test]
    fn test_duplicate_key_same_tenant_rejected() {
        let mut reg = IdempotencyRegistry::new();
        let key = IdempotencyKey::new("key1");
        reg.check_and_register("tenant1", &key, "tx1", 1000).unwrap();
        assert!(reg.check_and_register("tenant1", &key, "tx2", 1000).is_err());
    }

    #[test]
    fn test_same_key_different_tenant_allowed() {
        let mut reg = IdempotencyRegistry::new();
        let key = IdempotencyKey::new("key1");
        assert!(reg.check_and_register("tenant1", &key, "tx1", 1000).is_ok());
        assert!(reg.check_and_register("tenant2", &key, "tx2", 1000).is_ok());
    }

    #[test]
    fn test_expired_key_allows_reregistration() {
        let mut reg = IdempotencyRegistry::new();
        let key = IdempotencyKey::new("key1");
        reg.check_and_register("tenant1", &key, "tx1", 0).unwrap();
        sleep(Duration::from_millis(1));
        assert!(reg.check_and_register("tenant1", &key, "tx2", 1000).is_ok());
    }

    #[test]
    fn test_duplicate_returns_original_transaction_id() {
        let mut reg = IdempotencyRegistry::new();
        let key = IdempotencyKey::new("key1");
        reg.check_and_register("tenant1", &key, "tx1", 1000).unwrap();
        let err = reg.check_and_register("tenant1", &key, "tx2", 1000).unwrap_err();
        assert_eq!(err.original_transaction_id, "tx1");
    }

    #[test]
    fn test_complete_marks_record() {
        let mut reg = IdempotencyRegistry::new();
        let key = IdempotencyKey::new("key1");
        reg.check_and_register("tenant1", &key, "tx1", 1000).unwrap();
        reg.complete("tenant1", &key);
        let map_key = ("tenant1".to_string(), "key1".to_string());
        assert_eq!(reg.store.get(&map_key).unwrap().status, IdempotencyStatus::Completed);
    }

    #[test]
    fn test_purge_removes_expired() {
        let mut reg = IdempotencyRegistry::new();
        let key1 = IdempotencyKey::new("key1");
        let key2 = IdempotencyKey::new("key2");
        reg.check_and_register("tenant1", &key1, "tx1", 0).unwrap();
        reg.check_and_register("tenant1", &key2, "tx2", 1000).unwrap();
        sleep(Duration::from_millis(1));
        reg.purge_expired();
        assert_eq!(reg.store.len(), 1);
        assert!(reg.store.contains_key(&("tenant1".to_string(), "key2".to_string())));
    }
}
