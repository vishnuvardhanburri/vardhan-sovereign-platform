//! Durable idempotency registry for API/transaction ingress.
//!
//! This layer survives process restart and serializes writers with an OS lock.
//! For multi-node deployments, use a shared strongly-consistent filesystem or
//! replace this adapter with a transactional database implementation.

use crate::{DuplicateDetected, IdempotencyKey, IdempotencyRecord, IdempotencyStatus};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, thiserror::Error)]
pub enum DurableIdempotencyError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("lock acquisition timed out")]
    LockTimeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DurableRecord {
    key: String,
    record: IdempotencyRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DurableState {
    records: Vec<DurableRecord>,
}

/// Restart-safe idempotency store with atomic check/register semantics.
pub struct DurableIdempotencyRegistry {
    path: PathBuf,
    lock_path: PathBuf,
}

impl DurableIdempotencyRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let lock_path = path.with_extension("lock");
        Self { path, lock_path }
    }

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
    }

    fn load(&self) -> Result<DurableState, DurableIdempotencyError> {
        if !self.path.exists() {
            return Ok(DurableState::default());
        }
        Ok(serde_json::from_slice(&fs::read(&self.path)?)?)
    }

    fn save(&self, state: &DurableState) -> Result<(), DurableIdempotencyError> {
        let tmp = self.path.with_extension("state.tmp");
        let bytes = serde_json::to_vec_pretty(state)?;
        let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&tmp)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&tmp, perms)?;
        }
        fs::rename(tmp, &self.path)?;
        Ok(())
    }

    fn with_lock<T>(&self, mut operation: impl FnMut() -> Result<T, DurableIdempotencyError>) -> Result<T, DurableIdempotencyError> {
        for _ in 0..200 {
            match OpenOptions::new().write(true).create_new(true).open(&self.lock_path) {
                Ok(mut lock) => {
                    let _ = lock.write_all(b"vardhan-idempotency-lock");
                    let result = operation();
                    let _ = fs::remove_file(&self.lock_path);
                    return result;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(DurableIdempotencyError::LockTimeout)
    }

    pub fn check_and_register(
        &self,
        tenant_id: &str,
        key: &IdempotencyKey,
        transaction_id: &str,
        window_ms: u64,
    ) -> Result<Result<(), DuplicateDetected>, DurableIdempotencyError> {
        self.with_lock(|| {
            let now = Self::now_ms();
            let mut state = self.load()?;
            state.records.retain(|entry| entry.record.expires_at_ms > now);

            if let Some(entry) = state.records.iter().find(|entry| {
                entry.record.tenant_id == tenant_id && entry.key == key.as_str()
            }) {
                if entry.record.status != IdempotencyStatus::Failed {
                    return Ok(Err(DuplicateDetected {
                        original_transaction_id: entry.record.transaction_id.clone(),
                        registered_at_ms: entry.record.registered_at_ms,
                    }));
                }
            }

            let expires_at_ms = now.saturating_add(window_ms);
            state.records.push(DurableRecord {
                key: key.as_str().to_string(),
                record: IdempotencyRecord {
                    transaction_id: transaction_id.to_string(),
                    tenant_id: tenant_id.to_string(),
                    registered_at_ms: now,
                    expires_at_ms,
                    status: IdempotencyStatus::Pending,
                },
            });
            self.save(&state)?;
            Ok(Ok(()))
        })
    }

    pub fn complete(&self, tenant_id: &str, key: &IdempotencyKey) -> Result<(), DurableIdempotencyError> {
        self.with_lock(|| {
            let mut state = self.load()?;
            if let Some(entry) = state.records.iter_mut().find(|entry| entry.record.tenant_id == tenant_id && entry.key == key.as_str()) {
                entry.record.status = IdempotencyStatus::Completed;
            }
            self.save(&state)
        })
    }

    pub fn fail(&self, tenant_id: &str, key: &IdempotencyKey) -> Result<(), DurableIdempotencyError> {
        self.with_lock(|| {
            let mut state = self.load()?;
            if let Some(entry) = state.records.iter_mut().find(|entry| entry.record.tenant_id == tenant_id && entry.key == key.as_str()) {
                entry.record.status = IdempotencyStatus::Failed;
            }
            self.save(&state)
        })
    }

    pub fn path(&self) -> &Path { &self.path }
}
