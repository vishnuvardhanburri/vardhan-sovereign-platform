//! AER-KEP-Q runtime orchestration.
//!
//! Tracks in-flight application messages by cryptographic epoch, performs
//! exposure-driven quarantine/reissue transitions, validates authenticated
//! peer epoch descriptors, and provides encrypted restart-safe control state.
//! Application plaintext is never retained here.

use crate::aer_kep_q::{EpochDescriptor, EpochStatus};
use crate::exposure_detector::{
    ExposureDetector, ExposureDetectorError, ExposureEvent, ExposureTransition,
    PeerEpochRegistry,
};
use crate::vault::{self, KeyProtector};
use crate::QuantumNodeIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

const STATE_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct PendingMessage {
    pub message_id: u64,
    pub epoch: u64,
    pub context_commitment: [u8; 32],
}

#[derive(Default)]
pub struct PendingMessageRegistry {
    pending: HashMap<u64, PendingMessage>,
}

impl PendingMessageRegistry {
    pub fn register(&mut self, message_id: u64, epoch: u64, context: &[u8]) -> Result<(), RuntimeError> {
        if self.pending.contains_key(&message_id) {
            return Err(RuntimeError::DuplicateMessageId(message_id));
        }
        self.pending.insert(message_id, PendingMessage {
            message_id,
            epoch,
            context_commitment: QuantumNodeIdentity::hash_ledger_block(context),
        });
        Ok(())
    }

    pub fn acknowledge(&mut self, message_id: u64) -> Result<PendingMessage, RuntimeError> {
        self.pending.remove(&message_id).ok_or(RuntimeError::UnknownMessageId(message_id))
    }

    pub fn pending_for_epoch(&self, epoch: u64) -> Vec<PendingMessage> {
        let mut values: Vec<_> = self.pending.values().filter(|m| m.epoch == epoch).cloned().collect();
        values.sort_by_key(|m| m.message_id);
        values
    }

    fn snapshot(&self) -> Vec<PendingMessage> {
        let mut values: Vec<_> = self.pending.values().cloned().collect();
        values.sort_by_key(|m| m.message_id);
        values
    }

    fn restore(values: Vec<PendingMessage>) -> Result<Self, RuntimeError> {
        let mut registry = Self::default();
        for value in values {
            if registry.pending.insert(value.message_id, value).is_some() {
                return Err(RuntimeError::PersistedStateInvalid("duplicate pending message id".into()));
            }
        }
        Ok(registry)
    }

    pub fn len(&self) -> usize { self.pending.len() }
    pub fn is_empty(&self) -> bool { self.pending.is_empty() }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedRuntimeState {
    version: u32,
    domain_id: String,
    committed_epoch: u64,
    pending: Vec<PendingMessage>,
}

/// Encrypted, atomic runtime state store.
///
/// Only control metadata and commitments are persisted. Private ML-KEM key
/// material remains in the cryptographic runtime and is never serialized here.
/// A restart therefore always advances to a fresh epoch, invalidating all
/// previously in-flight ciphertexts and preventing accidental key reuse.
pub struct RuntimeStateStore<P: KeyProtector> {
    path: PathBuf,
    protector: Arc<P>,
}

impl<P: KeyProtector> RuntimeStateStore<P> {
    pub fn new(path: impl Into<PathBuf>, protector: Arc<P>) -> Self {
        Self { path: path.into(), protector }
    }

    fn load(&self, domain_id: &str) -> Result<Option<PersistedRuntimeState>, RuntimeError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let envelope = std::fs::read_to_string(&self.path)?;
        let envelope: vault::EncryptedEnvelope = serde_json::from_str(&envelope)
            .map_err(|e| RuntimeError::PersistedStateInvalid(e.to_string()))?;
        let plaintext = vault::unwrap_envelope(self.protector.as_ref(), &envelope)?;
        let state: PersistedRuntimeState = serde_json::from_slice(&plaintext)
            .map_err(|e| RuntimeError::PersistedStateInvalid(e.to_string()))?;
        if state.version != STATE_VERSION || state.domain_id != domain_id {
            return Err(RuntimeError::PersistedStateInvalid("version or domain mismatch".into()));
        }
        Ok(Some(state))
    }

    fn save(&self, state: &PersistedRuntimeState) -> Result<(), RuntimeError> {
        let plaintext = serde_json::to_vec(state)
            .map_err(|e| RuntimeError::PersistedStateInvalid(e.to_string()))?;
        let envelope = vault::wrap_envelope(self.protector.as_ref(), &plaintext)?;
        let encoded = serde_json::to_string_pretty(&envelope)
            .map_err(|e| RuntimeError::PersistedStateInvalid(e.to_string()))?;
        let tmp = self.path.with_extension("state.tmp");
        std::fs::write(&tmp, encoded)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }

    pub fn initialize_epoch(&self, domain_id: &str, requested_epoch: u64) -> Result<u64, RuntimeError> {
        let next = match self.load(domain_id)? {
            Some(state) => state.committed_epoch.checked_add(1).ok_or(RuntimeError::EpochExhausted)?,
            None => requested_epoch,
        };
        self.save(&PersistedRuntimeState {
            version: STATE_VERSION,
            domain_id: domain_id.to_string(),
            committed_epoch: next,
            pending: Vec::new(),
        })?;
        Ok(next)
    }

    fn load_state(&self, domain_id: &str) -> Result<Option<PersistedRuntimeState>, RuntimeError> {
        self.load(domain_id)
    }

    fn commit(&self, state: &PersistedRuntimeState) -> Result<(), RuntimeError> {
        self.save(state)
    }

    pub fn path(&self) -> &Path { &self.path }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("duplicate message id: {0}")]
    DuplicateMessageId(u64),
    #[error("unknown message id: {0}")]
    UnknownMessageId(u64),
    #[error("runtime is not active")]
    RuntimeNotActive,
    #[error("epoch counter exhausted")]
    EpochExhausted,
    #[error("persisted state invalid: {0}")]
    PersistedStateInvalid(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault error: {0}")]
    Vault(#[from] crate::vault::VaultError),
    #[error("exposure detector error: {0}")]
    Exposure(#[from] ExposureDetectorError),
}

/// Complete local operational state for AER-KEP-Q.
pub struct AerKepQRuntime {
    detector: ExposureDetector,
    signer: Arc<QuantumNodeIdentity>,
    pending: PendingMessageRegistry,
    peer_epochs: HashMap<String, PeerEpochRegistry>,
}

impl AerKepQRuntime {
    pub fn new(domain_id: impl Into<String>, initial_epoch: u64, signer: Arc<QuantumNodeIdentity>) -> Result<Self, RuntimeError> {
        Ok(Self {
            detector: ExposureDetector::new(domain_id, initial_epoch)?,
            signer,
            pending: PendingMessageRegistry::default(),
            peer_epochs: HashMap::new(),
        })
    }

    /// Restart-safe constructor. The persisted epoch is never reused: the
    /// runtime advances one epoch and creates a fresh ML-KEM keypair.
    pub fn new_persistent<P: KeyProtector>(
        domain_id: impl Into<String>,
        initial_epoch: u64,
        signer: Arc<QuantumNodeIdentity>,
        store: &RuntimeStateStore<P>,
    ) -> Result<Self, RuntimeError> {
        let domain_id = domain_id.into();
        let epoch = match store.load_state(&domain_id)? {
            Some(state) => state.committed_epoch.checked_add(1).ok_or(RuntimeError::EpochExhausted)?,
            None => initial_epoch,
        };
        let pending = match store.load_state(&domain_id)? {
            Some(state) => PendingMessageRegistry::restore(state.pending)?,
            None => PendingMessageRegistry::default(),
        };
        let runtime = Self {
            detector: ExposureDetector::new(domain_id.clone(), epoch)?,
            signer,
            pending,
            peer_epochs: HashMap::new(),
        };
        runtime.persist(store)?;
        Ok(runtime)
    }

    fn persist<P: KeyProtector>(&self, store: &RuntimeStateStore<P>) -> Result<(), RuntimeError> {
        store.commit(&PersistedRuntimeState {
            version: STATE_VERSION,
            domain_id: self.domain_id().to_string(),
            committed_epoch: self.active_epoch(),
            pending: self.pending.snapshot(),
        })
    }

    pub fn domain_id(&self) -> &str { self.detector.domain_id() }
    pub fn active_epoch(&self) -> u64 { self.detector.active_epoch() }
    pub fn status(&self) -> EpochStatus { self.detector.status() }
    pub fn descriptor(&self) -> Result<EpochDescriptor, RuntimeError> { Ok(self.detector.descriptor(&self.signer)?) }

    pub fn register_pending(&mut self, message_id: u64, context: &[u8]) -> Result<(), RuntimeError> {
        if self.status() != EpochStatus::Active { return Err(RuntimeError::RuntimeNotActive); }
        self.pending.register(message_id, self.active_epoch(), context)
    }

    pub fn acknowledge(&mut self, message_id: u64) -> Result<PendingMessage, RuntimeError> {
        self.pending.acknowledge(message_id)
    }

    pub fn pending_for_epoch(&self, epoch: u64) -> Vec<PendingMessage> { self.pending.pending_for_epoch(epoch) }

    /// Quarantine the exposed epoch and return application messages whose
    /// transport artifacts must be reissued under the fresh epoch.
    pub fn on_exposure(&mut self, event: ExposureEvent) -> Result<(ExposureTransition, Vec<PendingMessage>), RuntimeError> {
        let old_epoch = self.active_epoch();
        let transition = self.detector.on_exposure(event, &self.signer)?;
        let reissue = self.pending.pending_for_epoch(old_epoch);
        Ok((transition, reissue))
    }

    /// Crash-safe exposure transition. The next epoch is committed before the
    /// in-memory rotation, so a crash at any point after exposure can only
    /// restart on a newer epoch; the exposed epoch can never be reused.
    pub fn on_exposure_persistent<P: KeyProtector>(
        &mut self,
        event: ExposureEvent,
        store: &RuntimeStateStore<P>,
    ) -> Result<(ExposureTransition, Vec<PendingMessage>), RuntimeError> {
        if event.observed_epoch != self.active_epoch() {
            return Err(RuntimeError::Exposure(ExposureDetectorError::StaleExposure));
        }
        let next_epoch = self.active_epoch().checked_add(1).ok_or(RuntimeError::EpochExhausted)?;
        let mut checkpoint = PersistedRuntimeState {
            version: STATE_VERSION,
            domain_id: self.domain_id().to_string(),
            committed_epoch: next_epoch,
            pending: self.pending.snapshot(),
        };
        store.commit(&checkpoint)?;
        let result = self.on_exposure(event)?;
        checkpoint.committed_epoch = result.0.new_epoch;
        checkpoint.pending = self.pending.snapshot();
        store.commit(&checkpoint)?;
        Ok(result)
    }

    pub fn apply_peer_descriptor(
        &mut self,
        peer_id: impl Into<String>,
        descriptor: &EpochDescriptor,
        trusted_peer_signer: &[u8],
    ) -> Result<bool, RuntimeError> {
        let peer_id = peer_id.into();
        let registry = self.peer_epochs.entry(peer_id).or_insert_with(|| PeerEpochRegistry::new(descriptor.domain_id.clone()));
        Ok(registry.apply(descriptor, trusted_peer_signer)?)
    }

    pub fn peer_epoch(&self, peer_id: &str) -> Option<u64> {
        self.peer_epochs.get(peer_id).and_then(PeerEpochRegistry::active_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure_detector::ExposureReason;
    use crate::vault::LocalDevKeyProtector;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn runtime_returns_reissue_set_after_exposure() {
        let signer = Arc::new(QuantumNodeIdentity::generate_node_identity().unwrap());
        let mut runtime = AerKepQRuntime::new("bank-a", 1, signer).unwrap();
        runtime.register_pending(10, b"txn-a").unwrap();
        runtime.register_pending(11, b"txn-b").unwrap();
        let (transition, reissue) = runtime.on_exposure(ExposureEvent { observed_epoch: 1, reason: ExposureReason::SecretMaterialExposure }).unwrap();
        assert_eq!(transition.previous_epoch, 1);
        assert_eq!(transition.new_epoch, 2);
        assert_eq!(reissue.len(), 2);
        assert_eq!(runtime.active_epoch(), 2);
    }

    #[test]
    fn acknowledged_message_is_removed() {
        let signer = Arc::new(QuantumNodeIdentity::generate_node_identity().unwrap());
        let mut runtime = AerKepQRuntime::new("bank-a", 1, signer).unwrap();
        runtime.register_pending(42, b"ctx").unwrap();
        let msg = runtime.acknowledge(42).unwrap();
        assert_eq!(msg.message_id, 42);
        assert!(runtime.pending_for_epoch(1).is_empty());
    }

    #[test]
    fn peer_epoch_advances_only_from_authenticated_descriptor() {
        let signer = Arc::new(QuantumNodeIdentity::generate_node_identity().unwrap());
        let peer_signer = QuantumNodeIdentity::generate_node_identity().unwrap();
        let mut runtime = AerKepQRuntime::new("bank-a", 1, signer).unwrap();
        let peer_detector = ExposureDetector::new("bank-a", 7).unwrap();
        let descriptor = peer_detector.descriptor(&peer_signer).unwrap();
        assert!(runtime.apply_peer_descriptor("node-b", &descriptor, &peer_signer.dsa_public_key_bytes()).unwrap());
        assert_eq!(runtime.peer_epoch("node-b"), Some(7));
    }

    #[test]
    fn persistent_restart_advances_epoch_and_keeps_pending_metadata() {
        let root = std::env::temp_dir();
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let state_path = root.join(format!("aer-kep-q-{stamp}.state"));
        let kek_path = root.join(format!("aer-kep-q-{stamp}.kek"));
        let protector = Arc::new(LocalDevKeyProtector::new(kek_path.clone()));
        let store = RuntimeStateStore::new(&state_path, protector.clone());
        let signer = Arc::new(QuantumNodeIdentity::generate_node_identity().unwrap());
        let mut first = AerKepQRuntime::new_persistent("bank-a", 1, signer.clone(), &store).unwrap();
        assert_eq!(first.active_epoch(), 1);
        first.register_pending(9, b"ctx").unwrap();
        first.persist(&store).unwrap();
        drop(first);
        let second = AerKepQRuntime::new_persistent("bank-a", 1, signer, &store).unwrap();
        assert_eq!(second.active_epoch(), 2);
        assert_eq!(second.pending_for_epoch(1).len(), 1);
        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(kek_path);
    }
}
