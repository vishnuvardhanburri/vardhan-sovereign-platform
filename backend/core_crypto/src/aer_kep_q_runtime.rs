//! AER-KEP-Q runtime orchestration.
//!
//! Tracks in-flight application messages by cryptographic epoch, performs
//! exposure-driven quarantine/reissue transitions, and validates authenticated
//! peer epoch descriptors. Application plaintext is never retained here.

use crate::aer_kep_q::{EpochDescriptor, EpochStatus};
use crate::exposure_detector::{
    ExposureDetector, ExposureDetectorError, ExposureEvent, ExposureTransition,
    PeerEpochRegistry,
};
use crate::QuantumNodeIdentity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

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
    pub fn register(
        &mut self,
        message_id: u64,
        epoch: u64,
        context: &[u8],
    ) -> Result<(), RuntimeError> {
        if self.pending.contains_key(&message_id) {
            return Err(RuntimeError::DuplicateMessageId(message_id));
        }
        self.pending.insert(
            message_id,
            PendingMessage {
                message_id,
                epoch,
                context_commitment: QuantumNodeIdentity::hash_ledger_block(context),
            },
        );
        Ok(())
    }

    pub fn acknowledge(&mut self, message_id: u64) -> Result<PendingMessage, RuntimeError> {
        self.pending
            .remove(&message_id)
            .ok_or(RuntimeError::UnknownMessageId(message_id))
    }

    pub fn pending_for_epoch(&self, epoch: u64) -> Vec<PendingMessage> {
        let mut values: Vec<_> = self
            .pending
            .values()
            .filter(|m| m.epoch == epoch)
            .cloned()
            .collect();
        values.sort_by_key(|m| m.message_id);
        values
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("duplicate message id: {0}")]
    DuplicateMessageId(u64),
    #[error("unknown message id: {0}")]
    UnknownMessageId(u64),
    #[error("runtime is not active")]
    RuntimeNotActive,
    #[error("exposure detector error: {0}")]
    Exposure(#[from] ExposureDetectorError),
}

/// Complete local operational state for AER-KEP-Q.
///
/// The existing ML-DSA-87 identity authenticates epoch descriptors. It remains
/// separate from the existing receipt/signing pipeline.
pub struct AerKepQRuntime {
    detector: ExposureDetector,
    signer: Arc<QuantumNodeIdentity>,
    pending: PendingMessageRegistry,
    peer_epochs: HashMap<String, PeerEpochRegistry>,
}

impl AerKepQRuntime {
    pub fn new(
        domain_id: impl Into<String>,
        initial_epoch: u64,
        signer: Arc<QuantumNodeIdentity>,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            detector: ExposureDetector::new(domain_id, initial_epoch)?,
            signer,
            pending: PendingMessageRegistry::default(),
            peer_epochs: HashMap::new(),
        })
    }

    pub fn domain_id(&self) -> &str {
        self.detector.domain_id()
    }

    pub fn active_epoch(&self) -> u64 {
        self.detector.active_epoch()
    }

    pub fn status(&self) -> EpochStatus {
        self.detector.status()
    }

    pub fn descriptor(&self) -> Result<EpochDescriptor, RuntimeError> {
        Ok(self.detector.descriptor(&self.signer)?)
    }

    pub fn register_pending(
        &mut self,
        message_id: u64,
        context: &[u8],
    ) -> Result<(), RuntimeError> {
        if self.status() != EpochStatus::Active {
            return Err(RuntimeError::RuntimeNotActive);
        }
        self.pending
            .register(message_id, self.active_epoch(), context)
    }

    pub fn acknowledge(&mut self, message_id: u64) -> Result<PendingMessage, RuntimeError> {
        self.pending.acknowledge(message_id)
    }

    pub fn pending_for_epoch(&self, epoch: u64) -> Vec<PendingMessage> {
        self.pending.pending_for_epoch(epoch)
    }

    /// Quarantine the exposed epoch and return exactly the application
    /// messages whose transport artifacts must be reissued.
    pub fn on_exposure(
        &mut self,
        event: ExposureEvent,
    ) -> Result<(ExposureTransition, Vec<PendingMessage>), RuntimeError> {
        let old_epoch = self.active_epoch();
        let transition = self.detector.on_exposure(event, &self.signer)?;
        let reissue = self.pending.pending_for_epoch(old_epoch);
        Ok((transition, reissue))
    }

    /// Validate and record an authenticated peer descriptor. Private peer
    /// keys are never imported into this runtime.
    pub fn apply_peer_descriptor(
        &mut self,
        peer_id: impl Into<String>,
        descriptor: &EpochDescriptor,
        trusted_peer_signer: &[u8],
    ) -> Result<bool, RuntimeError> {
        let peer_id = peer_id.into();
        let registry = self
            .peer_epochs
            .entry(peer_id)
            .or_insert_with(|| PeerEpochRegistry::new(descriptor.domain_id.clone()));
        Ok(registry.apply(descriptor, trusted_peer_signer)?)
    }

    pub fn peer_epoch(&self, peer_id: &str) -> Option<u64> {
        self.peer_epochs
            .get(peer_id)
            .and_then(PeerEpochRegistry::active_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure_detector::ExposureReason;

    #[test]
    fn runtime_returns_reissue_set_after_exposure() {
        let signer = Arc::new(QuantumNodeIdentity::generate_node_identity().unwrap());
        let mut runtime = AerKepQRuntime::new("bank-a", 1, signer).unwrap();
        runtime.register_pending(10, b"txn-a").unwrap();
        runtime.register_pending(11, b"txn-b").unwrap();

        let (transition, reissue) = runtime
            .on_exposure(ExposureEvent {
                observed_epoch: 1,
                reason: ExposureReason::SecretMaterialExposure,
            })
            .unwrap();

        assert_eq!(transition.previous_epoch, 1);
        assert_eq!(transition.new_epoch, 2);
        assert_eq!(reissue.len(), 2);
        assert!(reissue.iter().all(|m| m.epoch == 1));
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

        assert!(runtime
            .apply_peer_descriptor("node-b", &descriptor, &peer_signer.dsa_public_key_bytes())
            .unwrap());
        assert_eq!(runtime.peer_epoch("node-b"), Some(7));
    }
}
