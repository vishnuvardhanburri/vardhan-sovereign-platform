//! ExposureDetector integration for AER-KEP-Q.
//!
//! This module owns the control-plane transition around cryptographic exposure:
//! an exposed epoch is quarantined, a fresh ML-KEM epoch is generated locally,
//! and its descriptor is authenticated with the existing ML-DSA-87 identity.
//!
//! Network transport is intentionally outside core_crypto. `on_exposure` returns
//! the authenticated descriptor for the HA/control-plane layer to broadcast.

use crate::aer_kep_q::{AerKepQ, AerKepQError, EpochDescriptor, EpochStatus};
use crate::QuantumNodeIdentity;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExposureReason {
    SecretMaterialExposure,
    IntegrityAlert,
    OperatorQuarantine,
    PeerExposureReport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExposureEvent {
    pub observed_epoch: u64,
    pub reason: ExposureReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureTransition {
    pub previous_epoch: u64,
    pub new_epoch: u64,
    pub reason: ExposureReason,
    pub descriptor: EpochDescriptor,
}

#[derive(Debug, Error)]
pub enum ExposureDetectorError {
    #[error("exposure event targets a stale epoch")]
    StaleExposure,
    #[error("exposure event targets a future epoch")]
    FutureExposure,
    #[error("descriptor domain does not match detector domain")]
    DomainMismatch,
    #[error("descriptor is not active")]
    DescriptorNotActive,
    #[error("descriptor epoch is stale")]
    StaleDescriptor,
    #[error("descriptor conflicts with the current epoch")]
    ConflictingDescriptor,
    #[error("descriptor signature is invalid")]
    InvalidSignature,
    #[error("AER-KEP-Q error: {0}")]
    Aer(#[from] AerKepQError),
}

/// Owns the local AER-KEP-Q epoch lifecycle.
///
/// The detector never exports private KEM material. On exposure it quarantines
/// the old epoch and returns only the newly authenticated public descriptor.
pub struct ExposureDetector {
    domain_id: String,
    current: AerKepQ,
}

impl ExposureDetector {
    pub fn new(domain_id: impl Into<String>, initial_epoch: u64) -> Result<Self, ExposureDetectorError> {
        let domain_id = domain_id.into();
        let current = AerKepQ::new(domain_id.clone(), initial_epoch)?;
        Ok(Self { domain_id, current })
    }

    pub fn domain_id(&self) -> &str {
        &self.domain_id
    }

    pub fn active_epoch(&self) -> u64 {
        self.current.epoch()
    }

    pub fn status(&self) -> EpochStatus {
        self.current.status()
    }

    pub fn on_exposure(
        &mut self,
        event: ExposureEvent,
        signer: &QuantumNodeIdentity,
    ) -> Result<ExposureTransition, ExposureDetectorError> {
        let current_epoch = self.current.epoch();
        match event.observed_epoch.cmp(&current_epoch) {
            std::cmp::Ordering::Less => return Err(ExposureDetectorError::StaleExposure),
            std::cmp::Ordering::Greater => return Err(ExposureDetectorError::FutureExposure),
            std::cmp::Ordering::Equal => {}
        }

        // Idempotency: an already quarantined epoch cannot be rotated twice
        // from the same exposure event.
        if self.current.status() != EpochStatus::Active {
            return Err(ExposureDetectorError::StaleExposure);
        }

        let previous_epoch = current_epoch;
        self.current.quarantine();

        let next_epoch = previous_epoch
            .checked_add(1)
            .ok_or(ExposureDetectorError::FutureExposure)?;
        self.current = AerKepQ::new(self.domain_id.clone(), next_epoch)?;
        let descriptor = self.current.descriptor(signer)?;

        Ok(ExposureTransition {
            previous_epoch,
            new_epoch: next_epoch,
            reason: event.reason,
            descriptor,
        })
    }
}

/// Control-plane view of an authenticated descriptor received from an HA peer.
///
/// This registry does not import or copy peer private keys. It tracks only the
/// highest authenticated epoch and the descriptor fingerprint, allowing the HA
/// transport layer to reject rollback and conflicting same-epoch state.
#[derive(Default)]
pub struct PeerEpochRegistry {
    domain_id: Option<String>,
    active_epoch: Option<u64>,
    descriptor_fingerprint: Option<[u8; 32]>,
}

impl PeerEpochRegistry {
    pub fn new(domain_id: impl Into<String>) -> Self {
        Self {
            domain_id: Some(domain_id.into()),
            active_epoch: None,
            descriptor_fingerprint: None,
        }
    }

    pub fn active_epoch(&self) -> Option<u64> {
        self.active_epoch
    }

    /// Apply an authenticated peer descriptor.
    ///
    /// Returns `true` when the registry advances to a new epoch and `false`
    /// for an exact duplicate. Older epochs and conflicting descriptors at the
    /// current epoch are rejected. Signature verification is performed against
    /// the explicitly configured trusted peer signing key.
    pub fn apply(
        &mut self,
        descriptor: &EpochDescriptor,
        trusted_signer_pub_bytes: &[u8],
    ) -> Result<bool, ExposureDetectorError> {
        let expected_domain = self.domain_id.as_deref().unwrap_or_default();
        if descriptor.domain_id != expected_domain {
            return Err(ExposureDetectorError::DomainMismatch);
        }
        if descriptor.status != EpochStatus::Active {
            return Err(ExposureDetectorError::DescriptorNotActive);
        }
        if !QuantumNodeIdentity::verify_signature(
            trusted_signer_pub_bytes,
            &descriptor.signable_bytes(),
            &descriptor.signature,
        ) {
            return Err(ExposureDetectorError::InvalidSignature);
        }

        let fingerprint = QuantumNodeIdentity::hash_ledger_block(&descriptor.signable_bytes());
        match self.active_epoch {
            None => {
                self.active_epoch = Some(descriptor.epoch);
                self.descriptor_fingerprint = Some(fingerprint);
                Ok(true)
            }
            Some(current) if descriptor.epoch < current => Err(ExposureDetectorError::StaleDescriptor),
            Some(current) if descriptor.epoch == current => {
                if self.descriptor_fingerprint == Some(fingerprint) {
                    Ok(false)
                } else {
                    Err(ExposureDetectorError::ConflictingDescriptor)
                }
            }
            Some(_) => {
                self.active_epoch = Some(descriptor.epoch);
                self.descriptor_fingerprint = Some(fingerprint);
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> (ExposureDetector, QuantumNodeIdentity) {
        (
            ExposureDetector::new("bank-a", 10).unwrap(),
            QuantumNodeIdentity::generate_node_identity().unwrap(),
        )
    }

    #[test]
    fn exposure_quarantines_and_advances_epoch() {
        let (mut detector, signer) = detector();
        let transition = detector
            .on_exposure(
                ExposureEvent {
                    observed_epoch: 10,
                    reason: ExposureReason::SecretMaterialExposure,
                },
                &signer,
            )
            .unwrap();

        assert_eq!(transition.previous_epoch, 10);
        assert_eq!(transition.new_epoch, 11);
        assert_eq!(detector.active_epoch(), 11);
        assert_eq!(detector.status(), EpochStatus::Active);
        assert_eq!(transition.descriptor.epoch, 11);
    }

    #[test]
    fn stale_and_future_exposures_are_rejected() {
        let (mut detector, signer) = detector();
        assert!(matches!(
            detector.on_exposure(
                ExposureEvent { observed_epoch: 9, reason: ExposureReason::IntegrityAlert },
                &signer,
            ),
            Err(ExposureDetectorError::StaleExposure)
        ));
        assert!(matches!(
            detector.on_exposure(
                ExposureEvent { observed_epoch: 11, reason: ExposureReason::IntegrityAlert },
                &signer,
            ),
            Err(ExposureDetectorError::FutureExposure)
        ));
    }

    #[test]
    fn peer_registry_rejects_rollback_and_conflict() {
        let (mut detector, signer) = detector();
        let first = detector
            .on_exposure(
                ExposureEvent { observed_epoch: 10, reason: ExposureReason::OperatorQuarantine },
                &signer,
            )
            .unwrap();
        let pubkey = signer.dsa_public_key_bytes();
        let mut registry = PeerEpochRegistry::new("bank-a");

        assert!(registry.apply(&first.descriptor, &pubkey).unwrap());
        assert!(!registry.apply(&first.descriptor, &pubkey).unwrap());

        let old = AerKepQ::new("bank-a", 10).unwrap().descriptor(&signer).unwrap();
        assert!(matches!(
            registry.apply(&old, &pubkey),
            Err(ExposureDetectorError::StaleDescriptor)
        ));

        let second_detector = AerKepQ::new("bank-a", 11).unwrap();
        let mut conflicting = second_detector.descriptor(&signer).unwrap();
        assert_eq!(conflicting.epoch, first.descriptor.epoch);
        assert!(matches!(
            registry.apply(&conflicting, &pubkey),
            Err(ExposureDetectorError::ConflictingDescriptor)
        ));
    }

    #[test]
    fn peer_registry_rejects_wrong_signer_and_domain() {
        let (mut detector, signer) = detector();
        let transition = detector
            .on_exposure(
                ExposureEvent { observed_epoch: 10, reason: ExposureReason::PeerExposureReport },
                &signer,
            )
            .unwrap();
        let mut registry = PeerEpochRegistry::new("bank-a");
        let wrong_signer = QuantumNodeIdentity::generate_node_identity().unwrap();

        assert!(matches!(
            registry.apply(&transition.descriptor, &wrong_signer.dsa_public_key_bytes()),
            Err(ExposureDetectorError::InvalidSignature)
        ));

        let mut wrong_domain = transition.descriptor.clone();
        wrong_domain.domain_id = "bank-b".into();
        assert!(matches!(
            registry.apply(&wrong_domain, &signer.dsa_public_key_bytes()),
            Err(ExposureDetectorError::DomainMismatch)
        ));
    }
}
