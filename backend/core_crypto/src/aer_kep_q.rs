//! AER-KEP-Q: Asynchronous Exposure-Resilient Key Establishment — Quarantine/Reissue.
//!
//! This module is deliberately scoped to the first production integration slice:
//! one ML-KEM epoch, transcript-bound HKDF key derivation, replay rejection, and
//! exposure quarantine. It does not claim retroactive protection for ciphertexts
//! created under a fully exposed epoch.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_512};
use std::collections::HashSet;
use thiserror::Error;
use zeroize::Zeroizing;

pub const AER_KEY_LEN: usize = 32;
pub const AER_CIPHERTEXT_LEN: usize = 1568;
const DOMAIN_TAG: &[u8] = b"VARDHAN-AER-KEP-Q-v2";
const KDF_INFO: &[u8] = b"AER-KEP-Q SESSION KEY";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochStatus {
    Active,
    Quarantined,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochDescriptor {
    pub domain_id: String,
    pub epoch: u64,
    pub status: EpochStatus,
    pub encapsulation_key: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum AerKepQError {
    #[error("epoch is not active")]
    EpochNotActive,
    #[error("epoch descriptor is invalid")]
    InvalidDescriptor,
    #[error("ciphertext has invalid length")]
    InvalidCiphertext,
    #[error("ciphertext decapsulation failed")]
    DecapsulationFailed,
    #[error("message id has already been accepted")]
    Replay,
    #[error("context or transcript validation failed")]
    TranscriptMismatch,
    #[error("key derivation failed")]
    KeyDerivationFailed,
}

/// Receiver-side AER-KEP-Q state for a single active epoch.
///
/// The secret decapsulation key is held only while the epoch is active. Quarantine
/// drops the secret key, making the old epoch unusable for future decapsulation.
pub struct AerKepQ {
    domain_id: String,
    epoch: u64,
    status: EpochStatus,
    encapsulation_key: Option<<MlKem1024 as KemCore>::EncapsulationKey>,
    decapsulation_key: Option<<MlKem1024 as KemCore>::DecapsulationKey>,
    accepted_message_ids: HashSet<u64>,
}

impl AerKepQ {
    pub fn new(domain_id: impl Into<String>, epoch: u64) -> Result<Self, AerKepQError> {
        let domain_id = domain_id.into();
        if domain_id.is_empty() {
            return Err(AerKepQError::InvalidDescriptor);
        }

        let (decapsulation_key, encapsulation_key) = MlKem1024::generate(&mut OsRng);

        Ok(Self {
            domain_id,
            epoch,
            status: EpochStatus::Active,
            encapsulation_key: Some(encapsulation_key),
            decapsulation_key: Some(decapsulation_key),
            accepted_message_ids: HashSet::new(),
        })
    }

    pub fn status(&self) -> EpochStatus {
        self.status
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn descriptor(&self) -> Result<EpochDescriptor, AerKepQError> {
        if self.status != EpochStatus::Active {
            return Err(AerKepQError::EpochNotActive);
        }

        let encapsulation_key = self
            .encapsulation_key
            .as_ref()
            .ok_or(AerKepQError::EpochNotActive)?;

        Ok(EpochDescriptor {
            domain_id: self.domain_id.clone(),
            epoch: self.epoch,
            status: self.status,
            encapsulation_key: encapsulation_key.as_bytes().to_vec(),
        })
    }

    /// Encapsulate a fresh ML-KEM shared secret using an authenticated epoch
    /// descriptor supplied by the caller.
    pub fn encapsulate(
        descriptor: &EpochDescriptor,
        message_id: u64,
        context: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), AerKepQError> {
        if descriptor.status != EpochStatus::Active || descriptor.encapsulation_key.is_empty() {
            return Err(AerKepQError::EpochNotActive);
        }

        let key_bytes: [u8; 1568] = descriptor
            .encapsulation_key
            .as_slice()
            .try_into()
            .map_err(|_| AerKepQError::InvalidDescriptor)?;
        let encoded = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::from(key_bytes);
        let encapsulation_key =
            <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&encoded);

        let (ciphertext, shared_secret) = encapsulation_key
            .encapsulate(&mut OsRng)
            .map_err(|_| AerKepQError::InvalidDescriptor)?;

        let ciphertext_bytes = ciphertext.to_vec();
        let key = derive_session_key(
            &descriptor.domain_id,
            descriptor.epoch,
            message_id,
            &ciphertext_bytes,
            context,
            shared_secret.as_ref(),
        )?;

        Ok((ciphertext_bytes, key))
    }

    /// Decapsulate and derive the transcript-bound session key.
    pub fn decapsulate(
        &mut self,
        ciphertext_bytes: &[u8],
        message_id: u64,
        context: &[u8],
    ) -> Result<Vec<u8>, AerKepQError> {
        if self.status != EpochStatus::Active {
            return Err(AerKepQError::EpochNotActive);
        }
        if self.accepted_message_ids.contains(&message_id) {
            return Err(AerKepQError::Replay);
        }
        if ciphertext_bytes.len() != AER_CIPHERTEXT_LEN {
            return Err(AerKepQError::InvalidCiphertext);
        }

        let ciphertext_array: [u8; AER_CIPHERTEXT_LEN] = ciphertext_bytes
            .try_into()
            .map_err(|_| AerKepQError::InvalidCiphertext)?;
        let ciphertext: Ciphertext<MlKem1024> = ciphertext_array.into();

        let decapsulation_key = self
            .decapsulation_key
            .as_ref()
            .ok_or(AerKepQError::EpochNotActive)?;
        let shared_secret = decapsulation_key
            .decapsulate(&ciphertext)
            .map_err(|_| AerKepQError::DecapsulationFailed)?;

        let key = derive_session_key(
            &self.domain_id,
            self.epoch,
            message_id,
            ciphertext_bytes,
            context,
            shared_secret.as_ref(),
        )?;

        self.accepted_message_ids.insert(message_id);
        Ok(key)
    }

    /// Permanently invalidates the current epoch for this in-memory state.
    ///
    /// Pending ciphertexts from this epoch are intentionally not recovered here;
    /// callers must re-encapsulate application messages under a fresh epoch.
    pub fn quarantine(&mut self) -> Result<(), AerKepQError> {
        if self.status == EpochStatus::Quarantined {
            return Ok(());
        }

        self.status = EpochStatus::Quarantined;
        self.decapsulation_key = None;
        self.encapsulation_key = None;
        Ok(())
    }
}

fn derive_session_key(
    domain_id: &str,
    epoch: u64,
    message_id: u64,
    ciphertext: &[u8],
    context: &[u8],
    shared_secret: &[u8],
) -> Result<Vec<u8>, AerKepQError> {
    let transcript = transcript_hash(domain_id, epoch, message_id, ciphertext, context);
    let shared_secret = Zeroizing::new(shared_secret.to_vec());
    let hk = Hkdf::<Sha3_512>::new(Some(&transcript), shared_secret.as_ref());
    let mut output = [0u8; AER_KEY_LEN];
    hk.expand(KDF_INFO, &mut output)
        .map_err(|_| AerKepQError::KeyDerivationFailed)?;
    Ok(output.to_vec())
}

fn transcript_hash(
    domain_id: &str,
    epoch: u64,
    message_id: u64,
    ciphertext: &[u8],
    context: &[u8],
) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(DOMAIN_TAG);
    append_len_prefixed(&mut hasher, domain_id.as_bytes());
    hasher.update(epoch.to_be_bytes());
    hasher.update(message_id.to_be_bytes());
    append_len_prefixed(&mut hasher, ciphertext);
    append_len_prefixed(&mut hasher, context);
    hasher.finalize().into()
}

fn append_len_prefixed<D: Digest>(hasher: &mut D, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
