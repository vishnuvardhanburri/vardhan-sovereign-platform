//! # core_crypto
//!
//! Post-quantum cryptographic identity for a proxy node.
//! Wraps FIPS 203 (ML-KEM-1024) and FIPS 204 (ML-DSA-87).

pub mod avx512;

pub mod vault;

use crate::vault::{EncryptedEnvelope, KeyProtector, VaultError};
use fips204::ml_dsa_87;
use fips204::traits::{SerDes, Signer, Verifier};
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem1024, SharedKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

pub use serde_cbor;

/// Cryptographic errors for core operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("PQC Encapsulation failed")]
    EncapsulationFailed,
    #[error("PQC Decapsulation failed")]
    DecapsulationFailed,
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("Internal crypto error: {0}")]
    Internal(String),
}

/// ML-KEM-1024 encapsulation key byte length (1568 bytes).
pub const ENCAP_KEY_LEN: usize = 1568;

/// ML-KEM-1024 ciphertext byte length (1568 bytes).
pub const CIPHERTEXT_LEN: usize = 1568;

/// ML-KEM-1024 shared key byte length (32 bytes).
pub const SHARED_KEY_LEN: usize = 32;

/// ML-DSA-87 public key byte length (2592 bytes).
pub const DSA_PUB_KEY_LEN: usize = ml_dsa_87::PK_LEN; // 2592

/// ML-DSA-87 signature byte length (4627 bytes).
pub const DSA_SIG_LEN: usize = ml_dsa_87::SIG_LEN; // 4627

/// Quantum-safe proxy node cryptographic identity.
///
/// Holds:
/// - An ML-KEM-1024 key pair (FIPS 203) for key encapsulation.
/// - An ML-DSA-87 key pair (FIPS 204) for node authentication.
#[derive(Clone)]
pub struct QuantumNodeIdentity {
    pub secure_dsa_private: Option<crate::secure_memory::SecureKeyMaterial>,
    pub secure_kem_private: Option<crate::secure_memory::SecureKeyMaterial>,
    kem_encap_key: <MlKem1024 as KemCore>::EncapsulationKey,
    pub dsa_public_key: ml_dsa_87::PublicKey,

    // Hardened secret keys: stored as zeroized byte arrays
    kem_decap_key_bytes: zeroize::Zeroizing<Vec<u8>>,
    dsa_private_key_bytes: zeroize::Zeroizing<[u8; ml_dsa_87::SK_LEN]>,
}

impl QuantumNodeIdentity {
    // ──────────────────────────────────────────────────────────────────
    // Identity generation
    // ──────────────────────────────────────────────────────────────────

    /// Generate fresh ML-KEM-1024 and ML-DSA-87 key pairs.
    pub fn generate_node_identity() -> Result<Self, Box<dyn std::error::Error>> {
        let (decap_key, encap_key) = MlKem1024::generate(&mut OsRng);

        let (dsa_pk, dsa_sk) = ml_dsa_87::try_keygen()
            .map_err(|e| format!("Failed to generate ML-DSA-87 keypair: {e}"))?;

        // Extract bytes for hardened storage
        let decap_bytes = zeroize::Zeroizing::new(decap_key.as_bytes().to_vec());
        let dsa_sk_bytes = zeroize::Zeroizing::new(dsa_sk.into_bytes());

        Ok(QuantumNodeIdentity {
            kem_encap_key: encap_key,
            dsa_public_key: dsa_pk,
            kem_decap_key_bytes: decap_bytes,
            dsa_private_key_bytes: dsa_sk_bytes,
            secure_dsa_private: None,
            secure_kem_private: None,
        })
    }

    /// Load the persistent node identity from a vault, or generate a new one.
    pub fn load_or_generate<P: KeyProtector>(
        vault_path: &Path,
        protector: &P,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if vault_path.exists() {
            let env_json = std::fs::read_to_string(vault_path)?;
            let env: EncryptedEnvelope = serde_json::from_str(&env_json)?;
            let plaintext = vault::unwrap_envelope(protector, &env)?;

            let stored: StoredIdentity = serde_json::from_slice(&plaintext)?;

            // Reconstruct ML-KEM
            let ek_arr: [u8; ENCAP_KEY_LEN] = stored
                .kem_encap_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid encap key length")?;
            let ek_encoded =
                ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::from(ek_arr);
            let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_encoded);

            // Reconstruct ML-DSA
            let pk_arr: [u8; ml_dsa_87::PK_LEN] = stored
                .dsa_public_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "Invalid DSA pk length")?;
            let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_arr).map_err(|e| e.to_string())?;

            let mut dsa_sk = [0u8; ml_dsa_87::SK_LEN];
            dsa_sk.copy_from_slice(&stored.dsa_private_key_bytes);

            return Ok(QuantumNodeIdentity {
                kem_encap_key: ek,
                dsa_public_key: pk,
                kem_decap_key_bytes: zeroize::Zeroizing::new(stored.kem_decap_key_bytes.clone()),
                dsa_private_key_bytes: zeroize::Zeroizing::new(dsa_sk),
                secure_dsa_private: None,
                secure_kem_private: None,
            });
        }

        let new_id = Self::generate_node_identity()?;

        let mut stored = StoredIdentity {
            kem_encap_key_bytes: new_id.kem_encap_key.as_bytes().to_vec(),
            kem_decap_key_bytes: new_id.kem_decap_key_bytes.to_vec(),
            dsa_public_key_bytes: new_id.dsa_public_key_bytes(),
            dsa_private_key_bytes: new_id.dsa_private_key_bytes.to_vec(),
        };

        let pt = serde_json::to_vec(&stored)?;
        stored.zeroize();

        let env = vault::wrap_envelope(protector, &pt)?;
        let env_json = serde_json::to_string_pretty(&env)?;
        std::fs::write(vault_path, env_json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(vault_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(vault_path, perms)?;
        }

        Ok(new_id)
    }

    /// Re-wrap the persistent identity using a new or rotated key protector
    pub fn rotate_key_protector<P: KeyProtector>(
        &self,
        vault_path: &Path,
        new_protector: &P,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut stored = StoredIdentity {
            kem_encap_key_bytes: self.kem_encap_key.as_bytes().to_vec(),
            kem_decap_key_bytes: self.kem_decap_key_bytes.to_vec(),
            dsa_public_key_bytes: self.dsa_public_key_bytes(),
            dsa_private_key_bytes: self.dsa_private_key_bytes.to_vec(),
        };

        let pt = serde_json::to_vec(&stored)?;
        stored.zeroize();

        let env = vault::wrap_envelope(new_protector, &pt)?;
        let env_json = serde_json::to_string_pretty(&env)?;
        std::fs::write(vault_path, env_json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(vault_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(vault_path, perms)?;
        }
        Ok(())
    }

    /// Rotate the ML-DSA-87 signing key while preserving the ML-KEM-1024
    /// key-encapsulation identity.
    ///
    /// This addresses the P8-003 finding: `rotate_key_protector` only
    /// re-wraps the existing key at rest — it does NOT generate a new
    /// signing key. If the signing key is compromised, there is no way
    /// to rotate it.
    ///
    /// Lifecycle:
    /// 1. Generate a new ML-DSA-87 keypair (FIPS 204).
    /// 2. Sign the new public key with the OLD private key — producing a
    ///    `KeyTransitionRecord` that serves as proof of continuity:
    ///    `OldKey signs NewPubKey → verifiable by anyone who trusts OldPubKey`.
    /// 3. Persist the new identity to the vault (re-encrypting with the
    ///    same key protector).
    /// 4. Return the transition record so it can be published to the
    ///    ledger / audit log for verifiers to follow key history.
    ///
    /// The old private key is zeroized immediately after signing the
    /// transition record, ensuring the node cannot sign new forged entries
    /// with the old identity going forward.
    pub fn rotate_signing_key<P: KeyProtector>(
        &mut self,
        vault_path: &Path,
        protector: &P,
    ) -> Result<KeyTransitionRecord, Box<dyn std::error::Error>> {
        // 1. Generate a new ML-DSA-87 keypair (FIPS 204)
        let (new_dsa_pk, new_dsa_sk) = ml_dsa_87::try_keygen()
            .map_err(|e| format!("Failed to generate new ML-DSA-87 keypair: {e}"))?;

        // 2. Sign the new public key with the OLD private key (proof of continuity)
        let new_pk_bytes = {
            let pk_arr: [u8; ml_dsa_87::PK_LEN] = new_dsa_pk.clone().into_bytes();
            pk_arr.to_vec()
        };

        let transition_payload = KeyTransitionPayload {
            old_pubkey_fingerprint: self.signer_pub_fingerprint(),
            new_pubkey_fingerprint: QuantumNodeIdentity::hash_ledger_block(&new_pk_bytes),
            old_pubkey_bytes: self.dsa_public_key_bytes(),
            new_pubkey_bytes: new_pk_bytes.clone(),
        };

        let transition_payload_bytes = serde_cbor::to_vec(&transition_payload)
            .map_err(|e| format!("Failed to serialize transition payload: {e}"))?;

        let old_sig = self.sign_payload(&transition_payload_bytes)?;
        let old_sk_bytes = self.dsa_private_key_bytes.to_vec();

        // Record the transition BEFORE replacing the key
        let transition = KeyTransitionRecord {
            old_pubkey_fingerprint: transition_payload.old_pubkey_fingerprint,
            new_pubkey_fingerprint: transition_payload.new_pubkey_fingerprint,
            old_pubkey_bytes: transition_payload.old_pubkey_bytes,
            new_pubkey_bytes: transition_payload.new_pubkey_bytes,
            transition_sig_bytes: old_sig.clone(),
            transition_timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()
                as u128,
        };

        // 3. Replace the signing key, zeroizing the old private key
        self.dsa_public_key = new_dsa_pk;
        self.dsa_private_key_bytes = zeroize::Zeroizing::new(new_dsa_sk.into_bytes());
        drop(old_sk_bytes); // old private key bytes go out of scope

        // 4. Persist the updated identity to the vault (re-wrap with same protector)
        let stored = StoredIdentity {
            kem_encap_key_bytes: self.kem_encap_key.as_bytes().to_vec(),
            kem_decap_key_bytes: self.kem_decap_key_bytes.to_vec(),
            dsa_public_key_bytes: self.dsa_public_key_bytes(),
            dsa_private_key_bytes: self.dsa_private_key_bytes.to_vec(),
        };

        let pt = serde_json::to_vec(&stored)?;
        let env = vault::wrap_envelope(protector, &pt)?;
        let env_json = serde_json::to_string_pretty(&env)?;

        // Atomic write: write to temp file then rename
        let tmp_path = vault_path.with_extension("vault.tmp");
        std::fs::write(&tmp_path, env_json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&tmp_path, perms)?;
        }
        std::fs::rename(&tmp_path, vault_path)?;

        Ok(transition)
    }

    /// Compute the BLAKE3 fingerprint of this node's ML-DSA-87 public key.
    ///
    /// This is the "signer identity" that appears in checkpoints and is
    /// used by `pq_verify` to identify which key signed an artifact.
    pub fn signer_pub_fingerprint(&self) -> [u8; 32] {
        Self::hash_ledger_block(&self.dsa_public_key_bytes())
    }
}

/// Payload signed during a key rotation transition.
///
/// `OldKey signs NewPubKey → verifiable by anyone who trusts OldPubKey`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyTransitionPayload {
    pub old_pubkey_fingerprint: [u8; 32],
    pub new_pubkey_fingerprint: [u8; 32],
    pub old_pubkey_bytes: Vec<u8>,
    pub new_pubkey_bytes: Vec<u8>,
}

/// Auditable record of a signing-key rotation event.
///
/// Published to the ledger / checkpoint metadata so verifiers can follow
/// the key history and reject signatures from retired keys.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyTransitionRecord {
    pub old_pubkey_fingerprint: [u8; 32],
    pub new_pubkey_fingerprint: [u8; 32],
    pub old_pubkey_bytes: Vec<u8>,
    pub new_pubkey_bytes: Vec<u8>,
    pub transition_sig_bytes: Vec<u8>,
    pub transition_timestamp_ms: u128,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct StoredIdentity {
    kem_encap_key_bytes: Vec<u8>,
    kem_decap_key_bytes: Vec<u8>,
    dsa_public_key_bytes: Vec<u8>,
    dsa_private_key_bytes: Vec<u8>,
}

impl QuantumNodeIdentity {
    // ──────────────────────────────────────────────────────────────────
    // Byte-level serialization / deserialization
    // ──────────────────────────────────────────────────────────────────

    /// Serialize the ML-KEM-1024 encapsulation key to bytes (1568 bytes).
    pub fn encap_key_bytes(&self) -> Vec<u8> {
        self.kem_encap_key.as_bytes().to_vec()
    }

    /// Serialize the ML-DSA-87 public key to bytes (2592 bytes).
    pub fn dsa_public_key_bytes(&self) -> Vec<u8> {
        // `into_bytes` consumes `self`, so we clone via SerDes round-trip.
        let pk_bytes: [u8; ml_dsa_87::PK_LEN] = self.dsa_public_key.clone().into_bytes();
        pk_bytes.to_vec()
    }

    // ──────────────────────────────────────────────────────────────────
    // ML-KEM-1024 — typed API (struct-level, using crate types)
    // ──────────────────────────────────────────────────────────────────

    /// Encapsulate a shared key to `remote_encap_key`.
    ///
    /// Returns `(ciphertext, shared_key)`.
    pub fn encapsulate_shared_secret(
        remote_encap_key: &<MlKem1024 as KemCore>::EncapsulationKey,
    ) -> Result<(Ciphertext<MlKem1024>, SharedKey<MlKem1024>), CryptoError> {
        remote_encap_key
            .encapsulate(&mut OsRng)
            .map_err(|_| CryptoError::EncapsulationFailed)
    }

    /// Decapsulate a shared key from `ciphertext` using this node's decapsulation key.
    pub fn decapsulate_shared_secret(
        &self,
        ciphertext: &Ciphertext<MlKem1024>,
    ) -> Result<SharedKey<MlKem1024>, CryptoError> {
        let dk_arr: ml_kem::Encoded<<MlKem1024 as KemCore>::DecapsulationKey> = self
            .kem_decap_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 2400,
                actual: self.kem_decap_key_bytes.len(),
            })?;
        let decap_key = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(&dk_arr);
        decap_key
            .decapsulate(ciphertext)
            .map_err(|_| CryptoError::DecapsulationFailed)
    }

    // ──────────────────────────────────────────────────────────────────
    // ML-KEM-1024 — byte-level API (for use over the wire)
    // ──────────────────────────────────────────────────────────────────

    /// Encapsulate a shared secret towards a remote node identified by its
    /// raw encapsulation-key bytes.
    ///
    /// Returns `(ciphertext_bytes, shared_key_bytes)`.
    pub fn encapsulate_shared_secret_from_bytes(
        remote_encap_key_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        if remote_encap_key_bytes.len() != ENCAP_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ENCAP_KEY_LEN,
                actual: remote_encap_key_bytes.len(),
            });
        }

        // `EncapsulationKey<P>` implements `EncodedSizeUser` with `from_bytes(&Encoded<Self>)`.
        // `Encoded<EncapsulationKey<P>>` = `Array<u8, EncapsulationKeySize<P>>`.
        // We convert the slice to a fixed-size array then into the hybrid_array::Array type.
        let ek_fixed: [u8; ENCAP_KEY_LEN] = remote_encap_key_bytes
            .try_into()
            .map_err(|_| CryptoError::Internal("Bad encap key slice length".to_string()))?;
        let ek_arr = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::from(ek_fixed);
        let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| CryptoError::EncapsulationFailed)?;
        Ok((ct.to_vec(), ss.to_vec()))
    }

    /// Decapsulate a shared secret from raw ciphertext bytes.
    pub fn decapsulate_from_bytes(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_bytes.len() != CIPHERTEXT_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: CIPHERTEXT_LEN,
                actual: ciphertext_bytes.len(),
            });
        }

        // `Ciphertext<MlKem1024>` = `Array<u8, CiphertextSize<MlKem1024Params>>`.
        // Build it directly from the fixed-size byte array.
        let ct_fixed: [u8; CIPHERTEXT_LEN] = ciphertext_bytes
            .try_into()
            .map_err(|_| CryptoError::Internal("Bad ciphertext slice length".to_string()))?;
        let ct: Ciphertext<MlKem1024> = ct_fixed.into();

        let dk_arr: ml_kem::Encoded<<MlKem1024 as KemCore>::DecapsulationKey> = self
            .kem_decap_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength {
                expected: 2400,
                actual: self.kem_decap_key_bytes.len(),
            })?;
        let decap_key = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(&dk_arr);
        let ss = decap_key
            .decapsulate(&ct)
            .map_err(|_| CryptoError::DecapsulationFailed)?;
        Ok(ss.to_vec())
    }

    // ──────────────────────────────────────────────────────────────────
    // ML-DSA-87 — signing and verification
    // ──────────────────────────────────────────────────────────────────

    /// Sign `payload` using this node's ML-DSA-87 private key.
    ///
    /// Returns the raw signature bytes (4627 bytes for ML-DSA-87).
    pub fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let dsa_private_key = ml_dsa_87::PrivateKey::try_from_bytes(*self.dsa_private_key_bytes)
            .map_err(|e| format!("Failed to restore ML-DSA-87 key: {e}"))?;
        let signature = dsa_private_key
            .try_sign(payload, &[])
            .map_err(|e| format!("Failed to sign payload with ML-DSA-87: {e}"))?;
        Ok(signature.to_vec())
    }

    /// Verify a signature produced by a remote node.
    ///
    /// - `peer_dsa_pub_bytes`: the 2592-byte ML-DSA-87 public key of the signer.
    /// - `payload`: the signed message.
    /// - `signature`: the raw signature bytes (must be exactly 4627 bytes).
    ///
    /// Returns `true` if the signature is valid.
    pub fn verify_signature(peer_dsa_pub_bytes: &[u8], payload: &[u8], signature: &[u8]) -> bool {
        // Reconstruct the public key
        let pk_arr: [u8; ml_dsa_87::PK_LEN] = match peer_dsa_pub_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let pk = match ml_dsa_87::PublicKey::try_from_bytes(pk_arr) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Reconstruct the fixed-size signature array
        let sig_arr: [u8; ml_dsa_87::SIG_LEN] = match signature.try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };

        pk.verify(payload, &sig_arr, &[])
    }

    // ──────────────────────────────────────────────────────────────────
    // BLAKE3
    // ──────────────────────────────────────────────────────────────────

    /// Compute a BLAKE3 hash over `data`.
    pub fn hash_ledger_block(data: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_identity_handshake() {
        let node_a = QuantumNodeIdentity::generate_node_identity().unwrap();
        let node_b = QuantumNodeIdentity::generate_node_identity().unwrap();

        // FIPS 203 ML-KEM-1024 typed key exchange
        let (ciphertext, secret_a) =
            QuantumNodeIdentity::encapsulate_shared_secret(&node_b.kem_encap_key).unwrap();
        let secret_b = node_b.decapsulate_shared_secret(&ciphertext).unwrap();
        assert_eq!(
            secret_a.as_slice(),
            secret_b.as_slice(),
            "ML-KEM-1024 shared secrets must match"
        );

        // FIPS 203 byte-level round-trip
        let ek_bytes = node_b.encap_key_bytes();
        let (ct_bytes, ss_a_bytes) =
            QuantumNodeIdentity::encapsulate_shared_secret_from_bytes(&ek_bytes).unwrap();
        let ss_b_bytes = node_b.decapsulate_from_bytes(&ct_bytes).unwrap();
        assert_eq!(ss_a_bytes, ss_b_bytes, "Byte-level KEM must agree");

        // FIPS 204 ML-DSA-87 signature
        let payload = b"VARDHAN_QUANTUM_PROXY_MANIFEST_001";
        let signature = node_a.sign_payload(payload).unwrap();
        let dsa_pub = node_a.dsa_public_key_bytes();
        assert!(
            QuantumNodeIdentity::verify_signature(&dsa_pub, payload, &signature),
            "ML-DSA-87 signature must be valid"
        );

        // Wrong key must fail
        let dsa_pub_b = node_b.dsa_public_key_bytes();
        assert!(
            !QuantumNodeIdentity::verify_signature(&dsa_pub_b, payload, &signature),
            "Signature verified by wrong key must fail"
        );

        // BLAKE3
        let block_hash = QuantumNodeIdentity::hash_ledger_block(payload);
        assert_ne!(block_hash, [0u8; 32]);
    }
}

#[cfg(test)]
mod clone_test {
    use super::*;
    #[test]
    fn test_clone() {
        let id = QuantumNodeIdentity::generate_node_identity().unwrap();
        let _id2 = id.clone();
    }
}
pub mod anti_tamper;
pub mod enclave;
pub mod license;
pub mod secure_memory;
pub mod aer_kep_q;
