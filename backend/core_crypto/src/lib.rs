//! # core_crypto
//!
//! Post-quantum cryptographic identity for a proxy node.
//! Wraps FIPS 203 (ML-KEM-1024) and FIPS 204 (ML-DSA-87).

pub mod aer_kep_q;
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
