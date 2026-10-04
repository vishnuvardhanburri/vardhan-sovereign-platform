# Runtime Report

## Current State
- Q-Core runtime and AER-KEP-Q integration are active on `main`.
- Existing receipt, authority, ledger, and verification paths remain unchanged.
- AER-KEP-Q provides authenticated epoch lifecycle, exposure quarantine, fresh epoch recovery, replay protection, and HA descriptor validation.

## Security Boundary
- Full-state exposure does not provide retroactive protection for ciphertexts created under the exposed epoch.
- Exposed epochs are quarantined and new traffic uses a fresh authenticated epoch.
- AER-KEP-Q is a protocol candidate built on standardized ML-KEM and ML-DSA primitives; this repository does not claim a new cryptographic primitive.

## Validation
See `runtime/status.md` and `runtime/tests.md`.
