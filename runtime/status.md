# Runtime Status

**Branch:** `main`

## Green
- Intelligence Plane build
- ZK engine build
- eBPF Linux production build
- AER-KEP-Q core integration build
- Authenticated epoch descriptors
- Exposure quarantine and fresh epoch generation
- HA epoch validation and rollback protection

## Known Limits
- No retroactive protection for ciphertexts from an exposed epoch.
- No complete QROM proof is claimed.
- Production HSM/KMS persistence and deployment-specific HA transport remain infrastructure work, not cryptographic correctness claims.
