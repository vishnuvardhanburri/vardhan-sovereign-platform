# Runtime Tests

## Required CI
- Rust workspace build/test
- Intelligence Plane build
- ZK engine build
- Linux eBPF build

## AER-KEP-Q coverage
- ML-KEM session derivation
- transcript/domain/epoch/message binding
- replay rejection
- descriptor signature verification
- quarantine invalidation
- fresh epoch recovery
- stale epoch rejection
- future epoch rejection
- conflicting same-epoch descriptor rejection
- duplicate descriptor idempotency
- rollback rejection

## Regression rule
Existing receipt signing, authority evaluation, ledger formats, and Intelligence → Q-Core trust-boundary behavior must remain unchanged.
