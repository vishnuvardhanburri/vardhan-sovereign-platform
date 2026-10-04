# VARDHAN Q-CORE PLATFORM

> High-assurance cryptographic infrastructure for regulated enterprises, banks, and high-consequence digital operations.

## What it is

Vardhan Q-Core is a sovereign-grade security platform for governed digital operations. It combines independent verification, policy/authority controls, post-quantum cryptography, sealed receipts, HA consensus, and runtime security controls.

The platform does **not** treat an upstream `VERIFIED_FINDING` label as trusted. Intelligence findings cross a versioned trust boundary and are independently validated by Q-Core before a transaction can be sealed.

## Core architecture

```text
Intelligence
    ↓
Evidence / Verification
    ↓
VerifiedFindingContract
    ↓
Trust Boundary
    ↓
Q-Core Gateway
    ↓
Authority / Policy
    ↓
Transaction State Machine
    ↓
PQ / Hybrid Signing
    ↓
Ledger + Independent Verification
```

### Cryptographic substrate

- ML-DSA-87 / FIPS 204 for post-quantum signatures
- Ed25519 for classical signatures
- ML-KEM for post-quantum key establishment
- BLAKE3 for integrity commitments
- zeroized secret material and anti-tamper controls

### AER-KEP-Q

AER-KEP-Q is the platform's asynchronous exposure-resilient key-establishment capability.

It provides:

- authenticated epoch descriptors
- ML-KEM session establishment
- transcript/domain/epoch/message binding
- replay rejection
- exposure detection
- epoch quarantine
- fresh epoch generation after exposure
- authenticated HA peer epoch validation
- stale/future/conflicting epoch rejection
- rollback protection
- idempotent duplicate descriptor handling
- pending-message reissue semantics

AER-KEP-Q deliberately does **not** claim retroactive protection for ciphertexts created under an epoch whose complete decryption state has already been exposed. Such traffic is quarantined and new traffic moves to a fresh authenticated epoch.

AER-KEP-Q is a protocol candidate built from established cryptographic primitives. It is not presented as a newly invented primitive or as a completed peer-reviewed cryptographic proof.

## Existing Q-Core security path

The existing receipt and governance path remains independent from AER-KEP-Q:

```text
Authority
   ↓
Transaction
   ↓
Ed25519 + ML-DSA-87 signatures
   ↓
BLAKE3 integrity
   ↓
Ledger
   ↓
Independent verification
```

AER-KEP-Q adds confidential session key establishment and exposure-aware key lifecycle management. It does not replace receipt authentication or governance controls.

## Runtime reports

Runtime documentation is intentionally kept in one small directory:

```text
runtime/
├── report.md
├── status.md
├── tests.md
└── errors.md
```

No generated logs, timestamp-heavy filenames, duplicate runtime-report directories, or large diagnostic dumps belong in `runtime/`.

## Validation

The repository CI covers:

- Rust Quantum Core
- Intelligence Plane
- Zero-Knowledge Engine
- Linux eBPF production path

AER-KEP-Q validation includes key derivation, transcript binding, replay protection, descriptor authentication, quarantine, recovery, stale/future epoch rejection, conflict detection, duplicate handling, and rollback protection.

Current security limitations are recorded in `runtime/status.md` rather than presented as completed cryptographic guarantees.

## Repository structure

```text
backend/              Rust Q-Core services and cryptographic substrate
intelligence_plane/   Intelligence, evidence, verification, trust boundary
sdks/                 TypeScript and Python SDKs
contracts/            Versioned platform contracts
zk_engine/            Zero-knowledge proof engine
runtime/              Short operational reports only
.github/              CI and release workflows
```

## Local development

### Q-Core Gateway

```bash
cd backend/vardhan_receipt
cargo run -- serve --port 8080
```

### Intelligence Plane

```bash
cd intelligence_plane
npm install
npm run vardhan
```

### Rust validation

```bash
cargo test --workspace
cargo check --workspace
```

### Intelligence validation

```bash
cd intelligence_plane
npx tsc --noEmit
npx tsx tests/trust_boundary.test.ts
```

## Security position

Vardhan Q-Core is positioned as a security infrastructure and cryptographic control platform—not as a collection of unrelated algorithms. Cryptographic combinations are used only where their security boundary and rationale are explicit.

For research status, implementation status, and known limits, use the files under `runtime/`.

## Licence

Proprietary. All rights reserved. © Vardhan Intelligence Ltd.
