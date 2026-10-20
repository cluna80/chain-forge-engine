# DIS Core — Decentralized Identity Signing Protocol

[![CI](https://github.com/cluna80/chain-forge-engine/actions/workflows/ci.yml/badge.svg)](https://github.com/cluna80/chain-forge-engine/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![PQ Safe](https://img.shields.io/badge/post--quantum-ML--DSA--65-green)

**DIS** is a post-quantum authentication protocol that lets users prove their identity to vendors using ML-DSA-65 (NIST FIPS 204) without ever exposing their private key.

> Private keys never leave the device. QR challenges expire after use. No elliptic curves. No quantum vulnerability.

---

## How It Works

---

## Why DIS?

Every QR authentication system in use today — FIDO2, WebAuthn, OAuth — relies on elliptic curve cryptography. A sufficiently powerful quantum computer breaks all of it.

DIS uses ML-DSA-65 (Dilithium3), standardized by NIST as FIPS 204 in August 2024. It is quantum-resistant by design.

---

## Features

- ✅ **Post-quantum secure** — ML-DSA-65 (NIST FIPS 204)
- ✅ **Private key never leaves device** — signing happens locally
- ✅ **Replay attack prevention** — every challenge is single-use
- ✅ **Vendor isolation** — separate keys per vendor
- ✅ **Scope binding** — signatures tied to specific resources and actions
- ✅ **Domain separation** — cryptographic binding prevents cross-protocol attacks
- ✅ **10/10 unit tests passing** — CI on every commit

---

## Crates in This Repository

| Crate | Description | License |
|-------|-------------|---------|
| `dis-core` | Protocol library — canonical request encoding, signing, verification | Apache 2.0 (this file) |
| `dis-wallet-android` | Android wallet app with JNI bridge | Commercial (BSL 1.1) |
| `dis-vendor-server` | Rust HTTP server for issuing challenges and verifying proofs | Commercial (BSL 1.1) |

---

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
dis-core = { git = "https://github.com/cluna80/chain-forge-engine", subdirectory = "dis-core" }
```

```rust
use dis_core::{canonical_request, Request, SUITE_ML_DSA_65};

let request = Request {
    suite_id: SUITE_ML_DSA_65,
    rp_id: "your-vendor-id".into(),
    rp_origin: "https://your-vendor.com".into(),
    // ... challenge fields
};

let transcript = canonical_request(&request)?;
// Sign transcript with ML-DSA-65 and send proof to your server
```

---

## Part of Qattice

DIS is the authentication layer of [Qattice](https://github.com/cluna80/chain-forge-engine) — a post-quantum blockchain built from scratch. DIS is also available as a standalone protocol for any vendor who needs post-quantum authentication.

---

## Commercial Licensing

`dis-core` is free and open source under Apache 2.0.

The **DIS Android SDK** and **DIS Vendor Server** are available under a commercial license for vendors who want:

- A white-label Android wallet with their branding
- A hosted or self-hosted vendor authentication server
- Integration support and SLA

**Contact for commercial licensing:**
- GitHub: [@cluna80](https://github.com/cluna80)
- Open an issue in this repo with the subject: `[DIS Commercial License]`

---

## Status

| Component | Status |
|-----------|--------|
| Protocol spec | ✅ Complete |
| Rust core library | ✅ Complete |
| Android wallet (Galaxy A15) | ✅ Working on real hardware |
| QR scan-to-sign | ✅ Complete |
| Vendor server | ✅ Complete |
| Persistent key storage | ✅ Complete |
| Production hardening | 🔲 In progress |

---

## License

`dis-core` is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

The DIS Android SDK and DIS Vendor Server are licensed under the Business Source License 1.1.
Commercial use requires a paid license. See the LICENSE files in those directories.
