# DIS-SDK-001: Vendor SDK and Reference Wallet

**Status:** Complete v0.1 — reference implementation, not production-ready  
**Branch:** dis-sec-004  
**Depends on:** DIS-PRIV-001, DIS-AGENT-001

---

## Overview

Two ergonomic Rust crates wrap `dis-core` for the two parties in a DIS-KS-V1 flow:

- **`dis-sdk` / `VendorSdk`** — relying-party (vendor server) integration
- **`dis-sdk` / `WalletSdk`** — holder (wallet) integration
- **`dis-wallet-android` / `dis-jni`** — Android reference wallet via JNI

---

## VendorSdk

```rust
let sdk = VendorSdk::new(
    VendorConfig::new("vendor-acme", "https://acme.example.com")
        .with_grant("document:001", "read", "document:read")
        .with_min_suite(SUITE_ML_DSA_65),
);
```

Key methods:

| Method | Description |
|--------|-------------|
| `enroll_key(pk)` | Enroll a holder's public key |
| `revoke_key(pk)` | Revoke a key |
| `rotate_key(old, new)` | Atomic key rotation |
| `issue_challenge(request)` | Generate a CSPRNG-filled challenge |
| `verify(request, proof, now)` | Verify a holder proof |
| `verify_delegated(request, proof, now)` | Verify a delegated agent proof |
| `approve_challenge(id)` | Approve a high-risk challenge before delegation verify |
| `request(resource, action, scopes, iat, exp)` | Build a `Request` template |

---

## WalletSdk

```rust
let mut sdk = WalletSdk::new();
let pk = sdk.provision("vendor-acme", "https://acme.example.com", "v1")?;
let proof = sdk.sign(&request, "document:001", "read")?;
```

Key methods:

| Method | Description |
|--------|-------------|
| `provision(vendor_id, origin, policy)` | Generate fresh ML-DSA-65 keypair |
| `import_key(...)` | Restore from encrypted storage |
| `sign(request, resource, action)` | Sign a challenge |
| `rotate(vendor_id)` | Rotate keypair, returns `(old_pk, new_pk)` |
| `export_key(vendor_id)` | Raw `(pk, sk)` for persistence |
| `list_vendors()` | All provisioned vendor IDs |

---

## Android Reference Wallet

`dis-wallet-android` demonstrates a complete integration:

- **`dis-jni`** — Rust JNI bridge, thin wrapper over `DemoWallet`
- **`DisWallet.kt`** — Kotlin `external fun` declarations
- **`WalletKeyStore.kt`** — Android Keystore AES-256-GCM key encryption
- **`WalletViewModel.kt`** — coroutine-based ViewModel with provision/sign/rotate/serverAuth flows
- **`VendorServerClient.kt`** — HTTP client for enroll/challenge/verify endpoints

Key JNI functions: `provision`, `signChallenge`, `listVendors`, `exportKey`, `importKey`, `rotateKey`.

---

## Conformance Vectors

`dis-core/conformance/vectors.json` contains two frozen `canonical_request()` byte sequences. Any implementation (Kotlin, Swift, Python) MUST produce identical hex before attempting ML-DSA-65 signing.

---

## Return Gates (before production use)

- [ ] Replace `DemoWallet` with HSM-backed or OS Keychain key storage
- [ ] Implement production enrollment flow (RP-authenticated bootstrap, not `enroll_test_key`)
- [ ] Android JNI: link against production ML-DSA-65 library (currently uses Dilithium from `pqcrypto`)
- [ ] External audit of `canonical_request` encoding and `DOMAIN` prefix
- [ ] Conformance test suite run against at least one non-Rust implementation
- [ ] `VendorSdk` is not thread-safe — document `Mutex` requirement or make it `Send + Sync`
