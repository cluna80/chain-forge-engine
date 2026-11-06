//! Encrypted key storage for ML-DSA-65 production keys (issue #107). See `docs/key-storage/SPEC.md`.
//! SCAFFOLD (tests first): every operation returns `Error::NotImplemented`.
#![cfg_attr(not(feature = "signing-v2"), allow(dead_code))]

#[cfg(feature = "signing-v2")]
pub mod fsperm;
#[cfg(feature = "signing-v2")]
pub mod keystore;
