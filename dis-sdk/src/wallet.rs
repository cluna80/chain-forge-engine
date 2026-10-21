//! Wallet SDK — ergonomic wrapper around `DemoWallet`.

use crate::SdkError;
use dis_core::wallet::DemoWallet;
use dis_core::verifier::HolderProof;
use dis_core::Request;

/// Ergonomic wallet SDK wrapping `DemoWallet`.
///
/// One instance per process; wrap in a `Mutex` for concurrent access.
pub struct WalletSdk {
    inner: DemoWallet,
}

impl WalletSdk {
    pub fn new() -> Self {
        Self { inner: DemoWallet::new() }
    }

    /// Generate a fresh ML-DSA-65 keypair for `vendor_id` and return the public key.
    pub fn provision(&mut self, vendor_id: &str, origin: &str, policy_id: &str) -> Result<Vec<u8>, SdkError> {
        self.inner.provision(vendor_id, origin, policy_id)
            .map_err(|e| SdkError::Other(format!("{e:?}")))
    }

    /// Import an existing keypair (e.g. restored from encrypted storage).
    pub fn import_key(
        &mut self,
        vendor_id: &str,
        origin: &str,
        policy_id: &str,
        pk: &[u8],
        sk: &[u8],
    ) -> Result<(), SdkError> {
        self.inner.import_key(vendor_id, origin, policy_id, pk, sk)
            .map_err(|e| SdkError::Verify(e))
    }

    /// Sign a `Request` challenge. Returns a `HolderProof`.
    /// `expected_resource` and `expected_action` are validated against the request.
    pub fn sign(&self, request: &Request, expected_resource: &str, expected_action: &str) -> Result<HolderProof, SdkError> {
        self.inner.sign(request, expected_resource, expected_action)
            .map_err(|e| SdkError::Verify(e))
    }

    /// Rotate the keypair for `vendor_id`. Returns `(old_pk, new_pk)`.
    pub fn rotate(&mut self, vendor_id: &str) -> Result<(Vec<u8>, Vec<u8>), SdkError> {
        self.inner.rotate(vendor_id)
            .map_err(|e| SdkError::Other(format!("{e:?}")))
    }

    /// Export raw `(pk, sk)` bytes for persistence.
    pub fn export_key(&self, vendor_id: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        self.inner.export_key(vendor_id)
    }

    /// Return the public key for `vendor_id`, if provisioned.
    pub fn get_public_key(&self, vendor_id: &str) -> Option<Vec<u8>> {
        self.inner.get_public_key(vendor_id)
    }

    /// List all provisioned vendor IDs.
    pub fn list_vendors(&self) -> Vec<String> {
        self.inner.list_vendors()
    }
}

impl Default for WalletSdk {
    fn default() -> Self { Self::new() }
}
