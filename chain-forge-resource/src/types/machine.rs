//! Machine registry types.
//!
//! A *machine* is a real compute node operated by a provider.  Every
//! machine has a unique MachineID, an attestation key (separate from the
//! provider's identity key), and a capability descriptor that tells the
//! marketplace what the machine can offer.

use serde::{Deserialize, Serialize};

/// Opaque identifier for a resource node.
///
/// On devnet this is a human-readable tag (e.g. `"MACH-CAROL-003"`).
/// On mainnet this will be a hash of the attestation public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MachineId(pub String);

impl std::fmt::Display for MachineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identifier of an individual provider (human or legal person).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SponsorId(pub String);

/// Identifier of an enterprise provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnterpriseId(pub String);

/// Who owns and is accountable for this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id")]
pub enum ProviderOwner {
    /// A single identified person.
    Individual(SponsorId),
    /// A registered enterprise entity.
    Enterprise(EnterpriseId),
}

/// Whether this machine accepts marketplace jobs, Grand Challenge
/// contributions, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MachineMode {
    /// Accepts only open-market resource requests.
    MarketplaceOnly,
    /// Participates only in governance-voted Grand Challenges.
    ContributionOnly,
    /// Participates in both.
    Both,
}

/// Ed25519 public key (32 bytes, base64-encoded) used exclusively for
/// machine attestation.  Kept separate from the provider's identity key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineAttestationKey {
    /// Base64-encoded 32-byte Ed25519 public key.
    pub public_key_b64: String,
}

/// Lifecycle status of a machine in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MachineStatus {
    /// Registered but not yet active.
    Pending,
    /// Active and accepting work.
    Active,
    /// Voluntarily offline.
    Inactive,
    /// Slashed / removed from the market.
    Banned,
}

/// The full record for a registered resource node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineRecord {
    /// Unique identifier for this machine.
    pub machine_id: MachineId,
    /// The owner / accountable party.
    pub owner: ProviderOwner,
    /// Attestation key (NOT the provider's identity key).
    pub attestation_key: MachineAttestationKey,
    /// What this machine can do and how much it charges.
    pub capability_descriptor: super::capability::ResourceCapabilityDescriptor,
    /// Operating mode (marketplace / contribution / both).
    pub mode: MachineMode,
    /// Current status in the registry.
    pub status: MachineStatus,
}
