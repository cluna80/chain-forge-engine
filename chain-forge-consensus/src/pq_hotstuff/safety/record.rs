//! Canonical, checksummed encoding of the safety record and the initialization marker (stub: tests-first commit).
use super::*;

/// The initialization marker: written once, before any state exists, so that a missing state file is distinguishable from a
/// never-initialized validator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    pub protocol_profile: String,
    pub chain_id: String,
    pub public_key: Vec<u8>,
    pub instance_id: [u8; 16],
}

pub fn encode_record(_r: &SafetyRecord) -> Result<Vec<u8>, RecordError> { Err(RecordError::Unimplemented) }
pub fn decode_record(_b: &[u8]) -> Result<SafetyRecord, RecordError> { Err(RecordError::Unimplemented) }
pub fn encode_marker(_m: &Marker) -> Result<Vec<u8>, RecordError> { Err(RecordError::Unimplemented) }
pub fn decode_marker(_b: &[u8]) -> Result<Marker, RecordError> { Err(RecordError::Unimplemented) }
