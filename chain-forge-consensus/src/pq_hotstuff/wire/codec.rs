//! Encoders and strict decoders (stub: tests-first commit; every call fails until the implementation lands).
use super::*;

pub fn encode_bitmap(_bits: &[bool]) -> Result<Vec<u8>, WireError> { Err(WireError::Unimplemented) }
pub fn decode_bitmap(_bytes: &[u8]) -> Result<Vec<bool>, WireError> { Err(WireError::Unimplemented) }

macro_rules! stub_codec {
    ($($t:ty),*) => {$(
        impl $t {
            pub fn encode(&self) -> Result<Vec<u8>, WireError> { Err(WireError::Unimplemented) }
            pub fn decode(_bytes: &[u8], _permitted: AlgId) -> Result<Self, WireError> { Err(WireError::Unimplemented) }
        }
    )*};
}
stub_codec!(VoteMessage, TimeoutMessage, BlockSigningMessage, BlockIdInput, PopMessage, SignatureEnvelope, KeyRegistration);

impl BlockIdInput {
    pub fn block_id(&self) -> Result<[u8; HASH_LEN], WireError> { Err(WireError::Unimplemented) }
}
