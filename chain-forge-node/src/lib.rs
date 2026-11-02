/// Public library surface of chain-forge-node.
///
/// Integration tests (tests/*.rs) can import from this crate only when a
/// `[lib]` target exists.  We expose only what tests need; the bulk of the
/// crate lives in the [[bin]] targets.
pub mod persistence;
