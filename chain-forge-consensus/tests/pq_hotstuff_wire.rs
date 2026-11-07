//! PQ-HotStuff-2 canonical serialization (docs/pq-hotstuff-001-spec.md section 3.2): golden vectors, strictness, field binding.
//!
//! The golden vectors come from an independent oracle written from the spec (tests/vectors/gen_pq_hotstuff_wire_vectors.py),
//! not from the encoder under test.
//! Run: cargo test -p chain-forge-consensus --features pq-hotstuff --test pq_hotstuff_wire
#![cfg(feature = "pq-hotstuff")]

use chain_forge_consensus::pq_hotstuff::wire::*;
use sha3::{Digest, Sha3_256};

const ALG: AlgId = AlgId::MLDSA65_FIPS204;
const CHAIN: &str = "qattice-pqhs2-dev";
const PROFILE: &str = "qattice-pq-hotstuff-2-v2";
const PROPOSER: &str = "qcb1validator0";

const VOTE_HEX: &str = "434648317c766f74657c000100000011716174746963652d70716873322d6465760000000000000007000000000000002a111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222220000000000000029";
const TIMEOUT_HEX: &str = "434648317c74696d656f75747c000100000011716174746963652d70716873322d6465760000000000000007000000000000002a0000000000000029";
const BLOCK_SIGN_HEX: &str = "434648317c626c6f636b7c00011111111111111111111111111111111111111111111111111111111111111111";
const BLOCKID_ABSENT_HEX: &str = "434648317c626c6f636b69647c000100000018716174746963652d70712d686f7473747566662d322d763200000011716174746963652d70716873322d6465760000000000000007000000000000002a00000000000003e8222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334444444444444444444444444444444444444444444444444444444444444444000000000e7163623176616c696461746f7230";
const BLOCKID_PRESENT_HEX: &str = "434648317c626c6f636b69647c000100000018716174746963652d70712d686f7473747566662d322d763200000011716174746963652d70716873322d6465760000000000000007000000000000002a00000000000003e82222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333344444444444444444444444444444444444444444444444444444444444444440155555555555555555555555555555555555555555555555555555555555555550000000e7163623176616c696461746f7230";
// (length, sha3-256) for the long items
const POP_LEN_DIGEST: (usize, &str) = (2006, "2c4779923aa74b1eb4c2f8a1177db6836f7143aaf01fa3b5af72e4475940d62f");
const ENVELOPE_LEN_DIGEST: (usize, &str) = (3315, "ccbd4941f2df3d3d4b1b3af6187d5610758817b81e6279a50dfae75ae6adb8d9");
const KEYREG_LEN_DIGEST: (usize, &str) = (1958, "c9c9e9d31be7abcbf03e5312595770c4713cdc82566dad7ccb503b548861c8b2");
const BLOCK_ID_ABSENT: &str = "fff373a32fc29addff924db0506d0b3807b827582df6333dc066fc69efd38ffd";
const BLOCK_ID_PRESENT: &str = "4ccfbc0ec268eb9c80b1e46e4db19587f8cd9126cb3c79d07c3bc7bf131665ba";

fn b32(v: u8) -> [u8; 32] { [v; 32] }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn digest(b: &[u8]) -> String { hex(&Sha3_256::digest(b)) }
fn from_hex(s: &str) -> Vec<u8> { (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect() }
fn pubkey() -> Vec<u8> { (0..1952).map(|i| (i % 251) as u8).collect() }
fn sig() -> Vec<u8> { (0..3309).map(|i| ((i * 7) % 251) as u8).collect() }

fn vote() -> VoteMessage {
    VoteMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 7, round: 42, block_id: b32(0x11), parent_id: b32(0x22), parent_round: 41 }
}
fn timeout() -> TimeoutMessage { TimeoutMessage { alg_id: ALG, chain_id: CHAIN.into(), epoch: 7, round: 42, high_qc_round: 41 } }
fn block_sign() -> BlockSigningMessage { BlockSigningMessage { alg_id: ALG, block_id: b32(0x11) } }
fn bid(tc: Option<[u8; 32]>) -> BlockIdInput {
    BlockIdInput {
        alg_id: ALG, protocol_profile: PROFILE.into(), chain_id: CHAIN.into(), epoch: 7, round: 42, height: 1000,
        parent_id: b32(0x22), payload_hash: b32(0x33), qc_hash: b32(0x44), tc_hash: tc, proposer: PROPOSER.into(),
    }
}
fn pop() -> PopMessage { PopMessage { alg_id: ALG, chain_id: CHAIN.into(), address: PROPOSER.into(), public_key: pubkey() } }
fn envelope() -> SignatureEnvelope { SignatureEnvelope { alg_id: ALG, signature: sig() } }
fn keyreg() -> KeyRegistration { KeyRegistration { alg_id: ALG, public_key: pubkey() } }

/// Uniform decode access so the strictness tests run over every item.
trait Wire: Sized + PartialEq + std::fmt::Debug {
    fn dec(b: &[u8]) -> Result<Self, WireError>;
}
macro_rules! wire_impl { ($($t:ty),*) => {$(
    impl Wire for $t {
        fn dec(b: &[u8]) -> Result<Self, WireError> { <$t>::decode(b, ALG) }
    }
)*}; }
wire_impl!(VoteMessage, TimeoutMessage, BlockSigningMessage, BlockIdInput, PopMessage, SignatureEnvelope, KeyRegistration);

/// (name, canonical bytes, offset of alg_id, decode-ok closure)
fn all_items() -> Vec<(&'static str, Vec<u8>, usize, fn(&[u8]) -> Result<(), WireError>)> {
    fn chk<T: Wire>(b: &[u8]) -> Result<(), WireError> { T::dec(b).map(|_| ()) }
    vec![
        ("vote", vote().encode().unwrap(), TAG_VOTE.len(), chk::<VoteMessage>),
        ("timeout", timeout().encode().unwrap(), TAG_TIMEOUT.len(), chk::<TimeoutMessage>),
        ("block_sign", block_sign().encode().unwrap(), TAG_BLOCK.len(), chk::<BlockSigningMessage>),
        ("blockid_absent", bid(None).encode().unwrap(), TAG_BLOCK_ID.len(), chk::<BlockIdInput>),
        ("blockid_present", bid(Some(b32(0x55))).encode().unwrap(), TAG_BLOCK_ID.len(), chk::<BlockIdInput>),
        ("pop", pop().encode().unwrap(), TAG_POP.len(), chk::<PopMessage>),
        ("envelope", envelope().encode().unwrap(), 0, chk::<SignatureEnvelope>),
        ("keyreg", keyreg().encode().unwrap(), 0, chk::<KeyRegistration>),
    ]
}

// ---------------------------------------------------------------- golden vectors (independent oracle)

#[test]
fn golden_short_items_match_the_independent_oracle_byte_for_byte() {
    assert_eq!(hex(&vote().encode().unwrap()), VOTE_HEX);
    assert_eq!(hex(&timeout().encode().unwrap()), TIMEOUT_HEX);
    assert_eq!(hex(&block_sign().encode().unwrap()), BLOCK_SIGN_HEX);
    assert_eq!(hex(&bid(None).encode().unwrap()), BLOCKID_ABSENT_HEX);
    assert_eq!(hex(&bid(Some(b32(0x55))).encode().unwrap()), BLOCKID_PRESENT_HEX);
    assert_eq!(VoteMessage::decode(&from_hex(VOTE_HEX), ALG).unwrap(), vote());
    assert_eq!(TimeoutMessage::decode(&from_hex(TIMEOUT_HEX), ALG).unwrap(), timeout());
    assert_eq!(BlockSigningMessage::decode(&from_hex(BLOCK_SIGN_HEX), ALG).unwrap(), block_sign());
    assert_eq!(BlockIdInput::decode(&from_hex(BLOCKID_ABSENT_HEX), ALG).unwrap(), bid(None));
    assert_eq!(BlockIdInput::decode(&from_hex(BLOCKID_PRESENT_HEX), ALG).unwrap(), bid(Some(b32(0x55))));
}

#[test]
fn golden_long_items_match_the_oracle_length_and_digest() {
    let (p, e, k) = (pop().encode().unwrap(), envelope().encode().unwrap(), keyreg().encode().unwrap());
    assert_eq!((p.len(), digest(&p).as_str()), POP_LEN_DIGEST);
    assert_eq!((e.len(), digest(&e).as_str()), ENVELOPE_LEN_DIGEST);
    assert_eq!((k.len(), digest(&k).as_str()), KEYREG_LEN_DIGEST);
}

#[test]
fn block_id_is_sha3_256_of_the_canonical_input_and_matches_the_oracle() {
    assert_eq!(hex(&bid(None).block_id().unwrap()), BLOCK_ID_ABSENT);
    assert_eq!(hex(&bid(Some(b32(0x55))).block_id().unwrap()), BLOCK_ID_PRESENT);
}

#[test]
fn integers_are_big_endian_and_alg_id_is_two_bytes() {
    let v = vote().encode().unwrap();
    let a = TAG_VOTE.len();
    assert_eq!(&v[a..a + 2], &[0x00, 0x01], "alg_id u16 big-endian");
    let epoch_at = a + 2 + 4 + CHAIN.len(); // after the tag, alg_id, and the length-prefixed chain_id
    assert_eq!(&v[epoch_at..epoch_at + 8], &7u64.to_be_bytes(), "epoch u64 big-endian");
}

// ---------------------------------------------------------------- round trip and canonical form

#[test]
fn every_item_round_trips_and_re_encodes_to_identical_bytes() {
    for (name, bytes, _, chk) in all_items() {
        assert!(chk(&bytes).is_ok(), "{name} decodes");
    }
    assert_eq!(VoteMessage::decode(&vote().encode().unwrap(), ALG).unwrap().encode().unwrap(), vote().encode().unwrap());
    assert_eq!(BlockIdInput::decode(&bid(None).encode().unwrap(), ALG).unwrap(), bid(None));
    assert_eq!(PopMessage::decode(&pop().encode().unwrap(), ALG).unwrap(), pop());
    assert_eq!(SignatureEnvelope::decode(&envelope().encode().unwrap(), ALG).unwrap(), envelope());
    assert_eq!(KeyRegistration::decode(&keyreg().encode().unwrap(), ALG).unwrap(), keyreg());
}

#[test]
fn encoding_is_deterministic() {
    assert_eq!(vote().encode().unwrap(), vote().encode().unwrap());
    assert_eq!(bid(Some(b32(1))).encode().unwrap(), bid(Some(b32(1))).encode().unwrap());
}

// ---------------------------------------------------------------- strict decoding

#[test]
fn every_proper_prefix_of_every_item_is_rejected() {
    for (name, bytes, _, chk) in all_items() {
        for n in 0..bytes.len() {
            assert!(chk(&bytes[..n]).is_err(), "{name}: a {n}-byte prefix of a {}-byte item must not decode", bytes.len());
        }
    }
}

#[test]
fn trailing_bytes_after_a_complete_item_are_rejected() {
    for (name, bytes, _, chk) in all_items() {
        for extra in [1usize, 2, 100] {
            let mut b = bytes.clone();
            b.extend(std::iter::repeat(0u8).take(extra));
            assert_eq!(chk(&b).unwrap_err(), WireError::TrailingBytes(extra), "{name} +{extra}");
        }
    }
}

#[test]
fn alg_id_zero_and_unknown_values_are_rejected_before_anything_else() {
    assert_eq!(AlgId::new(0).unwrap_err(), WireError::AlgIdReserved);
    assert_eq!(AlgId::new(2).unwrap_err(), WireError::AlgIdUnknown(2));
    assert_eq!(AlgId::new(65535).unwrap_err(), WireError::AlgIdUnknown(65535));
    assert_eq!(AlgId::new(1).unwrap(), ALG);
    for (name, bytes, at, chk) in all_items() {
        for bad in [0u16, 2, 0x0100, 0xFFFF] {
            let mut b = bytes.clone();
            b[at..at + 2].copy_from_slice(&bad.to_be_bytes());
            assert!(chk(&b).is_err(), "{name}: alg_id {bad} must be rejected");
        }
    }
}

#[test]
fn a_message_of_one_type_never_decodes_as_another() {
    let msgs: Vec<(&str, Vec<u8>)> = vec![
        ("vote", vote().encode().unwrap()), ("timeout", timeout().encode().unwrap()), ("block", block_sign().encode().unwrap()),
        ("blockid", bid(None).encode().unwrap()), ("pop", pop().encode().unwrap()),
    ];
    for (n, b) in &msgs {
        assert_eq!(*n == "vote", VoteMessage::decode(b, ALG).is_ok(), "{n} as vote");
        assert_eq!(*n == "timeout", TimeoutMessage::decode(b, ALG).is_ok(), "{n} as timeout");
        assert_eq!(*n == "block", BlockSigningMessage::decode(b, ALG).is_ok(), "{n} as block");
        assert_eq!(*n == "blockid", BlockIdInput::decode(b, ALG).is_ok(), "{n} as blockid");
        assert_eq!(*n == "pop", PopMessage::decode(b, ALG).is_ok(), "{n} as pop");
    }
}

#[test]
fn a_wrong_tag_of_the_right_length_is_rejected_for_every_tagged_item() {
    let tagged: Vec<(&str, Vec<u8>, usize, fn(&[u8]) -> Result<(), WireError>)> =
        all_items().into_iter().filter(|(n, ..)| !matches!(*n, "envelope" | "keyreg")).collect();
    assert_eq!(tagged.len(), 6);
    for (name, bytes, tag_len, chk) in tagged {
        // the tag is the first `tag_len` bytes (alg_id starts right after it)
        for i in 0..tag_len {
            let mut b = bytes.clone();
            b[i] ^= 0x01;
            assert_eq!(chk(&b).unwrap_err(), WireError::BadTag, "{name}: tag byte {i} flipped");
        }
    }
}

#[test]
fn tags_are_distinct_and_prefix_free() {
    for (i, a) in ALL_TAGS.iter().enumerate() {
        for (j, b) in ALL_TAGS.iter().enumerate() {
            if i != j {
                assert!(!b.starts_with(a), "{:?} is a prefix of {:?}", std::str::from_utf8(a), std::str::from_utf8(b));
            }
        }
    }
}

#[test]
fn the_option_flag_must_be_exactly_zero_or_one() {
    for (tc, flag_from_end) in [(None, 4 + PROPOSER.len() + 1), (Some(b32(0x55)), 4 + PROPOSER.len() + 32 + 1)] {
        let good = bid(tc).encode().unwrap();
        let at = good.len() - flag_from_end;
        assert!(good[at] == 0 || good[at] == 1);
        for bad in [2u8, 3, 0x80, 0xFF] {
            let mut b = good.clone();
            b[at] = bad;
            assert_eq!(BlockIdInput::decode(&b, ALG).unwrap_err(), WireError::BadOption(bad));
        }
    }
}

// ---------------------------------------------------------------- strings

#[test]
fn strings_are_length_prefixed_utf8_without_nul_and_at_most_255_bytes() {
    let mut v = vote();
    v.chain_id = "a".repeat(255);
    let b = v.encode().unwrap();
    assert_eq!(VoteMessage::decode(&b, ALG).unwrap(), v);
    v.chain_id = "a".repeat(256);
    assert!(v.encode().is_err(), "256 bytes is over the limit");
    v.chain_id = "ab\0cd".into();
    assert!(v.encode().is_err(), "NUL is not allowed");

    let good = vote().encode().unwrap();
    let len_at = TAG_VOTE.len() + 2;
    // a 256-byte chain_id built by hand (so every declared byte is really present) is over the limit
    let mut b = good[..len_at].to_vec();
    b.extend_from_slice(&256u32.to_be_bytes());
    b.extend(std::iter::repeat(b'a').take(256));
    b.extend_from_slice(&good[len_at + 4 + CHAIN.len()..]);
    assert_eq!(VoteMessage::decode(&b, ALG).unwrap_err(), WireError::LengthTooLarge { what: "chain_id", len: 256 });
    // the same message with a 255-byte chain_id is accepted, so the rejection above is the limit and nothing else
    let mut ok = good[..len_at].to_vec();
    ok.extend_from_slice(&255u32.to_be_bytes());
    ok.extend(std::iter::repeat(b'a').take(255));
    ok.extend_from_slice(&good[len_at + 4 + CHAIN.len()..]);
    assert!(VoteMessage::decode(&ok, ALG).is_ok());
    // a length prefix far larger than the input must be an error, not a panic or a huge allocation
    let mut b = good.clone();
    b[len_at..len_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(VoteMessage::decode(&b, ALG).is_err());
    // invalid UTF-8
    let mut b = good.clone();
    b[len_at + 4] = 0xFF;
    assert!(VoteMessage::decode(&b, ALG).is_err());
    // NUL inside the string
    let mut b = good.clone();
    b[len_at + 4] = 0;
    assert!(VoteMessage::decode(&b, ALG).is_err());
}

#[test]
fn a_variable_field_split_differently_gives_different_bytes() {
    let mut a = bid(None);
    a.protocol_profile = "ab".into();
    a.chain_id = "c".into();
    let mut b = bid(None);
    b.protocol_profile = "a".into();
    b.chain_id = "bc".into();
    assert_ne!(a.encode().unwrap(), b.encode().unwrap());
    assert_ne!(a.block_id().unwrap(), b.block_id().unwrap());
    let mut c = bid(None);
    c.chain_id = "x".into();
    c.proposer = "yz".into();
    let mut d = bid(None);
    d.chain_id = "xy".into();
    d.proposer = "z".into();
    assert_ne!(c.encode().unwrap(), d.encode().unwrap());
}

// ---------------------------------------------------------------- exact key and signature lengths

#[test]
fn key_and_signature_lengths_for_alg_1_are_exact() {
    for n in [0usize, 1, 1951, 1953, 4000] {
        let mut p = pop();
        p.public_key = vec![7; n];
        assert!(p.encode().is_err(), "pop key of {n} bytes");
        assert!(KeyRegistration { alg_id: ALG, public_key: vec![7; n] }.encode().is_err(), "key registration of {n} bytes");
    }
    for n in [0usize, 1, 3308, 3310, 5000] {
        assert!(SignatureEnvelope { alg_id: ALG, signature: vec![7; n] }.encode().is_err(), "signature of {n} bytes");
    }
    // decoding rejects a well-formed length prefix that names the wrong size
    let good = keyreg().encode().unwrap();
    let mut b = good.clone();
    b[2..6].copy_from_slice(&1951u32.to_be_bytes());
    b.pop();
    assert!(KeyRegistration::decode(&b, ALG).is_err());
    let good = envelope().encode().unwrap();
    let mut b = good.clone();
    b[2..6].copy_from_slice(&3308u32.to_be_bytes());
    b.pop();
    assert!(SignatureEnvelope::decode(&b, ALG).is_err());
    // a declared length far beyond the input is an error, not an allocation
    let mut b = good;
    b[2..6].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(SignatureEnvelope::decode(&b, ALG).is_err());
}

// ---------------------------------------------------------------- bitmap primitive

#[test]
fn bitmap_is_a_bit_count_then_msb_first_bytes_with_zero_padding() {
    let bits = [true, false, true, true, false, false, false, false, true];
    let enc = encode_bitmap(&bits).unwrap();
    assert_eq!(hex(&enc), "00000009b080");
    assert_eq!(decode_bitmap(&enc).unwrap(), bits);
    assert_eq!(hex(&encode_bitmap(&[]).unwrap()), "00000000");
    assert_eq!(decode_bitmap(&from_hex("00000000")).unwrap(), Vec::<bool>::new());
}

#[test]
fn bitmaps_round_trip_for_every_length_up_to_40() {
    for n in 0..=40usize {
        let bits: Vec<bool> = (0..n).map(|i| (i * 5 + n) % 3 == 0).collect();
        let enc = encode_bitmap(&bits).unwrap();
        assert_eq!(enc.len(), 4 + (n + 7) / 8);
        assert_eq!(decode_bitmap(&enc).unwrap(), bits, "n={n}");
    }
}

#[test]
fn a_bitmap_with_a_set_padding_bit_a_wrong_byte_count_or_trailing_bytes_is_rejected() {
    assert_eq!(decode_bitmap(&from_hex("00000009b081")).unwrap_err(), WireError::BadBitmap, "pad bit set");
    assert!(decode_bitmap(&from_hex("00000009b0")).is_err(), "too few bytes");
    assert!(decode_bitmap(&from_hex("00000009b08000")).is_err(), "too many bytes");
    assert!(decode_bitmap(&from_hex("00000000ff")).is_err(), "zero bits with data");
    assert!(decode_bitmap(&from_hex("0000")).is_err(), "truncated count");
    assert!(decode_bitmap(&from_hex("ffffffff00")).is_err(), "huge count with little data");
}

// ---------------------------------------------------------------- every field is bound

fn all_differ(name: &str, base: &[u8], variants: Vec<Vec<u8>>) {
    for (i, v) in variants.iter().enumerate() {
        assert_ne!(base, v.as_slice(), "{name}: field #{i} is not bound into the bytes");
    }
    for i in 0..variants.len() {
        for j in i + 1..variants.len() {
            assert_ne!(variants[i], variants[j], "{name}: fields #{i} and #{j} collide");
        }
    }
}

#[test]
fn every_field_of_a_vote_changes_the_bytes() {
    let base = vote();
    let mut vs = vec![];
    let mut m = base.clone(); m.chain_id = "other-chain".into(); vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.epoch += 1; vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.round += 1; vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.block_id = b32(0x12); vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.parent_id = b32(0x23); vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.parent_round += 1; vs.push(m.encode().unwrap());
    all_differ("vote", &base.encode().unwrap(), vs);
}

#[test]
fn every_field_of_a_timeout_and_a_block_signing_message_changes_the_bytes() {
    let base = timeout();
    let mut vs = vec![];
    let mut m = base.clone(); m.chain_id = "other-chain".into(); vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.epoch += 1; vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.round += 1; vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.high_qc_round += 1; vs.push(m.encode().unwrap());
    all_differ("timeout", &base.encode().unwrap(), vs);
    assert_ne!(block_sign().encode().unwrap(), BlockSigningMessage { alg_id: ALG, block_id: b32(0x12) }.encode().unwrap());
}

#[test]
fn every_field_of_the_pop_message_changes_the_bytes() {
    let base = pop();
    let mut vs = vec![];
    let mut m = base.clone(); m.chain_id = "other-chain".into(); vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.address = "qcb1validator1".into(); vs.push(m.encode().unwrap());
    let mut m = base.clone(); m.public_key[0] ^= 1; vs.push(m.encode().unwrap());
    all_differ("pop", &base.encode().unwrap(), vs);
}

#[test]
fn every_field_of_block_id_input_changes_the_input_and_the_block_id() {
    let base = bid(Some(b32(0x55)));
    let mut vs: Vec<BlockIdInput> = vec![];
    let mut m = base.clone(); m.protocol_profile = "qattice-pq-hotstuff-2-v3".into(); vs.push(m);
    let mut m = base.clone(); m.chain_id = "other-chain".into(); vs.push(m);
    let mut m = base.clone(); m.epoch += 1; vs.push(m);
    let mut m = base.clone(); m.round += 1; vs.push(m);
    let mut m = base.clone(); m.height += 1; vs.push(m);
    let mut m = base.clone(); m.parent_id = b32(0x23); vs.push(m);
    let mut m = base.clone(); m.payload_hash = b32(0x34); vs.push(m);
    let mut m = base.clone(); m.qc_hash = b32(0x45); vs.push(m);
    let mut m = base.clone(); m.tc_hash = Some(b32(0x56)); vs.push(m);
    let mut m = base.clone(); m.tc_hash = None; vs.push(m);
    let mut m = base.clone(); m.proposer = "qcb1validator1".into(); vs.push(m);
    let inputs: Vec<Vec<u8>> = vs.iter().map(|m| m.encode().unwrap()).collect();
    let ids: Vec<Vec<u8>> = vs.iter().map(|m| m.block_id().unwrap().to_vec()).collect();
    all_differ("block_id input", &base.encode().unwrap(), inputs);
    all_differ("block_id", &base.block_id().unwrap(), ids);
}

#[test]
fn the_same_proposal_under_a_different_profile_has_a_different_block_id() {
    let a = bid(None);
    let mut b = bid(None);
    b.protocol_profile = "qattice-pq-hotstuff-2-v2-other".into();
    assert_ne!(a.block_id().unwrap(), b.block_id().unwrap());
}
