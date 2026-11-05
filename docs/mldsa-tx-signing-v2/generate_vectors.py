"""Generate vectors/v2.json. Deterministic: no randomness, no clock."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference_encoder as enc

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "v2.json")

TRANSFER = '{"Transfer":{"to":"qcb1recv","denom":"uqcb","amount":100}}'
BURN = '{"Burn":{"denom":"uqcb","amount":5}}'
CANCEL = '"CancelRecovery"'


def key(n: int) -> bytes:
    """Deterministic stand-in public key of n bytes (not a real ML-DSA key)."""
    out = b""
    c = 0
    while len(out) < n:
        out += hashlib.sha256(b"vector-key" + c.to_bytes(4, "big")).digest()
        c += 1
    return out[:n]


BASE = dict(chain_id="qcb-testnet-1", tx_id="tx-0001", sender="qcb1sender", nonce=0, gas_limit=500000,
            body_json=TRANSFER, pq_public_key=key(32))


def case(name, note, **over):
    p = dict(BASE)
    p.update(over)
    msg = enc.v2_message(**p)
    d2 = enc.v2_digest(**p)
    d1 = enc.v1_digest(p["chain_id"], p["body_json"])
    return {
        "name": name, "note": note,
        "chain_id": p["chain_id"], "id": p["tx_id"], "sender": p["sender"], "nonce": p["nonce"],
        "gas_limit": p["gas_limit"], "body_json": p["body_json"], "pq_public_key_hex": p["pq_public_key"].hex(),
        "v2_message_hex": msg.hex(), "v2_digest_hex": d2.hex(), "v1_digest_hex": d1.hex(),
    }


def envelope_vectors():
    good_sig = "mldsa65:" + "ab" * enc.MLDSA65_SIG_BYTES
    pk = "cd" * enc.MLDSA65_PK_BYTES
    base = {"sig_scheme": "MlDsa", "signature_hex": "", "public_key_hex": "",
            "pq_signatures": [good_sig], "pq_public_key_hex": pk}
    rows = [
        ("accept_first_use", "valid envelope, unbound sender, key carried", {}, None),
        ("accept_bound_key_omitted", "valid envelope, key already bound, tx omits the key", {"pq_public_key_hex": ""}, pk),
        ("accept_bound_key_repeated", "valid envelope, key already bound, tx repeats the same key", {}, pk),
        ("reject_scheme_missing", "sig_scheme absent (legacy implicit detection)", {"sig_scheme": None}, None),
        ("reject_ed25519", "Ed25519-tagged transaction", {"sig_scheme": "Classical"}, None),
        ("reject_hybrid", "hybrid-tagged transaction", {"sig_scheme": "HybridEd25519MlDsa"}, None),
        ("reject_slhdsa", "SLH-DSA tag (no live verifier, not allowed)", {"sig_scheme": "SlhDsa"}, None),
        ("reject_fndsa", "FN-DSA tag", {"sig_scheme": "FnDsa"}, None),
        ("reject_ed25519_signature_present", "ML-DSA tag but an Ed25519 signature rides along", {"signature_hex": "00" * 64}, None),
        ("reject_ed25519_key_present", "ML-DSA tag but an Ed25519 public key rides along", {"public_key_hex": "11" * 32}, None),
        ("reject_no_signature", "no pq_signatures", {"pq_signatures": []}, None),
        ("reject_two_signatures", "two pq_signatures entries", {"pq_signatures": [good_sig, good_sig]}, None),
        ("reject_wrong_tag", "entry tagged slhdsa:", {"pq_signatures": ["slhdsa:" + "ab" * enc.MLDSA65_SIG_BYTES]}, None),
        ("reject_not_hex", "non-hex signature body", {"pq_signatures": ["mldsa65:" + "zz" * enc.MLDSA65_SIG_BYTES]}, None),
        ("reject_short_signature", "signature one byte short", {"pq_signatures": ["mldsa65:" + "ab" * (enc.MLDSA65_SIG_BYTES - 1)]}, None),
        ("reject_long_signature", "signature one byte long", {"pq_signatures": ["mldsa65:" + "ab" * (enc.MLDSA65_SIG_BYTES + 1)]}, None),
        ("reject_first_use_without_key", "unbound sender and no key", {"pq_public_key_hex": ""}, None),
        ("reject_first_use_short_key", "unbound sender, key one byte short", {"pq_public_key_hex": "cd" * (enc.MLDSA65_PK_BYTES - 1)}, None),
        ("reject_key_differs_from_bound", "bound key present, tx carries a different key", {"pq_public_key_hex": "ee" * enc.MLDSA65_PK_BYTES}, pk),
    ]
    out = []
    for name, note, over, bound in rows:
        tx = dict(base)
        tx.update(over)
        res, code = enc.check_envelope(tx, bound)
        out.append({"name": name, "note": note, "tx": tx, "bound_key_hex": bound, "expect": res, "code": code})
    return out


def main(out_path=None):
    cases = [
        case("baseline", "reference transfer, nonce 0"),
        case("nonce_1", "only the nonce differs: v1 digest is IDENTICAL (the H0-4 replay), v2 differs", nonce=1),
        case("id_changed", "only the id differs", tx_id="tx-0002"),
        case("sender_changed", "only the sender differs", sender="qcb1other"),
        case("gas_limit_changed", "only gas_limit differs", gas_limit=500001),
        case("pq_public_key_changed", "only the public key differs", pq_public_key=key(33)),
        case("chain_id_changed", "only the chain id differs", chain_id="qcb-testnet-2"),
        case("body_changed", "different body (Burn)", body_json=BURN),
        case("unit_variant_body", "body that serialises as a bare string", body_json=CANCEL),
        case("max_nonce", "nonce = u64::MAX", nonce=enc.U64_MAX),
        case("max_gas_limit", "gas_limit = u64::MAX", gas_limit=enc.U64_MAX),
        case("empty_id", "empty id is encodable (length 0)", tx_id=""),
        case("unicode_id", "non-ASCII id, UTF-8 bytes", tx_id="tx-é世"),
        case("real_size_key", "1952-byte public key (ML-DSA-65 size)", pq_public_key=key(1952)),
        case("adjacent_fields_a", "id='ab', sender='c' (prefix-freeness pair, part 1)", tx_id="ab", sender="c"),
        case("adjacent_fields_b", "id='a', sender='bc' (prefix-freeness pair, part 2): must differ from part 1", tx_id="a", sender="bc"),
    ]
    envelope_cases = envelope_vectors()
    digests = [c["v2_digest_hex"] for c in cases]
    assert len(set(digests)) == len(digests), "every case must have a distinct v2 digest"
    out = {
        "spec": "docs/mldsa-tx-signing-v2/SPEC.md",
        "domain_v1": enc.DOMAIN_V1.decode(), "domain_v2": enc.DOMAIN_V2.decode(),
        "hash": "SHA-256",
        "note": "Keys are deterministic stand-ins, not real ML-DSA keys. v2 is a PROPOSAL; nothing in the Rust code uses it.",
        "algorithm_id_hex": enc.ALG_MLDSA65.hex(),
        "cases": cases,
        "envelope_cases": envelope_cases,
    }
    out_path = out_path or OUT
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {out_path}: {len(cases)} cases")


if __name__ == "__main__":
    main()
