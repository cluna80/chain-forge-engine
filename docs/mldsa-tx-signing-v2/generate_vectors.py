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


def main():
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
    digests = [c["v2_digest_hex"] for c in cases]
    assert len(set(digests)) == len(digests), "every case must have a distinct v2 digest"
    out = {
        "spec": "docs/mldsa-tx-signing-v2/SPEC.md",
        "domain_v1": enc.DOMAIN_V1.decode(), "domain_v2": enc.DOMAIN_V2.decode(),
        "hash": "SHA-256",
        "note": "Keys are deterministic stand-ins, not real ML-DSA keys. v2 is a PROPOSAL; nothing in the Rust code uses it.",
        "cases": cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {OUT}: {len(cases)} cases")


if __name__ == "__main__":
    main()
