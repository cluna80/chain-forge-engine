"""Generate vectors/v2.json: real FIPS 204 ML-DSA-65 keys and signatures over the signing-v2 preimage.

Deterministic: fixed seeds, deterministic signing (rnd = 0^32), no clock, no randomness.
Signing uses an independent pure-Python FIPS 204 implementation (dilithium-py 1.5.1, installed from a hash-checked
wheel; point QATTICE_PYSITE at its site directory). The committed vectors/v2.json is the product: consumers do not
need Python or that package, and every Rust backend can verify the file (tools/k1-backend-eval `verify-v2`).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.environ.get("QATTICE_PYSITE", os.path.join(HERE, "..", "..", "..", "pyeval", "site")))
import reference_encoder as enc  # noqa: E402

OUT = os.path.join(HERE, "vectors", "v2.json")

TRANSFER = '{"Transfer":{"to":"qcb1recv","denom":"uqcb","amount":100}}'
BURN = '{"Burn":{"denom":"uqcb","amount":5}}'
CANCEL = '"CancelRecovery"'
SEED_A = bytes([0x11]) * 32
SEED_B = bytes([0x22]) * 32
BASE = dict(chain_id="qattice-alpha-1", tx_id="tx-0001", sender="qcb1sender", nonce=0, gas_limit=500000,
            body_json=TRANSFER)


def load_signer():
    from dilithium_py.ml_dsa import ML_DSA_65 as D
    return D


def build():
    D = load_signer()
    pk_a, sk_a = D.key_derive(SEED_A)
    pk_b, sk_b = D.key_derive(SEED_B)
    ctx_tx = enc.CTX_TX_V2

    def sign(sk, message, ctx):
        return D.sign(sk, message, ctx, deterministic=True)

    def hexs(b):
        return b.hex()

    def case(name, note, signer="A", expect_valid=True, sig=None, ctx=ctx_tx, verify_key=None, **over):
        p = dict(BASE)
        p.update(over)
        pk, sk = (pk_a, sk_a) if signer == "A" else (pk_b, sk_b)
        p["pq_public_key"] = over.get("pq_public_key", pk)
        msg = enc.tx_preimage(**p)
        signature = sig if sig is not None else sign(sk, msg, ctx_tx)
        vk = verify_key if verify_key is not None else pk
        return {
            "name": name, "note": note, "expect_valid": expect_valid,
            "chain_id": p["chain_id"], "id": p["tx_id"], "sender": p["sender"], "nonce": p["nonce"],
            "gas_limit": p["gas_limit"], "body_json": p["body_json"],
            "pq_public_key_hex": hexs(p["pq_public_key"]),
            "preimage_hex": hexs(msg), "context": ctx.decode(), "m_prime_hex": hexs(enc.m_prime_pure(ctx, msg)),
            "verify_public_key_hex": hexs(vk), "signature_hex": hexs(signature),
            "v1_digest_hex": hexs(enc.v1_digest(p["chain_id"], p["body_json"])),
        }

    base = case("baseline", "reference transfer, nonce 0, signed by key A")
    base_sig = bytes.fromhex(base["signature_hex"])
    cases = [
        base,
        case("nonce_1", "only the nonce differs: v1 digest is IDENTICAL to baseline (the H0-4 replay), the v2 preimage differs", nonce=1),
        case("id_changed", "only the id differs", tx_id="tx-0002"),
        case("sender_changed", "only the sender differs", sender="qcb1other"),
        case("gas_limit_changed", "only gas_limit differs", gas_limit=500001),
        case("chain_id_changed", "only the chain id differs", chain_id="qattice-alpha-2"),
        case("body_changed", "different body (Burn)", body_json=BURN),
        case("unit_variant_body", "body that serialises as a bare string", body_json=CANCEL),
        case("signer_b", "a different key signs; the key field in the preimage is key B", signer="B"),
        case("max_nonce", "nonce = u64::MAX", nonce=enc.U64_MAX),
        case("max_gas_limit", "gas_limit = u64::MAX", gas_limit=enc.U64_MAX),
        case("empty_id", "empty id is encodable (length 0)", tx_id=""),
        case("unicode_id", "non-ASCII id, UTF-8 bytes", tx_id="tx-é世"),
        case("adjacent_fields_a", "id='ab', sender='c' (prefix-freeness pair, part 1)", tx_id="ab", sender="c"),
        case("adjacent_fields_b", "id='a', sender='bc' (prefix-freeness pair, part 2): different preimage from part 1", tx_id="a", sender="bc"),
    ]
    # ---- negatives: every one must be REJECTED by every conforming verifier ----
    def neg(name, note, **kw):
        c = case(name, note, expect_valid=False, **kw)
        return c

    flipped = bytearray(base_sig); flipped[1000] ^= 0x01
    negatives = [
        neg("replay_nonce_changed", "baseline signature over a preimage whose nonce was changed to 1 (the H0-4 attack)", sig=base_sig, nonce=1),
        neg("replay_id_changed", "baseline signature, id changed", sig=base_sig, tx_id="tx-0002"),
        neg("replay_sender_changed", "baseline signature, sender changed", sig=base_sig, sender="qcb1other"),
        neg("replay_gas_changed", "baseline signature, gas_limit changed", sig=base_sig, gas_limit=500001),
        neg("replay_chain_changed", "baseline signature, chain id changed (cross-chain replay)", sig=base_sig, chain_id="qattice-alpha-2"),
        neg("replay_body_changed", "baseline signature, body changed", sig=base_sig, body_json=BURN),
        neg("replay_key_field_changed", "baseline signature, but the preimage names key B (signed by A)", sig=base_sig, pq_public_key=pk_b),
        neg("signature_bit_flipped", "one bit flipped in the baseline signature", sig=bytes(flipped)),
        neg("signature_by_other_key", "signed by key B, verified against key A", sig=sign(sk_b, enc.tx_preimage(**dict(BASE, pq_public_key=pk_a)), ctx_tx)),
    ]
    # ---- context separation: a valid signature in another protocol's context must not verify as a transaction ----
    m_base = bytes.fromhex(base["preimage_hex"])
    ctx_negs = []
    for label, ctx in (("consensus_vote", enc.CONTEXTS["consensus_vote"]), ("empty_context", b""),
                       ("transaction_v1_name", b"qattice/tx/v1"), ("max_length_context", bytes([0x41]) * 255)):
        s = D.sign(sk_a, m_base, ctx, deterministic=True)
        c = case("context_" + label, f"signature made over the same preimage in context {ctx[:40]!r}{'...' if len(ctx) > 40 else ''}; verified as a transaction (context qattice/tx/v2)",
                 expect_valid=False, sig=s)
        ctx_negs.append(c)
    # the reverse direction: a transaction signature verified in the vote context must fail too
    rev = case("context_tx_signature_as_vote", "the baseline TRANSACTION signature verified in the consensus-vote context",
               expect_valid=False, sig=base_sig)
    rev["context"] = enc.CONTEXTS["consensus_vote"].decode()
    rev["m_prime_hex"] = enc.m_prime_pure(enc.CONTEXTS["consensus_vote"], m_base).hex()
    ctx_negs.append(rev)

    all_cases = cases + negatives + ctx_negs
    return {
        "spec": "docs/mldsa-tx-signing-v2/SPEC.md",
        "algorithm": "FIPS 204 ML-DSA-65, pure interface (ML-DSA.Sign / ML-DSA.Verify with a context string)",
        "signed_message": "the complete canonical preimage (no pre-hash)",
        "preimage_version": enc.PREIMAGE_VERSION_TX,
        "context_registry": {k: v.decode() for k, v in enc.CONTEXTS.items()},
        "keys": {"A": {"seed_hex": SEED_A.hex(), "pk_hex": pk_a.hex()}, "B": {"seed_hex": SEED_B.hex(), "pk_hex": pk_b.hex()}},
        "note": "Keys are derived from fixed public seeds with FIPS 204 KeyGen_internal; they are TEST keys, never to be used elsewhere. "
                "Signatures are deterministic (rnd = 0^32), produced by an independent pure-Python FIPS 204 implementation.",
        "cases": all_cases,
        "envelope_cases": envelope_vectors(),
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
    data = build()
    names = [c["name"] for c in data["cases"] if c["expect_valid"]]
    pre = [c["preimage_hex"] for c in data["cases"] if c["expect_valid"] and c["name"] != "signer_b"]
    assert len(set(pre)) == len(pre), "every valid case must have a distinct preimage"
    assert len(names) == len(set(names))
    out_path = out_path or OUT
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    print(f"wrote {out_path}: {len(data['cases'])} cases, {len(data['envelope_cases'])} envelope cases")


if __name__ == "__main__":
    main()
