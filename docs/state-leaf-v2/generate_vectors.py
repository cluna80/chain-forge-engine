#!/usr/bin/env python3
"""Regenerates vectors/state-leaf-v2.json and vectors/state-leaf-v1-legacy.json from the account definitions below.

The committed files are the contract: test_reference_encoder.py checks that regenerating them gives byte-identical output,
so a vector can only change through a reviewed edit of BOTH this file and the JSON. Run: python3 generate_vectors.py
Byte strings in the vector files are written either as {"hex": "..."} or, for large deterministic keys, as
{"seq": {"seed": s, "len": n}} meaning byte i = (s + i) mod 256 for i in 0..n.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reference_encoder as E  # noqa: E402


def seq(seed, n):
    return bytes((seed + i) % 256 for i in range(n))


class B:
    """A byte string with a compact JSON representation."""
    def __init__(self, raw, seq_args=None):
        self.raw, self.seq_args = bytes(raw), seq_args

    @staticmethod
    def seq(seed, n):
        return B(seq(seed, n), (seed, n))

    @staticmethod
    def hex(h):
        return B(bytes.fromhex(h))


def to_json(x):
    if isinstance(x, B):
        return {"seq": {"seed": x.seq_args[0], "len": x.seq_args[1]}} if x.seq_args else {"hex": x.raw.hex()}
    if isinstance(x, dict):
        return {k: to_json(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [to_json(v) for v in x]
    return x


def to_raw(x):
    """Account with B -> bytes (what the encoder takes)."""
    if isinstance(x, B):
        return x.raw
    if isinstance(x, dict):
        return {k: to_raw(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [to_raw(v) for v in x]
    return x


def acct(address="qcb1alice", nonce=0, role="user", balances=None, public_key=None, key_version=0, policy_generation=0,
         recovery_policy=None, pending_recovery=None, charm=None, escrow=None):
    return {"address": address, "nonce": nonce, "role": role, "balances": dict(balances or {}), "public_key": public_key,
            "key_version": key_version, "policy_generation": policy_generation, "recovery_policy": recovery_policy,
            "pending_recovery": pending_recovery, "charm": charm, "escrow": escrow}


def policy(seed=10, n=3, threshold=2, enrolled=4, pid=7):
    return {"guardians": [B.seq(seed + 7 * i, 1952) for i in range(n)], "threshold": threshold,
            "enrolled_at_key_version": enrolled, "policy_id": pid}


def pending(pk_seed=40, activation=50, cancelled=False):
    return {"new_public_key": B.seq(pk_seed, 1952), "new_key_scheme": "ml-dsa-65", "key_version": 5,
            "submitted_at_height": 10, "activation_height": activation, "policy_id": 7, "cancelled": cancelled}


def charm(tier="Verified", days=30, earned=12, since=3, attested=44, active=9, wot=True):
    return {"tier": tier, "decay_exemption": {"days": days, "last_earned_epoch": earned},
            "verified_since_epoch": since, "last_attested_epoch": attested, "consecutive_active_epochs": active,
            "verified_via_wot": wot}


ESCROW = {"job_id": "job-1", "agent_wallet": "qcb1wallet", "funding_source": "qcb1fund"}

CASES = [
    ("minimal", "no optional field, no balance", acct()),
    ("balances_sorted_input_unsorted", "three denoms given out of order; the leaf lists them ascending by byte order",
     acct(balances={"uqcb": 1000, "aaa": 5, "uex": 0})),
    ("zero_balance_entry_is_kept", "a denom with amount 0 is still an entry", acct(balances={"uqcb": 0})),
    ("with_public_key_mldsa65_size", "1952-byte public key", acct(public_key=B.seq(1, 1952), key_version=2)),
    ("empty_public_key_is_present", "Some(empty) is distinct from None", acct(public_key=B(b""))),
    ("with_recovery_policy", "3 guardians of 1952 bytes, threshold 2", acct(recovery_policy=policy(), policy_generation=2)),
    ("recovery_policy_guardian_order_matters", "same guardians in another order give another hash",
     acct(recovery_policy={**policy(), "guardians": list(reversed(policy()["guardians"]))}, policy_generation=2)),
    ("with_pending_recovery", "pending record, not cancelled", acct(pending_recovery=pending())),
    ("with_pending_recovery_cancelled", "same record with cancelled = true", acct(pending_recovery=pending(cancelled=True))),
    ("with_charm_verified", "charm with every field set", acct(charm=charm())),
    ("with_charm_provisional_no_since", "verified_since_epoch absent", acct(charm=charm("Provisional", since=None, wot=False))),
    ("with_charm_established", "tier Established", acct(charm=charm("Established", days=0, earned=0, since=1, attested=0, active=0))),
    ("with_escrow", "dormant escrow binding", acct(escrow=ESCROW)),
    ("all_fields", "every optional field present",
     acct(address="qcb1all", nonce=77, role="validator", balances={"uqcb": 10**30, "uex": 1},
          public_key=B.seq(3, 1952), key_version=9, policy_generation=4, recovery_policy=policy(),
          pending_recovery=pending(), charm=charm(), escrow=ESCROW)),
    ("non_ascii_strings", "UTF-8 is hashed as bytes, never normalised",
     acct(address="qcb1ünï", role="用户", balances={"µqcb": 3})),
    ("denom_with_separators", "denoms containing '|' and '=' (ambiguous in v1) are unambiguous in v2",
     acct(balances={"a=1|b": 2})),
    ("two_denoms_a_and_b", "the honest map {'a':1,'b':2}; its v1 text equals the one for the forged single denom 'a=1|b' (see denom_with_separators), its v2 leaf does not",
     acct(balances={"a": 1, "b": 2})),
    ("numeric_extremes", "u64 / u128 / u32 maxima", acct(nonce=E.U64_MAX, balances={"uqcb": E.U128_MAX},
                                                          key_version=E.U32_MAX, policy_generation=E.U64_MAX)),
    ("max_balance_entries", "256 entries, the bound", acct(balances={f"d{i:03d}": i for i in range(256)})),
]


def _hex(b): return b.hex()


def case_vector(name, desc, account):
    raw = to_raw(account)
    leaf = E.encode_leaf_v2(raw)
    hashes, bodies = {}, {}
    for key, enc, h in (("recovery_policy", E.encode_recovery_policy, E.recovery_policy_hash),
                        ("pending_recovery", E.encode_pending_recovery, E.pending_recovery_hash),
                        ("charm", E.encode_charm, E.charm_hash), ("escrow", E.encode_escrow, E.escrow_hash)):
        if raw.get(key) is not None:
            body = enc(raw[key])
            hashes[key] = _hex(h(raw[key]))
            bodies[key] = ({"body_hex": _hex(body)} if len(body) <= 512 else
                           {"body_len": len(body), "body_sha3_256": hashlib.sha3_256(body).hexdigest()})
    return {
        "name": name, "description": desc, "account": to_json(account),
        "expected": {
            "leaf_hex": _hex(leaf), "leaf_len": len(leaf), "leaf_sha3_256": hashlib.sha3_256(leaf).hexdigest(),
            "substructure_hashes": hashes, "substructure_bodies": bodies,
            "jmt_value_hash": _hex(E.jmt_value_hash(leaf)),
            "jmt_leaf_node_hash": _hex(E.jmt_leaf_node_hash(raw["address"], leaf)),
        },
    }


def negative_vectors():
    out = []

    def add(name, data, code, kind="leaf"):
        out.append({"name": name, "kind": kind, "hex": _hex(data), "expected_error": code})

    def frame(fields, version=2, length=None):
        """MAGIC || version || U32 body length || fields (length can be forged)."""
        return E.MAGIC + bytes([version]) + (len(fields) if length is None else length).to_bytes(4, "big") + fields

    def fields_of(leaf):
        return leaf[13:]

    minimal = E.encode_leaf_v2(to_raw(acct()))
    f = fields_of(minimal)
    addr = f[:1 + 4 + len(b"qcb1alice")]                         # tag 01 + str
    rest = f[len(addr):]
    nonce_f, after_nonce = rest[:1 + 8], rest[1 + 8:]

    # framing and header
    add("bad_magic", b"\x01" + minimal[1:], "bad_magic")
    add("bad_version_1", frame(f, version=1), "bad_version")
    add("bad_version_3", frame(f, version=3), "bad_version")
    add("empty_input", b"", "truncated")
    add("magic_only", E.MAGIC, "truncated")
    add("body_length_one_too_large", frame(f, length=len(f) + 1), "truncated")
    add("body_length_one_too_small", frame(f, length=len(f) - 1), "trailing_bytes")
    add("body_length_zero", frame(f, length=0), "trailing_bytes")
    add("trailing_byte_after_a_complete_leaf", minimal + b"\x00", "trailing_bytes")
    add("trailing_garbage_tag_ff", minimal + b"\xff", "trailing_bytes")
    # tags
    add("tag_out_of_order", frame(nonce_f + addr + after_nonce), "tag_out_of_order")   # tag 02 placed before tag 01
    add("duplicate_tag", frame(addr + addr + rest), "duplicate_tag")
    add("missing_address", frame(rest), "missing_required_tag")
    add("missing_nonce", frame(addr + after_nonce), "missing_required_tag")
    add("unknown_tag_0d", frame(f + b"\x0d"), "unknown_tag")
    add("unknown_tag_00", frame(b"\x00" + f), "unknown_tag")
    add("unknown_tag_ff", frame(f + b"\xff"), "unknown_tag")
    # tier
    tier_idx = minimal.index(bytes([E.TAG_TIER]) + b"\x00" + bytes([E.TAG_BALANCES]))
    add("tier_out_of_range", minimal[:tier_idx + 1] + b"\x04" + minimal[tier_idx + 2:], "tier_out_of_range")
    add("tier_nonzero_without_charm_hash", minimal[:tier_idx + 1] + b"\x02" + minimal[tier_idx + 2:], "tier_charm_mismatch")
    with_charm = E.encode_leaf_v2(to_raw(acct(charm=charm())))
    ti = with_charm.index(bytes([E.TAG_TIER]) + b"\x02")
    add("charm_hash_with_tier_zero", with_charm[:ti + 1] + b"\x00" + with_charm[ti + 2:], "tier_charm_mismatch")
    # strings and lengths
    add("address_over_bound", frame(b"\x01" + (E.MAX_ADDRESS_BYTES + 1).to_bytes(4, "big") + b"a" * (E.MAX_ADDRESS_BYTES + 1) + rest),
        "length_over_bound")
    add("address_empty", frame(b"\x01" + b"\x00\x00\x00\x00" + rest), "empty_not_allowed")
    add("address_invalid_utf8", frame(b"\x01" + b"\x00\x00\x00\x02" + b"\xc3\x28" + rest), "invalid_utf8")
    add("address_length_runs_past_end", frame(b"\x01" + b"\x00\x00\x00\xff" + b"abc"), "truncated")
    add("role_over_bound", frame(addr + nonce_f + b"\x03" + (E.MAX_ROLE_BYTES + 1).to_bytes(4, "big") + b"r" * (E.MAX_ROLE_BYTES + 1) +
                                 after_nonce[1 + 4 + 4:]), "length_over_bound")
    # balances
    two = E.encode_leaf_v2(to_raw(acct(balances={"aaa": 1, "bbb": 2})))
    bi = two.index(bytes([E.TAG_BALANCES]) + b"\x00\x00\x00\x02")
    ent = 4 + 3 + 16
    first, second = two[bi + 5: bi + 5 + ent], two[bi + 5 + ent: bi + 5 + 2 * ent]
    tail = two[bi + 5 + 2 * ent:]
    add("balances_descending", two[:bi + 5] + second + first + tail, "balances_not_strictly_ascending")
    add("balances_duplicate_denom", two[:bi + 5] + first + first + tail, "balances_not_strictly_ascending")
    add("balances_count_over_bound", two[:bi + 1] + (E.MAX_BALANCE_ENTRIES + 1).to_bytes(4, "big") + two[bi + 5:],
        "balance_count_over_bound")
    add("balances_count_larger_than_entries", two[:bi + 1] + b"\x00\x00\x00\x03" + two[bi + 5:],
        "length_over_bound")   # the 3rd entry's length is read from the next field bytes (07 00 00 00 ...) and exceeds the bound
    add("balances_empty_denom", frame(fields_of(two)[:bi - 13 + 1] + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x00" +
                                      (1).to_bytes(16, "big") + tail), "empty_not_allowed")
    add("balances_invalid_utf8_denom", frame(fields_of(two)[:bi - 13 + 1] + b"\x00\x00\x00\x01" + b"\x00\x00\x00\x02\xc3\x28" +
                                             (1).to_bytes(16, "big") + tail), "invalid_utf8")
    # hashes and public key
    ch = E.encode_leaf_v2(to_raw(acct(charm=charm())))
    add("charm_hash_truncated_31_bytes", frame(fields_of(ch)[:-1]), "truncated")
    pk = E.encode_leaf_v2(to_raw(acct(public_key=B(b"\x09"))))
    pki = pk.index(bytes([E.TAG_PUBLIC_KEY]) + b"\x00\x00\x00\x01")
    add("public_key_over_bound", pk[:pki + 1] + (E.MAX_PUBLIC_KEY_BYTES + 1).to_bytes(4, "big") + pk[pki + 5:], "length_over_bound")
    add("leaf_over_total_bound", frame(f + b"\x00" * E.MAX_LEAF_BYTES), "leaf_over_bound")
    # substructure bodies
    rp = E.encode_recovery_policy(to_raw(policy(n=2)))
    add("recovery_policy_zero_guardians", rp[:16] + b"\x00\x00\x00\x00", "guardian_count", "recovery_policy")
    add("recovery_policy_too_many_guardians", rp[:16] + (E.MAX_GUARDIANS + 1).to_bytes(4, "big") + rp[20:],
        "guardian_count", "recovery_policy")
    add("recovery_policy_trailing_byte", rp + b"\x00", "trailing_bytes", "recovery_policy")
    add("recovery_policy_truncated", rp[:-1], "truncated", "recovery_policy")
    add("recovery_policy_guardian_over_bound", rp[:20] + (E.MAX_PUBLIC_KEY_BYTES + 1).to_bytes(4, "big") + rp[24:],
        "length_over_bound", "recovery_policy")
    pr = E.encode_pending_recovery(to_raw(pending()))
    add("pending_cancelled_byte_2", pr[:-1] + b"\x02", "bool_not_01", "pending_recovery")
    add("pending_trailing_byte", pr + b"\x00", "trailing_bytes", "pending_recovery")
    add("pending_scheme_invalid_utf8", pr[:4 + 1952] + b"\x00\x00\x00\x02\xc3\x28" + pr[4 + 1952 + 4 + 9:], "invalid_utf8",
        "pending_recovery")
    add("pending_truncated", pr[:-1], "truncated", "pending_recovery")
    cm = E.encode_charm(to_raw(charm()))
    add("charm_tier_zero", b"\x00" + cm[1:], "tier_out_of_range", "charm")
    add("charm_tier_4", b"\x04" + cm[1:], "tier_out_of_range", "charm")
    add("charm_since_flag_2", cm[:1 + 4 + 8] + b"\x02" + cm[1 + 4 + 8 + 1:], "bool_not_01", "charm")
    add("charm_wot_byte_2", cm[:-1] + b"\x02", "bool_not_01", "charm")
    add("charm_trailing_byte", cm + b"\x00", "trailing_bytes", "charm")
    add("charm_truncated", cm[:-1], "truncated", "charm")
    es = E.encode_escrow(ESCROW)
    add("escrow_trailing_byte", es + b"\x00", "trailing_bytes", "escrow")
    add("escrow_truncated", es[:-1], "truncated", "escrow")
    return out


LEGACY_CASES = [
    # (name, v1 input account, note). The first eight are the S1 parity corpus pinned in chain-forge-state's tests.
    ("plain", acct(address="ex1a", nonce=3, balances={"uex": 1000}), None),
    ("pk", acct(address="ex1a", nonce=3, balances={"uex": 1000}, public_key=B.hex("01020304")), None),
    ("escrow", acct(address="ex1a", nonce=3, balances={"uex": 1000},
                    escrow={"job_id": "j1", "agent_wallet": "w", "funding_source": "f"}), None),
    ("key_version_not_in_v1_leaf", acct(address="ex1a", nonce=3, balances={"uex": 1000}, key_version=5), None),
    ("recovery", acct(address="ex1a", nonce=3, balances={"uex": 1000},
                      recovery_policy={"guardians": [B.hex("01"), B.hex("02")], "threshold": 2,
                                       "enrolled_at_key_version": 1, "policy_id": 7}), None),
    ("pgen", acct(address="ex1a", nonce=3, balances={"uex": 1000}, policy_generation=4), None),
    ("pending_not_in_v1_leaf", acct(address="ex1a", nonce=3, balances={"uex": 1000},
                                    pending_recovery={"new_public_key": B.hex("01"), "new_key_scheme": "ml-dsa-65",
                                                      "key_version": 2, "submitted_at_height": 10,
                                                      "activation_height": 20, "policy_id": 1, "cancelled": False}), None),
    ("all", acct(address="ex1a", nonce=3, balances={"uex": 1000}, public_key=B.hex("01020304"), key_version=5,
                 policy_generation=4,
                 recovery_policy={"guardians": [B.hex("01"), B.hex("02")], "threshold": 2, "enrolled_at_key_version": 1,
                                  "policy_id": 7},
                 pending_recovery={"new_public_key": B.hex("01"), "new_key_scheme": "ml-dsa-65", "key_version": 2,
                                   "submitted_at_height": 10, "activation_height": 20, "policy_id": 1,
                                   "cancelled": False},
                 escrow={"job_id": "j1", "agent_wallet": "w", "funding_source": "f"}), None),
    ("v1_ambiguity_two_denoms", acct(address="x", balances={"a": 1, "b": 2}), "same v1 bytes as the next case"),
    ("v1_ambiguity_one_denom_with_separators", acct(address="x", balances={"a=1|b": 2}),
     "same v1 bytes as the previous case: v1 is not injective in principle"),
    ("v1_charm_tier_text", acct(address="ex1a", nonce=1, balances={"uex": 1}, charm=charm("Established")), None),
]


def legacy_vector(name, account, note):
    raw = to_raw(account)
    leaf = E.encode_leaf_v1(raw)
    return {"name": name, "note": note, "account": to_json(account), "expected": {
        "leaf_text": leaf.decode("utf-8"), "leaf_hex": _hex(leaf),
        "jmt_value_hash": _hex(E.jmt_value_hash(leaf)), "jmt_leaf_node_hash": _hex(E.jmt_leaf_node_hash(raw["address"], leaf))}}


def build_v2():
    return {
        "format": "qattice-state-leaf-vectors", "leaf_version": 2,
        "magic_hex": E.MAGIC.hex(),
        "domains": {"recovery_policy": E.DOMAIN_RECOVERY_POLICY.decode(), "pending_recovery": E.DOMAIN_PENDING_RECOVERY.decode(),
                    "charm": E.DOMAIN_CHARM.decode(), "escrow": E.DOMAIN_ESCROW.decode()},
        "bounds": {"address": E.MAX_ADDRESS_BYTES, "role": E.MAX_ROLE_BYTES, "denom": E.MAX_DENOM_BYTES,
                   "balance_entries": E.MAX_BALANCE_ENTRIES, "public_key": E.MAX_PUBLIC_KEY_BYTES,
                   "guardians": E.MAX_GUARDIANS, "scheme": E.MAX_SCHEME_BYTES, "escrow_field": E.MAX_ESCROW_FIELD_BYTES,
                   "leaf": E.MAX_LEAF_BYTES},
        "byte_string_notation": "{'hex': str} or {'seq': {'seed': s, 'len': n}} meaning byte i = (s + i) mod 256",
        "positive": [case_vector(*c) for c in CASES],
        "negative": negative_vectors(),
    }


def build_v1():
    return {"format": "qattice-state-leaf-vectors", "leaf_version": 1,
            "note": "Frozen legacy text leaf. The first eight cases mirror the S1 parity corpus in chain-forge-state.",
            "cases": [legacy_vector(*c) for c in LEGACY_CASES]}


def dump(obj):
    return json.dumps(obj, indent=1, sort_keys=False, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    out = os.path.join(HERE, "vectors")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "state-leaf-v2.json"), "w", encoding="utf-8", newline="\n") as f:
        f.write(dump(build_v2()))
    with open(os.path.join(out, "state-leaf-v1-legacy.json"), "w", encoding="utf-8", newline="\n") as f:
        f.write(dump(build_v1()))
    print("vectors written")
