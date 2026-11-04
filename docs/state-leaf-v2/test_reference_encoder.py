#!/usr/bin/env python3
"""Self-tests for the account-state leaf reference encoder (PR-A). Standard library only.

Run from the repository root:   python3 -m unittest discover -s docs/state-leaf-v2 -v
"""
import copy
import hashlib
import itertools
import json
import os
import random
import re
import shutil
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate_vectors as G  # noqa: E402
import reference_encoder as E  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
V2_PATH = os.path.join(HERE, "vectors", "state-leaf-v2.json")
V1_PATH = os.path.join(HERE, "vectors", "state-leaf-v1-legacy.json")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def revive(x):
    """JSON vector -> account with real bytes."""
    if isinstance(x, dict):
        if set(x) == {"hex"}:
            return bytes.fromhex(x["hex"])
        if set(x) == {"seq"}:
            return G.seq(x["seq"]["seed"], x["seq"]["len"])
        return {k: revive(v) for k, v in x.items()}
    if isinstance(x, list):
        return [revive(v) for v in x]
    return x


def decode_any(kind, data):
    return {"leaf": E.decode_leaf_v2, "recovery_policy": E.decode_recovery_policy,
            "pending_recovery": E.decode_pending_recovery, "charm": E.decode_charm,
            "escrow": E.decode_escrow}[kind](data)


class CommittedVectors(unittest.TestCase):
    def test_committed_files_equal_a_fresh_regeneration(self):
        for path, fresh in ((V2_PATH, G.build_v2()), (V1_PATH, G.build_v1())):
            with open(path, encoding="utf-8") as f:
                self.assertEqual(f.read(), G.dump(fresh))

    def test_vector_counts(self):
        v = load(V2_PATH)
        self.assertGreaterEqual(len(v["positive"]), 19)
        self.assertGreaterEqual(len(v["negative"]), 40)
        self.assertEqual(v["magic_hex"], "0051414c4541460" + "0")


class PositiveVectors(unittest.TestCase):
    def setUp(self):
        self.v = load(V2_PATH)

    def test_every_positive_vector_encodes_to_the_recorded_bytes(self):
        for case in self.v["positive"]:
            with self.subTest(case["name"]):
                acct = revive(case["account"])
                leaf = E.encode_leaf_v2(acct)
                exp = case["expected"]
                self.assertEqual(leaf.hex(), exp["leaf_hex"])
                self.assertEqual(len(leaf), exp["leaf_len"])
                self.assertEqual(hashlib.sha3_256(leaf).hexdigest(), exp["leaf_sha3_256"])
                self.assertEqual(E.jmt_value_hash(leaf).hex(), exp["jmt_value_hash"])
                self.assertEqual(E.jmt_leaf_node_hash(acct["address"], leaf).hex(), exp["jmt_leaf_node_hash"])
                for key, h in (("recovery_policy", E.recovery_policy_hash), ("pending_recovery", E.pending_recovery_hash),
                               ("charm", E.charm_hash), ("escrow", E.escrow_hash)):
                    if acct.get(key) is None:
                        self.assertNotIn(key, exp["substructure_hashes"])
                    else:
                        self.assertEqual(h(acct[key]).hex(), exp["substructure_hashes"][key])

    def test_decoder_round_trips_every_positive_vector(self):
        for case in self.v["positive"]:
            with self.subTest(case["name"]):
                acct = revive(case["account"])
                leaf = E.encode_leaf_v2(acct)
                d = E.decode_leaf_v2(leaf)
                self.assertEqual(d["address"], acct["address"])
                self.assertEqual(d["nonce"], acct["nonce"])
                self.assertEqual(d["role"], acct["role"])
                self.assertEqual(sorted(acct["balances"].items(), key=lambda kv: kv[0].encode()), d["balances"])
                self.assertEqual(d.get("public_key"), acct["public_key"])
                self.assertEqual(d["key_version"], acct["key_version"])
                self.assertEqual(d["policy_generation"], acct["policy_generation"])
                self.assertEqual(("charm_hash" in d), acct["charm"] is not None)
                self.assertEqual(("recovery_policy_hash" in d), acct["recovery_policy"] is not None)
                self.assertEqual(("pending_recovery_hash" in d), acct["pending_recovery"] is not None)
                self.assertEqual(("escrow_hash" in d), acct["escrow"] is not None)

    def test_substructure_bodies_round_trip(self):
        for case in self.v["positive"]:
            acct = revive(case["account"])
            if acct["recovery_policy"] is not None:
                self.assertEqual(E.decode_recovery_policy(E.encode_recovery_policy(acct["recovery_policy"])),
                                 {**{k: acct["recovery_policy"][k] for k in ("threshold", "enrolled_at_key_version", "policy_id")},
                                  "guardians": acct["recovery_policy"]["guardians"]})
            if acct["pending_recovery"] is not None:
                self.assertEqual(E.decode_pending_recovery(E.encode_pending_recovery(acct["pending_recovery"])),
                                 acct["pending_recovery"])
            if acct["charm"] is not None:
                self.assertEqual(E.decode_charm(E.encode_charm(acct["charm"])), acct["charm"])
            if acct["escrow"] is not None:
                self.assertEqual(E.decode_escrow(E.encode_escrow(acct["escrow"])), acct["escrow"])

    def test_layout_facts(self):
        leaf = E.encode_leaf_v2(G.to_raw(G.acct()))
        self.assertEqual(leaf[:8], bytes([0, 0x51, 0x41, 0x4C, 0x45, 0x41, 0x46, 0]))
        self.assertEqual(leaf[8], 2)                                         # version
        self.assertEqual(int.from_bytes(leaf[9:13], "big"), len(leaf) - 13)  # explicit body length
        self.assertEqual(leaf[13], 0x01)                                     # first field: address
        self.assertEqual(leaf[-9:], bytes([0x08]) + (0).to_bytes(8, "big"))  # last field of a minimal leaf: policy_generation
        self.assertEqual(leaf.hex(), load(V2_PATH)["positive"][0]["expected"]["leaf_hex"])

    def test_cases_are_pairwise_distinct(self):
        leaves = [c["expected"]["leaf_hex"] for c in self.v["positive"]]
        self.assertEqual(len(leaves), len(set(leaves)))


class NegativeVectors(unittest.TestCase):
    def test_every_malformed_input_is_rejected_with_the_expected_code(self):
        for case in load(V2_PATH)["negative"]:
            with self.subTest(case["name"]):
                with self.assertRaises(E.DecodingError) as cm:
                    decode_any(case["kind"], bytes.fromhex(case["hex"]))
                self.assertEqual(cm.exception.code, case["expected_error"])

    def test_every_proper_prefix_of_every_leaf_is_rejected(self):
        for case in load(V2_PATH)["positive"]:
            if case["expected"]["leaf_len"] > 3000:
                continue                                       # keep the quadratic scan small; large cases covered below
            leaf = bytes.fromhex(case["expected"]["leaf_hex"])
            for n in range(len(leaf)):
                with self.subTest(case=case["name"], prefix=n):
                    try:
                        E.decode_leaf_v2(leaf[:n])
                    except E.DecodingError:
                        continue
                    # The explicit body length makes the format prefix-free: no proper prefix can ever decode.
                    self.fail(f"proper prefix of length {n} decoded")

    def test_large_leaves_reject_a_sample_of_prefixes(self):
        rnd = random.Random(7)
        for case in load(V2_PATH)["positive"]:
            leaf = bytes.fromhex(case["expected"]["leaf_hex"])
            if len(leaf) <= 3000:
                continue
            for n in rnd.sample(range(len(leaf)), 300):
                with self.assertRaises(E.DecodingError):
                    E.decode_leaf_v2(leaf[:n])

    def test_no_single_bit_flip_decodes_to_the_same_value(self):
        for name in ("minimal", "with_charm_verified", "with_escrow", "balances_sorted_input_unsorted"):
            case = next(c for c in load(V2_PATH)["positive"] if c["name"] == name)
            leaf = bytes.fromhex(case["expected"]["leaf_hex"])
            original = E.decode_leaf_v2(leaf)
            for i in range(len(leaf)):
                for bit in range(8):
                    mutated = bytearray(leaf)
                    mutated[i] ^= 1 << bit
                    try:
                        d = E.decode_leaf_v2(bytes(mutated))
                    except E.DecodingError:
                        continue
                    self.assertNotEqual(d, original, f"{name}: flipping byte {i} bit {bit} left the decoded value unchanged")


class FieldMutation(unittest.TestCase):
    """T1 analogue: every field the account can carry changes the leaf, and every change gives a different leaf."""
    def test_every_single_field_mutation_changes_the_leaf(self):
        base = G.to_raw(G.CASES[[c[0] for c in G.CASES].index("all_fields")][2])
        base_leaf = E.encode_leaf_v2(base)

        def mut(fn):
            a = copy.deepcopy(base)
            fn(a)
            return a

        def flip_byte(b, i): return b[:i] + bytes([b[i] ^ 0x01]) + b[i + 1:]

        mutations = {
            "address": lambda a: a.__setitem__("address", "qcb1alicf"),
            "nonce": lambda a: a.__setitem__("nonce", a["nonce"] + 1),
            "role": lambda a: a.__setitem__("role", "user"),
            "balance_amount": lambda a: a["balances"].__setitem__("uex", 2),
            "balance_denom": lambda a: (a["balances"].pop("uex"), a["balances"].__setitem__("uey", 1)),
            "balance_added": lambda a: a["balances"].__setitem__("zzz", 1),
            "public_key_byte": lambda a: a.__setitem__("public_key", flip_byte(a["public_key"], 1000)),
            "public_key_removed": lambda a: a.__setitem__("public_key", None),
            "key_version": lambda a: a.__setitem__("key_version", a["key_version"] + 1),
            "policy_generation": lambda a: a.__setitem__("policy_generation", a["policy_generation"] + 1),
            "recovery_threshold": lambda a: a["recovery_policy"].__setitem__("threshold", 3),
            "recovery_enrolled_kv": lambda a: a["recovery_policy"].__setitem__("enrolled_at_key_version", 5),
            "recovery_policy_id": lambda a: a["recovery_policy"].__setitem__("policy_id", 8),
            "recovery_guardian_key_byte": lambda a: a["recovery_policy"]["guardians"].__setitem__(
                1, flip_byte(a["recovery_policy"]["guardians"][1], 500)),
            "recovery_guardian_order": lambda a: a["recovery_policy"]["guardians"].reverse(),
            "recovery_guardian_removed": lambda a: a["recovery_policy"]["guardians"].pop(),
            "recovery_removed": lambda a: a.__setitem__("recovery_policy", None),
            "pending_new_key_byte": lambda a: a["pending_recovery"].__setitem__(
                "new_public_key", flip_byte(a["pending_recovery"]["new_public_key"], 7)),
            "pending_scheme": lambda a: a["pending_recovery"].__setitem__("new_key_scheme", "ml-dsa-87"),
            "pending_key_version": lambda a: a["pending_recovery"].__setitem__("key_version", 6),
            "pending_submitted": lambda a: a["pending_recovery"].__setitem__("submitted_at_height", 11),
            "pending_activation": lambda a: a["pending_recovery"].__setitem__("activation_height", 51),
            "pending_policy_id": lambda a: a["pending_recovery"].__setitem__("policy_id", 8),
            "pending_cancelled": lambda a: a["pending_recovery"].__setitem__("cancelled", True),
            "pending_removed": lambda a: a.__setitem__("pending_recovery", None),
            "charm_tier": lambda a: a["charm"].__setitem__("tier", "Established"),
            "charm_days": lambda a: a["charm"]["decay_exemption"].__setitem__("days", 31),
            "charm_last_earned": lambda a: a["charm"]["decay_exemption"].__setitem__("last_earned_epoch", 13),
            "charm_verified_since": lambda a: a["charm"].__setitem__("verified_since_epoch", 4),
            "charm_verified_since_none": lambda a: a["charm"].__setitem__("verified_since_epoch", None),
            "charm_last_attested": lambda a: a["charm"].__setitem__("last_attested_epoch", 45),
            "charm_consecutive": lambda a: a["charm"].__setitem__("consecutive_active_epochs", 10),
            "charm_wot": lambda a: a["charm"].__setitem__("verified_via_wot", False),
            "charm_removed": lambda a: a.__setitem__("charm", None),
            "escrow_job": lambda a: a["escrow"].__setitem__("job_id", "job-2"),
            "escrow_wallet": lambda a: a["escrow"].__setitem__("agent_wallet", "qcb1walleu"),
            "escrow_funding": lambda a: a["escrow"].__setitem__("funding_source", "qcb1funE"),
            "escrow_removed": lambda a: a.__setitem__("escrow", None),
        }
        leaves = {}
        for name, fn in mutations.items():
            with self.subTest(name):
                leaf = E.encode_leaf_v2(mut(fn))
                self.assertNotEqual(leaf, base_leaf)
                leaves[name] = leaf
        self.assertEqual(len(set(leaves.values())), len(leaves), "two different mutations produced the same leaf")

    def test_the_mutation_table_covers_every_account_field(self):
        """If someone adds a key to the account dict (or a nested struct), this fails until a mutation is written."""
        base = G.to_raw(G.CASES[[c[0] for c in G.CASES].index("all_fields")][2])
        self.assertEqual(sorted(base), sorted(["address", "nonce", "role", "balances", "public_key", "key_version",
                                               "policy_generation", "recovery_policy", "pending_recovery", "charm",
                                               "escrow"]))
        self.assertEqual(sorted(base["recovery_policy"]), ["enrolled_at_key_version", "guardians", "policy_id", "threshold"])
        self.assertEqual(sorted(base["pending_recovery"]), ["activation_height", "cancelled", "key_version", "new_key_scheme",
                                                            "new_public_key", "policy_id", "submitted_at_height"])
        self.assertEqual(sorted(base["charm"]), ["consecutive_active_epochs", "decay_exemption", "last_attested_epoch",
                                                 "tier", "verified_since_epoch", "verified_via_wot"])
        self.assertEqual(sorted(base["charm"]["decay_exemption"]), ["days", "last_earned_epoch"])
        self.assertEqual(sorted(base["escrow"]), ["agent_wallet", "funding_source", "job_id"])


class DeterminismAndInjectivity(unittest.TestCase):
    def test_balance_insertion_order_cannot_change_the_leaf(self):
        items = [("uqcb", 1), ("aaa", 2), ("uex", 3), ("zzz", 4), ("µqcb", 5)]
        leaves = set()
        for perm in itertools.permutations(items):
            leaves.add(E.encode_leaf_v2(G.to_raw(G.acct(balances=dict(perm)))))
        self.assertEqual(len(leaves), 1)

    def test_denoms_sort_by_utf8_bytes_not_code_points_of_a_locale(self):
        a = E.encode_leaf_v2(G.to_raw(G.acct(balances={"Ａ": 1, "z": 1})))   # U+FF21 encodes as EF BC A1, after 'z' (7A)
        d = E.decode_leaf_v2(a)
        self.assertEqual([k for k, _ in d["balances"]], ["z", "Ａ"])

    def test_repeated_and_cross_process_encoding_is_identical(self):
        code = ("import sys; sys.path.insert(0, %r); import generate_vectors as G, reference_encoder as E;"
                "print(E.encode_leaf_v2(G.to_raw(dict((c[0], c[2]) for c in G.CASES)['all_fields'])).hex())" % HERE)
        outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout
                for _ in range(3)}
        self.assertEqual(len(outs), 1)
        here = E.encode_leaf_v2(G.to_raw(dict((c[0], c[2]) for c in G.CASES)["all_fields"])).hex() + "\n"
        self.assertEqual(outs.pop(), here)

    def test_v1_is_ambiguous_and_v2_is_not(self):
        honest = G.to_raw(G.acct(address="x", balances={"a": 1, "b": 2}))
        forged = G.to_raw(G.acct(address="x", balances={"a=1|b": 2}))
        self.assertEqual(E.encode_leaf_v1(honest), E.encode_leaf_v1(forged))           # the legacy weakness, documented
        self.assertNotEqual(E.encode_leaf_v2(honest), E.encode_leaf_v2(forged))

    def test_v1_does_not_commit_the_fields_that_motivated_v2_and_v2_does(self):
        base = G.acct(address="ex1a", nonce=3, balances={"uex": 1000})
        for field, other in (("key_version", 99), ):
            a = G.to_raw(base); b = G.to_raw({**base, field: other})
            self.assertEqual(E.encode_leaf_v1(a), E.encode_leaf_v1(b))
            self.assertNotEqual(E.encode_leaf_v2(a), E.encode_leaf_v2(b))
        pol_a = G.policy(10); pol_b = G.policy(200)
        a = G.to_raw({**base, "recovery_policy": pol_a}); b = G.to_raw({**base, "recovery_policy": pol_b})
        self.assertEqual(E.encode_leaf_v1(a), E.encode_leaf_v1(b))                     # guardian KEYS replaced: v1 blind
        self.assertNotEqual(E.encode_leaf_v2(a), E.encode_leaf_v2(b))
        for cancelled in (False, True):
            pass
        p1 = G.to_raw({**base, "pending_recovery": G.pending(cancelled=False)})
        p2 = G.to_raw({**base, "pending_recovery": G.pending(cancelled=True)})
        self.assertEqual(E.encode_leaf_v1(p1), E.encode_leaf_v1(p2))
        self.assertNotEqual(E.encode_leaf_v2(p1), E.encode_leaf_v2(p2))

    def test_a_v2_leaf_can_never_be_mistaken_for_a_v1_leaf(self):
        for case in load(V2_PATH)["positive"]:
            self.assertEqual(bytes.fromhex(case["expected"]["leaf_hex"])[0], 0x00)
        for case in load(V1_PATH)["cases"]:
            self.assertNotEqual(bytes.fromhex(case["expected"]["leaf_hex"])[0], 0x00)


class DomainSeparation(unittest.TestCase):
    def test_same_body_different_domain_gives_different_hash(self):
        body = b"\x00" * 16
        hashes = {E.domain_hash(d, body) for d in (E.DOMAIN_RECOVERY_POLICY, E.DOMAIN_PENDING_RECOVERY, E.DOMAIN_CHARM,
                                                   E.DOMAIN_ESCROW)}
        self.assertEqual(len(hashes), 4)

    def test_domain_length_prefix_makes_the_prefix_unambiguous(self):
        # Without the length byte, ("ab", "c...") and ("abc", "...") would hash the same input.
        self.assertNotEqual(E.domain_hash(b"ab", b"cd"), E.domain_hash(b"abc", b"d"))
        self.assertEqual(E.domain_hash(b"ab", b"cd"), hashlib.sha3_256(b"\x02abcd").digest())

    def test_substructure_hash_inputs_are_exactly_as_specified(self):
        body = E.encode_escrow(G.ESCROW)
        spec = bytes([len(b"qattice/state/escrow/v1")]) + b"qattice/state/escrow/v1" + body
        self.assertEqual(E.escrow_hash(G.ESCROW), hashlib.sha3_256(spec).digest())

    def test_bad_domains_are_refused(self):
        for bad in (b"", b"x" * 256, b"has\x00nul", "café".encode()):
            with self.assertRaises(E.EncodingError):
                E.domain_hash(bad, b"")

    def test_domain_prefix_cannot_collide_with_the_tree_tags(self):
        # The tree hashes start with 0x00 / 0x01 / 0x02; a domain-separated hash starts with the length byte (>= 0x14 here).
        for d in (E.DOMAIN_RECOVERY_POLICY, E.DOMAIN_PENDING_RECOVERY, E.DOMAIN_CHARM, E.DOMAIN_ESCROW):
            self.assertGreater(len(d), 2)

    def test_independent_sha3_implementation_agrees(self):
        """Every hash in the vectors is recomputed with the OpenSSL command line (a separate SHA3 implementation)."""
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("openssl not installed")
        probe = subprocess.run([openssl, "dgst", "-sha3-256"], input=b"", capture_output=True)
        if probe.returncode != 0:
            self.skipTest("openssl without sha3-256")

        def ossl(data):
            return subprocess.run([openssl, "dgst", "-sha3-256", "-binary"], input=data, capture_output=True,
                                  check=True).stdout

        checked = 0
        for case in load(V2_PATH)["positive"]:
            acct = revive(case["account"])
            leaf = E.encode_leaf_v2(acct)
            self.assertEqual(ossl(leaf).hex(), case["expected"]["leaf_sha3_256"])
            self.assertEqual(ossl(bytes([2]) + leaf).hex(), case["expected"]["jmt_value_hash"])
            for key, domain, enc in (("recovery_policy", E.DOMAIN_RECOVERY_POLICY, E.encode_recovery_policy),
                                     ("pending_recovery", E.DOMAIN_PENDING_RECOVERY, E.encode_pending_recovery),
                                     ("charm", E.DOMAIN_CHARM, E.encode_charm), ("escrow", E.DOMAIN_ESCROW, E.encode_escrow)):
                if acct.get(key) is not None:
                    self.assertEqual(ossl(bytes([len(domain)]) + domain + enc(acct[key])).hex(),
                                     case["expected"]["substructure_hashes"][key])
                    checked += 1
        self.assertGreater(checked, 10)


class EncoderRefusals(unittest.TestCase):
    def test_out_of_range_and_wrong_type_values_are_refused(self):
        bad = [
            G.acct(nonce=E.U64_MAX + 1), G.acct(nonce=-1), G.acct(key_version=E.U32_MAX + 1),
            G.acct(policy_generation=E.U64_MAX + 1), G.acct(balances={"uqcb": E.U128_MAX + 1}),
            G.acct(balances={"uqcb": -1}), G.acct(address=""), G.acct(address="a" * (E.MAX_ADDRESS_BYTES + 1)),
            G.acct(role="r" * (E.MAX_ROLE_BYTES + 1)), G.acct(balances={"": 1}),
            G.acct(balances={"d" * (E.MAX_DENOM_BYTES + 1): 1}),
            G.acct(balances={f"d{i}": 1 for i in range(E.MAX_BALANCE_ENTRIES + 1)}),
            G.acct(address="bad\ud800surrogate"), G.acct(public_key=B_over(E.MAX_PUBLIC_KEY_BYTES + 1)),
        ]
        for i, a in enumerate(bad):
            with self.subTest(i):
                with self.assertRaises(E.EncodingError):
                    E.encode_leaf_v2(G.to_raw(a))

    def test_substructure_refusals(self):
        with self.assertRaises(E.EncodingError):
            E.encode_recovery_policy({"guardians": [], "threshold": 1, "enrolled_at_key_version": 0, "policy_id": 0})
        with self.assertRaises(E.EncodingError):
            E.encode_recovery_policy({**G.to_raw(G.policy()), "guardians": [b"k"] * (E.MAX_GUARDIANS + 1)})
        with self.assertRaises(E.EncodingError):
            E.encode_pending_recovery({**G.to_raw(G.pending()), "cancelled": 1})          # not a real bool
        with self.assertRaises(E.EncodingError):
            E.encode_charm({**G.to_raw(G.charm()), "tier": None})

    def test_none_and_present_empty_public_key_differ(self):
        self.assertNotEqual(E.encode_leaf_v2(G.to_raw(G.acct(public_key=None))),
                            E.encode_leaf_v2(G.to_raw(G.acct(public_key=G.B(b"")))))


def B_over(n):
    return G.B(b"\x00" * n)


class LegacyV1(unittest.TestCase):
    def test_legacy_vectors_reproduce(self):
        for case in load(V1_PATH)["cases"]:
            with self.subTest(case["name"]):
                acct = revive(case["account"])
                leaf = E.encode_leaf_v1(acct)
                self.assertEqual(leaf.decode(), case["expected"]["leaf_text"])
                self.assertEqual(E.jmt_leaf_node_hash(acct["address"], leaf).hex(), case["expected"]["jmt_leaf_node_hash"])

    def test_python_v1_matches_the_rust_pinned_corpus_and_roots(self):
        """Cross-check against production code: the S1 parity corpus pinned in chain-forge-state/src/lib.rs
        (recorded from main 61e02c6 before any change). A one-account tree's root is its leaf-node hash."""
        src = os.path.join(REPO_ROOT, "chain-forge-state", "src", "lib.rs")
        if not os.path.exists(src):
            self.skipTest("chain-forge-state/src/lib.rs not found")
        with open(src, encoding="utf-8") as f:
            text = f.read()
        cases = re.findall(r'\(r#"(\w+)"#, r#"(\{.*?\})"#, r#"(.*?)"#, r#"([0-9a-f]{64})"#, r#"(\{.*?\})"#\)', text, re.S)
        self.assertEqual(len(cases), 8, "expected the eight S1 parity cases")
        for name, extra, pinned_leaf, pinned_root, _json in cases:
            with self.subTest(name):
                x = json.loads(extra)
                acct = G.to_raw(G.acct(address="ex1a", nonce=3, balances={"uex": 1000}))
                if "public_key" in x: acct["public_key"] = bytes(x["public_key"])
                if "escrow" in x: acct["escrow"] = x["escrow"]
                if "key_version" in x: acct["key_version"] = x["key_version"]
                if "policy_generation" in x: acct["policy_generation"] = x["policy_generation"]
                if "recovery_policy" in x:
                    rp = x["recovery_policy"]
                    acct["recovery_policy"] = {"guardians": [bytes(g) for g in rp["guardians"]], "threshold": rp["threshold"],
                                               "enrolled_at_key_version": rp["enrolled_at_key_version"], "policy_id": rp["policy_id"]}
                leaf = E.encode_leaf_v1(acct)
                self.assertEqual(leaf.decode(), pinned_leaf)
                self.assertEqual(E.jmt_leaf_node_hash("ex1a", leaf).hex(), pinned_root)

    def test_v1_encoder_is_frozen(self):
        """The legacy definition is part of the historical record: its output for these inputs may never change."""
        self.assertEqual(E.encode_leaf_v1(G.to_raw(G.acct(address="ex1a", nonce=3, balances={"uex": 1000}))),
                         b"ex1a|3|none|uex=1000")
        self.assertEqual(E.jmt_leaf_node_hash("ex1a", b"ex1a|3|none|uex=1000").hex(),
                         "ecb20f8869facd5dca72115f6d12dc67d9f11e21e04e7e7721988468f7717e6d")


if __name__ == "__main__":
    unittest.main(verbosity=2)
