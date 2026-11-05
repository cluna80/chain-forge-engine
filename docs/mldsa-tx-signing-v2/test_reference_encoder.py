"""Self-tests for the v2 reference encoder and its vectors. Run: python -m unittest discover -s docs/mldsa-tx-signing-v2"""
import hashlib
import json
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import reference_encoder as enc  # noqa: E402
import generate_vectors as gv  # noqa: E402

with open(os.path.join(HERE, "vectors", "v2.json"), encoding="utf-8") as f:
    VECTORS = json.load(f)

BASE = gv.BASE


def d2(**over):
    p = dict(BASE)
    p.update(over)
    return enc.v2_digest(**p)


class Vectors(unittest.TestCase):
    def test_vectors_match_encoder(self):
        for c in VECTORS["cases"]:
            p = dict(chain_id=c["chain_id"], tx_id=c["id"], sender=c["sender"], nonce=c["nonce"],
                     gas_limit=c["gas_limit"], body_json=c["body_json"],
                     pq_public_key=bytes.fromhex(c["pq_public_key_hex"]))
            self.assertEqual(enc.v2_message(**p).hex(), c["v2_message_hex"], c["name"])
            self.assertEqual(enc.v2_digest(**p).hex(), c["v2_digest_hex"], c["name"])
            self.assertEqual(hashlib.sha256(bytes.fromhex(c["v2_message_hex"])).hexdigest(), c["v2_digest_hex"])
            self.assertEqual(enc.v1_digest(p["chain_id"], p["body_json"]).hex(), c["v1_digest_hex"], c["name"])

    def test_generation_is_deterministic(self):
        """Regenerates into a temp file (never the committed one) and compares byte for byte."""
        import tempfile
        before = open(os.path.join(HERE, "vectors", "v2.json"), encoding="utf-8").read()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v2.json")
            gv.main(path)
            after = open(path, encoding="utf-8").read()
        self.assertEqual(before, after)

    def test_all_digests_distinct(self):
        ds = [c["v2_digest_hex"] for c in VECTORS["cases"]]
        self.assertEqual(len(ds), len(set(ds)))


class ReplayDefect(unittest.TestCase):
    def test_v1_digest_ignores_nonce_id_sender_gas_and_key(self):
        """Documents H0-4: under v1 these changes do NOT change what is signed."""
        base = enc.v1_digest(BASE["chain_id"], BASE["body_json"])
        # v1 takes only (chain_id, body); there is no way to express the other fields at all.
        self.assertEqual(base, enc.v1_digest(BASE["chain_id"], BASE["body_json"]))
        by_name = {c["name"]: c for c in VECTORS["cases"]}
        for n in ("nonce_1", "id_changed", "sender_changed", "gas_limit_changed", "pq_public_key_changed"):
            self.assertEqual(by_name[n]["v1_digest_hex"], by_name["baseline"]["v1_digest_hex"], n)

    def test_v2_binds_every_field(self):
        base = d2()
        mutations = {
            "chain_id": dict(chain_id="x"), "id": dict(tx_id="x"), "sender": dict(sender="x"),
            "nonce": dict(nonce=1), "gas_limit": dict(gas_limit=1), "body": dict(body_json=gv.BURN),
            "pq_public_key": dict(pq_public_key=b"\x01"),
        }
        for name, m in mutations.items():
            self.assertNotEqual(d2(**m), base, f"v2 digest must change when {name} changes")


class Structure(unittest.TestCase):
    def test_domain_and_field_order(self):
        m = enc.v2_message(**BASE)
        self.assertTrue(m.startswith(b"chain-forge/pq-tx/v2\n"))
        self.assertEqual(m[len(enc.DOMAIN_V2):len(enc.DOMAIN_V2) + 1], enc.ALG_MLDSA65)
        rest = m[len(enc.DOMAIN_V2) + 1:]
        n = struct.unpack(">I", rest[:4])[0]
        self.assertEqual(rest[4:4 + n], BASE["chain_id"].encode())

    def test_total_length(self):
        m = enc.v2_message(**BASE)
        expect = (len(enc.DOMAIN_V2) + 1 + 4 + len(BASE["chain_id"]) + 4 + len(BASE["tx_id"]) + 4 + len(BASE["sender"])
                  + 8 + 8 + 4 + len(BASE["body_json"].encode()) + 4 + len(BASE["pq_public_key"]))
        self.assertEqual(len(m), expect)

    def test_prefix_freeness_no_field_can_borrow_bytes(self):
        self.assertNotEqual(d2(tx_id="ab", sender="c"), d2(tx_id="a", sender="bc"))
        self.assertNotEqual(d2(chain_id="ab", tx_id="c"), d2(chain_id="a", tx_id="bc"))
        self.assertNotEqual(d2(body_json="ab", pq_public_key=b"c"), d2(body_json="a", pq_public_key=b"bc"))

    def test_no_message_is_a_prefix_of_another(self):
        a = enc.v2_message(**BASE)
        for extra in (dict(pq_public_key=BASE["pq_public_key"] + b"\x00"), dict(body_json=BASE["body_json"] + " ")):
            p = dict(BASE); p.update(extra)
            b = enc.v2_message(**p)
            self.assertFalse(b.startswith(a) or a.startswith(b))

    def test_domain_separation_from_v1_and_ed25519(self):
        self.assertNotEqual(enc.DOMAIN_V1, enc.DOMAIN_V2)
        self.assertNotEqual(d2(), enc.v1_digest(BASE["chain_id"], BASE["body_json"]))
        self.assertFalse(enc.v2_message(**BASE).startswith(b"chain-forge/tx/v1\n"))   # Ed25519 domain


class Algorithm(unittest.TestCase):
    def test_single_fixed_algorithm_identifier(self):
        self.assertEqual(enc.ALG_MLDSA65, b"\x01")
        self.assertEqual(VECTORS["algorithm_id_hex"], "01")

    def test_algorithm_identifier_is_in_the_preimage(self):
        import hashlib as h
        m = enc.v2_message(**BASE)
        other = m.replace(enc.DOMAIN_V2 + b"\x01", enc.DOMAIN_V2 + b"\x02", 1)
        self.assertNotEqual(h.sha256(m).digest(), h.sha256(other).digest())

    def test_v1_signature_digest_never_equals_a_v2_digest(self):
        """A signature made over the v1 digest must not verify under v2 (digests differ for every vector)."""
        for c in VECTORS["cases"]:
            self.assertNotEqual(c["v1_digest_hex"], c["v2_digest_hex"], c["name"])

    def test_cross_chain_digests_differ(self):
        self.assertNotEqual(d2(chain_id="qcb-testnet-1"), d2(chain_id="qcb-alpha-1"))


class Envelope(unittest.TestCase):
    def test_envelope_vectors(self):
        for c in VECTORS["envelope_cases"]:
            res, code = enc.check_envelope(c["tx"], c["bound_key_hex"])
            self.assertEqual((res, code), (c["expect"], c["code"]), c["name"])

    def test_exactly_three_accepts_and_every_reject_has_a_code(self):
        ok = [c for c in VECTORS["envelope_cases"] if c["expect"] == "ok"]
        bad = [c for c in VECTORS["envelope_cases"] if c["expect"] == "reject"]
        self.assertEqual(len(ok), 3)
        self.assertTrue(all(c["code"] for c in bad))

    def test_only_mldsa_scheme_tag_is_accepted(self):
        pk = "cd" * enc.MLDSA65_PK_BYTES
        base = {"signature_hex": "", "public_key_hex": "", "pq_signatures": ["mldsa65:" + "ab" * enc.MLDSA65_SIG_BYTES],
                "pq_public_key_hex": pk}
        for scheme in (None, "Classical", "HybridEd25519MlDsa", "SlhDsa", "FnDsa", "ml-dsa-65", "mldsa", ""):
            tx = dict(base, sig_scheme=scheme)
            self.assertEqual(enc.check_envelope(tx)[0], "reject", scheme)
        self.assertEqual(enc.check_envelope(dict(base, sig_scheme="MlDsa"))[0], "ok")

    def test_effective_key_prefers_bound_key(self):
        pk = "cd" * enc.MLDSA65_PK_BYTES
        self.assertEqual(enc.effective_public_key({"pq_public_key_hex": ""}, pk), bytes.fromhex(pk))
        self.assertEqual(enc.effective_public_key({"pq_public_key_hex": pk}, None), bytes.fromhex(pk))


class Rejections(unittest.TestCase):
    def test_u64_bounds(self):
        for bad in (-1, enc.U64_MAX + 1, True, 1.5, "1"):
            with self.assertRaises(enc.EncodeError):
                d2(nonce=bad)
            with self.assertRaises(enc.EncodeError):
                d2(gas_limit=bad)
        d2(nonce=enc.U64_MAX, gas_limit=enc.U64_MAX)  # boundary accepted

    def test_types(self):
        with self.assertRaises(enc.EncodeError):
            d2(tx_id=b"bytes")
        with self.assertRaises(enc.EncodeError):
            d2(pq_public_key="str")

    def test_lone_surrogate_not_encodable(self):
        with self.assertRaises(enc.EncodeError):
            d2(tx_id="\ud800")

    def test_length_prefix_overflow(self):
        with self.assertRaises(enc.EncodeError):
            enc._lp(type("Big", (bytes,), {"__len__": lambda s: enc.U32_MAX + 1})(b""))


if __name__ == "__main__":
    unittest.main()
