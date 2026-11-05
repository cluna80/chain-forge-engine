"""Self-tests for the signing-v2 reference encoder and vectors.
Run: python -m unittest discover -s docs/mldsa-tx-signing-v2
The signature checks need an independent FIPS 204 implementation (dilithium-py 1.5.1); set QATTICE_PYSITE to its
site directory. Without it those tests are skipped and the structural tests still run."""
import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
if os.environ.get("QATTICE_PYSITE"):
    sys.path.insert(0, os.environ["QATTICE_PYSITE"])
import reference_encoder as enc  # noqa: E402
import generate_vectors as gv  # noqa: E402

try:
    from dilithium_py.ml_dsa import ML_DSA_65 as D  # noqa: E402
except Exception:  # pragma: no cover
    D = None

with open(os.path.join(HERE, "vectors", "v2.json"), encoding="utf-8") as f:
    VECTORS = json.load(f)
BASE = dict(chain_id="qattice-alpha-1", tx_id="tx-0001", sender="qcb1sender", nonce=0, gas_limit=500000,
            body_json=gv.TRANSFER, pq_public_key=bytes.fromhex(VECTORS["keys"]["A"]["pk_hex"]))
CASES = {c["name"]: c for c in VECTORS["cases"]}


def pre(**over):
    p = dict(BASE)
    p.update(over)
    return enc.tx_preimage(**p)


class VectorStructure(unittest.TestCase):
    def test_preimage_and_m_prime_match_the_encoder(self):
        for c in VECTORS["cases"]:
            if c["name"].startswith(("replay_", "signature_", "context_")) or c["name"] in ("signer_b",):
                pass
            p = dict(chain_id=c["chain_id"], tx_id=c["id"], sender=c["sender"], nonce=c["nonce"], gas_limit=c["gas_limit"],
                     body_json=c["body_json"], pq_public_key=bytes.fromhex(c["pq_public_key_hex"]))
            m = enc.tx_preimage(**p)
            self.assertEqual(m.hex(), c["preimage_hex"], c["name"])
            self.assertEqual(enc.m_prime_pure(c["context"].encode(), m).hex(), c["m_prime_hex"], c["name"])
            self.assertEqual(enc.v1_digest(c["chain_id"], c["body_json"]).hex(), c["v1_digest_hex"], c["name"])

    def test_valid_cases_have_distinct_preimages(self):
        pres = [c["preimage_hex"] for c in VECTORS["cases"] if c["expect_valid"]]
        self.assertEqual(len(pres), len(set(pres)))

    def test_counts(self):
        self.assertEqual(sum(c["expect_valid"] for c in VECTORS["cases"]), 15)
        self.assertEqual(sum(not c["expect_valid"] for c in VECTORS["cases"]), 14)


class ReplayDefect(unittest.TestCase):
    def test_v1_digest_ignores_nonce_id_sender_gas_and_key(self):
        """Documents H0-4: under v1 these changes do NOT change what is signed."""
        for n in ("nonce_1", "id_changed", "sender_changed", "gas_limit_changed", "signer_b"):
            self.assertEqual(CASES[n]["v1_digest_hex"], CASES["baseline"]["v1_digest_hex"], n)

    def test_v2_preimage_binds_every_field(self):
        base = pre()
        mutations = {
            "chain_id": dict(chain_id="x"), "id": dict(tx_id="x"), "sender": dict(sender="x"), "nonce": dict(nonce=1),
            "gas_limit": dict(gas_limit=1), "body": dict(body_json=gv.BURN), "pq_public_key": dict(pq_public_key=b"\x01"),
        }
        for name, m in mutations.items():
            self.assertNotEqual(pre(**m), base, f"preimage must change when {name} changes")


class Structure(unittest.TestCase):
    def test_version_prefix_and_field_order(self):
        m = enc.tx_preimage(**BASE)
        self.assertEqual(struct.unpack(">H", m[:2])[0], 2)
        n = struct.unpack(">I", m[2:6])[0]
        self.assertEqual(m[6:6 + n], BASE["chain_id"].encode())

    def test_total_length(self):
        m = enc.tx_preimage(**BASE)
        expect = (2 + 4 + len(BASE["chain_id"]) + 4 + len(BASE["tx_id"]) + 4 + len(BASE["sender"]) + 8 + 8
                  + 4 + len(BASE["body_json"].encode()) + 4 + len(BASE["pq_public_key"]))
        self.assertEqual(len(m), expect)

    def test_there_is_no_prehash_and_no_domain_prefix_in_the_message(self):
        m = enc.tx_preimage(**BASE)
        self.assertFalse(m.startswith(b"chain-forge/") or m.startswith(b"qattice/"))   # domain separation lives in the context
        self.assertEqual(len(m), len(enc.tx_preimage(**BASE)))                            # variable length, not a 32-byte digest
        self.assertNotEqual(len(m), 32)

    def test_prefix_freeness_no_field_can_borrow_bytes(self):
        self.assertNotEqual(pre(tx_id="ab", sender="c"), pre(tx_id="a", sender="bc"))
        self.assertNotEqual(pre(chain_id="ab", tx_id="c"), pre(chain_id="a", tx_id="bc"))
        self.assertNotEqual(pre(body_json="ab", pq_public_key=b"c"), pre(body_json="a", pq_public_key=b"bc"))

    def test_no_preimage_is_a_prefix_of_another(self):
        a = enc.tx_preimage(**BASE)
        for extra in (dict(pq_public_key=BASE["pq_public_key"] + b"\x00"), dict(body_json=BASE["body_json"] + " ")):
            b = pre(**extra)
            self.assertFalse(b.startswith(a) or a.startswith(b))


class Contexts(unittest.TestCase):
    def test_registry_is_unique_ascii_bounded_and_namespaced(self):
        ctxs = list(enc.CONTEXTS.values())
        self.assertEqual(len(ctxs), len(set(ctxs)), "a context must never be shared between protocols")
        for c in ctxs:
            self.assertLessEqual(len(c), enc.MAX_CTX_BYTES)
            c.decode("ascii")
            self.assertTrue(c.startswith(b"qattice/"))
        self.assertEqual(enc.CONTEXTS["transaction"], enc.CTX_TX_V2)
        self.assertEqual(VECTORS["context_registry"], {k: v.decode() for k, v in enc.CONTEXTS.items()})

    def test_m_prime_is_the_fips204_pure_framing(self):
        m = enc.m_prime_pure(b"ctx", b"msg")
        self.assertEqual(m, bytes([0, 3]) + b"ctx" + b"msg")
        self.assertEqual(enc.m_prime_pure(b"", b"msg"), bytes([0, 0]) + b"msg")
        self.assertEqual(len(enc.m_prime_pure(b"\x41" * 255, b"")), 2 + 255)

    def test_context_over_255_bytes_is_refused(self):
        with self.assertRaises(enc.EncodeError):
            enc.m_prime_pure(b"\x41" * 256, b"m")
        with self.assertRaises(enc.EncodeError):
            enc.m_prime_pure("str", b"m")


@unittest.skipIf(D is None, "independent FIPS 204 implementation (dilithium-py) not available; set QATTICE_PYSITE")
class Signatures(unittest.TestCase):
    def test_every_vector_verifies_or_fails_as_recorded(self):
        for c in VECTORS["cases"]:
            ok = D.verify(bytes.fromhex(c["verify_public_key_hex"]), bytes.fromhex(c["preimage_hex"]),
                          bytes.fromhex(c["signature_hex"]), c["context"].encode())
            self.assertEqual(ok, c["expect_valid"], c["name"])

    def test_keys_are_derived_from_the_recorded_seeds(self):
        for k in ("A", "B"):
            pk, _ = D.key_derive(bytes.fromhex(VECTORS["keys"][k]["seed_hex"]))
            self.assertEqual(pk.hex(), VECTORS["keys"][k]["pk_hex"])

    def test_signature_and_key_sizes(self):
        for c in VECTORS["cases"]:
            self.assertEqual(len(bytes.fromhex(c["signature_hex"])), enc.MLDSA65_SIG_BYTES)
            self.assertEqual(len(bytes.fromhex(c["pq_public_key_hex"])), enc.MLDSA65_PK_BYTES)

    def test_generation_is_deterministic(self):
        """Regenerates into a temp file (never the committed one) and compares byte for byte."""
        before = open(os.path.join(HERE, "vectors", "v2.json"), encoding="utf-8").read()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "v2.json")
            gv.main(path)
            after = open(path, encoding="utf-8").read()
        self.assertEqual(before, after)


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
            self.assertEqual(enc.check_envelope(dict(base, sig_scheme=scheme))[0], "reject", scheme)
        self.assertEqual(enc.check_envelope(dict(base, sig_scheme="MlDsa"))[0], "ok")

    def test_effective_key_prefers_bound_key(self):
        pk = "cd" * enc.MLDSA65_PK_BYTES
        self.assertEqual(enc.effective_public_key({"pq_public_key_hex": ""}, pk), bytes.fromhex(pk))
        self.assertEqual(enc.effective_public_key({"pq_public_key_hex": pk}, None), bytes.fromhex(pk))


class Rejections(unittest.TestCase):
    def test_integer_bounds(self):
        for bad in (-1, enc.U64_MAX + 1, True, 1.5, "1"):
            with self.assertRaises(enc.EncodeError):
                pre(nonce=bad)
            with self.assertRaises(enc.EncodeError):
                pre(gas_limit=bad)
        pre(nonce=enc.U64_MAX, gas_limit=enc.U64_MAX)

    def test_types(self):
        with self.assertRaises(enc.EncodeError):
            pre(tx_id=b"bytes")
        with self.assertRaises(enc.EncodeError):
            pre(pq_public_key="str")

    def test_lone_surrogate_not_encodable(self):
        with self.assertRaises(enc.EncodeError):
            pre(tx_id="\ud800")

    def test_length_prefix_overflow(self):
        with self.assertRaises(enc.EncodeError):
            enc._lp(type("Big", (bytes,), {"__len__": lambda s: enc.U32_MAX + 1})(b""))


if __name__ == "__main__":
    unittest.main()
