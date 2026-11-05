"""Independent pure-Python FIPS 204 evaluation (dilithium-py 1.5.1, installed from a verified wheel into ../pyeval/site).
usage: py_eval.py kat | verify <interop.json> | gen | keycheck <interop-or-kat.json>"""
import hashlib, json, sys, time
import os
sys.path.insert(0, os.environ.get("QATTICE_PYSITE", "../pyeval/site"))
from dilithium_py.ml_dsa import ML_DSA_65 as D

fx = json.load(open(os.environ.get("QATTICE_FIXTURE", "../../chain-forge-crypto/tests/vectors/fips204/mldsa65.json")))
h = bytes.fromhex
HASHES = {  # alg -> (oid last byte, digest function)
    "SHA2-224": (0x04, lambda m: hashlib.sha224(m).digest()), "SHA2-256": (0x01, lambda m: hashlib.sha256(m).digest()),
    "SHA2-384": (0x02, lambda m: hashlib.sha384(m).digest()), "SHA2-512": (0x03, lambda m: hashlib.sha512(m).digest()),
    "SHA2-512/224": (0x05, lambda m: hashlib.new("sha512_224", m).digest()), "SHA2-512/256": (0x06, lambda m: hashlib.new("sha512_256", m).digest()),
    "SHA3-224": (0x07, lambda m: hashlib.sha3_224(m).digest()), "SHA3-256": (0x08, lambda m: hashlib.sha3_256(m).digest()),
    "SHA3-384": (0x09, lambda m: hashlib.sha3_384(m).digest()), "SHA3-512": (0x0A, lambda m: hashlib.sha3_512(m).digest()),
    "SHAKE-128": (0x0B, lambda m: hashlib.shake_128(m).digest(32)), "SHAKE-256": (0x0C, lambda m: hashlib.shake_256(m).digest(64)),
}
def mprime(group, msg, ctx, alg):
    if group == "internal": return msg
    if group == "external-pure": return bytes([0, len(ctx)]) + ctx + msg
    last, f = HASHES[alg]
    return bytes([1, len(ctx)]) + ctx + bytes([6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, last]) + f(msg)

def kat():
    r = {"implementation": "dilithium-py 1.5.1 (pure Python)"}
    ok = 0
    for t in fx["keygen"]:
        pk, sk = D.key_derive(h(t["seed"])); ok += (pk == h(t["pk"]) and sk == h(t["sk"]))
        assert D.pk_from_sk(h(t["sk"])) == h(t["pk"])
    r["keygen_from_seed"] = f"{ok}/{len(fx['keygen'])}"; r["pk_from_sk_matches_nist_pk"] = f"{len(fx['keygen'])}/{len(fx['keygen'])}"
    per = {}
    for t in fx["siggen"]:
        g = t["group"]; sk = h(t["sk"]); msg = h(t["message"]); ctx = h(t["context"])
        if g == "external-pure": sig = D.sign(sk, msg, ctx, deterministic=True)
        else: sig = D._sign_internal(sk, mprime(g, msg, ctx, t["hashAlg"]), bytes(32))   # internal native; prehash emulated through the internal interface
        e = per.setdefault(g, [0, 0]); e[0] += 1; e[1] += (sig == h(t["signature"]))
    r["siggen_deterministic"] = {k: f"{v[1]}/{v[0]}" for k, v in per.items()}
    per = {}
    for t in fx["sigver"]:
        g = t["group"]; pk = h(t["pk"]); msg = h(t["message"]); ctx = h(t["context"]); sig = h(t["signature"])
        got = D.verify(pk, msg, sig, ctx) if g == "external-pure" else D._verify_internal(pk, mprime(g, msg, ctx, t["hashAlg"]), sig)
        e = per.setdefault(g, [0, 0]); e[0] += 1; e[1] += (got == t["testPassed"])
    r["sigver"] = {k: f"{v[1]}/{v[0]}" for k, v in per.items()}
    print(json.dumps(r))

def verify(path):
    d = json.load(open(path)); ok = bad = 0; neg_ok = neg = 0
    for i, c in enumerate(d["cases"]):
        pk, msg, ctx, sig = h(c["pk"]), h(c["msg"]), h(c["ctx"]), h(c["sig"])
        ok += D.verify(pk, msg, sig, ctx)
        m = bytearray(sig); m[(i * 37) % len(m)] ^= 0x10
        neg += 1; neg_ok += (not D.verify(pk, msg, bytes(m), ctx))
    print(json.dumps({"verifier": "dilithium-py 1.5.1", "signer": d["signer"], "valid_accepted": f"{ok}/{len(d['cases'])}", "mutated_rejected": f"{neg_ok}/{neg}"}))

def gen():
    cases = []
    for s in range(3):
        seed = bytes([s]) + bytes(30) + bytes([0xB0 ^ s]); pk, sk = D.key_derive(seed)
        for ctx in (b"", b"qattice/tx/v2", bytes([0xAB]) * 255):
            for msg in (b"", bytes(range(200))):
                for det in (True, False):
                    cases.append({"hedged": not det, "pk": pk.hex(), "msg": msg.hex(), "ctx": ctx.hex(), "sig": D.sign(sk, msg, ctx, deterministic=det).hex()})
    print(json.dumps({"signer": "dilithium-py 1.5.1", "cases": cases}))

def keycheck(path):
    d = json.load(open(path)); ok = 0; seed_ok = 0; seeded = 0
    for k in d["keys"]:
        pk, sk = bytes.fromhex(k["pk"]), bytes.fromhex(k["sk"])
        ok += (D.pk_from_sk(sk) == pk)
        if k["kind"] == "seeded":
            seeded += 1; seed_ok += (D.key_derive(bytes.fromhex(k["seed"])) == (pk, sk))
    print(json.dumps({"backend": d["backend"], "keys": len(d["keys"]), "pk_equals_independent_pk_from_sk": f"{ok}/{len(d['keys'])}",
                      "seeded_keys_equal_independent_key_derive": f"{seed_ok}/{seeded}" if seeded else "n/a (no seeded keygen)"}))


if __name__ == "__main__":
    {"kat": kat, "gen": gen, "keycheck": lambda: keycheck(sys.argv[2])}.get(sys.argv[1], lambda: verify(sys.argv[2]))()
