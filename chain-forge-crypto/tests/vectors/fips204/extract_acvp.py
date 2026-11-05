"""Extract the ML-DSA-65 subset of NIST's ACVP FIPS 204 vectors into one compact JSON fixture.

Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/
Run:  python3 extract_acvp.py <dir containing the downloaded *internalProjection.json files named
      ML-DSA-<name>-FIPS204-internalProjection.json> > mldsa65.json
The repository commit of ACVP-Server was not available to the sandbox that produced the fixture, so provenance is
the SHA-256 of each downloaded source file (recorded in the output) and the retrieval date.
Selection: ML-DSA-65 only. sigGen: deterministic groups only (a nondeterministic signature has no fixed expected
value); externalMu groups are skipped (they hand the implementation a precomputed mu, which the library API cannot take).
"""
import hashlib
import json
import os
import sys

d = sys.argv[1]


def load(name):
    p = os.path.join(d, f"ML-DSA-{name}-FIPS204-internalProjection.json")
    raw = open(p, "rb").read()
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def lo(x):
    return x.lower() if isinstance(x, str) else x


kg, kg_h = load("keyGen")
sg, sg_h = load("sigGen")
sv, sv_h = load("sigVer")

out = {
    "source": {
        "origin": "NIST ACVP-Server, gen-val/json-files/ML-DSA-{keyGen,sigGen,sigVer}-FIPS204/internalProjection.json (master)",
        "retrieved": "2026-11-05",
        "sha256": {"keyGen": kg_h, "sigGen": sg_h, "sigVer": sv_h},
        "parameterSet": "ML-DSA-65",
    },
    "keygen": [],
    "siggen": [],
    "sigver": [],
}
for g in kg["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65":
        continue
    for t in g["tests"]:
        out["keygen"].append({"tcId": t["tcId"], "seed": lo(t["seed"]), "pk": lo(t["pk"]), "sk": lo(t["sk"])})


def kind(g):
    if g["signatureInterface"] == "internal":
        return "internal"
    return "external-prehash" if g.get("preHash") == "preHash" else "external-pure"


for g in sg["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65" or not g["deterministic"]:
        continue
    if g["signatureInterface"] == "internal" and g.get("externalMu"):
        continue
    for t in g["tests"]:
        out["siggen"].append({"group": kind(g), "tcId": t["tcId"], "sk": lo(t["sk"]), "pk": lo(t["pk"]),
                              "message": lo(t["message"]), "context": lo(t.get("context", "")),
                              "hashAlg": t.get("hashAlg", "none"), "signature": lo(t["signature"])})
for g in sv["testGroups"]:
    if g["parameterSet"] != "ML-DSA-65":
        continue
    if g["signatureInterface"] == "internal" and g.get("externalMu"):
        continue
    for t in g["tests"]:
        out["sigver"].append({"group": kind(g), "tcId": t["tcId"], "pk": lo(t["pk"]), "message": lo(t["message"]),
                              "context": lo(t.get("context", "")), "hashAlg": t.get("hashAlg", "none"),
                              "signature": lo(t["signature"]), "testPassed": t["testPassed"], "reason": t.get("reason", "")})
json.dump(out, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
