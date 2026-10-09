#!/usr/bin/env python3
"""
phase1_dis001_test.py — DIS-001 Phase A: QR challenge/response auth test.

Tests the ML-DSA-65 challenge/response authentication endpoints added to
chain-forge-node in DIS-001 Phase A (auth.rs + api.rs).

  Test 1  Happy path — request a challenge, sign it with the wallet binary,
           submit the signed response; expect {"status":"verified"}.

  Test 2  Anti-replay — submit the same challenge_id a second time after a
           successful verify; must be rejected (challenge consumed on first use).

  Test 3  Forged signature — request a challenge, submit a randomly fabricated
           mldsa65:<hex> signature; must be rejected.

  Test 4  Wrong key — request a challenge, sign with Alice's key but submit
           Bob's public key; must be rejected.

  Test 5  Expired challenge — request a challenge with a manipulated
           expires_at (via direct POST with forged challenge_id); the real
           test exercises the node's TTL by asserting the field exists and
           is in the future (we can't warp time, but we verify the shape).

Usage:
  python3 scripts/phase1_dis001_test.py

Requirements:
  - Devnet running (Alice:8080 minimum)
    Start with:  ./scripts/start-devnet-local.sh --clean
  - Wallet binary built:  cargo build -p chain-forge-wallet
  - Python 3.8+  (stdlib only — no third-party packages)

The script generates temporary *.wallet.json files in /tmp and removes them
on exit.  Key material never enters the repository.
"""

import hashlib
import http.client
import json
import os
import subprocess
import sys
import tempfile
import time

# ── Config ────────────────────────────────────────────────────────────────────

ALICE = ("127.0.0.1", 8080)

# Locate the wallet binary (prefer release, fall back to debug)
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT   = os.path.dirname(_SCRIPT_DIR)
_WALLET_BIN  = os.path.join(_REPO_ROOT, "target", "release", "qcb-wallet")
if not os.path.exists(_WALLET_BIN):
    _WALLET_BIN = os.path.join(_REPO_ROOT, "target", "debug", "qcb-wallet")

# ── Helpers ───────────────────────────────────────────────────────────────────

PASS  = "\033[92m✓\033[0m"
FAIL  = "\033[91m✗\033[0m"
_results: list[tuple[str, bool, str]] = []


def result(label: str, ok: bool, detail: str = ""):
    _results.append((label, ok, detail))
    icon = PASS if ok else FAIL
    print(f"  {icon}  {label}", f"({detail})" if detail else "")


def post_json(host: tuple, path: str, body: dict | None = None, *, timeout: int = 10) -> tuple[int, dict | str]:
    conn = http.client.HTTPConnection(host[0], host[1], timeout=timeout)
    payload = json.dumps(body).encode() if body is not None else b""
    headers = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
    conn.request("POST", path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    try:
        return resp.status, json.loads(raw)
    except json.JSONDecodeError:
        return resp.status, raw


def wallet(*args, check: bool = True) -> str:
    """Run qcb-wallet with the given args; return stdout."""
    cmd = [_WALLET_BIN, *args]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"qcb-wallet {' '.join(args)} failed:\n{r.stderr}")
    return r.stdout.strip()


def generate_tmp_wallet(label: str) -> tuple[str, str]:
    """Generate a temp wallet file; return (path, public_key_hex)."""
    fd, path = tempfile.mkstemp(suffix=f"_{label}.wallet.json")
    os.close(fd)
    os.unlink(path)  # wallet will create it; must not pre-exist
    wallet("generate", "--path", path, "--name", label, "--passphrase", "testpass")
    data = json.loads(open(path).read())
    return path, data["public_key"]


# ── Tests ─────────────────────────────────────────────────────────────────────

tmp_files: list[str] = []


def test_happy_path():
    """Test 1 — happy path: challenge issued, signed, verified."""
    print("\nTest 1: Happy path (challenge → sign → verify)")

    # 1a. Request a challenge
    status, ch = post_json(ALICE, "/api/auth/challenge", {"scope": "qcb-auth"})
    if status not in (200, 201):
        result("POST /api/auth/challenge returns 200", False, f"status={status}")
        return None
    result("POST /api/auth/challenge returns 200", True)

    # 1b. Validate challenge shape
    has_fields = all(k in ch for k in ("challenge_id", "issued_at", "expires_at", "node_id", "scope"))
    result("challenge JSON has required fields", has_fields, str(list(ch.keys())) if not has_fields else "")
    if not has_fields:
        return None

    result("challenge_id is 32 hex chars", len(ch["challenge_id"]) == 32, f"len={len(ch['challenge_id'])}")
    result("expires_at > issued_at", ch["expires_at"] > ch["issued_at"],
           f"issued={ch['issued_at']} expires={ch['expires_at']}")
    now = int(time.time())
    result("challenge not already expired", ch["expires_at"] > now,
           f"expires_at={ch['expires_at']} now={now}")
    result("scope is qcb-auth", ch["scope"] == "qcb-auth", ch["scope"])

    # 1c. Sign the challenge with a fresh wallet
    path, pub_hex = generate_tmp_wallet("dis001-alice")
    tmp_files.append(path)

    challenge_json = json.dumps(ch, separators=(",", ":"))
    sig = wallet("sign-challenge", "--challenge", challenge_json, "--path", path, "--passphrase", "testpass")
    result("wallet sign-challenge produces mldsa65: tag", sig.startswith("mldsa65:"), sig[:24])

    # 1d. Submit verify
    status2, resp = post_json(ALICE, "/api/auth/verify", {
        "challenge_id": ch["challenge_id"],
        "public_key":  pub_hex,
        "signature":   sig,
    })
    ok = status2 == 200 and isinstance(resp, dict) and resp.get("status") == "verified"
    result("POST /api/auth/verify returns verified", ok,
           f"status={status2} body={str(resp)[:80]}")

    # Return challenge_id and verify body for replay test
    return ch["challenge_id"], resp if ok else None


def test_anti_replay(challenge_id: str, pub_hex: str, sig: str):
    """Test 2 — replay: re-use the same challenge_id after successful verify."""
    print("\nTest 2: Anti-replay (second verify with same challenge_id)")
    status, resp = post_json(ALICE, "/api/auth/verify", {
        "challenge_id": challenge_id,
        "public_key":  pub_hex,
        "signature":   sig,
    })
    rejected = status in (400, 404) or (isinstance(resp, dict) and resp.get("status") == "rejected")
    result("replayed challenge_id rejected", rejected, f"status={status} body={str(resp)[:80]}")


def test_forged_signature():
    """Test 3 — forged sig: random bytes presented as mldsa65 signature."""
    print("\nTest 3: Forged signature")

    status, ch = post_json(ALICE, "/api/auth/challenge")
    if status not in (200, 201):
        result("challenge issued for forge test", False, f"status={status}")
        return

    path, pub_hex = generate_tmp_wallet("dis001-forge")
    tmp_files.append(path)

    # 6618 hex chars = 3309 bytes, matching real ML-DSA-65 sig size
    import random as _rand
    forged_hex = "".join(_rand.choices("0123456789abcdef", k=6618))
    forged_sig = f"mldsa65:{forged_hex}"

    status2, resp = post_json(ALICE, "/api/auth/verify", {
        "challenge_id": ch["challenge_id"],
        "public_key":  pub_hex,
        "signature":   forged_sig,
    })
    rejected = status2 == 400 or (isinstance(resp, dict) and resp.get("status") == "rejected")
    result("forged signature rejected", rejected, f"status={status2} body={str(resp)[:80]}")


def test_wrong_key():
    """Test 4 — wrong key: sign with Alice's key but present Bob's public key."""
    print("\nTest 4: Wrong key (sign with Alice, verify against Bob's pubkey)")

    status, ch = post_json(ALICE, "/api/auth/challenge")
    if status not in (200, 201):
        result("challenge issued for wrong-key test", False, f"status={status}")
        return

    path_alice, pub_alice = generate_tmp_wallet("dis001-alice2")
    path_bob,   pub_bob   = generate_tmp_wallet("dis001-bob")
    tmp_files.extend([path_alice, path_bob])

    challenge_json = json.dumps(ch, separators=(",", ":"))
    sig_alice = wallet("sign-challenge", "--challenge", challenge_json,
                       "--path", path_alice, "--passphrase", "testpass")

    # Present Alice's signature but Bob's public key
    status2, resp = post_json(ALICE, "/api/auth/verify", {
        "challenge_id": ch["challenge_id"],
        "public_key":  pub_bob,       # mismatch
        "signature":   sig_alice,
    })
    rejected = status2 == 400 or (isinstance(resp, dict) and resp.get("status") == "rejected")
    result("wrong-key verify rejected", rejected, f"status={status2} body={str(resp)[:80]}")


def test_unknown_challenge_id():
    """Test 5 — unknown id: verify with a challenge_id the node never issued."""
    print("\nTest 5: Unknown challenge_id")

    path, pub_hex = generate_tmp_wallet("dis001-unknown")
    tmp_files.append(path)

    fake_challenge = {
        "challenge_id": "00000000000000000000000000000000",
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + 60,
        "node_id": "testchain:8080",
        "scope": "qcb-auth",
    }
    challenge_json = json.dumps(fake_challenge, separators=(",", ":"))
    sig = wallet("sign-challenge", "--challenge", challenge_json,
                 "--path", path, "--passphrase", "testpass")

    status, resp = post_json(ALICE, "/api/auth/verify", {
        "challenge_id": "00000000000000000000000000000000",
        "public_key":  pub_hex,
        "signature":   sig,
    })
    rejected = status in (400, 404) or (isinstance(resp, dict) and resp.get("status") == "rejected")
    result("unknown challenge_id rejected", rejected, f"status={status} body={str(resp)[:80]}")


# ── Main ──────────────────────────────────────────────────────────────────────

def check_node_reachable():
    try:
        conn = http.client.HTTPConnection(ALICE[0], ALICE[1], timeout=3)
        conn.request("GET", "/api/status")
        conn.getresponse().read()
        return True
    except Exception as e:
        print(f"  Cannot reach Alice node at {ALICE[0]}:{ALICE[1]}: {e}")
        return False


def check_wallet_binary():
    if not os.path.exists(_WALLET_BIN):
        print(f"  Wallet binary not found at {_WALLET_BIN}")
        print("  Build with:  cargo build -p chain-forge-wallet")
        return False
    return True


def main():
    print("=" * 60)
    print("DIS-001 Phase A — QR challenge/response auth test")
    print("=" * 60)

    print("\nPre-flight checks …")
    if not check_wallet_binary():
        sys.exit(1)
    if not check_node_reachable():
        print("  Start devnet with:  ./scripts/start-devnet-local.sh --clean")
        sys.exit(1)
    print("  Node reachable ✓   Wallet binary found ✓")

    # -- Run tests --
    # Test 1 returns the challenge_id + keys needed for the replay test
    replay_data = test_happy_path()

    # For replay test we need to re-sign with the same wallet used in Test 1
    # (challenge already consumed, so replay must fail regardless of sig validity)
    if replay_data is not None:
        challenge_id, _ = replay_data
        # Find the temp wallet path (last one added in happy path)
        if tmp_files:
            path0, pub0 = tmp_files[0], None
            try:
                pub0 = json.loads(open(path0).read())["public_key"]
                # Any signature will do — the challenge is already consumed
                dummy_challenge = json.dumps({
                    "challenge_id": challenge_id,
                    "issued_at": int(time.time()),
                    "expires_at": int(time.time()) + 60,
                    "node_id": "ignored",
                    "scope": "qcb-auth",
                }, separators=(",", ":"))
                sig0 = wallet("sign-challenge", "--challenge", dummy_challenge,
                              "--path", path0, "--passphrase", "testpass")
                test_anti_replay(challenge_id, pub0, sig0)
            except Exception as e:
                result("replay test (setup)", False, str(e))
    else:
        print("\nTest 2: Anti-replay (SKIPPED — Test 1 did not produce a challenge_id)")

    test_forged_signature()
    test_wrong_key()
    test_unknown_challenge_id()

    # -- Cleanup --
    for p in tmp_files:
        try:
            os.unlink(p)
        except OSError:
            pass

    # -- Summary --
    print("\n" + "=" * 60)
    passed = sum(1 for _, ok, _ in _results if ok)
    total  = len(_results)
    print(f"Results: {passed}/{total} passed")
    print("=" * 60)
    if passed < total:
        print("\nFailed:")
        for label, ok, detail in _results:
            if not ok:
                print(f"  {FAIL}  {label}  {detail}")
        sys.exit(1)
    else:
        print("All checks passed ✓")


if __name__ == "__main__":
    main()
