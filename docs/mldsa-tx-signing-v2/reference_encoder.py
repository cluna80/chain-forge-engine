"""Independent reference encoder for the ML-DSA-65 transaction signing message, v1 (current) and v2 (proposed).

Pure standard library. Written from SPEC.md, not from the Rust code, so a Rust implementation can be
checked against it. v1 mirrors `chain_forge_crypto::mldsa_tx_prehash`; v2 is the proposed replacement.
"""
import hashlib
import struct

DOMAIN_V1 = b"chain-forge/pq-tx/v1\n"   # MLDSA_TX_DOMAIN_V1
DOMAIN_V2 = b"chain-forge/pq-tx/v2\n"   # proposed
ALG_MLDSA65 = b"\x01"                    # fixed algorithm identifier: ML-DSA-65 is the ONLY algorithm; there is no negotiation
MLDSA65_PK_BYTES = 1952
MLDSA65_SIG_BYTES = 3309

U32_MAX = 0xFFFF_FFFF
U64_MAX = 0xFFFF_FFFF_FFFF_FFFF


class EncodeError(ValueError):
    pass


def _lp(b: bytes) -> bytes:
    """U32 big-endian length prefix followed by the bytes."""
    if len(b) > U32_MAX:
        raise EncodeError("field longer than 2^32-1 bytes")
    return struct.pack(">I", len(b)) + b


def _u64(n: int) -> bytes:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n > U64_MAX:
        raise EncodeError("u64 out of range")
    return struct.pack(">Q", n)


def _text(s: str) -> bytes:
    if not isinstance(s, str):
        raise EncodeError("text field must be str")
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError as e:  # lone surrogates cannot be UTF-8
        raise EncodeError(str(e))


def v1_message(chain_id: str, body_json: str) -> bytes:
    """Exactly what v1 hashes: DOMAIN_V1 || chain_id || "\\n" || body_json."""
    return DOMAIN_V1 + _text(chain_id) + b"\n" + _text(body_json)


def v1_digest(chain_id: str, body_json: str) -> bytes:
    return hashlib.sha256(v1_message(chain_id, body_json)).digest()


def v2_message(chain_id: str, tx_id: str, sender: str, nonce: int, gas_limit: int,
               body_json: str, pq_public_key: bytes) -> bytes:
    """DOMAIN_V2 || ALG_MLDSA65 || LP(chain_id) || LP(id) || LP(sender) || U64(nonce) || U64(gas_limit)
       || LP(body_json) || LP(pq_public_key)

    Every variable-length field is length-prefixed, so the encoding is prefix-free and no field
    can borrow bytes from its neighbour. Fixed-width integers are big-endian.
    """
    if not isinstance(pq_public_key, (bytes, bytearray)):
        raise EncodeError("pq_public_key must be bytes")
    return (DOMAIN_V2 + ALG_MLDSA65
            + _lp(_text(chain_id)) + _lp(_text(tx_id)) + _lp(_text(sender))
            + _u64(nonce) + _u64(gas_limit)
            + _lp(_text(body_json)) + _lp(bytes(pq_public_key)))


def v2_digest(*args, **kwargs) -> bytes:
    return hashlib.sha256(v2_message(*args, **kwargs)).digest()


# ---------------------------------------------------------------------------------------------
# Envelope acceptance rules for a fresh ML-DSA-only (v2 profile) chain.
#
# These are the STRUCTURAL rules a verifier applies before any cryptography. They do not verify a
# signature (no ML-DSA implementation here); a signature check happens afterwards over v2_digest()
# with the key resolved as in rule E5. Every rejection has a stable code so a Rust implementation
# can be tested against the same table.
# ---------------------------------------------------------------------------------------------
HEX = set("0123456789abcdefABCDEF")


def _is_hex(s: str) -> bool:
    return len(s) % 2 == 0 and all(c in HEX for c in s)


def check_envelope(tx: dict, bound_key_hex=None):
    """Return ("ok", None) or ("reject", CODE) for a transaction envelope on a v2-profile chain.

    tx keys: sig_scheme (None | "MlDsa" | "Classical" | "HybridEd25519MlDsa" | "SlhDsa" | "FnDsa"),
             signature_hex, public_key_hex (the Ed25519 fields), pq_signatures (list[str]),
             pq_public_key_hex.
    bound_key_hex: the key already bound to the sender in state, or None for an unbound account.
    """
    scheme = tx.get("sig_scheme")
    if scheme is None:
        return ("reject", "E1_SCHEME_MISSING")          # no implicit/legacy detection on a v2 chain
    if scheme != "MlDsa":
        return ("reject", "E1_SCHEME_NOT_MLDSA")        # Ed25519, hybrid, SLH-DSA, FN-DSA, anything else
    if tx.get("signature_hex") or tx.get("public_key_hex"):
        return ("reject", "E2_CLASSICAL_MATERIAL_PRESENT")   # no Ed25519 signature or key may ride along
    sigs = tx.get("pq_signatures") or []
    if len(sigs) != 1:
        return ("reject", "E3_NOT_EXACTLY_ONE_SIGNATURE")
    entry = sigs[0]
    if not entry.startswith("mldsa65:"):
        return ("reject", "E4_BAD_SIGNATURE_TAG")
    body = entry[len("mldsa65:"):]
    if not _is_hex(body):
        return ("reject", "E4_SIGNATURE_NOT_HEX")
    if len(body) != 2 * MLDSA65_SIG_BYTES:
        return ("reject", "E4_SIGNATURE_WRONG_LENGTH")
    pk = tx.get("pq_public_key_hex") or ""
    if not _is_hex(pk):
        return ("reject", "E5_KEY_NOT_HEX")
    if bound_key_hex is None:
        if len(pk) != 2 * MLDSA65_PK_BYTES:
            return ("reject", "E5_FIRST_USE_KEY_MISSING_OR_WRONG_LENGTH")
    else:
        if pk and pk.lower() != bound_key_hex.lower():
            return ("reject", "E5_KEY_DIFFERS_FROM_BOUND_KEY")
    return ("ok", None)


def effective_public_key(tx: dict, bound_key_hex=None) -> bytes:
    """The key that enters the v2 preimage and verifies the signature: the bound key if there is one,
    otherwise the first-use key carried in the transaction."""
    return bytes.fromhex(bound_key_hex if bound_key_hex is not None else tx["pq_public_key_hex"])
