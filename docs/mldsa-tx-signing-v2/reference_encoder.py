"""Independent reference encoder for Qattice signing v2 (FIPS 204 pure ML-DSA-65, full canonical preimage).

Pure standard library. Written from SPEC.md, not from the Rust code, so a Rust implementation can be checked
against it. It builds the exact bytes that are handed to ML-DSA.Sign as the message `M`, the context string
`ctx`, and (for cross-checking against the internal interface) the FIPS 204 `M'`. It performs no cryptography:
signing and verification are done by a FIPS 204 implementation (see generate_vectors.py).

v1 (the current, defective digest) is kept only to demonstrate the replay defect (H0-4) in the vectors.
"""
import hashlib
import struct

PREIMAGE_VERSION_TX = 2                      # U16 at the start of every transaction preimage
CTX_TX_V2 = b"qattice/tx/v2"                 # FIPS 204 context string for transactions
MLDSA65_PK_BYTES = 1952
MLDSA65_SIG_BYTES = 3309
MAX_CTX_BYTES = 255                          # FIPS 204: |ctx| <= 255

# Context registry. Every authorization protocol has its OWN context; a context is never shared between message
# types. Only the transaction preimage is specified in this document; the others get their own versioned
# preimage specifications, and these names are reserved now so that no signature can be replayed across protocols.
CONTEXTS = {
    "transaction": b"qattice/tx/v2",
    "consensus_vote": b"qattice/consensus/vote/v1",
    "consensus_proposal": b"qattice/consensus/proposal/v1",
    "validator_key_pop": b"qattice/validator-key-pop/v1",
    "account_key_rotation": b"qattice/dis/rotate-key/v1",
    "recovery_guardian": b"qattice/dis/recovery-guardian/v1",
    "delegation": b"qattice/dis/delegation/v1",
    "wallet_auth": b"qattice/auth/challenge/v1",
    "governance_vote": b"qattice/governance/vote/v1",
}

U32_MAX = 0xFFFF_FFFF
U64_MAX = 0xFFFF_FFFF_FFFF_FFFF
U16_MAX = 0xFFFF


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


def _u16(n: int) -> bytes:
    if not isinstance(n, int) or isinstance(n, bool) or n < 0 or n > U16_MAX:
        raise EncodeError("u16 out of range")
    return struct.pack(">H", n)


def _text(s: str) -> bytes:
    if not isinstance(s, str):
        raise EncodeError("text field must be str")
    try:
        return s.encode("utf-8")
    except UnicodeEncodeError as e:  # lone surrogates cannot be UTF-8
        raise EncodeError(str(e))


def tx_preimage(chain_id: str, tx_id: str, sender: str, nonce: int, gas_limit: int,
                body_json: str, pq_public_key: bytes) -> bytes:
    """The complete canonical, versioned transaction preimage; this is `M` for ML-DSA.Sign (no hashing).

        U16(2) || LP(chain_id) || LP(id) || LP(sender) || U64(nonce) || U64(gas_limit)
               || LP(body_json) || LP(pq_public_key)

    Every variable-length field is length-prefixed, so the encoding is prefix-free and no field can borrow bytes
    from its neighbour. Integers are big-endian. Domain separation is NOT done here: it is the FIPS 204 context
    `CTX_TX_V2`, applied by the signature algorithm itself.
    """
    if not isinstance(pq_public_key, (bytes, bytearray)):
        raise EncodeError("pq_public_key must be bytes")
    return (_u16(PREIMAGE_VERSION_TX)
            + _lp(_text(chain_id)) + _lp(_text(tx_id)) + _lp(_text(sender))
            + _u64(nonce) + _u64(gas_limit)
            + _lp(_text(body_json)) + _lp(bytes(pq_public_key)))


def m_prime_pure(ctx: bytes, message: bytes) -> bytes:
    """FIPS 204 Algorithm 2 line 10: M' = 0x00 || |ctx| || ctx || M. What ML-DSA.Sign_internal actually signs."""
    if not isinstance(ctx, (bytes, bytearray)) or len(ctx) > MAX_CTX_BYTES:
        raise EncodeError("context must be bytes of at most 255 bytes")
    return bytes([0, len(ctx)]) + bytes(ctx) + bytes(message)


# --- v1: the current digest, kept only to show the replay defect -------------------------------------------------
DOMAIN_V1 = b"chain-forge/pq-tx/v1\n"


def v1_digest(chain_id: str, body_json: str) -> bytes:
    """What the current code hashes before signing: it covers only (chain_id, body), not the nonce."""
    return hashlib.sha256(DOMAIN_V1 + _text(chain_id) + b"\n" + _text(body_json)).digest()


# ---------------------------------------------------------------------------------------------------------------
# Envelope acceptance rules for a fresh ML-DSA-only (qattice-v2 profile) chain: structural, before any cryptography.
# ---------------------------------------------------------------------------------------------------------------
HEX = set("0123456789abcdefABCDEF")


def _is_hex(s: str) -> bool:
    return len(s) % 2 == 0 and all(c in HEX for c in s)


def check_envelope(tx: dict, bound_key_hex=None):
    """Return ("ok", None) or ("reject", CODE).

    tx keys: sig_scheme (None | "MlDsa" | "Classical" | "HybridEd25519MlDsa" | "SlhDsa" | "FnDsa"),
             signature_hex, public_key_hex (the Ed25519 fields), pq_signatures (list[str]), pq_public_key_hex.
    bound_key_hex: the key already bound to the sender in state, or None for an unbound account.
    """
    scheme = tx.get("sig_scheme")
    if scheme is None:
        return ("reject", "E1_SCHEME_MISSING")
    if scheme != "MlDsa":
        return ("reject", "E1_SCHEME_NOT_MLDSA")
    if tx.get("signature_hex") or tx.get("public_key_hex"):
        return ("reject", "E2_CLASSICAL_MATERIAL_PRESENT")
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
    """The key that enters the preimage and verifies the signature: the bound key if there is one, otherwise the
    first-use key carried in the transaction."""
    return bytes.fromhex(bound_key_hex if bound_key_hex is not None else tx["pq_public_key_hex"])
