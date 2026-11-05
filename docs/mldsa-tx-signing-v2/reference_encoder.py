"""Independent reference encoder for the ML-DSA-65 transaction signing message, v1 (current) and v2 (proposed).

Pure standard library. Written from SPEC.md, not from the Rust code, so a Rust implementation can be
checked against it. v1 mirrors `chain_forge_crypto::mldsa_tx_prehash`; v2 is the proposed replacement.
"""
import hashlib
import struct

DOMAIN_V1 = b"chain-forge/pq-tx/v1\n"   # MLDSA_TX_DOMAIN_V1
DOMAIN_V2 = b"chain-forge/pq-tx/v2\n"   # proposed

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
    """DOMAIN_V2 || LP(chain_id) || LP(id) || LP(sender) || U64(nonce) || U64(gas_limit)
       || LP(body_json) || LP(pq_public_key)

    Every variable-length field is length-prefixed, so the encoding is prefix-free and no field
    can borrow bytes from its neighbour. Fixed-width integers are big-endian.
    """
    if not isinstance(pq_public_key, (bytes, bytearray)):
        raise EncodeError("pq_public_key must be bytes")
    return (DOMAIN_V2
            + _lp(_text(chain_id)) + _lp(_text(tx_id)) + _lp(_text(sender))
            + _u64(nonce) + _u64(gas_limit)
            + _lp(_text(body_json)) + _lp(bytes(pq_public_key)))


def v2_digest(*args, **kwargs) -> bytes:
    return hashlib.sha256(v2_message(*args, **kwargs)).digest()
