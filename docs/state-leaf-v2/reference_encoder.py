#!/usr/bin/env python3
"""Reference encoder / strict decoder for the Qattice account-state leaf, version 2 (PR-A).

Independent of the Rust code base: standard library only (hashlib SHA3-256), no Rust types, no JSON in consensus bytes.
The normative text is ENCODING.md; this file is its executable form. Nothing here is used by consensus.

Account input format (plain dicts; bytes are Python `bytes`):
    {
      "address": str, "nonce": int, "role": str,
      "balances": {denom: int},                      # any insertion order; encoded sorted
      "public_key": bytes | None,
      "key_version": int, "policy_generation": int,
      "recovery_policy": None | {"guardians": [bytes, ...], "threshold": int,
                                 "enrolled_at_key_version": int, "policy_id": int},
      "pending_recovery": None | {"new_public_key": bytes, "new_key_scheme": str, "key_version": int,
                                  "submitted_at_height": int, "activation_height": int, "policy_id": int,
                                  "cancelled": bool},
      "charm": None | {"tier": "Provisional"|"Verified"|"Established",
                       "decay_exemption": {"days": int, "last_earned_epoch": int},
                       "verified_since_epoch": int | None, "last_attested_epoch": int,
                       "consecutive_active_epochs": int, "verified_via_wot": bool},
      "escrow": None | {"job_id": str, "agent_wallet": str, "funding_source": str},
    }
"""
import hashlib
import struct

# ----------------------------------------------------------------------------------------------------------------------
# Constants (ENCODING.md sections 2 and 7)
# ----------------------------------------------------------------------------------------------------------------------
MAGIC = bytes([0x00]) + b"QALEAF" + bytes([0x00])      # 8 bytes: 00 51 41 4C 45 41 46 00
assert len(MAGIC) == 8
LEAF_VERSION = 2

TAG_ADDRESS, TAG_NONCE, TAG_ROLE, TAG_TIER, TAG_BALANCES = 0x01, 0x02, 0x03, 0x04, 0x05
TAG_PUBLIC_KEY, TAG_KEY_VERSION, TAG_POLICY_GENERATION = 0x06, 0x07, 0x08
TAG_RECOVERY_POLICY_HASH, TAG_PENDING_RECOVERY_HASH, TAG_CHARM_HASH, TAG_ESCROW_HASH = 0x09, 0x0A, 0x0B, 0x0C
REQUIRED_TAGS = (TAG_ADDRESS, TAG_NONCE, TAG_ROLE, TAG_TIER, TAG_BALANCES, TAG_KEY_VERSION, TAG_POLICY_GENERATION)
ALL_TAGS = REQUIRED_TAGS + (TAG_PUBLIC_KEY, TAG_RECOVERY_POLICY_HASH, TAG_PENDING_RECOVERY_HASH, TAG_CHARM_HASH,
                            TAG_ESCROW_HASH)

DOMAIN_RECOVERY_POLICY = b"qattice/state/recovery-policy/v1"
DOMAIN_PENDING_RECOVERY = b"qattice/state/pending-recovery/v1"
DOMAIN_CHARM = b"qattice/state/charm/v1"
DOMAIN_ESCROW = b"qattice/state/escrow/v1"

# Bounds (proposal O8; they are part of the profile, ENCODING.md section 6)
MAX_ADDRESS_BYTES = 256
MAX_ROLE_BYTES = 64
MAX_DENOM_BYTES = 64
MAX_BALANCE_ENTRIES = 256
MAX_PUBLIC_KEY_BYTES = 4096
MAX_GUARDIANS = 64
MAX_SCHEME_BYTES = 64
MAX_ESCROW_FIELD_BYTES = 256
MAX_LEAF_BYTES = 32 * 1024

TIER_CODE = {None: 0, "Provisional": 1, "Verified": 2, "Established": 3}
TIER_NAME = {1: "Provisional", 2: "Verified", 3: "Established"}

U32_MAX, U64_MAX, U128_MAX = 2**32 - 1, 2**64 - 1, 2**128 - 1


class EncodingError(ValueError):
    """Raised for an account that cannot be encoded (out of range, over a bound, ...)."""
    def __init__(self, code, msg=""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


class DecodingError(ValueError):
    """Raised for malformed leaf / substructure bytes. `code` is a stable identifier used by the negative vectors."""
    def __init__(self, code, msg=""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


# ----------------------------------------------------------------------------------------------------------------------
# Primitive writers
# ----------------------------------------------------------------------------------------------------------------------
def _u8(v, name="u8"):
    if not (0 <= v <= 255):
        raise EncodingError("int_range", f"{name}={v}")
    return bytes([v])


def _u32(v, name="u32"):
    if not (0 <= v <= U32_MAX):
        raise EncodingError("int_range", f"{name}={v}")
    return struct.pack(">I", v)


def _u64(v, name="u64"):
    if not (0 <= v <= U64_MAX):
        raise EncodingError("int_range", f"{name}={v}")
    return struct.pack(">Q", v)


def _u128(v, name="u128"):
    if not (0 <= v <= U128_MAX):
        raise EncodingError("int_range", f"{name}={v}")
    return v.to_bytes(16, "big")


def _bool(v, name="bool"):
    if v is True or v is False:
        return bytes([1 if v else 0])
    raise EncodingError("bool_type", f"{name}={v!r}")


def _bytes(b, maxlen, name):
    if not isinstance(b, (bytes, bytearray)):
        raise EncodingError("type", f"{name} must be bytes")
    if len(b) > maxlen:
        raise EncodingError("length_over_bound", f"{name} {len(b)} > {maxlen}")
    return _u32(len(b)) + bytes(b)


def _str(s, maxlen, name, allow_empty=True):
    if not isinstance(s, str):
        raise EncodingError("type", f"{name} must be str")
    try:
        raw = s.encode("utf-8")      # lone surrogates raise UnicodeEncodeError (not valid UTF-8)
    except UnicodeEncodeError:
        raise EncodingError("invalid_utf8", name)
    if not allow_empty and not raw:
        raise EncodingError("empty_not_allowed", name)
    return _bytes(raw, maxlen, name)


# ----------------------------------------------------------------------------------------------------------------------
# Domain-separated hash (ENCODING.md section 3)
# ----------------------------------------------------------------------------------------------------------------------
def domain_hash(domain: bytes, body: bytes) -> bytes:
    """SHA3-256( U8(len(domain)) || domain || body ). `domain` is 1..255 printable-ASCII bytes."""
    if not (1 <= len(domain) <= 255) or any(not (0x20 <= c <= 0x7E) for c in domain):
        raise EncodingError("bad_domain", repr(domain))
    return hashlib.sha3_256(bytes([len(domain)]) + domain + body).digest()


# ----------------------------------------------------------------------------------------------------------------------
# Substructure bodies (encode)
# ----------------------------------------------------------------------------------------------------------------------
def encode_recovery_policy(p) -> bytes:
    g = p["guardians"]
    if not (1 <= len(g) <= MAX_GUARDIANS):
        raise EncodingError("guardian_count", str(len(g)))
    out = _u32(p["threshold"], "threshold") + _u32(p["enrolled_at_key_version"], "enrolled_at_key_version")
    out += _u64(p["policy_id"], "policy_id") + _u32(len(g))
    for i, k in enumerate(g):                       # STORED ORDER, never sorted
        out += _bytes(k, MAX_PUBLIC_KEY_BYTES, f"guardian[{i}]")
    return out


def encode_pending_recovery(p) -> bytes:
    return (_bytes(p["new_public_key"], MAX_PUBLIC_KEY_BYTES, "new_public_key")
            + _str(p["new_key_scheme"], MAX_SCHEME_BYTES, "new_key_scheme")
            + _u32(p["key_version"], "key_version")
            + _u64(p["submitted_at_height"], "submitted_at_height")
            + _u64(p["activation_height"], "activation_height")
            + _u64(p["policy_id"], "policy_id")
            + _bool(p["cancelled"], "cancelled"))


def encode_charm(c) -> bytes:
    tier = TIER_CODE[c["tier"]]
    if tier == 0:
        raise EncodingError("charm_tier_none")
    out = _u8(tier) + _u32(c["decay_exemption"]["days"], "days") + _u64(c["decay_exemption"]["last_earned_epoch"],
                                                                         "last_earned_epoch")
    v = c["verified_since_epoch"]
    out += b"\x00" if v is None else b"\x01" + _u64(v, "verified_since_epoch")
    out += _u64(c["last_attested_epoch"], "last_attested_epoch")
    out += _u32(c["consecutive_active_epochs"], "consecutive_active_epochs")
    out += _bool(c["verified_via_wot"], "verified_via_wot")
    return out


def encode_escrow(e) -> bytes:
    return (_str(e["job_id"], MAX_ESCROW_FIELD_BYTES, "job_id")
            + _str(e["agent_wallet"], MAX_ESCROW_FIELD_BYTES, "agent_wallet")
            + _str(e["funding_source"], MAX_ESCROW_FIELD_BYTES, "funding_source"))


def recovery_policy_hash(p): return domain_hash(DOMAIN_RECOVERY_POLICY, encode_recovery_policy(p))
def pending_recovery_hash(p): return domain_hash(DOMAIN_PENDING_RECOVERY, encode_pending_recovery(p))
def charm_hash(c): return domain_hash(DOMAIN_CHARM, encode_charm(c))
def escrow_hash(e): return domain_hash(DOMAIN_ESCROW, encode_escrow(e))


# ----------------------------------------------------------------------------------------------------------------------
# Leaf encoder (version 2)
# ----------------------------------------------------------------------------------------------------------------------
def encode_leaf_v2(a) -> bytes:
    charm = a.get("charm")
    tier = TIER_CODE[charm["tier"]] if charm is not None else 0
    fields = []                                               # (tag, bytes)
    fields.append((TAG_ADDRESS, _str(a["address"], MAX_ADDRESS_BYTES, "address", allow_empty=False)))
    fields.append((TAG_NONCE, _u64(a["nonce"], "nonce")))
    fields.append((TAG_ROLE, _str(a["role"], MAX_ROLE_BYTES, "role")))
    fields.append((TAG_TIER, _u8(tier)))
    bal = a["balances"]
    if len(bal) > MAX_BALANCE_ENTRIES:
        raise EncodingError("balance_count_over_bound", str(len(bal)))
    entries = []
    for denom, amount in bal.items():
        entries.append((_str(denom, MAX_DENOM_BYTES, "denom", allow_empty=False), _u128(amount, "amount")))
    entries.sort(key=lambda e: e[0][4:])                      # ascending by the denom's UTF-8 BYTES (not code points)
    seen = [e[0] for e in entries]
    if len(set(seen)) != len(seen):
        raise EncodingError("duplicate_denom")
    fields.append((TAG_BALANCES, _u32(len(entries)) + b"".join(d + v for d, v in entries)))
    if a.get("public_key") is not None:
        fields.append((TAG_PUBLIC_KEY, _bytes(a["public_key"], MAX_PUBLIC_KEY_BYTES, "public_key")))
    fields.append((TAG_KEY_VERSION, _u32(a["key_version"], "key_version")))
    fields.append((TAG_POLICY_GENERATION, _u64(a["policy_generation"], "policy_generation")))
    if a.get("recovery_policy") is not None:
        fields.append((TAG_RECOVERY_POLICY_HASH, recovery_policy_hash(a["recovery_policy"])))
    if a.get("pending_recovery") is not None:
        fields.append((TAG_PENDING_RECOVERY_HASH, pending_recovery_hash(a["pending_recovery"])))
    if charm is not None:
        fields.append((TAG_CHARM_HASH, charm_hash(charm)))
    if a.get("escrow") is not None:
        fields.append((TAG_ESCROW_HASH, escrow_hash(a["escrow"])))
    fields.sort(key=lambda f: f[0])                           # ascending tag order
    body = b"".join(bytes([t]) + v for t, v in fields)
    out = MAGIC + bytes([LEAF_VERSION]) + _u32(len(body)) + body          # explicit body length: the format is prefix-free
    if len(out) > MAX_LEAF_BYTES:
        raise EncodingError("leaf_over_bound", str(len(out)))
    return out


# ----------------------------------------------------------------------------------------------------------------------
# Strict decoder (rejects anything the encoder cannot have produced)
# ----------------------------------------------------------------------------------------------------------------------
class _Reader:
    def __init__(self, data, what="leaf"):
        self.d, self.i, self.what = data, 0, what

    def take(self, n, code="truncated"):
        if n < 0 or self.i + n > len(self.d):
            raise DecodingError(code, f"{self.what}: need {n} bytes at offset {self.i}, have {len(self.d) - self.i}")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u8(self): return self.take(1)[0]
    def u32(self): return struct.unpack(">I", self.take(4))[0]
    def u64(self): return struct.unpack(">Q", self.take(8))[0]
    def u128(self): return int.from_bytes(self.take(16), "big")

    def boolean(self):
        v = self.u8()
        if v > 1:
            raise DecodingError("bool_not_01", f"{self.what}: byte {v}")
        return v == 1

    def bytes_(self, maxlen, name):
        n = self.u32()
        if n > maxlen:
            raise DecodingError("length_over_bound", f"{name} {n} > {maxlen}")
        return self.take(n)

    def str_(self, maxlen, name, allow_empty=True):
        raw = self.bytes_(maxlen, name)
        if not allow_empty and not raw:
            raise DecodingError("empty_not_allowed", name)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise DecodingError("invalid_utf8", name)

    def done(self):
        if self.i != len(self.d):
            raise DecodingError("trailing_bytes", f"{self.what}: {len(self.d) - self.i} extra bytes")


def decode_leaf_v2(data: bytes):
    """Return {'fields': {...}} with hashed substructures kept as 32-byte digests (their preimages are not in the leaf)."""
    if len(data) > MAX_LEAF_BYTES:
        raise DecodingError("leaf_over_bound", str(len(data)))
    r = _Reader(data)
    if r.take(8, "truncated") != MAGIC:
        raise DecodingError("bad_magic")
    version = r.u8()
    if version != LEAF_VERSION:
        raise DecodingError("bad_version", str(version))
    body_len = r.u32()
    remaining = len(data) - r.i
    if remaining < body_len:
        raise DecodingError("truncated", f"declared body {body_len} bytes, {remaining} present")
    if remaining > body_len:
        raise DecodingError("trailing_bytes", f"declared body {body_len} bytes, {remaining} present")
    out, last_tag = {}, 0
    while r.i < len(data):
        tag = r.u8()
        if tag not in ALL_TAGS:
            raise DecodingError("unknown_tag", hex(tag))
        if tag == last_tag:
            raise DecodingError("duplicate_tag", hex(tag))
        if tag < last_tag:
            raise DecodingError("tag_out_of_order", hex(tag))
        last_tag = tag
        if tag == TAG_ADDRESS: out["address"] = r.str_(MAX_ADDRESS_BYTES, "address", allow_empty=False)
        elif tag == TAG_NONCE: out["nonce"] = r.u64()
        elif tag == TAG_ROLE: out["role"] = r.str_(MAX_ROLE_BYTES, "role")
        elif tag == TAG_TIER:
            t = r.u8()
            if t > 3:
                raise DecodingError("tier_out_of_range", str(t))
            out["tier_code"] = t
        elif tag == TAG_BALANCES:
            n = r.u32()
            if n > MAX_BALANCE_ENTRIES:
                raise DecodingError("balance_count_over_bound", str(n))
            bal, prev = [], None
            for _ in range(n):
                denom_raw = r.bytes_(MAX_DENOM_BYTES, "denom")
                if not denom_raw:
                    raise DecodingError("empty_not_allowed", "denom")
                try:
                    denom_raw.decode("utf-8")
                except UnicodeDecodeError:
                    raise DecodingError("invalid_utf8", "denom")
                if prev is not None and denom_raw <= prev:
                    raise DecodingError("balances_not_strictly_ascending")
                prev = denom_raw
                bal.append((denom_raw.decode("utf-8"), r.u128()))
            out["balances"] = bal
        elif tag == TAG_PUBLIC_KEY: out["public_key"] = r.bytes_(MAX_PUBLIC_KEY_BYTES, "public_key")
        elif tag == TAG_KEY_VERSION: out["key_version"] = r.u32()
        elif tag == TAG_POLICY_GENERATION: out["policy_generation"] = r.u64()
        elif tag == TAG_RECOVERY_POLICY_HASH: out["recovery_policy_hash"] = r.take(32)
        elif tag == TAG_PENDING_RECOVERY_HASH: out["pending_recovery_hash"] = r.take(32)
        elif tag == TAG_CHARM_HASH: out["charm_hash"] = r.take(32)
        elif tag == TAG_ESCROW_HASH: out["escrow_hash"] = r.take(32)
    for t in REQUIRED_TAGS:
        names = {TAG_ADDRESS: "address", TAG_NONCE: "nonce", TAG_ROLE: "role", TAG_TIER: "tier_code",
                 TAG_BALANCES: "balances", TAG_KEY_VERSION: "key_version", TAG_POLICY_GENERATION: "policy_generation"}
        if names[t] not in out:
            raise DecodingError("missing_required_tag", hex(t))
    if (out["tier_code"] != 0) != ("charm_hash" in out):
        raise DecodingError("tier_charm_mismatch", "tier_code != 0 iff a charm hash is present")
    return out


def decode_recovery_policy(body: bytes):
    r = _Reader(body, "recovery_policy")
    threshold, enrolled, pid, n = r.u32(), r.u32(), r.u64(), r.u32()
    if not (1 <= n <= MAX_GUARDIANS):
        raise DecodingError("guardian_count", str(n))
    g = [r.bytes_(MAX_PUBLIC_KEY_BYTES, f"guardian[{i}]") for i in range(n)]
    r.done()
    return {"threshold": threshold, "enrolled_at_key_version": enrolled, "policy_id": pid, "guardians": g}


def decode_pending_recovery(body: bytes):
    r = _Reader(body, "pending_recovery")
    out = {"new_public_key": r.bytes_(MAX_PUBLIC_KEY_BYTES, "new_public_key"),
           "new_key_scheme": r.str_(MAX_SCHEME_BYTES, "new_key_scheme"),
           "key_version": r.u32(), "submitted_at_height": r.u64(), "activation_height": r.u64(),
           "policy_id": r.u64(), "cancelled": r.boolean()}
    r.done()
    return out


def decode_charm(body: bytes):
    r = _Reader(body, "charm")
    t = r.u8()
    if t not in TIER_NAME:
        raise DecodingError("tier_out_of_range", str(t))
    out = {"tier": TIER_NAME[t], "decay_exemption": {"days": r.u32(), "last_earned_epoch": r.u64()}}
    flag = r.u8()
    if flag > 1:
        raise DecodingError("bool_not_01", "verified_since_epoch flag")
    out["verified_since_epoch"] = r.u64() if flag == 1 else None
    out["last_attested_epoch"] = r.u64()
    out["consecutive_active_epochs"] = r.u32()
    out["verified_via_wot"] = r.boolean()
    r.done()
    return out


def decode_escrow(body: bytes):
    r = _Reader(body, "escrow")
    out = {"job_id": r.str_(MAX_ESCROW_FIELD_BYTES, "job_id"), "agent_wallet": r.str_(MAX_ESCROW_FIELD_BYTES,
                                                                                    "agent_wallet"),
           "funding_source": r.str_(MAX_ESCROW_FIELD_BYTES, "funding_source")}
    r.done()
    return out


# ----------------------------------------------------------------------------------------------------------------------
# Tree-level hashing (ENCODING.md section 4). Reproduces chain-forge-state/src/jmt.rs; used only to document and test
# the distinction between the leaf VALUE (this file) and the tree's own hashing.
# ----------------------------------------------------------------------------------------------------------------------
JMT_TAG_LEAF, JMT_TAG_INTERNAL, JMT_TAG_VALUE = 0x00, 0x01, 0x02


def jmt_key_path(address: str) -> bytes:
    return hashlib.sha3_256(address.encode("utf-8")).digest()


def jmt_value_hash(leaf_value: bytes) -> bytes:
    return hashlib.sha3_256(bytes([JMT_TAG_VALUE]) + leaf_value).digest()


def jmt_leaf_node_hash(address: str, leaf_value: bytes) -> bytes:
    return hashlib.sha3_256(bytes([JMT_TAG_LEAF]) + jmt_key_path(address) + jmt_value_hash(leaf_value)).digest()


# ----------------------------------------------------------------------------------------------------------------------
# Legacy v1 text leaf (historical roots stay verifiable: the v1 definition is frozen here and in the Rust encoder)
# ----------------------------------------------------------------------------------------------------------------------
def _serde_json_str(s: str) -> str:
    """JSON string as serde_json writes it: UTF-8 kept, only quote, backslash and control characters escaped."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"': out.append('\\"')
        elif ch == "\\": out.append("\\\\")
        elif ch == "\n": out.append("\\n")
        elif ch == "\r": out.append("\\r")
        elif ch == "\t": out.append("\\t")
        elif o == 8: out.append("\\b")
        elif o == 12: out.append("\\f")
        elif o < 0x20: out.append("\\u%04x" % o)
        else: out.append(ch)
    out.append('"')
    return "".join(out)


def encode_leaf_v1(a) -> bytes:
    """The v1 leaf exactly as `AccountState::to_leaf_bytes` builds it (text, '|' joined)."""
    charm = a.get("charm")
    parts = [a["address"], str(a["nonce"]), charm["tier"] if charm is not None else "none"]
    for denom in sorted(a["balances"]):                      # BTreeMap<String,_>: ascending byte order
        parts.append(f"{denom}={a['balances'][denom]}")
    if a.get("public_key") is not None:
        parts.append("pk=" + bytes(a["public_key"]).hex())
    if a.get("escrow") is not None:
        e = a["escrow"]
        parts.append('escrow={"job_id":%s,"agent_wallet":%s,"funding_source":%s}' % (
            _serde_json_str(e["job_id"]), _serde_json_str(e["agent_wallet"]), _serde_json_str(e["funding_source"])))
    if a.get("recovery_policy") is not None:
        rp = a["recovery_policy"]
        parts.append(f"recovery=t{rp['threshold']}/{len(rp['guardians'])}/{rp['enrolled_at_key_version']}/pid{rp['policy_id']}")
    if a.get("policy_generation", 0) > 0:
        parts.append(f"pgen={a['policy_generation']}")
    return "|".join(parts).encode("utf-8")
