# PQ-HotStuff-2 Phase 1 step 1: safety-state persistence (design note)

Implements spec section 7 and the trusted-counter protocol of sections 7.1 and 7.1.1 of `docs/pq-hotstuff-001-spec.md`. Sections
7.1 and 7.1.1 were approved by the owner and merged through PR #129 (merge commit `3f797c4d82d3796db43799c534eee78f829dfc67`); they are the
design baseline for this code. Code: `chain-forge-consensus/src/pq_hotstuff/safety/`, feature `pq-hotstuff` (off by default). Nothing
here activates PQ-HotStuff-2, touches Tendermint, handles production validator keys, or provides a production counter backend.

## Commit sequence (a signature is returned to the caller only after step 7)
1. check the persisted state: floors (`hvr`), one message per kind and round, epoch, and that a next record counter exists;
2. build the canonical message (wire module, spec 3.2);
3. sign (hedged), through the `ConsensusSigner` trait;
4. write the new record to a temporary file; 5. `fsync` it; 6. rename it over the state file and `fsync` the directory;
7. **compare-and-advance** the counter from the state of the record being replaced, `(counter, digest)`, to `(counter + 1, digest of the
   new record)`, presenting the store's session.

Any failure from step 3 on latches the store: it refuses everything until reopened. A repeat of an already signed message is a
re-send of the stored message and envelope, byte for byte; the signer is not called and nothing is written.

## The counter protocol (spec 7.1 and 7.1.1)
* **Interface.** `binding()`, `read() -> CounterState{value, digest}`, `acquire_session()` and
  `advance(expected, new_digest, session)`: succeeds only if the counter equals `expected` (value **and** digest) and the session is the
  latest; there is no idempotent form (the lost-acknowledgement case does not need one: afterwards the file and the counter are equal).
* **Binding.** A counter handle belongs to one validator key and one instance; initialization and `open` refuse any other.
* **Sessions.** A store acquires its session only after all validation in `open` has passed, so a failed open never supersedes the
  running store. A superseded store is refused by the counter at its next commit, latches, and returns nothing.
* **Digest-bound records.** The digest of a record is the SHA3-256 checksum sealing its canonical body (format version 2), so it commits to
  `prev_digest`, the profile, the chain, the key, the instance, the counter, the epoch, the floors and every stored message and
  envelope. Each record carries `prev_digest`, the digest of the record it replaces (zero for the first).
* **Open rules** (file counter `f`, trusted `(t, d_t)`): `f == t` and the file's digest equals `d_t`: normal; `f == t` and any other
  digest: **fork**, refused; `f == t + 1` and `prev_digest == d_t`: the durable successor, adopted by a gated compare-and-advance;
  `f == t + 1` with any other predecessor: refused; `f < t`: rollback, refused; `f > t + 1`: inconsistent, refused; counter unreadable:
  refused.
* **Recovery advance** (`f == t + 1`): one compare-and-advance from the value just read, run after validation and before the store
  exists. If it fails, including because another writer moved the counter, `open` returns an error and no store.
* **Counter exhaustion.** Counter arithmetic is checked. If the counter is at `u64::MAX`, `open` refuses with
  `OpenError::CounterExhausted` before acquiring a session or writing anything, because "the committed value plus one" does not exist and
  no further record can ever be committed. If the record counter is at `u64::MAX`, a new signature is refused with
  `SignError::CounterExhausted` **before the signer is called**: nothing is signed, written or advanced. A re-send of an already committed
  message needs no new record and is unchanged. The only recovery is key rotation.
* **A successful advance is not a licence to expose a signature by another route.** The signer is called only inside the single commit
  path; the store has no method that returns a raw signature; a signature reaches the caller only inside `Signed`, after the file and
  the counter both succeeded. Holders of the signing key material can still sign outside the store (spec 7.1).

## Fail closed
`open` never creates or repairs anything. It refuses: no state; a marker without state; state without a marker; a damaged, truncated,
bit-flipped, wrong-version or non-canonical file (checksum and strict decoder); a different profile, chain, key or instance; a counter
bound to anything else; a stored message that is not canonical, is for another chain or epoch, or whose round disagrees; a stored
signature that does not verify; an internally inconsistent record; a record behind what the chain shows for the key; a fork; a
wrong successor; a rolled-back, inconsistent or exhausted counter. Initialization is explicit (`initialize_fresh`): it refuses an
existing state or marker, a nonzero counter or a zero counter that holds a digest, and a key the chain already shows participating.

## Limits, stated plainly
* The in-repository counters are test doubles. They are not trusted mechanisms, and a production counter backend (with a threat model
  and independent review) does not exist.
* The digest-bound state prevents retransmission of a record that is not the committed one. It does not stop a holder of an exportable
  signing key from signing outside the store; production prevention needs the signing operation inside a trusted boundary (spec 7.1).
* The checksum detects corruption; it does not authenticate. Someone who can write the file can forge a record (the stored signatures,
  however, are verified against the validator's key on load, and the counter commits to the digest).
* With the file and an untrusted counter both restored, the store opens and is stale; a test asserts this so nobody mistakes the file
  for a defence.
* Participation evidence (for the staleness rule and for refusing a fresh start of a key that already participated) is an input supplied
  by the caller; nothing here derives it from a chain. That belongs to the engine integration.
* Directory `fsync` on Windows is the same technique as `chain-forge-node` and is not proven durable across power loss on NTFS, which
  remains an operational acceptance requirement. The fault model (every post-crash state: unsynced writes absent, torn at sampled
  offsets, or complete; unsynced renames applied or not) is a model run in memory; the filesystem tests show only that the real
  directory behaves. Multi-process locking of the directory is out of scope.
