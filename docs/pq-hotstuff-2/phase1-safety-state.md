# PQ-HotStuff-2 Phase 1 step 1: safety-state persistence (design note)

Implements spec section 7 (`docs/pq-hotstuff-001-spec.md`). Code: `chain-forge-consensus/src/pq_hotstuff/safety/`, feature `pq-hotstuff`
(off by default). Nothing here activates PQ-HotStuff-2, touches Tendermint, or handles production validator keys.

## Commit sequence (a signature is returned to the caller only after step 7)
1. check the persisted state: floors (`hvr`), one message per kind and round, epoch;
2. build the canonical message (wire module, spec 3.2);
3. sign (hedged), through the `ConsensusSigner` trait;
4. write the new record to a temporary file; 5. `fsync` it; 6. rename it over the state file and `fsync` the directory;
7. advance the trusted monotonic counter to the record's counter.

Any failure from step 3 on latches the store: it refuses everything until reopened. A repeat of an already signed message is a
re-send of the stored message and envelope, byte for byte; the signer is not called and nothing is written.

## One addition to the spec's section 7: step 7, the trusted counter (needs owner and spec review)
The spec's sequence ends at "write, fsync, rename, fsync dir, send". An ordinary file cannot tell a restored old backup from the
current file, so the record carries a counter, and a trusted `MonotonicCounter` (hardware counter, HSM, remote witness) is advanced
after the file is durable and before the signature is returned. On open: file counter == trusted: normal; file == trusted + 1:
the crash window between steps 6 and 7 (nothing was returned yet), and open completes the counter; file < trusted: rollback,
refused; file > trusted + 1: inconsistent, refused. **If the spec keeps the shorter sequence, rollback of the file is not
detectable.** The counters in the tests are in-memory doubles, not trusted mechanisms.

## Fail closed
`open` never creates or repairs anything. It refuses: no state; a marker without state; state without a marker; a damaged,
truncated, bit-flipped or non-canonical file (checksum and strict decoder); a different profile, chain, key or instance; a stored
message that is not canonical, is for another chain or epoch, or whose round disagrees; a stored signature that does not verify;
an internally inconsistent record; a record behind what the chain shows for the key; a rolled-back or inconsistent counter.
Initialization is explicit (`initialize_fresh`): it refuses an existing state or marker, a nonzero trusted counter, and a key the
chain already shows participating.

## Limits, stated plainly
* The checksum detects corruption; it does not authenticate. Someone who can write the file can forge a record (the stored
  signatures, however, are verified against the validator's key on load).
* Rollback protection is exactly as strong as the counter. With the file and the counter both restored, the store opens and is
  stale; a test asserts this so nobody mistakes the file for a defence.
* Directory `fsync` on Windows is the same technique as `chain-forge-node` and is not proven durable across power loss on NTFS.
* The fault model (every post-crash state: unsynced writes absent, torn at sampled offsets, or complete; unsynced renames applied
  or not) is a model, run in memory; the filesystem tests show only that the real directory behaves.
* Multi-process locking of the directory is out of scope here.

## Strict compare-and-advance, sessions and binding (spec 7.1, PR #129; added after the owner's review)
* The counter trait is `binding()`, `read()`, `acquire_session()` and `advance(expected_previous, session)`. `advance` is a strict
  compare-and-advance: it succeeds only if the counter equals `expected_previous` and the session is the latest; there is no
  idempotent form (the lost-acknowledgement case does not need one: afterwards the file and the counter are equal).
* **Binding.** A counter handle belongs to one validator key and one instance. Initialization and `open` refuse a counter bound
  to anything else.
* **Sessions.** `initialize_fresh` and `open` acquire a session only after all validation has passed, so a failed open (damaged,
  stale, rolled back, mismatched) never takes the session from the running store. A superseded store is refused by the counter at
  its next commit, latches, and returns nothing.
* **Recovery advance** (`file == trusted + 1`): a compare-and-advance from the value just read, run after validation and before
  the store exists. If it fails, including because another writer moved the counter, `open` returns an error and no store.
* **A successful advance is not a licence to expose a signature by another route.** The signer is called only inside the single
  commit path; the store has no method that returns a raw signature; a signature reaches the caller only inside `Signed`, after
  the file and the counter both succeeded. Holders of the key material can still sign outside the store (spec 7.1).

## Digest-bound commits (spec 7.1.1, PR #129; implemented after the owner's approval)
The two-store tests exposed that a numeric counter cannot tell two records with the same number apart: a fenced-out writer on its
own disk fails at the counter step but leaves its record behind, and that record looked committed on restart. The counter now holds
`(value, digest)`:
* the **digest** of a record is the SHA3-256 checksum already sealing its canonical encoding, so it commits to the whole record:
  `prev_digest`, the profile, the chain, the validator key, the instance, the counter, the epoch, the floors, and every stored
  message and signature envelope (a test changes each field and requires the digest to change);
* each record carries `prev_digest`, the digest of the record it replaces (zero for the first), so records form a chain (format
  version 2; version 1 files are refused);
* a commit is `advance((n-1, d_(n-1)) -> d_n, session)`;
* on open: file counter equal and digest equal: normal; equal counter, different digest: **fork**, refused; one ahead with
  `prev_digest` equal to the committed digest: the durable successor, adopted by a gated compare-and-advance; one ahead with any
  other predecessor: refused; behind or further ahead: refused as before.

Tests: the two-disk conflicting-vote scenario, the shared-directory overwrite, two successors one ahead (the first restart commits,
the second is refused), and a process that died after its file was durable while a competitor committed a different successor
(the original fails closed even though its record is internally valid). Unchanged: a holder of the signing key can still sign
outside the store, and the in-repository counters are test doubles.
