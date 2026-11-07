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
