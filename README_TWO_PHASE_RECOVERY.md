# BridgeAgent: two-phase checkpoint registration (offline candidate)

**Status:** OFFLINE_TESTED_NOT_DEPLOYED. The `FakePinStore` is an ephemeral synthetic simulator, **not** an independently trusted witness or anchor. No Civil NX connection, numerical extraction, real signing authority, production integration, or engineering approval was performed.

## Intended sequence

1. Verify the signed capture/analysis evidence using existing offline guards; derive a deterministic candidate next head/count.
2. Persist a `PREPARED` transaction journal record (SQLite FULL synchronous), then request a conditional reservation (`prepare`) from the external pin-store adapter against the independently pinned previous head/count.
3. Append the signed receipt using the existing append-only registry; compare its actual resulting head/count to the reserved candidate.
4. Commit the independent high-water pin (`commit`) and then mark the local journal `COMMITTED`.

**Crash reconciliation:** With a pending journal, if the local registry is still at the old checkpoint, abort an authentic matching external reservation. If it is at the new checkpoint, finalize an authentic matching external reservation or recognize an already committed matching external pin. If local/external states disagree, hold without automatic acceptance. Any interrupted transaction must be reconciled before new appends. `append()` does not auto-reconcile a pending transaction.

**Same-host writer safety:** A separate SQLite `BEGIN IMMEDIATE` coordinator lock serializes `append` and `recover` across processes sharing one local filesystem. This is **not** a distributed lock; separate hosts, replicated filesystems, or independent processes with different lock paths are out of scope.

## What this does not establish

- The simulated external store is not independent, authenticated, durable, signed, or rollback-resistant. A production adapter must authenticate and independently persist the reservation and committed high-water record, provide idempotent CAS semantics, and survive its own crash/restart.
- A malicious or compromised independent store, trusted clock, or signer defeats important assumptions. Local SQLite durability is filesystem-dependent.
- A prepared record is **not** proof that a capture happened. Successful tests establish consistency of synthetic fixtures only.
- A genuine completed Civil NX analysis, result table, and authenticated capture evidence are still missing. Engineering acceptance is always false.

## Verification

Run `python -m unittest discover -v` from the extracted directory. The package includes all previous regression modules plus `two_phase_checkpoint.py` and `test_two_phase_checkpoint.py`.
