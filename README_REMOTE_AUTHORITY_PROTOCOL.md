# BridgeAgent offline remote-authority protocol candidate

Status: **OFFLINE_TESTED_NOT_DEPLOYED**. This is an in-process *wire-protocol simulation*, not a remotely hosted service, not TLS, not a genuine independent trust authority, and not a Civil NX integration. It changes no production files and has no live-model operations.

## Implemented in this cycle

- `encode_frame` / `decode_frame`: deterministic JSON byte frames with protocol version, content type, exact body length and SHA-256 integrity; strict duplicate-key and malformed JSON rejection, payload size limit, canonical body enforcement.
- `OfflineWireServer` / `OfflineWireAdapter`: serialized request/response boundary wrapping the existing authenticated durable checkpoint server. Existing Ed25519 request/response signatures and request ID binding remain enforced by the underlying client/server.
- `verify_independent_witness`: signed authority-specific checkpoint witness, with audience/store/client binding, UTC validity interval, checkpoint schema and **exact independently pinned fingerprint**. It produces a checkpoint for the existing high-water rollback guard only if all checks pass.
- Bridge Dojo: adversarial fixtures for malformed frames, integrity mismatches, protocol downgrade, signature/key failures, expired/forged witnesses, rollback of the simulated store, and ordinary prepare/commit over the serialized boundary.

## Important trust limits

1. No socket, network request, remote deployment, mutual TLS, certificate rotation, HSM, independent operator, or out-of-band pin distribution exists in this candidate.
2. The test fixture computes its own witness fingerprint to exercise verification logic; **that is not an independently obtained real-world pin**. In production, the pinned fingerprint must arrive from a separately controlled authenticated channel and be persisted outside the local checkpoint store.
3. A signed checkpoint or a valid wire response does not establish that Civil NX ran an analysis, that POST/TABLE returned authentic numerical data, or that engineering results are correct.
4. Existing durable-store tests and offline result gates are regression-tested; this package is not installed into the user's BridgeAgent repository.

## Execute offline tests

`python -m unittest discover -v` in this extracted directory (requires `cryptography`).

## Civil NX blocker

No authentic completed-analysis evidence or numerical `POST/TABLE` response was available in the reviewed offline artifact. Existing preserved empty-result evidence remains an unresolved blocker. A real analysis-run-to-response binding requires an approved read-only capture with trusted evidence, not an assumption from a successful HTTP status.

## Single next priority

Create a read-only **capture-evidence handoff specification and synthetic fixture generator** that links authenticated analysis completion, exact request/response bytes, and the independently anchored checkpoint; continue without making any Civil NX calls.
