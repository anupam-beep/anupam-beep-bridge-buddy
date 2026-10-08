# BridgeAgent — read-only evidence handoff (offline candidate)

## Purpose

Bind a captured Civil NX post-processing request and result to (1) a model digest,
(2) explicit analysis authorization, (3) a signed analysis-completion record,
(4) exact request and response bytes, (5) a signed capture receipt, and
(6) an independently pinned, signed registry checkpoint that includes the receipt.

**No Civil NX calls or model writes are implemented.** This is a candidate
verification skill, not production integration or engineering certification.

## Inputs and trust boundaries

`verify_handoff` receives an in-memory metadata-only manifest, model/request/response
bytes, the evidence envelope, signed analysis attestation, signed capture receipt,
read-only access to the existing local replay registry, and a signed checkpoint
anchor plus its **separately maintained** trust policy. The caller must obtain
signing keys and high-water checkpoint pins from trusted channels independent of
the submitted evidence. A source label alone cannot prove that independence.

The manifest has an exact allowlist of fields: schema/domain, capture/run IDs,
SHA-256 hashes of the model/request/response, signed receipt hash, and checkpoint.
It contains no raw HTTP bytes, authorization secrets, private keys, or results.

The gate refuses empty or malformed numerical results, altered request bytes,
invalid signatures, untrusted anchors, rollback, missing capture inclusion, or
metadata mismatches. Its success status is deliberately
`OFFLINE_HANDOFF_CONSISTENT_NOT_LIVE`; `engineering_accepted` and `live_verified`
remain false. A synthetic success must not be promoted to operational readiness.

## Evidence extraction blocker

The preserved `HTTP 200` / `{ "message": "" }` probe remains incomplete. No
authentic signed analysis-completion record, trusted independent capture witness,
or numerical `POST /post/TABLE` response is present. This module cannot infer
that the analysis completed or that results exist. A read-only capture in an
explicitly authorized environment would be required for an integration test.

## Run

From this extracted folder, with Python and `cryptography` available:

`python -m unittest discover -v`

Tests generate temporary signing keys and temporary SQLite databases and use
synthetic Civil NX-shaped payloads. They do not connect to MIDAS.

## Safety

No live-model PUT, ANALYZE, SAVE, uncontrolled production modification,
production promotion, or engineering approval. Raw HTTP request bytes may contain
credentials: never persist them to reports or the manifest. Run the verifier
only on trusted local memory copies, and redact credentials before any sharing.
