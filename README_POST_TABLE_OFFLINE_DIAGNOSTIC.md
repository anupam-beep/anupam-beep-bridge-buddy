# BridgeAgent — Civil NX result-extraction offline diagnostic (candidate only)

**Scope:** Offline review of synthetic or sanitized evidence; no network, no MIDAS Civil NX connection, no API key, no analysis, no model write/save, no engineering approval. `POST /post/TABLE` is a *result-query endpoint* but its HTTP method is POST. Do not equate HTTP method with permission to run it live. This package does not issue requests.

## Evidence actually available

The inherited cycle reports describe an earlier HTTP 200 response with `{"message":""}` and incomplete/empty result probes. The inherited offline packages do **not** contain independently authenticated evidence of a completed analysis, verified original request/response bytes, or an authentic numerical `POST/TABLE` response. Therefore **root cause is not established**. No claim of real-world extraction success is justified.

## Newly researched public documentation (consulted; not promoted to an approved manual)

1. MIDAS Support, *Designing with Intent: The Vision Behind POST/TABLE* (edited 2026-07-30): https://support.midasuser.com/hc/en-us/articles/45171987915929-Designing-with-Intent-The-Vision-Behind-POST-TABLE
   - `TABLE_TYPE` is required; `TABLE_NAME` optional. If no table name is specified, the response may use the key **`empty`**. Thus an `empty` **wrapper key** is not equivalent to an empty result.
   - `HEAD`/`DATA` contain tabular content; selector keys `LOAD_CASE_NAMES`, `NODE_ELEMS`, `PARTS` may limit results.
   - Load cases need appropriate suffixes (`(ST)`, `(CB)` / `(CB:max)`, `(MV:max)`, etc.); construction-stage queries may require `OPT_CS: true` and appropriate `STAGE_STEP`.
   - `EXPORT_PATH` causes server-side export and must not be used in the safe diagnostic plan.
2. MIDAS Support, *MIDAS API Online Manual* (edited 2026-07-14): https://support.midasuser.com/hc/en-us/articles/33016922742937-MIDAS-API-Online-Manual
   - Consult table-specific schema for exact enum and supported selectors; request envelope is `{"Argument": {...}}`.
3. MIDAS R&D Python documentation, *Result Table*: https://midas-rnd.github.io/midasapi-python/Result/02_resultTable/
   - Documents `REACTIONG`, `DISPLACEMENTG`, `BEAMFORCE`, `BEAMSTRESS` and load-case/element selection as illustrative table families. **Do not assume a particular table is available for a particular model without verification.**

## Fail-closed evidence matrix

| Gate | Evidence required | Status here | Meaning if absent |
|---|---|---|---|
| E1 Model identity | independently verified active model fingerprint, NX version | Missing | Cannot associate results with intended model |
| E2 Analysis | independently authenticated completed-run evidence and timestamp | Missing | Analysis may be absent, failed, or still running |
| E3 Request | exact original request bytes/hash and endpoint, with separately protected secrets | Missing | Cannot prove `Argument`, `TABLE_TYPE`, case/element filters |
| E4 Response | exact original status/response bytes/hash; `HEAD`/`DATA` numeric rows | Missing | HTTP 200 or message alone does not establish result |
| E5 Capture | signed independent collector receipt tied to E1–E4 | Missing | Locally supplied data could be fabricated |
| E6 Anchor | independently pinned anti-rollback checkpoint and registry proof | Missing | Evidence history not independently trustworthy |
| E7 Engineering | independent reactions/force equilibrium and units/combination check | Not started | Numerical extraction cannot be engineering acceptance |

**Gate order:** E1 → E2 → E3 → E4 → E5 → E6 → E7. A failed or missing earlier gate blocks downstream certification; do not infer that missing E2 *caused* missing E4.

## Diagnostic decision tree — offline first

1. Classify sanitized recorded HTTP status and response *shape*. `{"message":""}` is **incomplete**; `{"empty":{"HEAD":[...],"DATA":[...]}}` may contain actual data. `{"error":...}` or a failure message blocks acceptance even if HTTP status is 200.
2. Inspect the recorded request (without secrets): check `POST /post/TABLE`, top-level `Argument`, valid `TABLE_TYPE` per table-specific manual. The checker flags `EXPORT_PATH` because it is not suitable for the planned non-destructive read-only probe.
3. Review `LOAD_CASE_NAMES` suffixes, exact names, `NODE_ELEMS` IDs and `PARTS` against an independently verified model inventory. Empty filters may request all, depending on table; a nonempty mismatched filter may yield zero rows. Do not change model state or selectors automatically.
4. For construction-stage results, verify `OPT_CS` and `STAGE_STEP` semantics and ensure the analysis actually generated requested stage data.
5. If a numeric table shape is found, preserve original-byte hashes, complete provenance, trusted witness and independent checkpoint. Then run separate numerical sanity checks; **never auto-certify**.
6. If missing evidence persists, mark `RESULT INCOMPLETE — STOP`; do not rerun analysis or mutate model to resolve it.

**Competing hypotheses (unverified):** incomplete/failed analysis; incorrect table enum; wrong load case suffix/name; wrong node/element selector; construction-stage state mismatch; API/relay response interpretation; insufficient captured bytes. These are investigation branches, **not a diagnosis of the live model**.

## Offline usage

Run from the extracted folder:

```sh
python -m unittest discover -q
python -m offline_post_table_diagnostic synthetic_post_table_fixture.json
```

The fixture is synthetic and contains no credentials. The diagnostic prints **reason codes only**, not request/response content. Exit code 0 means only that numeric table *shape* exists, not that the results are authentic, complete or acceptable. Exit code 2 means incomplete/rejected evidence. Inputs are limited to 512 kB, bounded JSON depth, and a fixed top-level allowlist. Do not supply unredacted captures.

## Next approved-live-evidence checkpoint (not executed)

A future operator-approved read-only probe must first confirm the active model and completed analysis using independently authorized evidence, then make **only explicitly approved** result queries, without `EXPORT_PATH` and without analysis/save/model modification. Exact capture, witness, credential redaction and audit arrangements require separate security review. No live commands or credentials are included in this package.

## Candidate certification

`OFFLINE_TESTED_NOT_DEPLOYED`. The code detects response shapes and request inconsistencies, but cannot prove the root cause, actual network transmission, independent capture provenance, numerical validity or structural safety. Production deployment and any engineering acceptance remain blocked.
