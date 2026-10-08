"""Read-only, offline evidence-handoff verifier for BridgeAgent.

No network, filesystem writes, Civil NX access, engineering decisions or credential
logging. Raw HTTP bytes are supplied in memory by the caller and never returned.
Trust policy and pinned keys MUST be obtained independently; passing them from a
self-described handoff cannot establish independence.
"""
from __future__ import annotations

import hmac
import re
from datetime import datetime
from typing import Any

from independent_capture_receipt import verify_with_capture
from independent_checkpoint_anchor import verify_anchored_registry
from offline_result_certifier import canonical_bytes, digest

DOMAIN = 'BridgeAgent:read-only-evidence-handoff:v1'
FIELDS = frozenset({'schema_version', 'domain', 'capture_id', 'analysis_run_id',
                    'model_sha256', 'raw_request_sha256', 'raw_response_sha256',
                    'signed_receipt_sha256', 'checkpoint'})
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def handoff_manifest(*, envelope: dict, raw_request: bytes, response_bytes: bytes,
                     receipt: dict, receipt_signature_hex: str, checkpoint: dict) -> dict:
    """Build metadata-only manifest. This does NOT verify authenticity or accept evidence."""
    return {
        'schema_version': 1, 'domain': DOMAIN,
        'capture_id': receipt['capture_id'],
        'analysis_run_id': envelope['analysis']['run_id'],
        'model_sha256': envelope['model_evidence']['sha256'],
        'raw_request_sha256': digest(raw_request),
        'raw_response_sha256': digest(response_bytes),
        'signed_receipt_sha256': digest(canonical_bytes(receipt) + bytes.fromhex(receipt_signature_hex)),
        'checkpoint': dict(checkpoint),
    }


def verify_handoff(*, manifest: Any, envelope: dict, model_bytes: bytes,
                   raw_request: bytes, response_bytes: bytes, analysis_attestation: dict,
                   analysis_signature_hex: str, pinned_analysis_public_key: bytes,
                   receipt: dict, receipt_signature_hex: str, pinned_collector_id: str,
                   pinned_capture_public_key: bytes, registry, anchor: dict,
                   anchor_signature_hex: str, independent_policy: dict,
                   trusted_now: datetime) -> dict:
    """Fail closed across capture/provenance, independently pinned anchor and DB inclusion.

    Status never says that the real API ran or that results are engineer-approved.
    """
    reasons: list[str] = []
    if not isinstance(manifest, dict) or set(manifest) != FIELDS:
        return {'status': 'HOLD', 'reasons': ['HANDOFF_SCHEMA_INVALID'],
                'live_verified': False, 'engineering_accepted': False}
    if type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1 or manifest.get('domain') != DOMAIN:
        reasons.append('HANDOFF_VERSION_OR_DOMAIN_INVALID')
    for field in ('model_sha256', 'raw_request_sha256', 'raw_response_sha256', 'signed_receipt_sha256'):
        if not isinstance(manifest.get(field), str) or not HEX64.fullmatch(manifest[field]):
            reasons.append('HANDOFF_DIGEST_INVALID:' + field)
    try:
        expected = handoff_manifest(envelope=envelope, raw_request=raw_request,
                                    response_bytes=response_bytes, receipt=receipt,
                                    receipt_signature_hex=receipt_signature_hex,
                                    checkpoint=anchor['checkpoint'])
        for field in FIELDS - {'schema_version', 'domain'}:
            if manifest.get(field) != expected[field]:
                reasons.append('HANDOFF_BINDING_MISMATCH:' + field)
    except (ValueError, TypeError, KeyError, AttributeError):
        reasons.append('HANDOFF_INPUT_INVALID')

    capture = verify_with_capture(
        envelope, model_bytes, response_bytes, raw_request,
        analysis_attestation, analysis_signature_hex, pinned_analysis_public_key,
        receipt, receipt_signature_hex, pinned_collector_id,
        pinned_capture_public_key,
    )
    if capture['status'] != 'OFFLINE_EVIDENCE_GATES_PASS':
        reasons.append('CAPTURE_AND_PROVENANCE_HOLD')
        reasons.extend(capture['reasons'])

    anchor_check = verify_anchored_registry(
        registry, anchor, anchor_signature_hex, independent_policy, now=trusted_now)
    if anchor_check['status'] != 'OFFLINE_ANCHOR_MATCH':
        reasons.append('INDEPENDENT_ANCHOR_HOLD')
        reasons.extend(anchor_check['reasons'])

    # Never trust local DB inclusion until independent high-water anchor passes.
    if not reasons:
        try:
            row = registry.db.execute('''SELECT collector_id,receipt_sha256,raw_request_sha256,
                 raw_response_sha256,model_sha256,analysis_run_id FROM entries
                 WHERE capture_id=?''', (manifest['capture_id'],)).fetchone()
            expected_row = (
                receipt['collector_id'], manifest['signed_receipt_sha256'],
                manifest['raw_request_sha256'], manifest['raw_response_sha256'],
                manifest['model_sha256'], manifest['analysis_run_id'],
            )
            if row is None or len(row) != len(expected_row) or any(
                not isinstance(a, str) or not isinstance(b, str) or not hmac.compare_digest(a, b)
                for a, b in zip(row, expected_row)
            ):
                reasons.append('ANCHORED_REGISTRY_CAPTURE_INCLUSION_MISMATCH')
        except Exception:
            reasons.append('ANCHORED_REGISTRY_READ_FAILED')

    return {
        'status': 'OFFLINE_HANDOFF_CONSISTENT_NOT_LIVE' if not reasons else 'HOLD',
        'reasons': reasons,
        'capture_gate': capture['status'],
        'anchor_gate': anchor_check['status'],
        'live_verified': False, 'engineering_accepted': False,
        'note': 'An in-process synthetic PASS is not proof of actual Civil NX analysis or independent trust hosting.',
    }
