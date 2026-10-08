"""Offline E1-E6 evidence cross-reference gate for BridgeAgent.

This is an *additional* fail-closed check over the existing evidence inventory,
independent signed receipt, handoff, and externally pinned registry verifier.
It never performs network calls, Civil NX operations, writes, signing, or
engineering certification. The caller supplies all evidence and trust anchors.

IMPORTANT: A matching digest and even a valid synthetic signature are NOT proof
of genuine Civil NX execution or an independently administered trust authority.
Original HTTP request/response bytes may contain credentials; they are hashed
in memory but never emitted or logged by this module.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from pathlib import Path
from typing import Any

from offline_evidence_inventory import inventory, load_claims
from offline_evidence_handoff import verify_handoff
from offline_result_certifier import canonical_bytes

REQUIRED_GATES = ('E1', 'E2', 'E3', 'E4', 'E5', 'E6')
STATUS_PASS = 'OFFLINE_E1_E6_CHAIN_CONSISTENT_NOT_LIVE'


def _hold(reasons: list[str], *, inventory_status: str = 'NOT_RUN',
          handoff_status: str = 'NOT_RUN') -> dict:
    return {'status': 'HOLD', 'reasons': sorted(set(reasons)),
            'inventory_status': inventory_status, 'handoff_status': handoff_status,
            'verified_gate_count': 0, 'live_verified': False,
            'result_extraction_verified': False, 'engineering_accepted': False,
            'civil_nx_contacted': False}


def _signed_digest(record: dict, signature_hex: str) -> str:
    if not isinstance(record, dict) or not isinstance(signature_hex, str):
        raise ValueError('invalid signed record')
    sig = bytes.fromhex(signature_hex)
    if len(sig) != 64:
        raise ValueError('invalid signature length')
    return hashlib.sha256(canonical_bytes(record) + sig).hexdigest()


def verify_evidence_cross_reference(*, claims_raw: bytes, artifact_root: str | Path,
                                    manifest: dict, envelope: dict, model_bytes: bytes,
                                    raw_request: bytes, response_bytes: bytes,
                                    analysis_attestation: dict,
                                    analysis_signature_hex: str,
                                    pinned_analysis_public_key: bytes,
                                    receipt: dict, receipt_signature_hex: str,
                                    pinned_collector_id: str,
                                    pinned_capture_public_key: bytes,
                                    registry: Any, anchor: dict,
                                    anchor_signature_hex: str,
                                    independent_policy: dict,
                                    trusted_now: datetime) -> dict:
    """Require exactly one byte-matched artifact for E1-E6 and signed handoff.

    E1 model bytes; E2 signed analysis attestation; E3 original request;
    E4 original response; E5 signed capture receipt; E6 signed checkpoint.
    E7 (independent engineering review) is intentionally outside this gate.

    Evidence files are never read back into memory for handoff; the existing
    bounded inventory hashes each file and compares to its claimed digest.
    Supplied in-memory bytes must independently match the corresponding claims.
    This reduces substitution but does not prove network transmission.
    """
    reasons: list[str] = []
    try:
        # Fail before hashing filesystem artifacts if types or trust identity
        # are ambiguous. No trust keys may originate from the claims manifest.
        if any(type(v) is not bytes for v in (model_bytes, raw_request, response_bytes)):
            return _hold(['EVIDENCE_BYTES_TYPE_INVALID'])
        if not isinstance(receipt, dict) or not isinstance(manifest, dict):
            return _hold(['RECEIPT_OR_HANDOFF_INVALID'])
        if not isinstance(independent_policy, dict):
            return _hold(['INDEPENDENT_TRUST_POLICY_REQUIRED'])
        anchor_pub = independent_policy.get('pinned_public_key')
        pubs = (pinned_analysis_public_key, pinned_capture_public_key, anchor_pub)
        if any(type(p) is not bytes or len(p) != 32 for p in pubs):
            return _hold(['INDEPENDENT_TRUST_KEYS_REQUIRED'])
        if (hmac.compare_digest(pubs[0], pubs[1]) or
                hmac.compare_digest(pubs[0], pubs[2]) or
                hmac.compare_digest(pubs[1], pubs[2])):
            return _hold(['TRUST_ROLES_NOT_KEY_SEPARATED'])

        claims = load_claims(claims_raw)
        if (claims['capture_id'] != receipt.get('capture_id') or
                claims['capture_id'] != manifest.get('capture_id')):
            reasons.append('CAPTURE_ID_CROSS_REFERENCE_MISMATCH')

        expected = {
            'E1': hashlib.sha256(model_bytes).hexdigest(),
            'E2': _signed_digest(analysis_attestation, analysis_signature_hex),
            'E3': hashlib.sha256(raw_request).hexdigest(),
            'E4': hashlib.sha256(response_bytes).hexdigest(),
            'E5': _signed_digest(receipt, receipt_signature_hex),
            'E6': _signed_digest(anchor, anchor_signature_hex),
        }
        for gate in REQUIRED_GATES:
            matching_claims = [a for a in claims['artifacts'] if a['gate'] == gate]
            if len(matching_claims) != 1:
                reasons.append('GATE_CARDINALITY_INVALID:' + gate)
            elif not hmac.compare_digest(matching_claims[0]['sha256'], expected[gate]):
                reasons.append('GATE_BYTES_BINDING_MISMATCH:' + gate)

        if reasons:
            return _hold(reasons)

        observed = inventory(artifact_root, claims)
        for gate in REQUIRED_GATES:
            g = observed['gate_inventory'][gate]
            if g['status'] != 'PRESENT_HASH_MATCH_UNAUTHENTICATED' or g['matched_hashes'] != 1:
                reasons.append('INVENTORY_GATE_UNVERIFIED:' + gate)
        if reasons:
            return _hold(reasons, inventory_status=observed['status'])

        handoff = verify_handoff(
            manifest=manifest, envelope=envelope, model_bytes=model_bytes,
            raw_request=raw_request, response_bytes=response_bytes,
            analysis_attestation=analysis_attestation,
            analysis_signature_hex=analysis_signature_hex,
            pinned_analysis_public_key=pinned_analysis_public_key,
            receipt=receipt, receipt_signature_hex=receipt_signature_hex,
            pinned_collector_id=pinned_collector_id,
            pinned_capture_public_key=pinned_capture_public_key,
            registry=registry, anchor=anchor,
            anchor_signature_hex=anchor_signature_hex,
            independent_policy=independent_policy, trusted_now=trusted_now,
        )
        if handoff.get('status') != 'OFFLINE_HANDOFF_CONSISTENT_NOT_LIVE':
            # Existing verifier returns fixed reason codes; do not propagate
            # arbitrary messages from untrusted artifacts or exceptions.
            return _hold(['HANDOFF_OR_ANCHOR_HOLD'],
                         inventory_status=observed['status'],
                         handoff_status='HOLD')
        return {
            'status': STATUS_PASS, 'reasons': [],
            'inventory_status': observed['status'],
            'handoff_status': handoff['status'],
            'verified_gate_count': len(REQUIRED_GATES),
            'live_verified': False, 'result_extraction_verified': False,
            'engineering_accepted': False, 'civil_nx_contacted': False,
            'note_code': 'SYNTHETIC_OFFLINE_CONSISTENCY_IS_NOT_AUTHENTIC_EXECUTION',
        }
    except Exception:
        # Fail closed and never emit exception messages, paths, capture IDs,
        # filenames, keys or sensitive original HTTP bytes.
        return _hold(['CROSS_REFERENCE_INPUT_OR_IO_REJECTED'])
