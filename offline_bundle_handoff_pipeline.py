"""Fail-closed sanitized-ZIP intake -> independent offline evidence-handoff gate.

No network, model writes, analysis, result retrieval, or engineering acceptance.
This adapter does NOT convert sanitized bytes into evidence of real transmitted bytes.
The caller MUST independently supply the handoff manifest, trusted public keys,
registry and externally anchored checkpoint policy. Never obtain trust pins from ZIP.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from offline_capture_bundle_intake import (
    _load_validated_bundle_for_handoff, _safe_json, IntakeFailure,
)
from offline_evidence_handoff import verify_handoff

SIG = re.compile(r'^[a-f0-9]{128}$')


def _hold(reason: str, *, intake_status: str = 'NOT_RUN') -> dict:
    return {'status': 'HOLD', 'reasons': [reason], 'intake_status': intake_status,
            'handoff_status': 'NOT_RUN', 'live_verified': False,
            'engineering_accepted': False, 'civil_nx_contacted': False}


def _signed_record(raw: bytes, name: str) -> tuple[dict, str]:
    # ZIP has already passed bounded, strict JSON and credential checks.
    obj = _safe_json(raw)
    if not isinstance(obj, dict) or set(obj) != {'record', 'signature_hex'}:
        raise IntakeFailure(name + '_WRAPPER_INVALID')
    if not isinstance(obj['record'], dict):
        raise IntakeFailure(name + '_RECORD_INVALID')
    signature = obj['signature_hex']
    if not isinstance(signature, str) or not SIG.fullmatch(signature):
        raise IntakeFailure(name + '_SIGNATURE_FORMAT_INVALID')
    return obj['record'], signature


def verify_sanitized_bundle_handoff(
    *, bundle_path: str | Path, trusted_handoff_manifest: Any,
    envelope: dict, model_bytes: bytes, registry,
    pinned_analysis_public_key: bytes, pinned_collector_id: str,
    pinned_capture_public_key: bytes, independent_policy: dict,
    trusted_now: datetime,
) -> dict:
    """Offline consistency only. No evidence from ZIP is allowed to define trust pins.

    A trusted_handoff_manifest is REQUIRED from a separate trusted channel; its
    provenance cannot be established by this code. Never log the ZIP members.
    """
    if not isinstance(trusted_handoff_manifest, dict):
        return _hold('INDEPENDENT_HANDOFF_MANIFEST_REQUIRED')
    try:
        intake, blobs = _load_validated_bundle_for_handoff(bundle_path)
        if blobs is None:
            return _hold('INTAKE_' + intake.get('reason', 'REJECT'),
                         intake_status='REJECT')
        att, att_sig = _signed_record(blobs['analysis_attestation.json'], 'ANALYSIS')
        receipt, receipt_sig = _signed_record(blobs['capture_receipt.json'], 'CAPTURE')
        anchor, anchor_sig = _signed_record(blobs['checkpoint_anchor.json'], 'ANCHOR')
        handoff = verify_handoff(
            manifest=trusted_handoff_manifest, envelope=envelope,
            model_bytes=model_bytes, raw_request=blobs['request.bin'],
            response_bytes=blobs['response.json'],
            analysis_attestation=att, analysis_signature_hex=att_sig,
            pinned_analysis_public_key=pinned_analysis_public_key,
            receipt=receipt, receipt_signature_hex=receipt_sig,
            pinned_collector_id=pinned_collector_id,
            pinned_capture_public_key=pinned_capture_public_key,
            registry=registry, anchor=anchor, anchor_signature_hex=anchor_sig,
            independent_policy=independent_policy, trusted_now=trusted_now,
        )
        return {
            'status': ('OFFLINE_PIPELINE_CONSISTENT_NOT_LIVE' if
                       handoff['status'] == 'OFFLINE_HANDOFF_CONSISTENT_NOT_LIVE' else 'HOLD'),
            'reasons': list(handoff['reasons']),
            'intake_status': intake['status'],
            'handoff_status': handoff['status'],
            'live_verified': False, 'engineering_accepted': False,
            'civil_nx_contacted': False,
        }
    except (IntakeFailure, KeyError, ValueError, TypeError, AttributeError,
            OverflowError, RecursionError, json.JSONDecodeError) as exc:
        # Never include exception messages: they might contain evidence fragments.
        reason = str(exc) if isinstance(exc, IntakeFailure) else 'INVALID_EVIDENCE_OR_TRUST_INPUT'
        return _hold(reason, intake_status='REJECT' if isinstance(exc, IntakeFailure) else 'UNKNOWN')
