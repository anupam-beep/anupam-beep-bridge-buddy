"""BridgeAgent offline result-quality + provenance gate. NO NETWORK/FILE WRITES.

All PASS decisions are offline structural/provenance checks, not engineering acceptance.
Response layout based on MIDAS official Displacements - Analysis Result Table:
{TABLE_NAME: {HEAD: [column names], DATA: [[cell,...], ...]}}.
"""
from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime
from typing import Any


class DuplicateJSONKey(ValueError):
    pass


def _unique_pairs(pairs):
    out = {}
    for key, val in pairs:
        if key in out:
            raise DuplicateJSONKey(key)
        out[key] = val
    return out


def _reject_constant(value):
    raise ValueError('NON_FINITE_JSON_CONSTANT:' + value)


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _time(s):
    if not isinstance(s, str) or not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        return dt if dt.tzinfo is not None and dt.utcoffset() is not None else None
    except ValueError:
        return None


def _is_finite_number(value):
    if isinstance(value, bool) or value is None:
        return False
    try:
        return math.isfinite(float(value)) and str(value).strip() != ''
    except (ValueError, TypeError, OverflowError):
        return False


def inspect_table(raw: bytes, *, expected_node: int, expected_load: str,
                  expected_numeric=('DX', 'DY', 'DZ'), require_cs=True):
    reasons = []
    try:
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs,
                         parse_constant=_reject_constant)
    except (UnicodeError, ValueError, TypeError) as exc:
        return {'status': 'HOLD', 'reasons': ['INVALID_JSON:' + type(exc).__name__], 'row_count': 0}
    if not isinstance(doc, dict):
        return {'status': 'HOLD', 'reasons': ['RESPONSE_NOT_OBJECT'], 'row_count': 0}
    if 'error' in doc:
        return {'status': 'HOLD', 'reasons': ['API_ERROR_PRESENT'], 'row_count': 0}
    if not doc or (set(doc) == {'message'} and not doc['message']):
        return {'status': 'HOLD', 'reasons': ['EMPTY_OR_MESSAGE_ONLY'], 'row_count': 0}

    # Official response: table name is arbitrary; identify HEAD/DATA by shape.
    candidates = []
    if 'HEAD' in doc or 'DATA' in doc:
        candidates.append(('direct', doc))
    for key, value in doc.items():
        if isinstance(value, dict) and ('HEAD' in value or 'DATA' in value):
            candidates.append((key, value))
    if len(candidates) != 1:
        return {'status': 'HOLD', 'reasons': ['TABLE_CONTAINER_MISSING_OR_AMBIGUOUS'], 'row_count': 0}
    table_name, table = candidates[0]
    head, rows = table.get('HEAD'), table.get('DATA')
    if not isinstance(head, list) or not head or any(not isinstance(h, str) or not h for h in head) or len(head) != len(set(head)):
        reasons.append('INVALID_HEAD')
    if not isinstance(rows, list) or not rows:
        reasons.append('EMPTY_OR_INVALID_DATA')
    if reasons:
        return {'status': 'HOLD', 'reasons': reasons, 'row_count': 0}
    required = {'Node', 'Load', *expected_numeric}
    if require_cs:
        required.update({'Stage', 'Step'})
    missing = sorted(required.difference(head))
    if missing:
        return {'status': 'HOLD', 'reasons': ['MISSING_COLUMNS:' + ','.join(missing)], 'row_count': len(rows)}
    idx = {name: pos for pos, name in enumerate(head)}
    for n, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != len(head):
            reasons.append(f'ROW_WIDTH_OR_TYPE:{n}')
            continue
        try:
            node_matches = int(str(row[idx['Node']])) == expected_node
        except (ValueError, TypeError):
            node_matches = False
        if not node_matches:
            reasons.append(f'NODE_SELECTOR_MISMATCH:{n}')
        # API examples render Summation(CS) as Summation in the Load column.
        load_alias = expected_load[:-4] if expected_load.endswith('(CS)') else expected_load
        if row[idx['Load']] not in {expected_load, load_alias}:
            reasons.append(f'LOAD_SELECTOR_MISMATCH:{n}')
        if require_cs and (not isinstance(row[idx['Stage']], str) or not row[idx['Stage']].strip() or
                           not isinstance(row[idx['Step']], str) or not row[idx['Step']].strip()):
            reasons.append(f'CS_STAGE_STEP_MISSING:{n}')
        for name in expected_numeric:
            if not _is_finite_number(row[idx[name]]):
                reasons.append(f'NONFINITE_OR_MISSING_{name}:{n}')
    return {'status': 'STRUCTURAL_PASS' if not reasons else 'HOLD',
            'reasons': reasons, 'row_count': len(rows), 'table_name': table_name}


def certify(envelope: dict, model_bytes: bytes, response_bytes: bytes) -> dict:
    """Fail closed. No calls to Civil NX; only compares supplied bytes and metadata."""
    reasons = []
    selector = envelope.get('result_request', {}).get('selector', {})
    result_request = envelope.get('result_request', {})
    model = envelope.get('model_evidence', {})
    auth = envelope.get('authorization', {})
    analysis = envelope.get('analysis', {})
    result = envelope.get('result_response', {})
    binding = envelope.get('binding', {})
    if envelope.get('execution_enabled') is not False:
        reasons.append('EXECUTION_NOT_LOCKED')
    if envelope.get('certification', {}).get('engineering_acceptance') is not False:
        reasons.append('ENGINEERING_ACCEPTANCE_NOT_LOCKED')
    if model.get('sha256') != digest(model_bytes):
        reasons.append('MODEL_HASH_MISMATCH')
    if not auth.get('authorization_id') or auth.get('scope') != 'analysis/read-only-results':
        reasons.append('AUTHORIZATION_UNVERIFIED')
    if analysis.get('status') != 'COMPLETED' or not analysis.get('run_id'):
        reasons.append('ANALYSIS_COMPLETION_UNVERIFIED')
    if not (binding.get('model_sha256') == model.get('sha256') and
            binding.get('analysis_run_id') == analysis.get('run_id') and
            binding.get('authorization_id') == auth.get('authorization_id') and
            binding.get('result_analysis_run_id') == analysis.get('run_id')):
        reasons.append('PROVENANCE_BINDING_MISMATCH')
    if result_request.get('method') != 'POST' or result_request.get('path', '').lower() != '/post/table':
        reasons.append('REQUEST_METHOD_PATH_MISMATCH')
    if result_request.get('selector_sha256') != digest(canonical_bytes(selector)):
        reasons.append('SELECTOR_HASH_MISMATCH')
    if result.get('raw_payload_sha256') != digest(response_bytes):
        reasons.append('RESPONSE_HASH_MISMATCH')
    start = _time(analysis.get('started_at'))
    complete = _time(analysis.get('completed_at'))
    captured = _time(result.get('captured_at'))
    model_at = _time(model.get('captured_at'))
    if None in (start, complete, captured, model_at):
        reasons.append('TIMESTAMP_INVALID_OR_UNZONED')
    elif not (model_at <= start <= complete <= captured):
        reasons.append('TIMESTAMP_ORDER_INVALID')
    if (selector.get('TABLE_TYPE') != 'DISPLACEMENTG' or selector.get('OPT_CS') is not True or
            selector.get('LOAD_CASE_NAMES') != ['Summation(CS)'] or
            selector.get('STAGE_STEP') != [] or
            selector.get('NODE_ELEMS', {}).get('KEYS') != [15]):
        reasons.append('UNEXPECTED_SELECTOR')
    quality = inspect_table(response_bytes, expected_node=15, expected_load='Summation(CS)')
    if quality['status'] != 'STRUCTURAL_PASS':
        reasons.extend('RESPONSE_' + x for x in quality['reasons'])
    return {'status': 'OFFLINE_GATES_PASS' if not reasons else 'HOLD',
            'reasons': reasons, 'quality': quality,
            'engineering_accepted': False, 'live_verified': False}
