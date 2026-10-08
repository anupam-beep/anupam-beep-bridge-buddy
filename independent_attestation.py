"""Offline-only evidence verification for BridgeAgent.

No network, model writes, analysis, credential persistence, or key generation.
Trusted Ed25519 public key is passed independently by the verifier; NEVER load
it from an untrusted result envelope or its self-described signer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from offline_result_certifier import canonical_bytes, certify, digest, _unique_pairs, _reject_constant


def _utc(s: Any):
    if not isinstance(s, str):
        return None
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        if dt.tzinfo is None or dt.utcoffset() is None:
            return None
        return dt
    except ValueError:
        return None


def verify_attestation(envelope: dict, attestation: dict, signature_hex: str,
                       trusted_public_key_bytes: bytes) -> dict:
    """Require out-of-band pinned trust anchor and signature over exact canonical record."""
    reasons = []
    if not isinstance(attestation, dict):
        return {'status':'HOLD','reasons':['ATTESTATION_NOT_OBJECT']}
    expected = {
        'schema_version': 1,
        'event': 'CIVIL_NX_ANALYSIS_COMPLETED',
        'model_sha256': envelope.get('model_evidence',{}).get('sha256'),
        'authorization_id': envelope.get('authorization',{}).get('authorization_id'),
        'run_id': envelope.get('analysis',{}).get('run_id'),
        'started_at': envelope.get('analysis',{}).get('started_at'),
        'completed_at': envelope.get('analysis',{}).get('completed_at'),
        'status': 'COMPLETED',
    }
    if set(attestation) != set(expected) or attestation != expected:
        reasons.append('ATTESTATION_CONTENT_MISMATCH')
    start, finish = _utc(attestation.get('started_at')), _utc(attestation.get('completed_at'))
    if not start or not finish or finish < start:
        reasons.append('ATTESTATION_TIMESTAMPS_INVALID')
    if not isinstance(trusted_public_key_bytes, bytes) or len(trusted_public_key_bytes) != 32:
        reasons.append('TRUST_ANCHOR_NOT_PINNED')
    else:
        try:
            signature = bytes.fromhex(signature_hex)
            if len(signature) != 64:
                raise ValueError('invalid signature length')
            key = Ed25519PublicKey.from_public_bytes(trusted_public_key_bytes)
            key.verify(signature, canonical_bytes(attestation))
        except (InvalidSignature, ValueError, TypeError):
            reasons.append('ATTESTATION_SIGNATURE_INVALID')
    return {'status':'OFFLINE_SIGNATURE_VALID' if not reasons else 'HOLD', 'reasons':reasons}


def verify_http_request_bytes(raw_request: bytes, envelope: dict) -> dict:
    """Check exact HTTP/1.1 bytes without persisting credentials or parsing network traffic.

    This is a *byte capture* integrity check, not proof the request was sent.
    """
    reasons=[]
    if not isinstance(raw_request, bytes):
        return {'status':'HOLD','reasons':['REQUEST_NOT_BYTES']}
    try:
        header_blob, body = raw_request.split(b'\r\n\r\n', 1)
        lines=header_blob.split(b'\r\n')
        if lines[0] != b'POST /post/TABLE HTTP/1.1':
            reasons.append('REQUEST_LINE_UNEXPECTED')
        headers={}
        for line in lines[1:]:
            if b':' not in line:
                reasons.append('MALFORMED_HEADER'); continue
            k,v=line.split(b':',1)
            name=k.strip().lower()
            if not name or name in headers:
                reasons.append('DUPLICATE_OR_EMPTY_HEADER')
            headers[name]=v.strip()
        if headers.get(b'content-type', b'').split(b';')[0].lower()!=b'application/json':
            reasons.append('CONTENT_TYPE_UNEXPECTED')
        if b'transfer-encoding' in headers:
            reasons.append('TRANSFER_ENCODING_NOT_ALLOWED')
        try:
            n=int(headers[b'content-length'])
            if n != len(body):
                reasons.append('CONTENT_LENGTH_MISMATCH')
        except (KeyError, ValueError):
            reasons.append('CONTENT_LENGTH_INVALID')
        try:
            parsed=json.loads(body.decode('utf-8'), object_pairs_hook=_unique_pairs,
                              parse_constant=_reject_constant)
            if parsed != {'Argument':envelope['result_request']['selector']}:
                reasons.append('REQUEST_BODY_SELECTOR_MISMATCH')
        except (ValueError,UnicodeError,KeyError,TypeError):
            reasons.append('REQUEST_BODY_INVALID')
        req=envelope.get('result_request',{})
        if not hmac.compare_digest(str(req.get('raw_http_sha256','')),digest(raw_request)):
            reasons.append('RAW_REQUEST_HASH_MISMATCH')
        if not hmac.compare_digest(str(req.get('raw_body_sha256','')),digest(body)):
            reasons.append('RAW_BODY_HASH_MISMATCH')
        if not hmac.compare_digest(str(req.get('selector_sha256','')),
                                   digest(canonical_bytes(req.get('selector',{})))):
            reasons.append('CANONICAL_SELECTOR_HASH_MISMATCH')
    except ValueError:
        reasons.append('HTTP_REQUEST_FRAMING_INVALID')
    # No raw bytes or credential-bearing headers returned.
    return {'status':'OFFLINE_BYTES_VALID' if not reasons else 'HOLD',
            'reasons':reasons, 'request_sha256':digest(raw_request)}


def verify_all(envelope: dict, model_bytes: bytes, response_bytes: bytes,
               raw_request: bytes, attestation: dict, signature_hex: str,
               pinned_public_key: bytes) -> dict:
    base=certify(envelope,model_bytes,response_bytes)
    signed=verify_attestation(envelope,attestation,signature_hex,pinned_public_key)
    wire=verify_http_request_bytes(raw_request,envelope)
    return {
        'status':'OFFLINE_EVIDENCE_GATES_PASS' if all((base['status']=='OFFLINE_GATES_PASS',
                    signed['status']=='OFFLINE_SIGNATURE_VALID', wire['status']=='OFFLINE_BYTES_VALID')) else 'HOLD',
        'base_status':base['status'], 'signature_status':signed['status'],
        'request_bytes_status':wire['status'],
        'reasons':base['reasons']+signed['reasons']+wire['reasons'],
        'engineering_accepted':False,'live_verified':False,
        'note':'Synthetic PASS does not certify actual MIDAS analysis or trusted capture device.'
    }
