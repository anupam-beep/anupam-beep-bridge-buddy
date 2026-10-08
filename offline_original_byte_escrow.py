"""BridgeAgent OFFLINE encrypted original-byte evidence escrow candidate.

This is a cryptographic container and local POSIX storage prototype, not a
network capture mechanism, credential manager, proof of transmission, or
engineering certification. No MIDAS connection is made. No real secrets used.

Trust boundary: caller supplies 32-byte key via an independent secret manager;
key must NEVER be included in shareable bundles, command-line args or logs.
No plaintext capture is written by this module. Plaintext exists in memory
and can remain in process memory after return (Python offers no secure erase).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DOMAIN = 'BridgeAgent:original-byte-escrow:v1'
MAX_CAPTURE = 4 * 1024 * 1024
MAX_STORED = 12 * 1024 * 1024
RECORD_ID = re.compile(r'^[0-9a-f]{32}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')


class EscrowRejected(Exception):
    """Code-only failure: never interpolate sensitive data into this exception."""


def _fail(code: str):
    raise EscrowRejected(code)


def _key(key: Any) -> bytes:
    if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
        _fail('KEY_INVALID')
    return bytes(key)


def _private_dir(path: str | Path) -> Path:
    p = Path(path)
    # The parent path must be controlled by the operator; do not traverse
    # untrusted ancestors. Refuse symbolic links at the final directory.
    if not p.is_absolute():
        _fail('ABSOLUTE_ESCROW_DIRECTORY_REQUIRED')
    if os.name != 'posix':
        _fail('POSIX_STORAGE_ONLY_UNTIL_WINDOWS_ACL_REVIEW')
    try:
        if not p.exists() and not p.is_symlink():
            p.mkdir(mode=0o700, parents=False)
        st = p.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            _fail('ESCROW_DIRECTORY_NOT_PRIVATE')
    except (OSError, ValueError) as exc:
        _fail('ESCROW_DIRECTORY_UNAVAILABLE')
    return p


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str):
        _fail('ESCROW_SCHEMA_INVALID')
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        # Never return the input value.
        _fail('ESCROW_BASE64_INVALID')


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_json_unique(raw: bytes) -> Any:
    def pairs(kv):
        obj = {}
        for k, v in kv:
            if k in obj:
                _fail('ESCROW_DUPLICATE_JSON_KEY')
            obj[k] = v
        return obj
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError, RecursionError):
        _fail('ESCROW_JSON_INVALID')


def _aad(record_id: str) -> bytes:
    return _canonical({'domain': DOMAIN, 'record_id': record_id, 'version': 1})


def _read_record(root: Path, record_id: str) -> dict:
    if not isinstance(record_id, str) or not RECORD_ID.fullmatch(record_id):
        _fail('RECORD_ID_INVALID')
    p = root / (record_id + '.escrow')
    try:
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(p, flags)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
                _fail('ESCROW_FILE_NOT_PRIVATE')
            if st.st_size > MAX_STORED or st.st_size <= 0:
                _fail('ESCROW_FILE_SIZE_INVALID')
            with os.fdopen(fd, 'rb', closefd=False) as f:
                raw = f.read(MAX_STORED + 1)
        finally:
            os.close(fd)
    except EscrowRejected:
        raise
    except OSError:
        _fail('ESCROW_FILE_UNAVAILABLE')
    obj = _load_json_unique(raw)
    if not isinstance(obj, dict) or set(obj) != {'version', 'domain', 'record_id', 'nonce_b64', 'ciphertext_b64'}:
        _fail('ESCROW_SCHEMA_INVALID')
    if type(obj['version']) is not int or obj['version'] != 1 or obj['domain'] != DOMAIN or obj['record_id'] != record_id:
        _fail('ESCROW_HEADER_INVALID')
    return obj


def _decrypt(root: Path, record_id: str, key: bytes) -> dict:
    obj = _read_record(root, record_id)
    nonce = _unb64(obj['nonce_b64'])
    ct = _unb64(obj['ciphertext_b64'])
    if len(nonce) != 12 or len(ct) < 16 or len(ct) > MAX_STORED:
        _fail('ESCROW_CRYPTO_FORMAT_INVALID')
    try:
        raw = AESGCM(key).decrypt(nonce, ct, _aad(record_id))
    except (InvalidTag, ValueError):
        _fail('ESCROW_AUTHENTICATION_FAILED')
    if len(raw) > MAX_STORED:
        _fail('ESCROW_PLAINTEXT_SIZE_INVALID')
    payload = _load_json_unique(raw)
    if not isinstance(payload, dict) or set(payload) != {
        'capture_id', 'analysis_run_id', 'request_b64', 'response_b64',
        'request_sha256', 'response_sha256', 'domain', 'version',
    }:
        _fail('ESCROW_PAYLOAD_SCHEMA_INVALID')
    if type(payload['version']) is not int or payload['version'] != 1 or payload['domain'] != DOMAIN:
        _fail('ESCROW_PAYLOAD_DOMAIN_INVALID')
    if not all(isinstance(payload[k], str) and 1 <= len(payload[k]) <= 128
               for k in ('capture_id', 'analysis_run_id')):
        _fail('ESCROW_PAYLOAD_ID_INVALID')
    request = _unb64(payload['request_b64'])
    response = _unb64(payload['response_b64'])
    if len(request) > MAX_CAPTURE or len(response) > MAX_CAPTURE:
        _fail('ESCROW_CAPTURE_SIZE_INVALID')
    if not all(isinstance(payload[k], str) and HEX64.fullmatch(payload[k])
               for k in ('request_sha256', 'response_sha256')):
        _fail('ESCROW_PAYLOAD_HASH_INVALID')
    if not hmac.compare_digest(payload['request_sha256'], _digest(request)) or not hmac.compare_digest(payload['response_sha256'], _digest(response)):
        _fail('ESCROW_PAYLOAD_HASH_MISMATCH')
    return payload


def escrow_capture(*, directory: str | Path, key: bytes, capture_id: str,
                   analysis_run_id: str, raw_request: bytes,
                   raw_response: bytes) -> dict:
    """Store only authenticated ciphertext; return NON-AUTHENTICATING metadata.

    Never pass production API keys in testing. No plaintext output, no logging.
    Filesystem parent must be private and trusted. The file is committed via
    hard-link of a private temporary file (no overwrite), then fsync directory.
    """
    key = _key(key)
    if not all(isinstance(v, str) and 1 <= len(v) <= 128 and not any(ord(c) < 32 for c in v)
               for v in (capture_id, analysis_run_id)):
        _fail('CAPTURE_ID_INVALID')
    if not isinstance(raw_request, bytes) or not isinstance(raw_response, bytes):
        _fail('CAPTURE_BYTES_REQUIRED')
    if len(raw_request) > MAX_CAPTURE or len(raw_response) > MAX_CAPTURE:
        _fail('CAPTURE_SIZE_EXCEEDED')
    root = _private_dir(directory)
    record_id = secrets.token_hex(16)
    nonce = secrets.token_bytes(12)
    payload = {
        'version': 1, 'domain': DOMAIN, 'capture_id': capture_id,
        'analysis_run_id': analysis_run_id, 'request_b64': _b64(raw_request),
        'response_b64': _b64(raw_response), 'request_sha256': _digest(raw_request),
        'response_sha256': _digest(raw_response),
    }
    ct = AESGCM(key).encrypt(nonce, _canonical(payload), _aad(record_id))
    stored = _canonical({'version': 1, 'domain': DOMAIN, 'record_id': record_id,
                         'nonce_b64': _b64(nonce), 'ciphertext_b64': _b64(ct)})
    if len(stored) > MAX_STORED:
        _fail('ESCROW_STORED_SIZE_EXCEEDED')
    temp = root / ('.pending-' + secrets.token_hex(16))
    target = root / (record_id + '.escrow')
    fd = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(temp, flags, 0o600)
        with os.fdopen(fd, 'wb', closefd=True) as f:
            fd = None
            f.write(stored)
            f.flush()
            os.fsync(f.fileno())
        # Hard-link is an atomic no-clobber publication on the same filesystem.
        os.link(temp, target, follow_symlinks=False)
        dirfd = os.open(root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except OSError:
        _fail('ESCROW_STORAGE_FAILED')
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
    return {'status': 'ENCRYPTED_OFFLINE_NOT_CAPTURE_PROOF', 'record_id': record_id,
            'live_verified': False, 'engineering_accepted': False,
            'civil_nx_contacted': False}


def verify_escrow_binding(*, directory: str | Path, key: bytes,
                          record_id: str, trusted_handoff_manifest: Any) -> dict:
    """Return only hash/run/capture comparison status; never return raw bytes.

    Manifest MUST be obtained independently of the escrow, and its hashes
    must refer to the original wire bytes, not redacted/sanitized copies.
    A match does not prove transmission, authentic analysis or engineering.
    """
    base = {'status': 'HOLD', 'reasons': [], 'live_verified': False,
            'engineering_accepted': False, 'civil_nx_contacted': False}
    if not isinstance(trusted_handoff_manifest, dict):
        base['reasons'] = ['INDEPENDENT_HANDOFF_MANIFEST_REQUIRED']
        return base
    # Require the actual v1 handoff contract, not arbitrary caller metadata.
    # Independent provenance of this manifest is a separate operator obligation.
    from offline_evidence_handoff import DOMAIN as HANDOFF_DOMAIN
    if (type(trusted_handoff_manifest.get('schema_version')) is not int or
        trusted_handoff_manifest['schema_version'] != 1 or
        trusted_handoff_manifest.get('domain') != HANDOFF_DOMAIN):
        base['reasons'] = ['HANDOFF_SCHEMA_OR_DOMAIN_INVALID']
        return base
    required = ('capture_id', 'analysis_run_id', 'raw_request_sha256', 'raw_response_sha256')
    if not all(isinstance(trusted_handoff_manifest.get(k), str) for k in required):
        base['reasons'] = ['HANDOFF_BINDING_FIELDS_INVALID']
        return base
    if not all(HEX64.fullmatch(trusted_handoff_manifest[k])
               for k in ('raw_request_sha256', 'raw_response_sha256')):
        base['reasons'] = ['HANDOFF_BINDING_DIGEST_INVALID']
        return base
    try:
        payload = _decrypt(_private_dir(directory), record_id, _key(key))
    except EscrowRejected as exc:
        base['reasons'] = [str(exc)]
        return base
    fields = {
        'capture_id': 'capture_id', 'analysis_run_id': 'analysis_run_id',
        'raw_request_sha256': 'request_sha256',
        'raw_response_sha256': 'response_sha256',
    }
    for manifest_field, payload_field in fields.items():
        a, b = trusted_handoff_manifest[manifest_field], payload[payload_field]
        if not hmac.compare_digest(a.encode(), b.encode()):
            base['reasons'].append('ESCROW_HANDOFF_BINDING_MISMATCH:' + manifest_field)
    if not base['reasons']:
        base['status'] = 'OFFLINE_ESCROW_BINDING_MATCH_NOT_LIVE'
    return base
