"""Offline, non-mutating intake gate for *sanitized* Civil NX evidence bundles.

This is not a provenance verifier, a live MIDAS client, or engineering certification.
Never use this gate to silently redact exact-byte signed evidence; keep sensitive raw
captures in a separately controlled vault and never distribute them in bundles.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
import zipfile
from pathlib import Path

SCHEMA = 'bridgeagent.capture_bundle.v1'
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 12 * 1024 * 1024
MAX_RATIO = 50
MAX_JSON_DEPTH = 32

ROLES = {
    'request': ('request.bin', 'application/octet-stream'),
    'response': ('response.json', 'application/json'),
    'analysis_attestation': ('analysis_attestation.json', 'application/json'),
    'capture_receipt': ('capture_receipt.json', 'application/json'),
    'checkpoint_anchor': ('checkpoint_anchor.json', 'application/json'),
}

# Scan bytes rather than decoded JSON values, so JSON-escaped secrets and binary
# payloads cannot bypass a purely decoded-text check. Also scan decoded JSON.
SECRET_BYTES = (
    re.compile(rb'(?i)authorization\s*[=:]\s*["\']?\s*[^\s"\',}]{4,}'),
    re.compile(rb'(?i)(?:x[-_]api[-_]key|midas_mapi_key|mapi[-_]?key|api[-_]?key|access[-_]?token|password|client[-_]?secret)\s*["\']?\s*[:=]\s*["\']?\s*[^\s"\',}]{4,}'),
    re.compile(rb'-----BEGIN\s+(?:[A-Z ]+\s+)?PRIVATE KEY-----'),
)
SECRET_TEXT = re.compile(r'(?i)(?<![a-z0-9_])(?:authorization|x[-_]api[-_]key|midas_mapi_key|mapi[-_]?key|api[-_]?key|access[-_]?token|password|client[-_]?secret)(?![a-z0-9_])')

class IntakeFailure(Exception):
    pass


def _fail(code):
    raise IntakeFailure(code)


def _safe_json(raw):
    try:
        txt = raw.decode('utf-8', 'strict')
        def no_duplicate(pairs):
            d = {}
            for k, v in pairs:
                if k in d:
                    _fail('DUPLICATE_JSON_KEY')
                d[k] = v
            return d
        def bad_constant(_):
            _fail('NONFINITE_JSON_NUMBER')
        obj = json.loads(txt, object_pairs_hook=no_duplicate, parse_constant=bad_constant)
    except IntakeFailure:
        raise
    except (ValueError, UnicodeDecodeError, RecursionError):
        _fail('INVALID_JSON')
    def depth_check(v, depth=0):
        if depth > MAX_JSON_DEPTH:
            _fail('JSON_TOO_DEEP')
        if isinstance(v, dict):
            for k, x in v.items():
                if SECRET_TEXT.search(k):
                    _fail('POTENTIAL_CREDENTIAL')
                depth_check(x, depth+1)
        elif isinstance(v, list):
            for x in v:
                depth_check(x, depth+1)
        elif isinstance(v, str) and ('-----BEGIN PRIVATE KEY-----' in v or SECRET_TEXT.search(v)):
            _fail('POTENTIAL_CREDENTIAL')
    depth_check(obj)
    return obj


def _read_limited(z, info):
    data = bytearray()
    with z.open(info, 'r') as fh:
        while True:
            chunk = fh.read(min(65536, MAX_MEMBER_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_MEMBER_BYTES:
                _fail('MEMBER_TOO_LARGE')
    if len(data) != info.file_size:
        _fail('SIZE_MISMATCH')
    return bytes(data)


def _check_secret(raw):
    if any(p.search(raw) for p in SECRET_BYTES):
        _fail('POTENTIAL_CREDENTIAL')
    # Catch escaped key names in JSON and header fragments without returning values.
    if b'\\u' in raw or b'\\/' in raw:
        try:
            expanded = raw.decode('unicode_escape').encode('utf-8')
        except (UnicodeError, ValueError):
            expanded = b''
        if expanded and any(p.search(expanded) for p in SECRET_BYTES):
            _fail('POTENTIAL_CREDENTIAL')


def _validated_bundle(path: str | Path, *, include_blobs: bool = False):
    """Single-open validation: never extract data from a different, unchecked ZIP."""
    try:
        path = Path(path)
        if not path.is_file() or path.is_symlink():
            _fail('ARCHIVE_NOT_REGULAR_FILE')
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            _fail('ARCHIVE_TOO_LARGE')
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            expected = {'manifest.json'} | {filename for filename, _ in ROLES.values()}
            names = [i.filename for i in infos]
            if len(names) != len(expected) or set(names) != expected:
                _fail('UNEXPECTED_OR_MISSING_MEMBER')
            if len(names) != len(set(names)):
                _fail('DUPLICATE_MEMBER')
            total = 0
            for i in infos:
                if (i.filename not in expected or '/' in i.filename or '\\' in i.filename or
                    i.filename.startswith('.') or i.is_dir()):
                    _fail('UNSAFE_MEMBER_PATH')
                mode = (i.external_attr >> 16) & 0xFFFF
                if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                    _fail('NONREGULAR_MEMBER')
                if i.flag_bits & 1 or i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    _fail('UNSUPPORTED_ZIP_ENTRY')
                if i.file_size > MAX_MEMBER_BYTES:
                    _fail('MEMBER_TOO_LARGE')
                total += i.file_size
                if total > MAX_TOTAL_BYTES:
                    _fail('TOTAL_TOO_LARGE')
                if i.file_size and (i.file_size / max(i.compress_size, 1)) > MAX_RATIO:
                    _fail('SUSPICIOUS_COMPRESSION_RATIO')
            blobs = {i.filename: _read_limited(z, i) for i in infos}
        for raw in blobs.values():
            _check_secret(raw)
        manifest = _safe_json(blobs['manifest.json'])
        if not isinstance(manifest, dict) or set(manifest) != {'schema', 'artifacts'}:
            _fail('BAD_MANIFEST_SCHEMA')
        if manifest['schema'] != SCHEMA or not isinstance(manifest['artifacts'], list):
            _fail('BAD_MANIFEST_SCHEMA')
        if len(manifest['artifacts']) != len(ROLES):
            _fail('BAD_MANIFEST_ROLES')
        roles_seen = set()
        for record in manifest['artifacts']:
            if not isinstance(record, dict) or set(record) != {'role', 'path', 'mime', 'bytes', 'sha256'}:
                _fail('BAD_MANIFEST_RECORD')
            role = record['role']
            if not isinstance(role, str) or role not in ROLES or role in roles_seen:
                _fail('BAD_MANIFEST_ROLES')
            roles_seen.add(role)
            expected_name, expected_mime = ROLES[role]
            if record['path'] != expected_name or record['mime'] != expected_mime:
                _fail('FILE_TYPE_OR_NAME_MISMATCH')
            raw = blobs[expected_name]
            if type(record['bytes']) is not int or record['bytes'] != len(raw):
                _fail('SIZE_MISMATCH')
            if not isinstance(record['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', record['sha256']):
                _fail('INVALID_DIGEST')
            if hashlib.sha256(raw).hexdigest() != record['sha256']:
                _fail('HASH_MISMATCH')
            if expected_mime == 'application/json':
                parsed = _safe_json(raw)
                if not isinstance(parsed, dict):
                    _fail('JSON_ROOT_NOT_OBJECT')
        result = {'status':'OFFLINE_INTAKE_PASS_NOT_CERTIFIED', 'roles_checked':len(roles_seen),
                  'bytes_checked':sum(len(v) for v in blobs.values()),
                  'provenance_verified':False, 'engineering_accepted':False,
                  'civil_nx_contacted':False}
        return (result, blobs) if include_blobs else result
    except IntakeFailure as exc:
        return {'status':'REJECT', 'reason':str(exc), 'provenance_verified':False,
                'engineering_accepted':False, 'civil_nx_contacted':False}
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, RuntimeError):
        return {'status':'REJECT', 'reason':'INVALID_ARCHIVE', 'provenance_verified':False,
                'engineering_accepted':False, 'civil_nx_contacted':False}



def verify_capture_bundle(path: str | Path):
    """Metadata-only public intake; does not expose any evidence bytes."""
    return _validated_bundle(path)


def _load_validated_bundle_for_handoff(path: str | Path):
    """Internal-only validated in-memory blobs, never for logging or publication."""
    result = _validated_bundle(path, include_blobs=True)
    return result if isinstance(result, tuple) else (result, None)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print('usage: python offline_capture_bundle_intake.py <sanitized_bundle.zip>')
        raise SystemExit(2)
    result = verify_capture_bundle(sys.argv[1])
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['status'] == 'OFFLINE_INTAKE_PASS_NOT_CERTIFIED' else 1)

