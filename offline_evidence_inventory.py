"""Fail-closed, offline inventory of *untrusted* Civil NX evidence claims.

Hashes bytes but never prints/exports them. A matching hash is NOT authentication.
No network, credentials, MIDAS calls, model access, writes or certification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

GATES = ('E1', 'E2', 'E3', 'E4', 'E5', 'E6', 'E7')
GATE_NAMES = {
    'E1': 'model_identity', 'E2': 'analysis_completion',
    'E3': 'original_request', 'E4': 'original_response',
    'E5': 'independent_capture_receipt', 'E6': 'external_checkpoint',
    'E7': 'engineering_independent_verification',
}
MAX_MANIFEST_BYTES = 256_000
MAX_ARTIFACT_BYTES = 16_000_000
MAX_ARTIFACTS = 200
MAX_TOTAL_BYTES = 64_000_000
MAX_ARCHIVE_ENTRIES = 500
MAX_ARCHIVE_BYTES = 32_000_000
MAX_COMPRESSION_RATIO = 200
HEX_SHA = re.compile(r'^[0-9a-f]{64}$')
CAPTURE_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
STATUS = 'OFFLINE_INVENTORY_ONLY_NOT_CERTIFIED'

class InventoryRejected(ValueError):
    pass


def _strict_object(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise InventoryRejected('DUPLICATE_JSON_KEY')
        out[k] = v
    return out


def _safe_relative(name):
    if not isinstance(name, str) or not name or len(name) > 240:
        raise InventoryRejected('INVALID_RELATIVE_PATH')
    if '\\' in name or ':' in name or '\x00' in name or name.startswith('/'):
        raise InventoryRejected('INVALID_RELATIVE_PATH')
    parts = name.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise InventoryRejected('INVALID_RELATIVE_PATH')
    return PurePosixPath(name)


def _regular_no_links(root, rel):
    if root.is_symlink() or not root.is_dir():
        raise InventoryRejected('UNSAFE_ROOT')
    target = root
    for i, part in enumerate(rel.parts):
        target = target / part
        try:
            st = target.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            raise InventoryRejected('SYMLINK_REJECTED')
        if i < len(rel.parts) - 1 and not stat.S_ISDIR(st.st_mode):
            raise InventoryRejected('UNSAFE_PARENT')
        if i == len(rel.parts) - 1:
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise InventoryRejected('NONREGULAR_OR_LINKED_ARTIFACT')
            if st.st_size > MAX_ARTIFACT_BYTES:
                raise InventoryRejected('ARTIFACT_TOO_LARGE')
            return target
    return None


def _digest(path):
    # O_NOFOLLOW guards the final path against replacement with a symlink.
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        st1 = os.fstat(fd)
        if not stat.S_ISREG(st1.st_mode) or st1.st_nlink != 1 or st1.st_size > MAX_ARTIFACT_BYTES:
            raise InventoryRejected('UNSAFE_ARTIFACT')
        h, size = hashlib.sha256(), 0
        with os.fdopen(os.dup(fd), 'rb') as f:
            while True:
                buf = f.read(65536)
                if not buf:
                    break
                size += len(buf)
                if size > MAX_ARTIFACT_BYTES:
                    raise InventoryRejected('ARTIFACT_TOO_LARGE')
                h.update(buf)
        st2 = os.fstat(fd)
        if (st1.st_ino, st1.st_dev, st1.st_size, st1.st_mtime_ns) != (st2.st_ino, st2.st_dev, st2.st_size, st2.st_mtime_ns) or size != st2.st_size:
            raise InventoryRejected('ARTIFACT_CHANGED_DURING_READ')
        return h.hexdigest(), size
    finally:
        os.close(fd)


def load_claims(raw):
    if type(raw) is not bytes or len(raw) > MAX_MANIFEST_BYTES:
        raise InventoryRejected('MANIFEST_TOO_LARGE')
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=_strict_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(InventoryRejected('NONFINITE_JSON')))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InventoryRejected('INVALID_MANIFEST_JSON') from None
    if not isinstance(data, dict) or set(data) != {'schema_version', 'capture_id', 'artifacts'}:
        raise InventoryRejected('INVALID_MANIFEST_SCHEMA')
    if type(data['schema_version']) is not int or data['schema_version'] != 1:
        raise InventoryRejected('INVALID_SCHEMA_VERSION')
    if not isinstance(data['capture_id'], str) or not CAPTURE_ID.fullmatch(data['capture_id']):
        raise InventoryRejected('INVALID_CAPTURE_ID')
    records = data['artifacts']
    if not isinstance(records, list) or len(records) > MAX_ARTIFACTS:
        raise InventoryRejected('INVALID_ARTIFACT_COUNT')
    seen = set()
    for entry in records:
        if not isinstance(entry, dict) or set(entry) != {'gate', 'relative_path', 'sha256'}:
            raise InventoryRejected('INVALID_ARTIFACT_SCHEMA')
        if entry['gate'] not in GATES or not isinstance(entry['sha256'], str) or not HEX_SHA.fullmatch(entry['sha256']):
            raise InventoryRejected('INVALID_GATE_OR_HASH')
        rel = _safe_relative(entry['relative_path'])
        if str(rel).casefold() in seen:
            raise InventoryRejected('DUPLICATE_ARTIFACT_PATH')
        seen.add(str(rel).casefold())
    return data


def inventory(root, claims):
    """Return reason codes/counts only; never report names, IDs or capture content."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise InventoryRejected('UNSAFE_ROOT')
    per_gate = {gate: {'gate_name': GATE_NAMES[gate], 'status': 'MISSING',
                       'matched_hashes': 0, 'missing_files': 0, 'hash_mismatches': 0}
                for gate in GATES}
    total = 0
    for entry in claims['artifacts']:
        gate = per_gate[entry['gate']]
        target = _regular_no_links(root, _safe_relative(entry['relative_path']))
        if target is None:
            gate['missing_files'] += 1
            continue
        digest, size = _digest(target)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise InventoryRejected('TOTAL_ARTIFACT_BYTES_EXCEEDED')
        if digest != entry['sha256']:
            gate['hash_mismatches'] += 1
        else:
            gate['matched_hashes'] += 1
    for gate in per_gate.values():
        if gate['hash_mismatches']:
            gate['status'] = 'INTEGRITY_MISMATCH'
        elif gate['missing_files']:
            gate['status'] = 'INCOMPLETE'
        elif gate['matched_hashes']:
            gate['status'] = 'PRESENT_HASH_MATCH_UNAUTHENTICATED'
    return {
        'status': STATUS,
        'gate_inventory': per_gate,
        'artifact_claims': len(claims['artifacts']),
        'hash_matched': sum(x['matched_hashes'] for x in per_gate.values()),
        'missing_files': sum(x['missing_files'] for x in per_gate.values()),
        'hash_mismatches': sum(x['hash_mismatches'] for x in per_gate.values()),
        'all_gates_authenticated': False,
        'result_extraction_verified': False,
        'engineering_accepted': False,
        'civil_nx_contacted': False,
        'note_code': 'HASH_MATCH_IS_NOT_PROVENANCE_OR_CERTIFICATION',
    }


def inspect_prior_archive(path):
    """Read only ZIP central-directory metadata. Never extract or parse capture bytes."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise InventoryRejected('UNSAFE_ARCHIVE')
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            raise InventoryRejected('TOO_MANY_ARCHIVE_ENTRIES')
        seen, total = set(), 0
        kinds = {'test': 0, 'candidate_code': 0, 'cycle_report': 0,
                 'synthetic_fixture': 0, 'manifest': 0, 'other': 0}
        for item in infos:
            if item.is_dir():
                continue
            _safe_relative(item.filename)
            key = item.filename.casefold()
            if key in seen:
                raise InventoryRejected('DUPLICATE_ARCHIVE_ENTRY')
            seen.add(key)
            mode = (item.external_attr >> 16) & 0xFFFF
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                raise InventoryRejected('ARCHIVE_SYMLINK')
            if item.flag_bits & 1:
                raise InventoryRejected('ENCRYPTED_ARCHIVE_ENTRY')
            total += item.file_size
            if total > MAX_ARCHIVE_BYTES or item.file_size > MAX_ARTIFACT_BYTES:
                raise InventoryRejected('ARCHIVE_SIZE_LIMIT')
            if item.file_size and item.file_size / max(1, item.compress_size) > MAX_COMPRESSION_RATIO:
                raise InventoryRejected('ARCHIVE_COMPRESSION_RATIO')
            name = item.filename.rsplit('/', 1)[-1].lower()
            if name.startswith('test_') and name.endswith('.py'):
                kind = 'test'
            elif name.startswith('sha256_manifest_') and name.endswith('.json'):
                kind = 'manifest'
            elif 'synthetic' in name and name.endswith('.json'):
                kind = 'synthetic_fixture'
            elif name.endswith('_cycle_report.json'):
                kind = 'cycle_report'
            elif name.endswith('.py'):
                kind = 'candidate_code'
            else:
                kind = 'other'
            kinds[kind] += 1
        return {'status': STATUS, 'archive_entries': len(infos),
                'classified_file_counts': kinds,
                'authentic_capture_confirmed': False,
                'gate_status': {gate: 'NOT_ESTABLISHED_BY_ARCHIVE_METADATA' for gate in GATES},
                'note_code': 'ARCHIVE_METADATA_IS_NOT_ANALYSIS_EVIDENCE'}


def main(argv=None):
    p = argparse.ArgumentParser(description='Offline Civil NX evidence inventory; metadata-only output')
    p.add_argument('--root', type=Path, help='Directory containing locally held evidence')
    p.add_argument('--claims', type=Path, help='Sanitized claims manifest, schema v1')
    p.add_argument('--prior-archive', type=Path, help='Inspect ZIP central-directory metadata only')
    a = p.parse_args(argv)
    try:
        if a.prior_archive and not (a.root or a.claims):
            result = inspect_prior_archive(a.prior_archive)
        elif a.root and a.claims and not a.prior_archive:
            if a.claims.is_symlink() or not a.claims.is_file():
                raise InventoryRejected('UNSAFE_CLAIMS_MANIFEST')
            with a.claims.open('rb') as f:
                claims = load_claims(f.read(MAX_MANIFEST_BYTES + 1))
            result = inventory(a.root, claims)
        else:
            raise InventoryRejected('INVALID_ARGUMENT_COMBINATION')
    except (InventoryRejected, OSError, zipfile.BadZipFile, RuntimeError) as exc:
        code = str(exc) if isinstance(exc, InventoryRejected) else 'INPUT_REJECTED'
        result = {'status': STATUS, 'classification': 'INPUT_REJECTED',
                  'issue_code': code, 'engineering_accepted': False,
                  'civil_nx_contacted': False}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result.get('classification') == 'INPUT_REJECTED' else 0

if __name__ == '__main__':
    raise SystemExit(main())
