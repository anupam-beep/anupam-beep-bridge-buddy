"""Opt-in candidate integration of inode/handle-pinned snapshots with E1–E7 inventory.

Never mutates the inherited inventory module or production BridgeAgent.
"""
from __future__ import annotations
from pathlib import Path
from offline_evidence_inventory import (GATES, GATE_NAMES, MAX_TOTAL_BYTES, STATUS,
                                         load_claims, InventoryRejected, _safe_relative)
from offline_snapshot_reader import snapshot_sha256, SnapshotRejected


def inventory_hardened(root, claims):
    root = Path(root)
    per_gate = {g: {'gate_name': GATE_NAMES[g], 'status': 'MISSING',
                    'matched_hashes': 0, 'missing_files': 0, 'hash_mismatches': 0}
                for g in GATES}
    total = 0
    for entry in claims['artifacts']:
        gate = per_gate[entry['gate']]
        rel = str(_safe_relative(entry['relative_path']))
        try:
            result = snapshot_sha256(root, rel)
        except SnapshotRejected as exc:
            # Missing evidence is a hard incomplete state, not evidence of success.
            if str(exc) == 'FILE_MISSING':
                gate['missing_files'] += 1
                continue
            raise InventoryRejected(str(exc)) from None
        total += result['size']
        if total > MAX_TOTAL_BYTES:
            raise InventoryRejected('TOTAL_ARTIFACT_BYTES_EXCEEDED')
        if result['sha256'] == entry['sha256']:
            gate['matched_hashes'] += 1
        else:
            gate['hash_mismatches'] += 1
    for gate in per_gate.values():
        if gate['hash_mismatches']:
            gate['status'] = 'INTEGRITY_MISMATCH'
        elif gate['missing_files']:
            gate['status'] = 'INCOMPLETE'
        elif gate['matched_hashes']:
            gate['status'] = 'PRESENT_HASH_MATCH_UNAUTHENTICATED'
    return {
        'status': STATUS, 'gate_inventory': per_gate,
        'artifact_claims': len(claims['artifacts']),
        'hash_matched': sum(v['matched_hashes'] for v in per_gate.values()),
        'missing_files': sum(v['missing_files'] for v in per_gate.values()),
        'hash_mismatches': sum(v['hash_mismatches'] for v in per_gate.values()),
        'all_gates_authenticated': False, 'result_extraction_verified': False,
        'engineering_accepted': False, 'civil_nx_contacted': False,
        'note_code': 'HANDLE_PINNED_HASH_NOT_PROVENANCE_OR_CERTIFICATION',
    }
