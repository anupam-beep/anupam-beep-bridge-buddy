"""BridgeAgent offline-only signed-receipt replay registry.

Persists metadata/hashes only, never raw HTTP bytes, credentials, or private keys.
SQLite BEGIN IMMEDIATE serializes writers; hash-chain detects in-place tampering.
An INDEPENDENTLY pinned head/count checkpoint is REQUIRED for append, otherwise
an attacker could rewrite or truncate the entire local chain undetected.
This is NOT a capture witness, result extraction, or engineering acceptance.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
from pathlib import Path
from typing import Any

from offline_result_certifier import canonical_bytes, digest
from independent_capture_receipt import verify_with_capture

GENESIS = hashlib.sha256(b'BridgeAgent:offline-replay-registry:v1:genesis').hexdigest()
DOMAIN = b'BridgeAgent:offline-replay-registry:v1:entry\x00'


class RegistryHold(RuntimeError):
    """Fail-closed registry refusal; no data should be trusted or committed."""


def entry_hash(previous_hash: str, sequence: int, record: dict) -> str:
    return digest(DOMAIN + canonical_bytes({
        'previous_hash': previous_hash, 'sequence': sequence, 'record': record,
    }))


class OfflineReplayRegistry:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self.db = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        self.db.execute('PRAGMA busy_timeout=10000')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS entries (
            seq INTEGER PRIMARY KEY,
            capture_id TEXT NOT NULL UNIQUE,
            collector_id TEXT NOT NULL,
            receipt_sha256 TEXT NOT NULL,
            raw_request_sha256 TEXT NOT NULL,
            raw_response_sha256 TEXT NOT NULL,
            model_sha256 TEXT NOT NULL,
            analysis_run_id TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
          );
          CREATE TRIGGER IF NOT EXISTS entries_no_update
            BEFORE UPDATE ON entries BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
          CREATE TRIGGER IF NOT EXISTS entries_no_delete
            BEFORE DELETE ON entries BEGIN SELECT RAISE(ABORT, 'APPEND_ONLY'); END;
        ''')

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _audit_unlocked(self, checkpoint: dict | None = None) -> dict:
        prior, count = GENESIS, 0
        for row in self.db.execute('''
          SELECT seq,capture_id,collector_id,receipt_sha256,raw_request_sha256,
                 raw_response_sha256,model_sha256,analysis_run_id,previous_hash,entry_hash
          FROM entries ORDER BY seq
        '''):
            seq, cap, collector, rh, reqh, resph, modelh, runid, previous, actual = row
            count += 1
            record = dict(capture_id=cap, collector_id=collector,
                          receipt_sha256=rh, raw_request_sha256=reqh,
                          raw_response_sha256=resph, model_sha256=modelh,
                          analysis_run_id=runid)
            expected = entry_hash(prior, count, record)
            if seq != count or not hmac.compare_digest(previous, prior) or not hmac.compare_digest(actual, expected):
                raise RegistryHold('CHAIN_CORRUPTION_AT_ENTRY:' + str(count))
            prior = actual
        if checkpoint is not None:
            if not isinstance(checkpoint, dict) or type(checkpoint.get('count')) is not int or not isinstance(checkpoint.get('head'), str):
                raise RegistryHold('INVALID_INDEPENDENT_CHECKPOINT')
            if checkpoint['count'] != count or not hmac.compare_digest(checkpoint['head'], prior):
                raise RegistryHold('INDEPENDENT_CHECKPOINT_MISMATCH')
        return {'count': count, 'head': prior,
                'status': 'CHAIN_MATCHES_PINNED_CHECKPOINT' if checkpoint is not None else 'LOCAL_CHAIN_ONLY',
                'engineering_accepted': False, 'live_verified': False}

    def audit(self, pinned_checkpoint: dict | None = None) -> dict:
        return self._audit_unlocked(pinned_checkpoint)

    def accept_signed_receipt(self, *, pinned_checkpoint: dict,
                              envelope: dict, model_bytes: bytes, response_bytes: bytes,
                              raw_request: bytes, analysis_attestation: dict,
                              analysis_signature_hex: str, pinned_analysis_public_key: bytes,
                              receipt: dict, receipt_signature_hex: str,
                              pinned_collector_id: str, pinned_capture_public_key: bytes) -> dict:
        """Atomic verify+append. Caller MUST store returned checkpoint independently.

        Refuses to append without a prior independently pinned checkpoint.
        A PASS here is *offline fixture consistency*, never proof of a real run.
        """
        if pinned_checkpoint is None:
            raise RegistryHold('INDEPENDENT_CHECKPOINT_REQUIRED')
        try:
            self.db.execute('BEGIN IMMEDIATE')
            before = self._audit_unlocked(pinned_checkpoint)
            capture_id = receipt.get('capture_id') if isinstance(receipt, dict) else None
            seen = bool(isinstance(capture_id, str) and self.db.execute(
                'SELECT 1 FROM entries WHERE capture_id=?', (capture_id,)).fetchone())
            result = verify_with_capture(
                envelope, model_bytes, response_bytes, raw_request, analysis_attestation,
                analysis_signature_hex, pinned_analysis_public_key, receipt,
                receipt_signature_hex, pinned_collector_id, pinned_capture_public_key,
                previously_seen_capture_ids={capture_id} if seen else frozenset(),
            )
            if result['status'] != 'OFFLINE_EVIDENCE_GATES_PASS':
                raise RegistryHold('RECEIPT_VERIFICATION_HOLD:' + ','.join(result['reasons']))
            record = dict(
                capture_id=capture_id, collector_id=receipt['collector_id'],
                receipt_sha256=digest(canonical_bytes(receipt) + bytes.fromhex(receipt_signature_hex)),
                raw_request_sha256=receipt['raw_request_sha256'],
                raw_response_sha256=receipt['raw_response_sha256'],
                model_sha256=receipt['model_sha256'],
                analysis_run_id=receipt['analysis_run_id'],
            )
            sequence = before['count'] + 1
            head = entry_hash(before['head'], sequence, record)
            self.db.execute('''INSERT INTO entries
                (seq,capture_id,collector_id,receipt_sha256,raw_request_sha256,
                 raw_response_sha256,model_sha256,analysis_run_id,previous_hash,entry_hash)
                 VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (sequence, record['capture_id'], record['collector_id'],
                 record['receipt_sha256'], record['raw_request_sha256'],
                 record['raw_response_sha256'], record['model_sha256'],
                 record['analysis_run_id'], before['head'], head))
            self.db.execute('COMMIT')
            return {'status': 'OFFLINE_RECEIPT_REGISTERED',
                    'checkpoint_to_pin_independently': {'count': sequence, 'head': head},
                    'engineering_accepted': False, 'live_verified': False}
        except Exception:
            if self.db.in_transaction:
                self.db.execute('ROLLBACK')
            raise
