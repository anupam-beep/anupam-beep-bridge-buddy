"""Synthetic, offline-only escrow adversarial Bridge Dojo."""
import base64
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from offline_original_byte_escrow import (
    MAX_CAPTURE, EscrowRejected, escrow_capture, verify_escrow_binding,
)

KEY = b'k' * 32
REQUEST = b'POST /civil/post/table HTTP/1.1\r\nMAPI-Key: FAKE-SYNTHETIC-SECRET\r\n\r\n{}'
RESPONSE = b'{"message":""}'


class OriginalByteEscrowDojo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'private'
        import hashlib
        from offline_evidence_handoff import DOMAIN as HANDOFF_DOMAIN
        self.manifest = {'schema_version': 1, 'domain': HANDOFF_DOMAIN,
                         'capture_id': 'synthetic-cap-001',
                         'analysis_run_id': 'synthetic-run-001',
                         'raw_request_sha256': hashlib.sha256(REQUEST).hexdigest(),
                         'raw_response_sha256': hashlib.sha256(RESPONSE).hexdigest()}

    def store(self, **kw):
        args = dict(directory=self.root, key=KEY,
                    capture_id='synthetic-cap-001',
                    analysis_run_id='synthetic-run-001',
                    raw_request=REQUEST, raw_response=RESPONSE)
        args.update(kw)
        return escrow_capture(**args)

    def bind(self, record_id, **kw):
        args = dict(directory=self.root, key=KEY, record_id=record_id,
                    trusted_handoff_manifest=self.manifest)
        args.update(kw)
        return verify_escrow_binding(**args)

    def test_roundtrip_binding_offline_only(self):
        saved = self.store()
        check = self.bind(saved['record_id'])
        self.assertEqual(check['status'], 'OFFLINE_ESCROW_BINDING_MATCH_NOT_LIVE')
        self.assertFalse(check['engineering_accepted'])
        self.assertFalse(check['live_verified'])
        self.assertFalse(check['civil_nx_contacted'])

    def test_no_secret_plaintext_on_disk_or_in_output(self):
        saved = self.store()
        blob = (self.root / (saved['record_id'] + '.escrow')).read_bytes()
        self.assertNotIn(b'MAPI-Key', blob)
        self.assertNotIn(b'FAKE-SYNTHETIC-SECRET', blob)
        self.assertNotIn(b'synthetic-cap-001', blob)
        self.assertNotIn(b'synthetic-run-001', blob)
        self.assertNotIn(b'MAPI-Key', str(saved).encode())
        self.assertNotIn(b'MAPI-Key', str(self.bind(saved['record_id'])).encode())

    def test_private_directory_and_file_modes(self):
        saved = self.store()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / (saved['record_id'] + '.escrow')).stat().st_mode), 0o600)

    def test_wrong_key_hold(self):
        rid = self.store()['record_id']
        self.assertIn('ESCROW_AUTHENTICATION_FAILED', self.bind(rid, key=b'x'*32)['reasons'])

    def test_invalid_key_store_rejected(self):
        with self.assertRaisesRegex(EscrowRejected, 'KEY_INVALID'):
            self.store(key=b'weak')

    def test_missing_independent_manifest(self):
        rid = self.store()['record_id']
        self.assertIn('INDEPENDENT_HANDOFF_MANIFEST_REQUIRED', self.bind(rid, trusted_handoff_manifest=None)['reasons'])

    def test_wrong_handoff_domain(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m['domain'] = 'attacker-domain'
        self.assertIn('HANDOFF_SCHEMA_OR_DOMAIN_INVALID', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_wrong_handoff_version(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m['schema_version'] = True
        self.assertIn('HANDOFF_SCHEMA_OR_DOMAIN_INVALID', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_sanitized_bytes_cannot_claim_original_binding(self):
        rid = self.store()['record_id']
        import hashlib
        m = dict(self.manifest)
        m['raw_request_sha256'] = hashlib.sha256(REQUEST.replace(b'FAKE-SYNTHETIC-SECRET', b'[REDACTED]')).hexdigest()
        self.assertIn('ESCROW_HANDOFF_BINDING_MISMATCH:raw_request_sha256',
                      self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_request_digest_mismatch(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m['raw_request_sha256'] = 'a'*64
        self.assertIn('ESCROW_HANDOFF_BINDING_MISMATCH:raw_request_sha256', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_response_digest_mismatch(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m['raw_response_sha256'] = 'a'*64
        self.assertIn('ESCROW_HANDOFF_BINDING_MISMATCH:raw_response_sha256', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_capture_id_mismatch(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m['capture_id'] = 'other'
        self.assertIn('ESCROW_HANDOFF_BINDING_MISMATCH:capture_id', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_run_id_mismatch(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m['analysis_run_id'] = 'other'
        self.assertIn('ESCROW_HANDOFF_BINDING_MISMATCH:analysis_run_id', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_missing_manifest_field(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m.pop('capture_id')
        self.assertIn('HANDOFF_BINDING_FIELDS_INVALID', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_invalid_manifest_digest(self):
        rid = self.store()['record_id']
        m = dict(self.manifest); m['raw_request_sha256'] = 'not-hex'
        self.assertIn('HANDOFF_BINDING_DIGEST_INVALID', self.bind(rid, trusted_handoff_manifest=m)['reasons'])

    def test_tamper_ciphertext(self):
        rid = self.store()['record_id']; p = self.root / (rid + '.escrow')
        obj = json.loads(p.read_bytes()); ct = bytearray(base64.b64decode(obj['ciphertext_b64']))
        ct[3] ^= 1; obj['ciphertext_b64'] = base64.b64encode(ct).decode()
        p.write_text(json.dumps(obj))
        self.assertIn('ESCROW_AUTHENTICATION_FAILED', self.bind(rid)['reasons'])

    def test_tamper_nonce(self):
        rid = self.store()['record_id']; p = self.root / (rid + '.escrow')
        obj = json.loads(p.read_bytes()); obj['nonce_b64'] = base64.b64encode(b'1'*12).decode()
        p.write_text(json.dumps(obj))
        self.assertIn('ESCROW_AUTHENTICATION_FAILED', self.bind(rid)['reasons'])

    def test_record_id_swapping(self):
        a = self.store()['record_id']; b = self.store()['record_id']
        p = self.root / (b + '.escrow'); p.write_bytes((self.root / (a + '.escrow')).read_bytes())
        self.assertIn('ESCROW_HEADER_INVALID', self.bind(b)['reasons'])

    def test_invalid_record_id_path_traversal(self):
        self.assertIn('RECORD_ID_INVALID', self.bind('../outside')['reasons'])

    def test_symlink_file_rejected(self):
        rid = self.store()['record_id']; p = self.root / (rid + '.escrow')
        elsewhere = Path(self.tmp.name) / 'elsewhere'; p.rename(elsewhere); p.symlink_to(elsewhere)
        self.assertIn('ESCROW_FILE_UNAVAILABLE', self.bind(rid)['reasons'])

    def test_symlink_directory_rejected(self):
        elsewhere = Path(self.tmp.name) / 'elsewhere'; elsewhere.mkdir(mode=0o700)
        self.root.symlink_to(elsewhere)
        with self.assertRaisesRegex(EscrowRejected, 'ESCROW_DIRECTORY_NOT_PRIVATE'):
            self.store()

    def test_world_readable_directory_rejected(self):
        self.root.mkdir(mode=0o700); self.root.chmod(0o755)
        with self.assertRaisesRegex(EscrowRejected, 'ESCROW_DIRECTORY_NOT_PRIVATE'):
            self.store()

    def test_world_readable_file_rejected(self):
        rid = self.store()['record_id']; (self.root / (rid + '.escrow')).chmod(0o644)
        self.assertIn('ESCROW_FILE_NOT_PRIVATE', self.bind(rid)['reasons'])

    def test_missing_record(self):
        self.root.mkdir(mode=0o700)
        self.assertIn('ESCROW_FILE_UNAVAILABLE', self.bind('a'*32)['reasons'])

    def test_oversize_request_rejected(self):
        with self.assertRaisesRegex(EscrowRejected, 'CAPTURE_SIZE_EXCEEDED'):
            self.store(raw_request=b'a'*(MAX_CAPTURE+1))

    def test_oversize_response_rejected(self):
        with self.assertRaisesRegex(EscrowRejected, 'CAPTURE_SIZE_EXCEEDED'):
            self.store(raw_response=b'a'*(MAX_CAPTURE+1))

    def test_nonbytes_request_rejected(self):
        with self.assertRaisesRegex(EscrowRejected, 'CAPTURE_BYTES_REQUIRED'):
            self.store(raw_request='bad')

    def test_empty_response_is_allowed_but_not_analysis_pass(self):
        rid = self.store(raw_response=b'')['record_id']
        m = dict(self.manifest)
        import hashlib
        m['raw_response_sha256'] = hashlib.sha256(b'').hexdigest()
        r = self.bind(rid, trusted_handoff_manifest=m)
        self.assertEqual(r['status'], 'OFFLINE_ESCROW_BINDING_MATCH_NOT_LIVE')
        self.assertFalse(r['engineering_accepted'])

    def test_missing_response_does_not_claim_results(self):
        rid = self.store()['record_id']
        r = self.bind(rid)
        self.assertNotIn('response', r)
        self.assertNotIn('request', r)

    def test_duplicate_records_distinct_ids_and_nonces(self):
        a = self.store()['record_id']; b = self.store()['record_id']
        self.assertNotEqual(a, b)
        obj_a = json.loads((self.root / (a + '.escrow')).read_text())
        obj_b = json.loads((self.root / (b + '.escrow')).read_text())
        self.assertNotEqual(obj_a['nonce_b64'], obj_b['nonce_b64'])

    def test_corrupt_json_hold(self):
        rid = self.store()['record_id']; (self.root / (rid + '.escrow')).write_text('{')
        self.assertIn('ESCROW_JSON_INVALID', self.bind(rid)['reasons'])

    def test_duplicate_json_keys_hold(self):
        rid = self.store()['record_id']; p = self.root / (rid + '.escrow')
        p.write_text('{"version":1,"version":1}')
        self.assertIn('ESCROW_DUPLICATE_JSON_KEY', self.bind(rid)['reasons'])

    def test_invalid_capture_id(self):
        with self.assertRaisesRegex(EscrowRejected, 'CAPTURE_ID_INVALID'):
            self.store(capture_id='\n')

    def test_missing_capture_id(self):
        with self.assertRaisesRegex(EscrowRejected, 'CAPTURE_ID_INVALID'):
            self.store(capture_id='')

    def test_no_pending_files_after_success(self):
        self.store()
        self.assertFalse(list(self.root.glob('.pending-*')))

    def test_storage_failure_not_claimed_success(self):
        with patch('offline_original_byte_escrow.os.link', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(EscrowRejected, 'ESCROW_STORAGE_FAILED'):
                self.store()
        self.assertFalse(list(self.root.glob('.pending-*')))
        self.assertFalse(list(self.root.glob('*.escrow')))

    def test_file_oversize_rejected(self):
        rid = self.store()['record_id']; p = self.root / (rid + '.escrow')
        with p.open('ab') as f:
            f.truncate(12 * 1024 * 1024 + 1)
        self.assertIn('ESCROW_FILE_SIZE_INVALID', self.bind(rid)['reasons'])


if __name__ == '__main__':
    unittest.main()
