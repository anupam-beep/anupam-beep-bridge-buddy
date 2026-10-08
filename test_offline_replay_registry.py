"""Synthetic-only Bridge Dojo. No MIDAS connection or real witness is used."""
import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path

from offline_replay_registry import OfflineReplayRegistry, RegistryHold, GENESIS
from test_independent_capture_receipt import make_fixture
from test_offline_result_certifier import MODEL_BYTES, RESPONSE


class TestOfflineReplayRegistry(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'audit.sqlite3'
        self.registry = OfflineReplayRegistry(self.path)
        self.genesis = {'count': 0, 'head': GENESIS}

    def tearDown(self):
        self.registry.close()
        self.temp.cleanup()

    def fixture(self, capture_id='SYNTHETIC-CAPTURE-001'):
        env, req, att, att_sig, analysis_pub, witness_pub, receipt, sign = make_fixture()
        receipt['capture_id'] = capture_id
        return dict(envelope=env, model_bytes=MODEL_BYTES, response_bytes=RESPONSE,
                    raw_request=req, analysis_attestation=att,
                    analysis_signature_hex=att_sig, pinned_analysis_public_key=analysis_pub,
                    receipt=receipt, receipt_signature_hex=sign(),
                    pinned_collector_id=receipt['collector_id'], pinned_capture_public_key=witness_pub)

    def add(self, checkpoint=None, capture_id='SYNTHETIC-CAPTURE-001'):
        return self.registry.accept_signed_receipt(
            pinned_checkpoint=checkpoint if checkpoint is not None else self.genesis,
            **self.fixture(capture_id))

    def test_empty_registry_is_genesis(self):
        self.assertEqual(self.registry.audit(self.genesis)['status'], 'CHAIN_MATCHES_PINNED_CHECKPOINT')

    def test_one_valid_synthetic_receipt_appended(self):
        result = self.add()
        self.assertEqual(result['status'], 'OFFLINE_RECEIPT_REGISTERED')
        self.assertEqual(self.registry.audit(result['checkpoint_to_pin_independently'])['count'], 1)
        self.assertFalse(result['live_verified'])
        self.assertFalse(result['engineering_accepted'])

    def test_two_sequential_receipts_with_pinned_checkpoint(self):
        cp = self.add()['checkpoint_to_pin_independently']
        cp2 = self.add(cp, 'SYNTHETIC-CAPTURE-002')['checkpoint_to_pin_independently']
        self.assertEqual(self.registry.audit(cp2)['count'], 2)

    def test_replay_duplicate_capture_id_fails(self):
        cp = self.add()['checkpoint_to_pin_independently']
        with self.assertRaisesRegex(RegistryHold, 'CAPTURE_REPLAY_DETECTED'):
            self.add(cp)
        self.assertEqual(self.registry.audit(cp)['count'], 1)

    def test_stale_pinned_checkpoint_fails(self):
        cp = self.add()['checkpoint_to_pin_independently']
        with self.assertRaisesRegex(RegistryHold, 'INDEPENDENT_CHECKPOINT_MISMATCH'):
            self.add(self.genesis, 'SYNTHETIC-CAPTURE-002')
        self.assertEqual(self.registry.audit(cp)['count'], 1)

    def test_no_checkpoint_fails_closed(self):
        with self.assertRaisesRegex(RegistryHold, 'INDEPENDENT_CHECKPOINT_REQUIRED'):
            self.registry.accept_signed_receipt(pinned_checkpoint=None, **self.fixture())

    def test_forged_signature_not_inserted(self):
        args = self.fixture()
        args['receipt_signature_hex'] = '00'*64
        with self.assertRaisesRegex(RegistryHold, 'RECEIPT_VERIFICATION_HOLD'):
            self.registry.accept_signed_receipt(pinned_checkpoint=self.genesis, **args)
        self.assertEqual(self.registry.audit(self.genesis)['count'], 0)

    def test_invalid_analysis_binding_not_inserted(self):
        args = self.fixture()
        args['envelope']['binding']['result_analysis_run_id'] = 'FORGED'
        with self.assertRaisesRegex(RegistryHold, 'RECEIPT_VERIFICATION_HOLD'):
            self.registry.accept_signed_receipt(pinned_checkpoint=self.genesis, **args)
        self.assertEqual(self.registry.audit(self.genesis)['count'], 0)

    def test_append_only_update_trigger(self):
        self.add()
        with self.assertRaisesRegex(sqlite3.DatabaseError, 'APPEND_ONLY'):
            self.registry.db.execute("UPDATE entries SET collector_id='X' WHERE seq=1")

    def test_append_only_delete_trigger(self):
        self.add()
        with self.assertRaisesRegex(sqlite3.DatabaseError, 'APPEND_ONLY'):
            self.registry.db.execute('DELETE FROM entries WHERE seq=1')

    def test_tamper_detected_even_after_trigger_bypass(self):
        self.add()
        self.registry.db.execute('DROP TRIGGER entries_no_update')  # simulate DB administrator tampering
        self.registry.db.execute("UPDATE entries SET collector_id='FORGED' WHERE seq=1")
        with self.assertRaisesRegex(RegistryHold, 'CHAIN_CORRUPTION'):
            self.registry.audit()

    def test_truncation_detected_only_with_independent_checkpoint(self):
        cp = self.add()['checkpoint_to_pin_independently']
        self.registry.db.execute('DROP TRIGGER entries_no_delete')
        self.registry.db.execute('DELETE FROM entries WHERE seq=1')
        self.assertEqual(self.registry.audit()['status'], 'LOCAL_CHAIN_ONLY')
        with self.assertRaisesRegex(RegistryHold, 'INDEPENDENT_CHECKPOINT_MISMATCH'):
            self.registry.audit(cp)

    def test_persistent_reopen_audit(self):
        cp = self.add()['checkpoint_to_pin_independently']
        self.registry.close()
        self.registry = OfflineReplayRegistry(self.path)
        self.assertEqual(self.registry.audit(cp)['count'], 1)

    def test_invalid_checkpoint_count_type(self):
        with self.assertRaisesRegex(RegistryHold, 'INVALID_INDEPENDENT_CHECKPOINT'):
            self.registry.audit({'count': True, 'head': GENESIS})

    def test_second_connection_stale_checkpoint_rejected(self):
        cp = self.add()['checkpoint_to_pin_independently']
        with OfflineReplayRegistry(self.path) as second:
            with self.assertRaisesRegex(RegistryHold, 'INDEPENDENT_CHECKPOINT_MISMATCH'):
                second.accept_signed_receipt(pinned_checkpoint=self.genesis,
                                             **self.fixture('SYNTHETIC-CAPTURE-002'))
        self.assertEqual(self.registry.audit(cp)['count'], 1)

    def test_no_raw_payload_persisted(self):
        self.add()
        raw = self.path.read_bytes()
        self.assertNotIn(MODEL_BYTES, raw)
        self.assertNotIn(RESPONSE, raw)
        self.assertNotIn(b'POST /post/TABLE HTTP/1.1', raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
