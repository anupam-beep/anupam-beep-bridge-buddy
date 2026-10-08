"""Independent signed-handoff + encrypted-original-byte escrow cross-gate tests.

All evidence, signatures, keys and results are synthetic; no Civil NX access.
"""
import copy
import tempfile
import unittest
from pathlib import Path

from offline_original_byte_escrow import escrow_capture, verify_escrow_binding
import test_offline_evidence_handoff as handoff_fixture
from test_offline_result_certifier import RESPONSE

KEY = b'c' * 32


class EscrowHandoffIntegrationDojo(unittest.TestCase):
    def setUp(self):
        self.fixture = handoff_fixture.TestOfflineEvidenceHandoff('test_synthetic_handoff_passes_only_offline')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / 'vault'
        f = self.fixture
        self.record = escrow_capture(directory=self.directory, key=KEY,
            capture_id=f.manifest['capture_id'],
            analysis_run_id=f.manifest['analysis_run_id'],
            raw_request=f.request, raw_response=RESPONSE)

    def check(self, **changes):
        args = dict(directory=self.directory, key=KEY,
                    record_id=self.record['record_id'],
                    trusted_handoff_manifest=self.fixture.manifest)
        args.update(changes)
        return verify_escrow_binding(**args)

    def test_signed_handoff_and_escrow_both_pass_only_offline(self):
        self.assertEqual(self.fixture.check()['status'], 'OFFLINE_HANDOFF_CONSISTENT_NOT_LIVE')
        result = self.check()
        self.assertEqual(result['status'], 'OFFLINE_ESCROW_BINDING_MATCH_NOT_LIVE')
        self.assertFalse(result['live_verified'])
        self.assertFalse(result['engineering_accepted'])

    def test_forged_manifest_digest_rejected_by_escrow(self):
        m = copy.deepcopy(self.fixture.manifest)
        m['raw_request_sha256'] = '0' * 64
        self.assertEqual(self.check(trusted_handoff_manifest=m)['status'], 'HOLD')

    def test_wrong_analysis_run_rejected_by_escrow(self):
        m = copy.deepcopy(self.fixture.manifest)
        m['analysis_run_id'] = 'another-run'
        self.assertEqual(self.check(trusted_handoff_manifest=m)['status'], 'HOLD')

    def test_empty_response_cannot_reuse_original_result_manifest(self):
        f = self.fixture
        record = escrow_capture(directory=self.directory, key=KEY,
            capture_id=f.manifest['capture_id'], analysis_run_id=f.manifest['analysis_run_id'],
            raw_request=f.request, raw_response=b'{"message":""}')
        result = self.check(record_id=record['record_id'])
        self.assertEqual(result['status'], 'HOLD')
        self.assertIn('ESCROW_HANDOFF_BINDING_MISMATCH:raw_response_sha256', result['reasons'])

    def test_signed_handoff_failure_cannot_be_overridden_by_escrow(self):
        # The escrow hash match is not a certification decision and cannot
        # override an independently rejected attestation signature.
        self.assertEqual(self.check()['status'], 'OFFLINE_ESCROW_BINDING_MATCH_NOT_LIVE')
        result = self.fixture.check(analysis_signature_hex='00' * 64)
        self.assertEqual(result['status'], 'HOLD')
        self.assertFalse(result['engineering_accepted'])


if __name__ == '__main__':
    unittest.main()
