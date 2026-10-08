"""Synthetic cross-gate adversarial Bridge Dojo; no Civil NX calls."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from offline_bundle_handoff_pipeline import verify_sanitized_bundle_handoff
from test_offline_capture_bundle_intake import make_zip
import test_offline_evidence_handoff as handoff_fixture
from test_offline_result_certifier import MODEL_BYTES, RESPONSE


def signed(record, signature):
    return json.dumps({'record': record, 'signature_hex': signature},
                      sort_keys=True, separators=(',', ':')).encode()


class IntegratedBundleDojo(unittest.TestCase):
    def setUp(self):
        self.base = handoff_fixture.TestOfflineEvidenceHandoff('test_synthetic_handoff_passes_only_offline')
        self.base.setUp()
        self.addCleanup(self.base.tearDown)
        b = self.base
        self.files = {
            'request.bin': b.request,
            'response.json': RESPONSE,
            'analysis_attestation.json': signed(b.att, b.att_sig),
            'capture_receipt.json': signed(b.receipt, b.receipt_sig),
            'checkpoint_anchor.json': signed(b.anchor, b.anchor_sig),
        }
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'evidence.zip'
        self.kwargs = dict(trusted_handoff_manifest=b.manifest, envelope=b.env,
            model_bytes=MODEL_BYTES, registry=b.registry,
            pinned_analysis_public_key=b.analysis_pub,
            pinned_collector_id=b.receipt['collector_id'],
            pinned_capture_public_key=b.capture_pub,
            independent_policy=b.policy, trusted_now=handoff_fixture.NOW)

    def check(self, *, files=None, zip_bytes=None, **updates):
        self.path.write_bytes(make_zip(self.files if files is None else files)
                              if zip_bytes is None else zip_bytes)
        args = dict(self.kwargs)
        args.update(updates)
        return verify_sanitized_bundle_handoff(bundle_path=self.path, **args)

    def assert_hold(self, needle=None, **kw):
        result = self.check(**kw)
        self.assertEqual(result['status'], 'HOLD', result)
        self.assertFalse(result['live_verified'])
        self.assertFalse(result['engineering_accepted'])
        self.assertFalse(result['civil_nx_contacted'])
        if needle:
            self.assertIn(needle, str(result['reasons']), result)
        return result

    def test_valid_synthetic_bundle_consistent_not_live(self):
        result = self.check()
        self.assertEqual(result['status'], 'OFFLINE_PIPELINE_CONSISTENT_NOT_LIVE', result)
        self.assertFalse(result['live_verified'])
        self.assertFalse(result['engineering_accepted'])

    def test_missing_independent_manifest(self):
        self.assert_hold('INDEPENDENT_HANDOFF_MANIFEST_REQUIRED', trusted_handoff_manifest=None)

    def test_tampered_request_with_rehashed_zip_manifest(self):
        files = dict(self.files); files['request.bin'] += b' '
        self.assert_hold('HANDOFF_BINDING_MISMATCH:raw_request_sha256', files=files)

    def test_tampered_response_with_rehashed_zip_manifest(self):
        files = dict(self.files); files['response.json'] += b' '
        self.assert_hold('HANDOFF_BINDING_MISMATCH:raw_response_sha256', files=files)

    def test_empty_http_200_response_with_valid_zip_manifest(self):
        files = dict(self.files); files['response.json'] = b'{"message":""}'
        self.assert_hold('CAPTURE_AND_PROVENANCE_HOLD', files=files)

    def test_wrong_capture_signature(self):
        files = dict(self.files)
        files['capture_receipt.json'] = signed(self.base.receipt, '00'*64)
        self.assert_hold('CAPTURE_SIGNATURE_INVALID', files=files)

    def test_wrong_analysis_signature(self):
        files = dict(self.files)
        files['analysis_attestation.json'] = signed(self.base.att, '00'*64)
        self.assert_hold('ATTESTATION_SIGNATURE_INVALID', files=files)

    def test_wrong_anchor_signature(self):
        files = dict(self.files)
        files['checkpoint_anchor.json'] = signed(self.base.anchor, '00'*64)
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD', files=files)

    def test_missing_independent_anchor_policy(self):
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD', independent_policy=None)

    def test_trust_key_from_wrong_signer(self):
        self.assert_hold('CAPTURE_AND_PROVENANCE_HOLD', pinned_capture_public_key=b'0'*32)

    def test_incorrect_model_evidence(self):
        self.assert_hold('MODEL_HASH_MISMATCH', model_bytes=b'wrong')

    def test_invalid_capture_wrapper(self):
        files = dict(self.files); files['capture_receipt.json'] = b'{"signed":true}'
        self.assert_hold('CAPTURE_WRAPPER_INVALID', files=files)

    def test_invalid_signature_format(self):
        files = dict(self.files)
        files['capture_receipt.json'] = signed(self.base.receipt, 'not-hex')
        self.assert_hold('CAPTURE_SIGNATURE_FORMAT_INVALID', files=files)

    def test_duplicate_json_key_rejected_at_intake(self):
        files = dict(self.files); files['response.json'] = b'{"x":1,"x":2}'
        self.assert_hold('INTAKE_DUPLICATE_JSON_KEY', files=files)

    def test_secret_in_zip_rejected_without_value_leak(self):
        files = dict(self.files); files['request.bin'] += b'\r\nMAPI-Key: TOPSECRET1234567'
        result = self.assert_hold('INTAKE_POTENTIAL_CREDENTIAL', files=files)
        self.assertNotIn('TOPSECRET', str(result))

    def test_zip_manifest_wrong_hash_rejected(self):
        import hashlib
        from test_offline_capture_bundle_intake import make_manifest
        manifest = make_manifest(self.files)
        manifest['artifacts'][0]['sha256'] = 'f'*64
        self.assert_hold('INTAKE_HASH_MISMATCH', zip_bytes=make_zip(self.files, manifest=manifest))

    def test_archive_missing_member_rejected(self):
        files = dict(self.files); files.pop('checkpoint_anchor.json')
        from test_offline_capture_bundle_intake import make_manifest
        self.assert_hold('INTAKE_UNEXPECTED_OR_MISSING_MEMBER',
                         zip_bytes=make_zip(files, manifest=make_manifest(self.files)))

    def test_capture_run_id_cross_gate_mismatch(self):
        files = dict(self.files)
        forged = dict(self.base.receipt); forged['analysis_run_id'] = 'OTHER'
        files['capture_receipt.json'] = signed(forged, self.base.receipt_sig)
        self.assert_hold('CAPTURE_AND_PROVENANCE_HOLD', files=files)

    def test_replayed_capture_missing_from_anchored_registry(self):
        self.base.registry.db.execute('DROP TRIGGER entries_no_delete')
        self.base.registry.db.execute('DELETE FROM entries')
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD')

    def test_stale_anchor(self):
        from datetime import datetime, timezone
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD', trusted_now=datetime(2026, 10, 10, tzinfo=timezone.utc))

    def test_bad_handoff_manifest_checkpoint(self):
        m = copy.deepcopy(self.base.manifest)
        m['checkpoint'] = {'count': 0, 'head': '0'*64}
        self.assert_hold('HANDOFF_BINDING_MISMATCH:checkpoint', trusted_handoff_manifest=m)

    def test_wrong_collector_identity(self):
        self.assert_hold('CAPTURE_COLLECTOR_ID_UNTRUSTED', pinned_collector_id='NOT-TRUSTED')

    def test_bundle_never_returns_raw_request_or_result(self):
        r = self.check()
        self.assertNotIn(self.base.request.decode(), str(r))
        self.assertNotIn(RESPONSE.decode(), str(r))
        self.assertNotIn('signature_hex', str(r))

if __name__ == '__main__': unittest.main(verbosity=2)
