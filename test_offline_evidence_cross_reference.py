"""Synthetic-only adversarial Bridge Dojo for E1-E6 evidence cross-reference."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from offline_evidence_cross_reference import verify_evidence_cross_reference, STATUS_PASS
from offline_result_certifier import canonical_bytes
import test_offline_evidence_handoff as _fixture
MODEL_BYTES, RESPONSE, NOW = _fixture.MODEL_BYTES, _fixture.RESPONSE, _fixture.NOW


class TestOfflineEvidenceCrossReference(unittest.TestCase):
    def setUp(self):
        # Reuse established synthetic fixture without copying private keys or
        # contacting any Civil NX service. All files are disposable test data.
        _fixture.TestOfflineEvidenceHandoff.setUp(self)
        self.artifacts = Path(self.temp.name) / 'synthetic-evidence'
        self.artifacts.mkdir()
        self.payloads = {
            'E1': MODEL_BYTES,
            'E2': canonical_bytes(self.att) + bytes.fromhex(self.att_sig),
            'E3': self.request,
            'E4': RESPONSE,
            'E5': canonical_bytes(self.receipt) + bytes.fromhex(self.receipt_sig),
            'E6': canonical_bytes(self.anchor) + bytes.fromhex(self.anchor_sig),
        }
        self.claims = {'schema_version': 1,
                       'capture_id': self.receipt['capture_id'],
                       'artifacts': []}
        for gate, payload in self.payloads.items():
            (self.artifacts / (gate + '.bin')).write_bytes(payload)
            self.claims['artifacts'].append({
                'gate': gate, 'relative_path': gate + '.bin',
                'sha256': hashlib.sha256(payload).hexdigest()})
        self.kwargs = dict(
            artifact_root=self.artifacts, manifest=self.manifest,
            envelope=self.env, model_bytes=MODEL_BYTES, raw_request=self.request,
            response_bytes=RESPONSE, analysis_attestation=self.att,
            analysis_signature_hex=self.att_sig,
            pinned_analysis_public_key=self.analysis_pub,
            receipt=self.receipt, receipt_signature_hex=self.receipt_sig,
            pinned_collector_id=self.receipt['collector_id'],
            pinned_capture_public_key=self.capture_pub, registry=self.registry,
            anchor=self.anchor, anchor_signature_hex=self.anchor_sig,
            independent_policy=self.policy, trusted_now=NOW)

    def tearDown(self):
        _fixture.TestOfflineEvidenceHandoff.tearDown(self)

    def run_gate(self, claims=None, **updates):
        kw = self.kwargs.copy()
        kw.update(updates)
        raw = json.dumps(self.claims if claims is None else claims).encode('utf-8')
        return verify_evidence_cross_reference(claims_raw=raw, **kw)

    def assert_hold(self, needle=None, claims=None, **updates):
        result = self.run_gate(claims, **updates)
        self.assertEqual(result['status'], 'HOLD', result)
        if needle:
            self.assertTrue(any(needle in x for x in result['reasons']), result)
        self.assertFalse(result['live_verified'])
        self.assertFalse(result['engineering_accepted'])
        self.assertFalse(result['result_extraction_verified'])
        return result

    def test_synthetic_e1_e6_chain_consistent_not_live(self):
        r = self.run_gate()
        self.assertEqual(r['status'], STATUS_PASS, r)
        self.assertEqual(r['verified_gate_count'], 6)
        self.assertFalse(r['result_extraction_verified'])
        self.assertFalse(r['civil_nx_contacted'])

    def test_capture_id_mismatch(self):
        c = copy.deepcopy(self.claims)
        c['capture_id'] = 'other'
        self.assert_hold('CAPTURE_ID_CROSS_REFERENCE_MISMATCH', c)

    def test_missing_each_gate(self):
        for gate in self.payloads:
            with self.subTest(gate=gate):
                c = copy.deepcopy(self.claims)
                c['artifacts'] = [a for a in c['artifacts'] if a['gate'] != gate]
                self.assert_hold('GATE_CARDINALITY_INVALID:' + gate, c)

    def test_duplicate_each_gate(self):
        for gate in self.payloads:
            with self.subTest(gate=gate):
                c = copy.deepcopy(self.claims)
                a = next(a for a in c['artifacts'] if a['gate'] == gate)
                c['artifacts'].append({**a, 'relative_path': gate + '-other.bin'})
                self.assert_hold('GATE_CARDINALITY_INVALID:' + gate, c)

    def test_wrong_digest_each_gate(self):
        for gate in self.payloads:
            with self.subTest(gate=gate):
                c = copy.deepcopy(self.claims)
                next(a for a in c['artifacts'] if a['gate'] == gate)['sha256'] = '0'*64
                self.assert_hold('GATE_BYTES_BINDING_MISMATCH:' + gate, c)

    def test_missing_artifact_each_gate(self):
        for gate in self.payloads:
            with self.subTest(gate=gate):
                p = self.artifacts / (gate + '.bin')
                data = p.read_bytes(); p.unlink()
                self.assert_hold('INVENTORY_GATE_UNVERIFIED:' + gate)
                p.write_bytes(data)

    def test_tampered_artifact_each_gate(self):
        for gate in self.payloads:
            with self.subTest(gate=gate):
                p = self.artifacts / (gate + '.bin')
                data = p.read_bytes(); p.write_bytes(data + b'\x00')
                self.assert_hold('INVENTORY_GATE_UNVERIFIED:' + gate)
                p.write_bytes(data)

    def test_original_request_changed(self):
        self.assert_hold('GATE_BYTES_BINDING_MISMATCH:E3', raw_request=self.request+b' ')

    def test_original_response_changed(self):
        self.assert_hold('GATE_BYTES_BINDING_MISMATCH:E4', response_bytes=b'{"message":""}')

    def test_model_bytes_changed(self):
        self.assert_hold('GATE_BYTES_BINDING_MISMATCH:E1', model_bytes=b'model-forged')

    def test_analysis_signature_changed(self):
        self.assert_hold('GATE_BYTES_BINDING_MISMATCH:E2', analysis_signature_hex='00'*64)

    def test_receipt_signature_changed(self):
        self.assert_hold('GATE_BYTES_BINDING_MISMATCH:E5', receipt_signature_hex='00'*64)

    def test_anchor_signature_changed(self):
        self.assert_hold('GATE_BYTES_BINDING_MISMATCH:E6', anchor_signature_hex='00'*64)

    def test_analysis_and_anchor_key_reuse_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy['pinned_public_key'] = self.analysis_pub
        self.assert_hold('TRUST_ROLES_NOT_KEY_SEPARATED', independent_policy=policy)

    def test_capture_and_anchor_key_reuse_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy['pinned_public_key'] = self.capture_pub
        self.assert_hold('TRUST_ROLES_NOT_KEY_SEPARATED', independent_policy=policy)

    def test_capture_and_analysis_key_reuse_rejected(self):
        self.assert_hold('TRUST_ROLES_NOT_KEY_SEPARATED', pinned_capture_public_key=self.analysis_pub)

    def test_missing_independent_policy_rejected(self):
        self.assert_hold('INDEPENDENT_TRUST_POLICY_REQUIRED', independent_policy=None)

    def test_untrusted_policy_source_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy['source'] = 'LOCAL_DB'
        self.assert_hold('HANDOFF_OR_ANCHOR_HOLD', independent_policy=policy)

    def test_stale_anchor_pin_rejected(self):
        policy = copy.deepcopy(self.policy)
        policy['latest_anchor_sha256'] = '0'*64
        self.assert_hold('HANDOFF_OR_ANCHOR_HOLD', independent_policy=policy)

    def test_modified_registry_row_rejected(self):
        self.registry.db.execute('DROP TRIGGER entries_no_update')
        self.registry.db.execute("UPDATE entries SET capture_id='forged' WHERE seq=1")
        self.assert_hold('HANDOFF_OR_ANCHOR_HOLD')

    def test_manifest_capture_id_mismatch(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['capture_id'] = 'other'
        self.assert_hold('CAPTURE_ID_CROSS_REFERENCE_MISMATCH', manifest=manifest)

    def test_manifest_response_digest_mismatch(self):
        manifest = copy.deepcopy(self.manifest)
        manifest['raw_response_sha256'] = '0'*64
        self.assert_hold('HANDOFF_OR_ANCHOR_HOLD', manifest=manifest)

    def test_invalid_raw_type_rejected(self):
        self.assert_hold('EVIDENCE_BYTES_TYPE_INVALID', raw_request='POST /post/TABLE')

    def test_missing_artifact_root_rejected_without_path_leak(self):
        r = self.assert_hold('CROSS_REFERENCE_INPUT_OR_IO_REJECTED', artifact_root=self.artifacts/'missing')
        self.assertNotIn(str(self.artifacts), json.dumps(r))

    def test_malformed_claims_fail_closed(self):
        r = verify_evidence_cross_reference(claims_raw=b'{bad', **self.kwargs)
        self.assertEqual(r['status'], 'HOLD')
        self.assertEqual(r['reasons'], ['CROSS_REFERENCE_INPUT_OR_IO_REJECTED'])

    def test_duplicate_json_key_rejected(self):
        raw = b'{"schema_version":1,"schema_version":1,"capture_id":"x","artifacts":[]}'
        r = verify_evidence_cross_reference(claims_raw=raw, **self.kwargs)
        self.assertEqual(r['status'], 'HOLD')

    def test_e7_not_an_engineering_acceptance(self):
        c = copy.deepcopy(self.claims)
        (self.artifacts/'E7.bin').write_bytes(b'synthetic engineering note')
        c['artifacts'].append({'gate': 'E7', 'relative_path': 'E7.bin',
            'sha256': hashlib.sha256(b'synthetic engineering note').hexdigest()})
        r = self.run_gate(c)
        self.assertEqual(r['status'], STATUS_PASS)
        self.assertFalse(r['engineering_accepted'])

    def test_no_sensitive_bytes_ids_paths_in_output(self):
        r = self.run_gate()
        encoded = json.dumps(r)
        for secret in ('SYNTHETIC-CAPTURE-001', str(self.artifacts),
                       'POST /post/TABLE', 'MAPI', 'SYNTHETIC-RUN'):
            self.assertNotIn(secret, encoded)

    def test_symlink_rejected(self):
        target = self.artifacts/'E1.bin'
        target.unlink()
        try:
            target.symlink_to(self.artifacts/'E2.bin')
        except (OSError, NotImplementedError):
            self.skipTest('symlink unsupported')
        self.assert_hold('CROSS_REFERENCE_INPUT_OR_IO_REJECTED')

    def test_invalid_anchor_public_key_rejected(self):
        p = copy.deepcopy(self.policy); p['pinned_public_key'] = b'x'
        self.assert_hold('INDEPENDENT_TRUST_KEYS_REQUIRED', independent_policy=p)


if __name__ == '__main__':
    unittest.main(verbosity=2)
