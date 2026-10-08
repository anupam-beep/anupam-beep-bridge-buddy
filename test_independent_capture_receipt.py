"""Synthetic-only Bridge Dojo; ephemeral keys do not attest real MIDAS events."""
import copy
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from independent_capture_receipt import verify_with_capture, verify_capture_receipt, signed_attestation_hash
from offline_result_certifier import canonical_bytes, digest
from test_independent_attestation import setup
from test_offline_result_certifier import MODEL_BYTES, RESPONSE


def make_fixture():
    env, request, attestation, att_sig, analysis_pub = setup()
    witness_key = Ed25519PrivateKey.generate()  # TEST-ONLY
    witness_pub = witness_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    receipt = {
        'schema_version': 1,
        'event': 'CIVIL_NX_RESULT_CAPTURED',
        'capture_id': 'SYNTHETIC-CAPTURE-001',
        'collector_id': 'SYNTHETIC-WITNESS-NOT-DEPLOYED',
        'model_sha256': env['model_evidence']['sha256'],
        'authorization_id': env['authorization']['authorization_id'],
        'analysis_run_id': env['analysis']['run_id'],
        'signed_analysis_attestation_sha256': signed_attestation_hash(attestation, att_sig),
        'raw_request_sha256': digest(request),
        'raw_response_sha256': digest(RESPONSE),
        'sent_at': '2026-01-01T10:30:20+00:00',
        'received_at': '2026-01-01T10:31:00+00:00',
        'http_status': 200,
        'method': 'POST',
        'path': '/post/TABLE',
    }
    def sign():
        return witness_key.sign(canonical_bytes(receipt)).hex()
    return env, request, attestation, att_sig, analysis_pub, witness_pub, receipt, sign

class TestCaptureReceipt(unittest.TestCase):
    def check(self, mutate=None, expect='HOLD', seen=frozenset(), same_key=False):
        env, req, att, att_sig, analysis_pub, witness_pub, receipt, sign = make_fixture()
        if mutate:
            mutate(env, receipt)
        sig=sign()
        if same_key:
            witness_pub=analysis_pub
        result=verify_with_capture(env, MODEL_BYTES, RESPONSE, req, att, att_sig,
                                   analysis_pub, receipt, sig, receipt['collector_id'],
                                   witness_pub, previously_seen_capture_ids=seen)
        self.assertEqual(result['status'], expect, result)
        self.assertFalse(result['live_verified'])
        self.assertFalse(result['engineering_accepted'])
        return result

    def test_synthetic_all_pass(self): self.check(expect='OFFLINE_EVIDENCE_GATES_PASS')
    def test_wrong_run(self): self.check(lambda e,r: r.update(analysis_run_id='OTHER'))
    def test_wrong_model_hash(self): self.check(lambda e,r: r.update(model_sha256='0'*64))
    def test_wrong_auth(self): self.check(lambda e,r: r.update(authorization_id='OTHER'))
    def test_wrong_request_hash(self): self.check(lambda e,r: r.update(raw_request_sha256='0'*64))
    def test_wrong_response_hash(self): self.check(lambda e,r: r.update(raw_response_sha256='0'*64))
    def test_wrong_analysis_attestation_hash(self): self.check(lambda e,r: r.update(signed_analysis_attestation_sha256='0'*64))
    def test_early_capture(self): self.check(lambda e,r: r.update(sent_at='2026-01-01T10:29:00+00:00'))
    def test_capture_duration_exceeded(self): self.check(lambda e,r: r.update(sent_at='2026-01-01T10:30:00+00:00',received_at='2026-01-01T10:40:00+00:00'))
    def test_capture_timestamp_mismatch(self): self.check(lambda e,r: r.update(received_at='2026-01-01T10:31:01+00:00'))
    def test_unzoned_capture_time(self): self.check(lambda e,r: r.update(sent_at='2026-01-01T10:30:20'))
    def test_duplicate_capture_id(self): self.check(seen={'SYNTHETIC-CAPTURE-001'})
    def test_invalid_status(self): self.check(lambda e,r: r.update(http_status=500))
    def test_boolean_status_not_accepted(self): self.check(lambda e,r: r.update(http_status=True))
    def test_wrong_path(self): self.check(lambda e,r: r.update(path='/db/STAG'))
    def test_unexpected_field(self): self.check(lambda e,r: r.update(untrusted_key='x'))
    def test_unpinned_collector_id(self):
        e,q,a,s,p,w,r,sign=make_fixture()
        self.assertEqual(verify_capture_receipt(e,q,RESPONSE,a,s,r,sign(),'DIFFERENT',w,p)['status'],'HOLD')
    def test_unpinned_witness_key(self):
        e,q,a,s,p,w,r,sign=make_fixture()
        self.assertEqual(verify_capture_receipt(e,q,RESPONSE,a,s,r,sign(),r['collector_id'],b'',p)['status'],'HOLD')
    def test_wrong_signature(self):
        e,q,a,s,p,w,r,sign=make_fixture()
        r['analysis_run_id']='TAMPERED'  # signed bytes changed, signature not refreshed
        sig=sign()
        r['analysis_run_id']='SYNTHETIC-RUN'
        self.assertEqual(verify_capture_receipt(e,q,RESPONSE,a,s,r,sig,r['collector_id'],w,p)['status'],'HOLD')
    def test_missing_signature(self):
        e,q,a,s,p,w,r,sign=make_fixture()
        self.assertEqual(verify_capture_receipt(e,q,RESPONSE,a,s,r,'',r['collector_id'],w,p)['status'],'HOLD')
    def test_invalid_capture_id(self): self.check(lambda e,r: r.update(capture_id=''))
    def test_missing_capture_field(self): self.check(lambda e,r: r.pop('raw_response_sha256'))
    def test_analysis_and_capture_key_same_rejected(self):
        e,q,a,s,p,w,r,sign=make_fixture()
        # Even with a correctly signed receipt, two independently pinned keys must differ.
        self.assertEqual(verify_capture_receipt(e,q,RESPONSE,a,s,r,sign(),r['collector_id'],p,p)['status'],'HOLD')
    def test_base_provenance_failure_even_with_valid_receipt(self):
        self.check(lambda e,r: e['binding'].update(result_analysis_run_id='OTHER'))
    def test_malformed_receipt(self):
        e,q,a,s,p,w,r,sign=make_fixture()
        self.assertEqual(verify_capture_receipt(e,q,RESPONSE,a,s,None,'',r['collector_id'],w,p)['status'],'HOLD')

if __name__ == '__main__': unittest.main(verbosity=2)
