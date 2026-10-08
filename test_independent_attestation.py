"""Synthetic-only, offline regression tests. No real signing authority."""
import copy
import json
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from independent_attestation import verify_all, verify_attestation, verify_http_request_bytes
from offline_result_certifier import canonical_bytes, digest
from test_offline_result_certifier import fixture, MODEL_BYTES, RESPONSE


def setup():
    envelope=fixture()
    selector=envelope['result_request']['selector']
    body=canonical_bytes({'Argument':selector})
    raw=b'POST /post/TABLE HTTP/1.1\r\nHost: synthetic.invalid\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
    envelope['result_request']['raw_http_sha256']=digest(raw)
    envelope['result_request']['raw_body_sha256']=digest(body)
    att={
      'schema_version':1,'event':'CIVIL_NX_ANALYSIS_COMPLETED',
      'model_sha256':envelope['model_evidence']['sha256'],
      'authorization_id':envelope['authorization']['authorization_id'],
      'run_id':envelope['analysis']['run_id'],
      'started_at':envelope['analysis']['started_at'],
      'completed_at':envelope['analysis']['completed_at'],
      'status':'COMPLETED',
    }
    # TEST-ONLY ephemeral signer. This is not a real analysis attestation.
    key=Ed25519PrivateKey.generate()
    pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    sig=key.sign(canonical_bytes(att)).hex()
    return envelope,raw,att,sig,pub

class TestIndependentAttestation(unittest.TestCase):
    def test_synthetic_all_passes_offline(self):
        e,r,a,s,p=setup()
        x=verify_all(e,MODEL_BYTES,RESPONSE,r,a,s,p)
        self.assertEqual(x['status'],'OFFLINE_EVIDENCE_GATES_PASS')
        self.assertFalse(x['live_verified'])
        self.assertFalse(x['engineering_accepted'])
    def test_missing_trust_anchor(self):
        e,r,a,s,p=setup()
        self.assertEqual(verify_attestation(e,a,s,b'')['status'],'HOLD')
    def test_wrong_trust_anchor(self):
        e,r,a,s,p=setup()
        other=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.assertEqual(verify_attestation(e,a,s,other)['status'],'HOLD')
    def test_modified_signed_run_id(self):
        e,r,a,s,p=setup(); a['run_id']='OTHER'
        self.assertEqual(verify_attestation(e,a,s,p)['status'],'HOLD')
    def test_modified_signed_completion(self):
        e,r,a,s,p=setup(); a['completed_at']='2026-01-01T10:31:00+00:00'
        self.assertEqual(verify_attestation(e,a,s,p)['status'],'HOLD')
    def test_missing_signature(self):
        e,r,a,s,p=setup()
        self.assertEqual(verify_attestation(e,a,'',p)['status'],'HOLD')
    def test_request_byte_changed_after_hash(self):
        e,r,a,s,p=setup()
        self.assertEqual(verify_http_request_bytes(r+b' ',e)['status'],'HOLD')
    def test_selector_body_mismatch_even_rehashed(self):
        e,r,a,s,p=setup()
        body=canonical_bytes({'Argument':{'TABLE_TYPE':'OTHER'}})
        changed=b'POST /post/TABLE HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        e['result_request']['raw_http_sha256']=digest(changed)
        e['result_request']['raw_body_sha256']=digest(body)
        self.assertEqual(verify_http_request_bytes(changed,e)['status'],'HOLD')
    def test_wrong_content_length(self):
        e,r,a,s,p=setup()
        changed=r.replace(b'Content-Length: ',b'Content-Length: 1',1)
        e['result_request']['raw_http_sha256']=digest(changed)
        self.assertEqual(verify_http_request_bytes(changed,e)['status'],'HOLD')
    def test_duplicate_content_length(self):
        e,r,a,s,p=setup()
        changed=r.replace(b'\r\n\r\n',b'\r\nContent-Length: 3\r\n\r\n',1)
        e['result_request']['raw_http_sha256']=digest(changed)
        self.assertEqual(verify_http_request_bytes(changed,e)['status'],'HOLD')
    def test_wrong_http_method(self):
        e,r,a,s,p=setup()
        changed=r.replace(b'POST /post/TABLE',b'GET /post/TABLE',1)
        e['result_request']['raw_http_sha256']=digest(changed)
        self.assertEqual(verify_http_request_bytes(changed,e)['status'],'HOLD')
    def test_duplicate_json_key_in_request_body(self):
        e,r,a,s,p=setup()
        selector=canonical_bytes(e['result_request']['selector'])
        # Duplicate Argument keys are ambiguous across parsers; must HOLD even if hashes updated.
        body=b'{"Argument":{},"Argument":'+selector+b'}'
        changed=b'POST /post/TABLE HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        e['result_request']['raw_http_sha256']=digest(changed)
        e['result_request']['raw_body_sha256']=digest(body)
        self.assertEqual(verify_http_request_bytes(changed,e)['status'],'HOLD')
    def test_nonfinite_json_constant_in_request(self):
        e,r,a,s,p=setup()
        body=b'{"Argument":'+canonical_bytes(e['result_request']['selector'])[:-1]+b',"EXTRA":NaN}}'
        changed=b'POST /post/TABLE HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        e['result_request']['raw_http_sha256']=digest(changed)
        e['result_request']['raw_body_sha256']=digest(body)
        self.assertEqual(verify_http_request_bytes(changed,e)['status'],'HOLD')
    def test_no_trust_anchor_holds_combined(self):
        e,r,a,s,p=setup()
        self.assertEqual(verify_all(e,MODEL_BYTES,RESPONSE,r,a,s,b'')['status'],'HOLD')
    def test_base_response_invalid_holds_combined(self):
        e,r,a,s,p=setup()
        self.assertEqual(verify_all(e,MODEL_BYTES,b'{"message":""}',r,a,s,p)['status'],'HOLD')
    def test_no_self_attested_trust_anchor(self):
        e,r,a,s,p=setup(); a['signer_public_key']=p.hex()
        self.assertEqual(verify_attestation(e,a,s,p)['status'],'HOLD')

if __name__=='__main__': unittest.main(verbosity=2)
