"""Bridge Dojo: synthetic-only end-to-end handoff, with adversarial negatives."""
import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from independent_checkpoint_anchor import DOMAIN as ANCHOR_DOMAIN, _digest
from offline_evidence_handoff import handoff_manifest, verify_handoff
from offline_replay_registry import OfflineReplayRegistry, GENESIS
from offline_result_certifier import canonical_bytes
from test_independent_capture_receipt import make_fixture
from test_offline_result_certifier import MODEL_BYTES, RESPONSE

NOW = datetime(2026, 10, 8, 6, 20, tzinfo=timezone.utc)
PUB = lambda key: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

class TestOfflineEvidenceHandoff(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.registry = OfflineReplayRegistry(Path(self.temp.name)/'registry.sqlite')
        self.env, self.request, self.att, self.att_sig, self.analysis_pub, self.capture_pub, self.receipt, sign = make_fixture()
        self.receipt_sig = sign()
        self.anchor_key = Ed25519PrivateKey.generate()
        self.cp = self.registry.accept_signed_receipt(
            pinned_checkpoint={'count': 0, 'head': GENESIS},
            envelope=self.env, model_bytes=MODEL_BYTES, response_bytes=RESPONSE,
            raw_request=self.request, analysis_attestation=self.att,
            analysis_signature_hex=self.att_sig, pinned_analysis_public_key=self.analysis_pub,
            receipt=self.receipt, receipt_signature_hex=self.receipt_sig,
            pinned_collector_id=self.receipt['collector_id'], pinned_capture_public_key=self.capture_pub,
        )['checkpoint_to_pin_independently']
        self.anchor = {'schema_version':1, 'domain':ANCHOR_DOMAIN,
            'registry_id':'synthetic-registry', 'anchor_id':'synthetic-anchor',
            'checkpoint':copy.deepcopy(self.cp),
            'issued_at':'2026-10-08T05:00:00+00:00',
            'expires_at':'2026-10-08T15:00:00+00:00'}
        self.anchor_sig = self.anchor_key.sign(canonical_bytes(self.anchor)).hex()
        self.policy = {'registry_id':self.anchor['registry_id'],
            'anchor_id':self.anchor['anchor_id'],
            'pinned_public_key':PUB(self.anchor_key),
            'latest_checkpoint':copy.deepcopy(self.cp),
            'latest_anchor_sha256':_digest(self.anchor,bytes.fromhex(self.anchor_sig)),
            'source':'INDEPENDENT_OUT_OF_BAND_PIN'}
        self.manifest = handoff_manifest(envelope=self.env, raw_request=self.request,
            response_bytes=RESPONSE, receipt=self.receipt,
            receipt_signature_hex=self.receipt_sig, checkpoint=self.cp)

    def tearDown(self):
        self.registry.close()
        self.temp.cleanup()

    def check(self, **updates):
        kwargs=dict(manifest=self.manifest,envelope=self.env,model_bytes=MODEL_BYTES,
            raw_request=self.request,response_bytes=RESPONSE,
            analysis_attestation=self.att,analysis_signature_hex=self.att_sig,
            pinned_analysis_public_key=self.analysis_pub,receipt=self.receipt,
            receipt_signature_hex=self.receipt_sig,pinned_collector_id=self.receipt['collector_id'],
            pinned_capture_public_key=self.capture_pub,registry=self.registry,
            anchor=self.anchor,anchor_signature_hex=self.anchor_sig,
            independent_policy=self.policy,trusted_now=NOW)
        kwargs.update(updates)
        return verify_handoff(**kwargs)

    def assert_hold(self, needle=None, **kwargs):
        result=self.check(**kwargs)
        self.assertEqual(result['status'],'HOLD')
        if needle:self.assertTrue(any(needle in reason for reason in result['reasons']),result)
        self.assertFalse(result['live_verified'])
        self.assertFalse(result['engineering_accepted'])

    def test_synthetic_handoff_passes_only_offline(self):
        r=self.check()
        self.assertEqual(r['status'],'OFFLINE_HANDOFF_CONSISTENT_NOT_LIVE')
        self.assertFalse(r['live_verified'])
        self.assertFalse(r['engineering_accepted'])

    def test_empty_http_response_rejected(self):
        self.assert_hold('CAPTURE_AND_PROVENANCE_HOLD',response_bytes=b'{"message":""}')

    def test_modified_raw_request_rejected(self):
        self.assert_hold('CAPTURE_AND_PROVENANCE_HOLD',raw_request=self.request+b' ')

    def test_forged_analysis_signature_rejected(self):
        self.assert_hold('CAPTURE_AND_PROVENANCE_HOLD',analysis_signature_hex='00'*64)

    def test_forged_capture_signature_rejected(self):
        self.assert_hold('CAPTURE_AND_PROVENANCE_HOLD',receipt_signature_hex='00'*64)

    def test_missing_manifest_rejected(self):
        self.assert_hold('HANDOFF_SCHEMA_INVALID',manifest=None)

    def test_extra_manifest_field_rejected(self):
        m=copy.deepcopy(self.manifest);m['mapi_key']='DO_NOT_ALLOW'
        self.assert_hold('HANDOFF_SCHEMA_INVALID',manifest=m)

    def test_wrong_manifest_request_hash_rejected(self):
        m=copy.deepcopy(self.manifest);m['raw_request_sha256']='0'*64
        self.assert_hold('HANDOFF_BINDING_MISMATCH:raw_request_sha256',manifest=m)

    def test_wrong_manifest_capture_id_rejected(self):
        m=copy.deepcopy(self.manifest);m['capture_id']='other'
        self.assert_hold('HANDOFF_BINDING_MISMATCH:capture_id',manifest=m)

    def test_manifest_wrong_checkpoint_rejected(self):
        m=copy.deepcopy(self.manifest);m['checkpoint']={'count':0,'head':GENESIS}
        self.assert_hold('HANDOFF_BINDING_MISMATCH:checkpoint',manifest=m)

    def test_unpinned_anchor_rejected(self):
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD',independent_policy=None)

    def test_wrong_anchor_signature_rejected(self):
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD',anchor_signature_hex='00'*64)

    def test_stale_anchor_rejected(self):
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD',trusted_now=datetime(2026,10,9,tzinfo=timezone.utc))

    def test_untrusted_source_rejected(self):
        p=copy.deepcopy(self.policy);p['source']='LOCAL_SQLITE'
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD',independent_policy=p)

    def test_registry_rollback_rejected(self):
        self.registry.db.execute('DROP TRIGGER entries_no_delete')
        self.registry.db.execute('DELETE FROM entries')
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD')

    def test_registry_entry_absent_even_if_chain_anchored(self):
        # A correctly signed anchor for a different capture is not inclusion proof.
        m=copy.deepcopy(self.manifest);m['capture_id']='nonexistent'
        self.assert_hold('HANDOFF_BINDING_MISMATCH:capture_id',manifest=m)

    def test_no_raw_http_or_credentials_in_manifest(self):
        serialized=canonical_bytes(self.manifest)
        self.assertNotIn(b'POST /post/TABLE',serialized)
        self.assertNotIn(b'MAPI',serialized)
        self.assertNotIn(MODEL_BYTES,serialized)
        self.assertNotIn(RESPONSE,serialized)

    def test_registry_row_capture_id_mismatch_rejected(self):
        # Simulate an attacker with database write access bypassing trigger;
        # anchored chain audit must still detect the modified row.
        self.registry.db.execute('DROP TRIGGER entries_no_update')
        self.registry.db.execute("UPDATE entries SET capture_id='forged' WHERE seq=1")
        self.assert_hold('INDEPENDENT_ANCHOR_HOLD')

    def test_invalid_manifest_version_rejected(self):
        m=copy.deepcopy(self.manifest);m['schema_version']=True
        self.assert_hold('HANDOFF_VERSION_OR_DOMAIN_INVALID',manifest=m)

    def test_signed_receipt_mismatch_rejected(self):
        m=copy.deepcopy(self.manifest);m['signed_receipt_sha256']='f'*64
        self.assert_hold('HANDOFF_BINDING_MISMATCH:signed_receipt_sha256',manifest=m)

if __name__=='__main__': unittest.main(verbosity=2)
