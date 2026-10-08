"""Synthetic-only trust anchor tests. Test keys never used outside fixtures."""
import copy
import sqlite3
import tempfile
import unittest
from datetime import datetime,timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

from offline_result_certifier import canonical_bytes
from offline_replay_registry import OfflineReplayRegistry, GENESIS
from independent_checkpoint_anchor import DOMAIN, _digest, verify_anchored_registry
from test_independent_capture_receipt import make_fixture
from test_offline_result_certifier import MODEL_BYTES, RESPONSE

NOW=datetime(2026,10,8,1,0,tzinfo=timezone.utc)

class TestIndependentCheckpointAnchor(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.dbpath=Path(self.tmp.name)/'registry.sqlite'
        self.registry=OfflineReplayRegistry(self.dbpath)
        self.key=Ed25519PrivateKey.generate()  # TEST-ONLY synthetic signer
        self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.cp={'count':0,'head':GENESIS}

    def tearDown(self):
        self.registry.close()
        self.tmp.cleanup()

    def append(self, capture_id='SYNTHETIC-ANCHOR-CAPTURE-1'):
        env,req,att,att_sig,analysis_pub,collector_pub,receipt,sign=make_fixture()
        receipt['capture_id']=capture_id
        result=self.registry.accept_signed_receipt(
            pinned_checkpoint=self.cp, envelope=env, model_bytes=MODEL_BYTES,
            response_bytes=RESPONSE, raw_request=req, analysis_attestation=att,
            analysis_signature_hex=att_sig, pinned_analysis_public_key=analysis_pub,
            receipt=receipt,receipt_signature_hex=sign(),
            pinned_collector_id=receipt['collector_id'],pinned_capture_public_key=collector_pub)
        self.cp=result['checkpoint_to_pin_independently']
        return self.cp

    def anchor(self, cp=None):
        doc={'schema_version':1,'domain':DOMAIN,'registry_id':'synthetic-bridge-registry',
             'anchor_id':'synthetic-independent-anchor','checkpoint':copy.deepcopy(cp or self.cp),
             'issued_at':'2026-10-08T00:00:00+00:00','expires_at':'2026-10-08T12:00:00+00:00'}
        sig=self.key.sign(canonical_bytes(doc))
        policy={'registry_id':doc['registry_id'],'anchor_id':doc['anchor_id'],
                'pinned_public_key':self.pub,'latest_checkpoint':copy.deepcopy(self.cp),
                'latest_anchor_sha256':_digest(doc,sig),
                'source':'INDEPENDENT_OUT_OF_BAND_PIN'}
        return doc,sig.hex(),policy

    def check(self, doc=None, sig=None, policy=None, now=NOW):
        if doc is None: doc,sig,policy=self.anchor()
        return verify_anchored_registry(self.registry,doc,sig,policy,now=now)

    def assert_hold(self,doc,sig,policy,needle=None,now=NOW):
        r=self.check(doc,sig,policy,now)
        self.assertEqual(r['status'],'HOLD')
        if needle:self.assertIn(needle,r['reasons'])

    def test_valid_signed_genesis_anchor(self):
        self.assertEqual(self.check()['status'],'OFFLINE_ANCHOR_MATCH')

    def test_valid_signed_one_entry_anchor(self):
        self.append()
        r=self.check()
        self.assertEqual(r['status'],'OFFLINE_ANCHOR_MATCH')
        self.assertFalse(r['engineering_accepted'])
        self.assertFalse(r['live_verified'])

    def test_missing_independent_policy(self):
        doc,sig,p=self.anchor()
        self.assert_hold(doc,sig,None,'TRUST_POLICY_INVALID')

    def test_wrong_trust_source(self):
        doc,sig,p=self.anchor();p['source']='SAME_LOCAL_SQLITE'
        self.assert_hold(doc,sig,p,'TRUST_SOURCE_NOT_INDEPENDENTLY_PINNED')

    def test_wrong_public_key(self):
        doc,sig,p=self.anchor()
        p['pinned_public_key']=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.assert_hold(doc,sig,p,'ANCHOR_SIGNATURE_INVALID')

    def test_forged_signature(self):
        doc,sig,p=self.anchor()
        self.assert_hold(doc,'00'*64,p,'ANCHOR_SIGNATURE_INVALID')

    def test_tampered_anchor(self):
        doc,sig,p=self.anchor();doc['checkpoint']['head']='a'*64
        self.assert_hold(doc,sig,p,'ANCHOR_SIGNATURE_INVALID')

    def test_wrong_registry_id(self):
        doc,sig,p=self.anchor();p['registry_id']='another-registry'
        self.assert_hold(doc,sig,p,'ANCHOR_IDENTITY_MISMATCH')

    def test_wrong_anchor_id(self):
        doc,sig,p=self.anchor();p['anchor_id']='another-signer'
        self.assert_hold(doc,sig,p,'ANCHOR_IDENTITY_MISMATCH')

    def test_expired_anchor(self):
        doc,sig,p=self.anchor()
        self.assert_hold(doc,sig,p,'ANCHOR_EXPIRED_OR_NOT_YET_VALID',now=datetime(2026,10,9,1,tzinfo=timezone.utc))

    def test_not_yet_valid_anchor(self):
        doc,sig,p=self.anchor()
        self.assert_hold(doc,sig,p,'ANCHOR_EXPIRED_OR_NOT_YET_VALID',now=datetime(2026,10,7,23,tzinfo=timezone.utc))

    def test_invalid_oversized_window(self):
        doc,sig,p=self.anchor();doc['expires_at']='2026-10-12T00:00:00+00:00'
        self.assert_hold(doc,sig,p,'ANCHOR_TIME_WINDOW_INVALID')

    def test_untrusted_naive_clock(self):
        doc,sig,p=self.anchor()
        self.assert_hold(doc,sig,p,'TRUSTED_CLOCK_INVALID',now=datetime(2026,10,8,1))

    def test_bool_checkpoint_count_rejected(self):
        doc,sig,p=self.anchor();doc['checkpoint']['count']=True
        self.assert_hold(doc,sig,p,'ANCHOR_CHECKPOINT_INVALID')

    def test_mismatched_external_high_water(self):
        self.append()
        doc,sig,p=self.anchor();p['latest_checkpoint']={'count':0,'head':GENESIS}
        self.assert_hold(doc,sig,p,'TRUSTED_HIGH_WATER_MISMATCH')

    def test_anchor_fingerprint_mismatch(self):
        doc,sig,p=self.anchor();p['latest_anchor_sha256']='0'*64
        self.assert_hold(doc,sig,p,'LATEST_ANCHOR_PIN_MISMATCH')

    def test_registry_truncation_detected(self):
        self.append()
        doc,sig,p=self.anchor()
        self.registry.db.execute('DROP TRIGGER entries_no_delete')
        self.registry.db.execute('DELETE FROM entries')
        self.assert_hold(doc,sig,p,'REGISTRY_DOES_NOT_MATCH_ANCHORED_CHECKPOINT')

    def test_local_record_tamper_detected(self):
        self.append()
        doc,sig,p=self.anchor()
        self.registry.db.execute('DROP TRIGGER entries_no_update')
        self.registry.db.execute("UPDATE entries SET collector_id='tampered' WHERE seq=1")
        self.assert_hold(doc,sig,p,'REGISTRY_DOES_NOT_MATCH_ANCHORED_CHECKPOINT')

    def test_full_rollback_with_old_signed_anchor_rejected_by_high_water(self):
        old_doc,old_sig,_=self.anchor()
        self.append()
        new_doc,new_sig,new_policy=self.anchor()
        self.registry.db.execute('DROP TRIGGER entries_no_delete')
        self.registry.db.execute('DELETE FROM entries')
        # Even a correctly signed old anchor cannot be used against a newer
        # independently pinned high-water mark.
        self.assert_hold(old_doc,old_sig,new_policy,'TRUSTED_HIGH_WATER_MISMATCH')
        self.assert_hold(new_doc,new_sig,new_policy,'REGISTRY_DOES_NOT_MATCH_ANCHORED_CHECKPOINT')

    def test_unknown_extra_anchor_fields_rejected(self):
        doc,sig,p=self.anchor();doc['trusted_public_key']=self.pub.hex()
        self.assert_hold(doc,sig,p,'ANCHOR_SCHEMA_INVALID')

    def test_invalid_signature_encoding(self):
        doc,sig,p=self.anchor()
        self.assert_hold(doc,'nothex',p,'ANCHOR_SIGNATURE_INVALID')

    def test_blank_trusted_identity_rejected(self):
        doc,sig,p=self.anchor();p['registry_id']=''
        self.assert_hold(doc,sig,p,'TRUSTED_IDENTITY_INVALID')

    def test_blank_anchor_identity_rejected(self):
        doc,sig,p=self.anchor();doc['anchor_id']=''
        self.assert_hold(doc,sig,p,'ANCHOR_IDENTITY_INVALID')

    def test_no_secrets_or_private_key_in_anchor(self):
        doc,sig,p=self.anchor()
        self.assertNotIn('private_key',str(doc))
        self.assertNotIn('MAPI_KEY',str(doc))
        self.assertNotIn('private_key',str(p))

if __name__=='__main__':unittest.main(verbosity=2)
