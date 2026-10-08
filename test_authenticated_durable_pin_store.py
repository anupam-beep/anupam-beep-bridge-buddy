"""Synthetic, offline Bridge Dojo: authenticated durable pin-store adapter."""
import copy
import sqlite3
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from authenticated_durable_pin_store import (DurablePinStoreServer, AuthenticatedDurablePinClient,
    CheckpointHold, REQ_DOMAIN, sha256)
from offline_result_certifier import canonical_bytes
from offline_replay_registry import OfflineReplayRegistry, GENESIS
from two_phase_checkpoint import TwoPhaseCheckpoint
from test_independent_capture_receipt import make_fixture
from test_offline_result_certifier import MODEL_BYTES, RESPONSE

PUB=lambda key:key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)

class TestAuthenticatedDurableStore(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'durable_pin.sqlite'
        self.client_key=Ed25519PrivateKey.generate()
        self.server_key=Ed25519PrivateKey.generate()
        self.initial={'count':0,'head':GENESIS}
        self._reopen()
    def _reopen(self):
        self.server=DurablePinStoreServer(self.path,store_id='OFFLINE-STORE-1',client_id='OFFLINE-CLIENT-1',
            pinned_client_public_key=PUB(self.client_key),server_signing_key=self.server_key,
            initial_checkpoint=self.initial)
        self.client=AuthenticatedDurablePinClient(self.server,store_id='OFFLINE-STORE-1',
            client_id='OFFLINE-CLIENT-1',client_signing_key=self.client_key,
            pinned_server_public_key=PUB(self.server_key))
    def tearDown(self):
        self.server.close();self.temp.cleanup()
    def cp(self): return {'count':1,'head':'a'*64}
    def test_genesis_snapshot(self): self.assertEqual(self.client.snapshot(),self.initial)
    def test_prepare_status_commit(self):
        self.client.prepare('t1',self.initial,self.cp())
        self.assertEqual(self.client.status('t1')[0],'PREPARED')
        self.client.commit('t1',self.initial,self.cp())
        self.assertEqual(self.client.snapshot(),self.cp())
        self.assertEqual(self.client.status('t1'),('COMMITTED',self.cp()))
    def test_restart_retains_committed_pin(self):
        self.client.prepare('t1',self.initial,self.cp());self.client.commit('t1',self.initial,self.cp())
        self.server.close();self._reopen()
        self.assertEqual(self.client.snapshot(),self.cp())
    def test_restart_retains_prepared_tx(self):
        self.client.prepare('t1',self.initial,self.cp())
        self.server.close();self._reopen()
        self.assertEqual(self.client.status('t1')[0],'PREPARED')
        self.client.commit('t1',self.initial,self.cp())
        self.assertEqual(self.client.snapshot(),self.cp())
    def test_abort_survives_restart(self):
        self.client.prepare('t1',self.initial,self.cp());self.client.abort('t1',self.initial,self.cp())
        self.server.close();self._reopen()
        self.assertEqual(self.client.status('t1'),('UNKNOWN',None))
        self.assertEqual(self.client.snapshot(),self.initial)
    def test_idempotent_prepare_commit_abort(self):
        self.client.prepare('t1',self.initial,self.cp());self.client.prepare('t1',self.initial,self.cp())
        self.client.commit('t1',self.initial,self.cp());self.client.commit('t1',self.initial,self.cp())
        self.assertEqual(self.client.snapshot(),self.cp())
    def test_cas_rejects_wrong_old(self):
        with self.assertRaisesRegex(CheckpointHold,'STORE_CAS_FAILED'):
            self.client.prepare('t1',{'count':0,'head':'f'*64},self.cp())
    def test_txid_reuse_conflict(self):
        self.client.prepare('t1',self.initial,self.cp())
        with self.assertRaisesRegex(CheckpointHold,'STORE_TXID_CONFLICT'):
            self.client.prepare('t1',self.initial,{'count':1,'head':'b'*64})
    def test_prepared_tx_blocks_other_tx(self):
        self.client.prepare('t1',self.initial,self.cp())
        with self.assertRaisesRegex(CheckpointHold,'STORE_PENDING_CONFLICT'):
            self.client.prepare('t2',self.initial,{'count':1,'head':'b'*64})
    def test_abort_committed_holds(self):
        self.client.prepare('t1',self.initial,self.cp());self.client.commit('t1',self.initial,self.cp())
        with self.assertRaisesRegex(CheckpointHold,'STORE_ABORT_CONFLICT'):
            self.client.abort('t1',self.initial,self.cp())
    def test_non_monotonic_pin_holds(self):
        with self.assertRaisesRegex(CheckpointHold,'STORE_NON_MONOTONIC_CHECKPOINT'):
            self.client.prepare('t1',self.initial,{'count':5,'head':'a'*64})
    def test_wrong_client_key_holds(self):
        bad=AuthenticatedDurablePinClient(self.server,store_id='OFFLINE-STORE-1',client_id='OFFLINE-CLIENT-1',
            client_signing_key=Ed25519PrivateKey.generate(),pinned_server_public_key=PUB(self.server_key))
        with self.assertRaisesRegex(CheckpointHold,'STORE_CLIENT_AUTHENTICATION_FAILED'):bad.snapshot()
    def test_wrong_server_key_holds(self):
        bad=AuthenticatedDurablePinClient(self.server,store_id='OFFLINE-STORE-1',client_id='OFFLINE-CLIENT-1',
            client_signing_key=self.client_key,pinned_server_public_key=PUB(Ed25519PrivateKey.generate()))
        with self.assertRaisesRegex(CheckpointHold,'STORE_SERVER_AUTHENTICATION_FAILED'):bad.snapshot()
    def test_wrong_server_identity_holds(self):
        bad=AuthenticatedDurablePinClient(self.server,store_id='OTHER-STORE',client_id='OFFLINE-CLIENT-1',
            client_signing_key=self.client_key,pinned_server_public_key=PUB(self.server_key))
        with self.assertRaisesRegex(CheckpointHold,'STORE_REQUEST_IDENTITY_INVALID'):bad.snapshot()
    def test_duplicate_request_id_same_payload_idempotent(self):
        req={'domain':REQ_DOMAIN,'store_id':'OFFLINE-STORE-1','client_id':'OFFLINE-CLIENT-1',
             'request_id':'fixed-1','operation':'prepare','txid':'t1','old':self.initial,'new':self.cp()}
        sig=self.client_key.sign(canonical_bytes(req)).hex()
        first=self.server.dispatch(req,sig)
        second=self.server.dispatch(req,sig)
        self.assertEqual(first,second)
        self.assertEqual(self.client.status('t1')[0],'PREPARED')
    def test_duplicate_request_id_changed_payload_holds(self):
        req={'domain':REQ_DOMAIN,'store_id':'OFFLINE-STORE-1','client_id':'OFFLINE-CLIENT-1',
             'request_id':'fixed-1','operation':'snapshot','txid':None,'old':None,'new':None}
        self.server.dispatch(req,self.client_key.sign(canonical_bytes(req)).hex())
        req['operation']='status';req['txid']='t1'
        with self.assertRaisesRegex(CheckpointHold,'STORE_REQUEST_ID_REUSE_CONFLICT'):
            self.server.dispatch(req,self.client_key.sign(canonical_bytes(req)).hex())
    def test_unsigned_tamper_request_holds(self):
        req={'domain':REQ_DOMAIN,'store_id':'OFFLINE-STORE-1','client_id':'OFFLINE-CLIENT-1',
             'request_id':'fixed-2','operation':'snapshot','txid':None,'old':None,'new':None}
        sig=self.client_key.sign(canonical_bytes(req)).hex();req['operation']='status';req['txid']='t1'
        with self.assertRaisesRegex(CheckpointHold,'STORE_CLIENT_AUTHENTICATION_FAILED'):
            self.server.dispatch(req,sig)
    def test_unsigned_tamper_response_holds(self):
        real=self.server.dispatch
        def modified(req,sig):
            response,rsig=real(req,sig)
            response=copy.deepcopy(response);response['result']['checkpoint']['head']='0'*64
            return response,rsig
        self.server.dispatch=modified
        with self.assertRaisesRegex(CheckpointHold,'STORE_SERVER_AUTHENTICATION_FAILED'):
            self.client.snapshot()
    def test_replay_response_to_different_request_holds(self):
        real=self.server.dispatch
        cached=None
        def replay(req,sig):
            nonlocal cached
            if cached is None: cached=real(req,sig)
            return cached
        self.server.dispatch=replay
        self.client.snapshot()
        with self.assertRaisesRegex(CheckpointHold,'STORE_RESPONSE_BINDING_INVALID'):
            self.client.snapshot()
    def test_independent_high_water_detects_store_rollback(self):
        self.client.prepare('t1',self.initial,self.cp());self.client.commit('t1',self.initial,self.cp())
        # This is a synthetic stand-in for a separately preserved pin.
        pinned=copy.deepcopy(self.client.snapshot())
        self.server.db.execute('DELETE FROM commands')
        self.server.db.execute('DELETE FROM transactions')
        self.server.db.execute('UPDATE pin SET count=?,head=?,revision=0 WHERE id=1',
                               (self.initial['count'],self.initial['head']))
        anchored=AuthenticatedDurablePinClient(self.server,store_id='OFFLINE-STORE-1',
            client_id='OFFLINE-CLIENT-1',client_signing_key=self.client_key,
            pinned_server_public_key=PUB(self.server_key),independently_pinned_high_water=pinned)
        with self.assertRaisesRegex(CheckpointHold,'STORE_INDEPENDENT_HIGH_WATER_ROLLBACK'):
            anchored.snapshot()

    def test_independent_pin_mismatch_same_count_holds(self):
        anchored=AuthenticatedDurablePinClient(self.server,store_id='OFFLINE-STORE-1',
            client_id='OFFLINE-CLIENT-1',client_signing_key=self.client_key,
            pinned_server_public_key=PUB(self.server_key),
            independently_pinned_high_water={'count':0,'head':'b'*64})
        with self.assertRaisesRegex(CheckpointHold,'STORE_INDEPENDENT_HIGH_WATER_ROLLBACK'):
            anchored.snapshot()

    def test_invalid_independent_pin_holds(self):
        with self.assertRaisesRegex(CheckpointHold,'STORE_INDEPENDENT_PIN_INVALID'):
            AuthenticatedDurablePinClient(self.server,store_id='OFFLINE-STORE-1',
                client_id='OFFLINE-CLIENT-1',client_signing_key=self.client_key,
                pinned_server_public_key=PUB(self.server_key),
                independently_pinned_high_water={'count':-1,'head':'0'*64})

    def test_db_identity_change_holds(self):
        self.server.close()
        with self.assertRaisesRegex(CheckpointHold,'STORE_IDENTITY_CHANGED'):
            DurablePinStoreServer(self.path,store_id='DIFFERENT',client_id='OFFLINE-CLIENT-1',
                pinned_client_public_key=PUB(self.client_key),server_signing_key=self.server_key,
                initial_checkpoint=self.initial)
        self._reopen()
    def test_corrupt_pin_holds(self):
        self.server.db.execute("UPDATE pin SET head='INVALID' WHERE id=1")
        with self.assertRaisesRegex(CheckpointHold,'STORE_PIN_CORRUPT'):self.client.snapshot()
    def test_no_private_keys_stored_in_sqlite_schema(self):
        dump='\n'.join(self.server.db.iterdump()).lower()
        self.assertNotIn('private_key',dump)
        self.assertNotIn('secret_key',dump)
    def test_coordinator_integrates_with_durable_store(self):
        reg=OfflineReplayRegistry(Path(self.temp.name)/'registry.sqlite')
        coord=TwoPhaseCheckpoint(reg,self.client)
        try:
            env,req,att,att_sig,analysis_pub,witness_pub,receipt,sign=make_fixture()
            kwargs=dict(envelope=env,model_bytes=MODEL_BYTES,response_bytes=RESPONSE,
                raw_request=req,analysis_attestation=att,analysis_signature_hex=att_sig,
                pinned_analysis_public_key=analysis_pub,receipt=receipt,receipt_signature_hex=sign(),
                pinned_collector_id=receipt['collector_id'],pinned_capture_public_key=witness_pub)
            self.assertEqual(coord.append(**kwargs)['status'],'OFFLINE_TWO_PHASE_COMMITTED')
            self.assertEqual(coord.recover()['status'],'STABLE')
            self.server.close();self._reopen()
            coord.pin_store=self.client
            self.assertEqual(coord.recover()['status'],'STABLE')
        finally: coord.close();reg.close()
    def test_crash_gap_recovered_after_external_store_restart(self):
        reg=OfflineReplayRegistry(Path(self.temp.name)/'registry.sqlite')
        coord=TwoPhaseCheckpoint(reg,self.client)
        try:
            env,req,att,att_sig,analysis_pub,witness_pub,receipt,sign=make_fixture()
            kwargs=dict(envelope=env,model_bytes=MODEL_BYTES,response_bytes=RESPONSE,
                raw_request=req,analysis_attestation=att,analysis_signature_hex=att_sig,
                pinned_analysis_public_key=analysis_pub,receipt=receipt,receipt_signature_hex=sign(),
                pinned_collector_id=receipt['collector_id'],pinned_capture_public_key=witness_pub)
            original=self.client.commit
            def drop(*args): raise CheckpointHold('SIMULATED_EXTERNAL_COMMIT_DROP')
            self.client.commit=drop
            with self.assertRaisesRegex(CheckpointHold,'SIMULATED_EXTERNAL_COMMIT_DROP'):
                coord.append(**kwargs)
            self.assertEqual(reg.audit()['count'],1)
            self.server.close();self._reopen()
            coord.pin_store=self.client
            self.assertEqual(coord.recover()['status'],'RECOVERED_COMMITTED')
            self.assertEqual(coord.recover()['status'],'STABLE')
        finally:coord.close();reg.close()

if __name__=='__main__':unittest.main()
