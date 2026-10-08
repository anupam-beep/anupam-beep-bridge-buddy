"""Offline Bridge Dojo: strict simulated wire frames and independently pinned witness."""
import copy
import json
import tempfile
import unittest
from datetime import datetime,timezone,timedelta
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from authenticated_durable_pin_store import (AuthenticatedDurablePinClient,DurablePinStoreServer,CheckpointHold)
from offline_result_certifier import canonical_bytes
from offline_replay_registry import GENESIS
from offline_remote_authority_protocol import (encode_frame,decode_frame,OfflineWireServer,
    OfflineWireAdapter,verify_independent_witness,WITNESS_DOMAIN,_hex)

PUB=lambda k:k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
NOW=datetime(2026,10,8,5,29,tzinfo=timezone.utc)

class TestRemoteProtocol(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.clientkey=Ed25519PrivateKey.generate()
        self.serverkey=Ed25519PrivateKey.generate()
        self.witnesskey=Ed25519PrivateKey.generate()
        self.genesis={'count':0,'head':GENESIS}
        self.server=DurablePinStoreServer(Path(self.tmp.name)/'store.sqlite',
            store_id='OFFLINE-STORE',client_id='OFFLINE-CLIENT',
            pinned_client_public_key=PUB(self.clientkey),server_signing_key=self.serverkey,
            initial_checkpoint=self.genesis)
        self.endpoint=OfflineWireServer(self.server)
        self.adapter=OfflineWireAdapter(self.endpoint)
        self.client=AuthenticatedDurablePinClient(self.adapter,
            store_id='OFFLINE-STORE',client_id='OFFLINE-CLIENT',
            client_signing_key=self.clientkey,pinned_server_public_key=PUB(self.serverkey))
        self.statement={'domain':WITNESS_DOMAIN,'authority_id':'INDEPENDENT-WITNESS',
            'store_id':'OFFLINE-STORE','client_id':'OFFLINE-CLIENT','sequence':0,
            'checkpoint':self.genesis,'issued_at':(NOW-timedelta(minutes=1)).isoformat(),
            'expires_at':(NOW+timedelta(hours=1)).isoformat()}
    def tearDown(self):
        self.server.close();self.tmp.cleanup()
    def witness(self,statement=None,key=None,pin=None,now=NOW):
        statement=statement or self.statement
        key=key or self.witnesskey
        sig=key.sign(canonical_bytes(statement))
        fingerprint=_hex(b'BridgeAgent:independent-witness-fingerprint:v1\0'+canonical_bytes(statement)+sig)
        return verify_independent_witness(statement,sig.hex(),pinned_public_key=PUB(self.witnesskey),
            pinned_fingerprint=pin if pin is not None else fingerprint,
            expected_authority='INDEPENDENT-WITNESS',expected_store='OFFLINE-STORE',
            expected_client='OFFLINE-CLIENT',now=now)
    def test_roundtrip(self): self.assertEqual(decode_frame(encode_frame({'a':1})),{'a':1})
    def test_end_to_end_snapshot(self): self.assertEqual(self.client.snapshot(),self.genesis)
    def test_end_to_end_commit(self):
        next_cp={'count':1,'head':'a'*64}
        self.client.prepare('tx-1',self.genesis,next_cp)
        self.client.commit('tx-1',self.genesis,next_cp)
        self.assertEqual(self.client.snapshot(),next_cp)
    def test_end_to_end_pinned_witness(self):
        pin=self.witness()
        guarded=AuthenticatedDurablePinClient(self.adapter,store_id='OFFLINE-STORE',
            client_id='OFFLINE-CLIENT',client_signing_key=self.clientkey,
            pinned_server_public_key=PUB(self.serverkey),independently_pinned_high_water=pin)
        self.assertEqual(guarded.snapshot(),self.genesis)
    def test_wire_wrong_type(self):
        with self.assertRaisesRegex(CheckpointHold,'WIRE_SIZE_OR_TYPE_INVALID'):decode_frame('text')
    def test_wire_oversized(self):
        with self.assertRaisesRegex(CheckpointHold,'WIRE_SIZE_OR_TYPE_INVALID'):decode_frame(b'x'*140000)
    def test_wire_nonjson(self):
        with self.assertRaisesRegex(CheckpointHold,'WIRE_JSON_INVALID'):decode_frame(b'bad')
    def test_wire_duplicate_keys(self):
        with self.assertRaisesRegex(CheckpointHold,'WIRE_DUPLICATE_JSON_KEY'):decode_frame(b'{"x":1,"x":2}')
    def test_wire_body_tampered(self):
        frame=json.loads(encode_frame({'a':1}));frame['body']='{"a":2}'
        with self.assertRaisesRegex(CheckpointHold,'WIRE_BODY_INTEGRITY_FAILED'):decode_frame(canonical_bytes(frame))
    def test_wire_wrong_length(self):
        frame=json.loads(encode_frame({'a':1}));frame['body_length']=True
        with self.assertRaisesRegex(CheckpointHold,'WIRE_BODY_INTEGRITY_FAILED'):decode_frame(canonical_bytes(frame))
    def test_wire_protocol_downgrade(self):
        frame=json.loads(encode_frame({'a':1}));frame['protocol']='v0'
        with self.assertRaisesRegex(CheckpointHold,'WIRE_PROTOCOL_INVALID'):decode_frame(canonical_bytes(frame))
    def test_wire_extra_field(self):
        frame=json.loads(encode_frame({'a':1}));frame['extra']=1
        with self.assertRaisesRegex(CheckpointHold,'WIRE_FRAME_SCHEMA_INVALID'):decode_frame(canonical_bytes(frame))
    def test_wire_noncanonical_body(self):
        frame=json.loads(encode_frame({'a':1,'b':2}));raw=b'{"b":2,"a":1}'
        frame['body']=raw.decode();frame['body_length']=len(raw);frame['body_sha256']=_hex(raw)
        with self.assertRaisesRegex(CheckpointHold,'WIRE_BODY_NONCANONICAL'):decode_frame(canonical_bytes(frame))
    def test_wire_malformed_request(self):
        with self.assertRaisesRegex(CheckpointHold,'WIRE_REQUEST_SCHEMA_INVALID'):
            self.endpoint.receive(encode_frame({'request':{}}))
    def test_wire_malformed_response(self):
        class BadEndpoint:
            def receive(self,_):return encode_frame({'other':1})
        with self.assertRaisesRegex(CheckpointHold,'WIRE_RESPONSE_SCHEMA_INVALID'):
            OfflineWireAdapter(BadEndpoint()).dispatch({},'0')
    def test_wire_tampered_response(self):
        endpoint=self.endpoint
        class BadEndpoint:
            def receive(self,wire):
                resp=json.loads(endpoint.receive(wire))
                resp['body']=resp['body'].replace('OFFLINE-STORE','EVIL-STORE')
                return canonical_bytes(resp)
        self.client.server=OfflineWireAdapter(BadEndpoint())
        with self.assertRaisesRegex(CheckpointHold,'WIRE_BODY_INTEGRITY_FAILED'):self.client.snapshot()
    def test_witness_valid(self): self.assertEqual(self.witness(),self.genesis)
    def test_witness_wrong_key(self):
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_SIGNATURE_INVALID'):
            self.witness(key=Ed25519PrivateKey.generate())
    def test_witness_unpinned(self):
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_OUT_OF_BAND_PIN_MISMATCH'):
            self.witness(pin='f'*64)
    def test_witness_wrong_authority(self):
        x=copy.deepcopy(self.statement);x['authority_id']='FAKE'
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_IDENTITY_INVALID'):self.witness(x)
    def test_witness_wrong_store(self):
        x=copy.deepcopy(self.statement);x['store_id']='FAKE'
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_IDENTITY_INVALID'):self.witness(x)
    def test_witness_expired(self):
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_TIME_INVALID'):
            self.witness(now=NOW+timedelta(days=2))
    def test_witness_future(self):
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_TIME_INVALID'):
            self.witness(now=NOW-timedelta(days=2))
    def test_witness_invalid_sequence(self):
        x=copy.deepcopy(self.statement);x['sequence']=True
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_CHECKPOINT_INVALID'):self.witness(x)
    def test_witness_invalid_checkpoint(self):
        x=copy.deepcopy(self.statement);x['checkpoint']={'count':-1,'head':'bad'}
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_CHECKPOINT_INVALID'):self.witness(x)
    def test_witness_extra_field(self):
        x=copy.deepcopy(self.statement);x['other']='oops'
        with self.assertRaisesRegex(CheckpointHold,'WITNESS_SCHEMA_INVALID'):self.witness(x)
    def test_witness_rollback_detected_by_client(self):
        next_cp={'count':1,'head':'a'*64}
        self.client.prepare('tx-1',self.genesis,next_cp);self.client.commit('tx-1',self.genesis,next_cp)
        x=copy.deepcopy(self.statement);x['checkpoint']=next_cp;x['sequence']=1
        trusted_pin=self.witness(x)
        self.server.close()
        # Deliberate rollback of LOCAL simulator, not a real external authority.
        Path(self.tmp.name,'store.sqlite').unlink()
        for suffix in ('-wal','-shm'):
            p=Path(self.tmp.name,'store.sqlite'+suffix)
            if p.exists():p.unlink()
        self.server=DurablePinStoreServer(Path(self.tmp.name)/'store.sqlite',
            store_id='OFFLINE-STORE',client_id='OFFLINE-CLIENT',
            pinned_client_public_key=PUB(self.clientkey),server_signing_key=self.serverkey,
            initial_checkpoint=self.genesis)
        self.adapter=OfflineWireAdapter(OfflineWireServer(self.server))
        guarded=AuthenticatedDurablePinClient(self.adapter,store_id='OFFLINE-STORE',
            client_id='OFFLINE-CLIENT',client_signing_key=self.clientkey,
            pinned_server_public_key=PUB(self.serverkey),independently_pinned_high_water=trusted_pin)
        with self.assertRaisesRegex(CheckpointHold,'STORE_INDEPENDENT_HIGH_WATER_ROLLBACK'):
            guarded.snapshot()

if __name__=='__main__':unittest.main()
