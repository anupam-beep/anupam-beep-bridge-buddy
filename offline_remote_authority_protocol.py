"""BridgeAgent remote-authority *protocol simulator* (offline only).

No sockets, HTTP, TLS, Civil NX, production integration or actual independent
operator. The adapter serializes the existing signed durable-pin messages into
strict wire frames and verifies a separately signed, independently pinned
high-water checkpoint statement. Synthetic keys are injected by tests.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from offline_result_certifier import canonical_bytes
from authenticated_durable_pin_store import CheckpointHold, checkpoint_ok

PROTOCOL = 'BridgeAgent:remote-pin-wire:v1'
WITNESS_DOMAIN = 'BridgeAgent:independent-high-water:v1'
MAX_WIRE_BYTES = 65536
WIRE_FIELDS = {'protocol','content_type','body_sha256','body_length','body'}
WITNESS_FIELDS = {'domain','authority_id','store_id','client_id','sequence',
                  'checkpoint','issued_at','expires_at'}


def _hex(data):
    return hashlib.sha256(data).hexdigest()


def _parse_json_strict(raw):
    def unique_pairs(pairs):
        obj={}
        for key,value in pairs:
            if key in obj: raise CheckpointHold('WIRE_DUPLICATE_JSON_KEY')
            obj[key]=value
        return obj
    try:
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique_pairs,
                         parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except CheckpointHold: raise
    except (UnicodeDecodeError,ValueError,TypeError):
        raise CheckpointHold('WIRE_JSON_INVALID') from None
    return value


def encode_frame(body):
    if not isinstance(body,dict): raise CheckpointHold('WIRE_BODY_INVALID')
    raw=canonical_bytes(body)
    if len(raw)>MAX_WIRE_BYTES: raise CheckpointHold('WIRE_BODY_TOO_LARGE')
    return canonical_bytes({'protocol':PROTOCOL,'content_type':'application/json',
                            'body_sha256':_hex(raw),'body_length':len(raw),
                            'body':raw.decode('utf-8')})


def decode_frame(wire):
    if not isinstance(wire,bytes) or len(wire)>MAX_WIRE_BYTES*2:
        raise CheckpointHold('WIRE_SIZE_OR_TYPE_INVALID')
    frame=_parse_json_strict(wire)
    if not isinstance(frame,dict) or set(frame)!=WIRE_FIELDS:
        raise CheckpointHold('WIRE_FRAME_SCHEMA_INVALID')
    if frame['protocol']!=PROTOCOL or frame['content_type']!='application/json':
        raise CheckpointHold('WIRE_PROTOCOL_INVALID')
    body=frame['body']
    if not isinstance(body,str): raise CheckpointHold('WIRE_BODY_INVALID')
    raw=body.encode('utf-8')
    if (len(raw)>MAX_WIRE_BYTES or type(frame['body_length']) is not int
        or frame['body_length']!=len(raw) or not isinstance(frame['body_sha256'],str)
        or not hmac.compare_digest(frame['body_sha256'],_hex(raw))):
        raise CheckpointHold('WIRE_BODY_INTEGRITY_FAILED')
    obj=_parse_json_strict(raw)
    if not isinstance(obj,dict) or canonical_bytes(obj)!=raw:
        raise CheckpointHold('WIRE_BODY_NONCANONICAL')
    return obj


class OfflineWireServer:
    """In-process test transport endpoint; not a remote server."""
    def __init__(self, durable_server):
        self.server=durable_server
    def receive(self, wire):
        obj=decode_frame(wire)
        if set(obj)!={'request','signature'} or not isinstance(obj['signature'],str):
            raise CheckpointHold('WIRE_REQUEST_SCHEMA_INVALID')
        response,sig=self.server.dispatch(obj['request'],obj['signature'])
        return encode_frame({'response':response,'signature':sig})


class OfflineWireAdapter:
    """Drop-in dispatch interface for AuthenticatedDurablePinClient.

    A future network adapter would require separate review, mTLS and pinned
    service identity; no network behavior is implemented here.
    """
    def __init__(self, endpoint):
        self.endpoint=endpoint
    def dispatch(self, request, signature):
        reply=decode_frame(self.endpoint.receive(encode_frame({'request':request,'signature':signature})))
        if set(reply)!={'response','signature'} or not isinstance(reply['signature'],str):
            raise CheckpointHold('WIRE_RESPONSE_SCHEMA_INVALID')
        return reply['response'],reply['signature']


def verify_independent_witness(statement, signature_hex, *, pinned_public_key,
                               pinned_fingerprint, expected_authority,
                               expected_store, expected_client, now):
    """Return trusted checkpoint only when an out-of-band fingerprint matches.

    IMPORTANT: caller MUST supply pinned_fingerprint from an actually independent
    trusted channel. This code cannot prove operational independence.
    """
    if not isinstance(statement,dict) or set(statement)!=WITNESS_FIELDS:
        raise CheckpointHold('WITNESS_SCHEMA_INVALID')
    if (statement['domain']!=WITNESS_DOMAIN or
        statement['authority_id']!=expected_authority or
        statement['store_id']!=expected_store or statement['client_id']!=expected_client):
        raise CheckpointHold('WITNESS_IDENTITY_INVALID')
    if type(statement['sequence']) is not int or statement['sequence']<0 or not checkpoint_ok(statement['checkpoint']):
        raise CheckpointHold('WITNESS_CHECKPOINT_INVALID')
    try:
        start=datetime.fromisoformat(statement['issued_at'].replace('Z','+00:00'))
        end=datetime.fromisoformat(statement['expires_at'].replace('Z','+00:00'))
    except (ValueError,AttributeError,TypeError):
        raise CheckpointHold('WITNESS_TIME_INVALID') from None
    if (not isinstance(now,datetime) or now.tzinfo is None or
        start.tzinfo is None or end.tzinfo is None or
        end<=start or end-start>timedelta(hours=24) or
        not start<=now.astimezone(timezone.utc)<=end):
        raise CheckpointHold('WITNESS_TIME_INVALID')
    try:
        if not isinstance(pinned_public_key,bytes) or len(pinned_public_key)!=32:
            raise ValueError('key')
        sig=bytes.fromhex(signature_hex)
        if len(sig)!=64: raise ValueError('signature')
        Ed25519PublicKey.from_public_bytes(pinned_public_key).verify(sig,canonical_bytes(statement))
    except (InvalidSignature,ValueError,TypeError):
        raise CheckpointHold('WITNESS_SIGNATURE_INVALID') from None
    fingerprint=_hex(b'BridgeAgent:independent-witness-fingerprint:v1\0'+canonical_bytes(statement)+sig)
    if not isinstance(pinned_fingerprint,str) or not hmac.compare_digest(fingerprint,pinned_fingerprint):
        raise CheckpointHold('WITNESS_OUT_OF_BAND_PIN_MISMATCH')
    return dict(statement['checkpoint'])
