"""Offline-only independently pinned signed checkpoint verifier.

No signing, network, Civil NX, or repository mutation. An anchor's signature
alone cannot defeat rollback: the verifier also requires an OUT-OF-BAND pin of
both the latest anchor fingerprint and registry head/count. The caller is
responsible for obtaining this policy from an actually independent trusted
channel; a policy copied from the local SQLite DB is NOT independent.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from offline_result_certifier import canonical_bytes
from offline_replay_registry import RegistryHold

DOMAIN = 'BridgeAgent:independent-checkpoint-anchor:v1'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
EXPECTED_ANCHOR_FIELDS = {'schema_version','domain','registry_id','anchor_id',
                          'checkpoint','issued_at','expires_at'}
EXPECTED_POLICY_FIELDS = {'registry_id','anchor_id','pinned_public_key',
                          'latest_checkpoint','latest_anchor_sha256','source'}


def _time(s):
    if not isinstance(s, str):
        return None
    try:
        t = datetime.fromisoformat(s.replace('Z','+00:00'))
        if t.tzinfo is None or t.utcoffset() is None:
            return None
        return t.astimezone(timezone.utc)
    except ValueError:
        return None


def _checkpoint_ok(cp):
    return (isinstance(cp, dict) and set(cp) == {'count','head'}
            and type(cp['count']) is int and cp['count'] >= 0
            and isinstance(cp['head'], str) and bool(HEX64.fullmatch(cp['head'])))


def _digest(anchor, signature_bytes):
    return hashlib.sha256(b'BridgeAgent:checkpoint-anchor-fingerprint:v1\x00'
                          + canonical_bytes(anchor) + signature_bytes).hexdigest()


def verify_anchored_registry(registry, anchor, signature_hex, policy, *, now):
    """Return HOLD or OFFLINE_ANCHOR_MATCH; never certify live/engineering results.

    ``policy`` must be supplied from an independently maintained, authenticated
    trust store, not the registry being audited. ``source`` is a mandatory
    declared provenance label, not proof of independence by itself.
    """
    reasons = []
    if not isinstance(policy, dict) or set(policy) != EXPECTED_POLICY_FIELDS:
        return {'status':'HOLD','reasons':['TRUST_POLICY_INVALID'],
                'live_verified':False,'engineering_accepted':False}
    if policy.get('source') != 'INDEPENDENT_OUT_OF_BAND_PIN':
        reasons.append('TRUST_SOURCE_NOT_INDEPENDENTLY_PINNED')
    if not all(isinstance(policy.get(k),str) and policy[k].strip() for k in ('registry_id','anchor_id')):
        reasons.append('TRUSTED_IDENTITY_INVALID')
    pub = policy.get('pinned_public_key')
    if not isinstance(pub, bytes) or len(pub) != 32:
        reasons.append('TRUSTED_PUBLIC_KEY_MISSING')
    if not _checkpoint_ok(policy.get('latest_checkpoint')):
        reasons.append('TRUSTED_HIGH_WATER_INVALID')
    pin = policy.get('latest_anchor_sha256')
    if not isinstance(pin,str) or not HEX64.fullmatch(pin):
        reasons.append('TRUSTED_ANCHOR_FINGERPRINT_INVALID')
    if not isinstance(anchor,dict) or set(anchor) != EXPECTED_ANCHOR_FIELDS:
        reasons.append('ANCHOR_SCHEMA_INVALID')
        return {'status':'HOLD','reasons':reasons,'live_verified':False,
                'engineering_accepted':False}
    if type(anchor.get('schema_version')) is not int or anchor['schema_version'] != 1 or anchor.get('domain') != DOMAIN:
        reasons.append('ANCHOR_DOMAIN_OR_VERSION_INVALID')
    if not all(isinstance(anchor.get(k),str) and anchor[k].strip() for k in ('registry_id','anchor_id')):
        reasons.append('ANCHOR_IDENTITY_INVALID')
    if anchor.get('registry_id') != policy.get('registry_id') or anchor.get('anchor_id') != policy.get('anchor_id'):
        reasons.append('ANCHOR_IDENTITY_MISMATCH')
    cp = anchor.get('checkpoint')
    if not _checkpoint_ok(cp):
        reasons.append('ANCHOR_CHECKPOINT_INVALID')
    elif _checkpoint_ok(policy.get('latest_checkpoint')) and cp != policy['latest_checkpoint']:
        reasons.append('TRUSTED_HIGH_WATER_MISMATCH')
    issued, expiry, current = _time(anchor.get('issued_at')), _time(anchor.get('expires_at')), now
    if not isinstance(current,datetime) or current.tzinfo is None or current.utcoffset() is None:
        reasons.append('TRUSTED_CLOCK_INVALID')
    elif not issued or not expiry or expiry <= issued or expiry-issued > timedelta(hours=24):
        reasons.append('ANCHOR_TIME_WINDOW_INVALID')
    elif not (issued <= current.astimezone(timezone.utc) <= expiry):
        reasons.append('ANCHOR_EXPIRED_OR_NOT_YET_VALID')
    try:
        sig = bytes.fromhex(signature_hex)
        if len(sig) != 64:
            raise ValueError('invalid signature length')
    except (TypeError, ValueError):
        sig = b''
        reasons.append('ANCHOR_SIGNATURE_INVALID')
    if isinstance(pub,bytes) and len(pub)==32 and len(sig)==64:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig,canonical_bytes(anchor))
        except (InvalidSignature,ValueError,TypeError):
            reasons.append('ANCHOR_SIGNATURE_INVALID')
    if len(sig)==64 and isinstance(pin,str) and HEX64.fullmatch(pin):
        if not hmac.compare_digest(pin,_digest(anchor,sig)):
            reasons.append('LATEST_ANCHOR_PIN_MISMATCH')
    # Do not audit local DB until all independently checkable trust gates pass.
    if not reasons:
        try:
            registry.audit(cp)
        except Exception:
            reasons.append('REGISTRY_DOES_NOT_MATCH_ANCHORED_CHECKPOINT')
    return {'status':'OFFLINE_ANCHOR_MATCH' if not reasons else 'HOLD',
            'reasons':reasons, 'live_verified':False,
            'engineering_accepted':False}
