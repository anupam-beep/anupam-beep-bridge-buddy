"""Offline-only two-phase checkpoint protocol; no network, keys or Civil NX calls.

This coordinates a local append-only registry with an abstract independently
trusted pin store. A store MUST be independent and authenticated in production.
The supplied FakePinStore is TEST ONLY and offers NO independent trust.
No engineering or live-result certification is provided.
"""
from __future__ import annotations

import hashlib
import hmac
import sqlite3
from contextlib import contextmanager

from offline_result_certifier import canonical_bytes, digest
from independent_capture_receipt import verify_with_capture
from offline_replay_registry import OfflineReplayRegistry, RegistryHold, entry_hash


class CheckpointHold(RuntimeError):
    pass


def cp_equal(a, b):
    return isinstance(a, dict) and isinstance(b, dict) and type(a.get('count')) is int and type(b.get('count')) is int and a == b


class FakePinStore:
    """Ephemeral simulation ONLY. Do not use as an independent anchor."""
    def __init__(self, initial):
        self.current = dict(initial)
        self.pending = None
        self.completed = {}
        self.fail_prepare = False
        self.fail_commit = False
        self.fail_abort = False

    def snapshot(self):
        return dict(self.current)

    def status(self, txid):
        if txid in self.completed:
            return 'COMMITTED', dict(self.completed[txid])
        if self.pending and self.pending['txid'] == txid:
            return 'PREPARED', dict(self.pending)
        return 'UNKNOWN', None

    def prepare(self, txid, old, new):
        if self.fail_prepare: raise CheckpointHold('EXTERNAL_PREPARE_UNAVAILABLE')
        if txid in self.completed:
            if self.completed[txid] != new: raise CheckpointHold('EXTERNAL_TXID_CONFLICT')
            return
        if self.pending:
            if self.pending != {'txid':txid,'old':old,'new':new}:
                raise CheckpointHold('EXTERNAL_PENDING_CONFLICT')
            return
        if not cp_equal(self.current, old): raise CheckpointHold('EXTERNAL_PIN_CAS_FAILED')
        self.pending = {'txid':txid,'old':dict(old),'new':dict(new)}

    def commit(self, txid, old, new):
        if self.fail_commit: raise CheckpointHold('EXTERNAL_COMMIT_UNAVAILABLE')
        if txid in self.completed:
            if self.completed[txid] != new: raise CheckpointHold('EXTERNAL_COMMITTED_CONFLICT')
            return
        if self.pending != {'txid':txid,'old':old,'new':new}:
            raise CheckpointHold('EXTERNAL_PREPARE_MISSING')
        if not cp_equal(self.current,old): raise CheckpointHold('EXTERNAL_PIN_CAS_FAILED')
        self.current = dict(new)
        self.completed[txid] = dict(new)
        self.pending = None

    def abort(self, txid, old, new):
        if self.fail_abort: raise CheckpointHold('EXTERNAL_ABORT_UNAVAILABLE')
        if self.pending == {'txid':txid,'old':old,'new':new}:
            self.pending = None
        elif self.pending or txid in self.completed:
            raise CheckpointHold('EXTERNAL_ABORT_CONFLICT')


class TwoPhaseCheckpoint:
    def __init__(self, registry: OfflineReplayRegistry, pin_store):
        self.registry = registry
        self.pin_store = pin_store
        # Separate SQLite file lock serializes coordinators on the SAME host.
        # Cross-host safety requires a real distributed lock/trust service.
        self._lock_db = sqlite3.connect(registry.path + '.coordlock', timeout=0.25,
                                        isolation_level=None)
        self._lock_db.execute('CREATE TABLE IF NOT EXISTS coordinator_guard (id INTEGER PRIMARY KEY)')
        registry.db.executescript('''
          CREATE TABLE IF NOT EXISTS checkpoint_journal (
            txid TEXT PRIMARY KEY, old_count INTEGER NOT NULL, old_head TEXT NOT NULL,
            new_count INTEGER NOT NULL, new_head TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('PREPARED','COMMITTED','ABORTED'))
          );
          CREATE UNIQUE INDEX IF NOT EXISTS one_open_checkpoint
          ON checkpoint_journal(state) WHERE state='PREPARED';
        ''')

    @contextmanager
    def _exclusive(self):
        try:
            self._lock_db.execute('BEGIN IMMEDIATE')
        except sqlite3.OperationalError as e:
            raise CheckpointHold('COORDINATOR_BUSY') from e
        try:
            yield
        finally:
            if self._lock_db.in_transaction:
                self._lock_db.execute('ROLLBACK')  # lock-only transaction

    def close(self):
        self._lock_db.close()

    def _pending(self):
        rows = list(self.registry.db.execute('''SELECT txid,old_count,old_head,new_count,new_head
                FROM checkpoint_journal WHERE state='PREPARED' '''))
        if len(rows)>1: raise CheckpointHold('MULTIPLE_PENDING_TRANSACTIONS')
        if not rows: return None
        txid,oc,oh,nc,nh=rows[0]
        return txid, {'count':oc,'head':oh}, {'count':nc,'head':nh}

    def _current(self):
        state=self.registry.audit()
        return {'count':state['count'],'head':state['head']}

    def _finish(self, txid, state):
        self.registry.db.execute('UPDATE checkpoint_journal SET state=? WHERE txid=? AND state=?',
                                 (state,txid,'PREPARED'))

    def recover(self):
        """Reconcile crash states under same-host exclusive lock."""
        with self._exclusive():
            return self._recover_locked()

    def _recover_locked(self):
        """Reconcile crash states. Any ambiguity remains HOLD; no silent trust promotion."""
        pending=self._pending()
        if pending is None:
            current=self._current()
            if not cp_equal(current,self.pin_store.snapshot()):
                raise CheckpointHold('LOCAL_AND_EXTERNAL_HIGH_WATER_DIFFER')
            return {'status':'STABLE','checkpoint':current}
        txid,old,new=pending
        current=self._current()
        ext_state, ext_doc=self.pin_store.status(txid)
        if cp_equal(current,old):
            if ext_state == 'COMMITTED': raise CheckpointHold('EXTERNAL_COMMITTED_WITHOUT_LOCAL_APPEND')
            if ext_state == 'PREPARED':
                if ext_doc != {'txid':txid,'old':old,'new':new}:
                    raise CheckpointHold('EXTERNAL_RESERVATION_MISMATCH')
                self.pin_store.abort(txid,old,new)
            elif ext_state != 'UNKNOWN': raise CheckpointHold('EXTERNAL_STATE_INVALID')
            if not cp_equal(self.pin_store.snapshot(),old):
                raise CheckpointHold('EXTERNAL_PIN_MISMATCH_BEFORE_ABORT')
            self._finish(txid,'ABORTED')
            return {'status':'ABORTED_UNAPPENDED','checkpoint':old}
        if cp_equal(current,new):
            if ext_state == 'UNKNOWN': raise CheckpointHold('APPENDED_WITHOUT_EXTERNAL_RESERVATION')
            if ext_state == 'PREPARED':
                if ext_doc != {'txid':txid,'old':old,'new':new}:
                    raise CheckpointHold('EXTERNAL_RESERVATION_MISMATCH')
                self.pin_store.commit(txid,old,new)
            elif ext_state == 'COMMITTED':
                if not cp_equal(ext_doc,new): raise CheckpointHold('EXTERNAL_COMMIT_MISMATCH')
            else: raise CheckpointHold('EXTERNAL_STATE_INVALID')
            if not cp_equal(self.pin_store.snapshot(),new):
                raise CheckpointHold('EXTERNAL_PIN_MISMATCH_AFTER_COMMIT')
            self._finish(txid,'COMMITTED')
            return {'status':'RECOVERED_COMMITTED','checkpoint':new}
        raise CheckpointHold('LOCAL_REGISTRY_DIVERGED_FROM_PENDING')

    def append(self, **kwargs):
        """Offline synthetic fixture intake. Verify before reservation; reverify in registry."""
        with self._exclusive():
            return self._append_locked(**kwargs)

    def _append_locked(self, **kwargs):
        # Never automatically reconcile another writer's pending transaction.
        # Recovery is an explicit separate action under exclusive lock.
        if self._pending() is not None:
            raise CheckpointHold('PENDING_CHECKPOINT_REQUIRES_RECOVERY')
        stable=self._recover_locked()
        if stable['status']!='STABLE':
            raise CheckpointHold('RECOVERY_COMPLETED_RETRY_SEPARATELY')
        old=stable['checkpoint']
        receipt=kwargs['receipt']; signature=kwargs['receipt_signature_hex']
        if not isinstance(receipt,dict): raise CheckpointHold('RECEIPT_INVALID')
        result=verify_with_capture(
            kwargs['envelope'],kwargs['model_bytes'],kwargs['response_bytes'],kwargs['raw_request'],
            kwargs['analysis_attestation'],kwargs['analysis_signature_hex'],kwargs['pinned_analysis_public_key'],
            receipt,signature,kwargs['pinned_collector_id'],kwargs['pinned_capture_public_key'],
            previously_seen_capture_ids=frozenset())
        if result['status']!='OFFLINE_EVIDENCE_GATES_PASS':
            raise CheckpointHold('RECEIPT_VERIFICATION_HOLD')
        record=dict(capture_id=receipt['capture_id'],collector_id=receipt['collector_id'],
                    receipt_sha256=digest(canonical_bytes(receipt)+bytes.fromhex(signature)),
                    raw_request_sha256=receipt['raw_request_sha256'],
                    raw_response_sha256=receipt['raw_response_sha256'],
                    model_sha256=receipt['model_sha256'],analysis_run_id=receipt['analysis_run_id'])
        new={'count':old['count']+1,'head':entry_hash(old['head'],old['count']+1,record)}
        txid=digest(b'BridgeAgent:checkpoint-transaction:v1\x00'+canonical_bytes(
            {'old':old,'new':new,'capture_id':receipt['capture_id']}))
        self.registry.db.execute('INSERT INTO checkpoint_journal VALUES (?,?,?,?,?,?)',
                                 (txid,old['count'],old['head'],new['count'],new['head'],'PREPARED'))
        # If external reservation fails, journal remains pending. Next recovery
        # may safely abort ONLY if registry is still at the old checkpoint.
        self.pin_store.prepare(txid,old,new)
        appended=self.registry.accept_signed_receipt(pinned_checkpoint=old,**kwargs)
        if not cp_equal(appended['checkpoint_to_pin_independently'],new):
            raise CheckpointHold('ACTUAL_APPEND_HEAD_DIFFERS_FROM_PREPARED')
        self.pin_store.commit(txid,old,new)
        self._finish(txid,'COMMITTED')
        return {'status':'OFFLINE_TWO_PHASE_COMMITTED','checkpoint':new,
                'live_verified':False,'engineering_accepted':False}
