"""Crash-injection Bridge Dojo. Entirely synthetic; fake pin store is not trusted."""
import tempfile
import unittest
from pathlib import Path
from offline_replay_registry import OfflineReplayRegistry, GENESIS
from two_phase_checkpoint import TwoPhaseCheckpoint, FakePinStore, CheckpointHold
from test_independent_capture_receipt import make_fixture
from test_offline_result_certifier import MODEL_BYTES, RESPONSE

class TestTwoPhaseCheckpoint(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.reg=OfflineReplayRegistry(Path(self.temp.name)/'registry.sqlite')
        self.pin=FakePinStore({'count':0,'head':GENESIS})
        self.coord=TwoPhaseCheckpoint(self.reg,self.pin)
    def tearDown(self):
        self.coord.close(); self.reg.close(); self.temp.cleanup()
    def fixture(self, capture_id='TEST-CAPTURE-1'):
        env,req,att,att_sig,analysis_pub,witness_pub,receipt,sign=make_fixture()
        receipt['capture_id']=capture_id
        return dict(envelope=env,model_bytes=MODEL_BYTES,response_bytes=RESPONSE,
            raw_request=req,analysis_attestation=att,analysis_signature_hex=att_sig,
            pinned_analysis_public_key=analysis_pub,receipt=receipt,
            receipt_signature_hex=sign(),pinned_collector_id=receipt['collector_id'],
            pinned_capture_public_key=witness_pub)
    def test_genesis_stable(self):
        self.assertEqual(self.coord.recover()['status'],'STABLE')
    def test_normal_append(self):
        r=self.coord.append(**self.fixture())
        self.assertEqual(r['status'],'OFFLINE_TWO_PHASE_COMMITTED')
        self.assertEqual(self.coord.recover()['status'],'STABLE')
        self.assertFalse(r['engineering_accepted'])
    def test_two_appends(self):
        self.coord.append(**self.fixture())
        self.coord.append(**self.fixture('TEST-CAPTURE-2'))
        self.assertEqual(self.pin.snapshot()['count'],2)
    def test_prepare_failure_recover_abort(self):
        self.pin.fail_prepare=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        self.pin.fail_prepare=False
        self.assertEqual(self.coord.recover()['status'],'ABORTED_UNAPPENDED')
        self.assertEqual(self.coord.recover()['status'],'STABLE')
    def test_commit_failure_recover_commit(self):
        self.pin.fail_commit=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        self.assertEqual(self.reg.audit()['count'],1)
        self.assertEqual(self.pin.snapshot()['count'],0)
        self.pin.fail_commit=False
        self.assertEqual(self.coord.recover()['status'],'RECOVERED_COMMITTED')
        self.assertEqual(self.coord.recover()['status'],'STABLE')
    def test_commit_failure_blocks_next_append(self):
        self.pin.fail_commit=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        with self.assertRaisesRegex(CheckpointHold,'PENDING_CHECKPOINT_REQUIRES_RECOVERY'): self.coord.append(**self.fixture('TEST-CAPTURE-2'))
        self.assertEqual(self.reg.audit()['count'],1)
    def test_prepare_reserved_but_not_appended_recover_abort(self):
        self.pin.fail_prepare=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        self.pin.fail_prepare=False
        txid,old,new=self.coord._pending()
        self.pin.prepare(txid,old,new)
        self.assertEqual(self.coord.recover()['status'],'ABORTED_UNAPPENDED')
        self.assertIsNone(self.pin.pending)
    def test_external_commit_ahead_of_local_append_holds(self):
        self.pin.fail_prepare=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        self.pin.fail_prepare=False
        txid,old,new=self.coord._pending()
        self.pin.prepare(txid,old,new); self.pin.commit(txid,old,new)
        with self.assertRaisesRegex(CheckpointHold,'EXTERNAL_COMMITTED_WITHOUT_LOCAL_APPEND'):
            self.coord.recover()
    def test_local_tamper_holds(self):
        self.coord.append(**self.fixture())
        self.reg.db.execute('DROP TRIGGER entries_no_update')
        self.reg.db.execute("UPDATE entries SET collector_id='tampered' WHERE seq=1")
        with self.assertRaises(Exception): self.coord.recover()
    def test_external_pin_rollback_holds(self):
        self.coord.append(**self.fixture())
        self.pin.current={'count':0,'head':GENESIS}
        with self.assertRaisesRegex(CheckpointHold,'LOCAL_AND_EXTERNAL_HIGH_WATER_DIFFER'):
            self.coord.recover()
    def test_duplicate_capture_rejected_without_new_pin(self):
        self.coord.append(**self.fixture())
        with self.assertRaises(Exception): self.coord.append(**self.fixture())
        self.assertEqual(self.pin.snapshot()['count'],1)
    def test_bad_signature_rejected_before_prepare(self):
        args=self.fixture();args['receipt_signature_hex']='00'*64
        with self.assertRaises(CheckpointHold): self.coord.append(**args)
        self.assertIsNone(self.coord._pending())
    def test_reopen_recovery(self):
        self.pin.fail_commit=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        self.coord.close(); self.reg.close()
        self.reg=OfflineReplayRegistry(Path(self.temp.name)/'registry.sqlite')
        self.coord=TwoPhaseCheckpoint(self.reg,self.pin)
        self.pin.fail_commit=False
        self.assertEqual(self.coord.recover()['status'],'RECOVERED_COMMITTED')
    def test_exclusive_coordinator_lock_refuses_second_process(self):
        import sqlite3
        lock=sqlite3.connect(self.reg.path+'.coordlock', isolation_level=None)
        lock.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaisesRegex(CheckpointHold,'COORDINATOR_BUSY'):
                self.coord.recover()
        finally:
            lock.execute('ROLLBACK');lock.close()

    def test_external_commit_then_crash_before_journal_finish(self):
        old_finish=self.coord._finish
        def crash(*args):
            raise RuntimeError('SIMULATED_CRASH_AFTER_EXTERNAL_COMMIT')
        self.coord._finish=crash
        with self.assertRaisesRegex(RuntimeError,'SIMULATED_CRASH'):
            self.coord.append(**self.fixture())
        self.coord._finish=old_finish
        self.assertEqual(self.pin.snapshot()['count'],1)
        self.assertEqual(self.coord.recover()['status'],'RECOVERED_COMMITTED')
        self.assertEqual(self.coord.recover()['status'],'STABLE')

    def test_abort_unavailable_holds(self):
        self.pin.fail_prepare=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        self.pin.fail_prepare=False
        txid,old,new=self.coord._pending();self.pin.prepare(txid,old,new)
        self.pin.fail_abort=True
        with self.assertRaisesRegex(CheckpointHold,'EXTERNAL_ABORT_UNAVAILABLE'):
            self.coord.recover()
        self.assertIsNotNone(self.coord._pending())
    def test_divergent_external_reservation_holds(self):
        self.pin.fail_prepare=True
        with self.assertRaises(CheckpointHold): self.coord.append(**self.fixture())
        self.pin.fail_prepare=False
        txid,old,new=self.coord._pending()
        self.pin.pending={'txid':txid,'old':old,'new':{'count':42,'head':'0'*64}}
        with self.assertRaisesRegex(CheckpointHold,'EXTERNAL_RESERVATION_MISMATCH'):
            self.coord.recover()

if __name__=='__main__':unittest.main()
