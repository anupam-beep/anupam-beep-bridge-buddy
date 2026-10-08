"""Synthetic-only regression fixtures; not a Civil NX analysis or engineering validation."""
import copy
import json
import unittest
from offline_result_certifier import canonical_bytes, certify, digest, inspect_table

MODEL_BYTES = b'{"verified":"synthetic-only"}'
HEAD = ['Index','Node','Load','Stage','Step','DX','DY','DZ','RX','RY','RZ']
ROW = ['1','15','Summation','Service Stage','001(last)','1.0e-03','0.0','-2.0e-03','0','0','0']
RESPONSE = canonical_bytes({'Displacements(Global)': {'FORCE':'N','DIST':'mm','HEAD':HEAD,'DATA':[ROW]}})
SELECTOR = {'TABLE_TYPE':'DISPLACEMENTG','NODE_ELEMS':{'KEYS':[15]},'LOAD_CASE_NAMES':['Summation(CS)'],'OPT_CS':True,'STAGE_STEP':[]}

def fixture():
    return {
      'execution_enabled':False, 'model_evidence':{'sha256':digest(MODEL_BYTES),'captured_at':'2026-01-01T09:00:00+00:00'},
      'authorization':{'authorization_id':'SYNTHETIC-NOT-AUTHORIZED','scope':'analysis/read-only-results'},
      'analysis':{'run_id':'SYNTHETIC-RUN','status':'COMPLETED','started_at':'2026-01-01T10:00:00+00:00','completed_at':'2026-01-01T10:30:00+00:00'},
      'result_request':{'method':'POST','path':'/post/TABLE','selector':copy.deepcopy(SELECTOR),'selector_sha256':digest(canonical_bytes(SELECTOR))},
      'result_response':{'captured_at':'2026-01-01T10:31:00+00:00','raw_payload_sha256':digest(RESPONSE)},
      'binding':{'model_sha256':digest(MODEL_BYTES),'analysis_run_id':'SYNTHETIC-RUN','result_analysis_run_id':'SYNTHETIC-RUN','authorization_id':'SYNTHETIC-NOT-AUTHORIZED'},
      'certification':{'engineering_acceptance':False}
    }

class TestQuality(unittest.TestCase):
    def assert_hold(self, obj):
        raw = canonical_bytes(obj)
        self.assertEqual(inspect_table(raw, expected_node=15, expected_load='Summation(CS)')['status'],'HOLD')
    def test_official_shape_passes(self):
        self.assertEqual(inspect_table(RESPONSE,expected_node=15,expected_load='Summation(CS)')['status'],'STRUCTURAL_PASS')
    def test_empty_message(self): self.assert_hold({'message':''})
    def test_empty_object(self): self.assert_hold({})
    def test_empty_data(self): self.assert_hold({'empty':{'HEAD':HEAD,'DATA':[]}})
    def test_empty_row(self): self.assert_hold({'empty':{'HEAD':HEAD,'DATA':[[]]}})
    def test_missing_head(self): self.assert_hold({'empty':{'DATA':[ROW]}})
    def test_wrong_node(self):
        row=ROW.copy(); row[1]='16'; self.assert_hold({'empty':{'HEAD':HEAD,'DATA':[row]}})
    def test_wrong_load(self):
        row=ROW.copy(); row[2]='Other'; self.assert_hold({'empty':{'HEAD':HEAD,'DATA':[row]}})
    def test_missing_stage(self):
        row=ROW.copy(); row[3]=''; self.assert_hold({'empty':{'HEAD':HEAD,'DATA':[row]}})
    def test_nan_value(self):
        row=ROW.copy(); row[5]='NaN'; self.assert_hold({'empty':{'HEAD':HEAD,'DATA':[row]}})
    def test_duplicate_json_keys(self):
        raw=b'{"a":1,"a":2}'
        self.assertEqual(inspect_table(raw,expected_node=15,expected_load='Summation(CS)')['status'],'HOLD')
    def test_ambiguous_tables(self):
        table={'HEAD':HEAD,'DATA':[ROW]}; self.assert_hold({'a':table,'b':table})
    def test_api_error_200(self): self.assert_hold({'error':{'message':'Please perform analysis'}})

class TestCrossGate(unittest.TestCase):
    def assert_rejected(self, edit=None, response=RESPONSE, model=MODEL_BYTES):
        e=fixture()
        if edit: edit(e)
        self.assertEqual(certify(e,model,response)['status'],'HOLD')
    def test_synthetic_valid(self):
        got=certify(fixture(),MODEL_BYTES,RESPONSE)
        self.assertEqual(got['status'],'OFFLINE_GATES_PASS')
        self.assertFalse(got['engineering_accepted'])
        self.assertFalse(got['live_verified'])
    def test_missing_analysis(self): self.assert_rejected(lambda e:e['analysis'].update(status='NOT_RUN'))
    def test_wrong_model_bytes(self): self.assert_rejected(model=b'changed')
    def test_wrong_run_binding(self): self.assert_rejected(lambda e:e['binding'].update(result_analysis_run_id='other'))
    def test_stale_response(self): self.assert_rejected(lambda e:e['result_response'].update(captured_at='2026-01-01T10:00:00+00:00'))
    def test_unzoned_time(self): self.assert_rejected(lambda e:e['analysis'].update(completed_at='2026-01-01T10:30:00'))
    def test_wrong_selector_hash(self): self.assert_rejected(lambda e:e['result_request'].update(selector_sha256='0'*64))
    def test_wrong_payload_hash(self): self.assert_rejected(lambda e:e['result_response'].update(raw_payload_sha256='0'*64))
    def test_structural_fail_even_with_correct_hash(self):
        raw=canonical_bytes({'message':''})
        self.assert_rejected(lambda e:e['result_response'].update(raw_payload_sha256=digest(raw)),response=raw)
    def test_engineering_acceptance_must_be_false(self): self.assert_rejected(lambda e:e['certification'].update(engineering_acceptance=True))
    def test_live_execution_lock(self): self.assert_rejected(lambda e:e.update(execution_enabled=True))
    def test_authorization_binding(self): self.assert_rejected(lambda e:e['authorization'].update(authorization_id='different'))
    def test_selector_mutation_even_if_hash_updated(self):
        def mutate(e):
            e['result_request']['selector']['NODE_ELEMS']['KEYS']=[99]
            e['result_request']['selector_sha256']=digest(canonical_bytes(e['result_request']['selector']))
        self.assert_rejected(mutate)

if __name__=='__main__': unittest.main(verbosity=2)
