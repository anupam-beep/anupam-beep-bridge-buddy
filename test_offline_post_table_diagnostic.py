"""Synthetic offline-only Bridge Dojo: Civil NX result triage; never network."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from offline_post_table_diagnostic import (
    MAX_FILE, UnsafeEvidence, diagnose, parse_sanitized_json, main,
)


def case(**kw):
    v = {'method':'POST', 'path':'/post/TABLE', 'http_status':200,
         'request_body':{'Argument':{'TABLE_TYPE':'BEAMFORCE'}},
         'response_body':{'Result Table':{'HEAD':['Index','Force'], 'DATA':[[1,2.3]]}}}
    v.update(kw)
    return v

class OfflineResultDiagnosticDojo(unittest.TestCase):
    def codes(self, **kw):
        return diagnose(case(**kw))['issue_codes']

    def test_numeric_shape_not_certification(self):
        v=diagnose(case())
        self.assertEqual(v['classification'], 'NUMERIC_TABLE_SHAPE_PRESENT_UNVERIFIED')
        self.assertFalse(v['live_verified'])
        self.assertFalse(v['engineering_accepted'])
        self.assertFalse(v['civil_nx_contacted'])

    def test_empty_named_wrapper_can_hold_valid_table(self):
        self.assertEqual(diagnose(case(response_body={'empty':{'HEAD':['Index','Fx'],'DATA':[[1,100.0]]}}))['table_shapes_detected'],1)

    def test_message_empty_is_incomplete(self):
        r=diagnose(case(response_body={'message':''}))
        self.assertEqual(r['classification'], 'RESULT_EXTRACTION_INCOMPLETE')
        self.assertIn('EMPTY_MESSAGE_NO_RESULT',r['issue_codes'])

    def test_error_even_http200(self):
        self.assertIn('API_ERROR_BODY', self.codes(response_body={'error':{'code':1}}))

    def test_analysis_failure_message(self):
        self.assertIn('FAILURE_MESSAGE', self.codes(response_body={'message':'Analysis failed.'}))

    def test_success_message_not_table(self):
        self.assertIn('MESSAGE_ONLY_NOT_RESULT', self.codes(response_body={'message':'command complete'}))

    def test_http_500(self):
        self.assertIn('HTTP_NON_2XX', self.codes(http_status=500))

    def test_bool_http_status_invalid(self):
        self.assertIn('HTTP_STATUS_MISSING_OR_INVALID', self.codes(http_status=True))

    def test_invalid_endpoint(self):
        self.assertIn('ENDPOINT_OR_METHOD_NOT_ALLOWED', self.codes(path='/doc/SAVE'))

    def test_get_method_invalid(self):
        self.assertIn('ENDPOINT_OR_METHOD_NOT_ALLOWED', self.codes(method='GET'))

    def test_civil_prefix_allowed(self):
        self.assertNotIn('ENDPOINT_OR_METHOD_NOT_ALLOWED', self.codes(path='/civil/post/table'))

    def test_missing_argument(self):
        self.assertIn('REQUEST_ARGUMENT_MISSING', self.codes(request_body={}))

    def test_missing_tabletype(self):
        self.assertIn('TABLE_TYPE_MISSING', self.codes(request_body={'Argument':{}}))

    def test_export_path_warns(self):
        self.assertIn('EXPORT_PATH_PRESENT', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','EXPORT_PATH':'C:/out.json'}}))

    def test_filter_needs_verification(self):
        self.assertIn('LOAD_CASE_FILTER_REQUIRES_VERIFICATION', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','LOAD_CASE_NAMES':['DL(ST)']}}))

    def test_invalid_filter(self):
        self.assertIn('LOAD_CASE_FILTER_INVALID', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','LOAD_CASE_NAMES':'DL(ST)'}}))

    def test_selector_needs_verification(self):
        self.assertIn('NODE_ELEMENT_SELECTOR_REQUIRES_VERIFICATION', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','NODE_ELEMS':{'KEYS':[1]}}}))

    def test_invalid_selector(self):
        self.assertIn('NODE_ELEMENT_SELECTOR_INVALID', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','NODE_ELEMS':{}}}))

    def test_stage_without_opt_cs(self):
        self.assertIn('STAGE_STEP_WITHOUT_OPT_CS', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','STAGE_STEP':['CS1:001(last)']}}))

    def test_valid_cs_stage_no_warning(self):
        self.assertNotIn('STAGE_STEP_WITHOUT_OPT_CS', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','OPT_CS':True,'STAGE_STEP':['CS1:001(last)']}}))

    def test_bad_opt_cs(self):
        self.assertIn('OPT_CS_INVALID', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','OPT_CS':'true'}}))

    def test_bad_parts(self):
        self.assertIn('PARTS_INVALID', self.codes(request_body={'Argument':{'TABLE_TYPE':'BEAMFORCE','PARTS':'Part I'}}))

    def test_empty_rows(self):
        self.assertIn('TABLE_ZERO_ROWS', self.codes(response_body={'empty':{'HEAD':['X'],'DATA':[]}}))

    def test_string_only_rows(self):
        self.assertIn('NO_NUMERIC_RESULT_ROWS', self.codes(response_body={'empty':{'HEAD':['X'],'DATA':[['none']]}}))

    def test_bool_not_numeric(self):
        self.assertIn('NO_NUMERIC_RESULT_ROWS', self.codes(response_body={'empty':{'HEAD':['X'],'DATA':[[True]]}}))

    def test_identifier_numbers_not_result(self):
        self.assertIn('NO_NUMERIC_RESULT_ROWS', self.codes(response_body={'empty':{'HEAD':['Index','Elem','Load','Moment-y'],'DATA':[[1,101,'DL(ST)','missing']]}}))

    def test_numeric_force_with_identifier(self):
        self.assertEqual(diagnose(case(response_body={'empty':{'HEAD':['Index','Elem','Force'],'DATA':[[1,101,-8.2]]}}))['rows_with_numeric_cells'],1)

    def test_missing_tabletype_cannot_be_numeric_candidate(self):
        r=diagnose(case(request_body={'Argument':{}}))
        self.assertEqual(r['classification'], 'RESULT_EXTRACTION_INCOMPLETE')

    def test_nonstring_path_flagged_not_crash(self):
        self.assertIn('ENDPOINT_OR_METHOD_NOT_ALLOWED', self.codes(path=5))

    def test_mismatched_head(self):
        self.assertIn('TABLE_ROW_HEADER_MISMATCH', self.codes(response_body={'empty':{'HEAD':['A','B'],'DATA':[[1]]}}))

    def test_invalid_head(self):
        self.assertIn('TABLE_HEAD_INVALID', self.codes(response_body={'empty':{'HEAD':'A','DATA':[[1]]}}))

    def test_invalid_row(self):
        self.assertIn('TABLE_ROW_INVALID', self.codes(response_body={'empty':{'HEAD':['A'],'DATA':[123]}}))

    def test_self_report_not_independent(self):
        self.assertIn('SELF_REPORTED_ANALYSIS_EVIDENCE_NOT_TRUSTED', self.codes(analysis_completion_evidence={'claimed':True}))

    def test_secret_field_in_envelope_rejected(self):
        with self.assertRaises(UnsafeEvidence):
            diagnose({**case(), 'MAPI-Key':'SECRET'})

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(UnsafeEvidence,'DUPLICATE_JSON_KEY'):
            parse_sanitized_json(b'{"method":"POST","method":"GET"}')

    def test_nonfinite_rejected(self):
        with self.assertRaisesRegex(UnsafeEvidence,'NONFINITE_NUMBER'):
            parse_sanitized_json(b'{"http_status":NaN}')

    def test_too_large_rejected(self):
        with self.assertRaisesRegex(UnsafeEvidence,'EVIDENCE_TOO_LARGE'):
            parse_sanitized_json(b'x'*(MAX_FILE+1))

    def test_depth_limit(self):
        with self.assertRaisesRegex(UnsafeEvidence,'EVIDENCE_COMPLEXITY_EXCEEDED'):
            parse_sanitized_json(json.dumps({'a':[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]}).encode())

    def test_non_json_rejected(self):
        with self.assertRaisesRegex(UnsafeEvidence,'INVALID_JSON_OR_ENCODING'):
            parse_sanitized_json(b'not-json')

    def test_main_redacts_secret_input_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'secret.json'; f.write_text('{"MAPI-Key":"FAKE-SECRET-DO-NOT-LOG"}')
            out=io.StringIO()
            with redirect_stdout(out):
                ret=main([str(f)])
            self.assertEqual(ret,2)
            self.assertNotIn('FAKE-SECRET',out.getvalue())
            self.assertIn('EVIDENCE_REJECTED',out.getvalue())

    def test_main_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a'; a.write_text(json.dumps(case()))
            b=Path(tmp)/'b'; b.symlink_to(a)
            out=io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main([str(b)]),2)
            self.assertIn('EVIDENCE_REJECTED',out.getvalue())

    def test_main_synthetic_good_only_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Path(tmp)/'safe.json'; f.write_text(json.dumps(case()))
            out=io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main([str(f)]),0)
            self.assertIn('NOT_CERTIFIED',out.getvalue())

    def test_no_network_modules_imported(self):
        import offline_post_table_diagnostic as m
        for forbidden in ('requests','urllib.request','socket','http.client'):
            self.assertNotIn(forbidden, m.__dict__)

if __name__=='__main__':
    unittest.main()
