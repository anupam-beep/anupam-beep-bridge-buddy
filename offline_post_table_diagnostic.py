"""Offline, fail-closed Civil NX POST/TABLE *evidence* triage.

No networking, API keys, model access, analysis, file writes, or certification.
Accepts only synthetic/sanitized, bounded JSON envelope supplied by operator.
Never echoes request/response contents. Observations are NOT root-cause proof.
"""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path

MAX_FILE = 512_000
MAX_DEPTH = 24
MAX_NODES = 100_000
MAX_ROWS = 20_000
ALLOWED_FIELDS = frozenset({'method', 'path', 'http_status', 'request_body', 'response_body', 'analysis_completion_evidence'})
RESULT_STATUS = 'OFFLINE_DIAGNOSTIC_ONLY_NOT_CERTIFIED'

class UnsafeEvidence(ValueError):
    pass


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise UnsafeEvidence('DUPLICATE_JSON_KEY')
        out[k] = v
    return out


def _bounded_tree(root):
    stack = [(root, 0)]
    n = 0
    while stack:
        obj, depth = stack.pop()
        n += 1
        if n > MAX_NODES or depth > MAX_DEPTH:
            raise UnsafeEvidence('EVIDENCE_COMPLEXITY_EXCEEDED')
        if isinstance(obj, dict):
            stack.extend((x, depth+1) for x in obj.values())
        elif isinstance(obj, list):
            stack.extend((x, depth+1) for x in obj)
        elif not (obj is None or type(obj) in (str, int, float, bool)):
            raise UnsafeEvidence('EVIDENCE_TYPE_UNSUPPORTED')
        if type(obj) is float and not math.isfinite(obj):
            raise UnsafeEvidence('NONFINITE_NUMBER')


def parse_sanitized_json(raw: bytes):
    if not isinstance(raw, bytes) or len(raw) > MAX_FILE:
        raise UnsafeEvidence('EVIDENCE_TOO_LARGE')
    try:
        obj = json.loads(raw.decode('utf-8'), object_pairs_hook=_no_duplicates,
                         parse_constant=lambda _: (_ for _ in ()).throw(UnsafeEvidence('NONFINITE_NUMBER')))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UnsafeEvidence('INVALID_JSON_OR_ENCODING') from None
    _bounded_tree(obj)
    return obj


def _numeric_cell(v):
    return type(v) in (int, float) and math.isfinite(v)


IDENTIFIER_COLUMNS = frozenset({'index', 'idx', 'id', 'elem', 'element', 'node', 'beam',
                                'row', 'no', 'number', 'load', 'part', 'case', 'stage'})

def _has_result_number(row, head):
    if isinstance(row, dict):
        return any(_numeric_cell(v) and str(k).strip().lower() not in IDENTIFIER_COLUMNS
                   for k, v in row.items())
    return any(_numeric_cell(v) and j < len(head) and
               head[j].strip().lower() not in IDENTIFIER_COLUMNS
               for j, v in enumerate(row))


def _extract_tables(body):
    """Find HEAD/DATA by shape; response wrapper name is not stable."""
    if not isinstance(body, dict):
        return []
    found = []
    for val in body.values():
        if isinstance(val, dict) and 'HEAD' in val and 'DATA' in val:
            found.append(val)
    if 'HEAD' in body and 'DATA' in body:
        found.append(body)
    return found


def diagnose(evidence):
    """Return bounded reason codes, never evidence contents or any success certification."""
    issues = []
    hints = []
    def add(code, hint=None):
        if code not in issues:
            issues.append(code)
        if hint and hint not in hints:
            hints.append(hint)

    if not isinstance(evidence, dict) or not set(evidence).issubset(ALLOWED_FIELDS):
        raise UnsafeEvidence('INVALID_OR_SENSITIVE_ENVELOPE')
    _bounded_tree(evidence)
    if evidence.get('method') != 'POST' or not isinstance(evidence.get('path'), str) or evidence['path'].lower() not in ('/post/table', '/civil/post/table'):
        add('ENDPOINT_OR_METHOD_NOT_ALLOWED', 'Verify the exact endpoint and method from approved documentation; never auto-send.')
    code = evidence.get('http_status')
    if type(code) is not int or code < 100 or code > 599:
        add('HTTP_STATUS_MISSING_OR_INVALID')
    elif code < 200 or code >= 300:
        add('HTTP_NON_2XX', 'Check the status and independently retained sanitized failure evidence.')
    elif code == 200:
        add('HTTP_200_NOT_PROOF_OF_RESULT')

    req = evidence.get('request_body')
    if not isinstance(req, dict) or not isinstance(req.get('Argument'), dict):
        add('REQUEST_ARGUMENT_MISSING', 'MIDAS requires an Argument object containing TABLE_TYPE.')
        arg = {}
    else:
        arg = req['Argument']
    if not isinstance(arg.get('TABLE_TYPE'), str) or not arg.get('TABLE_TYPE', '').strip():
        add('TABLE_TYPE_MISSING', 'Verify TABLE_TYPE enum against the specific result table manual.')
    if 'EXPORT_PATH' in arg:
        add('EXPORT_PATH_PRESENT', 'Remove EXPORT_PATH from future read-only diagnostic request plans; no remote file writes.')
    if 'LOAD_CASE_NAMES' in arg and (not isinstance(arg['LOAD_CASE_NAMES'], list) or any(not isinstance(x, str) for x in arg['LOAD_CASE_NAMES'])):
        add('LOAD_CASE_FILTER_INVALID')
    elif isinstance(arg.get('LOAD_CASE_NAMES'), list) and arg['LOAD_CASE_NAMES']:
        add('LOAD_CASE_FILTER_REQUIRES_VERIFICATION', 'Compare exact case names and suffixes (ST/CB/MV/CS) to the model.')
    if 'NODE_ELEMS' in arg:
        ne = arg['NODE_ELEMS']
        if not isinstance(ne, dict) or not (set(ne) & {'KEYS', 'TO', 'STRUCTURE_GROUP_NAME'}):
            add('NODE_ELEMENT_SELECTOR_INVALID')
        else:
            add('NODE_ELEMENT_SELECTOR_REQUIRES_VERIFICATION', 'Check that requested node/element IDs actually exist.')
    if 'OPT_CS' in arg and type(arg['OPT_CS']) is not bool:
        add('OPT_CS_INVALID')
    if 'STAGE_STEP' in arg and arg.get('OPT_CS') is not True:
        add('STAGE_STEP_WITHOUT_OPT_CS', 'Construction-stage table queries require OPT_CS true and valid STAGE_STEP.')
    if 'STAGE_STEP' in arg and (not isinstance(arg['STAGE_STEP'], list) or any(not isinstance(x, str) for x in arg['STAGE_STEP'])):
        add('STAGE_STEP_INVALID')
    if 'PARTS' in arg and (not isinstance(arg['PARTS'], list) or any(not isinstance(x, str) for x in arg['PARTS'])):
        add('PARTS_INVALID')

    body = evidence.get('response_body')
    numeric_rows = 0
    table_count = 0
    if not isinstance(body, dict):
        add('RESPONSE_MISSING_OR_NOT_OBJECT')
    else:
        if 'error' in body:
            add('API_ERROR_BODY', 'HTTP 2xx can still contain a failure body.')
        if 'message' in body:
            msg = body['message']
            if msg == '':
                add('EMPTY_MESSAGE_NO_RESULT', 'An empty message is not a result table or proof of completed analysis.')
            elif isinstance(msg, str) and 'fail' in msg.lower():
                add('FAILURE_MESSAGE', 'Confirm analysis completion from independently verified evidence.')
            elif isinstance(msg, str):
                add('MESSAGE_ONLY_NOT_RESULT')
        tables = _extract_tables(body)
        table_count = len(tables)
        if not tables:
            add('NO_HEAD_DATA_TABLE', 'A wrapper named empty is not inherently a failure; inspect HEAD/DATA shape.')
        for table in tables:
            head, data = table['HEAD'], table['DATA']
            if not isinstance(head, list) or not all(isinstance(h, str) for h in head):
                add('TABLE_HEAD_INVALID')
                continue
            if not isinstance(data, list) or len(data) > MAX_ROWS:
                add('TABLE_DATA_INVALID_OR_TOO_LARGE')
                continue
            if not data:
                add('TABLE_ZERO_ROWS', 'Verify completed analysis and table selectors before interpreting empty rows.')
            for row in data:
                if not isinstance(row, (list, dict)):
                    add('TABLE_ROW_INVALID')
                    continue
                if isinstance(row, list) and len(row) != len(head):
                    add('TABLE_ROW_HEADER_MISMATCH')
                if _has_result_number(row, head):
                    numeric_rows += 1
        if table_count and numeric_rows == 0:
            add('NO_NUMERIC_RESULT_ROWS')
    # These flags are NOT accepted as independently verified: cannot be self-attested.
    if evidence.get('analysis_completion_evidence') is not None:
        add('SELF_REPORTED_ANALYSIS_EVIDENCE_NOT_TRUSTED')
    add('INDEPENDENT_COMPLETION_AND_PROVENANCE_MISSING', 'Require signed completion witness, original-byte binding and independent checkpoint before certification.')
    # Remove generic informational code from blocking issues for clearer classification.
    material = [i for i in issues if i != 'HTTP_200_NOT_PROOF_OF_RESULT']
    nonblocking = {'INDEPENDENT_COMPLETION_AND_PROVENANCE_MISSING',
                   'LOAD_CASE_FILTER_REQUIRES_VERIFICATION',
                   'NODE_ELEMENT_SELECTOR_REQUIRES_VERIFICATION',
                   'SELF_REPORTED_ANALYSIS_EVIDENCE_NOT_TRUSTED'}
    if numeric_rows and all(i in nonblocking for i in material):
        classification = 'NUMERIC_TABLE_SHAPE_PRESENT_UNVERIFIED'
    else:
        classification = 'RESULT_EXTRACTION_INCOMPLETE'
    return {
        'status': RESULT_STATUS, 'classification': classification,
        'issue_codes': issues, 'hypothesis_hints': hints,
        'table_shapes_detected': table_count, 'rows_with_numeric_cells': numeric_rows,
        'live_verified': False, 'engineering_accepted': False,
        'civil_nx_contacted': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline sanitized Civil NX POST/TABLE triage; never calls NX')
    parser.add_argument('sanitized_fixture_json', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.sanitized_fixture_json.is_symlink():
            raise UnsafeEvidence('SYMLINK_INPUT_REJECTED')
        with args.sanitized_fixture_json.open('rb') as f:
            raw = f.read(MAX_FILE+1)
        output = diagnose(parse_sanitized_json(raw))
    except (OSError, UnsafeEvidence, TypeError, AttributeError, RecursionError):
        output = {'status': RESULT_STATUS, 'classification': 'EVIDENCE_REJECTED',
                  'issue_codes': ['INPUT_REJECTED'], 'live_verified': False,
                  'engineering_accepted': False, 'civil_nx_contacted': False}
    print(json.dumps(output, indent=2))
    return 0 if output['classification'] == 'NUMERIC_TABLE_SHAPE_PRESENT_UNVERIFIED' else 2

if __name__ == '__main__':
    raise SystemExit(main())
