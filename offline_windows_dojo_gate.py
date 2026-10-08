"""Candidate-only, fail-closed native Windows synthetic-test evidence gate.

No MIDAS access, network access, live-model writes, or engineering certification.
The lockfile and JSON report are self-declared integrity evidence, NOT signatures.
Only synthetic unit tests run. A native Windows result is NOT proof of security.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import sys
import unittest

SCHEMA = 'bridgeagent_windows_synthetic_dojo_v1'
SUITES = {
    'test_offline_snapshot_reader': 26,
    'test_windows_root_contract': 34,
    'test_windows_snapshot_runtime': 13,
    'test_windows_snapshot_safety_contract': 4,
    'test_windows_win32_mock_dojo': 25,
}
REQUIRED_NATIVE_SUITE = 'test_windows_snapshot_runtime'
# Pinned identities of every expected test, not just the number of tests.
# SHA256(json.dumps(sorted(test_ids), separators=(',', ':')).encode('utf-8'))
# Values are candidate-code pins, NOT independent attestations.
SUITE_TEST_IDS_SHA256 = {
    'test_offline_snapshot_reader': 'f8cf61bf8aaf9ccee7e19958f10c21e6ee76d6aef9b10a5eef75c5de8b21cfa0',
    'test_windows_root_contract': 'f47ad26142d702d4bbc09beccb6254ff25ba685e242bca9bf534887a44e07fbb',
    'test_windows_snapshot_runtime': '60f721404b6157e3335ceb4c9c2e79f8ab98df2df5052fe92edd0de84fd6bb40',
    'test_windows_snapshot_safety_contract': 'a635c94a6666a97f3649a89ea75b1482b1563a97e08196bcf2ac10f72f7344c8',
    'test_windows_win32_mock_dojo': 'ea6752a2dfc60de63dc50a62d3c3763a3cd157a682c444f2722c1f0468df2ff1',
}
SOURCE_FILES = (
    'offline_snapshot_reader.py',
    'offline_windows_dojo_gate.py',
    'run_windows_synthetic_dojo.ps1',
    'test_offline_windows_dojo_gate.py',
    'test_offline_snapshot_reader.py',
    'test_windows_root_contract.py',
    'test_windows_snapshot_runtime.py',
    'test_windows_snapshot_safety_contract.py',
    'test_windows_win32_mock_dojo.py',
)
# The following skips are expected on Windows because they test POSIX-only APIs.
ALLOWED_WINDOWS_SKIPS = frozenset({
    'test_offline_snapshot_reader.SnapshotReaderTests.test_fifo_rejected_nonblocking',
    'test_offline_snapshot_reader.SnapshotReaderTests.test_changed_during_read_rejected',
    'test_offline_snapshot_reader.SnapshotReaderTests.test_changed_same_length_rejected',
    'test_offline_snapshot_reader.SnapshotReaderTests.test_parent_swap_cannot_redirect_pinned_reader',
    'test_offline_snapshot_reader.SnapshotReaderTests.test_final_name_replacement_does_not_redirect_reader',
})
HEX = re.compile(r'^[0-9a-f]{64}$')


class DojoGateRejected(ValueError):
    """No paths, content, secrets or test tracebacks in exception messages."""


def native_windows() -> bool:
    return os.name == 'nt' and sys.platform == 'win32' and platform.system() == 'Windows'


def source_hashes(folder: Path) -> dict[str, str]:
    out = {}
    for name in SOURCE_FILES:
        p = folder / name
        if not p.is_file() or p.is_symlink() or p.stat().st_size > 1_000_000:
            raise DojoGateRejected('SOURCE_FILE_INVALID')
        out[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def read_lock(folder: Path) -> dict[str, str]:
    p = folder / 'windows_native_suite_lock.json'
    if not p.is_file() or p.is_symlink() or p.stat().st_size > 16_384:
        raise DojoGateRejected('SUITE_LOCK_INVALID')
    try:
        data = json.loads(p.read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError):
        raise DojoGateRejected('SUITE_LOCK_INVALID') from None
    if (not isinstance(data, dict) or data.get('schema') != 'self_declared_suite_lock_v1'
            or set(data) != {'schema', 'source_sha256', 'authenticity'}
            or data.get('authenticity') != 'SELF_DECLARED_NOT_INDEPENDENT'):
        raise DojoGateRejected('SUITE_LOCK_INVALID')
    digests = data['source_sha256']
    if (not isinstance(digests, dict) or set(digests) != set(SOURCE_FILES)
            or any(not isinstance(h, str) or not HEX.fullmatch(h) for h in digests.values())):
        raise DojoGateRejected('SUITE_LOCK_INVALID')
    return digests


def verify_lock(folder: Path) -> dict[str, str]:
    expected = read_lock(folder)
    if source_hashes(folder) != expected:
        raise DojoGateRejected('SOURCE_LOCK_MISMATCH')
    return expected


def _suite_tests(suite):
    """Enumerate concrete unittest cases; never trust count-only discovery."""
    if not isinstance(suite, unittest.TestSuite):
        raise DojoGateRejected('INVALID_TEST_DISCOVERY')
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _suite_tests(item)
        elif isinstance(item, unittest.TestCase):
            yield item
        else:
            raise DojoGateRejected('INVALID_TEST_DISCOVERY')


def _identity_digest(ids: list[str]) -> str:
    raw = json.dumps(sorted(ids), separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def verify_suite_identity(module: str, suite: unittest.TestSuite) -> list[str]:
    """Fail if any expected test is renamed, replaced, duplicated or omitted."""
    if module not in SUITES:
        raise DojoGateRejected('UNKNOWN_TEST_SUITE')
    tests = list(_suite_tests(suite))
    ids = [t.id() for t in tests]
    if (len(ids) != SUITES[module] or len(ids) != len(set(ids))
            or any(not isinstance(tid, str) or not tid.startswith(module + '.')
                   or len(tid) > 200 for tid in ids)
            or _identity_digest(ids) != SUITE_TEST_IDS_SHA256[module]):
        raise DojoGateRejected('TEST_IDENTITY_MISMATCH')
    return ids


class _IdentityTrackingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_ids = []

    def startTest(self, test):
        self.executed_ids.append(test.id())
        super().startTest(test)


def _check_suite(suite_name: str, result: dict) -> None:
    if not isinstance(result, dict) or set(result) != {'ran', 'failures', 'errors', 'skipped_ids'}:
        raise DojoGateRejected('MALFORMED_SUITE_RESULT')
    if (type(result['ran']) is not int or result['ran'] != SUITES[suite_name]
            or any(type(result[k]) is not int or result[k] < 0 or result[k] > result['ran']
                   for k in ('failures', 'errors'))):
        raise DojoGateRejected('SUITE_COUNT_MISMATCH')
    skipped = result['skipped_ids']
    if (not isinstance(skipped, list) or len(skipped) > result['ran']
            or any(not isinstance(s, str) or len(s) > 180 for s in skipped)
            or len(skipped) != len(set(skipped))):
        raise DojoGateRejected('MALFORMED_SKIP_RECORD')
    if result['failures'] or result['errors']:
        raise DojoGateRejected('TEST_FAILURES_PRESENT')
    if suite_name == REQUIRED_NATIVE_SUITE and skipped:
        raise DojoGateRejected('NATIVE_TESTS_SKIPPED')
    if any(not s.startswith(suite_name + '.') for s in skipped):
        raise DojoGateRejected('SKIP_SUITE_MISMATCH')
    if suite_name != REQUIRED_NATIVE_SUITE and any(s not in ALLOWED_WINDOWS_SKIPS for s in skipped):
        raise DojoGateRejected('UNEXPECTED_TEST_SKIP')
    if result['failures'] + result['errors'] + len(skipped) > result['ran']:
        raise DojoGateRejected('INCONSISTENT_TEST_COUNTS')


def evaluate(report: object, expected_source_hashes: dict[str, str]) -> str:
    """Gate a self-reported native synthetic run; never certify engineering use.

    Returns WINDOWS_SYNTHETIC_TESTS_PASS only for a fully populated report.
    This is an operational test gate, not an independently attested certificate.
    """
    if not isinstance(report, dict) or set(report) != {
        'schema', 'platform', 'python', 'suites', 'source_sha256',
        'civil_nx_calls', 'model_writes', 'engineering_accepted',
        'independent_authenticity', 'test_scope', 'suite_ids_sha256',
    }:
        raise DojoGateRejected('MALFORMED_REPORT')
    if (report['schema'] != SCHEMA or report['platform'] != 'WINDOWS_NATIVE'
            or report['test_scope'] != 'OFFLINE_SYNTHETIC_ONLY'
            or report['civil_nx_calls'] != 0 or type(report['civil_nx_calls']) is not int
            or report['model_writes'] != 0 or type(report['model_writes']) is not int
            or report['engineering_accepted'] is not False
            or report['independent_authenticity'] is not False):
        raise DojoGateRejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')
    if (not isinstance(report['python'], str) or not re.fullmatch(r'3\.(?:1[0-9]|[89])\.\d+', report['python'])):
        raise DojoGateRejected('INVALID_PYTHON_VERSION')
    if (not isinstance(expected_source_hashes, dict)
            or set(expected_source_hashes) != set(SOURCE_FILES)
            or any(not isinstance(h, str) or not HEX.fullmatch(h) for h in expected_source_hashes.values())
            or report['source_sha256'] != expected_source_hashes):
        raise DojoGateRejected('SOURCE_LOCK_MISMATCH')
    if (not isinstance(report['suite_ids_sha256'], dict)
            or report['suite_ids_sha256'] != SUITE_TEST_IDS_SHA256):
        raise DojoGateRejected('TEST_IDENTITY_MISMATCH')
    suites = report['suites']
    if not isinstance(suites, dict) or set(suites) != set(SUITES):
        raise DojoGateRejected('REQUIRED_SUITES_MISSING')
    for name, outcome in suites.items():
        _check_suite(name, outcome)
    return 'WINDOWS_SYNTHETIC_TESTS_PASS'


def run_synthetic(folder: Path) -> dict:
    """Run a fixed, offline test allowlist only on native Windows.

    Never labels results independently authenticated. Never runs on Linux.
    """
    if not native_windows():
        raise DojoGateRejected('NATIVE_WINDOWS_REQUIRED')
    if sys.version_info < (3, 8):
        raise DojoGateRejected('PYTHON_VERSION_UNSUPPORTED')
    verify_lock(folder)
    sys.dont_write_bytecode = True
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
    suites = {}
    for module in SUITES:
        suite = unittest.defaultTestLoader.loadTestsFromName(module)
        expected_ids = verify_suite_identity(module, suite)
        result = unittest.TextTestRunner(
            stream=io.StringIO(), verbosity=0, resultclass=_IdentityTrackingResult
        ).run(suite)
        if sorted(result.executed_ids) != sorted(expected_ids):
            raise DojoGateRejected('EXECUTED_TEST_IDENTITY_MISMATCH')
        suites[module] = {
            'ran': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'skipped_ids': [test.id() for test, _reason in result.skipped],
        }
    report = {
        'schema': SCHEMA,
        'platform': 'WINDOWS_NATIVE',
        'python': f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}',
        'suites': suites,
        'source_sha256': source_hashes(folder),
        'suite_ids_sha256': dict(SUITE_TEST_IDS_SHA256),
        'civil_nx_calls': 0,
        'model_writes': 0,
        'engineering_accepted': False,
        'independent_authenticity': False,
        'test_scope': 'OFFLINE_SYNTHETIC_ONLY',
    }
    evaluate(report, read_lock(folder))
    return report


def main() -> int:
    folder = Path(__file__).parent
    try:
        report = run_synthetic(folder)
    except DojoGateRejected as exc:
        # Do not serialize potentially sensitive test failures or file paths.
        print(json.dumps({'status': 'BLOCKED', 'reason': str(exc),
                          'native_windows_validated': False,
                          'engineering_accepted': False}, sort_keys=True))
        return 2
    print(json.dumps({'status': 'WINDOWS_SYNTHETIC_TESTS_PASS', 'report': report,
                      'native_windows_validated': True,
                      'engineering_accepted': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
