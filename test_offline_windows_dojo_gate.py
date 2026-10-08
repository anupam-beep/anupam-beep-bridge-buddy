"""Synthetic fail-closed gate adversarial tests; safe on Linux and Windows."""
import io
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import offline_windows_dojo_gate as gate


class NativeWindowsDojoGateTests(unittest.TestCase):
    def setUp(self):
        self.hashes = {name: hashlib.sha256(name.encode()).hexdigest() for name in gate.SOURCE_FILES}
        self.report = {
            'schema': gate.SCHEMA,
            'platform': 'WINDOWS_NATIVE',
            'python': '3.13.2',
            'suites': {name: {'ran': count, 'failures': 0, 'errors': 0, 'skipped_ids': []}
                       for name, count in gate.SUITES.items()},
            'source_sha256': self.hashes.copy(),
            'suite_ids_sha256': gate.SUITE_TEST_IDS_SHA256.copy(),
            'civil_nx_calls': 0,
            'model_writes': 0,
            'engineering_accepted': False,
            'independent_authenticity': False,
            'test_scope': 'OFFLINE_SYNTHETIC_ONLY',
        }

    def rejected(self, reason, report=None, hashes=None):
        with self.assertRaisesRegex(gate.DojoGateRejected, reason):
            gate.evaluate(self.report if report is None else report,
                          self.hashes if hashes is None else hashes)

    def test_complete_native_report_accepted_as_synthetic_only(self):
        self.assertEqual(gate.evaluate(self.report, self.hashes), 'WINDOWS_SYNTHETIC_TESTS_PASS')

    def test_allowed_posix_only_skips_do_not_block(self):
        self.report['suites']['test_offline_snapshot_reader']['skipped_ids'] = sorted(gate.ALLOWED_WINDOWS_SKIPS)
        self.assertEqual(gate.evaluate(self.report, self.hashes), 'WINDOWS_SYNTHETIC_TESTS_PASS')

    def test_linux_report_rejected(self):
        self.report['platform'] = 'LINUX'
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_mac_report_rejected(self):
        self.report['platform'] = 'DARWIN'
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_missing_native_suite_rejected(self):
        self.report['suites'].pop(gate.REQUIRED_NATIVE_SUITE)
        self.rejected('REQUIRED_SUITES_MISSING')

    def test_extra_suite_rejected(self):
        self.report['suites']['unknown_test'] = {'ran': 1, 'failures': 0, 'errors': 0, 'skipped_ids': []}
        self.rejected('REQUIRED_SUITES_MISSING')

    def test_native_suite_skip_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE]['skipped_ids'] = [
            'test_windows_snapshot_runtime.WindowsSnapshotRuntime.test_valid_snapshot_hash']
        self.rejected('NATIVE_TESTS_SKIPPED')

    def test_unexpected_skip_rejected(self):
        self.report['suites']['test_windows_root_contract']['skipped_ids'] = [
            'test_windows_root_contract.WindowsRootContract.test_reject_unc']
        self.rejected('UNEXPECTED_TEST_SKIP')

    def test_allowed_skip_wrong_suite_rejected(self):
        self.report['suites']['test_windows_root_contract']['skipped_ids'] = [
            next(iter(gate.ALLOWED_WINDOWS_SKIPS))]
        self.rejected('SKIP_SUITE_MISMATCH')

    def test_duplicate_skip_rejected(self):
        name = next(iter(gate.ALLOWED_WINDOWS_SKIPS))
        self.report['suites']['test_offline_snapshot_reader']['skipped_ids'] = [name, name]
        self.rejected('MALFORMED_SKIP_RECORD')

    def test_nonlist_skip_rejected(self):
        self.report['suites']['test_offline_snapshot_reader']['skipped_ids'] = 'no'
        self.rejected('MALFORMED_SKIP_RECORD')

    def test_wrong_test_count_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE]['ran'] -= 1
        self.rejected('SUITE_COUNT_MISMATCH')

    def test_float_test_count_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE]['ran'] = 13.0
        self.rejected('SUITE_COUNT_MISMATCH')

    def test_negative_failure_count_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE]['failures'] = -1
        self.rejected('SUITE_COUNT_MISMATCH')

    def test_failure_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE]['failures'] = 1
        self.rejected('TEST_FAILURES_PRESENT')

    def test_error_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE]['errors'] = 1
        self.rejected('TEST_FAILURES_PRESENT')

    def test_wrong_hash_rejected(self):
        self.report['source_sha256']['offline_snapshot_reader.py'] = '0' * 64
        self.rejected('SOURCE_LOCK_MISMATCH')

    def test_missing_hash_rejected(self):
        self.report['source_sha256'].pop('offline_snapshot_reader.py')
        self.rejected('SOURCE_LOCK_MISMATCH')

    def test_invalid_expected_hash_rejected(self):
        expected = self.hashes.copy()
        expected['offline_snapshot_reader.py'] = 'wrong'
        self.report['source_sha256'] = expected.copy()
        self.rejected('SOURCE_LOCK_MISMATCH', hashes=expected)

    def test_model_write_claim_rejected(self):
        self.report['model_writes'] = 1
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_civil_nx_call_claim_rejected(self):
        self.report['civil_nx_calls'] = 1
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_boolean_zero_calls_rejected(self):
        self.report['civil_nx_calls'] = False
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_engineering_accepted_rejected(self):
        self.report['engineering_accepted'] = True
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_claim_of_independent_authenticity_rejected(self):
        self.report['independent_authenticity'] = True
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_wrong_scope_rejected(self):
        self.report['test_scope'] = 'LIVE_MODEL'
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_wrong_schema_rejected(self):
        self.report['schema'] = 'legacy'
        self.rejected('INVALID_SAFETY_OR_PLATFORM_CLAIM')

    def test_unsupported_python_version_rejected(self):
        self.report['python'] = '2.7.18'
        self.rejected('INVALID_PYTHON_VERSION')

    def test_untrusted_python_version_string_rejected(self):
        self.report['python'] = '3.13.2; secret'
        self.rejected('INVALID_PYTHON_VERSION')

    def test_extra_report_field_rejected(self):
        self.report['engineering_certified'] = True
        self.rejected('MALFORMED_REPORT')

    def test_missing_report_field_rejected(self):
        self.report.pop('independent_authenticity')
        self.rejected('MALFORMED_REPORT')

    def test_nonobject_report_rejected(self):
        self.rejected('MALFORMED_REPORT', report=['untrusted'])

    def test_nonobject_suite_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE] = 'pass'
        self.rejected('MALFORMED_SUITE_RESULT')

    def test_extra_suite_field_rejected(self):
        self.report['suites'][gate.REQUIRED_NATIVE_SUITE]['certificate'] = True
        self.rejected('MALFORMED_SUITE_RESULT')

    def test_all_suite_id_pins_match_discovery(self):
        for name in gate.SUITES:
            with self.subTest(name=name):
                suite = unittest.defaultTestLoader.loadTestsFromName(name)
                self.assertEqual(len(gate.verify_suite_identity(name, suite)), gate.SUITES[name])

    def test_report_missing_suite_identity_digest_rejected(self):
        self.report['suite_ids_sha256'].pop(gate.REQUIRED_NATIVE_SUITE)
        self.rejected('TEST_IDENTITY_MISMATCH')

    def test_report_changed_suite_identity_digest_rejected(self):
        self.report['suite_ids_sha256'][gate.REQUIRED_NATIVE_SUITE] = '0' * 64
        self.rejected('TEST_IDENTITY_MISMATCH')

    def test_report_extra_suite_identity_digest_rejected(self):
        self.report['suite_ids_sha256']['untrusted'] = '0' * 64
        self.rejected('TEST_IDENTITY_MISMATCH')

    def test_unknown_suite_identity_rejected(self):
        with self.assertRaisesRegex(gate.DojoGateRejected, 'UNKNOWN_TEST_SUITE'):
            gate.verify_suite_identity('untrusted', unittest.TestSuite())

    def test_empty_suite_identity_rejected(self):
        with self.assertRaisesRegex(gate.DojoGateRejected, 'TEST_IDENTITY_MISMATCH'):
            gate.verify_suite_identity(gate.REQUIRED_NATIVE_SUITE, unittest.TestSuite())

    def test_duplicate_suite_identity_rejected(self):
        suite = unittest.defaultTestLoader.loadTestsFromName(gate.REQUIRED_NATIVE_SUITE)
        first = next(iter(next(iter(suite))))
        duplicate = unittest.TestSuite([first] * gate.SUITES[gate.REQUIRED_NATIVE_SUITE])
        with self.assertRaisesRegex(gate.DojoGateRejected, 'TEST_IDENTITY_MISMATCH'):
            gate.verify_suite_identity(gate.REQUIRED_NATIVE_SUITE, duplicate)

    def test_wrong_test_same_count_rejected(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)
                                    for _ in range(gate.SUITES[gate.REQUIRED_NATIVE_SUITE])])
        with self.assertRaisesRegex(gate.DojoGateRejected, 'TEST_IDENTITY_MISMATCH'):
            gate.verify_suite_identity(gate.REQUIRED_NATIVE_SUITE, suite)

    def test_non_suite_discovery_rejected(self):
        with self.assertRaisesRegex(gate.DojoGateRejected, 'INVALID_TEST_DISCOVERY'):
            gate.verify_suite_identity(gate.REQUIRED_NATIVE_SUITE, object())

    def test_execution_identity_tracker_records_actual_cases(self):
        class SingleCase(unittest.TestCase):
            def runTest(self):
                self.assertTrue(True)
        suite = unittest.TestSuite([SingleCase()])
        result = unittest.TextTestRunner(stream=io.StringIO(), resultclass=gate._IdentityTrackingResult).run(suite)
        self.assertEqual(result.executed_ids, [SingleCase().id()])

    def test_required_suite_counts_match_discovery(self):
        for name, expected in gate.SUITES.items():
            with self.subTest(name=name):
                self.assertEqual(unittest.defaultTestLoader.loadTestsFromName(name).countTestCases(), expected)

    def test_nonwindows_host_is_not_native(self):
        if os.name != 'nt':
            self.assertFalse(gate.native_windows())
            with self.assertRaisesRegex(gate.DojoGateRejected, 'NATIVE_WINDOWS_REQUIRED'):
                gate.run_synthetic(Path(__file__).parent)


class NativeSuiteLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.hashes = {}
        for name in gate.SOURCE_FILES:
            (self.folder / name).write_bytes(name.encode())
            self.hashes[name] = hashlib.sha256(name.encode()).hexdigest()
        self.lock = {'schema': 'self_declared_suite_lock_v1',
                     'source_sha256': self.hashes,
                     'authenticity': 'SELF_DECLARED_NOT_INDEPENDENT'}
        self.write_lock()

    def write_lock(self):
        (self.folder / 'windows_native_suite_lock.json').write_text(json.dumps(self.lock), encoding='utf-8')

    def test_lock_matching(self):
        self.assertEqual(gate.verify_lock(self.folder), self.hashes)

    def test_modified_source_rejected(self):
        (self.folder / 'offline_snapshot_reader.py').write_bytes(b'tampered')
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SOURCE_LOCK_MISMATCH'):
            gate.verify_lock(self.folder)

    def test_missing_source_rejected(self):
        (self.folder / 'offline_snapshot_reader.py').unlink()
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SOURCE_FILE_INVALID'):
            gate.verify_lock(self.folder)

    def test_missing_lock_rejected(self):
        (self.folder / 'windows_native_suite_lock.json').unlink()
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SUITE_LOCK_INVALID'):
            gate.verify_lock(self.folder)

    def test_malformed_lock_rejected(self):
        (self.folder / 'windows_native_suite_lock.json').write_text('{', encoding='utf-8')
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SUITE_LOCK_INVALID'):
            gate.verify_lock(self.folder)

    def test_lock_extra_field_rejected(self):
        self.lock['certified'] = True
        self.write_lock()
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SUITE_LOCK_INVALID'):
            gate.verify_lock(self.folder)

    def test_lock_claims_independent_authenticity_rejected(self):
        self.lock['authenticity'] = 'INDEPENDENT'
        self.write_lock()
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SUITE_LOCK_INVALID'):
            gate.verify_lock(self.folder)

    def test_lock_missing_digest_rejected(self):
        self.lock['source_sha256'].pop('offline_snapshot_reader.py')
        self.write_lock()
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SUITE_LOCK_INVALID'):
            gate.verify_lock(self.folder)

    def test_source_symlink_rejected(self):
        target = self.folder / 'offline_snapshot_reader.py'
        target.unlink()
        try:
            target.symlink_to(self.folder / 'offline_windows_dojo_gate.py')
        except (OSError, NotImplementedError):
            self.skipTest('symlink not supported')
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SOURCE_FILE_INVALID'):
            gate.verify_lock(self.folder)

    def test_oversized_lock_rejected(self):
        (self.folder / 'windows_native_suite_lock.json').write_bytes(b' ' * 20_000)
        with self.assertRaisesRegex(gate.DojoGateRejected, 'SUITE_LOCK_INVALID'):
            gate.verify_lock(self.folder)


if __name__ == '__main__':
    unittest.main()
