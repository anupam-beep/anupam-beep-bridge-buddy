"""Windows-only, offline synthetic Win32 API tests. No Civil NX access."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from offline_snapshot_reader import snapshot_sha256, SnapshotRejected


@unittest.skipUnless(os.name == 'nt', 'Windows runtime required; not validated on Linux')
class WindowsSnapshotRuntime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'capture'
        self.root.mkdir()
        (self.root / 'nested').mkdir()
        self.payload = b'ONLY-SYNTHETIC-BRIDGE-DOJO-EVIDENCE'
        (self.root / 'nested' / 'capture.bin').write_bytes(self.payload)

    def test_valid_snapshot_hash(self):
        result = snapshot_sha256(self.root, 'nested/capture.bin')
        self.assertEqual(result['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(result['size'], len(self.payload))

    def test_no_modification(self):
        target = self.root / 'nested' / 'capture.bin'
        before = target.stat()
        snapshot_sha256(self.root, 'nested/capture.bin')
        after = target.stat()
        self.assertEqual(target.read_bytes(), self.payload)
        self.assertEqual(before.st_mtime_ns, after.st_mtime_ns)

    def test_missing_rejected(self):
        with self.assertRaisesRegex(SnapshotRejected, 'FILE_MISSING'):
            snapshot_sha256(self.root, 'missing.bin')

    def test_directory_rejected(self):
        with self.assertRaises(SnapshotRejected):
            snapshot_sha256(self.root, 'nested')

    def test_oversized_rejected(self):
        with (self.root / 'large.bin').open('wb') as f:
            f.truncate(16_000_001)
        with self.assertRaisesRegex(SnapshotRejected, 'ARTIFACT_SIZE_LIMIT'):
            snapshot_sha256(self.root, 'large.bin')

    def test_hardlink_rejected(self):
        try:
            os.link(self.root / 'nested' / 'capture.bin', self.root / 'hardlink.bin')
        except OSError as exc:
            self.skipTest('Hardlinks unsupported in synthetic temp volume: ' + type(exc).__name__)
        with self.assertRaisesRegex(SnapshotRejected, 'WINDOWS_HARDLINK_REJECTED'):
            snapshot_sha256(self.root, 'hardlink.bin')

    def test_final_symlink_rejected(self):
        try:
            (self.root / 'alias.bin').symlink_to(self.root / 'nested' / 'capture.bin')
        except OSError as exc:
            self.skipTest('Windows symlink permission not granted: ' + type(exc).__name__)
        with self.assertRaisesRegex(SnapshotRejected, 'WINDOWS_REPARSE_POINT_REJECTED'):
            snapshot_sha256(self.root, 'alias.bin')

    def test_parent_symlink_rejected(self):
        try:
            (self.root / 'aliasdir').symlink_to(self.root / 'nested', target_is_directory=True)
        except OSError as exc:
            self.skipTest('Windows symlink permission not granted: ' + type(exc).__name__)
        with self.assertRaisesRegex(SnapshotRejected, 'WINDOWS_REPARSE_POINT_REJECTED'):
            snapshot_sha256(self.root, 'aliasdir/capture.bin')

    def test_root_symlink_rejected(self):
        alias = Path(self.tmp.name) / 'root_alias'
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except OSError as exc:
            self.skipTest('Windows symlink permission not granted: ' + type(exc).__name__)
        with self.assertRaisesRegex(SnapshotRejected, 'WINDOWS_REPARSE_POINT_REJECTED'):
            snapshot_sha256(alias, 'nested/capture.bin')

    def test_fail_closed_unsafe_root(self):
        with self.assertRaisesRegex(SnapshotRejected, 'UNSUPPORTED_WINDOWS_ROOT'):
            snapshot_sha256('relative-capture', 'nested/capture.bin')

    def test_concurrent_write_open_denied_during_capture(self):
        # Native Windows FILE_SHARE_READ must prevent a new writer while the
        # pinned snapshot handle is open. All files are synthetic temp data.
        target = self.root / 'nested' / 'capture.bin'
        with target.open('r+b'):
            pass  # Confirm normal write-open is permitted before capture.
        real_sha256 = hashlib.sha256
        observed = []
        def attempt_writer():
            try:
                with target.open('r+b'):
                    observed.append('WRITER_OPENED')
            except OSError:
                observed.append('WRITER_BLOCKED')
            return real_sha256()
        with patch('offline_snapshot_reader.hashlib.sha256', side_effect=attempt_writer):
            result = snapshot_sha256(self.root, 'nested/capture.bin')
        self.assertEqual(observed, ['WRITER_BLOCKED'])
        self.assertEqual(result['sha256'], real_sha256(self.payload).hexdigest())

    def test_concurrent_rename_denied_during_capture(self):
        # FILE_SHARE_DELETE is intentionally absent; a concurrent rename
        # must not redirect a pinned file while the reader is active.
        target = self.root / 'nested' / 'capture.bin'
        renamed = self.root / 'nested' / 'renamed.bin'
        real_sha256 = hashlib.sha256
        observed = []
        def attempt_rename():
            try:
                target.rename(renamed)
                observed.append('RENAME_SUCCEEDED')
            except OSError:
                observed.append('RENAME_BLOCKED')
            return real_sha256()
        with patch('offline_snapshot_reader.hashlib.sha256', side_effect=attempt_rename):
            result = snapshot_sha256(self.root, 'nested/capture.bin')
        self.assertEqual(observed, ['RENAME_BLOCKED'])
        self.assertTrue(target.is_file())
        self.assertFalse(renamed.exists())
        self.assertEqual(result['sha256'], real_sha256(self.payload).hexdigest())

    def test_readonly_file(self):
        target = self.root / 'nested' / 'capture.bin'
        target.chmod(0o444)
        try:
            self.assertEqual(snapshot_sha256(self.root, 'nested/capture.bin')['size'], len(self.payload))
        finally:
            target.chmod(0o666)


if __name__ == '__main__':
    unittest.main()
