"""Offline adversarial tests; synthetic content only, no credentials or MIDAS access."""
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from offline_snapshot_reader import snapshot_sha256, validate_relative, SnapshotRejected
from offline_evidence_inventory import load_claims, InventoryRejected
from offline_evidence_inventory_hardened import inventory_hardened


class SnapshotReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'evidence'
        self.root.mkdir()
        (self.root / 'sub').mkdir()
        self.payload = b'synthetic-test-bytes-not-real-Civil-NX-data'
        (self.root / 'sub' / 'test.bin').write_bytes(self.payload)

    def test_hash(self):
        got = snapshot_sha256(self.root, 'sub/test.bin')
        self.assertEqual(got['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(got['size'], len(self.payload))

    def test_empty(self):
        (self.root / 'zero').write_bytes(b'')
        self.assertEqual(snapshot_sha256(self.root, 'zero')['size'], 0)

    def test_nested(self):
        (self.root / 'sub' / 'more').mkdir()
        (self.root / 'sub' / 'more' / 'a').write_bytes(b'a')
        self.assertEqual(snapshot_sha256(self.root, 'sub/more/a')['size'], 1)

    def test_missing_rejected(self):
        with self.assertRaises(SnapshotRejected):
            snapshot_sha256(self.root, 'missing')

    def test_directory_rejected(self):
        with self.assertRaises(SnapshotRejected):
            snapshot_sha256(self.root, 'sub')

    def test_file_over_limit(self):
        with (self.root / 'large').open('wb') as f:
            f.truncate(16_000_001)
        with self.assertRaisesRegex(SnapshotRejected, 'ARTIFACT_SIZE_LIMIT'):
            snapshot_sha256(self.root, 'large')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'requires symlinks')
    def test_final_symlink_rejected(self):
        try:
            (self.root / 'alias').symlink_to(self.root / 'sub' / 'test.bin')
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation unsupported')
        with self.assertRaises(SnapshotRejected):
            snapshot_sha256(self.root, 'alias')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'requires symlinks')
    def test_parent_symlink_rejected(self):
        try:
            (self.root / 'diralias').symlink_to(self.root / 'sub', target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation unsupported')
        with self.assertRaises(SnapshotRejected):
            snapshot_sha256(self.root, 'diralias/test.bin')

    @unittest.skipUnless(hasattr(os, 'symlink'), 'requires symlinks')
    def test_root_symlink_rejected(self):
        alias = Path(self.tmp.name) / 'alias'
        try:
            alias.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation unsupported')
        expected = 'WINDOWS_REPARSE_POINT_REJECTED' if os.name == 'nt' else 'UNSAFE_ROOT'
        with self.assertRaisesRegex(SnapshotRejected, expected):
            snapshot_sha256(alias, 'sub/test.bin')

    def test_hardlink_rejected(self):
        try:
            os.link(self.root / 'sub' / 'test.bin', self.root / 'hard')
        except (OSError, NotImplementedError):
            self.skipTest('Hardlink creation unsupported')
        expected = 'WINDOWS_HARDLINK_REJECTED' if os.name == 'nt' else 'NOT_SINGLE_LINK_REGULAR_FILE'
        with self.assertRaisesRegex(SnapshotRejected, expected):
            snapshot_sha256(self.root, 'hard')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'requires FIFO')
    def test_fifo_rejected_nonblocking(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaisesRegex(SnapshotRejected, 'NOT_SINGLE_LINK_REGULAR_FILE'):
            snapshot_sha256(self.root, 'pipe')

    @unittest.skipUnless(os.name == 'posix', 'POSIX os.read hook; Windows has separate runtime suite')
    def test_changed_during_read_rejected(self):
        original_read = os.read
        target = self.root / 'sub' / 'test.bin'
        changed = [False]
        def mutating_read(fd, count):
            chunk = original_read(fd, count)
            if chunk and not changed[0]:
                changed[0] = True
                target.write_bytes(b'changed-content')
            return chunk
        with patch('offline_snapshot_reader.os.read', side_effect=mutating_read):
            with self.assertRaisesRegex(SnapshotRejected, 'ARTIFACT_CHANGED_DURING_READ'):
                snapshot_sha256(self.root, 'sub/test.bin')

    @unittest.skipUnless(os.name == 'posix', 'POSIX os.read hook; Windows has separate runtime suite')
    def test_changed_same_length_rejected(self):
        original_read = os.read
        target = self.root / 'sub' / 'test.bin'
        changed = [False]
        def mutating_read(fd, count):
            chunk = original_read(fd, count)
            if chunk and not changed[0]:
                changed[0] = True
                target.write_bytes(b'Z' * len(self.payload))
            return chunk
        with patch('offline_snapshot_reader.os.read', side_effect=mutating_read):
            with self.assertRaisesRegex(SnapshotRejected, 'ARTIFACT_CHANGED_DURING_READ'):
                snapshot_sha256(self.root, 'sub/test.bin')

    @unittest.skipUnless(os.name == 'posix', 'POSIX dirfd race test')
    def test_parent_swap_cannot_redirect_pinned_reader(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (outside / 'test.bin').write_bytes(b'ATTACKER_DATA')
        original_read = os.read
        changed = [False]
        def parent_swapping_read(fd, count):
            if not changed[0]:
                changed[0] = True
                (self.root / 'sub').rename(self.root / 'sub-old')
                (self.root / 'sub').symlink_to(outside, target_is_directory=True)
            return original_read(fd, count)
        with patch('offline_snapshot_reader.os.read', side_effect=parent_swapping_read):
            got = snapshot_sha256(self.root, 'sub/test.bin')
        self.assertEqual(got['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertNotEqual(got['sha256'], hashlib.sha256(b'ATTACKER_DATA').hexdigest())

    @unittest.skipUnless(os.name == 'posix', 'POSIX inode-pinning test')
    def test_final_name_replacement_does_not_redirect_reader(self):
        original_read = os.read
        changed = [False]
        def replacing_read(fd, count):
            if not changed[0]:
                changed[0] = True
                (self.root / 'sub' / 'test.bin').rename(self.root / 'sub' / 'old.bin')
                (self.root / 'sub' / 'test.bin').write_bytes(b'ATTACKER_DATA')
            return original_read(fd, count)
        with patch('offline_snapshot_reader.os.read', side_effect=replacing_read):
            with self.assertRaisesRegex(SnapshotRejected, 'ARTIFACT_CHANGED_DURING_READ'):
                snapshot_sha256(self.root, 'sub/test.bin')

    def test_does_not_modify_file(self):
        before = (self.root / 'sub' / 'test.bin').read_bytes()
        snapshot_sha256(self.root, 'sub/test.bin')
        self.assertEqual((self.root / 'sub' / 'test.bin').read_bytes(), before)

    def test_digest_does_not_return_bytes_or_path(self):
        got = snapshot_sha256(self.root, 'sub/test.bin')
        self.assertEqual(set(got), {'sha256', 'size', 'snapshot_status'})

    def test_relative_path_rejections(self):
        bad = ('', '../escape', '/absolute', 'sub//file', 'sub/./file',
               'sub/../file', 'sub\\file', 'C:/file', 'file:stream',
               'CON', 'con.txt', 'NUL', 'LPT1.log', 'file.', 'file ',
               'foo?bar', 'foo*bar', 'a\x00b', 'a\nb', 'a<', 'a>',
               'a"b', 'a|b', 'a' * 121, 'a/' * 21 + 'x')
        for rel in bad:
            with self.subTest(rel=repr(rel)):
                with self.assertRaises(SnapshotRejected):
                    validate_relative(rel)

    def test_relative_valid(self):
        self.assertEqual(validate_relative('a/b-c_1.json'), ('a', 'b-c_1.json'))

    def test_root_file_rejected(self):
        with self.assertRaises(SnapshotRejected):
            snapshot_sha256(self.root / 'sub' / 'test.bin', 'sub/test.bin')


class HardenedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'e1').write_bytes(b'synthetic')
        self.claims = {'schema_version': 1, 'capture_id': 'test1', 'artifacts': [
            {'gate': 'E1', 'relative_path': 'e1', 'sha256': hashlib.sha256(b'synthetic').hexdigest()}]}

    def test_one_matching_claim(self):
        out = inventory_hardened(self.root, self.claims)
        self.assertEqual(out['hash_matched'], 1)
        self.assertFalse(out['result_extraction_verified'])
        self.assertFalse(out['engineering_accepted'])
        self.assertEqual(out['gate_inventory']['E1']['status'], 'PRESENT_HASH_MATCH_UNAUTHENTICATED')
        self.assertEqual(out['gate_inventory']['E7']['status'], 'MISSING')

    def test_hash_mismatch(self):
        self.claims['artifacts'][0]['sha256'] = '0' * 64
        self.assertEqual(inventory_hardened(self.root, self.claims)['hash_mismatches'], 1)

    def test_missing_file(self):
        (self.root / 'e1').unlink()
        out = inventory_hardened(self.root, self.claims)
        self.assertEqual(out['missing_files'], 1)
        self.assertEqual(out['hash_matched'], 0)

    def test_unsafe_symlink_never_matches(self):
        if not hasattr(os, 'symlink'):
            self.skipTest('requires symlink')
        (self.root / 'e1').unlink()
        try:
            (self.root / 'e1').symlink_to(Path(self.tmp.name) / 'external')
        except (OSError, NotImplementedError):
            self.skipTest('Symlink creation unsupported')
        with self.assertRaises(InventoryRejected):
            inventory_hardened(self.root, self.claims)

    def test_manifest_loader_round_trip(self):
        claims = load_claims(json.dumps(self.claims).encode())
        self.assertEqual(inventory_hardened(self.root, claims)['hash_matched'], 1)

    def test_total_limit_enforced(self):
        # No huge files: inject a synthetic digest size through a mocked reader.
        claims = dict(self.claims)
        claims['artifacts'] = [self.claims['artifacts'][0]] * 5
        with patch('offline_evidence_inventory_hardened.snapshot_sha256',
                   return_value={'size': 16_000_000, 'sha256': self.claims['artifacts'][0]['sha256']}):
            with self.assertRaisesRegex(InventoryRejected, 'TOTAL_ARTIFACT_BYTES_EXCEEDED'):
                inventory_hardened(self.root, claims)


if __name__ == '__main__':
    unittest.main()
