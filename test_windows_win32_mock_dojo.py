"""Offline Win32 call-contract simulator; runs on Linux without contacting Windows/MIDAS.

This deliberately does NOT validate real Win32 ABI, ACLs, reparse behavior or sharing.
It checks fail-closed branches and cleanup in the candidate snapshot reader.
"""
from __future__ import annotations

import ctypes
import hashlib
import unittest
from unittest.mock import patch

from offline_snapshot_reader import _windows_snapshot, SnapshotRejected, MAX_BYTES


class Fn:
    def __init__(self, action):
        self.action = action
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.action(*args)


class VirtualNode:
    def __init__(self, data=b'', directory=False, reparse=False, links=1, volume=9, index=1):
        self.data = data
        self.directory = directory
        self.reparse = reparse
        self.links = links
        self.volume = volume
        self.index = index
        self.modified = 3
        self.created = 2
        self.attrs_extra = 0


class FakeWin32:
    """Controlled behavior of six Win32 APIs, not an operating-system emulator."""
    INVALID = ctypes.c_void_p(-1).value

    def __init__(self):
        self.nodes = {
            'C:\\': VirtualNode(directory=True, index=1),
            'C:\\evidence': VirtualNode(directory=True, index=2),
            'C:\\evidence\\data.bin': VirtualNode(data=b'BRIDGE-DOJO-SYNTHETIC', index=3),
        }
        self.handles = {}
        self.next_handle = 100
        self.opened = []
        self.closed = []
        self.drive_type = 3
        self.last_error = 2
        self.read_fail = False
        self.info_fail = False
        self.non_disk = False
        self.mutate_during_read = False
        self.mutate_field = None
        self.force_early_eof = False
        self.open_error_paths = set()
        self.read_events = 0
        self.api = type('FakeKernel32', (), {})()
        for name, callback in {
            'CreateFileW': self.create_file,
            'CloseHandle': self.close_handle,
            'GetFileInformationByHandle': self.get_info,
            'GetFileType': self.get_file_type,
            'GetDriveTypeW': self.get_drive_type,
            'ReadFile': self.read_file,
        }.items():
            setattr(self.api, name, Fn(callback))

    def create_file(self, path, access, share, security, disposition, flags, template):
        self.opened.append((path, access, share, disposition, flags))
        if path not in self.nodes or path in self.open_error_paths:
            return self.INVALID
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = {'node': self.nodes[path], 'offset': 0}
        return handle

    def close_handle(self, handle):
        self.closed.append(handle)
        self.handles.pop(handle, None)
        return 1

    def get_info(self, handle, pointer):
        if self.info_fail:
            return 0
        node = self.handles[handle]['node']
        obj = pointer._obj
        obj.attrs = (0x10 if node.directory else 0) | (0x400 if node.reparse else 0) | node.attrs_extra
        obj.volume = node.volume
        obj.index_high = 0
        obj.index_low = node.index
        obj.links = node.links
        size = len(node.data)
        obj.size_high = size >> 32
        obj.size_low = size & 0xffffffff
        obj.modified.high = 0
        obj.modified.low = node.modified
        obj.created.high = 0
        obj.created.low = node.created
        return 1

    def get_file_type(self, handle):
        return 2 if self.non_disk else 1

    def get_drive_type(self, root):
        return self.drive_type

    def read_file(self, handle, buffer, capacity, nread_pointer, overlapped):
        self.read_events += 1
        if self.read_fail:
            return 0
        state = self.handles[handle]
        node = state['node']
        if self.force_early_eof:
            nread_pointer._obj.value = 0
            return 1
        offset = state['offset']
        chunk = node.data[offset:offset + capacity]
        if chunk:
            ctypes.memmove(buffer, chunk, len(chunk))
        nread_pointer._obj.value = len(chunk)
        state['offset'] += len(chunk)
        if self.mutate_during_read:
            node.modified += 1
        if self.mutate_field and chunk:
            setattr(node, self.mutate_field, getattr(node, self.mutate_field) + 1)
        return 1


class MockWin32SnapshotDojo(unittest.TestCase):
    def setUp(self):
        self.fake = FakeWin32()
        self.dll = patch.object(ctypes, 'WinDLL', create=True, return_value=self.fake.api)
        self.err = patch.object(ctypes, 'get_last_error', create=True, return_value=self.fake.last_error)
        self.dll.start()
        self.err.start()
        self.addCleanup(self.dll.stop)
        self.addCleanup(self.err.stop)

    def snap(self, root='C:\\evidence', parts=('data.bin',)):
        return _windows_snapshot(root, parts)

    def assert_clean(self):
        self.assertEqual(self.fake.handles, {})
        self.assertEqual(len(self.fake.closed), len(self.fake.opened) - sum(
            path not in self.fake.nodes or path in self.fake.open_error_paths
            for path, *_ in self.fake.opened))

    def assert_rejected(self, reason, **kwargs):
        with self.assertRaisesRegex(SnapshotRejected, reason):
            self.snap(**kwargs)
        self.assert_clean()

    def test_valid_hash_and_no_write_access(self):
        output = self.snap()
        self.assertEqual(output['sha256'], hashlib.sha256(b'BRIDGE-DOJO-SYNTHETIC').hexdigest())
        self.assertEqual(output['size'], 21)
        self.assertEqual(output['snapshot_status'], 'READ_ONLY_PINNED')
        self.assertEqual([p for p, *_ in self.fake.opened], ['C:\\', 'C:\\evidence', 'C:\\evidence\\data.bin'])
        self.assertTrue(all(share == 1 and disposition == 3 for _, _, share, disposition, _ in self.fake.opened))
        self.assertEqual([a for _, a, *_ in self.fake.opened], [0x80, 0x80, 0x81])
        self.assertEqual(self.fake.closed, [102, 101, 100])
        self.assert_clean()

    def test_drive_not_fixed(self):
        self.fake.drive_type = 4
        self.assert_rejected('UNSUPPORTED_WINDOWS_DRIVE_TYPE')
        self.assertEqual(self.fake.opened, [])

    def test_relative_root_no_open(self):
        self.assert_rejected('UNSUPPORTED_WINDOWS_ROOT', root='evidence')
        self.assertEqual(self.fake.opened, [])

    def test_missing_root_child(self):
        self.assert_rejected('FILE_MISSING', parts=('missing.bin',))

    def test_open_access_denied(self):
        self.fake.open_error_paths.add('C:\\evidence\\data.bin')
        self.fake.last_error = 5
        with patch.object(ctypes, 'get_last_error', create=True, return_value=5):
            self.assert_rejected('WINDOWS_SAFE_OPEN_FAILED')

    def test_file_reparse(self):
        self.fake.nodes['C:\\evidence\\data.bin'].reparse = True
        self.assert_rejected('WINDOWS_REPARSE_POINT_REJECTED')

    def test_parent_reparse(self):
        self.fake.nodes['C:\\evidence'].reparse = True
        self.assert_rejected('WINDOWS_REPARSE_POINT_REJECTED')
        self.assertEqual(len(self.fake.opened), 2)

    def test_root_reparse(self):
        self.fake.nodes['C:\\'].reparse = True
        self.assert_rejected('WINDOWS_REPARSE_POINT_REJECTED')
        self.assertEqual(len(self.fake.opened), 1)

    def test_file_is_directory(self):
        self.fake.nodes['C:\\evidence\\data.bin'].directory = True
        self.assert_rejected('WINDOWS_FILE_TYPE_REJECTED')

    def test_parent_is_file(self):
        self.fake.nodes['C:\\evidence'].directory = False
        self.assert_rejected('WINDOWS_FILE_TYPE_REJECTED')

    def test_nondisk_handle(self):
        self.fake.non_disk = True
        self.assert_rejected('WINDOWS_NONDISK_REJECTED')

    def test_hardlink(self):
        self.fake.nodes['C:\\evidence\\data.bin'].links = 2
        self.assert_rejected('WINDOWS_HARDLINK_REJECTED')

    def test_oversize(self):
        self.fake.nodes['C:\\evidence\\data.bin'].data = b'x' * (MAX_BYTES + 1)
        self.assert_rejected('ARTIFACT_SIZE_LIMIT')
        self.assertEqual(self.fake.read_events, 0)

    def test_read_failure(self):
        self.fake.read_fail = True
        self.assert_rejected('WINDOWS_READ_FAILED')

    def test_read_early_eof(self):
        self.fake.force_early_eof = True
        self.assert_rejected('ARTIFACT_CHANGED_DURING_READ')

    def test_modified_metadata_during_read(self):
        self.fake.mutate_during_read = True
        self.assert_rejected('ARTIFACT_CHANGED_DURING_READ')

    def test_identity_index_change(self):
        self.fake.mutate_field = 'index'
        self.assert_rejected('ARTIFACT_CHANGED_DURING_READ')

    def test_identity_volume_change(self):
        self.fake.mutate_field = 'volume'
        self.assert_rejected('ARTIFACT_CHANGED_DURING_READ')

    def test_identity_creation_time_change(self):
        self.fake.mutate_field = 'created'
        self.assert_rejected('ARTIFACT_CHANGED_DURING_READ')

    def test_identity_attribute_change(self):
        self.fake.mutate_field = 'attrs_extra'
        self.assert_rejected('ARTIFACT_CHANGED_DURING_READ')

    def test_result_is_not_engineering_certificate(self):
        self.assertEqual(set(self.snap()), {'sha256', 'size', 'snapshot_status'})
        self.assert_clean()

    def test_info_failure(self):
        self.fake.info_fail = True
        self.assert_rejected('WINDOWS_HANDLE_INFO_FAILED')

    def test_zero_length_file(self):
        self.fake.nodes['C:\\evidence\\data.bin'].data = b''
        self.assertEqual(self.snap()['sha256'], hashlib.sha256(b'').hexdigest())
        self.assert_clean()

    def test_long_multichunk(self):
        payload = b'x' * 100_000
        self.fake.nodes['C:\\evidence\\data.bin'].data = payload
        self.assertEqual(self.snap()['sha256'], hashlib.sha256(payload).hexdigest())
        self.assertGreaterEqual(self.fake.read_events, 3)
        self.assert_clean()

    def test_fail_closed_before_open_on_unsafe_ads(self):
        self.assert_rejected('UNSAFE_WINDOWS_ROOT', root='C:\\evidence:ads')
        self.assertEqual(self.fake.opened, [])


if __name__ == '__main__':
    unittest.main()
