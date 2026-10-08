"""Pure-Python Win32 root contract tests; safe to run on Linux and Windows."""
import unittest
from offline_snapshot_reader import validate_windows_root, validate_relative, SnapshotRejected


class WindowsRootContract(unittest.TestCase):
    pass


INVALID_ROOTS = {
    'relative': r'evidence\captures',
    'drive_relative': r'C:evidence',
    'root_relative': r'\evidence',
    'unc': r'\\server\share\capture',
    'extended_unc': r'\\?\UNC\server\share',
    'extended_drive': r'\\?\C:\capture',
    'device': r'\\.\C:\capture',
    'forward_slash': 'C:/evidence',
    'mixed_slash': 'C:\\evidence/sub',
    'parent_component': r'C:\evidence\..\capture',
    'dot_component': r'C:\evidence\.\capture',
    'repeated_separator': 'C:\\evidence\\\\capture',
    'trailing_separator': 'C:\\evidence\\',
    'trailing_dot': 'C:\\evidence. ',
    'trailing_space': 'C:\\evidence ',
    'ads': 'C:\\evidence:stream',
    'embedded_nul': 'C:\\evidence\x00secret',
    'newline': 'C:\\evidence\nsecret',
    'wildcard': 'C:\\foo*bar',
    'question_mark': 'C:\\foo?bar',
    'reserved_con': 'C:\\CON',
    'reserved_lpt': 'C:\\LPT1.txt',
    'reserved_superscript': 'C:\\COM¹.txt',
    'reserved_console': 'C:\\CONOUT$',
    'empty': '',
    'too_long': 'C:\\' + 'x' * 239,
    'deep': 'C:\\' + '\\'.join(['d'] * 21),
}

VALID_ROOTS = {
    'drive_root': ('C:\\', ('C:', ())),
    'nested': ('d:\\evidence\\captures', ('D:', ('evidence', 'captures'))),
    'underscores': ('E:\\bridge_data\\2026-10-08', ('E:', ('bridge_data', '2026-10-08'))),
}


def add_rejected_test(name, value):
    def test(self):
        with self.assertRaises(SnapshotRejected):
            validate_windows_root(value)
    setattr(WindowsRootContract, 'test_reject_' + name, test)


for name, value in INVALID_ROOTS.items():
    add_rejected_test(name, value)


def add_valid_test(name, value, expected):
    def test(self):
        self.assertEqual(validate_windows_root(value), expected)
    setattr(WindowsRootContract, 'test_accept_' + name, test)


for name, (value, expected) in VALID_ROOTS.items():
    add_valid_test(name, value, expected)


class PortableDeviceNames(unittest.TestCase):
    def test_com_superscript(self):
        with self.assertRaises(SnapshotRejected):
            validate_relative('COM¹.txt')

    def test_lpt_superscript(self):
        with self.assertRaises(SnapshotRejected):
            validate_relative('LPT²')

    def test_conin(self):
        with self.assertRaises(SnapshotRejected):
            validate_relative('CONIN$')

    def test_conout(self):
        with self.assertRaises(SnapshotRejected):
            validate_relative('CONOUT$.log')


if __name__ == '__main__':
    unittest.main()
