"""Limited static safety guards; not a substitute for Windows runtime testing."""
import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent


class StaticSnapshotSafetyContract(unittest.TestCase):
    def test_no_network_or_process_imports(self):
        tree = ast.parse((ROOT / 'offline_snapshot_reader.py').read_text(encoding='utf-8'))
        banned = {'requests', 'socket', 'subprocess', 'urllib', 'http', 'ftplib', 'winreg'}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split('.')[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split('.')[0])
        self.assertFalse(imported & banned)

    def test_no_root_abspath_or_resolve_normalization(self):
        source = (ROOT / 'offline_snapshot_reader.py').read_text(encoding='utf-8')
        self.assertNotIn('ntpath.abspath(', source)
        self.assertNotIn('.resolve(', source)

    def test_win32_open_uses_read_access_and_share_read(self):
        source = (ROOT / 'offline_snapshot_reader.py').read_text(encoding='utf-8')
        self.assertIn('access = FILE_READ_ATTRIBUTES if directory else (FILE_READ_DATA | FILE_READ_ATTRIBUTES)', source)
        self.assertIn('k32.CreateFileW(path, access, FILE_SHARE_READ, None, OPEN_EXISTING, flags, None)', source)
        self.assertNotIn('FILE_WRITE_DATA', source)
        self.assertNotIn('FILE_SHARE_WRITE', source)
        self.assertNotIn('FILE_SHARE_DELETE', source)

    def test_hardened_inventory_never_certifies(self):
        source = (ROOT / 'offline_evidence_inventory_hardened.py').read_text(encoding='utf-8')
        self.assertIn("'engineering_accepted': False", source)
        self.assertIn("'civil_nx_contacted': False", source)
        self.assertIn("'result_extraction_verified': False", source)


if __name__ == '__main__':
    unittest.main()
