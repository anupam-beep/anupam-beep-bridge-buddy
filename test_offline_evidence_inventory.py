import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from offline_evidence_inventory import (
    GATES, InventoryRejected, _safe_relative, inspect_prior_archive,
    inventory, load_claims, main,
)


def claims(items=()):
    return {'schema_version': 1, 'capture_id': 'offline-example',
            'artifacts': list(items)}


def entry(gate='E1', path='one.bin', payload=b'data'):
    return {'gate': gate, 'relative_path': path,
            'sha256': hashlib.sha256(payload).hexdigest()}


class TestManifestValidation(unittest.TestCase):
    def parse(self, obj):
        return load_claims(json.dumps(obj).encode())

    def test_empty_claims_valid(self): self.assertEqual(self.parse(claims())['artifacts'], [])
    def test_duplicate_json_key(self):
        with self.assertRaisesRegex(InventoryRejected, 'DUPLICATE_JSON_KEY'):
            load_claims(b'{"schema_version":1,"schema_version":1,"capture_id":"c","artifacts":[]}')
    def test_invalid_json(self):
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_MANIFEST_JSON'):
            load_claims(b'{broken')
    def test_invalid_utf8(self):
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_MANIFEST_JSON'):
            load_claims(b'\xff')
    def test_oversize_manifest(self):
        with self.assertRaisesRegex(InventoryRejected, 'MANIFEST_TOO_LARGE'):
            load_claims(b'x'*256001)
    def test_schema_unknown_key(self):
        x = claims(); x['trusted'] = True
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_MANIFEST_SCHEMA'): self.parse(x)
    def test_bool_schema_version_rejected(self):
        x = claims(); x['schema_version'] = True
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_SCHEMA_VERSION'): self.parse(x)
    def test_bad_capture_id(self):
        x = claims(); x['capture_id'] = '../../secret'
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_CAPTURE_ID'): self.parse(x)
    def test_unknown_gate(self):
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_GATE_OR_HASH'):
            self.parse(claims([entry('E8')]))
    def test_uppercase_digest_rejected(self):
        e = entry(); e['sha256'] = e['sha256'].upper()
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_GATE_OR_HASH'):
            self.parse(claims([e]))
    def test_duplicate_path_casefold(self):
        with self.assertRaisesRegex(InventoryRejected, 'DUPLICATE_ARTIFACT_PATH'):
            self.parse(claims([entry(path='a.txt'), entry('E2', 'A.txt')]))
    def test_too_many_entries(self):
        x = claims([entry(path=f'{i}.txt') for i in range(201)])
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_ARTIFACT_COUNT'): self.parse(x)
    def test_entry_extra_field(self):
        e = entry(); e['trusted'] = True
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_ARTIFACT_SCHEMA'):
            self.parse(claims([e]))
    def test_path_traversal(self):
        for name in ('../secret', 'x/../y', '/absolute', 'C:/x', 'x\\y', 'x//y', 'x/./y', 'x/', ''):
            with self.subTest(name=name), self.assertRaises(InventoryRejected): _safe_relative(name)
    def test_nonfinite_json(self):
        with self.assertRaisesRegex(InventoryRejected, 'NONFINITE_JSON'):
            load_claims(b'{"schema_version":1,"capture_id":"a","artifacts":[],"x":NaN}')


class TestInventory(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, path='one.bin', payload=b'data'):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return target

    def test_missing_all_gates(self):
        result = inventory(self.root, claims())
        self.assertEqual(set(result['gate_inventory']), set(GATES))
        self.assertTrue(all(x['status'] == 'MISSING' for x in result['gate_inventory'].values()))
        self.assertFalse(result['engineering_accepted'])
    def test_hash_match_is_untrusted(self):
        self.write()
        result = inventory(self.root, claims([entry()]))
        self.assertEqual(result['gate_inventory']['E1']['status'], 'PRESENT_HASH_MATCH_UNAUTHENTICATED')
        self.assertFalse(result['all_gates_authenticated'])
        self.assertFalse(result['result_extraction_verified'])
    def test_all_gates_still_not_certified(self):
        entries = []
        for gate in GATES:
            name = gate + '.bin'; self.write(name)
            entries.append(entry(gate, name))
        result = inventory(self.root, claims(entries))
        self.assertEqual(result['hash_matched'], 7)
        self.assertFalse(result['engineering_accepted'])
        self.assertFalse(result['all_gates_authenticated'])
    def test_mismatch(self):
        self.write(payload=b'tampered')
        result = inventory(self.root, claims([entry()]))
        self.assertEqual(result['gate_inventory']['E1']['status'], 'INTEGRITY_MISMATCH')
    def test_missing_file(self):
        result = inventory(self.root, claims([entry()]))
        self.assertEqual(result['gate_inventory']['E1']['status'], 'INCOMPLETE')
    def test_multiple_one_gate_partial(self):
        self.write()
        result = inventory(self.root, claims([entry(), entry('E1', 'absent.bin')]))
        self.assertEqual(result['gate_inventory']['E1']['status'], 'INCOMPLETE')
    def test_multiple_one_gate_mismatch_precedence(self):
        self.write(payload=b'bad')
        result = inventory(self.root, claims([entry(), entry('E1', 'absent.bin')]))
        self.assertEqual(result['gate_inventory']['E1']['status'], 'INTEGRITY_MISMATCH')
    def test_no_content_leak(self):
        secret = b'API_KEY=secret-do-not-print'
        self.write(payload=secret)
        result = inventory(self.root, claims([entry(payload=secret)]))
        self.assertNotIn('secret-do-not-print', json.dumps(result))
        self.assertNotIn('one.bin', json.dumps(result))
        self.assertNotIn('offline-example', json.dumps(result))
    def test_symlink_file(self):
        target = self.write('target.bin')
        try: (self.root / 'one.bin').symlink_to(target)
        except (OSError, NotImplementedError): self.skipTest('symlink not supported')
        with self.assertRaisesRegex(InventoryRejected, 'SYMLINK_REJECTED'):
            inventory(self.root, claims([entry()]))
    def test_symlink_parent(self):
        (self.root / 'real').mkdir()
        self.write('real/one.bin')
        try: (self.root / 'alias').symlink_to(self.root / 'real', target_is_directory=True)
        except (OSError, NotImplementedError): self.skipTest('symlink not supported')
        with self.assertRaisesRegex(InventoryRejected, 'SYMLINK_REJECTED'):
            inventory(self.root, claims([entry(path='alias/one.bin')]))
    def test_hardlink_file(self):
        target = self.write('target.bin')
        try: os.link(target, self.root / 'one.bin')
        except OSError: self.skipTest('hardlink not supported')
        with self.assertRaisesRegex(InventoryRejected, 'NONREGULAR_OR_LINKED_ARTIFACT'):
            inventory(self.root, claims([entry()]))
    def test_oversize_file(self):
        target = self.root / 'one.bin'
        with target.open('wb') as f: f.truncate(16_000_001)
        with self.assertRaisesRegex(InventoryRejected, 'ARTIFACT_TOO_LARGE'):
            inventory(self.root, claims([entry()]))
    def test_root_symlink(self):
        link = self.root / 'alias'
        try: link.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError): self.skipTest('symlink not supported')
        with self.assertRaisesRegex(InventoryRejected, 'UNSAFE_ROOT'):
            inventory(link, claims())
    def test_cli_rejects_bad_claims_without_payload(self):
        p = self.write('claims.json', b'not-json')
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf): rc = main(['--root', str(self.root), '--claims', str(p)])
        self.assertEqual(rc, 2)
        self.assertNotIn('not-json', buf.getvalue())
    def test_cli_archive(self):
        p = self.root / 'p.zip'
        with zipfile.ZipFile(p, 'w') as z: z.writestr('synthetic_capture.json', '{}')
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf): rc = main(['--prior-archive', str(p)])
        self.assertEqual(rc, 0)
        self.assertIn('NOT_ESTABLISHED_BY_ARCHIVE_METADATA', buf.getvalue())


class TestArchive(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'archive.zip'
    def make(self, entries):
        with zipfile.ZipFile(self.path, 'w') as z:
            for name, payload in entries:
                z.writestr(name, payload)
    def test_classification_metadata_only(self):
        self.make([('test_x.py', b'x'), ('module.py', b'x'),
                   ('synthetic_example.json', b'{}'), ('sha256_manifest_x.json', b'{}'),
                   ('x_cycle_report.json', b'{}'), ('unknown.md', b'x')])
        result = inspect_prior_archive(self.path)
        self.assertEqual(result['archive_entries'], 6)
        self.assertEqual(sum(result['classified_file_counts'].values()), 6)
        self.assertFalse(result['authentic_capture_confirmed'])
    def test_archive_traversal(self):
        self.make([('../evil', b'x')])
        with self.assertRaisesRegex(InventoryRejected, 'INVALID_RELATIVE_PATH'):
            inspect_prior_archive(self.path)
    def test_duplicate_archive_name(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', UserWarning)
            self.make([('same', b'1'), ('same', b'2')])
        with self.assertRaisesRegex(InventoryRejected, 'DUPLICATE_ARCHIVE_ENTRY'):
            inspect_prior_archive(self.path)
    def test_case_insensitive_duplicate(self):
        self.make([('a', b'1'), ('A', b'2')])
        with self.assertRaisesRegex(InventoryRejected, 'DUPLICATE_ARCHIVE_ENTRY'):
            inspect_prior_archive(self.path)
    def test_symlink_archive_entry(self):
        with zipfile.ZipFile(self.path, 'w') as z:
            i = zipfile.ZipInfo('link')
            i.create_system = 3
            i.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(i, b'target')
        with self.assertRaisesRegex(InventoryRejected, 'ARCHIVE_SYMLINK'):
            inspect_prior_archive(self.path)
    def test_archive_size_limit(self):
        self.make([('huge.bin', b'0' * 16_000_001)])
        with self.assertRaisesRegex(InventoryRejected, 'ARCHIVE_SIZE_LIMIT'):
            inspect_prior_archive(self.path)
    def test_zip_bomb_ratio(self):
        with zipfile.ZipFile(self.path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('bomb.bin', b'0'*500_000)
        with self.assertRaisesRegex(InventoryRejected, 'ARCHIVE_COMPRESSION_RATIO'):
            inspect_prior_archive(self.path)
    def test_invalid_archive(self):
        self.path.write_bytes(b'not-a-zip')
        with self.assertRaises(zipfile.BadZipFile): inspect_prior_archive(self.path)


if __name__ == '__main__': unittest.main()
