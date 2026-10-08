"""Synthetic Bridge Dojo tests; never touches MIDAS or production models."""
import copy
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from offline_capture_bundle_intake import ROLES, SCHEMA, verify_capture_bundle


def fixture_files():
    d = {
        'request.bin': b'POST /post/TABLE HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"Argument":{"TABLE_NAME":"BeamForce"}}',
        'response.json': b'{"BeamForce":{"HEAD":["Elem","FX"],"DATA":[[1,42.0]]}}',
        'analysis_attestation.json': b'{"run_id":"synthetic-run-1","signed":true}',
        'capture_receipt.json': b'{"capture_id":"synthetic-capture-1","signed":true}',
        'checkpoint_anchor.json': b'{"checkpoint":"synthetic-checkpoint-1","signed":true}',
    }
    return d


def make_manifest(files):
    return {'schema': SCHEMA, 'artifacts': [
        {'role':role,'path':filename,'mime':mime,'bytes':len(files[filename]),
         'sha256':hashlib.sha256(files[filename]).hexdigest()}
        for role, (filename, mime) in ROLES.items()]}


def make_zip(files=None, manifest=None, extra=None, compression=zipfile.ZIP_DEFLATED, tamper_info=None):
    files = fixture_files() if files is None else dict(files)
    manifest = make_manifest(files) if manifest is None else manifest
    files['manifest.json'] = json.dumps(manifest, separators=(',',':')).encode()
    if extra:
        files.update(extra)
    bio = io.BytesIO()
    with zipfile.ZipFile(bio,'w',compression=compression) as z:
        for name, data in files.items():
            if tamper_info and name in tamper_info:
                zi = tamper_info[name]
                z.writestr(zi,data)
            else:
                z.writestr(name,data)
    return bio.getvalue()

class IntakeDojo(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'bundle.zip'

    def check(self, data, expected):
        self.path.write_bytes(data)
        result = verify_capture_bundle(self.path)
        self.assertEqual(result['status'],expected,result)
        self.assertFalse(result['provenance_verified'])
        self.assertFalse(result['engineering_accepted'])
        self.assertFalse(result['civil_nx_contacted'])
        return result

    def reject(self, data, reason=None):
        result=self.check(data,'REJECT')
        if reason: self.assertEqual(result['reason'],reason)

    def test_valid_sanitized_bundle_not_certified(self):
        result=self.check(make_zip(),'OFFLINE_INTAKE_PASS_NOT_CERTIFIED')
        self.assertEqual(result['roles_checked'],5)

    def test_bad_zip(self): self.reject(b'not zip','INVALID_ARCHIVE')
    def test_empty_zip(self): self.reject(self._empty_zip(),'UNEXPECTED_OR_MISSING_MEMBER')
    def _empty_zip(self):
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w'): pass
        return out.getvalue()
    def test_extra_member(self): self.reject(make_zip(extra={'debug.log':b'hi'}),'UNEXPECTED_OR_MISSING_MEMBER')
    def test_missing_member(self):
        files=fixture_files(); del files['capture_receipt.json']
        # generate manifest manually to avoid key error
        m=make_manifest(fixture_files())
        self.reject(make_zip(files,manifest=m),'UNEXPECTED_OR_MISSING_MEMBER')
    def test_path_traversal(self): self.reject(make_zip(extra={'../escape':b'bad'}),'UNEXPECTED_OR_MISSING_MEMBER')
    def test_windows_path_traversal(self): self.reject(make_zip(extra={'..\\escape':b'bad'}),'UNEXPECTED_OR_MISSING_MEMBER')
    def test_nested_zip(self): self.reject(make_zip(extra={'nested.zip':b'PK\x03\x04'}),'UNEXPECTED_OR_MISSING_MEMBER')
    def test_duplicate_archive_entry(self):
        data=make_zip()
        src=zipfile.ZipFile(io.BytesIO(data))
        bio=io.BytesIO()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',UserWarning)
            with zipfile.ZipFile(bio,'w') as z:
                for name in src.namelist(): z.writestr(name,src.read(name))
                z.writestr('request.bin',src.read('request.bin'))
        self.reject(bio.getvalue(),'UNEXPECTED_OR_MISSING_MEMBER')
    def test_symlink_member(self):
        zi=zipfile.ZipInfo('response.json'); zi.create_system=3
        zi.external_attr=(0o120777 << 16)
        self.reject(make_zip(tamper_info={'response.json':zi}),'NONREGULAR_MEMBER')
    def test_wrong_mime(self):
        m=make_manifest(fixture_files()); m['artifacts'][1]['mime']='text/plain'
        self.reject(make_zip(manifest=m),'FILE_TYPE_OR_NAME_MISMATCH')
    def test_wrong_digest(self):
        m=make_manifest(fixture_files()); m['artifacts'][0]['sha256']='0'*64
        self.reject(make_zip(manifest=m),'HASH_MISMATCH')
    def test_wrong_length(self):
        m=make_manifest(fixture_files()); m['artifacts'][0]['bytes']+=1
        self.reject(make_zip(manifest=m),'SIZE_MISMATCH')
    def test_bool_as_length(self):
        m=make_manifest(fixture_files()); m['artifacts'][0]['bytes']=True
        self.reject(make_zip(manifest=m),'SIZE_MISMATCH')
    def test_duplicate_role(self):
        m=make_manifest(fixture_files()); m['artifacts'][1]['role']='request'
        self.reject(make_zip(manifest=m),'BAD_MANIFEST_ROLES')
    def test_manifest_unknown_field(self):
        m=make_manifest(fixture_files()); m['debug']='secretless'
        self.reject(make_zip(manifest=m),'BAD_MANIFEST_SCHEMA')
    def test_duplicate_json_key(self):
        files=fixture_files(); files['response.json']=b'{"a":1,"a":2}'
        self.reject(make_zip(files),'DUPLICATE_JSON_KEY')
    def test_nan_json(self):
        files=fixture_files(); files['response.json']=b'{"x":NaN}'
        self.reject(make_zip(files),'NONFINITE_JSON_NUMBER')
    def test_invalid_utf8_json(self):
        files=fixture_files(); files['response.json']=b'{"x":"\xff"}'
        self.reject(make_zip(files),'INVALID_JSON')
    def test_deep_json(self):
        files=fixture_files(); files['response.json']=b'{"a":'+b'['*34+b'0'+b']'*34+b'}'
        self.reject(make_zip(files),'JSON_TOO_DEEP')
    def test_response_array_root(self):
        files=fixture_files(); files['response.json']=b'[1,2]'
        self.reject(make_zip(files),'JSON_ROOT_NOT_OBJECT')
    def test_auth_bearer_secret_no_leak(self):
        files=fixture_files(); files['request.bin']=b'Authorization: Bearer secretvalue123456'
        result=self.check(make_zip(files),'REJECT')
        self.assertEqual(result['reason'],'POTENTIAL_CREDENTIAL')
        self.assertNotIn('secretvalue',str(result))
    def test_midas_key_no_leak(self):
        files=fixture_files(); files['request.bin']=b'MIDAS_MAPI_KEY=secretvalue123456'
        self.reject(make_zip(files),'POTENTIAL_CREDENTIAL')
    def test_escaped_json_secret_key(self):
        files=fixture_files(); files['response.json']=b'{"api\\u005fkey":"abc123secret"}'
        self.reject(make_zip(files),'POTENTIAL_CREDENTIAL')
    def test_midas_mapi_header_secret(self):
        files=fixture_files(); files['request.bin']=b'MAPI-Key: secretvalue123456'
        self.reject(make_zip(files),'POTENTIAL_CREDENTIAL')
    def test_authorization_nonbearer_secret(self):
        files=fixture_files(); files['request.bin']=b'Authorization: Token abcdefghijk'
        self.reject(make_zip(files),'POTENTIAL_CREDENTIAL')
    def test_private_key_block(self):
        files=fixture_files(); files['request.bin']=b'-----BEGIN PRIVATE KEY-----\nSECRET\n'
        self.reject(make_zip(files),'POTENTIAL_CREDENTIAL')
    def test_compression_bomb_ratio(self):
        files=fixture_files(); files['request.bin']=b'X'*200_000
        self.reject(make_zip(files),'SUSPICIOUS_COMPRESSION_RATIO')
    def test_member_size_limit(self):
        files=fixture_files(); files['request.bin']=b'X'*(4*1024*1024+1)
        self.reject(make_zip(files),'MEMBER_TOO_LARGE')
    def test_truncated_zip(self):
        self.reject(make_zip()[:100],'INVALID_ARCHIVE')
    def test_nonexistent_path(self):
        result=verify_capture_bundle(Path(self.temp.name)/'not-there.zip')
        self.assertEqual(result['reason'],'ARCHIVE_NOT_REGULAR_FILE')

if __name__ == '__main__': unittest.main()
