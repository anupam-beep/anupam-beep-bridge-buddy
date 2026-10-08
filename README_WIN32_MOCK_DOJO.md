# BridgeAgent candidate: Win32 snapshot fault-injection Dojo

**Status:** OFFLINE_SIMULATOR_TESTED; WINDOWS_NATIVE_NOT_RUN; NOT_DEPLOYED; NOT_CERTIFIED.

This candidate-only addition exercises the existing `offline_snapshot_reader._windows_snapshot()` through a deliberately limited, in-memory substitute for the six Win32 functions it calls. It does **not** touch Civil NX, models, user captures, files, the network, or production code. The simulator is included only in `test_windows_win32_mock_dojo.py` and is never imported by the snapshot reader.

## Covered Dojo scenarios

The 25 new tests exercise a synthetic successful hash; read-only open parameters; reverse-order handle cleanup; fixed-drive rejection; unsafe roots and alternate streams; missing and access-denied opens; root, parent and file reparse rejection; file/directory type mismatch; non-disk handles; hardlinks; oversized files; failed and short reads; metadata/identity changes (mtime, volume, index, creation time, attributes); zero-byte and multichunk files; and absence of engineering certification in outputs.

The test uses mock `ctypes.WinDLL` and Win32-shaped structures. On Linux, `ctypes.wintypes` is *not* guaranteed to use Windows ABI sizes (e.g. DWORD can differ); therefore successful simulation is **not** Windows runtime validation. In particular it does not prove OS file-sharing, ACL, reparse, handle inheritance, file-system or race semantics. The Windows-specific runtime tests remain skipped on Linux.

## Reproducibility

From this isolated extracted candidate directory:

```sh
python -m unittest -q test_windows_win32_mock_dojo
python -m unittest discover -p 'test_*.py' -q
python -m compileall -q .
```

On a **separate Windows test machine** with no Civil NX connection, use `run_windows_synthetic_dojo.ps1` from the extracted candidate folder to run the platform tests. Do not run from the production BridgeAgent directory.

## Certification gate

A green simulated suite cannot promote this candidate. Native Windows synthetic tests, independent evidence provenance, authentic Civil NX result extraction, and human engineering review remain distinct gates. Do not claim that a digest by itself proves capture authenticity or analysis completion.
