# BridgeAgent offline Win32 evidence-snapshot contract hardening

**Candidate status: LINUX_TESTED / WINDOWS_RUNTIME_NOT_RUN / NOT_DEPLOYED.** No MIDAS Civil NX requests, model operations, engineering certification, or production modifications.

## Actual changes in this cycle

1. Closed a Windows root-path acceptance gap: the inherited reader used `ntpath.abspath`, which could normalize relative or traversal-containing caller input into an apparently safe root. The candidate now rejects these inputs *before* any Win32 file open.
2. Added a pure-Python `validate_windows_root()` contract: drive-absolute `X:\...` only, no UNC/device/extended roots, no forward slashes, parent traversal, alternate data streams, device names, ambiguous trailing separators/dots/spaces, control characters, or oversized/deep roots.
3. Added a conservative `GetDriveTypeW` gate that requires `DRIVE_FIXED`. This does **not** independently prove that every fixed-looking drive is local, especially with redirected/virtualized storage.
4. Extended the Windows file-identity comparison to include creation timestamp and attributes; extended device-name screening to superscript COM/LPT digits and `CONIN$`/`CONOUT$`.
5. Added portable adversarial path tests, Windows-only synthetic runtime tests, and limited static safety-contract tests. Adjusted inherited synthetic snapshot tests to use platform-correct expectations and skip POSIX-only read hooks on Windows.

## Reproducible tests

Linux offline regression (executed in this cycle):

```bash
python -m unittest discover -p 'test_*.py' -q
python -m compileall -q .
```

**Observed:** 480 discovered; 469 executed and passed; 11 Windows-only tests skipped on Linux. All Python modules compiled. The previous ZIP's self-declared SHA-256 manifest was independently recomputed against its archive bytes: 91/91 matched; this establishes consistency, **not** third-party authenticity.

Windows test instructions (prepared, **not executed**): extract this ZIP to an isolated temporary folder on a fixed local drive; run `run_windows_synthetic_dojo.ps1` using PowerShell. The script executes only four relevant synthetic test modules, not the unrelated POSIX-only escrow tests. No API key or Civil NX installation is required. Do not run it inside the production BridgeAgent directory.

## Certification / limitations

- Actual Win32 API behavior, file-sharing semantics, junction/reparse handling, Windows ACLs and race resistance are **not verified** until the Windows-only suite runs on Windows 10/11.
- A fixed-drive type check is not a cryptographic local-device guarantee. Pre-existing writable file handles may still mutate a file; before/after metadata checks do not provide a formally atomic snapshot against hostile in-place writes.
- Tests are synthetic and contain no authentic Civil NX numerical results. `POST/TABLE` result extraction, E1–E7 provenance, independent authority and engineering acceptance remain blocked.
- Existing production code and safety locks are unchanged. No auto-promotion.
