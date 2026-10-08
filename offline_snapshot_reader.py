"""Candidate read-only evidence snapshot reader. No MIDAS calls or model writes.

POSIX: directory-fd walk with O_NOFOLLOW and inode-pinned reads.
Windows: Win32 handles for every ancestor, reject reparse points and deny write/delete
sharing during capture. Windows branch is intentionally NOT validated on Windows yet.
No captured bytes or paths are emitted in exception messages or reports.
"""
from __future__ import annotations

import errno
import hashlib
import ntpath
import os
import re
import stat
from pathlib import Path

MAX_BYTES = 16_000_000
MAX_DEPTH = 20
MAX_COMPONENT = 120

class SnapshotRejected(ValueError):
    """Generic, non-sensitive reason code only."""


_RESERVED = re.compile(r'^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?$', re.I)


def validate_relative(relative: str) -> tuple[str, ...]:
    """Accept one conservative portable relative syntax on all platforms."""
    if not isinstance(relative, str) or not relative or len(relative) > 240:
        raise SnapshotRejected('INVALID_RELATIVE_PATH')
    if relative.startswith('/') or '\\' in relative or '\x00' in relative or ':' in relative:
        raise SnapshotRejected('INVALID_RELATIVE_PATH')
    parts = relative.split('/')
    if len(parts) > MAX_DEPTH:
        raise SnapshotRejected('EXCESSIVE_PATH_DEPTH')
    for part in parts:
        if (not part or part in ('.', '..') or len(part) > MAX_COMPONENT
                or part[-1] in ('.', ' ') or _RESERVED.fullmatch(part)
                or any(ord(c) < 32 or c in '<>"|?*' for c in part)):
            raise SnapshotRejected('UNSAFE_PATH_COMPONENT')
    return tuple(parts)


def validate_windows_root(root) -> tuple[str, tuple[str, ...]]:
    """Validate an *already absolute* fixed-drive path without Win32 normalization.

    Pure Python to permit adversarial root-path tests on non-Windows hosts.
    Never use abspath/resolve here: those could silently turn a relative or
    traversal-containing caller-controlled path into an apparently safe root.
    Drive type, reparse status and filesystem permissions are checked later.
    """
    try:
        raw = os.fspath(root)
    except TypeError:
        raise SnapshotRejected('UNSUPPORTED_WINDOWS_ROOT') from None
    if (not isinstance(raw, str) or not raw or len(raw) > 240
            or '/' in raw or '\x00' in raw or raw.startswith('\\\\')):
        raise SnapshotRejected('UNSUPPORTED_WINDOWS_ROOT')
    drive, tail = ntpath.splitdrive(raw)
    if not re.fullmatch(r'[A-Za-z]:', drive) or not tail.startswith('\\'):
        raise SnapshotRejected('UNSUPPORTED_WINDOWS_ROOT')
    if tail == '\\':
        return drive.upper(), ()
    # Disallow duplicate separators and trailing separators except drive root.
    parts = tail[1:].split('\\')
    if not parts or any(not part for part in parts) or len(parts) > MAX_DEPTH:
        raise SnapshotRejected('UNSAFE_WINDOWS_ROOT')
    for part in parts:
        if (part in ('.', '..') or len(part) > MAX_COMPONENT
                or part[-1] in ('.', ' ') or _RESERVED.fullmatch(part)
                or any(ord(c) < 32 or c in '<>"|?*:' for c in part)):
            raise SnapshotRejected('UNSAFE_WINDOWS_ROOT')
    return drive.upper(), tuple(parts)


def _assert_file(st):
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SnapshotRejected('NOT_SINGLE_LINK_REGULAR_FILE')
    if st.st_size < 0 or st.st_size > MAX_BYTES:
        raise SnapshotRejected('ARTIFACT_SIZE_LIMIT')


def _posix_snapshot(root, parts):
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise SnapshotRejected('SAFE_OPEN_UNSUPPORTED')
    root = Path(root)
    if root.is_symlink():
        raise SnapshotRejected('UNSAFE_ROOT')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    handles = []
    try:
        try:
            handles.append(os.open(root, flags))
            for part in parts[:-1]:
                handles.append(os.open(part, flags, dir_fd=handles[-1]))
            fflags = (os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0)
                      | getattr(os, 'O_CLOEXEC', 0))
            handles.append(os.open(parts[-1], fflags, dir_fd=handles[-1]))
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise SnapshotRejected('FILE_MISSING') from None
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise SnapshotRejected('UNSAFE_PATH_COMPONENT') from None
            raise SnapshotRejected('SAFE_OPEN_FAILED') from None
        fd = handles[-1]
        before = os.fstat(fd)
        _assert_file(before)
        sha, size = hashlib.sha256(), 0
        while True:
            try:
                buf = os.read(fd, min(65536, MAX_BYTES + 1 - size))
            except OSError:
                raise SnapshotRejected('READ_FAILED') from None
            if not buf:
                break
            size += len(buf)
            if size > MAX_BYTES:
                raise SnapshotRejected('ARTIFACT_SIZE_LIMIT')
            sha.update(buf)
        after = os.fstat(fd)
        _assert_file(after)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if size != after.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
            raise SnapshotRejected('ARTIFACT_CHANGED_DURING_READ')
        return {'sha256': sha.hexdigest(), 'size': size, 'snapshot_status': 'READ_ONLY_PINNED'}
    finally:
        for fd in reversed(handles):
            os.close(fd)


def _windows_snapshot(root, parts):
    # Import only on Windows; never silently substitute the unsafe Path.read_bytes().
    import ctypes
    from ctypes import wintypes

    FILE_READ_DATA = 0x0001
    FILE_READ_ATTRIBUTES = 0x0080
    FILE_SHARE_READ = 0x0001  # no share-write, no share-delete
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    FILE_ATTRIBUTE_DIRECTORY = 0x10
    FILE_ATTRIBUTE_REPARSE_POINT = 0x400
    FILE_TYPE_DISK = 1
    DRIVE_FIXED = 3
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class FILETIME(ctypes.Structure):
        _fields_ = [('low', wintypes.DWORD), ('high', wintypes.DWORD)]

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [('attrs', wintypes.DWORD), ('created', FILETIME),
                    ('accessed', FILETIME), ('modified', FILETIME),
                    ('volume', wintypes.DWORD), ('size_high', wintypes.DWORD),
                    ('size_low', wintypes.DWORD), ('links', wintypes.DWORD),
                    ('index_high', wintypes.DWORD), ('index_low', wintypes.DWORD)]

    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                               ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                               wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
    k32.GetFileInformationByHandle.restype = wintypes.BOOL
    k32.GetFileType.argtypes = [wintypes.HANDLE]
    k32.GetFileType.restype = wintypes.DWORD
    k32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    k32.GetDriveTypeW.restype = wintypes.UINT
    k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    k32.ReadFile.restype = wintypes.BOOL

    def open_handle(path, directory):
        access = FILE_READ_ATTRIBUTES if directory else (FILE_READ_DATA | FILE_READ_ATTRIBUTES)
        flags = FILE_FLAG_OPEN_REPARSE_POINT | (FILE_FLAG_BACKUP_SEMANTICS if directory else 0)
        handle = k32.CreateFileW(path, access, FILE_SHARE_READ, None, OPEN_EXISTING, flags, None)
        if handle == INVALID_HANDLE_VALUE or handle is None:
            error = ctypes.get_last_error()
            if error in (2, 3):
                raise SnapshotRejected('FILE_MISSING')
            raise SnapshotRejected('WINDOWS_SAFE_OPEN_FAILED')
        return handle

    def info(handle, directory):
        obj = BY_HANDLE_FILE_INFORMATION()
        if not k32.GetFileInformationByHandle(handle, ctypes.byref(obj)):
            raise SnapshotRejected('WINDOWS_HANDLE_INFO_FAILED')
        if obj.attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            raise SnapshotRejected('WINDOWS_REPARSE_POINT_REJECTED')
        if bool(obj.attrs & FILE_ATTRIBUTE_DIRECTORY) != directory:
            raise SnapshotRejected('WINDOWS_FILE_TYPE_REJECTED')
        if k32.GetFileType(handle) != FILE_TYPE_DISK:
            raise SnapshotRejected('WINDOWS_NONDISK_REJECTED')
        return obj

    def identity(obj):
        return (obj.volume, obj.index_high, obj.index_low, obj.links,
                obj.size_high, obj.size_low, obj.modified.high, obj.modified.low,
                obj.created.high, obj.created.low, obj.attrs)

    # Do not normalize caller-controlled roots. UNC, relative, ADS, traversal,
    # DOS devices and extended paths fail closed before any CreateFileW call.
    drive, root_parts = validate_windows_root(root)
    if k32.GetDriveTypeW(drive + '\\') != DRIVE_FIXED:
        raise SnapshotRejected('UNSUPPORTED_WINDOWS_DRIVE_TYPE')
    components = root_parts + parts
    handles = []
    try:
        current = drive + '\\'
        handles.append(open_handle(current, True))
        info(handles[-1], True)
        for i, part in enumerate(components):
            current = ntpath.join(current, part)
            directory = i != len(components) - 1
            handles.append(open_handle(current, directory))
            info(handles[-1], directory)
        file_handle = handles[-1]
        before = info(file_handle, False)
        if before.links != 1:
            raise SnapshotRejected('WINDOWS_HARDLINK_REJECTED')
        expected_size = (before.size_high << 32) | before.size_low
        if expected_size > MAX_BYTES:
            raise SnapshotRejected('ARTIFACT_SIZE_LIMIT')
        sha, size = hashlib.sha256(), 0
        buffer = ctypes.create_string_buffer(65536)
        while True:
            nread = wintypes.DWORD()
            if not k32.ReadFile(file_handle, buffer, len(buffer), ctypes.byref(nread), None):
                raise SnapshotRejected('WINDOWS_READ_FAILED')
            if nread.value == 0:
                break
            size += nread.value
            if size > MAX_BYTES:
                raise SnapshotRejected('ARTIFACT_SIZE_LIMIT')
            sha.update(buffer.raw[:nread.value])
        after = info(file_handle, False)
        if identity(before) != identity(after) or size != expected_size:
            raise SnapshotRejected('ARTIFACT_CHANGED_DURING_READ')
        return {'sha256': sha.hexdigest(), 'size': size, 'snapshot_status': 'READ_ONLY_PINNED'}
    finally:
        for handle in reversed(handles):
            k32.CloseHandle(handle)


def snapshot_sha256(root, relative):
    """Digest one pinned file; return digest/size only, never content or path."""
    parts = validate_relative(relative)
    if os.name == 'nt':
        return _windows_snapshot(root, parts)
    return _posix_snapshot(root, parts)
